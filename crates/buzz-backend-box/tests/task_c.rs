use buzz_backend_box::provision::{
    EMBEDDED_ENTRYPOINT, EMBEDDED_EXTERNAL_STOP, EMBEDDED_POSTSTOP, EMBEDDED_SUPERVISOR,
    EMBEDDED_UNIT,
};
use buzz_backend_box::redact::Redactor;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn asset_test_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "buzz-box-task-c-{label}-{}-{suffix}",
        std::process::id()
    ))
}

fn install_fake_box(bin_dir: &PathBuf, log_path: &PathBuf) {
    fs::create_dir_all(bin_dir).expect("fake bin directory should be created");
    let box_path = bin_dir.join("box");
    fs::write(
        &box_path,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BOX_LOG\"\n",
    )
    .expect("fake box should be written");
    let mut permissions = fs::metadata(&box_path)
        .expect("fake box metadata should be readable")
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
    }
    fs::set_permissions(&box_path, permissions).expect("fake box should be executable");
    if log_path.exists() {
        fs::remove_file(log_path).expect("old fake box log should be removed");
    }
}

fn install_executable(path: &PathBuf, content: &str) {
    fs::write(path, content).expect("fake executable should be written");
    let mut permissions = fs::metadata(path)
        .expect("fake executable metadata should be readable")
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
    }
    fs::set_permissions(path, permissions).expect("fake executable should be executable");
}

struct HandoffHarness {
    root: PathBuf,
    run_dir: PathBuf,
    bin_dir: PathBuf,
    supervisor_path: PathBuf,
    external_stop_path: PathBuf,
    docker_log: PathBuf,
    box_log: PathBuf,
    image_ref: String,
    docker_release: PathBuf,
    stop_release: PathBuf,
    supervisor_run_entered: PathBuf,
    external_stop_entered: PathBuf,
}

impl Drop for HandoffHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn handoff_harness(label: &str) -> HandoffHarness {
    let root = asset_test_root(label);
    let var_dir = root.join("var/lib/buzz-agent");
    let run_dir = root.join("run/buzz-agent");
    let libexec_dir = root.join("usr/local/libexec");
    let bin_dir = root.join("bin");
    let supervisor_path = root.join("supervise.sh");
    let external_stop_path = root.join("external-stop.sh");
    let docker_log = root.join("docker.log");
    let box_log = root.join("box.log");
    let docker_release = root.join("docker-release");
    let stop_release = root.join("stop-release");
    let supervisor_run_entered = root.join("supervisor-run-entered");
    let external_stop_entered = root.join("external-stop-entered");
    let image_ref =
        "registry.example/buzz@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string();

    fs::create_dir_all(&var_dir).expect("state directory should be created");
    fs::create_dir_all(&run_dir).expect("run directory should be created");
    fs::create_dir_all(&libexec_dir).expect("libexec directory should be created");
    fs::create_dir_all(&bin_dir).expect("fake bin directory should be created");
    fs::write(run_dir.join("invocation"), "nonce-1\n").expect("invocation should be written");
    fs::write(var_dir.join("image.ref"), format!("{image_ref}\n"))
        .expect("image marker should be written");
    fs::write(
        run_dir.join("env.pending"),
        r#"{"BUZZ_MANAGED_AGENT_START_NONCE":"nonce-1"}"#,
    )
    .expect("pending env should be written");
    #[cfg(unix)]
    fs::set_permissions(run_dir.join("env.pending"), {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o600)
    })
    .expect("pending env should be secured");
    fs::write(run_dir.join("launch-authorized"), "nonce-1\n")
        .expect("launch authorization should be written");

    install_executable(
        &bin_dir.join("stat"),
        "#!/bin/sh\nprintf '%s\\n' '0:0:600'\n",
    );
    install_executable(
        &bin_dir.join("box"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BOX_LOG\"\n",
    );
    install_executable(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$DOCKER_LOG"
case "$1" in
    image)
        printf '%s\n' "$DOCKER_IMAGE"
        ;;
    run)
        : > "$SUPERVISOR_RUN_ENTERED"
        while [ ! -f "$DOCKER_RELEASE" ]; do
            sleep 1
        done
        printf '%s\n' consumed > "$CONSUMED_PATH"
        ;;
    stop)
        : > "$EXTERNAL_STOP_ENTERED"
        : > "$DOCKER_RELEASE"
        while [ ! -f "$STOP_RELEASE" ]; do
            sleep 1
        done
        ;;
    rm)
        ;;
esac
"#,
    );

    let supervisor = EMBEDDED_SUPERVISOR
        .replace(
            "/var/lib/buzz-agent",
            var_dir.to_str().expect("temporary path should be UTF-8"),
        )
        .replace(
            "/run/buzz-agent",
            run_dir.to_str().expect("temporary path should be UTF-8"),
        )
        .replace(
            "/usr/local/libexec",
            libexec_dir
                .to_str()
                .expect("temporary path should be UTF-8"),
        );
    fs::write(&supervisor_path, supervisor).expect("supervisor script should be written");

    let external_stop = EMBEDDED_EXTERNAL_STOP
        .replace(
            "/var/lib/buzz-agent",
            var_dir.to_str().expect("temporary path should be UTF-8"),
        )
        .replace(
            "/run/buzz-agent",
            run_dir.to_str().expect("temporary path should be UTF-8"),
        );
    fs::write(&external_stop_path, external_stop).expect("external-stop script should be written");

    HandoffHarness {
        root,
        run_dir,
        bin_dir,
        supervisor_path,
        external_stop_path,
        docker_log,
        box_log,
        image_ref,
        docker_release,
        stop_release,
        supervisor_run_entered,
        external_stop_entered,
    }
}

fn command_path(harness: &HandoffHarness) -> String {
    format!(
        "{}:{}",
        harness.bin_dir.display(),
        std::env::var("PATH").expect("test PATH should be set")
    )
}

fn spawn_supervisor(harness: &HandoffHarness) -> Child {
    Command::new("sh")
        .arg(&harness.supervisor_path)
        .env("PATH", command_path(harness))
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &harness.docker_log)
        .env("DOCKER_IMAGE", &harness.image_ref)
        .env("BOX_LOG", &harness.box_log)
        .env("DOCKER_RELEASE", &harness.docker_release)
        .env("STOP_RELEASE", &harness.stop_release)
        .env("SUPERVISOR_RUN_ENTERED", &harness.supervisor_run_entered)
        .env("EXTERNAL_STOP_ENTERED", &harness.external_stop_entered)
        .env("CONSUMED_PATH", harness.run_dir.join("env-consumed"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("supervisor should spawn")
}

fn spawn_external_stop(harness: &HandoffHarness) -> Child {
    Command::new("sh")
        .arg(&harness.external_stop_path)
        .env("PATH", command_path(harness))
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &harness.docker_log)
        .env("DOCKER_IMAGE", &harness.image_ref)
        .env("BOX_LOG", &harness.box_log)
        .env("DOCKER_RELEASE", &harness.docker_release)
        .env("STOP_RELEASE", &harness.stop_release)
        .env("SUPERVISOR_RUN_ENTERED", &harness.supervisor_run_entered)
        .env("EXTERNAL_STOP_ENTERED", &harness.external_stop_entered)
        .env("CONSUMED_PATH", harness.run_dir.join("env-consumed"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("external-stop should spawn")
}

fn wait_for_path(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {label}: {}", path.display());
}

fn wait_for_success(child: &mut Child, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            assert!(status.success(), "{label} exited unsuccessfully: {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("timed out waiting for {label}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_status(child: &mut Child, label: &str, expected_code: i32) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            assert_eq!(
                status.code(),
                Some(expected_code),
                "{label} exited with an unexpected status: {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("timed out waiting for {label}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn seed_live_handoff_lock(harness: &HandoffHarness) {
    let lock_path = harness.run_dir.join("launch-handoff.lock");
    fs::create_dir(&lock_path).expect("handoff lock should be seeded");
    fs::write(lock_path.join("pid"), format!("{}\n", std::process::id()))
        .expect("handoff lock owner should be written");
}

fn release_seeded_handoff_lock(harness: &HandoffHarness) {
    let lock_path = harness.run_dir.join("launch-handoff.lock");
    let _ = fs::remove_file(lock_path.join("pid"));
    fs::remove_dir(lock_path).expect("seeded handoff lock should be released");
}

fn shorten_handoff_retries(path: &Path) {
    let script = fs::read_to_string(path).expect("handoff script should be readable");
    assert!(script.contains("handoff_lock_max_attempts=120"));
    assert!(script.contains("handoff_lock_retry_seconds=1"));
    let script = script
        .replace(
            "handoff_lock_max_attempts=120",
            "handoff_lock_max_attempts=3",
        )
        .replace(
            "handoff_lock_retry_seconds=1",
            "handoff_lock_retry_seconds=0.01",
        );
    fs::write(path, script).expect("shortened handoff script should be written");
}

fn install_owner_case_docker(harness: &HandoffHarness, inspect_image: bool) {
    let image = if inspect_image {
        "case \"$1\" in\n    image) printf '%s\\n' \"$DOCKER_IMAGE\" ;;\nesac\n"
    } else {
        ""
    };
    install_executable(
        &harness.bin_dir.join("docker"),
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\n{image}"),
    );
}

fn seed_owner_case(harness: &HandoffHarness, owner: Option<&str>) {
    let lock_path = harness.run_dir.join("launch-handoff.lock");
    fs::create_dir(&lock_path).expect("owner-case lock should be seeded");
    if let Some(owner) = owner {
        fs::write(lock_path.join("pid"), owner).expect("owner-case pid should be written");
    }
}

#[test]
fn unverifiable_handoff_owners_fail_closed_for_external_stop() {
    for (label, owner) in [
        ("missing-owner", None),
        ("empty-owner", Some("")),
        ("zero-owner", Some("0\n")),
        ("malformed-owner", Some("malformed\n")),
    ] {
        let harness = handoff_harness(label);
        shorten_handoff_retries(&harness.external_stop_path);
        install_owner_case_docker(&harness, false);
        seed_owner_case(&harness, owner);

        let mut external_stop = spawn_external_stop(&harness);
        wait_for_status(&mut external_stop, label, 74);

        assert!(
            harness.run_dir.join("launch-handoff.lock").exists(),
            "unverifiable {label} lock must remain"
        );
        assert!(
            fs::read_to_string(&harness.docker_log)
                .unwrap_or_default()
                .is_empty(),
            "unverifiable {label} owner must not reach Docker"
        );
    }
}

#[test]
fn numeric_handoff_owners_keep_dead_recovery_and_live_protection() {
    let dead = handoff_harness("dead-owner-short-retry");
    shorten_handoff_retries(&dead.external_stop_path);
    install_owner_case_docker(&dead, false);
    seed_owner_case(&dead, Some("99999999\n"));
    let mut dead_stop = spawn_external_stop(&dead);
    wait_for_success(&mut dead_stop, "dead numeric owner recovery");
    assert!(!dead.run_dir.join("launch-handoff.lock").exists());
    assert!(fs::read_to_string(&dead.docker_log)
        .expect("dead-owner Docker log should exist")
        .lines()
        .any(|line| line.starts_with("stop ")));

    let live = handoff_harness("live-owner-short-retry");
    shorten_handoff_retries(&live.external_stop_path);
    install_owner_case_docker(&live, false);
    seed_owner_case(&live, Some(&format!("{}\n", std::process::id())));
    let mut live_stop = spawn_external_stop(&live);
    wait_for_status(&mut live_stop, "live numeric owner protection", 74);
    assert!(live.run_dir.join("launch-handoff.lock").exists());
    assert!(
        fs::read_to_string(&live.docker_log)
            .unwrap_or_default()
            .is_empty(),
        "live numeric owner must not reach Docker"
    );
}

#[test]
fn supervisor_unverifiable_owner_keeps_lock_and_never_runs_docker() {
    for (label, owner) in [
        ("supervisor-missing-owner", None),
        ("supervisor-empty-owner", Some("")),
        ("supervisor-zero-owner", Some("0\n")),
        ("supervisor-malformed-owner", Some("malformed\n")),
    ] {
        let harness = handoff_harness(label);
        shorten_handoff_retries(&harness.supervisor_path);
        install_owner_case_docker(&harness, true);
        seed_owner_case(&harness, owner);

        let mut supervisor = spawn_supervisor(&harness);
        wait_for_status(&mut supervisor, label, 74);

        let docker_log = fs::read_to_string(&harness.docker_log).unwrap_or_default();
        assert!(
            !docker_log.lines().any(|line| line.starts_with("run ")),
            "unverifiable {label} owner must not start Docker: {docker_log}"
        );
        assert!(
            harness.run_dir.join("launch-handoff.lock").exists(),
            "unverifiable {label} lock must remain"
        );
    }
}

#[test]
fn term_during_final_handoff_check_aborts_before_docker_run() {
    let harness = handoff_harness("term-before-launch");
    let count_path = harness.root.join("stop-intent-count");
    let term_sent = harness.root.join("term-sent");
    let supervisor_pid_path = harness.root.join("supervisor-pid");
    install_executable(
        &harness.bin_dir.join("cat"),
        "#!/bin/sh\ncase \"$1\" in\n  *stop-intent)\n    count=0\n    if [ -f \"$CAT_COUNT_PATH\" ]; then read count < \"$CAT_COUNT_PATH\"; fi\n    count=$((count + 1))\n    printf '%s\\n' \"$count\" > \"$CAT_COUNT_PATH\"\n    if [ \"$count\" -eq 3 ]; then\n      : > \"$TERM_SENT\"\n      target=$(/bin/cat \"$SUPERVISOR_PID_PATH\")\n      kill -TERM \"$target\"\n    fi\n    ;;\nesac\nexec /bin/cat \"$@\"\n",
    );

    let mut supervisor = Command::new("sh")
        .arg(&harness.supervisor_path)
        .env("PATH", command_path(&harness))
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &harness.docker_log)
        .env("DOCKER_IMAGE", &harness.image_ref)
        .env("BOX_LOG", &harness.box_log)
        .env("STOP_RELEASE", &harness.stop_release)
        .env("CONSUMED_PATH", harness.run_dir.join("env-consumed"))
        .env("CAT_COUNT_PATH", &count_path)
        .env("TERM_SENT", &term_sent)
        .env("SUPERVISOR_PID_PATH", &supervisor_pid_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("supervisor should spawn for prelaunch TERM race");
    fs::write(&supervisor_pid_path, format!("{}\n", supervisor.id()))
        .expect("supervisor pid should be written");
    wait_for_success(&mut supervisor, "prelaunch TERM supervisor");

    let docker_log = fs::read_to_string(&harness.docker_log).unwrap_or_default();
    assert!(
        term_sent.exists(),
        "TERM should be injected during final check"
    );
    assert_eq!(
        docker_log
            .lines()
            .filter(|line| line.starts_with("run "))
            .count(),
        0,
        "prelaunch TERM must prevent docker run: {docker_log}"
    );
    assert!(
        docker_log.lines().any(|line| line.starts_with("stop ")),
        "prelaunch TERM should attempt to stop a named container: {docker_log}"
    );
    assert!(!harness.run_dir.join("launch-handoff.lock").exists());
    assert!(!harness.run_dir.join("env.pending").exists());
    assert!(!harness.run_dir.join("launch-authorized").exists());
}

#[test]
fn term_after_launch_stops_and_reaps_child_without_self_stop() {
    let harness = handoff_harness("term-after-launch");
    install_executable(
        &harness.bin_dir.join("docker"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\ncase \"$1\" in\n  image) printf '%s\\n' \"$DOCKER_IMAGE\" ;;\n  run) : > \"$RUN_ENTERED\"; : > \"$CONSUMED_PATH\"; while [ ! -f \"$RUN_RELEASE\" ]; do sleep 1; done ;;\n  stop) : > \"$STOP_ENTERED\"; : > \"$RUN_RELEASE\" ;;\nesac\n",
    );
    let run_entered = harness.root.join("run-entered");
    let run_release = harness.root.join("run-release");
    let stop_entered = harness.root.join("stop-entered");
    let mut supervisor = Command::new("sh")
        .arg(&harness.supervisor_path)
        .env("PATH", command_path(&harness))
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &harness.docker_log)
        .env("DOCKER_IMAGE", &harness.image_ref)
        .env("BOX_LOG", &harness.box_log)
        .env("CONSUMED_PATH", harness.run_dir.join("env-consumed"))
        .env("RUN_ENTERED", &run_entered)
        .env("RUN_RELEASE", &run_release)
        .env("STOP_ENTERED", &stop_entered)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("supervisor should spawn for postlaunch TERM race");
    wait_for_path(&run_entered, "postlaunch docker run");
    let status = Command::new("kill")
        .args(["-TERM", &supervisor.id().to_string()])
        .status()
        .expect("kill should be available");
    assert!(status.success(), "postlaunch TERM should be sent");
    wait_for_path(&stop_entered, "postlaunch docker stop");
    wait_for_success(&mut supervisor, "postlaunch TERM supervisor");

    let docker_log = fs::read_to_string(&harness.docker_log).unwrap_or_default();
    assert_eq!(
        docker_log
            .lines()
            .filter(|line| line.starts_with("run "))
            .count(),
        1,
        "postlaunch TERM should have exactly one child: {docker_log}"
    );
    assert_eq!(
        docker_log
            .lines()
            .filter(|line| line.starts_with("stop "))
            .count(),
        1,
        "postlaunch TERM should stop the child once: {docker_log}"
    );
    assert!(
        !harness.box_log.exists(),
        "external TERM must not self-stop"
    );
    assert!(!harness.run_dir.join("launch-handoff.lock").exists());
}

#[test]
fn external_stop_wins_handoff_lock_before_supervisor_and_prevents_run() {
    // The external-stop winner linearizes before the supervisor's final check,
    // so the supervisor must refuse without starting Docker.
    let harness = handoff_harness("external-wins");
    seed_live_handoff_lock(&harness);
    let supervisor_waiting = harness.root.join("supervisor-handoff-waiting");
    let supervisor_allow = harness.root.join("supervisor-handoff-allow");
    install_executable(
        &harness.bin_dir.join("mkdir"),
        "#!/bin/sh\nif [ -n \"${SUPERVISOR_HANDOFF_WAITING:-}\" ] && case \"$1\" in */launch-handoff.lock) true;; *) false;; esac; then\n    status=0\n    /bin/mkdir \"$@\" || status=$?\n    : > \"$SUPERVISOR_HANDOFF_WAITING\"\n    while [ ! -f \"$SUPERVISOR_HANDOFF_ALLOW\" ]; do sleep 1; done\n    exit \"$status\"\nfi\nexec /bin/mkdir \"$@\"\n",
    );
    let mut supervisor = Command::new("sh")
        .arg(&harness.supervisor_path)
        .env("PATH", command_path(&harness))
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &harness.docker_log)
        .env("DOCKER_IMAGE", &harness.image_ref)
        .env("BOX_LOG", &harness.box_log)
        .env("DOCKER_RELEASE", &harness.docker_release)
        .env("STOP_RELEASE", &harness.stop_release)
        .env("SUPERVISOR_RUN_ENTERED", &harness.supervisor_run_entered)
        .env("EXTERNAL_STOP_ENTERED", &harness.external_stop_entered)
        .env("CONSUMED_PATH", harness.run_dir.join("env-consumed"))
        .env("SUPERVISOR_HANDOFF_WAITING", &supervisor_waiting)
        .env("SUPERVISOR_HANDOFF_ALLOW", &supervisor_allow)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("supervisor should spawn");
    wait_for_path(&supervisor_waiting, "supervisor handoff wait");

    let mut external_stop = spawn_external_stop(&harness);
    release_seeded_handoff_lock(&harness);
    wait_for_path(
        &harness.external_stop_entered,
        "external-stop handoff ownership",
    );
    fs::write(&supervisor_allow, "ok\n").expect("supervisor handoff wrapper should be released");
    fs::write(&harness.stop_release, "ok\n").expect("external-stop should be released");
    wait_for_success(&mut external_stop, "external-stop");
    wait_for_status(&mut supervisor, "supervisor external refusal", 67);

    let docker_log = fs::read_to_string(&harness.docker_log).unwrap_or_default();
    assert_eq!(
        docker_log
            .lines()
            .filter(|line| line.starts_with("run "))
            .count(),
        0,
        "external-stop winning the handoff must prevent docker run: {docker_log}"
    );
    assert_eq!(
        docker_log
            .lines()
            .filter(|line| line.starts_with("stop "))
            .count(),
        1,
        "external-stop should issue one docker stop: {docker_log}"
    );
    assert!(!harness.run_dir.join("launch-handoff.lock").exists());
}

#[test]
fn supervisor_wins_handoff_then_external_stop_stops_one_container() {
    // The supervisor winner is also valid: Docker may already exist, but the
    // next handoff owner must issue docker stop and both processes must finish.
    let harness = handoff_harness("supervisor-wins");
    let mut supervisor = spawn_supervisor(&harness);
    wait_for_path(&harness.supervisor_run_entered, "supervisor docker run");
    let mut external_stop = spawn_external_stop(&harness);
    wait_for_path(&harness.external_stop_entered, "external-stop docker stop");
    fs::write(&harness.stop_release, "ok\n").expect("external-stop should be released");
    wait_for_success(&mut external_stop, "external-stop");
    wait_for_success(&mut supervisor, "supervisor");

    let docker_log = fs::read_to_string(&harness.docker_log).unwrap_or_default();
    assert_eq!(
        docker_log
            .lines()
            .filter(|line| line.starts_with("run "))
            .count(),
        1,
        "supervisor may start at most one container: {docker_log}"
    );
    assert_eq!(
        docker_log
            .lines()
            .filter(|line| line.starts_with("stop "))
            .count(),
        1,
        "external-stop should stop the launched container: {docker_log}"
    );
    assert!(!harness.run_dir.join("launch-handoff.lock").exists());
}

#[test]
fn stale_handoff_owner_is_recovered_without_unbounded_wait() {
    let harness = handoff_harness("stale-owner");
    let lock_path = harness.run_dir.join("launch-handoff.lock");
    fs::create_dir(&lock_path).expect("stale handoff lock should be seeded");
    fs::write(lock_path.join("pid"), "99999999\n").expect("stale owner should be written");

    let mut external_stop = spawn_external_stop(&harness);
    wait_for_path(&harness.external_stop_entered, "stale-owner recovery");
    fs::write(&harness.stop_release, "ok\n").expect("external-stop should be released");
    wait_for_success(&mut external_stop, "external-stop stale-owner recovery");
    assert!(!lock_path.exists(), "stale handoff lock should be removed");
}

#[test]
fn supervisor_signal_while_handoff_check_is_blocked_cleans_lock() {
    let harness = handoff_harness("supervisor-signal-cleanup");
    let count_path = harness.root.join("stop-intent-count");
    let final_check_entered = harness.root.join("final-check-entered");
    let final_check_release = harness.root.join("final-check-release");
    install_executable(
        &harness.bin_dir.join("cat"),
        "#!/bin/sh\ncase \"$1\" in\n  *stop-intent)\n    count=0\n    if [ -f \"$CAT_COUNT_PATH\" ]; then read count < \"$CAT_COUNT_PATH\"; fi\n    count=$((count + 1))\n    printf '%s\\n' \"$count\" > \"$CAT_COUNT_PATH\"\n    if [ \"$count\" -eq 3 ]; then\n      : > \"$FINAL_CHECK_ENTERED\"\n      while [ ! -f \"$FINAL_CHECK_RELEASE\" ]; do sleep 1; done\n    fi\n    ;;\nesac\nexec /bin/cat \"$@\"\n",
    );
    let mut supervisor = Command::new("sh")
        .arg(&harness.supervisor_path)
        .env("PATH", command_path(&harness))
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &harness.docker_log)
        .env("DOCKER_IMAGE", &harness.image_ref)
        .env("BOX_LOG", &harness.box_log)
        .env("DOCKER_RELEASE", &harness.docker_release)
        .env("STOP_RELEASE", &harness.stop_release)
        .env("SUPERVISOR_RUN_ENTERED", &harness.supervisor_run_entered)
        .env("EXTERNAL_STOP_ENTERED", &harness.external_stop_entered)
        .env("CONSUMED_PATH", harness.run_dir.join("env-consumed"))
        .env("CAT_COUNT_PATH", &count_path)
        .env("FINAL_CHECK_ENTERED", &final_check_entered)
        .env("FINAL_CHECK_RELEASE", &final_check_release)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("supervisor should spawn");
    wait_for_path(&final_check_entered, "supervisor final handoff check");
    assert!(harness.run_dir.join("launch-handoff.lock").exists());
    let status = Command::new("kill")
        .args(["-TERM", &supervisor.id().to_string()])
        .status()
        .expect("kill should be available");
    assert!(status.success(), "supervisor TERM should be sent");
    fs::write(&final_check_release, "ok\n").expect("final check should be released");
    fs::write(&harness.stop_release, "ok\n").expect("signal stop should be released");
    wait_for_success(&mut supervisor, "signalled supervisor");
    assert!(
        !harness.run_dir.join("launch-handoff.lock").exists(),
        "signal exit must not leave handoff lock"
    );
}

#[test]
fn external_stop_signal_while_handoff_write_is_blocked_cleans_lock() {
    let harness = handoff_harness("external-stop-signal-cleanup");
    let mv_entered = harness.root.join("mv-entered");
    let mv_release = harness.root.join("mv-release");
    install_executable(
        &harness.bin_dir.join("mv"),
        "#!/bin/sh\ncase \"$3\" in\n  *stop-intent)\n    : > \"$MV_ENTERED\"\n    while [ ! -f \"$MV_RELEASE\" ]; do sleep 1; done\n    ;;\nesac\nexec /bin/mv \"$@\"\n",
    );
    let mut external_stop = Command::new("sh")
        .arg(&harness.external_stop_path)
        .env("PATH", command_path(&harness))
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &harness.docker_log)
        .env("DOCKER_IMAGE", &harness.image_ref)
        .env("BOX_LOG", &harness.box_log)
        .env("DOCKER_RELEASE", &harness.docker_release)
        .env("STOP_RELEASE", &harness.stop_release)
        .env("SUPERVISOR_RUN_ENTERED", &harness.supervisor_run_entered)
        .env("EXTERNAL_STOP_ENTERED", &harness.external_stop_entered)
        .env("CONSUMED_PATH", harness.run_dir.join("env-consumed"))
        .env("MV_ENTERED", &mv_entered)
        .env("MV_RELEASE", &mv_release)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("external-stop should spawn");
    wait_for_path(&mv_entered, "external-stop handoff write");
    assert!(harness.run_dir.join("launch-handoff.lock").exists());
    let status = Command::new("kill")
        .args(["-TERM", &external_stop.id().to_string()])
        .status()
        .expect("kill should be available");
    assert!(status.success(), "external-stop TERM should be sent");
    fs::write(&mv_release, "ok\n").expect("external-stop write should be released");
    wait_for_status(&mut external_stop, "signalled external-stop", 143);
    assert!(
        !harness.run_dir.join("launch-handoff.lock").exists(),
        "signal exit must not leave handoff lock"
    );
}

fn supervisor_race_case(label: &str, prior_external: bool, inject_external: bool) {
    let root = asset_test_root(label);
    let var_dir = root.join("var/lib/buzz-agent");
    let run_dir = root.join("run/buzz-agent");
    let libexec_dir = root.join("usr/local/libexec");
    let bin_dir = root.join("bin");
    let script_path = root.join("supervise.sh");
    let docker_log = root.join("docker.log");
    let box_log = root.join("box.log");
    let image_ref =
        "registry.example/buzz@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fs::create_dir_all(&var_dir).expect("state directory should be created");
    fs::create_dir_all(&run_dir).expect("run directory should be created");
    fs::create_dir_all(&libexec_dir).expect("libexec directory should be created");
    fs::create_dir_all(&bin_dir).expect("fake bin directory should be created");
    fs::write(run_dir.join("invocation"), "nonce-1\n").expect("invocation should be written");
    fs::write(var_dir.join("image.ref"), format!("{image_ref}\n"))
        .expect("image marker should be written");
    fs::write(
        run_dir.join("env.pending"),
        r#"{"BUZZ_MANAGED_AGENT_START_NONCE":"nonce-1"}"#,
    )
    .expect("pending env should be written");
    #[cfg(unix)]
    fs::set_permissions(run_dir.join("env.pending"), {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o600)
    })
    .expect("pending env should be secured");
    fs::write(run_dir.join("launch-authorized"), "nonce-1\n")
        .expect("launch authorization should be written");
    if prior_external {
        fs::write(var_dir.join("stop-intent"), "external\n")
            .expect("external intent should be written");
    }

    install_executable(
        &bin_dir.join("stat"),
        "#!/bin/sh\nprintf '%s\\n' '0:0:600'\n",
    );
    let external_marker = var_dir.join("stop-intent");
    install_executable(
        &bin_dir.join("box"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BOX_LOG\"\n",
    );
    let docker_script = if inject_external {
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\nif [ \"$1\" = rm ] && [ \"$2\" = -f ]; then\n    printf '%s\\n' external > \"$STOP_INTENT_PATH\"\nfi\nif [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n    printf '%s\\n' \"$DOCKER_IMAGE\"\nfi\n".to_string()
    } else {
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\nif [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n    printf '%s\\n' \"$DOCKER_IMAGE\"\nfi\n".to_string()
    };
    install_executable(&bin_dir.join("docker"), &docker_script);

    let script = EMBEDDED_SUPERVISOR
        .replace(
            "/var/lib/buzz-agent",
            var_dir.to_str().expect("temporary path should be UTF-8"),
        )
        .replace(
            "/run/buzz-agent",
            run_dir.to_str().expect("temporary path should be UTF-8"),
        )
        .replace(
            "/usr/local/libexec",
            libexec_dir
                .to_str()
                .expect("temporary path should be UTF-8"),
        );
    fs::write(&script_path, script).expect("supervisor script should be written");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").expect("test PATH should be set")
    );
    let output = Command::new("sh")
        .arg(&script_path)
        .env("PATH", path)
        .env_remove("GREP_OPTIONS")
        .env("DOCKER_LOG", &docker_log)
        .env("DOCKER_IMAGE", image_ref)
        .env("STOP_INTENT_PATH", &external_marker)
        .env("BOX_LOG", &box_log)
        .output()
        .expect("supervisor should execute");
    assert_eq!(
        output.status.code(),
        Some(67),
        "unexpected refusal status for {label}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let docker_log = fs::read_to_string(&docker_log).unwrap_or_default();
    assert!(
        !docker_log.lines().any(|line| line.starts_with("run ")),
        "supervisor started Docker for {label}: {docker_log}"
    );
    assert!(
        !box_log.exists(),
        "supervisor invoked box stop self for {label}"
    );
    assert!(
        !run_dir.join("env.pending").exists(),
        "pending env leaked for {label}"
    );
    assert!(
        !run_dir.join("launch-authorized").exists(),
        "launch authorization leaked for {label}"
    );
    assert!(
        fs::read_to_string(var_dir.join("state.json"))
            .expect("refusal state should exist")
            .contains("refused-external"),
        "external refusal state missing for {label}"
    );
    fs::remove_dir_all(root).expect("asset test root should be removed");
}

#[test]
fn supervisor_refuses_matching_authorization_with_preexisting_external_intent() {
    supervisor_race_case("preexisting-external", true, false);
}

#[test]
fn supervisor_refuses_external_intent_injected_before_docker_run() {
    supervisor_race_case("injected-external", false, true);
}

fn assert_no_marker_temps(path: &PathBuf, label: &str) {
    let temps = fs::read_dir(path)
        .expect("marker directory should be readable")
        .map(|entry| entry.expect("marker entry should be readable").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains(".tmp."))
        })
        .collect::<Vec<_>>();
    assert!(
        temps.is_empty(),
        "marker temp files leaked for {label}: {temps:?}"
    );
}

#[test]
fn external_stop_cleans_marker_temp_when_mv_fails() {
    let root = asset_test_root("external-stop-mv-failure");
    let var_dir = root.join("var/lib/buzz-agent");
    let run_dir = root.join("run/buzz-agent");
    let bin_dir = root.join("bin");
    let script_path = root.join("external-stop.sh");
    fs::create_dir_all(&var_dir).expect("state directory should be created");
    fs::create_dir_all(&run_dir).expect("run directory should be created");
    fs::create_dir_all(&bin_dir).expect("fake bin directory should be created");
    install_executable(&bin_dir.join("mv"), "#!/bin/sh\nexit 73\n");
    let script = EMBEDDED_EXTERNAL_STOP
        .replace(
            "/var/lib/buzz-agent",
            var_dir.to_str().expect("temporary path should be UTF-8"),
        )
        .replace(
            "/run/buzz-agent",
            run_dir.to_str().expect("temporary path should be UTF-8"),
        );
    fs::write(&script_path, script).expect("external-stop script should be written");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").expect("test PATH should be set")
    );
    let output = Command::new("sh")
        .arg(&script_path)
        .env("PATH", path)
        .env_remove("GREP_OPTIONS")
        .output()
        .expect("external-stop should execute");
    assert_eq!(output.status.code(), Some(73));
    assert_no_marker_temps(&var_dir, "external-stop");
    fs::remove_dir_all(root).expect("asset test root should be removed");
}

#[test]
fn external_stop_marks_external_and_revokes_launch_authorization() {
    let root = asset_test_root("external-stop-revokes-auth");
    let var_dir = root.join("var/lib/buzz-agent");
    let run_dir = root.join("run/buzz-agent");
    let bin_dir = root.join("bin");
    let script_path = root.join("external-stop.sh");
    fs::create_dir_all(&var_dir).expect("state directory should be created");
    fs::create_dir_all(&run_dir).expect("run directory should be created");
    fs::create_dir_all(&bin_dir).expect("fake bin directory should be created");
    fs::write(run_dir.join("launch-authorized"), "nonce-1\n")
        .expect("launch authorization should be written");
    install_executable(&bin_dir.join("docker"), "#!/bin/sh\nexit 0\n");
    let script = EMBEDDED_EXTERNAL_STOP
        .replace(
            "/var/lib/buzz-agent",
            var_dir.to_str().expect("temporary path should be UTF-8"),
        )
        .replace(
            "/run/buzz-agent",
            run_dir.to_str().expect("temporary path should be UTF-8"),
        );
    fs::write(&script_path, script).expect("external-stop script should be written");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").expect("test PATH should be set")
    );
    let output = Command::new("sh")
        .arg(&script_path)
        .env("PATH", path)
        .env_remove("GREP_OPTIONS")
        .output()
        .expect("external-stop should execute");
    assert!(
        output.status.success(),
        "external-stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!run_dir.join("launch-authorized").exists());
    assert_eq!(
        fs::read_to_string(var_dir.join("stop-intent")).expect("external intent should exist"),
        "external\n"
    );
    assert!(fs::read_to_string(var_dir.join("state.json"))
        .expect("external state should exist")
        .contains("\"stop_intent\":\"external\""));
    fs::remove_dir_all(root).expect("asset test root should be removed");
}

#[test]
fn poststop_cleans_marker_temp_when_mv_fails() {
    let root = asset_test_root("poststop-mv-failure");
    let var_dir = root.join("var/lib/buzz-agent");
    let bin_dir = root.join("bin");
    let script_path = root.join("poststop.sh");
    fs::create_dir_all(&var_dir).expect("state directory should be created");
    fs::create_dir_all(&bin_dir).expect("fake bin directory should be created");
    fs::write(
        var_dir.join("state.json"),
        "{\"launch_armed\":true,\"startup\":\"armed\",\"stop_intent\":\"none\"}",
    )
    .expect("state marker should be written");
    install_executable(&bin_dir.join("mv"), "#!/bin/sh\nexit 73\n");
    let script = EMBEDDED_POSTSTOP.replace(
        "/var/lib/buzz-agent",
        var_dir.to_str().expect("temporary path should be UTF-8"),
    );
    fs::write(&script_path, script).expect("poststop script should be written");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").expect("test PATH should be set")
    );
    let output = Command::new("sh")
        .arg(&script_path)
        .env("PATH", path)
        .env_remove("GREP_OPTIONS")
        .output()
        .expect("poststop should execute");
    assert_eq!(output.status.code(), Some(73));
    assert_no_marker_temps(&var_dir, "poststop");
    fs::remove_dir_all(root).expect("asset test root should be removed");
}

fn run_poststop_case(label: &str, intent: Option<&str>, state: &str, should_stop: bool) {
    let root = asset_test_root(label);
    let var_dir = root.join("var/lib/buzz-agent");
    let bin_dir = root.join("bin");
    let script_path = root.join("poststop.sh");
    let log_path = root.join("box.log");
    fs::create_dir_all(&var_dir).expect("marker directory should be created");
    fs::write(var_dir.join("state.json"), state).expect("state marker should be written");
    if let Some(intent) = intent {
        fs::write(var_dir.join("stop-intent"), intent).expect("intent marker should be written");
    }
    install_fake_box(&bin_dir, &log_path);
    let script = EMBEDDED_POSTSTOP.replace(
        "/var/lib/buzz-agent",
        var_dir.to_str().expect("temporary path should be UTF-8"),
    );
    fs::write(&script_path, script).expect("poststop script should be written");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").expect("test PATH should be set")
    );
    let output = Command::new("sh")
        .arg(&script_path)
        .env("PATH", path)
        .env("BOX_LOG", &log_path)
        .output()
        .expect("poststop should execute");
    assert!(
        output.status.success(),
        "poststop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        log_path.exists(),
        should_stop,
        "unexpected self-stop for {label}"
    );
    fs::remove_dir_all(root).expect("asset test root should be removed");
}

#[test]
fn poststop_obeys_armed_external_and_refusal_matrix() {
    run_poststop_case(
        "armed-crash",
        None,
        "{\"launch_armed\":true,\"startup\":\"armed\",\"stop_intent\":\"none\"}",
        true,
    );
    run_poststop_case(
        "armed-self",
        Some("self"),
        "{\"launch_armed\":true,\"stop_intent\":\"self\"}",
        true,
    );
    run_poststop_case(
        "armed-external",
        Some("external"),
        "{\"launch_armed\":true,\"stop_intent\":\"external\"}",
        false,
    );
    run_poststop_case(
        "not-armed",
        Some("refused-not-armed"),
        "{\"launch_armed\":false,\"startup\":\"refused-not-armed\",\"stop_intent\":\"refused-not-armed\"}",
        false,
    );
    run_poststop_case(
        "refused-external",
        Some("refused-external"),
        "{\"launch_armed\":false,\"startup\":\"refused-external\",\"stop_intent\":\"external\"}",
        false,
    );
}

#[test]
fn supervisor_refusal_is_dedicated_and_cleans_pending_env() {
    for (label, prior_intent) in [
        ("none", None),
        ("self", Some("self")),
        ("external", Some("external")),
    ] {
        let root = asset_test_root(label);
        let var_dir = root.join("var/lib/buzz-agent");
        let run_dir = root.join("run/buzz-agent");
        let libexec_dir = root.join("usr/local/libexec");
        let script_path = root.join("supervise.sh");
        fs::create_dir_all(&var_dir).expect("state directory should be created");
        fs::create_dir_all(&run_dir).expect("run directory should be created");
        fs::create_dir_all(&libexec_dir).expect("libexec directory should be created");
        fs::write(run_dir.join("invocation"), "nonce-1\n").expect("invocation should be written");
        fs::write(
            var_dir.join("image.ref"),
            "registry.example/buzz@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .expect("image marker should be written");
        fs::write(run_dir.join("env.pending"), "{}\n").expect("pending env should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                run_dir.join("env.pending"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("pending env should be secured");
        }
        if let Some(intent) = prior_intent {
            fs::write(var_dir.join("stop-intent"), intent).expect("prior intent should be written");
        }
        let script = EMBEDDED_SUPERVISOR
            .replace(
                "/var/lib/buzz-agent",
                var_dir.to_str().expect("temporary path should be UTF-8"),
            )
            .replace(
                "/run/buzz-agent",
                run_dir.to_str().expect("temporary path should be UTF-8"),
            )
            .replace(
                "/usr/local/libexec",
                libexec_dir
                    .to_str()
                    .expect("temporary path should be UTF-8"),
            );
        fs::write(&script_path, script).expect("supervisor script should be written");
        let output = Command::new("sh")
            .arg(&script_path)
            .output()
            .expect("supervisor should execute");
        assert_eq!(
            output.status.code(),
            Some(67),
            "unexpected refusal status for {label}"
        );
        assert!(
            !run_dir.join("env.pending").exists(),
            "pending env leaked on {label} refusal"
        );
        assert_eq!(
            fs::read_to_string(var_dir.join("stop-intent")).expect("refusal intent should exist"),
            "refused-not-armed\n"
        );
        assert!(fs::read_to_string(var_dir.join("state.json"))
            .expect("refusal state should exist")
            .contains("refused-not-armed"));
        fs::remove_dir_all(root).expect("asset test root should be removed");
    }
}

#[test]
fn task_c_redactor_covers_values_urls_and_token_shapes() {
    let redactor = Redactor::from_values([
        "short".to_string(),
        "long-secret-value".to_string(),
        "https://user:password@example.invalid/path".to_string(),
    ]);
    let output = redactor.redact(
        "long-secret-value short https://user:password@example.invalid/path \
         nsec1abcdef sprt_tok_secret ghp_abcdef gho_abcdef ghu_abcdef \
         ghs_abcdef ghr_abcdef github_pat_abcdef",
    );
    assert!(!output.contains("long-secret-value"));
    assert!(!output.contains("short"));
    assert!(!output.contains("user:password"));
    for token in [
        "nsec1abcdef",
        "sprt_tok_secret",
        "ghp_abcdef",
        "gho_abcdef",
        "ghu_abcdef",
        "ghs_abcdef",
        "ghr_abcdef",
        "github_pat_abcdef",
    ] {
        assert!(!output.contains(token), "token leaked: {token}");
    }
}

#[test]
fn task_c_assets_are_shell_safe_and_unit_has_required_supervision_policy() {
    for script in [
        EMBEDDED_SUPERVISOR,
        EMBEDDED_ENTRYPOINT,
        EMBEDDED_EXTERNAL_STOP,
        EMBEDDED_POSTSTOP,
    ] {
        assert!(!script.contains("source"));
        assert!(!script.contains("eval"));
        assert!(!script.contains("--env-file"));
        assert!(script.starts_with("#!"));

        let mut child = Command::new("sh")
            .args(["-n", "-s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("sh should be available for asset syntax validation");
        child
            .stdin
            .as_mut()
            .expect("sh stdin should be available")
            .write_all(script.as_bytes())
            .expect("asset should be written to sh stdin");
        let output = child
            .wait_with_output()
            .expect("sh syntax process should finish");
        assert!(
            output.status.success(),
            "asset failed sh -n: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for required in [
        "Restart=no",
        "KillMode=process",
        "KillSignal=SIGTERM",
        "TimeoutStopSec=120s",
        "SendSIGKILL=yes",
        "NoNewPrivileges=yes",
        "UMask=0077",
        "ExecStart=/usr/local/libexec/buzz-box-supervise",
        "ExecStop=/usr/local/libexec/buzz-box-external-stop",
        "ExecStopPost=/usr/local/libexec/buzz-box-poststop",
    ] {
        assert!(EMBEDDED_UNIT.contains(required), "unit missing {required}");
    }
    for required in [
        "docker stop --time=110",
        "launch-authorized",
        "refused-not-armed",
        "launch_armed",
        "dst=/run/buzz-agent/env.pending,ro",
        "dst=/run/buzz-agent/env-consumed,rw",
        "box stop self",
        "launch-handoff.lock",
        "handoff_owner_path",
        "handoff_lock_max_attempts",
        "kill -0",
        "linearization point",
        "launch-winning process can never be created",
    ] {
        assert!(
            EMBEDDED_SUPERVISOR.contains(required),
            "supervisor missing {required}"
        );
    }
    assert!(EMBEDDED_ENTRYPOINT.contains("/run/buzz-agent/env-consumed"));
    assert!(!EMBEDDED_ENTRYPOINT.contains("rm -f -- \"$env_file\""));
    assert!(EMBEDDED_SUPERVISOR.contains("while :; do"));
    assert!(EMBEDDED_SUPERVISOR.contains("mv -f"));
    assert!(EMBEDDED_EXTERNAL_STOP.contains("mv -f"));
    assert!(EMBEDDED_EXTERNAL_STOP.contains("launch_authorized_path"));
    assert!(EMBEDDED_EXTERNAL_STOP.contains("rm -f -- \"$launch_authorized_path\""));
    for required in [
        "launch-handoff.lock",
        "handoff_owner_path",
        "handoff_lock_max_attempts",
        "kill -0",
        "short-lived lock",
    ] {
        assert!(
            EMBEDDED_EXTERNAL_STOP.contains(required),
            "external-stop missing {required}"
        );
    }
    assert!(EMBEDDED_POSTSTOP.contains("mv -f"));
    assert!(EMBEDDED_POSTSTOP.contains("refused-external"));
    assert!(!EMBEDDED_UNIT.contains("Environment="));
}
