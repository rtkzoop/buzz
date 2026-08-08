use buzz_backend_box::provision::{
    EMBEDDED_ENTRYPOINT, EMBEDDED_EXTERNAL_STOP, EMBEDDED_POSTSTOP, EMBEDDED_SUPERVISOR,
    EMBEDDED_UNIT,
};
use buzz_backend_box::redact::Redactor;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
    assert!(EMBEDDED_POSTSTOP.contains("mv -f"));
    assert!(!EMBEDDED_UNIT.contains("Environment="));
}
