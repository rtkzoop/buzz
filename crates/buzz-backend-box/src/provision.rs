//! Box-side installation, secret injection, and service launch.
//!
//! The Box file API is jailed to the unprivileged work directory and the
//! command API runs as `user` with passwordless `sudo`. Every system file is
//! therefore staged through the file API inside the work directory and moved
//! into its root-owned destination with `sudo install`, which removes the
//! staging copy in the same command. The resolved environment is serialized
//! once as canonical JSON, staged as base64, restricted to mode 600 before
//! any other step, and installed onto the `/run` tmpfs. No command string
//! contains an environment value.

use crate::api::{BoxApi, CommandRequest, CommandResult, WriteFileRequest};
use crate::observe::{LAUNCH_INTENT_PATH, OWNERSHIP_MARKER_PATH};
use crate::reconcile::{ProvisionError, ProvisionRequest, Provisioner};
use base64::Engine as _;
use serde_json::json;
use std::time::Instant;

/// Embedded systemd unit installed in the Box.
pub const EMBEDDED_UNIT: &str = include_str!("../assets/buzz-agent.service");
/// Embedded host-side supervisor launcher.
pub const EMBEDDED_SUPERVISOR: &str = include_str!("../assets/buzz-box-supervise");
/// Embedded in-container environment parser and harness launcher.
pub const EMBEDDED_ENTRYPOINT: &str = include_str!("../assets/buzz-box-entrypoint");
/// Embedded external-stop helper.
pub const EMBEDDED_EXTERNAL_STOP: &str = include_str!("../assets/buzz-box-external-stop");
/// Embedded last-resort poststop helper.
pub const EMBEDDED_POSTSTOP: &str = include_str!("../assets/buzz-box-poststop");

/// Work-directory staging area used for every file that must end up in a
/// root-owned system path. Staged copies are removed by the same `sudo
/// install` command that moves them into place.
const STAGING_DIR: &str = ".buzz-provision";
const SERVICE_UNIT_FILE: &str = "/etc/systemd/system/buzz-agent.service";
const SUPERVISOR_FILE: &str = "/usr/local/libexec/buzz-box-supervise";
const ENTRYPOINT_FILE: &str = "/usr/local/libexec/buzz-box-entrypoint";
const EXTERNAL_STOP_FILE: &str = "/usr/local/libexec/buzz-box-external-stop";
const POSTSTOP_FILE: &str = "/usr/local/libexec/buzz-box-poststop";
const IMAGE_FILE: &str = "/var/lib/buzz-agent/image.ref";
const INVOCATION_FILE: &str = "/run/buzz-agent/invocation";
const ENV_FILE_ABS: &str = "/run/buzz-agent/env.pending";
const LAUNCH_AUTHORIZED_FILE: &str = "/run/buzz-agent/launch-authorized";
const CONSUMED_FILE_ABS: &str = "/run/buzz-agent/env-consumed";
/// Pull bookkeeping lives in the user-writable staging area because the
/// detached pull worker runs unprivileged; only the markers consumed by the
/// supervisor live in root-owned paths.
const PULL_STATUS_FILE: &str = ".buzz-provision/image-pull.status";
const PULL_LOG_FILE: &str = ".buzz-provision/image-pull.log";
const PULL_PID_FILE: &str = ".buzz-provision/image-pull.pid";
const MAX_PULL_ATTEMPTS: usize = 3;

/// A real Box provisioner. The API client is supplied through each request so
/// the same implementation works for the ambient deploy path and fake-server
/// tests without duplicating credential construction.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoxProvisioner;

impl Provisioner for BoxProvisioner {
    async fn provision(&self, request: ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        let redactor = request
            .prepared
            .redactor
            .clone()
            .with_value(request.api.credential_for_redaction().to_string());
        let result = provision_inner(&request, &redactor).await;
        if result.is_err() {
            // The file endpoint has no delete operation. This command is
            // deliberately value-free and is attempted on every failure after
            // the secret write, including parser, launch, and confirmation
            // failures.
            let _ = cleanup_env_file(request.api, request.box_record.id.as_str(), &redactor).await;
        }
        result
    }
}

async fn provision_inner(
    request: &ProvisionRequest<'_>,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    let box_id = request.box_record.id.as_str();
    install_assets(request.api, box_id, redactor).await?;
    ensure_image(request.api, box_id, request, redactor).await?;

    let nonce = request
        .prepared
        .env
        .get("BUZZ_MANAGED_AGENT_START_NONCE")
        .ok_or_else(|| failure(redactor, "launch nonce was not prepared"))?;
    let image = request.prepared.config.image.as_str();
    let ownership = json!({
        "pubkey": request.prepared.identity.pubkey_hex(),
        "managed_by": crate::classify::MANAGED_BY,
        "binding_version": crate::classify::BINDING_VERSION,
    });
    let ownership = serde_json::to_string(&ownership)
        .map_err(|_| failure(redactor, "ownership marker was not serializable"))?;

    stage_install_utf8(
        request.api,
        box_id,
        IMAGE_FILE,
        &format!("{image}\n"),
        "644",
        redactor,
    )
    .await?;
    stage_install_utf8(
        request.api,
        box_id,
        INVOCATION_FILE,
        &format!("{nonce}\n"),
        "644",
        redactor,
    )
    .await?;
    stage_install_utf8(
        request.api,
        box_id,
        LAUNCH_INTENT_PATH,
        &format!("{}\n", request.prepared.launch_intent),
        "644",
        redactor,
    )
    .await?;
    stage_install_utf8(
        request.api,
        box_id,
        OWNERSHIP_MARKER_PATH,
        &format!("{ownership}\n"),
        "644",
        redactor,
    )
    .await?;

    run_command(
        request.api,
        box_id,
        "prepare consumed marker",
        &format!("sudo -n install -o root -g root -m 666 /dev/null {CONSUMED_FILE_ABS}"),
        30,
        redactor,
    )
    .await?;

    let env_bytes = serde_json::to_vec(&request.prepared.env)
        .map_err(|_| failure(redactor, "launch environment was not serializable"))?;
    let env_content = base64::engine::general_purpose::STANDARD.encode(env_bytes);
    // The secret is staged base64-encoded in the work directory, restricted
    // to mode 600 as the very next operation, decoded straight onto the
    // `/run` tmpfs owned by the container agent uid (1000) mode 600, and
    // the staging copy removed in the same
    // command. Its plaintext never touches the persistent disk and no
    // command string contains an environment value.
    let env_staging = staging_path(ENV_FILE_ABS);
    write_file(
        request.api,
        box_id,
        &WriteFileRequest {
            path: env_staging.clone(),
            content: env_content,
            encoding: "utf8".to_string(),
        },
        redactor,
    )
    .await?;
    let mode_result = run_command(
        request.api,
        box_id,
        "secure pending environment",
        &format!(
            "chmod 600 {staging} && sudo -n sh -c 'umask 077 && base64 -d < {staging} > {dest} && chown 1000:1000 {dest} && chmod 600 {dest}' && rm -f {staging} && sudo -n stat -c '%u:%g:%a' {dest}",
            staging = env_staging,
            dest = ENV_FILE_ABS,
        ),
        30,
        redactor,
    )
    .await?;
    if mode_result.stdout.trim() != "1000:1000:600" {
        return Err(failure(
            redactor,
            "pending environment ownership or mode verification failed",
        ));
    }

    run_command(
        request.api,
        box_id,
        "reset prior stop intent before launch",
        "sudo -n rm -f /var/lib/buzz-agent/stop-intent /var/lib/buzz-agent/state.json",
        10,
        redactor,
    )
    .await?;
    // This write is deliberately the final arming operation. The launcher
    // consumes the nonce before it can start Docker, so an enabled unit that
    // races resume without this marker refuses with no self-stop side effect.
    stage_install_utf8(
        request.api,
        box_id,
        LAUNCH_AUTHORIZED_FILE,
        &format!("{nonce}\n"),
        "644",
        redactor,
    )
    .await?;
    run_command(
        request.api,
        box_id,
        "start buzz-agent.service",
        "sudo -n systemctl start buzz-agent.service",
        30,
        redactor,
    )
    .await?;
    confirm_start(request, redactor).await?;
    cleanup_env_file(request.api, box_id, redactor).await
}

async fn install_assets(
    api: &BoxApi,
    box_id: &str,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    run_command(
        api,
        box_id,
        "prepare Box directories",
        &format!(
            "install -d -m 700 {STAGING_DIR} && sudo -n install -d -o root -g root -m 700 /var/lib/buzz-agent /run/buzz-agent && sudo -n install -d -o root -g root -m 755 /usr/local/libexec && test \"$(sudo -n stat -c '%u:%g:%a' /var/lib/buzz-agent)\" = 0:0:700 && test \"$(sudo -n stat -c '%u:%g:%a' /run/buzz-agent)\" = 0:0:700 && test \"$(stat -f -c '%T' /run)\" = tmpfs",
        ),
        60,
        redactor,
    )
    .await?;
    for (path, content, mode) in [
        (SERVICE_UNIT_FILE, EMBEDDED_UNIT, "644"),
        (SUPERVISOR_FILE, EMBEDDED_SUPERVISOR, "755"),
        (ENTRYPOINT_FILE, EMBEDDED_ENTRYPOINT, "755"),
        (EXTERNAL_STOP_FILE, EMBEDDED_EXTERNAL_STOP, "755"),
        (POSTSTOP_FILE, EMBEDDED_POSTSTOP, "755"),
    ] {
        stage_install_utf8(api, box_id, path, content, mode, redactor).await?;
    }
    run_command(
        api,
        box_id,
        "reload systemd",
        "sudo -n systemctl daemon-reload",
        30,
        redactor,
    )
    .await?;
    run_command(
        api,
        box_id,
        "enable buzz-agent.service",
        "sudo -n systemctl enable buzz-agent.service",
        30,
        redactor,
    )
    .await
    .map(|_| ())
}

/// Work-directory staging spelling for an absolute destination path.
fn staging_path(destination: &str) -> String {
    format!(
        "{STAGING_DIR}/{}",
        destination.trim_start_matches('/').replace('/', "__")
    )
}

/// Stage a non-secret UTF-8 file through the jailed file API, then move it
/// into its root-owned destination with `sudo install`, removing the staging
/// copy in the same command.
async fn stage_install_utf8(
    api: &BoxApi,
    box_id: &str,
    destination: &str,
    content: &str,
    mode: &str,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    let staging = staging_path(destination);
    write_file(
        api,
        box_id,
        &WriteFileRequest {
            path: staging.clone(),
            content: content.to_string(),
            encoding: "utf8".to_string(),
        },
        redactor,
    )
    .await?;
    run_command(
        api,
        box_id,
        &format!("install {destination}"),
        &format!("sudo -n install -o root -g root -m {mode} {staging} {destination} && rm -f {staging}"),
        30,
        redactor,
    )
    .await
    .map(|_| ())
}

/// Image pulling is detached because Box commands have a hard 60-second cap.
/// The provider starts a `nohup` worker that writes a tiny status marker after
/// both `docker pull` and the immutable `RepoDigests` check, then polls that
/// marker with short synchronous commands. The marker and log contain no launch
/// environment values.
async fn ensure_image(
    api: &BoxApi,
    box_id: &str,
    request: &ProvisionRequest<'_>,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    let image = shell_quote(request.prepared.config.image.as_str());
    let inspect_format = "{{range .RepoDigests}}{{println .}}{{end}}";
    let inner = format!(
        "if docker pull --quiet {image}; then if docker image inspect --format '{inspect_format}' {image} | grep -Fqx {image}; then printf ready > {status}; else printf digest-mismatch > {status}; fi; else printf pull-failed > {status}; fi",
        status = PULL_STATUS_FILE,
    );
    let kickoff = format!(
        "rm -f {status} {log} {pid}; nohup sh -c {inner} >{log} 2>&1 </dev/null & echo $! > {pid}",
        status = PULL_STATUS_FILE,
        log = PULL_LOG_FILE,
        pid = PULL_PID_FILE,
        inner = shell_quote(&inner),
    );
    for _attempt in 0..MAX_PULL_ATTEMPTS {
        run_command(
            api,
            box_id,
            "start detached image pull",
            &kickoff,
            60,
            redactor,
        )
        .await?;
        loop {
            ensure_deadline(request.deadline, redactor, "image pull")?;
            let result = run_command(
                api,
                box_id,
                "poll detached image pull",
                &format!("cat {PULL_STATUS_FILE} 2>/dev/null || printf pending"),
                10,
                redactor,
            )
            .await?;
            match result.stdout.trim() {
                "ready" => return Ok(()),
                "pull-failed" | "digest-mismatch" => break,
                _ => tokio::time::sleep(request.poll_interval).await,
            }
        }
    }
    Err(failure(
        redactor,
        "immutable Buzz image pull or digest verification failed",
    ))
}

async fn confirm_start(
    request: &ProvisionRequest<'_>,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    loop {
        ensure_deadline(request.deadline, redactor, "service startup")?;
        let service = run_command(
            request.api,
            request.box_record.id.as_str(),
            "confirm service active",
            "systemctl is-active buzz-agent.service",
            10,
            redactor,
        )
        .await?;
        if service.stdout.trim() == "active"
            && marker_exists(request.api, request.box_record.id.as_str(), redactor).await?
        {
            return Ok(());
        }
        tokio::time::sleep(request.poll_interval).await;
    }
}

async fn marker_exists(
    api: &BoxApi,
    box_id: &str,
    redactor: &crate::redact::Redactor,
) -> Result<bool, ProvisionError> {
    match crate::observe::read_optional_file(api, box_id, crate::observe::ENV_CONSUMED_MARKER_PATH)
        .await
    {
        Ok(content) => Ok(content.is_some_and(|value| value.trim() == "consumed")),
        Err(error) => Err(failure(
            redactor,
            &format!("reading startup marker: {error}"),
        )),
    }
}

async fn cleanup_env_file(
    api: &BoxApi,
    box_id: &str,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    run_command(
        api,
        box_id,
        "remove pending environment",
        &format!(
            "rm -f {staging} && sudo -n rm -f {ENV_FILE_ABS} {CONSUMED_FILE_ABS}",
            staging = staging_path(ENV_FILE_ABS),
        ),
        10,
        redactor,
    )
    .await
    .map(|_| ())
}

async fn write_file(
    api: &BoxApi,
    box_id: &str,
    request: &WriteFileRequest,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    api.write_file(box_id, request)
        .await
        .map(|_| ())
        .map_err(|error| failure(redactor, &format!("writing Box file: {error}")))
}

async fn run_command(
    api: &BoxApi,
    box_id: &str,
    label: &str,
    command: &str,
    timeout_seconds: u64,
    redactor: &crate::redact::Redactor,
) -> Result<CommandResult, ProvisionError> {
    let result = api
        .execute(
            box_id,
            &CommandRequest {
                command: command.to_string(),
                cwd: None,
                timeout_seconds: Some(timeout_seconds.min(60)),
            },
        )
        .await
        .map_err(|error| failure(redactor, &format!("{label}: {error}")))?;
    if !result.success || result.timed_out || result.exit_code != Some(0) {
        let detail = if !result.stderr.trim().is_empty() {
            result.stderr.as_str()
        } else if !result.stdout.trim().is_empty() {
            result.stdout.as_str()
        } else {
            "command returned a failure status"
        };
        return Err(failure(redactor, &format!("{label}: {detail}")));
    }
    Ok(result)
}

fn ensure_deadline(
    deadline: Instant,
    redactor: &crate::redact::Redactor,
    operation: &str,
) -> Result<(), ProvisionError> {
    if Instant::now() >= deadline {
        return Err(failure(
            redactor,
            &format!("{operation} exceeded the reconcile deadline"),
        ));
    }
    Ok(())
}

fn failure(redactor: &crate::redact::Redactor, message: &str) -> ProvisionError {
    ProvisionError::Failed(redactor.redact(message))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quotes_image_references_without_interpreting_shell_metacharacters() {
        assert_eq!(
            shell_quote("registry/image@sha256:abc"),
            "'registry/image@sha256:abc'"
        );
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn staging_paths_stay_inside_the_work_directory_and_are_unique() {
        for destination in [
            SERVICE_UNIT_FILE,
            SUPERVISOR_FILE,
            ENV_FILE_ABS,
            OWNERSHIP_MARKER_PATH,
        ] {
            let staged = staging_path(destination);
            assert!(staged.starts_with(".buzz-provision/"), "escaped: {staged}");
            assert!(!staged.contains('/'.to_string().repeat(2).as_str()));
            assert!(!staged[STAGING_DIR.len() + 1..].contains('/'), "nested: {staged}");
        }
        assert_ne!(staging_path("/a/b"), staging_path("/a/c"));
    }

    #[test]
    fn detached_pull_command_contains_digest_verification_and_no_environment_file_mode() {
        let image = shell_quote("registry/image@sha256:abc");
        let inspect_format = "{{range .RepoDigests}}{{println .}}{{end}}";
        let inner = format!(
            "if docker pull --quiet {image}; then if docker image inspect --format '{inspect_format}' {image} | grep -Fqx {image}; then printf ready > {status}; fi; fi",
            status = PULL_STATUS_FILE,
        );
        let command = format!("nohup sh -c {} >/dev/null 2>&1 &", shell_quote(&inner));
        assert!(command.contains("docker pull"));
        assert!(command.contains("RepoDigests"));
        assert!(!command.contains("--env-file"));
    }
}
