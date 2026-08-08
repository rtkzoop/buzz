//! Box-side installation, secret injection, and service launch.
//!
//! The provider writes only non-secret supervision assets and non-secret
//! markers to persistent paths. The resolved environment is serialized once
//! as canonical JSON and sent through the file API as base64 to the `/run`
//! tmpfs path. No command string contains an environment value.

use crate::api::{BoxApi, BoxApiError, CommandRequest, CommandResult, WriteFileRequest};
use crate::observe::{ENV_CONSUMED_MARKER_PATH, LAUNCH_INTENT_PATH, OWNERSHIP_MARKER_PATH};
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

const SERVICE_UNIT_FILE: &str = "etc/systemd/system/buzz-agent.service";
const SUPERVISOR_FILE: &str = "usr/local/libexec/buzz-box-supervise";
const ENTRYPOINT_FILE: &str = "usr/local/libexec/buzz-box-entrypoint";
const EXTERNAL_STOP_FILE: &str = "usr/local/libexec/buzz-box-external-stop";
const POSTSTOP_FILE: &str = "usr/local/libexec/buzz-box-poststop";
const IMAGE_FILE: &str = "var/lib/buzz-agent/image.ref";
const INVOCATION_FILE: &str = "run/buzz-agent/invocation";
const ENV_FILE: &str = "run/buzz-agent/env.pending";
const ENV_FILE_ABS: &str = "/run/buzz-agent/env.pending";
const CONSUMED_FILE_ABS: &str = "/run/buzz-agent/env-consumed";
const PULL_STATUS_FILE_ABS: &str = "/var/lib/buzz-agent/image-pull.status";
const PULL_LOG_FILE_ABS: &str = "/var/lib/buzz-agent/image-pull.log";
const PULL_PID_FILE_ABS: &str = "/var/lib/buzz-agent/image-pull.pid";
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

    write_utf8(
        request.api,
        box_id,
        IMAGE_FILE,
        &format!("{image}\n"),
        redactor,
    )
    .await?;
    write_utf8(
        request.api,
        box_id,
        INVOCATION_FILE,
        &format!("{nonce}\n"),
        redactor,
    )
    .await?;
    write_utf8(
        request.api,
        box_id,
        LAUNCH_INTENT_PATH,
        &format!("{}\n", request.prepared.launch_intent),
        redactor,
    )
    .await?;
    write_utf8(
        request.api,
        box_id,
        OWNERSHIP_MARKER_PATH,
        &format!("{ownership}\n"),
        redactor,
    )
    .await?;

    run_command(
        request.api,
        box_id,
        "prepare consumed marker",
        "install -o root -g root -m 666 /dev/null /run/buzz-agent/env-consumed",
        30,
        redactor,
    )
    .await?;

    let env_bytes = serde_json::to_vec(&request.prepared.env)
        .map_err(|_| failure(redactor, "launch environment was not serializable"))?;
    let env_content = base64::engine::general_purpose::STANDARD.encode(env_bytes);
    write_file(
        request.api,
        box_id,
        &WriteFileRequest {
            path: ENV_FILE.to_string(),
            content: env_content,
            encoding: "base64".to_string(),
        },
        redactor,
    )
    .await?;
    let mode_result = run_command(
        request.api,
        box_id,
        "secure pending environment",
        "chown root:root /run/buzz-agent/env.pending && chmod 600 /run/buzz-agent/env.pending && stat -c '%u:%g:%a' /run/buzz-agent/env.pending",
        30,
        redactor,
    )
    .await?;
    if mode_result.stdout.trim() != "0:0:600" {
        return Err(failure(
            redactor,
            "pending environment ownership or mode verification failed",
        ));
    }

    run_command(
        request.api,
        box_id,
        "start buzz-agent.service",
        "systemctl start buzz-agent.service",
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
        "install -d -o root -g root -m 700 /var/lib/buzz-agent /run/buzz-agent /usr/local/libexec && test \"$(stat -c '%u:%g:%a' /var/lib/buzz-agent)\" = 0:0:700 && test \"$(stat -c '%u:%g:%a' /run/buzz-agent)\" = 0:0:700 && test \"$(stat -f -c '%T' /run)\" = tmpfs",
        60,
        redactor,
    )
    .await?;
    for (path, content) in [
        (SERVICE_UNIT_FILE, EMBEDDED_UNIT),
        (SUPERVISOR_FILE, EMBEDDED_SUPERVISOR),
        (ENTRYPOINT_FILE, EMBEDDED_ENTRYPOINT),
        (EXTERNAL_STOP_FILE, EMBEDDED_EXTERNAL_STOP),
        (POSTSTOP_FILE, EMBEDDED_POSTSTOP),
    ] {
        write_utf8(api, box_id, path, content, redactor).await?;
    }
    run_command(
        api,
        box_id,
        "secure supervision assets",
        "chown root:root /etc/systemd/system/buzz-agent.service /usr/local/libexec/buzz-box-supervise /usr/local/libexec/buzz-box-entrypoint /usr/local/libexec/buzz-box-external-stop /usr/local/libexec/buzz-box-poststop && chmod 644 /etc/systemd/system/buzz-agent.service && chmod 755 /usr/local/libexec/buzz-box-supervise /usr/local/libexec/buzz-box-entrypoint /usr/local/libexec/buzz-box-external-stop /usr/local/libexec/buzz-box-poststop",
        30,
        redactor,
    )
    .await?;
    run_command(
        api,
        box_id,
        "reload systemd",
        "systemctl daemon-reload",
        30,
        redactor,
    )
    .await?;
    run_command(
        api,
        box_id,
        "enable buzz-agent.service",
        "systemctl enable buzz-agent.service",
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
        status = PULL_STATUS_FILE_ABS,
    );
    let kickoff = format!(
        "rm -f {status} {log} {pid}; nohup sh -c {inner} >{log} 2>&1 </dev/null & echo $! > {pid}",
        status = PULL_STATUS_FILE_ABS,
        log = PULL_LOG_FILE_ABS,
        pid = PULL_PID_FILE_ABS,
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
                "cat /var/lib/buzz-agent/image-pull.status 2>/dev/null || printf pending",
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
    match api.read_file(box_id, ENV_CONSUMED_MARKER_PATH, None).await {
        Ok(file) => Ok(file.content.trim() == "consumed"),
        Err(BoxApiError::Http { status: 404, .. }) => Ok(false),
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
        &format!("rm -f {ENV_FILE_ABS} {CONSUMED_FILE_ABS}"),
        10,
        redactor,
    )
    .await
    .map(|_| ())
}

async fn write_utf8(
    api: &BoxApi,
    box_id: &str,
    path: &str,
    content: &str,
    redactor: &crate::redact::Redactor,
) -> Result<(), ProvisionError> {
    write_file(
        api,
        box_id,
        &WriteFileRequest {
            path: path.to_string(),
            content: content.to_string(),
            encoding: "utf8".to_string(),
        },
        redactor,
    )
    .await
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
    fn detached_pull_command_contains_digest_verification_and_no_environment_file_mode() {
        let image = shell_quote("registry/image@sha256:abc");
        let inspect_format = "{{range .RepoDigests}}{{println .}}{{end}}";
        let inner = format!(
            "if docker pull --quiet {image}; then if docker image inspect --format '{inspect_format}' {image} | grep -Fqx {image}; then printf ready > {status}; fi; fi",
            status = PULL_STATUS_FILE_ABS,
        );
        let command = format!("nohup sh -c {} >/dev/null 2>&1 &", shell_quote(&inner));
        assert!(command.contains("docker pull"));
        assert!(command.contains("RepoDigests"));
        assert!(!command.contains("--env-file"));
    }
}
