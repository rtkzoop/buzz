use buzz_backend_box::provision::{
    EMBEDDED_ENTRYPOINT, EMBEDDED_EXTERNAL_STOP, EMBEDDED_POSTSTOP, EMBEDDED_SUPERVISOR,
    EMBEDDED_UNIT,
};
use buzz_backend_box::redact::Redactor;
use std::io::Write;
use std::process::{Command, Stdio};

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
    assert!(!EMBEDDED_UNIT.contains("Environment="));
}
