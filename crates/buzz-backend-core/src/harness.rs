//! Driving a provider binary over a real pipe (spec §Provider Protocol).
//!
//! Not `#[cfg(test)]`: this is consumed by the integration tests of *other*
//! crates, which compile against the normal library. It is nonetheless test
//! support, which is why its failures panic with a diagnostic rather than
//! returning `Result` — a fallible helper would push `unwrap()` into every
//! assertion in every binding's fixture suite, which is the outcome
//! AGENTS.md's no-`unwrap()` rule exists to avoid.
//!
//! Providers are tested through the built binary rather than an in-process
//! call because the contract is `stdin -> one JSON object on stdout -> exit
//! code`, and an in-process test skips the three things that actually break:
//! writing nothing, writing two objects, or signalling through the exit code.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The shared golden **request** directory. Response goldens are per-binding
/// and live in the binding's own `tests/fixtures/provider-wire/`.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/provider-wire")
}

/// Read one shared fixture by file name.
pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures_dir().join(name))
        .unwrap_or_else(|e| panic!("could not read fixture {name}: {e}"))
}

/// Feed one request to a provider binary; return `(stdout, exit code)`.
pub fn run(binary: &Path, request: &str) -> (String, i32) {
    run_with_env(binary, request, &[])
}

/// [`run`], with extra environment variables set on the child.
///
/// The hook exists so a binding can fence its fixture suite away from real
/// infrastructure — the Kubernetes suite points `KUBECONFIG` at a path that
/// cannot exist, so a fixture that accidentally reaches a cluster fails at
/// the intended boundary instead of talking to a developer's live cluster.
pub fn run_with_env(binary: &Path, request: &str, env: &[(&str, &str)]) -> (String, i32) {
    let mut child = Command::new(binary)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("could not run {}: {e}", binary.display()));
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(request.as_bytes())
        .expect("could not write the request");
    let out = child.wait_with_output().expect("provider did not exit");
    (
        String::from_utf8(out.stdout).expect("stdout was not UTF-8"),
        out.status.code().unwrap_or(-1),
    )
}
