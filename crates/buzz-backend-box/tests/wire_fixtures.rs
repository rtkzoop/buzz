//! Golden wire fixtures for the Box provider process contract.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provider-wire")
}

fn run(request: &str) -> (String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_buzz-backend-box"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("could not run the provider binary");
    child
        .stdin
        .take()
        .expect("no stdin")
        .write_all(request.as_bytes())
        .expect("could not write the request");
    let output = child.wait_with_output().expect("provider did not exit");
    (
        String::from_utf8(output.stdout).expect("stdout was not UTF-8"),
        output.status.code().unwrap_or(-1),
    )
}

fn read(name: &str) -> String {
    std::fs::read_to_string(fixtures().join(name))
        .unwrap_or_else(|error| panic!("could not read fixture {name}: {error}"))
}

#[test]
fn responses_match_info_and_deploy_fixtures() {
    for case in ["info", "deploy-not-implemented"] {
        let (stdout, code) = run(&read(&format!("{case}.request.json")));
        assert_eq!(code, 0, "{case}: response-producing invocation must exit 0");
        assert_eq!(
            stdout.matches('\n').count(),
            1,
            "{case}: expected exactly one newline-terminated response: {stdout:?}"
        );

        let actual: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{case}: {error}"));
        let expected: serde_json::Value =
            serde_json::from_str(&read(&format!("{case}.response.json")))
                .expect("fixture response must be valid JSON");
        assert_eq!(actual, expected, "{case}: response drifted from fixture");
    }
}
