//! The stdin/stdout contract, driven through the built binary.

use buzz_backend_core::harness::{fixture, run};
use std::path::{Path, PathBuf};

fn binary() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_buzz-backend-gcp")).to_path_buf()
}

#[test]
fn info_carries_exactly_the_six_contract_fields() {
    let (stdout, code) = run(&binary(), &fixture("info.request.json"));
    assert_eq!(code, 0, "info must exit 0; stdout={stdout}");
    assert_eq!(
        stdout.matches('\n').count(),
        1,
        "expected exactly one line, got {stdout:?}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON object");

    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["name"], serde_json::json!("gcp"));
    assert_eq!(v["protocol_version"], serde_json::json!(1));
    assert!(v["version"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["description"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["config_schema"].is_object());

    // The desktop rejects any seventh field (backend.rs:48-63).
    let mut keys: Vec<&str> = v
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "config_schema",
            "description",
            "name",
            "ok",
            "protocol_version",
            "version"
        ]
    );
}

#[test]
fn the_config_schema_names_no_credential() {
    let (stdout, _) = run(&binary(), &fixture("info.request.json"));
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // I2 / backend.rs:536-566: the desktop refuses any config key whose words
    // include one of these, so a schema advertising one is dead on arrival.
    let forbidden = ["secret", "password", "token", "key", "credential"];
    for name in v["config_schema"]["properties"]
        .as_object()
        .expect("properties")
        .keys()
    {
        let lowered = name.to_ascii_lowercase();
        for word in forbidden {
            assert!(
                !lowered.contains(word),
                "config key {name} looks like a credential"
            );
        }
    }
}

#[test]
fn an_unknown_op_is_an_in_band_error_with_exit_zero() {
    let (stdout, code) = run(&binary(), r#"{"op":"teleport","request_id":"r"}"#);
    assert_eq!(code, 0, "in-band errors still exit 0");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["ok"], serde_json::json!(false));
    assert!(v["error"].as_str().is_some_and(|s| !s.is_empty()));
}

#[test]
fn malformed_input_is_an_in_band_error_with_exit_zero() {
    let (stdout, code) = run(&binary(), "not json at all");
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["ok"], serde_json::json!(false));
    assert!(v["error"]
        .as_str()
        .unwrap_or_default()
        .contains("valid JSON"));
}
