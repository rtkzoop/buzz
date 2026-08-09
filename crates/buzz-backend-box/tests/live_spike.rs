//! Safe command-line contract tests for the live validation spike.
//!
//! These tests intentionally exercise only help, dry-run, and safety-gate paths.
//! They must never pass `--confirm-live`, so no Box API mutation or read occurs.

use std::process::Command;

fn run(args: &[&str], api_key: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_box-live-spike"));
    command.args(args).env_remove("BOX_API_KEY");
    if let Some(api_key) = api_key {
        command.env("BOX_API_KEY", api_key);
    }
    command.output().expect("box-live-spike should start")
}

#[test]
fn help_is_local_and_does_not_require_credentials() {
    let output = run(&["--help"], None);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");
    assert!(stdout.contains("box-live-spike"));
    assert!(stdout.contains("--confirm-live"));
    assert!(stdout.contains("docker-snapshot-resume"));
}

#[test]
fn dry_run_all_is_json_and_lists_mutations_without_credentials() {
    let output = run(&["--dry-run", "all"], None);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("dry-run should be UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("dry-run should be JSON");
    assert_eq!(value["mode"], "dry-run");
    assert_eq!(value["network_io"], false);
    assert!(value["planned_mutations"]
        .as_array()
        .is_some_and(|mutations| !mutations.is_empty()));
    assert!(!stdout.contains("BOX_API_KEY"));
}

#[test]
fn dry_run_does_not_echo_an_inherited_api_key() {
    let secret = "box-live-spike-dry-run-secret";
    let output = run(&["--dry-run", "all"], Some(secret));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("dry-run should be UTF-8");
    assert!(!stdout.contains(secret));
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("dry-run should be JSON");
    assert_eq!(value["network_io"], false);
}

#[test]
fn mutating_group_requires_confirmation_before_network_io() {
    let secret = "box-live-spike-test-secret";
    let output = run(&["all"], Some(secret));
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).expect("gate response should be UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("gate should be JSON");
    assert_eq!(value["status"], "blocked");
    assert_eq!(value["network_io"], false);
    assert!(value["missing"]
        .as_array()
        .is_some_and(|missing| missing.iter().any(|item| item == "--confirm-live")));
    assert!(!stdout.contains(secret));
}

#[test]
fn live_group_requires_ambient_api_key_before_network_io() {
    let output = run(&["--confirm-live", "limits"], None);
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).expect("gate response should be UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("gate should be JSON");
    assert_eq!(value["status"], "blocked");
    assert_eq!(value["network_io"], false);
    assert!(value["missing"]
        .as_array()
        .is_some_and(|missing| missing.iter().any(|item| item == "BOX_API_KEY")));
}

#[test]
fn mutating_group_without_any_gate_reports_both_missing_requirements() {
    let output = run(&["all"], None);
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).expect("gate response should be UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("gate should be JSON");
    assert_eq!(value["network_io"], false);
    let missing = value["missing"]
        .as_array()
        .expect("missing should be an array");
    assert!(missing.iter().any(|item| item == "BOX_API_KEY"));
    assert!(missing.iter().any(|item| item == "--confirm-live"));
}

#[test]
fn usage_errors_have_documented_exit_code_and_json_output() {
    let output = run(&["--not-a-real-option"], None);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).expect("usage response should be UTF-8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("usage should be JSON");
    assert_eq!(value["error_code"], "usage");
    assert_eq!(value["network_io"], false);
}
