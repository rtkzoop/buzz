//! ASCII Box backend provider for Buzz remote agents.
//!
//! The binary consumes one JSON request from stdin and emits one JSON response
//! on stdout. Operational failures are in-band and still exit successfully.

pub mod config;
pub mod image;
pub mod naming;
pub mod wire;

use std::io::Read;
use wire::{Request, Response};

fn main() {
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("could not read the request from stdin: {error}");
        std::process::exit(1);
    }

    let response = respond(&input);
    let serialized = match serde_json::to_string(&response) {
        Ok(value) => value,
        Err(_) => r#"{"ok":false,"error":"could not serialize provider response"}"#.to_string(),
    };
    println!("{serialized}");
}

/// Produce the single protocol response for an input request.
fn respond(input: &str) -> Response {
    let raw: serde_json::Value = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(error) => return Response::error(format!("request is not valid JSON: {error}")),
    };
    let request: Request = match serde_json::from_value(raw) {
        Ok(request) => request,
        Err(error) => return Response::error(format!("could not understand the request: {error}")),
    };

    match request {
        Request::Info => Response::info(),
        Request::Deploy(_) => Response::error("deploy not yet implemented"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_returns_box_protocol_metadata() {
        let value = serde_json::to_value(respond(r#"{"op":"info"}"#))
            .expect("info response should serialize");
        assert_eq!(value["ok"], true);
        assert_eq!(value["name"], "box");
        assert_eq!(value["protocol_version"], 1);
        assert!(value["config_schema"].is_object());
    }

    #[test]
    fn deploy_is_an_in_band_not_implemented_error() {
        let response = respond(
            r#"{"op":"deploy","agent":{"relay_url":"wss://relay","private_key_nsec":"nsec1test"}}"#,
        );
        let value = serde_json::to_value(response).expect("error response should serialize");
        assert_eq!(
            value,
            serde_json::json!({"ok": false, "error": "deploy not yet implemented"})
        );
    }

    #[test]
    fn malformed_requests_are_in_band_errors() {
        let value = serde_json::to_value(respond("not json")).expect("error should serialize");
        assert_eq!(value["ok"], false);
        assert!(value["error"]
            .as_str()
            .is_some_and(|error| error.contains("valid JSON")));
    }
}
