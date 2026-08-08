//! ASCII Box backend provider for Buzz remote agents.
//!
//! The binary consumes one JSON request from stdin and emits one JSON response
//! on stdout. Operational failures are in-band and still exit successfully.

use buzz_backend_box::provision::BoxProvisioner;
use buzz_backend_box::reconcile;
use buzz_backend_box::wire::{self, Request, Response};
use std::io::Read;

#[tokio::main]
async fn main() {
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("could not read the request from stdin: {error}");
        std::process::exit(1);
    }

    let response = respond(&input).await;
    let serialized = match serde_json::to_string(&response) {
        Ok(value) => value,
        Err(_) => r#"{"ok":false,"error":"could not serialize provider response"}"#.to_string(),
    };
    println!("{serialized}");
}

/// Produce the single protocol response for an input request.
async fn respond(input: &str) -> Response {
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
        Request::Deploy(request) => match reconcile::deploy(&request, &BoxProvisioner).await {
            Ok(agent_id) => Response::Deploy(wire::DeployResponse { ok: true, agent_id }),
            Err(error) => Response::error(error.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn info_returns_box_protocol_metadata() {
        let value = serde_json::to_value(respond(r#"{"op":"info"}"#).await)
            .expect("info response should serialize");
        assert_eq!(value["ok"], true);
        assert_eq!(value["name"], "box");
        assert_eq!(value["protocol_version"], 1);
        assert!(value["config_schema"].is_object());
    }

    #[tokio::test]
    async fn deploy_is_an_in_band_error() {
        let response = respond(
            r#"{"op":"deploy","agent":{"relay_url":"wss://relay","private_key_nsec":"nsec1test"}}"#,
        )
        .await;
        let value = serde_json::to_value(response).expect("error response should serialize");
        assert_eq!(value["ok"], false);
        assert!(value["error"]
            .as_str()
            .is_some_and(|error| error.contains("private_key_nsec")
                || error.contains("invalid Box deploy request")));
    }

    #[tokio::test]
    async fn malformed_requests_are_in_band_errors() {
        let value =
            serde_json::to_value(respond("not json").await).expect("error should serialize");
        assert_eq!(value["ok"], false);
        assert!(value["error"]
            .as_str()
            .is_some_and(|error| error.contains("valid JSON")));
    }
}
