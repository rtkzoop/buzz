//! GCE/systemd backend provider for Buzz remote agents
//! (spec `docs/remote-agents.md`).
//!
//! One process per operation: read exactly one JSON request from stdin, write
//! exactly one JSON response to stdout, exit. The exit code carries exactly
//! one bit — 0 for a response that was produced, 1 for a failure to produce
//! one. Everything a caller needs to distinguish is *inside* the response's
//! `ok` field, because a provider that encoded outcomes in exit codes would
//! have a second, redundant error channel to keep in sync ([L2] item 1).

mod config;

use buzz_backend_core::wire::{Request, Response};
use std::io::Read;

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        // No request means no response contract to honor. The one nonzero path.
        eprintln!("could not read the request from stdin: {e}");
        std::process::exit(1);
    }

    let response = respond(&input);
    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|e| {
            // The response types are plain data; this cannot fail in practice,
            // and a hand-built object is still a conforming response.
            format!(r#"{{"ok":false,"error":"could not serialize a response: {e}"}}"#)
        })
    );
}

/// Produce the single response for one request. Separated from `main` so the
/// whole dispatch is testable without a process.
fn respond(input: &str) -> Response {
    let request: Request = match serde_json::from_str(input) {
        Ok(request) => request,
        Err(e) => return Response::error(format!("request is not valid JSON: {e}")),
    };
    match request {
        Request::Info => Response::info(
            "gcp",
            "Runs agents as systemd units on a GCE instance",
            config::config_schema(),
        ),
        Request::Deploy(_) => Response::error("deploy is not implemented yet"),
    }
}
