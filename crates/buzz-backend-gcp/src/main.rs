//! GCE/systemd backend provider for Buzz remote agents
//! (spec `docs/remote-agents.md`).
//!
//! One process per operation: read exactly one JSON request from stdin, write
//! exactly one JSON response to stdout, exit. The exit code carries exactly
//! one bit — 0 for a response that was produced, 1 for a failure to produce
//! one. Everything a caller needs to distinguish is *inside* the response's
//! `ok` field, because a provider that encoded outcomes in exit codes would
//! have a second, redundant error channel to keep in sync ([L2] item 1).

mod capacity;
mod config;
mod naming;
mod observe;
mod operator;
mod reconcile;
mod remote;
mod render;
mod secrets;

use buzz_backend_core::wire::{self, Request, Response};
use std::io::Read;

/// The provider a shared-compute agent resolves to. Refused here as the
/// spec's backstop ([L2] item 3, `docs/remote-agents.md:1453-1458`): a mesh
/// agent runs on the relay's compute, so starting a systemd unit for it would
/// create a second, contending consumer of the same agent identity — an I4
/// violation across substrates.
const RELAY_MESH_PROVIDER: &str = "relay-mesh";

fn main() {
    // The desktop invokes this binary with no arguments, so anything on argv
    // is a human running an operator command.
    if std::env::args_os().count() > 1 {
        use clap::Parser;
        if let Err(e) = operator::run(operator::Cli::parse()) {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("could not read the request from stdin: {e}");
        std::process::exit(1);
    }

    let response = respond(&input);
    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|e| {
            format!(r#"{{"ok":false,"error":"could not serialize a response: {e}"}}"#)
        })
    );
}

/// Produce the single response for one request. Separated from `main` so the
/// whole dispatch is testable without a process.
fn respond(input: &str) -> Response {
    // Parsed as raw JSON first: the relay-mesh refusal below MUST see the wire
    // value, and `AgentPayload` deliberately does not carry `provider`.
    let raw: serde_json::Value = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(e) => return Response::error(format!("request is not valid JSON: {e}")),
    };

    if let Some(refusal) = refuse_relay_mesh(&raw) {
        return Response::error(refusal);
    }

    let request: Request = match serde_json::from_value(raw) {
        Ok(request) => request,
        Err(e) => return Response::error(format!("could not understand the request: {e}")),
    };

    match request {
        Request::Info => Response::info(
            "gcp",
            "Runs agents as systemd units on a GCE instance",
            config::config_schema(),
        ),
        Request::Deploy(deploy) => match deploy_agent(&deploy) {
            Ok(agent_id) => Response::deployed(agent_id),
            Err(e) => Response::error(e),
        },
    }
}

/// Refuse a shared-compute agent, reading the **raw wire value**.
///
/// Trimmed before comparing, and deliberately so even though the desktop now
/// trims too. `ensure_remote_provider_supported`
/// (`desktop/src-tauri/src/commands/agents_deploy.rs:93-94`) compares
/// `provider.map(str::trim)`, so a padded value is refused there today — but a
/// backstop that assumes its front layer is correct is not a backstop, and this
/// one exists precisely for the callers that are not the desktop. `non_blank`
/// also preserves surrounding whitespace on a non-blank value, so an untrimmed
/// comparison here would let `" relay-mesh "` through.
fn refuse_relay_mesh(raw: &serde_json::Value) -> Option<String> {
    let provider = raw.get("agent")?.get("provider")?.as_str()?;
    (provider.trim() == RELAY_MESH_PROVIDER).then(|| {
        "deploy refused: this agent is configured for shared compute \
         (relay-mesh), which runs on the relay rather than on a GCE instance. \
         Switch the agent to a local runtime before deploying it to GCE."
            .to_string()
    })
}

/// Run one deploy to a terminal outcome.
///
/// Config parsing happens here; everything after it lives in `reconcile`,
/// which completes its whole pure phase — identity, rendering, refusals —
/// before constructing a transport.
fn deploy_agent(request: &wire::DeployRequest) -> Result<String, String> {
    let cfg = config::ProviderConfig::parse(&request.provider_config)?;
    reconcile::deploy(&cfg, &request.agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_of(response: &Response) -> String {
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["ok"], false, "expected a refusal: {json}");
        json["error"].as_str().unwrap_or_default().to_string()
    }

    /// The exact refusal, so no assertion here can be satisfied by an error
    /// that merely *mentions* `relay-mesh` — "gcloud was not found while
    /// deploying relay-mesh" would pass a `contains` check while proving the
    /// backstop never fired. This is the same sentence the two response
    /// goldens carry, so drift breaks the unit tests and the fixtures together.
    const RELAY_MESH_REFUSAL: &str = "deploy refused: this agent is configured \
        for shared compute (relay-mesh), which runs on the relay rather than on \
        a GCE instance. Switch the agent to a local runtime before deploying it \
        to GCE.";

    /// The spec's backstop for the relay-mesh MUST. The desktop refuses first
    /// (`desktop/src-tauri/src/commands/agents_deploy.rs:93-94`); this is the
    /// layer that owes the obligation.
    #[test]
    fn refuses_a_relay_mesh_agent() {
        let request = r#"{"op":"deploy","agent":{
            "relay_url":"wss://r","private_key_nsec":"nsec1x","provider":"relay-mesh"},
            "provider_config":{}}"#;
        assert_eq!(error_of(&respond(request)), RELAY_MESH_REFUSAL);
    }

    /// Padding must not bypass the backstop, and must not change the answer
    /// either. Reachable by construction: `GlobalConfig.provider` is a bare
    /// `Option<String>` with no trim on write, and `non_blank` rejects
    /// whitespace-only while preserving surrounding whitespace on everything
    /// else.
    #[test]
    fn refuses_a_padded_relay_mesh_agent() {
        let request = r#"{"op":"deploy","agent":{
            "relay_url":"wss://r","private_key_nsec":"nsec1x","provider":"  relay-mesh  "},
            "provider_config":{}}"#;
        assert_eq!(error_of(&respond(request)), RELAY_MESH_REFUSAL);
    }

    /// The refusal must precede deserialization, or it is not the backstop the
    /// spec asks for — `AgentPayload` deliberately does not carry `provider`,
    /// so after `from_value` the evidence is gone. A `relay-mesh` payload that
    /// is *also* malformed for `DeployRequest` must still produce this exact
    /// sentence; if the order ever flips, the error becomes a serde message
    /// and this fails.
    #[test]
    fn the_relay_mesh_refusal_precedes_deserialization() {
        let request = r#"{"op":"deploy","agent":{"provider":"relay-mesh"},
            "provider_config":{}}"#;
        assert_eq!(error_of(&respond(request)), RELAY_MESH_REFUSAL);
    }

    /// A guard that refuses everything passes its own test and ships a
    /// provider that deploys nothing.
    #[test]
    fn does_not_refuse_a_normal_provider() {
        let raw: serde_json::Value =
            serde_json::from_str(r#"{"agent":{"provider":"openai"}}"#).unwrap();
        assert!(refuse_relay_mesh(&raw).is_none());
        // …nor when the field is absent entirely, which is the common case:
        // `AgentPayload` does not carry `provider`.
        let bare: serde_json::Value = serde_json::from_str(r#"{"agent":{}}"#).unwrap();
        assert!(refuse_relay_mesh(&bare).is_none());
    }

    #[test]
    fn malformed_input_is_an_in_band_error() {
        assert!(error_of(&respond("not json")).contains("valid JSON"));
        assert!(error_of(&respond(r#"{"op":"undeploy"}"#)).contains("understand"));
    }
}
