//! The stdin/stdout JSON protocol for the Box provider.
//!
//! Keep this module structurally aligned with
//! `buzz-backend-kubernetes/src/wire.rs`; the two providers intentionally
//! accept the same forward-compatible Desktop payload.

// keep in sync with buzz-backend-kubernetes/src/wire.rs

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The wire-contract version this provider speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// A provider operation request.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    /// Return provider metadata and configuration schema.
    Info,
    /// Request deployment of one agent.
    Deploy(Box<DeployRequest>),
}

/// Deployment request payload.
#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    /// Agent identity and launch data.
    pub agent: AgentPayload,
    /// Provider-specific configuration, defaulting to JSON null when omitted.
    #[serde(default)]
    pub provider_config: serde_json::Value,
}

/// The Desktop agent payload consumed by providers.
#[derive(Debug, Deserialize)]
pub struct AgentPayload {
    /// Relay WebSocket URL.
    pub relay_url: String,
    /// Bech32 nsec used to derive the agent identity.
    pub private_key_nsec: String,
    /// Optional authentication tag.
    #[serde(default)]
    pub auth_tag: Option<String>,
    /// Respond-to policy.
    #[serde(default)]
    pub respond_to: Option<String>,
    /// Optional respond-to allowlist.
    #[serde(default)]
    pub respond_to_allowlist: Option<Vec<String>>,
    /// Legacy merged user environment.
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    /// Resolved Desktop launch block.
    #[serde(default)]
    pub launch: Option<LaunchBlock>,
}

/// Resolved launch data from Desktop.
#[derive(Debug, Default, Deserialize)]
pub struct LaunchBlock {
    /// Command name resolved against the runtime image PATH.
    #[serde(default)]
    pub command: Option<String>,
    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Resolved user environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Overridable policy defaults.
    #[serde(default)]
    pub policy_env: BTreeMap<String, String>,
    /// Resolved workspace owner public key.
    #[serde(default)]
    pub owner_pubkey: Option<String>,
}

/// A flat provider response envelope.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    /// Successful provider metadata.
    Info(InfoResponse),
    /// Successful deployment response.
    Deploy(DeployResponse),
    /// In-band provider failure.
    Error(ErrorResponse),
}

/// Successful `info` response.
#[derive(Debug, Serialize)]
pub struct InfoResponse {
    /// Always true for this response shape.
    pub ok: bool,
    /// Provider name.
    pub name: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Wire protocol version.
    pub protocol_version: u32,
    /// Human-readable provider description.
    pub description: &'static str,
    /// Non-secret provider configuration schema.
    pub config_schema: serde_json::Value,
}

/// Successful `deploy` response.
#[derive(Debug, Serialize)]
pub struct DeployResponse {
    /// Always true for this response shape.
    pub ok: bool,
    /// Stable provider-specific agent handle.
    pub agent_id: String,
}

/// In-band failure response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Always false for this response shape.
    pub ok: bool,
    /// Human-readable error message.
    pub error: String,
}

impl Response {
    /// Construct an in-band failure response.
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error(ErrorResponse {
            ok: false,
            error: message.into(),
        })
    }

    /// Construct the provider self-description.
    pub fn info() -> Self {
        Self::Info(InfoResponse {
            ok: true,
            name: "box",
            version: env!("CARGO_PKG_VERSION"),
            protocol_version: PROTOCOL_VERSION,
            description: "Deploys Buzz agents to ASCII Box VMs",
            config_schema: crate::config::config_schema(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_info_with_optional_request_id() {
        let request: Request = serde_json::from_str(r#"{"op":"info","request_id":"req-1"}"#)
            .expect("info request should parse");
        assert!(matches!(request, Request::Info));
    }

    #[test]
    fn accepts_forward_compatible_agent_fields() {
        let request: Request = serde_json::from_str(
            r#"{
                "op":"deploy",
                "agent": {
                    "name":"demo",
                    "relay_url":"wss://relay",
                    "private_key_nsec":"nsec1demo",
                    "model":"model",
                    "provider":"openai",
                    "agent_command":"buzz-acp",
                    "agent_args":[],
                    "launch":{"env":{"A":"B"}}
                }
            }"#,
        )
        .expect("forward-compatible deploy payload should parse");
        assert!(matches!(request, Request::Deploy(_)));
    }

    #[test]
    fn rejects_unknown_operations() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"undeploy"}"#).is_err());
    }
}
