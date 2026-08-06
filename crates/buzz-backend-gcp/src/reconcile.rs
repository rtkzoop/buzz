//! The deploy state machine (spec §Deploy Reconciliation, I4).
//!
//! `deploy` is not "create": the desktop issues it on every Start and tracks
//! no substrate state, so the only safe shape is a strict no-op on a live
//! instance and every destructive write fenced to the observation that
//! authorized it. Task 12 fills that in; this skeleton exists so the pure
//! phase — identity derivation — is already in its final position.

use crate::config::ProviderConfig;
use buzz_backend_core::identity::AgentIdentity;
use buzz_backend_core::wire::AgentPayload;

/// Run one deploy to a terminal outcome.
pub fn deploy(cfg: &ProviderConfig, agent: &AgentPayload) -> Result<String, String> {
    // Step 0: identity from the nsec, before any mutation and before any
    // transport exists — so every refusal reachable without GCP stays
    // reachable without GCP.
    let identity = AgentIdentity::from_nsec(&agent.private_key_nsec)?;
    let _ = (cfg, identity);
    Err("deploy is not implemented yet".to_string())
}
