//! Library surface for the ASCII Box backend provider.

/// Typed Box API client.
pub mod api;
/// Pure lifecycle classifier.
pub mod classify;
/// Provider configuration.
pub mod config;
/// Image reference validation.
pub mod image;
/// Deterministic identity and naming.
pub mod naming;
/// Trusted Box observation.
pub mod observe;
/// Box-side installation, secret injection, and service launch.
pub mod provision;
/// Ordered deployment reconciliation.
pub mod reconcile;
/// Provider-local redaction of untrusted output.
pub mod redact;
/// Stdin/stdout provider protocol types.
pub mod wire;
