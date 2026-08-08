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
/// Ordered deployment reconciliation.
pub mod reconcile;
/// Stdin/stdout provider protocol types.
pub mod wire;
