//! Nsec identity derivation and deterministic Box names.

use nostr::nips::nip19::FromBech32;
use sha2::{Digest, Sha256};

/// Provider marker used for deterministic container names.
pub const CONTAINER_PREFIX: &str = "buzz-agent";

/// An identity derived from the deploy payload's private nsec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pubkey_hex: String,
}

impl AgentIdentity {
    /// Decode an `nsec1...` key and derive its public key, failing closed.
    pub fn from_nsec(nsec: &str) -> Result<Self, String> {
        let secret = nostr::SecretKey::from_bech32(nsec.trim())
            .map_err(|_| "private_key_nsec is not a decodable nsec1 key".to_string())?;
        let keys = nostr::Keys::new(secret);
        Ok(Self {
            pubkey_hex: keys.public_key().to_hex(),
        })
    }

    /// Return the full 64-character public key.
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// Return a deterministic Box subdomain for a validated deployment scope.
    ///
    /// The final `a` is intentional: it keeps the value away from Box's
    /// reserved `-<number>` and `-desktop` suffixes regardless of hash bytes.
    pub fn subdomain(&self, scope: &str) -> String {
        let scope_hash = short_hash(scope.as_bytes());
        let pubkey_hash = short_hash(self.pubkey_hex.as_bytes());
        format!("buzz-{scope_hash}-{pubkey_hash}a")
    }

    /// Return the stable name used for the agent's inner container.
    pub fn container_name(&self) -> String {
        format!("{CONTAINER_PREFIX}-{}", &self.pubkey_hex[..12])
    }
}

fn short_hash(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex::encode(digest)[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::nips::nip19::ToBech32;

    fn identity() -> AgentIdentity {
        let keys = nostr::Keys::generate();
        let nsec = keys
            .secret_key()
            .to_bech32()
            .expect("generated key must encode");
        let identity = AgentIdentity::from_nsec(&nsec).expect("generated nsec must decode");
        assert_eq!(identity.pubkey_hex(), keys.public_key().to_hex());
        identity
    }

    #[test]
    fn invalid_nsec_fails_closed() {
        for value in ["", "nsec1", "not-a-key", "npub1abc"] {
            assert!(
                AgentIdentity::from_nsec(value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn subdomain_is_deterministic_and_box_safe() {
        let identity = identity();
        let first = identity.subdomain("default");
        assert_eq!(first, identity.subdomain("default"));
        assert!((3..=40).contains(&first.len()));
        assert!(first.chars().all(|character| character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '-'));
        assert!(!first.starts_with('-'));
        assert!(!first.ends_with('-'));
        assert!(!first.contains("--"));
        assert!(!first.ends_with("-desktop"));
        assert!(first
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_lowercase()));
    }

    #[test]
    fn scope_changes_the_subdomain() {
        let identity = identity();
        assert_ne!(
            identity.subdomain("default"),
            identity.subdomain("production")
        );
    }

    #[test]
    fn container_name_is_stable_and_safe() {
        let identity = identity();
        assert_eq!(identity.container_name(), identity.container_name());
        assert!(identity.container_name().starts_with("buzz-agent-"));
        assert!(identity
            .container_name()
            .chars()
            .all(|character| character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'));
    }
}
