//! Identity derivation (spec §Deploy State Machine step 0).
//!
//! The pubkey is decoded from `private_key_nsec` by the provider itself and
//! never taken from a caller-supplied field. Constructing [`AgentIdentity`] is
//! the only way to obtain the derived forms, so a caller-supplied pubkey
//! cannot reach a selector, an object name, or a filesystem path by any route.

use nostr::nips::nip19::FromBech32;

/// An agent identity the provider derived itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pubkey_hex: String,
}

impl AgentIdentity {
    /// Derive from the payload's `private_key_nsec`.
    ///
    /// Accepts bech32 `nsec1…`; a malformed or undecodable key is an
    /// immediate error, before any substrate read or mutation.
    pub fn from_nsec(nsec: &str) -> Result<Self, String> {
        let secret = nostr::SecretKey::from_bech32(nsec.trim())
            .map_err(|_| "private_key_nsec is not a decodable nsec1 key".to_string())?;
        let keys = nostr::Keys::new(secret);
        Ok(Self {
            pubkey_hex: keys.public_key().to_hex(),
        })
    }

    /// Full 64-hex public key — the collision-free identity, and the operand
    /// every destructive fence compares against.
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// First 12 hex chars, for short object names. Collision-*resistant*
    /// only: always pair it with a [`AgentIdentity::pubkey_hex`] check before
    /// acting destructively.
    pub fn short12(&self) -> &str {
        &self.pubkey_hex[..12]
    }

    /// First 32 hex chars (128 bits), for selector keys that cap below 64.
    pub fn short32(&self) -> &str {
        &self.pubkey_hex[..32]
    }
}

/// A fresh generation token: 8 lowercase hex chars from the OS RNG.
///
/// Appears as `BUZZ_MANAGED_AGENT_START_NONCE`, and on substrates with
/// per-generation objects also in their names — so the substrate generation
/// and the harness's lifecycle-frame correlator are one identity.
pub fn new_generation() -> String {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    format!("{n:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated() -> (nostr::Keys, String) {
        use nostr::nips::nip19::ToBech32;
        let keys = nostr::Keys::generate();
        let nsec = keys
            .secret_key()
            .to_bech32()
            .expect("a generated key encodes to bech32");
        (keys, nsec)
    }

    #[test]
    fn the_pubkey_is_derived_from_the_secret_never_supplied() {
        let (keys, nsec) = generated();
        let id = AgentIdentity::from_nsec(&nsec).unwrap();
        assert_eq!(id.pubkey_hex(), keys.public_key().to_hex());
        assert_eq!(id.pubkey_hex().len(), 64);
        assert_eq!(id.short12(), &id.pubkey_hex()[..12]);
        assert_eq!(id.short32(), &id.pubkey_hex()[..32]);
    }

    #[test]
    fn a_padded_key_still_decodes() {
        let (keys, nsec) = generated();
        let padded = format!("  {nsec}\n");
        assert_eq!(
            AgentIdentity::from_nsec(&padded).unwrap().pubkey_hex(),
            keys.public_key().to_hex()
        );
    }

    #[test]
    fn a_malformed_key_is_refused_not_guessed() {
        for bad in ["", "nsec1", "npub1xyz", "deadbeef"] {
            assert!(
                AgentIdentity::from_nsec(bad).is_err(),
                "accepted malformed key {bad:?}"
            );
        }
    }

    #[test]
    fn generations_do_not_repeat() {
        assert_ne!(new_generation(), new_generation());
        assert_eq!(new_generation().len(), 8);
    }
}
