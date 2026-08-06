//! Shared implementation of the Buzz backend-provider contract
//! (`docs/remote-agents.md`).
//!
//! Everything here is substrate-neutral: the wire types, the three-tier
//! launch-environment algorithm, and identity derivation. Two conforming
//! providers must produce interchangeable launches from the same payload, so
//! these live in one place rather than being reimplemented per binding.

pub mod wire;
