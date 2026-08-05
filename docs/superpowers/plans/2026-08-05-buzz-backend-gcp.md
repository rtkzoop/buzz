# buzz-backend-gcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `buzz-backend-gcp`, a conforming Buzz backend provider that deploys managed agents as systemd units on the `buzz-agent` GCE VM, so the desktop's "Where to run" selector can target the team's remote server.

**Architecture:** Extract the substrate-neutral half of `buzz-backend-kubernetes` (wire types, three-tier env algorithm, identity derivation, golden request fixtures, pipe harness) into a new `buzz-backend-core` crate; both providers depend on it. `buzz-backend-gcp` then adds the GCE binding: pure rendering of six remote artifacts across two marker tiers, an IAP-SSH transport, label-fenced Secret Manager storage, and an I4 reconciler that separates systemd state from marker state.

**Tech Stack:** Rust 2021 (workspace, rust-version 1.88.0), `serde_json`, `nostr` 0.44 (nsec decoding), `sha2` 0.11 + `hex` 0.4, `rand` 0.10, `chrono` 0.4, `clap` 4 for the operator argv surface. No async runtime in the GCP crate — every remote call is a blocking `gcloud` subprocess.

**Design:** [`docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md`](../specs/2026-08-05-buzz-backend-gcp-design.md) — **approved**. Where this plan and the design disagree, the design wins.
**Normative spec:** [`docs/remote-agents.md`](../../remote-agents.md)
**Review this revision answers:** [`docs/superpowers/reviews/2026-08-05-buzz-backend-gcp-plan-review-r1.md`](../reviews/2026-08-05-buzz-backend-gcp-plan-review-r1.md)

## Global Constraints

- `docs/remote-agents.md` is normative. Every behavior traces to a clause; when in doubt, read it rather than inferring.
- **No `unsafe`.** No new `unwrap()`/`expect()` in production paths — use `?` and typed errors. (AGENTS.md:114-115)
- New public API needs doc comments. (AGENTS.md:116)
- Commit with `git commit -s`; the DCO check fails any commit without a `Signed-off-by` trailer. (AGENTS.md:111)
- Activate hermit before any git/cargo work: `. ./bin/activate-hermit`. (AGENTS.md:80, :107-109)
- Exit codes carry exactly one bit: 0 = the response on stdout is trustworthy, nonzero = failure regardless of stdout. Never encode structured meaning in a nonzero value. ([L2] item 1, `docs/remote-agents.md:1443-1450`)
- `Restart=always` and equivalents are non-conforming. ([L1] item 5, `:1434-1436`)
- Agent identity env is built from top-level payload fields, never from `env_vars`. ([L2] item 3, `:1453-1458`)
- The provider never accepts credentials through `provider_config`. (I2, [L2] item 2, `:1451-1452`)
- **No secret material in any output** — stdout, stderr, error strings, the deploy trail, or `dry-run`. ([L2] item 5, `:1477-1478`)
- Object names derive from the pubkey the provider decodes itself, never from a caller-supplied pubkey or a display name.
- Run `just fmt` and `cargo clippy --workspace --all-targets -- -D warnings` before each commit. Do not run the full `just ci` per task; run it once at the end (Task 15).

### Three facts that were verified and must not be "fixed"

A future reader will be tempted to change each of these. Each was tested; changing it is a regression.

1. **`gcloud compute ssh --command` DOES forward local stdin.** It execs a real `/usr/bin/ssh` with the remote command as trailing argv, and `ssh` forwards stdin to it. Measured: 30 bytes piped to `buzz-agent`, the remote `wc -c` returned `30` with a matching md5. This is what makes the stdin install path sound — **do not** rewrite the transport onto `scp` or remote temp files. (Review r1, rejected finding 1.)
2. **`RuntimeDirectory=` at `0750` root:root does not block the agent.** systemd's *manager* reads `EnvironmentFile=` as root before dropping to `User=`. Live proof on this same host: the running `buzz-acp.service` has `User=buzzacp` and `EnvironmentFile=/etc/buzz/acp.env` at mode **0600 root:root**, and starts. **Do not** widen the runtime directory mode. (Review r1, rejected finding 2.)
3. **`StrictHostKeyChecking` is deliberately left alone.** `gcloud` already selects `StrictHostKeyChecking=yes` against `~/.ssh/google_compute_known_hosts`, keyed by `HostKeyAlias=compute.<instance id>` with `CheckHostIP=no`. Passing `-o StrictHostKeyChecking=no` would be a strict *downgrade* while installing root-owned unit files. **Do not** add that flag back. (Design §Transport.)

`sudo -n` is used on every privileged step. Passwordless sudo is verified on this host, so `-n` changes no outcome today; it stays because on a host that *did* prompt, the prompt would consume the piped file body as keystrokes and write a truncated root-owned unit file.

---

## Task 1: Create `buzz-backend-core` with the wire types

**Files:**
- Create: `crates/buzz-backend-core/Cargo.toml`
- Create: `crates/buzz-backend-core/src/lib.rs`
- Move: `crates/buzz-backend-kubernetes/src/wire.rs` → `crates/buzz-backend-core/src/wire.rs`
- Modify: root `Cargo.toml` (`members`, `[workspace.dependencies]` internal crates block)
- Modify: `crates/buzz-backend-kubernetes/Cargo.toml`
- Modify: `crates/buzz-backend-kubernetes/src/main.rs:23`, `:26`, `:80`

**Interfaces:**
- Produces: `buzz_backend_core::wire::{Request, DeployRequest, AgentPayload, LaunchBlock, Response, InfoResponse, DeployResponse, ErrorResponse, PROTOCOL_VERSION}` and
  `Response::info(name: &'static str, description: &'static str, config_schema: serde_json::Value) -> Response` — **signature change**: the k8s version called a crate-local `config_schema()`, which cannot exist in a shared crate.
- Consumes: nothing.

- [ ] **Step 1: Create the crate manifest**

`crates/buzz-backend-core/Cargo.toml`:

```toml
[package]
name = "buzz-backend-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Shared wire contract and launch-environment algorithm for Buzz backend providers (docs/remote-agents.md)"

[dependencies]
nostr = { workspace = true }
rand = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
```

(`repository` is deliberately omitted, matching the sibling `crates/buzz-backend-kubernetes/Cargo.toml`.)

- [ ] **Step 2: Register the crate in the workspace**

In the root `Cargo.toml`, add to `members` immediately after `"crates/buzz-backend-kubernetes",`:

```toml
    "crates/buzz-backend-core",
```

And to the `# Internal crates` block of `[workspace.dependencies]`:

```toml
buzz-backend-core = { path = "crates/buzz-backend-core" }
```

- [ ] **Step 3: Move `wire.rs` and parameterize `info()`**

```bash
git mv crates/buzz-backend-kubernetes/src/wire.rs crates/buzz-backend-core/src/wire.rs
```

In the moved file, replace the whole `pub fn info()` constructor (it referenced `crate::config::config_schema()`, which does not exist here):

```rust
    /// The provider's self-description (spec §Info). Pure — no substrate
    /// contact — because the desktop calls it to render the config form
    /// before any credentials are known to exist.
    ///
    /// Parameterized over the binding's identity: the six response fields are
    /// fixed by the contract (`desktop/src-tauri/src/managed_agents/backend.rs:48-63`
    /// rejects any seventh), but `name`, `description`, and the schema are
    /// each binding's own.
    ///
    /// `version` resolves to **this** crate's `CARGO_PKG_VERSION`, not the
    /// caller's. Every workspace crate sets `version.workspace = true`, so the
    /// value is identical today; if a binding is ever versioned separately
    /// this constructor must gain a `version` parameter.
    pub fn info(
        name: &'static str,
        description: &'static str,
        config_schema: serde_json::Value,
    ) -> Self {
        Response::Info(InfoResponse {
            ok: true,
            name,
            version: env!("CARGO_PKG_VERSION"),
            protocol_version: PROTOCOL_VERSION,
            description,
            config_schema,
        })
    }
```

Leave every other item in the file byte-identical, including its test module.

- [ ] **Step 4: Create the lib root**

`crates/buzz-backend-core/src/lib.rs`:

```rust
//! Shared implementation of the Buzz backend-provider contract
//! (`docs/remote-agents.md`).
//!
//! Everything here is substrate-neutral: the wire types, the three-tier
//! launch-environment algorithm, and identity derivation. Two conforming
//! providers must produce interchangeable launches from the same payload, so
//! these live in one place rather than being reimplemented per binding.

pub mod wire;
```

- [ ] **Step 5: Point the Kubernetes crate at the shared types**

In `crates/buzz-backend-kubernetes/Cargo.toml`, add to `[dependencies]`:

```toml
buzz-backend-core = { workspace = true }
```

In `crates/buzz-backend-kubernetes/src/main.rs`, delete the `mod wire;` line (`:23`) and replace the import at `:26`:

```rust
use buzz_backend_core::wire::{self, Request, Response};
```

Replace the `Request::Info` arm at `:80`:

```rust
        Request::Info => Response::info(
            "kubernetes",
            "Runs agents as pods in a Kubernetes cluster",
            config::config_schema(),
        ),
```

Repoint every remaining `crate::wire::` path in the crate:

```bash
grep -rn "crate::wire" crates/buzz-backend-kubernetes/src
```

Each hit becomes `buzz_backend_core::wire::`. At the time of writing the only one is `src/env.rs:8` (`use crate::wire::{AgentPayload, LaunchBlock};`) — verify with the grep rather than trusting this sentence.

- [ ] **Step 6: Verify the Kubernetes suite is still green**

Run: `cargo test -p buzz-backend-kubernetes`
Expected: PASS — 154 unit tests + 4 integration tests, the same counts as the pre-extraction baseline. **No test file may be edited in this task.** If a test needed changing, the extraction changed behavior; revert and find out why.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -s -m "refactor(backend): extract wire contract into buzz-backend-core"
```

---

## Task 2: Move the env algorithm and identity derivation into the core

Resolves review **P1-8**.

**Files:**
- Move: `crates/buzz-backend-kubernetes/src/env.rs` → `crates/buzz-backend-core/src/env.rs`
- Create: `crates/buzz-backend-core/src/identity.rs`
- Modify: `crates/buzz-backend-core/src/lib.rs`
- Modify: `crates/buzz-backend-kubernetes/src/main.rs:15` (drop `mod env;`), `:124-130` (call site)
- Modify: `crates/buzz-backend-kubernetes/src/naming.rs:1-123` (keep the k8s constants, wrap the shared identity)

**Interfaces:**
- Produces:
  - `buzz_backend_core::env::build_env(agent: &AgentPayload, auth: AuthoritativeInputs<'_>) -> Result<BTreeMap<String, String>, String>`
  - `buzz_backend_core::env::AuthoritativeInputs<'a> { generation: &'a str, inactivity_seconds: Option<u64>, max_env_bytes: Option<usize> }` — **the third field is new.** Kubernetes passes `Some(1_048_576)`, GCP passes `None`.
  - `buzz_backend_core::env::AUTHORITATIVE_KEYS: &[&str]` — **now `pub`** (it was private at `env.rs:23`), plus the already-public `START_NONCE_KEY`.
  - `buzz_backend_core::identity::AgentIdentity` with `from_nsec(&str) -> Result<Self, String>`, `pubkey_hex(&self) -> &str`, `short12(&self) -> &str`, `short32(&self) -> &str`; derives `Debug, Clone, PartialEq, Eq`.
  - `buzz_backend_core::identity::new_generation() -> String`
- Consumes: `buzz_backend_core::wire::{AgentPayload, LaunchBlock}` from Task 1.

**Why the k8s crate gets a newtype rather than a re-export.** The k8s `AgentIdentity` carries five inherently Kubernetes methods (`label_pubkey`, `pod_name`, `secret_name`, `selector`, `labels`) used across `gc.rs`, `observe.rs`, `pod.rs`, `reconcile.rs` and their tests. The orphan rule forbids `impl`ing them on a foreign type, and an extension trait would force a `use` line into every one of those modules **including their test modules**. A newtype keeps every existing call site — production and test — byte-identical.

- [ ] **Step 1: Move the env module**

```bash
git mv crates/buzz-backend-kubernetes/src/env.rs crates/buzz-backend-core/src/env.rs
```

In the moved file, restore the crate-local import (Task 1 pointed it at `buzz_backend_core::wire`, which is now `crate`):

```rust
use crate::wire::{AgentPayload, LaunchBlock};
```

- [ ] **Step 2: Make `AUTHORITATIVE_KEYS` public**

At `crates/buzz-backend-core/src/env.rs:23`, change `const AUTHORITATIVE_KEYS` to `pub const AUTHORITATIVE_KEYS`. Its existing doc comment stays; append this paragraph to it, because the GCP binding's secrecy allowlist sits next door and the two are easy to confuse:

```rust
/// This list is **not** a secrecy classification. Three of its twelve entries
/// (`BUZZ_PRIVATE_KEY`, `NOSTR_PRIVATE_KEY`, `BUZZ_AUTH_TAG`) are credentials;
/// the rest are public. A binding that splits the environment by sensitivity
/// must use its own allowlist, not this one.
```

- [ ] **Step 3: Replace the hardcoded Kubernetes size cap with a parameter**

Delete the `MAX_SECRET_BYTES` constant (`env.rs:49-53`). Replace `AuthoritativeInputs` (`:151-159`) with:

```rust
/// Inputs the provider itself supplies to the authoritative tier.
pub struct AuthoritativeInputs<'a> {
    /// The attempt's generation token — the lifecycle correlator, and on
    /// substrates with per-generation objects also their name suffix.
    pub generation: &'a str,
    /// Resolved from the binding's inactivity config; `None` means the
    /// indefinite opt-in.
    pub inactivity_seconds: Option<u64>,
    /// Substrate cap on the summed environment value bytes, enforced here so
    /// an oversized environment surfaces as a named provider error rather
    /// than a rejection partway through a deploy. `None` when the substrate
    /// imposes no such limit — a systemd `EnvironmentFile` on an ordinary
    /// filesystem, for instance.
    pub max_env_bytes: Option<usize>,
}
```

Replace the trailing size check (`:288-294`) with:

```rust
    if let Some(cap) = auth.max_env_bytes {
        let total: usize = env.values().map(String::len).sum();
        if total > cap {
            return Err(format!(
                "agent environment is {total} bytes; this substrate caps it at {cap}"
            ));
        }
    }

    Ok(env)
```

Keep the `is_posix_env_key` validation unconditional: systemd's `EnvironmentFile` parser is no more forgiving of exotic keys than the kubelet, and one shared rule is one behavior to reason about.

- [ ] **Step 4: Update the two moved test constructors**

The moved test module builds `AuthoritativeInputs` in exactly two places, and both now miss a required field. **Neither needs an assertion changed** — verified: no test in the module asserts the size-cap message, so deleting `MAX_SECRET_BYTES` and rewording its error changes no expectation.

First, the shared `build` helper at `crates/buzz-backend-core/src/env.rs:319-327`:

```rust
    fn build(agent: &AgentPayload) -> Result<BTreeMap<String, String>, String> {
        build_env(
            agent,
            AuthoritativeInputs {
                generation: "gen0001",
                inactivity_seconds: Some(7200),
                // Kubernetes' own cap, so every test routed through this
                // helper keeps exactly the behavior it had before the move.
                max_env_bytes: Some(1024 * 1024),
            },
        )
    }
```

Second, `inactivity_omitted_when_unset` at `crates/buzz-backend-core/src/env.rs:546-558`, the one test that calls `build_env` directly. Its body and assertion are otherwise untouched:

```rust
    #[test]
    fn inactivity_omitted_when_unset() {
        let agent = payload_json(serde_json::json!({"launch": {"owner_pubkey": "b"}}));
        let env = build_env(
            &agent,
            AuthoritativeInputs {
                generation: "g",
                inactivity_seconds: None,
                max_env_bytes: Some(1024 * 1024),
            },
        )
        .unwrap();
        assert!(!env.contains_key("BUZZ_ACP_EXIT_AFTER_INACTIVITY"));
    }
```

Then add one case beside it, proving the new degree of freedom actually works — without it, `max_env_bytes: None` is a parameter no test exercises:

```rust
    /// A substrate with no cap must not inherit Kubernetes' 1 MiB rule: on a
    /// systemd `EnvironmentFile` there is no such boundary to respect.
    #[test]
    fn an_uncapped_substrate_accepts_an_environment_kubernetes_would_refuse() {
        let big = "x".repeat(2 * 1024 * 1024);
        let agent = payload_json(serde_json::json!({
            "launch": { "owner_pubkey": "a".repeat(64), "env": { "BIG": big } }
        }));
        let env = build_env(
            &agent,
            AuthoritativeInputs {
                generation: "g",
                inactivity_seconds: Some(7200),
                max_env_bytes: None,
            },
        )
        .expect("no cap means no refusal");
        assert_eq!(env["BIG"].len(), 2 * 1024 * 1024);
    }
```

- [ ] **Step 5: Create the shared identity module**

`crates/buzz-backend-core/src/identity.rs`. The `nostr` and `rand` call shapes below are copied verbatim from `crates/buzz-backend-kubernetes/src/naming.rs:52-59` and `:119-123`, which compile today against the pinned `nostr` 0.44 and `rand` 0.10 — do not "modernize" them.

```rust
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
```

- [ ] **Step 6: Export the new modules**

Replace the module list in `crates/buzz-backend-core/src/lib.rs`:

```rust
pub mod env;
pub mod identity;
pub mod wire;
```

- [ ] **Step 7: Wrap the shared identity in the Kubernetes crate**

Replace `crates/buzz-backend-kubernetes/src/naming.rs:37-123` — the struct, its `impl`, and `new_generation` — with the newtype below. Lines `1-36` (the module doc and the six constants) stay exactly as they are, except that `use nostr::nips::nip19::FromBech32;` at `:7` is now unused and must be deleted.

```rust
/// An agent identity the provider derived itself, plus every Kubernetes name
/// it implies.
///
/// A newtype over the shared [`buzz_backend_core::identity::AgentIdentity`]
/// rather than a re-export: the five methods below are inherently Kubernetes'
/// and the orphan rule forbids attaching them to a type from another crate.
/// Constructing this is still the *only* way to obtain the names, so a
/// caller-supplied pubkey cannot reach a selector by any path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity(buzz_backend_core::identity::AgentIdentity);

impl AgentIdentity {
    /// Derive from the payload's `private_key_nsec`.
    ///
    /// Accepts bech32 `nsec1…`; a malformed or undecodable key is an
    /// immediate error, before any cluster read or mutation
    /// (§Deploy State Machine step 0).
    pub fn from_nsec(nsec: &str) -> Result<Self, String> {
        buzz_backend_core::identity::AgentIdentity::from_nsec(nsec).map(Self)
    }

    /// Full 64-hex public key — the annotation value and the comparison
    /// operand for candidate authentication.
    pub fn pubkey_hex(&self) -> &str {
        self.0.pubkey_hex()
    }

    /// Selector label value: first 32 hex chars (128 bits). A full hex pubkey
    /// is 64 chars and label values cap at 63, which is why this is truncated
    /// and why the annotation check is normative rather than decorative.
    pub fn label_pubkey(&self) -> &str {
        self.0.short32()
    }

    /// Deterministic pod name, also the returned `agent_id`.
    pub fn pod_name(&self) -> String {
        format!("buzz-agent-{}", self.0.short12())
    }

    /// Per-attempt Secret name. `generation` is a fresh random token per
    /// create attempt — never reused — which is what makes payload and Secret
    /// atomic at the pod-spec boundary (§K8s Secrets).
    pub fn secret_name(&self, generation: &str) -> String {
        format!("buzz-agent-{}-{}", self.0.short12(), generation)
    }

    /// Label selector matching this identity's objects *and* our management
    /// marker. Selecting on the marker as well as the identity means an
    /// unmarked look-alike never even enters the candidate list.
    pub fn selector(&self) -> String {
        format!(
            "{LABEL_AGENT_PUBKEY}={},{LABEL_MANAGED_BY}={MANAGED_BY}",
            self.label_pubkey()
        )
    }

    /// The label set stamped on every object this provider creates.
    pub fn labels(&self) -> std::collections::BTreeMap<String, String> {
        [
            (
                LABEL_AGENT_PUBKEY.to_string(),
                self.label_pubkey().to_string(),
            ),
            (LABEL_MANAGED_BY.to_string(), MANAGED_BY.to_string()),
            (
                LABEL_BINDING_VERSION.to_string(),
                BINDING_VERSION.to_string(),
            ),
        ]
        .into_iter()
        .collect()
    }
}

/// A fresh generation token, shared with every other binding so the
/// correlator has one spelling across substrates.
pub use buzz_backend_core::identity::new_generation;
```

Everything below (`#[cfg(test)] mod tests`, `naming.rs:125-224`) stays byte-identical: every method it calls still exists with the same name and signature.

- [ ] **Step 8: Update the Kubernetes env call site**

In `crates/buzz-backend-kubernetes/src/main.rs`, delete `mod env;` (`:15`) and replace the `build_env` call (`:124-130`):

```rust
    let env = buzz_backend_core::env::build_env(
        &request.agent,
        buzz_backend_core::env::AuthoritativeInputs {
            generation: &naming::new_generation(),
            inactivity_seconds: cfg.inactivity_seconds,
            // Kubernetes' own `MaxSecretSize` (`pkg/apis/core/types.go`).
            max_env_bytes: Some(1024 * 1024),
        },
    )?;
```

Then repoint any remaining `env::` paths:

```bash
grep -rn "crate::env\|[^_a-z]env::" crates/buzz-backend-kubernetes/src
```

- [ ] **Step 9: Verify the core crate first, then the regression gate**

Run: `cargo test -p buzz-backend-core`
Expected: PASS — the moved `env` and `wire` test modules plus the four new `identity` tests.

Then run: `cargo test -p buzz-backend-kubernetes`
Expected: PASS — 154 unit + 4 integration, unchanged counts. **No `#[cfg(test)]` module and no file under `crates/buzz-backend-kubernetes/tests/` may be edited in this task.** The only test edits permitted anywhere in the extraction are the two `AuthoritativeInputs` struct literals enumerated in Step 4, which live in the *moved* `env.rs` and are forced by a new required field — **no assertion, no expectation, and no test count changes anywhere**. If anything else needs touching, the extraction changed behavior; stop and find out why.

- [ ] **Step 10: Commit**

```bash
git add -A && git commit -s -m "refactor(backend): share env algorithm and identity derivation"
```

---

## Task 3: Share the request fixtures and the pipe harness

Resolves review **P2-5**.

**Files:**
- Create: `crates/buzz-backend-core/src/harness.rs`
- Modify: `crates/buzz-backend-core/src/lib.rs`
- Move: `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/*.request.json` and `README.md` → `crates/buzz-backend-core/fixtures/provider-wire/`
- Modify: `crates/buzz-backend-kubernetes/tests/wire_fixtures.rs:10-45` (the imports and three private helpers only)

**Interfaces:**
- Produces:
  - `buzz_backend_core::harness::fixtures_dir() -> PathBuf`
  - `buzz_backend_core::harness::fixture(name: &str) -> String`
  - `buzz_backend_core::harness::run(binary: &Path, request: &str) -> (String, i32)`
  - `buzz_backend_core::harness::run_with_env(binary: &Path, request: &str, env: &[(&str, &str)]) -> (String, i32)`
- Consumes: nothing.

**What moves and what does not.** The `*.request.json` payloads are the desktop's, shared by every binding — they move. The `*.response.json` goldens are each binding's own *text* (the k8s relay-mesh refusal says "rather than in a pod … deploying it to Kubernetes") — they stay in the crate that produces them. `README.md` documents the request-recording rules, so it moves with the requests.

**The `KUBECONFIG` override is load-bearing and survives.** `wire_fixtures.rs:20-24` forces `KUBECONFIG=/nonexistent/kubeconfig-for-fixture-tests` so a fixture that accidentally reaches a cluster fails loudly instead of hitting whatever cluster the developer is pointed at — and several assertions (`error.contains("kubeconfig")`) *are* the ordering proof that an earlier gate passed. A shared harness with no env hook would silently let those tests reach a live cluster on a developer machine, voiding the very regression gate this extraction depends on. Hence `run_with_env`, plus a thin local `run` in the k8s test that supplies the override.

- [ ] **Step 1: Move the request fixtures**

```bash
mkdir -p crates/buzz-backend-core/fixtures/provider-wire
git mv crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/README.md \
       crates/buzz-backend-core/fixtures/provider-wire/README.md
for f in crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/*.request.json; do
  git mv "$f" crates/buzz-backend-core/fixtures/provider-wire/
done
```

Expected afterwards: `crates/buzz-backend-core/fixtures/provider-wire/` holds `README.md`, `info.request.json`, `deploy-full-launch.request.json`, `deploy-no-owner.request.json`, `deploy-relay-mesh.request.json`, `deploy-relay-mesh-padded.request.json`, `deploy-tag-image.request.json`; and `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/` holds exactly the four `*.response.json` files.

Add this paragraph to the moved `README.md`, after its opening two paragraphs:

```markdown
Requests live here because they are the desktop's payloads and every binding
must accept the same ones. **Responses do not**: each binding's refusal text
names its own substrate, so `*.response.json` stays in the crate that produces
it — `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/` and
`crates/buzz-backend-gcp/tests/fixtures/provider-wire/`.
```

- [ ] **Step 2: Write the shared harness**

`crates/buzz-backend-core/src/harness.rs`:

```rust
//! Driving a provider binary over a real pipe (spec §Provider Protocol).
//!
//! Not `#[cfg(test)]`: this is consumed by the integration tests of *other*
//! crates, which compile against the normal library. It is nonetheless test
//! support, which is why its failures panic with a diagnostic rather than
//! returning `Result` — a fallible helper would push `unwrap()` into every
//! assertion in every binding's fixture suite, which is the outcome
//! AGENTS.md's no-`unwrap()` rule exists to avoid.
//!
//! Providers are tested through the built binary rather than an in-process
//! call because the contract is `stdin -> one JSON object on stdout -> exit
//! code`, and an in-process test skips the three things that actually break:
//! writing nothing, writing two objects, or signalling through the exit code.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The shared golden **request** directory. Response goldens are per-binding
/// and live in the binding's own `tests/fixtures/provider-wire/`.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/provider-wire")
}

/// Read one shared fixture by file name.
pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures_dir().join(name))
        .unwrap_or_else(|e| panic!("could not read fixture {name}: {e}"))
}

/// Feed one request to a provider binary; return `(stdout, exit code)`.
pub fn run(binary: &Path, request: &str) -> (String, i32) {
    run_with_env(binary, request, &[])
}

/// [`run`], with extra environment variables set on the child.
///
/// The hook exists so a binding can fence its fixture suite away from real
/// infrastructure — the Kubernetes suite points `KUBECONFIG` at a path that
/// cannot exist, so a fixture that accidentally reaches a cluster fails at
/// the intended boundary instead of talking to a developer's live cluster.
pub fn run_with_env(binary: &Path, request: &str, env: &[(&str, &str)]) -> (String, i32) {
    let mut child = Command::new(binary)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("could not run {}: {e}", binary.display()));
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(request.as_bytes())
        .expect("could not write the request");
    let out = child.wait_with_output().expect("provider did not exit");
    (
        String::from_utf8(out.stdout).expect("stdout was not UTF-8"),
        out.status.code().unwrap_or(-1),
    )
}
```

Update `crates/buzz-backend-core/src/lib.rs`:

```rust
pub mod env;
pub mod harness;
pub mod identity;
pub mod wire;
```

- [ ] **Step 3: Repoint only the imports and three private helpers in the Kubernetes test**

In `crates/buzz-backend-kubernetes/tests/wire_fixtures.rs`, replace lines `10-45` with:

```rust
use std::path::{Path, PathBuf};

/// This binding's **response** goldens. Requests are shared and live in
/// `buzz-backend-core`.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provider-wire")
}

/// Feed one request to the binary; return `(stdout, exit code)`.
///
/// The `KUBECONFIG` override is not incidental: it points at a path that
/// cannot exist, so a fixture that accidentally reaches the cluster fails
/// loudly here instead of depending on whatever cluster the developer is
/// pointed at — and several assertions below read `error.contains("kubeconfig")`
/// as proof that an earlier gate passed.
fn run(request: &str) -> (String, i32) {
    buzz_backend_core::harness::run_with_env(
        Path::new(env!("CARGO_BIN_EXE_buzz-backend-kubernetes")),
        request,
        &[("KUBECONFIG", "/nonexistent/kubeconfig-for-fixture-tests")],
    )
}

fn read(name: &str) -> String {
    if name.ends_with(".request.json") {
        buzz_backend_core::harness::fixture(name)
    } else {
        std::fs::read_to_string(fixtures().join(name))
            .unwrap_or_else(|e| panic!("could not read fixture {name}: {e}"))
    }
}
```

Every `#[test]` body in the file stays byte-identical. The old `use std::io::Write;` and `use std::process::{Command, Stdio};` imports are removed by the replacement above because nothing in the file spawns a process directly any more.

- [ ] **Step 4: Verify**

Run: `cargo test -p buzz-backend-core && cargo test -p buzz-backend-kubernetes`
Expected: PASS in both, k8s at 154 unit + 4 integration — the same counts as the baseline, with no assertion changed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "refactor(backend): share provider-wire requests and the pipe harness"
```

---

## Task 4: `buzz-backend-gcp` skeleton — `info`, the config schema, and the closed value grammars

Resolves review **P1-6**.

**Files:**
- Create: `crates/buzz-backend-gcp/Cargo.toml`
- Create: `crates/buzz-backend-gcp/src/main.rs`
- Create: `crates/buzz-backend-gcp/src/config.rs`
- Create: `crates/buzz-backend-gcp/tests/wire.rs`
- Modify: root `Cargo.toml` (`members`, internal crate deps)

**Interfaces:**
- Produces:
  - `config::config_schema() -> serde_json::Value`
  - `config::ProviderConfig { project: String, zone: String, instance: String, memory_max: String, memory_max_bytes: u64, cpu_quota: String, inactivity_seconds: Option<u64> }` with `ProviderConfig::parse(&serde_json::Value) -> Result<Self, String>`
  - `config::parse_memory_max(&str) -> Result<u64, String>`, `config::parse_cpu_quota(&str) -> Result<u32, String>`
  - `config::{DEFAULT_PROJECT, DEFAULT_ZONE, DEFAULT_INSTANCE, DEFAULT_MEMORY_MAX, DEFAULT_CPU_QUOTA, DEFAULT_INACTIVITY_SECONDS}`
  - `respond(input: &str) -> Response` in `main.rs`
- Consumes: `buzz_backend_core::wire::{Request, Response}`, `buzz_backend_core::harness`.

**Why the grammars are closed and rejecting, not sanitizing.** `memory_max` and `cpu_quota` are the only config values this binding interpolates into a **root-installed systemd drop-in**. A drop-in is line-oriented and systemd accepts every `[Service]` directive it finds, so an accepted value containing a newline *is* arbitrary unit content: `2G\nEnvironmentFile=/tmp/x.env` adds a second environment source that overrides the authoritative tier, and `2G\nExecStart=\nExecStart=/bin/sh -c …` uses systemd's empty-assignment reset to replace the agent command outright — both while the file still carries a valid management marker, so every fence in this design reads it as legitimately ours. The desktop cannot catch this: `validate_provider_config` (`desktop/src-tauri/src/managed_agents/backend.rs:536-566`) checks flatness, field count, scalar-ness and secret-like key *names*, never a value's contents. The provider is the only place this stops.

- [ ] **Step 1: Write the failing wire test**

`crates/buzz-backend-gcp/tests/wire.rs`:

```rust
//! The stdin/stdout contract, driven through the built binary.

use buzz_backend_core::harness::{fixture, run};
use std::path::{Path, PathBuf};

fn binary() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_buzz-backend-gcp")).to_path_buf()
}

#[test]
fn info_carries_exactly_the_six_contract_fields() {
    let (stdout, code) = run(&binary(), &fixture("info.request.json"));
    assert_eq!(code, 0, "info must exit 0; stdout={stdout}");
    assert_eq!(
        stdout.matches('\n').count(),
        1,
        "expected exactly one line, got {stdout:?}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON object");

    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["name"], serde_json::json!("gcp"));
    assert_eq!(v["protocol_version"], serde_json::json!(1));
    assert!(v["version"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["description"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["config_schema"].is_object());

    // The desktop rejects any seventh field (backend.rs:48-63).
    let mut keys: Vec<&str> = v
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "config_schema",
            "description",
            "name",
            "ok",
            "protocol_version",
            "version"
        ]
    );
}

#[test]
fn the_config_schema_names_no_credential() {
    let (stdout, _) = run(&binary(), &fixture("info.request.json"));
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // I2 / backend.rs:536-566: the desktop refuses any config key whose words
    // include one of these, so a schema advertising one is dead on arrival.
    let forbidden = ["secret", "password", "token", "key", "credential"];
    for name in v["config_schema"]["properties"]
        .as_object()
        .expect("properties")
        .keys()
    {
        let lowered = name.to_ascii_lowercase();
        for word in forbidden {
            assert!(
                !lowered.contains(word),
                "config key {name} looks like a credential"
            );
        }
    }
}

#[test]
fn an_unknown_op_is_an_in_band_error_with_exit_zero() {
    let (stdout, code) = run(&binary(), r#"{"op":"teleport","request_id":"r"}"#);
    assert_eq!(code, 0, "in-band errors still exit 0");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["ok"], serde_json::json!(false));
    assert!(v["error"].as_str().is_some_and(|s| !s.is_empty()));
}

#[test]
fn malformed_input_is_an_in_band_error_with_exit_zero() {
    let (stdout, code) = run(&binary(), "not json at all");
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["ok"], serde_json::json!(false));
    assert!(v["error"].as_str().unwrap_or_default().contains("valid JSON"));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p buzz-backend-gcp`
Expected: FAIL — `error: package ID specification 'buzz-backend-gcp' did not match any packages`.

- [ ] **Step 3: Create the manifest and register the crate**

`crates/buzz-backend-gcp/Cargo.toml`:

```toml
[package]
name = "buzz-backend-gcp"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "GCE/systemd backend provider for Buzz remote agents (docs/remote-agents.md)"

[[bin]]
name = "buzz-backend-gcp"
path = "src/main.rs"

[dependencies]
buzz-backend-core = { workspace = true }
chrono = { workspace = true }
hex = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
clap = { version = "4", features = ["derive"] }
```

`clap` carries an explicit version rather than `workspace = true` because the workspace has no `clap` entry; `crates/buzz-cli/Cargo.toml:20` sets the same precedent. There is no `serde` dependency: this crate deserializes only through `buzz_backend_core::wire`, and its own config parsing reads `serde_json::Value` directly.

Root `Cargo.toml`: add `"crates/buzz-backend-gcp",` to `members` and `buzz-backend-gcp = { path = "crates/buzz-backend-gcp" }` to the `# Internal crates` block.

- [ ] **Step 4: Write the failing config tests**

`crates/buzz-backend-gcp/src/config.rs`, test module (write it first; the implementation follows in Step 6):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_config_takes_every_default() {
        let c = ProviderConfig::parse(&json!({})).unwrap();
        assert_eq!(c.project, DEFAULT_PROJECT);
        assert_eq!(c.zone, DEFAULT_ZONE);
        assert_eq!(c.instance, DEFAULT_INSTANCE);
        assert_eq!(c.memory_max, DEFAULT_MEMORY_MAX);
        assert_eq!(c.memory_max_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(c.cpu_quota, DEFAULT_CPU_QUOTA);
        assert_eq!(c.inactivity_seconds, Some(DEFAULT_INACTIVITY_SECONDS));
    }

    /// A null `provider_config` is what the desktop sends when the user
    /// accepted every default; it must not be a parse error.
    #[test]
    fn a_null_config_is_an_empty_config() {
        assert_eq!(
            ProviderConfig::parse(&serde_json::Value::Null).unwrap(),
            ProviderConfig::parse(&json!({})).unwrap()
        );
    }

    /// `inactivity_seconds: 0` is the blessed indefinite opt-in and MUST parse
    /// (spec §`provider_config` v1 fields). Whether this binding can *honor*
    /// it is a separate question, answered by `render::plan`.
    #[test]
    fn zero_inactivity_parses_as_the_indefinite_opt_in() {
        let c = ProviderConfig::parse(&json!({"inactivity_seconds": 0})).unwrap();
        assert_eq!(c.inactivity_seconds, None);
    }

    #[test]
    fn a_non_integer_inactivity_is_refused() {
        assert!(ProviderConfig::parse(&json!({"inactivity_seconds": "soon"})).is_err());
        assert!(ProviderConfig::parse(&json!({"inactivity_seconds": -5})).is_err());
    }

    #[test]
    fn memory_sizes_resolve_to_bytes() {
        assert_eq!(parse_memory_max("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory_max("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory_max("1.5G").unwrap(), 1_610_612_736);
        assert_eq!(parse_memory_max("1024").unwrap(), 1024);
        assert_eq!(parse_memory_max("4K").unwrap(), 4096);
    }

    #[test]
    fn memory_sizes_outside_the_grammar_are_refused() {
        for bad in [
            "infinity", "", "2 G", "-1", "0", "1e9", "2GB", "2g", "2.", ".5G", "2.5555G",
            "1234567", "G", "2G ", "0K",
        ] {
            assert!(
                parse_memory_max(bad).is_err(),
                "accepted out-of-grammar memory_max {bad:?}"
            );
        }
    }

    #[test]
    fn cpu_quotas_inside_the_bound_parse() {
        assert_eq!(parse_cpu_quota("150%").unwrap(), 150);
        assert_eq!(parse_cpu_quota("1%").unwrap(), 1);
        assert_eq!(parse_cpu_quota("200%").unwrap(), 200);
    }

    #[test]
    fn cpu_quotas_outside_the_bound_are_refused() {
        // 200% is the ceiling because the instance has 2 vCPU: anything above
        // is unenforceable, so it is either a typo or a parser probe.
        for bad in ["150", "150%%", "0%", "201%", "400%", "%", "", " 150%", "1.5%"] {
            assert!(
                parse_cpu_quota(bad).is_err(),
                "accepted out-of-grammar cpu_quota {bad:?}"
            );
        }
    }

    /// The named injection payloads from design §Testing. Each must be a
    /// refusal, and the refusal must not echo the value.
    #[test]
    fn systemd_injection_payloads_are_refused_without_echoing_them() {
        let cases = [
            ("memory_max", "2G\nExecStart=/bin/sh -c id"),
            ("cpu_quota", "150%\nEnvironmentFile=/tmp/x"),
            ("memory_max", "2G\rMemoryMax=1K"),
            ("cpu_quota", "150%\u{0}"),
            ("project", "zoop-innovation\nExecStart=/bin/sh"),
        ];
        for (field, payload) in cases {
            let err = ProviderConfig::parse(&json!({ field: payload }))
                .expect_err("an embedded control character must be refused");
            assert!(
                err.contains(field),
                "{field}: the refusal must name the field: {err}"
            );
            assert!(
                !err.contains("ExecStart")
                    && !err.contains("EnvironmentFile")
                    && !err.contains("MemoryMax=1K"),
                "{field}: the refusal echoed the value, which L2 item 5 forbids: {err}"
            );
        }
    }

    /// The control-character scan must run **before** trimming. `str::trim`
    /// removes a trailing newline, so a scan placed after it would accept
    /// `"2G\n"` — and teach the next reviewer that trimming is a defense.
    #[test]
    fn a_trailing_newline_is_refused_not_trimmed_away() {
        let err = ProviderConfig::parse(&json!({"memory_max": " 2G\n"}))
            .expect_err("trim must not sanitize a control character away");
        assert!(err.contains("memory_max"), "{err}");
    }

    /// Padding with ordinary spaces is still accepted, and the trimmed form is
    /// what gets written — validator and writer must never disagree.
    #[test]
    fn ordinary_padding_is_trimmed_and_accepted() {
        let c = ProviderConfig::parse(&json!({"memory_max": "  512M  "})).unwrap();
        assert_eq!(c.memory_max, "512M");
        assert_eq!(c.memory_max_bytes, 512 * 1024 * 1024);
    }

    /// A key belonging to another binding must not be a hard refusal: the
    /// desktop does not validate `provider_config` against `config_schema`
    /// (backend.rs:536-566 checks shape and key names only), and the same
    /// agent record is redeployable across bindings.
    #[test]
    fn a_foreign_binding_key_is_ignored_not_refused() {
        let c = ProviderConfig::parse(&json!({
            "namespace": "buzz-agents-test",
            "image": "ghcr.io/block/buzz-sprig@sha256:aa",
            "memory_max": "512M"
        }))
        .unwrap();
        assert_eq!(c.memory_max, "512M");
        assert_eq!(c.instance, DEFAULT_INSTANCE);
    }

    #[test]
    fn a_non_object_config_is_refused() {
        assert!(ProviderConfig::parse(&json!("2G")).is_err());
        assert!(ProviderConfig::parse(&json!([1, 2])).is_err());
    }
}
```

- [ ] **Step 5: Run to verify they fail**

Run: `cargo test -p buzz-backend-gcp config`
Expected: FAIL — `cannot find function parse_memory_max in this scope`.

- [ ] **Step 6: Implement the config module**

Prepend to `crates/buzz-backend-gcp/src/config.rs`:

```rust
//! `provider_config` schema, parsing, and the two closed value grammars
//! (spec §`provider_config` v1 fields, §Value grammars for the drop-in fields).
//!
//! Every field here is non-secret by construction: I2 forbids a provider from
//! accepting credentials through config, and the desktop independently rejects
//! any key that looks like one
//! (`desktop/src-tauri/src/managed_agents/backend.rs:536-566`).

use serde_json::json;

pub const DEFAULT_PROJECT: &str = "zoop-innovation";
pub const DEFAULT_ZONE: &str = "asia-south1-a";
pub const DEFAULT_INSTANCE: &str = "buzz-agent";
pub const DEFAULT_MEMORY_MAX: &str = "2G";
pub const DEFAULT_CPU_QUOTA: &str = "150%";
/// Two hours, matching the Kubernetes binding's default.
pub const DEFAULT_INACTIVITY_SECONDS: u64 = 7200;

/// The instance has 2 vCPU, so a quota above this is unenforceable: it is
/// always either a typo or an attempt to probe the parser, and both deserve
/// the same refusal.
const MAX_CPU_QUOTA_PERCENT: u32 = 200;

/// The JSON Schema the desktop renders into the "Where to run" form.
pub fn config_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "project": {
                "type": "string", "default": DEFAULT_PROJECT,
                "description": "GCP project containing the instance"
            },
            "zone": {
                "type": "string", "default": DEFAULT_ZONE,
                "description": "Compute zone of the instance"
            },
            "instance": {
                "type": "string", "default": DEFAULT_INSTANCE,
                "description": "Instance the agent runs on"
            },
            "memory_max": {
                "type": "string", "default": DEFAULT_MEMORY_MAX,
                "pattern": r"^[0-9]{1,6}(\.[0-9]{1,3})?[KMGT]?$",
                "description": "systemd MemoryMax for this agent, e.g. 512M, 2G, 1.5G"
            },
            "cpu_quota": {
                "type": "string", "default": DEFAULT_CPU_QUOTA,
                "pattern": "^[0-9]{1,3}%$",
                "description":
                    "systemd CPUQuota for this agent, 1% to 200% (the instance has 2 vCPU)"
            },
            "inactivity_seconds": {
                "type": "integer", "minimum": 0,
                "default": DEFAULT_INACTIVITY_SECONDS,
                "description":
                    "Exit after this many seconds with no dispatched events. 0 means no bound."
            }
        },
        "required": ["project", "zone", "instance"],
        "additionalProperties": false
    })
}

/// Parsed, defaulted, validated provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub project: String,
    pub zone: String,
    pub instance: String,
    /// The validated `MemoryMax` spelling, written verbatim into the drop-in.
    pub memory_max: String,
    /// `memory_max` resolved to bytes, for the capacity arithmetic.
    pub memory_max_bytes: u64,
    /// The validated `CPUQuota` spelling, written verbatim into the drop-in.
    pub cpu_quota: String,
    /// `None` encodes the indefinite opt-in (`inactivity_seconds: 0`).
    pub inactivity_seconds: Option<u64>,
}

/// Refuse any string value carrying CR, LF, or NUL.
///
/// A belt for the next field added to the schema: `memory_max` and
/// `cpu_quota` have closed grammars that already exclude these, but a field
/// added later would not, and this class of defect must not be able to recur
/// by omission. The refusal names the field and the character class and
/// **never echoes the value** — an attacker-supplied value could itself be
/// secret material, which `docs/remote-agents.md:1477-1478` forbids emitting.
fn reject_control_characters(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for (key, value) in fields {
        let Some(text) = value.as_str() else { continue };
        let Some(bad) = text.chars().find(|c| matches!(c, '\r' | '\n' | '\0')) else {
            continue;
        };
        let class = match bad {
            '\r' => "a carriage return",
            '\n' => "a newline",
            _ => "a NUL byte",
        };
        return Err(format!(
            "provider_config.{key} contains {class}. This binding writes \
             configuration into a root-installed systemd drop-in, where a line \
             break becomes an additional unit directive, so such a value is \
             refused rather than sanitized. The value is not echoed."
        ));
    }
    Ok(())
}

/// Parse `memory_max` against its closed grammar and resolve it to bytes.
///
/// `^[0-9]{1,6}(\.[0-9]{1,3})?[KMGT]?$`, suffix case-**sensitive**, result
/// required `> 0`. Lowercase suffixes are refused rather than folded: systemd
/// reads a bare number as bytes, so quietly accepting `512m` would hand the
/// operator 512 bytes when they asked for 512 mebibytes.
pub fn parse_memory_max(value: &str) -> Result<u64, String> {
    let refuse = || {
        "provider_config.memory_max is not a size this binding accepts \
         (one to six digits, an optional '.' and up to three more digits, and \
         an optional uppercase K, M, G or T — for example 512M, 2G or 1.5G — \
         resolving to more than zero bytes). It is refused rather than \
         sanitized because it is interpolated into a root-installed systemd \
         drop-in. The value is not echoed."
            .to_string()
    };

    // `chars().last()`, not `as_bytes().last()`: on a value ending in a
    // multi-byte character the byte form matches `Some(_)` and the byte slice
    // below would split a code point and panic. Every accepted suffix is one
    // ASCII byte, so `len() - 1` is only reached where it is sound.
    let (digits, unit) = match value.chars().last() {
        Some('K') => (&value[..value.len() - 1], 1024_u64),
        Some('M') => (&value[..value.len() - 1], 1024_u64 * 1024),
        Some('G') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        Some('T') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024 * 1024),
        Some(_) => (value, 1_u64),
        None => return Err(refuse()),
    };

    let (whole_text, frac_text) = match digits.split_once('.') {
        // A trailing '.' with no fraction is not in the grammar.
        Some((_, "")) => return Err(refuse()),
        Some((whole, frac)) => (whole, frac),
        None => (digits, ""),
    };
    if whole_text.is_empty()
        || whole_text.len() > 6
        || !whole_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(refuse());
    }
    if !frac_text.is_empty()
        && (frac_text.len() > 3 || !frac_text.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(refuse());
    }

    // Bounds make this arithmetic total: whole <= 999_999 and unit <= 2^40, so
    // whole * unit <= 1.1e18 < u64::MAX; frac <= 999, so frac * unit <= 1.1e15.
    // Integer throughout — no float rounding to reason about.
    let whole: u64 = whole_text.parse().map_err(|_| refuse())?;
    let mut bytes = whole * unit;
    if !frac_text.is_empty() {
        let frac: u64 = frac_text.parse().map_err(|_| refuse())?;
        bytes += frac * unit / 10_u64.pow(frac_text.len() as u32);
    }
    if bytes == 0 {
        return Err(refuse());
    }
    Ok(bytes)
}

/// Parse `cpu_quota` against its closed grammar: `^[0-9]{1,3}%$`, with the
/// integer in `1..=MAX_CPU_QUOTA_PERCENT`.
pub fn parse_cpu_quota(value: &str) -> Result<u32, String> {
    let refuse = || {
        format!(
            "provider_config.cpu_quota is not a percentage this binding accepts \
             (one to three digits followed by '%', from 1% to \
             {MAX_CPU_QUOTA_PERCENT}% — the instance has 2 vCPU, so a higher \
             quota is unenforceable). It is refused rather than sanitized \
             because it is interpolated into a root-installed systemd drop-in. \
             The value is not echoed."
        )
    };
    let Some(digits) = value.strip_suffix('%') else {
        return Err(refuse());
    };
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    let percent: u32 = digits.parse().map_err(|_| refuse())?;
    if percent == 0 || percent > MAX_CPU_QUOTA_PERCENT {
        return Err(refuse());
    }
    Ok(percent)
}

impl ProviderConfig {
    /// Parse with defaults.
    ///
    /// An absent or null object is not an error: the desktop sends one when
    /// the user accepted every schema default. Keys this binding does not know
    /// are ignored rather than refused — the desktop does not validate
    /// `provider_config` against `config_schema`, and the same agent record is
    /// redeployable across bindings, so a Kubernetes key must not brick a GCE
    /// deploy. A key this binding *does* know always has its value validated.
    pub fn parse(value: &serde_json::Value) -> Result<Self, String> {
        let empty = serde_json::Map::new();
        let fields = match value {
            serde_json::Value::Null => &empty,
            serde_json::Value::Object(map) => map,
            _ => return Err("provider_config must be a JSON object".to_string()),
        };

        // Before any trimming: `str::trim` strips a trailing newline, so a
        // scan placed after it would accept `"2G\n"`.
        reject_control_characters(fields)?;

        let text = |key: &str, default: &str| -> String {
            fields
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .unwrap_or(default)
                .to_string()
        };

        let inactivity_seconds = match fields.get("inactivity_seconds") {
            None | Some(serde_json::Value::Null) => Some(DEFAULT_INACTIVITY_SECONDS),
            Some(value) => {
                let seconds = value.as_u64().ok_or_else(|| {
                    "provider_config.inactivity_seconds must be a non-negative integer".to_string()
                })?;
                // 0 is the blessed indefinite opt-in and must parse; the
                // refusal for it lives in `render::plan`, with a message
                // naming the prerequisite.
                (seconds > 0).then_some(seconds)
            }
        };

        let memory_max = text("memory_max", DEFAULT_MEMORY_MAX);
        let memory_max_bytes = parse_memory_max(&memory_max)?;
        let cpu_quota = text("cpu_quota", DEFAULT_CPU_QUOTA);
        parse_cpu_quota(&cpu_quota)?;

        Ok(Self {
            project: text("project", DEFAULT_PROJECT),
            zone: text("zone", DEFAULT_ZONE),
            instance: text("instance", DEFAULT_INSTANCE),
            memory_max,
            memory_max_bytes,
            cpu_quota,
            inactivity_seconds,
        })
    }
}
```

- [ ] **Step 7: Write `main.rs` with dispatch only**

`crates/buzz-backend-gcp/src/main.rs`:

```rust
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
```

The single-stage parse and the placeholder `Deploy` arm are both temporary: Task 5 replaces `respond` with the two-stage form the `relay-mesh` refusal requires. Nothing else in this file changes after that.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS — 4 integration tests (`tests/wire.rs`) and 13 unit tests (`config`).

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): provider skeleton with info and closed config grammars"
```

---

## Task 5: The raw-JSON `relay-mesh` refusal, before deserialization

Resolves review **P1-4**.

**Files:**
- Modify: `crates/buzz-backend-gcp/src/main.rs`
- Create: `crates/buzz-backend-gcp/src/reconcile.rs` (pure-phase skeleton; Task 12 completes it)
- Create: `crates/buzz-backend-gcp/tests/fixtures/provider-wire/deploy-ordinary-provider.request.json`
- Create: `crates/buzz-backend-gcp/tests/fixtures/provider-wire/deploy-relay-mesh.response.json`
- Create: `crates/buzz-backend-gcp/tests/fixtures/provider-wire/deploy-relay-mesh-padded.response.json`
- Create: `crates/buzz-backend-gcp/tests/fixtures/provider-wire/deploy-no-owner.response.json`
- Create: `crates/buzz-backend-gcp/tests/fixtures/provider-wire/deploy-ordinary-provider.response.json`
- Modify: `crates/buzz-backend-gcp/tests/wire.rs`

**Interfaces:**
- Produces: `refuse_relay_mesh(raw: &serde_json::Value) -> Option<String>` and a two-stage `respond` (raw `Value` first, typed `Request` second) in `main.rs`; `deploy_agent(&wire::DeployRequest) -> Result<String, String>`; `reconcile::deploy(cfg: &ProviderConfig, agent: &AgentPayload) -> Result<String, String>`.
- Consumes: `buzz_backend_core::wire::{self, Request, Response}`, `crate::config::ProviderConfig`.

**Why it cannot live after deserialization.** `docs/remote-agents.md:1453-1458` requires refusing a deploy "whose provider is `relay-mesh`". The shared `AgentPayload` deliberately does not type the raw `provider` field (`wire.rs:35-42`), so by the time a typed `DeployRequest` exists the evidence is gone. The Kubernetes binding parses to `serde_json::Value` first (`main.rs:65-68`), calls the refusal (`:70-72`), and only then deserializes (`:74-77`). This binding does exactly the same.

**Why the comparison is trimmed.** The Kubernetes rationale (`main.rs:97-113`) applies verbatim: the desktop's own layers disagree about padding — two of them trim, the deploy guard did not — and the payload's non-blank helper preserves surrounding whitespace on a non-blank value. *A backstop that shares its bypass with the layer it backs is not a backstop.*

**Why all four deploy goldens are offline.** They stop before any transport exists:

| fixture | stops at | why it needs no GCP |
|---|---|---|
| `deploy-relay-mesh` | `refuse_relay_mesh` | before deserialization |
| `deploy-relay-mesh-padded` | `refuse_relay_mesh` | before deserialization |
| `deploy-ordinary-provider` | the indefinite-lifetime refusal in `render::plan` | pure rendering; `Remote` is constructed after it |
| `deploy-no-owner` | `build_env`'s owner check | pure; same reason |

`deploy-ordinary-provider` is the control the design asks for: an ordinary `provider` value (`openai`) that is **not** refused as shared compute, proven by the response naming the lifetime prerequisite instead. It is authored here rather than shared because a GCE request must name a GCE target, and it names a project that does not exist so a developer with an authenticated `gcloud` cannot have `cargo test` touch real infrastructure.

- [ ] **Step 1: Write the control request fixture**

`crates/buzz-backend-gcp/tests/fixtures/provider-wire/deploy-ordinary-provider.request.json`:

```json
{
  "op": "deploy",
  "request_id": "req-gcp-1",
  "agent": {
    "name": "ordinary",
    "relay_url": "wss://relay.example",
    "private_key_nsec": "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
    "auth_tag": "tag-1",
    "provider": "openai"
  },
  "provider_config": {
    "project": "buzz-fixture-no-such-project",
    "zone": "asia-south1-a",
    "instance": "buzz-fixture-no-such-instance",
    "inactivity_seconds": 0
  }
}
```

- [ ] **Step 2: Write the four response goldens**

`deploy-relay-mesh.response.json` and `deploy-relay-mesh-padded.response.json` — identical content, because the whole point of the padded case is that padding changes nothing:

```json
{"ok":false,"error":"deploy refused: this agent is configured for shared compute (relay-mesh), which runs on the relay rather than on a GCE instance. Switch the agent to a local runtime before deploying it to GCE."}
```

`deploy-no-owner.response.json` — produced by the shared `build_env`, so this text is identical to the Kubernetes binding's:

```json
{"ok":false,"error":"deploy refused: neither auth_tag nor launch.owner_pubkey resolved — without an owner the agent cannot honor !shutdown"}
```

`deploy-ordinary-provider.response.json`:

```json
{"ok":false,"error":"deploy refused: provider_config.inactivity_seconds is 0 (indefinite lifetime), which this binding does not support yet: it requires Restart=on-failure, and docs/remote-agents.md withholds that until the harness clean-exit contract is pinned (Known Defect 6). Set a positive number of seconds."}
```

- [ ] **Step 3: Write the failing fixture test**

Append to `crates/buzz-backend-gcp/tests/wire.rs`:

```rust
/// This binding's response goldens, plus the one GCE-specific request.
/// Everything else is shared and lives in `buzz-backend-core`.
fn local_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provider-wire")
}

fn local(name: &str) -> String {
    std::fs::read_to_string(local_fixtures().join(name))
        .unwrap_or_else(|e| panic!("could not read fixture {name}: {e}"))
}

/// Every deploy response fixture, compared after parsing so a field rename
/// fails here rather than in a desktop reading `undefined`.
#[test]
fn deploy_responses_match_their_fixtures() {
    // (case, request comes from the shared fixture directory)
    let cases = [
        ("deploy-relay-mesh", true),
        ("deploy-relay-mesh-padded", true),
        ("deploy-no-owner", true),
        ("deploy-ordinary-provider", false),
    ];

    // The list must cover every response fixture on disk. A literal array is
    // never empty, so what can actually go wrong is a fixture added to the
    // directory and never added here — a suite that exercises one case fewer
    // than it appears to.
    let mut on_disk: Vec<String> = std::fs::read_dir(local_fixtures())
        .expect("could not read the fixture directory")
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter_map(|name| Some(name.strip_suffix(".response.json")?.to_string()))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = cases.iter().map(|(c, _)| (*c).to_string()).collect();
    listed.sort();
    assert_eq!(on_disk, listed, "response fixtures and cases disagree");

    for (case, shared) in cases {
        let request_name = format!("{case}.request.json");
        let request = if shared {
            fixture(&request_name)
        } else {
            local(&request_name)
        };
        let (stdout, code) = run(&binary(), &request);
        assert_eq!(code, 0, "{case}: a produced response must exit 0");
        assert_eq!(
            stdout.matches('\n').count(),
            1,
            "{case}: expected exactly one line, got {stdout:?}"
        );
        let actual: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{case}: {e}: {stdout:?}"));
        let expected: serde_json::Value =
            serde_json::from_str(&local(&format!("{case}.response.json"))).unwrap();
        assert_eq!(actual, expected, "{case}: response drifted from its fixture");
    }
}

/// The control, stated as a property rather than only as a golden: an
/// ordinary provider value must not trip the shared-compute backstop, and the
/// request must reach the deploy path's own gates.
#[test]
fn an_ordinary_provider_is_not_refused_as_shared_compute() {
    let (stdout, _) = run(&binary(), &local("deploy-ordinary-provider.request.json"));
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let error = v["error"].as_str().unwrap_or_default();
    assert!(
        !error.contains("relay-mesh"),
        "the backstop fired on an ordinary provider: {error}"
    );
    assert!(
        error.contains("indefinite lifetime"),
        "the request must reach the deploy path's own gates: {error}"
    );
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cargo test -p buzz-backend-gcp --test wire`
Expected: FAIL — `deploy-relay-mesh: response drifted from its fixture`, because `respond` still answers `deploy is not implemented yet`.

- [ ] **Step 5: Implement the two-stage dispatch**

In `crates/buzz-backend-gcp/src/main.rs`, change the module list and import to:

```rust
mod config;
mod reconcile;

use buzz_backend_core::wire::{self, Request, Response};
use std::io::Read;

/// The provider a shared-compute agent resolves to. Refused here as the
/// spec's backstop ([L2] item 3, `docs/remote-agents.md:1453-1458`): a mesh
/// agent runs on the relay's compute, so starting a systemd unit for it would
/// create a second, contending consumer of the same agent identity — an I4
/// violation across substrates.
const RELAY_MESH_PROVIDER: &str = "relay-mesh";
```

Replace `respond` in full and add the two functions below it:

```rust
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
/// Trimmed before comparing: the desktop's own layers disagree about padding
/// (`relay_mesh.rs:17` and `effective_config/mod.rs:46` trim; the deploy guard
/// at `agents_deploy.rs:116` did not), and `non_blank` preserves surrounding
/// whitespace on a non-blank value. A backstop that shares its bypass with the
/// layer it backs is not a backstop.
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
```

Create `crates/buzz-backend-gcp/src/reconcile.rs`:

```rust
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
```

- [ ] **Step 6: Add the in-process guard tests**

Append to `crates/buzz-backend-gcp/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn error_of(response: &Response) -> String {
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["ok"], false, "expected a refusal: {json}");
        json["error"].as_str().unwrap_or_default().to_string()
    }

    /// The spec's backstop for the relay-mesh MUST. The desktop refuses first
    /// (`agents_deploy.rs:116`); this is the layer that owes the obligation.
    #[test]
    fn refuses_a_relay_mesh_agent() {
        let request = r#"{"op":"deploy","agent":{
            "relay_url":"wss://r","private_key_nsec":"nsec1x","provider":"relay-mesh"},
            "provider_config":{}}"#;
        assert!(error_of(&respond(request)).contains("relay-mesh"));
    }

    /// Padding must not bypass the backstop. Reachable by construction:
    /// `GlobalConfig.provider` is a bare `Option<String>` with no trim on
    /// write, and `non_blank` rejects whitespace-only while preserving
    /// surrounding whitespace on everything else.
    #[test]
    fn refuses_a_padded_relay_mesh_agent() {
        let request = r#"{"op":"deploy","agent":{
            "relay_url":"wss://r","private_key_nsec":"nsec1x","provider":"  relay-mesh  "},
            "provider_config":{}}"#;
        assert!(error_of(&respond(request)).contains("relay-mesh"));
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
```

- [ ] **Step 7: Run the tests and gate the two not-yet-reachable goldens**

Run: `cargo test -p buzz-backend-gcp`
Expected: the four `main` unit tests PASS; `deploy_responses_match_their_fixtures` FAILS on `deploy-no-owner` and `an_ordinary_provider_is_not_refused_as_shared_compute` FAILS on its second assertion, because `render::plan` does not exist yet. Add to both:

```rust
#[ignore = "enabled in Task 7, when render::plan supplies these two refusals"]
```

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS, 2 ignored.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): refuse relay-mesh from the raw wire value"
```

---

## Task 6: Naming and the two marker tiers

Resolves review **P2-2**.

**Files:**
- Create: `crates/buzz-backend-gcp/src/naming.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod naming;`)

**Interfaces:**
- Produces:
  - `naming::{MANAGED_BY, BINDING_VERSION, SHARED_SCOPE}`
  - `naming::sha256_hex(&[u8]) -> String`
  - `naming::Names::new(&AgentIdentity) -> Names` with `instance()`, `unit()`, `secret_unit()`, `env_path()`, `trail_path()`, `dropin_dir()`, `dropin_path()`, `secret_dropin_dir()`, `secret_dropin_path()`, `secret_name()`, `runtime_dir()`
  - `naming::Names::from_pubkey_hex(pubkey_hex: &str) -> Result<Names, String>` and `naming::normalize_pubkey(value: &str) -> Result<String, String>` — the operator route, used only by `remove`
  - `naming::AgentMarker { pubkey_full: String, create_intent: String }` with `render() -> String`, `parse(&str) -> Option<AgentMarker>`
  - `naming::SharedMarker { content_hash: String }` with `render() -> String`, `parse(&str) -> Option<SharedMarker>`
- Consumes: `buzz_backend_core::identity::AgentIdentity`, `sha2`, `hex`.

**Why two tiers.** A template unit is installed once and used by every instance. Stamping it with one agent's `agent-pubkey-full` and `create-intent` means the next deploy of a *different* agent rewrites the same file with a different identity, so the identity recorded on a shared file means nothing more than "whoever deployed most recently" — while the fence that reads it is asking "is this file *this* agent's?". Answering that from a shared file is wrong in both directions: it authorizes destroying a file three other agents depend on, and it refuses when the file is legitimately ours. The invariant the tests enforce is therefore *"every installed file carries the marker of its own tier"* — never *"every installed file carries the per-agent marker"*, which is enforceable only by making the shared marker a lie.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/naming.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture nsec from the shared golden payloads.
    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    fn identity() -> AgentIdentity {
        AgentIdentity::from_nsec(NSEC).unwrap()
    }

    #[test]
    fn every_path_is_derived_from_the_pubkey_not_a_display_name() {
        let id = identity();
        let n = Names::new(&id);
        let s = id.short12();
        assert_eq!(n.instance(), s);
        assert_eq!(n.unit(), format!("buzz-acp@{s}.service"));
        assert_eq!(n.secret_unit(), format!("buzz-acp-secret@{s}.service"));
        assert_eq!(n.env_path(), format!("/etc/buzz/acp-{s}.env"));
        assert_eq!(n.trail_path(), format!("/etc/buzz/acp-{s}.trail"));
        assert_eq!(
            n.dropin_path(),
            format!("/etc/systemd/system/buzz-acp@{s}.service.d/agent.conf")
        );
        assert_eq!(
            n.secret_dropin_path(),
            format!("/etc/systemd/system/buzz-acp-secret@{s}.service.d/agent.conf")
        );
        assert_eq!(n.secret_name(), format!("buzz-agent-{s}-private-key"));
        assert_eq!(n.runtime_dir(), format!("/run/buzz-acp-{s}"));
    }

    /// The instance name is what `%i` expands to and what the fetcher script's
    /// shape check enforces, so it must be exactly 12 lowercase hex.
    #[test]
    fn the_instance_name_is_twelve_lowercase_hex() {
        let n = Names::new(&identity());
        assert_eq!(n.instance().len(), 12);
        assert!(n
            .instance()
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn a_per_agent_marker_round_trips() {
        let m = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "c0ffee".to_string(),
        };
        assert_eq!(AgentMarker::parse(&m.render()).expect("parses"), m);
    }

    #[test]
    fn a_shared_marker_round_trips() {
        let m = SharedMarker {
            content_hash: sha256_hex(b"body"),
        };
        assert_eq!(SharedMarker::parse(&m.render()).expect("parses"), m);
    }

    /// The tiers must not be readable as each other. A shared file parsed as
    /// per-agent would hand a fence an identity that is not there; a per-agent
    /// file parsed as shared would hand it a content hash that is not there.
    #[test]
    fn the_two_tiers_do_not_parse_as_one_another() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "c0ffee".to_string(),
        }
        .render();
        let shared = SharedMarker {
            content_hash: sha256_hex(b"body"),
        }
        .render();
        assert!(SharedMarker::parse(&agent).is_none());
        assert!(AgentMarker::parse(&shared).is_none());
    }

    #[test]
    fn an_unmarked_file_yields_no_marker_of_either_tier() {
        let body = "# just some file\nFOO=bar\n";
        assert!(AgentMarker::parse(body).is_none());
        assert!(SharedMarker::parse(body).is_none());
    }

    /// A marker from a future binding version must not be read as ours: the
    /// artifact layout it describes is one this build does not understand.
    #[test]
    fn a_foreign_binding_version_is_not_our_marker() {
        let body = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 99\n\
             # agent-pubkey-full: {}\n# create-intent: ci\n",
            "ab".repeat(32)
        );
        assert!(AgentMarker::parse(&body).is_none());
    }

    #[test]
    fn a_marker_from_another_tool_is_not_ours() {
        let body = format!(
            "# managed-by: some-other-tool\n# binding-version: {BINDING_VERSION}\n\
             # agent-pubkey-full: {}\n# create-intent: ci\n",
            "ab".repeat(32)
        );
        assert!(AgentMarker::parse(&body).is_none());
    }

    /// `remove` names its target by pubkey, because the operator holds no
    /// key. Validation happens once, here, before the value can become a path.
    #[test]
    fn an_operator_supplied_pubkey_is_validated_then_folded() {
        let upper = "AB".repeat(32);
        assert_eq!(normalize_pubkey(&format!("  {upper}\n")).unwrap(), "ab".repeat(32));
        assert_eq!(
            Names::from_pubkey_hex(&upper).unwrap().instance(),
            "abababababab"
        );
        for bad in ["", "abc", &"ab".repeat(33), &format!("{}z", "a".repeat(63))] {
            assert!(
                normalize_pubkey(bad).is_err(),
                "accepted a malformed pubkey {bad:?}"
            );
            assert!(Names::from_pubkey_hex(bad).is_err());
        }
    }

    /// Both routes must land on the same names, or `remove` could target a
    /// path `deploy` never wrote.
    #[test]
    fn the_two_name_routes_agree() {
        let id = identity();
        let from_key = Names::new(&id);
        let from_pubkey = Names::from_pubkey_hex(id.pubkey_hex()).unwrap();
        assert_eq!(from_key.env_path(), from_pubkey.env_path());
        assert_eq!(from_key.unit(), from_pubkey.unit());
        assert_eq!(from_key.secret_name(), from_pubkey.secret_name());
        assert_eq!(from_key.dropin_path(), from_pubkey.dropin_path());
        assert_eq!(from_key.trail_path(), from_pubkey.trail_path());
    }

    /// The marker header must be exactly four contiguous lines starting at
    /// `# managed-by: `, because the observer strips it with
    /// `sed '/^# managed-by: buzz-backend-gcp$/,+3d'` before hashing the body.
    /// A fifth line would silently shift what gets hashed.
    #[test]
    fn each_marker_header_is_exactly_four_lines() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "ci".to_string(),
        }
        .render();
        let shared = SharedMarker {
            content_hash: "hh".to_string(),
        }
        .render();
        for header in [&agent, &shared] {
            assert_eq!(header.lines().count(), 4, "{header}");
            assert!(header.starts_with(&format!("# managed-by: {MANAGED_BY}\n")));
            assert!(header.ends_with('\n'));
        }
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p buzz-backend-gcp naming`
Expected: FAIL — `cannot find type Names in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/buzz-backend-gcp/src/naming.rs`:

```rust
//! Object naming and the two management-marker tiers
//! (spec §Naming and the Management Marker).
//!
//! Names come from [`AgentIdentity`], which can only be constructed by
//! decoding the nsec — so a caller-supplied pubkey or a mutable display name
//! can never reach a path this provider writes to or deletes.

use buzz_backend_core::identity::AgentIdentity;
use sha2::{Digest, Sha256};

/// The management marker's identity half. **No destructive action may touch a
/// file lacking the marker of its own tier** — that is the auto-repair fence.
pub const MANAGED_BY: &str = "buzz-backend-gcp";

/// Schema version of the artifact layout. Bump when the unit/env shape changes
/// in a way an older provider would mishandle.
pub const BINDING_VERSION: &str = "1";

/// The `scope:` value that distinguishes a provider-level marker from a
/// per-agent one. Present on shared artifacts, absent from per-agent ones.
pub const SHARED_SCOPE: &str = "provider-shared";

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Every path and name one agent implies.
#[derive(Debug, Clone)]
pub struct Names {
    instance: String,
}

impl Names {
    /// Derive every name from a provider-decoded identity.
    pub fn new(identity: &AgentIdentity) -> Self {
        Self {
            instance: identity.short12().to_string(),
        }
    }

    /// The systemd instance name, i.e. what `%i` expands to.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Full agent unit name — also the `agent_id` returned to the desktop.
    pub fn unit(&self) -> String {
        format!("buzz-acp@{}.service", self.instance)
    }

    /// The per-instance key-fetcher unit the agent unit `Requires=`.
    pub fn secret_unit(&self) -> String {
        format!("buzz-acp-secret@{}.service", self.instance)
    }

    /// Allowlisted environment, 0600 root, on the persistent boot disk.
    pub fn env_path(&self) -> String {
        format!("/etc/buzz/acp-{}.env", self.instance)
    }

    /// The durable deploy trail, 0644 root (spec §Capacity).
    pub fn trail_path(&self) -> String {
        format!("/etc/buzz/acp-{}.trail", self.instance)
    }

    /// Drop-in directory for the agent unit. An operator may keep their own
    /// files here, which is why `remove` never deletes the directory itself.
    pub fn dropin_dir(&self) -> String {
        format!("/etc/systemd/system/buzz-acp@{}.service.d", self.instance)
    }

    /// This provider's drop-in on the agent unit: `MemoryMax` and `CPUQuota`.
    pub fn dropin_path(&self) -> String {
        format!("{}/agent.conf", self.dropin_dir())
    }

    /// Drop-in directory for the fetcher unit.
    pub fn secret_dropin_dir(&self) -> String {
        format!(
            "/etc/systemd/system/buzz-acp-secret@{}.service.d",
            self.instance
        )
    }

    /// This provider's drop-in on the fetcher unit: the project and secret
    /// name the shared fetcher script reads from its environment.
    pub fn secret_dropin_path(&self) -> String {
        format!("{}/agent.conf", self.secret_dropin_dir())
    }

    /// Secret Manager resource name. Its payload is the whole
    /// secret-classified environment, not just the key.
    pub fn secret_name(&self) -> String {
        format!("buzz-agent-{}-private-key", self.instance)
    }

    /// tmpfs directory systemd creates and reaps for the fetcher unit.
    pub fn runtime_dir(&self) -> String {
        format!("/run/buzz-acp-{}", self.instance)
    }

    /// Derive every name from an **operator-supplied** full pubkey.
    ///
    /// `deploy` never uses this: it decodes the nsec and takes the identity
    /// route above. `remove` has to, because the operator holds no key — only
    /// the pubkey `list` printed. This is the single entry point where a
    /// caller-supplied identity becomes a path, so the shape is checked here
    /// and nowhere else.
    pub fn from_pubkey_hex(pubkey_hex: &str) -> Result<Self, String> {
        Ok(Self {
            instance: normalize_pubkey(pubkey_hex)?[..12].to_string(),
        })
    }
}

/// Validate and normalize an operator-supplied full pubkey to 64 lowercase hex.
///
/// Uppercase input is folded rather than refused — a pubkey copied out of a
/// UI is routinely uppercase, and the marker comparison downstream is exact,
/// so normalizing here is what keeps `remove` usable without weakening it.
pub fn normalize_pubkey(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{value:?} is not a 64-character hex agent pubkey. Copy the value \
             `buzz-backend-gcp list` prints for the agent you mean to remove."
        ));
    }
    Ok(normalized)
}

/// Read one `# <name>: <value>` header field out of a file body.
fn header_field(body: &str, name: &str) -> Option<String> {
    let prefix = format!("# {name}: ");
    body.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(|value| value.trim().to_string())
}

/// Both tiers share these two lines; neither tier is ours without both.
fn is_ours(body: &str) -> bool {
    header_field(body, "managed-by").as_deref() == Some(MANAGED_BY)
        && header_field(body, "binding-version").as_deref() == Some(BINDING_VERSION)
}

/// The header written into every artifact that belongs to exactly one agent:
/// the env file, both drop-ins, and the deploy trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMarker {
    /// Full 64-hex pubkey. The 12-hex instance name is only
    /// collision-*resistant*; this is what makes acting on it safe.
    pub pubkey_full: String,
    /// Fingerprint of the rendered spec, for divergence detection.
    pub create_intent: String,
}

impl AgentMarker {
    /// The four-line header, exactly as it appears at the top of the file.
    ///
    /// Exactly four contiguous lines beginning with `# managed-by: ` — the
    /// observer strips the header with a `sed` range anchored on that first
    /// line and a `+3` offset, so a fifth line here would change what gets
    /// hashed on the instance.
    pub fn render(&self) -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n\
             # binding-version: {BINDING_VERSION}\n\
             # agent-pubkey-full: {}\n\
             # create-intent: {}\n",
            self.pubkey_full, self.create_intent
        )
    }

    /// Parse a per-agent marker from a file body.
    ///
    /// `None` means "not ours, at this tier, at this binding version" — which
    /// is a refusal to act, never a licence to overwrite. A shared artifact's
    /// header parses to `None` here because it declares a scope.
    pub fn parse(body: &str) -> Option<Self> {
        if !is_ours(body) || header_field(body, "scope").is_some() {
            return None;
        }
        Some(Self {
            pubkey_full: header_field(body, "agent-pubkey-full")?,
            create_intent: header_field(body, "create-intent")?,
        })
    }
}

/// The header written into every artifact shared by all instances: the two
/// template units and the fetcher script.
///
/// It states exactly what is true — this provider wrote it, at this binding
/// version, with this content — and **nothing that is not**. In particular it
/// carries no pubkey and no create-intent, because a shared file belongs to no
/// single agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedMarker {
    /// SHA-256 of the artifact's content excluding this four-line header.
    pub content_hash: String,
}

impl SharedMarker {
    /// The four-line header. Same four-line rule as [`AgentMarker::render`].
    pub fn render(&self) -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n\
             # binding-version: {BINDING_VERSION}\n\
             # scope: {SHARED_SCOPE}\n\
             # content-hash: {}\n",
            self.content_hash
        )
    }

    /// Parse a provider-level marker from a file body. A per-agent header
    /// parses to `None` here because it declares no scope.
    pub fn parse(body: &str) -> Option<Self> {
        if !is_ours(body) || header_field(body, "scope").as_deref() != Some(SHARED_SCOPE) {
            return None;
        }
        Some(Self {
            content_hash: header_field(body, "content-hash")?,
        })
    }
}
```

Add `mod naming;` to `main.rs`.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p buzz-backend-gcp naming`
Expected: PASS — 11 tests.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): pubkey-derived naming and two marker tiers"
```

---

## Task 7: `render.rs` — six artifacts, the non-secret allowlist, and the hardened fetcher

Resolves review **P1-7** and **P2-8**.

**Files:**
- Create: `crates/buzz-backend-gcp/src/render.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod render;`)
- Modify: `crates/buzz-backend-gcp/src/reconcile.rs` (extend the pure phase to call `render::plan`)
- Modify: `crates/buzz-backend-gcp/tests/wire.rs` (drop the two `#[ignore]` attributes)

**Interfaces:**
- Produces:
  - `render::RemoteFile { path: String, mode: &'static str, body: String }`
  - `render::SharedArtifact { file: RemoteFile, content_hash: String }`
  - `render::Plan { per_agent: Vec<RemoteFile>, shared: Vec<SharedArtifact>, secret_env: BTreeMap<String, String>, create_intent: String, trail_header: String }` with `Plan::secret_body(&self) -> String` and `Plan::redacted_secret_body(&self) -> String`
  - `render::plan(agent: &AgentPayload, cfg: &ProviderConfig, names: &Names, identity: &AgentIdentity, generation: &str) -> Result<Plan, String>`
  - `render::dry_run_report(plan: &Plan, names: &Names, trail_record: &str) -> String`
  - `render::NON_SECRET_KEYS: [&str; 9]`
  - `render::harness_basename(agent: &AgentPayload) -> String`
- Consumes: `buzz_backend_core::env::{build_env, AuthoritativeInputs, START_NONCE_KEY}`, `buzz_backend_core::identity::AgentIdentity`, `buzz_backend_core::wire::AgentPayload`, `crate::capacity` (tests only), `crate::config::ProviderConfig`, `crate::naming::{sha256_hex, AgentMarker, Names, SharedMarker}`.

**Classification is an allowlist of non-secret keys, not a denylist of known-secret ones.** A denylist leaves `BUZZ_AUTH_TAG` — a bearer credential the relay treats as interchangeable with a resolved owner pubkey (`docs/remote-agents.md:1416-1419`) — plus every `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GITHUB_TOKEN` that tiers 1 and 2 routinely carry, on the **persistent boot disk**, where a disk snapshot or image capture picks them up. The desktop already refuses to draw that distinction: `env_secrets_from_request` treats *every* non-empty value in `env_vars`, `launch.env`, and `launch.policy_env` as redaction-worthy (`backend.rs:395-415`), and its doc comment says why. A provider whose classification is narrower than the redaction defending it has the polarity backwards. The list below is closed and the default is *secret*, so a new authoritative key added to `buzz_backend_core::env` lands on the safe side without anyone remembering to classify it.

**Six artifacts, not five.** The design's §Remote Artifacts lists five files; its §fetcher hardening independently requires the fetcher's `--project` to come from `cfg.project`. Those two requirements meet where the two-tier marker rule resolves them: `project` is per-agent configuration, the fetcher unit and script are *shared*, and a shared artifact must carry no per-agent data. So the project reaches the fetcher through a **sixth artifact** — a per-agent drop-in on `buzz-acp-secret@<short12>.service` carrying two `Environment=` lines. Both shared files then stay byte-identical across every agent, which is exactly what makes the strict no-op strict.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/render.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use buzz_backend_core::wire::DeployRequest;

    /// A second valid nsec, for the cross-agent shared-artifact test.
    const OTHER_NSEC: &str = "nsec1jlfhdrsltzfvxs026lfa96hnvnzp7hcwe93uh6ehy8tmt0znf03qxdgm79";

    fn request() -> DeployRequest {
        let raw = buzz_backend_core::harness::fixture("deploy-full-launch.request.json");
        serde_json::from_str(&raw).expect("the shared full-launch payload parses")
    }

    fn gcp_config() -> ProviderConfig {
        ProviderConfig::parse(&serde_json::json!({})).unwrap()
    }

    fn names_for(req: &DeployRequest) -> Names {
        Names::new(&AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap())
    }

    fn plan_for(req: &DeployRequest) -> Plan {
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef").expect("renders")
    }

    /// Look a per-agent file up by its **exact** path: both drop-ins end in
    /// `.service.d/agent.conf`, so a suffix match would silently pick one.
    fn per_agent<'a>(plan: &'a Plan, path: &str) -> &'a str {
        &plan
            .per_agent
            .iter()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("no per-agent file at {path}"))
            .body
    }

    fn shared<'a>(plan: &'a Plan, suffix: &str) -> &'a str {
        &plan
            .shared
            .iter()
            .find(|a| a.file.path.ends_with(suffix))
            .unwrap_or_else(|| panic!("no shared artifact ending in {suffix}"))
            .file
            .body
    }

    #[test]
    fn the_unit_never_restarts_an_intentional_exit() {
        let p = plan_for(&request());
        let unit = shared(&p, "/buzz-acp@.service");
        assert!(unit.contains("\nRestart=no\n"), "bounded lifetime is Restart=no");
        assert!(
            !unit.contains("Restart=always") && !unit.contains("Restart=on-failure"),
            "[L1] item 5: a supervisor must never resurrect an intentional clean exit"
        );
    }

    #[test]
    fn the_harness_receives_the_termination_signal_directly() {
        let p = plan_for(&request());
        let unit = shared(&p, "/buzz-acp@.service");
        // No shell wrapper: a wrapper would swallow SIGTERM ([L1] item 3).
        assert!(unit.contains("\nExecStart=/usr/local/bin/buzz-acp\n"));
        assert!(unit.contains("\nTimeoutStopSec=120\n"));
    }

    /// The fetcher unit deliberately omits the agent unit's metadata block —
    /// that block being cgroup-wide is the entire reason a second unit exists.
    #[test]
    fn the_fetcher_unit_is_sandboxed_but_can_still_reach_the_metadata_server() {
        let p = plan_for(&request());
        let unit = shared(&p, "/buzz-acp-secret@.service");
        for directive in [
            "ProtectSystem=strict",
            "ProtectHome=true",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "RestrictSUIDSGID=true",
            "LockPersonality=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "RuntimeDirectoryMode=0750",
        ] {
            assert!(unit.contains(directive), "the fetcher unit lacks {directive}");
        }
        assert!(
            !unit.contains("IPAddressDeny"),
            "IPAddressDeny would block the metadata fetch this unit exists to perform"
        );
    }

    #[test]
    fn the_fetcher_script_checks_its_argument_before_using_it() {
        let p = plan_for(&request());
        let script = shared(&p, "/buzz-acp-fetch-key");
        assert!(script.starts_with("#!/bin/bash\n"), "must start with a shebang");
        assert!(script.contains("set -euo pipefail"));
        assert!(script.contains(r#"[ "$#" -eq 1 ]"#), "arity check");
        assert!(script.contains("^[0-9a-f]{12}$"), "instance shape check");
        assert!(script.contains("--project="), "explicit project, never ambient");
        assert!(script.contains("secret.env.tmp"), "atomic temp file");
        assert!(script.contains("mv -f"), "rename into place");
        assert!(
            script.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            "a script run by systemd inherits systemd's environment, not a shell's"
        );
    }

    #[test]
    fn the_project_reaches_the_fetcher_through_a_per_agent_dropin() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = ProviderConfig::parse(&serde_json::json!({"project": "other-project"})).unwrap();
        let p = plan(&req.agent, &cfg, &names, &identity, "deadbeef").unwrap();
        let dropin = per_agent(&p, &names.secret_dropin_path());
        assert!(dropin.contains("Environment=BUZZ_GCP_PROJECT=other-project"));
        assert!(dropin.contains(&format!("Environment=BUZZ_GCP_SECRET={}", names.secret_name())));
        // …and the shared script stays identical for every agent and project.
        assert!(!shared(&p, "/buzz-acp-fetch-key").contains("other-project"));
    }

    #[test]
    fn an_owner_is_always_present_in_the_environment() {
        let req = request();
        let p = plan_for(&req);
        let env = per_agent(&p, &names_for(&req).env_path());
        assert!(
            p.secret_body().contains("BUZZ_AUTH_TAG=") || env.contains("BUZZ_ACP_AGENT_OWNER="),
            "without an owner the harness cannot match !shutdown"
        );
    }

    #[test]
    fn the_dropin_carries_the_configured_limits() {
        let req = request();
        let p = plan_for(&req);
        let dropin = per_agent(&p, &names_for(&req).dropin_path());
        assert!(dropin.contains("\nMemoryMax=2G\n"));
        assert!(dropin.contains("\nCPUQuota=150%\n"));
    }

    /// Design §Testing's secret-leak test, defined over **every**
    /// secret-classified value rather than only the nsec. The old nsec-only
    /// grep is what let this class of defect through: it passes while four
    /// tokens leak.
    #[test]
    fn no_secret_classified_value_reaches_any_artifact() {
        let mut req = request();
        let launch = req.agent.launch.as_mut().expect("the fixture has a launch block");
        launch
            .env
            .insert("ANTHROPIC_API_KEY".into(), "sk-ant-LEAK-ME-0001".into());
        launch
            .policy_env
            .insert("SOME_NEW_TOKEN".into(), "tok-LEAK-ME-0002".into());
        req.agent.auth_tag = Some("tag-LEAK-ME-0003".into());

        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let p = plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef").unwrap();
        let warnings = crate::capacity::warning_lines(
            1024 * 1024 * 1024,
            1024 * 1024 * 1024,
            &names.unit(),
            2 * 1024 * 1024 * 1024,
        );
        let record = crate::capacity::trail_record(
            "2026-08-05T09:14:02Z",
            "deadbeef",
            &p.create_intent,
            &warnings,
        );
        let report = dry_run_report(&p, &names, &record);

        let leaked = [
            req.agent.private_key_nsec.as_str(),
            "sk-ant-LEAK-ME-0001",
            "tok-LEAK-ME-0002",
            "tag-LEAK-ME-0003",
        ];
        let mut surfaces: Vec<(String, &str)> = Vec::new();
        for f in &p.per_agent {
            surfaces.push((f.path.clone(), f.body.as_str()));
        }
        for a in &p.shared {
            surfaces.push((a.file.path.clone(), a.file.body.as_str()));
        }
        surfaces.push(("trail header".into(), p.trail_header.as_str()));
        surfaces.push(("trail record".into(), record.as_str()));
        surfaces.push(("dry-run report".into(), report.as_str()));
        for warning in &warnings {
            surfaces.push(("stderr warning".into(), warning.as_str()));
        }

        for (where_, text) in surfaces {
            for value in leaked {
                assert!(
                    !text.contains(value),
                    "{where_} leaked a secret-classified value"
                );
            }
        }

        // …and every one of their keys must be in the Secret Manager payload.
        for key in [
            "BUZZ_PRIVATE_KEY",
            "NOSTR_PRIVATE_KEY",
            "BUZZ_AUTH_TAG",
            "ANTHROPIC_API_KEY",
            "SOME_NEW_TOKEN",
        ] {
            assert!(
                p.secret_env.contains_key(key),
                "{key} was not classified as secret"
            );
        }
        let secret = p.secret_body();
        for value in leaked {
            assert!(secret.contains(value), "the secret payload lost a value");
        }
    }

    /// The on-disk env file holds allowlisted keys and nothing else — if a
    /// non-allowlisted key appears there, that *is* the finding.
    #[test]
    fn the_on_disk_env_file_holds_only_allowlisted_keys() {
        let req = request();
        let p = plan_for(&req);
        for line in per_agent(&p, &names_for(&req).env_path()).lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let key = line.split('=').next().unwrap_or_default();
            assert!(
                NON_SECRET_KEYS.contains(&key),
                "{key} is on the boot disk but is not allowlisted"
            );
        }
    }

    #[test]
    fn dry_run_redacts_every_secret_value_but_keeps_the_keys() {
        let req = request();
        let names = names_for(&req);
        let p = plan_for(&req);
        let report = dry_run_report(&p, &names, "deploy T generation=g intent=i\n");
        assert!(report.contains("BUZZ_PRIVATE_KEY=[REDACTED]"));
        assert!(report.contains("NOSTR_PRIVATE_KEY=[REDACTED]"));
        assert!(!report.contains("nsec1"));
        // The on-disk file is printed verbatim, because every value in it is
        // allowlisted by construction.
        assert!(report.contains("BUZZ_RELAY_URL=\"wss://relay.example\""));
    }

    /// Per-agent artifacts carry the per-agent marker; shared artifacts carry
    /// the provider-level marker and **no** pubkey or intent. This replaces
    /// `every_installed_file_carries_the_marker`, which asserted the wrong
    /// invariant — one enforceable only by making the shared marker a lie.
    #[test]
    fn every_installed_file_carries_the_marker_of_its_own_tier() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let p = plan_for(&req);

        for f in &p.per_agent {
            let marker = AgentMarker::parse(&f.body)
                .unwrap_or_else(|| panic!("{} carries no per-agent marker", f.path));
            assert_eq!(marker.pubkey_full, identity.pubkey_hex());
            assert_eq!(marker.create_intent, p.create_intent);
            assert!(SharedMarker::parse(&f.body).is_none());
        }
        assert!(AgentMarker::parse(&p.trail_header).is_some());

        for a in &p.shared {
            let marker = SharedMarker::parse(&a.file.body)
                .unwrap_or_else(|| panic!("{} carries no provider-level marker", a.file.path));
            assert_eq!(marker.content_hash, a.content_hash);
            assert!(
                AgentMarker::parse(&a.file.body).is_none(),
                "{} claims an agent identity it cannot have",
                a.file.path
            );
            assert!(
                !a.file.body.contains(identity.pubkey_hex()),
                "{} embeds an agent pubkey",
                a.file.path
            );
            assert!(
                !a.file.body.contains(&p.create_intent),
                "{} embeds an agent create-intent",
                a.file.path
            );
        }
    }

    /// Two different agents must render byte-identical shared artifacts, or
    /// the "zero mutation, shared files included" no-op is unreachable.
    #[test]
    fn shared_artifacts_are_identical_across_agents() {
        let a = plan_for(&request());
        let mut req = request();
        req.agent.private_key_nsec = OTHER_NSEC.to_string();
        let b = plan_for(&req);

        let digest = |p: &Plan| -> Vec<(String, String, String)> {
            p.shared
                .iter()
                .map(|s| {
                    (
                        s.file.path.clone(),
                        s.content_hash.clone(),
                        s.file.body.clone(),
                    )
                })
                .collect()
        };
        assert_eq!(digest(&a), digest(&b));
    }

    /// The declared content hash must be the hash of what is actually below
    /// the header, or the observer's recomputation would disagree with every
    /// freshly rendered file.
    #[test]
    fn a_shared_marker_declares_the_hash_of_its_own_body() {
        let p = plan_for(&request());
        for a in &p.shared {
            let header = SharedMarker {
                content_hash: a.content_hash.clone(),
            }
            .render();
            let without_header = a.file.body.replace(header.as_str(), "");
            assert_eq!(
                sha256_hex(without_header.as_bytes()),
                a.content_hash,
                "{} declares a hash of something other than its body",
                a.file.path
            );
        }
    }

    #[test]
    fn env_values_are_quoted_so_spaces_survive_systemd_parsing() {
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .policy_env
            .insert("BUZZ_ACP_SESSION_TITLE".into(), "a b".into());
        let p = plan_for(&req);
        // BUZZ_ACP_SESSION_TITLE is not allowlisted, so it lands in the secret
        // payload — where the same quoting rule applies.
        assert!(p.secret_body().contains("BUZZ_ACP_SESSION_TITLE=\"a b\""));
    }

    #[test]
    fn an_env_value_containing_a_newline_is_refused() {
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .env
            .insert("MULTILINE".into(), "a\nb".into());
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let err = plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef")
            .expect_err("a raw newline in an EnvironmentFile value must be refused");
        assert!(err.contains("MULTILINE"), "{err}");
        assert!(!err.contains("a\nb"), "the refusal must not echo the value");
    }

    #[test]
    fn a_divergent_spec_produces_a_different_create_intent() {
        let a = plan_for(&request());
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .policy_env
            .insert("BUZZ_ACP_MODEL".into(), "different".into());
        assert_ne!(a.create_intent, plan_for(&req).create_intent);
    }

    /// The generation must not perturb the intent, or every deploy would look
    /// divergent and the reconciler would replace a healthy unit on each
    /// Start. `BUZZ_MANAGED_AGENT_START_NONCE` *is* the generation and lives
    /// in the on-disk environment, so the intent feed must skip it by name.
    #[test]
    fn the_generation_does_not_perturb_the_create_intent() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = gcp_config();
        let a = plan(&req.agent, &cfg, &names, &identity, "aaaaaaaa").unwrap();
        let b = plan(&req.agent, &cfg, &names, &identity, "bbbbbbbb").unwrap();
        assert_eq!(a.create_intent, b.create_intent);
        assert_ne!(
            per_agent(&a, &names.env_path()),
            per_agent(&b, &names.env_path()),
            "the nonce still has to reach the agent"
        );
    }

    /// A different memory limit is a different unit, so it must diverge.
    #[test]
    fn a_changed_resource_limit_diverges_the_intent() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let a = plan(&req.agent, &gcp_config(), &names, &identity, "g").unwrap();
        let cfg = ProviderConfig::parse(&serde_json::json!({"memory_max": "1G"})).unwrap();
        let b = plan(&req.agent, &cfg, &names, &identity, "g").unwrap();
        assert_ne!(a.create_intent, b.create_intent);
    }

    /// v1 ships bounded lifetimes only, and the refusal must name the
    /// prerequisite rather than silently downgrading the request.
    #[test]
    fn the_indefinite_lifetime_is_refused_with_its_prerequisite_named() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = ProviderConfig::parse(&serde_json::json!({"inactivity_seconds": 0})).unwrap();
        let err = plan(&req.agent, &cfg, &names, &identity, "deadbeef").expect_err("refused");
        assert!(err.contains("indefinite lifetime"));
        assert!(err.contains("clean-exit contract"));
    }

    /// `launch.command` is resolved against the *desktop's* PATH, so only its
    /// basename is meaningful on the instance.
    #[test]
    fn the_harness_command_is_reduced_to_a_basename() {
        let mut req = request();
        req.agent.launch.as_mut().unwrap().command = Some("/opt/homebrew/bin/codex-acp".into());
        assert_eq!(harness_basename(&req.agent), "codex-acp");
        req.agent.launch.as_mut().unwrap().command = None;
        assert_eq!(harness_basename(&req.agent), "buzz-acp");
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p buzz-backend-gcp render`
Expected: FAIL — `cannot find function plan in this scope`.

- [ ] **Step 3: Implement the renderer**

Prepend to `crates/buzz-backend-gcp/src/render.rs`:

```rust
//! Pure rendering of the remote artifacts (spec §Remote Artifacts).
//!
//! No IO: a payload in, the exact bytes of every file out. Every
//! conformance-critical decision — supervision policy, the secret split, both
//! marker tiers — is visible here and testable without touching GCP.

use crate::config::ProviderConfig;
use crate::naming::{sha256_hex, AgentMarker, Names, SharedMarker};
use buzz_backend_core::env::{build_env, AuthoritativeInputs, START_NONCE_KEY};
use buzz_backend_core::identity::AgentIdentity;
use buzz_backend_core::wire::AgentPayload;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The **only** environment keys that may live on the persistent boot disk.
///
/// An allowlist, not a denylist: the default is *secret*, so a new
/// authoritative key added to `buzz_backend_core::env` lands on the safe side
/// without anyone remembering to classify it. Note that
/// `buzz_backend_core::env::AUTHORITATIVE_KEYS` is **not** this list — three
/// of its twelve entries are credentials.
///
/// Each entry is non-secret for a stated reason: a public endpoint, a public
/// nostr pubkey, a binary name already visible in `ps` and in the unit file,
/// argv already visible in `ps`, a mode name, a list of public pubkeys, an
/// integer number of seconds, and a per-attempt correlator that authorizes
/// nothing and is already in the journal.
pub const NON_SECRET_KEYS: [&str; 9] = [
    "BUZZ_ACP_AGENT_ARGS",
    "BUZZ_ACP_AGENT_COMMAND",
    "BUZZ_ACP_AGENT_OWNER",
    "BUZZ_ACP_EXIT_AFTER_INACTIVITY",
    "BUZZ_ACP_MCP_COMMAND",
    "BUZZ_ACP_RESPOND_TO",
    "BUZZ_ACP_RESPOND_TO_ALLOWLIST",
    "BUZZ_MANAGED_AGENT_START_NONCE",
    "BUZZ_RELAY_URL",
];

/// A file to install on the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    pub path: String,
    /// Octal mode string passed to `install -m`.
    pub mode: &'static str,
    pub body: String,
}

/// A shared artifact plus the hash its provider-level marker declares.
///
/// The hash travels alongside so the reconciler can decide "write or skip"
/// without re-deriving it from a body that already embeds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedArtifact {
    pub file: RemoteFile,
    /// SHA-256 of the artifact's content excluding the four marker lines.
    pub content_hash: String,
}

/// Everything one deploy needs to write.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Files belonging to exactly this agent. Rewritten by a create or a
    /// fenced replace.
    pub per_agent: Vec<RemoteFile>,
    /// Files shared by every instance. Written only when absent, or when the
    /// installed content differs from what this provider would render.
    pub shared: Vec<SharedArtifact>,
    /// The Secret Manager payload. Never written to a file this provider
    /// installs, never logged, redacted by `dry-run`.
    pub secret_env: BTreeMap<String, String>,
    /// Fingerprint of everything that decides the unit's behavior, excluding
    /// the generation and every secret *value*.
    pub create_intent: String,
    /// The per-agent marker the deploy trail gets when it is first created.
    pub trail_header: String,
}

impl Plan {
    /// The exact bytes uploaded as the secret version.
    pub fn secret_body(&self) -> String {
        env_file_body(&self.secret_env, "")
    }

    /// The same document with every value replaced and every key intact —
    /// the form `dry-run` prints.
    pub fn redacted_secret_body(&self) -> String {
        let mut out = String::new();
        for key in self.secret_env.keys() {
            out.push_str(key);
            out.push_str("=[REDACTED]\n");
        }
        out
    }
}

/// Quote a value for a systemd `EnvironmentFile`.
///
/// systemd accepts double-quoted values with backslash escapes. Quoting
/// unconditionally is simpler to reason about than deciding per value and
/// costs nothing. Raw newlines are refused upstream rather than escaped here,
/// because a multi-line `EnvironmentFile` value is exactly the ambiguity this
/// binding declines to introduce into a file systemd parses.
fn quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn env_file_body(env: &BTreeMap<String, String>, header: &str) -> String {
    let mut out = String::from(header);
    for (key, value) in env {
        out.push_str(key);
        out.push('=');
        out.push_str(&quote(value));
        out.push('\n');
    }
    out
}

/// Build a shared artifact: hash the content, then stamp the marker onto it.
///
/// `prologue` is content that must precede the header — a shebang. It is part
/// of the hashed content, so a tampered shebang is detected like any other
/// content change.
fn shared_artifact(
    path: &str,
    mode: &'static str,
    prologue: &str,
    content: &str,
) -> SharedArtifact {
    let content_hash = sha256_hex(format!("{prologue}{content}").as_bytes());
    let marker = SharedMarker {
        content_hash: content_hash.clone(),
    };
    SharedArtifact {
        file: RemoteFile {
            path: path.to_string(),
            mode,
            body: format!("{prologue}{}{content}", marker.render()),
        },
        content_hash,
    }
}

/// The harness binary this agent needs, as a bare name.
///
/// `launch.command` is resolved against the **desktop's** PATH; on the VM that
/// path is meaningless, so only the basename carries over. `buzz-acp` is the
/// default because that is what the unit's `ExecStart` runs when the payload
/// names nothing.
pub fn harness_basename(agent: &AgentPayload) -> String {
    agent
        .launch
        .as_ref()
        .and_then(|launch| launch.command.as_deref())
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .and_then(|command| command.rsplit('/').next())
        .unwrap_or("buzz-acp")
        .to_string()
}

/// Render every artifact for one deploy.
pub fn plan(
    agent: &AgentPayload,
    cfg: &ProviderConfig,
    names: &Names,
    identity: &AgentIdentity,
    generation: &str,
) -> Result<Plan, String> {
    // v1 supervises bounded lifetimes only. `inactivity_seconds: 0` is a legal,
    // blessed request, but honoring it needs `Restart=on-failure`, which
    // `docs/remote-agents.md` withholds until the harness clean-exit contract
    // is pinned (Known Defect 6): an undefended exit convention would let the
    // supervisor restart agents that exited on purpose, violating I5. When the
    // contract lands this becomes a one-line change.
    let Some(inactivity) = cfg.inactivity_seconds else {
        return Err(
            "deploy refused: provider_config.inactivity_seconds is 0 (indefinite \
             lifetime), which this binding does not support yet: it requires \
             Restart=on-failure, and docs/remote-agents.md withholds that until \
             the harness clean-exit contract is pinned (Known Defect 6). Set a \
             positive number of seconds."
                .to_string(),
        );
    };

    let env = build_env(
        agent,
        AuthoritativeInputs {
            generation,
            inactivity_seconds: Some(inactivity),
            // A systemd `EnvironmentFile` on a 38 GB disk has no meaningful cap.
            max_env_bytes: None,
        },
    )?;

    // Both destinations are files systemd parses line by line, so a raw
    // newline in a value is the same class of defect as §Value grammars —
    // refused, not escaped, and never echoed.
    for (key, value) in &env {
        if value.contains('\n') || value.contains('\r') {
            return Err(format!(
                "deploy refused: the value of {key} contains a line break. Both \
                 environment destinations are files systemd parses line by line, \
                 so such a value cannot be represented unambiguously. The value \
                 is not echoed."
            ));
        }
    }

    // Split by sensitivity. Precedence is already resolved, so this moves
    // values without changing them, and both files are `EnvironmentFile=`
    // entries on the same unit — so no value and no precedence changes.
    let mut disk_env: BTreeMap<String, String> = BTreeMap::new();
    let mut secret_env: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in env {
        if NON_SECRET_KEYS.contains(&key.as_str()) {
            disk_env.insert(key, value);
        } else {
            secret_env.insert(key, value);
        }
    }

    let shared = vec![
        shared_artifact(
            "/etc/systemd/system/buzz-acp@.service",
            "0644",
            "",
            AGENT_UNIT,
        ),
        shared_artifact(
            "/etc/systemd/system/buzz-acp-secret@.service",
            "0644",
            "",
            FETCHER_UNIT,
        ),
        shared_artifact(
            "/usr/local/sbin/buzz-acp-fetch-key",
            "0755",
            "#!/bin/bash\n",
            FETCH_KEY_SCRIPT,
        ),
    ];

    // The intent fingerprint covers everything that decides the unit's
    // behavior, and deliberately excludes two things: the generation (which
    // changes on every attempt, so including it would make every deploy look
    // divergent) and every secret *value* (which must not be reconstructible
    // from a marker any reader of a 0644 file can see). Secret *keys* are
    // included, because adding or removing one does change behavior.
    let mut hasher = Sha256::new();
    let mut feed = |label: &str, value: &str| {
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    };
    for (key, value) in &disk_env {
        if key == START_NONCE_KEY {
            continue;
        }
        feed("disk-key", key);
        feed("disk-value", value);
    }
    for key in secret_env.keys() {
        feed("secret-key", key);
    }
    feed("memory_max", &cfg.memory_max);
    feed("cpu_quota", &cfg.cpu_quota);
    feed("project", &cfg.project);
    feed("secret-name", &names.secret_name());
    for artifact in &shared {
        feed("shared", &artifact.content_hash);
    }
    let create_intent = hex::encode(hasher.finalize());

    let marker = AgentMarker {
        pubkey_full: identity.pubkey_hex().to_string(),
        create_intent: create_intent.clone(),
    }
    .render();

    let per_agent = vec![
        RemoteFile {
            path: names.env_path(),
            mode: "0600",
            body: env_file_body(&disk_env, &marker),
        },
        RemoteFile {
            path: names.dropin_path(),
            mode: "0644",
            body: format!(
                "{marker}[Service]\nMemoryMax={}\nCPUQuota={}\n",
                cfg.memory_max, cfg.cpu_quota
            ),
        },
        RemoteFile {
            path: names.secret_dropin_path(),
            mode: "0644",
            // The fetcher's two inputs. They live here, per agent, rather than
            // in the shared script, because a shared artifact carries no
            // per-agent data — see the tier rules in `naming.rs`.
            body: format!(
                "{marker}[Service]\n\
                 Environment=BUZZ_GCP_PROJECT={}\n\
                 Environment=BUZZ_GCP_SECRET={}\n",
                cfg.project,
                names.secret_name()
            ),
        },
    ];

    Ok(Plan {
        per_agent,
        shared,
        secret_env,
        create_intent,
        trail_header: marker,
    })
}

/// The operator-facing render of a plan, with every secret-classified value
/// replaced by `[REDACTED]`.
///
/// This is the binding's secret-classification audit: the on-disk env file is
/// printed **verbatim** because every value in it is allowlisted by
/// construction — if a non-allowlisted key appears there, that *is* the
/// finding — and the Secret Manager payload is printed keys-only, so a human
/// can confirm the allowlist held for one particular payload.
pub fn dry_run_report(plan: &Plan, names: &Names, trail_record: &str) -> String {
    let mut out = format!(
        "agent_id: {}\nsecret:   {}\n",
        names.unit(),
        names.secret_name()
    );
    for file in &plan.per_agent {
        out.push_str(&format!("\n=== {} (mode {}) ===\n", file.path, file.mode));
        out.push_str(&file.body);
    }
    for artifact in &plan.shared {
        out.push_str(&format!(
            "\n=== {} (mode {}, provider-shared) ===\n",
            artifact.file.path, artifact.file.mode
        ));
        out.push_str(&artifact.file.body);
    }
    out.push_str(&format!("\n=== {} (mode 0644) ===\n", names.trail_path()));
    out.push_str(&plan.trail_header);
    out.push_str(trail_record);
    out.push_str(&format!(
        "\n=== secretmanager://{} (values redacted) ===\n",
        names.secret_name()
    ));
    out.push_str(&plan.redacted_secret_body());
    out
}

/// The shared agent unit.
///
/// Mirrors the hardened unit the deployment already runs, with three
/// deliberate differences: `Restart=no` (I5 — a supervisor must never
/// resurrect an intentional exit), `TimeoutStopSec=120` (I3 — room for
/// in-flight drain, presence→offline, and a graceful relay close before
/// SIGKILL), and the second `EnvironmentFile` holding the tmpfs-materialized
/// secret environment. `MemoryMax`/`CPUQuota` live in the per-instance drop-in
/// so they are configurable.
const AGENT_UNIT: &str = "\
[Unit]
Description=Buzz ACP agent harness (%i)
After=network-online.target buzz-block-metadata-agent.service buzz-acp-secret@%i.service
Wants=network-online.target
Requires=buzz-block-metadata-agent.service buzz-acp-secret@%i.service

[Service]
Type=simple
User=buzzacp
Group=buzzacp
WorkingDirectory=/var/lib/buzzacp
EnvironmentFile=/etc/buzz/acp-%i.env
EnvironmentFile=/run/buzz-acp-%i/secret.env
ExecStart=/usr/local/bin/buzz-acp
Restart=no
TimeoutStopSec=120
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/buzzacp
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=169.254.169.254/32
TasksMax=512
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
";

/// The shared key-fetcher unit.
///
/// A separate unit rather than an `ExecStartPre=+` on the agent unit, because
/// that unit's `IPAddressDeny=169.254.169.254/32` is a **cgroup-wide** BPF
/// filter: it blocks every process in the unit including one running as root,
/// so a metadata-authenticated gcloud call cannot live inside it.
///
/// `RuntimeDirectoryMode=0750` root:root is correct and must not be widened.
/// systemd's *manager* reads `EnvironmentFile=` as root before dropping to
/// `User=buzzacp` — proven on this host by the running `buzz-acp.service`,
/// which has `User=buzzacp` and `EnvironmentFile=/etc/buzz/acp.env` at mode
/// 0600 root:root and starts.
///
/// Every sandbox directive from the agent unit is carried over except
/// `IPAddressDeny`, whose absence is this unit's entire reason to exist.
const FETCHER_UNIT: &str = "\
[Unit]
Description=Materialize the Buzz agent secret environment for %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
RuntimeDirectory=buzz-acp-%i
RuntimeDirectoryMode=0750
ExecStart=/usr/local/sbin/buzz-acp-fetch-key %i
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
StandardOutput=journal
StandardError=journal
";

/// The shared fetcher script — the highest-privilege code this design
/// installs, so every guard is explicit rather than left to the implementer.
///
/// `BUZZ_GCP_PROJECT` and `BUZZ_GCP_SECRET` arrive from the per-agent drop-in
/// on `buzz-acp-secret@<instance>.service`, and neither is defaulted. An
/// omitted `--project` works today only because the VM happens to carry
/// `core/project=zoop-innovation` in its gcloud config; a
/// `gcloud config unset project`, a different service account, or a VM rebuilt
/// from a changed image turns that into `latest` resolved against the wrong
/// project or none at all.
const FETCH_KEY_SCRIPT: &str = r#"# Materialize one agent's secret environment onto tmpfs.
set -euo pipefail

# A script run by systemd inherits systemd's environment, not a login shell's.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Invoked with zero arguments — a hand-typed `systemctl start
# buzz-acp-secret@` — this would otherwise write to `/run/buzz-acp-/secret.env`.
if [ "$#" -eq 1 ]; then
  instance="$1"
else
  echo "buzz-acp-fetch-key: exactly one instance argument is required" >&2
  exit 2
fi

# %i is a systemd instance name and reaches this script unescaped. The naming
# rule derives exactly 12 lowercase hex, so anything else is not one of ours
# and must not become a Secret Manager name or a filesystem path.
if ! [[ "$instance" =~ ^[0-9a-f]{12}$ ]]; then
  echo "buzz-acp-fetch-key: instance name is not 12 lowercase hex characters" >&2
  exit 2
fi

: "${BUZZ_GCP_PROJECT:?buzz-acp-fetch-key: BUZZ_GCP_PROJECT is not set}"
: "${BUZZ_GCP_SECRET:?buzz-acp-fetch-key: BUZZ_GCP_SECRET is not set}"

dir="/run/buzz-acp-$instance"
out="$dir/secret.env"
tmp="$dir/secret.env.tmp"

umask 077
trap 'rm -f "$tmp"' EXIT

# Created with its final mode and owner, then filled, then renamed. A partial
# secret.env is not a truncated key — it is an EnvironmentFile missing its
# later lines, which for this binding's allowlist means an agent that starts
# *without* BUZZ_AUTH_TAG and fails identity assembly for a reason that looks
# nothing like a write error. `mv` within one tmpfs is a rename, so the agent
# unit never observes a half-written file. The fetched value is never echoed:
# the journal is output, and L2 item 5 forbids secret material there.
install -m 0400 -o buzzacp -g buzzacp /dev/null "$tmp"
gcloud secrets versions access latest \
  --project="$BUZZ_GCP_PROJECT" \
  --secret="$BUZZ_GCP_SECRET" > "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
"#;
```

Add `mod render;` to `main.rs`.

- [ ] **Step 4: Extend the pure phase so the two ignored fixtures reach their refusals**

Replace the body of `deploy` in `crates/buzz-backend-gcp/src/reconcile.rs`:

```rust
/// Run one deploy to a terminal outcome.
pub fn deploy(cfg: &ProviderConfig, agent: &AgentPayload) -> Result<String, String> {
    // Step 0: identity from the nsec, before any mutation and before any
    // transport exists — so every refusal reachable without GCP stays
    // reachable without GCP.
    let identity = AgentIdentity::from_nsec(&agent.private_key_nsec)?;
    let names = crate::naming::Names::new(&identity);
    let generation = buzz_backend_core::identity::new_generation();
    let plan = crate::render::plan(agent, cfg, &names, &identity, &generation)?;
    let _ = plan;
    Err("deploy is not implemented yet".to_string())
}
```

Remove the two `#[ignore]` attributes added in Task 5 Step 7.

- [ ] **Step 5: Run the full crate suite**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS — 20 `render` tests, plus `deploy_responses_match_their_fixtures` now matching all four goldens (`deploy-no-owner` from `build_env`, `deploy-ordinary-provider` from the indefinite-lifetime refusal) and `an_ordinary_provider_is_not_refused_as_shared_compute` no longer ignored.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): render six artifacts across two marker tiers"
```

---

## Task 8: Capacity arithmetic and the durable deploy trail

Resolves review **P1-1**.

**Files:**
- Create: `crates/buzz-backend-gcp/src/capacity.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod capacity;`)

**Interfaces:**
- Produces:
  - `capacity::parse_reported_bytes(&str) -> Option<u64>`
  - `capacity::warning_lines(available_bytes: u64, reserved_bytes: u64, unit: &str, requested_bytes: u64) -> Vec<String>`
  - `capacity::trail_record(timestamp: &str, generation: &str, create_intent: &str, warnings: &[String]) -> String`
  - `capacity::now_rfc3339() -> String`
- Consumes: `chrono`.

**Why the warning is written to the instance and not only to stderr.** `invoke_provider` builds `stderr_redacted` and consults it in exactly two places: when the child exited non-zero (`backend.rs:252-260`) and when no line of stdout parses as JSON (`:271-280`). On a successful deploy it falls through to `Ok(response)` at `:287` and the buffer is dropped; `provider_deploy` then reads one field, `agent_id` (`:529-532`). A successful deploy carrying a capacity warning is a clean success in the UI, followed later by an OOM kill with nothing connecting the two. Adding a `warning` field to the response would not be *rejected* — the unknown-field check exists only for `info` (`:48-63`) — it would simply never be read, and `docs/remote-agents.md:421` defines the deploy response as `{"ok": true, "agent_id": str}`, so inventing a field is a protocol change this binding has no authority to make unilaterally. The warning is therefore recorded durably in the per-agent trail, and `list` surfaces it (Task 13). The same text still goes to stderr, which costs nothing and *is* surfaced on the two failure paths above.

The trail obeys the same [L2] item 5 rule as any other output: timestamps, the generation, the create-intent digest, and capacity arithmetic — **never an environment value**. It is a 0644 file on a shared host, so treating it as public is the only safe reading.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/capacity.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_reported_sizes_parse() {
        assert_eq!(parse_reported_bytes("2147483648"), Some(2 * GIB));
        assert_eq!(parse_reported_bytes("  1024  "), Some(1024));
        // `infinity` is systemd's "no bound", which reserves nothing.
        assert_eq!(parse_reported_bytes("infinity"), None);
        assert_eq!(parse_reported_bytes(""), None);
        assert_eq!(parse_reported_bytes("[not set]"), None);
    }

    #[test]
    fn an_agent_that_fits_produces_no_warning() {
        assert!(warning_lines(2_899_102_924, 0, "buzz-acp@abc.service", 2 * GIB).is_empty());
        // Exactly filling the headroom is not overcommit.
        assert!(warning_lines(2 * GIB, GIB, "buzz-acp@abc.service", GIB).is_empty());
    }

    #[test]
    fn an_overcommit_names_the_numbers_the_unit_and_the_remedy() {
        let w = warning_lines(2_899_102_924, 2 * GIB, "buzz-acp@abc.service", 2 * GIB);
        assert_eq!(w.len(), 3);
        assert!(w.iter().all(|l| l.starts_with("warning capacity: ")));
        assert!(w[0].contains("2.7G available"));
        assert!(w[0].contains("reserve 2G"));
        assert!(w[1].contains("buzz-acp@abc.service"));
        assert!(w[2].contains("e2-standard-4"), "the warning must name a remedy");
    }

    #[test]
    fn a_trail_record_carries_the_correlators_and_every_warning() {
        let warnings = warning_lines(GIB, GIB, "buzz-acp@abc.service", GIB);
        let record = trail_record(
            "2026-08-05T09:14:02Z",
            "3f9c1a04",
            "8d1e77c2b0a4deadbeef0000000000000000000000000000000000000000cafe",
            &warnings,
        );
        let lines: Vec<&str> = record.lines().collect();
        assert_eq!(
            lines[0],
            "deploy 2026-08-05T09:14:02Z generation=3f9c1a04 intent=8d1e77c2b0a4"
        );
        assert_eq!(lines.len(), 1 + warnings.len());
        assert!(record.ends_with('\n'), "records must append cleanly");
    }

    #[test]
    fn a_clean_deploy_still_leaves_a_record() {
        let record = trail_record("2026-08-05T09:14:02Z", "3f9c1a04", &"a".repeat(64), &[]);
        assert_eq!(record.lines().count(), 1);
    }

    #[test]
    fn the_timestamp_is_second_precision_utc() {
        let now = now_rfc3339();
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(now.len(), 20, "{now}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp capacity`
Expected: FAIL — `cannot find function parse_reported_bytes`.

- [ ] **Step 3: Implement**

Prepend to `crates/buzz-backend-gcp/src/capacity.rs`:

```rust
//! Memory headroom arithmetic and the durable deploy trail (spec §Capacity).
//!
//! Overcommit is a **warning, not a refusal**: the operator asked for the risk
//! to be reported, not vetoed, and a provider that vetoes a deploy the
//! operator understands is a provider they will work around. The hard part is
//! not computing the warning; it is putting it somewhere the operator will
//! actually see it — see `reconcile`, which writes it, and `operator::list`,
//! which reads it back.

/// One gibibyte, the unit the warning quotes and the instance is sized in.
pub const GIB: u64 = 1024 * 1024 * 1024;

/// Parse a size **systemd itself reported**: always a plain byte count, or the
/// literal `infinity` when no bound is set.
///
/// Deliberately separate from `config::parse_memory_max`, which is the closed
/// grammar for *operator input* and caps at six digits. Different jobs on
/// different data: one guards a root-installed drop-in against injection, the
/// other reads back a ten-digit number systemd printed.
pub fn parse_reported_bytes(value: &str) -> Option<u64> {
    let text = value.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("infinity") {
        return None;
    }
    text.parse().ok()
}

/// Render a byte count the way the warning quotes it.
fn human(bytes: u64) -> String {
    if bytes % GIB == 0 {
        format!("{}G", bytes / GIB)
    } else {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    }
}

/// The overcommit warning, or an empty vector when the new agent fits.
///
/// Three lines rather than one: the arithmetic, the consequence, and the
/// remedy. They are appended verbatim to the deploy trail and each is
/// individually greppable, which is what `list` relies on.
pub fn warning_lines(
    available_bytes: u64,
    reserved_bytes: u64,
    unit: &str,
    requested_bytes: u64,
) -> Vec<String> {
    if reserved_bytes.saturating_add(requested_bytes) <= available_bytes {
        return Vec::new();
    }
    vec![
        format!(
            "warning capacity: the instance has {} available; existing units reserve {}.",
            human(available_bytes),
            human(reserved_bytes)
        ),
        format!(
            "warning capacity: adding {unit} ({}) may cause OOM kills.",
            human(requested_bytes)
        ),
        "warning capacity: lower memory_max or resize the instance to e2-standard-4."
            .to_string(),
    ]
}

/// One deploy-trail record: the deploy line, then one line per warning.
///
/// Carries timestamps, the generation, the create-intent digest, and capacity
/// arithmetic — **never an environment value**. The trail is a 0644 file on a
/// shared host, so treating it as public is the only safe reading.
pub fn trail_record(
    timestamp: &str,
    generation: &str,
    create_intent: &str,
    warnings: &[String],
) -> String {
    // The intent is 64 hex characters; 12 is enough to correlate and short
    // enough to read at a glance. Taken by `chars()` so the function is total
    // for any input, not only the hex its callers happen to pass.
    let short_intent: String = create_intent.chars().take(12).collect();
    let mut record = format!("deploy {timestamp} generation={generation} intent={short_intent}\n");
    for warning in warnings {
        record.push_str(warning);
        record.push('\n');
    }
    record
}

/// The current UTC instant, second precision, as the trail spells it.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
```

Add `mod capacity;` to `main.rs`.

- [ ] **Step 4: Run the whole crate**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS — the 6 capacity tests plus every earlier test, including `no_secret_classified_value_reaches_any_artifact`, which now compiles because `crate::capacity` exists.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): capacity warning and durable deploy trail"
```

---

## Task 9: `remote.rs` — the IAP SSH transport

Resolves review **P1-2**.

**Files:**
- Create: `crates/buzz-backend-gcp/src/remote.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod remote;`)

**Interfaces:**
- Produces:
  - `remote::Output { stdout: String, stderr: String, code: i32 }` with `ok(&self) -> bool`
  - `remote::Remote::new(project: &str, zone: &str, instance: &str) -> Result<Remote, String>`
  - `Remote::gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String>`
  - `Remote::run(&self, script: &str) -> Result<Output, String>`
  - `Remote::install(&self, file: &RemoteFile) -> Result<(), String>`
  - `Remote::append(&self, path: &str, mode: &str, header: &str, record: &str) -> Result<(), String>`
  - `remote::sq(value: &str) -> String` — POSIX single-quoting, reused by `observe` and `operator`
- Consumes: `crate::render::RemoteFile`.

**Security rule for this module:** no secret value may ever appear in an argv element. Bodies go on stdin. That is enforced structurally by `install` taking the whole `RemoteFile` and never formatting `body` into a command string, and it is sound because `gcloud compute ssh` execs a real `ssh` that forwards local stdin to the remote command (measured — see Global Constraints).

**Why `PATH` is prepended.** The provider is exec'd by a Tauri app inheriting launchd's `/usr/bin:/bin:/usr/sbin:/sbin`. `gcloud` installs to `/opt/homebrew/bin`, `/usr/local/bin`, or `~/.local/bin` — none of which are on that `PATH` — so a bare `Command::new("gcloud")` fails to resolve for a reason that has nothing to do with GCP. The Kubernetes binding already carries this exact fix and names the same cause (`crates/buzz-backend-kubernetes/src/client.rs:12-47`). Two details carry over verbatim because they are the parts that are easy to get wrong: mutating the process's own `PATH` is sound here (one process per operation, done before any child exists, `client.rs:36-40`), and empty entries in the inherited `PATH` are **dropped** rather than propagated, because an empty entry resolves as the current directory (`client.rs:29-32`).

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/remote.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn file(path: &str, mode: &'static str, body: &str) -> RemoteFile {
        RemoteFile {
            path: path.to_string(),
            mode,
            body: body.to_string(),
        }
    }

    #[test]
    fn the_install_command_never_carries_the_body() {
        let script = install_script(&file(
            "/etc/buzz/acp-abc.env",
            "0600",
            "SUPER_SENSITIVE=1\n",
        ));
        assert!(script.contains("/dev/stdin"));
        assert!(script.contains("'/etc/buzz/acp-abc.env'"));
        assert!(script.contains("-m 0600"));
        assert!(
            !script.contains("SUPER_SENSITIVE"),
            "the body must travel on stdin, never in the command"
        );
    }

    #[test]
    fn every_privileged_step_is_non_interactive() {
        let script = install_script(&file(
            "/etc/systemd/system/buzz-acp@abc.service.d/agent.conf",
            "0644",
            "",
        ));
        assert!(script.contains("sudo -n mkdir -p '/etc/systemd/system/buzz-acp@abc.service.d'"));
        assert!(script.contains("sudo -n install"));
        // A bare `sudo` on a prompting host would consume the piped body as
        // keystrokes and write a truncated root-owned unit file.
        assert!(
            !script.contains("sudo mkdir") && !script.contains("sudo install"),
            "a privileged step without -n can prompt"
        );
    }

    #[test]
    fn the_append_script_creates_the_file_once_then_appends() {
        let script = append_script("/etc/buzz/acp-abc.trail", "0644", "# managed-by: x\n");
        assert!(script.contains("if [ ! -e '/etc/buzz/acp-abc.trail' ]"));
        assert!(script.contains("sudo -n install -m 0644 /dev/stdin '/etc/buzz/acp-abc.trail'"));
        assert!(script.contains("sudo -n tee -a '/etc/buzz/acp-abc.trail'"));
    }

    /// `gcloud` already selects `StrictHostKeyChecking=yes` against its own
    /// known-hosts file, keyed by `HostKeyAlias` rather than by IP. Passing
    /// `no` would be a strict *downgrade* of a check that is already correct —
    /// while installing root-owned unit files over that same channel.
    #[test]
    fn the_ssh_argv_never_downgrades_host_key_checking() {
        let argv = ssh_argv("proj", "zone-a", "inst", "true");
        assert!(
            !argv.iter().any(|a| a.contains("StrictHostKeyChecking")),
            "the provider must pass no StrictHostKeyChecking option at all"
        );
        assert!(argv.iter().any(|a| a == "--tunnel-through-iap"));
        assert!(argv.iter().any(|a| a == "--project=proj"));
        assert!(argv.iter().any(|a| a == "--zone=zone-a"));
        assert!(argv.iter().any(|a| a == "inst"));
        // The script reaches the remote as `--command`, so stdin stays free
        // for the file body.
        let command = argv.iter().position(|a| a == "--command").expect("--command");
        assert_eq!(argv[command + 1], "true");
    }

    #[test]
    fn single_quoting_survives_an_embedded_quote() {
        assert_eq!(sq("plain"), "'plain'");
        assert_eq!(sq("it's"), r"'it'\''s'");
    }

    #[test]
    fn the_prepended_path_puts_the_gcloud_directories_first() {
        let home = std::path::PathBuf::from("/Users/x");
        let joined = prepended_path(Some(home.as_path()), &OsString::from("/usr/bin:/bin"))
            .expect("join");
        let dirs: Vec<String> = std::env::split_paths(&joined)
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            dirs,
            [
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/Users/x/.local/bin",
                "/usr/bin",
                "/bin"
            ]
        );
    }

    /// An empty inherited `PATH` splits into one empty entry, which POSIX
    /// resolves as the current directory — never a place `gcloud` may be found.
    #[test]
    fn empty_path_entries_are_dropped_not_propagated() {
        let joined = prepended_path(None, &OsString::from("")).expect("join");
        let dirs: Vec<String> = std::env::split_paths(&joined)
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(dirs, ["/opt/homebrew/bin", "/usr/local/bin"]);
    }

    /// A bare `NotFound` from `Command::spawn` tells the operator nothing
    /// actionable, and the cause has nothing to do with GCP.
    #[test]
    fn the_not_found_error_names_the_remedy() {
        let message = gcloud_not_found();
        assert!(message.contains("gcloud"));
        assert!(message.contains("/opt/homebrew/bin"));
        assert!(
            message.contains("Google Cloud CLI"),
            "the operator needs to know what to install"
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp remote`
Expected: FAIL — `cannot find function install_script in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/buzz-backend-gcp/src/remote.rs`:

```rust
//! The `gcloud compute ssh` transport (spec §Transport, §Remote Artifacts).
//!
//! Every file body travels on **stdin**. Nothing sensitive is ever formatted
//! into a command string: argv is visible in `ps` on the instance and lands in
//! shell history, and the desktop's redaction can reach neither.
//!
//! `gcloud compute ssh` execs a real `ssh` with the remote command as trailing
//! argv, and `ssh` forwards local stdin to it — measured on this host, 30
//! bytes in and a matching md5 out. That is what makes the stdin install path
//! sound with no `scp` staging and no remote temp file.

use crate::render::RemoteFile;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Directories prepended to `PATH` before the first `gcloud` spawn.
///
/// The provider is exec'd by a Tauri app inheriting launchd's minimal
/// `/usr/bin:/bin:/usr/sbin:/sbin`, which contains none of the places `gcloud`
/// installs to. Same fix and same cause as
/// `crates/buzz-backend-kubernetes/src/client.rs:12-19`.
const PATH_PREPEND: [&str; 2] = ["/opt/homebrew/bin", "/usr/local/bin"];

/// One completed `gcloud` invocation.
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

impl Output {
    /// Did the process exit 0? Every caller must consult this: a `gcloud`
    /// that fails prints nothing useful on stdout, and treating an empty
    /// stdout as an empty result is how an auth failure becomes a silent
    /// success.
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// A bound instance this provider can run commands on.
pub struct Remote {
    project: String,
    zone: String,
    instance: String,
}

/// Quote a value for a single-quoted POSIX shell context.
pub fn sq(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Compute the new `PATH` value: `gcloud` directories first, inherited entries
/// after, in order. Pure, so the ordering is testable without mutating the
/// process environment.
fn prepended_path(home: Option<&Path>, existing: &OsStr) -> Option<OsString> {
    let mut dirs: Vec<PathBuf> = PATH_PREPEND.iter().map(PathBuf::from).collect();
    if let Some(home) = home {
        dirs.push(home.join(".local/bin"));
    }
    // An empty inherited PATH splits into one empty entry, which POSIX
    // resolves as the current directory — never a place `gcloud` may be found.
    // Drop empties rather than propagate them.
    dirs.extend(std::env::split_paths(existing).filter(|p| !p.as_os_str().is_empty()));
    std::env::join_paths(dirs).ok()
}

/// Prepend the `gcloud` directories to this process's own `PATH`.
///
/// Modifying the provider's environment is sound here: one process per
/// operation, called before any child exists, and the only child that reads it
/// is the `gcloud` this exists for.
fn prepend_gcloud_path() {
    let home = std::env::var_os("HOME");
    let existing = std::env::var_os("PATH").unwrap_or_default();
    if let Some(joined) = prepended_path(home.as_ref().map(Path::new), &existing) {
        std::env::set_var("PATH", joined);
    }
}

/// Is `command` an executable somewhere on the current `PATH`?
fn resolves_on_path(command: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(command).is_file()))
        .unwrap_or(false)
}

/// The refusal for a `gcloud` that still does not resolve — never a bare
/// `NotFound`, whose cause has nothing to do with GCP.
fn gcloud_not_found() -> String {
    format!(
        "gcloud was not found. This provider is launched by the desktop app, \
         which inherits a minimal PATH, so {} and $HOME/.local/bin are searched \
         in addition to the inherited one. Install the Google Cloud CLI into \
         one of those directories, run `gcloud auth login`, and restart Buzz \
         Desktop.",
        PATH_PREPEND.join(", ")
    )
}

/// The remote script that installs one file, reading its body from stdin.
fn install_script(file: &RemoteFile) -> String {
    let parent = Path::new(&file.path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string());
    format!(
        "set -euo pipefail; sudo -n mkdir -p {}; sudo -n install -m {} /dev/stdin {}",
        sq(&parent),
        file.mode,
        sq(&file.path),
    )
}

/// The remote script that appends one record, creating the file with `header`
/// if it is absent.
///
/// The header is a marker — pubkey, binding version, create-intent — all of
/// which are public, so passing it in argv is safe. The *record* travels on
/// stdin along with everything a capacity warning might carry.
fn append_script(path: &str, mode: &str, header: &str) -> String {
    format!(
        "set -euo pipefail; \
         if [ ! -e {path} ]; then printf '%s' {header} | sudo -n install -m {mode} /dev/stdin {path}; fi; \
         sudo -n tee -a {path} > /dev/null",
        path = sq(path),
        mode = mode,
        header = sq(header),
    )
}

/// The full `gcloud` argv for running `script` on the instance over IAP.
///
/// Pure, so the two properties that matter — the tunnel is used, and no
/// `StrictHostKeyChecking` option is passed — are asserted without a network.
fn ssh_argv(project: &str, zone: &str, instance: &str, script: &str) -> Vec<String> {
    vec![
        "compute".to_string(),
        "ssh".to_string(),
        instance.to_string(),
        format!("--project={project}"),
        format!("--zone={zone}"),
        "--tunnel-through-iap".to_string(),
        "--quiet".to_string(),
        "--command".to_string(),
        script.to_string(),
        // Trailing options are handed to the real `ssh`. Deliberately no
        // `-o StrictHostKeyChecking`: gcloud already selects `yes` against
        // ~/.ssh/google_compute_known_hosts, keyed by HostKeyAlias.
        "--".to_string(),
        "-o".to_string(),
        "ConnectTimeout=20".to_string(),
    ]
}

impl Remote {
    /// Bind to an instance, resolving `gcloud` first.
    ///
    /// The `PATH` prepend and the resolution probe live here so there is
    /// exactly one place they can be forgotten, and so a missing `gcloud` is a
    /// named refusal rather than a `NotFound` from some later spawn.
    pub fn new(project: &str, zone: &str, instance: &str) -> Result<Self, String> {
        prepend_gcloud_path();
        if !resolves_on_path("gcloud") {
            return Err(gcloud_not_found());
        }
        Ok(Self {
            project: project.to_string(),
            zone: zone.to_string(),
            instance: instance.to_string(),
        })
    }

    /// Invoke `gcloud`, optionally piping `stdin`. Never logs `stdin`.
    pub fn gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String> {
        let mut child = Command::new("gcloud")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{} ({e})", gcloud_not_found()))?;
        if let Some(body) = stdin {
            child
                .stdin
                .take()
                .ok_or_else(|| "gcloud stdin was not available".to_string())?
                .write_all(body.as_bytes())
                .map_err(|e| format!("writing to gcloud stdin failed: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for gcloud failed: {e}"))?;
        Ok(Output {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code().unwrap_or(-1),
        })
    }

    /// Run a shell script on the instance over IAP.
    pub fn run(&self, script: &str) -> Result<Output, String> {
        self.run_with_stdin(script, None)
    }

    fn run_with_stdin(&self, script: &str, stdin: Option<&str>) -> Result<Output, String> {
        let argv = ssh_argv(&self.project, &self.zone, &self.instance, script);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.gcloud(&borrowed, stdin)
    }

    /// Install one file, body on stdin.
    pub fn install(&self, file: &RemoteFile) -> Result<(), String> {
        let out = self.run_with_stdin(&install_script(file), Some(&file.body))?;
        if !out.ok() {
            // `file.body` is deliberately absent from this message.
            return Err(format!(
                "installing {} failed (exit {}): {}",
                file.path,
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    /// Append one record to a file, creating it with `header` when absent.
    pub fn append(
        &self,
        path: &str,
        mode: &str,
        header: &str,
        record: &str,
    ) -> Result<(), String> {
        let out = self.run_with_stdin(&append_script(path, mode, header), Some(record))?;
        if !out.ok() {
            return Err(format!(
                "appending to {path} failed (exit {}): {}",
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }
}
```

Add `mod remote;` to `main.rs`.

- [ ] **Step 4: Run to verify passing**

Run: `cargo test -p buzz-backend-gcp remote`
Expected: PASS — 8 tests.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): IAP ssh transport with stdin-only bodies"
```

---

## Task 10: `secrets.rs` — Secret Manager storage behind an ownership gate

Resolves review **P2-1**.

**Files:**
- Create: `crates/buzz-backend-gcp/src/secrets.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod secrets;`)

**Interfaces:**
- Produces:
  - `secrets::labels_for(pubkey_full: &str) -> String` — the `--labels` argument value
  - `secrets::annotations_for(pubkey_full: &str) -> String` — the `--set-annotations` value
  - `secrets::verify_owned(described: &serde_json::Value, pubkey_full: &str, name: &str) -> Result<(), String>` — pure, unit-tested
  - `secrets::describe(remote: &Remote, project: &str, name: &str) -> Result<Option<serde_json::Value>, String>`
  - `secrets::store(remote: &Remote, project: &str, name: &str, pubkey_full: &str, body: &str, service_account: &str) -> Result<(), String>`
  - `secrets::destroy(remote: &Remote, project: &str, name: &str, pubkey_full: &str) -> Result<(), String>`
  - `secrets::instance_service_account(remote: &Remote, project: &str, zone: &str, instance: &str) -> Result<String, String>`
- Consumes: `crate::remote::Remote`, `crate::naming::{BINDING_VERSION, MANAGED_BY}`.

**Why the operand is a `&str` and not an `AgentIdentity`.** `deploy` holds a decoded identity, but `remove` never does — the operator has the pubkey `list` printed, not the agent's key. Taking the validated 64-hex string keeps one gate for both callers instead of inventing a second, weaker one for the operator path. `naming::normalize_pubkey` (Task 13) is where an operator-supplied value is validated before it can reach this module.

**The marker is verified before every add-version, IAM binding, and delete — not merely written.** The precedent is `secret_is_ours`, which requires *both* marker halves *and* a full-pubkey match (`crates/buzz-backend-kubernetes/src/observe.rs:64-67`, over `has_marker` at `:42-46` and `annotation_matches` at `:52-60`), and whose comment states the principle: *"Identity labels prove identity; the marker asserts protocol ownership. Without it an object that merely matches our schema fails closed"* (`observe.rs:38-41`). Without that gate, a name-matching secret created by anything else — an operator, another tool, an older binding version — receives this agent's whole secret environment as a new version *and* a grant of read access to the VM service account. **Name collision is not ownership.**

**Destroy-before-forget.** `remove` (Task 13) destroys the secret *before* deleting local marker files. The reverse order fails in a specific way: markers gone, secret still holding a live key, and no local evidence left to identify or retry it. Ordered this way an interrupted `remove` is idempotent — a re-run finds the marked files still present, the secret already gone, and treats delete-of-absent as success ([L2] item 4, `docs/remote-agents.md:1476`).

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/secrets.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use buzz_backend_core::identity::AgentIdentity;
    use serde_json::json;

    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    fn pubkey() -> String {
        AgentIdentity::from_nsec(NSEC)
            .unwrap()
            .pubkey_hex()
            .to_string()
    }

    fn described(pubkey: &str) -> serde_json::Value {
        json!({
            "name": "projects/p/secrets/buzz-agent-abc-private-key",
            "labels": {
                "managed_by": MANAGED_BY,
                "binding_version": BINDING_VERSION,
                "agent_pubkey": &pubkey[..32],
            },
            "annotations": { "agent-pubkey-full": pubkey }
        })
    }

    #[test]
    fn labels_carry_the_marker_and_the_selectable_identity() {
        let pubkey = pubkey();
        let labels = labels_for(&pubkey);
        assert!(labels.contains(&format!("managed_by={MANAGED_BY}")));
        assert!(labels.contains(&format!("binding_version={BINDING_VERSION}")));
        assert!(labels.contains(&format!("agent_pubkey={}", &pubkey[..32])));
        // GCP label values allow only lowercase letters, digits, `-` and `_`.
        assert!(labels
            .split(',')
            .filter_map(|pair| pair.split('=').nth(1))
            .all(|v| v
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')));
        // The full pubkey is 64 chars, over the 63-char label-value cap, so it
        // is an annotation instead.
        assert!(!labels.contains(&pubkey));
        assert!(annotations_for(&pubkey).contains(&pubkey));
    }

    #[test]
    fn a_fully_marked_secret_is_ours() {
        let pubkey = pubkey();
        assert!(verify_owned(&described(&pubkey), &pubkey, "s").is_ok());
    }

    /// An object that merely matches our schema fails closed: the marker is
    /// what asserts protocol ownership, and labels alone do not.
    #[test]
    fn an_unmarked_secret_is_a_refusal_never_a_takeover() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]
            .as_object_mut()
            .unwrap()
            .remove("managed_by");
        let err = verify_owned(&secret, &pubkey, "s").expect_err("must refuse");
        assert!(err.contains("not managed by"), "{err}");
    }

    #[test]
    fn a_foreign_binding_version_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]["binding_version"] = json!("99");
        assert!(verify_owned(&secret, &pubkey, "s").is_err());
    }

    /// The 12-hex name is collision-*resistant*, not collision-free, so the
    /// full-pubkey annotation is what makes acting on the name safe.
    #[test]
    fn a_short_name_collision_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["annotations"]["agent-pubkey-full"] = json!("ff".repeat(32));
        let err = verify_owned(&secret, &pubkey, "s").expect_err("must refuse");
        assert!(err.contains("belongs to pubkey"), "{err}");
    }

    #[test]
    fn a_secret_with_no_annotation_at_all_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret.as_object_mut().unwrap().remove("annotations");
        assert!(verify_owned(&secret, &pubkey, "s").is_err());
    }

    /// The refusal must name the conflicting resource so the operator can go
    /// look at it, but must never echo any payload.
    #[test]
    fn the_refusal_names_the_secret() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"] = json!({});
        let err = verify_owned(&secret, &pubkey, "buzz-agent-abc-private-key")
            .expect_err("must refuse");
        assert!(err.contains("buzz-agent-abc-private-key"), "{err}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp secrets`
Expected: FAIL — `cannot find function labels_for in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/buzz-backend-gcp/src/secrets.rs`:

```rust
//! Agent secret storage in Secret Manager (spec §Secret Manager ownership).
//!
//! The payload is the whole secret-classified environment, not just the key,
//! and it reaches `gcloud` on **stdin** — never as an argv element.
//!
//! The secret is the one artifact that does not live on the instance, so its
//! marker cannot be a header comment: it is labels plus an annotation, written
//! at create time and **verified before every add-version, IAM binding, and
//! delete**. Name collision is not ownership.

use crate::naming::{BINDING_VERSION, MANAGED_BY};
use crate::remote::Remote;

/// Label key carrying the marker's identity half.
const LABEL_MANAGED_BY: &str = "managed_by";
/// Label key carrying the marker's schema half.
const LABEL_BINDING_VERSION: &str = "binding_version";
/// Label key carrying the truncated, *selectable* identity.
const LABEL_AGENT_PUBKEY: &str = "agent_pubkey";
/// Annotation key carrying the full pubkey — 64 chars, over the 63-char cap
/// on a label value, and the operand every destructive fence compares against.
const ANNOTATION_PUBKEY_FULL: &str = "agent-pubkey-full";

/// The `--labels` argument value for `gcloud secrets create`.
///
/// Labels are the half that must be *selectable*, which is what lets `list`
/// enumerate our secrets server-side with
/// `--filter="labels.managed_by=buzz-backend-gcp"`. `pubkey_full` must
/// already be 64 lowercase hex; the truncation below is by `chars()` so the
/// function is total for any input rather than panicking on a short or
/// non-ASCII one.
pub fn labels_for(pubkey_full: &str) -> String {
    let selector: String = pubkey_full.chars().take(32).collect();
    format!(
        "{LABEL_MANAGED_BY}={MANAGED_BY},\
         {LABEL_BINDING_VERSION}={BINDING_VERSION},\
         {LABEL_AGENT_PUBKEY}={selector}"
    )
}

/// The `--set-annotations` argument value for `gcloud secrets create`.
pub fn annotations_for(pubkey_full: &str) -> String {
    format!("{ANNOTATION_PUBKEY_FULL}={pubkey_full}")
}

/// Fail-closed ownership gate over `gcloud secrets describe --format=json`.
///
/// Requires **both** marker halves *and* a full-pubkey match, mirroring
/// `secret_is_ours` in the Kubernetes binding (`observe.rs:64-67`). Pure, so
/// every branch is tested without a project.
pub fn verify_owned(
    described: &serde_json::Value,
    pubkey_full: &str,
    name: &str,
) -> Result<(), String> {
    let label = |key: &str| {
        described
            .get("labels")
            .and_then(|labels| labels.get(key))
            .and_then(serde_json::Value::as_str)
    };
    if label(LABEL_MANAGED_BY) != Some(MANAGED_BY)
        || label(LABEL_BINDING_VERSION) != Some(BINDING_VERSION)
    {
        return Err(format!(
            "secret {name} already exists but is not managed by {MANAGED_BY} at \
             binding version {BINDING_VERSION}. Refusing to modify a secret this \
             provider did not create — rename or delete it, or point this agent \
             at a different instance."
        ));
    }
    let annotated = described
        .get("annotations")
        .and_then(|annotations| annotations.get(ANNOTATION_PUBKEY_FULL))
        .and_then(serde_json::Value::as_str);
    match annotated {
        Some(pubkey) if pubkey == pubkey_full => Ok(()),
        Some(pubkey) => Err(format!(
            "secret {name} belongs to pubkey {pubkey}, not {pubkey_full}. The \
             12-hex name is collision-resistant, not collision-free; refusing \
             rather than overwriting another agent's key."
        )),
        None => Err(format!(
            "secret {name} carries no {ANNOTATION_PUBKEY_FULL} annotation, so \
             which agent it belongs to cannot be established. Refusing."
        )),
    }
}

/// Read a secret's metadata. `Ok(None)` means it does not exist.
pub fn describe(
    remote: &Remote,
    project: &str,
    name: &str,
) -> Result<Option<serde_json::Value>, String> {
    let out = remote.gcloud(
        &[
            "secrets",
            "describe",
            name,
            "--project",
            project,
            "--format=json",
        ],
        None,
    )?;
    if !out.ok() {
        if out.stderr.contains("NOT_FOUND") || out.stderr.contains("was not found") {
            return Ok(None);
        }
        return Err(format!(
            "describing secret {name} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    serde_json::from_str(&out.stdout)
        .map(Some)
        .map_err(|e| format!("could not parse the description of secret {name}: {e}"))
}

/// Create-if-absent behind the ownership gate, then add a version carrying
/// `body`, then grant the instance service account read access.
///
/// Idempotent: versions are cheap, and adding one is the only way to guarantee
/// the latest value matches this deploy.
pub fn store(
    remote: &Remote,
    project: &str,
    name: &str,
    pubkey_full: &str,
    body: &str,
    service_account: &str,
) -> Result<(), String> {
    match describe(remote, project, name)? {
        Some(existing) => verify_owned(&existing, pubkey_full, name)?,
        None => {
            let labels = labels_for(pubkey_full);
            let annotations = annotations_for(pubkey_full);
            let out = remote.gcloud(
                &[
                    "secrets",
                    "create",
                    name,
                    "--project",
                    project,
                    "--replication-policy",
                    "automatic",
                    "--labels",
                    &labels,
                    "--set-annotations",
                    &annotations,
                ],
                None,
            )?;
            if !out.ok() {
                return Err(format!(
                    "creating secret {name} failed (exit {}): {}",
                    out.code,
                    out.stderr.trim()
                ));
            }
            // Re-read and re-verify: two concurrent deploys can both observe
            // "absent" and one of them loses the create. The winner's marker
            // is the one that counts.
            let created = describe(remote, project, name)?.ok_or_else(|| {
                format!("secret {name} was created but cannot be read back")
            })?;
            verify_owned(&created, pubkey_full, name)?;
        }
    }

    let out = remote.gcloud(
        &[
            "secrets",
            "versions",
            "add",
            name,
            "--project",
            project,
            "--data-file=-",
        ],
        Some(body),
    )?;
    if !out.ok() {
        // stderr can echo the request body on some failures; report only the
        // code and the name (L2 item 5).
        return Err(format!(
            "adding a version to secret {name} failed with exit {}",
            out.code
        ));
    }

    let member = format!("serviceAccount:{service_account}");
    let out = remote.gcloud(
        &[
            "secrets",
            "add-iam-policy-binding",
            name,
            "--project",
            project,
            "--member",
            &member,
            "--role",
            "roles/secretmanager.secretAccessor",
        ],
        None,
    )?;
    if !out.ok() {
        return Err(format!(
            "granting {service_account} access to secret {name} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    Ok(())
}

/// Delete the secret and every version, behind the same ownership gate.
///
/// Delete-of-absent is success ([L2] item 4), which is what makes an
/// interrupted `remove` idempotent.
pub fn destroy(
    remote: &Remote,
    project: &str,
    name: &str,
    pubkey_full: &str,
) -> Result<(), String> {
    let Some(existing) = describe(remote, project, name)? else {
        return Ok(());
    };
    verify_owned(&existing, pubkey_full, name)?;
    let out = remote.gcloud(
        &["secrets", "delete", name, "--project", project, "--quiet"],
        None,
    )?;
    if out.ok() || out.stderr.contains("NOT_FOUND") {
        return Ok(());
    }
    Err(format!(
        "deleting secret {name} failed (exit {}): {}",
        out.code,
        out.stderr.trim()
    ))
}

/// The instance's attached service account — the identity the fetcher unit
/// authenticates as, and the only principal granted access to the secret.
pub fn instance_service_account(
    remote: &Remote,
    project: &str,
    zone: &str,
    instance: &str,
) -> Result<String, String> {
    let out = remote.gcloud(
        &[
            "compute",
            "instances",
            "describe",
            instance,
            "--project",
            project,
            "--zone",
            zone,
            "--format",
            "value(serviceAccounts[0].email)",
        ],
        None,
    )?;
    if !out.ok() {
        return Err(format!(
            "describing instance {instance} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    let email = out.stdout.trim().to_string();
    if email.is_empty() {
        return Err(format!(
            "{instance} has no attached service account, so the fetcher unit \
             would have no identity to read the secret with"
        ));
    }
    Ok(email)
}
```

Add `mod secrets;` to `main.rs`.

- [ ] **Step 4: Run to verify passing and clippy-clean**

Run: `cargo test -p buzz-backend-gcp secrets && cargo clippy -p buzz-backend-gcp --all-targets -- -D warnings`
Expected: PASS — 7 tests — and no clippy warnings.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): label-fenced Secret Manager storage"
```

---

## Task 11: `observe.rs` — systemd state and marker state, separately

Resolves the observation half of review **P1-5**.

**Files:**
- Create: `crates/buzz-backend-gcp/src/observe.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod observe;`)

**Interfaces:**
- Produces:
  - `observe::SystemdState { load_state, active_state, sub_state, unit_file_state, main_pid }` with `instance_known(&self) -> bool` and `running(&self) -> bool`
  - `observe::SharedFileState { path: String, present: bool, computed_hash: String, declared_hash: String }` with `marked(&self) -> bool`
  - `observe::MarkerState { env_file_present: bool, agent_marker: Option<AgentMarker>, trail_present: bool, shared: Vec<SharedFileState> }`
  - `observe::Observation { systemd, markers, harness_installed: bool, reserved_bytes: u64, available_bytes: u64 }`
  - `observe::SHARED_PATHS: [&str; 3]`
  - `observe::look(remote: &Remote, names: &Names, harness: &str) -> Result<Observation, String>`
  - `observe::parse_observation(stdout: &str, own_dropin: &str) -> Observation`
  - `observe::section(body: &str, name: &str) -> &str` and `observe::property(block: &str, key: &str) -> &str` — `pub(crate)`, reused by `reconcile`'s startup poll, which drives a script of the same sectioned shape
- Consumes: `crate::capacity::parse_reported_bytes`, `crate::config::parse_memory_max`, `crate::naming::{AgentMarker, Names, MANAGED_BY}`, `crate::remote::{sq, Remote}`.

**Why the two states are separate types.** The previous revision derived `unit_present` solely from the env file, so a real unit with no env file classified as `Create` and got provider files installed around it. They are independent facts and must be observed independently: systemd knows about install symlinks and running jobs; markers know about ownership. Note the trap the split makes visible — once the *template* `buzz-acp@.service` exists, `systemctl show buzz-acp@<anything>.service` reports `LoadState=loaded` for **every** instance name, so `LoadState` is not evidence that *this* instance exists. `UnitFileState=enabled` (an install symlink) or a non-`inactive` `ActiveState` is.

**Content verification, not just a declared hash.** The observer recomputes each shared file's hash on the instance with the four marker lines stripped, and reports both the computed and the declared value. A file whose declared hash disagrees with its content has been edited underneath us and is a refusal, not a rewrite. The strip uses `sed '/^# managed-by: buzz-backend-gcp$/,+3d'`, which relies on GNU `sed`'s `addr,+N` form — correct on the Debian-family GCE image, and the reason `naming.rs` pins both markers to exactly four contiguous lines.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/observe.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const OWN_DROPIN: &str = "/etc/systemd/system/buzz-acp@a1b2c3d4e5f6.service.d/agent.conf";

    fn sample(unit: &str, marker: &str, shared: &str, reserved: &str) -> String {
        format!(
            "---UNIT---\n{unit}\
             ---AGENTMARKER---\n{marker}\
             ---SHARED---\n{shared}\
             ---RESERVED---\n{reserved}\
             ---STANDING---\ninfinity\n\
             ---AVAILABLE---\n2831156\n\
             ---HARNESS---\nyes\n\
             ---TRAIL---\nyes\n\
             ---END---\n"
        )
    }

    fn our_marker() -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 1\n\
             # agent-pubkey-full: {}\n# create-intent: ci\n",
            "ab".repeat(32)
        )
    }

    fn all_shared_marked() -> String {
        SHARED_PATHS
            .iter()
            .map(|p| format!("{p}|present|hash-{p}|hash-{p}\n"))
            .collect()
    }

    #[test]
    fn a_running_instance_parses_as_live_and_owned() {
        let out = sample(
            "LoadState=loaded\nActiveState=active\nSubState=running\n\
             UnitFileState=enabled\nMainPID=4242\n",
            &our_marker(),
            &all_shared_marked(),
            &format!("{OWN_DROPIN}=2G\n/etc/systemd/system/buzz-acp@ffffffffffff.service.d/agent.conf=1G\n"),
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.systemd.instance_known());
        assert!(o.systemd.running());
        assert!(o.markers.env_file_present);
        assert!(o.markers.trail_present);
        assert!(o.markers.agent_marker.is_some());
        assert!(o.harness_installed);
        // Our own drop-in is excluded, or a redeploy would double-count itself.
        assert_eq!(o.reserved_bytes, 1024 * 1024 * 1024);
        assert_eq!(o.available_bytes, 2_831_156 * 1024);
        assert!(o.markers.shared.iter().all(|s| s.present && s.marked()));
    }

    /// A template unit makes `systemctl show` report `LoadState=loaded` for
    /// every instance name, so `LoadState` alone must never mean "this
    /// instance exists".
    #[test]
    fn a_loaded_template_is_not_evidence_that_this_instance_exists() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=disabled\nMainPID=0\n",
            "",
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(!o.systemd.instance_known());
        assert!(!o.systemd.running());
        assert!(!o.markers.env_file_present);
    }

    /// A failed unit is very much this instance: it has to be observable, or
    /// the reconciler classifies a broken agent as absent and installs over it.
    #[test]
    fn a_failed_instance_is_known() {
        let out = sample(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\n\
             UnitFileState=enabled\nMainPID=0\n",
            &our_marker(),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.systemd.instance_known());
        assert!(!o.systemd.running());
    }

    /// `active` with no main PID is not started. I4's "live" means the harness
    /// process is confirmed running, not that systemd accepted the unit.
    #[test]
    fn active_without_a_main_pid_is_not_running() {
        let out = sample(
            "LoadState=loaded\nActiveState=active\nSubState=running\n\
             UnitFileState=enabled\nMainPID=0\n",
            &our_marker(),
            &all_shared_marked(),
            "",
        );
        assert!(!parse_observation(&out, OWN_DROPIN).systemd.running());
    }

    #[test]
    fn an_absent_agent_parses_as_absent() {
        let out = sample(
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=\nMainPID=0\n",
            "",
            &SHARED_PATHS
                .iter()
                .map(|p| format!("{p}|absent||\n"))
                .collect::<String>(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(!o.systemd.instance_known());
        assert!(!o.markers.env_file_present);
        assert!(o.markers.agent_marker.is_none());
        assert!(o.markers.shared.iter().all(|s| !s.present && !s.marked()));
        assert_eq!(o.reserved_bytes, 0);
    }

    #[test]
    fn an_env_file_without_our_marker_is_present_but_unowned() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=enabled\nMainPID=0\n",
            "# hand-written by an operator\nBUZZ_RELAY_URL=\"wss://r\"\n",
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.markers.env_file_present);
        assert!(o.markers.agent_marker.is_none());
    }

    /// A shared file whose declared hash disagrees with its content has been
    /// edited underneath us.
    #[test]
    fn a_tampered_shared_file_reports_mismatched_hashes() {
        let shared = format!(
            "{}|present|computed-a|declared-b\n{}|present|h|h\n{}|present|h|h\n",
            SHARED_PATHS[0], SHARED_PATHS[1], SHARED_PATHS[2]
        );
        let o = parse_observation(
            &sample(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
                 UnitFileState=disabled\nMainPID=0\n",
                "",
                &shared,
                "",
            ),
            OWN_DROPIN,
        );
        let first = &o.markers.shared[0];
        assert!(first.marked());
        assert_ne!(first.computed_hash, first.declared_hash);
    }

    #[test]
    fn a_missing_harness_is_observed() {
        let out = sample(
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=\nMainPID=0\n",
            "",
            &all_shared_marked(),
            "",
        )
        .replace("---HARNESS---\nyes\n", "---HARNESS---\nno\n");
        assert!(!parse_observation(&out, OWN_DROPIN).harness_installed);
    }

    /// The standing `buzz-acp.service` counts toward reserved memory when it
    /// declares a bound, and contributes nothing when it says `infinity`.
    #[test]
    fn the_standing_unit_contributes_its_declared_bound() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=disabled\nMainPID=0\n",
            "",
            &all_shared_marked(),
            "",
        )
        .replace("---STANDING---\ninfinity\n", "---STANDING---\n536870912\n");
        assert_eq!(
            parse_observation(&out, OWN_DROPIN).reserved_bytes,
            512 * 1024 * 1024
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp observe`
Expected: FAIL — `cannot find function parse_observation in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/buzz-backend-gcp/src/observe.rs`:

```rust
//! Reading remote state (spec §Deploy Reconciliation step 1).
//!
//! Two independent facts, deliberately two types: what **systemd** reports
//! about the units, and what our **markers** say about ownership. Deriving one
//! from the other is how a real unit with no env file classifies as "absent"
//! and gets provider files installed around it.

use crate::capacity::parse_reported_bytes;
use crate::config::parse_memory_max;
use crate::naming::{AgentMarker, Names, MANAGED_BY};
use crate::remote::{sq, Remote};

/// The three artifacts every instance shares. Order is fixed so the observer's
/// output and the renderer's plan line up by index as well as by path.
pub const SHARED_PATHS: [&str; 3] = [
    "/etc/systemd/system/buzz-acp@.service",
    "/etc/systemd/system/buzz-acp-secret@.service",
    "/usr/local/sbin/buzz-acp-fetch-key",
];

/// What systemd reports about this agent's unit — independent of any file this
/// provider wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemdState {
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub main_pid: u32,
}

impl SystemdState {
    /// Does systemd know about **this instance**?
    ///
    /// Deliberately not `LoadState`: once the template `buzz-acp@.service`
    /// exists, `systemctl show buzz-acp@<anything>.service` reports
    /// `LoadState=loaded` for every instance name. An install symlink
    /// (`UnitFileState=enabled`) or a live job is the real evidence.
    pub fn instance_known(&self) -> bool {
        self.unit_file_state == "enabled"
            || !matches!(self.active_state.as_str(), "" | "inactive")
    }

    /// Is the harness process confirmed running? I4's "live" means *started*,
    /// not that systemd accepted the unit body.
    pub fn running(&self) -> bool {
        self.active_state == "active" && self.main_pid > 0
    }
}

/// One shared artifact as it exists on the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedFileState {
    pub path: String,
    pub present: bool,
    /// SHA-256 recomputed on the instance with the marker header stripped.
    pub computed_hash: String,
    /// The hash the file's own marker declares. Empty when unmarked.
    pub declared_hash: String,
}

impl SharedFileState {
    /// Does the file carry a provider-level marker at all?
    pub fn marked(&self) -> bool {
        !self.declared_hash.is_empty()
    }

    /// Has the content been edited underneath us?
    pub fn tampered(&self) -> bool {
        self.present && self.marked() && self.computed_hash != self.declared_hash
    }
}

/// What our markers say — independent of systemd.
#[derive(Debug, Clone, Default)]
pub struct MarkerState {
    pub env_file_present: bool,
    /// `Some` only when the env file carries a per-agent marker at this
    /// binding version.
    pub agent_marker: Option<AgentMarker>,
    pub trail_present: bool,
    pub shared: Vec<SharedFileState>,
}

/// Everything one reconciliation pass needs, read in a single round trip.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    pub systemd: SystemdState,
    pub markers: MarkerState,
    /// The requested harness binary exists and is executable in
    /// `/usr/local/bin` on the instance.
    pub harness_installed: bool,
    /// Summed `MemoryMax` of every *other* marked agent plus the standing
    /// `buzz-acp.service`.
    pub reserved_bytes: u64,
    pub available_bytes: u64,
}

/// One round trip that collects everything the reconciler needs.
pub fn look(remote: &Remote, names: &Names, harness: &str) -> Result<Observation, String> {
    let script = observe_script(names, harness);
    let out = remote.run(&script)?;
    if !out.ok() {
        return Err(format!(
            "observing {} failed (exit {}): {}",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }
    Ok(parse_observation(&out.stdout, &names.dropin_path()))
}

/// The observer script. Sectioned so the parser is a pure function of text.
fn observe_script(names: &Names, harness: &str) -> String {
    format!(
        "set -uo pipefail\n\
         echo '---UNIT---'\n\
         systemctl show {unit} -p LoadState -p ActiveState -p SubState \
             -p UnitFileState -p MainPID 2>/dev/null || true\n\
         echo '---AGENTMARKER---'\n\
         sudo -n sed -n '1,4p' {env} 2>/dev/null || true\n\
         echo '---SHARED---'\n\
         for p in {shared}; do \
           if sudo -n test -e \"$p\"; then \
             h=$(sudo -n sed '/^# managed-by: {managed_by}$/,+3d' \"$p\" | sha256sum | cut -d' ' -f1); \
             d=$(sudo -n sed -n 's/^# content-hash: //p' \"$p\" | head -n 1); \
             printf '%s|present|%s|%s\\n' \"$p\" \"$h\" \"$d\"; \
           else \
             printf '%s|absent||\\n' \"$p\"; \
           fi; \
         done\n\
         echo '---RESERVED---'\n\
         for f in /etc/systemd/system/buzz-acp@*.service.d/agent.conf; do \
           [ -e \"$f\" ] || continue; \
           v=$(sudo -n sed -n 's/^MemoryMax=//p' \"$f\" | head -n 1); \
           printf '%s=%s\\n' \"$f\" \"$v\"; \
         done\n\
         echo '---STANDING---'\n\
         systemctl show buzz-acp.service -p MemoryMax --value 2>/dev/null || true\n\
         echo '---AVAILABLE---'\n\
         awk '/^MemAvailable:/ {{print $2}}' /proc/meminfo\n\
         echo '---HARNESS---'\n\
         test -x {harness_path} && echo yes || echo no\n\
         echo '---TRAIL---'\n\
         sudo -n test -e {trail} && echo yes || echo no\n\
         echo '---END---'\n",
        unit = sq(&names.unit()),
        env = sq(&names.env_path()),
        shared = SHARED_PATHS
            .iter()
            .map(|p| sq(p))
            .collect::<Vec<_>>()
            .join(" "),
        managed_by = MANAGED_BY,
        harness_path = sq(&format!("/usr/local/bin/{harness}")),
        trail = sq(&names.trail_path()),
    )
}

/// Extract one `---NAME---` section body.
///
/// `pub(crate)` because `reconcile`'s startup poll uses the same sectioned
/// script shape; two copies of a text splitter would be two places to get the
/// terminator wrong.
pub(crate) fn section<'a>(body: &'a str, name: &str) -> &'a str {
    let opener = format!("---{name}---\n");
    let Some(rest) = body.split(opener.as_str()).nth(1) else {
        return "";
    };
    rest.split("---").next().unwrap_or("")
}

/// Read one `Key=value` line out of a `systemctl show` block.
pub(crate) fn property<'a>(block: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    block
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or("")
        .trim()
}

/// Decode the observer script's output.
///
/// `own_dropin` is this agent's own drop-in path, excluded from the reserved
/// total: a redeploy would otherwise count the memory it is about to rewrite.
pub fn parse_observation(stdout: &str, own_dropin: &str) -> Observation {
    let unit = section(stdout, "UNIT");
    let systemd = SystemdState {
        load_state: property(unit, "LoadState").to_string(),
        active_state: property(unit, "ActiveState").to_string(),
        sub_state: property(unit, "SubState").to_string(),
        unit_file_state: property(unit, "UnitFileState").to_string(),
        main_pid: property(unit, "MainPID").parse().unwrap_or(0),
    };

    let marker_body = section(stdout, "AGENTMARKER");
    let shared = section(stdout, "SHARED")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut parts = line.split('|');
            SharedFileState {
                path: parts.next().unwrap_or("").to_string(),
                present: parts.next().unwrap_or("") == "present",
                computed_hash: parts.next().unwrap_or("").trim().to_string(),
                declared_hash: parts.next().unwrap_or("").trim().to_string(),
            }
        })
        .collect();

    let reserved_from_agents: u64 = section(stdout, "RESERVED")
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(path, _)| *path != own_dropin)
        // Our own drop-ins carry the operator's spelling (`2G`), which is the
        // closed input grammar — not systemd's byte echo.
        .filter_map(|(_, value)| parse_memory_max(value.trim()).ok())
        .sum();
    let standing = parse_reported_bytes(section(stdout, "STANDING")).unwrap_or(0);

    let available_kb: u64 = section(stdout, "AVAILABLE").trim().parse().unwrap_or(0);

    Observation {
        systemd,
        markers: MarkerState {
            env_file_present: !marker_body.trim().is_empty(),
            agent_marker: AgentMarker::parse(marker_body),
            trail_present: section(stdout, "TRAIL").trim() == "yes",
            shared,
        },
        harness_installed: section(stdout, "HARNESS").trim() == "yes",
        reserved_bytes: reserved_from_agents.saturating_add(standing),
        available_bytes: available_kb.saturating_mul(1024),
    }
}
```

Add `mod observe;` to `main.rs`.

- [ ] **Step 4: Run to verify passing**

Run: `cargo test -p buzz-backend-gcp observe`
Expected: PASS — 9 tests.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): observe systemd state and marker state separately"
```

---

## Task 12: `reconcile.rs` — the I4 state machine, the fence, and the startup poll

Resolves the classification half of review **P1-5**, and **P2-3**.

**Files:**
- Modify: `crates/buzz-backend-gcp/src/reconcile.rs` (replaces the Task 5 skeleton wholesale)

**Interfaces:**
- Produces:
  - `reconcile::Action` — `NoOp | Create | RestartSame | FencedReplace | Refuse(String)`, deriving `Debug, Clone, PartialEq, Eq`
  - `reconcile::classify(obs: &Observation, pubkey_full: &str, intent: &str) -> Action`
  - `reconcile::shared_writes<'a>(plan: &'a Plan, obs: &Observation) -> Vec<&'a RemoteFile>`
  - `reconcile::Startup` — `Confirmed | Failed(String) | Pending`
  - `reconcile::parse_startup(stdout: &str) -> Startup`
  - `reconcile::deploy(cfg: &ProviderConfig, agent: &AgentPayload) -> Result<String, String>` (signature unchanged from Task 5, so `main.rs` needs no edit)
- Consumes: `crate::capacity`, `crate::config::ProviderConfig`, `crate::naming::{Names, MANAGED_BY}`, `crate::observe::{self, property, section, Observation}`, `crate::remote::{sq, Remote}`, `crate::render::{self, Plan, RemoteFile}`, `crate::secrets`, `buzz_backend_core::identity::{new_generation, AgentIdentity}`, `buzz_backend_core::wire::AgentPayload`. The test module additionally imports `crate::naming::AgentMarker` and `crate::observe::{MarkerState, SharedFileState, SystemdState, SHARED_PATHS}` — the parent module never names those types, so importing them there would be an unused import under `-D warnings`.

**Why the startup budget is 240 s.** The desktop gives a deploy 600 s (`backend.rs:528`) and kills the child at that mark with `provider timed out after 600s` — an error that tells the operator nothing. Before polling begins this provider makes roughly a dozen `gcloud` round trips (observe, three secret calls, up to six installs, the trail append, `daemon-reload` + `enable --now`), each of which pays IAP tunnel setup and lands in the 3-5 s range, so 40-90 s of the budget is gone before the first poll. On the other side, a `codex-acp` cold start on an `e2-medium` has to run the fetcher unit (a Secret Manager round trip from the VM), then load Node and the harness, then complete a relay TLS handshake and nostr auth. **240 s**, polled every 5 s, is roughly 8× the observed warm start while still leaving ≥ 250 s of slack under the desktop's own timeout — so a genuinely stuck agent produces this provider's actionable error naming the journal command, not the desktop's opaque one. The old 30 s was picked against nothing.

**Why the fence re-reads the whole tuple.** [L2] item 4 requires destructive writes fenced to the exact observation that authorized them. Comparing only `create_intent` misses the two changes that matter most: the file becoming someone else's between the read and the write, and the agent *starting* between them. Both are re-checked.

- [ ] **Step 1: Write the failing classification tests**

Replace the test module of `crates/buzz-backend-gcp/src/reconcile.rs` (the Task 5 skeleton has none; append this):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::AgentMarker;
    use crate::observe::{MarkerState, SharedFileState, SystemdState, SHARED_PATHS};

    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const INTENT: &str = "c0ffee";

    fn pubkey() -> String {
        AgentIdentity::from_nsec(NSEC)
            .unwrap()
            .pubkey_hex()
            .to_string()
    }

    fn healthy_shared() -> Vec<SharedFileState> {
        SHARED_PATHS
            .iter()
            .map(|path| SharedFileState {
                path: (*path).to_string(),
                present: true,
                computed_hash: format!("hash-{path}"),
                declared_hash: format!("hash-{path}"),
            })
            .collect()
    }

    fn ours(intent: &str) -> Option<AgentMarker> {
        Some(AgentMarker {
            pubkey_full: pubkey(),
            create_intent: intent.to_string(),
        })
    }

    /// `(unit_file_state, active_state, main_pid)` -> a systemd view.
    fn systemd(unit_file_state: &str, active_state: &str, main_pid: u32) -> SystemdState {
        SystemdState {
            load_state: "loaded".to_string(),
            active_state: active_state.to_string(),
            sub_state: String::new(),
            unit_file_state: unit_file_state.to_string(),
            main_pid,
        }
    }

    fn obs(systemd: SystemdState, env_file_present: bool, marker: Option<AgentMarker>) -> Observation {
        Observation {
            systemd,
            markers: MarkerState {
                env_file_present,
                agent_marker: marker,
                trail_present: false,
                shared: healthy_shared(),
            },
            harness_installed: true,
            reserved_bytes: 0,
            available_bytes: u64::MAX,
        }
    }

    #[test]
    fn an_absent_agent_is_created() {
        let o = obs(systemd("disabled", "inactive", 0), false, None);
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);
    }

    /// I4: a deploy against a running agent must not mutate anything. Without
    /// this, every Start click bounces a healthy agent.
    #[test]
    fn a_live_agent_is_a_strict_no_op() {
        let o = obs(systemd("enabled", "active", 4242), true, ours(INTENT));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::NoOp);
    }

    /// Reconfiguring a *running* agent is out of scope: I4 puts
    /// at-most-one-live-instance above convergence. The operator stops it first.
    #[test]
    fn a_live_agent_with_divergent_intent_is_still_a_no_op() {
        let o = obs(systemd("enabled", "active", 4242), true, ours("stale"));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::NoOp);
    }

    #[test]
    fn a_stopped_agent_with_the_same_intent_is_restarted_not_replaced() {
        let o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::RestartSame);
    }

    #[test]
    fn a_stopped_agent_with_a_divergent_intent_is_fence_replaced() {
        let o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// P1-5's exact case: a real unit with no env file must never classify as
    /// `Create`, or the provider installs its files around somebody else's unit.
    #[test]
    fn a_known_instance_with_no_marker_is_refused_never_created() {
        let o = obs(systemd("enabled", "inactive", 0), false, None);
        let action = classify(&o, &pubkey(), INTENT);
        assert!(matches!(action, Action::Refuse(_)), "got {action:?}");
        let Action::Refuse(why) = action else { unreachable!() };
        assert!(why.contains(MANAGED_BY), "{why}");
    }

    #[test]
    fn an_unmarked_env_file_is_refused_never_overwritten() {
        let o = obs(systemd("disabled", "inactive", 0), true, None);
        assert!(matches!(classify(&o, &pubkey(), INTENT), Action::Refuse(_)));
    }

    /// The 12-hex name is collision-resistant, not collision-free.
    #[test]
    fn a_short_name_collision_is_refused() {
        let foreign = Some(AgentMarker {
            pubkey_full: "ff".repeat(32),
            create_intent: INTENT.to_string(),
        });
        let o = obs(systemd("enabled", "inactive", 0), true, foreign);
        let action = classify(&o, &pubkey(), INTENT);
        assert!(matches!(action, Action::Refuse(_)), "got {action:?}");
    }

    /// A shared file with our name but no marker is somebody else's file.
    #[test]
    fn an_unmarked_shared_file_is_refused() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[0].declared_hash = String::new();
        let action = classify(&o, &pubkey(), INTENT);
        assert!(matches!(action, Action::Refuse(_)), "got {action:?}");
    }

    /// A shared file whose content no longer matches its own declared hash was
    /// edited underneath us; rewriting it would erase the evidence.
    #[test]
    fn a_tampered_shared_file_is_refused() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[1].computed_hash = "something-else".to_string();
        assert!(matches!(classify(&o, &pubkey(), INTENT), Action::Refuse(_)));
    }

    /// A missing shared file is normal on a first deploy, not a refusal.
    #[test]
    fn absent_shared_files_are_not_a_refusal() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        for shared in &mut o.markers.shared {
            shared.present = false;
            shared.computed_hash = String::new();
            shared.declared_hash = String::new();
        }
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);
    }
}
```

- [ ] **Step 2: Write the failing shared-write and startup tests**

Append to the same test module:

```rust
    fn plan_with_shared(hashes: [&str; 3]) -> Plan {
        Plan {
            per_agent: Vec::new(),
            shared: SHARED_PATHS
                .iter()
                .zip(hashes)
                .map(|(path, hash)| crate::render::SharedArtifact {
                    file: RemoteFile {
                        path: (*path).to_string(),
                        mode: "0644",
                        body: String::new(),
                    },
                    content_hash: hash.to_string(),
                })
                .collect(),
            secret_env: std::collections::BTreeMap::new(),
            create_intent: INTENT.to_string(),
            trail_header: String::new(),
        }
    }

    /// The strict no-op is only strict if a deploy that changes nothing shared
    /// performs **zero** writes there.
    #[test]
    fn matching_shared_files_are_not_rewritten() {
        let o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        let plan = plan_with_shared([
            "hash-/etc/systemd/system/buzz-acp@.service",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        assert!(shared_writes(&plan, &o).is_empty());
    }

    #[test]
    fn an_absent_shared_file_is_written() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[2].present = false;
        o.markers.shared[2].computed_hash = String::new();
        o.markers.shared[2].declared_hash = String::new();
        let plan = plan_with_shared([
            "hash-/etc/systemd/system/buzz-acp@.service",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        let writes = shared_writes(&plan, &o);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, SHARED_PATHS[2]);
    }

    /// A shared file present with a *different* content hash is an older
    /// rendering of ours and is upgraded in place.
    #[test]
    fn a_stale_shared_file_is_rewritten() {
        let o = obs(systemd("disabled", "inactive", 0), false, None);
        let plan = plan_with_shared([
            "brand-new-hash",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        let writes = shared_writes(&plan, &o);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, SHARED_PATHS[0]);
    }

    #[test]
    fn a_confirmed_start_needs_a_live_pid_and_the_harness_line() {
        let confirmed = "---UNIT---\nActiveState=active\nMainPID=4242\nResult=success\n\
                         ---JOURNAL---\n1\n---END---\n";
        assert_eq!(parse_startup(confirmed), Startup::Confirmed);
    }

    /// systemd calling the unit `active` is not the harness having started —
    /// I4's "live" means the process is confirmed running.
    #[test]
    fn an_active_unit_without_the_harness_line_is_still_pending() {
        let pending = "---UNIT---\nActiveState=active\nMainPID=4242\nResult=success\n\
                       ---JOURNAL---\n0\n---END---\n";
        assert_eq!(parse_startup(pending), Startup::Pending);

        let no_pid = "---UNIT---\nActiveState=activating\nMainPID=0\nResult=success\n\
                      ---JOURNAL---\n0\n---END---\n";
        assert_eq!(parse_startup(no_pid), Startup::Pending);
    }

    /// A failed unit must end the poll immediately: burning the whole budget
    /// on a unit systemd has already given up on wastes four minutes and
    /// produces a worse error.
    #[test]
    fn a_failed_unit_ends_the_poll_immediately() {
        let failed = "---UNIT---\nActiveState=failed\nMainPID=0\nResult=exit-code\n\
                      ---JOURNAL---\n0\n---END---\n";
        let Startup::Failed(why) = parse_startup(failed) else {
            panic!("a failed unit must not read as pending")
        };
        assert!(why.contains("exit-code"), "{why}");
    }
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp reconcile`
Expected: FAIL — `cannot find function classify in this scope`.

- [ ] **Step 4: Implement the reconciler**

Replace `crates/buzz-backend-gcp/src/reconcile.rs`'s non-test content in full:

```rust
//! The deploy state machine (spec §Deploy Reconciliation, I4).
//!
//! `deploy` is not "create": the desktop issues it on every Start and tracks
//! no substrate state. The only way that is safe is for a live instance to be
//! a strict no-op and for every destructive write to be fenced to the exact
//! observation that authorized it.

use crate::capacity;
use crate::config::ProviderConfig;
use crate::naming::{Names, MANAGED_BY};
use crate::observe::{self, property, section, Observation};
use crate::remote::{sq, Remote};
use crate::render::{self, Plan, RemoteFile};
use crate::secrets;
use buzz_backend_core::identity::{new_generation, AgentIdentity};
use buzz_backend_core::wire::AgentPayload;
use std::time::{Duration, Instant};

/// How long to wait for a confirmed harness start.
///
/// The desktop's deploy budget is 600 s (`backend.rs:528`), and roughly a
/// dozen `gcloud` round trips at 3-5 s each precede the first poll. 240 s is
/// about 8× an observed warm start — enough for a `codex-acp` cold start on an
/// e2-medium, which has to run the fetcher unit, load Node and the harness,
/// and complete a relay handshake — while leaving ≥ 250 s of slack, so a stuck
/// agent produces this provider's actionable error rather than the desktop's
/// opaque `provider timed out after 600s`.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(240);

/// One `gcloud compute ssh` round trip costs 3-5 s on its own, so polling
/// faster than this buys nothing but load.
const STARTUP_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The harness's own first log line. Its presence is what distinguishes
/// "systemd accepted the unit" from "the agent started".
const HARNESS_STARTUP_LINE: &str = "buzz-acp starting:";

/// What one deploy must do, decided from an observation alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The agent is already live. Zero mutation (I4).
    NoOp,
    /// Nothing of ours is there. Install and start.
    Create,
    /// Our files are there with the same recorded intent, and it is not
    /// running: start it. Never delete.
    RestartSame,
    /// Our files are there with a divergent intent, and it is not running:
    /// replace them, fenced.
    FencedReplace,
    /// Something is there that is not ours, or not this agent's.
    Refuse(String),
}

/// Decide what to do from an observation alone.
///
/// Pure, so the whole state machine is testable without an instance. Order
/// matters: every refusal is checked before any action, because an action
/// taken on somebody else's file cannot be undone by a later check.
pub fn classify(obs: &Observation, pubkey_full: &str, intent: &str) -> Action {
    // Shared artifacts first: they are installed once and depended on by every
    // instance, so one unowned file poisons every deploy on the box.
    for shared in &obs.markers.shared {
        if shared.present && !shared.marked() {
            return Action::Refuse(format!(
                "{} exists but carries no {MANAGED_BY} provider marker. It is \
                 somebody else's file that happens to share our name; refusing \
                 to overwrite it. Move it aside to let this provider install \
                 its own.",
                shared.path
            ));
        }
        if shared.tampered() {
            return Action::Refuse(format!(
                "{} carries our marker but its content no longer matches the \
                 hash that marker declares — it was edited outside this \
                 provider. Refusing to overwrite the change silently; restore \
                 or delete the file.",
                shared.path
            ));
        }
    }

    // Per-agent state. Systemd knowledge and marker ownership are separate
    // facts: a real unit with no env file must not read as "absent".
    let known = obs.systemd.instance_known();
    let Some(marker) = obs.markers.agent_marker.as_ref() else {
        if known {
            return Action::Refuse(format!(
                "a unit for this agent exists on the instance but carries no \
                 {MANAGED_BY} marker at this binding version. Refusing to \
                 adopt, restart, or replace a unit this provider did not \
                 create."
            ));
        }
        if obs.markers.env_file_present {
            return Action::Refuse(format!(
                "an environment file for this agent exists but carries no \
                 {MANAGED_BY} marker at this binding version. Refusing to \
                 overwrite a file this provider did not create."
            ));
        }
        return Action::Create;
    };

    if marker.pubkey_full != pubkey_full {
        return Action::Refuse(format!(
            "short-name collision: the existing unit belongs to pubkey {}, not \
             {pubkey_full}. The 12-hex instance name is collision-resistant, \
             not collision-free; refusing rather than destroying another \
             agent's deployment.",
            marker.pubkey_full
        ));
    }

    // Live is a strict no-op regardless of intent: reconfiguring a running
    // agent would mean killing it, and I4 puts at-most-one-live-instance above
    // convergence. The operator stops it, then redeploys.
    if obs.systemd.running() {
        return Action::NoOp;
    }

    if marker.create_intent == intent {
        Action::RestartSame
    } else {
        Action::FencedReplace
    }
}

/// Which shared artifacts this deploy must write.
///
/// A shared file that matches by content is skipped, which is what makes the
/// strict no-op on a live instance actually strict rather than "no-op except
/// for three files rewritten identically". Refusals for unmarked or tampered
/// shared files are `classify`'s job and have already run.
pub fn shared_writes<'a>(plan: &'a Plan, obs: &Observation) -> Vec<&'a RemoteFile> {
    plan.shared
        .iter()
        .filter(|artifact| {
            match obs
                .markers
                .shared
                .iter()
                .find(|state| state.path == artifact.file.path)
            {
                Some(state) => !state.present || state.computed_hash != artifact.content_hash,
                // Never observed: write it rather than assume it is there.
                None => true,
            }
        })
        .map(|artifact| &artifact.file)
        .collect()
}

/// What one startup poll saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// Active, with a live main PID, and the harness logged its own start.
    Confirmed,
    /// systemd gave up. Polling further would only waste the budget.
    Failed(String),
    Pending,
}

/// The remote script one startup poll runs.
fn startup_script(unit: &str) -> String {
    format!(
        "set -uo pipefail\n\
         echo '---UNIT---'\n\
         systemctl show {unit} -p ActiveState -p MainPID -p Result 2>/dev/null || true\n\
         echo '---JOURNAL---'\n\
         sudo -n journalctl -u {unit} --since '-30 min' --no-pager 2>/dev/null \
           | grep -c {needle} || true\n\
         echo '---END---'\n",
        unit = sq(unit),
        needle = sq(HARNESS_STARTUP_LINE),
    )
}

/// Decode one startup poll. Pure, so the three outcomes are testable.
pub fn parse_startup(stdout: &str) -> Startup {
    let unit = section(stdout, "UNIT");
    let active = property(unit, "ActiveState");
    let main_pid: u32 = property(unit, "MainPID").parse().unwrap_or(0);
    let result = property(unit, "Result");
    if active == "failed" {
        return Startup::Failed(format!(
            "systemd reports the unit failed (Result={result})"
        ));
    }
    let started = section(stdout, "JOURNAL")
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    if active == "active" && main_pid > 0 && started > 0 {
        return Startup::Confirmed;
    }
    Startup::Pending
}

/// Re-read the authorizing observation immediately before destroying anything.
///
/// [L2] item 4 requires a destructive write fenced to the exact observation
/// that authorized it. Comparing only the create-intent misses the two changes
/// that matter most: the marker becoming somebody else's, and the agent having
/// *started* since we classified.
fn fence(
    remote: &Remote,
    names: &Names,
    harness: &str,
    authorized: &Observation,
) -> Result<(), String> {
    let now = observe::look(remote, names, harness)?;
    if now.markers.agent_marker != authorized.markers.agent_marker {
        return Err(format!(
            "{} changed while this deploy was preparing: its management marker \
             no longer matches the one that authorized the replacement. \
             Nothing was modified; run the deploy again.",
            names.env_path()
        ));
    }
    if now.systemd.running() {
        return Err(format!(
            "{} started while this deploy was preparing. Refusing to stop a \
             running agent (I4); nothing was modified.",
            names.unit()
        ));
    }
    Ok(())
}

/// Poll until the harness confirms it started, or the budget runs out.
///
/// Takes `cfg` only so both failure messages can print the exact `gcloud`
/// command the operator needs; a message that says "check the journal" without
/// saying how is a message nobody acts on.
fn confirm_started(
    remote: &Remote,
    names: &Names,
    cfg: &ProviderConfig,
) -> Result<String, String> {
    let script = startup_script(&names.unit());
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let inspect = format!(
        "gcloud compute ssh {instance} --zone {zone} --tunnel-through-iap \
         --command 'sudo journalctl -u {unit} -n 50 --no-pager'",
        instance = cfg.instance,
        zone = cfg.zone,
        unit = names.unit(),
    );
    loop {
        let out = remote.run(&script)?;
        if !out.ok() {
            return Err(format!(
                "could not read the startup state of {} (exit {}): {}",
                names.unit(),
                out.code,
                out.stderr.trim()
            ));
        }
        match parse_startup(&out.stdout) {
            Startup::Confirmed => return Ok(names.unit()),
            Startup::Failed(why) => {
                return Err(format!(
                    "{} did not start: {why}. Inspect it with `{inspect}`.",
                    names.unit()
                ))
            }
            Startup::Pending => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} did not confirm a running harness within {}s. Inspect it \
                 with `{inspect}`.",
                names.unit(),
                STARTUP_TIMEOUT.as_secs(),
            ));
        }
        std::thread::sleep(STARTUP_POLL_INTERVAL);
    }
}

/// Run one deploy to a terminal outcome.
pub fn deploy(cfg: &ProviderConfig, agent: &AgentPayload) -> Result<String, String> {
    // ---- Pure phase: no gcloud, no VM. -----------------------------------
    // Step 0: identity from the nsec, before any mutation. Everything that can
    // be refused offline is refused here, which is also what keeps the wire
    // fixtures offline.
    let identity = AgentIdentity::from_nsec(&agent.private_key_nsec)?;
    let names = Names::new(&identity);
    let generation = new_generation();
    let plan = render::plan(agent, cfg, &names, &identity, &generation)?;
    let harness = render::harness_basename(agent);

    // ---- Transport phase. -------------------------------------------------
    let remote = Remote::new(&cfg.project, &cfg.zone, &cfg.instance)?;
    let obs = observe::look(&remote, &names, &harness)?;

    // `launch.command` was resolved against the desktop's PATH, which means
    // nothing here. Refusing now beats deploying a unit that fails at exec.
    if !obs.harness_installed {
        return Err(format!(
            "deploy refused: {harness} is not installed in /usr/local/bin on \
             {}. launch.command is resolved against the desktop's PATH, which \
             does not exist on the instance; install the harness there first.",
            cfg.instance
        ));
    }

    // Matched by reference so `action` survives for the two comparisons below.
    // Taking it by value here would move it — the defect this revision fixes.
    let action = classify(&obs, identity.pubkey_hex(), &plan.create_intent);
    match &action {
        Action::Refuse(why) => return Err(why.clone()),
        Action::NoOp => return Ok(names.unit()),
        Action::Create | Action::RestartSame | Action::FencedReplace => {}
    }

    // Overcommit is reported, never vetoed — but stderr is dropped by the
    // desktop on the success path, so the durable copy below is the one an
    // operator can actually find (§Capacity).
    let warnings = capacity::warning_lines(
        obs.available_bytes,
        obs.reserved_bytes,
        &names.unit(),
        cfg.memory_max_bytes,
    );
    for warning in &warnings {
        eprintln!("{warning}");
    }

    if action == Action::FencedReplace {
        fence(&remote, &names, &harness, &obs)?;
        let out = remote.run(&format!(
            "set -uo pipefail; \
             sudo -n systemctl disable --now {unit} 2>/dev/null || true; \
             sudo -n systemctl stop {secret_unit} 2>/dev/null || true",
            unit = sq(&names.unit()),
            secret_unit = sq(&names.secret_unit()),
        ))?;
        if !out.ok() {
            return Err(format!(
                "stopping the stale {} failed (exit {}): {}",
                names.unit(),
                out.code,
                out.stderr.trim()
            ));
        }
    }

    if action != Action::RestartSame {
        let service_account =
            secrets::instance_service_account(&remote, &cfg.project, &cfg.zone, &cfg.instance)?;
        secrets::store(
            &remote,
            &cfg.project,
            &names.secret_name(),
            identity.pubkey_hex(),
            &plan.secret_body(),
            &service_account,
        )?;
        // Shared first: the agent unit `Requires=` the fetcher unit, so the
        // fetcher must exist before the agent unit is enabled.
        for file in shared_writes(&plan, &obs) {
            remote.install(file)?;
        }
        for file in &plan.per_agent {
            remote.install(file)?;
        }
    }

    // The durable record, written before the start attempt so a deploy that
    // then fails to start still leaves its capacity warning behind.
    remote.append(
        &names.trail_path(),
        "0644",
        &plan.trail_header,
        &capacity::trail_record(
            &capacity::now_rfc3339(),
            &generation,
            &plan.create_intent,
            &warnings,
        ),
    )?;

    let out = remote.run(&format!(
        "set -euo pipefail; \
         sudo -n systemctl daemon-reload; \
         sudo -n systemctl enable --now {unit}",
        unit = sq(&names.unit()),
    ))?;
    if !out.ok() {
        return Err(format!(
            "starting {} failed (exit {}): {}",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }

    confirm_started(&remote, &names, cfg)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS — 17 new `reconcile` tests plus everything from Tasks 1-11. The four wire goldens still pass: `deploy` reaches `Remote::new` only after the pure phase, so `deploy-no-owner` and `deploy-ordinary-provider` still stop offline.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): I4 reconciler with a full-tuple destructive fence"
```

---

## Task 13: Operator subcommands — `list`, `remove`, `dry-run`

Resolves review **P2-4**, **P2-6**, and P3's "`dry-run` is exercised by no acceptance criterion".

**Files:**
- Create: `crates/buzz-backend-gcp/src/operator.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod operator;` and the argv branch)

**Interfaces:**
- Produces: `operator::Cli` (clap `Parser`), `operator::Cmd`, `operator::run(cli: Cli) -> Result<(), String>`, `operator::render_listing(stdout: &str) -> String`
- Consumes: `crate::config::{self, ProviderConfig}`, `crate::naming::{self, Names, MANAGED_BY}`, `crate::remote::{sq, Remote}`, `crate::render`, `crate::secrets`, `buzz_backend_core::identity::AgentIdentity`, `buzz_backend_core::wire::DeployRequest`, `clap`.

The desktop passes no argv, so argv presence unambiguously selects operator mode. With empty argv the binary behaves exactly as the protocol requires.

**`remove` requires `--pubkey`, and that is the point.** `managed-by` proves only that this provider wrote a file; it says nothing about *which* agent. Since the 12-hex name is collision-resistant rather than collision-free, a `managed-by`-only fence would let `remove buzz-acp@a1b2c3d4e5f6` destroy a different agent that truncated to the same 12 hex. The full pubkey has to come from somewhere, and the operator is the only party who can supply it — which is exactly why `list` prints it.

**`remove` deletes enumerated paths, never a directory.** `rm -rf /etc/systemd/system/buzz-acp@<short12>.service.d/` is not a fence, it is a fence-shaped hole: a drop-in directory is precisely where an operator puts `override.conf` or `team.conf`, and the live host already has such an out-of-band drop-in. `remove` deletes the marker-verified files it knows it wrote, then `rmdir`s each drop-in directory **only if empty**. A non-empty directory is reported, not emptied. Shared artifacts are never touched: they carry the provider-level marker and other agents depend on them.

**`remove` destroys the secret before deleting local markers.** The reverse order fails in a specific way — markers gone, secret still holding a live key, no local evidence left to identify or retry it.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/operator.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_id_yields_its_instance() {
        assert_eq!(instance_of("buzz-acp@a1b2c3d4e5f6.service").unwrap(), "a1b2c3d4e5f6");
        assert_eq!(instance_of("buzz-acp@a1b2c3d4e5f6").unwrap(), "a1b2c3d4e5f6");
    }

    #[test]
    fn a_malformed_agent_id_is_refused() {
        for bad in [
            "a1b2c3d4e5f6",
            "buzz-acp@",
            "buzz-acp@NOTHEX123456",
            "buzz-acp@abc",
            "buzz-acp@a1b2c3d4e5f6g7",
            "buzz-agent-a1b2c3d4e5f6",
        ] {
            assert!(instance_of(bad).is_err(), "accepted malformed agent id {bad:?}");
        }
    }

    /// The operator's pubkey must actually name the agent they typed, or the
    /// fence is checking one identity while the paths belong to another.
    #[test]
    fn the_pubkey_must_agree_with_the_agent_id() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        assert!(resolve_target("buzz-acp@a1b2c3d4e5f6.service", &pubkey).is_ok());
        let other = format!("ffffffffffff{}", "0".repeat(52));
        let err = resolve_target("buzz-acp@a1b2c3d4e5f6.service", &other)
            .expect_err("mismatched pubkey must be refused");
        assert!(err.contains("does not begin"), "{err}");
    }

    /// `list` renders unit rows and every `warning` line from each trail: the
    /// trail is the only place a success-path capacity warning survives.
    #[test]
    fn the_listing_shows_units_and_their_capacity_warnings() {
        let raw = "unit\tbuzz-acp@a1b2c3d4e5f6.service\tactive\tdeadbeef\n\
                   warning\twarning capacity: adding buzz-acp@a1b2c3d4e5f6.service (2G) may cause OOM kills.\n\
                   unit\tbuzz-acp@ffffffffffff.service\tinactive\tcafebabe\n";
        let rendered = render_listing(raw);
        assert!(rendered.contains("buzz-acp@a1b2c3d4e5f6.service"));
        assert!(rendered.contains("active"));
        assert!(rendered.contains("deadbeef"));
        assert!(rendered.contains("may cause OOM kills"));
        assert!(rendered.contains("buzz-acp@ffffffffffff.service"));
    }

    #[test]
    fn an_empty_listing_says_so_rather_than_printing_nothing() {
        assert!(render_listing("").contains("no agents"));
    }

    /// Enumerated paths only. A drop-in directory is where an operator keeps
    /// `override.conf`; deleting the directory is a fence-shaped hole.
    #[test]
    fn the_removal_script_deletes_named_files_and_never_a_directory_tree() {
        let names = Names::from_pubkey_hex(&format!("a1b2c3d4e5f6{}", "0".repeat(52))).unwrap();
        let script = removal_script(&names);
        for path in [
            names.env_path(),
            names.trail_path(),
            names.dropin_path(),
            names.secret_dropin_path(),
        ] {
            assert!(script.contains(&sq(&path)), "{path} is not deleted by name");
        }
        assert!(!script.contains("rm -rf"), "a directory tree must never be removed");
        assert!(script.contains("rmdir"), "empty drop-in directories are tidied");
        // Shared artifacts belong to every agent and are never touched.
        for shared in crate::observe::SHARED_PATHS {
            assert!(!script.contains(shared), "{shared} must survive a remove");
        }
    }

    /// The marker check runs against the file's own header, and must require
    /// the whole per-agent tuple rather than `managed-by` alone.
    #[test]
    fn the_fence_requires_the_whole_marker_tuple() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let good = crate::naming::AgentMarker {
            pubkey_full: pubkey.clone(),
            create_intent: "ci".to_string(),
        }
        .render();
        assert!(verify_removable(&good, &pubkey, &names.env_path()).is_ok());

        let foreign = crate::naming::AgentMarker {
            pubkey_full: "ff".repeat(32),
            create_intent: "ci".to_string(),
        }
        .render();
        assert!(verify_removable(&foreign, &pubkey, &names.env_path()).is_err());

        assert!(verify_removable("# hand-written\n", &pubkey, &names.env_path()).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp operator`
Expected: FAIL — `cannot find function instance_of in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/buzz-backend-gcp/src/operator.rs`:

```rust
//! Operator-facing commands (spec §Operator Surface).
//!
//! Not protocol operations: the desktop invokes this binary with **no**
//! arguments, so anything on argv is a human. These exist because the protocol
//! has no `stop` — I5 routes intentional termination through `!shutdown` on the
//! relay — and because a success-path capacity warning has nowhere else to go.

use crate::config::{self, ProviderConfig};
use crate::naming::{self, AgentMarker, Names, MANAGED_BY};
use crate::remote::{sq, Remote};
use crate::secrets;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "buzz-backend-gcp",
    about = "GCE/systemd backend provider for Buzz remote agents"
)]
pub struct Cli {
    #[arg(long, default_value = config::DEFAULT_PROJECT)]
    pub project: String,
    #[arg(long, default_value = config::DEFAULT_ZONE)]
    pub zone: String,
    #[arg(long, default_value = config::DEFAULT_INSTANCE)]
    pub instance: String,
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List the agent units this provider manages, with every capacity
    /// warning recorded in their deploy trails.
    List,
    /// Stop, disable, destroy the secret, then delete this agent's own files.
    Remove {
        /// The `agent_id` the desktop recorded, e.g. `buzz-acp@a1b2c3d4e5f6`.
        agent_id: String,
        /// The agent's full 64-hex pubkey, as printed by `list`.
        ///
        /// Required, not optional: `managed-by` proves only that this provider
        /// wrote a file, never *which* agent it belongs to, and the 12-hex
        /// name is collision-resistant rather than collision-free.
        #[arg(long)]
        pubkey: String,
    },
    /// Render a deploy request read from stdin, secrets redacted, touching
    /// nothing.
    DryRun,
}

/// Dispatch one operator command.
///
/// `Cli` is destructured before matching, so the subcommand can be moved out
/// while `project`/`zone`/`instance` stay usable — matching on `cli.command`
/// with `&cli` borrowed afterwards does not compile.
pub fn run(cli: Cli) -> Result<(), String> {
    let Cli {
        project,
        zone,
        instance,
        command,
    } = cli;
    match command {
        Cmd::List => {
            let remote = Remote::new(&project, &zone, &instance)?;
            list(&remote)
        }
        Cmd::Remove { agent_id, pubkey } => {
            let remote = Remote::new(&project, &zone, &instance)?;
            remove(&remote, &project, &agent_id, &pubkey)
        }
        // No transport: `dry-run` exists to be safe to run anywhere.
        Cmd::DryRun => dry_run(),
    }
}

/// Extract the 12-hex instance from an `agent_id`.
fn instance_of(agent_id: &str) -> Result<String, String> {
    let malformed = || {
        format!(
            "{agent_id:?} is not a buzz-acp agent id. Expected \
             buzz-acp@<12 lowercase hex>[.service], as returned by deploy and \
             printed by `list`."
        )
    };
    let rest = agent_id.trim().strip_prefix("buzz-acp@").ok_or_else(malformed)?;
    let instance = rest.strip_suffix(".service").unwrap_or(rest);
    if instance.len() != 12
        || !instance
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed());
    }
    Ok(instance.to_string())
}

/// Resolve and cross-check the operator's two identifiers.
///
/// Both are caller-supplied, so neither is trusted alone: the pubkey is
/// validated to 64 hex and must *derive* the instance the agent id names.
fn resolve_target(agent_id: &str, pubkey: &str) -> Result<(Names, String), String> {
    let instance = instance_of(agent_id)?;
    let pubkey = naming::normalize_pubkey(pubkey)?;
    if pubkey[..12] != instance {
        return Err(format!(
            "the supplied pubkey does not begin with {instance}, so it does not \
             name {agent_id}. Copy the pubkey `list` prints on that unit's row."
        ));
    }
    Ok((Names::from_pubkey_hex(&pubkey)?, pubkey))
}

/// The remote script `list` runs.
fn listing_script() -> String {
    format!(
        "set -uo pipefail\n\
         for f in /etc/buzz/acp-*.env; do\n\
           [ -e \"$f\" ] || continue\n\
           i=$(basename \"$f\" .env); i=${{i#acp-}}\n\
           mb=$(sudo -n sed -n 's/^# managed-by: //p' \"$f\" | head -n 1)\n\
           [ \"$mb\" = '{MANAGED_BY}' ] || continue\n\
           pk=$(sudo -n sed -n 's/^# agent-pubkey-full: //p' \"$f\" | head -n 1)\n\
           st=$(systemctl is-active \"buzz-acp@$i.service\" 2>/dev/null || echo unknown)\n\
           printf 'unit\\tbuzz-acp@%s.service\\t%s\\t%s\\n' \"$i\" \"$st\" \"$pk\"\n\
           t=\"/etc/buzz/acp-$i.trail\"\n\
           if sudo -n test -e \"$t\"; then\n\
             sudo -n sed -n 's/^\\(warning .*\\)$/warning\\t\\1/p' \"$t\"\n\
           fi\n\
         done\n"
    )
}

/// Turn the listing script's tab-separated output into operator-readable text.
///
/// Pure, so the rendering is tested without an instance.
pub fn render_listing(stdout: &str) -> String {
    let mut out = String::new();
    let mut units = 0usize;
    for line in stdout.lines() {
        let mut fields = line.split('\t');
        match fields.next() {
            Some("unit") => {
                units += 1;
                let unit = fields.next().unwrap_or("<unknown>");
                let state = fields.next().unwrap_or("unknown");
                let pubkey = fields.next().unwrap_or("<unmarked>");
                out.push_str(&format!("{unit}\t{state}\t{pubkey}\n"));
            }
            Some("warning") => {
                out.push_str(&format!("    {}\n", fields.next().unwrap_or_default()));
            }
            _ => {}
        }
    }
    if units == 0 {
        out.push_str(&format!("no agents managed by {MANAGED_BY} on this instance\n"));
    }
    out
}

fn list(remote: &Remote) -> Result<(), String> {
    let out = remote.run(&listing_script())?;
    // Checking this is not optional: an auth failure produces empty stdout,
    // and printing nothing while exiting 0 makes a broken install look healthy.
    if !out.ok() {
        return Err(format!(
            "listing agents failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    print!("{}", render_listing(&out.stdout));
    Ok(())
}

/// The fence every deletion passes: the whole per-agent marker tuple, read
/// from the file's own header immediately before it is destroyed.
fn verify_removable(body: &str, pubkey_full: &str, path: &str) -> Result<(), String> {
    let Some(marker) = AgentMarker::parse(body) else {
        return Err(format!(
            "{path} carries no {MANAGED_BY} marker at this binding version. \
             Refusing to delete a file this provider did not create."
        ));
    };
    if marker.pubkey_full != pubkey_full {
        return Err(format!(
            "{path} belongs to pubkey {}, not {pubkey_full}. Refusing: the \
             12-hex name is collision-resistant, not collision-free.",
            marker.pubkey_full
        ));
    }
    Ok(())
}

/// The remote script that deletes this agent's own files — by name, never a
/// directory tree — and tidies each drop-in directory only when it is empty.
fn removal_script(names: &Names) -> String {
    format!(
        "set -uo pipefail\n\
         sudo -n systemctl disable --now {unit} 2>/dev/null || true\n\
         sudo -n systemctl stop {secret_unit} 2>/dev/null || true\n\
         for p in {env} {trail} {dropin} {secret_dropin}; do\n\
           sudo -n rm -f \"$p\"\n\
         done\n\
         for d in {dropin_dir} {secret_dropin_dir}; do\n\
           if sudo -n test -d \"$d\"; then\n\
             if sudo -n rmdir \"$d\" 2>/dev/null; then :; else\n\
               echo \"kept $d: it still holds files this provider did not write\"\n\
             fi\n\
           fi\n\
         done\n\
         sudo -n systemctl daemon-reload\n",
        unit = sq(&names.unit()),
        secret_unit = sq(&names.secret_unit()),
        env = sq(&names.env_path()),
        trail = sq(&names.trail_path()),
        dropin = sq(&names.dropin_path()),
        secret_dropin = sq(&names.secret_dropin_path()),
        dropin_dir = sq(&names.dropin_dir()),
        secret_dropin_dir = sq(&names.secret_dropin_dir()),
    )
}

fn remove(remote: &Remote, project: &str, agent_id: &str, pubkey: &str) -> Result<(), String> {
    let (names, pubkey) = resolve_target(agent_id, pubkey)?;

    // Re-read the authorizing evidence immediately before acting on it. Every
    // per-agent file carries the same tuple, so one read fences them all — and
    // it is read here, not earlier, so nothing stale can authorize a deletion.
    let out = remote.run(&format!(
        "sudo -n sed -n '1,4p' {env} 2>/dev/null || true",
        env = sq(&names.env_path()),
    ))?;
    if !out.ok() {
        return Err(format!(
            "could not read {} (exit {}): {}",
            names.env_path(),
            out.code,
            out.stderr.trim()
        ));
    }
    if out.stdout.trim().is_empty() {
        return Err(format!(
            "{} does not exist on the instance; there is nothing here to \
             remove under that identity.",
            names.env_path()
        ));
    }
    verify_removable(&out.stdout, &pubkey, &names.env_path())?;

    // Secret first. The reverse order leaves markers gone, the secret still
    // holding a live key, and no local evidence left to identify or retry it.
    // Ordered this way an interrupted remove is idempotent: a re-run finds the
    // marked files present, the secret already absent, and treats
    // delete-of-absent as success ([L2] item 4).
    secrets::destroy(remote, project, &names.secret_name(), &pubkey)?;

    let out = remote.run(&removal_script(&names))?;
    if !out.ok() {
        return Err(format!(
            "removing {agent_id} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    print!("{}", out.stdout);
    println!("removed {agent_id}");
    Ok(())
}

fn dry_run() -> Result<(), String> {
    use buzz_backend_core::identity::AgentIdentity;
    use buzz_backend_core::wire::DeployRequest;
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("could not read the request from stdin: {e}"))?;
    let request: DeployRequest =
        serde_json::from_str(&input).map_err(|e| format!("invalid deploy request: {e}"))?;

    let cfg = ProviderConfig::parse(&request.provider_config)?;
    let identity = AgentIdentity::from_nsec(&request.agent.private_key_nsec)?;
    let names = Names::new(&identity);
    let plan = crate::render::plan(&request.agent, &cfg, &names, &identity, "dryrun00")?;
    let record = crate::capacity::trail_record("<deploy time>", "dryrun00", &plan.create_intent, &[]);
    print!("{}", crate::render::dry_run_report(&plan, &names, &record));
    Ok(())
}
```

- [ ] **Step 4: Branch on argv in `main.rs`**

Add `mod operator;` to the module list and replace the top of `main`:

```rust
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS — 7 new `operator` tests, and every wire test still green (they spawn the binary with **no** argv, so they must still see protocol behavior).

- [ ] **Step 6: Exercise `dry-run` as the acceptance criterion the design asks for**

Design §`dry-run` is the secret-classification audit requires this exact check. Build a payload carrying three secret-classified values, then confirm none of them appears in the output:

```bash
cargo build -p buzz-backend-gcp
jq '.agent.auth_tag = "tag-AUDIT-1"
    | .agent.launch.env.ANTHROPIC_API_KEY = "sk-ant-AUDIT-2"
    | .provider_config = {}' \
  crates/buzz-backend-core/fixtures/provider-wire/deploy-full-launch.request.json \
  > /tmp/audit.json
./target/debug/buzz-backend-gcp dry-run < /tmp/audit.json > /tmp/audit.out
grep -c -e nsec1 -e tag-AUDIT-1 -e sk-ant-AUDIT-2 /tmp/audit.out
grep -c -e 'BUZZ_PRIVATE_KEY=\[REDACTED\]' -e 'BUZZ_AUTH_TAG=\[REDACTED\]' \
        -e 'ANTHROPIC_API_KEY=\[REDACTED\]' /tmp/audit.out
```

Expected: the first `grep -c` prints `0` (and exits 1, which is the expected outcome for "no matches" — do not treat that as a failure); the second prints `3`. If any value appears, the allowlist regressed and Task 7 is wrong.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): operator list, fenced remove and redacted dry-run"
```

---

## Task 14: Install target, README, and the `[L3]` conformance section

**Files:**
- Modify: `justfile` (after the `build-release` recipe at `:91-92`)
- Create: `crates/buzz-backend-gcp/README.md`
- Modify: `docs/remote-agents.md` (a new `[L3]` section after `### [L3] Kubernetes binding conformance — this binding` ends at `:1571`, and a row in `## Implementation Correspondence` at `:1678`)

**Interfaces:**
- Produces: `just install-backend-gcp`.

[L2] item 6 makes the documentation mandatory, not optional: *"its binding **documents** how it realizes each L2 term on its substrate, and how the owner's lifetime policy (bounded vs indefinite) and clean-exit restart behavior are realized there"* (`docs/remote-agents.md:1479-1482`).

- [ ] **Step 1: Add the install target**

In `justfile`, immediately after the `build-release` recipe:

```make
# Build and install the GCE backend provider for the desktop app
install-backend-gcp:
    cargo build --release -p buzz-backend-gcp
    mkdir -p ~/.local/bin
    install -m 0755 target/release/buzz-backend-gcp ~/.local/bin/buzz-backend-gcp
    @echo "installed to ~/.local/bin/buzz-backend-gcp — restart Buzz Desktop to discover it"
```

- [ ] **Step 2: Write the crate README**

`crates/buzz-backend-gcp/README.md`:

````markdown
# buzz-backend-gcp

A conforming Buzz backend provider (`docs/remote-agents.md`) that runs managed
agents as systemd units on a GCE instance.

## Where it runs

On the **operator's Mac**, not on the VM. Buzz Desktop discovers providers on
its own machine, stages a copy, and executes it as a child process speaking
one JSON request in and one JSON response out. Installing it on the VM would
make it undiscoverable.

```
Mac: Buzz Desktop ──stdin/stdout JSON──> buzz-backend-gcp
                                              │ gcloud compute ssh --tunnel-through-iap
                                              v
                                         buzz-agent VM ── buzz-acp@<id>.service ──wss──> relay
```

## Install

```bash
just install-backend-gcp
```

Then restart Buzz Desktop. `gcp` appears in the agent dialog's **Where to run**
selector.

## Prerequisites

- `gcloud` installed and authenticated (`gcloud auth login`) with IAP
  tunnelling access to the target project. The provider prepends
  `/opt/homebrew/bin`, `/usr/local/bin`, and `~/.local/bin` to its own `PATH`,
  because a GUI-launched app inherits launchd's minimal one.
- The harness binary the agent launches (`buzz-acp`, `codex-acp`, …) must
  already exist in `/usr/local/bin` **on the instance**. `launch.command` is
  resolved against the desktop's PATH, which means nothing there; a deploy
  naming a harness the instance lacks is refused rather than deployed.
- Passwordless `sudo` on the instance. Every privileged step runs `sudo -n`.

## `provider_config`

| Field | Type | Default | Notes |
|---|---|---|---|
| `project` | string | `zoop-innovation` | |
| `zone` | string | `asia-south1-a` | |
| `instance` | string | `buzz-agent` | |
| `memory_max` | string | `2G` | systemd `MemoryMax`. `^[0-9]{1,6}(\.[0-9]{1,3})?[KMGT]?$`, uppercase suffix, `> 0`. |
| `cpu_quota` | string | `150%` | systemd `CPUQuota`. `^[0-9]{1,3}%$`, `1`–`200` (the instance has 2 vCPU). |
| `inactivity_seconds` | integer | `7200` | Feeds `BUZZ_ACP_EXIT_AFTER_INACTIVITY`. `0` parses but is refused — see below. |

Both interpolated values are parsed against closed grammars and **rejected**,
never sanitized: they land in a root-installed systemd drop-in, where a
newline becomes an additional unit directive. Every `provider_config` string
value is additionally scanned for CR, LF, and NUL.

No field names a credential (I2), and none may carry one.

## Operator commands

The desktop passes no argv, so argv selects operator mode.

| Command | Effect |
|---|---|
| `buzz-backend-gcp list` | Every marked unit with its state, full pubkey, and every `warning` line from its deploy trail. |
| `buzz-backend-gcp remove <agent_id> --pubkey <64 hex>` | Stop, disable, destroy the secret, then delete this agent's enumerated files. `--pubkey` is required: the 12-hex name is collision-resistant, not collision-free. Copy it from `list`. |
| `buzz-backend-gcp dry-run < request.json` | Print every rendered artifact with all secret-classified values redacted. Touches nothing. |

`list` is where a capacity warning is readable: the desktop drops provider
stderr on the success path, so an over-capacity deploy is recorded durably in
`/etc/buzz/acp-<id>.trail` instead.

## What lands on the instance

Three shared artifacts, written only when absent or when their content hash
differs, each carrying a provider-level marker with no agent identity in it:

- `/etc/systemd/system/buzz-acp@.service`
- `/etc/systemd/system/buzz-acp-secret@.service`
- `/usr/local/sbin/buzz-acp-fetch-key`

Four per-agent artifacts, each carrying the full-pubkey marker:

- `/etc/buzz/acp-<id>.env` (0600, allowlisted non-secret values only)
- `/etc/systemd/system/buzz-acp@<id>.service.d/agent.conf`
- `/etc/systemd/system/buzz-acp-secret@<id>.service.d/agent.conf`
- `/etc/buzz/acp-<id>.trail` (0644, appended per deploy)

Everything else — the nsec, `BUZZ_AUTH_TAG`, and every API key the launch
carries — goes to Secret Manager and is materialized to
`/run/buzz-acp-<id>/secret.env` on tmpfs, 0400 `buzzacp`. It never touches the
persistent boot disk.

## Not isolated from each other

Every instance runs as the same Unix user, `buzzacp`. Per-secret IAM shrinks
the blast radius *outside* the VM and gives a per-secret audit trail; inside
the VM, agents are mutually trusting — a compromised agent can read a
sibling's materialized key. Agents on this instance are isolated from the
network and from the metadata server, **not from each other**.
````

- [ ] **Step 3: Add the `[L3]` conformance section**

In `docs/remote-agents.md`, after the Kubernetes `[L3]` section ends (immediately before `## Known Defects` at `:1572`), insert:

```markdown
### [L3] GCE/systemd binding conformance — `buzz-backend-gcp`

The second binding's realization of the two lists above, in its own vocabulary:

1. **L2 item 4's terms.** Identity evidence is the `agent-pubkey-full` line of
   the four-line marker header this provider writes into every per-agent file,
   compared in full — the 12-hex instance name is collision-resistant only.
   "Started" is `ActiveState=active` **and** a non-zero `MainPID` **and** the
   harness's own `buzz-acp starting:` line in the journal; systemd accepting
   the unit is not a start. Most-recent semantics come from re-reading the
   whole marker tuple immediately before any stop, disable, or delete, and
   from re-confirming the unit is still not running: those two comparisons are
   the compare-and-delete this substrate has. The auto-repair fence is the
   marker itself — no destructive action touches a file lacking the marker of
   its own tier.
2. **Two marker tiers.** Per-agent artifacts carry `managed-by`,
   `binding-version`, `agent-pubkey-full`, and `create-intent`. Shared
   artifacts — the two template units and the fetcher script — carry
   `managed-by`, `binding-version`, `scope: provider-shared`, and a
   `content-hash`, and **no agent identity at all**, because a file used by
   every instance belongs to none of them. Shared artifacts are written only
   when absent or when their content differs, which is what makes the
   live-instance no-op zero-mutation rather than "no-op except three files
   rewritten identically".
3. **Lifetime policy.** Bounded (`inactivity_seconds > 0`) is `Restart=no`.
   Indefinite (`inactivity_seconds: 0`) parses — it is the blessed opt-in and
   must not be rejected as invalid — and is then **refused by deploy** with a
   message naming its prerequisite, because honoring it needs
   `Restart=on-failure` against a clean-exit convention Known Defect 6 has not
   yet pinned. [L1] item 5 forbids the alternative.
4. **Signal delivery.** `ExecStart=` invokes `/usr/local/bin/buzz-acp`
   directly — no shell wrapper — so `SIGTERM` reaches the harness itself.
   `TimeoutStopSec=120` is the graceful-shutdown budget: in-flight drain,
   presence→offline, and a graceful relay close before `SIGKILL`.
5. **I2 and L2 item 5.** `provider_config` carries no credentials, and the
   environment is split by an **allowlist of non-secret keys**: everything not
   on that list — both nsec keys, `BUZZ_AUTH_TAG`, and every unrecognized
   tier-1/tier-2 key — goes to Secret Manager and is materialized only to
   tmpfs. The deploy trail records timestamps, generations, intent digests,
   and capacity arithmetic, never an environment value. `dry-run` prints the
   secret payload keys-only.
6. **The fetcher unit.** The agent unit's `IPAddressDeny=169.254.169.254/32`
   is a cgroup-wide filter, so a metadata-authenticated fetch cannot live
   inside it; `buzz-acp-secret@%i.service` exists solely to run outside that
   cgroup, and carries every other sandbox directive the agent unit does.
```

Add to the `## Implementation Correspondence` table (`:1680`):

```markdown
| GCE/systemd binding | `crates/buzz-backend-gcp/` |
| shared provider contract | `crates/buzz-backend-core/` |
```

- [ ] **Step 4: Verify the install works end to end**

Run:
```bash
just install-backend-gcp
~/.local/bin/buzz-backend-gcp list
```
Expected: the install line prints, and `list` prints either agent rows or
`no agents managed by buzz-backend-gcp on this instance`. An auth error is
reported with a nonzero exit, not swallowed — if it prints nothing and exits
0, Task 13's `out.ok()` check regressed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "docs(backend-gcp): L3 conformance, README and install target"
```

---

## Task 15: Live smoke test on `buzz-agent`

**Files:** none — this is the manual verification gate.

**Prerequisites:** `gcloud auth login` with access to `zoop-innovation`, Buzz
Desktop built from source, and Task 14's install completed.

Throughout, `<id>` is the 12-hex instance from the returned `agent_id` and
`<pk>` is the full pubkey `list` prints.

- [ ] **Step 1: Confirm discovery**

Restart Buzz Desktop. Open the agent create dialog and check that **Where to
run** offers `gcp` beside `This computer`.
Expected: `gcp` is listed. If it is not, the binary is not executable or not in
`~/.local/bin`.

- [ ] **Step 2: Deploy a throwaway agent**

Create an agent named `smoke`, harness `codex-acp`, Run on `gcp`, accept the
config defaults, and submit.
Expected: success within the startup budget, with
`agent_id = buzz-acp@<12 hex>` recorded.

- [ ] **Step 3: Verify supervision policy on the instance**

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'systemctl is-active buzz-acp@<id>.service; \
   systemctl show buzz-acp@<id>.service -p Restart --value; \
   systemctl show buzz-acp@<id>.service -p TimeoutStopUSec --value'
```
Expected: `active`, `no`, `2min`. If `Restart` prints `always`, Task 7
regressed and [L1] item 5 is violated.

- [ ] **Step 4: Verify identity and owner resolution**

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'sudo journalctl -u buzz-acp@<id> -n 40 --no-pager | grep -iE "buzz-acp starting|agent owner"'
```
Expected: a `buzz-acp starting:` line **and** an `agent owner: …` line. The
owner line's absence means the owner variable was dropped and the agent will
silently ignore every message.

- [ ] **Step 5: Verify no secret-classified value is on the boot disk**

This is the live half of the leak test — the allowlist is the whole defense for
[L2] item 5 in this binding.

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'sudo cat /etc/buzz/acp-<id>.env; echo "--- non-allowlisted keys ---"; \
   sudo grep -vE "^#|^$|^(BUZZ_RELAY_URL|BUZZ_ACP_AGENT_OWNER|BUZZ_ACP_AGENT_COMMAND|BUZZ_ACP_AGENT_ARGS|BUZZ_ACP_MCP_COMMAND|BUZZ_ACP_RESPOND_TO|BUZZ_ACP_RESPOND_TO_ALLOWLIST|BUZZ_ACP_EXIT_AFTER_INACTIVITY|BUZZ_MANAGED_AGENT_START_NONCE)=" \
     /etc/buzz/acp-<id>.env || echo NONE; \
   echo "--- nsec anywhere under /etc ---"; \
   sudo grep -rl "nsec1" /etc/buzz/ /etc/systemd/system/ || echo CLEAN; \
   echo "--- tmpfs ---"; sudo ls -l /run/buzz-acp-<id>/'
```
Expected: `NONE` under non-allowlisted keys, `CLEAN` under `/etc`, and a
`secret.env` at mode `-r--------` owned by `buzzacp`. Any other outcome means
the allowlist is not holding.

- [ ] **Step 6: Verify the redacted `dry-run` against the live payload shape**

```bash
~/.local/bin/buzz-backend-gcp dry-run < /tmp/audit.json | grep -c "REDACTED"
~/.local/bin/buzz-backend-gcp dry-run < /tmp/audit.json | grep -c "nsec1"
```
Expected: a non-zero count for `REDACTED` and `0` for `nsec1` (the second
`grep -c` exits 1 with no matches, which is the pass condition).

- [ ] **Step 7: Verify the I4 no-op, shared files included**

Record the state, click Start again in the desktop, then re-read it.

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'systemctl show buzz-acp@<id>.service -p ActiveEnterTimestamp --value; \
   sudo stat -c "%n %Y" /etc/systemd/system/buzz-acp@.service \
     /etc/systemd/system/buzz-acp-secret@.service \
     /usr/local/sbin/buzz-acp-fetch-key \
     /etc/buzz/acp-<id>.env'
```
Expected: **every** value identical before and after. A changed
`ActiveEnterTimestamp` means the live instance was restarted, violating I4. A
changed mtime on any shared file means the write-only-when-changed rule
regressed and the no-op is not strict.

- [ ] **Step 8: Exercise the agent end to end**

Add the agent to a channel from the desktop and mention it.
Expected: it replies — proving identity assembly, owner resolution, the
respond-to gate, and the tmpfs secret path all survived the remote route.

- [ ] **Step 9: Verify the marker fence actually refuses**

```bash
~/.local/bin/buzz-backend-gcp remove buzz-acp@<id> --pubkey $(printf 'f%.0s' {1..64})
```
Expected: a refusal naming the mismatch, and **no** change on the instance.
Confirm with `~/.local/bin/buzz-backend-gcp list` that the unit is still there.

- [ ] **Step 10: Tear down and verify the ordering**

```bash
~/.local/bin/buzz-backend-gcp list          # copy the full pubkey for <pk>
~/.local/bin/buzz-backend-gcp remove buzz-acp@<id> --pubkey <pk>
~/.local/bin/buzz-backend-gcp list
gcloud secrets list --project zoop-innovation --filter="name~<id>"
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'ls -l /etc/systemd/system/buzz-acp@.service \
      /etc/systemd/system/buzz-acp-secret@.service \
      /usr/local/sbin/buzz-acp-fetch-key; \
   ls /etc/systemd/system/buzz-acp@<id>.service.d 2>/dev/null || echo "drop-in dir gone"'
```
Expected: `removed buzz-acp@<id>`; the unit absent from `list`; no secret rows
for `<id>`; the **three shared artifacts still present** (other agents depend
on them, and they are re-verified by content hash on the next deploy); and the
drop-in directory gone because it was empty.

- [ ] **Step 11: Full gate**

Run: `just ci`
Expected: PASS. This is the only run of the full gate; the per-task steps used
`cargo test -p …` plus `cargo clippy -p buzz-backend-gcp`.

- [ ] **Step 12: Commit any fixes and open the PR**

```bash
git add -A && git commit -s -m "test(backend-gcp): live smoke fixes"
```

---

## Self-Review

Run against the **approved** design (`docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md`), not the revision that preceded it.

### Spec coverage

| Design section | Task |
|---|---|
| §Where the Provider Runs, §Transport `PATH` | Task 9 (`Remote::new`, `prepended_path`, the named not-found refusal) |
| §Transport host trust, `sudo -n` | Task 9 (`ssh_argv` asserts no `StrictHostKeyChecking`; `install_script`/`append_script`/`removal_script` all use `sudo -n`) |
| §`crates/buzz-backend-core` | Tasks 1-3 |
| §`crates/buzz-backend-gcp` module table | Tasks 4-13, one module per task or per half-task |
| §`info` | Task 4 |
| §`provider_config` v1 fields, §Value grammars | Task 4 (`parse_memory_max`, `parse_cpu_quota`, `reject_control_characters`, the named injection payloads) |
| §Refusals that precede deserialization | Task 5 (raw-JSON, trimmed, exact + padded + control fixtures) |
| §Environment Construction | Task 2 (shared `build_env`) |
| §Binding-specific split: a non-secret allowlist | Task 7 (`NON_SECRET_KEYS`, the four-value leak test) |
| §Host-resolved values | Task 7 (`harness_basename`) + Task 12 (the `harness_installed` refusal) |
| §Lifetime and Supervision | Task 7 (`Restart=no`, `TimeoutStopSec=120`, the indefinite refusal and its golden) |
| §Naming, §Two marker tiers | Task 6 |
| §Secret Manager ownership, destroy-before-forget | Task 10 + Task 13 (`remove` ordering) |
| §Deploy Reconciliation (I4) | Task 12 |
| §Remote Artifacts 1-5 + the fetcher drop-in | Task 7 |
| §fetcher hardening (arity, shape, `--project`, absolute PATH, atomic write, sandbox) | Task 7 |
| §Capacity, the durable trail, `list` surfacing it | Task 8 + Task 13 |
| §Operator Surface, §`dry-run` is the audit, §`remove` fences on identity | Task 13 (including the acceptance criterion at Step 6) |
| §Security Properties | Tasks 7, 9, 10 enforce; Task 14's README states the same-UID residual honestly |
| §Testing (every row) | Tasks 4-13 unit/integration + Task 15 live |
| [L2] item 6 documentation | Task 14 |

### The eight P1 defects, and where each is answered

| Finding | Answer |
|---|---|
| P1-1 capacity warning invisible on success | Task 8 records it durably in the trail; Task 13's `list` reads it back; the design's stderr rationale is corrected in Task 8's preamble. |
| P1-2 `gcloud` not on a GUI `PATH` | Task 9 prepends the three directories and refuses with a named remedy. |
| P1-3 two snippets do not compile | Task 12 matches `&action` so `action` survives the two later comparisons; Task 13 destructures `Cli` before matching `command`. Every other block was re-checked — see below. |
| P1-4 no `relay-mesh` refusal | Task 5, raw JSON before `from_value`, trimmed, with exact/padded/control fixtures. |
| P1-5 `FencedReplace` TOCTOU, observation too weak | Task 11 splits `SystemdState` from `MarkerState`; Task 12 refuses present-but-unmarked and pubkey mismatch, and `fence` re-reads the whole tuple *and* re-confirms not-running. |
| P1-6 `memory_max`/`cpu_quota` injection | Task 4's closed grammars, the CR/LF/NUL scan before trimming, and the named injection payloads. |
| P1-7 non-nsec secrets on disk and in `dry-run` | Task 7's allowlist, `redacted_secret_body`, and the leak test over all four values; Task 13 Step 6 exercises it. |
| P1-8 extraction breaks unmentioned tests | Task 2 Step 4 updates both `AuthoritativeInputs` struct literals (the shared `build` helper and `inactivity_omitted_when_unset`) and adds a case covering `max_env_bytes: None`; Step 2 makes `AUTHORITATIVE_KEYS` `pub`; Step 9 runs `cargo test -p buzz-backend-core` **before** the k8s regression run. Verified while writing this revision: no test asserts the size-cap message, so rewording it changes no expectation — the extraction needs **zero** assertion edits. |

P2-1, P2-2, P2-3, P2-4, P2-5, P2-6, P2-8 are answered by Tasks 10, 6, 12, 13, 3, 13, and 7 respectively. P2-9 (same-UID exposure) is documented as accepted residual risk in Task 14's README, matching the design. P3's `dry-run` criterion is Task 13 Step 6.

### The three rejected findings

Each is recorded in Global Constraints with its evidence, and repeated at the code that would tempt a future reader to "fix" it: stdin forwarding in `remote.rs`'s module doc, `RuntimeDirectoryMode=0750` in `render.rs`'s `FETCHER_UNIT` doc comment, and `StrictHostKeyChecking` in both `ssh_argv`'s doc comment and its test.

### Type consistency across tasks

- `buzz_backend_core::identity::AgentIdentity::{from_nsec, pubkey_hex, short12, short32}` — defined Task 2, used in Tasks 5, 6, 7, 12, 13. The Kubernetes newtype (Task 2 Step 7) exposes the five k8s methods its existing call sites need, unchanged.
- `AuthoritativeInputs { generation, inactivity_seconds, max_env_bytes }` — defined Task 2; both existing call sites updated there (k8s `Some(1024 * 1024)`), new call site Task 7 (`None`).
- `Response::info(name, description, config_schema)` — defined Task 1; call sites Task 1 (kubernetes) and Task 4 (gcp).
- `harness::{fixture, run, run_with_env}` — defined Task 3; used Tasks 3, 4, 5, 7.
- `Names` — defined Task 6 with both constructors; `new(&AgentIdentity)` used in Tasks 7, 12, 13; `from_pubkey_hex(&str)` used only in Task 13's `remove`. Its eleven accessors are used in Tasks 7 (`env_path`, `dropin_path`, `secret_dropin_path`, `secret_name`), 11 (`unit`, `env_path`, `trail_path`, `dropin_path`), 12 (`unit`, `secret_unit`, `env_path`, `trail_path`), and 13 (all of them plus `dropin_dir`, `secret_dropin_dir`).
- `AgentMarker { pubkey_full, create_intent }` / `SharedMarker { content_hash }` — defined Task 6; rendered Task 7, parsed Tasks 11 and 13, compared Task 12.
- `RemoteFile { path, mode, body }` and `SharedArtifact { file, content_hash }` — defined Task 7; consumed Tasks 9 (`install`), 12 (`shared_writes`).
- `Plan { per_agent, shared, secret_env, create_intent, trail_header }` with `secret_body()` / `redacted_secret_body()` — defined Task 7; consumed Tasks 12 and 13.
- `Observation { systemd, markers, harness_installed, reserved_bytes, available_bytes }` — defined Task 11; consumed Task 12. `SHARED_PATHS` is the shared ordering between Tasks 11 and 12 and matches the three `shared_artifact` calls in Task 7.
- `secrets::{verify_owned, store, destroy}` take `pubkey_full: &str` — defined Task 10; `deploy` passes `identity.pubkey_hex()` (Task 12), `remove` passes the operator's normalized value (Task 13). `naming::normalize_pubkey` (Task 6) is the single validation point.
- `capacity::{warning_lines, trail_record, now_rfc3339, parse_reported_bytes}` — defined Task 8; used in Task 7's leak test, Task 11's parser, Tasks 12 and 13.
- `reconcile::deploy(cfg: &ProviderConfig, agent: &AgentPayload)` — signature fixed in Task 5 and unchanged by Task 12, so `main.rs` is written once.

### Move and borrow re-check of every code block

Both reported defects are fixed, and each remaining block was walked:

- Task 12 `deploy`: `action` is matched **by reference**, so the later `action == Action::FencedReplace` and `action != Action::RestartSame` still compile; `PartialEq::eq` borrows. `plan.per_agent` and `plan.create_intent` are disjoint field borrows. `identity` outlives every `identity.pubkey_hex()` use. `warnings` is borrowed by the `eprintln!` loop and then by `trail_record`, both shared borrows.
- Task 13 `run`: `Cli` is destructured first, so `command` moves while `project`/`zone`/`instance` remain owned locals — no borrow of a partially moved value.
- Task 13 `remove`: `resolve_target` returns owned `(Names, String)`, so the shadowed `pubkey` is a fresh `String` and the parameter is not borrowed afterwards.
- Task 7 `plan`: `for (key, value) in env` consumes the map **after** the newline scan that borrows it — the scan's borrow ends at the loop it lives in. `create_intent` is cloned once into the marker and once into `Plan`.
- Task 7 `feed` is a `FnMut` closure capturing `hasher` mutably; it is dropped before `hasher.finalize()` because the last `feed` call is in a `for` loop that ends first. **If the borrow checker objects, replace the closure with a plain `fn feed(hasher: &mut Sha256, label: &str, value: &str)` and pass `&mut hasher` at each call** — same behavior, no capture.
- Task 9 `run_with_stdin`: `argv` is a local `Vec<String>` and `borrowed` a `Vec<&str>` derived from it; both live to the end of the call.
- Task 11 `parse_observation`: every `section(...)` returns a `&str` borrowed from `stdout`, and each is converted to `String` before the `Observation` is built.
- Task 5 `respond`: `raw` is borrowed by `refuse_relay_mesh(&raw)` and then **moved** into `serde_json::from_value(raw)` — the borrow has ended. Same shape as `crates/buzz-backend-kubernetes/src/main.rs:65-77`, which compiles.
- Task 5 `deploy_agent(&deploy)` where `deploy: Box<DeployRequest>` — `&Box<T>` derefs to `&T`; identical to the k8s call at `main.rs:89`.

### Remaining risk, stated honestly

1. **The shared-artifact tamper check depends on GNU `sed`.** Task 11's observer strips the marker with `sed '/^# managed-by: buzz-backend-gcp$/,+3d'`, and `addr,+N` is a GNU extension. The GCE image is Debian-family, so this holds today; on a BusyBox-`sed` image the strip silently removes nothing, every computed hash mismatches, and *every* deploy refuses with "edited outside this provider" — loud, not silent, but wrong. Task 15 Step 7 would catch it on the first live run.
2. **Concurrent deploys of the same agent are not serialized.** Two providers can observe the same state and both proceed. The fence catches the destructive half (the second one's marker or running-state re-read disagrees) and `secrets::store` re-verifies after a create race, but two simultaneous `Create`s can still each install the same files. The outcome is convergent because the content is identical, so this is untidy rather than unsafe — and the desktop issues one deploy per Start click.
3. **The startup poll costs one `gcloud` round trip every 5 s.** For a 240 s worst case that is up to 48 IAP tunnel setups. Correct but wasteful; a future revision should hold one SSH master connection open.
4. **`list` enumerates by globbing `/etc/buzz/acp-*.env` rather than by Secret Manager label.** An agent whose env file was deleted but whose secret survives will not appear. The labels are written and selectable (Task 10) precisely so a follow-up can cross-check both sides; this revision does not.
5. **No test proves the fetcher script actually runs.** Its content is asserted byte-wise offline, but its behavior — arity refusal, shape refusal, atomic rename — is only exercised by Task 15's live deploy succeeding. A shellcheck step or a container-based script test would close this; neither is in scope here.
6. **The desktop still cannot render a success-path warning.** Task 8 works around it durably, but closing it properly needs a `warning` field added to `docs/remote-agents.md:421` and rendered desktop-side. Recorded as design §Follow-ups item 4, deliberately not attempted here.
