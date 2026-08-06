# buzz-backend-gcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `buzz-backend-gcp`, a conforming Buzz backend provider that deploys managed agents as systemd units on the `buzz-agent` GCE VM, so the desktop's "Where to run" selector can target the team's remote server.

**Architecture:** Extract the substrate-neutral half of `buzz-backend-kubernetes` (wire types, three-tier env algorithm, identity derivation, golden request fixtures, pipe harness) into a new `buzz-backend-core` crate; both providers depend on it. `buzz-backend-gcp` then adds the GCE binding: pure rendering of six remote artifacts across two marker tiers, an IAP-SSH transport, label-fenced Secret Manager storage, and an I4 reconciler that separates systemd state from marker state.

**Tech Stack:** Rust 2021 (workspace, rust-version 1.88.0), `serde_json`, `nostr` 0.44 (nsec decoding), `sha2` 0.11 + `hex` 0.4, `rand` 0.10, `chrono` 0.4, `clap` 4 for the operator argv surface. No async runtime in the GCP crate — every remote call is a blocking `gcloud` subprocess.

**Design:** [`docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md`](../specs/2026-08-05-buzz-backend-gcp-design.md) — **approved**. Where this plan and the design disagree, the design wins.
**Normative spec:** [`docs/remote-agents.md`](../../remote-agents.md)
**Reviews this revision answers:** [r1](../reviews/2026-08-05-buzz-backend-gcp-plan-review-r1.md) · [r2](../reviews/2026-08-05-buzz-backend-gcp-plan-review-r2.md) · [r3](../reviews/2026-08-05-buzz-backend-gcp-plan-review-r3.md)

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
- **`--workspace` does not mean the whole repo.** Root `Cargo.toml:33` has `exclude = ["desktop/src-tauri"]`, so the desktop crate is a *separate* Cargo workspace that no `--workspace` or `-p` command in this plan reaches (AGENTS.md gotcha 5). It nonetheless depends on things this plan moves: `desktop/src-tauri/src/commands/agents_tests.rs:417` reads the shared `deploy-full-launch.request.json` fixture by relative path, because that fixture is the arbiter of a contract the desktop and every provider share. **Any task that moves, renames, or changes a shared fixture must also run** `cargo test --manifest-path desktop/src-tauri/Cargo.toml deploy_payload_matches_the_shared_full_launch_fixture` **and report the result.** Task 3 discovered this the hard way: the extraction broke that test, every plan-scoped command stayed green, and only a clean-cutover sweep for callers caught it.
- **Interim `#[allow(dead_code)]` is permitted, and must come due.** `buzz-backend-gcp` is a binary crate with no `[lib]` target, so dead-code analysis is rooted at `main()`. Tasks 6-10 each add a module (`naming.rs`, `render.rs`, `capacity.rs`, `remote.rs`, `secrets.rs`) that nothing outside its own tests calls until the reconciler wires it, so `cargo clippy --all-targets -- -D warnings` will fail on the non-test build in between. Two rules, decided once so it is not rediscovered five times. **First:** annotate per item, never per module or crate, and give every annotation a comment naming the condition that removes it — a condition, not a guess ("once `reconcile::deploy` calls it", not "by Task N", because task numbers move). **Second: the task that wires a module deletes the annotations it makes live, in the same commit.** Do not leave one behind on the grounds that clippy still passes; an allow that outlives its reason is a permanent suppression wearing a promise. Task 14 sweeps for stragglers and fails if any remain.

### Three facts that were verified and must not be "fixed"

A future reader will be tempted to change each of these. Each was tested; changing it is a regression.

1. **`gcloud compute ssh --command` DOES forward local stdin.** It execs a real `/usr/bin/ssh` with the remote command as trailing argv, and `ssh` forwards stdin to it. Measured: 30 bytes piped to `buzz-agent`, the remote `wc -c` returned `30` with a matching md5. This is what makes the stdin install path sound — **do not** rewrite the transport onto `scp` or remote temp files. (Review r1, rejected finding 1.)
2. **`RuntimeDirectory=` at `0750` root:root does not block the agent.** systemd's *manager* reads `EnvironmentFile=` as root before dropping to `User=`. Live proof on this same host: the running `buzz-acp.service` has `User=buzzacp` and `EnvironmentFile=/etc/buzz/acp.env` at mode **0600 root:root**, and starts. **Do not** widen the runtime directory mode. (Review r1, rejected finding 2.)
3. **`StrictHostKeyChecking` is deliberately left alone.** `gcloud` already selects `StrictHostKeyChecking=yes` against `~/.ssh/google_compute_known_hosts`, keyed by `HostKeyAlias=compute.<instance id>` with `CheckHostIP=no`. Passing `-o StrictHostKeyChecking=no` would be a strict *downgrade* while installing root-owned unit files. **Do not** add that flag back. (Design §Transport.)

`sudo -n` is used on every privileged step. Passwordless sudo is verified on this host, so `-n` changes no outcome today; it stays because on a host that *did* prompt, the prompt would consume the piped file body as keystrokes and write a truncated root-owned unit file.

### One mechanism that was deliberately removed

The revision before this one gave shared artifacts a `# content-hash:` marker line and had the observer recompute it with the header stripped, to detect out-of-band edits to root-owned units. **That mechanism is deleted, not disabled, and must not be reintroduced.** A digest a file declares about itself cannot detect an editor who can also edit the digest; the strip was a GNU-`sed` range that removed every matching block anywhere in the file, so hidden directives were excluded from the hash and executed by systemd anyway; and a `binding-version` bump hashed differently and read as "tampered", making a provider upgrade an unrecoverable lockout. Nothing in the approved design asks for it. Shared artifacts are **write-if-absent-or-content-differs**, compared by hashing both sides independently.

**What deleting it did not fix.** Round 3 found that the *upgrade lockout* survived the deletion: it had a second home in the ownership predicate, which conjoined `managed-by` with an **exact** `binding-version`, so the first bump would have made every artifact already on the instance read as "present and not ours" — `deploy` refusing to upgrade it, `remove` refusing to delete it, and the refusal telling the operator their own agent was somebody else's. Ownership is therefore version-aware everywhere in this binding (`naming::Ownership`, Task 6): an **older** binding version is an authorised upgrade target at both file tiers and in Secret Manager, a **newer** one is a refusal that names the version, and the shell fences compare the version with `-le` rather than matching it as a literal line. Do not re-collapse that into a boolean — it reads like a simplification and it is the lockout.

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

Two more changes to the moved file, and nothing else:

1. Add `Clone` to the derive lists of `AgentPayload` and `LaunchBlock` — `#[derive(Debug, Clone, Deserialize)]` and `#[derive(Debug, Default, Clone, Deserialize)]`. Every field is already `Clone`, so this is additive and changes no behavior. Task 7 needs it: the GCE binding rewrites `launch.command` to the instance's spelling of the harness on a **copy** of the payload before `build_env` reads it, which is what stops a desktop host path from reaching the VM (review r2, P1-1).
2. Correct `LaunchBlock::command`'s doc comment, which currently reads *"Command **name**, resolved against the image's PATH — never a host path."* That is a statement of intent the desktop does not honor: `discovery.rs:443-449` deliberately preserves an explicit host path. Replace it with what is true, so the next reader does not rely on the wrong half:

```rust
    /// The command the desktop resolved, **as the desktop resolved it** — which
    /// may be a bare name or an absolute host path
    /// (`desktop/src-tauri/src/managed_agents/discovery.rs:443-449`). A host
    /// path is meaningless on any remote substrate, so each binding is
    /// responsible for reducing this to something its own substrate can exec
    /// before it reaches an environment (see `buzz-backend-gcp`'s
    /// `render::with_instance_harness`).
    #[serde(default)]
    pub command: Option<String>,
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
Expected: PASS. **Counts move with the code, so check the total, not one crate.** `wire.rs` carries its own `#[cfg(test)] mod tests` (7 tests), and Step 3 moves that file — so those 7 relocate to `buzz-backend-core` and kubernetes drops to **147 unit + 4 integration**, with `cargo test -p buzz-backend-core` reporting **7**. The invariant is `147 + 7 = 154`, the pre-extraction total, conserved. **No test file may be edited in this task** — relocation is not modification. If an assertion needed changing to make either crate pass, the extraction changed behavior; revert and find out why.

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
    /// A substrate with no cap must not inherit Kubernetes' 1 MiB rule: a
    /// systemd `EnvironmentFile` on a 38 GB boot disk has no such boundary to
    /// respect, and `MAX_SECRET_BYTES` was an apiserver limit, not a law.
    ///
    /// What this does **not** say is that any environment this accepts is
    /// deployable. `max_env_bytes: None` means "this core has no opinion", not
    /// "no limit applies": each binding still owes its own substrate's rules.
    /// The 2 MiB below is a case in point — `BIG` is not on the GCP binding's
    /// non-secret allowlist, so that binding classifies it as secret, and the
    /// secret half travels as one Secret Manager version, whose payload is
    /// capped at 64 KiB. `buzz_backend_gcp::render::plan` therefore **refuses**
    /// this exact environment, in its pure phase, before any mutation
    /// (`a_secret_payload_over_secret_managers_cap_is_refused_before_any_mutation`).
    /// That division is the point of the parameter: the core stops asserting a
    /// limit it cannot know, and each binding asserts the one it can.
    #[test]
    fn an_uncapped_substrate_leaves_the_size_rule_to_its_binding() {
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
        .expect("no cap here means no refusal here");
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
Expected: PASS. **Check the conserved total, not one crate's count** — see Task 1 Step 6 for why. `env.rs` and the identity code carry their own test modules, so moving them relocates those tests into `buzz-backend-core`; kubernetes falls by exactly that many and core rises by the same. Record both numbers and confirm the sum still equals 154. **What is frozen is what a test asserts** — no assertion, no expectation and no count may change, in any `#[cfg(test)]` module or any file under `crates/buzz-backend-kubernetes/tests/`. That is the rule's whole purpose: it stops a failing test being made to pass by weakening it. **An import path forced by a move is not a test edit** — repointing `crate::env::START_NONCE_KEY` to `buzz_backend_core::env::START_NONCE_KEY` inside a test module names the same symbol at its new address, exercises the same values, and hides nothing; do it, and call it out in the report so the reviewer can see it was a path change. Do **not** preserve the old path with a re-export shim: the Global Constraints mandate a clean cutover, and a shim leaves a second permanent name for one module. Beyond those mechanical repoints, the only substantive test edits permitted anywhere in the extraction are the two `AuthoritativeInputs` struct literals enumerated in Step 4, which live in the *moved* `env.rs` and are forced by a new required field. If anything else needs touching, the extraction changed behavior.

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
Expected: PASS in both, with **every count unchanged from where Task 2 left them** — `buzz-backend-core` at **36 unit**, `buzz-backend-kubernetes` at **123 unit + 4 integration**, total **159 unit + 4 integration**. That 159 is the 154 pre-existing tests conserved plus the 5 Task 2 prescribed; it is not drift. This task moves fixture *data* and the harness, and repoints three private helpers inside an integration test file — no unit test is in scope, so a moved number here is a finding to report, not a discrepancy to explain away. The count that carries the real risk is the **4**: after the harness moves, each integration test must still spawn the built binary and talk to it over a real pipe. A fixture test that quietly stopped spawning a process would keep passing while proving nothing, so confirm the mechanism, not just the colour of the result.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "refactor(backend): share provider-wire requests and the pipe harness"
```

---

## Task 4: `buzz-backend-gcp` skeleton — `info`, the config schema, and the closed value grammars

Resolves review **P1-6**, and round 2's **P1-3** (`project` reaches a root drop-in as an unvalidated `Environment=` value).

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
  - `config::parse_memory_max(&str) -> Result<u64, String>`, `config::parse_cpu_quota(&str) -> Result<u32, String>`, `config::parse_resource_name(field: &str, value: &str) -> Result<(), String>`
  - `config::{DEFAULT_PROJECT, DEFAULT_ZONE, DEFAULT_INSTANCE, DEFAULT_MEMORY_MAX, DEFAULT_CPU_QUOTA, DEFAULT_INACTIVITY_SECONDS}`
  - `respond(input: &str) -> Response` in `main.rs`
- Consumes: `buzz_backend_core::wire::{Request, Response}`, `buzz_backend_core::harness`.

**Why the grammars are closed and rejecting, not sanitizing.** `memory_max` and `cpu_quota` are the only config values this binding interpolates into a **root-installed systemd drop-in**. A drop-in is line-oriented and systemd accepts every `[Service]` directive it finds, so an accepted value containing a newline *is* arbitrary unit content: `2G\nEnvironmentFile=/tmp/x.env` adds a second environment source that overrides the authoritative tier, and `2G\nExecStart=\nExecStart=/bin/sh -c …` uses systemd's empty-assignment reset to replace the agent command outright — both while the file still carries a valid management marker, so every fence in this design reads it as legitimately ours. The desktop cannot catch this: `validate_provider_config` (`desktop/src-tauri/src/managed_agents/backend.rs:536-566`) checks flatness, field count, scalar-ness and secret-like key *names*, never a value's contents. The provider is the only place this stops.

**The third interpolation, and why it gets the same treatment.** The revision that closed `memory_max` and `cpu_quota` introduced a value the threat model had not covered: `Environment=BUZZ_GCP_PROJECT={cfg.project}` in the fetcher's per-agent drop-in. `project` was only trimmed and CR/LF/NUL-scanned — but systemd's `Environment=` is *whitespace- and quote-parsed* and expands `%` specifiers, so a space, a quote, an `=` or a `%` appends a second assignment to the one unit deliberately allowed to reach the metadata server and Secret Manager. `project = "zoop BUZZ_GCP_SECRET=evil"` renames the secret that unit fetches; `CLOUDSDK_CONFIG` or `HTTPS_PROXY` redirect where it fetches from. `zone` and `instance` reach `gcloud` argv rather than a unit file, which is a weaker exposure — but they are the same class of caller-supplied name and get the same grammar rather than a second, weaker rule that has to be remembered. The grammar is the intersection of what GCE and Secret Manager accept for project ids, zones and instance names, so nothing legitimate is excluded.

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

    #[test]
    fn resource_names_inside_the_grammar_parse() {
        let c = ProviderConfig::parse(&json!({
            "project": "zoop-innovation",
            "zone": "asia-south1-a",
            "instance": "buzz-agent"
        }))
        .unwrap();
        assert_eq!(c.project, "zoop-innovation");
        assert_eq!(c.zone, "asia-south1-a");
        assert_eq!(c.instance, "buzz-agent");
    }

    /// P1-3: `project` is interpolated into `Environment=BUZZ_GCP_PROJECT=…`
    /// in a **root-installed** drop-in on the one unit allowed to reach the
    /// metadata server. systemd's `Environment=` is whitespace- and
    /// quote-parsed and expands `%` specifiers, so anything outside the closed
    /// grammar can append a second assignment. `zone` and `instance` get the
    /// same grammar rather than a second, weaker rule.
    #[test]
    fn resource_names_that_could_inject_a_systemd_directive_are_refused() {
        let cases = [
            // A second assignment on the same Environment= line.
            ("project", "zoop BUZZ_GCP_SECRET=evil"),
            ("project", "zoop CLOUDSDK_CONFIG=/tmp/x"),
            // systemd unquotes Environment= values, so quotes are structural.
            ("project", "\"zoop\""),
            ("project", "zoop'q"),
            // `%` is a specifier prefix, expanded before the value is used.
            ("project", "%i"),
            ("project", "zoop%n"),
            // Shape rules, so a typo is a refusal rather than a lookup failure
            // against a project that happens to exist.
            ("project", "-leading-hyphen"),
            ("project", "trailing-hyphen-"),
            ("project", "UPPERCASE"),
            ("project", "under_score"),
            ("project", "dot.separated"),
            ("project", "sl/ash"),
            ("zone", "asia-south1-a EnvironmentFile=/tmp/x"),
            ("instance", "buzz agent"),
            ("instance", "../../etc/passwd"),
        ];
        for (field, payload) in cases {
            let err = ProviderConfig::parse(&json!({ field: payload }))
                .err()
                .unwrap_or_else(|| panic!("accepted out-of-grammar {field} {payload:?}"));
            assert!(
                err.contains(field),
                "{field}: the refusal must name the field: {err}"
            );
            assert!(
                !err.contains(payload),
                "{field}: the refusal echoed the value, which L2 item 5 forbids: {err}"
            );
        }
    }

    /// Both length bounds, kept out of the refusal test above because a
    /// one-character payload appears in any English sentence and would trip
    /// that test's does-not-echo assertion for the wrong reason. 64 is one over
    /// the RFC 1035 label limit GCE enforces on instance names.
    #[test]
    fn resource_name_length_bounds_are_enforced() {
        assert!(parse_resource_name("project", "a").is_err());
        assert!(parse_resource_name("project", "").is_err());
        assert!(parse_resource_name("project", "ab").is_ok());
        assert!(parse_resource_name("project", &"a".repeat(63)).is_ok());
        assert!(parse_resource_name("project", &"a".repeat(64)).is_err());
    }

    /// The control-character scan runs before trimming for **every** string
    /// field, not only the two with closed size grammars — and neither refusal
    /// echoes the value.
    #[test]
    fn a_resource_name_carrying_a_control_character_is_refused_not_trimmed() {
        for payload in [
            "zoop-innovation\n",
            "zoop-innovation\r",
            "zoop-innovation\u{0}",
        ] {
            let err = ProviderConfig::parse(&json!({"project": payload}))
                .expect_err("a control character must be refused, never trimmed away");
            assert!(err.contains("project"), "{err}");
            assert!(
                !err.contains("zoop-innovation"),
                "the refusal echoed the value: {err}"
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
                "pattern": "^[a-z][a-z0-9-]{0,61}[a-z0-9]$",
                "description": "GCP project containing the instance"
            },
            "zone": {
                "type": "string", "default": DEFAULT_ZONE,
                "pattern": "^[a-z][a-z0-9-]{0,61}[a-z0-9]$",
                "description": "Compute zone of the instance"
            },
            "instance": {
                "type": "string", "default": DEFAULT_INSTANCE,
                "pattern": "^[a-z][a-z0-9-]{0,61}[a-z0-9]$",
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

/// The longest resource name this binding will interpolate. 63 is the RFC 1035
/// label limit GCE enforces on instance names, and the tightest of the three.
const MAX_RESOURCE_NAME_LEN: usize = 63;

/// Parse `project`, `zone` or `instance` against a closed grammar:
/// `^[a-z][a-z0-9-]{0,61}[a-z0-9]$`.
///
/// `project` is not decoration. It is interpolated into
/// `Environment=BUZZ_GCP_PROJECT=<value>` inside a **root-installed** drop-in
/// on the one unit deliberately allowed to reach the metadata server and Secret
/// Manager. systemd's `Environment=` is whitespace- and quote-parsed and
/// expands `%` specifiers, so a value carrying a space, a quote, an `=` or a
/// `%` appends a second assignment to that unit's environment —
/// `BUZZ_GCP_SECRET`, `CLOUDSDK_CONFIG`, `HTTPS_PROXY`. `zone` and `instance`
/// reach `gcloud` argv rather than a unit file, a weaker exposure, but they are
/// the same class of caller-supplied name and get the same rule rather than a
/// second one somebody has to remember.
///
/// The grammar is the intersection of what GCE and Secret Manager accept for
/// project ids, zones and instance names, so nothing legitimate is excluded.
/// Byte-wise throughout, so a multi-byte character fails the character-class
/// check rather than splitting a code point.
pub fn parse_resource_name(field: &str, value: &str) -> Result<(), String> {
    let refuse = || {
        format!(
            "provider_config.{field} is not a name this binding accepts (2 to \
             {MAX_RESOURCE_NAME_LEN} characters: a lowercase letter, then \
             lowercase letters, digits or '-', ending in a lowercase letter or \
             digit — for example zoop-innovation, asia-south1-a, buzz-agent). \
             It is refused rather than sanitized because it is interpolated \
             into a root-installed systemd drop-in, where a space, a quote, an \
             '=' or a '%' becomes a second unit directive. The value is not \
             echoed."
        )
    };
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.len() > MAX_RESOURCE_NAME_LEN {
        return Err(refuse());
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(refuse());
    }
    let last = bytes[bytes.len() - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return Err(refuse());
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(refuse());
    }
    Ok(())
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

        let project = text("project", DEFAULT_PROJECT);
        parse_resource_name("project", &project)?;
        let zone = text("zone", DEFAULT_ZONE);
        parse_resource_name("zone", &zone)?;
        let instance = text("instance", DEFAULT_INSTANCE);
        parse_resource_name("instance", &instance)?;

        let memory_max = text("memory_max", DEFAULT_MEMORY_MAX);
        let memory_max_bytes = parse_memory_max(&memory_max)?;
        let cpu_quota = text("cpu_quota", DEFAULT_CPU_QUOTA);
        parse_cpu_quota(&cpu_quota)?;

        Ok(Self {
            project,
            zone,
            instance,
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
Expected: PASS — 4 integration tests (`tests/wire.rs`) and 17 unit tests (`config`).

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): provider skeleton with info and closed config grammars"
```

---

## Task 5: The raw-JSON `relay-mesh` refusal, before deserialization

Resolves review **P1-4**, and round 2's **P2-7** (the golden was satisfied by any error mentioning the string `relay-mesh`).

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
    /// (`agents_deploy.rs:116`); this is the layer that owes the obligation.
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

Resolves review **P2-2**, round 2's **P1-6** — by *deleting* the shared-artifact content-hash tamper check rather than repairing it — and round 3's **P1-1**, which found that deleting the tamper check removed only one half of the upgrade lockout: the other half was living inside `is_ours`.

**Files:**
- Create: `crates/buzz-backend-gcp/src/naming.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod naming;`)

**Interfaces:**
- Produces:
  - `naming::{MANAGED_BY, BINDING_VERSION, SHARED_SCOPE}`
  - `naming::sha256_hex(&[u8]) -> String`
  - `naming::header_line(name: &str, value: &str) -> String`
  - `naming::Names::new(&AgentIdentity) -> Names` with `instance()`, `unit()`, `secret_unit()`, `env_path()`, `trail_path()`, `dropin_dir()`, `dropin_path()`, `secret_dropin_dir()`, `secret_dropin_path()`, `secret_name()`. There is deliberately **no** `runtime_dir()`: `/run/buzz-acp-%i` is spelled by systemd's `RuntimeDirectory=` and by the fetcher script, never by this provider, and a `pub` accessor nothing calls is `dead_code` in a binary crate — which `-D warnings` turns into a build failure.
  - `naming::Names::from_pubkey_hex(pubkey_hex: &str) -> Result<Names, String>` and `naming::normalize_pubkey(value: &str) -> Result<String, String>` — the operator route, used by `remove` and by the reconciler's tests
  - `naming::AgentMarker { pubkey_full: String, create_intent: String }` with `render() -> String`, `parse(&str) -> Option<AgentMarker>`
  - `naming::shared_marker() -> String`
  - `naming::Ownership` — `Ours | OursButOlder(u32) | OursButNewer(u32) | NotOurs`, deriving `Debug, Clone, Copy, Default, PartialEq, Eq`, with `actionable(self) -> bool`
  - `naming::ownership_of(managed_by: Option<&str>, binding_version: Option<&str>) -> Ownership`, and the two tier readers `naming::agent_ownership(body: &str) -> Ownership` and `naming::shared_ownership(body: &str) -> Ownership`
  - `naming::BINDING_VERSION_NUM: u32` — the same value as `BINDING_VERSION`, as a number, because ownership is an ordering question
- Consumes: `buzz_backend_core::identity::AgentIdentity`, `sha2`, `hex`.

**Why two tiers.** A template unit is installed once and used by every instance. Stamping it with one agent's `agent-pubkey-full` and `create-intent` means the next deploy of a *different* agent rewrites the same file with a different identity, so the identity recorded on a shared file means nothing more than "whoever deployed most recently" — while the fence that reads it is asking "is this file *this* agent's?". Answering that from a shared file is wrong in both directions: it authorizes destroying a file three other agents depend on, and it refuses when the file is legitimately ours. The invariant the tests enforce is therefore *"every installed file carries the marker of its own tier"* — never *"every installed file carries the per-agent marker"*, which is enforceable only by making the shared marker a lie.

**Why the provider-level marker carries no content hash — and why that mechanism is deleted rather than fixed.** The previous revision put a `# content-hash:` line in the shared header and had the observer recompute it with the header stripped. Round 2 found three defects in that one mechanism. The presence of the line alone was read as "this file is ours", so a foreign file carrying it was adopted. The strip was `sed '/^# managed-by: buzz-backend-gcp$/,+3d'`, which deletes **every** matching four-line block anywhere in the file, so directives hidden inside a second such block were removed before hashing and executed by systemd anyway. And a future `binding-version: 2` hashes differently, reads as "tampered", and turns a provider upgrade into an unrecoverable lockout. It also owned this binding's only GNU-`sed` dependency.

All three are symptoms of one thing: **a digest a file declares about itself cannot detect an editor who can also edit the digest.** The check was unsound as specified, not merely buggy. It was also the only mechanism in the plan solving a problem the approved spec does not pose — the spec asks for write-if-absent-or-different and for an unmarked shared file to be a refusal, and asks for nothing about detecting out-of-band edits to root-owned units.

What replaces it is what the spec already asked for: a shared artifact is written when it is **absent, or when the bytes on the instance differ from the bytes this provider would render**, compared by independently hashing both sides — `sha256sum` over the whole file on one, `sha256_hex` over the rendered body on the other. Neither side trusts a claim stored in the file. An out-of-band edit is therefore still *detected*, because it makes the bytes differ; the response is to converge, which is the right answer for a shared, identity-free, byte-identical, idempotent artifact. The GNU-`sed` dependency is gone. The provider-level marker survives as a plain provenance comment feeding the one fence the spec *does* state: a shared file present with **no** marker is a refusal, not an overwrite. (What deleting the digest did *not* fix is the upgrade lockout — that half lived in the ownership predicate, and is the subject of the next section.)

**Why ownership is four states and not a boolean.** Round 2 deleted the content-hash check partly because a `binding-version` bump made every existing shared file read as "tampered" — an unrecoverable upgrade lockout — and this plan then asserted in three places that the lockout was gone. It was not. `is_ours` was the conjunction `managed-by == MANAGED_BY ∧ binding-version == BINDING_VERSION`, so the moment `BINDING_VERSION` became `"2"` every artifact written at version 1 read as *present and not ours*. `classify` refused on the first one, so `deploy` could not upgrade the agent; `verify_removable` refused identically, so `remove` could not tear it down; and the refusal text told the operator that their own prior-version agent was somebody else's file. The lockout had not died, it had moved — and `BINDING_VERSION` is documented as "bump when the unit/env shape changes", a *designed-for* event.

So ownership is a verdict with four states rather than a flag:

| State | Meaning | What acts on it |
|---|---|---|
| `Ours` | This provider, this binding version | Ordinary reconciliation |
| `OursButOlder(v)` | This provider, a layout this build supersedes | **Authorised upgrade target**: per-agent artifacts classify `FencedReplace`, shared ones take the ordinary write-if-different path, the Secret Manager labels are rolled forward with `--update-labels` and then a version is added, and `remove` may still delete |
| `OursButNewer(v)` | This provider, a layout this build does not understand | Refusal, naming the version — a downgrade destroys a newer provider's work |
| `NotOurs` | Foreign `managed-by`, unparseable version, or no marker | Refusal — somebody else's file |

A fourth state rather than the three a strict reading would give: collapsing "newer" into `NotOurs` costs the operator the one sentence that tells them what actually happened, and P1-1 exists precisely because a refusal described the operator's own agent as foreign. `actionable()` is the single predicate every caller uses to mean "this build may write or delete this", and it is true for `Ours` and `OursButOlder` only.

`BINDING_VERSION_NUM` exists because the question is an *ordering* and a string comparison cannot answer it; `BINDING_VERSION` remains the decimal spelling written into headers and Secret Manager labels, and a test asserts the two agree. A version that is not a decimal number describes no layout to order against and is `NotOurs` — fail closed. The same `ownership_of` serves both file-header tiers and Secret Manager's two labels, so the four states mean one thing across this binding rather than one thing per storage medium. And the shell readers do the ordering too: `remote::marker_fn`, `reconcile::fenced_stop_script` and `operator::listing_script` all compare with `-le BINDING_VERSION_NUM` rather than matching an exact `# binding-version:` line, because a guard that required the exact current version would refuse the very install that upgrades the file.

**Header shapes.** A per-agent header is four contiguous lines; a shared header is three. No reader depends on the position: each takes the first `remote::MARKER_SCAN_LINES` of a file and asserts every required line independently, anywhere in that window, which is why the fetcher script's shebang above its header costs nothing. "Independently" is load-bearing — round 3's P1-3 found the shell readers counting matching *lines* with `grep -c` and comparing the count to the number of needles, which a header with a duplicated line satisfies while omitting another entirely.

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
    }

    /// The instance name is what `%i` expands to, what the fetcher script's
    /// shape check enforces, and what the deploy lease path is built from, so
    /// it must be exactly 12 lowercase hex.
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

    /// The provider-level marker states exactly three things: this provider
    /// wrote the file, at this binding version, for every instance. It carries
    /// no agent identity because a shared file belongs to no agent — and no
    /// content digest, because a claim a file makes about its own contents is
    /// worth exactly what its writer is worth.
    #[test]
    fn the_provider_marker_says_only_what_is_true() {
        let header = shared_marker();
        assert_eq!(shared_ownership(&header), Ownership::Ours);
        assert!(header.contains(&header_line("managed-by", MANAGED_BY)));
        assert!(header.contains(&header_line("binding-version", BINDING_VERSION)));
        assert!(header.contains(&header_line("scope", SHARED_SCOPE)));
        for absent in ["content-hash", "agent-pubkey", "create-intent"] {
            assert!(!header.contains(absent), "the shared marker claims {absent}");
        }
    }

    /// The two spellings of the binding version must agree, or the header a
    /// file carries and the number every ordering compares against describe
    /// different releases — and the one place that shows up is an upgrade.
    #[test]
    fn the_two_spellings_of_the_binding_version_agree() {
        assert_eq!(BINDING_VERSION.parse::<u32>(), Ok(BINDING_VERSION_NUM));
    }

    /// The tiers must not be readable as each other. A shared file read as
    /// per-agent would hand a fence an identity that is not there; a per-agent
    /// file read as shared would let a shared-file rule act on one agent's file.
    #[test]
    fn the_two_tiers_do_not_parse_as_one_another() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "c0ffee".to_string(),
        }
        .render();
        let shared = shared_marker();
        assert_eq!(shared_ownership(&agent), Ownership::NotOurs);
        assert_eq!(agent_ownership(&shared), Ownership::NotOurs);
        assert!(AgentMarker::parse(&shared).is_none());
    }

    #[test]
    fn an_unmarked_file_yields_no_marker_of_either_tier() {
        let body = "# just some file\nFOO=bar\n";
        assert!(AgentMarker::parse(body).is_none());
        assert_eq!(agent_ownership(body), Ownership::NotOurs);
        assert_eq!(shared_ownership(body), Ownership::NotOurs);
    }

    /// A per-agent header at an arbitrary binding version. Version 0 never
    /// shipped, but the ordering rule has to be exercised *now*: the bump that
    /// creates a real prior version is exactly the moment nobody will go back
    /// and re-derive what should happen to the artifacts already on the box.
    fn agent_header_at(version: &str) -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: {version}\n\
             # agent-pubkey-full: {}\n# create-intent: ci\n",
            "ab".repeat(32)
        )
    }

    fn shared_header_at(version: &str) -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: {version}\n\
             # scope: {SHARED_SCOPE}\n"
        )
    }

    /// P1-1. An **older** binding version is this provider's own work at a
    /// layout this build supersedes — an authorised upgrade target at both
    /// tiers, with its identity intact, because `remove` acts on that pubkey
    /// and `FencedReplace` rewrites the file that carries it. Reading it as
    /// "not ours" is what made a version bump lock the operator out of
    /// `deploy` *and* `remove` for every agent already installed.
    #[test]
    fn an_older_binding_version_is_ours_and_an_upgrade_target() {
        let body = agent_header_at("0");
        assert_eq!(agent_ownership(&body), Ownership::OursButOlder(0));
        assert!(agent_ownership(&body).actionable());
        let marker = AgentMarker::parse(&body).expect("an upgrade target keeps its identity");
        assert_eq!(marker.pubkey_full, "ab".repeat(32));

        let shared = shared_header_at("0");
        assert_eq!(shared_ownership(&shared), Ownership::OursButOlder(0));
        assert!(shared_ownership(&shared).actionable());
    }

    /// …and a **future** one is the refusal the rule reserves, at both tiers.
    /// The layout it describes is one this build cannot reason about, so
    /// overwriting or deleting it would destroy a newer provider's work — and
    /// it must be a *distinct* state from "somebody else's file", or the
    /// refusal tells the operator their own newer agent is foreign.
    #[test]
    fn a_future_binding_version_is_refused_at_both_tiers() {
        let body = agent_header_at("99");
        assert_eq!(agent_ownership(&body), Ownership::OursButNewer(99));
        assert!(!agent_ownership(&body).actionable());
        assert!(
            AgentMarker::parse(&body).is_none(),
            "a layout this build cannot read must yield nothing to act on"
        );
        assert_eq!(
            shared_ownership(&shared_header_at("99")),
            Ownership::OursButNewer(99)
        );
    }

    /// A version that is not a decimal number describes no layout to order
    /// against. Fail closed rather than guessing.
    #[test]
    fn a_binding_version_that_is_not_a_number_is_not_ours() {
        for version in ["", "1.0", "v1", "one", "-1", "0x1"] {
            assert_eq!(
                agent_ownership(&agent_header_at(version)),
                Ownership::NotOurs,
                "binding-version {version:?} was ordered against ours"
            );
            assert_eq!(
                shared_ownership(&shared_header_at(version)),
                Ownership::NotOurs,
                "binding-version {version:?} was ordered against ours"
            );
        }
    }

    #[test]
    fn a_marker_from_another_tool_is_not_ours() {
        let body = format!(
            "# managed-by: some-other-tool\n# binding-version: {BINDING_VERSION}\n\
             # agent-pubkey-full: {}\n# create-intent: ci\n",
            "ab".repeat(32)
        );
        assert!(AgentMarker::parse(&body).is_none());
        assert_eq!(agent_ownership(&body), Ownership::NotOurs);
        // …and a foreign file that merely declares our scope is still not ours.
        let scoped = format!(
            "# managed-by: some-other-tool\n# binding-version: {BINDING_VERSION}\n\
             # scope: {SHARED_SCOPE}\n"
        );
        assert_eq!(shared_ownership(&scoped), Ownership::NotOurs);
    }

    /// A file plainly ours that names no agent is neither ownable nor
    /// anonymous: `agent_ownership` says ours, `parse` says nothing to act on,
    /// and the caller owes the operator a different sentence from "somebody
    /// else's file".
    #[test]
    fn our_marker_without_an_identity_yields_ownership_but_no_marker() {
        let body = format!("# managed-by: {MANAGED_BY}\n# binding-version: {BINDING_VERSION}\n");
        assert_eq!(agent_ownership(&body), Ownership::Ours);
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

    /// Every header line is produced by `header_line`, and every reader — the
    /// observer's `grep -F -x`, the install guard, `remove`'s fence — matches
    /// those exact strings. A hand-rolled `format!` anywhere else would be a
    /// second spelling nobody notices until a deploy refuses a file it wrote.
    #[test]
    fn each_tier_renders_the_header_shape_its_readers_expect() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "ci".to_string(),
        }
        .render();
        let shared = shared_marker();
        assert_eq!(agent.lines().count(), 4, "{agent}");
        assert_eq!(shared.lines().count(), 3, "{shared}");
        for header in [&agent, &shared] {
            assert!(header.starts_with(&header_line("managed-by", MANAGED_BY)));
            assert!(header.ends_with('\n'));
            for line in header.lines() {
                let (name, value) = line
                    .strip_prefix("# ")
                    .and_then(|rest| rest.split_once(": "))
                    .unwrap_or_else(|| panic!("{line:?} is not a header line"));
                assert_eq!(line, header_line(name, value));
            }
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
//!
//! The provider-level marker deliberately carries **no content digest**. An
//! earlier revision stored one and had the observer recompute it with the
//! header stripped: the strip was a GNU-`sed` range that deleted every matching
//! block anywhere in the file, the presence of the digest line alone was read
//! as ownership, and a future `binding-version` hashed differently and read as
//! tampering — an unrecoverable upgrade lockout. All three follow from one
//! thing: a digest a file declares about itself cannot detect an editor who can
//! also edit the digest. The mechanism was deleted rather than repaired, and
//! the job it should have been doing is done by comparing the installed bytes
//! against the bytes this provider would render, hashed independently on each
//! side (`observe.rs`, `reconcile::shared_writes`).
//!
//! Deleting that check removed the *tamper* half of the upgrade lockout. The
//! other half lived here, in a boolean that conjoined `managed-by` with an
//! **exact** `binding-version`: on the first bump, every artifact this provider
//! had ever written read as "present and not ours", `deploy` refused to upgrade
//! it and `remove` refused to delete it, and the operator was told their own
//! agent was somebody else's file. Ownership is therefore [`Ownership`], a
//! four-state verdict — and an *older* version is an authorised upgrade target
//! everywhere in this binding, not a refusal.

use buzz_backend_core::identity::AgentIdentity;
use sha2::{Digest, Sha256};

/// The management marker's identity half. **No destructive action may touch a
/// file lacking the marker of its own tier** — that is the auto-repair fence.
pub const MANAGED_BY: &str = "buzz-backend-gcp";

/// Schema version of the artifact layout, as it appears in a header line and
/// in a Secret Manager label. Bump when the unit/env shape changes in a way an
/// older provider would mishandle — and bump [`BINDING_VERSION_NUM`] with it.
pub const BINDING_VERSION: &str = "1";

/// The same value as [`BINDING_VERSION`], as a number.
///
/// Ownership is an *ordering* question — is this artifact older than us, ours,
/// or newer — and a string comparison cannot answer it. This is also the value
/// the shell readers compare against with `-le`
/// (`remote::marker_fn`, `reconcile::fenced_stop_script`,
/// `operator::listing_script`), so the two spellings must agree;
/// `the_two_spellings_of_the_binding_version_agree` asserts it.
pub const BINDING_VERSION_NUM: u32 = 1;

/// The `scope:` value that distinguishes a provider-level marker from a
/// per-agent one. Present on shared artifacts, absent from per-agent ones.
pub const SHARED_SCOPE: &str = "provider-shared";

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Render one `# <name>: <value>` header line, without its newline.
///
/// One function, so the writer and every reader agree byte for byte: the
/// observer's `grep -F -x`, the install guard, and `remove`'s fence all match
/// against strings this produces. A hand-rolled `format!` elsewhere would be a
/// second spelling nobody notices until a deploy refuses a file it wrote.
pub fn header_line(name: &str, value: &str) -> String {
    format!("# {name}: {value}")
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

/// How an artifact's own marker relates to **this** build.
///
/// Four states rather than a boolean, and the reason is the upgrade path.
/// [`BINDING_VERSION`] is documented as "bump when the unit/env shape changes"
/// — a designed-for event — so the version an artifact carries is routinely
/// *older* than the one deciding what to do with it. Collapsing that into "not
/// ours" made every artifact written before a bump read as a foreign file:
/// `classify` refused, so `deploy` could not upgrade it, and
/// `verify_removable` refused identically, so `remove` could not tear it down.
/// The agent became unmanageable in both directions.
///
/// `OursButNewer` is a separate state from `NotOurs` even though both refuse,
/// because the sentences differ and the difference matters: one says "upgrade
/// this provider", the other says "somebody else's file is in the way".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Ownership {
    /// This provider, at exactly this binding version.
    Ours,
    /// This provider, at an **older** binding version. An authorised upgrade
    /// target: per-agent artifacts are replaced, shared ones are rewritten when
    /// their bytes differ, Secret Manager labels are rolled forward, and
    /// `remove` may still delete.
    OursButOlder(u32),
    /// This provider, at a **newer** binding version. A refusal: a build that
    /// cannot reason about a layout must not overwrite or delete it.
    OursButNewer(u32),
    /// A foreign `managed-by`, a version that is not a decimal number, or no
    /// marker at all.
    #[default]
    NotOurs,
}

impl Ownership {
    /// May this build write, replace, or delete the artifact?
    ///
    /// The single predicate every caller uses, so "may we act" has one
    /// definition. True for [`Ownership::Ours`] and [`Ownership::OursButOlder`]
    /// only — an upgrade is an action, not a refusal.
    pub fn actionable(self) -> bool {
        matches!(self, Ownership::Ours | Ownership::OursButOlder(_))
    }
}

/// The one rule that turns a `managed-by` / `binding-version` pair into a
/// verdict.
///
/// Fed by both file-header tiers below **and** by Secret Manager's two labels
/// (`secrets::verify_owned`), so the four states mean the same thing on every
/// storage medium this binding uses rather than one thing per medium.
///
/// A version that does not parse as a `u32` is [`Ownership::NotOurs`]: it
/// describes no layout to order against, and guessing is how a downgrade
/// silently destroys a newer provider's work.
pub fn ownership_of(managed_by: Option<&str>, binding_version: Option<&str>) -> Ownership {
    if managed_by != Some(MANAGED_BY) {
        return Ownership::NotOurs;
    }
    match binding_version.and_then(|value| value.parse::<u32>().ok()) {
        Some(version) if version == BINDING_VERSION_NUM => Ownership::Ours,
        Some(version) if version < BINDING_VERSION_NUM => Ownership::OursButOlder(version),
        Some(version) => Ownership::OursButNewer(version),
        None => Ownership::NotOurs,
    }
}

/// Ownership of a **per-agent** artifact, read from its own header.
///
/// A header declaring a `scope` is a shared one at a per-agent path, which is
/// not ours *at this tier* — the tiers must not be readable as each other.
pub fn agent_ownership(body: &str) -> Ownership {
    if header_field(body, "scope").is_some() {
        return Ownership::NotOurs;
    }
    ownership_of(
        header_field(body, "managed-by").as_deref(),
        header_field(body, "binding-version").as_deref(),
    )
}

/// Ownership of a **shared** artifact, read from its own header.
///
/// The whole question about a shared file: [`Ownership::actionable`] licenses a
/// rewrite when the bytes differ, and the two refusing states each earn their
/// own message. A per-agent header answers [`Ownership::NotOurs`] because it
/// declares no scope.
pub fn shared_ownership(body: &str) -> Ownership {
    if header_field(body, "scope").as_deref() != Some(SHARED_SCOPE) {
        return Ownership::NotOurs;
    }
    ownership_of(
        header_field(body, "managed-by").as_deref(),
        header_field(body, "binding-version").as_deref(),
    )
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
    /// Four contiguous lines beginning with `# managed-by: `, which is what
    /// lets every reader take the first `remote::MARKER_SCAN_LINES` of a file
    /// and have the whole marker.
    pub fn render(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n",
            header_line("managed-by", MANAGED_BY),
            header_line("binding-version", BINDING_VERSION),
            header_line("agent-pubkey-full", &self.pubkey_full),
            header_line("create-intent", &self.create_intent),
        )
    }

    /// Parse a per-agent marker from a file body.
    ///
    /// `None` means "there is nothing here this build may act on, at this
    /// tier" — a refusal to act, never a licence to overwrite. That covers a
    /// foreign or future [`agent_ownership`], a shared artifact's header
    /// (which declares a scope), and a header of ours that carries no identity
    /// lines. An **older** binding version parses normally, and must: `remove`
    /// acts on the pubkey a prior-version artifact carries, and
    /// `FencedReplace` rewrites the file that carries it.
    ///
    /// That last point is the compatibility floor. A future bump may add or
    /// reshape header lines freely, but it must keep `# agent-pubkey-full:`
    /// and `# create-intent:` spelled exactly as they are, or this function
    /// stops recognising the previous release's artifacts and the lockout
    /// comes straight back.
    pub fn parse(body: &str) -> Option<Self> {
        if !agent_ownership(body).actionable() {
            return None;
        }
        Some(Self {
            pubkey_full: header_field(body, "agent-pubkey-full")?,
            create_intent: header_field(body, "create-intent")?,
        })
    }
}

/// The provider-level header written into every artifact shared by all
/// instances: the two template units and the fetcher script.
///
/// Three lines, and deliberately nothing more. It states exactly what is true —
/// this provider wrote it, at this binding version, for every instance — and
/// **nothing that is not**: no pubkey and no create-intent, because a shared
/// file belongs to no single agent, and no content digest, for the reason in
/// the module preamble.
pub fn shared_marker() -> String {
    format!(
        "{}\n{}\n{}\n",
        header_line("managed-by", MANAGED_BY),
        header_line("binding-version", BINDING_VERSION),
        header_line("scope", SHARED_SCOPE),
    )
}
```

Add `mod naming;` to `main.rs`.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p buzz-backend-gcp naming`
Expected: PASS — 15 tests.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): pubkey-derived naming and two marker tiers"
```

---

## Task 7: `render.rs` — six artifacts, the non-secret allowlist, and the hardened fetcher

Resolves review **P1-7** and **P2-8**, round 2's **P1-1** (`launch.command` reaches the VM verbatim), the render half of **P1-6** (the shared marker loses its content hash), **P1-7** (credential rotation) and **P2-4** (the fetcher unit does not carry the hardening the docs claim), and round 3's **P2-2** (Secret Manager's 64 KiB version-payload cap is enforced as a preflight) and **P2-4** (a value that changes side must diverge the intent).

**Files:**
- Create: `crates/buzz-backend-gcp/src/render.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod render;`)
- Modify: `crates/buzz-backend-gcp/src/reconcile.rs` (extend the pure phase to call `render::plan`)
- Modify: `crates/buzz-backend-gcp/tests/wire.rs` (drop the two `#[ignore]` attributes)

**Interfaces:**
- Produces:
  - `render::RemoteFile { path: String, mode: &'static str, body: String, owner_marker: Vec<String> }`
  - `render::SharedArtifact { file: RemoteFile, sha256: String }`
  - `render::Plan { per_agent: Vec<RemoteFile>, shared: Vec<SharedArtifact>, secret_env: BTreeMap<String, String>, create_intent: String, trail: RemoteFile }` with `Plan::secret_body(&self) -> String` and `Plan::redacted_secret_body(&self) -> String`
  - `render::plan(agent: &AgentPayload, cfg: &ProviderConfig, names: &Names, identity: &AgentIdentity, generation: &str) -> Result<Plan, String>`
  - `render::dry_run_report(plan: &Plan, names: &Names, trail_record: &str) -> String`
  - `render::NON_SECRET_KEYS: [&str; 9]` and `render::SECRET_MANAGER_MAX_PAYLOAD_BYTES: usize`
  - `render::DEFAULT_HARNESS: &str` and `render::harness_basename(agent: &AgentPayload) -> String`
- Consumes: `buzz_backend_core::env::{build_env, AuthoritativeInputs, START_NONCE_KEY}`, `buzz_backend_core::identity::AgentIdentity`, `buzz_backend_core::wire::AgentPayload`, `crate::capacity` (tests only), `crate::config::ProviderConfig`, `crate::naming::{header_line, sha256_hex, shared_marker, AgentMarker, Names, MANAGED_BY, SHARED_SCOPE}`. The test module additionally imports `crate::naming::{shared_ownership, Ownership, BINDING_VERSION}` — the parent stopped naming `BINDING_VERSION` when the owner-marker needle lists dropped it, and an import only the tests use is an unused import under `-D warnings`.

**Where the size rule lives, and where it does not.** `build_env` takes `max_env_bytes: None` from this binding, and that is right: a systemd `EnvironmentFile` on a 38 GB boot disk has no cap worth inventing, and Kubernetes' 1 MiB is a `MaxSecretSize` this substrate does not have. But `None` means "the *core* has no opinion", not "no limit applies". This binding splits the environment, and the secret-classified half is uploaded as one Secret Manager **version**, whose payload is capped at 64 KiB. Enforcing that here — in the pure phase, before a transport even exists — is the difference between a refusal that changed nothing and a failure inside `secrets::store`, which is the *fourth* mutation of a deploy: the shared templates are already installed and the secret resource may already have been created by the time it fires.

**Classification is an allowlist of non-secret keys, not a denylist of known-secret ones.** A denylist leaves `BUZZ_AUTH_TAG` — a bearer credential the relay treats as interchangeable with a resolved owner pubkey (`docs/remote-agents.md:1416-1419`) — plus every `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GITHUB_TOKEN` that tiers 1 and 2 routinely carry, on the **persistent boot disk**, where a disk snapshot or image capture picks them up. The desktop already refuses to draw that distinction: `env_secrets_from_request` treats *every* non-empty value in `env_vars`, `launch.env`, and `launch.policy_env` as redaction-worthy (`backend.rs:395-415`), and its doc comment says why. A provider whose classification is narrower than the redaction defending it has the policy backwards.

**Six artifacts, not five.** The design's §Remote Artifacts lists five files; its §fetcher hardening independently requires the fetcher's `--project` to come from `cfg.project`. Those two requirements meet where the two-tier marker rule resolves them: `project` is per-agent configuration, the fetcher unit and script are *shared*, and a shared artifact must carry no per-agent data. So the project reaches the fetcher through a **sixth artifact** — a per-agent drop-in on `buzz-acp-secret@<short12>.service` carrying two `Environment=` lines. Both shared files then stay byte-identical across every agent, which is exactly what makes the strict no-op strict. The deploy trail is a seventh file but is *appended*, not installed, so it travels in `Plan::trail` rather than in `per_agent`.

**`launch.command` is normalized to the VM's spelling before `build_env` sees it.** The desktop deliberately preserves an explicit host path (`desktop/src-tauri/src/managed_agents/discovery.rs:443-449`), the shared `build_env` writes `launch.command` through unchanged (`crates/buzz-backend-kubernetes/src/env.rs:254-259`), and `buzz-acp` execs that exact string (`crates/buzz-acp/src/acp.rs:451-459`). A payload carrying `/opt/homebrew/bin/codex-acp` therefore passes Task 12's installation check for `codex-acp` and then tries to exec a macOS path on Debian. The rewrite happens on a **projected copy of the payload, before `build_env` reads it**, rather than by patching the rendered map afterwards: a second consumer of `launch.command` added to `build_env` later would silently escape a post-hoc fix, and this one it cannot. The rewritten value is absolute (`/usr/local/bin/<basename>`) rather than bare, so the `test -x` that gates the deploy and the `exec` that follows it name the same file instead of both resolving a name against systemd's `PATH`. The harness's own per-command defaults are unaffected: `normalize_agent_command_identity` reduces the absolute form back to the basename (`crates/buzz-acp/src/config.rs:678-698`).

**A digest of the secret payload is part of the create-intent.** Secret *values* stay out of everything readable — the marker lives in a 0644 file on a shared host — but leaving them out of the *fingerprint* meant an agent whose `auth_tag` or API key rotated, with nothing else changed, classified as `RestartSame`, which skips `secrets::store` and restarts against the previous secret version while reporting success. A `sha256` of the rendered secret body carries the divergence without carrying the material: confirming a guess against it requires already knowing the nsec the body contains, so it discloses nothing a reader did not already have. It also subsumes the secret *key* set, since adding or removing a key changes the body.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/render.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{shared_ownership, Ownership, BINDING_VERSION};
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

    /// P2-4: Task 14's `[L3]` section and the README both enumerate this unit's
    /// sandbox directives, and a directive that is documented but absent is
    /// worse than one that is neither. The only omission is `IPAddressDeny`,
    /// whose absence is this unit's entire reason to exist.
    #[test]
    fn the_fetcher_unit_carries_every_directive_the_docs_claim() {
        let p = plan_for(&request());
        let unit = shared(&p, "/buzz-acp-secret@.service");
        for directive in [
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "RestrictSUIDSGID=true",
            "RestrictRealtime=true",
            "LockPersonality=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "\nAmbientCapabilities=\n",
            "\nTasksMax=128\n",
            "RuntimeDirectoryMode=0750",
            "ReadWritePaths=-/run/buzz-acp-%i",
        ] {
            assert!(unit.contains(directive), "the fetcher unit lacks {directive}");
        }
        // Exactly one capability, and it is the one `chown buzzacp` needs.
        assert!(unit.contains("\nCapabilityBoundingSet=CAP_CHOWN\n"), "{unit}");
        assert!(
            !unit.contains("ReadWritePaths=/run\n"),
            "the whole of /run is not this unit's runtime directory"
        );
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
        // Written as root, then tightened, then handed over — which is what
        // keeps `CapabilityBoundingSet=` down to CAP_CHOWN.
        assert!(script.contains("chown buzzacp:buzzacp"), "{script}");
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

    /// P1-3: this drop-in is a **root-installed** unit file and `project`
    /// reaches it as an `Environment=` value, which systemd parses for
    /// whitespace, quotes and `%` specifiers. Task 4's closed grammar is what
    /// makes the interpolation safe; this asserts the rendered value cannot be
    /// anything the parser would treat specially, so the two stay in step.
    #[test]
    fn the_fetcher_dropin_environment_values_carry_no_systemd_metacharacters() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let p = plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef").unwrap();
        let dropin = per_agent(&p, &names.secret_dropin_path());
        let assignments: Vec<&str> = dropin
            .lines()
            .filter_map(|line| line.strip_prefix("Environment="))
            .collect();
        assert_eq!(assignments.len(), 2, "{dropin}");
        for assignment in assignments {
            let (_, value) = assignment
                .split_once('=')
                .expect("an Environment= line is NAME=VALUE");
            assert!(
                value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{assignment} carries a character systemd's Environment= parser \
                 treats specially"
            );
        }
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
        surfaces.push(("trail header".into(), p.trail.body.as_str()));
        surfaces.push(("trail record".into(), record.as_str()));
        surfaces.push(("dry-run report".into(), report.as_str()));
        // The intent now covers a *digest* of the secret payload; a digest of a
        // value is not the value, and this is where that stops being a claim.
        surfaces.push(("create-intent".into(), p.create_intent.as_str()));
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

        for f in p.per_agent.iter().chain(std::iter::once(&p.trail)) {
            let marker = AgentMarker::parse(&f.body)
                .unwrap_or_else(|| panic!("{} carries no per-agent marker", f.path));
            assert_eq!(marker.pubkey_full, identity.pubkey_hex());
            assert_eq!(marker.create_intent, p.create_intent);
            assert_eq!(shared_ownership(&f.body), Ownership::NotOurs);
        }

        for a in &p.shared {
            assert!(
                shared_ownership(&a.file.body) == Ownership::Ours,
                "{} carries no provider-level marker at this binding version",
                a.file.path
            );
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

    /// P1-4 and P1-9 are only safe if the fence travels with the file: every
    /// installed artifact declares the header its target must already carry,
    /// so `Remote::install` cannot be called unguarded. And the declared lines
    /// must be lines of the body we are about to write, or the next deploy
    /// would refuse the file this one just installed.
    #[test]
    fn every_rendered_file_declares_the_marker_its_target_must_carry() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let p = plan_for(&req);

        // The tier's identity lines, and nothing else. `binding-version` is
        // absent deliberately: `remote::marker_fn` compares it as an ordering,
        // so an exact needle would make the install that upgrades a
        // prior-version file be refused by that file's own fence.
        let agent_lines = [
            format!("# managed-by: {MANAGED_BY}"),
            format!("# agent-pubkey-full: {}", identity.pubkey_hex()),
        ];
        for f in p.per_agent.iter().chain(std::iter::once(&p.trail)) {
            assert_eq!(f.owner_marker, agent_lines, "{}", f.path);
            for line in &f.owner_marker {
                assert!(
                    f.body.lines().any(|l| l == line),
                    "{} would refuse itself on the next deploy: no {line:?}",
                    f.path
                );
            }
            // …and the version is still *written*, because the reader that
            // orders it has to have something to read.
            assert!(f
                .body
                .lines()
                .any(|l| l == format!("# binding-version: {BINDING_VERSION}")));
        }

        let shared_lines = [
            format!("# managed-by: {MANAGED_BY}"),
            format!("# scope: {SHARED_SCOPE}"),
        ];
        for a in &p.shared {
            assert_eq!(a.file.owner_marker, shared_lines, "{}", a.file.path);
            for line in &a.file.owner_marker {
                assert!(
                    a.file.body.lines().any(|l| l == line),
                    "{} would refuse itself on the next deploy: no {line:?}",
                    a.file.path
                );
            }
            assert!(a
                .file
                .body
                .lines()
                .any(|l| l == format!("# binding-version: {BINDING_VERSION}")));
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
                .map(|s| (s.file.path.clone(), s.sha256.clone(), s.file.body.clone()))
                .collect()
        };
        assert_eq!(digest(&a), digest(&b));
    }

    /// The digest the reconciler compares must be the digest of the exact bytes
    /// that land on disk — header included, nothing stripped. The instance
    /// answers with `sha256sum` over the whole file, so any asymmetry here
    /// rewrites all three shared artifacts on every deploy.
    #[test]
    fn a_shared_artifact_digest_covers_the_exact_bytes_installed() {
        for a in &plan_for(&request()).shared {
            assert_eq!(
                sha256_hex(a.file.body.as_bytes()),
                a.sha256,
                "{} declares a digest of something other than itself",
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

    /// P1-7: a rotated credential must diverge the intent. Otherwise the
    /// reconciler classifies it `RestartSame`, skips `secrets::store`, and
    /// restarts the agent against the previous secret version — a successful
    /// restart for the operator and the old identity for the relay.
    #[test]
    fn a_rotated_credential_diverges_the_intent_without_exposing_it() {
        let a = plan_for(&request());
        let mut rotated = request();
        rotated.agent.auth_tag = Some("tag-ROTATED-0001".into());
        let b = plan_for(&rotated);
        assert_ne!(
            a.create_intent, b.create_intent,
            "a rotated auth_tag must not look like the same deploy"
        );
        assert!(!b.create_intent.contains("ROTATED"));
        for f in b.per_agent.iter().chain(std::iter::once(&b.trail)) {
            assert!(!f.body.contains("tag-ROTATED-0001"), "{}", f.path);
        }
        // A key added to the payload diverges it too — the digest covers the
        // whole body, so the key set comes along for free.
        let mut renamed = request();
        renamed
            .agent
            .launch
            .as_mut()
            .unwrap()
            .env
            .insert("OPENAI_API_KEY".into(), "sk-x".into());
        assert_ne!(a.create_intent, plan_for(&renamed).create_intent);
    }

    /// P2-4 (round 3): the case above covers a changed value and an added key.
    /// The one it misses is a value that changes **side** — allowlisted on one
    /// deploy, secret-classified on the next — with the key set and the value
    /// multiset both unchanged. That is not hypothetical: it is what editing
    /// `NON_SECRET_KEYS` does to every agent already deployed, and the two
    /// deploys are genuinely different, because one writes the value into a
    /// 0600 file on the persistent boot disk and the other into Secret
    /// Manager. A fingerprint that hashed the whole environment *before* the
    /// split would call them identical, classify `RestartSame`, and never
    /// re-store the secret.
    #[test]
    fn a_value_that_changes_side_diverges_the_intent() {
        // `BUZZ_ACP_AGENT_ARGS` is allowlisted and comes from `launch.args`;
        // `TEAM_TOKEN` is not allowlisted, so it is secret-classified. Swap
        // which value each carries and nothing else moves.
        let side = |args: &str, token: &str| {
            let mut req = request();
            let launch = req.agent.launch.as_mut().unwrap();
            launch.args = vec![args.to_string()];
            launch.env.insert("TEAM_TOKEN".into(), token.to_string());
            plan_for(&req)
        };
        let a = side("SIDEONE", "SIDETWO");
        let b = side("SIDETWO", "SIDEONE");

        // Same two values, opposite halves of the split.
        assert!(a.secret_body().contains("SIDETWO") && !a.secret_body().contains("SIDEONE"));
        assert!(b.secret_body().contains("SIDEONE") && !b.secret_body().contains("SIDETWO"));
        assert_ne!(
            a.create_intent, b.create_intent,
            "the fingerprint must be side-aware, not merely content-aware"
        );
        for intent in [&a.create_intent, &b.create_intent] {
            assert!(!intent.contains("SIDE"), "the intent leaks a value: {intent}");
        }
    }

    /// P2-2 (round 3): `max_env_bytes: None` says the *core* imposes no cap,
    /// not that none applies. The secret half travels as one Secret Manager
    /// version, and a version payload is capped at 64 KiB, so an environment
    /// the core accepts can still be undeployable — and it must be refused
    /// here, in the pure phase, rather than in `secrets::store` after the
    /// shared templates are already installed.
    #[test]
    fn a_secret_payload_over_secret_managers_cap_is_refused_before_any_mutation() {
        let huge = "x".repeat(SECRET_MANAGER_MAX_PAYLOAD_BYTES);
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .env
            .insert("HUGE_API_KEY".into(), huge.clone());
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let err = plan(&req.agent, &gcp_config(), &names, &identity, "g")
            .expect_err("64 KiB is Secret Manager's hard cap on a version payload");
        assert!(err.contains("Secret Manager"), "{err}");
        assert!(
            err.contains(&SECRET_MANAGER_MAX_PAYLOAD_BYTES.to_string()),
            "the refusal must state the cap: {err}"
        );
        // [L2] item 5: a refusal about a secret value must not echo it.
        assert!(!err.contains(&huge), "the refusal echoes the value");
        assert!(!err.contains(&"x".repeat(64)), "the refusal echoes the value");
    }

    /// …and the same size on the **allowlisted** half is fine, which is the
    /// whole point of putting the cap on `secret_body()` rather than on the
    /// environment: the boot disk has no such boundary.
    #[test]
    fn an_oversized_allowlisted_value_is_not_capped() {
        let mut req = request();
        req.agent.launch.as_mut().unwrap().args =
            vec!["y".repeat(SECRET_MANAGER_MAX_PAYLOAD_BYTES)];
        let p = plan_for(&req);
        assert!(p.secret_body().len() <= SECRET_MANAGER_MAX_PAYLOAD_BYTES);
        assert!(
            per_agent(&p, &names_for(&req).env_path()).len() > SECRET_MANAGER_MAX_PAYLOAD_BYTES
        );
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
    /// basename is meaningful on the instance — and the default is what
    /// `buzz-acp` actually execs when nothing is named. That is `goose`
    /// (`crates/buzz-acp/src/config.rs:190-192`), **not** `buzz-acp`, which is
    /// the supervisor doing the exec'ing.
    #[test]
    fn the_harness_command_falls_back_to_the_harnesss_own_default() {
        let mut req = request();
        req.agent.launch.as_mut().unwrap().command = Some("/opt/homebrew/bin/codex-acp".into());
        assert_eq!(harness_basename(&req.agent), "codex-acp");
        req.agent.launch.as_mut().unwrap().command = None;
        assert_eq!(harness_basename(&req.agent), DEFAULT_HARNESS);
        assert_eq!(DEFAULT_HARNESS, "goose");
        // A payload naming nothing still gets an explicit, absolute command, so
        // Task 12's `test -x` and the harness's exec name the same file rather
        // than both resolving a bare name against systemd's PATH.
        let p = plan_for(&req);
        assert!(
            per_agent(&p, &names_for(&req).env_path())
                .contains("BUZZ_ACP_AGENT_COMMAND=\"/usr/local/bin/goose\""),
            "{}",
            per_agent(&p, &names_for(&req).env_path())
        );
    }

    /// P1-1: the *rendered environment* must carry the instance's spelling of
    /// the harness, never the desktop's. A host path here passes the
    /// installation check for its basename and then fails at exec on the VM.
    #[test]
    fn the_env_carries_the_instance_path_never_the_desktop_one() {
        let mut req = request();
        req.agent.launch.as_mut().unwrap().command = Some("/opt/homebrew/bin/codex-acp".into());
        let names = names_for(&req);
        let p = plan_for(&req);
        let env = per_agent(&p, &names.env_path());
        assert!(
            env.contains("BUZZ_ACP_AGENT_COMMAND=\"/usr/local/bin/codex-acp\""),
            "{env}"
        );

        let record = crate::capacity::trail_record("t", "g", &p.create_intent, &[]);
        let report = dry_run_report(&p, &names, &record);
        let secret = p.secret_body();
        let mut surfaces: Vec<&str> = p.per_agent.iter().map(|f| f.body.as_str()).collect();
        surfaces.extend(p.shared.iter().map(|a| a.file.body.as_str()));
        surfaces.push(p.trail.body.as_str());
        surfaces.push(secret.as_str());
        surfaces.push(report.as_str());
        for text in surfaces {
            assert!(
                !text.contains("/opt/homebrew"),
                "the desktop's path reached the instance"
            );
        }
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
//! marker tiers, the fence each file carries into its own install — is visible
//! here and testable without touching GCP.

use crate::config::ProviderConfig;
use crate::naming::{
    header_line, sha256_hex, shared_marker, AgentMarker, Names, MANAGED_BY, SHARED_SCOPE,
};
use buzz_backend_core::env::{build_env, AuthoritativeInputs, START_NONCE_KEY};
use buzz_backend_core::identity::AgentIdentity;
use buzz_backend_core::wire::AgentPayload;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Secret Manager's hard cap on a single version's payload, 64 KiB
/// (<https://cloud.google.com/secret-manager/quotas>).
///
/// Enforced in [`plan`], on `secret_body()` only. The on-disk half is
/// deliberately uncapped — a systemd `EnvironmentFile` on a 38 GB boot disk
/// has no such boundary, which is why this binding passes
/// `max_env_bytes: None` to `build_env` — but the secret-classified half is
/// uploaded as one version, and a payload over this is rejected by the API.
/// The check lives in the pure phase because `secrets::store` is the *fourth*
/// mutation of a deploy: failing there leaves the shared templates installed
/// and possibly an empty secret resource created, for a condition that was
/// knowable offline.
pub const SECRET_MANAGER_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

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

/// Where the instance keeps harness binaries.
///
/// Task 12 verifies `<HARNESS_DIR>/<basename>` with `test -x` before deploying
/// and `launch.command` is rewritten to that same absolute path, so the check
/// and the exec name one file rather than both resolving a bare name against
/// systemd's `PATH` — which searches `/usr/local/sbin` first.
const HARNESS_DIR: &str = "/usr/local/bin";

/// The harness `buzz-acp` execs when the payload names none.
///
/// `goose`, not `buzz-acp`: `BUZZ_ACP_AGENT_COMMAND` defaults to `goose` in the
/// harness's own CLI (`crates/buzz-acp/src/config.rs:190-192`), and `buzz-acp`
/// is the supervisor that execs it, not the child. Naming the supervisor here
/// would make the installation check verify a binary that is certainly present
/// while the one that actually runs is missing.
pub const DEFAULT_HARNESS: &str = "goose";

/// A file to install on the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    pub path: String,
    /// Octal mode string passed to `install -m`.
    pub mode: &'static str,
    pub body: String,
    /// The header lines the **installed** file must already carry if it exists.
    ///
    /// Attached at render time rather than passed to `Remote::install`, because
    /// the renderer is the only place that knows each file's tier and this
    /// agent's pubkey — and because a fence that travels with the file cannot
    /// be forgotten at one of several call sites.
    ///
    /// These are the tier's **identity** lines and nothing else. `create-intent`
    /// is excluded because it changes on every legitimate reconfiguration, so
    /// requiring it would refuse a file this agent wrote yesterday.
    /// `binding-version` is excluded because `remote::marker_fn` compares it as
    /// an *ordering* rather than matching it as a literal line: an artifact
    /// written by an older build of this provider is an authorised upgrade
    /// target, and an exact needle would have the install that upgrades a file
    /// be refused by that file's own fence.
    pub owner_marker: Vec<String>,
}

/// A shared artifact plus the digest of the exact bytes it installs.
///
/// The digest is **not** written into the file and makes no claim about it: it
/// is how the reconciler answers "is what is on the instance already
/// byte-identical to what I would write?" without shipping the body twice. The
/// instance answers with `sha256sum` over the whole file and the two are
/// compared, so both sides are hashes of real bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedArtifact {
    pub file: RemoteFile,
    /// SHA-256 of `file.body` in full, marker header included.
    pub sha256: String,
}

/// Everything one deploy needs to write.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Files belonging to exactly this agent. Rewritten by a create or a
    /// fenced replace.
    pub per_agent: Vec<RemoteFile>,
    /// Files shared by every instance. Written only when absent, or when the
    /// installed bytes differ from what this provider would render.
    pub shared: Vec<SharedArtifact>,
    /// The Secret Manager payload. Never written to a file this provider
    /// installs, never logged, redacted by `dry-run`.
    pub secret_env: BTreeMap<String, String>,
    /// Fingerprint of everything that decides the unit's behavior, excluding
    /// the generation and every secret *value* — though a digest of the secret
    /// body is included, so a rotated credential is a divergence.
    pub create_intent: String,
    /// The deploy trail. `body` is the four-line marker header the file gets
    /// when it does not exist yet; records are **appended** to it, so it is
    /// never installed like the others and does not live in `per_agent`.
    pub trail: RemoteFile,
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

/// The header lines a per-agent target must already carry, if it exists at all.
///
/// Identity only. The binding version is checked by `remote::marker_fn` as an
/// ordering rather than matched as a literal line, so that an artifact written
/// by an older build of this provider is an upgrade target instead of a file
/// its own fence refuses.
fn agent_owner_marker(pubkey_full: &str) -> Vec<String> {
    vec![
        header_line("managed-by", MANAGED_BY),
        header_line("agent-pubkey-full", pubkey_full),
    ]
}

/// The header lines a shared target must already carry, if it exists at all.
/// Same rule as [`agent_owner_marker`] for the binding version.
fn shared_owner_marker() -> Vec<String> {
    vec![
        header_line("managed-by", MANAGED_BY),
        header_line("scope", SHARED_SCOPE),
    ]
}

/// Build a shared artifact: stamp the provider-level marker onto it, then hash
/// the exact bytes that will land on disk.
///
/// `prologue` is content that must precede the header — a shebang, which the
/// kernel only honors on line 1. It is inside the hashed bytes like everything
/// else, because the hash covers the file rather than a chosen part of it.
fn shared_artifact(
    path: &str,
    mode: &'static str,
    prologue: &str,
    content: &str,
) -> SharedArtifact {
    let body = format!("{prologue}{}{content}", shared_marker());
    let sha256 = sha256_hex(body.as_bytes());
    SharedArtifact {
        file: RemoteFile {
            path: path.to_string(),
            mode,
            body,
            owner_marker: shared_owner_marker(),
        },
        sha256,
    }
}

/// The bare binary name inside a `launch.command`, or the harness's own default
/// when the payload names none or names only a directory.
fn basename_or_default(command: Option<&str>) -> String {
    command
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .and_then(|command| command.rsplit('/').next())
        .filter(|basename| !basename.is_empty())
        .unwrap_or(DEFAULT_HARNESS)
        .to_string()
}

/// The harness binary this agent needs, as a bare name.
///
/// `launch.command` is resolved against the **desktop's** PATH; on the VM that
/// path is meaningless, so only the basename carries over. Task 12 uses this to
/// decide which `/usr/local/bin/<name>` must exist before the deploy proceeds.
pub fn harness_basename(agent: &AgentPayload) -> String {
    basename_or_default(agent.launch.as_ref().and_then(|l| l.command.as_deref()))
}

/// A copy of `agent` whose `launch.command` is the **instance's** spelling of
/// the harness.
///
/// The desktop deliberately preserves an explicit host path
/// (`desktop/src-tauri/src/managed_agents/discovery.rs:443-449`), `build_env`
/// writes `launch.command` through unchanged
/// (`crates/buzz-backend-kubernetes/src/env.rs:254-259`), and `buzz-acp` execs
/// that exact string (`crates/buzz-acp/src/acp.rs:451-459`). Left alone,
/// `/opt/homebrew/bin/codex-acp` passes the installation check for `codex-acp`
/// and then fails at exec on Debian.
///
/// Rewritten **here**, before `build_env` reads it, rather than by patching the
/// rendered map afterwards: a second consumer of `launch.command` added to
/// `build_env` later would escape a post-hoc fix and cannot escape this one.
///
/// A payload with no launch block at all is left untouched — inventing one
/// would change owner resolution — so it reaches the harness's own default,
/// which is the same binary `harness_basename` names.
fn with_instance_harness(agent: &AgentPayload) -> AgentPayload {
    let mut agent = agent.clone();
    if let Some(launch) = agent.launch.as_mut() {
        let basename = basename_or_default(launch.command.as_deref());
        launch.command = Some(format!("{HARNESS_DIR}/{basename}"));
    }
    agent
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

    // Before `build_env`, so no consumer of `launch.command` — this one or a
    // future one — can observe the desktop's path.
    let agent = with_instance_harness(agent);

    let env = build_env(
        &agent,
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
    let secret_body = env_file_body(&secret_env, "");

    // The on-disk half has no cap — a systemd `EnvironmentFile` on a 38 GB
    // boot disk is bounded by the disk, which is why `max_env_bytes` above is
    // `None`. The secret half does: it is uploaded as one Secret Manager
    // version, and a version payload is capped at 64 KiB. Refusing here, in
    // the pure phase, is what keeps that from surfacing inside
    // `secrets::store` — the fourth mutation of a deploy, by which point the
    // shared templates are installed and the secret resource may already
    // exist. The refusal names sizes only: [L2] item 5 forbids echoing a
    // secret-classified value, and the oversized one is by definition secret.
    if secret_body.len() > SECRET_MANAGER_MAX_PAYLOAD_BYTES {
        return Err(format!(
            "deploy refused: this agent's secret-classified environment renders \
             to {} bytes, and Secret Manager caps one version's payload at \
             {SECRET_MANAGER_MAX_PAYLOAD_BYTES} bytes. Nothing was changed. \
             Move the oversized value off the agent payload — a file on the \
             instance, or a secret the harness fetches itself. No value is \
             echoed here.",
            secret_body.len()
        ));
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
    // behavior, and deliberately excludes one thing: the generation, which
    // changes on every attempt, so including it would make every deploy look
    // divergent.
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
    // Secret keys *and* values, as one digest. The values must not be
    // reconstructible from a marker any reader of a 0644 file can see — but
    // leaving them out of the fingerprint entirely is what let a rotated
    // credential classify as `RestartSame`, which skips `secrets::store` and
    // restarts the agent against the previous secret version. A digest carries
    // the divergence without carrying the material: confirming a guess against
    // it requires already knowing the nsec the body contains.
    feed("secret-digest", &sha256_hex(secret_body.as_bytes()));
    feed("memory_max", &cfg.memory_max);
    feed("cpu_quota", &cfg.cpu_quota);
    feed("project", &cfg.project);
    feed("secret-name", &names.secret_name());
    for artifact in &shared {
        feed("shared", &artifact.sha256);
    }
    let create_intent = hex::encode(hasher.finalize());

    let marker = AgentMarker {
        pubkey_full: identity.pubkey_hex().to_string(),
        create_intent: create_intent.clone(),
    }
    .render();
    let owner_marker = agent_owner_marker(identity.pubkey_hex());

    let per_agent = vec![
        RemoteFile {
            path: names.env_path(),
            mode: "0600",
            body: env_file_body(&disk_env, &marker),
            owner_marker: owner_marker.clone(),
        },
        RemoteFile {
            path: names.dropin_path(),
            mode: "0644",
            body: format!(
                "{marker}[Service]\nMemoryMax={}\nCPUQuota={}\n",
                cfg.memory_max, cfg.cpu_quota
            ),
            owner_marker: owner_marker.clone(),
        },
        RemoteFile {
            path: names.secret_dropin_path(),
            mode: "0644",
            // The fetcher's two inputs. They live here, per agent, rather than
            // in the shared script, because a shared artifact carries no
            // per-agent data — see the tier rules in `naming.rs`. Both values
            // are safe unquoted because both come from closed grammars:
            // `project` from `config::parse_resource_name`, the secret name
            // from the 12-hex instance.
            body: format!(
                "{marker}[Service]\n\
                 Environment=BUZZ_GCP_PROJECT={}\n\
                 Environment=BUZZ_GCP_SECRET={}\n",
                cfg.project,
                names.secret_name()
            ),
            owner_marker: owner_marker.clone(),
        },
    ];

    Ok(Plan {
        per_agent,
        shared,
        secret_env,
        create_intent,
        trail: RemoteFile {
            path: names.trail_path(),
            mode: "0644",
            body: marker,
            owner_marker,
        },
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
    out.push_str(&format!(
        "\n=== {} (mode {}) ===\n",
        plan.trail.path, plan.trail.mode
    ));
    out.push_str(&plan.trail.body);
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
/// 0600 root:root and starts. The agent *process* therefore never needs to
/// traverse this directory itself, and 0750 root:root is what stops it.
///
/// It carries every sandbox directive the agent unit does, with exactly three
/// deliberate differences:
///
/// * **No `IPAddressDeny`** — the absence is this unit's entire reason to exist.
/// * **`CapabilityBoundingSet=CAP_CHOWN`, not empty.** The fetched file is
///   `chown`ed to `buzzacp` so the manager can hand it to the agent unit as an
///   `EnvironmentFile=`; with an empty bounding set that `chown` fails with
///   EPERM even as root, and the agent starts *without* `BUZZ_AUTH_TAG` — a
///   failure that looks nothing like a permissions error. One capability, for
///   one syscall, and the script is ordered so no second one is needed.
/// * **`ReadWritePaths=-/run/buzz-acp-%i`, not `/var/lib/buzzacp`.** Scoped to
///   this instance's own runtime directory and nothing else. The `-` prefix
///   tolerates the path not existing yet when the mount namespace is built;
///   `RuntimeDirectory=` creates it for this unit either way.
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
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=CAP_CHOWN
AmbientCapabilities=
ReadWritePaths=-/run/buzz-acp-%i
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
TasksMax=128
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

# Filled while it is still root-owned and writable, then tightened, then handed
# over, then renamed. That order is what keeps this unit's capability set at
# exactly CAP_CHOWN: creating the file 0400 buzzacp *first* would make the
# redirect below fail with EACCES for a root process without CAP_DAC_OVERRIDE,
# and chmod after chown would need CAP_FOWNER. `mv` within one tmpfs is a
# rename, so the agent unit never observes a half-written file — and a partial
# secret.env is not a truncated key, it is an EnvironmentFile missing its later
# lines, which for this binding's allowlist means an agent that starts *without*
# BUZZ_AUTH_TAG and fails identity assembly for a reason that looks nothing like
# a write error. The fetched value is never echoed: the journal is output, and
# L2 item 5 forbids secret material there.
install -m 0600 /dev/null "$tmp"
gcloud secrets versions access latest \
  --project="$BUZZ_GCP_PROJECT" \
  --secret="$BUZZ_GCP_SECRET" > "$tmp"
chmod 0400 "$tmp"
chown buzzacp:buzzacp "$tmp"
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
Expected: PASS — 27 `render` tests, plus `deploy_responses_match_their_fixtures` now matching all four goldens (`deploy-no-owner` from `build_env`, `deploy-ordinary-provider` from the indefinite-lifetime refusal) and `an_ordinary_provider_is_not_refused_as_shared_compute` no longer ignored.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): render six artifacts across two marker tiers"
```

---

## Task 8: Capacity arithmetic and the durable deploy trail

Resolves review **P1-1**, and the writer half of round 2's **P2-1** (the capacity warning is findable but never found).

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

**The `warning ` prefix is a contract, not a spelling.** `operator::listing_script` greps the trail for lines beginning `warning ` and `render_listing` indents them under their unit's row. Nothing about that survives a rename of the prefix — and until round 2 nothing tested it, because the writer and the reader were each checked against hand-typed fixtures that happened to agree. Two tests close the loop from both ends: this task asserts the shape at the source, and Task 13 Step 1 feeds this function's **real** output through the real reader. Task 15 Step 9 then deploys an actually over-capacity agent, because a format both sides agree on is still worthless if no deploy ever produces one.

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

    /// The reader greps the trail for lines beginning `warning `
    /// (`operator::listing_script`), so that prefix is a contract between two
    /// modules rather than an incidental spelling. Task 13 Step 1 feeds this
    /// function's real output through the real reader; this asserts the shape
    /// that grep depends on, at the source.
    #[test]
    fn every_warning_line_carries_the_prefix_the_reader_greps_for() {
        let warnings = warning_lines(GIB, GIB, "buzz-acp@abc.service", GIB);
        assert!(!warnings.is_empty(), "this fixture must overcommit");
        let record = trail_record(
            "2026-08-05T09:14:02Z",
            "3f9c1a04",
            &"a".repeat(64),
            &warnings,
        );
        let recorded: Vec<&str> = record.lines().skip(1).collect();
        assert_eq!(recorded.len(), warnings.len(), "one line per warning");
        for line in &recorded {
            assert!(
                line.starts_with("warning "),
                "the reader's grep would drop {line:?}"
            );
        }
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
Expected: PASS — the 7 capacity tests plus every earlier test, including `no_secret_classified_value_reaches_any_artifact`, which now compiles because `crate::capacity` exists.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): capacity warning and durable deploy trail"
```

---

## Task 9: `remote.rs` — the IAP SSH transport

Resolves review **P1-2**, round 2's **P1-9** (atomic installs), the write half of **P1-4** (each install is fenced on its own target's marker) and the transport half of **P1-8** (the exit codes the deploy lease and the narrowed fence speak), round 3's **P1-3** (the guard compared `grep -c` against a count, which counts matching input *lines* rather than distinct matched patterns), and the transport half of round 4's **P1-1**: the marker guard proved provenance, not that the writer still held the lease.

**Files:**
- Create: `crates/buzz-backend-gcp/src/remote.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod remote;`)

**Interfaces:**
- Produces:
  - `remote::Output { stdout: String, stderr: String, code: i32 }` with `ok(&self) -> bool`
  - `remote::Gcloud` — one method, `gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String>`, implemented by `Remote`
  - `remote::{OWNERSHIP_REFUSED, LOCK_UNAVAILABLE, MARKER_CHANGED, AGENT_STARTED}: i32`, `remote::MARKER_SCAN_LINES: usize`, `remote::LEASE_DIR: &str` and `remote::LEASE_FLOCK_WAIT_SECONDS: u64` (the last two `pub(crate)`, read by Task 12's acquire and release)
  - `remote::marker_fn(required: &[String]) -> String` — `pub(crate)`; emits the `marker_ok` shell function Task 13's `removal_script` also calls
  - `remote::Held` — `pub(crate)`, one method `agent(&self) -> &str`, implemented only by `reconcile::DeployLease`
  - `remote::lease_paths(agent: &str) -> (String, String)`, `remote::lease_gate(owner: &str, token: &str) -> String`, `remote::under_lease(agent: &str, token: &str, root_script: &str) -> String` and `remote::lease_lost(target: &str) -> String` — all `pub(crate)`; `under_lease` is the single spelling of `sudo -n flock -w W -E 75 <lock> sh -c '<gate><work>'`, and Task 12's `renew_lease_script` is it with an empty body
  - `remote::Remote::new(project: &str, zone: &str, instance: &str) -> Result<Remote, String>` with `token(&self) -> &str`
  - `Remote::run(&self, script: &str) -> Result<Output, String>` — unfenced, for the read-only scripts (`observe::look`, the listing, the ownership scan, the startup poll, the lease scripts themselves)
  - `Remote::run_fenced(&self, lease: &dyn Held, root_script: &str) -> Result<Output, String>` — `pub(crate)`; the mutating counterpart, wrapping a root script in `under_lease`
  - `Remote::install(&self, file: &RemoteFile, lease: &dyn Held) -> Result<(), String>` — `pub(crate)`
  - `Remote::append(&self, file: &RemoteFile, record: &str, lease: &dyn Held) -> Result<(), String>` — `pub(crate)`
  - `remote::sq(value: &str) -> String` — POSIX single-quoting, reused by `observe`, `reconcile` and `operator`
- Consumes: `crate::naming::{BINDING_VERSION, BINDING_VERSION_NUM, MANAGED_BY}`, `crate::render::RemoteFile`, `buzz_backend_core::identity::new_generation`.

**Security rule for this module:** no secret value may ever appear in an argv element. Bodies go on stdin. That is enforced structurally by `install` taking the whole `RemoteFile` and never formatting `body` into a command string, and it is sound because `gcloud compute ssh` execs a real `ssh` that forwards local stdin to the remote command (measured — see Global Constraints).

**Exit codes the remote scripts speak.** Four numeric codes carry refusals back: a refusal is not a transport failure and must not read as one. The caller turns each into a sentence naming the path and the remedy; the script itself stays silent, because it does not know which of six callers is speaking or what the operator is trying to do. Codes are drawn from the `sysexits.h` range, well clear of the 1-2 that `sudo`, `install` and `systemctl` return and of 126/127 for exec failures. Round 4 gave `LOCK_UNAVAILABLE` a second home: it was the acquire's refusal, and it is now also every mutation's, because every mutation proves the lease itself.

**Every install is atomic and self-fencing, and it happens under a proven lease.** Three findings meet in one script, and none is safe alone. Round 2's P1-9: a dropped connection mid-install used to leave a truncated file at the *target* path. Round 2's P1-4: the fence must refuse any present file whose own header is not this agent's — which would turn every such fragment into a permanent, operator-only jam. Writing to `<path>.<token>.tmp` and `mv`ing into place means the target is never observed half-written, so the fence can be strict without being a trap. The guard sits in the same shell as the write, which is also the narrowest place to put it: an ownership check performed in an earlier round trip is a TOCTOU with a four-round-trip window. Round 4's P1-1 adds the third: the marker guard proves *provenance* and nothing else, so a provider whose lease had been legitimately taken over while it stalled could satisfy it and `mv` a stale render over the winner's files. The `mv` therefore runs inside `under_lease`, which takes the agent's `flock`, refuses `LOCK_UNAVAILABLE` unless the owner record still names this process, refreshes it, and only then lets the guard and the rename run — all in one `sh -c`. The record can only be changed under that same `flock`, so no takeover can interleave between the proof and the write.

**Where the `flock` is *not* held: the stdin drain.** The body is staged before the lock is taken. Holding a lock across a read that waits on the network would make a rival's acquire wait for a body transfer rather than for three local file operations, and `LEASE_FLOCK_WAIT_SECONDS` is 5 s precisely because every critical section is local. Staging first also preserves the property that makes the refusals clean: stdin is drained before anything can exit, so a refusal never arrives as a broken pipe. The staged file is `trap`ped away on every exit path, including both refusals.

**Why the lease's shell lives here and its policy lives in `reconcile`.** `LEASE_DIR`, `lease_paths`, `lease_gate` and `under_lease` are in this module because every mutating script this module renders has to carry the proof inside its own shell — that is a transport concern. `DEPLOY_LEASE_SECONDS`, the freshness arithmetic that decides when an abandoned record may be stolen, `acquire_lease`, the release and the `Drop` guard stay in `reconcile`, because they are about deploys. `Held` is the seam: one method, one implementor, and a `&dyn Held` parameter on `install`, `append` and `run_fenced` so a mutating call cannot be written without a lease in hand.

**Why `PATH` is prepended.** The provider is exec'd by a Tauri app inheriting launchd's `/usr/bin:/bin:/usr/sbin:/sbin`. `gcloud` installs to `/opt/homebrew/bin`, `/usr/local/bin`, or `~/.local/bin` — none of which are on that `PATH` — so a bare `Command::new("gcloud")` fails to resolve for a reason that has nothing to do with GCP. The Kubernetes binding already carries this exact fix and names the same cause (`crates/buzz-backend-kubernetes/src/client.rs:12-47`). Two details carry over verbatim because they are the parts that are easy to get wrong: mutating the process's own `PATH` is sound here (one process per operation, done before any child exists, `client.rs:36-40`), and empty entries in the inherited `PATH` are **dropped** rather than propagated, because POSIX resolves an empty entry as the current directory.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/remote.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{header_line, SHARED_SCOPE};
    use std::ffi::OsString;

    /// The 12-lowercase-hex agent whose lease the fenced scripts prove. It is
    /// only ever interpolated into the two lease paths, so any value the
    /// naming grammar can produce does.
    const AGENT: &str = "a1b2c3d4e5f6";

    /// The two identity lines a per-agent target must already carry.
    ///
    /// `create-intent` is absent because it changes on every legitimate
    /// reconfiguration, so requiring it would refuse a file this agent wrote.
    /// `binding-version` is absent for a different reason: `marker_ok`
    /// compares it as an *ordering*, so a file written by an older build of
    /// this provider can be upgraded rather than refused by its own fence.
    fn marker_lines() -> Vec<String> {
        vec![
            header_line("managed-by", MANAGED_BY),
            header_line("agent-pubkey-full", &"ab".repeat(32)),
        ]
    }

    fn file(path: &str, mode: &'static str, body: &str) -> RemoteFile {
        RemoteFile {
            path: path.to_string(),
            mode,
            body: body.to_string(),
            owner_marker: marker_lines(),
        }
    }

    /// A needle as it appears once a critical section has been `sq`-wrapped
    /// for `sh -c`: every single quote becomes `'\''`. Asserting on the
    /// wrapped form is the honest way to check a nested script — the
    /// alternative is asserting only on fragments that happen to carry no
    /// quotes, which silently stops covering the interesting ones.
    fn nested(fragment: &str) -> String {
        fragment.replace('\'', r"'\''")
    }

    #[test]
    fn the_install_command_never_carries_the_body() {
        let script = install_script(
            &file("/etc/buzz/acp-abc.env", "0600", "SUPER_SENSITIVE=1\n"),
            AGENT,
            "t0ken",
        );
        assert!(script.contains("/dev/stdin"));
        assert!(script.contains("'/etc/buzz/acp-abc.env'"));
        assert!(script.contains("-m 0600"));
        assert!(
            !script.contains("SUPER_SENSITIVE"),
            "the body must travel on stdin, never in the command"
        );
    }

    /// P1-9: a dropped connection must never leave a fragment at the target
    /// path. Stage with the final mode, then `mv` — a rename within one
    /// directory, so the target goes from old bytes to new with nothing in
    /// between.
    #[test]
    fn an_install_stages_and_renames_rather_than_writing_in_place() {
        let script =
            install_script(&file("/etc/buzz/acp-abc.env", "0600", "X=1\n"), AGENT, "t0ken");
        assert!(
            script.contains(&sq("/etc/buzz/acp-abc.env.t0ken.tmp")),
            "{script}"
        );
        assert!(script.contains("sudo -n install -m 0600 /dev/stdin"), "{script}");
        assert!(script.contains(&nested("mv -f")), "{script}");
        let staged = script.find("install -m").expect("the staged write");
        let rename = script.find("mv -f").expect("the rename");
        assert!(
            staged < rename,
            "the body is written before it is renamed: {script}"
        );
        // The staging path carries the per-process token, so two providers
        // installing the same shared artifact cannot collide on it.
        assert!(script.contains("t0ken"), "{script}");
        assert!(script.contains("trap"), "a refusal must not leak the staged file");
    }

    /// P1-4: the target's own marker vetoes the write, in the same shell as the
    /// write — and stdin is drained before the veto can fire, so a clean
    /// refusal never surfaces as a broken pipe.
    #[test]
    fn an_install_refuses_a_target_carrying_somebody_elses_marker() {
        let script =
            install_script(&file("/etc/buzz/acp-abc.env", "0600", "X=1\n"), AGENT, "t0ken");
        for required in marker_lines() {
            assert!(
                script.contains(&nested(&sq(&required))),
                "the guard omits {required:?}"
            );
        }
        assert!(script.contains(&OWNERSHIP_REFUSED.to_string()), "{script}");
        assert!(
            !script.contains("create-intent"),
            "requiring the intent would refuse a file this agent wrote: {script}"
        );
        let drained = script.find("/dev/stdin").expect("the staged write");
        let guard = script.find("marker_ok ||").expect("the ownership guard");
        let rename = script.find("mv -f").expect("the rename");
        assert!(
            drained < guard && guard < rename,
            "drain, then check, then rename: {script}"
        );
    }

    /// P1-3. The guard used to be `grep -c -F -x -e a -e b -e c` compared
    /// against `3`, and `grep -c` counts matching input **lines**, not
    /// distinct matched patterns. A header whose first lines repeat
    /// `# managed-by:` and `# binding-version:` therefore reached the expected
    /// count while carrying no `# agent-pubkey-full:` at all — so the guard
    /// authorized overwriting a file that never named this agent, which is the
    /// "a marker-looking file authorises the wrong file" hole the deleted
    /// tamper check was supposed to have closed. Each needle is asserted on
    /// its own now, and the first miss returns.
    #[test]
    fn a_header_that_repeats_one_marker_line_does_not_satisfy_the_guard() {
        let script =
            install_script(&file("/etc/buzz/acp-abc.env", "0600", "X=1\n"), AGENT, "t0ken");
        assert!(
            !script.contains("grep -c"),
            "counting lines instead of patterns is the defect: {script}"
        );
        assert_eq!(
            script.matches("grep -Fqx").count(),
            marker_lines().len(),
            "one independent check per needle: {script}"
        );
        for line in marker_lines() {
            assert!(
                script.contains(&nested(&format!("grep -Fqx -- {}", sq(&line)))),
                "{line:?} is not asserted on its own: {script}"
            );
        }

        // The shared tier is the same function with a different needle set, so
        // a header that repeats `# managed-by:` and omits `# scope:` fails for
        // the same reason.
        let shared = marker_guard(
            "/usr/local/sbin/buzz-acp-fetch-key",
            &[
                header_line("managed-by", MANAGED_BY),
                header_line("scope", SHARED_SCOPE),
            ],
        );
        assert_eq!(shared.matches("grep -Fqx").count(), 2, "{shared}");
        assert!(
            shared.contains(&format!(
                "grep -Fqx -- {}",
                sq(&header_line("scope", SHARED_SCOPE))
            )),
            "{shared}"
        );
    }

    /// P1-1's install half: the binding version is compared as an ordering, so
    /// the very install that upgrades a prior-version file is not refused by
    /// that file's own fence — and a *newer* one still is.
    #[test]
    fn the_guard_admits_an_older_binding_version_and_refuses_a_newer_one() {
        let script =
            install_script(&file("/etc/buzz/acp-abc.env", "0600", "X=1\n"), AGENT, "t0ken");
        assert!(
            script.contains(&format!("-le {BINDING_VERSION_NUM}")),
            "{script}"
        );
        assert!(
            !script.contains(&sq(&header_line("binding-version", BINDING_VERSION))),
            "an exact binding-version needle is the upgrade lockout: {script}"
        );
        // A version that is not a number describes no layout to order against.
        assert!(script.contains("[!0-9]"), "{script}");
    }

    /// Every privileged step is non-interactive, and there are exactly two of
    /// them: the staging write outside the lock, and the one `sudo -n flock`
    /// that elevates the whole critical section. A bare `sudo` on a prompting
    /// host would consume the piped body as keystrokes and write a truncated
    /// root-owned unit file.
    #[test]
    fn every_privileged_step_is_non_interactive() {
        let script = install_script(
            &file(
                "/etc/systemd/system/buzz-acp@abc.service.d/agent.conf",
                "0644",
                "",
            ),
            AGENT,
            "t0ken",
        );
        assert!(script.contains("sudo -n mkdir -p '/etc/systemd/system/buzz-acp@abc.service.d'"));
        assert!(script.contains("sudo -n install"));
        assert!(script.contains("sudo -n flock"));
        for bare in ["sudo mkdir", "sudo install", "sudo flock", "sudo mv"] {
            assert!(
                !script.contains(bare),
                "a privileged step without -n can prompt: {bare}"
            );
        }
        // Inside the wrapper everything is root already, so a nested `sudo`
        // would be a second thing to get wrong — and on a host whose sudoers
        // does not let root sudo, a second failure mode for no benefit.
        let inner = script.find("sh -c '").expect("the critical section");
        assert!(
            !script[inner..].contains("sudo"),
            "the critical section must not re-elevate: {script}"
        );
    }

    #[test]
    fn the_append_script_creates_the_file_once_then_appends_behind_the_same_fence() {
        let script = append_script(
            &file("/etc/buzz/acp-abc.trail", "0644", "# managed-by: x\n"),
            AGENT,
            "t0ken",
        );
        assert!(script.contains(&nested("if [ ! -e '/etc/buzz/acp-abc.trail' ]")), "{script}");
        assert!(
            script.contains(&nested("install -m 0644 /dev/stdin '/etc/buzz/acp-abc.trail'")),
            "{script}"
        );
        assert!(script.contains(&nested("tee -a '/etc/buzz/acp-abc.trail'")), "{script}");
        // A trail that is not ours must not be appended to either.
        assert!(script.contains(&OWNERSHIP_REFUSED.to_string()), "{script}");
        // …and neither must one whose lease has moved on.
        assert!(script.contains(&LOCK_UNAVAILABLE.to_string()), "{script}");
    }

    /// Round 4's P1-1. The marker guard proves *provenance*; it says nothing
    /// about whether this process still holds the lease, so a stalled holder
    /// that had been legitimately overtaken could satisfy it and `mv` a stale
    /// render over the winner's files. The proof and the mutation now share
    /// one `flock`, which is the only arrangement a takeover cannot slip
    /// between: changing the owner record needs the same lock.
    #[test]
    fn an_install_proves_the_lease_in_the_same_shell_as_the_rename() {
        let script =
            install_script(&file("/etc/buzz/acp-abc.env", "0600", "X=1\n"), AGENT, "t0ken");
        let (lock, owner) = lease_paths(AGENT);
        assert!(script.contains(&sq(&lock)), "no lock is taken: {script}");
        assert!(
            script.contains("sudo -n flock -w"),
            "the critical section is not elevated as one: {script}"
        );
        assert!(
            script.contains(&nested(&sq(&owner))),
            "the owner record is not read: {script}"
        );
        assert!(script.contains(&LOCK_UNAVAILABLE.to_string()), "{script}");

        // Drain, then lock, then prove, then check the marker, then rename.
        // The drain is outside the lock deliberately: holding it across a read
        // that waits on the network would block a rival's acquire for as long
        // as the body takes to arrive.
        let drained = script.find("/dev/stdin").expect("the staged write");
        let lock_at = script.find("flock -w").expect("the lock");
        let gate = script.find("cut -d").expect("the lease proof");
        let guard = script.find("marker_ok ||").expect("the ownership guard");
        let rename = script.find("mv -f").expect("the rename");
        assert!(
            drained < lock_at && lock_at < gate && gate < guard && guard < rename,
            "drain, lock, prove the lease, check the marker, rename: {script}"
        );
        assert_eq!(
            script.matches("sh -c '").count(),
            1,
            "a second shell is a second chance to lose the lease: {script}"
        );
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

use crate::naming::{BINDING_VERSION, BINDING_VERSION_NUM, MANAGED_BY};
use crate::render::RemoteFile;
use buzz_backend_core::identity::new_generation;
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

/// "This path is present but is not this agent's." Not a transport failure,
/// and must not read as one.
pub const OWNERSHIP_REFUSED: i32 = 76;
/// "Another deploy of this agent holds the instance lease."
pub const LOCK_UNAVAILABLE: i32 = 75;
/// "The authorizing marker moved between the observation and the write."
pub const MARKER_CHANGED: i32 = 77;
/// "The agent started between the observation and the stop."
pub const AGENT_STARTED: i32 = 78;

/// How many leading lines of a file can hold a marker header.
///
/// Four, not three: a per-agent header is four lines starting at line 1, while
/// a shared header is three lines starting at line 2 when a shebang precedes
/// it. One bound covers both, because the checks count exact whole-line
/// matches rather than comparing a fixed slice.
pub const MARKER_SCAN_LINES: usize = 4;

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

/// The one capability `secrets` needs from a transport.
///
/// A trait rather than the concrete `Remote` because the ownership discipline
/// `secrets` enforces is a property of the **command sequence** — describe,
/// verify, mutate, describe, verify, mutate — and a sequence can only be tested
/// by recording it. `Remote` is the sole production implementation.
pub trait Gcloud {
    fn gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String>;
}

/// A bound instance this provider can run commands on.
pub struct Remote {
    project: String,
    zone: String,
    instance: String,
    token: String,
}

/// Quote a value for a single-quoted POSIX shell context.
pub fn sq(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The private directory both deploy-lease files live in.
///
/// Not `/run/lock` directly. `/run` is the right filesystem — a tmpfs systemd
/// recreates on every boot, so a lease can never outlive the reboot that made
/// its holder irrelevant — but `/run/lock` is world-readable and, on several
/// distributions, group-writable, so a predictable `<agent>.owner` path there
/// is a record an unprivileged local user can watch and, in the worst case,
/// pre-create with contents of their choosing. `0700 root:root` puts the
/// record where exactly the identity that enforces it can read or write it.
///
/// The *shape* of a lease lives in this module and its *policy* lives in
/// `reconcile`, and the split is deliberate: every mutating script this module
/// renders has to carry the ownership proof inside its own shell, which makes
/// the proof a transport concern; how long a lease lives, when it is taken and
/// when an abandoned one may be stolen are questions about deploys, which
/// makes them the reconciler's.
pub(crate) const LEASE_DIR: &str = "/run/buzz-backend-gcp";

/// How long to wait for the lease's `flock`. Every critical section under it
/// is a handful of local file operations — never a network read — so anything
/// longer means a wedged holder rather than a busy one.
pub(crate) const LEASE_FLOCK_WAIT_SECONDS: u64 = 5;

/// Where one agent's deploy lease lives: `(lock, owner)`.
///
/// `agent` is the 12-lowercase-hex instance name derived from the pubkey
/// (`naming::Names::instance`) — **not** the GCE instance this `Remote` is
/// bound to — and the closed grammar it comes from is what makes it safe to
/// interpolate into a path.
pub(crate) fn lease_paths(agent: &str) -> (String, String) {
    (
        format!("{LEASE_DIR}/{agent}.lock"),
        format!("{LEASE_DIR}/{agent}.owner"),
    )
}

/// Evidence that the caller holds an agent's deploy lease.
///
/// One method, and exactly one implementor: `reconcile::DeployLease`, whose
/// only constructor writes the owner record first. Every mutating entry point
/// below takes `&dyn Held`, so "this write happens under a lease" is something
/// the signature enforces rather than something a comment asks for — the same
/// discipline round 3 applied to the authoritative observation, applied to the
/// writes. Adding a second implementor is a deliberate act with a compiler
/// error's worth of friction, which is the point.
pub(crate) trait Held {
    /// The 12-lowercase-hex agent whose lease is held.
    fn agent(&self) -> &str;
}

/// The first thing inside every mutating shell: prove the owner record still
/// names this process, then push its expiry out.
///
/// This is round 4's P1-1 in four lines. Renewing at phase boundaries proved
/// only that the lease was ours *at the boundary*; the write that followed
/// carried no lease check at all, because `marker_fn` proves provenance and
/// `owner_marker` deliberately carries neither the create-intent nor the
/// token. A holder that stalled past the TTL could therefore be legitimately
/// overtaken and still land its `mv` on the winner's files. Here the proof and
/// the mutation are one shell under one `flock`, and the record can only be
/// changed under that same `flock`, so no takeover can interleave between
/// them: either it completes first and this gate refuses, or this shell holds
/// the lock and the rival's `flock -w` times out.
///
/// It refreshes as well as verifies, which is why `DeployLease::renew` no
/// longer runs at every phase boundary — a window made of fenced mutations
/// renews itself, and the one stretch that is not (the Secret Manager calls,
/// which leave the instance entirely) keeps an explicit renewal.
///
/// [`LOCK_UNAVAILABLE`] for every failure, because the operator's remedy is
/// the same in each case: another operation owns this agent right now.
pub(crate) fn lease_gate(owner: &str, token: &str) -> String {
    format!(
        "now=$(date +%s)\n\
         [ -f {owner} ] || exit {busy}\n\
         [ \"$(cut -d' ' -f1 {owner})\" = {token} ] || exit {busy}\n\
         printf '%s %s\\n' {token} \"$now\" > {owner}\n",
        owner = sq(owner),
        token = sq(token),
        busy = LOCK_UNAVAILABLE,
    )
}

/// Wrap a **root** script so it runs only while this process still holds
/// `agent`'s deploy lease — the proof and the mutation in one shell, under one
/// `flock`.
///
/// `sudo -n flock … sh -c` rather than `sudo -n sh -c 'exec 9>…'`: [`LEASE_DIR`]
/// is `0700 root:root`, so the lock cannot be opened without elevating first,
/// and `flock`'s command form elevates **once** for the whole critical section
/// instead of once per command inside it. `-E` makes a lock we could not take
/// exit [`LOCK_UNAVAILABLE`] rather than the `1` that a hundred other things
/// also return. This is the single shape every critical section in this
/// binding uses — acquire, renew, release, each install, the append, the
/// fenced stop, the start and the removal are the same wrapper with a
/// different body.
///
/// `root_script` carries no `sudo -n` and no `set` line of its own: everything
/// inside the wrapper is already root, and a second `sudo` there is a second
/// thing to get wrong. It runs under `/bin/sh` (dash on Debian and Ubuntu
/// images), so no `pipefail`, no `[[`, no arrays — the outer script keeps
/// those.
///
/// The body is `sq`-wrapped, so every single quote it carries appears as
/// `'\''` in the emitted script. Tests that match on a quoted needle inside it
/// have to account for that; the `nested` helper in Tasks 9 and 12 is that
/// accounting, written down rather than worked around by matching only on
/// quote-free fragments.
pub(crate) fn under_lease(agent: &str, token: &str, root_script: &str) -> String {
    let (lock, owner) = lease_paths(agent);
    let inner = format!(
        "set -u\n{gate}{root_script}",
        gate = lease_gate(&owner, token),
    );
    format!(
        "sudo -n flock -w {wait} -E {busy} {lock} sh -c {inner}\n",
        wait = LEASE_FLOCK_WAIT_SECONDS,
        busy = LOCK_UNAVAILABLE,
        lock = sq(&lock),
        inner = sq(&inner),
    )
}

/// The refusal for a mutation whose lease could not be proven in its own shell.
///
/// One sentence for both ways it fails — the record names somebody else, or
/// the `flock` itself could not be taken within [`LEASE_FLOCK_WAIT_SECONDS`] —
/// because the outcome is identical (nothing was written) and so is the
/// remedy. It must not read like [`Remote::not_ours`]: that one tells the
/// operator to move a file aside, and following that advice when the real
/// cause is a concurrent deploy is how a healthy artifact gets deleted.
pub(crate) fn lease_lost(target: &str) -> String {
    format!(
        "the deploy lease for {target} was not held at the instant the write \
         reached the instance: another operation has taken it over, or it \
         expired while this one was stalled. Nothing was written, and \
         {target} was left exactly as it was. Re-run once the other operation \
         finishes."
    )
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

/// The `marker_ok` shell function: does the header captured in `$h` carry
/// every line of `required`, at a binding version this build may act on?
/// Exit 0 for yes, 1 for no.
///
/// One definition, `pub(crate)`, called by this module's install guard and by
/// Task 13's per-file delete veto — because both used to ask the question the
/// same wrong way. `grep -c -F -x -e a -e b -e c` compared against `3` counts
/// matching input **lines**, not distinct matched patterns, so a header whose
/// first three lines are `# managed-by: …` twice and `# binding-version: …`
/// once reaches the count while carrying no `# agent-pubkey-full:` at all, and
/// the guard then authorizes overwriting or deleting a file that does not
/// carry the tuple. Each needle is asserted on its own here, and the first
/// miss returns.
///
/// The binding version is deliberately **not** one of the needles. It is
/// compared as an ordering, `-le BINDING_VERSION_NUM`: a file written by an
/// older build of this provider is an authorised upgrade target, so requiring
/// an exact `# binding-version: N` line would make the very install that
/// upgrades a file be refused by that file's own fence. A non-numeric or newer
/// version is a refusal — a layout this build cannot reason about must not be
/// rewritten.
pub(crate) fn marker_fn(required: &[String]) -> String {
    let checks: String = required
        .iter()
        .map(|line| format!("printf '%s\\n' \"$h\" | grep -Fqx -- {} || return 1\n", sq(line)))
        .collect();
    format!(
        "marker_ok() {{\n\
         {checks}\
         v=$(printf '%s\\n' \"$h\" | sed -n 's/^# binding-version: //p' | head -n 1)\n\
         case \"$v\" in ''|*[!0-9]*) return 1 ;; esac\n\
         [ \"$v\" -le {version} ] || return 1\n\
         return 0\n\
         }}\n",
        checks = checks,
        version = BINDING_VERSION_NUM,
    )
}

/// The shell fragment that refuses to touch an existing file whose own header
/// is not ours.
///
/// `head -n MARKER_SCAN_LINES` rather than an exact slice: a shared artifact
/// carries a shebang on line 1, so its three header lines sit at 2-4, while a
/// per-agent artifact's four start at line 1. Matching exact whole lines
/// anywhere in that window makes the check independent of which.
///
/// The refusal carries no message. The caller knows the path, the reason and
/// which of several operations is speaking; the script knows none of that, and
/// a generic sentence from the wrong layer is worse than a number.
///
/// No `sudo -n` of its own: this fragment only ever appears inside
/// [`under_lease`]'s `sudo -n flock … sh -c`, which is already root. One
/// elevation for the whole critical section is also what lets the lock be
/// opened at all — [`LEASE_DIR`] is `0700 root:root`.
///
/// An empty `required` means unguarded, which `render::plan` never produces —
/// that invariant is asserted where it is established (Task 7), not defended
/// again here.
fn marker_guard(path: &str, required: &[String]) -> String {
    if required.is_empty() {
        return String::new();
    }
    format!(
        "{marker_ok}\
         if test -e {path}; then\n\
         h=$(head -n {scan} {path} || true)\n\
         marker_ok || exit {refused}\n\
         fi\n",
        marker_ok = marker_fn(required),
        path = sq(path),
        scan = MARKER_SCAN_LINES,
        refused = OWNERSHIP_REFUSED,
    )
}

/// The remote script that installs one file: body from stdin, atomically, and
/// only over a target whose own marker says it is ours — while this process
/// still holds the agent's deploy lease.
///
/// Four properties, each load-bearing:
///
/// * **stdin is drained first, and before the lock is taken.** The body
///   reaches the staging path *before* anything can refuse, so a refusal
///   cannot close the pipe under a local `write_all` still in flight and turn
///   a clean refusal into a transport error — and the `flock` is never held
///   across a read that depends on the network, so a rival's acquire waits on
///   three local file operations rather than on a body transfer.
/// * **The target is never observed half-written.** `mv` within one directory
///   is a `rename(2)`: the target goes from old bytes to new with nothing in
///   between. Without this a dropped connection leaves a truncated file with no
///   complete marker, which the guard must then refuse forever — P1-9 and P1-4
///   are only safe together.
/// * **The guard runs in the same shell as the write.** An ownership check
///   performed in an earlier round trip is a TOCTOU with a four-round-trip
///   window; here it is one `rename`.
/// * **So does the lease proof.** Round 4's P1-1: the marker guard establishes
///   *provenance* — this provider, this agent, a binding version we may act on
///   — and says nothing about whether we still hold the lease, so a stalled
///   holder whose lease had been taken over could satisfy it and `mv` a stale
///   render over the winner's files. [`under_lease`] wraps the check-and-mv
///   pair in one `flock`, and the owner record can only change under that same
///   `flock`, so a takeover cannot interleave between them.
///
/// The staging path carries the per-process token, so two providers installing
/// the same shared artifact at the same moment cannot collide on it, and the
/// `trap` removes it on every exit path including both refusals.
fn install_script(file: &RemoteFile, agent: &str, token: &str) -> String {
    let parent = Path::new(&file.path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string());
    let staged = sq(&format!("{}.{token}.tmp", file.path));
    let critical = format!(
        "set -e\n\
         {guard}\
         mv -f {staged} {path}\n",
        guard = marker_guard(&file.path, &file.owner_marker),
        staged = staged,
        path = sq(&file.path),
    );
    format!(
        "set -euo pipefail\n\
         sudo -n mkdir -p {parent}\n\
         trap \"sudo -n rm -f {staged}\" EXIT\n\
         sudo -n install -m {mode} /dev/stdin {staged}\n\
         {fenced}\
         trap - EXIT\n",
        parent = sq(&parent),
        staged = staged,
        mode = file.mode,
        fenced = under_lease(agent, token, &critical),
    )
}

/// The remote script that appends one record to a file, creating it with
/// `file.body` — its marker header — when absent.
///
/// The header is a marker: pubkey, binding version, create-intent, all public,
/// so passing it in argv is safe. The *record* travels on stdin along with
/// everything a capacity warning might carry.
///
/// Fenced like an install — by the target's own marker and by the lease — but
/// not staged: an append has no half-written-target failure mode, and the
/// record is a few hundred bytes, well inside a pipe buffer, so the whole
/// thing fits inside the critical section without the `flock` ever waiting on
/// the network.
fn append_script(file: &RemoteFile, agent: &str, token: &str) -> String {
    let critical = format!(
        "set -e\n\
         {guard}\
         if [ ! -e {path} ]; then \
           printf '%s' {header} | install -m {mode} /dev/stdin {path}; \
         fi\n\
         tee -a {path} > /dev/null\n",
        guard = marker_guard(&file.path, &file.owner_marker),
        path = sq(&file.path),
        mode = file.mode,
        header = sq(&file.body),
    );
    format!("set -euo pipefail\n{}", under_lease(agent, token, &critical))
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

impl Gcloud for Remote {
    /// Invoke `gcloud`, optionally piping `stdin`. Never logs `stdin`.
    fn gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String> {
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
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| "gcloud stdin was not available".to_string())?;
            // A remote script that refuses before reading closes the pipe, so a
            // `BrokenPipe` here is that refusal arriving early — not a transport
            // failure. The exit code and stderr collected below are what report
            // it, and returning an IO error instead would bury the real reason.
            // Rust sets SIGPIPE to ignore at startup, so this surfaces as an
            // `Err` rather than killing the process. Any other IO error is real.
            if let Err(e) = pipe.write_all(body.as_bytes()) {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err(format!("writing to gcloud stdin failed: {e}"));
                }
            }
            // Dropped explicitly: the child waits for EOF, and a pipe held open
            // by a named binding would deadlock `wait_with_output`.
            drop(pipe);
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
            // One per provider process, which is one per operation.
            token: new_generation(),
        })
    }

    /// This process's token, mixed into every staging path and into the deploy
    /// lease record, so two concurrent providers can neither collide on a
    /// staging path nor release each other's lease.
    pub fn token(&self) -> &str {
        &self.token
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

    /// The refusal for a target that exists and is not this agent's.
    ///
    /// "at a binding version this build may act on" rather than "at binding
    /// version N": the guard admits an *older* version — that is the upgrade
    /// path — and refuses a newer or foreign one, so naming this build's exact
    /// version would describe a check the script does not perform.
    fn not_ours(&self, path: &str, verb: &str) -> String {
        format!(
            "{path} is present on the instance but does not carry this agent's \
             {MANAGED_BY} marker at a binding version this build may act on \
             (this build writes {BINDING_VERSION}; a newer one is refused \
             rather than downgraded). Refusing to {verb} a file this provider \
             did not write for this agent — it was left exactly as it was. \
             Move it aside, or run `buzz-backend-gcp list` to see which agent \
             owns it."
        )
    }

    /// Install one file, body on stdin, atomically, behind its own marker
    /// guard **and** the deploy lease.
    ///
    /// `lease` is not decoration and it is not a `&str`: the only implementor
    /// of [`Held`] is `reconcile::DeployLease`, whose sole constructor writes
    /// the owner record first, so "this write happens under a lease" is a
    /// thing the signature says rather than a thing a comment hopes.
    /// [`LOCK_UNAVAILABLE`] and [`OWNERSHIP_REFUSED`] earn different
    /// sentences: one tells the operator to re-run, the other tells them to
    /// move a file aside, and acting on the wrong one deletes a healthy file.
    pub(crate) fn install(&self, file: &RemoteFile, lease: &dyn Held) -> Result<(), String> {
        let script = install_script(file, lease.agent(), &self.token);
        let out = self.run_with_stdin(&script, Some(&file.body))?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(lease_lost(&file.path));
        }
        if out.code == OWNERSHIP_REFUSED {
            return Err(self.not_ours(&file.path, "overwrite"));
        }
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

    /// Append one record, creating the file with its marker header when absent.
    pub(crate) fn append(
        &self,
        file: &RemoteFile,
        record: &str,
        lease: &dyn Held,
    ) -> Result<(), String> {
        let script = append_script(file, lease.agent(), &self.token);
        let out = self.run_with_stdin(&script, Some(record))?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(lease_lost(&file.path));
        }
        if out.code == OWNERSHIP_REFUSED {
            return Err(self.not_ours(&file.path, "append a deploy record to"));
        }
        if !out.ok() {
            return Err(format!(
                "appending to {} failed (exit {}): {}",
                file.path,
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    /// Run a **root** script on the instance under this agent's deploy lease.
    ///
    /// The counterpart to [`Remote::run`] for anything that mutates and is not
    /// a file install: the fenced stop, the start, and `operator`'s removal
    /// script. Callers write plain root commands — no `set` line, no `sudo -n`
    /// — and [`under_lease`] supplies the elevation, the `flock` and the
    /// ownership proof. The exit code reaches the caller untouched, because
    /// each of those three speaks its own vocabulary on top of
    /// [`LOCK_UNAVAILABLE`].
    pub(crate) fn run_fenced(
        &self,
        lease: &dyn Held,
        root_script: &str,
    ) -> Result<Output, String> {
        self.run(&format!(
            "set -uo pipefail\n{}",
            under_lease(lease.agent(), &self.token, root_script)
        ))
    }
}
```

Add `mod remote;` to `main.rs`.

- [ ] **Step 4: Run to verify passing**

Run: `cargo test -p buzz-backend-gcp remote`
Expected: PASS — 13 tests (round 4 adds `an_install_proves_the_lease_in_the_same_shell_as_the_rename`).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): IAP ssh transport with stdin-only bodies"
```

---

## Task 10: `secrets.rs` — Secret Manager storage behind an ownership gate

Resolves review **P2-1**, round 2's **P1-5** (ownership is verified once and then mutated twice), and the Secret Manager half of round 3's **P1-1**: a secret this provider created at an older binding version is an upgrade target, not a stranger.

**Files:**
- Create: `crates/buzz-backend-gcp/src/secrets.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod secrets;`)

**Interfaces:**
- Produces:
  - `secrets::labels_for(pubkey_full: &str) -> String` — the `--labels` argument value
  - `secrets::annotations_for(pubkey_full: &str) -> String` — the `--set-annotations` value
  - `secrets::verify_owned(described: &serde_json::Value, pubkey_full: &str, name: &str) -> Result<Ownership, String>` — pure, unit-tested; `Ok` carries `Ours` or `OursButOlder(v)` so `store` can tell a steady state from an upgrade
  - `secrets::describe(remote: &dyn Gcloud, project: &str, name: &str) -> Result<Option<serde_json::Value>, String>`
  - `secrets::store(remote: &dyn Gcloud, project: &str, name: &str, pubkey_full: &str, body: &str, service_account: &str) -> Result<(), String>`
  - `secrets::destroy(remote: &dyn Gcloud, project: &str, name: &str, pubkey_full: &str) -> Result<(), String>`
  - `secrets::instance_service_account(remote: &dyn Gcloud, project: &str, zone: &str, instance: &str) -> Result<String, String>`
- Consumes: `crate::remote::{Gcloud, Output}`, `crate::naming::{ownership_of, Ownership, BINDING_VERSION, MANAGED_BY}`.

**Why the transport is a trait here and nowhere else.** Every function above takes `&dyn Gcloud` rather than `&Remote`, and `Remote` is the only production implementation. The reason is narrow and specific: the property this module has to guarantee is a property of the **command sequence** — describe, verify, mutate, describe, verify, mutate — and a sequence can only be tested by recording it. `verify_owned` can be unit-tested to exhaustion while `store` still verifies once and mutates twice, which is exactly the defect round 2 found. `&dyn` rather than a generic because the call is once per deploy and the vtable costs nothing next to an IAP round trip.

**Why the operand is a `&str` and not an `AgentIdentity`.** `deploy` holds a decoded identity, but `remove` never does — the operator has the pubkey `list` printed, not the agent's key. Taking the validated 64-hex string keeps one gate for both callers instead of inventing a second, weaker one for the operator path. `naming::normalize_pubkey` (Task 13) is where an operator-supplied value is validated before it can reach this module.

**The marker is verified immediately before every add-version, IAM binding, and delete — not once per call.** The precedent is `secret_is_ours`, which requires *both* marker halves *and* a full-pubkey match (`crates/buzz-backend-kubernetes/src/observe.rs:64-67`, over `has_marker` at `:42-46` and `annotation_matches` at `:52-60`), and whose comment states the principle: *"Identity labels prove identity; the marker asserts protocol ownership. Without it an object that merely matches our schema fails closed"* (`observe.rs:38-41`). Without that gate, a name-matching secret created by anything else — an operator, another tool, a *foreign* binding — receives this agent's whole secret environment as a new version *and* a grant of read access to the VM service account. Name collision is not ownership.

**But "an older binding version" is not somebody else — it is us, last release.** The label pair goes through the same `naming::ownership_of` the file headers use, so the four states mean the same thing on both sides of the binding. `OursButOlder` is an authorised upgrade: `store` issues `secrets update --update-labels` to roll the marker forward and then adds the new version, which is what keeps a `BINDING_VERSION` bump from stranding every agent's secret. The refusals that remain are the ones worth having — a foreign or absent `managed_by`, a *newer* binding version whose layout this build cannot reason about, and an `agent-pubkey-full` that names a different agent.

**Once is not enough, and the distance is the point.** The previous revision verified at the top of `store` and then ran `versions add` and `add-iam-policy-binding` with no re-read between them. Each of those is a full API round trip, and a secret that changes hands inside that window is granted this agent's payload or hands the VM `secretAccessor` on a resource we no longer own. Every mutation now sits immediately after its own `describe_owned`, with **nothing** between the two, and a test asserts the resulting command sequence rather than trusting the reading of it.

**A lost create race converges; it does not fail.** Two concurrent deploys can both observe "absent" and both call `create`. Returning the loser's failure contradicts this binding's own residual-risk claim that conflicts converge by re-entry. `ALREADY_EXISTS` on create is therefore not a failure: it means somebody won, and the marker on what they created — read back immediately — is what decides whether this deploy may proceed. Anything *else* on create is still a hard failure.

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
        assert_eq!(
            verify_owned(&described(&pubkey), &pubkey, "s").expect("ours"),
            Ownership::Ours
        );
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

    /// P1-1, the Secret Manager half: an older binding version is this
    /// provider's own secret at a layout this build supersedes. Refusing it
    /// stranded every existing agent's secret behind a version bump — the
    /// deploy could not add a version and `remove` could not delete it.
    #[test]
    fn a_secret_from_an_older_binding_version_is_an_upgrade_target() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]["binding_version"] = json!("0");
        assert_eq!(
            verify_owned(&secret, &pubkey, "s").expect("ours, one release back"),
            Ownership::OursButOlder(0)
        );
    }

    /// …and a *newer* one is the refusal that reserves, naming the version so
    /// the operator is not told their own secret is foreign.
    #[test]
    fn a_secret_from_a_future_binding_version_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]["binding_version"] = json!("99");
        let err = verify_owned(&secret, &pubkey, "s").expect_err("must refuse");
        assert!(err.contains("99"), "{err}");
        assert!(err.contains("newer"), "{err}");
        assert!(!err.contains("not managed by"), "{err}");
    }

    /// A `binding_version` label that is not a number describes no layout at
    /// all, so it cannot be ordered against ours. Fail closed.
    #[test]
    fn a_non_numeric_binding_version_label_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]["binding_version"] = json!("1.0");
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

    /// A fake transport that records every `gcloud` invocation and answers
    /// `secrets describe` from a queue the test controls. The last queued
    /// answer repeats, so a test only has to spell out the entries that differ.
    struct Recorder {
        /// One entry per `secrets describe`, in order. `None` is NOT_FOUND.
        describes: std::cell::RefCell<std::collections::VecDeque<Option<serde_json::Value>>>,
        /// stderr for `secrets create`, so a lost create race is expressible.
        create_stderr: String,
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl Recorder {
        fn new(describes: Vec<Option<serde_json::Value>>) -> Self {
            Self {
                describes: std::cell::RefCell::new(describes.into()),
                create_stderr: String::new(),
                calls: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn losing_the_create_race(describes: Vec<Option<serde_json::Value>>) -> Self {
            Self {
                create_stderr:
                    "ERROR: (gcloud.secrets.create) ALREADY_EXISTS: Secret already exists"
                        .to_string(),
                ..Self::new(describes)
            }
        }

        /// The verbs, in the order they were invoked.
        fn sequence(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Gcloud for Recorder {
        fn gcloud(&self, args: &[&str], _stdin: Option<&str>) -> Result<Output, String> {
            let verb = match args {
                ["secrets", "describe", ..] => "describe",
                ["secrets", "create", ..] => "create",
                ["secrets", "update", ..] => "update",
                ["secrets", "versions", "add", ..] => "versions add",
                ["secrets", "add-iam-policy-binding", ..] => "add-iam-policy-binding",
                ["secrets", "delete", ..] => "delete",
                _ => "other",
            };
            self.calls.borrow_mut().push(verb.to_string());
            let mut out = Output {
                stdout: String::new(),
                stderr: String::new(),
                code: 0,
            };
            match verb {
                "describe" => {
                    let mut queue = self.describes.borrow_mut();
                    let answer = if queue.len() > 1 {
                        queue.pop_front().flatten()
                    } else {
                        queue.front().cloned().flatten()
                    };
                    match answer {
                        Some(value) => out.stdout = value.to_string(),
                        None => {
                            out.code = 1;
                            out.stderr = "NOT_FOUND: Secret [s] not found.".to_string();
                        }
                    }
                }
                "create" if !self.create_stderr.is_empty() => {
                    out.code = 1;
                    out.stderr = self.create_stderr.clone();
                }
                _ => {}
            }
            Ok(out)
        }
    }

    /// P1-5: `store` verified ownership once and then performed two mutations.
    /// Every mutation must be immediately preceded by a describe whose marker
    /// still matches — a property of the sequence, invisible to any test of
    /// `verify_owned` alone.
    #[test]
    fn every_mutation_is_immediately_preceded_by_a_describe_and_verify() {
        let pubkey = pubkey();
        let fake = Recorder::new(vec![Some(described(&pubkey))]);
        store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect("an owned secret stores");
        assert_eq!(
            fake.sequence(),
            ["describe", "versions add", "describe", "add-iam-policy-binding"]
        );
    }

    /// P1-1's sequence half. A secret at an older binding version is rolled
    /// forward *before* the new version is added, so a deploy interrupted
    /// after the label update leaves a secret the next run reads as `Ours`
    /// rather than repeating the upgrade. The re-read between the update and
    /// the add is not optional: a full API round trip now separates the
    /// verification from the mutation it authorizes.
    #[test]
    fn a_secret_from_an_older_binding_version_is_rolled_forward() {
        let pubkey = pubkey();
        let mut older = described(&pubkey);
        older["labels"]["binding_version"] = json!("0");
        // Older on the first look, current on every look after the update.
        let fake = Recorder::new(vec![Some(older), Some(described(&pubkey))]);
        store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect("this provider's own prior-version secret is an upgrade target");
        assert_eq!(
            fake.sequence(),
            [
                "describe",
                "update",
                "describe",
                "versions add",
                "describe",
                "add-iam-policy-binding"
            ]
        );
    }

    /// The attack that sequence prevents: ownership holds when the version is
    /// added and has moved by the time the IAM grant would be issued. The VM
    /// service account must not be granted read access to somebody else's key.
    #[test]
    fn a_secret_swapped_before_the_iam_grant_is_refused() {
        let pubkey = pubkey();
        let mut stolen = described(&pubkey);
        stolen["annotations"]["agent-pubkey-full"] = json!("ff".repeat(32));
        let fake = Recorder::new(vec![Some(described(&pubkey)), Some(stolen)]);
        let err = store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect_err("a secret that changed hands must not be granted away");
        assert!(err.contains("belongs to pubkey"), "{err}");
        assert!(
            !fake.sequence().contains(&"add-iam-policy-binding".to_string()),
            "the grant must never have been issued: {:?}",
            fake.sequence()
        );
    }

    /// The loser of a create race converges by re-entry rather than failing —
    /// which is what this binding's residual-risk note already promises.
    #[test]
    fn a_lost_create_race_is_re_read_and_verified_rather_than_failed() {
        let pubkey = pubkey();
        // Absent on the first look, then present and ours: the winner was
        // another deploy of this same agent.
        let fake = Recorder::losing_the_create_race(vec![None, Some(described(&pubkey))]);
        store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect("losing a create race must converge, not fail");
        assert_eq!(
            fake.sequence(),
            [
                "describe",
                "create",
                "describe",
                "versions add",
                "describe",
                "add-iam-policy-binding"
            ]
        );
    }

    /// …and losing it to something that is *not* ours is still a refusal: the
    /// winner's marker is what decides, not the fact that we lost.
    #[test]
    fn a_create_race_lost_to_a_foreign_secret_is_refused() {
        let pubkey = pubkey();
        let mut foreign = described(&pubkey);
        foreign["labels"] = json!({});
        let fake = Recorder::losing_the_create_race(vec![None, Some(foreign)]);
        let err = store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect_err("the winner's marker decides");
        assert!(err.contains("not managed by"), "{err}");
        assert!(!fake.sequence().contains(&"versions add".to_string()));
    }

    /// Delete is irreversible, so its describe-and-verify sits immediately
    /// before it with nothing in between.
    #[test]
    fn destroy_verifies_immediately_before_the_delete() {
        let pubkey = pubkey();
        let fake = Recorder::new(vec![Some(described(&pubkey))]);
        destroy(&fake, "p", "s", &pubkey).expect("an owned secret is deleted");
        assert_eq!(fake.sequence(), ["describe", "delete"]);
    }

    /// Delete-of-absent is success ([L2] item 4) and must not reach the delete.
    #[test]
    fn destroying_an_absent_secret_is_success_and_mutates_nothing() {
        let fake = Recorder::new(vec![None]);
        destroy(&fake, "p", "s", &pubkey()).expect("delete-of-absent is success");
        assert_eq!(fake.sequence(), ["describe"]);
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

use crate::naming::{ownership_of, Ownership, BINDING_VERSION, MANAGED_BY};
use crate::remote::{Gcloud, Output};

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
///
/// The two labels go through [`ownership_of`], the same rule the file-header
/// tiers use, so "ours / ours-but-older / ours-but-newer / not ours" has one
/// definition in this binding rather than one per storage medium. `Ok` carries
/// the verdict because the caller has to act on it: `OursButOlder` means the
/// labels need rolling forward before anything else happens.
pub fn verify_owned(
    described: &serde_json::Value,
    pubkey_full: &str,
    name: &str,
) -> Result<Ownership, String> {
    let label = |key: &str| {
        described
            .get("labels")
            .and_then(|labels| labels.get(key))
            .and_then(serde_json::Value::as_str)
    };
    let ownership = ownership_of(label(LABEL_MANAGED_BY), label(LABEL_BINDING_VERSION));
    match ownership {
        Ownership::Ours | Ownership::OursButOlder(_) => {}
        Ownership::OursButNewer(found) => {
            return Err(format!(
                "secret {name} was created by a newer {MANAGED_BY} (binding \
                 version {found}; this build writes {BINDING_VERSION}). \
                 Refusing to write a version into, or delete, a secret whose \
                 layout this build does not understand. Upgrade this provider."
            ))
        }
        Ownership::NotOurs => {
            return Err(format!(
                "secret {name} already exists but is not managed by \
                 {MANAGED_BY} at a binding version this build recognises. \
                 Refusing to modify a secret this provider did not create — \
                 rename or delete it, or point this agent at a different \
                 instance."
            ))
        }
    }
    let annotated = described
        .get("annotations")
        .and_then(|annotations| annotations.get(ANNOTATION_PUBKEY_FULL))
        .and_then(serde_json::Value::as_str);
    match annotated {
        Some(pubkey) if pubkey == pubkey_full => Ok(ownership),
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
    remote: &dyn Gcloud,
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

/// Read the secret and verify our marker, as one step, immediately before a
/// mutation.
///
/// Every mutation in this module is preceded by this call with **nothing** in
/// between. A single verification at the top of `store` authorized an
/// add-version and an IAM grant that happened one and two API round trips
/// later, and a name-matching secret swapped into that window receives this
/// agent's whole environment or hands the VM `secretAccessor` on a resource we
/// no longer own.
///
/// A secret that vanished between two checks is a refusal, not a create: this
/// is only reached on a path that has already established it exists.
fn describe_owned(
    remote: &dyn Gcloud,
    project: &str,
    name: &str,
    pubkey_full: &str,
) -> Result<Ownership, String> {
    let Some(described) = describe(remote, project, name)? else {
        return Err(format!(
            "secret {name} disappeared between two checks in this deploy. \
             Nothing further was changed; run the deploy again."
        ));
    };
    verify_owned(&described, pubkey_full, name)
}

/// Does this `gcloud secrets create` failure mean somebody else won the race?
///
/// Two spellings because `gcloud` surfaces the API status on some paths and a
/// prose message on others. Matching either is what keeps a lost race
/// convergent instead of turning it into a hard failure.
fn already_exists(out: &Output) -> bool {
    out.stderr.contains("ALREADY_EXISTS") || out.stderr.contains("already exists")
}

/// Create-if-absent behind the ownership gate, then add a version carrying
/// `body`, then grant the instance service account read access.
///
/// Idempotent: versions are cheap, and adding one is the only way to guarantee
/// the latest value matches this deploy. Both mutations are individually
/// fenced — see `describe_owned`.
pub fn store(
    remote: &dyn Gcloud,
    project: &str,
    name: &str,
    pubkey_full: &str,
    body: &str,
    service_account: &str,
) -> Result<(), String> {
    match describe(remote, project, name)? {
        Some(existing) => {
            // Verified here. On the steady-state path nothing at all separates
            // this check from the `versions add` below — that is the invariant
            // round 2's P1-5 established and the sequence test asserts.
            if let Ownership::OursButOlder(from) = verify_owned(&existing, pubkey_full, name)? {
                // Ours, one layout back. Roll the marker forward *first*, so a
                // deploy interrupted after this point leaves a secret the next
                // run reads as `Ours` rather than repeating the upgrade.
                // Nothing separates this mutation from the check above either.
                let labels = labels_for(pubkey_full);
                let out = remote.gcloud(
                    &[
                        "secrets",
                        "update",
                        name,
                        "--project",
                        project,
                        "--update-labels",
                        &labels,
                    ],
                    None,
                )?;
                if !out.ok() {
                    return Err(format!(
                        "rolling secret {name} forward from binding version \
                         {from} to {BINDING_VERSION} failed (exit {}): {}",
                        out.code,
                        out.stderr.trim()
                    ));
                }
                // A full API round trip now separates the verification above
                // from the add below, so the add gets its own re-read. On the
                // steady-state path this costs nothing, because it does not run.
                describe_owned(remote, project, name, pubkey_full)?;
            }
        }
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
            // A failed create is not decisive. Two concurrent deploys can both
            // observe "absent", and the loser must converge by re-entry rather
            // than fail. `ALREADY_EXISTS` says somebody won; the marker on what
            // they created is what decides whether we may proceed, and reading
            // it is the very next thing that happens.
            if !out.ok() && !already_exists(&out) {
                return Err(format!(
                    "creating secret {name} failed (exit {}): {}",
                    out.code,
                    out.stderr.trim()
                ));
            }
            describe_owned(remote, project, name, pubkey_full)?;
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

    // The IAM grant is a second mutation and gets its own re-read: a full API
    // round trip separates it from the check above.
    describe_owned(remote, project, name, pubkey_full)?;
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
    remote: &dyn Gcloud,
    project: &str,
    name: &str,
    pubkey_full: &str,
) -> Result<(), String> {
    let Some(existing) = describe(remote, project, name)? else {
        return Ok(());
    };
    // The same describe-and-verify `describe_owned` performs, inlined so the
    // absent case above costs no second round trip. Nothing separates this
    // check from the delete it authorizes.
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
    remote: &dyn Gcloud,
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
Expected: PASS — 16 tests — and no clippy warnings.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): label-fenced Secret Manager storage"
```

---

## Task 11: `observe.rs` — systemd state and marker state, separately

Resolves the observation half of review **P1-5**, round 2's **P1-4** (each artifact is observed against its own marker) and the observation half of **P1-6** (the content-hash tamper check is deleted), and the observation half of round 3's **P1-1**: an artifact's binding version is now reported as a three-way verdict rather than folded into a boolean, so `classify` can tell "ours, one layout behind" from "not ours".

**Files:**
- Create: `crates/buzz-backend-gcp/src/observe.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod observe;`)

**Interfaces:**
- Produces:
  - `observe::SystemdState { load_state, active_state, sub_state, unit_file_state, main_pid }` with `instance_known(&self) -> bool` and `running(&self) -> bool`
  - `observe::AgentFileState { path: String, present: bool, ownership: Ownership, marker: Option<AgentMarker> }`
  - `observe::SharedFileState { path: String, present: bool, ownership: Ownership, sha256: String }`
  - `observe::MarkerState { env: AgentFileState, siblings: Vec<AgentFileState>, shared: Vec<SharedFileState> }` with `agent_files(&self) -> impl Iterator<Item = &AgentFileState>`
  - `observe::Observation { systemd, markers, harness_installed: bool, reserved_bytes: u64, available_bytes: u64 }`
  - `observe::SHARED_PATHS: [&str; 3]` and `observe::agent_paths(names: &Names) -> [String; 4]`
  - `observe::look(remote: &Remote, names: &Names, harness: &str) -> Result<Observation, String>`
  - `observe::parse_observation(stdout: &str, own_dropin: &str) -> Observation`
  - `observe::section(body: &str, name: &str) -> &str` and `observe::property(block: &str, key: &str) -> &str` — `pub(crate)`, reused by `reconcile`'s startup poll and its start round trip, which drive scripts of the same sectioned shape
  - `observe::FIELD_HELPER: &str`, `observe::agent_file_rows(names: &Names) -> String` and `observe::parse_agent_file_row(line: &str) -> AgentFileState` — `pub(crate)`, the emitter/parser pair Task 13's pre-stop ownership scan reuses
- Consumes: `crate::capacity::parse_reported_bytes`, `crate::config::parse_memory_max`, `crate::naming::{agent_ownership, header_line, shared_ownership, AgentMarker, Names, Ownership}`, `crate::remote::{sq, Remote, MARKER_SCAN_LINES}`.

**Why the two states are separate types.** The previous revision derived `unit_present` solely from the env file, so a real unit with no env file classified as `Create` and got provider files installed around it. They are independent facts and must be observed independently: systemd knows about install symlinks and running jobs; markers know about ownership. Note the trap the split makes visible — once the *template* `buzz-acp@.service` exists, `systemctl show buzz-acp@<anything>.service` reports `LoadState=loaded` for **every** instance name, so `LoadState` is not evidence that *this* instance exists. `UnitFileState=enabled` (an install symlink) or a non-`inactive` `ActiveState` is.

**Four per-agent rows, not one.** A replace rewrites four files and a remove deletes four files, so an observation that records only the env file's marker cannot authorize either without authorizing them from a *sibling's* header. That is not the auto-repair fence, which says no destructive action may touch a file lacking the marker of its own tier (`docs/remote-agents.md:1460-1476`). The observer therefore reports one `AgentFileState` per artifact, and `classify` refuses on the first present-but-not-ours among them, naming that path. The env file keeps its own field rather than an index into a vector, because it is genuinely special: it is the only artifact that records what the deploy *was*, and so the only one anything classifies on.

**Bytes, not claims.** A shared file is compared by hashing the whole file on the instance and comparing that to the digest of the exact bytes this provider would render. Nothing is stripped, nothing stored in the file is trusted, and there is no `sed` range to get wrong. Whether the file carries the provider marker is a separate question, and it is answered the same way the per-agent rows are: the script extracts the three header values with one `field` helper and ships them, and Rust reassembles the header and hands it to `naming::shared_ownership`. That keeps "is this ours" in **one** function per tier for both the bytes this provider writes and the bytes it reads back — the alternative, a `grep -F -x` needle list built in the script, is a second spelling of the same rule.

**Ownership is a verdict, not a flag.** Each row carries an `Ownership` beside its marker, and the two are not redundant: `ownership` answers the *provenance* question — this provider at this binding version, at an older one, at a newer one, or not us — while `marker` answers the *identity* one, which pubkey and which intent. A file can be plainly ours and still carry no `agent-pubkey-full`, and that deserves a different refusal from "somebody else's file". `marker` is `Some` only when `ownership` is actionable, so the implication runs one way and the observer is the single place both are derived, from the same header, in one function per tier.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/observe.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{BINDING_VERSION, MANAGED_BY, SHARED_SCOPE};

    const INSTANCE: &str = "a1b2c3d4e5f6";
    const OWN_DROPIN: &str = "/etc/systemd/system/buzz-acp@a1b2c3d4e5f6.service.d/agent.conf";
    /// A row body for a file that is not there. Both tiers carry four header
    /// fields — `managed-by`, `binding-version`, then `agent-pubkey-full` and
    /// `create-intent` for a per-agent row or `scope` and the digest for a
    /// shared one — so one spelling serves both.
    const ABSENT: &str = "absent||||";

    fn pubkey() -> String {
        "ab".repeat(32)
    }

    /// A row body for a present file carrying our full per-agent marker.
    fn marked() -> String {
        format!("present|{MANAGED_BY}|{BINDING_VERSION}|{}|ci", pubkey())
    }

    /// The four per-agent rows the observer emits, in `agent_paths` order.
    fn agent_rows(env: &str, dropin: &str, secret_dropin: &str, trail: &str) -> String {
        format!(
            "/etc/buzz/acp-{INSTANCE}.env|{env}\n\
             {OWN_DROPIN}|{dropin}\n\
             /etc/systemd/system/buzz-acp-secret@{INSTANCE}.service.d/agent.conf|{secret_dropin}\n\
             /etc/buzz/acp-{INSTANCE}.trail|{trail}\n"
        )
    }

    fn sample(unit: &str, agent_files: &str, shared: &str, reserved: &str) -> String {
        format!(
            "---UNIT---\n{unit}\
             ---AGENTFILES---\n{agent_files}\
             ---SHARED---\n{shared}\
             ---RESERVED---\n{reserved}\
             ---STANDING---\ninfinity\n\
             ---AVAILABLE---\n2831156\n\
             ---HARNESS---\nyes\n\
             ---END---\n"
        )
    }

    fn all_shared_marked() -> String {
        SHARED_PATHS
            .iter()
            .map(|p| {
                format!("{p}|present|{MANAGED_BY}|{BINDING_VERSION}|{SHARED_SCOPE}|hash-{p}\n")
            })
            .collect()
    }

    /// A row body for a present file carrying our per-agent marker at an
    /// arbitrary binding version, so the ordering rule can be exercised now —
    /// the bump that creates a real prior version is exactly the moment nobody
    /// will re-derive it.
    fn marked_at(version: &str) -> String {
        format!("present|{MANAGED_BY}|{version}|{}|ci", pubkey())
    }

    #[test]
    fn a_running_instance_parses_as_live_and_owned() {
        let out = sample(
            "LoadState=loaded\nActiveState=active\nSubState=running\n\
             UnitFileState=enabled\nMainPID=4242\n",
            &agent_rows(&marked(), &marked(), &marked(), &marked()),
            &all_shared_marked(),
            &format!("{OWN_DROPIN}=2G\n/etc/systemd/system/buzz-acp@ffffffffffff.service.d/agent.conf=1G\n"),
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.systemd.instance_known());
        assert!(o.systemd.running());
        assert!(o.markers.env.present);
        assert!(o.markers.env.marker.is_some());
        assert!(o.markers.agent_files().all(|f| f.marker.is_some()));
        assert!(o.harness_installed);
        // Our own drop-in is excluded, or a redeploy would double-count itself.
        assert_eq!(o.reserved_bytes, 1024 * 1024 * 1024);
        assert_eq!(o.available_bytes, 2_831_156 * 1024);
        assert!(o
            .markers
            .shared
            .iter()
            .all(|s| s.present && s.ownership == Ownership::Ours));
    }

    /// A template unit makes `systemctl show` report `LoadState=loaded` for
    /// every instance name, so `LoadState` alone must never mean "this
    /// instance exists".
    #[test]
    fn a_loaded_template_is_not_evidence_that_this_instance_exists() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=disabled\nMainPID=0\n",
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(!o.systemd.instance_known());
        assert!(!o.systemd.running());
        assert!(!o.markers.env.present);
    }

    /// A failed unit is very much this instance: it has to be observable, or
    /// the reconciler classifies a broken agent as absent and installs over it.
    #[test]
    fn a_failed_instance_is_known() {
        let out = sample(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\n\
             UnitFileState=enabled\nMainPID=0\n",
            &agent_rows(&marked(), ABSENT, ABSENT, ABSENT),
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
            &agent_rows(&marked(), ABSENT, ABSENT, ABSENT),
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
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
            &SHARED_PATHS
                .iter()
                .map(|p| format!("{p}|{ABSENT}\n"))
                .collect::<String>(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(!o.systemd.instance_known());
        assert!(o.markers.agent_files().all(|f| !f.present && f.marker.is_none()));
        assert!(o
            .markers
            .shared
            .iter()
            .all(|s| !s.present && s.ownership == Ownership::NotOurs));
        assert_eq!(o.reserved_bytes, 0);
    }

    #[test]
    fn an_env_file_without_our_marker_is_present_but_unowned() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=enabled\nMainPID=0\n",
            &agent_rows("present||||", ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.markers.env.present);
        assert!(o.markers.env.marker.is_none());
    }

    /// P1-1's observation half. A version this build supersedes must read as
    /// *ours, one layout behind* — with its identity intact, because `remove`
    /// needs that pubkey — and a version it does not understand must read as
    /// neither ours nor anonymous.
    #[test]
    fn a_row_reports_an_older_version_as_ours_and_a_newer_one_as_not() {
        let unit = "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
                    UnitFileState=enabled\nMainPID=0\n";
        let older = parse_observation(
            &sample(
                unit,
                &agent_rows(&marked_at("0"), ABSENT, ABSENT, ABSENT),
                &all_shared_marked(),
                "",
            ),
            OWN_DROPIN,
        );
        assert_eq!(older.markers.env.ownership, Ownership::OursButOlder(0));
        assert_eq!(
            older.markers.env.marker.as_ref().map(|m| m.pubkey_full.clone()),
            Some(pubkey()),
            "an upgrade target must keep the identity remove acts on"
        );

        let newer = parse_observation(
            &sample(
                unit,
                &agent_rows(&marked_at("99"), ABSENT, ABSENT, ABSENT),
                &all_shared_marked(),
                "",
            ),
            OWN_DROPIN,
        );
        assert_eq!(newer.markers.env.ownership, Ownership::OursButNewer(99));
        assert!(
            newer.markers.env.marker.is_none(),
            "a layout this build cannot read yields no marker to act on"
        );
    }

    /// P1-4's observation half: four artifacts, four independent verdicts. A
    /// marked env file beside an unmarked drop-in has to read as exactly that,
    /// or the fence downstream has nothing to refuse on.
    #[test]
    fn each_per_agent_artifact_reports_its_own_marker() {
        let foreign = format!("present|{MANAGED_BY}|{BINDING_VERSION}|{}|ci", "ff".repeat(32));
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=enabled\nMainPID=0\n",
            &agent_rows(&marked(), "present||||", &foreign, ABSENT),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert_eq!(o.markers.agent_files().count(), 4);
        assert!(o.markers.env.marker.is_some());
        assert!(o.markers.siblings[0].present, "the drop-in is there");
        assert!(
            o.markers.siblings[0].marker.is_none(),
            "…and carries no marker of ours, which must be visible on its own row"
        );
        assert_eq!(
            o.markers.siblings[1].marker.as_ref().map(|m| m.pubkey_full.as_str()),
            Some("ff".repeat(32).as_str()),
            "a sibling belonging to another agent keeps its own identity"
        );
        assert!(!o.markers.siblings[2].present);
    }

    /// A shared file with our name and no provider marker is somebody else's.
    /// There is deliberately no third state: nothing in the file claims what
    /// its own content should be, so "edited underneath us" is not a verdict
    /// this observer can reach — or should try to.
    #[test]
    fn a_shared_file_without_the_provider_marker_is_reported_unmarked() {
        let shared = format!(
            "{}|present||||deadbeef\n\
             {}|present|{MANAGED_BY}|{BINDING_VERSION}|{SHARED_SCOPE}|h\n\
             {}|present|{MANAGED_BY}|{BINDING_VERSION}|{SHARED_SCOPE}|h\n",
            SHARED_PATHS[0], SHARED_PATHS[1], SHARED_PATHS[2]
        );
        let o = parse_observation(
            &sample(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
                 UnitFileState=disabled\nMainPID=0\n",
                &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
                &shared,
                "",
            ),
            OWN_DROPIN,
        );
        assert!(o.markers.shared[0].present);
        assert_eq!(o.markers.shared[0].ownership, Ownership::NotOurs);
        assert_eq!(o.markers.shared[0].sha256, "deadbeef");
        assert_eq!(o.markers.shared[1].ownership, Ownership::Ours);
    }

    #[test]
    fn a_missing_harness_is_observed() {
        let out = sample(
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=\nMainPID=0\n",
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
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
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        )
        .replace("---STANDING---\ninfinity\n", "---STANDING---\n536870912\n");
        assert_eq!(
            parse_observation(&out, OWN_DROPIN).reserved_bytes,
            512 * 1024 * 1024
        );
    }

    /// The script has to read all four per-agent artifacts and hash each shared
    /// file **whole**. A script that read only the env file would leave the
    /// per-artifact fence with nothing to fence on, and one that stripped a
    /// header before hashing would be the deleted tamper check growing back.
    #[test]
    fn the_observer_reads_every_artifact_and_hashes_shared_files_whole() {
        let names = Names::from_pubkey_hex(&format!("{INSTANCE}{}", "0".repeat(52))).unwrap();
        let script = observe_script(&names, "codex-acp");
        for path in agent_paths(&names) {
            assert!(script.contains(&sq(&path)), "{path} is never read");
        }
        assert!(script.contains("sha256sum"), "{script}");
        assert!(
            !script.contains("content-hash"),
            "nothing reads a digest back out of a file any more"
        );
        assert!(
            !script.contains(",+3d"),
            "the GNU-sed marker strip went with it"
        );
    }

    /// Both marker headers must fit inside the window this observer scans. The
    /// worst case is the fetcher script, whose shebang pushes its three-line
    /// provider header down to lines 2-4. If a header ever grows, this fails
    /// here rather than as a deploy refusing a file it wrote itself.
    #[test]
    fn every_marker_header_fits_the_scan_window() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "ci".to_string(),
        }
        .render();
        assert!(agent.lines().count() <= MARKER_SCAN_LINES, "{agent}");
        let shared = crate::naming::shared_marker();
        assert!(
            shared.lines().count() + 1 <= MARKER_SCAN_LINES,
            "a shebang sits above this header: {shared}"
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
//!
//! Ownership is recorded per artifact, not per agent. Four files are written by
//! a replace and deleted by a remove, so one shared verdict would authorize
//! destroying three files nothing ever looked at.

use crate::capacity::parse_reported_bytes;
use crate::config::parse_memory_max;
use crate::naming::{
    agent_ownership, header_line, shared_ownership, AgentMarker, Names, Ownership,
};
use crate::remote::{sq, Remote, MARKER_SCAN_LINES};

/// The three artifacts every instance shares. Order is fixed so the observer's
/// output and the renderer's plan line up by index as well as by path.
pub const SHARED_PATHS: [&str; 3] = [
    "/etc/systemd/system/buzz-acp@.service",
    "/etc/systemd/system/buzz-acp-secret@.service",
    "/usr/local/sbin/buzz-acp-fetch-key",
];

/// The four artifacts belonging to exactly one agent, in one fixed order shared
/// by the observer script, its parser, and `remove`.
///
/// The env file is first, and [`MarkerState`] keeps it in its own field: it is
/// the artifact a deploy *classifies on*, because it is the one whose marker
/// records what the previous deploy intended.
///
/// That does **not** mean its siblings are never read for intent — they were
/// not, and round 4's P1-3 is what that cost. An install torn between the env
/// write and a later per-agent write leaves the env marker carrying the new
/// create-intent beside siblings carrying the old one, all of them still ours
/// and still this agent's, and `classify` called it healthy and restarted the
/// unit against stale drop-ins. `reconcile::classify` now reads every
/// sibling's `create_intent` and lets `RestartSame` stand only when all four
/// agree with the env file; the env file's primacy is that it supplies the
/// intent the others are compared against, not that the others are ignored.
pub fn agent_paths(names: &Names) -> [String; 4] {
    [
        names.env_path(),
        names.dropin_path(),
        names.secret_dropin_path(),
        names.trail_path(),
    ]
}

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

/// One per-agent artifact as it exists on the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFileState {
    pub path: String,
    pub present: bool,
    /// What **this file's own** header says about who wrote it, and at which
    /// binding version. [`Ownership::OursButOlder`] is an authorised upgrade
    /// target; [`Ownership::OursButNewer`] and [`Ownership::NotOurs`] are
    /// refusals, and they are separate states because a newer build of this
    /// provider is not a stranger and must not be described as one.
    pub ownership: Ownership,
    /// The identity half of the same header: which agent, and what intent.
    ///
    /// Independent of `ownership`, not a restatement of it — a file can carry
    /// our marker at our version and still have no `agent-pubkey-full` line,
    /// which is its own refusal with its own message. The implication runs one
    /// way: `Some` is only ever produced for an actionable `ownership`,
    /// because [`AgentMarker::parse`] checks that first.
    pub marker: Option<AgentMarker>,
}

/// One shared artifact as it exists on the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedFileState {
    pub path: String,
    pub present: bool,
    /// What the file's provider-level header says. Ours at this version or an
    /// older one takes the ordinary write-if-different path; a newer one and
    /// an absent marker are both refusals, for different reasons.
    pub ownership: Ownership,
    /// SHA-256 of the file's **whole** contents, header included.
    ///
    /// Compared against the digest of the exact bytes this provider would
    /// render ([`crate::render::SharedArtifact::sha256`]). Both sides are
    /// hashes of real bytes, so there is nothing here for a file to claim about
    /// itself and nothing to strip before hashing.
    pub sha256: String,
}

/// What our markers say — independent of systemd.
#[derive(Debug, Clone, Default)]
pub struct MarkerState {
    /// The env file.
    pub env: AgentFileState,
    /// The agent drop-in, the fetcher drop-in, and the deploy trail, in
    /// [`agent_paths`] order after the env file.
    pub siblings: Vec<AgentFileState>,
    pub shared: Vec<SharedFileState>,
}

impl MarkerState {
    /// Every per-agent artifact, env file first.
    pub fn agent_files(&self) -> impl Iterator<Item = &AgentFileState> {
        std::iter::once(&self.env).chain(self.siblings.iter())
    }
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
    let out = remote.run(&observe_script(names, harness))?;
    if !out.ok() {
        return Err(format!(
            "observing {} failed (exit {}): {}",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }
    let observation = parse_observation(&out.stdout, &names.dropin_path());
    // A short observation is a malformed one, and a malformed observation reads
    // as "nothing of ours is here" — which classifies as `Create` and installs
    // over a live agent. Four rows, or nothing happens.
    let expected = agent_paths(names).len();
    let seen = observation.markers.agent_files().count();
    if seen != expected {
        return Err(format!(
            "the observer reported {seen} of {expected} per-agent artifacts for \
             {}. Refusing to act on a partial observation.",
            names.unit()
        ));
    }
    Ok(observation)
}

/// The `field` helper both row emitters need: read one `# <name>: ` value out
/// of `$h`, the first few lines of whatever file the loop is currently on.
///
/// `pub(crate)` and a `const` rather than an inline fragment because Task 13's
/// pre-stop ownership scan reuses [`agent_file_rows`], and a helper defined in
/// one script and called from another is the kind of coupling that breaks
/// silently.
pub(crate) const FIELD_HELPER: &str =
    "field() { printf '%s\\n' \"$h\" | sed -n \"s/^# $1: //p\" | head -n 1; }\n";

/// The shell that emits one
/// `path|present|managed-by|binding-version|agent-pubkey-full|create-intent`
/// row per per-agent artifact.
///
/// Factored out of [`observe_script`] and `pub(crate)` because `remove`
/// (Task 13) needs exactly these rows and nothing else: a second emitter of
/// the same shape would be a second thing to keep in step with
/// [`parse_agent_file_row`], and `deploy` and `remove` disagreeing about what
/// a header says is precisely the failure the marker exists to prevent.
/// Assumes [`FIELD_HELPER`] is already defined in the surrounding script.
pub(crate) fn agent_file_rows(names: &Names) -> String {
    format!(
        "for p in {agent_files}; do \
           if sudo -n test -e \"$p\"; then \
             h=$(sudo -n head -n {scan} \"$p\"); \
             printf '%s|present|%s|%s|%s|%s\\n' \"$p\" \"$(field managed-by)\" \
               \"$(field binding-version)\" \"$(field agent-pubkey-full)\" \
               \"$(field create-intent)\"; \
           else \
             printf '%s|absent||||\\n' \"$p\"; \
           fi; \
         done\n",
        agent_files = agent_paths(names)
            .iter()
            .map(|p| sq(p))
            .collect::<Vec<_>>()
            .join(" "),
        scan = MARKER_SCAN_LINES,
    )
}

/// The observer script. Sectioned so the parser is a pure function of text.
///
/// Emitting the header *values* as one `|`-separated row keeps each section
/// line-oriented, and a value that itself contains a `|` is truncated at it,
/// which makes the reassembled header fail to match — the fail-closed
/// direction. Nothing here decides ownership; that is `naming::agent_ownership`
/// / `AgentMarker::parse` and `naming::shared_ownership`, in Rust, for both
/// tiers.
fn observe_script(names: &Names, harness: &str) -> String {
    format!(
        "set -uo pipefail\n\
         {field}\
         echo '---UNIT---'\n\
         systemctl show {unit} -p LoadState -p ActiveState -p SubState \
             -p UnitFileState -p MainPID 2>/dev/null || true\n\
         echo '---AGENTFILES---'\n\
         {agent_rows}\
         echo '---SHARED---'\n\
         for p in {shared}; do \
           if sudo -n test -e \"$p\"; then \
             s=$(sudo -n sha256sum \"$p\" | cut -d' ' -f1); \
             h=$(sudo -n head -n {scan} \"$p\"); \
             printf '%s|present|%s|%s|%s|%s\\n' \"$p\" \"$(field managed-by)\" \
               \"$(field binding-version)\" \"$(field scope)\" \"$s\"; \
           else \
             printf '%s|absent||||\\n' \"$p\"; \
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
         echo '---END---'\n",
        field = FIELD_HELPER,
        unit = sq(&names.unit()),
        agent_rows = agent_file_rows(names),
        shared = SHARED_PATHS
            .iter()
            .map(|p| sq(p))
            .collect::<Vec<_>>()
            .join(" "),
        scan = MARKER_SCAN_LINES,
        harness_path = sq(&format!("/usr/local/bin/{harness}")),
    )
}

/// Extract one `---NAME---` section body.
///
/// `pub(crate)` because `reconcile` drives scripts of the same sectioned shape;
/// two copies of a text splitter would be two places to get the terminator
/// wrong.
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

/// Decode one `path|present|managed-by|binding-version|pubkey|intent` row.
///
/// The four header values are reassembled into the lines they came from and
/// handed to [`agent_ownership`] and [`AgentMarker::parse`], so "is this ours"
/// is decided by exactly one pair of functions for the bytes this provider
/// renders and the bytes it reads back. `pub(crate)` because Task 13's
/// pre-stop scan parses the same rows.
pub(crate) fn parse_agent_file_row(line: &str) -> AgentFileState {
    let mut parts = line.split('|');
    let path = parts.next().unwrap_or("").to_string();
    let present = parts.next().unwrap_or("") == "present";
    let header = format!(
        "{}\n{}\n{}\n{}\n",
        header_line("managed-by", parts.next().unwrap_or("").trim()),
        header_line("binding-version", parts.next().unwrap_or("").trim()),
        header_line("agent-pubkey-full", parts.next().unwrap_or("").trim()),
        header_line("create-intent", parts.next().unwrap_or("").trim()),
    );
    AgentFileState {
        path,
        present,
        // An absent file carries no marker of any kind, whatever the rest of
        // the row says — the row for an absent file is all-empty fields, but
        // being explicit here keeps the invariant local rather than implied.
        ownership: if present {
            agent_ownership(&header)
        } else {
            Ownership::NotOurs
        },
        marker: present.then(|| AgentMarker::parse(&header)).flatten(),
    }
}

/// Decode one `path|present|managed-by|binding-version|scope|sha256` row.
///
/// Same shape as [`parse_agent_file_row`] and the same discipline: the header
/// values are reassembled and handed to the one function that also judges the
/// bytes this provider renders, so "is this ours" has a single definition per
/// tier rather than one in Rust and one in shell.
fn parse_shared_file_row(line: &str) -> SharedFileState {
    let mut parts = line.split('|');
    let path = parts.next().unwrap_or("").to_string();
    let present = parts.next().unwrap_or("") == "present";
    let header = format!(
        "{}\n{}\n{}\n",
        header_line("managed-by", parts.next().unwrap_or("").trim()),
        header_line("binding-version", parts.next().unwrap_or("").trim()),
        header_line("scope", parts.next().unwrap_or("").trim()),
    );
    SharedFileState {
        path,
        present,
        ownership: if present {
            shared_ownership(&header)
        } else {
            Ownership::NotOurs
        },
        sha256: parts.next().unwrap_or("").trim().to_string(),
    }
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

    let mut agent_files: Vec<AgentFileState> = section(stdout, "AGENTFILES")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_agent_file_row)
        .collect();
    // `agent_paths` puts the env file first. An empty section yields a default
    // absent env file rather than a panic; `look` refuses on the row count.
    let env = if agent_files.is_empty() {
        AgentFileState::default()
    } else {
        agent_files.remove(0)
    };

    let shared = section(stdout, "SHARED")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_shared_file_row)
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
            env,
            siblings: agent_files,
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
Expected: PASS — 13 tests.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): observe systemd state and marker state separately"
```

---

## Task 12: `reconcile.rs` — the I4 state machine, the fence, and the startup poll

Resolves the classification half of review **P1-5**, round 2's **P1-2** (startup confirmation), **P1-4** (the per-artifact fence), the classification half of **P1-6** (the tamper verdict is gone), **P1-7** (credential rotation), **P1-8** (serialization and the narrowed fence) and **P2-3** (shared repair on `RestartSame`), round 3's **P1-4** (the lease was acquired after the decision it protects), the `classify` half of **P1-1** (a prior-version artifact read as foreign), and **P2-1** (the lease TTL was shorter than the deploy budget) and **P2-3** (the lease record was a trust boundary without controls), and round 4's **P1-1** (the lease was renewed between mutations but not proved inside them), **P1-3** (a torn install classified as `RestartSame`) and **P2** (a previewed-live agent was returned as a success without being re-observed).

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
- Consumes: `crate::capacity`, `crate::config::ProviderConfig`, `crate::naming::{Names, Ownership, BINDING_VERSION, BINDING_VERSION_NUM, MANAGED_BY}`, `crate::observe::{self, property, section, Observation}`, `crate::remote::{lease_lost, lease_paths, sq, under_lease, Held, Remote, AGENT_STARTED, LEASE_DIR, LEASE_FLOCK_WAIT_SECONDS, LOCK_UNAVAILABLE, MARKER_CHANGED, MARKER_SCAN_LINES}`, `crate::render::{self, Plan, RemoteFile}`, `crate::secrets`, `buzz_backend_core::identity::{new_generation, AgentIdentity}`, `buzz_backend_core::wire::AgentPayload`. The test module additionally imports `crate::observe::{AgentFileState, MarkerState, SharedFileState, SystemdState, SHARED_PATHS}` and `crate::naming::AgentMarker` — the parent module never names those, so importing them there would be an unused import under `-D warnings`. `Ownership` needs no test import: the parent names it, so `use super::*` carries it, and that is also how the tests reach `lease_paths`, `under_lease` and `lease_lost`.

**Why the startup budget is 240 s.** The desktop gives a deploy 600 s (`backend.rs:528`) and kills the child at that mark with `provider timed out after 600s` — an error that tells the operator nothing. Before polling begins this provider makes a dozen or so `gcloud` round trips (a pre-lease look, the lease, the authoritative look under it, one renewal before the secret calls, three secret calls, up to seven installs, the trail append, `daemon-reload` + `enable --now`), each of which pays IAP tunnel setup and lands in the 3-5 s range, so 40-90 s of the budget is gone before the first poll. Round 4 removed three of round 3's four standalone renewals, because the lease gate every mutation carries refreshes the record itself. On the other side, a `codex-acp` cold start on an `e2-medium` has to run the fetcher unit (a Secret Manager round trip from the VM), then load Node and the harness, then complete a relay TLS handshake and nostr auth. **240 s**, polled every 5 s, is about 8× an observed warm start and still leaves ≥ 250 s of slack, so a stuck agent produces this provider's actionable error rather than the desktop's opaque one.

**Why the startup poll is scoped to one attempt.** The harness's startup line carries no generation and no start nonce (`crates/buzz-acp/src/config.rs:1119-1146`), and `enable --now` on a `Type=simple` unit returns before the new process logs anything. A poll that counts any `buzz-acp starting:` line in a fixed lookback window is therefore *confirmed by the previous run* whenever an agent is restarted soon after a success — the deploy reports a healthy start it never observed. Two independent bounds close it: `_SYSTEMD_INVOCATION_ID`, which systemd re-mints on every start, and `--since @<epoch>` taken **on the instance** immediately before `enable --now`. The first pins the query to this invocation; the second covers the case the first cannot see, where the unit was already running and `enable --now` was a no-op, so the "current" invocation id is the *old* run's.

**Why the fence and the stop share one shell.** [L2] item 4 requires a destructive write fenced to the exact observation that authorized it. The previous shape read the observation in one `gcloud` round trip and performed the stop in the next, with the installs four to six round trips after that; a competing `enable --now` anywhere in that window starts a unit over a half-rewritten file set. A fence that wide is a TOCTOU with more steps. The re-read and the stop now execute in a single remote shell, and every write after it carries its **own** marker guard inside its own install script — so no later step leans on a check that ran earlier.

**Why the mutating window takes a lease, and why it is taken first.** `flock` cannot be *held* across the window from here: every round trip is a separate SSH session, so the descriptor holding the lock closes when the session ends. What `flock` *can* do is make each read-modify-write of a lease record atomic — the acquire, and the gate every mutation carries — which is exactly what a lease needs and, as the round-4 section below argues, is enough to make the whole class of stale writes unreachable. The lock file is the mutex; a sibling owner file holds `<token> <epoch>` and expires after `DEPLOY_LEASE_SECONDS`, so a provider killed mid-window blocks the next deploy for minutes rather than forever. Both live in a private `install -d -m 0700 -o root -g root /run/buzz-backend-gcp` rather than directly under `/run/lock`: `/run` is a tmpfs systemd recreates on every boot, so a lease can never outlive the reboot that made its holder irrelevant, but `/run/lock` is world-readable and a predictable record path there is one an unprivileged local user can watch or pre-create.

The lease is now acquired **before the observation the deploy acts on**, not after it. The previous ordering ran `observe::look` and `classify` first and then took the lease and acted on that pre-lease verdict — a deploy could observe "absent/stopped", lose the race, and mutate on stale state. What survives of the old reasoning is the cheap part, narrowed by round 4's P2: a *pre-lease* look still runs, and a **refusal** from it still exits early, because refusing an unowned file changes nothing and should cost nobody a lease. A pre-lease `NoOp` no longer exits, because reporting success is a claim rather than a refusal. Everything the deploy acts on — and everything it reports — comes from `DeployLease::observe`, a method on the guard, so there is no way to reach the authoritative observation without holding the lease and the ordering is a property of the type rather than of the order somebody wrote two statements in. The lease is released before the startup poll, which mutates nothing and may run for four minutes.

**Why the lease is proved inside every mutation, and why not one long session.** Round 3 raised `DEPLOY_LEASE_SECONDS` to 900 s and added `DeployLease::renew` at each phase boundary. Round 4 found that neither is a fence. A renewal proves the lease *at the boundary*; the remote step that follows carried no lease check of its own, because `marker_fn` proves provider identity and `binding-version <= current` and `owner_marker` deliberately excludes both the intent and the token. So a holder that renewed and then stalled past the TTL was legitimately overtaken by a second provider — and its delayed `mv` still landed, over the winner's current files, with every marker guard satisfied. Provenance is not ownership of the lease.

The finding's recommended fix was architectural: hold the lease for the whole mutating window inside one long-lived remote session — a single SSH invocation that takes `flock` and then performs the mutations while holding it — instead of N round trips each re-checking a record. **That shape was evaluated and rejected, and the reason is not taste.** A single session cannot contain the mutating window, because two of its steps are not remote: `secrets::instance_service_account` and `secrets::store` are `gcloud` API calls issued from the operator's machine with the operator's own credentials. They cannot move onto the VM, because the instance's service account holds per-secret `secretAccessor` only — deliberately, so that a compromised instance can neither mint nor read another agent's secret — and granting it secret-admin to get the call under the lock would trade this binding's central security property for a concurrency one. So the "single session" is really two sessions with a local gap between them, and a gap is precisely what must not exist. The only way to close it is to have the remote shell *block on stdin* while the Mac does the Secret Manager work and then release it — which needs an interleaved, streaming stdin/stdout handshake in place of `wait_with_output`, a reader thread, a line protocol, and a bet on ssh's flushing behaviour that cannot be verified offline. It would also collapse the per-step error vocabulary: six install refusals, `MARKER_CHANGED`, `AGENT_STARTED` and `LOCK_UNAVAILABLE` currently reach the operator as distinct sentences naming a path and a remedy, and one session has one exit code, so distinguishing them needs a step-tag protocol on stdout *and* a story for which writes landed before the failure. Its genuine advantage — about ten fewer IAP tunnel setups, 30-50 s — is real and is recorded as residual risk 5, where it belongs beside the SSH master connection that would deliver it without any of this.

**What replaces it, and why the same stall cannot defeat it.** Every mutating script now carries the lease proof *in its own shell, under the same `flock`*: `remote::under_lease` emits `sudo -n flock -w 5 -E 75 <lock> sh -c '<gate><work>'`, where the gate reads the owner record, refuses `LOCK_UNAVAILABLE` unless it still names this process's token, and refreshes its timestamp — and only then does the `mv`, the `tee -a`, the `systemctl` or the `rm` run. The argument that this is not merely a narrower TOCTOU:

1. **The owner record can only change while the `flock` is held.** `acquire_lease`, `renew_lease_script`, `release_lease_script` and the gate are the only writers, and all four take it.
2. **The gate and the mutation hold that same `flock` for their whole duration.** They are one `sh -c` argument, so there is no round trip between them to stall inside.
3. Therefore a takeover **cannot interleave** between our check and our write. Either the takeover completes first, and our gate reads a record naming somebody else and refuses before touching anything; or our shell holds the lock, and the would-be taker's `flock -w 5` times out and *it* refuses. A stall before we reach `flock` makes the first case; a stall after we hold it makes the second. There is no third.
4. So a lost lease **prevents** the mutation rather than reporting it afterwards, which is what the finding demanded, and the loser's message says nothing was written — because nothing was.

A useful corollary, and the reason multi-round-trip is *sound* rather than merely safer: because acquire and every write are mutually exclusive under one lock, a loser's writes form a **prefix that strictly precedes the winner's acquire** in lock order. The winner's authoritative observation therefore sees everything the loser managed to write, and reconciles it. That is convergence by re-entry, which is what [L2] asks for.

`DeployLease::renew` survives, with a smaller job: the gate renews as a side effect of acting, so the only standalone renewals left are `DeployLease::observe`'s opening proof and the one before the Secret Manager calls — the single stretch of the window that performs no remote mutation, and the one thing the fence structurally cannot cover (residual risk 2). Three round trips leave the window as a result.

**Why a live no-op is decided under the lease.** `deploy` used to return `Ok(agent_id)` on a *pre-lease* `NoOp`. That reported "running" from an observation nothing serialized: an agent that a concurrent `remove` had just stopped — or that had simply crashed — was reported as a healthy success with an `agent_id` for something no longer there. Round 4's P2. The `NoOp` early return is deleted; the `Refuse` one stays, because a refusal changes nothing and costs the operator only a re-run, whereas a success is a claim. The cost is two round trips on a path that had one, which is noise against a 600 s budget, and the benefit is categorical: under the lease, "live" cannot be stale *with respect to another provider*, because nobody else can stop this unit while we hold the record. What remains stale — the agent crashing on its own, or a root user on the instance stopping it — is bounded by the microseconds between the classification and the return, and is irreducible: no observation is true after it is taken. Taking the lease for a no-op does mean a live-agent deploy can now fail with `another operation … is already in progress` where it previously succeeded; that is the right answer when the other operation is a `remove` tearing the agent down.

**Why `RestartSame` is safe to skip the secret with.** Secret *values* are excluded from the create-intent's readable content, but a **digest** of the secret payload is folded into it (`render::plan`). A rotated `auth_tag` or API key therefore diverges the intent, `classify` returns `FencedReplace`, and the secret is re-stored before the unit starts. Without that digest `RestartSame` would restart an agent against the previous secret version while reporting success — the operator sees a healthy restart and the relay sees the old identity.

**Why `RestartSame` has to look at all four artifacts.** `RestartSame` is a claim that everything this deploy would write is already on the instance and already says the same thing, and it acts on that claim by skipping `secrets::store` and every per-agent install and starting the unit. Round 4's P1-3: it used to be decided from the env marker alone, and this plan said outright that siblings are never interrogated for intent. But an install torn between the env write and a later per-agent write — a dropped SSH is enough — leaves the env marker carrying the **new** create-intent beside surviving siblings carrying the **old** one, all of them plainly ours and plainly this agent's. That state read as healthy, and the retry started the unit against stale drop-ins, a stale `project` among them, which points the fetcher at the wrong Secret Manager project and fails in a way that looks nothing like the deploy that caused it. So `RestartSame` now additionally requires every expected per-agent artifact to be present and to carry the same create-intent as the env marker; anything else is `FencedReplace`, which rewrites all four. The refusal loop above already establishes that every present artifact is ours-or-older and names this pubkey, so the added condition is exactly "none missing, and all agreeing" — and `observe::agent_paths`' doc comment, which asserted the opposite, is rewritten in Task 11.

- [ ] **Step 1: Write the failing classification tests**

Replace the test module of `crates/buzz-backend-gcp/src/reconcile.rs` (the Task 5 skeleton has none; append this):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::AgentMarker;
    use crate::observe::{
        AgentFileState, MarkerState, SharedFileState, SystemdState, SHARED_PATHS,
    };

    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const INTENT: &str = "c0ffee";

    const ENV_PATH: &str = "/etc/buzz/acp-a1b2c3d4e5f6.env";
    /// The env file's three siblings, in the order `observe::agent_paths`
    /// reports them after it: agent drop-in, fetcher drop-in, trail.
    const SIBLING_PATHS: [&str; 3] = [
        "/etc/systemd/system/buzz-acp@a1b2c3d4e5f6.service.d/agent.conf",
        "/etc/systemd/system/buzz-acp-secret@a1b2c3d4e5f6.service.d/agent.conf",
        "/etc/buzz/acp-a1b2c3d4e5f6.trail",
    ];

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
                ownership: Ownership::Ours,
                sha256: format!("hash-{path}"),
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

    /// The healthy fixture is a **coherent** four-artifact set: the siblings
    /// mirror whatever the env file carries.
    ///
    /// Round 4's P1-3 is why. The helper used to leave all three siblings
    /// absent, which is not a steady state at all — it is a torn install — and
    /// `classify` now says so. Tests that exercise the per-artifact fence
    /// still overwrite the one entry they care about and say what is wrong
    /// with it.
    fn obs(
        systemd: SystemdState,
        env_present: bool,
        marker: Option<AgentMarker>,
    ) -> Observation {
        let siblings = SIBLING_PATHS
            .iter()
            .map(|path| AgentFileState {
                path: (*path).to_string(),
                present: marker.is_some(),
                ownership: if marker.is_some() {
                    Ownership::Ours
                } else {
                    Ownership::NotOurs
                },
                marker: marker.clone(),
            })
            .collect();
        Observation {
            systemd,
            markers: MarkerState {
                env: AgentFileState {
                    path: ENV_PATH.to_string(),
                    present: env_present,
                    // The pair is not redundant: `ownership` is the version
                    // half and `marker` the identity half, and a file can
                    // carry ours at this version while its identity lines are
                    // missing. A `Some` marker does imply an actionable
                    // ownership, though, so the helper keeps them consistent.
                    ownership: if marker.is_some() {
                        Ownership::Ours
                    } else {
                        Ownership::NotOurs
                    },
                    marker,
                },
                siblings,
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

    /// Round 1's P1-5 case: a real unit with no env file must never classify as
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
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a present, unmarked env file must never be overwritten")
        };
        assert!(why.contains(ENV_PATH), "the refusal must name the file: {why}");
    }

    /// The 12-hex name is collision-resistant, not collision-free.
    #[test]
    fn a_short_name_collision_is_refused() {
        let foreign = Some(AgentMarker {
            pubkey_full: "ff".repeat(32),
            create_intent: INTENT.to_string(),
        });
        let o = obs(systemd("enabled", "inactive", 0), true, foreign);
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a foreign pubkey must not be adopted")
        };
        assert!(why.contains("collision"), "{why}");
        assert!(why.contains(ENV_PATH), "{why}");
    }

    /// P1-4's exact case. `FencedReplace` rewrites all four per-agent files and
    /// `remove` deletes all four, so authorizing that from the env file's
    /// header alone destroys a hand-written drop-in no fence ever looked at.
    #[test]
    fn a_marked_env_file_does_not_authorize_writing_an_unmarked_sibling() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        o.markers.siblings[0].present = true;
        o.markers.siblings[0].ownership = Ownership::NotOurs;
        o.markers.siblings[0].marker = None;
        let action = classify(&o, &pubkey(), INTENT);
        let Action::Refuse(why) = action else {
            panic!("an unmarked sibling must stop the deploy, got {action:?}")
        };
        assert!(
            why.contains(SIBLING_PATHS[0]),
            "the refusal must name the offending file: {why}"
        );
        assert!(
            !why.contains(ENV_PATH),
            "the env file is fine; naming it sends the operator to the wrong \
             place: {why}"
        );
    }

    /// …and a sibling belonging to a *different* agent is a refusal for a
    /// different reason, so the two messages must not be interchangeable.
    #[test]
    fn a_sibling_belonging_to_another_agent_is_refused_by_name() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        o.markers.siblings[2].present = true;
        o.markers.siblings[2].ownership = Ownership::Ours;
        o.markers.siblings[2].marker = Some(AgentMarker {
            pubkey_full: "ff".repeat(32),
            create_intent: "stale".to_string(),
        });
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a foreign sibling must stop the deploy")
        };
        assert!(why.contains(SIBLING_PATHS[2]), "{why}");
        assert!(why.contains("collision"), "{why}");
    }

    /// All four present and all four ours is the ordinary replace — the fence
    /// must not be so strict that a legitimate reconfiguration cannot proceed.
    #[test]
    fn every_per_agent_file_marked_for_this_agent_is_a_fenced_replace() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        for sibling in &mut o.markers.siblings {
            sibling.present = true;
            sibling.ownership = Ownership::Ours;
            sibling.marker = ours("stale");
        }
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// Round 4's P1-3. The env install lands, a later per-agent install fails
    /// on a dropped SSH, and the retry sees a **new** create-intent on the env
    /// marker beside surviving **old** siblings that are still ours and still
    /// this agent's. Comparing only the env marker returned `RestartSame`,
    /// which skips `secrets::store` and every per-agent install and starts the
    /// unit against stale drop-ins — a stale `project` among them, pointing
    /// the fetcher at the wrong Secret Manager project. A torn install is a
    /// replace.
    #[test]
    fn a_torn_install_is_replaced_not_restarted() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        for sibling in &mut o.markers.siblings {
            sibling.marker = ours("the-intent-before-this-one");
        }
        // Every artifact is present, ours, and this agent's — the refusal loop
        // has nothing to say — and the env marker matches the request exactly.
        // Only the siblings' *intent* disagrees.
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// The other half of a torn install: the write never happened at all, so
    /// the sibling is simply missing. `RestartSame` would start the unit with
    /// a drop-in that does not exist.
    #[test]
    fn a_missing_sibling_is_replaced_not_restarted() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        o.markers.siblings[1].present = false;
        o.markers.siblings[1].ownership = Ownership::NotOurs;
        o.markers.siblings[1].marker = None;
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// A shared file with our name but no provider marker is somebody else's.
    #[test]
    fn an_unmarked_shared_file_is_refused() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[0].ownership = Ownership::NotOurs;
        let action = classify(&o, &pubkey(), INTENT);
        assert!(matches!(action, Action::Refuse(_)), "got {action:?}");
    }

    /// A *marked* shared file whose bytes differ from ours is an older
    /// rendering of ours and is upgraded in place. There is deliberately no
    /// third verdict: nothing in the file claims what its own content should
    /// be, so there is nothing for the content to disagree with (`naming.rs`).
    #[test]
    fn a_marked_shared_file_with_different_bytes_is_not_a_refusal() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[1].sha256 = "an-older-rendering".to_string();
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);
    }

    /// P1-1, the shared half: a template unit this provider wrote at an older
    /// binding version takes the ordinary write-if-different path. It is not a
    /// refusal — refusing it would stop every deploy on the box the moment the
    /// version bumped, on files this provider itself installed.
    #[test]
    fn a_shared_file_from_an_older_binding_version_is_rewritten_not_refused() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[1].ownership = Ownership::OursButOlder(0);
        o.markers.shared[1].sha256 = "the-version-0-rendering".to_string();
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);

        let plan = plan_with_shared([
            "hash-/etc/systemd/system/buzz-acp@.service",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        let writes = shared_writes(&plan, &o);
        assert_eq!(writes.len(), 1, "the older rendering must be rewritten");
        assert_eq!(writes[0].path, SHARED_PATHS[1]);
    }

    /// …and a shared file from a *newer* one is the refusal the version rule
    /// reserves, with that version named. Overwriting it would downgrade a
    /// template every other instance on the box is running against.
    #[test]
    fn a_shared_file_from_a_future_binding_version_is_refused_by_version() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[0].ownership = Ownership::OursButNewer(99);
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a newer provider's template must not be downgraded")
        };
        assert!(why.contains(SHARED_PATHS[0]), "{why}");
        assert!(why.contains("99"), "the refusal must name the version: {why}");
        assert!(
            !why.contains("somebody else's file"),
            "a newer build of this provider is not a stranger: {why}"
        );
    }

    /// P1-1, the per-agent half. `BINDING_VERSION` is documented as
    /// "bump when the unit/env shape changes" — a designed-for event — and the
    /// conjunction it used to sit in made every artifact written before the
    /// bump read as *present and not ours*: `classify` refused, so `deploy`
    /// could not upgrade the agent, and `verify_removable` refused
    /// identically, so `remove` could not tear it down. An older version is an
    /// authorised upgrade target, and it forces a replace even when the
    /// recorded intent still matches, because the intent says the inputs did
    /// not change — not that the artifact layout is current.
    #[test]
    fn a_prior_version_agent_is_upgraded_not_refused() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        o.markers.env.ownership = Ownership::OursButOlder(0);
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);

        // A live one is still a strict no-op: I4 puts at-most-one-live-instance
        // above convergence, and an upgrade is convergence.
        let mut live = obs(systemd("enabled", "active", 4242), true, ours(INTENT));
        live.markers.env.ownership = Ownership::OursButOlder(0);
        assert_eq!(classify(&live, &pubkey(), INTENT), Action::NoOp);
    }

    /// …and a per-agent artifact from a *future* binding version is refused,
    /// naming the version rather than calling the operator's own agent
    /// foreign.
    #[test]
    fn a_future_version_artifact_is_refused_with_its_version_named() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, None);
        o.markers.env.ownership = Ownership::OursButNewer(99);
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a layout this build cannot read must not be overwritten")
        };
        assert!(why.contains(ENV_PATH), "{why}");
        assert!(why.contains("99"), "{why}");
        assert!(why.contains(BINDING_VERSION), "{why}");
    }

    /// A file carrying our provider marker but no identity line is its own
    /// refusal, and it must not read as "somebody else's file": the operator
    /// needs to know the marker is ours and the identity is missing.
    #[test]
    fn our_marker_without_an_identity_line_is_refused_by_name() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, None);
        o.markers.env.ownership = Ownership::Ours;
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("an unidentifiable per-agent file must stop the deploy")
        };
        assert!(why.contains(ENV_PATH), "{why}");
        assert!(why.contains("agent-pubkey-full"), "{why}");
    }

    /// A missing shared file is normal on a first deploy, not a refusal.
    #[test]
    fn absent_shared_files_are_not_a_refusal() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        for shared in &mut o.markers.shared {
            shared.present = false;
            shared.ownership = Ownership::NotOurs;
            shared.sha256 = String::new();
        }
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);
    }
}
```

- [ ] **Step 2: Write the failing shared-write, startup, lease and fence tests**

Append to the same test module:

```rust
    fn shared_artifact(path: &str, sha256: &str) -> crate::render::SharedArtifact {
        crate::render::SharedArtifact {
            file: RemoteFile {
                path: path.to_string(),
                mode: "0644",
                body: String::new(),
                owner_marker: Vec::new(),
            },
            sha256: sha256.to_string(),
        }
    }

    fn plan_with_shared(hashes: [&str; 3]) -> Plan {
        Plan {
            per_agent: Vec::new(),
            shared: SHARED_PATHS
                .iter()
                .zip(hashes)
                .map(|(path, sha256)| shared_artifact(path, sha256))
                .collect(),
            secret_env: std::collections::BTreeMap::new(),
            create_intent: INTENT.to_string(),
            trail: RemoteFile {
                path: SIBLING_PATHS[2].to_string(),
                mode: "0644",
                body: String::new(),
                owner_marker: Vec::new(),
            },
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
        o.markers.shared[2].ownership = Ownership::NotOurs;
        o.markers.shared[2].sha256 = String::new();
        let plan = plan_with_shared([
            "hash-/etc/systemd/system/buzz-acp@.service",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        let writes = shared_writes(&plan, &o);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, SHARED_PATHS[2]);
    }

    /// A shared file present with different bytes is an older rendering of
    /// ours and is upgraded in place.
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

    /// One startup poll's stdout. `journal` is the count of matching harness
    /// lines the *scoped* query returned.
    fn poll(active: &str, main_pid: u32, result: &str, journal: u32) -> String {
        format!(
            "---UNIT---\nActiveState={active}\nMainPID={main_pid}\nResult={result}\n\
             InvocationID=1c1b0c1b0c1b0c1b0c1b0c1b0c1b0c1b\n\
             ---JOURNAL---\n{journal}\n---END---\n"
        )
    }

    #[test]
    fn a_confirmed_start_needs_a_live_pid_and_the_harness_line() {
        assert_eq!(
            parse_startup(&poll("active", 4242, "success", 1)),
            Startup::Confirmed
        );
    }

    /// systemd calling the unit `active` is not the harness having started —
    /// I4's "live" means the process is confirmed running.
    #[test]
    fn an_active_unit_without_the_harness_line_is_still_pending() {
        assert_eq!(
            parse_startup(&poll("active", 4242, "success", 0)),
            Startup::Pending
        );
        assert_eq!(
            parse_startup(&poll("activating", 0, "success", 0)),
            Startup::Pending
        );
    }

    /// A failed unit must end the poll immediately: burning the whole budget
    /// on a unit systemd has already given up on wastes four minutes and
    /// produces a worse error.
    #[test]
    fn a_failed_unit_ends_the_poll_immediately() {
        let Startup::Failed(why) = parse_startup(&poll("failed", 0, "exit-code", 0)) else {
            panic!("a failed unit must not read as pending")
        };
        assert!(why.contains("exit-code"), "{why}");
    }

    /// P1-2, both halves. The scoping has to live in the **query**: a poll that
    /// grepped a fixed lookback window would be satisfied by the previous run's
    /// `buzz-acp starting:` line, and `parse_startup` could never tell the
    /// difference. With the query scoped, a unit that is up with a live PID
    /// from an earlier run returns zero matches and stays `Pending`.
    #[test]
    fn a_prior_runs_startup_line_cannot_confirm_this_attempt() {
        let script = startup_script("buzz-acp@a1b2c3d4e5f6.service", 1_754_384_042);
        assert!(script.contains("_SYSTEMD_INVOCATION_ID="), "{script}");
        assert!(script.contains("@1754384042"), "{script}");
        assert!(
            !script.contains("-30 min"),
            "a fixed lookback window admits the previous run's line: {script}"
        );
        assert_eq!(
            parse_startup(&poll("active", 4242, "success", 0)),
            Startup::Pending
        );
    }

    /// P1-8: the mutating window is serialized per agent, the holder is
    /// identifiable, and an abandoned lease expires rather than wedging the
    /// instance. P2-3 adds the record's own controls: a private directory, a
    /// root-owned regular file, and a future timestamp read as corrupt.
    #[test]
    fn the_deploy_lease_is_per_agent_identifiable_and_bounded() {
        let script = acquire_lease_script("a1b2c3d4e5f6", "tok3n");
        assert!(script.contains("a1b2c3d4e5f6"), "the lease is per agent: {script}");
        assert!(script.contains("flock"), "{script}");
        assert!(script.contains("tok3n"), "the holder is identifiable: {script}");
        assert!(
            script.contains(&LOCK_UNAVAILABLE.to_string()),
            "a loser must exit with the code the caller can explain: {script}"
        );
        assert!(
            script.contains(&DEPLOY_LEASE_SECONDS.to_string()),
            "an abandoned lease must expire: {script}"
        );
        // The record lives in a private directory of our own, not loose under
        // the world-readable /run/lock.
        assert!(script.contains(LEASE_DIR), "{script}");
        assert!(!script.contains("/run/lock"), "{script}");
        assert!(
            script.contains("install -d -m 0700 -o root -g root"),
            "the directory must be created private, and repaired if it is not: \
             {script}"
        );
        // A record that is not a root-owned regular file is not a lease
        // record, and a clock that moved backwards must not grant one either.
        assert!(script.contains("stat -c %u"), "{script}");
        assert!(script.contains("-L"), "a symlink is not a lease record: {script}");
        assert!(
            script.contains("-ge 0"),
            "a future-dated record must read as corrupt, not fresh: {script}"
        );
        // Release must never steal: it clears the record only if we hold it.
        let release = release_lease_script("a1b2c3d4e5f6", "tok3n");
        assert!(release.contains("tok3n"), "{release}");
        assert!(release.contains("rm -f"), "{release}");
    }

    /// P2-1: the TTL must exceed every enforced lifetime, or a slow-but-live
    /// holder ages out and a second deploy starts mutating the same agent
    /// while the first is still writing.
    #[test]
    fn the_lease_outlives_the_desktops_deploy_budget() {
        // The desktop kills the provider at 600 s (`backend.rs:528`), and the
        // startup poll — which runs *after* the lease is released — is 240 s.
        assert!(
            DEPLOY_LEASE_SECONDS > 600,
            "a lease that expires under a live deploy is worse than none"
        );
        assert!(DEPLOY_LEASE_SECONDS > STARTUP_TIMEOUT.as_secs());
    }

    /// P1-4: nothing this deploy acts on is observed before the lease exists.
    /// The authoritative observation hangs off the guard
    /// (`DeployLease::observe`), so it is unreachable without one — the
    /// compiler enforces the ordering, not a convention about statement order
    /// — and its first act is this verify-then-refresh of the owner record, so
    /// a lease silently lost between acquire and observe stops the deploy
    /// instead of feeding it stale state.
    #[test]
    fn the_authoritative_observation_cannot_run_without_a_held_lease() {
        let script = renew_lease_script("a1b2c3d4e5f6", "tok3n");
        assert!(script.contains("tok3n"), "the record must name us: {script}");
        assert!(
            script.contains(&LOCK_UNAVAILABLE.to_string()),
            "losing the lease must stop the deploy, not warn: {script}"
        );
        // The whole critical section is `sq`-wrapped as the argument to
        // `sudo -n flock … sh -c`, so match on fragments that carry no single
        // quotes of their own — or wrap the needle with `nested`.
        let verify = script.find("cut -d").expect("the holder check");
        let refresh = script.rfind("printf").expect("the refreshed record");
        assert!(
            verify < refresh,
            "the renewal must prove the holder before it extends the lease: \
             {script}"
        );
    }

    /// P1-8's other half: the re-read that authorizes the stop runs in the same
    /// shell as the stop. A fence in one round trip and a `disable --now` in
    /// the next is a TOCTOU with more steps.
    #[test]
    fn the_destructive_fence_and_the_stop_share_one_shell() {
        let names = Names::from_pubkey_hex(&pubkey()).unwrap();
        let script = fenced_stop_script(&names, &pubkey(), INTENT);
        assert!(script.contains(&sq(&names.env_path())), "{script}");
        assert!(script.contains(INTENT), "the intent is re-compared: {script}");
        // The version is an ordering here too: `FencedReplace` is exactly what
        // a prior-version artifact classifies as, so an exact match would make
        // the fence refuse every upgrade it exists to authorize.
        assert!(
            script.contains(&format!("-le {BINDING_VERSION_NUM}")),
            "{script}"
        );
        assert!(
            !script.contains(&format!("!= {}", sq(BINDING_VERSION))),
            "an exact binding-version compare re-creates the upgrade lockout: \
             {script}"
        );
        assert!(
            script.contains("is-active"),
            "the running state is re-checked: {script}"
        );
        let reread = script.find("agent-pubkey-full").expect("the marker re-read");
        let stop = script.find("disable --now").expect("the stop");
        assert!(
            reread < stop,
            "the re-read must precede the stop it authorizes: {script}"
        );
    }

    /// A needle as it appears once a critical section has been `sq`-wrapped
    /// for `sh -c`: every single quote becomes `'\''`. Asserting on the
    /// wrapped form is the honest way to check a nested script — the
    /// alternative is asserting on fragments that happen to carry no quotes,
    /// which silently stops covering the interesting ones.
    fn nested(fragment: &str) -> String {
        fragment.replace('\'', r"'\''")
    }

    /// Round 4's P1-1. Every remote mutation carries the lease proof inside
    /// its own shell — not in a round trip that preceded it — so a lease lost
    /// or taken over while this provider was stalled *prevents* the write
    /// rather than being noticed afterwards.
    #[test]
    fn every_mutating_script_proves_the_lease_in_its_own_shell() {
        let names = Names::from_pubkey_hex(&pubkey()).unwrap();
        let (lock, owner) = lease_paths(names.instance());
        let fenced = [
            under_lease(names.instance(), "tok3n", "systemctl daemon-reload\n"),
            renew_lease_script(names.instance(), "tok3n"),
        ];
        for script in &fenced {
            assert!(script.contains(&sq(&lock)), "no lock is taken: {script}");
            assert!(
                script.contains(&nested(&sq(&owner))),
                "the owner record is not read: {script}"
            );
            assert!(script.contains("tok3n"), "the record must name us: {script}");
            assert!(
                script.contains(&LOCK_UNAVAILABLE.to_string()),
                "a lost lease must exit with the code the caller explains: \
                 {script}"
            );
            // One elevation for the whole critical section: the lock lives in
            // a `0700 root:root` directory, so `flock` has to be root before
            // it can open it, and everything it runs is root already.
            assert!(
                script.contains("sudo -n flock -w"),
                "the critical section is not elevated as one: {script}"
            );
        }
    }

    /// …and the proof and the mutation cannot be separated, because they are
    /// one `sh -c` argument. A takeover needs the same `flock` this shell
    /// holds, so no second provider can slip between the check and the write
    /// however long this one stalls.
    #[test]
    fn the_lease_proof_and_the_mutation_cannot_be_separated() {
        let names = Names::from_pubkey_hex(&pubkey()).unwrap();
        let (_, owner) = lease_paths(names.instance());
        let script = under_lease(
            names.instance(),
            "tok3n",
            &fenced_stop_script(&names, &pubkey(), INTENT),
        );
        let gate = script.find("cut -d").expect("the holder check");
        // The gate's own redirect, not just any `printf`: the stop script has
        // a `printf` of its own inside `field()`.
        let refresh = script
            .find(&nested(&format!("> {}", sq(&owner))))
            .expect("the refreshed record");
        let stop = script.find("disable --now").expect("the stop");
        assert!(
            gate < refresh && refresh < stop,
            "prove the holder, refresh, then act — in that order: {script}"
        );
        // One shell: everything after the wrapper's opening quote is a single
        // argument to `sh -c`, so there is no round trip to stall inside.
        let opener = script.find("sh -c '").expect("the critical section");
        assert!(opener < gate, "the gate is outside the wrapper: {script}");
        assert_eq!(
            script.matches("sh -c '").count(),
            1,
            "a second shell is a second chance to lose the lease: {script}"
        );
    }

    /// The two refusals must not be confused. "Somebody else's file" tells the
    /// operator to move a file aside; "the lease moved" tells them to re-run.
    /// Acting on the first when the second is true is how an operator deletes
    /// a healthy artifact.
    #[test]
    fn a_lost_lease_reads_as_a_lease_loss_not_an_ownership_refusal() {
        let message = lease_lost("buzz-acp@a1b2c3d4e5f6.service");
        assert!(message.contains("buzz-acp@a1b2c3d4e5f6.service"), "{message}");
        assert!(message.contains("Nothing was written"), "{message}");
        assert!(message.contains("Re-run"), "{message}");
        assert!(
            !message.contains("Move it aside"),
            "that is the ownership refusal's remedy, and it is the wrong one \
             here: {message}"
        );
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
//! a strict no-op, and for every destructive write to be fenced to the exact
//! observation that authorized it — in the same remote shell, not four round
//! trips later.

use crate::capacity;
use crate::config::ProviderConfig;
use crate::naming::{Names, Ownership, BINDING_VERSION, BINDING_VERSION_NUM, MANAGED_BY};
use crate::observe::{self, property, section, Observation};
use crate::remote::{
    lease_lost, lease_paths, sq, under_lease, Held, Remote, AGENT_STARTED, LEASE_DIR,
    LEASE_FLOCK_WAIT_SECONDS, LOCK_UNAVAILABLE, MARKER_CHANGED, MARKER_SCAN_LINES,
};
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

/// How long a deploy lease on the instance stays valid.
///
/// It covers the mutating window only — the authoritative observation, the
/// installs, the trail append and `enable --now` — not the startup poll that
/// follows. 900 s is chosen to sit **above every enforced lifetime**: the
/// desktop kills the provider at 600 s (`backend.rs:528`), so a
/// desktop-driven deploy can never age out its own lease, which is what 300 s
/// allowed. A direct CLI run has no enforced lifetime at all, and no TTL can
/// cover that — the record is refreshed instead, by
/// [`crate::remote::lease_gate`] inside every mutation's own shell and by
/// [`DeployLease::renew`] across the one stretch that performs no remote
/// mutation. The TTL still bounds the other direction: a provider killed
/// between acquire and release blocks the next deploy for minutes, not
/// forever. It is **not** what keeps a stalled holder from writing after a
/// takeover — the per-mutation gate is; expiry only decides when an abandoned
/// record may be stolen.
const DEPLOY_LEASE_SECONDS: u64 = 900;

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
    // instance, so one unowned file poisons every deploy on the box. A marked
    // shared file whose bytes differ is an older rendering of ours, not a
    // finding — nothing in the file claims what its own content should be, and
    // that is true whether it was rendered by this build or by an older one.
    for shared in &obs.markers.shared {
        if !shared.present {
            continue;
        }
        match shared.ownership {
            // Ours, at this version or an earlier one. `shared_writes` decides
            // whether the bytes need rewriting; ownership has no further say.
            Ownership::Ours | Ownership::OursButOlder(_) => {}
            Ownership::OursButNewer(found) => {
                return Action::Refuse(format!(
                    "{} was written by a newer {MANAGED_BY} (binding version \
                     {found}; this build writes {BINDING_VERSION}). Refusing to \
                     downgrade a template every instance on this box runs \
                     against. Upgrade this provider.",
                    shared.path
                ))
            }
            Ownership::NotOurs => {
                return Action::Refuse(format!(
                    "{} exists but carries no {MANAGED_BY} provider marker. It \
                     is somebody else's file that happens to share our name; \
                     refusing to overwrite it. Move it aside to let this \
                     provider install its own.",
                    shared.path
                ))
            }
        }
    }

    // Then **every** per-agent artifact against its own header, not the env
    // file's. `FencedReplace` rewrites all four and `remove` deletes all four,
    // so authorizing that from one sibling is "delete enumerated paths if one
    // of them is marked" — the opposite of the auto-repair fence
    // (`docs/remote-agents.md:1460-1476`). A file that fails is reported and
    // left exactly where it is.
    //
    // Ownership is version-aware, and the asymmetry is the whole point of
    // round 3's P1-1. An *older* binding version is this provider's own work
    // at a layout this build supersedes — an authorised upgrade target, not a
    // stranger — because `BINDING_VERSION` is documented as
    // "bump when the unit/env shape changes", so treating it as foreign locked
    // the operator out of `deploy` *and* `remove` for every agent already
    // installed. A *newer* one is the refusal that reserves: a build that
    // cannot reason about a layout must not overwrite or delete it.
    for file in obs.markers.agent_files() {
        if !file.present {
            continue;
        }
        match file.ownership {
            Ownership::Ours | Ownership::OursButOlder(_) => {}
            Ownership::OursButNewer(found) => {
                return Action::Refuse(format!(
                    "{} was written by a newer {MANAGED_BY} (binding version \
                     {found}; this build writes {BINDING_VERSION}). Refusing to \
                     overwrite or delete an artifact whose layout this build \
                     does not understand; it is untouched. Upgrade this \
                     provider, or move the file aside.",
                    file.path
                ))
            }
            Ownership::NotOurs => {
                return Action::Refuse(format!(
                    "{} exists but carries no {MANAGED_BY} marker. Refusing to \
                     overwrite or delete a file this provider did not write; \
                     it is untouched. Move it aside to let this deploy \
                     proceed.",
                    file.path
                ))
            }
        }
        // Ours by provenance, but the identity half has to be there too: a
        // header carrying our marker and no `agent-pubkey-full` names no
        // agent, and "which agent is this?" is the question every destructive
        // step downstream asks.
        let Some(marker) = file.marker.as_ref() else {
            return Action::Refuse(format!(
                "{} carries the {MANAGED_BY} marker but no agent-pubkey-full \
                 line, so which agent it belongs to cannot be established. \
                 Refusing to overwrite or delete it; it is untouched.",
                file.path
            ));
        };
        if marker.pubkey_full != pubkey_full {
            return Action::Refuse(format!(
                "short-name collision: {} belongs to pubkey {}, not \
                 {pubkey_full}. The 12-hex instance name is \
                 collision-resistant, not collision-free; refusing rather than \
                 destroying another agent's deployment.",
                file.path, marker.pubkey_full
            ));
        }
    }

    // Per-agent state. Systemd knowledge and marker ownership are separate
    // facts: a real unit with no env file must not read as "absent".
    let Some(marker) = obs.markers.env.marker.as_ref() else {
        // A *present* env file that is not ours was refused above, so reaching
        // here means there is none — nothing of this agent's is recorded.
        if obs.systemd.instance_known() {
            return Action::Refuse(format!(
                "a unit for this agent exists on the instance (LoadState={}, \
                 SubState={}), but no {MANAGED_BY} marker records it. Refusing \
                 to adopt, restart, or replace a unit this provider did not \
                 create.",
                obs.systemd.load_state, obs.systemd.sub_state
            ));
        }
        return Action::Create;
    };

    // Live is a strict no-op regardless of intent: reconfiguring a running
    // agent would mean killing it, and I4 puts at-most-one-live-instance above
    // convergence. The operator stops it, then redeploys.
    if obs.systemd.running() {
        return Action::NoOp;
    }

    // An artifact still at an older binding version makes this a replace even
    // when the recorded intent matches: the intent says the *inputs* did not
    // change, not that the artifact layout is current, and rewriting the four
    // files is what rolls their markers forward. Checked after `running()`,
    // because an upgrade is convergence and I4 puts at-most-one-live-instance
    // above convergence.
    if obs
        .markers
        .agent_files()
        .any(|file| file.present && matches!(file.ownership, Ownership::OursButOlder(_)))
    {
        return Action::FencedReplace;
    }

    // `RestartSame` claims that everything this deploy would write is already
    // on the instance and already says the same thing. That is a claim about
    // **all four** artifacts, so it has to be checked against all four —
    // round 4's P1-3. An install torn between the env file and a later
    // per-agent write (a dropped SSH, say) leaves the env marker carrying the
    // *new* create-intent beside surviving siblings that still carry the
    // *old* one and are still perfectly ours and this agent's. Comparing only
    // the env marker called that state healthy: `RestartSame` skips
    // `secrets::store` and every per-agent install, then starts the unit
    // against stale drop-ins — including a stale `project`, which points the
    // fetcher at the wrong Secret Manager project and produces a start
    // failure that looks nothing like the deploy that caused it.
    //
    // The refusal loop above has already established, for every *present*
    // artifact, that it is ours (or ours-but-older) and that its marker names
    // this pubkey. So what remains to require is exactly: none is missing, and
    // they all agree with the env file about which deploy wrote them. The env
    // file is compared against itself here, harmlessly, because `agent_files`
    // yields it first and special-casing it would be a second rule.
    let coherent = obs.markers.agent_files().all(|file| {
        file.present
            && file
                .marker
                .as_ref()
                .is_some_and(|found| found.create_intent == marker.create_intent)
    });

    if marker.create_intent == intent && coherent {
        Action::RestartSame
    } else {
        Action::FencedReplace
    }
}

/// Which shared artifacts this deploy must write.
///
/// A shared file whose installed bytes already hash to what this provider
/// would render is skipped, which is what makes the strict no-op on a live
/// instance actually strict rather than "no-op except for three files
/// rewritten identically". Both sides of the comparison are hashes of real
/// bytes: one computed here from the rendered body, one computed on the
/// instance from the file. Refusals for unmarked shared files are `classify`'s
/// job and have already run.
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
                Some(state) => !state.present || state.sha256 != artifact.sha256,
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
    /// Active, with a live main PID, and the harness logged its own start
    /// **during this attempt**.
    Confirmed,
    /// systemd gave up. Polling further would only waste the budget.
    Failed(String),
    Pending,
}

/// The remote script one startup poll runs.
///
/// The journal query carries two independent bounds, because the harness's
/// startup line carries no generation and no start nonce
/// (`crates/buzz-acp/src/config.rs:1119-1146`) and `enable --now` on a
/// `Type=simple` unit returns before the new process logs anything:
///
/// * `_SYSTEMD_INVOCATION_ID` pins the query to the unit's **current**
///   invocation. systemd mints a fresh one on every start, so a line the
///   previous run wrote is not in this set at all.
/// * `--since @<epoch>` pins it to a timestamp read **on the instance**
///   immediately before `enable --now`. This is the bound that covers what the
///   invocation id cannot see: a unit already running from an earlier start,
///   where `enable --now` is a no-op and the "current" invocation is the old
///   run's. Its startup line predates the timestamp, the count is zero, and
///   the poll stays `Pending` until this attempt speaks for itself.
///
/// The epoch comes from the instance rather than from the operator's Mac: the
/// two clocks are unrelated, and a Mac a few seconds fast would silently
/// exclude the very line the poll is waiting for.
fn startup_script(unit: &str, since_epoch: u64) -> String {
    format!(
        "set -uo pipefail\n\
         echo '---UNIT---'\n\
         systemctl show {unit} -p ActiveState -p MainPID -p Result -p InvocationID \
           2>/dev/null || true\n\
         echo '---JOURNAL---'\n\
         inv=$(systemctl show {unit} -p InvocationID --value 2>/dev/null || true)\n\
         if [ -n \"$inv\" ]; then\n\
           sudo -n journalctl -u {unit} \"_SYSTEMD_INVOCATION_ID=$inv\" \
             --since '@{since}' --no-pager 2>/dev/null | grep -c {needle} || true\n\
         else\n\
           echo 0\n\
         fi\n\
         echo '---END---'\n",
        unit = sq(unit),
        since = since_epoch,
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

/// The shell that reads a lease record and decides whether it is *held by
/// somebody else, right now*.
///
/// Only [`acquire_lease_script`] needs it — [`crate::remote::lease_gate`], which
/// renewal and every fenced mutation share, asks the narrower question "is
/// this record still ours", which needs no freshness arithmetic at all. It is
/// a function rather than an inline block so the three controls below sit next
/// to the reasoning for them.
///
/// Three controls, each closing a way a record could lie:
///
/// * **`install -d -m 0700 -o root -g root`** creates the directory private and
///   *repairs* it if something loosened it, on every acquire.
/// * **A record that is not a root-owned regular file is not a record.** `-f`
///   follows symlinks, so `-L` is tested separately; a symlink is removed
///   (which removes the link, not its target) and treated as absent. `stat -c`
///   is GNU coreutils, which every Debian and Ubuntu GCE image ships — and
///   unlike the deleted `sed` range it is a plain field read with no
///   address-range semantics to get wrong.
/// * **A future-dated timestamp is corrupt, not fresh.** A clock step or a
///   hand-edited record must not grant an unbounded lease, so the age has to
///   be non-negative *and* under the TTL to count as held.
///
/// The stored epoch is filtered to digits before the arithmetic: a corrupted
/// record must not make `$(( ))` fail in a direction that hands out the lease.
fn lease_preamble(owner: &str, ttl_check: &str) -> String {
    format!(
        "if [ -e {owner} ]; then\n\
           if [ ! -f {owner} ] || [ -L {owner} ] || \
              [ \"$(stat -c %u {owner} 2>/dev/null || echo -1)\" != 0 ]; then\n\
             rm -f {owner}\n\
           else\n\
             held=$(cut -d' ' -f1 {owner})\n\
             at=$(cut -d' ' -f2 {owner} | tr -cd '0-9')\n\
             age=$(( now - ${{at:-0}} ))\n\
             {ttl_check}\
           fi\n\
         fi\n"
    )
}

/// Take the per-agent deploy lease, or exit [`LOCK_UNAVAILABLE`].
///
/// `flock` cannot be *held* across the whole mutating window from here: every
/// round trip is a separate SSH session, so the descriptor holding the lock
/// closes when the session ends. What `flock` can do is make each
/// read-modify-write of the lease record atomic — this one, and the one
/// [`crate::remote::lease_gate`] performs inside every mutation. The lock file
/// is the mutex; the owner file is the lease, and it carries a timestamp so an
/// abandoned one expires instead of wedging the instance.
///
/// `sudo -n flock … sh -c` rather than `sudo -n sh -c 'exec 9>…'`: the whole
/// critical section has to run as root because [`LEASE_DIR`] is `0700
/// root:root`, and `flock`'s command form elevates once for the section
/// instead of once per command inside it. Round 4 made that the single shape
/// for every critical section in this binding, so acquire, renew, release and
/// each fenced mutation are the same thing with a different body.
fn acquire_lease_script(instance: &str, token: &str) -> String {
    let (lock, owner) = lease_paths(instance);
    let inner = format!(
        "set -u\n\
         now=$(date +%s)\n\
         {preamble}\
         printf '%s %s\\n' {token} \"$now\" > {owner}\n",
        owner = sq(&owner),
        token = sq(token),
        preamble = lease_preamble(
            &sq(&owner),
            &format!(
                "if [ \"$held\" != {token} ] && [ \"$age\" -ge 0 ] && \
                 [ \"$age\" -lt {ttl} ]; then\n\
                   exit {busy}\n\
                 fi\n",
                token = sq(token),
                ttl = DEPLOY_LEASE_SECONDS,
                busy = LOCK_UNAVAILABLE,
            ),
        ),
    );
    format!(
        "set -uo pipefail\n\
         sudo -n install -d -m 0700 -o root -g root {dir}\n\
         sudo -n flock -w {wait} -E {busy} {lock} sh -c {inner}\n",
        dir = sq(LEASE_DIR),
        wait = LEASE_FLOCK_WAIT_SECONDS,
        busy = LOCK_UNAVAILABLE,
        lock = sq(&lock),
        inner = sq(&inner),
    )
}

/// Refresh the lease's timestamp — but only after proving we still hold it.
///
/// Nothing but [`crate::remote::under_lease`] with an empty body, and
/// deliberately so: the gate every mutation carries *is* a verify-then-refresh,
/// and a second spelling of "is this record still ours" is a second thing to
/// get wrong.
/// What is left for a standalone call is the stretch of the window that
/// performs no remote mutation at all — the Secret Manager calls — plus
/// [`DeployLease::observe`]'s opening proof.
///
/// It **verifies before it refreshes**: a record that no longer names this
/// token means the lease was stolen or expired and somebody else is mutating
/// this agent, and the only safe answer is [`LOCK_UNAVAILABLE`] — extending a
/// lease we do not hold would be worse than having none.
fn renew_lease_script(instance: &str, token: &str) -> String {
    format!(
        "set -uo pipefail\n{}",
        under_lease(instance, token, "")
    )
}

/// Release the lease — but only if we still hold it. A release that stole
/// somebody else's would be worse than having no lease at all.
///
/// No `-E`: the only caller is `Drop`, which discards the result, so a
/// contended lock needs no distinguishable exit code. The record expires on
/// its own after [`DEPLOY_LEASE_SECONDS`] either way.
fn release_lease_script(instance: &str, token: &str) -> String {
    let (lock, owner) = lease_paths(instance);
    let inner = format!(
        "set -u\n\
         if [ \"$(cut -d' ' -f1 {owner} 2>/dev/null || true)\" = {token} ]; then\n\
           rm -f {owner}\n\
         fi\n",
        owner = sq(&owner),
        token = sq(token),
    );
    format!(
        "set -uo pipefail\n\
         sudo -n flock -w {wait} {lock} sh -c {inner}\n",
        wait = LEASE_FLOCK_WAIT_SECONDS,
        lock = sq(&lock),
        inner = sq(&inner),
    )
}

/// The lease, released when it leaves scope.
///
/// The guard exists so that every `?` in the mutating window releases on the
/// way out — including the ones added after it was written. `pub(crate)`
/// because `operator::remove` takes the same lease around its own destructive
/// window. It carries the 12-hex agent rather than the GCE instance name: the
/// lease is per agent, and [`Held::agent`] hands exactly that to `remote`.
pub(crate) struct DeployLease<'a> {
    remote: &'a Remote,
    instance: String,
}

impl DeployLease<'_> {
    /// Prove we still hold the lease and push its expiry out.
    ///
    /// Round 4 narrowed this from "called at each phase boundary" to "called
    /// where nothing else proves the lease", which is one place in `deploy`
    /// and one in `remove`: the stretch spent talking to Secret Manager from
    /// this machine. Every *remote* mutation now carries
    /// [`crate::remote::lease_gate`] inside its own shell, which is the same
    /// verify-then-refresh — so it renews as a side effect of acting, and a
    /// renewal that merely precedes an unfenced write is exactly the shape
    /// round 4's P1-1 rejected.
    pub(crate) fn renew(&self) -> Result<(), String> {
        let out = self
            .remote
            .run(&renew_lease_script(&self.instance, self.remote.token()))?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(format!(
                "the deploy lease for buzz-acp@{}.service was lost while this \
                 operation was running — another provider holds it now. \
                 Stopping here rather than continuing to write under a lease \
                 we do not hold; re-run once the other operation finishes.",
                self.instance
            ));
        }
        if !out.ok() {
            return Err(format!(
                "could not renew the deploy lease for buzz-acp@{}.service \
                 (exit {}): {}",
                self.instance,
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    /// The **authoritative** observation: the one this deploy acts on.
    ///
    /// It hangs off the guard rather than being a free call, and that is the
    /// whole fix for P1-4. `deploy` used to `observe::look` and `classify`
    /// *before* taking the lease and then act on that pre-lease verdict, so a
    /// deploy could see "absent/stopped", lose the race, and mutate on state
    /// that had already moved. Written this way the ordering is a property of
    /// the type: there is no way to reach this observation without a
    /// `DeployLease`, and no way to hold one without having written the owner
    /// record first. The `renew` is not decoration either — it is what turns
    /// "we took a lease a moment ago" into "we hold it now".
    fn observe(&self, names: &Names, harness: &str) -> Result<Observation, String> {
        self.renew()?;
        observe::look(self.remote, names, harness)
    }
}

/// The one implementor of [`Held`].
///
/// `Remote::{install, append, run_fenced}` take `&dyn Held`, so a mutating
/// call cannot be written without a lease in hand — the same discipline
/// `observe` uses for the authoritative observation, applied to the writes.
/// The value handed over is the 12-hex agent, which is all `remote` needs to
/// find the lock and the owner record; the token comes from the `Remote`
/// itself, because the record holds `remote.token()` and there is exactly one
/// per provider process.
impl Held for DeployLease<'_> {
    fn agent(&self) -> &str {
        &self.instance
    }
}

impl Drop for DeployLease<'_> {
    /// Best effort. A release that does not land is not a leak: the record
    /// expires after `DEPLOY_LEASE_SECONDS`, which is the reason it carries a
    /// timestamp. There is nothing useful to report from a destructor — the
    /// operation that mattered has already returned its own result.
    fn drop(&mut self) {
        let _ = self
            .remote
            .run(&release_lease_script(&self.instance, self.remote.token()));
    }
}

/// Serialize the mutating window, or fail cleanly.
///
/// Losing is not an error to work around — it is the correct outcome: the loser
/// mutates nothing and says so, which is what makes "deploys are unserialised"
/// acceptable in the first place. `pub(crate)` so `operator::remove` can take
/// the same lease: it destroys a secret and four files, and taking none made
/// it freely interleavable with a deploy.
pub(crate) fn acquire_lease<'a>(
    remote: &'a Remote,
    names: &Names,
) -> Result<DeployLease<'a>, String> {
    let out = remote.run(&acquire_lease_script(names.instance(), remote.token()))?;
    if out.code == LOCK_UNAVAILABLE {
        return Err(format!(
            "another operation on {} is already in progress on this instance. \
             Nothing was modified; wait for it to finish and start again. A \
             lease left behind by a provider that died is reclaimed after \
             {DEPLOY_LEASE_SECONDS}s.",
            names.unit()
        ));
    }
    if !out.ok() {
        return Err(format!(
            "could not take the deploy lease for {} (exit {}): {}",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }
    Ok(DeployLease {
        remote,
        instance: names.instance().to_string(),
    })
}

/// Re-read the authorizing observation **and** perform the stop it authorizes,
/// in one remote shell.
///
/// [L2] item 4 requires a destructive write fenced to the exact observation
/// that authorized it. Reading in one round trip and stopping in the next
/// leaves a window a competing `enable --now` can start a unit in; here the
/// window is the microseconds between two `systemctl` calls on the instance.
/// Everything written afterwards carries its own marker guard inside its own
/// install script, so nothing downstream leans on this check.
///
/// `intent` is the intent the **observation** carried, not the one this deploy
/// is about to write: a divergent intent is precisely what makes a replacement
/// a replacement, so comparing against the new one would refuse every
/// legitimate `FencedReplace`. The binding version is compared as an ordering
/// for the same reason a step further on — an upgrade classifies as
/// `FencedReplace`, and an exact compare here would refuse the upgrade the
/// classification just authorized.
///
/// [`MARKER_CHANGED`] means the marker moved, [`AGENT_STARTED`] means the agent
/// started. Both are clean refusals that changed nothing, and each earns its
/// own message.
///
/// The **root** half only: no `set` line and no `sudo -n`, because
/// [`Remote::run_fenced`] runs it inside [`crate::remote::under_lease`]'s
/// `sudo -n flock … sh -c`, already elevated and already holding the lease. So
/// the shell that stops the unit proves three things at once — the marker is
/// the one that authorized this, the agent is not running, and the lease is
/// still ours — and a competing provider cannot slip between any two of them,
/// because taking the lease over needs the `flock` this shell is holding.
fn fenced_stop_script(names: &Names, pubkey_full: &str, intent: &str) -> String {
    format!(
        "h=$(sed -n '1,{scan}p' {env} 2>/dev/null || true)\n\
         field() {{ printf '%s\\n' \"$h\" | sed -n \"s/^# $1: //p\" | head -n 1; }}\n\
         if [ \"$(field managed-by)\" != {managed_by} ] \
            || [ \"$(field agent-pubkey-full)\" != {pubkey} ] \
            || [ \"$(field create-intent)\" != {intent} ]; then\n\
           exit {changed}\n\
         fi\n\
         v=$(field binding-version)\n\
         case \"$v\" in ''|*[!0-9]*) exit {changed} ;; esac\n\
         [ \"$v\" -le {version} ] || exit {changed}\n\
         if [ \"$(systemctl is-active {unit} 2>/dev/null || true)\" = active ]; then\n\
           exit {started}\n\
         fi\n\
         systemctl disable --now {unit} 2>/dev/null || true\n\
         systemctl stop {secret_unit} 2>/dev/null || true\n",
        scan = MARKER_SCAN_LINES,
        env = sq(&names.env_path()),
        managed_by = sq(MANAGED_BY),
        version = BINDING_VERSION_NUM,
        pubkey = sq(pubkey_full),
        intent = sq(intent),
        unit = sq(&names.unit()),
        secret_unit = sq(&names.secret_unit()),
        changed = MARKER_CHANGED,
        started = AGENT_STARTED,
    )
}

/// Run the fenced stop and translate its exit code into the operator's terms.
fn fenced_stop(
    remote: &Remote,
    lease: &DeployLease<'_>,
    names: &Names,
    pubkey_full: &str,
    intent: &str,
) -> Result<(), String> {
    let out = remote.run_fenced(lease, &fenced_stop_script(names, pubkey_full, intent))?;
    match out.code {
        LOCK_UNAVAILABLE => Err(lease_lost(&names.unit())),
        MARKER_CHANGED => Err(format!(
            "{} changed while this deploy was preparing: its management marker \
             no longer matches the one that authorized the replacement. \
             Nothing was modified; run the deploy again.",
            names.env_path()
        )),
        AGENT_STARTED => Err(format!(
            "{} started while this deploy was preparing. Refusing to stop a \
             running agent (I4); nothing was modified.",
            names.unit()
        )),
        _ if out.ok() => Ok(()),
        code => Err(format!(
            "stopping the stale {} failed (exit {code}): {}",
            names.unit(),
            out.stderr.trim()
        )),
    }
}

/// Poll until the harness confirms it started, or the budget runs out.
///
/// `since_epoch` is the instance's own clock, read immediately before
/// `enable --now`, and it is what keeps a previous run's startup line from
/// confirming this attempt. Takes `cfg` only so both failure messages can print
/// the exact `gcloud` command the operator needs; a message that says "check
/// the journal" without saying how is a message nobody acts on.
fn confirm_started(
    remote: &Remote,
    names: &Names,
    cfg: &ProviderConfig,
    since_epoch: u64,
) -> Result<String, String> {
    let script = startup_script(&names.unit(), since_epoch);
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

/// Refuse a deploy whose harness binary is not on the instance.
///
/// `launch.command` was resolved against the desktop's PATH, which means
/// nothing here. Refusing beats deploying a unit that fails at exec. Factored
/// out because both observations ask it — the cheap pre-lease look, so the
/// refusal costs no lease, and the authoritative one, because the binary can
/// be removed between them.
fn require_harness(obs: &Observation, harness: &str, instance: &str) -> Result<(), String> {
    if obs.harness_installed {
        return Ok(());
    }
    Err(format!(
        "deploy refused: {harness} is not installed in /usr/local/bin on \
         {instance}. launch.command is resolved against the desktop's PATH, \
         which does not exist on the instance; install the harness there first."
    ))
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
    // Taken from the original payload, and identical either way: the renderer
    // rewrites `launch.command` to `/usr/local/bin/<basename>`, whose basename
    // is this same string.
    let harness = render::harness_basename(agent);

    // ---- Transport phase: the lease-free look. ----------------------------
    // Refusing an unowned file should cost nobody a lease, so a first, cheap
    // observation answers that. Nothing this deploy *acts* on comes from it: it
    // is a fast exit, not a decision.
    let remote = Remote::new(&cfg.project, &cfg.zone, &cfg.instance)?;
    let preview = observe::look(&remote, &names, &harness)?;
    require_harness(&preview, &harness, &cfg.instance)?;
    match classify(&preview, identity.pubkey_hex(), &plan.create_intent) {
        Action::Refuse(why) => return Err(why),
        // A pre-lease `NoOp` deliberately does **not** return here — round 4's
        // P2. Returning on it reported "running, here is your agent_id" from an
        // observation taken outside the lease, so an agent that a concurrent
        // `remove` had just stopped, or that had crashed, was reported as a
        // healthy success. A refusal is conservative and changes nothing, which
        // is why it keeps its fast exit; a success is a claim, and this
        // provider makes claims from the authoritative observation only.
        Action::NoOp | Action::Create | Action::RestartSame | Action::FencedReplace => {}
    }

    // ---- Mutating window, serialized per agent. ---------------------------
    // The lease comes **before** the observation this deploy acts on. The
    // previous ordering observed and classified first and then took the lease
    // and acted on that pre-lease verdict, so a deploy could see
    // "absent/stopped", lose the race, and mutate on state that had already
    // moved. `lease.observe` is the only way to reach the authoritative
    // observation, so the ordering is enforced by the type rather than by the
    // order two statements happen to be written in. The block is entered even
    // for a no-op, because that is the only way the no-op is answered from
    // state no other provider can be changing. The lease is released at the end
    // of this block rather than after `confirm_started`, because the poll
    // mutates nothing and may run for four minutes.
    let started_at = {
        let lease = acquire_lease(&remote, &names)?;
        let obs = lease.observe(&names, &harness)?;
        require_harness(&obs, &harness, &cfg.instance)?;

        // Matched by reference so `action` survives for the two comparisons
        // below. Taking it by value here would move it.
        let action = classify(&obs, identity.pubkey_hex(), &plan.create_intent);
        match &action {
            Action::Refuse(why) => return Err(why.clone()),
            // The only place a no-op is answered. Under the lease, "live"
            // cannot be stale with respect to another provider: nobody else
            // can stop this unit while we hold the record, because `remove`
            // and `deploy` both take it and every stop is fenced on it. What
            // remains stale is the agent crashing on its own, or a root user
            // on the instance stopping it — bounded by the microseconds
            // between this classification and the return, and irreducible:
            // no observation is true after it is taken.
            Action::NoOp => return Ok(names.unit()),
            Action::Create | Action::RestartSame | Action::FencedReplace => {}
        }

        // Overcommit is reported, never vetoed — but stderr is dropped by the
        // desktop on the success path, so the durable copy below is the one an
        // operator can actually find (§Capacity). Computed from the
        // authoritative observation, which is also the freshest one.
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
            // The fence re-reads the marker that *authorized* this
            // replacement — the one the observation above carries — not the
            // one this deploy is about to write. A divergent intent is what
            // makes a replacement a replacement, so comparing against
            // `plan.create_intent` would refuse every legitimate one. An
            // unreadable marker here yields `""`, which the fence treats as a
            // mismatch and refuses cleanly; `FencedReplace` cannot be reached
            // without one, so the fallback is unreachable rather than lossy.
            let authorizing_intent = obs
                .markers
                .env
                .marker
                .as_ref()
                .map_or("", |marker| marker.create_intent.as_str());
            fenced_stop(
                &remote,
                &lease,
                &names,
                identity.pubkey_hex(),
                authorizing_intent,
            )?;
        }

        // Shared artifacts are repaired on every acting path, `RestartSame`
        // included. Zero mutation is I4's requirement for a *live* instance,
        // not for a stopped one — and the agent unit `Requires=` the fetcher
        // unit, so a shared template deleted out of band is a start failure
        // that re-entry would otherwise never converge on. Written before the
        // per-agent files because the agent unit depends on them. No `renew`
        // ahead of the loop: each install proves and refreshes the lease inside
        // its own shell, which is strictly stronger than a renewal that
        // preceded it by a round trip.
        for file in shared_writes(&plan, &obs) {
            remote.install(file, &lease)?;
        }

        if action != Action::RestartSame {
            // The one standalone renewal left in the window. Everything else
            // here proves the lease from inside its own shell, but
            // `instance_service_account` and `store` are `gcloud` calls from
            // *this* machine against Secret Manager — a service the instance's
            // lock knows nothing about — so no fenced shell covers them. They
            // stay here because the instance's service account holds per-secret
            // `secretAccessor` only, deliberately: moving them onto the VM to
            // get them under the lock would hand a compromised instance the
            // ability to mint and read every agent's secret. Renewing first at
            // least means a deploy that has already lost the lease stops before
            // it adds a version, and every step after this one is fenced, so a
            // deploy that loses it *during* the call cannot start an agent
            // against what it added.
            lease.renew()?;
            let service_account = secrets::instance_service_account(
                &remote,
                &cfg.project,
                &cfg.zone,
                &cfg.instance,
            )?;
            secrets::store(
                &remote,
                &cfg.project,
                &names.secret_name(),
                identity.pubkey_hex(),
                &plan.secret_body(),
                &service_account,
            )?;
            for file in &plan.per_agent {
                remote.install(file, &lease)?;
            }
        }
        // `RestartSame` skipping the secret is sound only because the intent
        // covers a digest of the secret payload (`render::plan`): a rotated
        // credential diverges the intent, so this branch is unreachable for one
        // and no agent is ever restarted against a stale secret version.

        // The durable record, written before the start attempt so a deploy that
        // then fails to start still leaves its capacity warning behind. Fenced
        // like every other write, so it needs no renewal ahead of it.
        remote.append(
            &plan.trail,
            &capacity::trail_record(
                &capacity::now_rfc3339(),
                &generation,
                &plan.create_intent,
                &warnings,
            ),
            &lease,
        )?;

        // The instance's own clock, printed after the reload and before the
        // start, is what bounds the startup query. It cannot be read on this
        // machine: the two clocks are unrelated. Fenced like every other
        // mutation, and this is the one that matters most — `enable --now`
        // starts an agent, and a provider that has lost the lease must not
        // start one over the winner's files.
        let out = remote.run_fenced(
            &lease,
            &format!(
                "set -e\n\
                 systemctl daemon-reload\n\
                 echo '---STARTEDAT---'\n\
                 date +%s\n\
                 echo '---START---'\n\
                 systemctl enable --now {unit}\n",
                unit = sq(&names.unit()),
            ),
        )?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(lease_lost(&names.unit()));
        }
        if !out.ok() {
            return Err(format!(
                "starting {} failed (exit {}): {}",
                names.unit(),
                out.code,
                out.stderr.trim()
            ));
        }
        section(&out.stdout, "STARTEDAT")
            .trim()
            .parse::<u64>()
            .map_err(|_| {
                format!(
                    "{} was started, but the instance's clock could not be read \
                     alongside it, so this deploy cannot bound the journal to \
                     its own attempt. Check the unit with `systemctl status {}`.",
                    names.unit(),
                    names.unit()
                )
            })?
    };

    confirm_started(&remote, &names, cfg, started_at)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS — 35 `reconcile` tests (round 4 adds `a_torn_install_is_replaced_not_restarted`, `a_missing_sibling_is_replaced_not_restarted`, `every_mutating_script_proves_the_lease_in_its_own_shell`, `the_lease_proof_and_the_mutation_cannot_be_separated` and `a_lost_lease_reads_as_a_lease_loss_not_an_ownership_refusal`) plus everything from Tasks 1-11. The four wire goldens still pass: `deploy` reaches `Remote::new` only after the pure phase, so `deploy-no-owner` and `deploy-ordinary-provider` still stop offline.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): I4 reconciler with a full-tuple destructive fence"
```

---

## Task 13: Operator subcommands — `list`, `remove`, `dry-run`

Resolves review **P2-4**, **P2-6**, P3's "`dry-run` is exercised by no acceptance criterion", round 2's **P1-4** (`remove`'s fence must read each file it deletes) and **P2-2** (an agent whose env file is gone must still be visible and still be removable), round 3's **P1-2** (`remove` stops a unit it has not proven it owns), the `remove` halves of **P1-1** (a prior-version agent must stay removable), **P1-3** (the delete veto counted lines, not patterns) and **P1-4** (`remove` took no lease at all), and round 4's **P1-2** (the pre-stop gate authorised a half-migrated fleet) and the `remove` half of **P1-1** (the removal script ran on a renewal rather than under a held lease).

**Files:**
- Create: `crates/buzz-backend-gcp/src/operator.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod operator;` and the argv branch)

**Interfaces:**
- Produces: `operator::Cli` (clap `Parser`), `operator::Cmd`, `operator::run(cli: Cli) -> Result<(), String>`, `operator::render_listing(stdout: &str) -> String`, and the private `instance_of`, `resolve_target`, `listing_script`, `ownership_scan_script`, `refusal`, `verify_removable`, `removal_script`
- Consumes: `crate::capacity`, `crate::config::{self, ProviderConfig}`, `crate::naming::{self, Names, Ownership, MANAGED_BY}`, `crate::observe::{self, AgentFileState}`, `crate::reconcile::acquire_lease`, `crate::remote::{lease_lost, marker_fn, sq, Remote, LOCK_UNAVAILABLE, MARKER_SCAN_LINES}`, `crate::render`, `crate::secrets`, `buzz_backend_core::identity::AgentIdentity`, `buzz_backend_core::wire::DeployRequest`, `clap`. The test module additionally imports `crate::naming::{agent_ownership, AgentMarker}` and reaches `crate::observe::{agent_paths, SHARED_PATHS}` by path — the parent names none of those, and an import only the tests use is an unused import under `-D warnings`. `Ownership` is **not** in the test import: round 4's `verify_removable` matches on it, so the parent names it and `use super::*` carries it, and naming it again would be a duplicate import rather than a redundant one.

The desktop passes no argv, so argv presence unambiguously selects operator mode. With empty argv the binary behaves exactly as the protocol requires.

**`remove` requires `--pubkey`, and that is the point.** `managed-by` proves only that this provider wrote a file; it says nothing about *which* agent. Since the 12-hex name is collision-resistant rather than collision-free, a `managed-by`-only fence would let `remove buzz-acp@a1b2c3d4e5f6` destroy a different agent that truncated to the same 12 hex. The full pubkey has to come from somewhere, and the operator is the only party who can supply it — which is exactly why `list` prints it.

**`remove` deletes enumerated paths, never a directory — and fences each path on its own header.** `rm -rf /etc/systemd/system/buzz-acp@<short12>.service.d/` is not a fence, it is a fence-shaped hole: a drop-in directory is precisely where an operator puts `override.conf` or `team.conf`, and the live host already has such an out-of-band drop-in. Nor is "verify the env file, then delete four paths" a fence: that authorizes destroying a hand-written drop-in from a *sibling's* header, which is exactly what [L2]'s auto-repair rule forbids (`docs/remote-agents.md:1460-1476`). Each of the four paths carries its own veto, evaluated in the same remote shell as its own `rm`; a file that fails it is reported and left exactly where it is. `remove` then `rmdir`s each drop-in directory only if it is empty, so an operator's own file both survives and keeps its directory. The veto is `remote::marker_fn`'s `marker_ok`, the same shell function the install guard uses — round 3 found that both had spelled it `grep -c -F -x -e … | [ "$n" -eq 3 ]`, which counts matching input *lines* rather than distinct matched patterns, so a header repeating `# managed-by:` satisfied the count while carrying no `# agent-pubkey-full:` at all.

**A missing env file is not "nothing to remove".** Both `list` and `remove` used to key off `/etc/buzz/acp-*.env`. Delete that one file — by hand, by a half-finished cleanup, by an interrupted `remove` — and a running, secret-bearing agent becomes invisible to `list` while `remove` answers "there is nothing here to remove". That is the operator's only reclamation path lying to them in a reachable state. `list` now unions three enumerations (the env glob, `systemctl list-units`/`list-unit-files`, and the drop-in directories) and recovers the pubkey from whichever per-agent artifact still carries a marker; `remove` proceeds without the env file, because authorization comes from `--pubkey` plus each file's own header, neither of which lives there exclusively.

**Nothing is stopped before ownership is proven, and a mixed fleet is not "ownership".** Deleting a file was fenced; *stopping a unit* was not. With the env file absent, `remove` used to run `systemctl disable --now buzz-acp@<id>.service` before reading a single marker, on the strength of `--pubkey` sharing its first twelve hex with the unit id — which is exactly the collision the full pubkey exists to close, and [L2] item 4 requires full-identity evidence before *any* action, not only before a delete. `remove` therefore opens with a read-only scan of all four per-agent artifacts in one shell. Round 4's P1-2 then fixed what that scan was allowed to conclude. "At least one present artifact carries a matching marker" is not a proof of ownership over the *unit*: `AgentMarker::parse` yields nothing for `OursButNewer`, so a half-migrated agent — an older-or-current env file this build owns, beside a drop-in a newer provider wrote — satisfied it by looking past the sibling entirely, and `remove` went on to destroy the secret and run a script whose first act is `systemctl disable --now`. The newer deployment was stopped and its key destroyed, and only *then* did the per-file fences politely keep its files. So `verify_removable` now takes the shape `classify` has: **every present artifact is checked for refusal first — foreign, unparseable, newer-than-this-build, ours-without-an-identity-line, or marked for another pubkey — and only then does one surviving present artifact authorise the removal.** `OursButOlder` stays accepted, because a uniform prior-version agent is this provider's own work and refusing it would close the reclamation path round 3 opened. A refusal names the offending path, the four paths it looked at, and the manual commands that reclaim the agent, because "refusing without a way forward" is how an operator ends up doing it with `rm -rf`.

**`remove` holds the same lease `deploy` takes — and proves it inside the shell that stops things.** It destroys a Secret Manager secret and four files while a concurrent deploy may be installing them; taking no lease made the two freely interleavable. The lease is acquired *before* the ownership scan, so the state that authorizes the removal cannot move between the read and the act. Holding it is not enough on its own, though — round 4's P1-1 — because "we renewed a moment ago" is not "we hold it now": `removal_script` therefore returns only the **root** half of the work, and `Remote::run_fenced` runs it inside the same `sudo -n flock … sh -c` wrapper the installs use, so the proof that the owner record still names this process and the `systemctl disable --now` it authorizes are one shell under one `flock`. The single standalone `renew` that remains sits before `secrets::destroy`, which is the only step here that leaves the instance.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/operator.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // `Ownership` is deliberately absent: round 4's `verify_removable` matches
    // on it, so the parent names it and `use super::*` carries it here. Naming
    // it again would be a duplicate import (E0252), not a redundant one.
    use crate::naming::{agent_ownership, AgentMarker};

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
        let raw = "unit\tbuzz-acp@a1b2c3d4e5f6.service\tactive\tdeadbeef\tok\n\
                   warning\twarning capacity: adding buzz-acp@a1b2c3d4e5f6.service (2G) may cause OOM kills.\n\
                   unit\tbuzz-acp@ffffffffffff.service\tinactive\tcafebabe\tok\n";
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

    /// P2-2: an agent whose env file was deleted out of band is still running
    /// and still holds a secret. Keying `list` off `/etc/buzz/acp-*.env` alone
    /// made it invisible here and un-removable there — the operator's only
    /// reclamation path lying to them in a reachable state.
    #[test]
    fn an_agent_whose_env_file_is_gone_is_still_listed_and_still_actionable() {
        let rendered =
            render_listing("unit\tbuzz-acp@a1b2c3d4e5f6.service\tactive\tdeadbeef\tno-env\n");
        assert!(rendered.contains("buzz-acp@a1b2c3d4e5f6.service"));
        assert!(
            rendered.contains("deadbeef"),
            "the pubkey survives on a sibling file: {rendered}"
        );
        assert!(rendered.contains("no environment file"), "{rendered}");
        assert!(rendered.contains("`remove` still works"), "{rendered}");
    }

    /// …and when *no* per-agent file carries a marker, the row still appears
    /// rather than being silently skipped.
    #[test]
    fn an_unmarked_instance_is_reported_not_hidden() {
        let rendered =
            render_listing("unit\tbuzz-acp@a1b2c3d4e5f6.service\tactive\t\tunmarked\n");
        assert!(rendered.contains("buzz-acp@a1b2c3d4e5f6.service"));
        assert!(rendered.contains("<pubkey unknown>"), "{rendered}");
        assert!(rendered.contains(MANAGED_BY), "{rendered}");
    }

    /// P2-1: the writer and the reader, wired together. Both were previously
    /// tested against hand-typed fixtures that happened to agree on the
    /// `warning ` prefix, so a rename on either side would have left every test
    /// green and the operator with no way to see an over-capacity deploy. This
    /// feeds `capacity::trail_record`'s **real** output through the shape
    /// `listing_script` emits and into the real reader.
    #[test]
    fn a_real_capacity_warning_survives_the_writer_reader_round_trip() {
        let unit = "buzz-acp@a1b2c3d4e5f6.service";
        let warnings = crate::capacity::warning_lines(
            crate::capacity::GIB,
            crate::capacity::GIB,
            unit,
            crate::capacity::GIB,
        );
        assert!(!warnings.is_empty(), "this fixture must overcommit");
        let record = crate::capacity::trail_record(
            "2026-08-05T09:14:02Z",
            "3f9c1a04",
            &"a".repeat(64),
            &warnings,
        );

        // Exactly what `listing_script` produces from that trail: the unit row,
        // then every line the remote `grep '^warning '` matched, tab-prefixed.
        let mut raw = format!("unit\t{unit}\tactive\t{}\tok\n", "ab".repeat(32));
        for line in record.lines().filter(|l| l.starts_with("warning ")) {
            raw.push_str(&format!("warning\t{line}\n"));
        }

        let rendered = render_listing(&raw);
        for warning in &warnings {
            assert!(
                rendered.contains(warning.as_str()),
                "the reader dropped {warning:?}:\n{rendered}"
            );
        }
        assert!(rendered.contains("may cause OOM kills"), "{rendered}");
        assert!(rendered.contains("e2-standard-4"), "{rendered}");
    }

    /// The enumeration must not be the env glob alone, or the ghost above is
    /// unreachable no matter how well `render_listing` renders it.
    #[test]
    fn the_listing_script_enumerates_units_as_well_as_env_files() {
        let script = listing_script();
        assert!(script.contains("/etc/buzz/acp-*.env"), "{script}");
        assert!(script.contains("systemctl list-units"), "{script}");
        assert!(script.contains("systemctl list-unit-files"), "{script}");
        assert!(script.contains("buzz-acp@*.service.d"), "{script}");
        // P1-1: a prior-version agent must remain listable. An exact
        // `# binding-version: N` match made a version bump hide every agent
        // already on the box behind `<pubkey unknown>`.
        assert!(
            script.contains(&format!("-le {}", naming::BINDING_VERSION_NUM)),
            "{script}"
        );
    }

    /// Enumerated paths only. A drop-in directory is where an operator keeps
    /// `override.conf`; deleting the directory is a fence-shaped hole.
    #[test]
    fn the_removal_script_deletes_named_files_and_never_a_directory_tree() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
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

    /// P1-4: each deletion is vetoed by the header of the file *it* deletes,
    /// in the same shell as the deletion. Authorizing four `rm`s from one
    /// sibling's header is "delete these paths if one of them is marked".
    #[test]
    fn every_deletion_is_fenced_on_the_file_it_deletes() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
        for required in [
            naming::header_line("managed-by", MANAGED_BY),
            naming::header_line("agent-pubkey-full", &pubkey),
        ] {
            assert!(script.contains(&sq(&required)), "the fence omits {required:?}");
        }
        assert!(
            script.contains(r#"head -n 4 "$p""#),
            "the fence must read the file being deleted: {script}"
        );
        assert!(script.contains(r#"rm -f "$p""#), "{script}");
        assert!(
            script.contains("kept $p"),
            "a file that fails the fence must be reported, not silently skipped"
        );
        // `create-intent` changes on every legitimate reconfiguration, so a
        // fence that required it would refuse a file this agent wrote itself.
        assert!(!script.contains("create-intent"), "{script}");
    }

    /// P1-3, the delete half. `grep -c -F -x -e a -e b -e c` compared against
    /// `3` counts matching input *lines*, not distinct matched patterns, so a
    /// header whose first lines repeat `# managed-by:` reaches the count while
    /// carrying no `# agent-pubkey-full:` at all — and the veto then
    /// authorizes deleting a file that does not carry this agent's identity.
    /// Each needle gets its own test, and the first miss returns.
    #[test]
    fn a_repeated_marker_line_does_not_authorize_a_delete() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
        assert!(
            !script.contains("grep -c"),
            "counting lines instead of patterns is the defect: {script}"
        );
        assert_eq!(
            script.matches("grep -Fqx").count(),
            2,
            "one independent check per needle: {script}"
        );
        assert!(
            script.contains(&format!(
                "grep -Fqx -- {}",
                sq(&naming::header_line("agent-pubkey-full", &pubkey))
            )),
            "the identity line must be asserted on its own: {script}"
        );
        // The binding version is an ordering, not a needle: a prior-version
        // file is this provider's own work, and `remove` must still delete it.
        assert!(
            script.contains(&format!("-le {}", naming::BINDING_VERSION_NUM)),
            "{script}"
        );
        assert!(
            !script.contains(&sq(&naming::header_line(
                "binding-version",
                naming::BINDING_VERSION
            ))),
            "an exact binding-version needle locks the operator out of a \
             prior-version agent: {script}"
        );
    }

    /// One row as the pre-stop scan reports it.
    fn scanned(path: &str, marker: Option<AgentMarker>) -> AgentFileState {
        AgentFileState {
            path: path.to_string(),
            present: marker.is_some(),
            ownership: if marker.is_some() {
                Ownership::Ours
            } else {
                Ownership::NotOurs
            },
            marker,
        }
    }

    fn our_marker(pubkey: &str) -> Option<AgentMarker> {
        Some(AgentMarker {
            pubkey_full: pubkey.to_string(),
            create_intent: "ci".to_string(),
        })
    }

    /// P1-2: `remove` may stop a unit only once it has proven the unit is this
    /// agent's. The env file is the artifact most likely to be missing, so the
    /// gate reads all four and any one of them is enough.
    #[test]
    fn an_env_absent_agent_with_a_marked_sibling_is_removable() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let files = [
            scanned(&names.env_path(), None),
            scanned(&names.dropin_path(), None),
            scanned(&names.secret_dropin_path(), None),
            scanned(&names.trail_path(), our_marker(&pubkey)),
        ];
        verify_removable(&files, &pubkey, &names)
            .expect("one marked sibling is full-identity evidence");
    }

    /// …and with nothing carrying this pubkey, the refusal arrives before
    /// anything is stopped. `--pubkey` sharing its first 12 hex with the unit
    /// id is not evidence — that is the collision the full pubkey closes — and
    /// this gate is a pure function precisely so it can refuse without a
    /// transport, which is what makes "nothing was stopped" structural rather
    /// than a promise.
    #[test]
    fn an_agent_with_no_matching_marker_is_refused_before_anything_stops() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let sibling = Some(AgentMarker {
            pubkey_full: format!("a1b2c3d4e5f6{}", "f".repeat(52)),
            create_intent: "ci".to_string(),
        });
        let files = [
            scanned(&names.env_path(), None),
            scanned(&names.dropin_path(), sibling),
            scanned(&names.secret_dropin_path(), None),
            scanned(&names.trail_path(), None),
        ];
        let err = verify_removable(&files, &pubkey, &names)
            .expect_err("a 12-hex prefix match must not authorize a stop");
        assert!(err.contains(&names.env_path()), "{err}");
        assert!(err.contains("Nothing was stopped"), "{err}");
        assert!(
            err.contains("systemctl") && err.contains(&names.secret_name()),
            "a refusal with no way forward is how an operator reaches for \
             rm -rf: {err}"
        );
    }

    /// P1-1: a prior-version agent must still be removable. Treating an older
    /// `binding-version` as foreign closed the operator's only reclamation
    /// path for every agent this provider itself deployed before the bump.
    #[test]
    fn a_prior_version_agent_is_still_removable() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let older = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 0\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        assert_eq!(agent_ownership(&older), Ownership::OursButOlder(0));
        let file = AgentFileState {
            path: names.env_path(),
            present: true,
            ownership: agent_ownership(&older),
            marker: AgentMarker::parse(&older),
        };
        verify_removable(&[file], &pubkey, &names)
            .expect("this provider's own prior-version agent is removable");
    }

    /// A *newer* binding version is the refusal the version rule reserves:
    /// deleting an artifact whose layout this build does not understand is
    /// destroying a newer provider's work, not reclaiming our own.
    #[test]
    fn a_future_version_agent_is_not_removable_by_this_build() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let newer = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 99\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        assert_eq!(agent_ownership(&newer), Ownership::OursButNewer(99));
        assert!(AgentMarker::parse(&newer).is_none(), "{newer}");
        let file = AgentFileState {
            path: names.env_path(),
            present: true,
            ownership: agent_ownership(&newer),
            marker: AgentMarker::parse(&newer),
        };
        assert!(verify_removable(&[file], &pubkey, &names).is_err());
    }

    /// The pre-stop scan reads every per-agent artifact in one shell, and it
    /// reads them with the *observer's* emitter — a second emitter of the same
    /// row shape is a second thing to keep in step with the parser. It must
    /// also touch no `systemctl` verb: it is the thing that decides whether
    /// stopping is allowed.
    #[test]
    fn the_ownership_scan_reads_all_four_artifacts_and_stops_nothing() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = ownership_scan_script(&names);
        for path in crate::observe::agent_paths(&names) {
            assert!(script.contains(&sq(&path)), "{path} is not scanned");
        }
        assert!(!script.contains("systemctl"), "{script}");
        assert!(!script.contains("rm -f"), "{script}");
    }

    /// Round 4's P1-2, the case the version rule existed for and got wrong.
    /// A half-migrated agent — an env file this build owns, for this pubkey,
    /// beside a drop-in a *newer* provider wrote — used to pass the gate,
    /// because the gate authorised on "any artifact carries a matching
    /// marker" and `AgentMarker::parse` yields nothing for `OursButNewer`, so
    /// the newer sibling was simply looked past. `remove` then destroyed the
    /// secret and ran a script whose first act is `systemctl disable --now`:
    /// the newer deployment was stopped and its key destroyed, and only then
    /// were its *files* politely kept. The gate must refuse.
    #[test]
    fn a_half_migrated_agent_is_refused_before_anything_stops() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let newer = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 99\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        let files = [
            // Ours, this build's own layout, and unambiguously this agent's.
            scanned(&names.env_path(), our_marker(&pubkey)),
            AgentFileState {
                path: names.dropin_path(),
                present: true,
                ownership: agent_ownership(&newer),
                marker: AgentMarker::parse(&newer),
            },
            scanned(&names.secret_dropin_path(), None),
            scanned(&names.trail_path(), None),
        ];
        let err = verify_removable(&files, &pubkey, &names)
            .expect_err("a newer sibling must block the whole removal");
        assert!(err.contains(&names.dropin_path()), "{err}");
        assert!(err.contains("99"), "the refusal must name the version: {err}");
        assert!(err.contains("Nothing was stopped"), "{err}");
        assert!(
            !err.contains("somebody else"),
            "a newer build of this provider is not a stranger: {err}"
        );
    }

    /// …and a uniform prior-version fleet is still removable, so the stricter
    /// gate did not close the reclamation path round 3's P1-1 opened.
    #[test]
    fn a_uniform_prior_version_fleet_is_still_removable() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let older = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 0\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        let at_version_zero = |path: String| AgentFileState {
            path,
            present: true,
            ownership: agent_ownership(&older),
            marker: AgentMarker::parse(&older),
        };
        let files: Vec<AgentFileState> = crate::observe::agent_paths(&names)
            .into_iter()
            .map(at_version_zero)
            .collect();
        verify_removable(&files, &pubkey, &names)
            .expect("a uniform prior-version agent is this provider's own work");
    }

    /// Round 4's P1-1, the `remove` half. The removal script is the **root**
    /// half only — `Remote::run_fenced` supplies the elevation, the `flock`
    /// and the ownership proof — so it must carry no `set` line and no `sudo`
    /// of its own, or it would run privileged commands outside the wrapper
    /// that proves the lease.
    #[test]
    fn the_removal_script_is_the_root_half_of_a_fenced_shell() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
        assert!(!script.contains("sudo"), "the wrapper elevates once: {script}");
        assert!(!script.contains("set -"), "the wrapper sets the shell: {script}");
        assert!(script.starts_with("marker_ok()"), "{script}");
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
use crate::naming::{self, Names, Ownership, MANAGED_BY};
use crate::observe::{self, AgentFileState};
use crate::reconcile::acquire_lease;
use crate::remote::{lease_lost, marker_fn, sq, Remote, LOCK_UNAVAILABLE, MARKER_SCAN_LINES};
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
///
/// Three independent enumerations, unioned: the env-file glob, the units
/// systemd knows about, and the drop-in directories. Keying off
/// `/etc/buzz/acp-*.env` alone is what turned a deleted env file into a ghost
/// — a running, secret-bearing agent that `list` could not see and `remove`
/// declared absent.
///
/// The pubkey is read from whichever per-agent artifact still carries a marker
/// **at a binding version this build may act on** — its own, or an older one.
/// All four carry the same tuple, so losing one costs nothing; losing all four
/// flags the row and sends the operator to Secret Manager, which holds the same
/// value as an annotation (Task 10). Requiring an *exact* `binding-version`
/// match here was the third face of round 3's P1-1: a version bump would have
/// hidden every agent already on the box behind `<pubkey unknown>`, and the
/// pubkey `remove` needs is the one `list` prints.
///
/// The instance-name `case` is not decoration: these ids come from a filesystem
/// glob and from `systemctl` output, and every one of them is about to be
/// interpolated into a path. Anything that is not exactly 12 lowercase hex is
/// not one of ours.
fn listing_script() -> String {
    format!(
        "set -uo pipefail\n\
         ids=$(\n\
           {{\n\
             for f in /etc/buzz/acp-*.env; do\n\
               [ -e \"$f\" ] || continue\n\
               b=$(basename \"$f\" .env); printf '%s\\n' \"${{b#acp-}}\"\n\
             done\n\
             systemctl list-units --all --no-legend --plain 'buzz-acp@*.service' \
               2>/dev/null | awk '{{print $1}}'\n\
             systemctl list-unit-files --no-legend --plain 'buzz-acp@*.service' \
               2>/dev/null | awk '{{print $1}}'\n\
             for d in /etc/systemd/system/buzz-acp@*.service.d; do\n\
               [ -d \"$d\" ] || continue\n\
               basename \"$d\" .service.d\n\
             done\n\
           }} | sed -n 's/^buzz-acp@//; s/\\.service$//; p' | sort -u\n\
         )\n\
         for i in $ids; do\n\
           case \"$i\" in\n\
             [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;\n\
             *) continue ;;\n\
           esac\n\
           env=\"/etc/buzz/acp-$i.env\"\n\
           trail=\"/etc/buzz/acp-$i.trail\"\n\
           pk=''\n\
           for c in \"$env\" \"$trail\" \
             \"/etc/systemd/system/buzz-acp@$i.service.d/agent.conf\" \
             \"/etc/systemd/system/buzz-acp-secret@$i.service.d/agent.conf\"; do\n\
             sudo -n test -e \"$c\" || continue\n\
             h=$(sudo -n head -n {scan} \"$c\")\n\
             printf '%s\\n' \"$h\" | grep -Fxq {managed_by} || continue\n\
             v=$(printf '%s\\n' \"$h\" | sed -n 's/^# binding-version: //p' | head -n 1)\n\
             case \"$v\" in ''|*[!0-9]*) continue ;; esac\n\
             [ \"$v\" -le {version} ] || continue\n\
             pk=$(printf '%s\\n' \"$h\" | sed -n 's/^# agent-pubkey-full: //p' | head -n 1)\n\
             if [ -n \"$pk\" ]; then break; fi\n\
           done\n\
           flags=ok\n\
           if [ -z \"$pk\" ]; then flags=unmarked; fi\n\
           if ! sudo -n test -e \"$env\"; then flags=no-env; fi\n\
           st=$(systemctl is-active \"buzz-acp@$i.service\" 2>/dev/null || echo unknown)\n\
           printf 'unit\\tbuzz-acp@%s.service\\t%s\\t%s\\t%s\\n' \"$i\" \"$st\" \"$pk\" \"$flags\"\n\
           if sudo -n test -e \"$trail\"; then\n\
             sudo -n grep '^warning ' \"$trail\" 2>/dev/null | while IFS= read -r w; do\n\
               printf 'warning\\t%s\\n' \"$w\"\n\
             done\n\
           fi\n\
         done\n",
        scan = MARKER_SCAN_LINES,
        managed_by = sq(&naming::header_line("managed-by", MANAGED_BY)),
        version = naming::BINDING_VERSION_NUM,
    )
}

/// Turn the listing script's tab-separated output into operator-readable text.
///
/// Pure, so the rendering is tested without an instance — and the *writer* of
/// the `warning ` lines it reads is exercised against this function directly
/// (Task 8 Step 1), because two sides agreeing with two hand-typed fixtures is
/// not the same as two sides agreeing with each other.
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
                let pubkey = fields.next().unwrap_or("");
                let flags = fields.next().unwrap_or("");
                let pubkey = if pubkey.is_empty() {
                    "<pubkey unknown>"
                } else {
                    pubkey
                };
                out.push_str(&format!("{unit}\t{state}\t{pubkey}\n"));
                match flags {
                    "no-env" => out.push_str(
                        "    no environment file — the unit, its drop-ins and its Secret \
                         Manager secret outlived it. It is still running and `remove` still \
                         works.\n",
                    ),
                    "unmarked" => out.push_str(&format!(
                        "    no {MANAGED_BY} marker this build recognises on any of this \
                         agent's files — either nothing here is ours, or a newer provider \
                         deployed it. Recover the pubkey with `gcloud secrets list \
                         --filter=\"labels.managed_by={MANAGED_BY}\" \
                         --format=\"value(name,annotations)\"`.\n"
                    )),
                    _ => {}
                }
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

/// Every pre-stop refusal, in one shape.
///
/// The reason varies; the tail never does — the four paths the gate looked at,
/// and the manual reclamation. A refusal with no way forward is how an
/// operator ends up doing it with `rm -rf`, and a refusal whose text depends
/// on which arm produced it is four messages to keep actionable instead of
/// one.
fn refusal(reason: &str, names: &Names) -> String {
    let looked_at = observe::agent_paths(names)
        .iter()
        .map(|path| format!("  {path}\n"))
        .collect::<String>();
    format!(
        "refusing to touch {unit}: {reason} Nothing was stopped, disabled or \
         destroyed. Looked at:\n{looked_at}\
         The 12-hex instance name is collision-resistant, not collision-free, \
         so a unit whose name matches is not evidence that this agent is \
         yours. If you are certain it is and you accept what the reason above \
         says, reclaim it by hand: `sudo systemctl disable --now {unit}`, \
         delete those paths, then `gcloud secrets delete {secret}`.",
        unit = names.unit(),
        secret = names.secret_name(),
    )
}

/// The pre-stop gate: **before** anything is stopped, disabled or destroyed,
/// every present per-agent artifact must be this provider's and this agent's,
/// and at least one of them must be there at all.
///
/// Deleting a file was already fenced on that file's own header. Stopping a
/// unit was not: with the env file absent, `remove` ran
/// `systemctl disable --now buzz-acp@<id>.service` before reading a single
/// marker, authorized only by `--pubkey` sharing its first twelve hex with the
/// unit id — the exact collision the full pubkey exists to close. [L2] item 4
/// requires full-identity evidence before *any* action.
///
/// **Refusals first, over every present artifact; authorisation second** — the
/// same order and the same four arms `reconcile::classify` uses, and for the
/// same reason: a stop cannot be undone by a later check. Round 4's P1-2 is
/// what forced the first half. The gate used to authorise as soon as *any*
/// present artifact carried a matching marker, and [`crate::naming::AgentMarker::parse`]
/// yields nothing at all for [`Ownership::OursButNewer`], so a half-migrated
/// agent — an older-or-current env file this build owns, beside a sibling a
/// *newer* provider wrote — walked straight through. `remove` then destroyed
/// the secret and ran a script whose first act is `systemctl disable --now`,
/// and the newer deployment was stopped and its secret destroyed before the
/// per-file fences got as far as politely "keeping" its files. The downgrade
/// refusal was sound for a uniform fleet and on the deploy path; it was unsound
/// here, in exactly the mixed state it exists for.
///
/// [`Ownership::OursButOlder`] is still accepted, and must be: a uniform
/// prior-version agent is this provider's own work at a layout this build
/// supersedes, and refusing it would close the operator's only reclamation
/// path for every agent installed before a version bump.
///
/// Once the loop has passed, "any one artifact is enough" is safe, and it is
/// still the point: the env file is the one most likely to be missing, and a
/// marked drop-in or trail proves the same thing it would have.
///
/// Pure, so it can refuse without a transport. That is what makes "nothing was
/// stopped" structural rather than a promise in a comment.
fn verify_removable(
    files: &[AgentFileState],
    pubkey_full: &str,
    names: &Names,
) -> Result<(), String> {
    for file in files.iter().filter(|file| file.present) {
        match file.ownership {
            Ownership::Ours | Ownership::OursButOlder(_) => {}
            Ownership::OursButNewer(found) => {
                return Err(refusal(
                    &format!(
                        "{path} was written by a newer {MANAGED_BY} (binding \
                         version {found}; this build writes {version}), so this \
                         build cannot tell what stopping the unit would destroy \
                         — and stopping it is the first thing a removal does. \
                         Upgrade this provider and remove the agent with it.",
                        path = file.path,
                        version = naming::BINDING_VERSION,
                    ),
                    names,
                ))
            }
            Ownership::NotOurs => {
                return Err(refusal(
                    &format!(
                        "{} exists but carries no {MANAGED_BY} marker at a \
                         binding version this build recognises, so it is not \
                         this provider's to tear down. Move it aside first.",
                        file.path
                    ),
                    names,
                ))
            }
        }
        let Some(marker) = file.marker.as_ref() else {
            return Err(refusal(
                &format!(
                    "{} carries the {MANAGED_BY} marker but no \
                     agent-pubkey-full line, so which agent it belongs to \
                     cannot be established.",
                    file.path
                ),
                names,
            ));
        };
        if marker.pubkey_full != pubkey_full {
            return Err(refusal(
                &format!(
                    "short-name collision: {} belongs to pubkey {}, not \
                     {pubkey_full}.",
                    file.path, marker.pubkey_full
                ),
                names,
            ));
        }
    }

    if files.iter().any(|file| file.present) {
        return Ok(());
    }
    Err(refusal(
        &format!(
            "none of its per-agent artifacts is present, so nothing carries a \
             {MANAGED_BY} marker for pubkey {pubkey_full} at a binding version \
             this build recognises."
        ),
        names,
    ))
}

/// The pre-stop ownership scan: every per-agent artifact's marker header, in
/// one remote shell, and nothing else.
///
/// It reads. It runs no `systemctl` verb and deletes nothing, because its whole
/// job is to decide whether `remove` is allowed to. The rows come from
/// [`observe::agent_file_rows`] — the same emitter the reconciler's observation
/// uses, parsed by the same [`observe::parse_agent_file_row`] — so `remove` and
/// `deploy` cannot come to different conclusions about the same header.
fn ownership_scan_script(names: &Names) -> String {
    format!(
        "set -uo pipefail\n{field}echo '---AGENTFILES---'\n{rows}echo '---END---'\n",
        field = observe::FIELD_HELPER,
        rows = observe::agent_file_rows(names),
    )
}

/// The remote script that deletes this agent's own files — by name, never a
/// directory tree, and each one only if **its own** header says it is ours.
///
/// The previous shape verified the env file in Rust and then `rm -f`'d four
/// enumerated paths. That is "delete these paths if one of them is marked", not
/// "delete only marked paths": a hand-written drop-in beside a marked env file
/// was destroyed by a fence that never looked at it. Each path now carries its
/// own veto, evaluated in the same shell as its own `rm`, and a file that fails
/// it is reported and left exactly where it is.
///
/// `create-intent` is deliberately **not** among the required lines: it changes
/// on every legitimate reconfiguration, so requiring it would refuse a file
/// this very agent wrote yesterday. Neither is `binding-version` — `marker_ok`
/// compares it as an ordering, so a prior-version agent this provider itself
/// deployed can still be torn down.
///
/// The veto is `remote::marker_fn`'s `marker_ok`, shared with the install
/// guard. Both used to spell it `grep -c -F -x -e … | [ "$n" -eq 3 ]`, and
/// `grep -c` counts matching input **lines** rather than distinct matched
/// patterns: a header repeating `# managed-by:` reached the count while
/// carrying no `# agent-pubkey-full:` at all, so the veto authorized deleting a
/// file that never named this agent.
///
/// This returns the **root** half only: no `set`, no `sudo -n`, because
/// `Remote::run_fenced` runs it inside `remote::under_lease`'s
/// `sudo -n flock … sh -c`, already elevated and already holding the lease.
/// That is round 4's P1-1 — the `systemctl disable --now` on the first line is
/// the most destructive thing this binding does, and it must not execute
/// unless the owner record still names this process at the instant it runs.
fn removal_script(names: &Names, pubkey_full: &str) -> String {
    let required = [
        naming::header_line("managed-by", MANAGED_BY),
        naming::header_line("agent-pubkey-full", pubkey_full),
    ];
    format!(
        "{marker_ok}\
         systemctl disable --now {unit} 2>/dev/null || true\n\
         systemctl stop {secret_unit} 2>/dev/null || true\n\
         for p in {env} {trail} {dropin} {secret_dropin}; do\n\
           test -f \"$p\" || continue\n\
           h=$(head -n {scan} \"$p\" || true)\n\
           if marker_ok; then\n\
             rm -f \"$p\"\n\
           else\n\
             echo \"kept $p: it carries no {managed_by} marker for this agent at \
a binding version this build may act on\"\n\
           fi\n\
         done\n\
         for d in {dropin_dir} {secret_dropin_dir}; do\n\
           if test -d \"$d\"; then\n\
             if rmdir \"$d\" 2>/dev/null; then :; else\n\
               echo \"kept $d: it still holds files this provider did not write\"\n\
             fi\n\
           fi\n\
         done\n\
         systemctl daemon-reload\n",
        marker_ok = marker_fn(&required),
        unit = sq(&names.unit()),
        secret_unit = sq(&names.secret_unit()),
        env = sq(&names.env_path()),
        trail = sq(&names.trail_path()),
        dropin = sq(&names.dropin_path()),
        secret_dropin = sq(&names.secret_dropin_path()),
        scan = MARKER_SCAN_LINES,
        managed_by = MANAGED_BY,
        dropin_dir = sq(&names.dropin_dir()),
        secret_dropin_dir = sq(&names.secret_dropin_dir()),
    )
}

fn remove(remote: &Remote, project: &str, agent_id: &str, pubkey: &str) -> Result<(), String> {
    let (names, pubkey) = resolve_target(agent_id, pubkey)?;

    // The same per-agent lease `deploy` takes, and for the same reason: this
    // destroys a Secret Manager secret and four files while a concurrent deploy
    // may be installing them, and taking none left the two freely
    // interleavable. It is acquired *before* the scan whose verdict authorizes
    // everything below, so the state that authorizes cannot move between the
    // read and the act, and it is held to the end of this function.
    let lease = acquire_lease(remote, &names)?;

    // ---- Pre-stop gate ([L2] item 4). -------------------------------------
    // Stopping a unit is itself destructive, so it waits behind full-identity
    // evidence like every other destructive step. All four artifacts are read
    // in one shell; a *missing env file* is still not "nothing to remove",
    // because the unit, both drop-ins, the trail and the secret all outlive it
    // and any one surviving marker proves the same thing the env file would.
    let out = remote.run(&ownership_scan_script(&names))?;
    if !out.ok() {
        return Err(format!(
            "could not read {}'s marker headers (exit {}): {}. Nothing was \
             stopped or destroyed.",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }
    let files: Vec<AgentFileState> = observe::section(&out.stdout, "AGENTFILES")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(observe::parse_agent_file_row)
        .collect();
    verify_removable(&files, &pubkey, &names)?;
    if !files
        .iter()
        .any(|file| file.path == names.env_path() && file.present)
    {
        eprintln!(
            "note: {} is absent. Removing {} anyway — a sibling artifact \
             carries this agent's marker, and each deletion below is still \
             fenced on that file's own header.",
            names.env_path(),
            names.unit()
        );
    }

    // Secret first. The reverse order leaves markers gone, the secret still
    // holding a live key, and no local evidence left to identify or retry it.
    // Ordered this way an interrupted remove is idempotent: a re-run finds the
    // marked files present, the secret already absent, and treats
    // delete-of-absent as success ([L2] item 4).
    //
    // This is the one standalone renewal `remove` keeps, and for the same
    // reason `deploy` keeps its one: `secrets::destroy` is a `gcloud` call
    // from this machine against a service the instance's lock knows nothing
    // about, so it is the only step here that no fenced shell covers. Every
    // other mutation below proves the lease itself.
    lease.renew()?;
    secrets::destroy(remote, project, &names.secret_name(), &pubkey)?;

    // The removal itself runs *inside* the lease, not merely after a renewal
    // that preceded it: `run_fenced` wraps the script in the same
    // `sudo -n flock … sh -c` the installs use, so the proof that the record
    // still names this process and the `systemctl disable --now` it authorizes
    // share one shell. Round 4's P1-1 — a renewal that succeeds and is then
    // followed by a stall long enough for the lease to be taken over leaves
    // the mutation unguarded, and this one stops units and deletes files.
    let out = remote.run_fenced(&lease, &removal_script(&names, &pubkey))?;
    if out.code == LOCK_UNAVAILABLE {
        return Err(lease_lost(&names.unit()));
    }
    if !out.ok() {
        return Err(format!(
            "removing {agent_id} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    // Any `kept …` line is a file this provider declined to delete. Printing it
    // is the whole point: silence would read as a clean sweep.
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
Expected: PASS — 20 `operator` tests (round 4 adds `a_half_migrated_agent_is_refused_before_anything_stops`, `a_uniform_prior_version_fleet_is_still_removable` and `the_removal_script_is_the_root_half_of_a_fenced_shell`), and every wire test still green (they spawn the binary with **no** argv, so they must still see protocol behavior).

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
| `project` | string | `zoop-innovation` | `^[a-z][a-z0-9-]{0,61}[a-z0-9]$`. Reaches `Environment=BUZZ_GCP_PROJECT=` in a root-installed drop-in. |
| `zone` | string | `asia-south1-a` | Same grammar. |
| `instance` | string | `buzz-agent` | Same grammar. |
| `memory_max` | string | `2G` | systemd `MemoryMax`. `^[0-9]{1,6}(\.[0-9]{1,3})?[KMGT]?$`, uppercase suffix, `> 0`. |
| `cpu_quota` | string | `150%` | systemd `CPUQuota`. `^[0-9]{1,3}%$`, `1`–`200` (the instance has 2 vCPU). |
| `inactivity_seconds` | integer | `7200` | Feeds `BUZZ_ACP_EXIT_AFTER_INACTIVITY`. `0` parses but is refused — see below. |

All five interpolated values — `project`, `zone`, `instance`, `memory_max` and
`cpu_quota` — are parsed against closed grammars and **rejected**, never
sanitized: they land in root-installed systemd drop-ins, where a newline becomes
an additional unit directive and a space or `%` inside an `Environment=` value
becomes a second assignment. Every `provider_config` string value is
additionally scanned for CR, LF, and NUL *before* it is trimmed.

No field names a credential (I2), and none may carry one.

## Operator commands

The desktop passes no argv, so argv selects operator mode.

| Command | Effect |
|---|---|
| `buzz-backend-gcp list` | Every marked unit with its state, full pubkey, and every `warning` line from its deploy trail. |
| `buzz-backend-gcp remove <agent_id> --pubkey <64 hex>` | Prove ownership, then stop, disable, destroy the secret, and delete this agent's enumerated files — each one only if its **own** header carries this pubkey; anything else is reported and left in place. `--pubkey` is required: the 12-hex name is collision-resistant, not collision-free. Copy it from `list`. Nothing is stopped until at least one of the four per-agent artifacts is found carrying a marker for that exact pubkey — stopping a unit is destructive, and a 12-hex prefix match is not evidence that it is yours. |
| `buzz-backend-gcp dry-run < request.json` | Print every rendered artifact with all secret-classified values redacted. Touches nothing. |

`list` is the only place a capacity warning is readable. **Buzz Desktop will not
show it**: `invoke_provider` keeps provider stderr only for a failed deploy
(`backend.rs:252-280`) and drops it on success, and the response envelope has no
`warning` field for a provider to fill. An over-capacity deploy therefore
succeeds silently in the UI and is recorded durably in
`/etc/buzz/acp-<id>.trail`, which `list` reads back. If an agent is OOM-killed
later, `list` is where the connection is.

`list` also enumerates `buzz-acp@*` **units**, not only `/etc/buzz/acp-*.env`.
An agent whose env file was deleted out of band is still running and still
holds a secret, so it is still listed — with `no environment file` on its row —
and is still removable. Its pubkey is recovered from whichever of its four
per-agent files still carries a marker; if none do,
`gcloud secrets list --project <project> --filter="labels.managed_by=buzz-backend-gcp" --format="value(name,annotations)"`
has it.

## What lands on the instance

Three shared artifacts, written only when absent or when their bytes differ from
what this provider would render, each carrying a provider-level marker that
records provenance and nothing else — no agent identity, no digest:

- `/etc/systemd/system/buzz-acp@.service`
- `/etc/systemd/system/buzz-acp-secret@.service`
- `/usr/local/sbin/buzz-acp-fetch-key`

Four per-agent artifacts, each carrying the full-pubkey marker. Every install
writes `<path>.<token>.tmp` first and `mv`s it into place, so a dropped
connection never leaves a half-written file at a real path; and every install
refuses if the target already exists carrying somebody else's marker:

- `/etc/buzz/acp-<id>.env` (0600, allowlisted non-secret values only)
- `/etc/systemd/system/buzz-acp@<id>.service.d/agent.conf`
- `/etc/systemd/system/buzz-acp-secret@<id>.service.d/agent.conf`
- `/etc/buzz/acp-<id>.trail` (0644, appended per deploy)

Everything else — the nsec, `BUZZ_AUTH_TAG`, and every API key the launch
carries — goes to Secret Manager and is materialized to
`/run/buzz-acp-<id>/secret.env` on tmpfs, 0400 `buzzacp`. It never touches the
persistent boot disk.

## Provider upgrades

Every artifact this provider writes carries a `binding-version`, bumped when the
unit or environment shape changes in a way an older build would mishandle. An
artifact written by an **older** build is this provider's own work at a layout
this one supersedes: `deploy` replaces it, rolls the Secret Manager labels
forward, and the marker comes out at the current version — no operator action,
no `--force`. An artifact written by a **newer** build is refused, by `deploy`
and by `remove` alike, and the refusal names the version it found: a build that
cannot reason about a layout must not overwrite or delete it. If you have rolled
the binary back, run the newer one to remove those agents.

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
   compared in full — the 12-hex instance name is collision-resistant only —
   and it is read from **each artifact's own header**, not from one sibling's:
   an unmarked drop-in beside a marked env file stops the deploy and survives
   it. "Started" is `ActiveState=active` **and** a non-zero `MainPID` **and**
   the harness's own `buzz-acp starting:` line in the journal, scoped to the
   unit's *current* `InvocationID` and to a timestamp taken on the instance
   immediately before `enable --now`; systemd accepting the unit is not a
   start, and neither is a line the previous run left behind. Most-recent
   semantics come from re-reading the whole marker tuple and the running state
   **in the same remote shell** as the stop that depends on them, so the
   compare and the act are not separated by a round trip. Every write is
   staged to `<path>.<token>.tmp` and `mv`d into place, so no target path is
   ever observed half-written and the fence never has a truncated fragment to
   refuse forever. The mutating window is serialized by a per-agent lease on
   the instance (`flock` over a lease record in a private `0700 root:root`
   `/run/buzz-backend-gcp`), acquired **before** the observation the deploy
   acts on and held by `remove` across the secret destroy and the file
   deletions. Every mutation re-proves that lease *inside its own shell, under
   the same `flock` the record can only be changed under*, and refreshes it
   there — so a holder that stalls past the TTL and is legitimately overtaken
   has its next write refused rather than landed, and a deploy that loses the
   lease mutates nothing and says so. `remove` additionally proves ownership
   before it stops anything: at least one of the four per-agent artifacts must
   be present, and **every** present one must carry this provider's marker at
   this binding version or older and name this pubkey, or nothing is stopped,
   disabled or destroyed. The
   auto-repair fence is the marker itself — no destructive action touches a
   file lacking the marker of its own tier.
2. **Two marker tiers.** Per-agent artifacts carry `managed-by`,
   `binding-version`, `agent-pubkey-full`, and `create-intent`. Shared
   artifacts — the two template units and the fetcher script — carry
   `managed-by`, `binding-version`, and `scope: provider-shared`, and **no
   agent identity at all**, because a file used by every instance belongs to
   none of them. The provider-level marker records provenance and nothing
   else: it makes no claim about the file's content, because a claim a file
   makes about itself is worth exactly what its writer is worth. Shared
   artifacts are written only when absent or when the bytes on the instance
   differ from the bytes this provider would render — compared by hashing both,
   not by trusting a digest stored in the file — which is what makes the
   live-instance no-op zero-mutation rather than "no-op except three files
   rewritten identically". A shared file present with no provider marker is a
   refusal, not an overwrite. **Ownership is version-aware at both tiers**: an
   artifact carrying an *older* `binding-version` is this provider's own work
   at a layout this build supersedes, so it is an authorised upgrade target —
   a per-agent one is replaced, a shared one is rewritten if its bytes differ,
   and the Secret Manager labels are rolled forward — while a *newer* one is a
   refusal, because a build that cannot reason about a layout must not
   overwrite or delete it. `binding-version` is documented as a
   bump-when-the-shape-changes value, so treating an older one as foreign
   would make every such bump lock the operator out of both `deploy` and
   `remove` for every agent already on the box.
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
   cgroup. It carries `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`,
   `ProtectSystem=strict`, `ProtectHome`, `ProtectKernelTunables`,
   `ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID`,
   `RestrictRealtime`, `LockPersonality`,
   `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `AmbientCapabilities=`,
   `TasksMax=128`, and `ReadWritePaths=` scoped to its own runtime directory.
   It differs from the agent unit in exactly three places, each deliberate:
   no `IPAddressDeny` (its reason to exist); `CapabilityBoundingSet=CAP_CHOWN`
   rather than empty, because the fetched file is `chown`ed to `buzzacp` so the
   agent unit's manager can hand it over as an `EnvironmentFile=` while the
   agent *process* cannot reach it; and `ReadWritePaths=-/run/buzz-acp-%i`
   rather than `/var/lib/buzzacp`.
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

- [ ] **Step 5: Sweep for suppressions that never came due**

Every `#[allow(dead_code)]` in this crate was interim, added because a module
landed a task or more before the code that calls it, and each carries a comment
naming the condition that retires it (Global Constraints). By this point every
module is wired, so every one of them should be gone.

Run:
```bash
grep -rn "allow(dead_code)" crates/buzz-backend-gcp/ && echo "STRAGGLERS ABOVE" || echo "clean"
```
Expected: `clean`, with no matches printed.

A match is one of exactly two things, and they need opposite responses. Either
the item **is** now reachable and the annotation is stale — delete it, and
confirm `cargo clippy -p buzz-backend-gcp --all-targets -- -D warnings` still
passes. Or the item is genuinely still unreachable, which means the plan
shipped code nothing calls: say so in the report rather than deleting the
annotation to make the grep quiet. Do not silence this step; a suppression that
outlived its stated reason is precisely what it exists to catch.

- [ ] **Step 6: Commit**

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

- [ ] **Step 7: Verify the fetcher unit carries the hardening the docs claim**

Task 14's `[L3]` section and the README both enumerate this unit's sandbox
directives. A directive that is documented but not present is worse than one
that is neither, so read them back from the loaded unit rather than from the
file:

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'systemctl show buzz-acp-secret@<id>.service \
     -p PrivateDevices -p ProtectKernelTunables -p ProtectKernelModules \
     -p ProtectControlGroups -p RestrictRealtime -p CapabilityBoundingSet \
     -p AmbientCapabilities -p TasksMax -p ReadWritePaths -p IPAddressDeny'
```
Expected: the five `Protect*`/`Restrict*`/`Private*` booleans are `yes`;
`CapabilityBoundingSet=cap_chown` and nothing else; `AmbientCapabilities` empty;
`TasksMax=128`; `ReadWritePaths=/run/buzz-acp-<id>`; and `IPAddressDeny` empty —
its absence is the whole reason this unit exists. Any mismatch means
`FETCHER_UNIT` and Task 14's documentation have drifted apart.

- [ ] **Step 8: Verify the I4 no-op, shared files included**

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
changed mtime on any shared file means the write-only-when-the-bytes-differ rule
regressed and the no-op is not strict.

- [ ] **Step 9: Verify the over-capacity warning reaches the operator**

Writer and reader are wired together in a unit test (Task 8 Step 1), but only a
live deploy proves the warning survives the round trip to a root-owned file and
back. Deploy a second throwaway agent that cannot fit: the instance has ~2.7 GB
available and the first agent already reserves 2G.

Create an agent named `smoke-big`, harness `codex-acp`, Run on `gcp`, leave
`memory_max` at its `2G` default, and submit. Then:

```bash
~/.local/bin/buzz-backend-gcp list
```
Expected: the deploy **succeeds** — overcommit is reported, never vetoed — and
`list` prints three indented `warning capacity:` lines under the new unit's row,
including `may cause OOM kills` and `e2-standard-4`. Rows without their warnings
mean the trail's `warning ` prefix and `listing_script`'s extractor have drifted
apart and the round-1 blind spot is back. The desktop shows none of this: it
drops provider stderr on the success path, which is why the trail exists (Task
8's preamble — and the README says so to the operator).

Tear this second agent down before continuing:

```bash
~/.local/bin/buzz-backend-gcp remove buzz-acp@<big-id> --pubkey <big-pk>
```

- [ ] **Step 10: Verify two concurrent deploys do not interleave**

The mutating window is serialized by a per-agent lease on the instance, and a
loser must fail cleanly rather than half-write. Run the same request twice at
once, straight at the binary — the desktop passes no argv, so this is exactly
the invocation it makes:

```bash
jq '.provider_config = {}' /tmp/audit.json > /tmp/race.json
~/.local/bin/buzz-backend-gcp < /tmp/race.json > /tmp/race-a.json &
~/.local/bin/buzz-backend-gcp < /tmp/race.json > /tmp/race-b.json &
wait
jq -r '.ok, (.error // .agent_id)' /tmp/race-a.json /tmp/race-b.json
```
Expected: at most one `true`, and any `false` carries
`another operation on buzz-acp@<id>.service is already in progress`. A second
failure with any *other* message — a half-installed file, a marker refusal, a
`systemctl` error — means the lease is not covering the window it must. A
`the deploy lease for … was not held` message is also acceptable and is the
per-mutation gate doing its job: it means the loser reached a write, proved the
record no longer named it, and refused before touching anything.

- [ ] **Step 11: Exercise the agent end to end**

Add the agent to a channel from the desktop and mention it.
Expected: it replies — proving identity assembly, owner resolution, the
respond-to gate, and the tmpfs secret path all survived the remote route.

- [ ] **Step 12: Verify the marker fence refuses, and refuses before it stops**

A mismatched `--pubkey` shares no marker with anything on the box, so the
pre-stop gate must refuse **before** `systemctl disable --now` runs. Run this
while the agent is *live* — that is the only way to see whether it survived:

```bash
~/.local/bin/buzz-backend-gcp remove buzz-acp@<id> --pubkey $(printf 'f%.0s' {1..64})
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command 'systemctl is-active buzz-acp@<id>.service'
```
Expected: a refusal that names the four paths it looked at and says
`Nothing was stopped, disabled or destroyed`, then `active` from the second
command. A refusal is not enough on its own — if `is-active` prints `inactive`,
the gate ran *after* the stop and P1-2 has regressed. Confirm with
`~/.local/bin/buzz-backend-gcp list` that the unit and its secret are intact.

- [ ] **Step 13: Verify a per-agent file this provider did not write is left alone**

The auto-repair fence is per artifact, not per agent: an unmarked sibling must
stop the write and survive it. Replace one drop-in with an unmarked file, then
redeploy from the desktop.

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'sudo systemctl stop buzz-acp@<id>.service; \
   sudo cp /etc/systemd/system/buzz-acp@<id>.service.d/agent.conf /tmp/agent.conf.bak; \
   printf "[Service]\nMemoryMax=1G\n" | \
     sudo install -m 0644 /dev/stdin /etc/systemd/system/buzz-acp@<id>.service.d/agent.conf'
```

Click Start in the desktop.
Expected: a refusal naming that exact path — not the env file — and the
hand-written `MemoryMax=1G` still present afterwards. Restore it, then confirm
the next Start succeeds:

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'sudo install -m 0644 /tmp/agent.conf.bak \
     /etc/systemd/system/buzz-acp@<id>.service.d/agent.conf; sudo rm -f /tmp/agent.conf.bak'
```

- [ ] **Step 14: Tear down and verify the ordering**

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
for `<id>`; the **three shared artifacts still present** (other agents depend on
them, and the next deploy re-checks them by comparing their bytes); and the
drop-in directory gone because it was empty.

- [ ] **Step 15: Full gate**

Run: `just ci`
Expected: PASS. This is the only run of the full gate; the per-task steps used
`cargo test -p …` plus `cargo clippy -p buzz-backend-gcp`.

- [ ] **Step 16: Commit any fixes and open the PR**

```bash
git add -A && git commit -s -m "test(backend-gcp): live smoke fixes"
```

---

## Self-Review

Run against the **approved** design (`docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md`), not the revision that preceded it, and against both review rounds.

### Spec coverage

| Design section | Task |
|---|---|
| §Where the Provider Runs, §Transport `PATH` | Task 9 (`Remote::new`, `prepended_path`, the named not-found refusal) |
| §Transport host trust, `sudo -n` | Task 9 (`ssh_argv` asserts no `StrictHostKeyChecking`; every privileged step is non-interactive — `install_script` and `append_script` reach `sudo -n` directly for the staging write and through `under_lease`'s single `sudo -n flock … sh -c` for the critical section, and Task 12's fenced stop and start step and Task 13's `removal_script` reach it through the same wrapper. `every_privileged_step_is_non_interactive` asserts no bare `sudo ` survives in any of them) |
| §`crates/buzz-backend-core` | Tasks 1-3 |
| §`crates/buzz-backend-gcp` module table | Tasks 4-13, one module per task or per half-task |
| §`info` | Task 4 |
| §`provider_config` v1 fields, §Value grammars | Task 4 (`parse_memory_max`, `parse_cpu_quota`, `parse_resource_name`, `reject_control_characters`, the named injection payloads) |
| §Refusals that precede deserialization | Task 5 (raw-JSON, trimmed, exact + padded + control fixtures, and an ordering test) |
| §Environment Construction | Task 2 (shared `build_env`) |
| §Binding-specific split: a non-secret allowlist | Task 7 (`NON_SECRET_KEYS`, the four-value leak test) |
| §Host-resolved values | Task 7 (`with_instance_harness`, `harness_basename`) + Task 12 (the `harness_installed` refusal) |
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

### Round 1's eight P1s — still answered, not regressed

| Finding | Answer |
|---|---|
| P1-1 capacity warning invisible on success | Task 8 records it durably in the trail; Task 13's `list` reads it back; Task 14's README tells the operator the desktop will not show it. |
| P1-2 `gcloud` not on a GUI `PATH` | Task 9 prepends the three directories and refuses with a named remedy. |
| P1-3 two snippets do not compile | Task 12 matches `&action`; Task 13 destructures `Cli` before matching `command`. Every block re-walked again this round — see below. |
| P1-4 no `relay-mesh` refusal | Task 5, raw JSON before `from_value`, trimmed, now asserted against the exact sentence plus an ordering test. |
| P1-5 `FencedReplace` TOCTOU, observation too weak | Task 11 splits `SystemdState` from `MarkerState`; Task 12 refuses present-but-unmarked and pubkey mismatch. Round 2 narrowed the fence further — see P1-8 below. |
| P1-6 `memory_max`/`cpu_quota` injection | Task 4's closed grammars and the CR/LF/NUL scan before trimming. Round 2 added the third interpolation, `project`. |
| P1-7 non-nsec secrets on disk and in `dry-run` | Task 7's allowlist, `redacted_secret_body`, and the leak test over all four values; Task 13 Step 6 exercises it. |
| P1-8 extraction breaks unmentioned tests | Task 2 Step 4 updates both `AuthoritativeInputs` struct literals and adds a `max_env_bytes: None` case; Step 2 makes `AUTHORITATIVE_KEYS` `pub`; Step 9 runs `cargo test -p buzz-backend-core` before the k8s regression run. Task 1 now also adds `Clone` to `AgentPayload`/`LaunchBlock` — additive, no assertion edits. |

### Round 2's nine P1s, and where each is answered

| Finding | Answer |
|---|---|
| P1-1 `launch.command` checked as a basename, written verbatim | Task 7 `with_instance_harness` rewrites it to `/usr/local/bin/<basename>` on a **copy of the payload before `build_env` reads it**, so no consumer — present or future — can see the host path. `the_env_carries_the_instance_path_never_the_desktop_one` asserts the rendered env carries the instance path and that `/opt/homebrew` reaches no surface at all. The no-command default is corrected from `buzz-acp` (the supervisor) to `goose` (`crates/buzz-acp/src/config.rs:190-192`, the child `buzz-acp` actually execs). |
| P1-2 startup confirmation accepts a stale journal line | Task 12's `startup_script` bounds the journal query to the unit's current `_SYSTEMD_INVOCATION_ID` **and** to `--since @<epoch>` read on the instance immediately before `enable --now` (printed by the start round trip, parsed from a `---STARTEDAT---` section). `a_prior_runs_startup_line_cannot_confirm_this_attempt` asserts both the query scoping and that a live, active unit with zero matching lines stays `Pending`. |
| P1-3 `project` reaches a root drop-in unvalidated | Task 4 `parse_resource_name` — a closed `^[a-z][a-z0-9-]{0,61}[a-z0-9]$` grammar applied to `project`, `zone` and `instance`, before the CR/LF/NUL scan's own pass. Tests cover `zoop BUZZ_GCP_SECRET=evil`, embedded quotes, `%` specifiers, both length bounds, and CR/LF/NUL before trimming. Task 7 additionally asserts the rendered `Environment=` values contain nothing systemd's parser treats specially, so the grammar and its consumer cannot drift apart. |
| P1-4 per-agent destruction authorized by one sibling | Task 11 reports an `AgentFileState` per artifact; Task 12's `classify` refuses on the first present-but-not-ours among all four, naming that path; Task 9's `install_script` carries the target's own marker guard in the same shell as the write; Task 13's `removal_script` vetoes each `rm` with the header of the file it deletes and reports the ones it kept. Tests: marked env + unmarked drop-in, and a sibling belonging to another agent. |
| P1-5 Secret Manager verified once, mutated twice | Task 10 `describe_owned` immediately precedes each mutation with nothing between; `ALREADY_EXISTS` on create is a re-read-and-verify rather than a failure; a `Recorder` implementing the new `remote::Gcloud` trait asserts the exact command sequences, including that a secret swapped before the IAM grant never receives it. |
| P1-6 the shared-artifact tamper check | **Deleted.** No `content-hash` line, no `SharedMarker` type, no `sed` strip, no `tampered()`, no tamper classification arm, no tamper tests. Shared artifacts are write-if-absent-or-content-differs, comparing `sha256sum` of the installed file against `sha256_hex` of the rendered body — both hashes of real bytes. The rationale is recorded in Global Constraints, in Task 6's preamble, in `naming.rs`'s module doc, and in the spec §Two marker tiers. Deleting it removed the tamper verdict; round 3's P1-1 removed the *other* half of the upgrade lockout, which had survived inside `is_ours`. |
| P1-7 credential rotation silently fails on `RestartSame` | Task 7 folds `sha256` of the rendered secret body — hash, never value — into the create-intent, so a rotated `auth_tag` or API key diverges the intent and classifies as `FencedReplace`, which does re-store the secret. `a_rotated_credential_diverges_the_intent_without_exposing_it` asserts both halves, and round 3 adds `a_value_that_changes_side_diverges_the_intent` for the case where nothing changes except which half of the split a value lands in. |
| P1-8 concurrent deploys interleave | Task 12 takes a per-agent lease on the instance for the mutating window (`flock` making a lease record's read-modify-write atomic under a private `0700 root:root /run/buzz-backend-gcp`, TTL 900 s, released by a `Drop` guard), and a loser fails cleanly with `another operation on buzz-acp@<id>.service is already in progress`. Round 3's P1-4 moved the acquire **before** the observation the deploy acts on, and gave `operator::remove` the same lease. Round 4's P1-1 moved the *proof* inside each mutation's own shell, so the lease is not merely renewed between steps but re-established under `flock` at the instant of every write. The destructive fence is narrowed from "re-read, then stop four to six round trips before the writes" to a single remote shell that re-reads the marker tuple and the running state and performs the stop; every later write carries its own marker guard and its own lease gate. Task 15 Step 10 races two real deploys. |
| P1-9 partial writes are unmarked and unrecoverable | Task 9's `install_script` stages to `<path>.<token>.tmp` with the final mode and `mv`s into place, so no target path is ever observed half-written; `an_install_stages_and_renames_rather_than_writing_in_place` asserts the ordering, and the `trap` removes the staging file on every exit path including the ownership refusal. |

**Round 2's P2s.** Folded in: P2-1 (writer→reader loop closed in Task 13 Step 1 against `capacity`'s real output, prefix contract asserted at the source in Task 8, over-capacity smoke at Task 15 Step 9, README says the desktop will not show it), P2-2 (`list` unions three enumerations and `remove` proceeds without the env file), P2-3 (`shared_writes` runs on `RestartSame`), P2-4 (`FETCHER_UNIT` carries the full set, with three documented deviations, asserted offline in Task 7 and against the loaded unit in Task 15 Step 7), P2-7 (the relay-mesh golden asserts the exact sentence). Not folded in, and recorded as residual risk below: P2-5 (capacity computed once, acted on later) and P2-6 (the standing `buzz-acp.service` is counted but not fenced).

### Round 3's four P1s, and where each is answered

| Finding | Answer |
|---|---|
| P1-1 the upgrade lockout moved rather than died | Ownership is version-aware, not version-blind. Task 6 replaces the `is_ours` boolean with `naming::Ownership` — `Ours`, `OursButOlder(v)`, `OursButNewer(v)`, `NotOurs` — computed by one rule, `ownership_of`, for file headers and Secret Manager labels alike. `OursButOlder` is an **authorised upgrade target** everywhere: Task 12's `classify` forces `FencedReplace` on a per-agent artifact carrying it, Task 12's `shared_writes` takes the ordinary write-if-different path for a shared one, Task 10's `store` rolls the labels forward with `secrets update --update-labels` and then adds a version, Task 13's `verify_removable` accepts it, and Task 9's `marker_fn` compares the version with `-le` rather than `=` so the install that rewrites the file is not refused by its own fence. Refusal is reserved for `OursButNewer` — a downgrade this build cannot reason about — and for a foreign or absent `managed-by`, and the two get different sentences. The two tests that enshrined the old behaviour are gone, replaced by `an_older_binding_version_is_ours_and_an_upgrade_target`, `a_future_binding_version_is_refused_at_both_tiers`, `a_binding_version_that_is_not_a_number_is_not_ours`, Task 12's `a_prior_version_agent_is_upgraded_not_refused`, Task 10's `a_secret_from_an_older_binding_version_is_rolled_forward`, and Task 13's `a_prior_version_agent_is_still_removable`. |
| P1-2 `remove` stops a unit it has not proven it owns | Task 13's `remove` now opens with a **pre-stop gate**: one remote shell reads all four per-agent artifacts (`observe::agent_file_rows`, the same emitter the observer uses), and `verify_removable` requires at least one artifact to be present and **every** present one to be this provider's, at this binding version or older, and marked for `--pubkey` (round 4's P1-2 added the "every present one" half). It runs before `secrets::destroy` and before `removal_script`, so nothing is stopped, disabled or destroyed on the strength of a 12-hex prefix match. A refusal names the four paths it looked at and tells the operator how to reclaim the agent by hand. `an_env_absent_agent_with_a_marked_sibling_is_removable`, `an_agent_with_no_matching_marker_is_refused_before_anything_stops` and `a_half_migrated_agent_is_refused_before_anything_stops` cover the directions, and the second also asserts the refusal is reached before any `systemctl` verb is sent. |
| P1-3 the marker guard counts lines, not distinct patterns | `grep -c -F -x{needles}` compared against `required.len()` is gone from both sites. Task 9's `marker_fn` emits a `marker_ok` shell function that captures the header once and asserts **each needle on its own** with `printf '%s\n' "$h" \| grep -Fqx -- <needle>`, returning non-zero on the first miss, then checks the binding version numerically. Task 9's `marker_guard` and Task 13's `removal_script` both call it, so there is one implementation rather than two copies of the same bug. `a_header_that_repeats_one_marker_line_does_not_satisfy_the_guard` and `a_repeated_marker_line_does_not_authorize_a_delete` feed a header whose first lines duplicate `# managed-by:` and omit `# agent-pubkey-full:` — and, for the shared tier, `# scope:` — and require a refusal. |
| P1-4 the lease is acquired after the decision it protects | Task 12's `deploy` keeps a cheap **pre-lease look** — it costs no lease to refuse an unowned file — and then takes the lease and observes and classifies **again** under it, acting only on that second observation: the fenced stop, the shared writes, the secret, the per-agent writes, the trail, `enable --now` and (since round 4) the live no-op all read from it. The authoritative observation is `DeployLease::observe`, a method on the guard, so it is unreachable without one and the ordering is a compile-time property rather than a convention; its first act is `renew`, a verify-then-refresh of the owner record, so a lease lost between acquire and observe stops the deploy instead of feeding it stale state. `operator::remove` takes the same per-agent lease and holds it across the ownership scan, `secrets::destroy` and the removal script. `the_authoritative_observation_cannot_run_without_a_held_lease` asserts the verify-before-refresh ordering and the `LOCK_UNAVAILABLE` exit. |

**Round 3's P2s.** All four folded in. P2-1: `DEPLOY_LEASE_SECONDS` is raised to 900 s — above the desktop's 600 s provider timeout — **and** the owner record is refreshed with a verify-then-refresh that runs inside every mutation's own shell (round 4 moved it there from the standalone phase-boundary calls), which is the half that covers an unbounded direct CLI run; losing the lease stops the operation rather than being papered over. P2-2: `render::plan` refuses a `secret_body()` over `SECRET_MANAGER_MAX_PAYLOAD_BYTES` (64 KiB) in the **pure** phase, before a transport exists, and the core's 2 MiB test is kept and re-documented to say exactly what it does and does not claim. P2-3: the lease record moved to a private `install -d -m 0700 -o root -g root /run/buzz-backend-gcp`, a non-regular or non-root-owned record is treated as corrupt and replaced, and a future-dated timestamp is corrupt rather than fresh. P2-4: `a_value_that_changes_side_diverges_the_intent` holds the key set and the value multiset fixed and swaps which half of the split each value lands in.

### Round 4's three P1s and its P2, and where each is answered

| Finding | Answer |
|---|---|
| P1-1 the lease is renewed, but not *held*, across each mutation | Every remote mutation now carries the lease proof **in its own shell, under the same `flock` the owner record can only be changed under**. Task 9 adds `under_lease(agent, token, root_script)` — `sudo -n flock -w 5 -E 75 <lock> sh -c '<gate><root_script>'` — where the gate is a verify-then-refresh of the record; `install_script`, `append_script`, `Remote::run_fenced`, Task 12's `fenced_stop_script` and start step, and Task 13's `removal_script` all run inside it, and `Remote::{install, append, run_fenced}` take `&dyn Held`, whose only implementor is `DeployLease`. A lost lease therefore **prevents** the write: the `mv`, the `tee -a`, the `systemctl` and the `rm` never execute, and the caller gets `remote::lease_lost`. The stall the finding describes cannot defeat it, because a takeover requires the same `flock` — Task 12's "Why the lease is proved inside every mutation, and why not one long session" records the argument in full, including how the single-session alternative was evaluated and why it was rejected. Tests: `every_mutating_script_proves_the_lease_in_its_own_shell`, `the_lease_proof_and_the_mutation_cannot_be_separated`, `a_lost_lease_reads_as_a_lease_loss_not_an_ownership_refusal`. |
| P1-2 `remove` stops and destroys before noticing a mixed-version fleet | Task 13's `verify_removable` is now the same shape as `classify`: **refusals over every present artifact first**, authorisation second. A present artifact that is `OursButNewer`, `NotOurs`, ours-without-an-identity-line, or marked for a different pubkey refuses the whole `remove` — even when a sibling proves the requested pubkey — and `OursButOlder` is still accepted, so a uniform prior-version agent stays removable. The gate still runs before `secrets::destroy` and before `removal_script`, so nothing is stopped, disabled or destroyed. Tests: `a_half_migrated_agent_is_refused_before_anything_stops` (an older-or-current env for this pubkey beside a newer sibling), plus the four pre-existing ones, unchanged. |
| P1-3 a torn install is misread as healthy | Task 12's `classify` now lets `RestartSame` hold only when **every** expected per-agent artifact is present and its marker carries the **same** create-intent as the env marker's; anything else is `FencedReplace`. The refusal loop above it already establishes that every present artifact is actionable and names this pubkey, so the added condition is exactly "none missing, and all agreeing". Task 11's `agent_paths` doc — which said the siblings are "never interrogated for intent" — is rewritten to say what is now true. Tests: `a_torn_install_is_replaced_not_restarted`, `a_missing_sibling_is_replaced_not_restarted`, and the `obs` fixture is now a coherent four-artifact set rather than an env file with three absent siblings. |
| P2 a previewed-live agent is never rechecked | **Revalidated**, not accepted. The pre-lease look keeps its `Refuse` fast exit — a refusal is conservative, changes nothing, and should cost nobody a lease — but the `NoOp` early return is deleted, so a live no-op is decided from `DeployLease::observe` like every other verdict. The reasoning, and the bound on what remains stale, is in Task 12's "Why a live no-op is decided under the lease". |

### The three rejected findings

Each is recorded in Global Constraints with its evidence, and repeated at the code that would tempt a future reader to "fix" it: stdin forwarding in `remote.rs`'s module doc, `RuntimeDirectoryMode=0750` in `render.rs`'s `FETCHER_UNIT` doc comment, and `StrictHostKeyChecking` in both `ssh_argv`'s doc comment and its test. Global Constraints now also carries a fourth entry — the *deleted* tamper check — for the same reason: the next reader will otherwise "restore" it.

### Type consistency across tasks

- `buzz_backend_core::identity::AgentIdentity::{from_nsec, pubkey_hex, short12, short32}` — defined Task 2, used in Tasks 5, 6, 7, 12, 13. The Kubernetes newtype (Task 2 Step 7) exposes the five k8s methods its existing call sites need, unchanged.
- `AgentPayload` / `LaunchBlock` gain `Clone` in Task 1; Task 7's `with_instance_harness` is the only caller. Additive, so no k8s call site changes.
- `AuthoritativeInputs { generation, inactivity_seconds, max_env_bytes }` — defined Task 2; both existing call sites updated there (k8s `Some(1024 * 1024)`), new call site Task 7 (`None`).
- `Response::info(name, description, config_schema)` — defined Task 1; call sites Task 1 (kubernetes) and Task 4 (gcp).
- `harness::{fixture, run, run_with_env}` — defined Task 3; used Tasks 3, 4, 5, 7.
- `config::parse_resource_name(field, value)` — defined Task 4, called three times in `ProviderConfig::parse` and nowhere else; `parse_memory_max` is additionally read back by Task 11's reserved-memory sum.
- `naming::header_line(name, value)` — defined Task 6; the single renderer of every marker line, used by Task 7 (`agent_owner_marker`, `shared_owner_marker`), Task 9's tests, Task 11 (`observe_script`, `parse_agent_file_row`), and Task 13 (`listing_script`, `removal_script`). Every reader matches strings this produces.
- `Names` — defined Task 6 with both constructors; `new(&AgentIdentity)` used in Tasks 7 and 12; `from_pubkey_hex(&str)` in Task 13's `remove` and in Tasks 11 and 12's tests. Its eleven accessors are used in Tasks 7, 11 (via `agent_paths`), 12 (`unit`, `secret_unit`, `env_path`, `instance`), and 13 (all of them plus `dropin_dir`, `secret_dropin_dir`).
- `AgentMarker { pubkey_full, create_intent }` — defined Task 6; rendered Task 7, parsed Tasks 11 and 13, compared Task 12. `AgentMarker::parse` returns `Some` for a header this build may act on — its own version *or older* — and `None` otherwise, so a parsed marker is by construction actionable and the version question is answered separately by `agent_ownership`. `shared_marker()` / `shared_ownership()` replace the former `SharedMarker` type and the former `is_shared_marker` boolean: rendered Task 7, matched line-wise by Tasks 11 and 9.
- `RemoteFile { path, mode, body, owner_marker }` and `SharedArtifact { file, sha256 }` — defined Task 7; consumed Tasks 9 (`install`, `append`) and 12 (`shared_writes`, and both test constructors, which pass `owner_marker: Vec::new()` because those files are never installed). `owner_marker` carries the tier's **identity** lines only — `managed-by` plus `agent-pubkey-full` or `scope` — because the binding version is compared as an ordering by `marker_fn`, not matched as a literal line; an exact `# binding-version: N` needle is what made an install refuse the very file it was upgrading. Round 4 changed only the *signatures* that consume it: `Remote::install(&self, file, lease: &dyn Held)` and `Remote::append(&self, file, record, lease: &dyn Held)`, so the struct itself is unchanged and Task 7 needs no edit.
- `Plan { per_agent, shared, secret_env, create_intent, trail }` with `secret_body()` / `redacted_secret_body()` — defined Task 7; consumed Tasks 12 and 13. `trail` is a `RemoteFile` rather than the former `trail_header: String`, which is what lets `Remote::append` carry the same marker fence and the same lease gate as `Remote::install` without extra parameters.
- `Observation { systemd, markers, harness_installed, reserved_bytes, available_bytes }` and `MarkerState { env, siblings, shared }` with `agent_files()` — defined Task 11; consumed Task 12. `SHARED_PATHS` is the shared ordering between Tasks 11, 12 and 13, and matches the three `shared_artifact` calls in Task 7; `agent_paths` is the shared ordering between Task 11's script and its parser.
- `remote::Gcloud` — defined Task 9, implemented for `Remote` there, consumed by Task 10 (`&dyn Gcloud`) and implemented again by Task 10's test `Recorder`. `&Remote` coerces at every call site (Tasks 12 and 13).
- `remote::{OWNERSHIP_REFUSED, LOCK_UNAVAILABLE, MARKER_CHANGED, AGENT_STARTED, MARKER_SCAN_LINES}` — defined Task 9. `OWNERSHIP_REFUSED` is mapped by `Remote::install`/`append` in the same task; `LOCK_UNAVAILABLE` is mapped in **both** tasks now, because round 4 made it a per-mutation outcome rather than only an acquire/renew one — Task 9's `install`/`append` and Task 12's `fenced_stop`, start step and `DeployLease::renew`, and Task 13's removal step, all translate it through the one sentence `remote::lease_lost` renders; `MARKER_CHANGED` and `AGENT_STARTED` are Task 12's alone; `MARKER_SCAN_LINES` is used by Tasks 11, 12 and 13. `remote::marker_fn(required) -> String` is `pub(crate)`, defined Task 9 and consumed by Task 9's own `marker_guard` and Task 13's `removal_script` — one definition of "does the header in `$h` carry every needle, at a binding version this build may act on", because `grep -c` counting lines rather than patterns was the same defect in both.
- `remote::{Held, under_lease, lease_gate, lease_paths, lease_lost, LEASE_DIR, LEASE_FLOCK_WAIT_SECONDS}` — defined Task 9, added in round 4. `Held` has one method, `agent(&self) -> &str`, and exactly one implementor, `reconcile::DeployLease`; `Remote::{install, append, run_fenced}` all take `&dyn Held`, so "this write happens under a lease" is a signature rather than a comment — the same discipline round 3 applied to the authoritative observation. `under_lease(agent, token, root_script)` is the single place the `sudo -n flock -w W -E 75 <lock> sh -c '<gate><root_script>'` shape is spelled; it is consumed by Task 9's `install_script`/`append_script`/`Remote::run_fenced` and by Task 12's `renew_lease_script`, which is now nothing but `under_lease(instance, token, "")` — one definition of "prove the record still names us, then push its expiry out". The *policy* stays in Task 12: `DEPLOY_LEASE_SECONDS`, `lease_preamble`'s freshness arithmetic, `acquire_lease`, `release_lease_script` and the `Drop` guard. The split is deliberate — the proof is a transport concern because every mutating script this binding sends has to carry it, and the policy is the reconciler's because it is about deploys.
- `secrets::{verify_owned, store, destroy}` take `pubkey_full: &str` — defined Task 10; `deploy` passes `identity.pubkey_hex()` (Task 12), `remove` passes the operator's normalized value (Task 13). `naming::normalize_pubkey` (Task 6) is the single validation point. `verify_owned` returns `Result<Ownership, String>` so `store` can tell an upgrade from a steady state; `destroy` discards it.
- `naming::{Ownership, ownership_of, agent_ownership, shared_ownership, BINDING_VERSION_NUM}` — defined Task 6. `ownership_of` is the single rule turning a `managed-by`/`binding-version` pair into a verdict, fed by both file-header tiers (Task 6) and by Secret Manager's two labels (Task 10), so the four states have one definition per binding rather than one per storage medium. `Ownership` is consumed by Task 10 (`verify_owned`), Task 11 (`AgentFileState::ownership`, `SharedFileState::ownership`), Task 12 (`classify`) and Task 13 (`verify_removable`, which round 4 turned from a marker-only scan into the same four-arm match `classify` uses — so it is imported into `operator`'s **parent** module now, and the test module's `use crate::naming::{…}` drops it to avoid a duplicate import beside `use super::*`). `BINDING_VERSION_NUM` additionally reaches the shell, in Task 9's `marker_fn`, Task 12's `fenced_stop_script` and Task 13's `listing_script`, as the right-hand side of a `-le` comparison.
- `observe::{FIELD_HELPER, agent_file_rows, parse_agent_file_row}` — `pub(crate)`, defined Task 11 and consumed by Task 13's pre-stop ownership scan. Factored out of `observe_script` rather than re-spelled there: the row format is a contract between an emitter and a parser, and a second emitter is a second thing to keep in sync.
- `capacity::{GIB, warning_lines, trail_record, now_rfc3339, parse_reported_bytes}` — defined Task 8; used in Task 7's leak test, Task 11's parser, Task 12, and Task 13 (both `dry_run` and the writer→reader test).
- `reconcile::deploy(cfg: &ProviderConfig, agent: &AgentPayload)` — signature fixed in Task 5 and unchanged by Task 12, so `main.rs` is written once.

### Move and borrow re-check of every code block

Every block was walked again after this round's edits:

- Task 12 `deploy`: `action` is matched **by reference**, so the later `action == Action::FencedReplace` and `action != Action::RestartSame` still compile. Both sit inside the mutating block, beside the `obs` they were computed from. The block is an expression whose value is `started_at: u64`; `lease` is dropped at its closing brace and on every `?` inside it, and the two `return`s inside it exit `deploy` — dropping the lease — rather than yielding a block value, which is why the block's type stays `u64`. The pre-lease match now has one `return` (the refusal) and one fall-through arm covering `NoOp` as well, so the only `NoOp` success comes from inside the block. `plan.per_agent`, `plan.shared` and `plan.trail` are disjoint field borrows. `warnings` is borrowed by the `eprintln!` loop and then by `trail_record`, both shared. `authorizing_intent` is a `&str` borrowed out of `obs` and read by `fenced_stop` before any later statement touches `obs` mutably — nothing does. Every mutating call in the block passes `&lease` alongside the `&remote` it is invoked on; both are shared borrows and `lease` outlives all of them.
- Task 12 `DeployLease` holds `&'a Remote` and a `String`; `Drop` takes `&mut self` and calls `self.remote.run(…)`, which needs only `&Remote` — no aliasing conflict. `acquire_lease` returns the guard with the `remote` borrow it was given, so the lease cannot outlive the transport. `DeployLease::observe` and `DeployLease::renew` take `&self` and call `self.remote.run(…)`, another shared borrow, so they compose with the `&Remote` every other call in the window already holds. `impl Held for DeployLease<'_>` returns `&self.instance` as `&str`, borrowed for the call it is passed into and no longer; `remote.install(file, &lease)` therefore holds two shared borrows of the same `Remote` (one direct, one through the guard), which is fine. The struct is `pub(crate)` because `acquire_lease` is — a private type in a `pub(crate)` signature does not compile — and Task 13's `remove` names neither type: `let lease = acquire_lease(remote, &names)?;` and inference does the rest. `renew` is `pub(crate)` for the same reason; `observe` stays private because only `deploy` takes it.
- Task 12 `fenced_stop` matches `out.code` against four `const i32` patterns plus a guarded `_` and a binding arm; constants are legal patterns, the four are distinct values (75/76/77/78), and the arms are exhaustive because the last binds.
- Task 11 `parse_observation`: `agent_files.remove(0)` moves the env row out of the `Vec` before the remainder becomes `siblings`; every `section(...)` borrow of `stdout` ends at the `String` conversion. `MarkerState::agent_files` returns `impl Iterator<Item = &AgentFileState>` borrowing `&self`, which every caller consumes inside one expression.
- Task 10 `store` takes `&dyn Gcloud`; `labels`/`annotations`/`member` are locals whose `&str` views live to the end of their `gcloud` call. The `match describe(...)?` arms both end before the first mutation, so no borrow of the described value survives into it. `verify_owned` now returns `Result<Ownership, String>`; `Ownership` is `Copy`, so the `if let Ownership::OursButOlder(from)` binding in `store` copies out of a temporary rather than borrowing it, and `destroy` discards the value with a plain `?;`.
- Task 9 `Gcloud for Remote`: `pipe` is a named binding so the `BrokenPipe` branch can inspect the error, and it is `drop`ped explicitly before `wait_with_output` — without that the child would never see EOF.
- Task 9 `install_script`/`append_script`/`marker_guard`/`marker_fn`/`lease_gate`/`under_lease` are pure `String` builders; `staged` is computed before the two `format!`s that read it, and `critical` before the `format!` that `sq`-wraps it. `marker_fn` returns the `marker_ok` shell definition and `marker_guard` prepends it, so a caller cannot emit the call without the definition. `under_lease` takes `&str` and returns an owned `String`, so the temporary `(lock, owner)` pair from `lease_paths` is consumed inside it and nothing borrows out.
- Task 7 `plan`: `agent` is shadowed by the owned `with_instance_harness(agent)` copy and then borrowed as `&agent` for `build_env` — the parameter is not used after the shadow. `for (key, value) in env` consumes the map **after** the newline scan that borrows it. `secret_body` is computed before the hasher and read once. `owner_marker` is cloned into each of the three `per_agent` files and moved into `trail` last.
- Task 7 `feed` is a `FnMut` closure capturing `hasher` mutably; it is dropped before `hasher.finalize()` because its last call is in a `for` loop that ends first. **If the borrow checker objects, replace the closure with a plain `fn feed(hasher: &mut Sha256, label: &str, value: &str)` and pass `&mut hasher` at each call** — same behavior, no capture.
- Task 13 `run`: `Cli` is destructured first, so `command` moves while `project`/`zone`/`instance` remain owned locals.
- Task 13 `remove`: `resolve_target` returns owned `(Names, String)`, so the shadowed `pubkey` is a fresh `String`; `removal_script(&names, &pubkey)` borrows both after `secrets::destroy` has finished with them. The lease is bound to `lease` before the ownership scan and lives to the end of `remove` — it is *used* (one `renew` call plus the `&lease` every fenced call takes), so no leading underscore — and `secrets::destroy` and the removal script both run under it; `remote.run_fenced(&lease, …)` passes `&DeployLease` where `&dyn Held` is expected, which is an unsized coercion of a shared borrow, so it composes with the `&Remote` the same expression already holds. `files` is an owned `Vec<AgentFileState>`, so the `verify_removable(&files, …)` slice borrow ends before the `files.iter()` check below it.
- Task 5 `respond`: `raw` is borrowed by `refuse_relay_mesh(&raw)` and then **moved** into `serde_json::from_value(raw)` — the borrow has ended. Same shape as `crates/buzz-backend-kubernetes/src/main.rs:65-77`, which compiles.

### Remaining risk, stated honestly

1. **The mutating window is a sequence of leased writes, not one atomic transaction.** Round 4's P1-1 closed what made that unsafe: every remote mutation now proves the owner record still names this process **inside its own shell, under the same `flock` the record can only be changed under**, so a holder that stalls past the TTL and is legitimately overtaken has its next write *refused* rather than landed. What remains is that the window is still a sequence. A loser's writes are a **prefix**: it can have installed the shared templates and then be refused at the per-agent installs, and because its last write strictly precedes the winner's acquire in lock order, the winner's authoritative observation sees that prefix and reconciles it. That is convergence by re-entry, which is what [L2] asks for — not a rollback, and this revision does not invent one. A provider killed between acquire and release still blocks the next deploy of that agent for up to `DEPLOY_LEASE_SECONDS` (900 s), and a lease older than that is stolen rather than waited on.
2. **One mutation in the window cannot carry the lease: the Secret Manager version add.** `secrets::instance_service_account` and `secrets::store` are `gcloud` API calls issued from the operator's machine with the operator's own credentials, against a service the instance's lock knows nothing about — and they have to stay there, because the instance's service account deliberately holds per-secret `secretAccessor` only, so a compromised VM cannot mint or read another agent's secret. A `flock` on the VM cannot fence a call that never reaches the VM. The exposure is bounded on both sides: `deploy` renews immediately before it (the only standalone renewal left in the window, precisely because this is the only stretch no fenced mutation covers), and every step after it — the per-agent installs, the trail, `enable --now` — is fenced, so a provider that lost the lease during the call cannot start an agent against what it added. What can survive is a superseded `latest` version added by a loser whose `gcloud secrets versions add` stalled past the takeover. A *running* agent is unaffected: the fetcher unit reads `latest` once, at unit start. A later `RestartSame` would fetch it, and the next `FencedReplace` re-stores and clears it. Closing this properly needs the fetcher to pin a version the deploy names, which is a design change rather than a patch.
3. **Capacity is computed once and acted on up to 240 s later** (round 2, P2-5). `warning_lines` runs against the observation taken before the mutating window; another agent started in between is not counted. The warning is advisory and never vetoes, so the failure mode is an under-reported warning rather than a wrong action.
4. **The pre-existing non-instanced `buzz-acp.service` is counted in capacity but never fenced** (round 2, P2-6). It contributes its declared `MemoryMax` to `reserved_bytes` and is otherwise invisible to this provider — it carries no marker, is not named `buzz-acp@*`, and is itself non-conforming (`Restart=always`). Nothing this binding does can touch it; nothing it does protects it either.
5. **The startup poll costs one `gcloud` round trip every 5 s.** For a 240 s worst case that is up to 48 IAP tunnel setups. The mutating window itself is cheaper than round 3's — the lease gate refreshes the record from inside each mutation, so three of the four standalone renewals are gone — but it is still a dozen round trips. Correct but wasteful; a future revision should hold one SSH master connection open, which is also the only shape in which the lease could be a `flock` *held* across the whole window rather than re-proved per write (Task 12 records why that shape was not taken here).
6. **`list` enumerates from the instance, never from Secret Manager.** It now unions the env glob, `systemctl list-units`/`list-unit-files` and the drop-in directories, so a deleted env file no longer hides a running agent — but an agent whose *entire* on-instance footprint is gone while its secret survives is still invisible, and the operator has to run the `gcloud secrets list --filter="labels.managed_by=buzz-backend-gcp"` the README prints. The labels exist precisely so a follow-up can cross-check both sides; this revision does not.
7. **No test proves the fetcher script actually runs.** Its content is asserted byte-wise offline, but its behavior — arity refusal, shape refusal, the chmod/chown ordering that keeps `CapabilityBoundingSet=CAP_CHOWN` sufficient, the atomic rename — is only exercised by Task 15's live deploy succeeding. Task 15 Step 7 reads the loaded unit's directives back, which catches a documentation/unit divergence but not a script defect. A shellcheck step or a container-based script test would close it; neither is in scope here.
8. **The desktop still cannot render a success-path warning.** Task 8 works around it durably and Task 14's README tells the operator so, but closing it properly needs a `warning` field added to `docs/remote-agents.md:421` and rendered desktop-side. Recorded as design §Follow-ups item 4, deliberately not attempted here.
9. **A stale `<path>.<token>.tmp` can survive a hard connection loss.** The install script's `trap` removes it on every shell exit, but a connection dropped mid-write leaves the remote shell killed by SIGHUP with the staging file behind. It is inert — never at a target path, never loaded by systemd, and reaped from `/run` on reboot for the fetcher's own temp — but a `/etc` one persists until an operator removes it. This is the cost of P1-9's fix, and it is the right side of the trade: a stray `.tmp` is visible and harmless, a truncated unit file is neither.
10. **A future binding version is refused, and that refusal is one-directional.** Round 3's P1-1 made ownership version-aware: an artifact written at an *older* `binding-version` is an upgrade target, and one written at a *newer* one is a refusal in both `deploy` and `remove`. That is deliberate — a build that does not understand a layout must not overwrite or delete it — but it means an operator who installs a newer provider, deploys, and then rolls back to an older binary cannot remove those agents with the old binary. Round 4's P1-2 widens that refusal to a *mixed* fleet: one newer sibling now blocks `remove` for the whole agent, which is the point, because the alternative was stopping the newer deployment and destroying its secret while politely keeping its files. The recovery is the same in both cases and the refusal names it: run the newer binary's `remove`. There is no in-band downgrade path and this revision does not invent one.
11. **`list` reports a newer-version agent as unmarked.** `listing_script` recovers a pubkey from any header at a binding version this build may act on, which now includes older ones; a *newer* one is skipped, so the row appears with `<pubkey unknown>`. The rendered note says "no marker this build recognises" rather than "no marker", so the text is not a lie, but the operator still has to reach for `gcloud secrets list` or a newer binary. Distinguishing the two would need a fourth flag value on the row and a fourth render arm; the failure is visible and recoverable, so it is recorded rather than built.
