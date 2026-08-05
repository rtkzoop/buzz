# buzz-backend-gcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `buzz-backend-gcp`, a conforming Buzz backend provider that deploys managed agents as systemd units on the `buzz-agent` GCE VM, so the desktop's "Where to run" selector can target the team's remote server.

**Architecture:** Extract the substrate-neutral half of `buzz-backend-kubernetes` (wire types, three-tier env algorithm, identity derivation, golden fixtures) into a new `buzz-backend-core` crate; both providers depend on it. `buzz-backend-gcp` then adds a GCE binding: pure rendering of four remote artifacts, an IAP-SSH transport, Secret Manager key storage, and an I4 reconciler.

**Tech Stack:** Rust 2021 (workspace, rust-version 1.88.0), `serde`/`serde_json`, `nostr` (nsec decoding), `sha2`, `rand`, `clap` for the operator argv surface. No async runtime in the GCP crate — every remote call is a blocking `gcloud` subprocess.

**Design:** [`docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md`](../specs/2026-08-05-buzz-backend-gcp-design.md)
**Normative spec:** [`docs/remote-agents.md`](../../remote-agents.md)

## Global Constraints

- `docs/remote-agents.md` is normative. Every behavior traces to a clause; when in doubt, read it rather than inferring.
- **No `unsafe`.** No new `unwrap()`/`expect()` in production paths — use `?` and typed errors. (AGENTS.md)
- New public API needs doc comments. (AGENTS.md)
- Commit with `git commit -s`; the DCO check fails any commit without a `Signed-off-by` trailer. (AGENTS.md)
- Activate hermit before any git/cargo work: `. ./bin/activate-hermit`.
- Exit codes carry exactly one bit: 0 = the response on stdout is trustworthy, nonzero = failure regardless of stdout. Never encode structured meaning in a nonzero value. (L2 item 1)
- `Restart=always` and equivalents are non-conforming. (L1 item 5)
- Agent identity env is built from top-level payload fields, never from `env_vars`. (L2 item 3)
- The provider never accepts credentials through `provider_config`. (I2, L2 item 2)
- No secret material in any output — stdout, stderr, or error strings. (L2 item 5)
- Object names derive from the pubkey the provider decodes itself, never from a caller-supplied pubkey or a display name.
- Run `just fmt` and `cargo clippy --workspace --all-targets -- -D warnings` before each commit. Do not run the full `just ci` per task; run it once at the end.

---

## Task 1: Create `buzz-backend-core` with the wire types

**Files:**
- Create: `crates/buzz-backend-core/Cargo.toml`
- Create: `crates/buzz-backend-core/src/lib.rs`
- Create: `crates/buzz-backend-core/src/wire.rs`
- Modify: `Cargo.toml:2-32` (workspace members), `Cargo.toml:133-145` (internal crate deps)
- Modify: `crates/buzz-backend-kubernetes/Cargo.toml:13-33`
- Delete: `crates/buzz-backend-kubernetes/src/wire.rs`
- Modify: `crates/buzz-backend-kubernetes/src/main.rs:11-26`

**Interfaces:**
- Produces: `buzz_backend_core::wire::{Request, DeployRequest, AgentPayload, LaunchBlock, Response, InfoResponse, DeployResponse, ErrorResponse, PROTOCOL_VERSION}`. `Response::info(name: &'static str, description: &'static str, config_schema: serde_json::Value) -> Response` — **note the signature change**: the k8s version called a crate-local `config_schema()`, which cannot work in a shared crate.
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
repository.workspace = true
description = "Shared wire contract and launch-environment algorithm for Buzz backend providers (docs/remote-agents.md)"

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
nostr = { workspace = true }
rand = { workspace = true }
```

- [ ] **Step 2: Register the crate in the workspace**

In the root `Cargo.toml`, add to `members` (after `"crates/buzz-backend-kubernetes",`):

```toml
    "crates/buzz-backend-core",
```

And to `[workspace.dependencies]`, in the `# Internal crates` block:

```toml
buzz-backend-core = { path = "crates/buzz-backend-core" }
```

- [ ] **Step 3: Move `wire.rs` verbatim, then parameterize `info()`**

```bash
git mv crates/buzz-backend-kubernetes/src/wire.rs crates/buzz-backend-core/src/wire.rs
```

In the moved file, replace the `info()` constructor (it referenced `crate::config::config_schema()`, which no longer exists here):

```rust
    /// The provider's self-description (spec §Info). Pure — no substrate
    /// contact — because the desktop calls it to render the config form
    /// before any credentials are known to exist.
    ///
    /// Parameterized over the binding's identity: the six response fields are
    /// fixed by the contract, but `name`, `description`, and the schema are
    /// each binding's own.
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

Note `env!("CARGO_PKG_VERSION")` now resolves to `buzz-backend-core`'s version. Both crates use `version.workspace = true`, so the value is identical — but make it explicit by having callers pass nothing and documenting this. If the versions ever diverge, this becomes wrong; add a doc line saying so.

- [ ] **Step 4: Create the lib root**

`crates/buzz-backend-core/src/lib.rs`:

```rust
//! Shared implementation of the Buzz backend-provider contract
//! (`docs/remote-agents.md`).
//!
//! Everything here is substrate-neutral: the wire types, the three-tier
//! launch-environment algorithm, and identity derivation. Two conforming
//! providers must produce interchangeable launches, so these live in one
//! place rather than being reimplemented per binding.

pub mod wire;
```

- [ ] **Step 5: Point the Kubernetes crate at the shared types**

In `crates/buzz-backend-kubernetes/Cargo.toml`, add to `[dependencies]`:

```toml
buzz-backend-core = { workspace = true }
```

In `crates/buzz-backend-kubernetes/src/main.rs`, delete the `mod wire;` line and replace the import:

```rust
use buzz_backend_core::wire::{self, Request, Response};
```

Fix the `Response::info()` call site to pass the binding's identity:

```rust
        Request::Info => Response::info(
            "kubernetes",
            "Runs agents as pods in a Kubernetes cluster",
            crate::config::config_schema(),
        ),
```

Update every other `crate::wire::` path in the k8s crate to `buzz_backend_core::wire::`. Find them with:

```bash
grep -rn "crate::wire\|use crate::wire" crates/buzz-backend-kubernetes/src
```

- [ ] **Step 6: Verify the Kubernetes suite is still green**

Run: `cargo test -p buzz-backend-kubernetes`
Expected: PASS. This is the regression gate for the extraction — the k8s provider's behavior must not change at all.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -s -m "refactor(backend): extract wire contract into buzz-backend-core"
```

---

## Task 2: Move the env algorithm and identity derivation into the core

**Files:**
- Create: `crates/buzz-backend-core/src/env.rs`
- Create: `crates/buzz-backend-core/src/identity.rs`
- Modify: `crates/buzz-backend-core/src/lib.rs`
- Delete: `crates/buzz-backend-kubernetes/src/env.rs`
- Modify: `crates/buzz-backend-kubernetes/src/naming.rs` (keep the k8s label constants, drop the moved identity type)
- Modify: `crates/buzz-backend-kubernetes/src/main.rs`, `src/pod.rs`, `src/reconcile.rs` (import paths)

**Interfaces:**
- Produces:
  - `buzz_backend_core::env::build_env(agent: &AgentPayload, auth: AuthoritativeInputs<'_>) -> Result<BTreeMap<String, String>, String>`
  - `buzz_backend_core::env::AuthoritativeInputs { generation: &str, inactivity_seconds: Option<u64>, max_env_bytes: Option<usize> }` — **the third field is new**; Kubernetes passes `Some(1_048_576)`, GCP passes `None`.
  - `buzz_backend_core::env::{AUTHORITATIVE_KEYS, START_NONCE_KEY}`
  - `buzz_backend_core::identity::AgentIdentity` with `from_nsec(&str) -> Result<Self, String>`, `pubkey_hex(&self) -> &str`, `short12(&self) -> &str`, `short32(&self) -> &str`
  - `buzz_backend_core::identity::new_generation() -> String`
- Consumes: `wire::{AgentPayload, LaunchBlock}` from Task 1.

- [ ] **Step 1: Move the env module**

```bash
git mv crates/buzz-backend-kubernetes/src/env.rs crates/buzz-backend-core/src/env.rs
```

Change the import at the top from `use crate::wire::{AgentPayload, LaunchBlock};` to:

```rust
use crate::wire::{AgentPayload, LaunchBlock};
```

(unchanged — both are now `crate::` within `buzz-backend-core`).

- [ ] **Step 2: Replace the hardcoded Kubernetes size cap with a parameter**

Delete the `MAX_SECRET_BYTES` constant. Add the field to `AuthoritativeInputs`:

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
    /// an oversized env surfaces as a named provider error rather than a
    /// partial deploy. `None` when the substrate imposes no such limit —
    /// a systemd `EnvironmentFile` on a normal filesystem, for instance.
    pub max_env_bytes: Option<usize>,
}
```

Replace the trailing size check with:

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

Keep the `is_posix_env_key` validation unconditional: systemd `EnvironmentFile` parsing is no more forgiving of exotic keys than the kubelet, and a shared rule is one behavior to reason about.

- [ ] **Step 3: Extract `AgentIdentity` into the core**

Create `crates/buzz-backend-core/src/identity.rs`. Move the `AgentIdentity` struct, its `impl`, and `new_generation()` out of `crates/buzz-backend-kubernetes/src/naming.rs`, renaming the truncation accessors to be substrate-neutral:

```rust
//! Identity derivation (spec §Deploy State Machine step 0).
//!
//! The pubkey is decoded from `private_key_nsec` by the provider itself and
//! never taken from a caller-supplied field. Constructing [`AgentIdentity`] is
//! the only way to obtain the derived forms, so a caller-supplied pubkey
//! cannot reach a selector or an object name by any path.

use nostr::nips::nip19::FromBech32;

/// An agent identity the provider derived itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pubkey_hex: String,
    short12: String,
    short32: String,
}

impl AgentIdentity {
    /// Decode the secret key and derive the public identity from it.
    pub fn from_nsec(nsec: &str) -> Result<Self, String> {
        let keys = nostr::Keys::from_bech32(nsec.trim())
            .map_err(|_| "private_key_nsec is not a valid bech32 nsec".to_string())?;
        let pubkey_hex = keys.public_key().to_hex().to_ascii_lowercase();
        Ok(Self {
            short12: pubkey_hex[..12].to_string(),
            short32: pubkey_hex[..32].to_string(),
            pubkey_hex,
        })
    }

    /// Full 64-hex public key. The collision-free identity.
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// First 12 hex chars — short object names. Collision-*resistant* only;
    /// always pair it with a full-pubkey check before acting destructively.
    pub fn short12(&self) -> &str {
        &self.short12
    }

    /// First 32 hex chars — 128-bit selector keys.
    pub fn short32(&self) -> &str {
        &self.short32
    }
}

/// A fresh generation token: 8 lowercase hex chars from the OS RNG.
pub fn new_generation() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
```

Verify the exact `nostr` and `rand` API spellings against the deleted k8s code before writing — copy its call shapes rather than the ones above if they differ, since that code compiles today against the pinned versions.

- [ ] **Step 4: Export the new modules**

In `crates/buzz-backend-core/src/lib.rs`:

```rust
pub mod env;
pub mod identity;
pub mod wire;
```

- [ ] **Step 5: Update the Kubernetes crate**

`crates/buzz-backend-kubernetes/src/naming.rs` keeps only the k8s-specific constants (`MANAGED_BY`, `LABEL_*`, `ANNOTATION_*`, `BINDING_VERSION`) and re-exports the shared identity for its existing call sites:

```rust
pub use buzz_backend_core::identity::{new_generation, AgentIdentity};
```

Update the k8s pod/name builders that previously called methods on the local `AgentIdentity` to use `short12()`/`short32()`/`pubkey_hex()`. Pass `max_env_bytes: Some(1_048_576)` at its `build_env` call site to preserve today's behavior.

- [ ] **Step 6: Verify the Kubernetes suite is still green**

Run: `cargo test -p buzz-backend-kubernetes`
Expected: PASS, with no test modified. If a test needed changing, the extraction changed behavior — revert and find out why.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -s -m "refactor(backend): share env algorithm and identity derivation"
```

---

## Task 3: Share the golden wire fixtures and the pipe harness

**Files:**
- Create: `crates/buzz-backend-core/src/harness.rs`
- Move: `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/*` → `crates/buzz-backend-core/fixtures/provider-wire/`
- Modify: `crates/buzz-backend-kubernetes/tests/wire_fixtures.rs`
- Modify: `crates/buzz-backend-core/src/lib.rs`

**Interfaces:**
- Produces:
  - `buzz_backend_core::harness::fixtures_dir() -> PathBuf` — resolves `<core crate>/fixtures/provider-wire`.
  - `buzz_backend_core::harness::run(binary: &Path, request: &str) -> (String, i32)` — writes one request to the binary's stdin, closes it, returns `(stdout, exit_code)`.
- Consumes: nothing.

**Why the fixtures move:** they are the arbiter of a contract shared with the desktop, not a Kubernetes asset. A second provider copying them would let the two drift.

- [ ] **Step 1: Move the fixture directory**

```bash
mkdir -p crates/buzz-backend-core/fixtures
git mv crates/buzz-backend-kubernetes/tests/fixtures/provider-wire \
       crates/buzz-backend-core/fixtures/provider-wire
```

- [ ] **Step 2: Write the shared harness**

`crates/buzz-backend-core/src/harness.rs`:

```rust
//! Test harness for driving a provider binary over a real pipe.
//!
//! Not `#[cfg(test)]`: this is consumed by the integration tests of *other*
//! crates, which compile against the normal library.
//!
//! Providers are tested through the built binary rather than an in-process
//! call because the contract is `stdin -> one JSON object on stdout -> exit
//! code`, and an in-process test skips the three things that actually break:
//! writing nothing, writing two objects, or signalling through the exit code.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The shared golden fixture directory.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/provider-wire")
}

/// Read one fixture by file name.
pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures_dir().join(name))
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// Feed one request to a provider binary; return `(stdout, exit code)`.
pub fn run(binary: &Path, request: &str) -> (String, i32) {
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", binary.display()));
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(request.as_bytes())
        .expect("write request");
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}
```

Export it from `lib.rs`: `pub mod harness;`

- [ ] **Step 3: Repoint the Kubernetes fixture test**

In `crates/buzz-backend-kubernetes/tests/wire_fixtures.rs`, delete the local `fixtures()`, `read()`, and `run()` helpers and use the shared ones:

```rust
use buzz_backend_core::harness::{fixture, run};

fn binary() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_BIN_EXE_buzz-backend-kubernetes")).to_path_buf()
}
```

Replace each `run(x)` call with `run(&binary(), x)` and each `read(x)` with `fixture(x)`.

Add `buzz-backend-core = { workspace = true }` to the k8s crate's `[dev-dependencies]` if the `[dependencies]` entry is not already visible to integration tests (it is, but be explicit if the build complains).

- [ ] **Step 4: Verify**

Run: `cargo test -p buzz-backend-kubernetes`
Expected: PASS, same test count as before.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "refactor(backend): share provider-wire fixtures and pipe harness"
```

---

## Task 4: `buzz-backend-gcp` skeleton — `info` and the config schema

**Files:**
- Create: `crates/buzz-backend-gcp/Cargo.toml`
- Create: `crates/buzz-backend-gcp/src/main.rs`
- Create: `crates/buzz-backend-gcp/src/config.rs`
- Create: `crates/buzz-backend-gcp/tests/wire.rs`
- Modify: root `Cargo.toml` members + internal deps

**Interfaces:**
- Produces: `config::config_schema() -> serde_json::Value`; `config::ProviderConfig { project, zone, instance, memory_max, cpu_quota, inactivity_seconds }` with `ProviderConfig::parse(&serde_json::Value) -> Result<Self, String>`; `respond(input: &str) -> Response`.
- Consumes: `buzz_backend_core::wire::{Request, Response}`.

- [ ] **Step 1: Write the failing wire test**

`crates/buzz-backend-gcp/tests/wire.rs`:

```rust
use buzz_backend_core::harness::{fixture, run};
use std::path::{Path, PathBuf};

fn binary() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_buzz-backend-gcp")).to_path_buf()
}

#[test]
fn info_carries_the_contract_fields() {
    let (stdout, code) = run(&binary(), &fixture("info.request.json"));
    assert_eq!(code, 0, "info must exit 0; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON object");

    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["name"], serde_json::json!("gcp"));
    assert_eq!(v["protocol_version"], serde_json::json!(1));
    assert!(v["version"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["description"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["config_schema"].is_object());

    // The desktop rejects any field outside this set (backend.rs:48-63).
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec!["config_schema", "description", "name", "ok", "protocol_version", "version"]
    );
}

#[test]
fn config_schema_names_no_credential() {
    let (stdout, _) = run(&binary(), &fixture("info.request.json"));
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // I2 / backend.rs:536-566: the desktop refuses any config key whose words
    // include one of these, so a schema advertising one is dead on arrival.
    let forbidden = ["secret", "password", "token", "key", "credential"];
    for name in v["config_schema"]["properties"].as_object().unwrap().keys() {
        let lowered = name.to_ascii_lowercase();
        for word in forbidden {
            assert!(!lowered.contains(word), "config key {name} looks like a credential");
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
repository.workspace = true
description = "GCE/systemd backend provider for Buzz remote agents (docs/remote-agents.md)"

[[bin]]
name = "buzz-backend-gcp"
path = "src/main.rs"

[dependencies]
buzz-backend-core = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
clap = { version = "4", features = ["derive"] }
```

Root `Cargo.toml`: add `"crates/buzz-backend-gcp",` to `members` and
`buzz-backend-gcp = { path = "crates/buzz-backend-gcp" }` to the internal deps block.

- [ ] **Step 4: Write the config schema**

`crates/buzz-backend-gcp/src/config.rs`:

```rust
//! `provider_config` schema and parsing (spec §`provider_config` v1 fields).
//!
//! Every field here is non-secret by construction: I2 forbids a provider from
//! accepting credentials through config, and the desktop independently rejects
//! any key that looks like one.

use serde_json::json;

pub const DEFAULT_PROJECT: &str = "zoop-innovation";
pub const DEFAULT_ZONE: &str = "asia-south1-a";
pub const DEFAULT_INSTANCE: &str = "buzz-agent";
pub const DEFAULT_MEMORY_MAX: &str = "2G";
pub const DEFAULT_CPU_QUOTA: &str = "150%";
/// Two hours, matching the Kubernetes binding's default.
pub const DEFAULT_INACTIVITY_SECONDS: u64 = 7200;

/// The JSON Schema the desktop renders into the "Where to run" form.
pub fn config_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "project":  { "type": "string", "default": DEFAULT_PROJECT,
                          "description": "GCP project containing the instance" },
            "zone":     { "type": "string", "default": DEFAULT_ZONE,
                          "description": "Compute zone of the instance" },
            "instance": { "type": "string", "default": DEFAULT_INSTANCE,
                          "description": "Instance the agent runs on" },
            "memory_max": { "type": "string", "default": DEFAULT_MEMORY_MAX,
                            "description": "systemd MemoryMax for this agent" },
            "cpu_quota":  { "type": "string", "default": DEFAULT_CPU_QUOTA,
                            "description": "systemd CPUQuota for this agent" },
            "inactivity_seconds": { "type": "integer", "minimum": 0,
                                    "default": DEFAULT_INACTIVITY_SECONDS,
                                    "description":
              "Exit after this many seconds with no dispatched events. 0 means no bound." }
        },
        "required": ["project", "zone", "instance"],
        "additionalProperties": false
    })
}

/// Parsed, defaulted provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub project: String,
    pub zone: String,
    pub instance: String,
    pub memory_max: String,
    pub cpu_quota: String,
    /// `None` encodes the indefinite opt-in (`inactivity_seconds: 0`).
    pub inactivity_seconds: Option<u64>,
}

impl ProviderConfig {
    /// Parse with defaults. Absent is not an error: the desktop may send `{}`
    /// when the user accepted every schema default.
    pub fn parse(value: &serde_json::Value) -> Result<Self, String> {
        let s = |key: &str, default: &str| -> String {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .unwrap_or(default)
                .to_string()
        };
        let inactivity = match value.get("inactivity_seconds") {
            None | Some(serde_json::Value::Null) => Some(DEFAULT_INACTIVITY_SECONDS),
            Some(v) => {
                let n = v
                    .as_u64()
                    .ok_or_else(|| "inactivity_seconds must be a non-negative integer".to_string())?;
                // 0 is a blessed value meaning "no bound" and MUST NOT be
                // rejected here (spec §Auto-Stop). Whether this binding can
                // *honor* it is a separate question, answered in deploy.
                if n == 0 { None } else { Some(n) }
            }
        };
        Ok(Self {
            project: s("project", DEFAULT_PROJECT),
            zone: s("zone", DEFAULT_ZONE),
            instance: s("instance", DEFAULT_INSTANCE),
            memory_max: s("memory_max", DEFAULT_MEMORY_MAX),
            cpu_quota: s("cpu_quota", DEFAULT_CPU_QUOTA),
            inactivity_seconds: inactivity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_takes_every_default() {
        let c = ProviderConfig::parse(&json!({})).unwrap();
        assert_eq!(c.project, DEFAULT_PROJECT);
        assert_eq!(c.instance, DEFAULT_INSTANCE);
        assert_eq!(c.inactivity_seconds, Some(DEFAULT_INACTIVITY_SECONDS));
    }

    #[test]
    fn zero_inactivity_is_the_indefinite_opt_in_not_an_error() {
        let c = ProviderConfig::parse(&json!({"inactivity_seconds": 0})).unwrap();
        assert_eq!(c.inactivity_seconds, None);
    }

    #[test]
    fn a_non_integer_inactivity_is_rejected() {
        assert!(ProviderConfig::parse(&json!({"inactivity_seconds": "soon"})).is_err());
    }
}
```

- [ ] **Step 5: Write `main.rs` with dispatch only**

```rust
//! GCE/systemd backend provider for Buzz remote agents
//! (spec `docs/remote-agents.md`).
//!
//! One process per operation: read exactly one JSON request from stdin, write
//! exactly one JSON response to stdout, exit. The exit code carries exactly
//! one bit — 0 for a response that was produced, 1 for a failure to produce
//! one. Outcomes live in the response's `ok` field, never in the exit value.

mod config;

use buzz_backend_core::wire::{Request, Response};
use std::io::Read;

fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        // No trustworthy response can be produced: the one nonzero case.
        std::process::exit(1);
    }
    let response = respond(&input);
    match serde_json::to_string(&response) {
        Ok(json) => println!("{json}"),
        Err(_) => std::process::exit(1),
    }
}

/// Produce the single response for one request. Separated from `main` so the
/// whole dispatch is testable without a process.
fn respond(input: &str) -> Response {
    let request: Request = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(e) => return Response::error(format!("invalid request: {e}")),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_op_produces_an_in_band_error() {
        let r = respond(r#"{"op":"teleport"}"#);
        let v = serde_json::to_value(r).unwrap();
        assert_eq!(v["ok"], serde_json::json!(false));
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS (3 integration + 4 unit). The deploy fixtures are not exercised yet.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): provider skeleton with info and config schema"
```

---

## Task 5: Naming and the management marker

**Files:**
- Create: `crates/buzz-backend-gcp/src/naming.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod naming;`)

**Interfaces:**
- Produces: `naming::Names::new(&AgentIdentity) -> Names` with fields/accessors `unit()`, `instance()`, `env_path()`, `dropin_dir()`, `dropin_path()`, `secret_name()`, `runtime_dir()`; `naming::Marker { pubkey_full, create_intent }` with `render() -> String` and `parse(&str) -> Option<Marker>`; consts `MANAGED_BY`, `BINDING_VERSION`.
- Consumes: `buzz_backend_core::identity::AgentIdentity`.

- [ ] **Step 1: Write the failing test**

Append to `crates/buzz-backend-gcp/src/naming.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use buzz_backend_core::identity::AgentIdentity;

    // The fixture nsec from the shared golden payloads.
    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    fn names() -> Names {
        Names::new(&AgentIdentity::from_nsec(NSEC).unwrap())
    }

    #[test]
    fn every_path_is_derived_from_the_pubkey_not_a_display_name() {
        let n = names();
        let id = AgentIdentity::from_nsec(NSEC).unwrap();
        let short = id.short12();
        assert_eq!(n.unit(), format!("buzz-acp@{short}.service"));
        assert_eq!(n.env_path(), format!("/etc/buzz/acp-{short}.env"));
        assert_eq!(n.secret_name(), format!("buzz-agent-{short}-private-key"));
        assert_eq!(n.runtime_dir(), format!("/run/buzz-acp-{short}"));
        assert_eq!(
            n.dropin_path(),
            format!("/etc/systemd/system/buzz-acp@{short}.service.d/agent.conf")
        );
    }

    #[test]
    fn a_marker_round_trips() {
        let m = Marker {
            pubkey_full: "ab".repeat(32),
            create_intent: "c0ffee".to_string(),
        };
        let parsed = Marker::parse(&m.render()).expect("parses");
        assert_eq!(parsed, m);
    }

    #[test]
    fn an_unmarked_file_yields_no_marker() {
        assert!(Marker::parse("# just some file\nFOO=bar\n").is_none());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p buzz-backend-gcp naming`
Expected: FAIL — `cannot find type Names in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/buzz-backend-gcp/src/naming.rs`:

```rust
//! Object naming and the management marker (spec §Naming and the Management
//! Marker).
//!
//! Names come from [`AgentIdentity`], which can only be constructed by
//! decoding the nsec — so a caller-supplied pubkey or a mutable display name
//! can never reach a path this provider writes to or deletes.

use buzz_backend_core::identity::AgentIdentity;

/// The management marker's identity half. No file without this may be
/// destroyed by this provider (the auto-repair fence).
pub const MANAGED_BY: &str = "buzz-backend-gcp";

/// Schema version of the artifact layout. Bump when the unit/env shape changes
/// in a way an older provider would mishandle.
pub const BINDING_VERSION: &str = "1";

/// Every path and name one agent implies.
#[derive(Debug, Clone)]
pub struct Names {
    instance: String,
}

impl Names {
    pub fn new(identity: &AgentIdentity) -> Self {
        Self { instance: identity.short12().to_string() }
    }

    /// The systemd instance name (`%i`).
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Full unit name — also the `agent_id` returned to the desktop.
    pub fn unit(&self) -> String {
        format!("buzz-acp@{}.service", self.instance)
    }

    pub fn env_path(&self) -> String {
        format!("/etc/buzz/acp-{}.env", self.instance)
    }

    pub fn dropin_dir(&self) -> String {
        format!("/etc/systemd/system/buzz-acp@{}.service.d", self.instance)
    }

    pub fn dropin_path(&self) -> String {
        format!("{}/agent.conf", self.dropin_dir())
    }

    pub fn secret_name(&self) -> String {
        format!("buzz-agent-{}-private-key", self.instance)
    }

    pub fn runtime_dir(&self) -> String {
        format!("/run/buzz-acp-{}", self.instance)
    }
}

/// The header this provider writes into every file it creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// Full 64-hex pubkey. The truncated instance name is only
    /// collision-resistant; this is what makes acting on it safe.
    pub pubkey_full: String,
    /// Fingerprint of the rendered spec, for divergence detection.
    pub create_intent: String,
}

impl Marker {
    pub fn render(&self) -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n\
             # binding-version: {BINDING_VERSION}\n\
             # agent-pubkey-full: {}\n\
             # create-intent: {}\n",
            self.pubkey_full, self.create_intent
        )
    }

    /// Parse a marker from a file body. Returns `None` when the file is not
    /// ours — which is a refusal to act, never a licence to overwrite.
    pub fn parse(body: &str) -> Option<Self> {
        let field = |name: &str| -> Option<String> {
            body.lines()
                .find_map(|l| l.strip_prefix(&format!("# {name}: ")))
                .map(|v| v.trim().to_string())
        };
        if field("managed-by")? != MANAGED_BY {
            return None;
        }
        Some(Self {
            pubkey_full: field("agent-pubkey-full")?,
            create_intent: field("create-intent")?,
        })
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp naming`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): pubkey-derived naming and management marker"
```

---

## Task 6: `render.rs` — the four remote artifacts

**Files:**
- Create: `crates/buzz-backend-gcp/src/render.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod render;`)

**Interfaces:**
- Produces: `render::RemoteFile { path: String, mode: &'static str, body: String }`; `render::plan(agent: &AgentPayload, cfg: &ProviderConfig, names: &Names, identity: &AgentIdentity, generation: &str) -> Result<Plan, String>` where `Plan { files: Vec<RemoteFile>, secret_body: String, create_intent: String }`.
- Consumes: `buzz_backend_core::env::{build_env, AuthoritativeInputs}`, `naming::{Names, Marker}`, `config::ProviderConfig`.

`secret_body` is kept out of `files` deliberately: it goes to Secret Manager, never to a file this provider installs over SSH.

- [ ] **Step 1: Write the failing tests**

`crates/buzz-backend-gcp/src/render.rs`, test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use buzz_backend_core::identity::AgentIdentity;
    use buzz_backend_core::wire::DeployRequest;

    fn request() -> DeployRequest {
        let raw = buzz_backend_core::harness::fixture("deploy-full-launch.request.json");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        serde_json::from_value(v).unwrap()
    }

    fn plan_for(req: &DeployRequest) -> Plan {
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = ProviderConfig::parse(&req.provider_config).unwrap();
        plan(&req.agent, &cfg, &names, &identity, "deadbeef").unwrap()
    }

    fn file<'a>(p: &'a Plan, suffix: &str) -> &'a RemoteFile {
        p.files.iter().find(|f| f.path.ends_with(suffix)).expect(suffix)
    }

    #[test]
    fn the_unit_never_restarts_an_intentional_exit() {
        let p = plan_for(&request());
        let unit = &file(&p, "buzz-acp@.service").body;
        assert!(unit.contains("Restart=no"), "bounded lifetime must be Restart=no");
        assert!(
            !unit.contains("Restart=always"),
            "L1 item 5: Restart=always is non-conforming — it resurrects what !shutdown terminates"
        );
    }

    #[test]
    fn the_harness_receives_the_termination_signal_directly() {
        let unit = plan_for(&request());
        let body = &file(&unit, "buzz-acp@.service").body;
        // No shell wrapper: a wrapper would swallow SIGTERM (L1 item 3).
        assert!(body.contains("ExecStart=/usr/local/bin/buzz-acp\n"));
        assert!(body.contains("TimeoutStopSec=120"));
    }

    #[test]
    fn an_owner_is_always_present_in_the_environment() {
        let p = plan_for(&request());
        let env = &file(&p, ".env").body;
        assert!(
            env.contains("BUZZ_AUTH_TAG=") || env.contains("BUZZ_ACP_AGENT_OWNER="),
            "without an owner the harness drops every event with only a WARN"
        );
    }

    #[test]
    fn the_nsec_never_lands_in_an_installed_file() {
        let req = request();
        let p = plan_for(&req);
        for f in &p.files {
            assert!(
                !f.body.contains(&req.agent.private_key_nsec),
                "{} leaked the nsec onto the boot disk",
                f.path
            );
        }
        assert!(p.secret_body.contains("BUZZ_PRIVATE_KEY="));
        assert!(p.secret_body.contains("NOSTR_PRIVATE_KEY="));
    }

    #[test]
    fn every_installed_file_carries_the_marker() {
        let p = plan_for(&request());
        for f in &p.files {
            assert!(Marker::parse(&f.body).is_some(), "{} has no marker", f.path);
        }
    }

    #[test]
    fn the_dropin_carries_the_configured_limits() {
        let p = plan_for(&request());
        let dropin = &file(&p, "agent.conf").body;
        assert!(dropin.contains("MemoryMax=2G"));
        assert!(dropin.contains("CPUQuota=150%"));
    }

    #[test]
    fn env_values_are_quoted_so_spaces_survive_systemd_parsing() {
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .env
            .insert("WITH_SPACE".into(), "a b".into());
        let p = plan_for(&req);
        assert!(file(&p, ".env").body.contains("WITH_SPACE=\"a b\""));
    }

    #[test]
    fn a_divergent_spec_produces_a_different_create_intent() {
        let a = plan_for(&request());
        let mut req = request();
        req.agent.launch.as_mut().unwrap().policy_env
            .insert("BUZZ_ACP_MODEL".into(), "different".into());
        let b = plan_for(&req);
        assert_ne!(a.create_intent, b.create_intent);
    }

    #[test]
    fn the_generation_does_not_perturb_the_create_intent() {
        // Otherwise every deploy looks divergent and the reconciler would
        // replace a healthy unit on each Start.
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = ProviderConfig::parse(&req.provider_config).unwrap();
        let a = plan(&req.agent, &cfg, &names, &identity, "aaaaaaaa").unwrap();
        let b = plan(&req.agent, &cfg, &names, &identity, "bbbbbbbb").unwrap();
        assert_eq!(a.create_intent, b.create_intent);
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p buzz-backend-gcp render`
Expected: FAIL — `cannot find function plan in this scope`.

- [ ] **Step 3: Implement the renderer**

```rust
//! Pure rendering of the remote artifacts (spec §Remote Artifacts).
//!
//! No IO: a payload in, the exact bytes of every file out. All the
//! conformance-critical decisions — supervision policy, the secret split, the
//! marker — are visible here and testable without touching GCP.

use crate::config::ProviderConfig;
use crate::naming::{Marker, Names};
use buzz_backend_core::env::{build_env, AuthoritativeInputs};
use buzz_backend_core::identity::AgentIdentity;
use buzz_backend_core::wire::AgentPayload;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Identity variables, which live in Secret Manager rather than on disk.
const SECRET_KEYS: [&str; 2] = ["BUZZ_PRIVATE_KEY", "NOSTR_PRIVATE_KEY"];

/// A file to install on the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    pub path: String,
    /// Octal mode string passed to `install -m`.
    pub mode: &'static str,
    pub body: String,
}

/// Everything one deploy needs to write.
#[derive(Debug, Clone)]
pub struct Plan {
    pub files: Vec<RemoteFile>,
    /// Body of the tmpfs env file, stored in Secret Manager. Never installed
    /// directly and never logged.
    pub secret_body: String,
    /// Fingerprint of the rendered spec, excluding the generation token.
    pub create_intent: String,
}

/// Quote a value for a systemd `EnvironmentFile`.
///
/// systemd accepts double-quoted values with backslash escapes. Quoting
/// unconditionally is simpler to reason about than deciding per value, and
/// costs nothing.
fn quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn env_file_body(env: &BTreeMap<String, String>, marker: &str) -> String {
    let mut out = String::from(marker);
    for (k, v) in env {
        out.push_str(&format!("{k}={}\n", quote(v)));
    }
    out
}

/// Render every artifact for one deploy.
pub fn plan(
    agent: &AgentPayload,
    cfg: &ProviderConfig,
    names: &Names,
    identity: &AgentIdentity,
    generation: &str,
) -> Result<Plan, String> {
    // v1 supervises bounded lifetimes only. `inactivity_seconds: 0` is a legal
    // request, but honoring it needs `Restart=on-failure`, and the spec
    // forbids shipping that until the harness clean-exit contract is pinned
    // (Known Defect 6) — an undefended exit convention would let the
    // supervisor restart agents that exited on purpose, violating I5.
    let Some(inactivity) = cfg.inactivity_seconds else {
        return Err(
            "inactivity_seconds: 0 (indefinite lifetime) is not supported by this binding \
             yet: it requires Restart=on-failure, which the spec withholds until the \
             harness clean-exit contract is pinned. Set a positive bound."
                .to_string(),
        );
    };

    let mut env = build_env(
        agent,
        AuthoritativeInputs {
            generation,
            inactivity_seconds: Some(inactivity),
            // A systemd EnvironmentFile on a 38 GB disk has no meaningful cap.
            max_env_bytes: None,
        },
    )?;

    // Split by sensitivity. Precedence is already resolved; this moves values,
    // it does not change them.
    let mut secret_env = BTreeMap::new();
    for key in SECRET_KEYS {
        if let Some(value) = env.remove(key) {
            secret_env.insert(key.to_string(), value);
        }
    }

    // The intent fingerprint covers everything that decides the unit's
    // behavior, minus the generation (which changes on every attempt) and
    // minus secret values (which must not be reconstructible from a marker a
    // reader can see).
    let mut hasher = Sha256::new();
    for (k, v) in &env {
        hasher.update(k.as_bytes());
        hasher.update([0]);
        hasher.update(v.as_bytes());
        hasher.update([0]);
    }
    for key in secret_env.keys() {
        hasher.update(key.as_bytes());
        hasher.update([0]);
    }
    hasher.update(cfg.memory_max.as_bytes());
    hasher.update(cfg.cpu_quota.as_bytes());
    let create_intent = format!("{:x}", hasher.finalize());

    let marker = Marker {
        pubkey_full: identity.pubkey_hex().to_string(),
        create_intent: create_intent.clone(),
    }
    .render();

    let instance = names.instance();
    let files = vec![
        RemoteFile {
            path: names.env_path(),
            mode: "0600",
            body: env_file_body(&env, &marker),
        },
        RemoteFile {
            path: "/etc/systemd/system/buzz-acp@.service".to_string(),
            mode: "0644",
            body: format!("{marker}{}", template_unit()),
        },
        RemoteFile {
            path: "/etc/systemd/system/buzz-acp-secret@.service".to_string(),
            mode: "0644",
            body: format!("{marker}{}", secret_unit()),
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
            path: "/usr/local/sbin/buzz-acp-fetch-key".to_string(),
            mode: "0755",
            body: fetch_key_script(&marker),
        },
    ];

    let _ = instance;
    Ok(Plan {
        files,
        secret_body: env_file_body(&secret_env, ""),
        create_intent,
    })
}

/// The shared template unit.
///
/// Mirrors the hardened unit the deployment already runs, with three
/// deliberate differences: `Restart=no` (I5 — a supervisor must never
/// resurrect an intentional exit), `TimeoutStopSec=120` (I3 — room for
/// in-flight drain and presence->offline before SIGKILL), and the second
/// `EnvironmentFile` holding the tmpfs-materialized identity.
fn template_unit() -> &'static str {
    "[Unit]\n\
     Description=Buzz ACP agent harness (%i)\n\
     After=network-online.target buzz-block-metadata-agent.service buzz-acp-secret@%i.service\n\
     Wants=network-online.target\n\
     Requires=buzz-block-metadata-agent.service buzz-acp-secret@%i.service\n\
     \n\
     [Service]\n\
     Type=simple\n\
     User=buzzacp\n\
     Group=buzzacp\n\
     WorkingDirectory=/var/lib/buzzacp\n\
     EnvironmentFile=/etc/buzz/acp-%i.env\n\
     EnvironmentFile=/run/buzz-acp-%i/secret.env\n\
     ExecStart=/usr/local/bin/buzz-acp\n\
     Restart=no\n\
     TimeoutStopSec=120\n\
     NoNewPrivileges=true\n\
     PrivateTmp=true\n\
     PrivateDevices=true\n\
     ProtectSystem=strict\n\
     ProtectHome=true\n\
     ProtectKernelTunables=true\n\
     ProtectKernelModules=true\n\
     ProtectControlGroups=true\n\
     RestrictSUIDSGID=true\n\
     RestrictRealtime=true\n\
     LockPersonality=true\n\
     CapabilityBoundingSet=\n\
     AmbientCapabilities=\n\
     ReadWritePaths=/var/lib/buzzacp\n\
     RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
     IPAddressDeny=169.254.169.254/32\n\
     TasksMax=512\n\
     StandardOutput=journal\n\
     StandardError=journal\n\
     \n\
     [Install]\n\
     WantedBy=multi-user.target\n"
}

/// The key fetcher.
///
/// A separate unit, not an `ExecStartPre=+`, because the agent unit's
/// `IPAddressDeny=169.254.169.254/32` is a cgroup-wide filter: it blocks every
/// process in that unit including root, so a metadata-authenticated gcloud
/// call cannot run inside it.
fn secret_unit() -> &'static str {
    "[Unit]\n\
     Description=Materialize the Buzz agent key for %i\n\
     After=network-online.target\n\
     Wants=network-online.target\n\
     \n\
     [Service]\n\
     Type=oneshot\n\
     RemainAfterExit=yes\n\
     RuntimeDirectory=buzz-acp-%i\n\
     RuntimeDirectoryMode=0750\n\
     ExecStart=/usr/local/sbin/buzz-acp-fetch-key %i\n"
}

fn fetch_key_script(marker: &str) -> String {
    format!(
        "#!/bin/bash\n\
         {marker}set -euo pipefail\n\
         instance=\"$1\"\n\
         out=\"/run/buzz-acp-$instance/secret.env\"\n\
         umask 077\n\
         gcloud secrets versions access latest \\\n\
        \x20 --secret=\"buzz-agent-$instance-private-key\" > \"$out\"\n\
         chown buzzacp:buzzacp \"$out\"\n\
         chmod 0400 \"$out\"\n"
    )
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp render`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): render unit, env, drop-in and key fetcher"
```

---

## Task 7: Capacity arithmetic and the warning

**Files:**
- Create: `crates/buzz-backend-gcp/src/capacity.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod capacity;`)

**Interfaces:**
- Produces: `capacity::parse_size(&str) -> Option<u64>` (bytes; accepts `512M`, `2G`, `1.5G`, a bare byte count); `capacity::warning(available_bytes: u64, reserved_bytes: u64, new_unit: &str, new_bytes: u64) -> Option<String>`.
- Consumes: nothing.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_in_the_units_systemd_accepts() {
        assert_eq!(parse_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("512M"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("1.5G"), Some(1_610_612_736));
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("infinity"), None);
        assert_eq!(parse_size(""), None);
    }

    #[test]
    fn a_fitting_agent_produces_no_warning() {
        // 2.7G available, 0 reserved, asking for 2G.
        assert!(warning(2_899_102_924, 0, "buzz-acp@abc.service", 2_147_483_648).is_none());
    }

    #[test]
    fn an_overcommit_names_the_numbers_and_the_remedy() {
        let w = warning(2_899_102_924, 2_147_483_648, "buzz-acp@abc.service", 2_147_483_648)
            .expect("overcommit must warn");
        assert!(w.starts_with("warning:"));
        assert!(w.contains("buzz-acp@abc.service"));
        assert!(w.contains("e2-standard-4"), "the warning must name a remedy");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp capacity`
Expected: FAIL — `cannot find function parse_size`.

- [ ] **Step 3: Implement**

```rust
//! Memory headroom arithmetic (spec §Capacity).
//!
//! The provider reports overcommit and proceeds: refusing would be the safer
//! default for the running fleet, but the operator asked to be warned rather
//! than blocked, and a provider that vetoes a deploy the operator understands
//! is a provider they will work around.

/// Parse a systemd size string into bytes. `None` for `infinity` and anything
/// unparseable — callers treat that as "no stated bound", not as zero.
pub fn parse_size(input: &str) -> Option<u64> {
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("infinity") {
        return None;
    }
    let (digits, multiplier) = match s.chars().last()? {
        'K' | 'k' => (&s[..s.len() - 1], 1024_f64),
        'M' | 'm' => (&s[..s.len() - 1], 1024_f64 * 1024.0),
        'G' | 'g' => (&s[..s.len() - 1], 1024_f64 * 1024.0 * 1024.0),
        'T' | 't' => (&s[..s.len() - 1], 1024_f64 * 1024.0 * 1024.0 * 1024.0),
        _ => (s, 1.0),
    };
    let value: f64 = digits.trim().parse().ok()?;
    if value < 0.0 {
        return None;
    }
    Some((value * multiplier) as u64)
}

fn gib(bytes: u64) -> String {
    format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// Build the overcommit warning, or `None` when the new agent fits.
pub fn warning(
    available_bytes: u64,
    reserved_bytes: u64,
    new_unit: &str,
    new_bytes: u64,
) -> Option<String> {
    if reserved_bytes.saturating_add(new_bytes) <= available_bytes {
        return None;
    }
    Some(format!(
        "warning: instance has {} available; existing units reserve {}. \
         Adding {new_unit} ({}) may cause OOM kills. \
         Lower memory_max or resize the instance to e2-standard-4.",
        gib(available_bytes),
        gib(reserved_bytes),
        gib(new_bytes),
    ))
}
```

- [ ] **Step 4: Run to verify passing**

Run: `cargo test -p buzz-backend-gcp capacity`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): memory headroom warning"
```

---

## Task 8: `remote.rs` — the IAP SSH transport

**Files:**
- Create: `crates/buzz-backend-gcp/src/remote.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod remote;`)

**Interfaces:**
- Produces: `remote::Remote::new(project, zone, instance) -> Remote`; `Remote::run(&self, script: &str) -> Result<Output, String>` where `Output { stdout: String, stderr: String, code: i32 }`; `Remote::install(&self, file: &RemoteFile) -> Result<(), String>`; `Remote::gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String>`.
- Consumes: `render::RemoteFile`.

**Security rule for this module:** no secret value may ever appear in an argv element. Bodies go on stdin. This is enforced by `install` taking the whole `RemoteFile` and never formatting `body` into a command string.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_install_command_never_carries_the_body() {
        let f = crate::render::RemoteFile {
            path: "/etc/buzz/acp-abc.env".into(),
            mode: "0600",
            body: "SUPER_SENSITIVE=1\n".into(),
        };
        let script = install_script(&f);
        assert!(script.contains("/dev/stdin"));
        assert!(script.contains("/etc/buzz/acp-abc.env"));
        assert!(script.contains("-m 0600"));
        assert!(
            !script.contains("SUPER_SENSITIVE"),
            "the body must travel on stdin, never in the command"
        );
    }

    #[test]
    fn the_install_script_creates_the_parent_directory() {
        let f = crate::render::RemoteFile {
            path: "/etc/systemd/system/buzz-acp@abc.service.d/agent.conf".into(),
            mode: "0644",
            body: String::new(),
        };
        assert!(install_script(&f).contains("mkdir -p '/etc/systemd/system/buzz-acp@abc.service.d'"));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp remote`
Expected: FAIL — `cannot find function install_script`.

- [ ] **Step 3: Implement**

```rust
//! The `gcloud compute ssh` transport (spec §Remote Artifacts).
//!
//! Every file body travels on stdin. Nothing sensitive is ever formatted into
//! a command string: argv is visible in `ps` on the instance and lands in
//! shell history, and the desktop's redaction cannot reach either.

use crate::render::RemoteFile;
use std::io::Write;
use std::process::{Command, Stdio};

pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

pub struct Remote {
    project: String,
    zone: String,
    instance: String,
}

/// Shell-quote for single-quoted POSIX context.
fn sq(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The remote script that installs one file, reading its body from stdin.
fn install_script(file: &RemoteFile) -> String {
    let parent = std::path::Path::new(&file.path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string());
    format!(
        "set -euo pipefail; sudo mkdir -p {}; sudo install -m {} /dev/stdin {}",
        sq(&parent),
        file.mode,
        sq(&file.path),
    )
}

impl Remote {
    pub fn new(project: &str, zone: &str, instance: &str) -> Self {
        Self {
            project: project.to_string(),
            zone: zone.to_string(),
            instance: instance.to_string(),
        }
    }

    /// Invoke gcloud, optionally piping stdin. Never logs `stdin`.
    pub fn gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String> {
        let mut child = Command::new("gcloud")
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("gcloud is not installed or not on PATH: {e}"))?;
        if let Some(body) = stdin {
            child
                .stdin
                .take()
                .ok_or_else(|| "gcloud stdin unavailable".to_string())?
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
        self.gcloud(
            &[
                "compute",
                "ssh",
                &self.instance,
                "--zone",
                &self.zone,
                "--project",
                &self.project,
                "--tunnel-through-iap",
                "--command",
                script,
                "--",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=20",
            ],
            stdin,
        )
    }

    /// Install one file, body on stdin.
    pub fn install(&self, file: &RemoteFile) -> Result<(), String> {
        let out = self.run_with_stdin(&install_script(file), Some(&file.body))?;
        if !out.ok() {
            // `file.body` is deliberately absent from this message.
            return Err(format!(
                "installing {} failed ({}): {}",
                file.path,
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run to verify passing**

Run: `cargo test -p buzz-backend-gcp remote`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): IAP ssh transport with stdin-only bodies"
```

---

## Task 9: `secrets.rs` — Secret Manager storage

**Files:**
- Create: `crates/buzz-backend-gcp/src/secrets.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs` (add `mod secrets;`)

**Interfaces:**
- Produces: `secrets::store(remote: &Remote, project: &str, name: &str, body: &str, service_account: &str) -> Result<(), String>`; `secrets::destroy(remote: &Remote, project: &str, name: &str) -> Result<(), String>`; `secrets::instance_service_account(remote: &Remote, project, zone, instance) -> Result<String, String>`.
- Consumes: `remote::Remote`.

`store` is idempotent: create the secret if absent, then always add a version. Versions are cheap and an add is the only way to guarantee the latest value matches this deploy.

- [ ] **Step 1: Implement**

```rust
//! Agent key storage in Secret Manager (spec §Secret flow).
//!
//! The nsec reaches gcloud on **stdin** and is never an argv element. The
//! instance service account is granted `secretAccessor` on the individual
//! secret — not project-wide — so one agent's key is not readable by a
//! compromise of another's unit.

use crate::remote::Remote;

/// Create-if-absent, then add a version carrying `body`.
pub fn store(
    remote: &Remote,
    project: &str,
    name: &str,
    body: &str,
    service_account: &str,
) -> Result<(), String> {
    let exists = remote
        .gcloud(&["secrets", "describe", name, "--project", project], None)?
        .ok();

    if !exists {
        let out = remote.gcloud(
            &[
                "secrets", "create", name,
                "--project", project,
                "--replication-policy", "automatic",
            ],
            None,
        )?;
        if !out.ok() {
            return Err(format!("creating secret {name} failed: {}", out.stderr.trim()));
        }
    }

    let out = remote.gcloud(
        &["secrets", "versions", "add", name, "--project", project, "--data-file=-"],
        Some(body),
    )?;
    if !out.ok() {
        // stderr may echo the request; report only the code and the name.
        return Err(format!(
            "adding a version to secret {name} failed with exit {}",
            out.code
        ));
    }

    let member = format!("serviceAccount:{service_account}");
    let out = remote.gcloud(
        &[
            "secrets", "add-iam-policy-binding", name,
            "--project", project,
            "--member", &member,
            "--role", "roles/secretmanager.secretAccessor",
        ],
        None,
    )?;
    if !out.ok() {
        return Err(format!(
            "granting {service_account} access to {name} failed: {}",
            out.stderr.trim()
        ));
    }
    Ok(())
}

/// Delete the secret and every version. Absent is success.
pub fn destroy(remote: &Remote, project: &str, name: &str) -> Result<(), String> {
    let out = remote.gcloud(
        &["secrets", "delete", name, "--project", project, "--quiet"],
        None,
    )?;
    if out.ok() || out.stderr.contains("NOT_FOUND") {
        return Ok(());
    }
    Err(format!("deleting secret {name} failed: {}", out.stderr.trim()))
}

/// The instance's attached service account — the identity the fetcher unit
/// authenticates as.
pub fn instance_service_account(
    remote: &Remote,
    project: &str,
    zone: &str,
    instance: &str,
) -> Result<String, String> {
    let out = remote.gcloud(
        &[
            "compute", "instances", "describe", instance,
            "--project", project,
            "--zone", zone,
            "--format", "value(serviceAccounts[0].email)",
        ],
        None,
    )?;
    if !out.ok() {
        return Err(format!("describing {instance} failed: {}", out.stderr.trim()));
    }
    let email = out.stdout.trim().to_string();
    if email.is_empty() {
        return Err(format!("{instance} has no attached service account"));
    }
    Ok(email)
}
```

- [ ] **Step 2: Verify it compiles and clippy is clean**

Run: `cargo clippy -p buzz-backend-gcp --all-targets -- -D warnings`
Expected: no warnings.

There are no unit tests here by design: every function is a thin `gcloud`
wrapper whose behavior is the CLI's. Task 13's live smoke exercises them.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): store agent keys in Secret Manager"
```

---

## Task 10: `observe.rs` and the I4 reconciler

**Files:**
- Create: `crates/buzz-backend-gcp/src/observe.rs`
- Create: `crates/buzz-backend-gcp/src/reconcile.rs`
- Modify: `crates/buzz-backend-gcp/src/main.rs`

**Interfaces:**
- Produces:
  - `observe::Observation { unit_present: bool, active: bool, marker: Option<Marker>, harness_running: bool, reserved_bytes: u64, available_bytes: u64, harness_installed: bool }`
  - `observe::look(remote, names, harness_command) -> Result<Observation, String>`
  - `reconcile::Action` enum: `NoOp`, `Create`, `RestartSame`, `FencedReplace`, `Refuse(String)`
  - `reconcile::classify(obs: &Observation, identity: &AgentIdentity, intent: &str) -> Action`
  - `reconcile::deploy(remote, cfg, agent) -> Result<String, String>`
- Consumes: everything above.

- [ ] **Step 1: Write the failing classification tests**

`crates/buzz-backend-gcp/src/reconcile.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::Marker;
    use buzz_backend_core::identity::AgentIdentity;

    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const INTENT: &str = "c0ffee";

    fn identity() -> AgentIdentity {
        AgentIdentity::from_nsec(NSEC).unwrap()
    }

    fn obs(unit_present: bool, active: bool, harness_running: bool, marker: Option<Marker>) -> Observation {
        Observation {
            unit_present,
            active,
            harness_running,
            marker,
            reserved_bytes: 0,
            available_bytes: u64::MAX,
            harness_installed: true,
        }
    }

    fn ours(intent: &str) -> Option<Marker> {
        Some(Marker {
            pubkey_full: identity().pubkey_hex().to_string(),
            create_intent: intent.to_string(),
        })
    }

    #[test]
    fn absent_unit_is_created() {
        assert_eq!(classify(&obs(false, false, false, None), &identity(), INTENT), Action::Create);
    }

    #[test]
    fn a_live_agent_is_a_strict_no_op() {
        // I4: deploy on a running instance must not mutate anything. Without
        // this, every Start click bounces a healthy agent.
        assert_eq!(
            classify(&obs(true, true, true, ours(INTENT)), &identity(), INTENT),
            Action::NoOp
        );
    }

    #[test]
    fn a_live_agent_with_divergent_intent_is_still_a_no_op() {
        // Reconfiguration of a *running* agent is out of scope: I4 wins over
        // convergence. The operator stops it first.
        assert_eq!(
            classify(&obs(true, true, true, ours("different")), &identity(), INTENT),
            Action::NoOp
        );
    }

    #[test]
    fn a_stopped_unit_with_the_same_intent_is_restarted_not_replaced() {
        assert_eq!(
            classify(&obs(true, false, false, ours(INTENT)), &identity(), INTENT),
            Action::RestartSame
        );
    }

    #[test]
    fn a_stopped_unit_with_divergent_intent_is_fenced_replaced() {
        assert_eq!(
            classify(&obs(true, false, false, ours("stale")), &identity(), INTENT),
            Action::FencedReplace
        );
    }

    #[test]
    fn an_unmarked_unit_is_refused_never_overwritten() {
        let a = classify(&obs(true, false, false, None), &identity(), INTENT);
        assert!(matches!(a, Action::Refuse(_)), "got {a:?}");
    }

    #[test]
    fn a_short_name_collision_is_refused() {
        let foreign = Some(Marker {
            pubkey_full: "ff".repeat(32),
            create_intent: INTENT.to_string(),
        });
        let a = classify(&obs(true, false, false, foreign), &identity(), INTENT);
        assert!(matches!(a, Action::Refuse(_)), "got {a:?}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p buzz-backend-gcp reconcile`
Expected: FAIL — `cannot find function classify`.

- [ ] **Step 3: Implement the observer**

```rust
//! Reading remote state (spec §Deploy Reconciliation step 1).

use crate::naming::{Marker, Names};
use crate::remote::Remote;

#[derive(Debug, Clone)]
pub struct Observation {
    pub unit_present: bool,
    pub active: bool,
    /// The harness process is actually running, not merely that systemd
    /// accepted the unit. "Live" in I4's sense means started.
    pub harness_running: bool,
    pub marker: Option<Marker>,
    pub reserved_bytes: u64,
    pub available_bytes: u64,
    /// The requested harness command exists on the instance.
    pub harness_installed: bool,
}

/// One round trip that collects everything the reconciler needs.
pub fn look(
    remote: &Remote,
    names: &Names,
    harness_command: &str,
) -> Result<Observation, String> {
    let script = format!(
        "set -uo pipefail\n\
         echo '---MARKER---'\n\
         sudo cat {env} 2>/dev/null || true\n\
         echo '---STATE---'\n\
         systemctl is-active {unit} 2>/dev/null || true\n\
         echo '---MAINPID---'\n\
         systemctl show {unit} -p MainPID --value 2>/dev/null || true\n\
         echo '---RESERVED---'\n\
         systemctl show 'buzz-acp*.service' -p MemoryMax --value 2>/dev/null || true\n\
         echo '---AVAILABLE---'\n\
         awk '/MemAvailable/ {{print $2}}' /proc/meminfo\n\
         echo '---HARNESS---'\n\
         command -v {harness} >/dev/null && echo yes || echo no\n",
        env = shell_single_quote(&names.env_path()),
        unit = shell_single_quote(&names.unit()),
        harness = shell_single_quote(harness_command),
    );
    let out = remote.run(&script)?;
    if !out.ok() {
        return Err(format!("observing the instance failed: {}", out.stderr.trim()));
    }
    Ok(parse_observation(&out.stdout))
}

fn shell_single_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

fn section<'a>(body: &'a str, name: &str) -> &'a str {
    body.split(&format!("---{name}---\n"))
        .nth(1)
        .map(|rest| rest.split("---").next().unwrap_or(""))
        .unwrap_or("")
}

fn parse_observation(stdout: &str) -> Observation {
    let marker_body = section(stdout, "MARKER");
    let state = section(stdout, "STATE").trim().to_string();
    let mainpid: u32 = section(stdout, "MAINPID").trim().parse().unwrap_or(0);
    let reserved_bytes = section(stdout, "RESERVED")
        .lines()
        .filter_map(|l| crate::capacity::parse_size(l.trim()))
        .sum();
    let available_kb: u64 = section(stdout, "AVAILABLE").trim().parse().unwrap_or(0);
    Observation {
        unit_present: !marker_body.trim().is_empty(),
        active: state == "active",
        harness_running: state == "active" && mainpid > 0,
        marker: Marker::parse(marker_body),
        reserved_bytes,
        available_bytes: available_kb * 1024,
        harness_installed: section(stdout, "HARNESS").trim() == "yes",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_unit_parses_as_live() {
        let out = "---MARKER---\n# managed-by: buzz-backend-gcp\n\
                   # binding-version: 1\n# agent-pubkey-full: ab\n# create-intent: ci\n\
                   ---STATE---\nactive\n---MAINPID---\n4242\n\
                   ---RESERVED---\n2G\n---AVAILABLE---\n2831156\n---HARNESS---\nyes\n";
        let o = parse_observation(out);
        assert!(o.unit_present && o.active && o.harness_running && o.harness_installed);
        assert_eq!(o.reserved_bytes, 2 * 1024 * 1024 * 1024);
        assert!(o.marker.is_some());
    }

    #[test]
    fn an_absent_unit_parses_as_absent() {
        let out = "---MARKER---\n---STATE---\n---MAINPID---\n\
                   ---RESERVED---\n---AVAILABLE---\n2831156\n---HARNESS---\nno\n";
        let o = parse_observation(out);
        assert!(!o.unit_present && !o.active && !o.harness_running && !o.harness_installed);
        assert!(o.marker.is_none());
    }
}
```

- [ ] **Step 4: Implement the reconciler**

Prepend to `reconcile.rs`:

```rust
//! The deploy state machine (spec §Deploy Reconciliation, I4).
//!
//! `deploy` is not "create": the desktop issues it on every Start and tracks
//! no substrate state. The only way that is safe is for a live instance to be
//! a strict no-op and for every destructive write to be fenced to the exact
//! observation that authorized it.

use crate::capacity;
use crate::config::ProviderConfig;
use crate::naming::Names;
use crate::observe::{self, Observation};
use crate::remote::Remote;
use crate::render;
use crate::secrets;
use buzz_backend_core::identity::{new_generation, AgentIdentity};
use buzz_backend_core::wire::AgentPayload;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The agent is already live. Zero mutation (I4).
    NoOp,
    Create,
    /// Same recorded intent, not running: start it. Never delete.
    RestartSame,
    /// Divergent intent on a stopped unit: replace, fenced.
    FencedReplace,
    Refuse(String),
}

/// Decide what to do from an observation alone. Pure, so the whole state
/// machine is testable without an instance.
pub fn classify(obs: &Observation, identity: &AgentIdentity, intent: &str) -> Action {
    if !obs.unit_present {
        return Action::Create;
    }
    let Some(marker) = obs.marker.as_ref() else {
        return Action::Refuse(format!(
            "a unit for this agent exists but carries no {} marker; \
             refusing to touch a file this provider did not create",
            crate::naming::MANAGED_BY
        ));
    };
    if marker.pubkey_full != identity.pubkey_hex() {
        return Action::Refuse(format!(
            "short-name collision: the existing unit belongs to pubkey {}, not {}",
            marker.pubkey_full,
            identity.pubkey_hex()
        ));
    }
    // Live is a strict no-op regardless of intent: reconfiguring a running
    // agent would mean killing it, and I4 puts at-most-one-live-instance above
    // convergence. The operator stops it, then redeploys.
    if obs.harness_running {
        return Action::NoOp;
    }
    if marker.create_intent == intent {
        Action::RestartSame
    } else {
        Action::FencedReplace
    }
}
```

Then the driver, which composes observe → classify → act:

```rust
/// Run one deploy to a terminal outcome.
pub fn deploy(
    remote: &Remote,
    cfg: &ProviderConfig,
    agent: &AgentPayload,
) -> Result<String, String> {
    // Step 0: identity from the nsec, before any mutation.
    let identity = AgentIdentity::from_nsec(&agent.private_key_nsec)?;
    let names = Names::new(&identity);
    let generation = new_generation();
    let plan = render::plan(agent, cfg, &names, &identity, &generation)?;

    let harness = agent
        .launch
        .as_ref()
        .and_then(|l| l.command.as_deref())
        .map(|c| c.rsplit('/').next().unwrap_or(c))
        .unwrap_or("buzz-acp")
        .to_string();

    let obs = observe::look(remote, &names, &harness)?;

    if !obs.harness_installed {
        return Err(format!(
            "{harness} is not installed on {}; install it before deploying an agent that uses it",
            cfg.instance
        ));
    }

    let action = classify(&obs, &identity, &plan.create_intent);
    if let Action::Refuse(why) = action {
        return Err(why);
    }
    if action == Action::NoOp {
        return Ok(names.unit());
    }

    if let Some(w) = capacity::warning(
        obs.available_bytes,
        obs.reserved_bytes,
        &names.unit(),
        capacity::parse_size(&cfg.memory_max).unwrap_or(0),
    ) {
        eprintln!("{w}");
    }

    if action == Action::FencedReplace {
        // Fence: re-read the intent and abort if it moved since we classified.
        let now = observe::look(remote, &names, &harness)?;
        if now.marker.as_ref().map(|m| m.create_intent.clone())
            != obs.marker.as_ref().map(|m| m.create_intent.clone())
        {
            return Err("the unit changed while deploying; retry".to_string());
        }
        let out = remote.run(&format!(
            "set -uo pipefail; sudo systemctl stop {unit} 2>/dev/null || true; \
             sudo systemctl disable {unit} 2>/dev/null || true",
            unit = names.unit()
        ))?;
        if !out.ok() {
            return Err(format!("stopping the stale unit failed: {}", out.stderr.trim()));
        }
    }

    if action != Action::RestartSame {
        let sa = secrets::instance_service_account(remote, &cfg.project, &cfg.zone, &cfg.instance)?;
        secrets::store(remote, &cfg.project, &names.secret_name(), &plan.secret_body, &sa)?;
        for file in &plan.files {
            remote.install(file)?;
        }
    }

    let out = remote.run(&format!(
        "set -euo pipefail; sudo systemctl daemon-reload; \
         sudo systemctl enable --now {unit}",
        unit = names.unit()
    ))?;
    if !out.ok() {
        return Err(format!("starting {} failed: {}", names.unit(), out.stderr.trim()));
    }

    // Success only on a confirmed harness start.
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let check = observe::look(remote, &names, &harness)?;
        if check.harness_running {
            return Ok(names.unit());
        }
    }
    Err(format!(
        "{} did not confirm a running harness within 30s; check `journalctl -u {}`",
        names.unit(),
        names.unit()
    ))
}
```

- [ ] **Step 5: Wire deploy into dispatch**

In `main.rs`, replace the `Request::Deploy(_)` arm:

```rust
        Request::Deploy(req) => {
            let cfg = match config::ProviderConfig::parse(&req.provider_config) {
                Ok(c) => c,
                Err(e) => return Response::error(e),
            };
            let remote = remote::Remote::new(&cfg.project, &cfg.zone, &cfg.instance);
            match reconcile::deploy(&remote, &cfg, &req.agent) {
                Ok(agent_id) => Response::deployed(agent_id),
                Err(e) => Response::error(e),
            }
        }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS. The classification tests (7) and observation-parsing tests (2)
are new; everything from Tasks 4-8 still passes.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): I4 reconciler with fenced replace"
```

---

## Task 11: Operator subcommands

**Files:**
- Modify: `crates/buzz-backend-gcp/src/main.rs`
- Create: `crates/buzz-backend-gcp/src/operator.rs`

**Interfaces:**
- Produces: `operator::Cli` (clap), `operator::run(cli) -> Result<(), String>`.
- Consumes: `remote`, `secrets`, `naming`, `render`.

The desktop passes no argv, so argv presence unambiguously selects operator
mode. When argv is empty, behave exactly as before.

- [ ] **Step 1: Implement**

```rust
//! Operator-facing commands (spec §Operator Surface).
//!
//! Not protocol operations: the desktop invokes this binary with no arguments,
//! so anything on argv is a human. These exist because the protocol has no
//! `stop` — I5 routes intentional termination through `!shutdown` on the
//! relay, and this is how the substrate is reclaimed afterwards.

use crate::config::ProviderConfig;
use crate::remote::Remote;
use crate::{naming, secrets};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "buzz-backend-gcp", about = "GCE/systemd backend provider for Buzz")]
pub struct Cli {
    #[arg(long, default_value = crate::config::DEFAULT_PROJECT)]
    pub project: String,
    #[arg(long, default_value = crate::config::DEFAULT_ZONE)]
    pub zone: String,
    #[arg(long, default_value = crate::config::DEFAULT_INSTANCE)]
    pub instance: String,
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List agent units this provider manages on the instance.
    List,
    /// Stop, disable, and delete an agent and its secret.
    Remove {
        /// The `agent_id` the desktop recorded, e.g. buzz-acp@a1b2c3d4e5f6.
        agent_id: String,
    },
    /// Render a deploy request read from stdin without touching the instance.
    DryRun,
}

pub fn run(cli: Cli) -> Result<(), String> {
    let remote = Remote::new(&cli.project, &cli.zone, &cli.instance);
    match cli.command {
        Cmd::List => list(&remote),
        Cmd::Remove { agent_id } => remove(&remote, &cli, &agent_id),
        Cmd::DryRun => dry_run(),
    }
}

fn list(remote: &Remote) -> Result<(), String> {
    let out = remote.run(
        "set -uo pipefail; \
         for f in /etc/buzz/acp-*.env; do \
           [ -e \"$f\" ] || continue; \
           i=$(basename \"$f\" .env); i=${i#acp-}; \
           pk=$(sudo grep -m1 '^# agent-pubkey-full: ' \"$f\" | cut -d' ' -f4); \
           st=$(systemctl is-active \"buzz-acp@$i.service\" 2>/dev/null || echo unknown); \
           printf '%s\\t%s\\t%s\\n' \"buzz-acp@$i\" \"$st\" \"$pk\"; \
         done",
    )?;
    print!("{}", out.stdout);
    Ok(())
}

fn remove(remote: &Remote, cli: &Cli, agent_id: &str) -> Result<(), String> {
    let instance = agent_id
        .strip_prefix("buzz-acp@")
        .map(|s| s.trim_end_matches(".service"))
        .ok_or_else(|| format!("{agent_id} is not a buzz-acp@<id> agent id"))?;
    if !instance.chars().all(|c| c.is_ascii_hexdigit()) || instance.len() != 12 {
        return Err(format!("{instance} is not a 12-hex agent instance"));
    }

    // Marker fence: never delete a file this provider did not create.
    let env_path = format!("/etc/buzz/acp-{instance}.env");
    let check = remote.run(&format!(
        "sudo grep -m1 '^# managed-by: ' '{env_path}' 2>/dev/null || true"
    ))?;
    if !check.stdout.contains(naming::MANAGED_BY) {
        return Err(format!(
            "{env_path} carries no {} marker; refusing to remove it",
            naming::MANAGED_BY
        ));
    }

    let out = remote.run(&format!(
        "set -uo pipefail; \
         sudo systemctl disable --now 'buzz-acp@{instance}.service' 2>/dev/null || true; \
         sudo systemctl stop 'buzz-acp-secret@{instance}.service' 2>/dev/null || true; \
         sudo rm -f '/etc/buzz/acp-{instance}.env'; \
         sudo rm -rf '/etc/systemd/system/buzz-acp@{instance}.service.d'; \
         sudo systemctl daemon-reload"
    ))?;
    if !out.ok() {
        return Err(format!("removing {agent_id} failed: {}", out.stderr.trim()));
    }
    secrets::destroy(
        remote,
        &cli.project,
        &format!("buzz-agent-{instance}-private-key"),
    )?;
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
        .map_err(|e| format!("reading stdin: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("invalid request: {e}"))?;
    let req: DeployRequest =
        serde_json::from_value(value).map_err(|e| format!("invalid deploy request: {e}"))?;

    let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec)?;
    let names = naming::Names::new(&identity);
    let cfg = ProviderConfig::parse(&req.provider_config)?;
    let plan = crate::render::plan(&req.agent, &cfg, &names, &identity, "dryrun00")?;

    println!("agent_id: {}", names.unit());
    println!("secret:   {} ({} bytes, not shown)", names.secret_name(), plan.secret_body.len());
    for f in &plan.files {
        println!("\n=== {} (mode {}) ===", f.path, f.mode);
        print!("{}", f.body);
    }
    Ok(())
}
```

In `main.rs`, branch on argv before reading stdin:

```rust
fn main() {
    if std::env::args_os().count() > 1 {
        use clap::Parser;
        match operator::run(operator::Cli::parse()) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    // ... existing stdin path unchanged
}
```

- [ ] **Step 2: Verify the protocol path is unaffected**

Run: `cargo test -p buzz-backend-gcp`
Expected: PASS — the wire tests spawn the binary with no argv, so they must
still see protocol behavior.

- [ ] **Step 3: Verify the operator path renders**

Run:
```bash
cargo run -p buzz-backend-gcp -- dry-run \
  < crates/buzz-backend-core/fixtures/provider-wire/deploy-full-launch.request.json
```
Expected: prints `agent_id: buzz-acp@<12 hex>`, the secret name with a byte
count, and five file bodies. Confirm by eye that **no `nsec1...` appears
anywhere** in the output.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -s -m "feat(backend-gcp): operator list, remove and dry-run"
```

---

## Task 12: Install target and documentation

**Files:**
- Modify: `justfile`
- Create: `crates/buzz-backend-gcp/README.md`
- Modify: `docs/remote-agents.md` (add the `[L3]` GCE binding section)

**Interfaces:**
- Produces: `just install-backend-gcp`.

L2 item 6 makes this mandatory, not optional: *"its binding documents how it
realizes each L2 term on its substrate, and how the owner's lifetime policy and
clean-exit restart behavior are realized there."*

- [ ] **Step 1: Add the install target**

In `justfile`, after the `build-release` recipe:

```make
# Build and install the GCE backend provider for the desktop app
install-backend-gcp:
    cargo build --release -p buzz-backend-gcp
    mkdir -p ~/.local/bin
    install -m 0755 target/release/buzz-backend-gcp ~/.local/bin/buzz-backend-gcp
    @echo "installed to ~/.local/bin/buzz-backend-gcp — restart Buzz Desktop to discover it"
```

- [ ] **Step 2: Write the crate README**

`crates/buzz-backend-gcp/README.md` must cover: what it is, that it installs on
the **operator's Mac** and not the VM, `just install-backend-gcp`, the
`provider_config` fields, the operator subcommands, the prerequisite that the
harness binary must already exist in `/usr/local/bin` on the instance, and that
`gcloud` must be authenticated with IAP access.

- [ ] **Step 3: Add the `[L3]` conformance section to the spec**

In `docs/remote-agents.md`, after `### [L3] Kubernetes binding conformance`, add
`### [L3] GCE/systemd binding conformance — buzz-backend-gcp`, stating in this
binding's vocabulary: identity derivation from the nsec; the marker as the
auto-repair fence; `Restart=no` for bounded lifetime and the deliberate refusal
of the indefinite case pending the clean-exit contract; `TimeoutStopSec=120` as
the graceful-shutdown budget; `ExecStart` invoking the harness directly so
`SIGTERM` reaches it; the two-file env split; and the separate fetcher unit with
the `IPAddressDeny` reason.

Also add a row to the `## Implementation Correspondence` table.

- [ ] **Step 4: Verify the install works end to end**

Run: `just install-backend-gcp && ~/.local/bin/buzz-backend-gcp list`
Expected: the install line prints, and `list` either prints existing units or
nothing. An auth error here means gcloud needs `gcloud auth login`.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "docs(backend-gcp): L3 conformance, README and install target"
```

---

## Task 13: Live smoke test

**Files:** none — this is a manual verification gate.

**Prerequisites:** `gcloud auth login` with access to `zoop-innovation`, and
Buzz Desktop built from source.

- [ ] **Step 1: Confirm discovery**

Restart Buzz Desktop. Open the agent create dialog and check that **Where to
run** now offers `gcp` beside `This computer`. If it does not, the binary is not
executable or not in `~/.local/bin`.

- [ ] **Step 2: Deploy a throwaway agent**

Create an agent named `smoke`, harness `codex-acp`, Run on `gcp`, accept the
config defaults. Submit.

Expected: the dialog reports success within ~40s and records
`agent_id = buzz-acp@<12 hex>`.

- [ ] **Step 3: Verify on the instance**

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'systemctl is-active buzz-acp@<id>.service; systemctl show buzz-acp@<id>.service -p Restart --value'
```
Expected: `active` and `no`. If `Restart` prints `always`, Task 6 regressed.

- [ ] **Step 4: Verify relay authentication**

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'sudo journalctl -u buzz-acp@<id> -n 30 --no-pager | grep -iE "owner|starting"'
```
Expected: a `buzz-acp starting:` line and an `agent owner:` line. **An
`agent owner: ...` line must be present** — its absence means the owner
variable was dropped and the agent will silently ignore every message.

- [ ] **Step 5: Verify the key is not on disk**

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'sudo grep -rl "nsec1" /etc/buzz/ || echo CLEAN; sudo ls -l /run/buzz-acp-<id>/'
```
Expected: `CLEAN`, and a `secret.env` at mode `0400` owned by `buzzacp`.

- [ ] **Step 6: Verify the I4 no-op**

Note the unit's `ActiveEnterTimestamp`, click Start again in the desktop, then
re-read it.

```bash
gcloud compute ssh buzz-agent --zone asia-south1-a --tunnel-through-iap \
  --project zoop-innovation --command \
  'systemctl show buzz-acp@<id>.service -p ActiveEnterTimestamp --value'
```
Expected: **identical** before and after. A changed timestamp means the live
instance was mutated, violating I4 — the classifier is wrong.

- [ ] **Step 7: Exercise the agent**

Add the agent to a channel from the desktop and mention it. Expected: it
replies, proving identity, owner resolution, and the response gate all survived
the remote path.

- [ ] **Step 8: Tear down**

```bash
~/.local/bin/buzz-backend-gcp remove buzz-acp@<id>
```
Expected: `removed buzz-acp@<id>`. Verify the unit and secret are gone:
```bash
~/.local/bin/buzz-backend-gcp list
gcloud secrets list --project zoop-innovation --filter="name~<id>"
```
Expected: no rows for that id in either.

- [ ] **Step 9: Full gate**

Run: `just ci`
Expected: PASS.

- [ ] **Step 10: Commit any fixes and open the PR**

```bash
git add -A && git commit -s -m "test(backend-gcp): live smoke fixes"
```

---

## Self-Review

**Spec coverage.** Design §Architecture → Tasks 1-4; §Environment Construction →
Task 2 (shared) + Task 6 (split); §Lifetime and Supervision → Task 6
(`Restart=no`, indefinite refusal) with the assertion in Task 6 Step 1;
§Naming → Task 5; §Deploy Reconciliation → Task 10; §Remote Artifacts → Tasks 6
and 8; §Capacity → Task 7; §Operator Surface → Task 11; §Security Properties →
enforced by the Task 6 nsec-leak test and Task 8's argv test; §Testing → Tasks
4-11 unit/integration plus Task 13 live; L2 item 6 documentation → Task 12.

**Type consistency.** `AgentIdentity::{from_nsec, pubkey_hex, short12, short32}`
defined in Task 2 and used in Tasks 5, 6, 10. `Names::{unit, instance, env_path,
dropin_path, secret_name, runtime_dir}` defined in Task 5 and used in 6, 10, 11.
`render::plan` returns `Plan { files, secret_body, create_intent }`, consumed in
10 and 11. `AuthoritativeInputs` gains `max_env_bytes` in Task 2; both call
sites updated there (k8s `Some(1_048_576)`) and in Task 6 (GCP `None`).
`Response::info` gains three parameters in Task 1; its only existing call site
is updated in the same task.

**Known risk.** Task 2 Step 3 reproduces `nostr`/`rand` call shapes from memory
of the deleted k8s code. The step says to copy the real spellings from that file
before deleting it — do that rather than trusting the snippet, since the pinned
`nostr` 0.44 and `rand` 0.10 APIs are version-sensitive.
