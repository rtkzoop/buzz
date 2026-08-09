# `buzz-backend-box` Implementation Plan

**Status:** Task D implementation complete; production enablement is blocked on the unrun live validation spike. No live Box mutation was authorized or performed in this change.

**Implementation status:**
- [ ] Phase 0 live account validation — **UNVERIFIED**; credentials were not assumed and no mutating spike group was run.
- [x] Phase 1 provider crate, wire contract, typed client, and config schema.
- [x] Phase 2 reconcile/deploy path.
- [x] Phase 3 supervision assets, secret-file flow, cleanup, and redaction.
- [x] Phase 4 offline/fake-server/unit coverage and safe CLI gate coverage. Live regression remains blocked on Phase 0.
- [x] Phase 5 desktop packaging, CI/release wiring, operator docs, and gated spike binary.
**Date:** 2026-08-08
**Depends on:**
- [`docs/buzz-backend-box-research.md`](./buzz-backend-box-research.md) — original architecture research
- [`docs/buzz-backend-box-platform-verification.md`](./buzz-backend-box-platform-verification.md) — ASCII Box public-docs verification (VERIFIED/UNVERIFIED labels)
- [`docs/buzz-backend-box-lifecycle-security-design.md`](./buzz-backend-box-lifecycle-security-design.md) — lifecycle, supervision, secrets, and reconciliation design

## Conclusion of the research swarm

Three parallel research tracks (provider contract, Box platform verification, lifecycle/security design) converged on the following verdict:

1. **ASCII Box is a viable primary substrate** for persistent Buzz agents: per-second billing, free archived Boxes, snapshot/resume in seconds, preinstalled Docker, `noEnv` isolation that is documented as "confined to itself and cannot act on the account or any other Box", dedicated IPv4, and 2 TB included egress.
2. **Provider protocol v1 needs no changes.** The new binary is a sibling of `buzz-backend-kubernetes`: one process per operation, one JSON object in on stdin, one JSON object out on stdout (1 MiB cap), stderr diagnostics only (64 KiB cap), in-band `{"ok":false,"error":...}` failures with exit 0, exit nonzero only for provider-process failure.
3. **`Restart=no` is the only safe supervision policy in v1.** `buzz-acp` currently returns exit 0 on several semantically abnormal paths (circuit-open all-slots-dead, relay reconnect exhaustion), so systemd cannot classify intent from the exit code. This is a known spec defect (`docs/remote-agents.md:264-285`, `:1411-1436`).
4. **Seven implementation-critical Box behaviors are UNVERIFIED** by public docs and gate implementation behind a live spike: `box stop self` from a `noEnv` Box, subdomain-claim atomicity and conflict code, command output byte caps, Docker image/layer persistence across snapshots, digest-pull and registry-auth behavior, explicit outbound WSS policy, and hard deletion (which the current public OpenAPI does not expose at all).
5. **The Kubernetes provider's decision structure — not its Pod API — is the template**: verify identity first, fence ownership, distinguish started-harness from substrate acceptance, live harness is a strict no-op, never recycle on age, replace only with positive evidence.

## Non-goals

- No changes to `buzz-acp`, the relay, or Desktop in phase 1 (except optional workspace registration glue).
- No provider protocol v2 operations (`status`, `logs`, `stop`, `undeploy`). Deferred.
- No E2B provider. Deferred to a follow-up crate once the Box provider ships.
- No hard-delete support: the current public Box API has no `DELETE /boxes/{boxId}`; cleanup is modeled as stop/archive.

---

## Phase 0 — Live validation spike (blocking gate)

A gated validation binary now lives at `crates/buzz-backend-box/src/bin/box-live-spike.rs`. It is compiled by `cargo build -p buzz-backend-box --all-targets` and safe CLI paths are tested, but it is not invoked by provider deploys or release jobs. Every live mutation requires both `BOX_API_KEY` and `--confirm-live`; `--dry-run all` performs zero network I/O. Every UNVERIFIED item below must be resolved and its outcome recorded in `docs/buzz-backend-box-platform-verification.md` before production enablement. The live items remain unchecked because no credentials or live authorization were assumed.

### 0.1 Identity and self-stop (highest risk)

- [ ] Create a `noEnv: true` Box; inventory env vars, secret files, and whether `~/.config/ascii/box/config.json` exists.
- [ ] Run `box stop self` from inside using only the machine identity (`ASCII_TOKEN`/machine token). No `BOX_API_KEY` inside the Box, ever.
- [ ] Confirm `box list`, `box stop <other-id>`, create/resume/fork of other Boxes are all denied from the machine identity.
- **Fallback if self-stop fails:** provider-side TTL management (`ttlSeconds` set at deploy and refreshed), or an external janitor. This changes the launcher design, so it must be answered first.

### 0.2 Deterministic identity claim

- [ ] Two candidate Boxes concurrently `PATCH` the same subdomain. Record: winner, loser HTTP status, error `code`, whether it is stable, whether the loser stays usable.
- **Fallback if not atomic:** claim via a marker file + list-and-verify with a jittered retry loop, or an external ownership record. The claim step must complete before any secret injection regardless of mechanism.

### 0.3 Secrets and files

- [ ] `PUT /files` a secret file, `chmod 600` via the command endpoint, verify mode. Confirm the value never appears in command args or API logs.
- [ ] Confirm the command endpoint's actual stdout/stderr truncation threshold (docs expose flags but no number).
- [ ] Confirm whether Docker persists env/`--env-file` values under `/var/lib/docker/containers/*/config.v2.json` on the installed Docker version.

### 0.4 Docker and image policy

- [ ] `docker version`; pull the approved Buzz image by immutable digest; verify `RepoDigests`.
- [ ] Private-registry login without leaving credentials in the snapshot.
- [ ] Stop/resume: is the image still present? Named volumes are documented to persist; image layers and writable layers are not guaranteed. Decide pull-on-resume vs rely-on-persistence.

### 0.5 Lifecycle and supervision

- [ ] Install a systemd unit, enable it, stop/archive, resume: confirm the unit restarts (documented) and that a `stop_intent: self` marker prevents an unwanted relaunch after an intentional `!shutdown` (I5).
- [ ] External `POST /stop`: confirm SIGTERM ordering reaches systemd → launcher → `docker stop` → container PID 1, and that `buzz-acp` publishes `offline` (kind 20001) before termination.
- [ ] Command timeout ceiling at 60 s: confirm setup steps fit; anything longer goes through systemd.

### 0.6 Network and limits

- [ ] Outbound WSS to a Buzz relay, HTTPS to a model provider, GitHub; long-lived idle WSS; reconnect after resume.
- [ ] `GET /limits` against expected start traffic (create/fork/resume each count as one start; ceilings 600/hour, 1,500/day; trial: 4 concurrent, 5 starts/min).

**Exit criteria:** every checkbox answered with recorded evidence; fallbacks selected for any failed assumption; verification doc updated.

---

## Phase 1 — Crate skeleton and shared extraction

### 1.1 New crate

```
crates/buzz-backend-box/
  src/
    main.rs        # stdin/stdout protocol driver (mirror kubernetes main.rs:34-135)
    wire.rs        # Request/Response types (initially copied; see 1.2)
    config.rs      # provider_config schema + validation
    env.rs         # three-tier env resolution (mirror kubernetes env.rs)
    naming.rs      # pubkey derivation, deterministic subdomain, container name
    api.rs         # typed Box API client (reqwest, bearer auth, ok/type envelope)
    observe.rs     # Box + service + intent + presence observation
    classify.rs    # pure state classifier (Box state × harness state → action)
    reconcile.rs   # ordered reconcile loop with fenced mutations
    intent.rs      # non-secret launch-intent fingerprint (mirror kubernetes intent.rs)
    provision.rs   # unit/launcher install, secret file injection, service start
    redact.rs      # provider-local redaction (see 4.3)
  assets/
    buzz-agent.service        # systemd unit template
    buzz-box-supervise        # launcher script
    buzz-box-entrypoint       # in-container entrypoint (exec buzz-acp)
  tests/
    wire_fixtures.rs          # golden fixtures shared with desktop
    fake_box.rs               # in-process fake Box API server
    reconcile_tests.rs
```

Registration: add to `Cargo.toml` workspace members (line ~30), the `just` build/package target lists (`justfile:446,493,522,558`), the sidecar staging arrays (`justfile:160,536,572`), and the nextest CI target (`justfile:308`).

### 1.2 Shared-code decision

The wire types (`wire.rs`), env tiering (`env.rs` authoritative-key model), identity derivation, and redaction primitives are near-identical between providers. Options:

- **Option A (recommended for v1):** copy with a `// keep in sync with buzz-backend-kubernetes` marker and share only the golden wire fixtures (`tests/fixtures/provider-wire/`), which are already "the arbiter shared with the desktop".
- **Option B (follow-up refactor):** extract `buzz-backend-core` with wire types, env resolution, pubkey derivation, and redaction. Do this after the Box provider is proven, in a separate PR, so the Kubernetes provider is not destabilized mid-feature.

### 1.3 `info` response

```json
{
  "ok": true,
  "name": "box",
  "version": "<crate version>",
  "protocol_version": 1,
  "description": "Deploys Buzz agents to ASCII Box VMs",
  "config_schema": { ... }
}
```

`config_schema` (all non-secret; Desktop rejects secret-like keys, `backend.rs:535-565`):

| Key | Values | Default |
|---|---|---|
| `machine_type` | `small` \| `default` \| `large` | `small` |
| `image` | approved immutable image reference (digest) | catalog default |
| `inactivity_seconds` | int ≥ 60 (0 rejected in v1, as Kubernetes does) | 7200 |
| `scope` | non-secret deployment scope id | `default` |
| `workspace_mode` | `persistent` \| `fresh` | `persistent` |

Box API auth: ambient only — `BOX_API_KEY` env, then Box CLI credential store. Never from `provider_config`. Document the macOS GUI env caveat (GUI apps do not inherit login-shell env).

---

## Phase 2 — Core deploy path

### 2.1 Ordered deploy algorithm

```
1. Parse request; derive pubkey from private_key_nsec. Fail closed before any Box read/mutation.
2. Build the full three-tier env map + redaction set (before any network I/O).
3. Resolve ambient Box credentials; fail with actionable (redacted) error if absent.
4. Locate: list Boxes, find deterministic subdomain buzz-<scope-hash>-<pubkey-hash-prefix>.
5. If found: verify ownership (full pubkey in in-Box marker file + management marker + binding version) before adopting. Never trust name alone.
6. Classify (see 2.2) and act.
7. On create path: create with noEnv:true → poll until ready → claim subdomain (spike-validated conflict handling) → loser stops own candidate and adopts winner → write ownership marker + intent fingerprint → install unit/launcher → inject secrets (see 3) → systemctl start → confirm service active + harness readiness.
8. Success only when the fixed service is confirmed started; return box.id as agent_id. Box "ready"/"idle" is never success by itself.
9. 600 s operation deadline, 2 s poll interval (matching Kubernetes reconcile.rs:98-119). Timeout reports observed state; it never recycles on age.
```

### 2.2 Reconciliation table (from lifecycle design doc §3.3)

| Box state | Service/harness observation | Action on explicit deploy |
|---|---|---|
| Absent | — | Create, claim, mark, inject, launch, confirm |
| Provisioning/cloning | Unknown | Observe until ready/archived/error; timeout reports, never recycles |
| Ready/idle | Service active, fresh presence | **Strict no-op**, return existing Box ID |
| Ready/idle | Service inactive, intentional-stop marker | This Start relaunches after confirming the old unit fully stopped |
| Ready/idle | Service inactive, abnormal-exit marker | Launch (explicit Start), report prior failure |
| Ready/idle | Never started, provably broken, provider-owned | Fenced archive/replace |
| Ready/idle | Never started, recoverable, same intent | Observe, never delete |
| Ready/idle | Never started, intent diverges | Fenced replace (fingerprint discriminates only never-started Boxes) |
| Archived | — | Resume, wait ready, verify unit + intent, inject current env, launch |
| Archiving | — | Wait for archived, then Archived row. Never race resume vs archiving |
| Error | Ambiguous | Redacted actionable error; replace only with positive ownership + intent evidence |
| Any | Lost the claim race | Stop own candidate **before** nsec injection; adopt winner |

Race protections copied from Kubernetes: fenced destructive ops (act only on the exact observation that authorized them; conflict → re-enter, don't retry), delete-not-found is success, a Box created by the current call is never hot-replaced within the same call.

### 2.3 Invariants I4/I5 mapping

- **I4 (one live instance):** deterministic subdomain claim + ownership marker verification + strict no-op on live harness.
- **I5 (no resurrection):** `Restart=no`; launcher self-stops the Box on harness exit; the `stop_intent` state file prevents systemd-enabled-unit auto-relaunch after resume from re-running an intentionally stopped agent. Only an explicit new `deploy` resumes.

---

## Phase 3 — In-Box supervision and secret injection

### 3.1 systemd unit (from design doc §4.2)

`Restart=no`, `KillMode=process`, `TimeoutStopSec=120s` (operational margin; the 60 s Kubernetes figure is a declared budget, not a proven ACP bound), `NoNewPrivileges=yes`, `UMask=0077`, no credentials in the unit. `ExecStop` records external-stop intent; `ExecStopPost` is last-resort cleanup that consults the intent file before any self-stop.

### 3.2 Launcher (`buzz-box-supervise`)

- Exclusive lock; SIGTERM/SIGINT trap sets `stop_intent: external` and runs `docker stop --time=110` (never self-stop from this path).
- Verifies env file is root:root 0600 with the expected invocation nonce, verifies image digest, then `docker run` with a read-only tmpfs bind of the env file. Never `--env-file`, never secrets in argv.
- Waits for the entrypoint's non-secret `env-consumed` marker, removes the host-side env file, waits on the child.
- On non-external exit: records `stop_intent: self` + child status, `docker rm`, then `box stop self` (the billing-coupling point — runs after crashes too, so a dead harness cannot leave a billed VM).

### 3.3 Entrypoint

`exec buzz-acp` (a lingering shell PID 1 swallows SIGTERM, `docs/remote-agents.md:1050-1065`). Parses the env blob with a fixed non-shell parser (canonical JSON or length-prefixed records — never `source`), unlinks it, emits the consumed marker, execs.

### 3.4 Secret injection flow

```
provider builds env map → wins claim → PUT /files (base64) to /run/buzz-agent/env.pending
  → chmod 600 via command endpoint (stdin pattern: install -m 600 /dev/stdin <path> if needed)
  → verify mode → systemctl start → entrypoint consumes + unlinks → launcher removes host copy
```

`/run/buzz-agent` is root-owned 0700 tmpfs, so secrets never touch the persistent snapshot. Reserved identity vars (`BUZZ_RELAY_URL`, `BUZZ_PRIVATE_KEY`, `NOSTR_PRIVATE_KEY`, owner/auth, command/args, MCP, inactivity, start nonce) are constructed from top-level payload fields only; authoritative keys are stripped from lower tiers first so a missing authoritative value clears a spoof (mirror `env.rs:211-216`). `BUZZ_ACP_NO_PRESENCE` is rejected.

### 3.5 Redaction (provider-local, before any output)

Longest-first exact replacement of: every env value (all tiers), `private_key_nsec`, `auth_tag`, ambient Box API/machine/CLI tokens, URL userinfo, plus token patterns `nsec1…`, `sprt_tok_…`, `ghp_/gho_/ghu_/ghs_/ghr_/github_pat_…`. Note: Desktop's redactor does not know Box token formats, so the provider must handle them itself (gap identified in design doc §5.3). Box API/command output is untrusted; surface only typed, allowlisted status messages.

---

## Phase 4 — Testing

1. **Golden wire fixtures** (`tests/fixtures/provider-wire/`): reuse the Desktop-shared fixture format; assert one newline-terminated JSON response, key-level comparison.
2. **Fake Box API server** (in-process axum/hyper): drives classifier + reconcile through every table row — no-op on live, provisioning timeout, archive/resume, claim conflict (both winner and loser), fingerprint divergence, external stop vs self stop, error states, 429 start-limit handling.
3. **Pure classifier unit tests**: exhaustive state-matrix coverage (mirror `classify.rs` test style; the Kubernetes crate has 154 unit tests as the bar).
4. **Opt-in live tests** gated on `BOX_API_KEY` (`#[ignore]` + env guard), re-running the Phase 0 spike assertions as regression checks.
5. `just ci` green; no `unwrap()`/`expect()` in production paths; doc comments on public API.

---

## Phase 5 — Packaging, docs, rollout

1. Build/publish `buzz-backend-box` separately from the agent image; add to justfile build/package/staging/production sidecar lists so Desktop discovery (`buzz-backend-*` exe scan) finds it. **Implemented in Task D.**
2. Update `docs/remote-agents.md` with a Box provider section: ambient auth setup, EU-only residency + SOC 2-in-progress caveat, persistent-disk retention warning (archive ≠ delete; no public hard-delete API), snapshot threat model. **Implemented in Task D.**
3. Update the three research docs' open questions with spike answers. **Live answers remain blocked on Phase 0; no result is claimed here.**
4. Follow-ups (separate work): `buzz-backend-core` extraction (1.2 Option B), protocol v2 (`undeploy`/status/logs, echo `backend_agent_id` into deploy to skip discovery scans), E2B provider for ephemeral workloads, pinned ACP exit-code contract enabling bounded `Restart=on-failure`.

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `box stop self` unauthorized from `noEnv` Box | Medium | High (billing leak on crash) | Spike first; fallback: provider-managed `ttlSeconds` heartbeat or janitor |
| Subdomain claim not atomic | Medium | High (double harness = I4 violation) | Spike; fallback marker-file + verify-retry claim protocol |
| Docker image layers lost on resume | Medium | Medium (slow resume, registry dependency) | Idempotent pull-by-digest in launcher start path |
| ACP exit-0-on-abnormal ambiguity | Certain (current tree) | Medium | `Restart=no` + self-stop on any exit; fix exit contract separately |
| Secrets in snapshot (`/var/lib/docker`, journal) | Medium | High | tmpfs-only secret path, no `--env-file`, `docker rm`, spike verification |
| EU-only + no SOC 2 | Certain | Product-level | Document; keep Kubernetes provider for regulated deployments |
| Start-rate ceilings (600/h, 1500/d platform-wide) | Low | Medium | Backoff on 429 `start_limit_reached`; surface actionable error |

## Estimated sequencing

1. **Phase 0 spike** — 1-2 days with a live account. Blocking.
2. **Phase 1 skeleton + wire fixtures** — 1 day. Can start in parallel with the spike.
3. **Phase 2 reconcile + fake-Box tests** — 3-4 days.
4. **Phase 3 supervision assets + secret flow** — 2-3 days (details fixed by spike results).
5. **Phase 4 test hardening + live regression tests** — 1-2 days.
6. **Phase 5 packaging + docs** — 1 day.
