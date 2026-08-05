# `buzz-backend-gcp` — GCE/systemd Backend Provider Design

`draft` · 2026-08-05

## Problem

Buzz Desktop can create an agent's identity and definition on a remote relay,
but it cannot run the agent anywhere except the user's own machine.
`BackendKind` is `Local` or `Provider { id, config }`
(`desktop/src-tauri/src/managed_agents/types.rs:7-18`); `Local` terminates in
`command.spawn()` on the Mac (`managed_agents/runtime.rs:908-918`), and the
"Where to run" selector offers only `This computer` plus whatever
`buzz-backend-*` executables are discovered locally
(`managed_agents/backend.rs:586-638`). No `buzz-backend-*` binary targeting GCE
exists, so a team running its relay on GCP still has every agent tethered to a
laptop.

This design specifies `buzz-backend-gcp`: a conforming backend provider that
runs agents as systemd units on the existing `buzz-agent` GCE VM.

## Governing Specification

`docs/remote-agents.md` is normative. This document is a **binding** of it —
the second, after `buzz-backend-kubernetes`. Every requirement below traces to
a clause there; where this design adds something, it is marked as a binding
choice rather than a protocol change.

The five invariants that constrain us: **I1 identity fail-closed**, **I2 no
secrets in configuration**, **I3 presence-is-status**, **I4
at-most-one-live-instance**, **I5 intentional-termination-is-final**.

## Substrate

| | |
|---|---|
| Host | `buzz-agent`, GCE `e2-medium`, `asia-south1-a`, project `zoop-innovation` |
| Reachability | No external IP; IAP TCP forwarding only (firewall `35.235.240.0/20`) |
| Capacity | 2 vCPU, 3.9 GB RAM (~2.7 GB available), 38 GB free disk |
| Container runtime | None. Docker is not installed and will not be. |
| Existing agent | `buzz-acp.service`, user `buzzacp` (uid 999), `EnvironmentFile=/etc/buzz/acp.env` |
| Installed runtimes | `buzz`, `buzz-acp`, `codex`, `codex-acp`, `goose`, `node` in `/usr/local/bin` |
| Instance SA | `buzz-agent@zoop-innovation.iam.gserviceaccount.com` |

Two host facts are load-bearing for the design:

1. The metadata blocker is **uid-scoped**, not global:
   `-A OUTPUT -d 169.254.169.254/32 -m owner --uid-owner 999 -j REJECT`. Root
   can reach the metadata server; `buzzacp` cannot.
2. The agent unit additionally sets `IPAddressDeny=169.254.169.254/32`, which
   is a **cgroup-wide** BPF filter. It applies to every process in the unit
   including `ExecStartPre=+` running as root. A Secret Manager fetch therefore
   cannot live inside the agent unit.

## Where the Provider Runs

On the **operator's Mac**, not on the VM. The desktop discovers providers on
its own machine, stages a copy, and executes it as a child process with JSON
over stdin/stdout. The provider is a translator: desktop payload in, `gcloud`
calls against the VM out. Installing it on the VM would make it undiscoverable.

```
Mac: Buzz Desktop ──stdin/stdout JSON──> buzz-backend-gcp
                                              │ gcloud compute ssh --tunnel-through-iap
                                              v
                                         buzz-agent VM ── buzz-acp@<id>.service ──wss──> relay
```

## Product Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Compute unit | systemd unit on the existing VM | Reuses the hardened sandbox and metadata blocker already there; ~5-10 s deploys; no new cost. |
| Agent key at rest | Secret Manager, materialized to tmpfs at start | I2 forbids credentials in `provider_config`; matches the pattern the deployment already uses; survives VM recreation, which `agent.tf`'s `ignore_changes` makes a real risk. |
| Implementation | Rust crate in the workspace | Repo convention, `just ci` coverage, and — decisively — a compiled binary has no interpreter to resolve when exec'd by a GUI app inheriting launchd's minimal `PATH`. |
| Shared logic | Extract `crates/buzz-backend-core` | The wire types and env algorithm are normative and substrate-neutral; two copies would drift on the next spec change. |
| Over-capacity deploy | Warn on stderr, proceed | Operator preference. The provider reports the risk; it does not veto. |

## Architecture

### `crates/buzz-backend-core` (new, shared)

Extracted from `buzz-backend-kubernetes` so both bindings compute identical
environments from identical payloads.

| Module | Contents |
|---|---|
| `wire.rs` | `Request`, `DeployRequest`, `AgentPayload`, `LaunchBlock`, `Response`, `InfoResponse`, `DeployResponse`, `ErrorResponse`. `Response::info()` becomes parameterized over `name`/`description`/`config_schema` instead of calling a crate-local `config_schema()`. |
| `env.rs` | `build_env`, `AUTHORITATIVE_KEYS`, `START_NONCE_KEY`, `validate_respond_to_gate`, `is_posix_env_key`. The Kubernetes 1 MiB `Secret` cap becomes a `max_env_bytes: Option<usize>` parameter — a substrate limit, not a protocol rule. |
| `identity.rs` | `AgentIdentity` (constructed only by decoding `private_key_nsec`, exposing `pubkey_hex`, `short12`, `short32`) and `new_generation()`. |
| `tests/fixtures/provider-wire/` | The golden payload fixtures, now shared. |
| `harness.rs` (dev) | The `run(request) -> (stdout, exit_code)` helper that drives a built binary over a real pipe. |

`buzz-backend-kubernetes` keeps everything substrate-specific: `pod.rs`,
`client.rs`, `cluster.rs`, `image.rs`, `gc.rs`, `reconcile.rs`, `classify.rs`,
`observe.rs`, its own `config.rs`, and its own naming constants (the
`app.kubernetes.io/*` label keys are not portable).

### `crates/buzz-backend-gcp` (new)

| Module | Responsibility | Offline-testable |
|---|---|---|
| `main.rs` | One request in, one response out; exit code carries one bit. Operator argv subcommands. | yes |
| `config.rs` | `provider_config` schema + parsing. | yes |
| `render.rs` | Pure `payload -> Vec<RemoteFile>`: env file, unit template, drop-in, fetcher unit. **Where the bugs live.** | yes |
| `naming.rs` | Unit names and the management marker, derived from `AgentIdentity`. | yes |
| `remote.rs` | `gcloud compute ssh` transport; file bodies piped on stdin. | no |
| `secrets.rs` | Secret Manager create / add-version / IAM binding. | no |
| `observe.rs` | Read remote unit state into a typed observation. | no |
| `reconcile.rs` | The I4 state machine over `observe` + `render` + `remote`. | partially |
| `capacity.rs` | Headroom arithmetic and the warning string. | yes |

## Provider Protocol

### `info`

Pure — no VM contact, because the desktop calls it to render the config form.

```json
{"ok": true, "name": "gcp", "version": "<CARGO_PKG_VERSION>",
 "protocol_version": 1,
 "description": "Runs agents as systemd units on a GCE instance",
 "config_schema": { ... }}
```

Exactly those six keys; the desktop rejects any additional field
(`backend.rs:48-63`).

### `provider_config` v1 fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `project` | string | `zoop-innovation` | |
| `zone` | string | `asia-south1-a` | |
| `instance` | string | `buzz-agent` | |
| `memory_max` | string | `2G` | systemd `MemoryMax` |
| `cpu_quota` | string | `150%` | systemd `CPUQuota` |
| `inactivity_seconds` | integer | `7200` | Feeds `BUZZ_ACP_EXIT_AFTER_INACTIVITY`. |

No field names a credential, satisfying I2 and the desktop's own key filter
(`backend.rs:536-566` rejects any key whose words include
`secret|password|token|key|credential`).

`inactivity_seconds: 0` is the blessed indefinite-lifetime opt-in and must not
be rejected as invalid — but see §Lifetime, which refuses it for a different,
spec-mandated reason.

### `deploy`

Returns `{"ok": true, "agent_id": "buzz-acp@<first-12-hex-of-pubkey>"}`.

Errors are in-band `{"ok": false, "error": "..."}` with exit code 0. Exit
nonzero only on a crash path, and never encode meaning in the value — the
desktop discards stdout entirely when the code is nonzero.

## Environment Construction

Delegated wholesale to `buzz_backend_core::env::build_env`. Restating the
algorithm because it is the single highest-risk area:

```
tier 1:  launch.policy_env
tier 2:  launch.env            (NOT re-merged with legacy env_vars when launch is present)
         validate: POSIX key names; refuse BUZZ_ACP_NO_PRESENCE
tier 3:  remove every AUTHORITATIVE_KEY, then write:
           BUZZ_RELAY_URL        <- agent.relay_url        (refuse if blank)
           BUZZ_PRIVATE_KEY      <- agent.private_key_nsec
           NOSTR_PRIVATE_KEY     <- agent.private_key_nsec (git helpers)
           BUZZ_AUTH_TAG         <- agent.auth_tag         if present
           BUZZ_ACP_AGENT_OWNER  <- launch.owner_pubkey    if present
             refuse if NEITHER resolved
           BUZZ_ACP_AGENT_COMMAND <- launch.command
           BUZZ_ACP_AGENT_ARGS    <- launch.args joined by ","
           BUZZ_ACP_MCP_COMMAND   <- "buzz-dev-mcp"
           BUZZ_ACP_RESPOND_TO / _ALLOWLIST  <- validated against the harness's four modes
           BUZZ_ACP_EXIT_AFTER_INACTIVITY    <- inactivity_seconds
           BUZZ_MANAGED_AGENT_START_NONCE    <- generation token
```

The tier-3 *clear* is not decoration: most authoritative keys are written
conditionally, so without clearing, a lower tier could supply the value for
exactly the cases tier 3 stays silent on.

### Binding-specific split

`build_env` yields one flat map. This binding splits it across two files by
sensitivity:

- `BUZZ_PRIVATE_KEY` and `NOSTR_PRIVATE_KEY` → the tmpfs secret file, written
  by the fetcher unit.
- Everything else → `/etc/buzz/acp-<id>.env`, mode 0600 root:root.

Both are `EnvironmentFile=` entries on the unit. Splitting changes no value and
no precedence; it only keeps the nsec off the boot disk.

### Host-resolved values

`launch.command` is resolved against the **desktop's** PATH. On the VM that
path is meaningless. The provider takes the basename and verifies it exists in
`/usr/local/bin` on the instance, refusing with a named error otherwise
(*"codex-acp is not installed on buzz-agent"*) rather than deploying a unit
that will fail at exec.

## Lifetime and Supervision

L1 item 5 is explicit: `Restart=always` and equivalents are **non-conforming**,
because a supervisor that restarts an intentional clean exit resurrects what
`!shutdown` and the inactivity reaper just terminated (I5).

| `inactivity_seconds` | Lifetime | k8s binding | this binding |
|---|---|---|---|
| `> 0` (default 7200) | bounded | `restartPolicy: Never` | `Restart=no` |
| `0` | indefinite | `OnFailure` | `Restart=on-failure` |

**v1 ships bounded only.** The spec requires a provider to *refuse* the
indefinite combination until the harness clean-exit contract is pinned (Known
Defect 6) — shipping `on-failure` against an undefended exit convention would
restart agents that exited on purpose. So `inactivity_seconds: 0` parses
successfully and is then refused by `deploy` with a message naming the
prerequisite. When the contract lands, this becomes a one-line change.

Signal delivery (L1 item 3): `ExecStart=` invokes `/usr/local/bin/buzz-acp`
directly — no shell wrapper, so `SIGTERM` reaches the harness itself. The unit
sets `TimeoutStopSec=120` to leave room for in-flight drain, presence→offline,
and graceful relay close before `SIGKILL`.

Accidental death is handled by intent, not machinery: the process dies →
presence goes `offline` (I3) → the user clicks Start → `deploy` re-enters the
reconciler.

**Existing-fleet finding:** the live `buzz-acp.service` uses `Restart=always`
and is therefore a non-conforming launcher today. Bringing it into line is
adjacent work, noted in §Follow-ups, not part of this design.

## Naming and the Management Marker

All names derive from the pubkey the provider decodes from
`private_key_nsec` — never from the display name, which is neither unique nor
stable, and never from a caller-supplied pubkey.

| Artifact | Name |
|---|---|
| Unit instance | `buzz-acp@<short12>.service` — also the returned `agent_id` |
| Env file | `/etc/buzz/acp-<short12>.env` |
| Drop-in dir | `/etc/systemd/system/buzz-acp@<short12>.service.d/` |
| Secret | `buzz-agent-<short12>-private-key` |
| Runtime dir | `/run/buzz-acp-<short12>/` |

The management marker is a header comment written into every file this provider
creates:

```
# managed-by: buzz-backend-gcp
# binding-version: 1
# agent-pubkey-full: <64 hex>
# create-intent: <sha256 of the rendered spec>
```

`agent-pubkey-full` is what makes the 12-hex name safe: truncation is
collision-*resistant*, not collision-free, so a candidate whose full pubkey does
not match fails closed to the operator. **No destructive action may touch a
file lacking the marker** — that is the auto-repair fence.

## Deploy Reconciliation (I4)

`deploy` is not "create". The desktop issues it unconditionally on every Start
and tracks no substrate state (M1). The loop:

```
0. Derive AgentIdentity from private_key_nsec.          (before any mutation)
1. Observe: systemctl show buzz-acp@<short12> + read the marker header.
2. Classify:
     no unit                      -> create
     unit exists, marker mismatch -> refuse, name the conflict
     unit exists, full pubkey differs -> refuse (collision)
     active + harness running     -> STRICT NO-OP, return agent_id
     failed / inactive, same create-intent  -> observe, never delete; restart only
     failed / inactive, divergent intent    -> fenced replace
3. Act. Every destructive write is fenced to the exact observation that
   authorized it: re-read the create-intent hash immediately before removal and
   abort if it changed.
4. Success only on confirmed harness start: poll `systemctl is-active` and the
   journal for the harness's startup line, with a bounded timeout.
5. Delete-of-absent is success. Conflicts converge by re-entry.
```

The strict no-op on a live instance is the clause that forbids the obvious
"rewrite the files and `systemctl restart`" implementation: that would bounce a
healthy agent every time the user clicks Start.

## Remote Artifacts

Four files, all installed by piping the body on **stdin** —
`ssh ... 'install -m 0600 /dev/stdin <path>'` — so no content reaches argv,
`ps`, or shell history.

1. **`/etc/systemd/system/buzz-acp@.service`** — the template unit, written
   once and shared by all instances.

```ini
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
```

Deliberately mirrors the existing hardened unit, with three differences:
`Restart=no` (I5), `TimeoutStopSec=120` (I3 staleness), and the second
`EnvironmentFile` for the tmpfs secret. `MemoryMax`/`CPUQuota` move to the
per-instance drop-in so they are configurable.

2. **`/etc/systemd/system/buzz-acp-secret@.service`** — the fetcher. Runs as
   root *outside* the agent unit's cgroup, which is the only way to reach the
   metadata server for SA credentials.

```ini
[Unit]
Description=Materialize the Buzz agent key for %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
RuntimeDirectory=buzz-acp-%i
RuntimeDirectoryMode=0750
ExecStart=/usr/local/sbin/buzz-acp-fetch-key %i
```

`RuntimeDirectory=` gives a tmpfs under `/run` that systemd reaps when the unit
stops. `buzz-acp-fetch-key` is a small root-owned shell script the provider
installs, which runs `gcloud secrets versions access latest` and writes
`BUZZ_PRIVATE_KEY=` / `NOSTR_PRIVATE_KEY=` at mode 0400 owned by `buzzacp`.

3. **`/etc/buzz/acp-<short12>.env`** — non-secret environment, 0600 root.

4. **`.../buzz-acp@<short12>.service.d/agent.conf`** — per-instance
   `MemoryMax`, `CPUQuota`, and the marker header.

## Capacity

Before creating a unit, sum `MemoryMax` across existing `buzz-acp@*` units plus
the standing `buzz-acp.service`, and compare against `MemoryAvailable`. On
overcommit, emit to **stderr** and continue:

```
warning: buzz-agent has 2.7G available; existing units reserve 2G.
Adding buzz-acp@a1b2c3d4e5f6 (2G) may cause OOM kills.
Lower memory_max or resize the instance to e2-standard-4.
```

stderr is the reliable channel: the desktop captures and redacts it, whereas the
`deploy` response is validated only for `agent_id` and an extra field would not
be rendered.

## Operator Surface

The desktop passes no argv, so argv is free. These are not protocol operations
and the desktop never invokes them:

| Command | Effect |
|---|---|
| `buzz-backend-gcp list` | Marked units on the instance, with state and pubkey. |
| `buzz-backend-gcp remove <agent_id>` | Stop, disable, delete files, destroy the secret. Marker-fenced. |
| `buzz-backend-gcp --dry-run < request.json` | Print rendered artifacts with secrets redacted; touch nothing. |

`remove` exists because the protocol has no `stop`: I5 routes intentional
termination through `!shutdown` on the relay, and this is the operator's path to
reclaim the substrate afterwards.

## Security Properties

**Holds.** The nsec never reaches argv or the boot disk; it lives in Secret
Manager (encrypted, audited, IAM-scoped) and a tmpfs file readable only by
`buzzacp`. `provider_config` carries no credentials. Destructive actions are
marker-fenced and identity-verified. The agent unit keeps every sandbox
directive the existing deployment uses.

**Does not hold, stated plainly.** The provider is handed the agent's private
key by design — that is its function. It executes with the operator's own
gcloud identity and can do anything that identity can. Root on the VM can read
the tmpfs key. A disk snapshot no longer captures the key, but a memory dump
would. This binding does not claim isolation from a hostile provider; the spec's
§Scope explicitly places that out of scope.

## Testing

| Layer | Method |
|---|---|
| `buzz-backend-core` | The existing k8s test suite must stay green after extraction — that is the regression gate for the move. |
| Wire contract | The shared golden fixtures, driven through the **built** `buzz-backend-gcp` binary over a real pipe: asserts one JSON object, correct fields, correct exit code. |
| `render.rs` | Golden byte comparison of all four artifacts. Explicit case: an owner variable is always present. Explicit case: `Restart=no`, never `always`. |
| `capacity.rs` | Table test over headroom arithmetic and the warning string. |
| Reconciler | Classification table over synthetic observations. |
| Live | One smoke deploy against `buzz-agent`: deploy → assert active → assert the journal shows relay auth → re-deploy and assert **zero mutation** → `remove`. |

## Non-Goals

No VM creation or autoscaling. No log streaming to the desktop (M1: no
management channel). No `stop` operation. No changes to `deploy/gcp/`
Terraform. No Docker on the VM. No `OnFailure` supervision until the harness
clean-exit contract is pinned.

## Follow-ups (out of scope, recorded)

1. The live `buzz-acp.service` uses `Restart=always` (non-conforming, L1 item 5)
   and its owner configuration lives in an out-of-band drop-in (`team.conf`)
   that the Terraform template does not render.
2. `deploy/gcp/templates/agent-startup.sh.tftpl` renders `goose` +
   `ANTHROPIC_API_KEY` while the instance actually runs `codex-acp` with ChatGPT
   auth. With `ignore_changes = [metadata_startup_script]`, a VM recreation
   would produce a different, ownerless agent.
3. `docs/remote-agents.md` needs an `[L3] GCE/systemd binding conformance`
   section; L2 item 6 requires every binding to document how it realizes each
   L2 term.
