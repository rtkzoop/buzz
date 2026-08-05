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

### Transport, `PATH`, and host trust

**`PATH`.** The provider is exec'd by a Tauri app that inherits launchd's
minimal `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`). `gcloud` installs to
`/opt/homebrew/bin`, `/usr/local/bin`, or `~/.local/bin` on a normal macOS
machine — none of which are on that `PATH` — so a bare `Command::new("gcloud")`
fails to resolve for a reason that has nothing to do with GCP. Before its first
`gcloud` spawn the provider prepends those three directories to its own `PATH`.
This is not a new idea: the Kubernetes binding already carries the identical fix
and names this exact cause in its doc comment
(`crates/buzz-backend-kubernetes/src/client.rs:12-19` defines
`PATH_PREPEND = ["/opt/homebrew/bin", "/usr/local/bin"]` and appends
`$HOME/.local/bin` at `:26-28`; `prepended_path` at `:24-34`,
`prepend_plugin_path` at `:41-47`). Two details carry over verbatim, because
they are the parts that are easy to get wrong:

- Mutating the process's own `PATH` is sound here — one process per operation,
  done before any child exists (`client.rs:36-40`).
- Empty entries in the inherited `PATH` are **dropped**, not propagated: an
  empty `PATH` splits into one empty entry, which POSIX resolves as the current
  directory, which is not a place `gcloud` may be found (`client.rs:29-32`).

A `gcloud` that still does not resolve is a named refusal stating the remedy,
never a bare `NotFound` (`client.rs:50-57` is the equivalent probe).

**Host trust.** Every VM call is `gcloud compute ssh --tunnel-through-iap`,
which execs the real `ssh`. Both properties below were verified by dumping the
generated argv on this host (`gcloud compute ssh buzz-agent --zone
asia-south1-a --tunnel-through-iap --dry-run --command true`):

```
/usr/bin/ssh -T -i ~/.ssh/google_compute_engine -o CheckHostIP=no
  -o HashKnownHosts=no -o HostKeyAlias=compute.5148504320112428893
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile=~/.ssh/google_compute_known_hosts
  -o "ProxyCommand ... compute start-iap-tunnel buzz-agent %p --listen-on-stdin
      --project=zoop-innovation --zone=asia-south1-a" ... -- true
```

1. **Local stdin reaches the remote command.** `gcloud` execs a real `ssh` with
   the remote command as trailing argv, and `ssh` forwards stdin to it. Verified
   empirically as well as structurally: 30 bytes piped into a remote `wc -c`
   returned `30` with a matching md5. This is what makes the stdin install path
   (§Remote Artifacts) sound — no `scp` staging and no remote temp files.
2. **`StrictHostKeyChecking` is left alone.** The provider passes no
   `-o StrictHostKeyChecking` at all, and specifically **not** `=no`. `gcloud`
   already selects `StrictHostKeyChecking=yes` against its own
   `~/.ssh/google_compute_known_hosts` (13 entries on this host), keyed by
   `HostKeyAlias=compute.<numeric instance id>` rather than by IP
   (`CheckHostIP=no`). Passing `no` would be a strict *downgrade* of a check
   that is already correct — while installing root-owned unit files over that
   same channel. The usual excuse for `no` does not apply either: a VM
   recreation (which `agent.tf`'s `ignore_changes` makes a real event) mints a
   **new** instance id, so the alias is new and the key is a fresh
   trust-on-first-use add, not a mismatch against a stale entry.

**`sudo -n`.** Every privileged step runs under `sudo -n`. Passwordless sudo is
verified on this host, so `-n` changes no outcome today; it stays because on a
host that *did* prompt, the prompt would consume the piped file body as
keystrokes and write a truncated root-owned unit file. `-n` turns that into a
clean refusal instead.

## Product Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Compute unit | systemd unit on the existing VM | Reuses the hardened sandbox and metadata blocker already there; ~5-10 s deploys; no new cost. |
| Agent key at rest | Secret Manager, materialized to tmpfs at start | I2 forbids credentials in `provider_config`; matches the pattern the deployment already uses; survives VM recreation, which `agent.tf`'s `ignore_changes` makes a real risk. |
| Implementation | Rust crate in the workspace | Repo convention, `just ci` coverage, and — decisively — a compiled binary has no interpreter to resolve when exec'd by a GUI app inheriting launchd's minimal `PATH`. |
| Shared logic | Extract `crates/buzz-backend-core` | The wire types and env algorithm are normative and substrate-neutral; two copies would drift on the next spec change. |
| Over-capacity deploy | Warn, record the warning durably on the instance, proceed | Operator preference is non-veto. But the desktop drops provider stderr on the success path (`backend.rs:287`), so a warning that lives only there is a warning nobody reads — see §Capacity. |
| Secret classification | Non-secret **allowlist**; everything else to Secret Manager | A two-key denylist leaves `auth_tag` and every API key from `env_vars`/`launch.env` on the persistent boot disk. The desktop already treats *every* deploy env value as secret-candidate material (`backend.rs:395-415`); this binding matches that posture instead of second-guessing it. |
| `gcloud` resolution | Prepend `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin` to `PATH` | Exec'd by a GUI app with launchd's minimal `PATH`; the Kubernetes binding already carries this fix (`client.rs:12-47`). |

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
| `main.rs` | One request in, one response out; exit code carries one bit. The raw-JSON `relay-mesh` refusal, before deserialization. Operator argv subcommands. | yes |
| `config.rs` | `provider_config` schema, parsing, and the closed grammars for `memory_max` / `cpu_quota` plus the control-character refusal. | yes |
| `render.rs` | Pure `payload -> Vec<RemoteFile>`: the secret/non-secret env split, unit template, fetcher unit, fetcher script, drop-in, trail record — each tagged with its marker tier. **Where the bugs live.** | yes |
| `naming.rs` | Unit names and both marker tiers, derived from `AgentIdentity`. | yes |
| `remote.rs` | `gcloud compute ssh` transport: `PATH` prepend, `sudo -n`, file bodies piped on stdin, no `StrictHostKeyChecking` override. | no |
| `secrets.rs` | Secret Manager create / add-version / IAM binding / destroy, each behind the label + full-pubkey ownership gate. | no |
| `observe.rs` | Read remote unit state into a typed observation. | no |
| `reconcile.rs` | The I4 state machine over `observe` + `render` + `remote`. | partially |
| `capacity.rs` | Headroom arithmetic, the warning string, and the trail record. | yes |

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
| `memory_max` | string | `2G` | systemd `MemoryMax`. Closed grammar — see below. |
| `cpu_quota` | string | `150%` | systemd `CPUQuota`. Closed grammar — see below. |
| `inactivity_seconds` | integer | `7200` | Feeds `BUZZ_ACP_EXIT_AFTER_INACTIVITY`. |

No field names a credential, satisfying I2 and the desktop's own key filter
(`backend.rs:536-566` rejects any key whose words include
`secret|password|token|key|credential`).

`inactivity_seconds: 0` is the blessed indefinite-lifetime opt-in and must not
be rejected as invalid — but see §Lifetime, which refuses it for a different,
spec-mandated reason.

#### Value grammars for the drop-in fields

`memory_max` and `cpu_quota` are the only config values this binding
interpolates into a **root-installed systemd drop-in**
(`.../buzz-acp@<short12>.service.d/agent.conf`). A drop-in is line-oriented and
systemd accepts every `[Service]` directive it finds there, so an accepted value
containing a newline *is* arbitrary unit content. The concrete threat is not
abstract: `2G\nEnvironmentFile=/tmp/x.env` adds a second environment source
whose values override the authoritative tier, and `2G\nExecStart=\nExecStart=/bin/sh -c ...`
uses systemd's empty-assignment reset to replace the agent command outright —
both while the file still carries a valid management marker, so every fence in
this design reads it as legitimately ours.

The desktop cannot catch this. `validate_provider_config` checks flatness,
field count, scalar-ness, and secret-like key *names*
(`desktop/src-tauri/src/managed_agents/backend.rs:536-566`); it never inspects
a value for embedded newlines. The provider is the only place this stops.

Both fields are therefore parsed against a closed grammar and **rejected**, not
sanitized, on any mismatch:

| Field | Grammar | Accepts | Rejects |
|---|---|---|---|
| `memory_max` | `^[0-9]{1,6}(\.[0-9]{1,3})?[KMGT]?$` — suffix case-sensitive, resolved to bytes, required `> 0` | `2G`, `512M`, `1.5G` | `2G\nExecStart=...`, `infinity`, `2 G`, `-1`, `0`, `1e9`, `2GB` |
| `cpu_quota` | `^[0-9]{1,3}%$` with the integer in `1..=200` | `150%`, `50%`, `200%` | `150`, `150%%`, `0%`, `400%`, `150%\nEnvironmentFile=...` |

`cpu_quota` is bounded at `200%` because the instance has 2 vCPU: a quota above
the vCPU count is unenforceable, so it is always either a typo or an attempt to
probe the parser, and both deserve the same refusal.

Independently of the two grammars, **every** `provider_config` string value is
scanned for `\r`, `\n`, and NUL and refused if any appears. That is a belt for
the next field added to the table above, so this class of defect cannot recur by
omission. The refusal names the field and the offending character class and
never echoes the value — an attacker-supplied value could itself be secret
material, and L2 item 5 forbids emitting that (`docs/remote-agents.md:1477-1478`).

### `deploy`

Returns `{"ok": true, "agent_id": "buzz-acp@<first-12-hex-of-pubkey>"}`.

Errors are in-band `{"ok": false, "error": "..."}` with exit code 0. Exit
nonzero only on a crash path, and never encode meaning in the value — the
desktop discards stdout entirely when the code is nonzero.

### Refusals that precede deserialization

L2 item 3 requires refusing a deploy "whose provider is `relay-mesh`"
(`docs/remote-agents.md:1453-1458`). This binding cannot enforce that after
deserialization: the shared `AgentPayload` deliberately does not carry the raw
`provider` field, so by the time a typed `DeployRequest` exists the evidence is
gone. The refusal therefore reads the **raw JSON**, before
`serde_json::from_value`, exactly as the Kubernetes binding does — parse to
`serde_json::Value` first (`crates/buzz-backend-kubernetes/src/main.rs:65-68`),
call the refusal (`:70-72`), and only then deserialize (`:74-77`):

```
raw["agent"]["provider"].as_str().trim() == "relay-mesh"  ->  refuse
```

The comparison is **trimmed**, and that is not cosmetic. The Kubernetes
binding's rationale (`main.rs:97-113`) applies verbatim: the desktop's own
layers disagree about padding — two of them trim, the deploy guard did not — and
the payload's non-blank helper preserves surrounding whitespace on a non-blank
value. *"A backstop that shares its bypass with the layer it backs is not a
backstop."*

The refusal is an in-band `{"ok": false, "error": "..."}` naming shared compute
and the remedy (switch the agent to a local runtime before deploying it to
GCE), never a crash — a shared-compute agent runs on the relay, so there is
nothing for this substrate to start and starting a second copy would violate I4
across substrates. Wire fixtures cover the exact spelling, a padded spelling
(`" relay-mesh "`), and a control case proving an ordinary provider value still
deploys.

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

### Binding-specific split: a non-secret allowlist

`build_env` yields one flat map. This binding splits it across two files by
sensitivity, and the split is an **allowlist of non-secret keys** — not a
denylist of known-secret ones.

A denylist was the earlier design (`BUZZ_PRIVATE_KEY` and `NOSTR_PRIVATE_KEY`
to Secret Manager, everything else to disk) and it is wrong on three counts.
`BUZZ_AUTH_TAG` is a bearer credential for the relay — the very thing L1 item 1
treats as interchangeable with a resolved owner pubkey for proving identity
(`docs/remote-agents.md:1416-1419`). Tier 1 and tier 2 are operator- and
definition-supplied maps that routinely carry `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, `GITHUB_TOKEN`, and whatever the next runtime needs, none of
which the provider can enumerate in advance. And a denylist writes every one of
them into `/etc/buzz/acp-<short12>.env` on the **persistent boot disk**, where a
disk snapshot or image capture picks them up — which makes the "the key never
reaches the boot disk" claim in §Security Properties true only of the one key
that happened to be named.

The desktop already refuses to draw this distinction. `env_secrets_from_request`
treats *every* non-empty string value in `env_vars`, `launch.env`, and
`launch.policy_env` as redaction-worthy secret material
(`desktop/src-tauri/src/managed_agents/backend.rs:395-415`), and its doc comment
says why: "Providers may echo any of these values in diagnostics, including
definition/baked values that exist only in the resolved launch block"
(`:392-394`). L2 item 5 forbids a provider from emitting secret material in any
output (`docs/remote-agents.md:1477-1478`). A provider whose classification is
*narrower* than the redaction it is being defended by has the polarity backwards.

So classification inverts. Exactly these keys are non-secret and stay in the
on-disk env file:

| Key | Why it is not secret |
|---|---|
| `BUZZ_RELAY_URL` | A public endpoint. |
| `BUZZ_ACP_AGENT_OWNER` | A public nostr pubkey. |
| `BUZZ_ACP_AGENT_COMMAND` | A binary name, already visible in `ps` and in the unit file. |
| `BUZZ_ACP_AGENT_ARGS` | Argv, already visible in `ps`. |
| `BUZZ_ACP_MCP_COMMAND` | A binary name. |
| `BUZZ_ACP_RESPOND_TO`, `BUZZ_ACP_RESPOND_TO_ALLOWLIST` | A mode name and a list of public pubkeys. |
| `BUZZ_ACP_EXIT_AFTER_INACTIVITY` | An integer number of seconds. |
| `BUZZ_MANAGED_AGENT_START_NONCE` | A per-attempt correlator that authorizes nothing and is already in the journal. |

**Everything else goes into the Secret Manager payload** — every key not on that
list, including `BUZZ_AUTH_TAG`, both nsec keys, and every tier-1/tier-2 key the
provider has never heard of — and is materialized to tmpfs by the fetcher unit.
The list is closed and the default is *secret*, so a new authoritative key added
to `buzz_backend_core::env` lands on the safe side without anyone remembering to
classify it. Note that `AUTHORITATIVE_KEYS`
(`crates/buzz-backend-kubernetes/src/env.rs:23-36`) is **not** the allowlist:
three of its twelve entries are secrets.

Both files are `EnvironmentFile=` entries on the unit, so the split changes no
value and no precedence. Two consequences worth stating:

- The secret payload is a multi-key `KEY=value` document rather than two fixed
  lines, so the fetcher writes the secret version's bytes through verbatim
  rather than composing them. The provider renders it with systemd
  `EnvironmentFile` quoting and refuses to upload a payload in which any value
  contains a raw newline — the same class of defect as §Value grammars, in the
  one other place this binding generates a file systemd parses.
- `/etc/buzz/acp-<short12>.env` (0600 root:root) now holds only allowlisted
  values, so its exposure surface is the unit file's own content. The secret
  file lives at `/run/buzz-acp-<short12>/secret.env`, 0400 `buzzacp`, on tmpfs.

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
| Secret | `buzz-agent-<short12>-private-key` (payload is the whole secret env, not just the key) |
| Runtime dir | `/run/buzz-acp-<short12>/` |

### Two marker tiers

The management marker is a header comment the provider writes into every file it
creates. But there are two kinds of file, and giving them the same marker makes
the marker mean nothing.

**Per-agent artifacts** — the env file, the drop-in, the deploy trail — carry the
full marker:

```
# managed-by: buzz-backend-gcp
# binding-version: 1
# agent-pubkey-full: <64 hex>
# create-intent: <sha256 of the rendered spec>
```

**Shared artifacts** — `/etc/systemd/system/buzz-acp@.service`,
`/etc/systemd/system/buzz-acp-secret@.service`, and
`/usr/local/sbin/buzz-acp-fetch-key` — carry a **provider-level marker with no
agent identity in it at all**:

```
# managed-by: buzz-backend-gcp
# binding-version: 1
# scope: provider-shared
# content-hash: <sha256 of the rendered body below this header>
```

The reason is mechanical. A template unit is installed once and used by every
instance. Stamping it with one agent's `agent-pubkey-full` and `create-intent`
means the next deploy of a *different* agent rewrites the same file with a
different identity, so the identity recorded on a shared file means nothing more
than "whoever deployed most recently" — while the fence that reads it is asking
"is this file *this* agent's?". Answering that question from a shared file is
wrong in both directions: it authorizes destroying a file three other agents
depend on, and it refuses when the file is legitimately ours. The provider-level
marker states exactly what is true — this provider wrote it, at this binding
version, with this content — and nothing that is not.

Shared artifacts are also **written only when absent, or when their
`content-hash` differs from the body this provider would render.** A deploy that
changes nothing shared performs zero writes there, which is what makes the
strict no-op on a live instance (§Deploy Reconciliation) actually strict rather
than "no-op except for three files rewritten identically". A shared file present
with a *different* `content-hash` is rewritten; a shared file present with **no
marker at all** is a refusal, not an overwrite — it is somebody else's file that
happens to share our name.

So the invariant the tests enforce is *"every installed file carries the marker
of its own tier"* — never *"every installed file carries the per-agent marker"*,
which is enforceable only by making the shared marker a lie.

`agent-pubkey-full` is what makes the 12-hex name safe: truncation is
collision-*resistant*, not collision-free, so a candidate whose full pubkey does
not match fails closed to the operator. **No destructive action may touch a file
lacking the marker of its own tier** — that is the auto-repair fence.

### Secret Manager ownership

The secret is the one artifact that does not live on the instance, so its marker
cannot be a header comment. It is **labels plus an annotation, written at create
time**:

| Field | Key | Value |
|---|---|---|
| label | `managed_by` | `buzz-backend-gcp` |
| label | `binding_version` | `1` |
| label | `agent_pubkey` | first 32 hex of the pubkey |
| annotation | `agent-pubkey-full` | all 64 hex |

`gcloud secrets create` takes both (`--labels=[KEY=VALUE,...]`,
`--set-annotations=[KEY=VALUE,...]`, verified in `gcloud secrets create --help`),
and the split mirrors the Kubernetes binding exactly: labels carry the marker and
the truncated selector (`crates/buzz-backend-kubernetes/src/naming.rs:10-23`),
the full pubkey is an annotation (`naming.rs:28`). Labels are the half that must
be selectable, which is what lets `list` enumerate our secrets server-side with
`--filter="labels.managed_by=buzz-backend-gcp"`.

**The marker is verified before every add-version, IAM binding, and delete — not
merely written.** The precedent is `secret_is_ours`, which requires *both* marker
halves *and* a full-pubkey match
(`crates/buzz-backend-kubernetes/src/observe.rs:64-67`, over `has_marker` at
`:42-46` and `annotation_matches` at `:52-60`), and whose own comment states the
principle: "Identity labels prove identity; the marker asserts protocol
ownership. Without it an object that merely matches our schema fails closed"
(`observe.rs:38-41`). The GC module spells out the consequence: "every one of
which must pass the full-pubkey annotation check *and* carry the management
marker. An unmarked object is never GC'd regardless of its labels"
(`crates/buzz-backend-kubernetes/src/gc.rs:3-7`).

Without that gate, a name-matching secret created by anything else — an operator,
another tool, an older binding version — receives this agent's whole secret env
as a new version *and* a grant of read access to the VM service account. Name
collision is not ownership. A present-but-unmarked secret, or one whose
`agent-pubkey-full` differs, is a **refusal naming the conflict**, never a
takeover.

**Destroy-before-forget.** `remove` destroys the secret *before* deleting the
local marker files. The reverse order — the earlier design — fails in a specific
way: markers gone, secret still holding a live key, and no local evidence left to
identify or retry it. Ordered this way, an interrupted `remove` is idempotent —
re-running it finds the marked files still present, the secret already gone, and
treats delete-of-absent as success (L2 item 4,
`docs/remote-agents.md:1476`).

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

Five files, all installed by piping the body on **stdin** —
`sudo -n install -m 0600 /dev/stdin <path>` — so no content reaches argv, `ps`,
or shell history. That path is sound because `gcloud compute ssh` execs a real
`ssh` which forwards local stdin to the remote command (§Transport, verified
empirically); no `scp` staging or remote temp file is involved.

1. **`/etc/systemd/system/buzz-acp@.service`** — the template unit, shared by all
   instances. Provider-level marker; written only when absent or when its
   `content-hash` differs.

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
   metadata server for SA credentials. Shared, so provider-level marker; same
   write-only-when-changed rule as the template unit.

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
stops. `RuntimeDirectoryMode=0750` root:root is not a problem for the agent unit:
systemd's **manager** reads `EnvironmentFile=` as root before dropping to
`User=buzzacp`. Verified on this same host — the running `buzz-acp.service` has
`User=buzzacp` and `EnvironmentFile=/etc/buzz/acp.env` at mode 0600 root:root,
and starts.

#### `/usr/local/sbin/buzz-acp-fetch-key` — hardening

A root-owned shell script, invoked by systemd as root with `%i` as its only
argument, that materializes the secret payload into the tmpfs directory. It is
the highest-privilege code this design installs, so it is specified rather than
left to the implementation:

| Requirement | Why |
|---|---|
| **Arity check**: exactly one argument, else exit nonzero with a message | Invoked with zero args (a hand-typed `systemctl start buzz-acp-secret@`) it would otherwise fetch `$1`-empty and write a path like `/run/buzz-acp-/secret.env`. |
| **Shape check**: `^[0-9a-f]{12}$` on `$1`, else refuse | `%i` is a systemd instance name and reaches the script unescaped. The shape is exactly what §Naming derives — 12 lowercase hex — so anything else is not one of ours and must not be turned into a Secret Manager name or a filesystem path. |
| **Explicit `--project`** on the `gcloud secrets versions access` call | Verified: the VM has `core/project=zoop-innovation` in its gcloud config, so an omitted `--project` works today by ambient accident. A `gcloud config unset project`, a different service account, or a VM rebuilt from a changed image turns that into `latest` resolved against the wrong project or no project at all. The provider passes `cfg.project` through so the script's behavior is a function of its inputs. |
| **Absolute `gcloud` path** (or an explicit `PATH=` line in the script) | Same class of defect as §Transport's `PATH` problem, one layer down: a script run by systemd inherits systemd's environment, not a login shell's. |
| **Atomic write**: render to `<dir>/secret.env.tmp` created with the final mode, then `mv` into place | A partial `secret.env` is not a truncated key — it is an `EnvironmentFile` missing its later lines, which for this binding's allowlist means an agent that starts *without* `BUZZ_AUTH_TAG` and fails identity assembly for a reason that looks nothing like a write error. `mv` within one tmpfs is a rename, so the agent unit never observes a half-written file. |
| **`set -euo pipefail`**, and the fetched value never echoed | L2 item 5: no secret material in output, and the journal is output. |
| **Sandbox directives on the unit**, matching the agent unit where they do not conflict with needing metadata access | `ProtectSystem=strict` with `ReadWritePaths=` limited to the runtime dir, `ProtectHome=true`, `NoNewPrivileges=true`, `PrivateTmp=true`, `RestrictSUIDSGID=true`, `LockPersonality=true`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`. Deliberately **absent**: `IPAddressDeny=169.254.169.254/32`, whose presence in the agent unit is the entire reason this second unit exists (§Substrate fact 2). |

3. **`/etc/buzz/acp-<short12>.env`** — allowlisted environment only, 0600 root.

4. **`.../buzz-acp@<short12>.service.d/agent.conf`** — per-instance `MemoryMax`,
   `CPUQuota`, and the per-agent marker header.

5. **`/etc/buzz/acp-<short12>.trail`** — the deploy trail, 0644 root, per-agent
   marker header, appended to on every deploy. See §Capacity.

## Capacity

Before creating a unit, sum `MemoryMax` across existing `buzz-acp@*` units plus
the standing `buzz-acp.service`, and compare against `MemoryAvailable`. Overcommit
is a **warning, not a refusal** — the operator asked for the risk to be reported,
not vetoed.

The hard part is not computing the warning; it is putting it somewhere the
operator will actually see it. The earlier design said "emit to stderr, the
desktop captures and redacts it". **That is false on exactly the path the warning
is emitted on.** `invoke_provider` builds `stderr_redacted` and then consults it
in two places only: when the child exited non-zero
(`desktop/src-tauri/src/managed_agents/backend.rs:252-260`) and when no line of
stdout parses as JSON (`:271-280`). On a successful deploy it falls through to
`Ok(response)` at `:287` and the buffer is dropped; `provider_deploy` then reads
one field, `agent_id` (`:529-532`). A successful deploy with a capacity warning
is a clean success in the UI, followed later by an OOM kill with nothing
connecting the two.

Adding a `warning` field to the response does not fix it either. It would not be
*rejected* — the unknown-field check exists only for `info` (`:48-63`), not for
`deploy` — it would simply never be read, and `docs/remote-agents.md:421` defines
the deploy response as `{"ok": true, "agent_id": str}`, so inventing a field is a
protocol change this binding has no authority to make unilaterally.

So the warning is recorded **durably on the instance**, in the per-agent deploy
trail (`/etc/buzz/acp-<short12>.trail`, 0644 root, per-agent marker header). Every
deploy appends one record; a warning becomes a `warning` line inside it:

```
deploy 2026-08-05T09:14:02Z generation=3f9c1a04 intent=8d1e77c2b0a4
warning capacity: buzz-agent has 2.7G available; existing units reserve 2G.
warning capacity: adding buzz-acp@a1b2c3d4e5f6 (2G) may cause OOM kills.
warning capacity: lower memory_max or resize the instance to e2-standard-4.
```

`buzz-backend-gcp list` prints each marked unit's state, pubkey, and **every
`warning` line from its trail**, so the warning outlives the process that emitted
it and is reachable without a management channel (M1 is not violated: the trail is
read by an operator running a command, not by the desktop). The same text still
goes to stderr, which costs nothing and *is* surfaced on the two failure paths
above.

The trail is subject to the same L2 item 5 rule as any other output: it carries
timestamps, the generation, the create-intent digest, and capacity arithmetic —
**never an environment value**. It is a 0644 file on a shared host, so treating it
as public is the only safe reading.

**Stated honestly:** the desktop cannot render a success-path warning today, and
nothing in this binding can make it. Closing that gap needs a desktop-side change
plus a `docs/remote-agents.md` amendment — recorded as §Follow-ups item 4, not
papered over here.

## Operator Surface

The desktop passes no argv, so argv is free. These are not protocol operations
and the desktop never invokes them. All three are kept, each for a reason that
survived review:

| Command | Effect | Why it exists |
|---|---|---|
| `buzz-backend-gcp list` | Marked units on the instance with state, pubkey, and every `warning` line from each unit's trail. Checks the `gcloud` exit status and fails loudly rather than printing nothing and exiting 0. | The only place a success-path capacity warning is readable (§Capacity). Not a `gcloud` one-liner: the marker filtering and the trail are this binding's own. |
| `buzz-backend-gcp remove <agent_id>` | Stop, disable, destroy the secret, then delete this agent's marked files. Fenced on the full pubkey. | The protocol has no `stop`: I5 routes intentional termination through `!shutdown` on the relay, and this is the operator's path to reclaim the substrate afterwards. |
| `buzz-backend-gcp --dry-run < request.json` | Print every rendered artifact with **all secret-classified values redacted**; touch nothing. | The operator's secret-leak inspection tool — see below. |

### `dry-run` is the secret-classification audit

`dry-run` earns its place by having one job beyond "look before you leap": it is
how a human confirms the §Binding-specific split allowlist actually held for a
*particular* payload. The allowlist is the whole defense for L2 item 5 in this
binding, and an allowlist is only as good as its last edit.

So `dry-run` prints the on-disk env file verbatim (every value in it is
allowlisted by construction — if a non-allowlisted key appears there, that *is*
the finding) and prints the Secret Manager payload with every value replaced by
`[REDACTED]`, keys intact. An acceptance criterion exercises it: render a payload
carrying an nsec, an `auth_tag`, and an `ANTHROPIC_API_KEY` in `launch.env`, then
assert that none of the three values appears anywhere in the output and that all
three keys appear in the secret payload.

### `remove` fences on identity, and deletes by name

Two rules, both from getting it wrong first:

1. **Verify `agent-pubkey-full`, not just `managed-by`.** `managed-by` proves
   only that this provider wrote the file; it says nothing about *which* agent.
   Since the 12-hex name is collision-resistant rather than collision-free, a
   `managed-by`-only fence would let `remove a1b2c3d4e5f6` destroy a different
   agent that truncated to the same 12 hex. The re-read immediately before each
   stop/disable/delete compares the whole per-agent marker tuple. This is the
   same fence `secret_is_ours` applies in the Kubernetes binding — marker *and*
   full-pubkey annotation, both (`observe.rs:64-67`).
2. **Delete only the files this provider knows it wrote — never a directory.**
   `rm -rf /etc/systemd/system/buzz-acp@<short12>.service.d/` is not a fence, it
   is a fence-shaped hole: a drop-in directory is exactly where an operator puts
   `override.conf` or `team.conf`, and the live host already has such an
   out-of-band drop-in (§Follow-ups item 1). `remove` deletes the enumerated,
   marker-verified paths — `agent.conf`, the env file, the trail — and then
   `rmdir`s the drop-in directory only if it is empty. A non-empty directory is
   reported, not emptied.

Shared artifacts are never touched by `remove`: they carry the provider-level
marker and other agents depend on them. Removing the last agent therefore leaves
the three shared files behind, which is correct — they are idempotent, contentless
with respect to identity, and re-verified by content hash on the next deploy.

## Security Properties

**Holds.** No secret-classified value reaches argv or the boot disk: the whole
secret env — nsec, `auth_tag`, and every unrecognized tier-1/tier-2 key — lives in
Secret Manager (encrypted, audited, IAM-scoped) and is materialized only to a
tmpfs file. `provider_config` carries no credentials, and its two interpolated
values are parsed against closed grammars so they cannot become systemd
directives. Destructive actions are marker-fenced on the full pubkey and delete
only enumerated paths. Secret Manager resources are label-verified before every
mutation. The agent unit keeps every sandbox directive the existing deployment
uses, and the fetcher unit keeps all of them except the one that would defeat its
purpose.

**Does not hold — no per-agent isolation.** Every instance runs as the same Unix
user, `buzzacp` (uid 999). Per-secret IAM therefore does **not** yield per-agent
isolation, and this document must not be read as claiming it does: the IAM binding
is scoped per secret, but the *reader* is one shared identity, so a compromised
agent can read a sibling's materialized key straight out of
`/proc/<sibling-pid>/environ`, or out of `/run/buzz-acp-<other>/secret.env` if the
directory mode permits. What per-secret IAM actually buys is a smaller blast
radius outside the VM (a leaked *service-account* token grants access to the named
secrets, not the project's) and an audit trail per secret. Inside the VM, agents
are mutually trusting.

This is **accepted residual risk for v1**, not an oversight, and the reason is
that closing it is a substrate change rather than a provider change: per-agent
isolation means a Unix user per agent (`User=buzz-acp-%i` with `DynamicUser=` or
provisioned accounts), per-user `ReadWritePaths`, per-user `RuntimeDirectory`
ownership, and re-homing `/var/lib/buzzacp`. Recorded as §Follow-ups item 5. Until
then the honest scope is: **agents on this instance are isolated from the
network and from the metadata server, not from each other.**

**Also does not hold, stated plainly.** The provider is handed the agent's private
key by design — that is its function. It executes with the operator's own gcloud
identity and can do anything that identity can. Root on the VM can read the tmpfs
secret. A disk snapshot no longer captures it, but a memory dump would. This
binding does not claim isolation from a hostile provider; the spec's §Scope
explicitly places that out of scope.

## Testing

| Layer | Method |
|---|---|
| `buzz-backend-core` | The existing k8s test suite must stay green after extraction — that is the regression gate for the move. |
| Wire contract | The shared golden fixtures, driven through the **built** `buzz-backend-gcp` binary over a real pipe: asserts one JSON object, correct fields, correct exit code. |
| Refusals | `relay-mesh` in the exact and padded spellings, plus a control provider value that deploys (§Refusals that precede deserialization). |
| `config.rs` | The injection payloads by name: `memory_max = "2G\nExecStart=/bin/sh -c id"`, `cpu_quota = "150%\nEnvironmentFile=/tmp/x"`, plus `\r`, NUL, `infinity`, `400%`, `0%`. Each must be a refusal, and the refusal must not echo the value. |
| `render.rs` | Golden byte comparison of all five artifacts. Per-agent artifacts carry the per-agent marker; shared artifacts carry the provider-level marker and **no** pubkey or intent. Explicit case: an owner variable is always present. Explicit case: `Restart=no`, never `always`. |
| **Secret leak** | Defined over **every secret-classified value**, not just the nsec. Build a payload carrying an nsec, an `auth_tag`, an `ANTHROPIC_API_KEY` in `launch.env`, and an unrecognized `SOME_NEW_TOKEN` in `launch.policy_env`; assert that **none** of those values appears in the rendered on-disk env file, in any unit or drop-in, in the trail, in stderr, in the JSON response, or in `dry-run` output — and that every one of their keys does appear in the Secret Manager payload. The old nsec-only grep is what let this class of defect through: it passes while four tokens leak. |
| `capacity.rs` | Table test over headroom arithmetic, the warning string, and the trail record it renders. |
| Reconciler | Classification table over synthetic observations. Includes present-but-unmarked and wrong-full-pubkey → `Refuse`. |
| `remove` | Table test: unmarked file → not deleted; wrong full pubkey → refusal; non-empty drop-in directory after deleting `agent.conf` → reported, not emptied; secret destroy ordered before marker deletion. |
| Live | One smoke deploy against `buzz-agent`: deploy → assert active → assert the journal shows relay auth → re-deploy and assert **zero mutation, shared files included** → `list` shows the unit → `remove` → assert the secret is gone and no unmarked file was touched. |

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
4. The desktop drops provider stderr on the success path
   (`desktop/src-tauri/src/managed_agents/backend.rs:287`) and `provider_deploy`
   reads only `agent_id` (`:529-532`), so a non-fatal provider warning cannot
   reach the UI. Closing this needs a `warning` field added to the normative
   deploy response in `docs/remote-agents.md:421` and rendered desktop-side.
   Until then §Capacity's trail plus `list` is the operator's only channel.
5. Per-agent Unix users on the instance. All instances currently share
   `buzzacp` (uid 999), which is why §Security Properties records same-UID
   sibling exposure as accepted residual risk rather than a solved problem.
