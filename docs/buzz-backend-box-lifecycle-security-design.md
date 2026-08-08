# `buzz-backend-box`: Lifecycle, Supervision, Secret Injection, and Reconciliation Design

**Status:** Design-level analysis grounded in the current Buzz source tree  
**Date:** 2026-08-08  
**Scope:** ASCII Box VM provider lifecycle, shutdown, secret handling, and deploy reconciliation

## Executive decision

1. Treat `buzz-acp`'s clean shutdown path as a **shutdown request protocol**, not as a reliable exit-code protocol yet. SIGINT, SIGTERM, owner `!shutdown`, and inactivity all enter the same shutdown watch and eventually publish offline presence before closing the relay. The normal path returns `Ok(())`, so it exits 0, but several semantically abnormal paths also break into the same cleanup and return 0. The current tree therefore cannot safely support `Restart=on-failure` without first pinning the harness exit contract.
2. Use a **systemd-managed supervision unit with a small launcher**, `Restart=no`, explicit signal forwarding to the Docker container, and a self-stop-on-exit path. Do not use a bare shell command or `Restart=always`.
3. Use a deterministic Box identity claim before any secret injection. Create candidates with `noEnv: true`; only the winner receives the nsec and launch environment.
4. Treat Box lifecycle state as substrate state, not harness liveness. Harness liveness is observed from an in-VM service marker plus fresh relay presence during deploy; Desktop's live indicator remains kind `20001` presence.
5. Mirror Kubernetes' ordered reconciliation rules, but replace Pod facts with Box facts: ownership marker, full pubkey, launch-intent fingerprint, Box lifecycle state, service state, and presence. Never recycle merely because a provisioning operation is old or a Box is `ready`/`idle`.

## Evidence model

- **Evidence** means directly supported by the cited repository code or specification.
- **Inference/design** means a recommendation derived from those facts for Box.
- **Unknown/live validation** means the current repository cannot establish the behavior and a real Box account or an API contract test is required.

---

## 1. `buzz-acp` shutdown behavior and exit status

### 1.1 Signals enter one shutdown channel

`buzz-acp` installs two asynchronous signal listeners:

- `tokio::signal::ctrl_c()` sends the shutdown watch signal for Ctrl-C/SIGINT.
- On Unix, a `SIGTERM` listener waits for the signal and sends the same watch signal.

**Evidence:** `crates/buzz-acp/src/lib.rs:1703-1721`.

The main event loop handles `shutdown_rx.changed()`, logs `"shutting down"`, and breaks out of the loop at `crates/buzz-acp/src/lib.rs:2446-2449`. This means systemd's SIGTERM must reach the `buzz-acp` process or a wrapper must forward it.

### 1.2 Owner `!shutdown` is a verified relay control message

The relay event path tests for a message with:

- the stream-message kind,
- content exactly `!shutdown` after trimming,
- a `p` tag mentioning this agent's derived public key,
- a sender matching the resolved owner public key.

The owner check and shutdown watch send are at `crates/buzz-acp/src/lib.rs:2112-2134`; the reusable predicate is at `crates/buzz-acp/src/lib.rs:2847-2856`.

A non-owner message containing `!shutdown` is not treated as control. It falls through as a regular message. This is important for Box: the launcher must not invent a second stop command or try to infer owner intent from process output.

### 1.3 Inactivity is an independent graceful shutdown path

The expiry predicate is:

```rust
!bound.is_zero() && !turn_in_flight && now.duration_since(last_activity) >= bound
```

**Evidence:** `crates/buzz-acp/src/lib.rs:1231-1238`.

The timer is created independently of pool readiness. A zero bound disables it; otherwise the polling interval is capped at 30 seconds. **Evidence:** `crates/buzz-acp/src/lib.rs:1662-1675`.

When the bound expires and there is no queued/in-flight turn or heartbeat, the main loop sends the same shutdown watch signal used by external shutdown. **Evidence:** `crates/buzz-acp/src/lib.rs:2359-2378`.

The specification confirms the intended semantic definition: inactivity is no dispatched work and no in-flight turn; raw relay traffic does not reset it. The reaper must be independent of lazy pool readiness. **Evidence:** `docs/remote-agents.md:916-949`.

The current Kubernetes provider defaults the bound to 7200 seconds and rejects `inactivity_seconds: 0` because its `Never` restart policy is not yet safe for indefinite agents. **Evidence:** `crates/buzz-backend-kubernetes/src/config.rs:33-62`, `crates/buzz-backend-kubernetes/src/config.rs:148-175`.

### 1.4 Shutdown ordering and grace budget

After the event loop breaks, the harness:

1. Signals wake tasks and waits up to 30 seconds for them to drain.
2. Waits up to 30 seconds for in-flight prompts.
3. Aborts remaining tasks after the prompt grace expires.
4. Reaps late-arriving and idle ACP children.
5. Cancels an in-flight presence heartbeat.
6. Publishes `offline` with a 2-second timeout.
7. Calls `relay.shutdown()`, which sends a WebSocket close command and waits up to 5 seconds for the relay task.
8. Logs `buzz-acp stopped` and returns `Ok(())`.

**Evidence:** `crates/buzz-acp/src/lib.rs:2710-2770`, `crates/buzz-acp/src/lib.rs:2777-2801`, and `crates/buzz-acp/src/lib.rs:2803-2831`.

The relay-side graceful shutdown sends a WebSocket close frame and waits up to 5 seconds before aborting the background task. **Evidence:** `crates/buzz-acp/src/relay.rs:909-925`. The background task handles `RelayCommand::Shutdown` by sending `Message::Close(None)` and returning. **Evidence:** `crates/buzz-acp/src/relay.rs:1895-1903`.

The declared Kubernetes budget is 60 seconds. **Evidence:** `crates/buzz-backend-kubernetes/src/config.rs:54-62` and `crates/buzz-backend-kubernetes/src/pod.rs:152-161`. However, the specification explicitly says the current shutdown tail is not proven to fit inside 60 seconds because per-slot reaping runs outside the main 30-second timeout. **Evidence:** `docs/remote-agents.md:875-910` and `docs/remote-agents.md:1199-1213`.

**Design consequence:** A Box unit should provision an operational margin, for example `TimeoutStopSec=120s`, until the harness has one shared shutdown deadline with a reserved finalization slice. A 60-second number is currently a declared Kubernetes budget, not a proven upper bound for the current `buzz-acp` implementation.

### 1.5 Clean versus crash exit codes

The binary entry point is:

```rust
fn main() -> anyhow::Result<()> {
    buzz_acp::run()
}
```

**Evidence:** `crates/buzz-acp/src/main.rs:1-3`.

Therefore:

| Path | Current observed behavior | Launcher meaning |
|---|---|---|
| SIGINT/SIGTERM | Sends the shutdown watch, performs graceful cleanup, returns `Ok(())` | Normal clean path, normally exit 0 |
| Owner `!shutdown` | Same shutdown watch and cleanup path | Intentional clean path, normally exit 0 |
| Inactivity expiry | Same shutdown watch and cleanup path | Intentional clean path, normally exit 0 |
| Unhandled `Err` from `run` | `anyhow::Result` reaches `main` | Nonzero process exit under Rust's `Termination` implementation |
| Panic | Process aborts through the normal panic runtime | Usually nonzero, commonly 101, but not a protocol guarantee |
| SIGKILL / VM loss | No cleanup; presence remains until relay TTL | Signal-derived failure such as 137 or no process status |
| ACP child exits | Harness normally respawns the child | Not a harness-level restart signal |
| All ACP slots die / circuit opens | `LoopAction::Exit` breaks the loop and the same cleanup returns `Ok(())` | Semantically abnormal, but currently can look like exit 0 |
| Relay background stream dies and reconnect fails | The event branch breaks after logging the failure | Semantically abnormal, but can also reach the same clean return path |

The child-crash path demonstrates the ambiguity: `PromptOutcome::AgentExited` is normally respawned, but when the circuit is open and no live slots remain, `handle_prompt_result` returns `LoopAction::Exit` at `crates/buzz-acp/src/lib.rs:3370-3409`; the outer loop then performs the normal cleanup and returns `Ok(())` at `crates/buzz-acp/src/lib.rs:2446-2449` and `crates/buzz-acp/src/lib.rs:2830-2831`.

The specification calls this out directly: intentional clean exit must be 0 and abnormal exit nonzero before a supervisor can safely use `Restart=on-failure`; at the cited revision this is a known defect. **Evidence:** `docs/remote-agents.md:264-285` and `docs/remote-agents.md:1411-1436`.

**Decision:** Box v1 must use `Restart=no`. The launcher should self-stop the Box after any unplanned container exit, but should not use the exit code to decide whether to restart. If a future harness release pins `intentional=0` and `abnormal!=0` with tests, a bounded `Restart=on-failure` policy can be reconsidered for explicitly indefinite agents.

---

## 2. Presence and the graceful-shutdown window Desktop relies on

### 2.1 Online/offline event

The harness publishes a self-signed ephemeral kind `20001` event. Its content is a bare status string: `online`, `away`, or `offline`. **Evidence:** `crates/buzz-acp/src/lib.rs:69-90`; the constant is `KIND_PRESENCE_UPDATE = 20001` at `crates/buzz-core/src/kind.rs:450`.

The harness publishes `online` only after connecting, discovering/subscribing to channels, and reaching the readiness boundary. **Evidence:** `crates/buzz-acp/src/lib.rs:1564-1571`.

It refreshes online presence every 60 seconds. **Evidence:** `crates/buzz-acp/src/lib.rs:1640-1647` and `crates/buzz-acp/src/lib.rs:2403-2421`.

On shutdown it publishes `offline` with a 2-second timeout before closing the relay. **Evidence:** `crates/buzz-acp/src/lib.rs:2803-2820`.

The relay verifies the ephemeral event, clears presence for `offline`, and stores all other statuses with a TTL. **Evidence:** `crates/buzz-relay/src/handlers/event.rs:762-828`. The TTL is 180 seconds, three times the 60-second heartbeat; clean disconnect deletes the Redis key immediately. **Evidence:** `crates/buzz-pubsub/src/presence.rs:1-5`, `crates/buzz-pubsub/src/presence.rs:15-16`, and `crates/buzz-pubsub/src/presence.rs:27-58`.

### 2.2 What Desktop can and cannot infer

Desktop treats remote presence as the live status signal. A stored `backend_agent_id` only records that infrastructure was deployed. The remote-agent spec states that `start` unconditionally invokes `deploy`, and `deploy` is a convergence operation rather than a create-only operation. **Evidence:** `docs/remote-agents.md:632-638` and `docs/buzz-backend-box-research.md:87-107`.

A Box `ready` or `idle` state therefore cannot be displayed as harness-online. Box documentation also says self-run processes do not update those lifecycle states. **Evidence:** `docs/buzz-backend-box-research.md:324-329`.

### 2.3 Graceful-stop expectation

The Desktop-level stop command for a remote agent is an owner-authenticated `!shutdown`, not a provider `stop` operation. The harness is expected to drain turns, publish offline, and close the relay. **Evidence:** `docs/remote-agents.md:875-914`.

For Box, the substrate-specific rule is:

```text
systemd/Box termination signal
        -> launcher trap
        -> docker stop --time=<grace>
        -> container PID 1 / buzz-acp receives SIGTERM
        -> buzz-acp publishes offline and closes WSS
        -> launcher waits, then permits Box archive
```

The specification's launcher conformance rule requires both directions: harness exit must terminate the substrate execution unit, and substrate termination must reach the harness. **Evidence:** `docs/remote-agents.md:965-980` and `docs/remote-agents.md:1411-1436`.

---

## 3. Kubernetes invariants 4 and 5, and the Box state machine

### 3.1 Kubernetes implementation in detail

The Kubernetes provider performs identity verification before cluster contact or mutation. **Evidence:** `crates/buzz-backend-kubernetes/src/main.rs:115-134`; the derivation itself is `crates/buzz-backend-kubernetes/src/naming.rs:46-59`.

Candidate verification is structural, not just name-based:

- The full derived pubkey must match the annotation.
- The provider management marker and binding version must be present.
- Unverified objects never reach classification or destructive actions.

**Evidence:** `crates/buzz-backend-kubernetes/src/observe.rs:1-18`, `crates/buzz-backend-kubernetes/src/observe.rs:38-67`.

The pure classifier has six meaningful observations and six actions:

```text
no object                         -> Create
marked for deletion               -> AwaitDisappearance
started harness container         -> NoOp(existing agent_id)
terminated container              -> Delete(fenced), then recreate
never-started provably broken     -> Delete(fenced), then recreate
never-started pull failure        -> Report, never delete
never-started recoverable + same intent
                                   -> Observe, never delete
never-started recoverable + changed intent
                                   -> Delete(fenced), then recreate
```

**Evidence:** `crates/buzz-backend-kubernetes/src/classify.rs:83-169`.

The classifier checks deletion before startup because a gracefully deleting Pod remains phase `Running`. **Evidence:** `crates/buzz-backend-kubernetes/src/classify.rs:114-123`. `Started` means the target container's `state.running`, not Pod phase. **Evidence:** `crates/buzz-backend-kubernetes/src/observe.rs:69-119`.

The reconciler runs this table in a loop with a 600-second operation deadline and a two-second poll interval. It never treats Pod acceptance as success; only a started harness container returns an `agent_id`. **Evidence:** `crates/buzz-backend-kubernetes/src/reconcile.rs:98-119`, `crates/buzz-backend-kubernetes/src/reconcile.rs:351-404`.

Important race protections:

- A delete carries the UID and `resourceVersion` fence from the exact observation that authorized it. **Evidence:** `crates/buzz-backend-kubernetes/src/classify.rs:19-26`; `crates/buzz-backend-kubernetes/src/reconcile.rs:406-443`.
- Delete-not-found is success; a precondition conflict causes re-entry, not a delete retry using a newer observation. **Evidence:** `crates/buzz-backend-kubernetes/src/reconcile.rs:40-51`, `crates/buzz-backend-kubernetes/src/reconcile.rs:429-443`.
- A create race loser drops only its own per-attempt Secret and adopts the deterministic winner without repairing it. **Evidence:** `crates/buzz-backend-kubernetes/src/reconcile.rs:278-347` and `crates/buzz-backend-kubernetes/src/reconcile.rs:446-484`.
- A Pod created by the current deploy call is never hot-delete/recreated during the same call. It reports the failure and leaves the next Start to perform preflight cleanup. **Evidence:** `crates/buzz-backend-kubernetes/src/reconcile.rs:364-373` and `crates/buzz-backend-kubernetes/src/reconcile.rs:406-427`.

The create-intent fingerprint is deliberately non-secret. It hashes a canonical template containing image, resources, restart policy, grace, workspace shape, and sorted environment **keys**, but never Secret values or generation identity. **Evidence:** `crates/buzz-backend-kubernetes/src/intent.rs:1-21`, `crates/buzz-backend-kubernetes/src/intent.rs:60-86`, and `crates/buzz-backend-kubernetes/src/intent.rs:91-133`.

This gives the intended I4/I5 semantics:

- **I4, single live instance:** a started harness is strict no-op, races converge on one deterministic winner, and no live generation is patched or replaced.
- **I5, no resurrection:** the running unit is not automatically restarted after intentional clean exit. A later explicit Start may reconcile and launch a new generation.

### 3.2 Box-specific state model

Box state and harness state must be separate axes:

```text
Box lifecycle:       absent | provisioning | ready | idle | archiving | archived | error
Harness lifecycle:   unknown | never-started | live | exited-intentional | exited-abnormal
Relay status:         absent | online | away | offline/stale
Intent:               absent | matching | divergent
Ownership:            unclaimed | candidate | claimed-and-verified | collision
```

**Inference/design:** `ready` and `idle` are only substrate states. The Box provider should query a fixed systemd service and the service's non-secret state marker during `deploy`; it should not use Box state as proof that `buzz-acp` is live.

A proposed Box reconciliation loop:

```text
1. Derive pubkey from nsec. Refuse before any Box mutation if invalid.
2. Locate or claim the deterministic Box identity using a non-secret marker.
3. Verify full pubkey + provider management marker before adopting any candidate.
4. Inspect Box lifecycle state, service state, intent fingerprint, and recent presence.
5. Apply the table below.
6. After every mutation, re-read state and re-enter the table.
7. Return success only after the launcher/service is confirmed started and the
   harness has crossed its readiness boundary. Return Box ID as agent_id.
```

### 3.3 Box state × harness state reconciliation table

| Box state | Harness/service observation | Intent/ownership | Action on an explicit `deploy`/Start | Automatic action without Start |
|---|---|---|---|---|
| Absent | None | None | Create with `noEnv: true`; wait for ready; claim deterministic subdomain; on claim success write marker, inject secrets, launch; confirm service and fresh presence | None |
| Provisioning / cloning | Unknown or never-started | Claimed candidate or same verified intent | Observe until ready, archived, or terminal error. Timeout reports current state and does not recycle merely because of age | None |
| Ready / idle | Service active; fresh `online`/`away` presence | Claimed, matching | **Strict no-op**, return existing Box ID. Do not rewrite env, restart container, or change Box state | None |
| Ready / idle | Service inactive; launch marker absent | Claimed, no live harness | Inspect startup evidence. If provider-created and provably broken, archive/replace only with a compare-and-recheck fence. If recoverable, observe/report. A new explicit Start may launch after the old unit is stopped | Never auto-launch |
| Ready / idle | Service inactive; prior intentional stop marker | Claimed, matching or current explicit intent | Treat this call as the new owner Start: launch only after confirming the prior unit is fully stopped. Do not let systemd resurrect it by itself | No resurrection |
| Ready / idle | Service inactive; prior abnormal exit marker | Claimed, matching | Report the prior failure or launch only because this is an explicit Start. Do not use `Restart=on-failure` in v1 | No resurrection |
| Ready / idle | Service inactive; fingerprint differs | Claimed, never-started or not-live | If no harness ever started and the Box API supports a fenced archive/replace, archive and relaunch. If a harness is live, strict no-op wins over divergence | None |
| Archived | None | Claimed, marker verified | Resume; wait for ready; verify service unit and intent; inject current environment; launch; confirm startup | None |
| Archiving | None or stopping | Claimed | Wait for archived, then follow the Archived row for this explicit Start. Do not race a stop/archive request with resume | None |
| Error | Unknown | Unverified or ambiguous | Return a redacted actionable error. Replace only if the Box is positively provider-owned, not live, the intent is known, and the API gives a safe compare-and-replace or archive path | None |
| Any state | Candidate loses deterministic claim | Candidate not claimed | Stop/archive the losing candidate **before** injecting nsec; adopt and observe the winner | None |

The key I5 property is that `!shutdown` and inactivity cause the in-Box service to stop itself and then archive the Box. No background controller is allowed to call `resume` after that event. A later explicit Desktop Start is allowed to resume it because the specification defines finality as final to automatic restart, not final against a new owner action. **Evidence:** `docs/remote-agents.md:243-249`.

---

## 4. Recommended Box supervision design

### 4.1 Prefer systemd plus a fixed launcher

**Inference/design:** Use systemd rather than a user-invoked plain launcher script because the VM may resume after a snapshot, the process must be observable through a stable unit, and the launcher needs a defined stop hook. The unit must not restart an intentional clean exit.

A plain script is acceptable only as the `ExecStart` implementation under systemd. A script started by an SSH session or a Box command API is not sufficient: it has no reliable lifetime owner and can leave a billed VM behind after the process exits.

### 4.2 Unit sketch

```ini
# /etc/systemd/system/buzz-agent.service
[Unit]
Description=Buzz ACP agent in Docker
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/buzz-agent

# The launcher is the signal receiver and owns the Docker child.
ExecStart=/usr/local/libexec/buzz-box-supervise
ExecStop=/usr/local/libexec/buzz-box-external-stop
ExecStopPost=/usr/local/libexec/buzz-box-poststop

# Intentional exits are final. Do not let systemd resurrect !shutdown or inactivity.
Restart=no

# Only the launcher receives SIGTERM first. It forwards the signal with
# `docker stop --time=...` and waits for the container.
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=120s
SendSIGKILL=yes
FinalKillSignal=SIGKILL

# Do not put credentials in this unit or in an Environment= line.
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=multi-user.target
```

The 120-second timeout is an operational Box margin, not a claim that the current ACP implementation has a 120-second formal bound. It should be reduced or aligned with the future shared ACP deadline after that contract is implemented.

`ExecStop` is intentionally a small helper that records an external-stop intent before asking the launcher/container to stop. The launcher also records the intent in its SIGTERM trap, so direct systemd termination is covered. `ExecStopPost` is a last-resort cleanup path; it must never pass credentials in arguments and must consult the root-owned intent file before calling `box stop self`.

### 4.3 Launcher pseudocode

```text
buzz-box-supervise:
  set umask 077
  acquire exclusive lock /run/buzz-agent/supervisor.lock
  invocation = random non-secret nonce
  state = /run/buzz-agent/state.json
  env_file = /run/buzz-agent/env.pending
  container = buzz-agent-<derived-pubkey-prefix>

  external_stop = false
  on SIGTERM or SIGINT:
      external_stop = true
      atomically write state { invocation, stop_intent: "external" }
      docker stop --time=110 container || true
      # Do not call `box stop self` from this path.

  install signal handlers before starting Docker
  verify env_file is root-owned, mode 0600, and has the expected invocation marker
  verify the image reference is the approved immutable digest

  docker run --name container \
      --mount type=bind,src=/run/buzz-agent/env.pending,dst=/run/buzz-agent/env.pending,ro \
      approved-image@sha256:<digest> \
      /usr/local/libexec/buzz-box-entrypoint /run/buzz-agent/env.pending &
  child = $!

  wait for the entrypoint's non-secret "env-consumed" readiness marker
  remove the host-side env_file, regardless of readiness result
  wait child
  child_status = $?

  if external_stop or state.stop_intent == "external":
      docker rm -f container || true
      exit 0

  atomically write state {
      invocation,
      stop_intent: "self",
      child_status,
      exited_at
  }
  docker rm container || true

  # This is the VM coupling point. It runs after any unplanned harness exit too,
  # so a crash cannot leave a billed VM running. It is not a restart operation.
  box stop self
  exit child_status
```

The fixed container entrypoint must use `exec`, not `bash -c "... buzz-acp"`:

```bash
#!/bin/sh
set -eu
umask 077
env_file="$1"

# Parse a safe, non-shell-evaluated canonical env format. Do not `source` an
# arbitrary file and do not put values in argv. The real implementation should
# use a small fixed parser for length-prefixed records or canonical JSON.
read_and_export_env_without_eval "$env_file"
rm -f -- "$env_file"
printf '%s\n' consumed > /run/buzz-agent/env-consumed

exec buzz-acp
```

The `exec` requirement is directly consistent with the existing remote-agent guidance: a shell that remains PID 1 can swallow SIGTERM and leave presence online until force-kill. **Evidence:** `docs/remote-agents.md:1050-1065`.

### 4.4 Stop-vs-restart decision

- **v1:** `Restart=no`. Any harness exit causes the launcher to stop/archive the Box unless the systemd stop path has already marked the stop as external.
- **Do not use `Restart=always`:** it resurrects after `!shutdown` and violates I5. **Evidence:** `docs/remote-agents.md:243-287`.
- **Do not use `Restart=on-failure` yet:** the current harness can return 0 after semantically abnormal loop exits, so systemd cannot classify intent reliably. **Evidence:** `crates/buzz-acp/src/lib.rs:3370-3409` and `docs/remote-agents.md:264-285`.
- If a future ACP release pins clean exit 0 and abnormal exit nonzero, a bounded `Restart=on-failure` policy could be enabled only for an explicitly indefinite Box lifetime. The launcher still needs an external-stop guard so a service stop does not trigger a restart loop.

### 4.5 Launch-intent fingerprint file

Mirror Kubernetes' non-secret fingerprint model. The fingerprint must cover only facts that affect Box creation or service shape:

```json
{
  "schema": 1,
  "agent_pubkey": "<full-64-hex-public-key>",
  "box_machine_type": "small",
  "disk_mode": "persistent",
  "image_digest": "sha256:<digest>",
  "service_unit_version": 1,
  "restart_policy": "no",
  "termination_timeout_seconds": 120,
  "env_keys": ["BUZZ_ACP_AGENT_COMMAND", "BUZZ_RELAY_URL", "..."],
  "workspace_mode": "persistent"
}
```

Canonicalize this object and store `SHA-256(canonical_bytes)` in a root-owned file such as:

```text
/var/lib/buzz-agent/launch-intent.sha256
```

Do **not** hash or store nsec, auth tags, API-key values, or user environment values. Kubernetes explicitly excludes Secret data because a public hash of a low-entropy secret creates a dictionary oracle. **Evidence:** `crates/buzz-backend-kubernetes/src/intent.rs:1-21` and `crates/buzz-backend-kubernetes/src/intent.rs:60-86`.

The fingerprint is a divergence discriminator only for a Box whose harness has never started. A live harness remains strict no-op even if the desired fingerprint changes, matching Kubernetes. A changed fingerprint must not trigger a live service restart.

---

## 5. Secret injection and redaction

### 5.1 Three-tier environment model

The current provider resolves the environment before serialization because a flat Secret map has no precedence of its own. The tiers are:

1. `launch.policy_env`: overridable behavior defaults.
2. `launch.env`: Desktop-resolved user/layered environment; legacy `env_vars` is used only when `launch` is absent.
3. Provider-authoritative values derived from top-level payload and provider policy.

**Evidence:** `crates/buzz-backend-kubernetes/src/env.rs:161-187`.

The authoritative key list includes relay identity, nsec, auth/owner fields, harness command/args, MCP command, inactivity, and start nonce. **Evidence:** `crates/buzz-backend-kubernetes/src/env.rs:11-42`.

The lower tiers are validated for POSIX names. `BUZZ_ACP_NO_PRESENCE` is refused because presence is the only remote liveness signal. **Evidence:** `crates/buzz-backend-kubernetes/src/env.rs:189-209`.

The provider removes all authoritative keys before writing tier 3, so a missing authoritative value clears a lower-tier spoof rather than leaving it in place. **Evidence:** `crates/buzz-backend-kubernetes/src/env.rs:211-216`.

Identity is built from top-level fields, never from user env:

- `relay_url` -> `BUZZ_RELAY_URL`
- `private_key_nsec` -> `BUZZ_PRIVATE_KEY` and `NOSTR_PRIVATE_KEY`
- `auth_tag` and/or `launch.owner_pubkey` -> owner environment
- resolved command/args/MCP policy
- inactivity and generation token

**Evidence:** `crates/buzz-backend-kubernetes/src/env.rs:217-286`.

This is also a pre-mutation invariant: the provider derives the pubkey and builds the environment before connecting to or mutating the cluster. **Evidence:** `crates/buzz-backend-kubernetes/src/main.rs:115-134`.

### 5.2 Secure Box file flow

Recommended flow:

```text
Desktop payload
  -> provider builds authoritative env map
  -> provider constructs redaction set
  -> provider wins deterministic Box claim
  -> provider writes a one-shot env blob to a root-owned tmpfs path
  -> fixed entrypoint reads blob without shell evaluation
  -> entrypoint unlinks the blob and emits a non-secret consumed marker
  -> launcher removes the host-side file
  -> entrypoint execs buzz-acp
```

Concrete requirements:

1. Create `/run/buzz-agent` as root-owned `0700`, preferably on tmpfs.
2. Serialize a canonical, non-shell-evaluated format. A length-prefixed binary record or JSON consumed by a fixed parser is safer than `source` or `KEY=value` shell parsing because values may contain whitespace, quotes, newlines, or shell metacharacters.
3. Write via an API/file operation that does not put values in command arguments. If the Box API only supports command input, use stdin and a fixed command such as `install -o root -g root -m 600 /dev/stdin /run/buzz-agent/env.pending`.
4. Verify `root:root` and mode `0600` before launch. Use `umask 077` and a unique invocation name.
5. Pass only the path in `docker run`, never a secret value in argv or `--env` arguments.
6. Prefer a tmpfs bind mount plus a fixed in-container parser. Do not use Docker `--env-file` if it causes the Docker daemon to persist environment values in `/var/lib/docker/containers/*/config.v2.json`, which is part of the Box snapshot threat surface.
7. Unlink inside the entrypoint immediately after parsing and remove the host-side file from the launcher after the consumed marker. Do not rely on `shred` on a copy-on-write persistent disk; deletion plus tmpfs is the useful boundary.
8. Do not emit the env blob to systemd journal, command history, provider debug logs, Box API request logs, or Docker inspect output.
9. Never put the Box API credential in `provider_config` or inside the agent container. It must remain ambient to the provider/launcher or a Box machine-scoped credential that cannot control other Boxes.

### 5.3 Redaction set

The provider must redact before returning any error, including Box API errors, command stdout/stderr, systemd status, Docker output, and JSON response errors. Desktop also redacts provider output, but the provider cannot rely on that boundary.

Desktop's current redactor replaces every request environment value of length at least four, longest-first, and recognizes `nsec1`, `sprt_tok_`, and GitHub token prefixes. **Evidence:** `desktop/src-tauri/src/managed_agents/backend.rs:238-285`, `desktop/src-tauri/src/managed_agents/backend.rs:330-390`, and `desktop/src-tauri/src/managed_agents/backend.rs:392-430`. The protocol separately states that provider stderr, response errors, and output are untrusted. **Evidence:** `docs/remote-agents.md:378-385`.

Box v1 must include all of these value classes in its own redaction set:

- `private_key_nsec`, `BUZZ_PRIVATE_KEY`, and `NOSTR_PRIVATE_KEY`.
- `auth_tag` and any owner attestation or bearer-like owner credential.
- Every non-empty value from `env_vars`, `launch.env`, and `launch.policy_env`, including model keys, GitHub/Git credentials, MCP credentials, package registry credentials, proxy credentials, and arbitrary user secrets. Use longest-first exact replacement, as Desktop does.
- Ambient Box API keys, CLI tokens, machine tokens, refresh tokens, and credential-file contents that the provider/launcher can read.
- Any secret embedded in a URL userinfo component or private registry URL.
- Token-shaped values not present in the env map, including at least `nsec1…`, `sprt_tok_…`, `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, and `github_pat_…`, matching the existing Desktop patterns.
- Temporary file paths or generation values only if they encode a secret or credential. Ordinary Box ID, agent ID, image digest, and launch-intent fingerprint are not secret values.

**Important gap:** Desktop's `env_secrets_from_request` collects env-map values but not every top-level field, and its prefix recognizer does not know an arbitrary Box API-key format. **Evidence:** `desktop/src-tauri/src/managed_agents/backend.rs:392-415`. Box must therefore add top-level nsec/auth/Box credential values explicitly to its provider-local redactor.

---

## 6. Threat-model deltas versus Kubernetes

| Delta | Kubernetes reference | Box risk | Mitigation |
|---|---|---|---|
| Persistent disk | Default workspace is `emptyDir`; pod death removes checkout/scratch | Box disk and snapshots may retain source, temp files, logs, Docker layers, stopped containers, and credentials | Default to `noEnv: true`; tmpfs secret path; unlink before archive; `docker rm`; scrub journal/history/temp; do not persist secrets in workspace; document retention and use fresh-workspace mode for regulated data |
| `/var/lib/docker` snapshot contents | Container runtime state is cluster-managed and usually not part of a user-visible persistent workspace | Docker metadata/config may retain env values, mounts, command lines, image layers, stopped containers, and build cache | Never use `--env-file` if Docker persists its contents; pass only a tmpfs bind path; remove container; prune only safe, non-workspace Docker data; validate exact snapshot contents live |
| Account environment | Kubernetes Pod does not receive a cluster ServiceAccount token by default and has explicit `automountServiceAccountToken=false` | Box `env` may inherit account GitHub/model credentials and owner CLI sessions | Always create Box with `noEnv: true`; pass only resolved launch env after ownership claim; test that `noEnv` removes account credentials |
| Machine-token blast radius | Provider uses ambient kubeconfig outside the Pod; Pod cannot control the cluster | In-VM `box` identity may be available to agent code or wrapper and could stop/list other Boxes | Use machine-scoped self-only identity; keep it outside the container and out of child env; run the agent non-root; do not mount Docker socket; validate `box stop self` authorization and deny list/other-Box operations |
| API error leakage | Kubernetes classifier deliberately omits kubelet waiting/terminated messages because they can echo credentials | Box command/API stderr may echo env files, headers, URLs, or tokens | Treat all Box output as untrusted; typed allowlisted status messages; provider-local redaction before stdout/stderr/response |
| Resumption | Kubernetes Pod creation is fresh and deterministic | Box resume may restart enabled systemd units and reuse stale disk state | Verify unit state and launch-intent fingerprint after resume; do not auto-resume after intentional stop; require explicit Start |
| Host escape | Pod hardening drops capabilities, runs non-root, disables service-account token, and forbids host paths/namespaces | Docker socket, privileged container, host mounts, or root service mistakes can give agent VM control | Non-root container, no privileged mode, no Docker socket, minimal mounts, fixed immutable image digest, restricted systemd unit, no credentials in argv |
| Billing/liveness | Pod termination releases compute through Kubernetes lifecycle | A child harness exit can leave a running Box billing indefinitely | Launcher self-stop-on-exit; `Restart=no`; post-stop cleanup; live validation that stop/archive completes and billing stops |
| Snapshot deletion | Kubernetes object/Secret GC has explicit ownership and fences | Box may only archive, with unclear deletion/retention semantics | Treat archive as data retention, not deletion; publish retention warning; validate deletion API and regulated-workload eligibility before production |
| Presence staleness | Relay presence TTL is 180 seconds, clean offline is immediate | VM loss, SIGKILL, or broken wrapper leaves stale online | Preserve signal forwarding, reserve final offline/relay-close slice, use the 180-second bounded stale-online window as the only liveness fallback |

The Kubernetes hardening baseline is concrete in `crates/buzz-backend-kubernetes/src/pod.rs:131-178`: non-root UID/GID, no privilege escalation, drop all capabilities, RuntimeDefault seccomp, no service-account token mount, no host namespace/path, and a 60-second declared grace period. Box should reproduce the applicable parts inside Docker and systemd.

---

## 7. Live-API validation required before implementation

The repository establishes the Buzz-side contracts, but not the following Box behaviors. These transitions should be covered by a fake Box server plus opt-in live tests:

### Identity and concurrency

1. Does creating or updating the deterministic subdomain provide an atomic uniqueness conflict, and what machine-readable discriminator identifies the loser?
2. Is list/read-after-claim consistent enough to adopt the winner after a concurrent conflict?
3. Can a losing candidate be stopped/archived without affecting the winner?
4. Can a candidate be created with `noEnv: true` and remain free of account-wide credentials until after the claim?

### Lifecycle transitions

5. Exact Box state taxonomy and meanings for `ready`, `idle`, `provisioning`, `cloning`, `archiving`, `archived`, and `error`.
6. Whether self-run processes update Box state at all, confirming that service state and presence are required.
7. What happens if `resume` races with `archiving`, and whether the provider can wait for a stable archived state before resuming.
8. Whether a provisioning timeout is safely observational across later deploys, or whether the API supplies a compare-and-cancel primitive.
9. Whether an `error` Box can be safely archived/replaced and how ownership/version fencing works.
10. Whether an enabled systemd service restarts on resume and whether that behavior can be disabled or explicitly controlled.

### Shutdown and supervision

11. Does `box stop self` work using only the in-box machine-scoped identity in a `noEnv` Box?
12. Can the machine identity list, read, or stop any Box other than `self`?
13. Does an external Box stop deliver SIGTERM to systemd, the launcher, Docker, and the container PID 1 in the required order?
14. Does `docker stop --time=N` reach `buzz-acp` and allow the offline event to be published before the Box is archived?
15. Does the external-stop marker survive enough of the systemd stop sequence to prevent the launcher or `ExecStopPost` from calling `box stop self` redundantly?
16. Does a harness self-exit cause the systemd service to stop and the Box to archive without a second supervisor restarting it?
17. Does resume after an intentional `!shutdown` stay down until a new explicit provider `deploy`?

### Secrets and persistence

18. Does the Box file API support an atomic write with mode `0600`, owner control, stdin payloads, and no command/API-log echo?
19. Does Docker persist `--env-file` values or process environment values under `/var/lib/docker` on the chosen Docker version?
20. Does a tmpfs bind-mounted env file avoid Docker metadata persistence, and does unlinking inside the container remove the host copy?
21. What exactly is captured in a Box snapshot, including `/var/lib/docker`, journald, shell history, deleted-file blocks, swap, and mounted volumes?
22. Can an archived Box be deleted or securely retired, or is archive retention indefinite?
23. Do Box API responses, command errors, journal records, and CLI history retain temporary env content or credentials?

### Operational limits

24. Confirm Box start-rate limits against repeated Desktop Starts and race retries.
25. Confirm stopped Boxes stop billing while retaining exactly the intended persistent workspace.
26. Confirm approved Buzz images can be pulled and run by immutable digest on each supported Box machine type and architecture.

---

## 8. Implementation checklist

Before merging `buzz-backend-box`:

- [ ] Derive pubkey from nsec before any Box read or mutation.
- [ ] Create candidates with `noEnv: true`.
- [ ] Claim deterministic identity before injecting any agent secret.
- [ ] Verify full pubkey, management marker, binding version, and launch-intent fingerprint before adoption or destructive action.
- [ ] Implement one ordered reconcile loop with conflict re-entry and no age-based recycle.
- [ ] Return success only after fixed service startup and harness readiness, not Box `ready`/`idle`.
- [ ] Use systemd `Restart=no`, a signal-forwarding launcher, and a self-stop-on-exit path.
- [ ] Make external-stop intent observable before forwarding SIGTERM; prevent self-stop during external stop.
- [ ] Keep the machine-scoped Box credential outside the container and never in `provider_config`.
- [ ] Serialize secrets into a root-owned `0600` tmpfs file; parse without shell evaluation; unlink promptly.
- [ ] Avoid Docker environment mechanisms that persist secrets in `/var/lib/docker`.
- [ ] Redact every env value plus nsec, auth tag, Box credentials, URL userinfo, and recognized token patterns before provider output.
- [ ] Add fake-Box reconciliation tests for no-op, provisioning timeout, archive/resume, claim conflict, fingerprint divergence, external stop, self-stop, and error states.
- [ ] Add opt-in live tests for the Box-specific unknowns listed above.

## Bottom line

The Box binding should copy Kubernetes' **decision structure**, not its Pod API: verify identity first, fence ownership, distinguish started harness from substrate acceptance, make live a strict no-op, observe recoverable startup without age-based deletion, and only replace a non-live object when positive evidence authorizes it. The VM-specific addition is a supervised execution unit that couples harness exit to Box archival while preserving the 180-second relay presence bound. Until the ACP exit-code contract is pinned, `Restart=no` is the only safe supervisor policy.
