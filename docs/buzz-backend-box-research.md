# Buzz Backend Box Research

**Status:** Research and architecture recommendation

**Date:** 2026-08-08

**Target:** A future `buzz-backend-box` provider for ASCII Box

## Executive summary

Buzz can run managed agents on sandbox platforms such as ASCII Box or E2B without changing the `buzz-acp` conversational runtime. Buzz already has a substrate-neutral provider plugin contract. A provider executable named `buzz-backend-<id>` receives a resolved agent launch payload, deploys it to a remote substrate, and returns a stable deployment identifier.

The current remote-agent architecture is a particularly good fit for managed sandboxes because the deployed process only needs outbound WebSocket access to the Buzz relay. Buzz Desktop does not require an inbound connection to the sandbox and does not retain a substrate management session after deployment.

The recommended first provider is **ASCII Box**:

- It supports indefinitely running VMs with `ttlSeconds: null`.
- It provides persistent disk snapshots and fast resume.
- It includes Docker, which preserves Buzz's approved immutable-image model.
- An in-box, machine-scoped Box identity and the CLI `self` alias appear suitable for stopping the Box when `buzz-acp` exits.
- Its advertised runtime price is substantially below E2B for comparable CPU and memory, although the products do not promise identical CPU isolation.

E2B remains attractive for short-lived, disposable, or evaluation agents because it has stronger first-class process APIs, server-side metadata filtering, custom templates, and memory-preserving pause. Its documented 24-hour maximum continuous runtime and unclear self-only sandbox termination mechanism make it a weaker primary fit for continuously relay-connected Buzz agents.

No production code was changed as part of this research.

## Current Buzz execution architecture

### Local agents

For a local agent, Buzz Desktop directly starts and supervises the `buzz-acp` process. It tracks the process identifier, owns local log files, applies process ownership markers, and terminates the process group when the user stops the agent.

Relevant code:

- `desktop/src-tauri/src/managed_agents/runtime/process.rs`
- `desktop/src-tauri/src/managed_agents/runtime/stop.rs`
- `desktop/src-tauri/src/commands/agents.rs:267-448`

### Remote agents

Remote execution is deliberately different. Buzz Desktop invokes a provider binary once per operation using JSON over stdin and stdout. Provider discovery is based on executable names of the form:

```text
buzz-backend-<provider-id>
```

Provider protocol v1 exposes two operations:

```text
info
  Returns provider identity, protocol version, and a JSON Schema for configuration.

deploy
  Converges the requested agent to a running remote deployment and returns agent_id.
```

The Desktop stages and hashes the provider binary, calls `info` before exposing the agent private key, validates protocol version 1, and invokes `deploy` on the same immutable staged bytes.

Relevant code and specification:

- `docs/remote-agents.md:7-36`
- `docs/remote-agents.md:305-465`
- `desktop/src-tauri/src/managed_agents/backend.rs:433-533`
- `crates/buzz-backend-kubernetes/src/main.rs:1-135`
- `crates/buzz-backend-kubernetes/src/wire.rs:20-108`

### Launch payload

Buzz Desktop resolves the effective persona, runtime, model, system prompt, team instructions, environment layers, and runtime policy before calling the provider. The provider must apply this resolved launch contract mechanically rather than reimplementing Desktop configuration resolution.

The payload includes:

- Concrete relay WebSocket URL
- Agent Nostr private key and NIP-OA auth tag
- Selected ACP runtime command and arguments
- Merged environment variables
- Model and system prompt
- Owner public key
- Timeout, parallelism, and response-policy settings

Relevant code:

- `desktop/src-tauri/src/commands/agents_deploy.rs:30-92`
- `desktop/src-tauri/src/commands/agents_deploy.rs:104-184`
- `crates/buzz-backend-kubernetes/src/env.rs:166-296`

### Remote observation and control

After `deploy` succeeds, Buzz Desktop does not maintain a management connection to the remote substrate.

- Relay presence is the live status signal.
- `backend_agent_id` records that infrastructure was deployed, not that the process is currently online.
- An owner-authenticated `!shutdown` relay message stops the remote harness.
- Starting a remote agent invokes `deploy` again.
- Remote logs are not available through the current Desktop command.
- Provider protocol v1 has no `status`, `logs`, `stop`, or `undeploy` operation.

Relevant code:

- `docs/remote-agents.md:90-104`
- `docs/remote-agents.md:200-226`
- `desktop/src-tauri/src/commands/agents.rs:1125-1156`
- `desktop/src-tauri/src/commands/agents.rs:1242-1249`
- `desktop/src-tauri/src/managed_agents/runtime.rs:148-169`
- `desktop/src-tauri/src/commands/agent_logs.rs:28-30`

This means the sandbox provider does not need to expose an inbound agent port. The agent only needs outbound HTTPS and WSS access to its model provider, MCP integrations, source control, and Buzz relay.

## Provider invariants that a sandbox binding must preserve

The remote-agent specification defines five important invariants.

### 1. Identity fails closed

A provider must derive the public key from the supplied nsec and refuse malformed or missing identity before creating remote infrastructure.

### 2. Secrets do not belong in provider configuration

`provider_config` is persisted and rendered in the Desktop UI. Buzz rejects secret-like configuration keys. The Box API credential must therefore come from ambient provider authentication, such as `BOX_API_KEY`, a local Box CLI credential, or a future OS-keychain integration. It must not be stored in the agent's provider JSON.

Relevant code:

- `desktop/src-tauri/src/managed_agents/backend.rs:535-565`
- `docs/remote-agents.md:185-198`

### 3. Relay presence is status

The provider may inspect sandbox state during `deploy`, but the Desktop's live indicator must continue to use relay presence. A Box reporting `ready` or `idle` does not prove that `buzz-acp` is running.

### 4. At most one live instance exists per provider scope

A repeated Start must not create another active process for the same agent. A live, confirmed harness is a strict no-op. Concurrency conflicts must converge on one winner.

### 5. Intentional termination remains final

When the owner sends `!shutdown`, or the harness inactivity timer expires, the remote execution unit must stop and must not be automatically resurrected. `Restart=always` is not conforming. Buzz currently uses Kubernetes `restartPolicy: Never` because the clean-exit versus crash-exit contract is not yet formally pinned.

Relevant specification:

- `docs/remote-agents.md:151-304`
- `docs/remote-agents.md:632-746`
- `docs/remote-agents.md:1411-1482`

## Current Kubernetes realization

The Kubernetes provider is the reference implementation, not a requirement of `buzz-acp`.

It creates:

- One immutable Secret per deployment attempt
- One Pod named deterministically from the agent public key
- An `emptyDir` workspace mounted at `/home/agent`
- A non-root container with dropped Linux capabilities
- `restartPolicy: Never`
- A 60-second termination grace period
- The approved Buzz image by immutable digest

The image entrypoint launches the harness as the container's signal-receiving process. When the harness exits, the Pod stops consuming compute.

Relevant code:

- `crates/buzz-backend-kubernetes/src/pod.rs:29-58`
- `crates/buzz-backend-kubernetes/src/pod.rs:61-180`
- `crates/buzz-backend-kubernetes/src/config.rs:33-62`

A VM sandbox differs in one crucial respect: a child `buzz-acp` process can exit while the surrounding VM continues running and billing. A Box binding must explicitly couple harness exit to Box stop.

## Sandbox provider comparison

| Requirement | E2B | ASCII Box |
|---|---|---|
| Outbound relay WSS | Supported through configurable internet access | Supported with included egress and a dedicated IPv4 |
| Custom Buzz runtime | Custom templates, files, commands, and start commands | Full Ubuntu VM with Docker and snapshot or fork workflows |
| Approved image by digest | Template can reproduce the approved environment | Run the approved Buzz image by digest inside Docker |
| Process APIs | First-class start, list, reconnect, signal, and stream APIs | Bounded command API, SSH, Docker, and systemd |
| Persistent filesystem | Yes | Yes |
| Pause behavior | Full memory pause can preserve running processes | Disk snapshot. Hand-run processes stop, enabled systemd units restart |
| Maximum uninterrupted runtime | 1 hour Base, 24 hours Pro | Numeric TTL up to 30 days or no auto-stop with `null` |
| Lookup and reconciliation | Server-side metadata filtering | List Boxes and claim a globally unique deterministic subdomain |
| Self-termination | No clearly documented self-only platform kill credential | In-box machine identity and `self` CLI alias appear suitable for `box stop self` |
| Default secret posture | Explicit env and secure sandbox controls | Must use `noEnv: true` to avoid account-wide credentials |
| Current geographic or compliance caveat | Enterprise offering exists | EU regions only and SOC 2 reported as in progress |

### Published pricing snapshot

Pricing changes over time and should be rechecked before implementation.

- E2B Pro is advertised at $150 per month plus usage. Two vCPUs and 4 GiB of memory calculate to roughly $0.166 per running hour using the published CPU and RAM rates.
- ASCII Box advertises a 2-vCPU, 4-GB `small` Box at $0.018 per running hour and a 4-vCPU, 8-GB `default` Box at $0.036 per hour.
- Box uses shared vCPUs, so the numbers are not a direct performance-equivalence claim.
- Box enforces machine-start ceilings, including 600 starts per hour and 1,500 per day on self-service plans.

## Recommendation

### Primary provider: ASCII Box

ASCII Box is the stronger first implementation for persistent Buzz coding agents.

The primary reasons are:

1. A Box can run indefinitely when auto-stop is disabled.
2. A stopped Box is snapshotted and no longer billed.
3. Docker is preinstalled, preserving the approved Buzz image catalog and immutable digest policy.
4. Resume takes seconds and can restart an enabled service.
5. A machine-scoped in-box credential appears capable of stopping the Box itself after the harness exits.
6. Persistent workspaces are useful for repositories, dependencies, and agent skill bundles.

### Secondary provider: E2B

E2B is a good follow-up provider for bounded workloads such as:

- One-off repository analysis
- CI and evaluation agents
- Disposable per-task sandboxes
- Runs that benefit from full-memory pause and resume
- High-volume sandboxes that finish well inside the continuous-runtime limit

E2B's process control surface is cleaner than Box's for ephemeral execution. The unresolved issues for persistent Buzz agents are its 24-hour continuous-runtime limit and the absence of a clearly documented self-only sandbox kill mechanism that does not expose a team-level API key inside the sandbox.

### Kubernetes remains useful

The Kubernetes provider should remain available for deployments that require:

- Private networking
- Cluster-native log shipping
- Organization-controlled workload identity
- Strict namespace and RBAC policies
- Existing compliance controls
- Predictable infrastructure ownership

The sandbox providers should be additional backends, not a removal of Kubernetes support.

## Proposed `buzz-backend-box` architecture

### Provider discovery and configuration

The new executable would be named:

```text
buzz-backend-box
```

Its `info` response should expose only non-secret fields, potentially:

```text
machine_type       small | default | large
image              approved immutable image reference
inactivity_seconds harness self-stop policy
scope               non-secret deployment scope identifier
workspace_mode      persistent | fresh
```

Provider authentication should be resolved from ambient Box credentials. `BOX_API_KEY` is acceptable for a server or shell-launched Desktop. A production Desktop integration should prefer the Box CLI credential store or the OS keychain because macOS GUI applications do not reliably inherit a login-shell environment.

### Stable identity and concurrency

The provider must derive the agent public key from `private_key_nsec` before any Box mutation.

A possible deterministic ownership identifier is:

```text
buzz-<scope-hash>-<pubkey-hash>
```

Box permits updating a globally unique subdomain. This can act as the provider's substrate-level identity claim:

1. List existing Boxes and find the deterministic subdomain.
2. If a matching Box exists, inspect its machine and harness state.
3. Otherwise create a `noEnv` candidate Box without agent secrets.
4. Wait until the candidate is ready.
5. Attempt to claim the deterministic subdomain.
6. A concurrent loser receives a uniqueness conflict, stops its candidate, and adopts the winner.
7. Inject the nsec and launch environment only after the claim succeeds.

This prevents concurrent candidates from both receiving the agent key or starting the harness. The exact conflict behavior must be validated against the live API.

A local cache from agent pubkey to Box ID can accelerate lookup, but the deterministic substrate identity must remain the recovery path after cache loss.

### Secret injection

Every agent Box should be created with:

```json
{
  "noEnv": true
}
```

This prevents account-level GitHub credentials, model credentials, secret files, and owner CLI sessions from entering the agent environment.

After the provider wins the deterministic identity claim, it should:

1. Serialize the authoritative three-tier environment into a temporary file through the Box file API.
2. Set file mode `0600` using a fixed command.
3. Start a fixed, preinstalled launcher without placing secrets in command arguments.
4. Have the launcher read the environment and immediately unlink the temporary file.
5. Redact every submitted environment value from provider errors before returning them to Desktop.

The provider must continue to construct reserved identity variables from top-level payload fields, not from user `env_vars`.

### Approved runtime image

The recommended outer and inner execution model is:

```text
ASCII Box VM
  └── Docker container from approved Buzz image digest
        ├── buzz-acp
        ├── selected ACP agent adapter
        ├── buzz-dev-mcp or resolved MCP executables
        └── approved skill bundle mount
```

This preserves the existing image policy:

- One shared Buzz base image
- Thin images for third-party agent CLIs where needed
- Images selected from an approved catalog
- Immutable digest verification
- Runtime credentials injected after provisioning

The Box VM is the isolation and persistence substrate. The inner container defines the Buzz runtime and dependency contract.

### Process supervision

Box's `ready`, `idle`, and `running` states cannot be used as harness status. Box documentation explicitly states that self-run processes do not update those states.

The provider should install one fixed service or launcher whose health can be queried using `systemctl` or `docker inspect`.

Initial policy:

```text
Restart=no
```

The launcher must:

1. Forward SIGTERM and SIGINT to the container or `buzz-acp` process.
2. Allow the full Buzz graceful-shutdown window.
3. Wait for the harness exit.
4. Stop the Box when the harness exits intentionally.
5. Avoid calling self-stop when the process is already being terminated as part of an externally initiated Box stop.

The candidate mechanism is:

```bash
box stop self
```

This must be verified from a `noEnv` Box using only its machine-scoped identity. A team-wide `BOX_API_KEY` must never be copied into the Box solely to enable self-stop.

### Deploy reconciliation

A repeated `deploy` should behave as follows:

| Observed Box state | Harness state | Provider action |
|---|---|---|
| No Box | N/A | Create, claim identity, inject secrets, launch, confirm startup |
| Ready or idle | Harness confirmed live | Strict no-op and return existing Box ID |
| Ready or idle | Harness absent after intentional exit | Stop or await Box archival, then resume only for an explicit Start |
| Archived | N/A | Resume, wait for ready, inject current launch environment, launch |
| Provisioning or cloning | Not yet observable | Poll until ready or return an actionable timeout |
| Error | N/A | Return a redacted actionable error. Replace only when ownership and intent evidence permit it |
| Archiving | N/A | Wait for archived, then resume because the user explicitly requested Start |

The provider should persist a non-secret launch-intent fingerprint inside the Box. A live harness remains a strict no-op even if the desired intent changed. A stopped or never-started environment can be updated before relaunch.

### Skills and MCP servers

Moving execution to Box should not cause all skills and MCP servers to be baked into every VM.

The desired model remains:

1. Buzz resolves the agent's capability profile or Persona Pack.
2. Only approved skills are copied or mounted into the runtime's skill discovery paths.
3. Approved MCP server definitions are materialized into ACP `session/new` configuration.
4. MCP executables come from the approved runtime image or an approved runtime install step.
5. MCP credentials are injected at runtime.

The current Box provider can initially reproduce Kubernetes behavior by supplying `buzz-dev-mcp`. Broader Persona Pack integration remains a separate Buzz capability-assignment task.

## Security considerations

1. The Box provider receives the nsec by design and is therefore trusted with the agent identity.
2. Box API credentials must never appear in provider configuration, logs, or agent payloads.
3. Every Box must use `noEnv: true` unless an explicit trusted-owner workflow requires otherwise.
4. The agent sandbox should never receive a credential capable of controlling other Boxes.
5. The approved inner image must be referenced by immutable digest.
6. The provider must redact nsecs, Box tokens, model keys, and every submitted environment value from errors.
7. Persistent disk changes the retention model compared with Kubernetes `emptyDir`. Sensitive temporary files must be removed before snapshots.
8. Box is currently documented as EU-only, with SOC 2 in progress. This may exclude some production or regulated deployments.
9. The public API reference should be checked for explicit Box deletion and snapshot-retention controls before storing regulated source code.

## Required validation spike

Before implementing the full provider, validate these behaviors against a real Box account:

1. Create a `noEnv` Box with no owner or account secrets.
2. Confirm outbound WSS connectivity to a Buzz relay.
3. Confirm `box stop self` works with the machine-scoped in-box identity.
4. Confirm self-stop does not expose credentials to the child process.
5. Confirm deterministic subdomain conflicts are atomic and return a stable conflict code.
6. Confirm concurrent candidate Boxes can converge without either loser receiving the nsec.
7. Confirm Docker can pull and run the approved Buzz image by digest.
8. Confirm SIGTERM reaches the container and `buzz-acp` publishes offline presence before force termination.
9. Confirm stopped Boxes no longer bill and preserve only the intended workspace data.
10. Confirm resume plus service launch does not accidentally resurrect an agent that stopped through `!shutdown` without a new user Start.
11. Confirm command, journal, and API responses do not retain temporary environment contents.
12. Confirm account start-rate limits match expected agent-start traffic.

## Suggested implementation sequence

1. Build a small standalone API spike for create, subdomain claim, file write, command execution, self-stop, and resume.
2. Record verified Box behavior and revise this document where assumptions differ.
3. Add `crates/buzz-backend-box` implementing provider protocol v1.
4. Share provider-wire fixtures with the Kubernetes provider where practical.
5. Add a fake Box API server for deterministic reconciliation tests.
6. Add opt-in live tests guarded by `BOX_API_KEY`.
7. Build and publish the provider binary separately from the agent image.
8. Add Desktop documentation explaining ambient Box authentication and the remote status model.
9. Add remote log support only through a future provider protocol revision rather than extending v1 ad hoc.

## Open questions

- Does the machine-scoped Box token authorize `box stop self` in a `noEnv` Box?
- Can a Box be explicitly deleted through the current public API, or only archived indefinitely?
- What exact data is included in a Box snapshot under `/var/lib/docker`?
- Can per-Box environment variables be updated securely after creation, or is temporary file injection required?
- Should the persistent workspace be the default, or should Buzz offer a fresh-workspace mode matching Kubernetes `emptyDir`?
- Should provider protocol v2 send the stored `backend_agent_id` back to `deploy` to avoid substrate discovery scans?
- Should protocol v2 add explicit `undeploy`, status, and remote-log operations?
- What Box regions, data residency, and compliance requirements apply to each Buzz deployment?

## Sources

### Buzz repository

- `docs/remote-agents.md`
- `desktop/src-tauri/src/commands/agents.rs`
- `desktop/src-tauri/src/commands/agents_deploy.rs`
- `desktop/src-tauri/src/commands/agent_logs.rs`
- `desktop/src-tauri/src/managed_agents/backend.rs`
- `desktop/src-tauri/src/managed_agents/runtime.rs`
- `crates/buzz-backend-kubernetes/src/config.rs`
- `crates/buzz-backend-kubernetes/src/env.rs`
- `crates/buzz-backend-kubernetes/src/main.rs`
- `crates/buzz-backend-kubernetes/src/pod.rs`
- `crates/buzz-backend-kubernetes/src/reconcile.rs`
- `crates/buzz-backend-kubernetes/src/wire.rs`
- `crates/buzz-acp/src/lib.rs`
- `crates/buzz-acp/src/relay.rs`

### ASCII Box

- [Box Public API v1](https://docs.ascii.dev/box/api/v1)
- [Create Box](https://docs.ascii.dev/box/api/reference/boxes/create-box)
- [Update Box](https://docs.ascii.dev/box/api/reference/boxes/update-box)
- [List Boxes](https://docs.ascii.dev/box/api/reference/boxes/list-boxes)
- [Execute Box command](https://docs.ascii.dev/box/api/reference/agent/execute-box-command)
- [Stop and archive Box](https://docs.ascii.dev/box/api/reference/boxes/stop-and-archive-box)
- [Resume Box](https://docs.ascii.dev/box/api/reference/boxes/resume-box)
- [Long-running tasks](https://docs.ascii.dev/box/long-running-tasks)
- [Build a platform on Box](https://docs.ascii.dev/box/platform-guide)
- [Secrets and setup](https://docs.ascii.dev/box/secrets)
- [Machine capabilities](https://docs.ascii.dev/box/machines)
- [Billing and limits](https://docs.ascii.dev/box/billing)
- [CLI reference](https://docs.ascii.dev/box/cli-reference)
- [FAQ](https://docs.ascii.dev/box/faq)

### E2B

- [Sandbox lifecycle](https://e2b.dev/docs/sandbox)
- [Sandbox persistence](https://e2b.dev/docs/sandbox/persistence)
- [List and filter sandboxes](https://e2b.dev/docs/sandbox/list)
- [Custom template quickstart](https://e2b.dev/docs/template/quickstart)
- [Create sandbox API](https://e2b.dev/docs/api-reference/sandboxes/create-sandbox)
- [Start process API](https://e2b.dev/docs/api-reference/process/start)
- [List process API](https://e2b.dev/docs/api-reference/process/list)
- [Connect to process API](https://e2b.dev/docs/api-reference/process/connect)
- [Send process signal API](https://e2b.dev/docs/api-reference/process/sendsignal)
- [Pricing](https://e2b.dev/pricing)
