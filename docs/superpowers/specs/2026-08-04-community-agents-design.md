# Community-Managed Cloud Agents

**Date:** 2026-08-04
**Status:** Draft for final review

## Goal

Let a Buzz community owner create and operate a small set of always-on cloud agents that every community member can discover and invoke, while keeping personal Desktop-managed agents separate and keeping the community owner's private key out of Terraform, the relay, and the agent VM.

The initial deployment targets one existing GCE agent VM, one controller process, and 1–5 trusted-community agents. It deliberately accepts process-level rather than sandbox-grade isolation.

## Current State

- The relay runs at `wss://buzz.zoop.tools` on GCP and requires NIP-42 authentication.
- The `buzz-agent` VM is private, uses Cloud NAT for egress, and is reachable administratively through IAP.
- One manually installed Codex-backed `buzz-acp.service` runs on that VM under the unprivileged `buzzacp` account.
- That Codex identity is admitted to the relay and `#general`, responds to community members, and has existing message history.
- Desktop-managed agents are local child processes launched by Tauri and stored in Desktop's local managed-agent registry.
- The main Agents page intentionally no longer lists arbitrary relay kind `10100` publishers. Community agents must therefore be an explicit owner-authorized product concept, not a restoration of the old open relay directory.
- Terraform currently provisions the VM and its bootstrap, but must not become the source of agent definitions or lifecycle state.

## Product Decisions

| Question | Decision |
|---|---|
| Creation authority | Community owner through Buzz |
| Terraform role | Infrastructure only; no agent definitions or proposals |
| Initial scale | 1–5 always-on agents |
| Invocation | Owner-assigned channels plus direct messages |
| Member permissions | Discover, view profile, mention, and message |
| Owner permissions | Create, configure, assign, start, stop, restart, delete, and view encrypted activity |
| Desktop placement | A separate **Community agents** section on the Agents page |
| Runtime | One controller service supervising child `buzz-acp` processes |
| Initial isolation | Shared unprivileged Unix account and host kernel; trusted-community preview |
| Agent credentials | Protected controller state on the encrypted VM disk |
| Recovery | Scheduled GCE disk snapshots and a tested restore procedure |
| Existing Codex bot | Adopt its current identity and preserve its pubkey/history |
| Routine agent changes | Never require `terraform apply` |

## Non-Goals

- Hostile multi-tenant code isolation.
- Kubernetes, GKE, gVisor, containers, or one VM per agent.
- Per-agent systemd units or dynamically generated unit files.
- Elastic scheduling across multiple machines.
- Member-visible tool-call or transcript activity.
- Giving members VM access, provider credentials, agent private keys, or lifecycle controls.
- Reintroducing a directory of every kind `10100` event on the relay.
- Terraform-authored agent desired state or Terraform/Buzz drift reconciliation.
- Automatic replacement of a missing agent key with a new identity.

## Architecture

```text
Community owner Desktop
  | owner-signed desired state + membership events
  v
Buzz relay at wss://buzz.zoop.tools
  ^                         |
  | status/profile/presence | authenticated subscription
  |                         v
buzz-agent-controller.service on buzz-agent VM
  | concrete process supervisor
  +-- buzz-acp child: adopted Codex identity
  +-- buzz-acp child: community agent B
  +-- ... up to configured hard maximum

Community member Desktop
  | query verified registry + profiles
  | mention in assigned channel / direct message
  v
Buzz relay -> matching buzz-acp child
```

Add a small Rust binary, `buzz-agent-controller`, to the existing repository. It maintains local controller state, subscribes to community-agent desired-state events, validates their signer against the current community owner, reconciles child processes, and publishes provisioning status.

The first implementation uses a concrete `ProcessSupervisor`. It exposes a narrow internal boundary—start, stop, inspect—but does not introduce an executor trait before a second runtime exists. A later sandbox scheduler can replace that module without changing the Nostr records or Desktop contract.

The controller runs as the existing unprivileged `buzzacp` user and starts children under the same user. It passes an explicit environment allowlist and an agent-specific working directory. The systemd unit applies aggregate CPU, memory, filesystem, network, and metadata-server restrictions to the controller subtree. The design does not claim per-agent resource or filesystem isolation.

## Trust Model

### Community owner

The authoritative owner pubkey is the relay's current community owner. A desired-state record is actionable only when its event author is exactly that pubkey. Relay storage acceptance alone is not authorization: the controller and Desktop both perform this check.

The owner key remains in the owner's client. It never reaches Terraform, Secret Manager, the relay process, the controller, an agent environment, or a snapshot.

### Controller

The controller has its own Nostr identity. During infrastructure enrollment, the community owner issues it two separate NIP-OA authorizations whose conditions are exactly:

```text
kind=30179
kind=30180
```

The status authorization is attached only to kind `30179`; the capability authorization is attached only to kind `30180`. NIP-OA conditions are conjunctive, so these must remain separate signatures rather than one combined condition. Desktop trusts either controller event only when:

1. the event signature is valid;
2. the matching NIP-OA signature is valid;
3. the NIP-OA owner is the current community owner; and
4. its conditions authorize exactly the event's controller kind.

A normal agent's broader or differently scoped owner attestation does not grant controller authority.

### Community agents

Each agent has its own Nostr key. The owner signs separate NIP-OA authorizations for kind `0` profile publication and kind `10100` agent-directory publication. The controller stores these public authorization tags with the agent configuration and attaches the matching one to each event.

An official community agent must satisfy every link:

- an owner-authored desired-state event identifies it;
- a current, trusted controller status binds the desired-state ID to the agent pubkey;
- its kind `0` profile has valid owner authorization;
- its kind `10100` record has valid owner authorization; and
- it is an active relay member.

A random member publishing kind `10100` cannot appear as an official community agent.

## Nostr Records

Reserve three parameterized replaceable kinds in `buzz-core/src/kind.rs` after confirming the integers remain unallocated at implementation time:

| Kind | Name | Author | Key |
|---|---|---|---|
| `30178` | Community agent desired state | Current community owner | `d = agent UUID` |
| `30179` | Community agent provisioning status | Owner-authorized controller | `d = agent UUID` |
| `30180` | Community agent runtime capabilities | Owner-authorized controller | `d = controller` |

All three are community-global records. They do not use an `h` tag. Community isolation continues to come from the relay's host-derived tenant boundary.

### Desired state — kind `30178`

Required tags:

```text
["d", "<stable-agent-uuid>"]
```

Content uses a versioned, closed JSON schema:

```json
{
  "version": 1,
  "display_name": "Codex",
  "description": "Shared coding agent",
  "persona_id": null,
  "team_id": null,
  "runtime": "codex",
  "model": "gpt-5.6",
  "desired_status": "running",
  "channel_ids": ["92249104-96c8-513f-9d43-0322fe43783a"],
  "allow_direct_messages": true,
  "agent_pubkey": null,
  "profile_auth": null,
  "directory_auth": null
}
```

Rules:

- Unknown fields, unknown enum values, invalid UUIDs, duplicate channels, and values outside configured size/count limits are rejected.
- Runtime and model must resolve through an operator-maintained allowlist. Desired state never contains commands, filesystem paths, environment variables, provider keys, or arbitrary executable arguments.
- `desired_status` is one of `running`, `stopped`, or `deleted`.
- `agent_pubkey` is null during initial provisioning. Once attested, it is immutable for that agent UUID. Re-keying is an explicit replacement operation, not an update.
- `profile_auth` and `directory_auth` are public NIP-OA authorization tags and must match `agent_pubkey`, the community owner, and kinds `0` and `10100` respectively.
- The newest valid owner-authored event for each `d` tag is authoritative.

### Provisioning status — kind `30179`

Required tags:

```text
["d", "<stable-agent-uuid>"]
["e", "<desired-state-event-id>"]
["auth", "<owner-pubkey>", "kind=30179", "<owner-signature>"]
```

Content schema:

```json
{
  "version": 1,
  "state": "awaiting_attestation",
  "agent_pubkey": "<64-hex-or-null>",
  "error_code": null,
  "message": null
}
```

Allowed states:

```text
pending
awaiting_attestation
waiting_for_membership
starting
running
degraded
stopped
rejected
credential_missing
deleting
deleted
```

Status messages are sanitized and bounded. They must never contain raw subprocess output, filesystem paths, commands, prompts, provider responses, secrets, or environment values. Desktop ignores a status whose `e` tag does not identify the current desired-state event.

### Runtime capabilities — kind `30180`

The controller publishes one `d = controller` record after startup validation and whenever an operator-triggered rescan changes availability. Its `auth` tag contains the separate owner authorization scoped exactly to `kind=30180`.

Content is a versioned map keyed by stable runtime ID:

```json
{
  "version": 1,
  "runtimes": {
    "codex": {
      "status": "available",
      "adapter_version": "1.19",
      "cli_version": "0.146.0"
    },
    "ompl": {
      "status": "not_installed",
      "adapter_version": null,
      "cli_version": null
    }
  }
}
```

Allowed statuses are `available`, `not_installed`, `not_executable`, `unsupported_version`, `authentication_required`, and `probe_failed`. The public event never includes absolute paths, command arguments, usernames, home directories, environment values, probe output, or credentials.

## Agent Lifecycle

### Create

1. The owner completes **Create community agent** in Desktop.
2. Desktop publishes kind `30178` with a new stable UUID, null pubkey/auth fields, and the requested lifecycle state.
3. The controller validates the owner signature, closed schema, allowlisted runtime/model, limits, and absence of secret-bearing fields.
4. The controller generates an agent nsec, writes it atomically to protected local storage, fsyncs the file and parent directory, then publishes `awaiting_attestation` with the derived pubkey.
5. Desktop validates the controller's scoped NIP-OA status authorization.
6. Desktop asks the owner key to sign kind `0` and kind `10100` NIP-OA authorizations for the candidate pubkey.
7. Desktop admits the pubkey to the relay through the existing owner/admin relay-member command, adds it to every assigned channel with role `bot`, and publishes an updated desired state containing the immutable pubkey and both authorization tags.
8. The controller independently verifies the authorizations and relay/channel memberships.
9. The controller publishes the agent's kind `0` profile and kind `10100` metadata, starts its `buzz-acp` child, and waits for relay connection/presence before publishing `running`.

The UI treats steps 6–7 as a resumable onboarding transaction. If one write succeeds and another fails, reopening the flow queries current desired state and memberships and resumes missing operations instead of minting another key.

### Update

- Profile, persona, team, runtime, model, DM policy, or channel changes create a new owner-signed desired-state revision.
- Desktop performs owner-required relay/channel membership additions and removals.
- The controller applies only the newest revision and restarts the child only when a runtime-affecting field changed.
- Status always references the exact desired event being reconciled, preventing stale completions from overwriting current UI state.

### Stop and restart

`stopped` is reversible. The controller terminates the child with a bounded graceful timeout, retains identity and workspace state, and publishes `stopped`. Returning desired state to `running` restarts the same identity.

An explicit **Restart** action does not require a fake desired-state value. Desktop republishes `running` with a new revision/nonce, and the controller restarts once for that desired event ID.

### Delete

Deletion is deliberately multi-step:

1. Owner publishes desired state `deleted` after destructive confirmation.
2. Controller stops the child and publishes `deleting`.
3. Desktop removes the bot from assigned channels and relay membership using owner-authorized commands.
4. Controller submits the existing NIP-IA archive/tombstone operation from the agent identity.
5. After relay acknowledgement, controller removes active credentials and workspace state atomically and publishes `deleted`.

Failure before acknowledgement leaves `deleting` and retains credentials so the operation can resume. Old disk snapshots can still contain deleted credentials until their configured retention expires; the UI and operations guide must state that limitation.

## Process Supervision

For every desired-running agent, the controller builds one child environment from:

- fixed controller configuration;
- an allowlisted runtime definition containing root-owned absolute adapter and CLI paths;
- the agent's local nsec;
- its owner pubkey and public NIP-OA tags;
- assigned channel/DM response policy; and
- community-scoped provider credentials already materialized by VM bootstrap.

It does not inherit the controller's complete environment. Each child gets a separate home/workspace directory and ACP session/config paths, but the shared Unix identity means those paths are not a security boundary against a malicious sibling.

Runtime discovery is allowlist plus live validation, not arbitrary `PATH` scanning. At controller startup and immediately before create or restart, each configured runtime is probed under the same `buzzacp` user, `HOME`, systemd sandbox, and explicit environment used by children. Validation confirms that the configured absolute files exist and are executable, the ACP adapter protocol/version is supported, the underlying CLI is present, and its normalized authentication probe succeeds. Interactive login shells and another Unix user's home are never searched. Probe output stays local; only normalized kind `30180` capability state is published.

The controller:

- enforces a configured hard maximum of five agents initially;
- starts desired agents after its relay subscription reaches EOSE;
- refuses creation or restart when the selected runtime is not currently `available`;
- rescans capabilities at startup, before lifecycle actions, and on an explicit owner refresh;
- uses bounded exponential restart backoff;
- distinguishes process-up from relay-connected;
- reports process-up but relay-disconnected as `degraded`;
- restores desired-running children after controller or VM restart; and
- shuts down children before exiting.

No child is started from owner-supplied shell text, arbitrary binary paths, or a same-named executable discovered through `PATH`.

## Desktop Experience

The Agents page retains two distinct sections:

```text
Your agents
  Local and personal definitions/instances

Community agents
  Owner-authorized, always-on shared services
```

### Member view

Every active community member can see:

- display name, avatar, and purpose;
- online, offline, provisioning, or degraded state;
- assigned channels visible to that member;
- profile details;
- **Message**; and
- mention-autocomplete entries in assigned channels.

Members cannot see start/stop controls, configuration, credentials, raw errors, logs, tool calls, prompts, or encrypted observer activity.

### Owner view

The owner additionally gets:

- create and resumable attestation;
- edit profile/persona/team/runtime/model from allowed values;
- view live VM runtime availability and request a capability refresh;
- channel and DM assignment;
- start, stop, restart, and delete;
- sanitized provisioning errors; and
- owner-only live activity through the existing encrypted NIP-AO observer path.

Pending agents render from owner desired state. Desktop does not invent a profile or claim the agent is official until a verified pubkey/profile chain exists.

The relay remains the source for discovery. Desktop queries explicit kinds and joins desired state, trusted status, trusted runtime capabilities, verified kind `0`, verified kind `10100`, presence, and visible memberships. The create/edit controls offer only runtime/model combinations that are both operator-allowlisted and currently reported `available`. They surface normalized remediation states without exposing VM paths or probe output. Desktop must not merge arbitrary relay agents into this section.

## Terraform and Deployment Boundary

Terraform provisions only:

- the existing agent VM and service account;
- the `buzz-agent-controller` binary and one systemd service;
- static runtime definitions with root-owned absolute adapter/CLI paths and provider credential references;
- controller-wide limits and hardening; and
- the disk snapshot resource policy.

Terraform contains no agent name, agent UUID, persona, model assignment, channel assignment, desired lifecycle state, or agent private key. There are no Terraform agent proposals and no controller logic that reconciles Terraform agent definitions.

Controller identity enrollment is infrastructure setup, not agent creation: provision a dedicated controller nsec, obtain separate owner NIP-OA authorizations scoped exactly to kinds `30179` and `30180`, and materialize them into the controller service configuration without storing the owner key.

Routine community-agent creation and modification happen entirely through Buzz and never require `terraform apply`.

## Persistence, Snapshots, and Recovery

Controller state lives under:

```text
/var/lib/buzz-agent-controller/
  state.sqlite
  credentials/<agent-uuid>.env
  agents/<agent-uuid>/...
```

Files are written with restrictive modes, atomic rename, and directory fsync before the controller publishes the corresponding pubkey or success status. SQLite uses WAL with startup recovery and explicit checkpointing before orderly shutdown.

Attach a Terraform-managed hourly GCE snapshot schedule to the agent VM disk and retain snapshots for seven days. Snapshots are incremental and Google-encrypted. The recovery-point objective is less than one hour; an identity created after the latest successful snapshot can still require recovery from another export or explicit replacement. The controller must never silently mint a replacement when local credentials are missing.

Restore procedure:

1. Restore the newest snapshot into an isolated replacement VM.
2. Keep the original controller stopped to prevent concurrent reconcilers.
3. start the restored controller against the same relay configuration.
4. Verify every local credential derives the pubkey recorded in desired state.
5. Reconcile desired-running agents and verify presence.
6. Promote the replacement only after the identity checks pass.

A real restore rehearsal is required before declaring the feature operational.

## Existing Codex Adoption

Adopt the manually installed Codex service rather than re-keying it:

1. Record its current pubkey and take an immediate VM snapshot.
2. Stop and disable the standalone `buzz-acp.service` without deleting its state.
3. Import its nsec, workspace/session directory, runtime settings, owner binding, and channel policy into a new controller record.
4. Publish owner-signed desired state using a stable UUID and the existing pubkey.
5. Issue/verify kind `0` and kind `10100` NIP-OA authorizations for that same pubkey.
6. Ensure it remains an active relay member and `bot` member of `#general`.
7. Start it as a controller child and publish its verified profile/directory records.
8. Verify old messages still resolve to the same profile and a new mention receives a reply from the same pubkey.
9. Remove obsolete standalone service configuration only after the end-to-end check succeeds.

An ACP in-memory session reset during the handoff is acceptable. Nostr identity and message history changes are not.

## Failure Handling

- **Unauthorized desired event:** ignore it, emit a bounded audit record, and do not create local state.
- **Unsupported runtime/model or invalid schema:** publish `rejected` with a stable non-secret error code.
- **Harness unavailable or unauthenticated:** reject create/restart with the normalized kind `30180` capability state; never fall back to another same-named executable.
- **Owner attestation absent or invalid:** remain `awaiting_attestation`; never start the child.
- **Relay or channel membership incomplete:** remain `waiting_for_membership`; Desktop offers resumable repair.
- **Child spawn failure:** publish `degraded`, preserve desired state, and retry with bounded backoff.
- **Process alive but relay disconnected:** publish `degraded`, not `running`.
- **Controller restart:** wait for EOSE, select the newest valid desired events, then reconcile; do not act on an incomplete subscription snapshot.
- **Missing local credential:** publish `credential_missing`; never generate a new key automatically.
- **Snapshot older than relay state:** keep affected agents stopped and require a newer restore or explicit owner-approved replacement.
- **Deletion partially completes:** retain credentials and resume from `deleting` until archive and membership acknowledgements complete.
- **Community owner changes:** stop reconciliation until controller authorization and desired-state ownership are re-established for the new owner.

## Verification Strategy

### Protocol and controller

Use controller integration tests with a fake ACP child to prove observable contracts:

- only current-owner desired state is actionable;
- separately scoped NIP-OA validation for status and capability events;
- create → awaiting attestation → membership wait → running;
- invalid auth and invalid schema fail closed;
- stale status cannot override a newer desired revision;
- restart restores every desired-running child only after EOSE;
- child crash produces bounded retries and `degraded`;
- stop retains identity;
- delete retains the key until acknowledgement;
- missing local key produces `credential_missing` without re-keying;
- absolute-path runtime validation and sanitized capability publication; and
- the configured five-agent maximum is enforced.

### Relay and Desktop

Add existing-convention tests for:

- kind registration, required scope, global-only classification, and explicit query kinds;
- member versus owner controls;
- exclusion of arbitrary kind `10100` publishers;
- owner desired-state/onboarding recovery after partial writes;
- channel visibility filtering;
- mention autocomplete and direct-message actions;
- owner create/edit options filtered by trusted live runtime capabilities; and
- owner-only observer activity.

### GCP smoke test

1. Adopt the current Codex identity.
2. Confirm an ordinary community member sees it in **Community agents** and can mention it in `#general`.
3. Confirm the reply is authored by the pre-migration pubkey.
4. Confirm the member sees no lifecycle or activity controls.
5. Confirm the owner can stop, start, and observe encrypted activity.
6. Restart the controller service and verify Codex returns with the same pubkey.
7. Restore a snapshot into an isolated VM and verify identity derivation before connecting it as the active controller.
8. Confirm the agent VM still has no external IP and child processes cannot reach the GCE metadata service.
9. Confirm the controller reports the installed Codex adapter as `available` using the configured service-visible path, while an unconfigured same-named executable is ignored.

Desktop UI verification must run through the repository's mock Tauri bridge and screenshot workflow rather than a plain browser.

## Rollout

1. Add protocol kinds and validation.
2. Implement controller state and process supervision.
3. Add owner/member Desktop surfaces and resumable onboarding.
4. Add Terraform installation and snapshot policy without agent definitions.
5. Enroll the controller identity with scoped owner authorization.
6. Adopt Codex and run the live smoke test.
7. Rehearse snapshot restoration.
8. Only then remove the standalone service artifacts.

Rollback stops the controller and re-enables the preserved standalone Codex service/configuration. Because adoption retains the same nsec, rollback does not change the agent identity. Do not run both supervisors concurrently.

## Security Follow-Up

Before opening the service to untrusted or hostile tenants, replace shared-process execution with a sandboxed substrate such as gVisor-backed pods or equivalent per-agent isolation. That phase must also separate Unix identities, provider credentials, filesystem access, resource quotas, and egress policy. The Nostr desired/status contract and Desktop registry should remain unchanged.

## Success Criteria

The feature is complete when all of the following are true:

1. An owner can create, attest, assign, start, stop, restart, and delete a community agent entirely from Buzz.
2. No routine agent lifecycle operation requires Terraform.
3. Every member can discover and invoke assigned community agents without receiving management or activity privileges.
4. Arbitrary kind `10100` publishers cannot appear as official community agents.
5. The controller starts only owner-authored, fully attested, admitted agents using allowlisted runtimes.
6. Controller and agent private keys never enter relay events, Terraform agent definitions, Desktop storage, logs, or status errors.
7. The adopted Codex bot retains its existing pubkey and history.
8. Controller restart restores desired-running agents.
9. A tested GCE snapshot restore recovers the same agent identities within the documented RPO.
10. The VM remains private and metadata access remains blocked for the controller/agent service account at the guest boundary.
11. The initial release explicitly documents that shared UID/kernel execution is not a hostile multi-tenant sandbox.
