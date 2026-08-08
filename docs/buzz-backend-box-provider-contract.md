# `buzz-backend-box` Provider Contract and Kubernetes Reference

## 0. Implementation-level conclusions

The new binary must be a one-request/one-response executable named `buzz-backend-box`. Desktop discovers it by filename, stages the exact executable bytes into a private temporary directory, hashes and locks that staged copy, calls `info` on that copy, validates protocol v1, then calls `deploy` on the same copy. The nsec is absent from `info` and is only sent in the subsequent deploy request. The provider must return all operational failures as an in-band JSON error with process exit 0, except failures to read stdin or an equivalent provider-process failure. Provider-side launch reconciliation must be idempotent and race-safe, with all credentials supplied through the launch Secret/environment rather than `provider_config`.

The required context document confirms the intended Box direction: provider binaries use the `buzz-backend-<id>` contract and Desktop performs discovery, staging, hashing, and pre-secret `info` validation (`docs/buzz-backend-box-research.md:39-66`); Desktop resolves and sends the launch payload (`docs/buzz-backend-box-research.md:67-86`); identity must fail closed, provider config must contain no secrets, and live-instance semantics must be at-most-one with intentional termination final (`docs/buzz-backend-box-research.md:109-142`); the Box design should use ambient auth, deterministic ownership/concurrency, `noEnv: true`, Secret injection, and process supervision (`docs/buzz-backend-box-research.md:233-350`).

## 1. Protocol v1 wire format

### 1.1 Process and response contract

The normative provider process contract is in `docs/remote-agents.md:361-385`:

* Desktop starts one provider process per operation.
* It writes exactly one JSON object to stdin, normally followed by a newline, then closes stdin.
* The provider writes exactly one JSON object to stdout and exits.
* Provider stdout is capped at 1 MiB (`1,048,576` bytes), stderr at 64 KiB (`65,536` bytes). Reads and process completion are bounded.
* Any nonzero process exit is failure regardless of whether stdout contains valid JSON. A provider should therefore use exit 0 for a valid in-band success or in-band failure response.
* In-band failure is `{"ok":false,"error":"<message>"}`.
* Provider diagnostics must not be written to stdout. Stderr is diagnostic-only.
* The provider inherits Desktop's environment and must prepend any required helper paths itself.
* Provider output is untrusted. Desktop redacts every submitted request environment value, longest-first and only for values of length at least four, plus `nsec1...` and `sprt_tok_...` tokens before persisting/displaying diagnostics (`docs/remote-agents.md:378-385`).

Desktop implements the same rules in `desktop/src-tauri/src/managed_agents/backend.rs`: caps are constants at `desktop/src-tauri/src/managed_agents/backend.rs:1-11`; stdin is one serialized JSON value plus newline and the child has piped stdin/out/err at `desktop/src-tauri/src/managed_agents/backend.rs:67-95`; output and stderr are read on bounded threads and the process is polled against a deadline at `desktop/src-tauri/src/managed_agents/backend.rs:97-236`; nonzero exit always returns an error and only a bounded stderr snippet is retained at `desktop/src-tauri/src/managed_agents/backend.rs:238-261`; stdout is parsed as one JSON line or trimmed JSON, and an in-band `ok:false` is returned as an error at `desktop/src-tauri/src/managed_agents/backend.rs:263-287`.

Current K8s `main` follows this exactly. It reads stdin, prints one JSON line, and only uses process exit 1 when stdin cannot be read (`crates/buzz-backend-kubernetes/src/main.rs:34-58`). Invalid request JSON, deserialize errors, relay-mesh refusal, config errors, identity errors, and reconciliation errors become `Response::error` JSON with process exit 0 (`crates/buzz-backend-kubernetes/src/main.rs:60-135`). The K8s wire tests assert one newline-terminated response and compare parsed JSON keys, not formatting (`crates/buzz-backend-kubernetes/tests/wire_fixtures.rs:47-92`; fixture README `crates/buzz-backend-kubernetes/tests/fixtures/README.md:1-39`).

### 1.2 `info` request and response

Normative request (`docs/remote-agents.md:387-394`):

```json
{"op":"info","request_id":"<uuid>"}
```

Normative successful response (`docs/remote-agents.md:395-408`):

```json
{
  "ok": true,
  "name": "<provider software name>",
  "version": "<provider software version>",
  "protocol_version": 1,
  "description": "<human-readable description>",
  "config_schema": { "<JSON Schema>" : "..." }
}
```

Every field is required: `ok` boolean and true, `name` nonempty string, `version` nonempty string, `protocol_version` integer exactly `1`, `description` nonempty string, and `config_schema` JSON object. `version` is provider software version, not wire version. `protocol_version` is the wire protocol and a missing value is an error. `config_schema` drives Desktop's provider configuration UI and is also validated during provider creation (`docs/remote-agents.md:409-415`).

Desktop's validator is intentionally strict: response must be an object; `protocol_version` must be an integer equal to 1; `ok` must be exactly true; name/version/description must be nonempty strings; config_schema must be an object; and allowed keys are exactly `ok`, `name`, `version`, `protocol_version`, `description`, and `config_schema`. Unknown fields are rejected (`desktop/src-tauri/src/managed_agents/backend.rs:13-64`). The info call has a 10-second timeout (`docs/remote-agents.md:412-415`; Desktop invokes it with 10 seconds at `desktop/src-tauri/src/managed_agents/backend.rs:507-521`).

K8s emits the flat response through `Response::info`: `{"ok":true,"name":"kubernetes","version":env!("CARGO_PKG_VERSION"),"protocol_version":1,"description":...,"config_schema":...}` (`crates/buzz-backend-kubernetes/src/wire.rs:128-140`). The binary fixture verifies all fields and the schema (`crates/buzz-backend-kubernetes/tests/wire_fixtures.rs:94-125`).

### 1.3 `deploy` request and response

Normative request (`docs/remote-agents.md:416-428`):

```json
{
  "op": "deploy",
  "request_id": "<uuid>",
  "agent": {
    "name": "...",
    "relay_url": "...",
    "private_key_nsec": "nsec1...",
    "auth_tag": "...",
    "agent_command": "...",
    "agent_args": ["..."],
    "system_prompt": "...",
    "model": "...",
    "provider": "...",
    "turn_timeout_seconds": 0,
    "idle_timeout_seconds": 0,
    "max_turn_duration_seconds": 0,
    "parallelism": 1,
    "respond_to": "owner-only|allowlist|anyone|nobody",
    "respond_to_allowlist": ["<64-hex-pubkey>"],
    "env_vars": {"KEY":"VALUE"},
    "launch": {
      "command": "...",
      "args": ["..."],
      "env": {"KEY":"VALUE"},
      "policy_env": {"KEY":"VALUE"},
      "owner_pubkey": "<64-hex-pubkey>"
    }
  },
  "provider_config": {"<provider-specific configuration>": "..."}
}
```

The exact top-level `agent` field contract and launch schema are specified at `docs/remote-agents.md:429-465` and `docs/remote-agents.md:467-508`. `provider_config` is JSON object provider configuration. The successful response is exactly:

```json
{"ok":true,"agent_id":"<stable provider handle>"}
```

The provider-generated `agent_id` is persisted by Desktop as `backend_agent_id`, must be stable across retries, and is the only management handle in v1. There is no undeploy/stop operation in the v1 provider protocol; deleting the Desktop record can orphan provider substrate (`docs/remote-agents.md:457-465`). Deploy timeout is 600 seconds (`docs/remote-agents.md:416-428`).

The generic failure response is exactly:

```json
{"ok":false,"error":"<redacted human-readable error>"}
```

K8s models the response as a flat untagged enum: `Info`, `Deploy { ok, agent_id }`, or `Error { ok, error }` (`crates/buzz-backend-kubernetes/src/wire.rs:88-126`). The K8s success constructor is at `crates/buzz-backend-kubernetes/src/wire.rs:142-147`. Its `Request` is tagged by lowercase `op`, with `Info {}` or `Deploy(DeployRequest)` (`crates/buzz-backend-kubernetes/src/wire.rs:21-26`); `request_id` is intentionally ignored by Serde (`crates/buzz-backend-kubernetes/src/wire.rs:13-20`), as are extra Desktop agent fields (`crates/buzz-backend-kubernetes/src/wire.rs:35-63`). This is protocol-compatible but means a future shared wire crate should preserve forward-compatible unknown-field handling while retaining the normative full request schema.

### 1.4 K8s wire deserialization nuance

`DeployRequest` has an `agent` and defaulted `provider_config`; `AgentPayload` currently types only the fields the K8s provider consumes: `relay_url`, `private_key_nsec`, optional `auth_tag`, `respond_to`, `respond_to_allowlist`, `env_vars`, and optional `launch` (`crates/buzz-backend-kubernetes/src/wire.rs:28-63`). `LaunchBlock` types optional command, args, env, policy_env, and owner_pubkey (`crates/buzz-backend-kubernetes/src/wire.rs:65-86`). Serde ignores the remaining normative fields rather than rejecting them. Unit tests explicitly verify that Desktop's unconsumed fields are accepted and that launch/nullable owner values parse (`crates/buzz-backend-kubernetes/src/wire.rs:150-249`). A sibling Box provider should either reuse this forward-compatible behavior or put the complete protocol types in a shared crate and derive provider-specific effective inputs from them.

## 2. Desktop provider discovery, staging, hashing, invocation, and the nsec gate

### 2.1 Discovery and resolution

The provider filename contract is `buzz-backend-<id>`. Discovery scans executable files from the current executable's directory first, then PATH entries, then `~/.local/bin`; it never executes candidates. First filename hit wins. The executable prefix and Windows suffix stripping are implemented at `desktop/src-tauri/src/managed_agents/backend.rs:568-638`; provider IDs are lower-case ASCII starting with an alphanumeric and continuing with alphanumeric, `_`, or `-`, and only discovered candidates can be resolved (`desktop/src-tauri/src/managed_agents/backend.rs:640-677`). Executability and canonical path validation are at `desktop/src-tauri/src/managed_agents/backend.rs:679-704`. The spec documents the same discovery order, filename regex `[a-z0-9][a-z0-9_-]*`, shadowing, and diagnostics at `docs/remote-agents.md:305-332`.

Creation validates provider config and resolves the executable before side effects (`desktop/src-tauri/src/commands/agents.rs:655-660`). Deployment reuses a cached path only if its current discovery result still matches the provider id; otherwise it resolves again, then runs the blocking provider call (`desktop/src-tauri/src/commands/agents.rs:450-515`).

### 2.2 Staging and hashing

`stage_provider` creates a private temporary directory named `buzz-provider-*`, copies the provider executable in 64 KiB chunks while calculating SHA-256, flushes/syncs the staged file, makes it read/execute-only on Unix (`0500`, with the Windows equivalent), and creates an execution guard file that prevents replacement/deletion while the child runs (`desktop/src-tauri/src/managed_agents/backend.rs:433-505`). The staged path is canonicalized and is the exact path passed to the process.

The protocol gate requires the same staged bytes for both operations: stage once, hash while copying, invoke `info`, validate explicit protocol v1, then invoke `deploy` on that same staged artifact, and delete the staging directory afterward (`docs/remote-agents.md:334-359`; current call sequence `desktop/src-tauri/src/managed_agents/backend.rs:507-533`). The computed digest is returned from `stage_provider`, but the current `provider_deploy` binds it to `_digest` and does not persist or compare it (`desktop/src-tauri/src/managed_agents/backend.rs:507-533`). This is important for the Box plan: preserve the staging invariant, but do not assume a digest approval store exists in current Desktop.

### 2.3 What is validated before the nsec is exposed

The pre-secret gate is:

1. Resolve a discovered executable and validate its path/permissions.
2. Stage immutable bytes and calculate SHA-256.
3. Invoke `info` without the agent payload or nsec.
4. Require a complete, flat, exact-key info response with `protocol_version == 1`.
5. Only after that invoke `deploy` using the same staged path, at which point the nsec is in the `agent` object.

This ordering is explicit in the spec (`docs/remote-agents.md:334-359`) and code (`desktop/src-tauri/src/managed_agents/backend.rs:507-533`). The provider info response is validated before any deploy request is constructed. Deployment errors are stored in Desktop's agent record; successful `agent_id` and `last_started_at` are persisted (`desktop/src-tauri/src/commands/agents.rs:450-515`).

Other pre-mutation checks include provider id/executable discovery (`desktop/src-tauri/src/managed_agents/backend.rs:640-704`), provider configuration validation (below), empty/malformed key refusal in payload construction (`desktop/src-tauri/src/commands/agents_deploy.rs:103-152`), and refusal of relay-mesh mode (`desktop/src-tauri/src/commands/agents_deploy.rs:93-101`; `docs/remote-agents.md:604-624`). The K8s provider independently derives the pubkey from nsec before reading or mutating substrate (`crates/buzz-backend-kubernetes/src/main.rs:115-135`; `docs/remote-agents.md:632-644`).

### 2.4 Redaction implementation

Desktop extracts nonempty string secrets from `agent.env_vars`, `agent.launch.env`, and `agent.launch.policy_env` (`desktop/src-tauri/src/managed_agents/backend.rs:392-415`). It redacts those values plus nsec/token prefixes and selected GitHub token prefixes, longest-first, only for values of length at least four, replacing with `[REDACTED]` (`desktop/src-tauri/src/managed_agents/backend.rs:330-390`). It applies redaction to stderr snippets, process errors, nonzero-exit messages, and in-band provider errors (`desktop/src-tauri/src/managed_agents/backend.rs:238-287`). Stderr snippets are bounded to 4096 characters in the returned error path (`desktop/src-tauri/src/managed_agents/backend.rs:238-261`). A Box provider must additionally ensure Box credentials, tokens, nsec, and submitted env values never enter raw provider errors.

## 3. Full Desktop deploy payload and environment construction

### 3.1 Exact payload emitted by Desktop

`build_deploy_payload` loads global settings, persona/team settings, merges user env, resolves the effective agent config, rejects relay mesh, resolves the effective harness descriptor, computes owner identity, and calls the JSON builder (`desktop/src-tauri/src/commands/agents_deploy.rs:103-152`). The exact top-level fields emitted by `deploy_payload_json` are 17 fields at `desktop/src-tauri/src/commands/agents_deploy.rs:155-185`:

1. `name`
2. `relay_url`
3. `private_key_nsec`
4. `auth_tag`
5. `agent_command`
6. `agent_args`
7. `system_prompt`
8. `model`
9. `provider`
10. `turn_timeout_seconds`
11. `idle_timeout_seconds`
12. `max_turn_duration_seconds`
13. `parallelism`
14. `respond_to`
15. `respond_to_allowlist`
16. `env_vars`
17. `launch`

The expected full launch fixture and exact values are asserted in `desktop/src-tauri/src/commands/agents_tests.rs:412-503` and `desktop/src-tauri/src/commands/agents_deploy.rs:187-260`.

### 3.2 `launch` schema and policy construction

`build_launch_block` constructs `launch.policy_env` from runtime defaults, optional `MCP_HOOK_SERVERS`, relay observer, lazy pool, parallelism, optional system prompt/model/idle timeout/max duration, resolved session title, and team instructions. It also emits `command`, `args`, merged runtime descriptor env, `policy_env`, and `owner_pubkey` (`desktop/src-tauri/src/commands/agents_deploy.rs:30-91`). The normative launch schema is documented as `command` string, `args` string array, `env` map, `policy_env` map, and nullable `owner_pubkey` (`docs/remote-agents.md:467-496`). The command/args are resolved using the same runtime resolver as local agents (`docs/remote-agents.md:498-508`).

`policy_env` is an overridable/default tier. The docs enumerate runtime defaults, observer, lazy pool, session title, team instructions, model, MCP hooks, and other policy values at `docs/remote-agents.md:510-563`. The provider must not remap the tier-1 authoritative `BUZZ_ACP_SYSTEM_PROMPT`, `BUZZ_ACP_IDLE_TIMEOUT`, `BUZZ_ACP_MAX_TURN_DURATION`, or `BUZZ_ACP_AGENTS`; it must construct authoritative identity/ownership/respond-to/inactivity/MCP/start-nonce variables itself.

### 3.3 Environment precedence and reserved/constructed keys

Desktop's saved user env rules are in `desktop/src-tauri/src/managed_agents/env_vars.rs`:

* Derived model/provider keys include `GOOSE_MODEL`, `GOOSE_PROVIDER`, `BUZZ_AGENT_MODEL`, and `BUZZ_AGENT_PROVIDER` (`desktop/src-tauri/src/managed_agents/env_vars.rs:16-40`).
* Reserved keys and reserved categories are defined at `desktop/src-tauri/src/managed_agents/env_vars.rs:42-94`. Exact reserved keys are `BUZZ_PRIVATE_KEY`, `NOSTR_PRIVATE_KEY`, `BUZZ_AUTH_TAG`, `BUZZ_API_TOKEN`, `BUZZ_ACP_PRIVATE_KEY`, `BUZZ_ACP_API_TOKEN`, `BUZZ_RELAY_URL`, `BUZZ_ACP_AGENT_COMMAND`, `BUZZ_ACP_AGENT_ARGS`, `BUZZ_ACP_MCP_COMMAND`, `BUZZ_ACP_RESPOND_TO`, `BUZZ_ACP_RESPOND_TO_ALLOWLIST`, `BUZZ_ACP_AGENT_OWNER`, `BUZZ_ACP_EXIT_AFTER_INACTIVITY`, `BUZZ_ACP_NO_PRESENCE`, `BUZZ_ACP_SETUP_PAYLOAD`, `BUZZ_MANAGED_AGENT`, and `BUZZ_MANAGED_AGENT_START_NONCE`.
* Environment keys must match POSIX `[A-Za-z_][A-Za-z0-9_]*`; this prevents separator/case tricks such as `BUZZ_AUTH_TAG=x` from bypassing reserved-key filtering (`desktop/src-tauri/src/managed_agents/env_vars.rs:102-119`).
* Save-time validation rejects malformed/reserved keys and NULs, caps a value at 32 KiB and total env at 256 KiB (`desktop/src-tauri/src/managed_agents/env_vars.rs:154-225`).
* Merged user env is persona first, agent second, so agent wins; reserved/malformed/NUL/oversize values are stripped (`desktop/src-tauri/src/managed_agents/env_vars.rs:261-316`). The payload's `env_vars` is already the merged global/persona/agent result (`desktop/src-tauri/src/commands/agents_deploy.rs:116-120`), so providers must not re-merge legacy env layers.

The spec's normative precedence is: (1) `launch.policy_env`, overridable; (2) `launch.env`, already merged global < persona < agent; (3) authoritative top-level identity, respond-to, owner, inactivity, MCP command, and provider-generated start nonce (`docs/remote-agents.md:510-584`). Host paths, host `PATH`, and `BUZZ_ACP_SETUP_PAYLOAD` must not be forwarded; providers derive runtime paths inside the image/sandbox (`docs/remote-agents.md:586-602`).

K8s makes the precedence secure and explicit in `env.rs`: policy env is inserted first, then `launch.env`, or legacy `agent.env_vars` when launch is absent; no legacy remerge occurs (`crates/buzz-backend-kubernetes/src/env.rs:151-187`). It validates lower-tier POSIX keys, rejects `BUZZ_ACP_NO_PRESENCE`, clears every authoritative key, then writes authoritative values (`crates/buzz-backend-kubernetes/src/env.rs:189-216`). It constructs relay/private key/NOSTR key/auth tag/owner, command/args, `BUZZ_ACP_MCP_COMMAND=buzz-dev-mcp`, respond-to/allowlist, inactivity, and a fresh start nonce (`crates/buzz-backend-kubernetes/src/env.rs:217-286`). It enforces an overall Secret env size cap (`crates/buzz-backend-kubernetes/src/env.rs:288-296`).

### 3.4 Top-level field mapping required of Box

The normative mapping table is `docs/remote-agents.md:1067-1103`:

* `relay_url` -> authoritative `BUZZ_RELAY_URL`.
* `private_key_nsec` -> authoritative `BUZZ_PRIVATE_KEY` and derived `NOSTR_PRIVATE_KEY`.
* `auth_tag` -> `BUZZ_AUTH_TAG`; it is also the owner identity when present.
* `launch.owner_pubkey` -> authoritative owner when no auth tag is used.
* `launch.command` -> `BUZZ_ACP_AGENT_COMMAND`.
* `launch.args` -> `BUZZ_ACP_AGENT_ARGS`, comma-joined in the K8s reference implementation.
* `BUZZ_ACP_MCP_COMMAND` -> exactly `buzz-dev-mcp` in K8s.
* `respond_to` -> `BUZZ_ACP_RESPOND_TO`; allowlist -> `BUZZ_ACP_RESPOND_TO_ALLOWLIST`.
* `idle_timeout_seconds` or `max_turn_duration_seconds` -> `BUZZ_ACP_EXIT_AFTER_INACTIVITY` according to the provider's supported inactivity policy; K8s uses the effective inactivity value and defaults to 7200.
* `launch.policy_env` and `launch.env` -> lower-tier environment after validation.
* `parallelism` -> `BUZZ_ACP_AGENTS` through policy env.
* `model`, `provider`, `system_prompt`, `turn_timeout_seconds` remain top-level semantic inputs. K8s deliberately does not remap model/provider or turn timeout (`crates/buzz-backend-kubernetes/src/env.rs:514-544` tests; `docs/remote-agents.md:1067-1103`).

## 4. `provider_config` secret rejection rules

Desktop validates provider config before invoking the provider and before create-side effects (`desktop/src-tauri/src/commands/agents.rs:655-660`). The exact validator is `desktop/src-tauri/src/managed_agents/backend.rs:535-565`:

* The value must be a JSON object.
* It may contain at most 20 fields.
* Serialized JSON must be at most 65,536 bytes.
* Every value must be scalar. Nested objects and arrays are rejected.
* Key names are split on `_`, `-`, `.`, and camel-case/acronym boundaries by `split_config_key` (`desktop/src-tauri/src/managed_agents/backend.rs:290-327`), lower-cased into semantic segments, and rejected if any segment is exactly one of `secret`, `password`, `token`, `key`, or `credential`.
* This catches names such as `api_token`, `clientSecret`, `private-key`, and `access.credential`.
* It intentionally accepts non-secret substrings such as `keyboard` and `monkey_wrench`; rejection is segment equality, not substring matching.

The provider therefore must never require Box credentials in `provider_config`. The Box research context explicitly calls for ambient provider authentication and Secret injection (`docs/buzz-backend-box-research.md:233-350`).

## 5. Kubernetes reference implementation

### 5.1 Crate and module layout

`crates/buzz-backend-kubernetes/Cargo.toml:1-36` defines the `buzz-backend-kubernetes` package and binary. The module list is in `crates/buzz-backend-kubernetes/src/main.rs:11-23`:

* `wire`: protocol JSON types and response constructors.
* `config`: provider config schema, defaults, validation, generated namespace.
* `env`: precedence, reserved/authoritative env construction, respond-to validation.
* `naming`: nsec-derived identity, stable pod name, labels/selectors, per-attempt secret generation.
* `image`: digest-only image validation and canonicalization.
* `intent`: deterministic non-secret launch fingerprint.
* `pod`: Secret and Pod object construction.
* `client`: ambient kubeconfig connection and helper PATH.
* `cluster`: Kubernetes substrate implementation and API error classification.
* `observe`: management-marker/pubkey verification and pod startup-state observation/redaction.
* `classify`: pure action classification from observed state.
* `gc`: preflight cleanup planning and stale-resource fencing.
* `reconcile`: deadline-bounded, race-safe deployment state machine.
* `main`: stdin/stdout process orchestration.

Dependencies include kube/k8s-openapi, nostr, Tokio, Serde, SHA-256/hex, rand, chrono, HTTP, rustls/ring, and test tower support (`crates/buzz-backend-kubernetes/Cargo.toml:1-36`).

### 5.2 Config schema and security defaults

Provider config has no credentials. It contains context, namespace, digest-qualified image, CPU/memory requests and limits, inactivity seconds, and optional service account (`crates/buzz-backend-kubernetes/src/config.rs:1-74`). Defaults include CPU request 1, memory request 2Gi, CPU limit 2, memory limit 4Gi (`crates/buzz-backend-kubernetes/src/config.rs:11-31`), inactivity 7200 seconds, digest-pinned default image, uid/gid 10001, workspace `/home/agent`, and 60-second termination grace (`crates/buzz-backend-kubernetes/src/config.rs:33-56`). Namespace is required and validated, image must include a lowercase 64-hex SHA-256 digest, and current `inactivity_seconds=0` is refused because indefinite runtime would require the not-yet-supported clean-exit/crash-loop policy (`crates/buzz-backend-kubernetes/src/config.rs:108-175`). The JSON schema exposes these fields and defaults at `crates/buzz-backend-kubernetes/src/config.rs:192-243`.

`image.rs` rejects tag-only image references and accepts only an exact lowercase `@sha256:<64 hex>` digest (`crates/buzz-backend-kubernetes/src/image.rs:1-94`). `client.rs` uses ambient kubeconfig/context, not credentials in config, and prepends Homebrew, `/usr/local/bin`, and `$HOME/.local/bin` to PATH for exec plugins (`crates/buzz-backend-kubernetes/src/client.rs:1-123`).

### 5.3 Identity, naming, and deterministic intent

`naming.rs` derives the full pubkey only from the submitted nsec using `nostr::SecretKey::from_bech32`; malformed keys fail before substrate access (`crates/buzz-backend-kubernetes/src/naming.rs:1-84`). The stable pod name is `buzz-agent-<first12-pubkey>`, and each attempt's Secret is `<pod>-<random-generation>` (`crates/buzz-backend-kubernetes/src/naming.rs:37-84`). Management labels/selectors and the full pubkey annotation are defined at `crates/buzz-backend-kubernetes/src/naming.rs:9-35` and `:86-111`; generation is random lowercase hex (`:114-123`).

`intent.rs` hashes only non-secret configuration: template version, namespace, canonical image, resources, service account, restart/grace values, sorted env key names, workspace, UID/GID, and a placeholder instead of Secret contents (`crates/buzz-backend-kubernetes/src/intent.rs:1-134`). This fingerprint is used for convergence and is safe to place in annotations.

### 5.4 Environment and Secret construction

The authoritative key list is `crates/buzz-backend-kubernetes/src/env.rs:11-42`; it includes relay/private/NOSTR/auth/owner, agent command/args, MCP command, respond-to/allowlist, inactivity, and start nonce. `BUZZ_ACP_NO_PRESENCE` is forbidden and the complete Secret payload is capped at 1 MiB (`crates/buzz-backend-kubernetes/src/env.rs:44-53`).

`pod.rs` creates an immutable Secret per attempt with the management labels and full pubkey annotation, `string_data` environment, and `immutable=true` (`crates/buzz-backend-kubernetes/src/pod.rs:1-59`). The Secret name includes a random generation so concurrent deploys cannot overwrite one another. The Pod references exactly that Secret through `envFrom`; cleanup is fenced to the current attempt.

### 5.5 Pod specification

`build_pod` constructs a bare Kubernetes Pod with deterministic name, labels, annotations, full pubkey, create intent, image fingerprint, resource requests/limits, 60-second grace, and `restartPolicy: Never` (`crates/buzz-backend-kubernetes/src/pod.rs:61-183`). It does not set command/args, relying on the image entrypoint to run the provider's ACP process as PID1. The container:

* imports the exact immutable Secret via `envFrom`;
* mounts an `emptyDir` workspace at `/home/agent`;
* does not request a service-account token by default;
* sets non-root uid/gid 10001, `allowPrivilegeEscalation=false`, drops all Linux capabilities, and uses RuntimeDefault seccomp;
* permits an optional configured service account.

The normative K8s requirements and exact Pod shape are also captured in `docs/remote-agents.md:1111-1237` and the context research at `docs/buzz-backend-box-research.md:144-166`.

### 5.6 Reconciliation and concurrency behavior

`reconcile.rs` defines the substrate interface and the operation deadline (`crates/buzz-backend-kubernetes/src/reconcile.rs:1-120`): a 600-second deadline, 2-second polling interval, namespace/resource listing, Secret/Pod create/delete, observation, sleep, and elapsed-time abstraction. The main state machine is `crates/buzz-backend-kubernetes/src/reconcile.rs:351-488`:

1. Ensure the namespace exists.
2. Run preflight GC; hygiene failure is non-fatal to the requested deploy.
3. Derive the deterministic intent fingerprint.
4. Observe managed pods, verifying management marker and full pubkey.
5. If a live Started pod exists, strict no-op regardless of intent divergence.
6. If a recoverable non-started pod has matching intent, observe/wait without deleting it.
7. If a terminated or provably broken pod exists, delete it using UID/resourceVersion fencing and wait for disappearance.
8. Pull failures are reported, not deleted, so registry/image remediation is possible.
9. If no usable pod exists, generate a new attempt generation, create that attempt's Secret first, then create the deterministic Pod.
10. If Pod creation races and returns AlreadyExists, adopt/observe the winner; do not replace it.
11. The caller deletes only its own Secret when it loses a race. It never deletes another attempt's Secret.
12. `created_this_call` prevents a just-created resource from being hot-replaced by the same call.

The pure classification layer makes these policies explicit. `classify.rs:1-174` defines `NoOp` for Started, `Delete` with a fence for Terminated/provably broken, `Report` for pull failures, `Observe` for matching recoverable state, and `Create` for no pod. Pull failures cannot reach Delete (`crates/buzz-backend-kubernetes/src/classify.rs:1-15`). Tests cover strict started no-op even with divergent intent, pull-failure report/no deletion, recoverable observation, termination replacement, delete fencing, and deletion waits (`crates/buzz-backend-kubernetes/src/reconcile.rs` tests beginning at `:490`).

`cluster.rs` implements the substrate with quorum reads, namespace/create handling, status.reason classification rather than HTTP status alone, fenced deletion using UID/resourceVersion, NotFound-as-success, and no local grace override (`crates/buzz-backend-kubernetes/src/cluster.rs:1-70`, `crates/buzz-backend-kubernetes/src/cluster.rs:136-257`). The server's HTTP Date is used for clock-safe GC listing (`crates/buzz-backend-kubernetes/src/cluster.rs:79-133`).

### 5.7 Observation, error redaction, and GC

`observe.rs` verifies the management marker and full pubkey before interpreting a Pod (`crates/buzz-backend-kubernetes/src/observe.rs:1-67`). It classifies running containers as Started, terminated containers as Terminated, invalid image names and pull errors as broken/pull-failure states, and delays `CreateContainerConfigError` classification until it checks whether the referenced Secret exists (`crates/buzz-backend-kubernetes/src/observe.rs:69-129`). Pull-failure messages are synthesized from safe image/registry data, while raw waiting/terminated messages are deliberately not echoed. Only safe Pod condition messages are retained (`crates/buzz-backend-kubernetes/src/observe.rs:131-246`).

`gc.rs` runs a bounded preflight plan with 600-second operation semantics, 1200-second orphan-age gate, management-marker plus annotation verification, and the same Kubernetes server Date for age checks (`crates/buzz-backend-kubernetes/src/gc.rs:1-115`). It never touches the current generation and never falls back to the local clock. The spec describes the same marker/annotation fence and `2 * 600s` gate at `docs/remote-agents.md:1285-1385`.

### 5.8 Tests and fixtures

The K8s crate has unit tests in every policy-heavy module: wire, config, env, naming, image, intent, classify, observe, GC, cluster error behavior, and reconcile. The built-binary golden tests are in `crates/buzz-backend-kubernetes/tests/wire_fixtures.rs:1-222`; fixtures include:

* `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/info.request.json:1`.
* Full Desktop deploy payload in `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/deploy-full.request.json:1-51`.
* No-owner refusal and exact response in `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/no-owner.request.json:1-8`.
* Tag-only image refusal in `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/tag-image.request.json:1-9`.
* Relay-mesh refusal in `crates/buzz-backend-kubernetes/tests/fixtures/provider-wire/relay-mesh.request.json:1-11`.

The fixture README says fixtures are a shared arbiter: Desktop should assert the emitted payload, fixtures must be recorded from real payloads rather than invented, and responses are compared by parsed JSON keys (`crates/buzz-backend-kubernetes/tests/fixtures/README.md:1-39`). This fixture/harness pattern is directly reusable for Box.

## 6. Reusable versus K8s-specific code for Box

The best existing extraction point is the sibling-provider design, which proposes a `buzz-backend-core` containing shared `wire.rs`, `env.rs`, `identity.rs`, fixtures, and a harness while leaving K8s-specific pod/client/cluster/image/GC/reconcile code in the K8s crate (`docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md:70-96`).

### Share or extract

* Full protocol request/response structs and response constructors, preserving unknown-field compatibility and flat error shape.
* Desktop environment precedence, POSIX key validation, reserved-key stripping, authoritative-key clearing, respond-to/allowlist validation, inactivity/start-nonce construction, and size limits.
* nsec-to-pubkey identity derivation and fail-closed owner checks.
* Safe redaction helpers and provider stderr/output handling where practical.
* Golden request fixtures and a subprocess harness that asserts one JSON response, exit semantics, and exact key/value behavior.
* Generic intent/convergence abstractions only if they can be made substrate-neutral. The current `Substrate` trait is already shaped around Kubernetes resources, so blindly sharing it would couple Box to Pods/Secrets.

### Keep provider-specific

* K8s image digest parser, namespace generation, Pod/Secret naming, Kubernetes labels/annotations, kubeconfig/exec-plugin client, API fences, resource-version handling, server-Date GC, Pod observation, and Pod security context.
* K8s-specific reconcile classification details tied to Pod phases/container waiting reasons.
* Box sandbox lifecycle, Box API/client, instance/container naming, `noEnv: true` semantics, ambient Box auth, process supervision, and Box-specific cleanup/adoption APIs.

For Box, use the context design's explicit requirements: deterministic owner key and one-live-instance convergence, inject the nsec/auth into the Box sandbox rather than `provider_config`, avoid forwarding host `PATH`/setup payload, and supervise the ACP process so the runtime can signal intentional termination (`docs/buzz-backend-box-research.md:233-350`, `docs/buzz-backend-box-research.md:352-367`).

## 7. Workspace, build, sidecar, test, and CI registration

The workspace includes `crates/buzz-backend-kubernetes` at `Cargo.toml:30`; its package manifest is `crates/buzz-backend-kubernetes/Cargo.toml:1-36`, and the lockfile has the package entry at `Cargo.lock:918-936`. A sibling Box crate needs a workspace member and lockfile package entry.

There is no dedicated `just buzz-backend-kubernetes` target. Instead:

* Unit-test orchestration runs `cargo nextest run -p buzz-backend-kubernetes` in the `test-unit` recipe (`Justfile:280-308`).
* Sidecar stubs include K8s on non-Windows (`Justfile:151-164`), and desktop release builds create those stubs (`Justfile:232-250`).
* Tauri declares `binaries/buzz-backend-kubernetes` as an external binary (`desktop/src-tauri/tauri.conf.json:52-62`).
* `scripts/bundle-sidecars.sh:4-53` builds/copies K8s on supported platforms and sets executable permissions.
* Test orchestration runs K8s unit tests (`scripts/run-tests.sh:110-114`).
* CI has a K8s placeholder/build step (`.github/workflows/ci.yml:1051-1060`).
* Release workflow packages/builds it at `.github/workflows/release.yml:92-95`, `.github/workflows/release.yml:309-312`, and `.github/workflows/release.yml:564-567`.
* Canary workflows include the binary on Linux and macOS Intel/signed macOS (`.github/workflows/linux-canary.yml:187-193`; `.github/workflows/macos-intel-canary.yml:84-90`; `.github/workflows/signed-macos-canary.yml:116-119`).
* Release-shaped provider testing is in `scripts/test-k8s-provider-release.sh:1-78`; it builds the release binary, sends an unreachable-cluster request, and asserts one JSON in-band error with process exit 0.
* Desktop platform expectations currently treat K8s as externalBin on macOS/Linux but not Windows (`desktop/src-tauri/src/commands/agents_tests.rs:482-503`). The spec says K8s distribution is standalone macOS arm64/x64 and Linux musl, with no Windows v1 (`docs/remote-agents.md:1394-1400`).

If Box is bundled into Desktop, mirror the K8s entries in the externalBin list, sidecar stub/bundle scripts, unit-test orchestration, CI, release, and canary matrices. If it is initially a standalone provider, the crate/workspace/fixture/release test still applies, but the Desktop sidecar wiring can be deferred.

## 8. Spec requirements the implementation plan must preserve

### Idempotency and concurrency

Provider deploy is explicitly idempotent: concurrent or sequential deploys with the same effective payload must converge to one live instance and return the same stable `agent_id` (`docs/remote-agents.md:833-873`). Desktop delegates this behavior to the provider (`desktop/src-tauri/src/commands/agents.rs:450-515`). K8s achieves it through identity-derived deterministic names, intent fingerprints, strict Started no-op, observe-only recovery, fenced deletion, random per-attempt Secret names, create-then-adopt race handling, and loser-owned Secret cleanup (`crates/buzz-backend-kubernetes/src/reconcile.rs:229-488`; `crates/buzz-backend-kubernetes/src/naming.rs:37-123`). Box must design the equivalent ownership key and race/adoption protocol rather than relying on Desktop serialization.

There is one provider process per operation and no provider-internal concurrent protocol channel (`docs/remote-agents.md:361-376`). The request UUID is available for tracing but current K8s deserializes and ignores it (`crates/buzz-backend-kubernetes/src/wire.rs:13-20`).

### Timeout and deadline

`info` has a 10-second timeout and `deploy` has a 600-second timeout (`docs/remote-agents.md:387-428`). Desktop enforces deadlines and kills timed-out provider processes (`desktop/src-tauri/src/managed_agents/backend.rs:160-201`). Provider reconciliation must itself honor the 600-second operation deadline, including cleanup and polling; K8s uses an injectable elapsed-time abstraction and deadline in `crates/buzz-backend-kubernetes/src/reconcile.rs:53-120`.

### Redaction

Every request env value of length >=4 must be treated as secret for diagnostic redaction, longest-first, along with nsec and token patterns (`docs/remote-agents.md:378-385`). Providers should synthesize safe errors rather than echo raw substrate/API messages, especially credentials, environment values, nsec, Box access tokens, or arbitrary command output. K8s's `observe.rs:131-246` is the reference for safe pull-error/condition handling; Desktop's outer redactor is at `desktop/src-tauri/src/managed_agents/backend.rs:330-390`.

### Ownership and identity rules

Before substrate reads or mutations, derive the pubkey from the nsec, fail closed on malformed keys, and use only the derived pubkey for management labels/ownership. `auth_tag` or `launch.owner_pubkey` must resolve an owner; both absent is refused; relay-mesh is refused in v1 (`docs/remote-agents.md:604-644`; K8s `env.rs:217-251`).

### Lifecycle and deletion

A Started managed instance is a strict no-op even when requested intent differs. Terminated or provably broken instances may be replaced with fencing; pull failures are reported and not deleted. The lifecycle table and no-op rules are at `docs/remote-agents.md:682-692`, `docs/remote-agents.md:833-873`, and K8s's pure classifier is `crates/buzz-backend-kubernetes/src/classify.rs:103-174`. Provider stop is not a v1 operation; Desktop's stop path uses the runtime's graceful `!shutdown` convention, with force deletion as an explicit separate policy (`docs/remote-agents.md:875-914`).

### Inactivity and restart

`BUZZ_ACP_EXIT_AFTER_INACTIVITY` controls provider runtime inactivity behavior. The spec defaults to zero/indefinite and documents K8s's 7200-second default at `docs/remote-agents.md:916-980`; current K8s config intentionally rejects explicit zero because its clean-exit/restart semantics are not yet implemented (`crates/buzz-backend-kubernetes/src/config.rs:148-164`). The Box plan must decide whether Box can support indefinite/clean exit and must not silently invent a restart policy.

### v2 direction

Protocol v1 intentionally has only `info` and `deploy`; no status/logs/undeploy channel (`docs/remote-agents.md:90-104`, `docs/remote-agents.md:457-465`). The spec discusses future stop/recycle convergence and provider management expansion at `docs/remote-agents.md:858-864`; relay-mesh/alternate owner semantics are deferred to a future version (`docs/remote-agents.md:604-624`). The Box research document explicitly lists a possible v2 that sends stored `backend_agent_id` and adds undeploy/status/log operations (`docs/buzz-backend-box-research.md:423-432`). Do not add v2 fields or operations to the v1 implementation unless they remain ignored/forward-compatible and do not alter the exact v1 gate.

## 9. Validation performed

Executed in the repository's Hermit environment:

```text
. ./bin/activate-hermit && cargo test -p buzz-backend-kubernetes -- --nocapture
```

Result: exit 0; 154 unit tests passed and 4 wire-fixture integration tests passed, with no failures. The test run covered wire parsing/response fixtures, config/env/identity/image/intent validation, Pod/Secret construction, observation/redaction, GC, classification, reconciliation races/fences/deadlines, and in-band error behavior.

## 10. Implementation-plan follow-ups

1. Extract or duplicate the shared wire/env/identity/redaction/fixture harness without weakening K8s's current tests.
2. Define Box `provider_config` as non-secret, scalar, schema-driven values only, with ambient Box authentication.
3. Specify Box's deterministic identity/owner key, at-most-one-live-instance race behavior, no-op/adoption rules, and safe deletion fence before coding.
4. Decide how Box maps launch env to its sandbox without forwarding host paths, `BUZZ_ACP_SETUP_PAYLOAD`, or arbitrary host PATH.
5. Add Box to workspace and, if Desktop-bundled, mirror all sidecar, Tauri externalBin, Justfile, test, CI, release, and canary registration points above.
6. Keep protocol v1 exact; document any v2-oriented metadata as ignored forward-compatible fields only.

## Caveat about historical defects

`docs/remote-agents.md` contains a “Known Defects” section pinned to old commit `28ae6cd21` (`docs/remote-agents.md:1572-1676`). Current-tree Desktop code already implements the staged same-artifact pre-secret gate, and current K8s code/tests contain the fixes. Treat the current source and tests as authoritative, and cite the old-commit defect list only as historical context.

**Blocker:** none.
