# ASCII Box Platform Verification for `buzz-backend-box`

**Status:** Public-documentation verification and implementation-plan input  
**Date:** 2026-08-08  
**Source context:** [`docs/buzz-backend-box-research.md`](./buzz-backend-box-research.md)

## Scope and evidence labels

This report verifies the ASCII Box platform-side claims in the research document using the current public ASCII Box documentation and the published OpenAPI specification.

- **VERIFIED** means the behavior is stated by a current public documentation page or schema.
- **UNVERIFIED** means the docs are silent, contradictory, or the behavior requires a live-account spike.
- **REFINEMENT** means the research document's assumption should be narrowed or changed based on the public docs.

The public OpenAPI document was downloaded and its complete path inventory was inspected. No live Box account or credentials were available, so live-dependent claims remain explicitly marked.

## Executive verdict

ASCII Box is a good fit for persistent Buzz agents. The public docs support full Linux VMs, no-env isolation, per-second billing, stop/resume snapshots, automatic restart of enabled systemd services, dedicated IPv4 addresses, and EU data residency.

The research document is directionally correct, but these implementation-critical assumptions are not verified by the public docs:

1. Whether `box stop self` works from a newly created `noEnv` Box using only its machine-scoped identity.
2. Whether deterministic subdomain claims are atomic and which conflict status/code is returned.
3. The numeric command stdout/stderr byte cap.
4. Whether Docker image layers, container writable layers, and Docker metadata survive snapshots.
5. A Box-specific digest-pull guarantee and private-registry authentication workflow.
6. Explicit outbound WSS/HTTPS policy or egress allowlists.
7. Whether hard deletion exists in the current public API.

## 1. Full Box lifecycle API

### 1.1 Authentication and response model

**VERIFIED.** The public API base URL is:

```text
https://ascii.dev/api/box/v1
```

Requests use a Box API key as a bearer token. Responses use an explicit `ok` discriminator and a stable `type` such as `box.created`, `box.stopping`, or `box.list`. HTTP status remains authoritative. The documented error envelope includes `status`, `code`, `message`, `error`, and `requestId`.

The API overview documents common statuses including 400, 401, 402, 404, 409, 429, and 5xx. The complete operation-specific response declarations are in the [public OpenAPI document](https://docs.ascii.dev/openapi/box-v1.yaml).

Sources:

- [Box Public API v1](https://docs.ascii.dev/box/api/v1)
- [API Keys](https://docs.ascii.dev/box/api-keys)
- [Public OpenAPI YAML](https://docs.ascii.dev/openapi/box-v1.yaml)

### 1.2 Create

**VERIFIED.** `POST /boxes` provisions a new Box and returns HTTP 202 with a `box.created` response. The returned Box initially has state `provisioning`. The provider should store the returned `box.id` and poll `GET /boxes/{boxId}`.

Create fields:

| Field | Public behavior |
|---|---|
| `type` | `small`, `default`, or `large`. Default is `default`. |
| `ttlSeconds` | Integer from 1 through 2,592,000 seconds, or `null`. Default is 3,600 seconds. `null` disables auto-stop. |
| `env` | Per-Box environment variables layered over account environment variables. Per-Box values win on key conflicts. |
| `noEnv` | Withholds account environment variables, secret files, and credentials. The Box is confined to itself and cannot act on the account or other Boxes. |

The backend also accepts the legacy string `infinite` for `ttlSeconds`, but new clients should send `null`.

The environment rules are bounded to at most 100 variables and 64 KB total. Reserved internal names including `ASCII_TOKEN`, `BOX_ID`, and other platform variables are rejected.

The current create schema does not expose `subdomain` as a create field. A deterministic subdomain claim must therefore happen later through `PATCH /boxes/{boxId}`.

Sources:

- [Create box](https://docs.ascii.dev/box/api/reference/boxes/create-box)
- [Secrets & Setup](https://docs.ascii.dev/box/secrets)
- [Build a Platform on Box](https://docs.ascii.dev/box/platform-guide)
- [Long-Running Tasks](https://docs.ascii.dev/box/long-running-tasks)

### 1.3 List and get

**VERIFIED.** `GET /boxes` lists Boxes owned by the authenticated Box account.

Supported query parameters:

- `limit`: 1 through 200, default 100.
- `cursor`: opaque pagination cursor returned as `pageInfo.nextCursor`.
- `sort`: `asc` or `desc`, default `desc`.
- `state`: comma-separated state filter, for example `ready,idle,running`.

`GET /boxes/{boxId}` returns the current Box details and is the documented polling endpoint after create, stop, resume, or fork.

Box states in the API schema include:

```text
init
provisioning
provisioned
cloning
ready
idle
running
archiving
archived
error
```

The API overview warns that `idle` and `running` only describe work queued through the first-class prompt API. Processes launched through SSH or the command endpoint do not change Box state. A Box can report `idle` while a custom Buzz agent is actively running inside it.

Sources:

- [List boxes](https://docs.ascii.dev/box/api/reference/boxes/list-boxes)
- [Get box](https://docs.ascii.dev/box/api/reference/boxes/get-box)
- [Box Public API v1](https://docs.ascii.dev/box/api/v1)

### 1.4 Update and subdomain claim semantics

**VERIFIED.** `PATCH /boxes/{boxId}` updates:

- `name`
- `ttlSeconds`
- `subdomain`

Subdomain validation and behavior:

- Length 3 through 40 characters.
- Lowercase letters, digits, and hyphens.
- No leading or trailing hyphen.
- No double hyphens.
- Cannot end in `-desktop` or `-<number>` because those forms are reserved for desktop and hosted-port URLs.
- Must be globally unique.
- Renaming repoints the Box base URL, desktop URL, and live `host <port>` URLs.
- Access tokens are preserved.
- Old URLs stop resolving.
- A transient routing error is described as HTTP 502 with code `gateway_error`. The docs say the rename is saved and should be retried with the same value to finish activating routes.

**UNVERIFIED: atomicity and conflict code.** The update operation in the published OpenAPI declares only these responses:

```text
200, 400, 401, 404
```

It does not declare a 409 uniqueness response, a conflict-specific error code, or compare-and-set semantics. The prose only says the subdomain must be globally unique. Therefore the research document's proposed flow of “candidate loser receives a uniqueness conflict, stops its candidate, and adopts the winner” is a hypothesis, not a verified contract.

A live spike must determine:

1. Whether two concurrent PATCH requests for the same subdomain are serialized atomically.
2. Which request wins.
3. Whether the losing request returns 409, 400, 502, or another status.
4. The exact error `code` and whether it is stable.
5. Whether the losing Box retains its prior subdomain and remains usable.

There is also a documentation inconsistency: the prose describes a 502 `gateway_error`, but the operation response list does not include 502.

Source:

- [Update box](https://docs.ascii.dev/box/api/reference/boxes/update-box)
- [Public OpenAPI YAML](https://docs.ascii.dev/openapi/box-v1.yaml)

### 1.5 Stop and archive

**VERIFIED.** `POST /boxes/{boxId}/stop` returns HTTP 202 and begins the `archiving` state. The normal stop path snapshots the Box filesystem before stopping it. The expected terminal state is `archived`.

Normal stop behavior:

- A stop always attempts to save the disk first.
- If the snapshot fails, the stop is refused and the Box remains running rather than discarding work.
- The Box is not billed during the state where a failed stop is being retried.
- `force: true` stops anyway and permanently loses everything written since the last successful snapshot.
- The CLI documents `box stop <id>` followed by polling until `archived`.

The provider should not use `force` as a normal cleanup path. It is explicitly documented as irreversible and intended only after a normal stop has already failed.

Sources:

- [Stop and archive box](https://docs.ascii.dev/box/api/reference/boxes/stop-and-archive-box)
- [Snapshots](https://docs.ascii.dev/box/snapshots)
- [CLI Reference](https://docs.ascii.dev/box/cli-reference)

### 1.6 Resume

**VERIFIED.** `POST /boxes/{boxId}/resume` returns HTTP 202 and restores the latest completed snapshot. The response state is initially `provisioning`; the provider should poll until `ready` or `idle` before issuing setup commands.

Resume options:

- `type`: move to `small`, `default`, or `large`. A resume already restores onto a fresh machine, so changing size costs no extra operation beyond the resume.
- `noEnv`: permanently convert the restored Box to no-env. Box scrubs inherited owner secrets before exposing the Box. Subsequent resumes remain no-env.

Resume is documented as usable in a few seconds regardless of Box size, with remaining file content streamed in the background. Commands sent before the Box reaches `ready` or `idle` can run before the intended environment is applied, so the provider must wait for readiness.

Sources:

- [Resume box](https://docs.ascii.dev/box/api/reference/boxes/resume-box)
- [FAQ](https://docs.ascii.dev/box/faq)
- [Machine Capabilities](https://docs.ascii.dev/box/machines)

### 1.7 Fork

**VERIFIED and relevant.** Although not explicitly listed in the requested lifecycle checklist, fork is important for template-based provisioning and appears in the public API.

`POST /boxes/{boxId}/fork` creates a new independent Box from the latest snapshot and returns HTTP 202. It supports:

- `env`
- `noEnv`
- `type`

A fork of a no-env Box is always no-env. A fork inherits the source's type unless a new type is supplied. The source Box is not modified.

Sources:

- [Fork box](https://docs.ascii.dev/box/api/reference/boxes/fork-box)
- [Template Boxes](https://docs.ascii.dev/box/templates)
- [Build a Platform on Box](https://docs.ascii.dev/box/platform-guide)

### 1.8 Delete and hard-delete behavior

**UNVERIFIED and likely unavailable in current public v1.** The complete current OpenAPI path inventory has no `DELETE /boxes/{boxId}` operation.

The current docs are inconsistent:

- [Box Public API v1](https://docs.ascii.dev/box/api/v1) says to stop/archive, resume, fork, or delete a Box according to retention policy.
- `https://docs.ascii.dev/llms.txt` lists a “Delete box” page.
- `https://docs.ascii.dev/box/api/reference/boxes/delete-box` returns 404.
- The `.md` variant also returns 404.
- [FAQ](https://docs.ascii.dev/box/faq) says stopped Boxes are free and snapshots are kept for the life of the Box, so there is normally nothing to delete.

Implementation consequence: treat stop/archive as the only currently documented retention operation. Do not design the provider around hard deletion until a live API test or an updated public API reference proves it exists.

Sources:

- [Box Public API v1](https://docs.ascii.dev/box/api/v1)
- [FAQ](https://docs.ascii.dev/box/faq)
- [Public OpenAPI YAML](https://docs.ascii.dev/openapi/box-v1.yaml)

## 2. Command execution and file APIs

### 2.1 Write and read files

**VERIFIED.** The current file endpoints are:

```text
PUT /boxes/{boxId}/files
GET /boxes/{boxId}/files?path=...
```

The write request supports:

- `path`: relative path inside the Box work directory.
- `content`: string content.
- `encoding`: `utf8` or `base64`, default `utf8`.

The read request supports:

- `path`: query parameter.
- `encoding`: `utf8` or `base64`, default `utf8`.

The public file schema does not expose a file mode or permission field. It also does not document a numeric file-size limit.

Sources:

- [Write Box file](https://docs.ascii.dev/box/api/reference/agent/write-box-file)
- [Read Box file](https://docs.ascii.dev/box/api/reference/agent/read-box-file)
- [SSH Access](https://docs.ascii.dev/box/ssh-access)

### 2.2 Writing a file with mode 0600

**VERIFIED as an implementation pattern, not as an API capability.** The file endpoint cannot request mode `0600`. The provider must:

1. Write the file through `PUT /files` or SSH/SCP.
2. Run `chmod 600 <relative-path>` through the command endpoint or SSH.
3. Avoid putting the secret value in command arguments.
4. Remove the file after the launcher has consumed it if it is only a bootstrap secret.

The docs do not promise the default mode created by the file API, so the provider must set the mode explicitly before launching the agent.

### 2.3 Command execution

**VERIFIED.** `POST /boxes/{boxId}/commands` accepts:

| Field | Behavior |
|---|---|
| `command` | Required command string. |
| `cwd` | Optional relative working directory inside the Box work directory. |
| `timeoutSeconds` | Optional integer from 1 through 60. Default 30. |

The response is synchronous and has type `command.finished`. It includes:

- `success`
- `exitCode`
- `signal`
- `stdout`
- `stderr`
- `timedOut`
- `stdoutTruncated`
- `stderrTruncated`
- `cwd`
- `startedAt`
- `finishedAt`

**UNVERIFIED: numeric output cap.** The response schema exposes truncation booleans but does not publish the stdout or stderr byte limit. The provider must treat output as bounded and use explicit redaction before returning command errors to Desktop.

The 60-second maximum is a real documented constraint. It should be treated as a hard limit for the provider's direct setup path.

Source:

- [Execute Box command](https://docs.ascii.dev/box/api/reference/agent/execute-box-command)
- [Public OpenAPI YAML](https://docs.ascii.dev/openapi/box-v1.yaml)

### 2.4 Async and long-running command support

**UNVERIFIED as a generic command feature, with a documented workaround.** The command endpoint is a synchronous command-result API with a maximum timeout of 60 seconds. The public docs do not define an asynchronous arbitrary-command endpoint that returns a command job ID and can later stream or retrieve the result.

There is a first-class asynchronous prompt API for Box-managed Codex and Claude work, with prompt status and event endpoints. That is not equivalent to arbitrary shell-command execution for a custom Buzz harness.

For custom harnesses, the documented platform pattern is:

1. Install a small daemon in the Box.
2. Run it as an enabled systemd service.
3. Expose it through `host <port> --private` if external streaming or concurrency is needed.
4. Drive it over HTTPS.

Enabled systemd services restart after resume or fork. The provider can use the command endpoint for short setup and service installation, then rely on systemd for the long-running agent.

Sources:

- [Build a Platform on Box](https://docs.ascii.dev/box/platform-guide)
- [Long-Running Tasks](https://docs.ascii.dev/box/long-running-tasks)
- [Box Public API v1](https://docs.ascii.dev/box/api/v1)
- [Use in Code](https://docs.ascii.dev/box/use-in-code)

## 3. In-box machine identity

### 3.1 Credentials and neutral identity

**VERIFIED at the documented model level.** The secrets documentation distinguishes account credentials from neutral Box-internal identity.

A normal Box receives:

- `BOX_ID`.
- A machine-scoped `ASCII_TOKEN`.
- Other neutral internal variables.
- An in-box Box CLI token at `~/.config/ascii/box/config.json`.
- Account environment variables, dashboard secret files, and configured provider credentials when the Box is not no-env.

A no-env Box receives:

- None of the account's environment variables.
- None of the account's secret files.
- None of the account's credentials.
- Neutral Box-internal variables and whatever explicit per-Box `env` values were supplied.

The hosting documentation says the in-box `host` CLI authenticates to the ASCII backend with the Box's machine token. This supports the existence of a machine-scoped identity usable from inside the Box without copying an account-wide API key into the agent environment.

Sources:

- [Secrets & Setup](https://docs.ascii.dev/box/secrets)
- [Host with box](https://docs.ascii.dev/box/hosting)
- [Machine Capabilities](https://docs.ascii.dev/box/machines)

### 3.2 Token scope

**VERIFIED as a no-env security contract.** The no-env documentation explicitly states that a no-env Box is confined to itself and cannot act on the account or any other Box.

This is the required scope for a Buzz provider. The agent Box must not receive a team-wide `BOX_API_KEY` merely to enable cleanup.

The secrets docs also state that converting a normal Box to no-env scrubs the in-box Box CLI token configuration file and other owner credentials. This means the provider should not assume that an account-style CLI token file exists in a no-env Box. It should rely on the documented neutral machine identity if self-control is supported.

### 3.3 Does `box stop self` work?

**UNVERIFIED as an exact operation.** The CLI reference states that wherever a command accepts a Box ID, the aliases `current` and `self` are also accepted. The `box stop` command accepts a Box ID. This strongly implies:

```bash
box stop self
```

However, no current public page explicitly demonstrates this command from a newly created no-env Box, nor does the API reference define the machine-token authorization matrix for lifecycle operations.

The live spike must verify:

1. `box stop self` succeeds from a `noEnv: true` Box.
2. It does not require `BOX_API_KEY` or an account credential.
3. `box list` is denied or appropriately scoped.
4. `box stop <other-box-id>` is denied.
5. A machine token cannot create, resume, fork, or mutate another Box.
6. Self-stop works when invoked by the launcher after `buzz-acp` exits.

Sources:

- [CLI Reference](https://docs.ascii.dev/box/cli-reference)
- [Secrets & Setup](https://docs.ascii.dev/box/secrets)
- [Host with box](https://docs.ascii.dev/box/hosting)
- [Build a Platform on Box](https://docs.ascii.dev/box/platform-guide)

## 4. Snapshot and resume semantics

### 4.1 What persists

**VERIFIED.** A Box snapshot is a point-in-time copy of the Box filesystem. The snapshot documentation explicitly lists the following as captured:

- `/home/user` code, files, and configuration.
- Docker named volumes under `/var/lib/docker/volumes`.
- Changes under `/etc`, `/usr`, `/opt`, `/root`, and `/srv`.
- Cron tables.
- The apt package database and installed packages.
- System configuration.
- Enabled systemd service units.

Snapshots are incremental and the latest snapshot is retained for the life of the Box. Snapshots are taken periodically while the Box is ready or idle and a final snapshot is taken during stop. If the final snapshot fails, the stop is aborted rather than silently losing data.

Sources:

- [Snapshots](https://docs.ascii.dev/box/snapshots)
- [Long-Running Tasks](https://docs.ascii.dev/box/long-running-tasks)
- [FAQ](https://docs.ascii.dev/box/faq)

### 4.2 What does not persist

**VERIFIED.** The snapshot docs explicitly exclude:

- The base OS and pre-installed tooling.
- Machine identity.
- Hostname and network configuration.
- SSH host keys.
- Running processes.
- Process memory.
- Open ports.

Resume behaves like a server reboot. Enabled systemd units start automatically. Hand-run processes do not survive, including manually started dev servers, background jobs, tunnels, browser sessions, and containers that were only running at snapshot time.

Resume is documented as usable in a few seconds regardless of data size. Files can continue streaming in the background after the Box becomes accessible.

### 4.3 Docker containers and images across resume

**UNVERIFIED in part.** The docs explicitly guarantee persistence for Docker named volumes. They do not explicitly guarantee persistence for:

- Docker image layers under `/var/lib/docker`.
- Container writable layers.
- Anonymous volumes.
- Docker metadata and container configuration.
- Running container processes.

Running processes are explicitly not captured, so running containers will not remain running across archive and resume. The research document's original question about `/var/lib/docker` should be narrowed:

- Named volumes are verified to persist.
- Image/layer retention is not guaranteed by the public docs.
- Container runtime state must be recreated or restarted.

A production provider should use one of these approaches:

1. Verify that the image is available after resume and pull by digest if necessary.
2. Install an idempotent systemd unit that starts the container after resume.
3. Keep critical workspace state in ordinary files or named volumes, not in a container writable layer.
4. Run a live snapshot/resume test against the exact Buzz image and Docker workload.

Source:

- [Snapshots](https://docs.ascii.dev/box/snapshots)
- [Long-Running Tasks](https://docs.ascii.dev/box/long-running-tasks)
- [Template Boxes](https://docs.ascii.dev/box/templates)

## 5. Docker support

### 5.1 Availability and version

**Docker availability: VERIFIED.** The machine capabilities page lists `docker` as a pre-installed container runtime on supported images.

**Exact version: UNVERIFIED.** The public machine documentation does not state:

- Docker Engine version.
- Containerd version.
- Whether the version is pinned across machine-image updates.
- Whether rootless Docker is available.
- Whether Docker-in-Docker is supported.

The initial provider should record `docker version` during the live validation spike and decide whether the launcher should reject unexpected versions.

Source:

- [Machine Capabilities](https://docs.ascii.dev/box/machines)

### 5.2 Pulling by digest

**UNVERIFIED as a Box-specific guarantee.** Docker itself supports references of the form:

```text
registry.example/buzz@sha256:<digest>
```

The ASCII Box docs do not document a Box-specific digest allowlist, digest verification, or approved-image registry. The provider must perform its own immutable-image policy:

1. Accept only an approved registry and repository.
2. Require a digest reference or resolve and record the digest.
3. Verify the pulled image's `RepoDigests` before launch.
4. Redact registry credentials from command output and errors.

### 5.3 Registry authentication

**No first-class Box registry-auth story is documented.** The secrets documentation says credentials not written by the platform, including Docker logins added inside a Box, are left alone during no-env conversion. This supports ordinary in-Box Docker authentication such as `docker login` or a credential helper, but it is not a Box-managed registry credential API.

For Buzz, registry credentials should be supplied only at runtime and should not be baked into the image or copied into account-wide dashboard secrets. The provider should avoid leaving registry credentials in a persistent snapshot unless the security model explicitly permits it.

Source:

- [Secrets & Setup](https://docs.ascii.dev/box/secrets)
- [API Keys](https://docs.ascii.dev/box/api-keys)

## 6. Networking

### 6.1 Dedicated IPv4 and HTTPS hosting

**VERIFIED.** Every Box has a dedicated IPv4 address. Box billing includes egress up to 2 TB per Box per month.

The `host` tool can expose a service on a stable HTTPS URL. Private hosted URLs include a `_token` query parameter by default. Hosted routes can be re-created after resume and retain the same URL and token for the same Box and port.

The hosting docs state:

- The service must bind to `0.0.0.0`.
- The ASCII backend terminates TLS and proxies to the Box.
- `host` uses the Box machine token to register the route.
- A Box can host up to 50 ports.
- `--private` protects the URL with a token.
- `--public` removes the access token requirement.

Sources:

- [Billing & Limits](https://docs.ascii.dev/box/billing)
- [FAQ](https://docs.ascii.dev/box/faq)
- [Host with box](https://docs.ascii.dev/box/hosting)

### 6.2 Outbound WSS and HTTPS

**UNVERIFIED as an explicit platform guarantee.** The docs demonstrate ordinary internet access through tools such as `curl`, package managers, GitHub CLI, and hosted HTTPS. They do not publish:

- An outbound allowlist.
- An outbound denylist.
- A proxy requirement.
- A specific statement guaranteeing arbitrary WSS egress.
- Firewall policy details.
- Whether outbound connections are restricted by port or destination.

The Buzz provider must live-test:

- WSS connectivity to the Buzz relay.
- HTTPS connectivity to the model provider.
- GitHub and MCP endpoint access as required.
- Long-lived idle WSS behavior.
- Reconnection after resume.

The public docs do not identify any special egress restriction beyond the 2 TB monthly inclusion.

## 7. Rate limits, billing, machine sizes, regions, and compliance

### 7.1 Billing granularity

**VERIFIED.** Box bills machine time by the second and only while a Box is running. Stopped Boxes are free. The billing docs state that `$1` buys 100,000 seconds, or roughly 27 hours of `default` machine time.

Effective rates:

| Type | Effective rate | Approximate 24/7 monthly cost |
|---|---:|---:|
| `small` | $0.018/hour | $13/month |
| `default` | $0.036/hour | $26/month |
| `large` | $0.072/hour | $52/month |

Snapshot storage, dedicated IPv4, and egress up to 2 TB per Box per month are included according to the billing and FAQ pages.

Sources:

- [Billing & Limits](https://docs.ascii.dev/box/billing)
- [FAQ](https://docs.ascii.dev/box/faq)

### 7.2 Machine sizes and storage

**VERIFIED.** The documented cloud machine sizes are:

| Type | CPU | Memory | Storage | Data floor | Machine-time multiplier | Architecture |
|---|---:|---:|---:|---:|---:|---|
| `small` | 2 shared vCPUs | 4 GB | 40 GB SSD | at least 12 GB | 0.5x | x86_64 |
| `default` | 4 shared vCPUs | 8 GB | 80 GB SSD | at least 50 GB | 1x | x86_64 |
| `large` | 8 shared vCPUs | 16 GB | 100 GB SSD | at least 70 GB | 2x | x86_64 |

The `large` storage floor is 100 GB and the docs say some available machines are roomier, often 160 GB. The documented CPUs are shared vCPUs, so pricing is not a direct performance-equivalence claim against dedicated CPU products.

The response schema mentions `bare-metal` as a possible Box type, but it is not a create choice in the current public create schema and is not covered by the current machine capabilities page. Do not target it in the initial provider without a separate contract.

Sources:

- [Machine Capabilities](https://docs.ascii.dev/box/machines)
- [Billing & Limits](https://docs.ascii.dev/box/billing)
- [FAQ](https://docs.ascii.dev/box/faq)

### 7.3 Account and machine-start limits

**VERIFIED.** Creating a Box, forking a Box, and resuming a stopped Box each count as one machine start.

Plan limits documented by ASCII:

| Plan | Monthly price | Included machine seconds | Concurrent Boxes | Starts/minute |
|---|---:|---:|---:|---:|
| `box_20` | $20/month | 2,000,000 | 100 | 10 |
| `box_100` | $100/month | 10,000,000 | 200 | 20 |
| `box_500` | $500/month | 50,000,000 | 800 | 35 |
| `box_2000` | $2,000/month | 200,000,000 | 1,200 | 60 |

Trial accounts are limited to:

- 4 concurrent Boxes.
- 5 starts per minute.
- 20 Box creations per day until the first payment.

Platform-wide ceilings that no plan lifts:

- 600 starts per hour.
- 1,500 starts per day.

The API returns HTTP 429 after a start limit and documents codes including `rate_limited` and `start_limit_reached`. `GET /limits` exposes the current account state, active count, maximum active Boxes, creation rate, and balance fields.

Sources:

- [Billing & Limits](https://docs.ascii.dev/box/billing)
- [Get Box limits](https://docs.ascii.dev/box/api/reference/account/get-box-limits)
- [Box Public API v1](https://docs.ascii.dev/box/api/v1)

### 7.4 Regions and data residency

**VERIFIED.** The FAQ states that Boxes run in the EU, specifically:

- Germany.
- Finland.
- France.

The FAQ says data and snapshots stay in those regions. It describes round trips from the US or Latin America as approximately 100..200 ms and recommends keeping Box for agent and development-preview work while publishing production builds to a CDN or regional host.

Source:

- [FAQ](https://docs.ascii.dev/box/faq)
- [Build a Platform on Box](https://docs.ascii.dev/box/platform-guide)

### 7.5 Compliance

**VERIFIED.** The FAQ states that ASCII does not yet have compliance certifications and that SOC 2 is in progress.

Boxes are full VMs with sudo. The docs say customers can add controls such as:

- Firewall rules.
- Proxies.
- Encryption.

This does not substitute for a provider certification. Regulated Buzz deployments must treat the current compliance position as a product and procurement constraint.

Source:

- [FAQ](https://docs.ascii.dev/box/faq)

## 8. Explicit refinements to `buzz-backend-box-research.md`

### Refinement 1: hard delete

The research document currently lists hard deletion as an open question. The public API evidence is stronger:

> The current public OpenAPI has no `DELETE /boxes/{boxId}` operation. Stop/archive is the documented lifecycle operation. The Delete box references in `llms.txt` and the API overview appear stale or unavailable.

Provider implication: model cleanup as stop/archive and preserve the Box ID. Do not require hard deletion for correctness.

### Refinement 2: deterministic subdomain claims

The research document's deterministic subdomain approach is reasonable, but the conflict behavior is not a documented contract. Public docs verify only that a subdomain must be globally unique.

Provider implication: treat the subdomain PATCH as an optimistic claim and require a live spike before implementing “loser receives stable conflict code” logic. Until then, a provider-side lock or external ownership record is safer than relying on an undocumented error code.

### Refinement 3: self-stop

The machine-token and `self` alias model is documented, but the exact `box stop self` operation from a no-env Box is not demonstrated.

Provider implication: keep self-stop in the required validation spike. Do not place an account-wide `BOX_API_KEY` in the Box. If self-stop is unavailable, the provider will need an external cleanup path or a future provider protocol operation.

### Refinement 4: snapshot coverage for Docker

The research document asks what happens to `/var/lib/docker`. Public docs now refine this:

- Docker named volumes under `/var/lib/docker/volumes` are captured.
- Running processes are not captured.
- Image layers and container writable layers are not explicitly guaranteed.

Provider implication: use a systemd launcher that can restore or pull the image and recreate the container. Verify the exact behavior with the approved image.

### Refinement 5: secret-file mode

The research document proposes writing a temporary file and setting mode `0600`. That remains a sound security pattern, but it is not supported directly by the file API.

Provider implication: write the file, run `chmod 600`, launch the process without putting values in command arguments, and remove the file after consumption.

### Refinement 6: command execution

The command endpoint has a documented maximum timeout of 60 seconds and exposes truncation flags without a numeric cap.

Provider implication: use direct commands only for bounded setup and launch actions. Use systemd or a daemon for long-running or streaming work. Treat returned output as potentially truncated and redact secrets before surfacing errors.

### Refinement 7: networking

Dedicated IPv4 and 2 TB monthly egress are verified. Explicit outbound WSS/HTTPS policy is not.

Provider implication: WSS relay connectivity and model HTTPS access remain live-spike requirements.

### Refinement 8: no-env and explicit environment

`noEnv` does not prohibit all environment values. It prevents account-wide secrets and credentials while permitting explicit per-Box `env` values at create/fork time, subject to 100-variable and 64 KB limits.

Provider implication: temporary-file injection remains preferable for high-sensitivity values, but `env` is a documented alternative for bounded non-account configuration.

### Refinement 9: TTL semantics

`ttlSeconds: null` is the current form for no auto-stop. Numeric TTL is capped at 30 days. The timer starts at creation or resume and does not reset based on activity.

Provider implication: the provider must own any inactivity countdown if it wants to stop a Box after agent completion. Resumes consume machine-start quota.

### Refinement 10: implementation planning data

The implementation plan should include:

- Shared-vCPU pricing assumptions.
- Storage floors and snapshot data caps.
- Trial and plan start-rate limits.
- The 600/hour and 1,500/day account ceilings.
- EU-only regions: Germany, Finland, and France.
- SOC 2 still in progress.
- `bare-metal` appearing in the response schema but not as a documented create option.

## 9. Unreachable or stale documentation observed

The following URLs were attempted while checking alternate references:

- `https://docs.ascii.dev/box/api/reference/boxes/delete-box` returned 404.
- `https://docs.ascii.dev/box/api/reference/boxes/delete-box.md` returned 404.
- `https://docs.ascii.dev/box/api/reference/files` returned 404.
- `https://docs.ascii.dev/box/api/reference/agent/write-file` returned 404. The current reachable page is [`write-box-file`](https://docs.ascii.dev/box/api/reference/agent/write-box-file).
- `https://docs.ascii.dev/box/docker` returned 404.
- `https://docs.ascii.dev/box/networking` returned 404.
- `https://docs.ascii.dev/box/regions` returned 404.
- `https://docs.ascii.dev/box/egress` returned 404.

Networking facts were recovered from the reachable [Billing & Limits](https://docs.ascii.dev/box/billing), [FAQ](https://docs.ascii.dev/box/faq), and [Host with box](https://docs.ascii.dev/box/hosting) pages. The deletion references appear stale because both the documentation index and API overview mention deletion while the page and OpenAPI operation are absent.

## 10. Required live validation spike

The safe operator harness is `crates/buzz-backend-box/src/bin/box-live-spike.rs`.
It compiles with the provider and exposes the checklist below as structured
JSON groups: `limits`, `no-env-self-stop`, `subdomain-race`,
`file-mode-output-caps`, `docker-snapshot-resume`, `network`, and `all`.
`--help` and `--dry-run all` perform zero network I/O. Every group that can
create, stop, or resume a Box requires both `BOX_API_KEY` and
`--confirm-live`; `limits` requires the ambient key and is read-only. The
binary uses stop/archive cleanup, never force-stop or hard-delete, and emits
`manual_check_required` records for claims that need operator judgment.

No live Box account was used for this implementation. The checklist below
therefore remains **UNVERIFIED** and must not be read as a result report.

Before production enablement, validate these behaviors against a real Box account:

1. Create a Box with `noEnv: true` and inspect neutral variables, files, and the presence or absence of the CLI token file.
2. Run `box stop self` from that Box without `BOX_API_KEY` and confirm it succeeds.
3. Confirm `box list`, `box stop <other-id>`, and other account-wide operations are denied from the no-env Box.
4. Create two candidate Boxes and concurrently PATCH the same deterministic subdomain. Record winner, loser status, error code, and whether the loser remains usable.
5. Write a secret file, run `chmod 600`, and verify the resulting mode through an in-Box command.
6. Generate stdout/stderr beyond expected sizes and record the actual truncation threshold and flags.
7. Test command timeouts at 60 seconds and above 60 seconds.
8. Install the Buzz launcher as a systemd unit, stop/archive, resume, and confirm the service restarts.
9. Confirm that an intentional Buzz shutdown does not accidentally trigger service restart or Box resurrection.
10. Test Docker image availability after resume and fork.
11. Test an immutable digest pull and verify the actual image digest before launch.
12. Test private-registry login without leaving credentials in the persistent snapshot.
13. Test named-volume persistence and image/container-layer behavior across stop/resume.
14. Confirm outbound WSS to the Buzz relay and HTTPS to the model provider.
15. Inspect the assigned dedicated IPv4 address.
16. Confirm expected machine-start behavior against `GET /limits` and the account ceilings.
17. Confirm the region and data-residency behavior for the account used by Buzz.
18. Recheck the public API for hard delete before adding any deletion operation to the provider.

## 11. Source index

### Primary ASCII Box sources

- [Box Public API v1](https://docs.ascii.dev/box/api/v1)
- [Public OpenAPI YAML](https://docs.ascii.dev/openapi/box-v1.yaml)
- [Create box](https://docs.ascii.dev/box/api/reference/boxes/create-box)
- [List boxes](https://docs.ascii.dev/box/api/reference/boxes/list-boxes)
- [Get box](https://docs.ascii.dev/box/api/reference/boxes/get-box)
- [Update box](https://docs.ascii.dev/box/api/reference/boxes/update-box)
- [Stop and archive box](https://docs.ascii.dev/box/api/reference/boxes/stop-and-archive-box)
- [Resume box](https://docs.ascii.dev/box/api/reference/boxes/resume-box)
- [Fork box](https://docs.ascii.dev/box/api/reference/boxes/fork-box)
- [Execute Box command](https://docs.ascii.dev/box/api/reference/agent/execute-box-command)
- [Write Box file](https://docs.ascii.dev/box/api/reference/agent/write-box-file)
- [Read Box file](https://docs.ascii.dev/box/api/reference/agent/read-box-file)
- [Get Box limits](https://docs.ascii.dev/box/api/reference/account/get-box-limits)
- [Long-Running Tasks](https://docs.ascii.dev/box/long-running-tasks)
- [Build a Platform on Box](https://docs.ascii.dev/box/platform-guide)
- [Secrets & Setup](https://docs.ascii.dev/box/secrets)
- [Snapshots](https://docs.ascii.dev/box/snapshots)
- [Machine Capabilities](https://docs.ascii.dev/box/machines)
- [Billing & Limits](https://docs.ascii.dev/box/billing)
- [CLI Reference](https://docs.ascii.dev/box/cli-reference)
- [Host with box](https://docs.ascii.dev/box/hosting)
- [SSH Access](https://docs.ascii.dev/box/ssh-access)
- [Template Boxes](https://docs.ascii.dev/box/templates)
- [FAQ](https://docs.ascii.dev/box/faq)
- [API Keys](https://docs.ascii.dev/box/api-keys)
- [Use in Code](https://docs.ascii.dev/box/use-in-code)

### Buzz research context

- [`docs/buzz-backend-box-research.md`](./buzz-backend-box-research.md)
