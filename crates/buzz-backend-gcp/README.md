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
