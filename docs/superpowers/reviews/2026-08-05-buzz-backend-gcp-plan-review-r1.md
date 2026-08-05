# buzz-backend-gcp — Plan Review, Round 1

**Plan:** `docs/superpowers/plans/2026-08-05-buzz-backend-gcp.md`
**Spec:** `docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md`
**Panel:** feasibility (openai-codex/gpt-5.5) · scope (zai/glm-5.2) · product (zai/glm-5.2) · adversarial (minimax-code/MiniMax-M3) · security (openai-codex/gpt-5.5)
**Fallbacks:** none — all five lenses ran on their pinned non-Anthropic models.
**Verdict:** BLOCKED — 8 P1.

Findings below are the merged panel output. Four claims were independently
verified against the code or the live VM before merging; three were **rejected**
with evidence rather than merged (see the last section) — a reviewer being
confident is not a reason to change the plan.

---

## P1 — must fix before executing

### P1-1 Capacity warning is invisible on the success path
**Lenses:** product (BLOCKER) + feasibility (SHOULD-FIX) — corroborated. **Verified.**
**Where:** design §Capacity; plan Task 7, Task 10.

`invoke_provider` consults `stderr_redacted` only when the provider exits
non-zero (`desktop/src-tauri/src/managed_agents/backend.rs:252-260`) or emits no
JSON (`:271-280`). On success it returns `Ok(response)` at `:287` and the buffer
is dropped; `provider_deploy` then reads only `agent_id` (`:529-532`). The
design's stated rationale — "stderr is the reliable channel: the desktop
captures and redacts it" — is false for exactly the path the warning is emitted
on. The operator sees a clean success, then an OOM kill with nothing connecting
the two.

**Fix:** pick one and correct the design's rationale either way — (a) add a
`warning` field to the deploy response and render it desktop-side, or (b) make
overcommit a refusal. Do not ship the current arrangement.

### P1-2 `gcloud` is not on a GUI-launched app's PATH
**Lens:** product. **Verified.**
**Where:** plan Task 8 `Remote::gcloud`.

The provider is exec'd by a Tauri app inheriting launchd's
`/usr/bin:/bin:/usr/sbin:/sbin`. `Command::new("gcloud")` will not resolve on a
normal macOS install. The reference provider already solves this:
`crates/buzz-backend-kubernetes/src/client.rs:19` defines
`PATH_PREPEND = ["/opt/homebrew/bin", "/usr/local/bin"]` plus `~/.local/bin`,
with a comment naming this exact cause.

**Fix:** mirror `prepend_plugin_path()` in `remote.rs`; make the not-found error
name the remedy.

### P1-3 Task 10 and Task 11 snippets do not compile
**Lens:** feasibility.

`if let Action::Refuse(why) = action` moves `action`, which is then used again
(plan `:2111-2115`). `match cli.command` moves out of `cli`, then `&cli` is
borrowed in the `Remove` arm (`:2265-2269`).

**Fix:** match once over all variants; destructure `Cli` before matching.

### P1-4 The normative `relay-mesh` refusal is absent
**Lens:** feasibility.
**Where:** plan Tasks 4 and 10.

`docs/remote-agents.md:1453-1458` requires refusing a deploy whose provider is
`relay-mesh`. The shared `AgentPayload` deliberately does not type the raw
`provider` field, so this cannot be enforced after deserialization — which is
why the Kubernetes binding keeps a raw-JSON backstop
(`crates/buzz-backend-kubernetes/src/main.rs:104-113`). The plan has no
equivalent at all.

**Fix:** inspect raw JSON and refuse (trimmed comparison) before
`serde_json::from_value`; add wire fixtures for exact and padded spellings.

### P1-5 `FencedReplace` is a TOCTOU and the observation is too weak to fence on
**Lenses:** feasibility + adversarial + security — triple-corroborated.
**Where:** plan Task 10 `observe::look`, `parse_observation`, `classify`.

`unit_present` is derived solely from the env file, so a real unit with no env
file classifies as `Create` and gets provider files installed around it. The
re-read before destruction compares only `create_intent`, not the full marker
tuple, and does not re-confirm `harness_running == false`. L2 item 4 requires
full-identity evidence before action and destructive writes fenced to the exact
authorizing observation.

**Fix:** model systemd state separately from marker state; `Refuse` on
present-but-unmarked and on pubkey mismatch; re-read and compare the whole
authorizing tuple immediately before any stop/disable.

### P1-6 `memory_max` / `cpu_quota` are systemd unit-file injection
**Lens:** security.
**Where:** plan Task 4 `ProviderConfig::parse`; Task 6 drop-in render.

Both are accepted as arbitrary trimmed strings and interpolated raw into a
root-installed drop-in as `MemoryMax={}` / `CPUQuota={}`. A newline yields
arbitrary additional `[Service]` directives — a second `EnvironmentFile=`, or an
`ExecStart=` reset. The desktop's own config validation checks scalar-ness and
key naming, not embedded newlines.

**Fix:** strict grammars — size for `memory_max`, bounded numeric percent for
`cpu_quota`; reject `\r`, `\n`, NUL and anything unrecognized; test the
injection payload explicitly.

### P1-7 Non-nsec secrets are written to the boot disk and printed by `dry-run`
**Lens:** security.
**Where:** plan Task 6 secret split; Task 11 `dry_run`.

Only `BUZZ_PRIVATE_KEY` and `NOSTR_PRIVATE_KEY` are routed to Secret Manager.
`auth_tag` and any provider API keys arriving in `env_vars` / `launch.env` land
in `/etc/buzz/acp-<id>.env` on the persistent disk and are printed verbatim by
`dry-run`. The desktop treats every deploy env value as a secret candidate for
redaction (`backend.rs:395-412`), and L2 item 5 forbids secret material in
output. The plan's leak test greps only for the nsec, so it passes while tokens
leak.

**Fix:** classify by allowlist — non-secret keys stay on disk, everything else
goes to the Secret Manager payload; redact env values in `dry-run`; broaden the
leak test beyond the nsec.

### P1-8 The extraction breaks tests the plan never mentions
**Lens:** feasibility.
**Where:** plan Task 2.

`AuthoritativeInputs` gains a required `max_env_bytes`, but the moved tests
construct it with two fields (`crates/buzz-backend-kubernetes/src/env.rs:321-325`,
`:550-554`). `AUTHORITATIVE_KEYS` is currently **private** (`env.rs:23`) though
the plan advertises it as part of the shared interface.

**Fix:** update every moved constructor; make the constant `pub`; add
`cargo test -p buzz-backend-core` to the Task 2 verification, before the
Kubernetes regression run.

---

## P2 — should fix

1. **Secret Manager resources are unowned and unverified.** No labels; `store`
   treats any name-matching secret as ours, adds a version and grants the VM SA
   access; `destroy` deletes by name. `remove` deletes local markers *before*
   `destroy`, so a failure orphans an nsec-bearing secret with the retry
   evidence already gone. Mirror the k8s `secret_is_ours` gate
   (`pod.rs:34-56`, `observe.rs:64-67`). *(security)*
2. **Shared template units carry a per-agent marker.** `buzz-acp@.service` and
   `buzz-acp-secret@.service` are re-rendered on every deploy of every agent
   with one agent's pubkey and intent in the header, making the marker on shared
   files meaningless — and the Task 6 test `every_installed_file_carries_the_marker`
   enforces the wrong invariant. Give shared artifacts a provider-level marker
   distinct from per-agent markers. *(adversarial)*
3. **30 s startup poll** against a 600 s deploy budget; a `codex-acp` cold start
   can exceed it. *(adversarial)*
4. **`remove` verifies `managed-by` but not `agent-pubkey-full`**, and
   `rm -rf`s the drop-in directory including unmarked operator files.
   *(adversarial + security)*
5. **The shared harness drops the k8s `KUBECONFIG` override.** `wire_fixtures.rs:20-24`
   forces `KUBECONFIG=/nonexistent/...` so fixture tests fail at the intended
   boundary; the shared harness has no env hook, so on a machine with a real
   kubeconfig the tests can reach a live cluster — defeating the very regression
   gate the extraction relies on. *(feasibility)*
6. **`list` never checks `out.ok()`** — an auth failure prints nothing, exits 0,
   and Task 12's install smoke false-passes. *(feasibility)*
7. **Fetcher omits `--project`.** Verified: the VM has
   `core/project=zoop-innovation`, so it works today by ambient accident. Make it
   explicit and pass `cfg.project`. *(feasibility, downgraded from BLOCKER)*
8. **`buzz-acp-fetch-key` is unhardened** — no arity/shape check on `$1`,
   non-atomic write, and the unit lacks the agent unit's sandboxing. *(security)*
9. **Same-UID sibling exposure.** All instances run as `buzzacp`, so a
   compromised agent can read siblings' keys from `/proc/<pid>/environ`. The
   spec's claim that per-secret IAM provides isolation is overstated: correct the
   claim or implement per-agent users. *(security)*
10. **`StrictHostKeyChecking=no`** while installing root-owned files — state the
    trust model or drop it. (`sudo -n` half is inert: verified passwordless sudo
    on this host, but `-n` remains correct defensive practice.) *(security)*

---

## P3 — consider

- `dry-run` is exercised by no acceptance criterion — the clean cut; `list`
  largely duplicates a `gcloud` one-liner. *(scope)*
- The capacity feature is additive, not required by L2 conformance; keep it
  deliberately or retire it together with two `Observation` fields and the
  observer script's RESERVED/AVAILABLE sections. *(scope)*
- `max_env_bytes` widens a shared API that only one binding exercises. *(scope)*
- Concurrent-`Create` and `secrets create` races. *(adversarial)*
- `Requires=buzz-block-metadata-agent.service` — verified enabled on the host.
  *(adversarial)*
- `%i` vs `%I` escaping — inert here, instance names are 12 lowercase hex.
  *(adversarial)*

---

## Rejected findings (evidence, not deference)

1. **"`gcloud compute ssh --command` discards local stdin, so every install
   silently writes a zero-byte file"** — adversarial's headline BLOCKER.
   **Disproved empirically:** piped 30 bytes to `buzz-agent`; the remote `wc -c`
   returned 30 and the md5 matched exactly. `gcloud compute ssh` execs real
   `ssh`, which forwards stdin to the remote command. Acting on this would have
   triggered a needless rewrite of the transport onto `scp`.
2. **"`RuntimeDirectory` at 0750 root:root blocks `buzzacp` from reading its own
   secret file"** — adversarial BLOCKER #2 (restated as #11). **Disproved:**
   systemd's *manager* reads `EnvironmentFile=` as root. Live proof on the same
   host — the running `buzz-acp.service` has `User=buzzacp` and
   `EnvironmentFile=/etc/buzz/acp.env` at mode **0600 root:root**.
3. **`parse_size` float rounding** — sub-byte arithmetic noise with no
   consequence at these magnitudes.

## Scope verdict

The `buzz-backend-core` extraction was explicitly **cleared**: every extracted
module has two real consumers created within this same plan, and
`crates/buzz-backend-kubernetes/src/env.rs` is ~617 lines of conformance-critical
logic whose duplication would be a standing drift defect. One caveat carried
into Task 2 — the k8s `AgentIdentity` has inherent k8s-specific methods
(`pod_name`, `selector`, `labels`) that cannot follow the type across the orphan
rule, so the extraction is real surgery, not a re-export.
