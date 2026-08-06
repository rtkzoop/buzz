# buzz-backend-gcp — Plan Review, Round 3

**Plan:** `docs/superpowers/plans/2026-08-05-buzz-backend-gcp.md` (15 tasks, 8,535 lines, commit `9f73d5efe`)
**Panel:** feasibility (openai-codex/gpt-5.5) · scope (zai/glm-5.2) · product (zai/glm-5.2) · adversarial (minimax-code/MiniMax-M3) · security (openai-codex/gpt-5.5)
**Degraded lanes:** none.
**Verdict:** BLOCKED — 4 P1, 4 P2.

## Trajectory

| Round | P1 | Where the defects lived |
|---|---|---|
| 1 | 8 | The original design |
| 2 | 9 | The hardening round 1 prompted |
| 3 | **4** | The hardening round 2 prompted |

Converging, and the character has changed: round 3's findings are mechanical
(shell semantics, call ordering, a version comparison) rather than structural.
**Scope reported clean for the first time** — "the round-3 machinery is
proportionate because each piece is the GCE-equivalent of a guarantee the
approved Kubernetes binding gets for free from its apiserver, not defensive
depth invented in a vacuum."

Round 2's product findings were independently **verified closed**: the capacity
writer→reader loop is now tested end to end with an over-capacity live step, and
the missing-env-file ghost is listed and actionable.

---

## P1 — must fix before executing

### P1-1 The upgrade lockout was not deleted — it moved
**Lenses:** adversarial (BLOCKER) + product (SHOULD-FIX) — corroborated, and the
two lenses found different halves of it.
**Where:** Task 6 `is_ours` / `is_shared_marker`; Task 10 `verify_owned`;
Task 12 `classify`; Task 13 `verify_removable` / `removal_script`.

Round 2's P1-6 deleted the content-hash tamper check *because* it made provider
upgrades an unrecoverable lockout, and the plan now asserts in three places that
the lockout is gone. It is not. `is_ours` is the conjunction
`managed-by == MANAGED_BY ∧ binding-version == BINDING_VERSION`, so the moment
`BINDING_VERSION` bumps to `"2"`, every artifact written at version 1 reads as
*present and not ours*. `classify` then refuses on the first such file, so
`deploy` never runs — and product found the worse half: `verify_removable`
refuses identically, so `remove` cannot tear the agent down either. The agent
becomes unmanageable in both directions, and the refusal text tells the operator
their own prior-version agent is foreign.

`BINDING_VERSION` is documented as "bump when the unit/env shape changes" — a
designed-for event. Two of the plan's own tests enshrine the broken behaviour
(`a_foreign_binding_version_is_not_our_marker`,
`a_future_binding_version_reads_as_present_and_unowned`).

**Fix:** make ownership version-aware, not version-blind. `is_ours` returns
`Ours | OursButOlder(v) | NotOurs`; `OursButOlder` is an authorised upgrade
target that classifies as `FencedReplace` (files) and `--update-labels` then a
new version (secret). Reserve hard refusal for *future* or genuinely foreign
versions. Replace both tests with upgrade-path assertions.

### P1-2 `remove` stops a unit it has not proven it owns
**Lens:** security (BLOCKER). **Where:** Task 13.

When the env file is absent, `remove` skips local marker verification and
`removal_script` runs `systemctl disable --now buzz-acp@<id>.service`
unconditionally, *before* any per-file marker check. The per-file delete fence is
real, but stopping a unit is itself a destructive action authorised only by
`--pubkey` sharing its first 12 hex with the unit id. L2 requires full-identity
evidence before any action.

**Fix:** scan all four per-agent artifacts in one shell first; require at least
one present marker with a matching `agent-pubkey-full` before `secrets::destroy`
or any `systemctl stop/disable`. Refuse otherwise, with recovery instructions.
Tests: env-absent + marked sibling proceeds; env-absent + no matching marker
refuses *without stopping*.

### P1-3 The marker guard counts lines, not distinct patterns
**Lens:** feasibility (BLOCKER). **Where:** Task 9 `marker_guard`, Task 13 `removal_script`.

Both authorise by `grep -c -F -x{needles}` and comparing the count to
`required.len()`. `grep -c` counts matching *input lines*, not distinct matched
patterns. A header whose first lines duplicate `# managed-by:` and
`# binding-version:` reaches the expected count while omitting
`# agent-pubkey-full:` entirely — so the guard authorises overwriting or deleting
a file that does not carry the full tuple. This is the replacement for the
deleted tamper check, reopening "a marker-looking file authorises the wrong file".

**Fix:** capture the header once, then assert each required line independently
(`printf '%s\n' "$h" | grep -Fqx -- <needle>` per needle). Test duplicated marker
lines that omit `agent-pubkey-full` / `scope`, for both install and remove.

### P1-4 The lease is acquired after the decision it is supposed to protect
**Lens:** feasibility (BLOCKER). **Where:** Task 12, Task 13.

`deploy` runs `observe::look` and `classify` **before** `acquire_lease`, then
acts on that pre-lease `action` — secret writes, per-agent writes, and
`enable --now` — without re-observing under the lease. A deploy can observe
"absent/stopped", lose the race, and then mutate based on stale state. Separately
`operator::remove` mutates the same secret and files while taking **no lease at
all**, so it can interleave with a deploy regardless.

**Fix:** acquire the lease first, then `observe` + `classify` again under it and
act on that second observation. Hold the same lease across `remove`'s
`secrets::destroy` and removal script.

---

## P2 — should fix

1. **Lease TTL is shorter than the deploy budget** *(feasibility)*. `DEPLOY_LEASE_SECONDS = 300`
   with no renewal, against the desktop's 600 s provider timeout
   (`backend.rs:528`) and unbounded direct CLI runs. A slow-but-live holder ages
   out and a second deploy starts mutating the same agent. Renew before each
   mutating round trip, or raise the TTL above every enforced lifetime.
2. **Secret Manager's 64 KiB payload cap is not enforced** *(feasibility)*. GCP passes
   `max_env_bytes: None` on the correct reasoning that a systemd `EnvironmentFile`
   has no disk cap — but the secret half goes to Secret Manager, which caps a
   version payload at 64 KiB. A large secret-classified value fails only during
   `secrets::store`, after shared installs have already happened. The plan even
   adds a core test asserting a 2 MiB environment is accepted, which is not
   deployable as written. Add a GCP preflight cap on `plan.secret_body()`.
3. **The lease record is a trust boundary without controls** *(security)*.
   Predictable `.lock`/`.owner` paths directly under `/run/lock`, no check that
   the owner file is a root-owned regular file, and a future timestamp reads as
   fresh. Use a private `0700 root:root /run/buzz-backend-gcp`; treat
   future-dated or non-regular records as corrupt.
4. **Secret-digest test coverage is thin** *(adversarial)*. The rotation test covers
   value change and key addition, but not a key whose classification flips
   between allowlist and secret-classified with values otherwise stable.

## Verified closed from round 2

Capacity writer→reader loop (now tested end to end, plus an over-capacity live
step and a README note that the desktop will not show it) · missing-env-file
ghost (`list` unions three enumerations; `remove` proceeds without the env file) ·
`Environment=` injection via `project` · per-agent per-file fencing (correct in
intent; see P1-3 for the shell defect) · Secret Manager describe-before-each-mutation ·
credential rotation via secret digest in the intent · `launch.command`
normalisation · startup correlation by invocation id.
