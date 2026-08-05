# buzz-backend-gcp — Plan Review, Round 2

**Plan:** `docs/superpowers/plans/2026-08-05-buzz-backend-gcp.md` (15 tasks, 6,467 lines, commit `a7d5f9ec3`)
**Spec:** `docs/superpowers/specs/2026-08-05-buzz-backend-gcp-design.md` (approved at the spec gate, `a8bbc18c0`)
**Panel:** feasibility (openai-codex/gpt-5.5) · scope (zai/glm-5.2) · product (zai/glm-5.2) · adversarial (minimax-code/MiniMax-M3) · security (openai-codex/gpt-5.5)
**Degraded lanes:** none. `Adversarial2` aborted once on an empty yield envelope and was resumed with its context intact — it produced a full review, so the panel is five-family complete.
**Verdict:** BLOCKED — 9 P1.

## The shape of this round

Round 1's defects were in the original design. **Round 2's are almost entirely in the
hardening the revision added** — the marker tiers, the tamper check, the ownership
gates, the startup confirmation. Every one of those mechanisms was introduced to
close a round-1 finding, and each brought its own surface. That is the central fact
about this round, and it should inform the fix strategy: three P1s below are
retired by *deleting* a mechanism, not by adding code to it.

Round 1's eight P1s are genuinely closed. None recurred.

---

## P1 — must fix before executing

### P1-1 `launch.command` is checked as a basename but written to the VM verbatim
**Lens:** feasibility. **Where:** Task 7 / Task 12.

Task 7 computes `harness_basename(agent)` and Task 12 verifies
`/usr/local/bin/{basename}` exists, but the env is built from the **original**
`agent`, and the shared env code writes `launch.command` through unchanged
(`crates/buzz-backend-kubernetes/src/env.rs:254-256`). The desktop can preserve an
explicit host path (`desktop/src-tauri/src/managed_agents/discovery.rs:443-449`) and
`buzz-acp` execs that exact string (`crates/buzz-acp/src/acp.rs:458-460`).

A payload carrying `/opt/homebrew/bin/codex-acp` passes the installation check for
`codex-acp`, then the VM tries to exec a macOS path. This is precisely the
host-resolved-value failure the approved spec says to prevent.

**Fix:** normalize `launch.command` to the VM spelling *before* `build_env`; assert
the rendered env contains the normalized command and not the desktop path.

### P1-2 Startup confirmation accepts a stale journal line
**Lenses:** feasibility (BLOCKER) + adversarial (#12). **Where:** Task 12.

The poll counts any `buzz-acp starting:` line for the unit within 30 minutes. That
line carries no generation/start nonce (`crates/buzz-acp/src/config.rs:1119-1146`),
so a restart within 30 minutes of a prior success is "confirmed" by the previous
process's output — `enable --now` on a `Type=simple` unit returns before the new
harness logs anything.

**Fix:** correlate to the current attempt — filter by the current `MainPID`, or by a
timestamp captured immediately before `enable --now`, or log the nonce and grep it.
Add a case where an old line exists, the current attempt has none, and the parser
stays `Pending`.

### P1-3 `project` reaches a root drop-in as an unvalidated `Environment=` value
**Lens:** security. **Where:** Task 4 / Task 7 fetcher drop-in.

The revision closed grammars for `memory_max`/`cpu_quota`, then introduced a third
interpolation the spec's threat model never covered:
`Environment=BUZZ_GCP_PROJECT={cfg.project}`. `project` is only trimmed and
CR/LF/NUL-scanned. systemd's `Environment=` is whitespace- and quote-parsed, so
spaces, quotes, `%` specifiers or a second assignment inject root-unit environment
(`CLOUDSDK_CONFIG`, proxies) into the one unit deliberately allowed to reach
metadata and Secret Manager.

**Fix:** closed grammar for `project` (and ideally `zone`/`instance`), or render
`Environment=` through a systemd quoting helper. Test
`project = "zoop BUZZ_GCP_SECRET=evil"`, quotes, `%`, and CR/LF/NUL-before-trim.

### P1-4 Per-agent destruction is authorized by one sibling file
**Lenses:** security (BLOCKER) + feasibility (SHOULD-FIX) — corroborated.
**Where:** Task 11 / Task 12 / Task 13.

`observe` records only the env file's `AgentMarker`. `FencedReplace` then installs
all per-agent files, and `remove` verifies the env file before `rm -f` of the env,
trail, agent drop-in and fetcher drop-in. That is "delete enumerated paths if one
sibling is marked", not "delete only marked paths" — and it contradicts both L2's
auto-repair fence (`docs/remote-agents.md:1460-1476`) and the approved spec's own
claim at `spec:753-771`.

**Fix:** observe each artifact's own marker; refuse to overwrite or delete any
present file whose own marker is absent, wrong-version or wrong-pubkey; report and
leave it.

### P1-5 Secret Manager ownership is verified once, then mutated twice
**Lenses:** security (BLOCKER) + adversarial (#5) + feasibility (SHOULD-FIX) — triple.
**Where:** Task 10.

`store` verifies ownership, then runs `versions add` and `add-iam-policy-binding`
with no re-read between. A name-matching secret swapped in that window receives this
agent's payload, or the VM service account is granted `secretAccessor` on a secret
we no longer own. Separately, `store` returns immediately on any failed `create`, so
the loser of a create race fails instead of converging by re-entry — contradicting
the plan's own residual-risk text.

**Fix:** `describe_owned()` immediately before *each* mutation; treat
`ALREADY_EXISTS` as a re-read-and-verify, not a failure; add a command-sequence test
proving every mutation is preceded by describe+verify.

### P1-6 The shared-artifact tamper check is unsound and self-locking
**Lenses:** security (BLOCKER) + adversarial (#4) + scope (CONSIDER) — triple.
**Where:** Task 6 / Task 11 / Task 12.

Three independent defects in one mechanism:
- `SharedFileState::marked()` means only "a `# content-hash:` line exists" — it never
  checks `managed-by`, `binding-version` or `scope`, so a foreign file with that line
  is treated as ours.
- The hash strip is `sed '/^# managed-by: buzz-backend-gcp$/,+3d'`, which deletes
  **every** matching block anywhere in the file. Malicious directives hidden inside an
  extra four-line block are stripped before hashing but still executed by systemd.
- A future `binding-version: 2` hashes differently and is rejected as "tampered",
  making provider upgrades an unrecoverable lockout.

Scope's separate verdict: this is the **only** mechanism in the plan solving a problem
the approved spec does not pose, and it owns the GNU-`sed` portability dependency the
plan itself flags.

**Fix (recommended):** delete the tamper check. Shared artifacts are byte-identical
across agents and derived from compiled-in constants; write-if-absent-or-different is
sufficient. If it is kept instead: parse the marker at an exact contiguous header
position, hash by removing only that header, and make the version check an upgrade
path rather than a refusal.

### P1-7 Credential rotation silently fails on `RestartSame`
**Lenses:** adversarial (#3, BLOCKER) + security (SHOULD-FIX) — corroborated.
**Where:** Task 7 create-intent / Task 12.

Secret *values* are excluded from the create-intent (correct for L2 item 5), but
`RestartSame` also skips `secrets::store`. An agent whose `auth_tag` or API key
changed while its non-secret intent did not is restarted against the **previous**
secret version. The operator sees a successful restart; the relay sees the old
identity. I1 fail-closed is not preserved.

**Fix:** call `secrets::store` on `RestartSame` too (keeping file writes skipped), or
fold `sha256` of the secret payload — hash, never value — into the intent.

### P1-8 Concurrent deploys interleave into a mixed state
**Lens:** adversarial (#1, #2). **Where:** Task 12.

Deploys are unserialised, which the plan acknowledges as residual risk. Two
concurrent `Create`s can leave Secret Manager holding A's payload while the disk
holds B's marker. Worse, the destructive fence's re-read window spans from `fence()`
through `daemon-reload` — four to six `gcloud` round trips — during which a competing
`enable --now` can start a unit over a half-rewritten file set. A fence that wide is
a TOCTOU with more steps.

**Fix:** take a per-agent lock on the instance (`flock` on a derived path) for the
mutating window, and narrow the fence to re-verify immediately before the write that
depends on it. "Unserialised" is acceptable only if a loser fails cleanly.

### P1-9 Partial-write fragments are left unmarked and therefore unrecoverable
**Lens:** adversarial (#9), reinforced by P1-4. **Where:** Task 8 installs.

A dropped connection mid-`install` leaves a truncated file at the target path with
no complete marker header. On the next deploy that file is "present but unmarked",
which P1-4's correct fence must refuse — so the fix for P1-4 turns every partial
write into a permanent, operator-only-recoverable jam.

**Fix:** install atomically — write to `<path>.tmp` and `mv` into place — so a target
path is never observed half-written. Pairs with P1-4; neither is safe alone.

---

## P2 — should fix

1. **The capacity warning is findable, not found** *(product)*. Writer and reader are
   each unit-tested against hand-typed fixtures that happen to agree on the
   `warning capacity:` prefix; nothing feeds `trail_record` output through
   `listing_script` + `render_listing`, and Task 15 never deploys an over-capacity
   agent. A format drift would silently restore the round-1 blind spot with all tests
   green. Close the writer→reader loop in a test, add an over-capacity smoke step, and
   tell the operator in the README that the desktop will not show this.
2. **A missing env file makes an agent a ghost** *(product)*. Both `remove` and `list`
   key off `/etc/buzz/acp-*.env`. If it is gone, a running, secret-bearing agent is
   invisible to `list` and `remove` reports "nothing here to remove" — the operator's
   only reclamation path lies, in a reachable state.
3. **`RestartSame` skips shared-artifact repair** *(feasibility)*. Zero-mutation is
   required for live `NoOp`, not for a stopped restart; if a shared template was
   deleted out of band, re-entry never converges.
4. **The fetcher unit does not carry the hardening the plan says it does**
   *(security)*. `FETCHER_UNIT` omits `PrivateDevices`, `ProtectKernelTunables`,
   `ProtectKernelModules`, `ProtectControlGroups`, `RestrictRealtime`,
   `CapabilityBoundingSet=`, `AmbientCapabilities=`, `TasksMax=`, and grants
   `ReadWritePaths=/run` rather than the runtime dir — while Task 14's L3 docs claim
   the full set. This is the highest-privilege code in the binding.
5. **Capacity is computed once and acted on up to 240 s later** *(adversarial #6)*.
6. **The pre-existing non-instanced `buzz-acp.service` is counted in capacity but
   never fenced** *(adversarial #8)* — and it is itself non-conforming (`Restart=always`).
7. **Weak relay-mesh regression net** *(adversarial #14)*: the golden asserts
   `error.contains("relay-mesh")`, satisfied by any error mentioning the string.

## P3 — consider

Intent hash is sensitive to `"2G"` vs `"2048M"` though both parse identically
(adversarial #11) · multi-MB secret bodies against the 5 s poll budget (#10) ·
concurrent `remove` racing `deploy` (#13) · key-rename intent divergence coverage (#7).

## Round-1 findings: all closed

Verified as resolved and not regressed: capacity channel, `gcloud` PATH, both compile
errors, the `relay-mesh` refusal, observation/fence split, config-value grammars,
secret allowlist, and the extraction's test/visibility corrections. The three round-1
findings rejected on measured evidence remain rejected; the plan records that evidence
inline so a future reader does not "fix" them.
