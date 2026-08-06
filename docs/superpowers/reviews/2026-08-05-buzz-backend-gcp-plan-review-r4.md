# buzz-backend-gcp — Plan Review, Round 4 (reduced confirmation panel)

**Plan:** `docs/superpowers/plans/2026-08-05-buzz-backend-gcp.md` (15 tasks, 9,949 lines, commit `8f5e51102`)
**Panel:** feasibility (openai-codex/gpt-5.5) · adversarial (minimax-code/MiniMax-M3) · security (openai-codex/gpt-5.5)
**Reduced deliberately:** scope reported clean in round 3 and product verified both of its round-2 findings closed, so only the three lenses with open round-3 defects were re-run. This is a confirmation panel, not full coverage — recorded as such.
**Lane health:** security yielded a null envelope on its first attempt and was re-run to a valid yield with its checks enumerated; not counted as degraded, since the same agent re-answered with work shown.
**Verdict:** BLOCKED — 3 P1, 1 P2. Two of three lenses clean.

## Trajectory

| Round | P1 | Lenses reporting clean |
|---|---|---|
| 1 | 8 | — |
| 2 | 9 | — |
| 3 | 4 | scope |
| 4 | **3** | **feasibility, security** |

Round 3's four P1s are all confirmed closed. Every remaining finding is
adversarial's, and all three sit in the same place: the lease and
partial-failure machinery. Feasibility found no compile or type defect for the
first time; security enumerated five specific checks and found no issue.

---

## P1 — must fix before executing

### P1-1 The lease is renewed, but not *held*, across each mutation
**Lens:** adversarial. **Where:** Task 12 `DeployLease::renew` / `deploy`; Task 9 `marker_fn` / `install_script`.

`renew` verifies and refreshes the owner record under `flock`, but only at phase
boundaries. If a renewal succeeds and the next remote step then stalls past the
900 s TTL, a second provider legitimately takes the lease over — and the first
provider's delayed operation has **no lease-token check**. `marker_fn` proves
provider identity and `binding-version <= current`; `owner_marker` deliberately
excludes `create-intent` and the token. So the stalled holder can `mv` a stale
render over the winner's current files.

The marker guard proves artifact *provenance*, not that this process still owns
the lease. The plan's residual-risk item 1 claims the loser fails cleanly; it
does not.

**Fix (architectural, and it collapses the class):** hold the lease for the whole
mutating window in one long-lived remote session — a single SSH invocation
holding `flock` across the mutations — rather than N independent round trips each
re-checking. Failing that, every mutation needs an atomic token check that cannot
expire mid-operation, and a lost check must *prevent* the write rather than
report it afterwards.

### P1-2 `remove` stops and destroys before noticing a mixed-version fleet
**Lens:** adversarial. **Where:** Task 13 `verify_removable` / `remove`; Task 6 `Ownership`.

`verify_removable` authorises when **any** present artifact carries a matching
actionable marker, and `AgentMarker::parse` returns no marker for `OursButNewer`.
So a half-migrated agent — an older-or-current env plus a sibling written by a
*newer* provider — passes the gate. `remove` then runs `secrets::destroy`, and
`removal_script` executes `systemctl disable --now` and stops the secret unit
**before** its per-file fences. The newer sibling is dutifully "kept" by the loop
afterwards, having already had its unit stopped and its secret destroyed.

The downgrade refusal is sound for a uniform fleet and on the deploy path; it is
unsound on `remove` in exactly the half-migrated state it exists for.

**Fix:** the pre-stop gate must reject any present artifact that is foreign,
unparseable, or `OursButNewer` — even when another artifact proves the pubkey.
Keep `OursButOlder` acceptance for uniform prior-version agents.

### P1-3 A torn install is misread as healthy
**Lens:** adversarial. **Where:** Task 12 `classify` / `deploy`; Task 9 `owner_marker`.

On a stopped `FencedReplace` where the env install succeeds and a later per-agent
install fails (dropped SSH), the retry sees an env marker carrying the **new**
create-intent beside surviving **old** siblings that are still actionable for the
same pubkey. `classify` checks sibling ownership and pubkey but never sibling
*intent* — the plan states outright that siblings are never interrogated for it —
and compares only the env marker's intent. Result: `RestartSame`, which skips
`secrets::store` and every per-agent install, then starts the unit against stale
or missing drop-ins. A changed `project` leaves the fetcher pointed at the old
Secret Manager project.

So a successful renewal followed by one failed step produces a state the next run
classifies as healthy and reports success for.

**Fix:** `RestartSame` must require every expected per-agent artifact to be
present, attributable to this pubkey, **and** carrying the same create-intent as
the env marker. Anything else is `FencedReplace`.

## P2

**A previewed-live agent is never rechecked** *(adversarial)*. `deploy` returns on a
pre-lease `NoOp` without taking the lease or re-observing. If the agent crashes,
or an operator removes it, between the preview and the return, the provider
reports success and an `agent_id` for something no longer running. The converse
(preview mutable, post-lease `NoOp`) is safe, and a preview refusal is
conservative — only the live-no-op shortcut is wrong. Either revalidate it or
state the staleness as accepted.

## Confirmed closed from round 3

Version-aware ownership threaded through all seven consuming tasks with no
boolean sites left (feasibility) · pre-stop ownership gate ordering, verified
against every destructive call site (security) · per-needle `marker_ok` with no
truncation or embedded-newline bypass (security) · lease acquired before the
authoritative observation, enforced by the type system rather than convention
(feasibility) · private lease directory safe against a pre-existing symlink or
non-directory (security) · `OursButOlder` does not weaken the fence — an attacker
cannot get a file adopted by backdating its marker (security) · numeric
binding-version parse is shell-safe against adversarial input (security).

Adversarial separately probed the 64 KiB Secret Manager cap and found **no**
bypass or spurious trigger: the check is a byte-exact length of the quoted body
actually sent via `--data-file=-`, CR/LF are rejected upstream, and the
allowlisted on-disk half bypasses the cap by design.
