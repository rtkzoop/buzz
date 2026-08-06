# buzz-backend-gcp — Plan Review, Round 5 (final confirmation) — CLEAN

**Plan:** `docs/superpowers/plans/2026-08-05-buzz-backend-gcp.md` (15 tasks, 10,700 lines, commit `0eb122fb4`)
**Panel:** feasibility (openai-codex/gpt-5.5) · adversarial (minimax-code/MiniMax-M3) · security (openai-codex/gpt-5.5)
**Reduced deliberately:** scope clean at r3, product's findings verified closed at r3; only the lenses with open defects were re-run. Recorded as a confirmation panel, not full coverage.
**Degraded lanes:** none.
**Verdict:** CLEAN — no P1, no P2, from any lane.

## Trajectory

| Round | P1 | Lenses clean |
|---|---|---|
| 1 | 8 | — |
| 2 | 9 | — |
| 3 | 4 | scope |
| 4 | 3 | feasibility, security |
| 5 | **0** | **feasibility, adversarial, security** |

Adversarial found all three of round 4's P1s and reports this round clean; it is
the strongest signal available, since it is the lane that has never yet returned
a clean result on this plan.

## What each lane verified

**Adversarial** attacked five vectors and each held:
- The central claim — gate and mutation share one `flock`, so a takeover cannot
  interleave — is airtight. `under_lease` renders exactly one
  `sudo -n flock -w 5 -E 75 <lock> sh -c '<gate><work>'`, and the structural test
  `an_install_proves_the_lease_in_the_same_shell_as_the_rename` asserts
  `script.matches("sh -c '").count() == 1`. A stall before `flock` means the
  rival's gate refuses; a stall after it means the rival's `flock -w` times out.
  There is no third case.
- The deliberate gap where `flock` is not held across the stdin drain is safe:
  the body is staged before the lock is taken, so a rival waits on local file
  operations rather than a network transfer.
- The Secret Manager calls — the one remaining mutation not fenced in-shell,
  because they run from the operator's Mac with operator credentials — are
  covered by the retained standalone renewal plus Task 10's re-describe and
  verify immediately before each of add-version, IAM grant and delete.
- `coherent` cannot be satisfied by a constructible torn state, nor made to fail
  spuriously.
- The restructured `verify_removable` cannot be talked into stopping anything.

**Feasibility** confirmed: every mutating call site passes `&lease` and
`&DeployLease` unsizes to `&dyn Held`; the only `impl Held` and the only
`DeployLease { … }` construction are the intended ones; `under_lease`'s nesting,
`-E 75` propagation and dash-safety are correct; no mutating step can outlive its
lease; `coherent` type-checks against the borrow in `MarkerState::agent_files()`;
and deleting the pre-lease `NoOp` return leaves `deploy`'s block still typed as an
expression yielding `started_at: u64`.

**Security** re-verified its five round-4 checks after the lease shell moved into
`remote`, plus the new composition: the pre-stop gate still precedes every
destructive call; `under_lease`'s root-body interpolation has no injection path
under `sq`; the retained renewal before the Secret Manager calls gives an
attacker who can write the owner record no influence over what is destroyed or
granted, because the secret name, pubkey, SA and IAM member all derive from
decoded identity and config rather than from that record; `&dyn Held` genuinely
prevents an unfenced mutation, with `Remote::run` reaching only read-only scripts
and the lease scripts themselves; and the deleted pre-lease `NoOp` discloses
nothing new.

## Accepted residual risks

Carried deliberately and recorded in the plan's own residual list, not
discovered here:
1. The Secret Manager calls remain the one mutation not fenced inside a remote
   shell — unavoidable without granting the instance service account
   secret-admin, which would trade the binding's central security property for a
   concurrency one.
2. The single long-lived session was evaluated and rejected for that same
   reason; an SSH master connection is recorded as the cheaper way to recover the
   ~30-50 s of tunnel-setup latency it would have saved.
3. Deploys remain unserialised across *different* agents; the lease is per-agent
   by design.

## Rejected findings across all rounds

Three round-1 claims were rejected on measured evidence and have stayed rejected:
`gcloud compute ssh --command` does forward stdin (30 bytes, md5 exact);
systemd's manager reads `EnvironmentFile=` as root before dropping privileges
(proven by the live `buzz-acp.service` reading a `0600 root:root` file as
`User=buzzacp`); and `gcloud` already passes `StrictHostKeyChecking=yes` with a
`HostKeyAlias`, so the plan passes no override. The plan records each of these
inline where a future reader might otherwise "fix" them.
