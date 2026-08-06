//! The deploy state machine (spec §Deploy Reconciliation, I4).
//!
//! `deploy` is not "create": the desktop issues it on every Start and tracks
//! no substrate state. The only way that is safe is for a live instance to be
//! a strict no-op, and for every destructive write to be fenced to the exact
//! observation that authorized it — in the same remote shell, not four round
//! trips later.

use crate::capacity;
use crate::config::ProviderConfig;
use crate::naming::{Names, Ownership, BINDING_VERSION, BINDING_VERSION_NUM, MANAGED_BY};
use crate::observe::{self, property, section, Observation};
use crate::remote::{
    lease_lost, lease_paths, sq, under_lease, Held, Remote, AGENT_STARTED, LEASE_DIR,
    LEASE_FLOCK_WAIT_SECONDS, LOCK_UNAVAILABLE, MARKER_CHANGED, MARKER_SCAN_LINES,
};
use crate::render::{self, Plan, RemoteFile};
use crate::secrets;
use buzz_backend_core::identity::{new_generation, AgentIdentity};
use buzz_backend_core::wire::AgentPayload;
use std::time::{Duration, Instant};

/// How long to wait for a confirmed harness start.
///
/// The desktop's deploy budget is 600 s (`backend.rs:528`), and roughly a
/// dozen `gcloud` round trips at 3-5 s each precede the first poll. 240 s is
/// about 8× an observed warm start — enough for a `codex-acp` cold start on an
/// e2-medium, which has to run the fetcher unit, load Node and the harness,
/// and complete a relay handshake — while leaving ≥ 250 s of slack, so a stuck
/// agent produces this provider's actionable error rather than the desktop's
/// opaque `provider timed out after 600s`.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(240);

/// One `gcloud compute ssh` round trip costs 3-5 s on its own, so polling
/// faster than this buys nothing but load.
const STARTUP_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long a deploy lease on the instance stays valid.
///
/// It covers the mutating window only — the authoritative observation, the
/// installs, the trail append and `enable --now` — not the startup poll that
/// follows. 900 s is chosen to sit **above every enforced lifetime**: the
/// desktop kills the provider at 600 s (`backend.rs:528`), so a
/// desktop-driven deploy can never age out its own lease, which is what 300 s
/// allowed. A direct CLI run has no enforced lifetime at all, and no TTL can
/// cover that — the record is refreshed instead, by
/// [`crate::remote::lease_gate`] inside every mutation's own shell and by
/// [`DeployLease::renew`] across the one stretch that performs no remote
/// mutation. The TTL still bounds the other direction: a provider killed
/// between acquire and release blocks the next deploy for minutes, not
/// forever. It is **not** what keeps a stalled holder from writing after a
/// takeover — the per-mutation gate is; expiry only decides when an abandoned
/// record may be stolen.
const DEPLOY_LEASE_SECONDS: u64 = 900;

/// The harness's own first log line. Its presence is what distinguishes
/// "systemd accepted the unit" from "the agent started".
const HARNESS_STARTUP_LINE: &str = "buzz-acp starting:";

/// What one deploy must do, decided from an observation alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The agent is already live. Zero mutation (I4).
    NoOp,
    /// Nothing of ours is there. Install and start.
    Create,
    /// Our files are there with the same recorded intent, and it is not
    /// running: start it. Never delete.
    RestartSame,
    /// Our files are there with a divergent intent, and it is not running:
    /// replace them, fenced.
    FencedReplace,
    /// Something is there that is not ours, or not this agent's.
    Refuse(String),
}

/// Decide what to do from an observation alone.
///
/// Pure, so the whole state machine is testable without an instance. Order
/// matters: every refusal is checked before any action, because an action
/// taken on somebody else's file cannot be undone by a later check.
pub fn classify(obs: &Observation, pubkey_full: &str, intent: &str) -> Action {
    // Shared artifacts first: they are installed once and depended on by every
    // instance, so one unowned file poisons every deploy on the box. A marked
    // shared file whose bytes differ is an older rendering of ours, not a
    // finding — nothing in the file claims what its own content should be, and
    // that is true whether it was rendered by this build or by an older one.
    for shared in &obs.markers.shared {
        if !shared.present {
            continue;
        }
        match shared.ownership {
            // Ours, at this version or an earlier one. `shared_writes` decides
            // whether the bytes need rewriting; ownership has no further say.
            Ownership::Ours | Ownership::OursButOlder(_) => {}
            Ownership::OursButNewer(found) => {
                return Action::Refuse(format!(
                    "{} was written by a newer {MANAGED_BY} (binding version \
                     {found}; this build writes {BINDING_VERSION}). Refusing to \
                     downgrade a template every instance on this box runs \
                     against. Upgrade this provider.",
                    shared.path
                ))
            }
            Ownership::NotOurs => {
                return Action::Refuse(format!(
                    "{} exists but carries no {MANAGED_BY} provider marker. It \
                     is somebody else's file that happens to share our name; \
                     refusing to overwrite it. Move it aside to let this \
                     provider install its own.",
                    shared.path
                ))
            }
        }
    }

    // Then **every** per-agent artifact against its own header, not the env
    // file's. `FencedReplace` rewrites all four and `remove` deletes all four,
    // so authorizing that from one sibling is "delete enumerated paths if one
    // of them is marked" — the opposite of the auto-repair fence
    // (`docs/remote-agents.md:1460-1476`). A file that fails is reported and
    // left exactly where it is.
    //
    // Ownership is version-aware, and the asymmetry is the whole point of
    // round 3's P1-1. An *older* binding version is this provider's own work
    // at a layout this build supersedes — an authorised upgrade target, not a
    // stranger — because `BINDING_VERSION` is documented as
    // "bump when the unit/env shape changes", so treating it as foreign locked
    // the operator out of `deploy` *and* `remove` for every agent already
    // installed. A *newer* one is the refusal that reserves: a build that
    // cannot reason about a layout must not overwrite or delete it.
    for file in obs.markers.agent_files() {
        if !file.present {
            continue;
        }
        match file.ownership {
            Ownership::Ours | Ownership::OursButOlder(_) => {}
            Ownership::OursButNewer(found) => {
                return Action::Refuse(format!(
                    "{} was written by a newer {MANAGED_BY} (binding version \
                     {found}; this build writes {BINDING_VERSION}). Refusing to \
                     overwrite or delete an artifact whose layout this build \
                     does not understand; it is untouched. Upgrade this \
                     provider, or move the file aside.",
                    file.path
                ))
            }
            Ownership::NotOurs => {
                return Action::Refuse(format!(
                    "{} exists but carries no {MANAGED_BY} marker. Refusing to \
                     overwrite or delete a file this provider did not write; \
                     it is untouched. Move it aside to let this deploy \
                     proceed.",
                    file.path
                ))
            }
        }
        // Ours by provenance, but the identity half has to be there too: a
        // header carrying our marker and no `agent-pubkey-full` names no
        // agent, and "which agent is this?" is the question every destructive
        // step downstream asks.
        let Some(marker) = file.marker.as_ref() else {
            return Action::Refuse(format!(
                "{} carries the {MANAGED_BY} marker but no agent-pubkey-full \
                 line, so which agent it belongs to cannot be established. \
                 Refusing to overwrite or delete it; it is untouched.",
                file.path
            ));
        };
        if marker.pubkey_full != pubkey_full {
            return Action::Refuse(format!(
                "short-name collision: {} belongs to pubkey {}, not \
                 {pubkey_full}. The 12-hex instance name is \
                 collision-resistant, not collision-free; refusing rather than \
                 destroying another agent's deployment.",
                file.path, marker.pubkey_full
            ));
        }
    }

    // Per-agent state. Systemd knowledge and marker ownership are separate
    // facts: a real unit with no env file must not read as "absent".
    let Some(marker) = obs.markers.env.marker.as_ref() else {
        // A *present* env file that is not ours was refused above, so reaching
        // here means there is none — nothing of this agent's is recorded.
        if obs.systemd.instance_known() {
            return Action::Refuse(format!(
                "a unit for this agent exists on the instance (LoadState={}, \
                 SubState={}), but no {MANAGED_BY} marker records it. Refusing \
                 to adopt, restart, or replace a unit this provider did not \
                 create.",
                obs.systemd.load_state, obs.systemd.sub_state
            ));
        }
        return Action::Create;
    };

    // Live is a strict no-op regardless of intent: reconfiguring a running
    // agent would mean killing it, and I4 puts at-most-one-live-instance above
    // convergence. The operator stops it, then redeploys.
    if obs.systemd.running() {
        return Action::NoOp;
    }

    // An artifact still at an older binding version makes this a replace even
    // when the recorded intent matches: the intent says the *inputs* did not
    // change, not that the artifact layout is current, and rewriting the four
    // files is what rolls their markers forward. Checked after `running()`,
    // because an upgrade is convergence and I4 puts at-most-one-live-instance
    // above convergence.
    if obs
        .markers
        .agent_files()
        .any(|file| file.present && matches!(file.ownership, Ownership::OursButOlder(_)))
    {
        return Action::FencedReplace;
    }

    // `RestartSame` claims that everything this deploy would write is already
    // on the instance and already says the same thing. That is a claim about
    // **all four** artifacts, so it has to be checked against all four —
    // round 4's P1-3. An install torn between the env file and a later
    // per-agent write (a dropped SSH, say) leaves the env marker carrying the
    // *new* create-intent beside surviving siblings that still carry the
    // *old* one and are still perfectly ours and this agent's. Comparing only
    // the env marker called that state healthy: `RestartSame` skips
    // `secrets::store` and every per-agent install, then starts the unit
    // against stale drop-ins — including a stale `project`, which points the
    // fetcher at the wrong Secret Manager project and produces a start
    // failure that looks nothing like the deploy that caused it.
    //
    // The refusal loop above has already established, for every *present*
    // artifact, that it is ours (or ours-but-older) and that its marker names
    // this pubkey. So what remains to require is exactly: none is missing, and
    // they all agree with the env file about which deploy wrote them. The env
    // file is compared against itself here, harmlessly, because `agent_files`
    // yields it first and special-casing it would be a second rule.
    let coherent = obs.markers.agent_files().all(|file| {
        file.present
            && file
                .marker
                .as_ref()
                .is_some_and(|found| found.create_intent == marker.create_intent)
    });

    if marker.create_intent == intent && coherent {
        Action::RestartSame
    } else {
        Action::FencedReplace
    }
}

/// Which shared artifacts this deploy must write.
///
/// A shared file whose installed bytes already hash to what this provider
/// would render is skipped, which is what makes the strict no-op on a live
/// instance actually strict rather than "no-op except for three files
/// rewritten identically". Both sides of the comparison are hashes of real
/// bytes: one computed here from the rendered body, one computed on the
/// instance from the file. Refusals for unmarked shared files are `classify`'s
/// job and have already run.
pub fn shared_writes<'a>(plan: &'a Plan, obs: &Observation) -> Vec<&'a RemoteFile> {
    plan.shared
        .iter()
        .filter(|artifact| {
            match obs
                .markers
                .shared
                .iter()
                .find(|state| state.path == artifact.file.path)
            {
                Some(state) => !state.present || state.sha256 != artifact.sha256,
                // Never observed: write it rather than assume it is there.
                None => true,
            }
        })
        .map(|artifact| &artifact.file)
        .collect()
}

/// What one startup poll saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// Active, with a live main PID, and the harness logged its own start
    /// **during this attempt**.
    Confirmed,
    /// systemd gave up. Polling further would only waste the budget.
    Failed(String),
    Pending,
}

/// The remote script one startup poll runs.
///
/// The journal query carries two independent bounds, because the harness's
/// startup line carries no generation and no start nonce
/// (`crates/buzz-acp/src/config.rs:1119-1146`) and `enable --now` on a
/// `Type=simple` unit returns before the new process logs anything:
///
/// * `_SYSTEMD_INVOCATION_ID` pins the query to the unit's **current**
///   invocation. systemd mints a fresh one on every start, so a line the
///   previous run wrote is not in this set at all.
/// * `--since @<epoch>` pins it to a timestamp read **on the instance**
///   immediately before `enable --now`. This is the bound that covers what the
///   invocation id cannot see: a unit already running from an earlier start,
///   where `enable --now` is a no-op and the "current" invocation is the old
///   run's. Its startup line predates the timestamp, the count is zero, and
///   the poll stays `Pending` until this attempt speaks for itself.
///
/// The epoch comes from the instance rather than from the operator's Mac: the
/// two clocks are unrelated, and a Mac a few seconds fast would silently
/// exclude the very line the poll is waiting for.
fn startup_script(unit: &str, since_epoch: u64) -> String {
    format!(
        "set -uo pipefail\n\
         echo '---UNIT---'\n\
         systemctl show {unit} -p ActiveState -p MainPID -p Result -p InvocationID \
           2>/dev/null || true\n\
         echo '---JOURNAL---'\n\
         inv=$(systemctl show {unit} -p InvocationID --value 2>/dev/null || true)\n\
         if [ -n \"$inv\" ]; then\n\
           sudo -n journalctl -u {unit} \"_SYSTEMD_INVOCATION_ID=$inv\" \
             --since '@{since}' --no-pager 2>/dev/null | grep -c {needle} || true\n\
         else\n\
           echo 0\n\
         fi\n\
         echo '---END---'\n",
        unit = sq(unit),
        since = since_epoch,
        needle = sq(HARNESS_STARTUP_LINE),
    )
}

/// Decode one startup poll. Pure, so the three outcomes are testable.
pub fn parse_startup(stdout: &str) -> Startup {
    let unit = section(stdout, "UNIT");
    let active = property(unit, "ActiveState");
    let main_pid: u32 = property(unit, "MainPID").parse().unwrap_or(0);
    let result = property(unit, "Result");
    if active == "failed" {
        return Startup::Failed(format!("systemd reports the unit failed (Result={result})"));
    }
    let started = section(stdout, "JOURNAL")
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    if active == "active" && main_pid > 0 && started > 0 {
        return Startup::Confirmed;
    }
    Startup::Pending
}

/// The shell that reads a lease record and decides whether it is *held by
/// somebody else, right now*.
///
/// Only [`acquire_lease_script`] needs it — [`crate::remote::lease_gate`], which
/// renewal and every fenced mutation share, asks the narrower question "is
/// this record still ours", which needs no freshness arithmetic at all. It is
/// a function rather than an inline block so the three controls below sit next
/// to the reasoning for them.
///
/// Three controls, each closing a way a record could lie:
///
/// * **`install -d -m 0700 -o root -g root`** creates the directory private and
///   *repairs* it if something loosened it, on every acquire.
/// * **A record that is not a root-owned regular file is not a record.** `-f`
///   follows symlinks, so `-L` is tested separately; a symlink is removed
///   (which removes the link, not its target) and treated as absent. `stat -c`
///   is GNU coreutils, which every Debian and Ubuntu GCE image ships — and
///   unlike the deleted `sed` range it is a plain field read with no
///   address-range semantics to get wrong.
/// * **A future-dated timestamp is corrupt, not fresh.** A clock step or a
///   hand-edited record must not grant an unbounded lease, so the age has to
///   be non-negative *and* under the TTL to count as held.
///
/// The stored epoch is filtered to digits before the arithmetic: a corrupted
/// record must not make `$(( ))` fail in a direction that hands out the lease.
fn lease_preamble(owner: &str, ttl_check: &str) -> String {
    format!(
        "if [ -e {owner} ]; then\n\
           if [ ! -f {owner} ] || [ -L {owner} ] || \
              [ \"$(stat -c %u {owner} 2>/dev/null || echo -1)\" != 0 ]; then\n\
             rm -f {owner}\n\
           else\n\
             held=$(cut -d' ' -f1 {owner})\n\
             at=$(cut -d' ' -f2 {owner} | tr -cd '0-9')\n\
             age=$(( now - ${{at:-0}} ))\n\
             {ttl_check}\
           fi\n\
         fi\n"
    )
}

/// Take the per-agent deploy lease, or exit [`LOCK_UNAVAILABLE`].
///
/// `flock` cannot be *held* across the whole mutating window from here: every
/// round trip is a separate SSH session, so the descriptor holding the lock
/// closes when the session ends. What `flock` can do is make each
/// read-modify-write of the lease record atomic — this one, and the one
/// [`crate::remote::lease_gate`] performs inside every mutation. The lock file
/// is the mutex; the owner file is the lease, and it carries a timestamp so an
/// abandoned one expires instead of wedging the instance.
///
/// `sudo -n flock … sh -c` rather than `sudo -n sh -c 'exec 9>…'`: the whole
/// critical section has to run as root because [`LEASE_DIR`] is `0700
/// root:root`, and `flock`'s command form elevates once for the section
/// instead of once per command inside it. Round 4 made that the single shape
/// for every critical section in this binding, so acquire, renew, release and
/// each fenced mutation are the same thing with a different body.
fn acquire_lease_script(instance: &str, token: &str) -> String {
    let (lock, owner) = lease_paths(instance);
    let inner = format!(
        "set -u\n\
         now=$(date +%s)\n\
         {preamble}\
         printf '%s %s\\n' {token} \"$now\" > {owner}\n",
        owner = sq(&owner),
        token = sq(token),
        preamble = lease_preamble(
            &sq(&owner),
            &format!(
                "if [ \"$held\" != {token} ] && [ \"$age\" -ge 0 ] && \
                 [ \"$age\" -lt {ttl} ]; then\n\
                   exit {busy}\n\
                 fi\n",
                token = sq(token),
                ttl = DEPLOY_LEASE_SECONDS,
                busy = LOCK_UNAVAILABLE,
            ),
        ),
    );
    format!(
        "set -uo pipefail\n\
         sudo -n install -d -m 0700 -o root -g root {dir}\n\
         sudo -n flock -w {wait} -E {busy} {lock} sh -c {inner}\n",
        dir = sq(LEASE_DIR),
        wait = LEASE_FLOCK_WAIT_SECONDS,
        busy = LOCK_UNAVAILABLE,
        lock = sq(&lock),
        inner = sq(&inner),
    )
}

/// Refresh the lease's timestamp — but only after proving we still hold it.
///
/// Nothing but [`crate::remote::under_lease`] with an empty body, and
/// deliberately so: the gate every mutation carries *is* a verify-then-refresh,
/// and a second spelling of "is this record still ours" is a second thing to
/// get wrong.
/// What is left for a standalone call is the stretch of the window that
/// performs no remote mutation at all — the Secret Manager calls — plus
/// [`DeployLease::observe`]'s opening proof.
///
/// It **verifies before it refreshes**: a record that no longer names this
/// token means the lease was stolen or expired and somebody else is mutating
/// this agent, and the only safe answer is [`LOCK_UNAVAILABLE`] — extending a
/// lease we do not hold would be worse than having none.
fn renew_lease_script(instance: &str, token: &str) -> String {
    format!("set -uo pipefail\n{}", under_lease(instance, token, ""))
}

/// Release the lease — but only if we still hold it. A release that stole
/// somebody else's would be worse than having no lease at all.
///
/// No `-E`: the only caller is `Drop`, which discards the result, so a
/// contended lock needs no distinguishable exit code. The record expires on
/// its own after [`DEPLOY_LEASE_SECONDS`] either way.
fn release_lease_script(instance: &str, token: &str) -> String {
    let (lock, owner) = lease_paths(instance);
    let inner = format!(
        "set -u\n\
         if [ \"$(cut -d' ' -f1 {owner} 2>/dev/null || true)\" = {token} ]; then\n\
           rm -f {owner}\n\
         fi\n",
        owner = sq(&owner),
        token = sq(token),
    );
    format!(
        "set -uo pipefail\n\
         sudo -n flock -w {wait} {lock} sh -c {inner}\n",
        wait = LEASE_FLOCK_WAIT_SECONDS,
        lock = sq(&lock),
        inner = sq(&inner),
    )
}

/// The lease, released when it leaves scope.
///
/// The guard exists so that every `?` in the mutating window releases on the
/// way out — including the ones added after it was written. `pub(crate)`
/// because `operator::remove` takes the same lease around its own destructive
/// window. It carries the 12-hex agent rather than the GCE instance name: the
/// lease is per agent, and [`Held::agent`] hands exactly that to `remote`.
pub(crate) struct DeployLease<'a> {
    remote: &'a Remote,
    instance: String,
}

impl DeployLease<'_> {
    /// Prove we still hold the lease and push its expiry out.
    ///
    /// Round 4 narrowed this from "called at each phase boundary" to "called
    /// where nothing else proves the lease", which is one place in `deploy`
    /// and one in `remove`: the stretch spent talking to Secret Manager from
    /// this machine. Every *remote* mutation now carries
    /// [`crate::remote::lease_gate`] inside its own shell, which is the same
    /// verify-then-refresh — so it renews as a side effect of acting, and a
    /// renewal that merely precedes an unfenced write is exactly the shape
    /// round 4's P1-1 rejected.
    pub(crate) fn renew(&self) -> Result<(), String> {
        let out = self
            .remote
            .run(&renew_lease_script(&self.instance, self.remote.token()))?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(format!(
                "the deploy lease for buzz-acp@{}.service was lost while this \
                 operation was running — another provider holds it now. \
                 Stopping here rather than continuing to write under a lease \
                 we do not hold; re-run once the other operation finishes.",
                self.instance
            ));
        }
        if !out.ok() {
            return Err(format!(
                "could not renew the deploy lease for buzz-acp@{}.service \
                 (exit {}): {}",
                self.instance,
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    /// The **authoritative** observation: the one this deploy acts on.
    ///
    /// It hangs off the guard rather than being a free call, and that is the
    /// whole fix for P1-4. `deploy` used to `observe::look` and `classify`
    /// *before* taking the lease and then act on that pre-lease verdict, so a
    /// deploy could see "absent/stopped", lose the race, and mutate on state
    /// that had already moved. Written this way the ordering is a property of
    /// the type: there is no way to reach this observation without a
    /// `DeployLease`, and no way to hold one without having written the owner
    /// record first. The `renew` is not decoration either — it is what turns
    /// "we took a lease a moment ago" into "we hold it now".
    fn observe(&self, names: &Names, harness: &str) -> Result<Observation, String> {
        self.renew()?;
        observe::look(self.remote, names, harness)
    }
}

/// The one implementor of [`Held`].
///
/// `Remote::{install, append, run_fenced}` take `&dyn Held`, so a mutating
/// call cannot be written without a lease in hand — the same discipline
/// `observe` uses for the authoritative observation, applied to the writes.
/// The value handed over is the 12-hex agent, which is all `remote` needs to
/// find the lock and the owner record; the token comes from the `Remote`
/// itself, because the record holds `remote.token()` and there is exactly one
/// per provider process.
impl Held for DeployLease<'_> {
    fn agent(&self) -> &str {
        &self.instance
    }
}

impl Drop for DeployLease<'_> {
    /// Best effort. A release that does not land is not a leak: the record
    /// expires after `DEPLOY_LEASE_SECONDS`, which is the reason it carries a
    /// timestamp. There is nothing useful to report from a destructor — the
    /// operation that mattered has already returned its own result.
    fn drop(&mut self) {
        let _ = self
            .remote
            .run(&release_lease_script(&self.instance, self.remote.token()));
    }
}

/// Serialize the mutating window, or fail cleanly.
///
/// Losing is not an error to work around — it is the correct outcome: the loser
/// mutates nothing and says so, which is what makes "deploys are unserialised"
/// acceptable in the first place. `pub(crate)` so `operator::remove` can take
/// the same lease: it destroys a secret and four files, and taking none made
/// it freely interleavable with a deploy.
pub(crate) fn acquire_lease<'a>(
    remote: &'a Remote,
    names: &Names,
) -> Result<DeployLease<'a>, String> {
    let out = remote.run(&acquire_lease_script(names.instance(), remote.token()))?;
    if out.code == LOCK_UNAVAILABLE {
        return Err(format!(
            "another operation on {} is already in progress on this instance. \
             Nothing was modified; wait for it to finish and start again. A \
             lease left behind by a provider that died is reclaimed after \
             {DEPLOY_LEASE_SECONDS}s.",
            names.unit()
        ));
    }
    if !out.ok() {
        return Err(format!(
            "could not take the deploy lease for {} (exit {}): {}",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }
    Ok(DeployLease {
        remote,
        instance: names.instance().to_string(),
    })
}

/// Re-read the authorizing observation **and** perform the stop it authorizes,
/// in one remote shell.
///
/// [L2] item 4 requires a destructive write fenced to the exact observation
/// that authorized it. Reading in one round trip and stopping in the next
/// leaves a window a competing `enable --now` can start a unit in; here the
/// window is the microseconds between two `systemctl` calls on the instance.
/// Everything written afterwards carries its own marker guard inside its own
/// install script, so nothing downstream leans on this check.
///
/// `intent` is the intent the **observation** carried, not the one this deploy
/// is about to write: a divergent intent is precisely what makes a replacement
/// a replacement, so comparing against the new one would refuse every
/// legitimate `FencedReplace`. The binding version is compared as an ordering
/// for the same reason a step further on — an upgrade classifies as
/// `FencedReplace`, and an exact compare here would refuse the upgrade the
/// classification just authorized.
///
/// [`MARKER_CHANGED`] means the marker moved, [`AGENT_STARTED`] means the agent
/// started. Both are clean refusals that changed nothing, and each earns its
/// own message.
///
/// The **root** half only: no `set` line and no `sudo -n`, because
/// [`Remote::run_fenced`] runs it inside [`crate::remote::under_lease`]'s
/// `sudo -n flock … sh -c`, already elevated and already holding the lease. So
/// the shell that stops the unit proves three things at once — the marker is
/// the one that authorized this, the agent is not running, and the lease is
/// still ours — and a competing provider cannot slip between any two of them,
/// because taking the lease over needs the `flock` this shell is holding.
fn fenced_stop_script(names: &Names, pubkey_full: &str, intent: &str) -> String {
    format!(
        "h=$(sed -n '1,{scan}p' {env} 2>/dev/null || true)\n\
         field() {{ printf '%s\\n' \"$h\" | sed -n \"s/^# $1: //p\" | head -n 1; }}\n\
         if [ \"$(field managed-by)\" != {managed_by} ] \
            || [ \"$(field agent-pubkey-full)\" != {pubkey} ] \
            || [ \"$(field create-intent)\" != {intent} ]; then\n\
           exit {changed}\n\
         fi\n\
         v=$(field binding-version)\n\
         case \"$v\" in ''|*[!0-9]*) exit {changed} ;; esac\n\
         [ \"$v\" -le {version} ] || exit {changed}\n\
         if [ \"$(systemctl is-active {unit} 2>/dev/null || true)\" = active ]; then\n\
           exit {started}\n\
         fi\n\
         systemctl disable --now {unit} 2>/dev/null || true\n\
         systemctl stop {secret_unit} 2>/dev/null || true\n",
        scan = MARKER_SCAN_LINES,
        env = sq(&names.env_path()),
        managed_by = sq(MANAGED_BY),
        version = BINDING_VERSION_NUM,
        pubkey = sq(pubkey_full),
        intent = sq(intent),
        unit = sq(&names.unit()),
        secret_unit = sq(&names.secret_unit()),
        changed = MARKER_CHANGED,
        started = AGENT_STARTED,
    )
}

/// Run the fenced stop and translate its exit code into the operator's terms.
fn fenced_stop(
    remote: &Remote,
    lease: &DeployLease<'_>,
    names: &Names,
    pubkey_full: &str,
    intent: &str,
) -> Result<(), String> {
    let out = remote.run_fenced(lease, &fenced_stop_script(names, pubkey_full, intent))?;
    match out.code {
        LOCK_UNAVAILABLE => Err(lease_lost(&names.unit())),
        MARKER_CHANGED => Err(format!(
            "{} changed while this deploy was preparing: its management marker \
             no longer matches the one that authorized the replacement. \
             Nothing was modified; run the deploy again.",
            names.env_path()
        )),
        AGENT_STARTED => Err(format!(
            "{} started while this deploy was preparing. Refusing to stop a \
             running agent (I4); nothing was modified.",
            names.unit()
        )),
        _ if out.ok() => Ok(()),
        code => Err(format!(
            "stopping the stale {} failed (exit {code}): {}",
            names.unit(),
            out.stderr.trim()
        )),
    }
}

/// Poll until the harness confirms it started, or the budget runs out.
///
/// `since_epoch` is the instance's own clock, read immediately before
/// `enable --now`, and it is what keeps a previous run's startup line from
/// confirming this attempt. Takes `cfg` only so both failure messages can print
/// the exact `gcloud` command the operator needs; a message that says "check
/// the journal" without saying how is a message nobody acts on.
fn confirm_started(
    remote: &Remote,
    names: &Names,
    cfg: &ProviderConfig,
    since_epoch: u64,
) -> Result<String, String> {
    let script = startup_script(&names.unit(), since_epoch);
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let inspect = format!(
        "gcloud compute ssh {instance} --zone {zone} --tunnel-through-iap \
         --command 'sudo journalctl -u {unit} -n 50 --no-pager'",
        instance = cfg.instance,
        zone = cfg.zone,
        unit = names.unit(),
    );
    loop {
        let out = remote.run(&script)?;
        if !out.ok() {
            return Err(format!(
                "could not read the startup state of {} (exit {}): {}",
                names.unit(),
                out.code,
                out.stderr.trim()
            ));
        }
        match parse_startup(&out.stdout) {
            Startup::Confirmed => return Ok(names.unit()),
            Startup::Failed(why) => {
                return Err(format!(
                    "{} did not start: {why}. Inspect it with `{inspect}`.",
                    names.unit()
                ))
            }
            Startup::Pending => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} did not confirm a running harness within {}s. Inspect it \
                 with `{inspect}`.",
                names.unit(),
                STARTUP_TIMEOUT.as_secs(),
            ));
        }
        std::thread::sleep(STARTUP_POLL_INTERVAL);
    }
}

/// Refuse a deploy whose harness binary is not on the instance.
///
/// `launch.command` was resolved against the desktop's PATH, which means
/// nothing here. Refusing beats deploying a unit that fails at exec. Factored
/// out because both observations ask it — the cheap pre-lease look, so the
/// refusal costs no lease, and the authoritative one, because the binary can
/// be removed between them.
fn require_harness(obs: &Observation, harness: &str, instance: &str) -> Result<(), String> {
    if obs.harness_installed {
        return Ok(());
    }
    Err(format!(
        "deploy refused: {harness} is not installed in /usr/local/bin on \
         {instance}. launch.command is resolved against the desktop's PATH, \
         which does not exist on the instance; install the harness there first."
    ))
}

/// Run one deploy to a terminal outcome.
pub fn deploy(cfg: &ProviderConfig, agent: &AgentPayload) -> Result<String, String> {
    // ---- Pure phase: no gcloud, no VM. -----------------------------------
    // Step 0: identity from the nsec, before any mutation. Everything that can
    // be refused offline is refused here, which is also what keeps the wire
    // fixtures offline.
    let identity = AgentIdentity::from_nsec(&agent.private_key_nsec)?;
    let names = Names::new(&identity);
    let generation = new_generation();
    let plan = render::plan(agent, cfg, &names, &identity, &generation)?;
    // Taken from the original payload, and identical either way: the renderer
    // rewrites `launch.command` to `/usr/local/bin/<basename>`, whose basename
    // is this same string.
    let harness = render::harness_basename(agent);

    // ---- Transport phase: the lease-free look. ----------------------------
    // Refusing an unowned file should cost nobody a lease, so a first, cheap
    // observation answers that. Nothing this deploy *acts* on comes from it: it
    // is a fast exit, not a decision.
    let remote = Remote::new(&cfg.project, &cfg.zone, &cfg.instance)?;
    let preview = observe::look(&remote, &names, &harness)?;
    require_harness(&preview, &harness, &cfg.instance)?;
    match classify(&preview, identity.pubkey_hex(), &plan.create_intent) {
        Action::Refuse(why) => return Err(why),
        // A pre-lease `NoOp` deliberately does **not** return here — round 4's
        // P2. Returning on it reported "running, here is your agent_id" from an
        // observation taken outside the lease, so an agent that a concurrent
        // `remove` had just stopped, or that had crashed, was reported as a
        // healthy success. A refusal is conservative and changes nothing, which
        // is why it keeps its fast exit; a success is a claim, and this
        // provider makes claims from the authoritative observation only.
        Action::NoOp | Action::Create | Action::RestartSame | Action::FencedReplace => {}
    }

    // ---- Mutating window, serialized per agent. ---------------------------
    // The lease comes **before** the observation this deploy acts on. The
    // previous ordering observed and classified first and then took the lease
    // and acted on that pre-lease verdict, so a deploy could see
    // "absent/stopped", lose the race, and mutate on state that had already
    // moved. `lease.observe` is the only way to reach the authoritative
    // observation, so the ordering is enforced by the type rather than by the
    // order two statements happen to be written in. The block is entered even
    // for a no-op, because that is the only way the no-op is answered from
    // state no other provider can be changing. The lease is released at the end
    // of this block rather than after `confirm_started`, because the poll
    // mutates nothing and may run for four minutes.
    let started_at = {
        let lease = acquire_lease(&remote, &names)?;
        let obs = lease.observe(&names, &harness)?;
        require_harness(&obs, &harness, &cfg.instance)?;

        // Matched by reference so `action` survives for the two comparisons
        // below. Taking it by value here would move it.
        let action = classify(&obs, identity.pubkey_hex(), &plan.create_intent);
        match &action {
            Action::Refuse(why) => return Err(why.clone()),
            // The only place a no-op is answered. Under the lease, "live"
            // cannot be stale with respect to another provider: nobody else
            // can stop this unit while we hold the record, because `remove`
            // and `deploy` both take it and every stop is fenced on it. What
            // remains stale is the agent crashing on its own, or a root user
            // on the instance stopping it — bounded by the microseconds
            // between this classification and the return, and irreducible:
            // no observation is true after it is taken.
            Action::NoOp => return Ok(names.unit()),
            Action::Create | Action::RestartSame | Action::FencedReplace => {}
        }

        // Overcommit is reported, never vetoed — but stderr is dropped by the
        // desktop on the success path, so the durable copy below is the one an
        // operator can actually find (§Capacity). Computed from the
        // authoritative observation, which is also the freshest one.
        let warnings = capacity::warning_lines(
            obs.available_bytes,
            obs.reserved_bytes,
            &names.unit(),
            cfg.memory_max_bytes,
        );
        for warning in &warnings {
            eprintln!("{warning}");
        }

        if action == Action::FencedReplace {
            // The fence re-reads the marker that *authorized* this
            // replacement — the one the observation above carries — not the
            // one this deploy is about to write. A divergent intent is what
            // makes a replacement a replacement, so comparing against
            // `plan.create_intent` would refuse every legitimate one. An
            // unreadable marker here yields `""`, which the fence treats as a
            // mismatch and refuses cleanly; `FencedReplace` cannot be reached
            // without one, so the fallback is unreachable rather than lossy.
            let authorizing_intent = obs
                .markers
                .env
                .marker
                .as_ref()
                .map_or("", |marker| marker.create_intent.as_str());
            fenced_stop(
                &remote,
                &lease,
                &names,
                identity.pubkey_hex(),
                authorizing_intent,
            )?;
        }

        // Shared artifacts are repaired on every acting path, `RestartSame`
        // included. Zero mutation is I4's requirement for a *live* instance,
        // not for a stopped one — and the agent unit `Requires=` the fetcher
        // unit, so a shared template deleted out of band is a start failure
        // that re-entry would otherwise never converge on. Written before the
        // per-agent files because the agent unit depends on them. No `renew`
        // ahead of the loop: each install proves and refreshes the lease inside
        // its own shell, which is strictly stronger than a renewal that
        // preceded it by a round trip.
        for file in shared_writes(&plan, &obs) {
            remote.install(file, &lease)?;
        }

        if action != Action::RestartSame {
            // The one standalone renewal left in the window. Everything else
            // here proves the lease from inside its own shell, but
            // `instance_service_account` and `store` are `gcloud` calls from
            // *this* machine against Secret Manager — a service the instance's
            // lock knows nothing about — so no fenced shell covers them. They
            // stay here because the instance's service account holds per-secret
            // `secretAccessor` only, deliberately: moving them onto the VM to
            // get them under the lock would hand a compromised instance the
            // ability to mint and read every agent's secret. Renewing first at
            // least means a deploy that has already lost the lease stops before
            // it adds a version, and every step after this one is fenced, so a
            // deploy that loses it *during* the call cannot start an agent
            // against what it added.
            lease.renew()?;
            let service_account =
                secrets::instance_service_account(&remote, &cfg.project, &cfg.zone, &cfg.instance)?;
            secrets::store(
                &remote,
                &cfg.project,
                &names.secret_name(),
                identity.pubkey_hex(),
                &plan.secret_body(),
                &service_account,
            )?;
            for file in &plan.per_agent {
                remote.install(file, &lease)?;
            }
        }
        // `RestartSame` skipping the secret is sound only because the intent
        // covers a digest of the secret payload (`render::plan`): a rotated
        // credential diverges the intent, so this branch is unreachable for one
        // and no agent is ever restarted against a stale secret version.

        // The durable record, written before the start attempt so a deploy that
        // then fails to start still leaves its capacity warning behind. Fenced
        // like every other write, so it needs no renewal ahead of it.
        remote.append(
            &plan.trail,
            &capacity::trail_record(
                &capacity::now_rfc3339(),
                &generation,
                &plan.create_intent,
                &warnings,
            ),
            &lease,
        )?;

        // The instance's own clock, printed after the reload and before the
        // start, is what bounds the startup query. It cannot be read on this
        // machine: the two clocks are unrelated. Fenced like every other
        // mutation, and this is the one that matters most — `enable --now`
        // starts an agent, and a provider that has lost the lease must not
        // start one over the winner's files.
        let out = remote.run_fenced(
            &lease,
            &format!(
                "set -e\n\
                 systemctl daemon-reload\n\
                 echo '---STARTEDAT---'\n\
                 date +%s\n\
                 echo '---START---'\n\
                 systemctl enable --now {unit}\n",
                unit = sq(&names.unit()),
            ),
        )?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(lease_lost(&names.unit()));
        }
        if !out.ok() {
            return Err(format!(
                "starting {} failed (exit {}): {}",
                names.unit(),
                out.code,
                out.stderr.trim()
            ));
        }
        section(&out.stdout, "STARTEDAT")
            .trim()
            .parse::<u64>()
            .map_err(|_| {
                format!(
                    "{} was started, but the instance's clock could not be read \
                     alongside it, so this deploy cannot bound the journal to \
                     its own attempt. Check the unit with `systemctl status {}`.",
                    names.unit(),
                    names.unit()
                )
            })?
    };

    confirm_started(&remote, &names, cfg, started_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::AgentMarker;
    use crate::observe::{
        AgentFileState, MarkerState, SharedFileState, SystemdState, SHARED_PATHS,
    };

    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const INTENT: &str = "c0ffee";

    const ENV_PATH: &str = "/etc/buzz/acp-a1b2c3d4e5f6.env";
    /// The env file's three siblings, in the order `observe::agent_paths`
    /// reports them after it: agent drop-in, fetcher drop-in, trail.
    const SIBLING_PATHS: [&str; 3] = [
        "/etc/systemd/system/buzz-acp@a1b2c3d4e5f6.service.d/agent.conf",
        "/etc/systemd/system/buzz-acp-secret@a1b2c3d4e5f6.service.d/agent.conf",
        "/etc/buzz/acp-a1b2c3d4e5f6.trail",
    ];

    fn pubkey() -> String {
        AgentIdentity::from_nsec(NSEC)
            .unwrap()
            .pubkey_hex()
            .to_string()
    }

    fn healthy_shared() -> Vec<SharedFileState> {
        SHARED_PATHS
            .iter()
            .map(|path| SharedFileState {
                path: (*path).to_string(),
                present: true,
                ownership: Ownership::Ours,
                sha256: format!("hash-{path}"),
            })
            .collect()
    }

    fn ours(intent: &str) -> Option<AgentMarker> {
        Some(AgentMarker {
            pubkey_full: pubkey(),
            create_intent: intent.to_string(),
        })
    }

    /// `(unit_file_state, active_state, main_pid)` -> a systemd view.
    fn systemd(unit_file_state: &str, active_state: &str, main_pid: u32) -> SystemdState {
        SystemdState {
            load_state: "loaded".to_string(),
            active_state: active_state.to_string(),
            sub_state: String::new(),
            unit_file_state: unit_file_state.to_string(),
            main_pid,
        }
    }

    /// The healthy fixture is a **coherent** four-artifact set: the siblings
    /// mirror whatever the env file carries.
    ///
    /// Round 4's P1-3 is why. The helper used to leave all three siblings
    /// absent, which is not a steady state at all — it is a torn install — and
    /// `classify` now says so. Tests that exercise the per-artifact fence
    /// still overwrite the one entry they care about and say what is wrong
    /// with it.
    fn obs(systemd: SystemdState, env_present: bool, marker: Option<AgentMarker>) -> Observation {
        let siblings = SIBLING_PATHS
            .iter()
            .map(|path| AgentFileState {
                path: (*path).to_string(),
                present: marker.is_some(),
                ownership: if marker.is_some() {
                    Ownership::Ours
                } else {
                    Ownership::NotOurs
                },
                marker: marker.clone(),
            })
            .collect();
        Observation {
            systemd,
            markers: MarkerState {
                env: AgentFileState {
                    path: ENV_PATH.to_string(),
                    present: env_present,
                    // The pair is not redundant: `ownership` is the version
                    // half and `marker` the identity half, and a file can
                    // carry ours at this version while its identity lines are
                    // missing. A `Some` marker does imply an actionable
                    // ownership, though, so the helper keeps them consistent.
                    ownership: if marker.is_some() {
                        Ownership::Ours
                    } else {
                        Ownership::NotOurs
                    },
                    marker,
                },
                siblings,
                shared: healthy_shared(),
            },
            harness_installed: true,
            reserved_bytes: 0,
            available_bytes: u64::MAX,
        }
    }

    #[test]
    fn an_absent_agent_is_created() {
        let o = obs(systemd("disabled", "inactive", 0), false, None);
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);
    }

    /// I4: a deploy against a running agent must not mutate anything. Without
    /// this, every Start click bounces a healthy agent.
    #[test]
    fn a_live_agent_is_a_strict_no_op() {
        let o = obs(systemd("enabled", "active", 4242), true, ours(INTENT));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::NoOp);
    }

    /// Reconfiguring a *running* agent is out of scope: I4 puts
    /// at-most-one-live-instance above convergence. The operator stops it first.
    #[test]
    fn a_live_agent_with_divergent_intent_is_still_a_no_op() {
        let o = obs(systemd("enabled", "active", 4242), true, ours("stale"));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::NoOp);
    }

    #[test]
    fn a_stopped_agent_with_the_same_intent_is_restarted_not_replaced() {
        let o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::RestartSame);
    }

    #[test]
    fn a_stopped_agent_with_a_divergent_intent_is_fence_replaced() {
        let o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// Round 1's P1-5 case: a real unit with no env file must never classify as
    /// `Create`, or the provider installs its files around somebody else's unit.
    #[test]
    fn a_known_instance_with_no_marker_is_refused_never_created() {
        let o = obs(systemd("enabled", "inactive", 0), false, None);
        let action = classify(&o, &pubkey(), INTENT);
        assert!(matches!(action, Action::Refuse(_)), "got {action:?}");
        let Action::Refuse(why) = action else {
            unreachable!()
        };
        assert!(why.contains(MANAGED_BY), "{why}");
    }

    #[test]
    fn an_unmarked_env_file_is_refused_never_overwritten() {
        let o = obs(systemd("disabled", "inactive", 0), true, None);
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a present, unmarked env file must never be overwritten")
        };
        assert!(
            why.contains(ENV_PATH),
            "the refusal must name the file: {why}"
        );
    }

    /// The 12-hex name is collision-resistant, not collision-free.
    #[test]
    fn a_short_name_collision_is_refused() {
        let foreign = Some(AgentMarker {
            pubkey_full: "ff".repeat(32),
            create_intent: INTENT.to_string(),
        });
        let o = obs(systemd("enabled", "inactive", 0), true, foreign);
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a foreign pubkey must not be adopted")
        };
        assert!(why.contains("collision"), "{why}");
        assert!(why.contains(ENV_PATH), "{why}");
    }

    /// P1-4's exact case. `FencedReplace` rewrites all four per-agent files and
    /// `remove` deletes all four, so authorizing that from the env file's
    /// header alone destroys a hand-written drop-in no fence ever looked at.
    #[test]
    fn a_marked_env_file_does_not_authorize_writing_an_unmarked_sibling() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        o.markers.siblings[0].present = true;
        o.markers.siblings[0].ownership = Ownership::NotOurs;
        o.markers.siblings[0].marker = None;
        let action = classify(&o, &pubkey(), INTENT);
        let Action::Refuse(why) = action else {
            panic!("an unmarked sibling must stop the deploy, got {action:?}")
        };
        assert!(
            why.contains(SIBLING_PATHS[0]),
            "the refusal must name the offending file: {why}"
        );
        assert!(
            !why.contains(ENV_PATH),
            "the env file is fine; naming it sends the operator to the wrong \
             place: {why}"
        );
    }

    /// …and a sibling belonging to a *different* agent is a refusal for a
    /// different reason, so the two messages must not be interchangeable.
    #[test]
    fn a_sibling_belonging_to_another_agent_is_refused_by_name() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        o.markers.siblings[2].present = true;
        o.markers.siblings[2].ownership = Ownership::Ours;
        o.markers.siblings[2].marker = Some(AgentMarker {
            pubkey_full: "ff".repeat(32),
            create_intent: "stale".to_string(),
        });
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a foreign sibling must stop the deploy")
        };
        assert!(why.contains(SIBLING_PATHS[2]), "{why}");
        assert!(why.contains("collision"), "{why}");
    }

    /// All four present and all four ours is the ordinary replace — the fence
    /// must not be so strict that a legitimate reconfiguration cannot proceed.
    #[test]
    fn every_per_agent_file_marked_for_this_agent_is_a_fenced_replace() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours("stale"));
        for sibling in &mut o.markers.siblings {
            sibling.present = true;
            sibling.ownership = Ownership::Ours;
            sibling.marker = ours("stale");
        }
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// Round 4's P1-3. The env install lands, a later per-agent install fails
    /// on a dropped SSH, and the retry sees a **new** create-intent on the env
    /// marker beside surviving **old** siblings that are still ours and still
    /// this agent's. Comparing only the env marker returned `RestartSame`,
    /// which skips `secrets::store` and every per-agent install and starts the
    /// unit against stale drop-ins — a stale `project` among them, pointing
    /// the fetcher at the wrong Secret Manager project. A torn install is a
    /// replace.
    #[test]
    fn a_torn_install_is_replaced_not_restarted() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        for sibling in &mut o.markers.siblings {
            sibling.marker = ours("the-intent-before-this-one");
        }
        // Every artifact is present, ours, and this agent's — the refusal loop
        // has nothing to say — and the env marker matches the request exactly.
        // Only the siblings' *intent* disagrees.
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// The other half of a torn install: the write never happened at all, so
    /// the sibling is simply missing. `RestartSame` would start the unit with
    /// a drop-in that does not exist.
    #[test]
    fn a_missing_sibling_is_replaced_not_restarted() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        o.markers.siblings[1].present = false;
        o.markers.siblings[1].ownership = Ownership::NotOurs;
        o.markers.siblings[1].marker = None;
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);
    }

    /// A shared file with our name but no provider marker is somebody else's.
    #[test]
    fn an_unmarked_shared_file_is_refused() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[0].ownership = Ownership::NotOurs;
        let action = classify(&o, &pubkey(), INTENT);
        assert!(matches!(action, Action::Refuse(_)), "got {action:?}");
    }

    /// A *marked* shared file whose bytes differ from ours is an older
    /// rendering of ours and is upgraded in place. There is deliberately no
    /// third verdict: nothing in the file claims what its own content should
    /// be, so there is nothing for the content to disagree with (`naming.rs`).
    #[test]
    fn a_marked_shared_file_with_different_bytes_is_not_a_refusal() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[1].sha256 = "an-older-rendering".to_string();
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);
    }

    /// P1-1, the shared half: a template unit this provider wrote at an older
    /// binding version takes the ordinary write-if-different path. It is not a
    /// refusal — refusing it would stop every deploy on the box the moment the
    /// version bumped, on files this provider itself installed.
    #[test]
    fn a_shared_file_from_an_older_binding_version_is_rewritten_not_refused() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[1].ownership = Ownership::OursButOlder(0);
        o.markers.shared[1].sha256 = "the-version-0-rendering".to_string();
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);

        let plan = plan_with_shared([
            "hash-/etc/systemd/system/buzz-acp@.service",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        let writes = shared_writes(&plan, &o);
        assert_eq!(writes.len(), 1, "the older rendering must be rewritten");
        assert_eq!(writes[0].path, SHARED_PATHS[1]);
    }

    /// …and a shared file from a *newer* one is the refusal the version rule
    /// reserves, with that version named. Overwriting it would downgrade a
    /// template every other instance on the box is running against.
    #[test]
    fn a_shared_file_from_a_future_binding_version_is_refused_by_version() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[0].ownership = Ownership::OursButNewer(99);
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a newer provider's template must not be downgraded")
        };
        assert!(why.contains(SHARED_PATHS[0]), "{why}");
        assert!(
            why.contains("99"),
            "the refusal must name the version: {why}"
        );
        assert!(
            !why.contains("somebody else's file"),
            "a newer build of this provider is not a stranger: {why}"
        );
    }

    /// P1-1, the per-agent half. `BINDING_VERSION` is documented as
    /// "bump when the unit/env shape changes" — a designed-for event — and the
    /// conjunction it used to sit in made every artifact written before the
    /// bump read as *present and not ours*: `classify` refused, so `deploy`
    /// could not upgrade the agent, and `verify_removable` refused
    /// identically, so `remove` could not tear it down. An older version is an
    /// authorised upgrade target, and it forces a replace even when the
    /// recorded intent still matches, because the intent says the inputs did
    /// not change — not that the artifact layout is current.
    #[test]
    fn a_prior_version_agent_is_upgraded_not_refused() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        o.markers.env.ownership = Ownership::OursButOlder(0);
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::FencedReplace);

        // A live one is still a strict no-op: I4 puts at-most-one-live-instance
        // above convergence, and an upgrade is convergence.
        let mut live = obs(systemd("enabled", "active", 4242), true, ours(INTENT));
        live.markers.env.ownership = Ownership::OursButOlder(0);
        assert_eq!(classify(&live, &pubkey(), INTENT), Action::NoOp);
    }

    /// …and a per-agent artifact from a *future* binding version is refused,
    /// naming the version rather than calling the operator's own agent
    /// foreign.
    #[test]
    fn a_future_version_artifact_is_refused_with_its_version_named() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, None);
        o.markers.env.ownership = Ownership::OursButNewer(99);
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("a layout this build cannot read must not be overwritten")
        };
        assert!(why.contains(ENV_PATH), "{why}");
        assert!(why.contains("99"), "{why}");
        assert!(why.contains(BINDING_VERSION), "{why}");
    }

    /// A file carrying our provider marker but no identity line is its own
    /// refusal, and it must not read as "somebody else's file": the operator
    /// needs to know the marker is ours and the identity is missing.
    #[test]
    fn our_marker_without_an_identity_line_is_refused_by_name() {
        let mut o = obs(systemd("enabled", "inactive", 0), true, None);
        o.markers.env.ownership = Ownership::Ours;
        let Action::Refuse(why) = classify(&o, &pubkey(), INTENT) else {
            panic!("an unidentifiable per-agent file must stop the deploy")
        };
        assert!(why.contains(ENV_PATH), "{why}");
        assert!(why.contains("agent-pubkey-full"), "{why}");
    }

    /// A missing shared file is normal on a first deploy, not a refusal.
    #[test]
    fn absent_shared_files_are_not_a_refusal() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        for shared in &mut o.markers.shared {
            shared.present = false;
            shared.ownership = Ownership::NotOurs;
            shared.sha256 = String::new();
        }
        assert_eq!(classify(&o, &pubkey(), INTENT), Action::Create);
    }

    fn shared_artifact(path: &str, sha256: &str) -> crate::render::SharedArtifact {
        crate::render::SharedArtifact {
            file: RemoteFile {
                path: path.to_string(),
                mode: "0644",
                body: String::new(),
                owner_marker: Vec::new(),
            },
            sha256: sha256.to_string(),
        }
    }

    fn plan_with_shared(hashes: [&str; 3]) -> Plan {
        Plan {
            per_agent: Vec::new(),
            shared: SHARED_PATHS
                .iter()
                .zip(hashes)
                .map(|(path, sha256)| shared_artifact(path, sha256))
                .collect(),
            secret_env: std::collections::BTreeMap::new(),
            create_intent: INTENT.to_string(),
            trail: RemoteFile {
                path: SIBLING_PATHS[2].to_string(),
                mode: "0644",
                body: String::new(),
                owner_marker: Vec::new(),
            },
        }
    }

    /// The strict no-op is only strict if a deploy that changes nothing shared
    /// performs **zero** writes there.
    #[test]
    fn matching_shared_files_are_not_rewritten() {
        let o = obs(systemd("enabled", "inactive", 0), true, ours(INTENT));
        let plan = plan_with_shared([
            "hash-/etc/systemd/system/buzz-acp@.service",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        assert!(shared_writes(&plan, &o).is_empty());
    }

    #[test]
    fn an_absent_shared_file_is_written() {
        let mut o = obs(systemd("disabled", "inactive", 0), false, None);
        o.markers.shared[2].present = false;
        o.markers.shared[2].ownership = Ownership::NotOurs;
        o.markers.shared[2].sha256 = String::new();
        let plan = plan_with_shared([
            "hash-/etc/systemd/system/buzz-acp@.service",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        let writes = shared_writes(&plan, &o);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, SHARED_PATHS[2]);
    }

    /// A shared file present with different bytes is an older rendering of
    /// ours and is upgraded in place.
    #[test]
    fn a_stale_shared_file_is_rewritten() {
        let o = obs(systemd("disabled", "inactive", 0), false, None);
        let plan = plan_with_shared([
            "brand-new-hash",
            "hash-/etc/systemd/system/buzz-acp-secret@.service",
            "hash-/usr/local/sbin/buzz-acp-fetch-key",
        ]);
        let writes = shared_writes(&plan, &o);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, SHARED_PATHS[0]);
    }

    /// One startup poll's stdout. `journal` is the count of matching harness
    /// lines the *scoped* query returned.
    fn poll(active: &str, main_pid: u32, result: &str, journal: u32) -> String {
        format!(
            "---UNIT---\nActiveState={active}\nMainPID={main_pid}\nResult={result}\n\
             InvocationID=1c1b0c1b0c1b0c1b0c1b0c1b0c1b0c1b\n\
             ---JOURNAL---\n{journal}\n---END---\n"
        )
    }

    #[test]
    fn a_confirmed_start_needs_a_live_pid_and_the_harness_line() {
        assert_eq!(
            parse_startup(&poll("active", 4242, "success", 1)),
            Startup::Confirmed
        );
    }

    /// systemd calling the unit `active` is not the harness having started —
    /// I4's "live" means the process is confirmed running.
    #[test]
    fn an_active_unit_without_the_harness_line_is_still_pending() {
        assert_eq!(
            parse_startup(&poll("active", 4242, "success", 0)),
            Startup::Pending
        );
        assert_eq!(
            parse_startup(&poll("activating", 0, "success", 0)),
            Startup::Pending
        );
    }

    /// A failed unit must end the poll immediately: burning the whole budget
    /// on a unit systemd has already given up on wastes four minutes and
    /// produces a worse error.
    #[test]
    fn a_failed_unit_ends_the_poll_immediately() {
        let Startup::Failed(why) = parse_startup(&poll("failed", 0, "exit-code", 0)) else {
            panic!("a failed unit must not read as pending")
        };
        assert!(why.contains("exit-code"), "{why}");
    }

    /// P1-2, both halves. The scoping has to live in the **query**: a poll that
    /// grepped a fixed lookback window would be satisfied by the previous run's
    /// `buzz-acp starting:` line, and `parse_startup` could never tell the
    /// difference. With the query scoped, a unit that is up with a live PID
    /// from an earlier run returns zero matches and stays `Pending`.
    #[test]
    fn a_prior_runs_startup_line_cannot_confirm_this_attempt() {
        let script = startup_script("buzz-acp@a1b2c3d4e5f6.service", 1_754_384_042);
        assert!(script.contains("_SYSTEMD_INVOCATION_ID="), "{script}");
        assert!(script.contains("@1754384042"), "{script}");
        assert!(
            !script.contains("-30 min"),
            "a fixed lookback window admits the previous run's line: {script}"
        );
        assert_eq!(
            parse_startup(&poll("active", 4242, "success", 0)),
            Startup::Pending
        );
    }

    /// P1-8: the mutating window is serialized per agent, the holder is
    /// identifiable, and an abandoned lease expires rather than wedging the
    /// instance. P2-3 adds the record's own controls: a private directory, a
    /// root-owned regular file, and a future timestamp read as corrupt.
    #[test]
    fn the_deploy_lease_is_per_agent_identifiable_and_bounded() {
        let script = acquire_lease_script("a1b2c3d4e5f6", "tok3n");
        assert!(
            script.contains("a1b2c3d4e5f6"),
            "the lease is per agent: {script}"
        );
        assert!(script.contains("flock"), "{script}");
        assert!(
            script.contains("tok3n"),
            "the holder is identifiable: {script}"
        );
        assert!(
            script.contains(&LOCK_UNAVAILABLE.to_string()),
            "a loser must exit with the code the caller can explain: {script}"
        );
        assert!(
            script.contains(&DEPLOY_LEASE_SECONDS.to_string()),
            "an abandoned lease must expire: {script}"
        );
        // The record lives in a private directory of our own, not loose under
        // the world-readable /run/lock.
        assert!(script.contains(LEASE_DIR), "{script}");
        assert!(!script.contains("/run/lock"), "{script}");
        assert!(
            script.contains("install -d -m 0700 -o root -g root"),
            "the directory must be created private, and repaired if it is not: \
             {script}"
        );
        // A record that is not a root-owned regular file is not a lease
        // record, and a clock that moved backwards must not grant one either.
        assert!(script.contains("stat -c %u"), "{script}");
        assert!(
            script.contains("-L"),
            "a symlink is not a lease record: {script}"
        );
        assert!(
            script.contains("-ge 0"),
            "a future-dated record must read as corrupt, not fresh: {script}"
        );
        // Release must never steal: it clears the record only if we hold it.
        let release = release_lease_script("a1b2c3d4e5f6", "tok3n");
        assert!(release.contains("tok3n"), "{release}");
        assert!(release.contains("rm -f"), "{release}");
    }

    /// P2-1: the TTL must exceed every enforced lifetime, or a slow-but-live
    /// holder ages out and a second deploy starts mutating the same agent
    /// while the first is still writing.
    #[test]
    fn the_lease_outlives_the_desktops_deploy_budget() {
        // The desktop kills the provider at 600 s (`backend.rs:528`), and the
        // startup poll — which runs *after* the lease is released — is 240 s.
        const { assert!(DEPLOY_LEASE_SECONDS > 600) };
        const { assert!(DEPLOY_LEASE_SECONDS > STARTUP_TIMEOUT.as_secs()) };
    }

    /// P1-4: nothing this deploy acts on is observed before the lease exists.
    /// The authoritative observation hangs off the guard
    /// (`DeployLease::observe`), so it is unreachable without one — the
    /// compiler enforces the ordering, not a convention about statement order
    /// — and its first act is this verify-then-refresh of the owner record, so
    /// a lease silently lost between acquire and observe stops the deploy
    /// instead of feeding it stale state.
    #[test]
    fn the_authoritative_observation_cannot_run_without_a_held_lease() {
        let script = renew_lease_script("a1b2c3d4e5f6", "tok3n");
        assert!(
            script.contains("tok3n"),
            "the record must name us: {script}"
        );
        assert!(
            script.contains(&LOCK_UNAVAILABLE.to_string()),
            "losing the lease must stop the deploy, not warn: {script}"
        );
        // The whole critical section is `sq`-wrapped as the argument to
        // `sudo -n flock … sh -c`, so match on fragments that carry no single
        // quotes of their own — or wrap the needle with `nested`.
        let verify = script.find("cut -d").expect("the holder check");
        let refresh = script.rfind("printf").expect("the refreshed record");
        assert!(
            verify < refresh,
            "the renewal must prove the holder before it extends the lease: \
             {script}"
        );
    }

    /// P1-8's other half: the re-read that authorizes the stop runs in the same
    /// shell as the stop. A fence in one round trip and a `disable --now` in
    /// the next is a TOCTOU with more steps.
    #[test]
    fn the_destructive_fence_and_the_stop_share_one_shell() {
        let names = Names::from_pubkey_hex(&pubkey()).unwrap();
        let script = fenced_stop_script(&names, &pubkey(), INTENT);
        assert!(script.contains(&sq(&names.env_path())), "{script}");
        assert!(
            script.contains(INTENT),
            "the intent is re-compared: {script}"
        );
        // The version is an ordering here too: `FencedReplace` is exactly what
        // a prior-version artifact classifies as, so an exact match would make
        // the fence refuse every upgrade it exists to authorize.
        assert!(
            script.contains(&format!("-le {BINDING_VERSION_NUM}")),
            "{script}"
        );
        assert!(
            !script.contains(&format!("!= {}", sq(BINDING_VERSION))),
            "an exact binding-version compare re-creates the upgrade lockout: \
             {script}"
        );
        assert!(
            script.contains("is-active"),
            "the running state is re-checked: {script}"
        );
        let reread = script
            .find("agent-pubkey-full")
            .expect("the marker re-read");
        let stop = script.find("disable --now").expect("the stop");
        assert!(
            reread < stop,
            "the re-read must precede the stop it authorizes: {script}"
        );
    }

    /// A needle as it appears once a critical section has been `sq`-wrapped
    /// for `sh -c`: every single quote becomes `'\''`. Asserting on the
    /// wrapped form is the honest way to check a nested script — the
    /// alternative is asserting on fragments that happen to carry no quotes,
    /// which silently stops covering the interesting ones.
    fn nested(fragment: &str) -> String {
        fragment.replace('\'', r"'\''")
    }

    /// Round 4's P1-1. Every remote mutation carries the lease proof inside
    /// its own shell — not in a round trip that preceded it — so a lease lost
    /// or taken over while this provider was stalled *prevents* the write
    /// rather than being noticed afterwards.
    #[test]
    fn every_mutating_script_proves_the_lease_in_its_own_shell() {
        let names = Names::from_pubkey_hex(&pubkey()).unwrap();
        let (lock, owner) = lease_paths(names.instance());
        let fenced = [
            under_lease(names.instance(), "tok3n", "systemctl daemon-reload\n"),
            renew_lease_script(names.instance(), "tok3n"),
        ];
        for script in &fenced {
            assert!(script.contains(&sq(&lock)), "no lock is taken: {script}");
            assert!(
                script.contains(&nested(&sq(&owner))),
                "the owner record is not read: {script}"
            );
            assert!(
                script.contains("tok3n"),
                "the record must name us: {script}"
            );
            assert!(
                script.contains(&LOCK_UNAVAILABLE.to_string()),
                "a lost lease must exit with the code the caller explains: \
                 {script}"
            );
            // One elevation for the whole critical section: the lock lives in
            // a `0700 root:root` directory, so `flock` has to be root before
            // it can open it, and everything it runs is root already.
            assert!(
                script.contains("sudo -n flock -w"),
                "the critical section is not elevated as one: {script}"
            );
        }
    }

    /// …and the proof and the mutation cannot be separated, because they are
    /// one `sh -c` argument. A takeover needs the same `flock` this shell
    /// holds, so no second provider can slip between the check and the write
    /// however long this one stalls.
    #[test]
    fn the_lease_proof_and_the_mutation_cannot_be_separated() {
        let names = Names::from_pubkey_hex(&pubkey()).unwrap();
        let (_, owner) = lease_paths(names.instance());
        let script = under_lease(
            names.instance(),
            "tok3n",
            &fenced_stop_script(&names, &pubkey(), INTENT),
        );
        let gate = script.find("cut -d").expect("the holder check");
        // The gate's own redirect, not just any `printf`: the stop script has
        // a `printf` of its own inside `field()`.
        let refresh = script
            .find(&nested(&format!("> {}", sq(&owner))))
            .expect("the refreshed record");
        let stop = script.find("disable --now").expect("the stop");
        assert!(
            gate < refresh && refresh < stop,
            "prove the holder, refresh, then act — in that order: {script}"
        );
        // One shell: everything after the wrapper's opening quote is a single
        // argument to `sh -c`, so there is no round trip to stall inside.
        let opener = script.find("sh -c '").expect("the critical section");
        assert!(opener < gate, "the gate is outside the wrapper: {script}");
        assert_eq!(
            script.matches("sh -c '").count(),
            1,
            "a second shell is a second chance to lose the lease: {script}"
        );
    }

    /// The two refusals must not be confused. "Somebody else's file" tells the
    /// operator to move a file aside; "the lease moved" tells them to re-run.
    /// Acting on the first when the second is true is how an operator deletes
    /// a healthy artifact.
    #[test]
    fn a_lost_lease_reads_as_a_lease_loss_not_an_ownership_refusal() {
        let message = lease_lost("buzz-acp@a1b2c3d4e5f6.service");
        assert!(
            message.contains("buzz-acp@a1b2c3d4e5f6.service"),
            "{message}"
        );
        assert!(message.contains("Nothing was written"), "{message}");
        assert!(message.contains("Re-run"), "{message}");
        assert!(
            !message.contains("Move it aside"),
            "that is the ownership refusal's remedy, and it is the wrong one \
             here: {message}"
        );
    }
}
