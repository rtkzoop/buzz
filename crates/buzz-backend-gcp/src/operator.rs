//! Operator-facing commands (spec §Operator Surface).
//!
//! Not protocol operations: the desktop invokes this binary with **no**
//! arguments, so anything on argv is a human. These exist because the protocol
//! has no `stop` — I5 routes intentional termination through `!shutdown` on the
//! relay — and because a success-path capacity warning has nowhere else to go.

use crate::config::{self, ProviderConfig};
use crate::naming::{self, Names, Ownership, MANAGED_BY};
use crate::observe::{self, AgentFileState};
use crate::reconcile::acquire_lease;
use crate::remote::{lease_lost, marker_fn, sq, Remote, LOCK_UNAVAILABLE, MARKER_SCAN_LINES};
use crate::secrets;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "buzz-backend-gcp",
    about = "GCE/systemd backend provider for Buzz remote agents"
)]
pub struct Cli {
    #[arg(long, default_value = config::DEFAULT_PROJECT)]
    pub project: String,
    #[arg(long, default_value = config::DEFAULT_ZONE)]
    pub zone: String,
    #[arg(long, default_value = config::DEFAULT_INSTANCE)]
    pub instance: String,
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List the agent units this provider manages, with every capacity
    /// warning recorded in their deploy trails.
    List,
    /// Stop, disable, destroy the secret, then delete this agent's own files.
    Remove {
        /// The `agent_id` the desktop recorded, e.g. `buzz-acp@a1b2c3d4e5f6`.
        agent_id: String,
        /// The agent's full 64-hex pubkey, as printed by `list`.
        ///
        /// Required, not optional: `managed-by` proves only that this provider
        /// wrote a file, never *which* agent it belongs to, and the 12-hex
        /// name is collision-resistant rather than collision-free.
        #[arg(long)]
        pubkey: String,
    },
    /// Render a deploy request read from stdin, secrets redacted, touching
    /// nothing.
    DryRun,
}

/// Dispatch one operator command.
///
/// `Cli` is destructured before matching, so the subcommand can be moved out
/// while `project`/`zone`/`instance` stay usable — matching on `cli.command`
/// with `&cli` borrowed afterwards does not compile.
pub fn run(cli: Cli) -> Result<(), String> {
    let Cli {
        project,
        zone,
        instance,
        command,
    } = cli;
    match command {
        Cmd::List => {
            let remote = Remote::new(&project, &zone, &instance)?;
            list(&remote)
        }
        Cmd::Remove { agent_id, pubkey } => {
            let remote = Remote::new(&project, &zone, &instance)?;
            remove(&remote, &project, &agent_id, &pubkey)
        }
        // No transport: `dry-run` exists to be safe to run anywhere.
        Cmd::DryRun => dry_run(),
    }
}

/// Extract the 12-hex instance from an `agent_id`.
fn instance_of(agent_id: &str) -> Result<String, String> {
    let malformed = || {
        format!(
            "{agent_id:?} is not a buzz-acp agent id. Expected \
             buzz-acp@<12 lowercase hex>[.service], as returned by deploy and \
             printed by `list`."
        )
    };
    let rest = agent_id
        .trim()
        .strip_prefix("buzz-acp@")
        .ok_or_else(malformed)?;
    let instance = rest.strip_suffix(".service").unwrap_or(rest);
    if instance.len() != 12
        || !instance
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed());
    }
    Ok(instance.to_string())
}

/// Resolve and cross-check the operator's two identifiers.
///
/// Both are caller-supplied, so neither is trusted alone: the pubkey is
/// validated to 64 hex and must *derive* the instance the agent id names.
fn resolve_target(agent_id: &str, pubkey: &str) -> Result<(Names, String), String> {
    let instance = instance_of(agent_id)?;
    let pubkey = naming::normalize_pubkey(pubkey)?;
    if pubkey[..12] != instance {
        return Err(format!(
            "the supplied pubkey does not begin with {instance}, so it does not \
             name {agent_id}. Copy the pubkey `list` prints on that unit's row."
        ));
    }
    Ok((Names::from_pubkey_hex(&pubkey)?, pubkey))
}

/// The remote script `list` runs.
///
/// Three independent enumerations, unioned: the env-file glob, the units
/// systemd knows about, and the drop-in directories. Keying off
/// `/etc/buzz/acp-*.env` alone is what turned a deleted env file into a ghost
/// — a running, secret-bearing agent that `list` could not see and `remove`
/// declared absent.
///
/// The pubkey is read from whichever per-agent artifact still carries a marker
/// **at a binding version this build may act on** — its own, or an older one.
/// All four carry the same tuple, so losing one costs nothing; losing all four
/// flags the row and sends the operator to Secret Manager, which holds the same
/// value as an annotation (Task 10). Requiring an *exact* `binding-version`
/// match here was the third face of round 3's P1-1: a version bump would have
/// hidden every agent already on the box behind `<pubkey unknown>`, and the
/// pubkey `remove` needs is the one `list` prints.
///
/// The instance-name `case` is not decoration: these ids come from a filesystem
/// glob and from `systemctl` output, and every one of them is about to be
/// interpolated into a path. Anything that is not exactly 12 lowercase hex is
/// not one of ours.
fn listing_script() -> String {
    format!(
        "set -uo pipefail\n\
         ids=$(\n\
           {{\n\
             for f in /etc/buzz/acp-*.env; do\n\
               [ -e \"$f\" ] || continue\n\
               b=$(basename \"$f\" .env); printf '%s\\n' \"${{b#acp-}}\"\n\
             done\n\
             systemctl list-units --all --no-legend --plain 'buzz-acp@*.service' \
               2>/dev/null | awk '{{print $1}}'\n\
             systemctl list-unit-files --no-legend --plain 'buzz-acp@*.service' \
               2>/dev/null | awk '{{print $1}}'\n\
             for d in /etc/systemd/system/buzz-acp@*.service.d; do\n\
               [ -d \"$d\" ] || continue\n\
               basename \"$d\" .service.d\n\
             done\n\
           }} | sed -n 's/^buzz-acp@//; s/\\.service$//; p' | sort -u\n\
         )\n\
         for i in $ids; do\n\
           case \"$i\" in\n\
             [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;\n\
             *) continue ;;\n\
           esac\n\
           env=\"/etc/buzz/acp-$i.env\"\n\
           trail=\"/etc/buzz/acp-$i.trail\"\n\
           pk=''\n\
           for c in \"$env\" \"$trail\" \
             \"/etc/systemd/system/buzz-acp@$i.service.d/agent.conf\" \
             \"/etc/systemd/system/buzz-acp-secret@$i.service.d/agent.conf\"; do\n\
             sudo -n test -e \"$c\" || continue\n\
             h=$(sudo -n head -n {scan} \"$c\")\n\
             printf '%s\\n' \"$h\" | grep -Fxq {managed_by} || continue\n\
             v=$(printf '%s\\n' \"$h\" | sed -n 's/^# binding-version: //p' | head -n 1)\n\
             case \"$v\" in ''|*[!0-9]*) continue ;; esac\n\
             [ \"$v\" -le {version} ] || continue\n\
             pk=$(printf '%s\\n' \"$h\" | sed -n 's/^# agent-pubkey-full: //p' | head -n 1)\n\
             if [ -n \"$pk\" ]; then break; fi\n\
           done\n\
           flags=ok\n\
           if [ -z \"$pk\" ]; then flags=unmarked; fi\n\
           if ! sudo -n test -e \"$env\"; then flags=no-env; fi\n\
           st=$(systemctl is-active \"buzz-acp@$i.service\" 2>/dev/null || echo unknown)\n\
           printf 'unit\\tbuzz-acp@%s.service\\t%s\\t%s\\t%s\\n' \"$i\" \"$st\" \"$pk\" \"$flags\"\n\
           if sudo -n test -e \"$trail\"; then\n\
             sudo -n grep '^warning ' \"$trail\" 2>/dev/null | while IFS= read -r w; do\n\
               printf 'warning\\t%s\\n' \"$w\"\n\
             done\n\
           fi\n\
         done\n",
        scan = MARKER_SCAN_LINES,
        managed_by = sq(&naming::header_line("managed-by", MANAGED_BY)),
        version = naming::BINDING_VERSION_NUM,
    )
}

/// Turn the listing script's tab-separated output into operator-readable text.
///
/// Pure, so the rendering is tested without an instance — and the *writer* of
/// the `warning ` lines it reads is exercised against this function directly
/// (Task 8 Step 1), because two sides agreeing with two hand-typed fixtures is
/// not the same as two sides agreeing with each other.
pub fn render_listing(stdout: &str) -> String {
    let mut out = String::new();
    let mut units = 0usize;
    for line in stdout.lines() {
        let mut fields = line.split('\t');
        match fields.next() {
            Some("unit") => {
                units += 1;
                let unit = fields.next().unwrap_or("<unknown>");
                let state = fields.next().unwrap_or("unknown");
                let pubkey = fields.next().unwrap_or("");
                let flags = fields.next().unwrap_or("");
                let pubkey = if pubkey.is_empty() {
                    "<pubkey unknown>"
                } else {
                    pubkey
                };
                out.push_str(&format!("{unit}\t{state}\t{pubkey}\n"));
                match flags {
                    "no-env" => out.push_str(
                        "    no environment file — the unit, its drop-ins and its Secret \
                         Manager secret outlived it. It is still running and `remove` still \
                         works.\n",
                    ),
                    "unmarked" => out.push_str(&format!(
                        "    no {MANAGED_BY} marker this build recognises on any of this \
                         agent's files — either nothing here is ours, or a newer provider \
                         deployed it. Recover the pubkey with `gcloud secrets list \
                         --filter=\"labels.managed_by={MANAGED_BY}\" \
                         --format=\"value(name,annotations)\"`.\n"
                    )),
                    _ => {}
                }
            }
            Some("warning") => {
                out.push_str(&format!("    {}\n", fields.next().unwrap_or_default()));
            }
            _ => {}
        }
    }
    if units == 0 {
        out.push_str(&format!(
            "no agents managed by {MANAGED_BY} on this instance\n"
        ));
    }
    out
}

fn list(remote: &Remote) -> Result<(), String> {
    let out = remote.run(&listing_script())?;
    // Checking this is not optional: an auth failure produces empty stdout,
    // and printing nothing while exiting 0 makes a broken install look healthy.
    if !out.ok() {
        return Err(format!(
            "listing agents failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    print!("{}", render_listing(&out.stdout));
    Ok(())
}

/// Every pre-stop refusal, in one shape.
///
/// The reason varies; the tail never does — the four paths the gate looked at,
/// and the manual reclamation. A refusal with no way forward is how an
/// operator ends up doing it with `rm -rf`, and a refusal whose text depends
/// on which arm produced it is four messages to keep actionable instead of
/// one.
fn refusal(reason: &str, names: &Names) -> String {
    let looked_at = observe::agent_paths(names)
        .iter()
        .map(|path| format!("  {path}\n"))
        .collect::<String>();
    format!(
        "refusing to touch {unit}: {reason} Nothing was stopped, disabled or \
         destroyed. Looked at:\n{looked_at}\
         The 12-hex instance name is collision-resistant, not collision-free, \
         so a unit whose name matches is not evidence that this agent is \
         yours. If you are certain it is and you accept what the reason above \
         says, reclaim it by hand: `sudo systemctl disable --now {unit}`, \
         delete those paths, then `gcloud secrets delete {secret}`.",
        unit = names.unit(),
        secret = names.secret_name(),
    )
}

/// The pre-stop gate: **before** anything is stopped, disabled or destroyed,
/// every present per-agent artifact must be this provider's and this agent's,
/// and at least one of them must be there at all.
///
/// Deleting a file was already fenced on that file's own header. Stopping a
/// unit was not: with the env file absent, `remove` ran
/// `systemctl disable --now buzz-acp@<id>.service` before reading a single
/// marker, authorized only by `--pubkey` sharing its first twelve hex with the
/// unit id — the exact collision the full pubkey exists to close. [L2] item 4
/// requires full-identity evidence before *any* action.
///
/// **Refusals first, over every present artifact; authorisation second** — the
/// same order and the same four arms `reconcile::classify` uses, and for the
/// same reason: a stop cannot be undone by a later check. Round 4's P1-2 is
/// what forced the first half. The gate used to authorise as soon as *any*
/// present artifact carried a matching marker, and [`crate::naming::AgentMarker::parse`]
/// yields nothing at all for [`Ownership::OursButNewer`], so a half-migrated
/// agent — an older-or-current env file this build owns, beside a sibling a
/// *newer* provider wrote — walked straight through. `remove` then destroyed
/// the secret and ran a script whose first act is `systemctl disable --now`,
/// and the newer deployment was stopped and its secret destroyed before the
/// per-file fences got as far as politely "keeping" its files. The downgrade
/// refusal was sound for a uniform fleet and on the deploy path; it was unsound
/// here, in exactly the mixed state it exists for.
///
/// [`Ownership::OursButOlder`] is still accepted, and must be: a uniform
/// prior-version agent is this provider's own work at a layout this build
/// supersedes, and refusing it would close the operator's only reclamation
/// path for every agent installed before a version bump.
///
/// Once the loop has passed, "any one artifact is enough" is safe, and it is
/// still the point: the env file is the one most likely to be missing, and a
/// marked drop-in or trail proves the same thing it would have.
///
/// Pure, so it can refuse without a transport. That is what makes "nothing was
/// stopped" structural rather than a promise in a comment.
fn verify_removable(
    files: &[AgentFileState],
    pubkey_full: &str,
    names: &Names,
) -> Result<(), String> {
    for file in files.iter().filter(|file| file.present) {
        match file.ownership {
            Ownership::Ours | Ownership::OursButOlder(_) => {}
            Ownership::OursButNewer(found) => {
                return Err(refusal(
                    &format!(
                        "{path} was written by a newer {MANAGED_BY} (binding \
                         version {found}; this build writes {version}), so this \
                         build cannot tell what stopping the unit would destroy \
                         — and stopping it is the first thing a removal does. \
                         Upgrade this provider and remove the agent with it.",
                        path = file.path,
                        version = naming::BINDING_VERSION,
                    ),
                    names,
                ))
            }
            Ownership::NotOurs => {
                return Err(refusal(
                    &format!(
                        "{} exists but carries no {MANAGED_BY} marker at a \
                         binding version this build recognises, so it is not \
                         this provider's to tear down. Move it aside first.",
                        file.path
                    ),
                    names,
                ))
            }
        }
        let Some(marker) = file.marker.as_ref() else {
            return Err(refusal(
                &format!(
                    "{} carries the {MANAGED_BY} marker but no \
                     agent-pubkey-full line, so which agent it belongs to \
                     cannot be established.",
                    file.path
                ),
                names,
            ));
        };
        if marker.pubkey_full != pubkey_full {
            return Err(refusal(
                &format!(
                    "short-name collision: {} belongs to pubkey {}, not \
                     {pubkey_full}.",
                    file.path, marker.pubkey_full
                ),
                names,
            ));
        }
    }

    if files.iter().any(|file| file.present) {
        return Ok(());
    }
    Err(refusal(
        &format!(
            "none of its per-agent artifacts is present, so nothing carries a \
             {MANAGED_BY} marker for pubkey {pubkey_full} at a binding version \
             this build recognises."
        ),
        names,
    ))
}

/// The pre-stop ownership scan: every per-agent artifact's marker header, in
/// one remote shell, and nothing else.
///
/// It reads. It runs no `systemctl` verb and deletes nothing, because its whole
/// job is to decide whether `remove` is allowed to. The rows come from
/// [`observe::agent_file_rows`] — the same emitter the reconciler's observation
/// uses, parsed by the same [`observe::parse_agent_file_row`] — so `remove` and
/// `deploy` cannot come to different conclusions about the same header.
fn ownership_scan_script(names: &Names) -> String {
    format!(
        "set -uo pipefail\n{field}echo '---AGENTFILES---'\n{rows}echo '---END---'\n",
        field = observe::FIELD_HELPER,
        rows = observe::agent_file_rows(names),
    )
}

/// The remote script that deletes this agent's own files — by name, never a
/// directory tree, and each one only if **its own** header says it is ours.
///
/// The previous shape verified the env file in Rust and then `rm -f`'d four
/// enumerated paths. That is "delete these paths if one of them is marked", not
/// "delete only marked paths": a hand-written drop-in beside a marked env file
/// was destroyed by a fence that never looked at it. Each path now carries its
/// own veto, evaluated in the same shell as its own `rm`, and a file that fails
/// it is reported and left exactly where it is.
///
/// `create-intent` is deliberately **not** among the required lines: it changes
/// on every legitimate reconfiguration, so requiring it would refuse a file
/// this very agent wrote yesterday. Neither is `binding-version` — `marker_ok`
/// compares it as an ordering, so a prior-version agent this provider itself
/// deployed can still be torn down.
///
/// The veto is `remote::marker_fn`'s `marker_ok`, shared with the install
/// guard. Both used to spell it `grep -c -F -x -e … | [ "$n" -eq 3 ]`, and
/// `grep -c` counts matching input **lines** rather than distinct matched
/// patterns: a header repeating `# managed-by:` reached the count while
/// carrying no `# agent-pubkey-full:` at all, so the veto authorized deleting a
/// file that never named this agent.
///
/// This returns the **root** half only: no `set`, no `sudo -n`, because
/// `Remote::run_fenced` runs it inside `remote::under_lease`'s
/// `sudo -n flock … sh -c`, already elevated and already holding the lease.
/// That is round 4's P1-1 — the `systemctl disable --now` on the first line is
/// the most destructive thing this binding does, and it must not execute
/// unless the owner record still names this process at the instant it runs.
fn removal_script(names: &Names, pubkey_full: &str) -> String {
    let required = [
        naming::header_line("managed-by", MANAGED_BY),
        naming::header_line("agent-pubkey-full", pubkey_full),
    ];
    format!(
        "{marker_ok}\
         systemctl disable --now {unit} 2>/dev/null || true\n\
         systemctl stop {secret_unit} 2>/dev/null || true\n\
         for p in {env} {trail} {dropin} {secret_dropin}; do\n\
           test -f \"$p\" || continue\n\
           h=$(head -n {scan} \"$p\" || true)\n\
           if marker_ok; then\n\
             rm -f \"$p\"\n\
           else\n\
             echo \"kept $p: it carries no {managed_by} marker for this agent at \
a binding version this build may act on\"\n\
           fi\n\
         done\n\
         for d in {dropin_dir} {secret_dropin_dir}; do\n\
           if test -d \"$d\"; then\n\
             if rmdir \"$d\" 2>/dev/null; then :; else\n\
               echo \"kept $d: it still holds files this provider did not write\"\n\
             fi\n\
           fi\n\
         done\n\
         systemctl daemon-reload\n",
        marker_ok = marker_fn(&required),
        unit = sq(&names.unit()),
        secret_unit = sq(&names.secret_unit()),
        env = sq(&names.env_path()),
        trail = sq(&names.trail_path()),
        dropin = sq(&names.dropin_path()),
        secret_dropin = sq(&names.secret_dropin_path()),
        scan = MARKER_SCAN_LINES,
        managed_by = MANAGED_BY,
        dropin_dir = sq(&names.dropin_dir()),
        secret_dropin_dir = sq(&names.secret_dropin_dir()),
    )
}

fn remove(remote: &Remote, project: &str, agent_id: &str, pubkey: &str) -> Result<(), String> {
    let (names, pubkey) = resolve_target(agent_id, pubkey)?;

    // The same per-agent lease `deploy` takes, and for the same reason: this
    // destroys a Secret Manager secret and four files while a concurrent deploy
    // may be installing them, and taking none left the two freely
    // interleavable. It is acquired *before* the scan whose verdict authorizes
    // everything below, so the state that authorizes cannot move between the
    // read and the act, and it is held to the end of this function.
    let lease = acquire_lease(remote, &names)?;

    // ---- Pre-stop gate ([L2] item 4). -------------------------------------
    // Stopping a unit is itself destructive, so it waits behind full-identity
    // evidence like every other destructive step. All four artifacts are read
    // in one shell; a *missing env file* is still not "nothing to remove",
    // because the unit, both drop-ins, the trail and the secret all outlive it
    // and any one surviving marker proves the same thing the env file would.
    let out = remote.run(&ownership_scan_script(&names))?;
    if !out.ok() {
        return Err(format!(
            "could not read {}'s marker headers (exit {}): {}. Nothing was \
             stopped or destroyed.",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }
    let files: Vec<AgentFileState> = observe::section(&out.stdout, "AGENTFILES")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(observe::parse_agent_file_row)
        .collect();
    verify_removable(&files, &pubkey, &names)?;
    if !files
        .iter()
        .any(|file| file.path == names.env_path() && file.present)
    {
        eprintln!(
            "note: {} is absent. Removing {} anyway — a sibling artifact \
             carries this agent's marker, and each deletion below is still \
             fenced on that file's own header.",
            names.env_path(),
            names.unit()
        );
    }

    // Secret first. The reverse order leaves markers gone, the secret still
    // holding a live key, and no local evidence left to identify or retry it.
    // Ordered this way an interrupted remove is idempotent: a re-run finds the
    // marked files present, the secret already absent, and treats
    // delete-of-absent as success ([L2] item 4).
    //
    // This is the one standalone renewal `remove` keeps, and for the same
    // reason `deploy` keeps its one: `secrets::destroy` is a `gcloud` call
    // from this machine against a service the instance's lock knows nothing
    // about, so it is the only step here that no fenced shell covers. Every
    // other mutation below proves the lease itself.
    lease.renew()?;
    secrets::destroy(remote, project, &names.secret_name(), &pubkey)?;

    // The removal itself runs *inside* the lease, not merely after a renewal
    // that preceded it: `run_fenced` wraps the script in the same
    // `sudo -n flock … sh -c` the installs use, so the proof that the record
    // still names this process and the `systemctl disable --now` it authorizes
    // share one shell. Round 4's P1-1 — a renewal that succeeds and is then
    // followed by a stall long enough for the lease to be taken over leaves
    // the mutation unguarded, and this one stops units and deletes files.
    let out = remote.run_fenced(&lease, &removal_script(&names, &pubkey))?;
    if out.code == LOCK_UNAVAILABLE {
        return Err(lease_lost(&names.unit()));
    }
    if !out.ok() {
        return Err(format!(
            "removing {agent_id} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    // Any `kept …` line is a file this provider declined to delete. Printing it
    // is the whole point: silence would read as a clean sweep.
    print!("{}", out.stdout);
    println!("removed {agent_id}");
    Ok(())
}

fn dry_run() -> Result<(), String> {
    use buzz_backend_core::identity::AgentIdentity;
    use buzz_backend_core::wire::DeployRequest;
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("could not read the request from stdin: {e}"))?;
    let request: DeployRequest =
        serde_json::from_str(&input).map_err(|e| format!("invalid deploy request: {e}"))?;

    let cfg = ProviderConfig::parse(&request.provider_config)?;
    let identity = AgentIdentity::from_nsec(&request.agent.private_key_nsec)?;
    let names = Names::new(&identity);
    let plan = crate::render::plan(&request.agent, &cfg, &names, &identity, "dryrun00")?;
    let record =
        crate::capacity::trail_record("<deploy time>", "dryrun00", &plan.create_intent, &[]);
    print!("{}", crate::render::dry_run_report(&plan, &names, &record));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // `Ownership` is deliberately absent: round 4's `verify_removable` matches
    // on it, so the parent names it and `use super::*` carries it here. Naming
    // it again would be a duplicate import (E0252), not a redundant one.
    use crate::naming::{agent_ownership, AgentMarker};

    #[test]
    fn an_agent_id_yields_its_instance() {
        assert_eq!(
            instance_of("buzz-acp@a1b2c3d4e5f6.service").unwrap(),
            "a1b2c3d4e5f6"
        );
        assert_eq!(
            instance_of("buzz-acp@a1b2c3d4e5f6").unwrap(),
            "a1b2c3d4e5f6"
        );
    }

    #[test]
    fn a_malformed_agent_id_is_refused() {
        for bad in [
            "a1b2c3d4e5f6",
            "buzz-acp@",
            "buzz-acp@NOTHEX123456",
            "buzz-acp@abc",
            "buzz-acp@a1b2c3d4e5f6g7",
            "buzz-agent-a1b2c3d4e5f6",
        ] {
            assert!(
                instance_of(bad).is_err(),
                "accepted malformed agent id {bad:?}"
            );
        }
    }

    /// The operator's pubkey must actually name the agent they typed, or the
    /// fence is checking one identity while the paths belong to another.
    #[test]
    fn the_pubkey_must_agree_with_the_agent_id() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        assert!(resolve_target("buzz-acp@a1b2c3d4e5f6.service", &pubkey).is_ok());
        let other = format!("ffffffffffff{}", "0".repeat(52));
        let err = resolve_target("buzz-acp@a1b2c3d4e5f6.service", &other)
            .expect_err("mismatched pubkey must be refused");
        assert!(err.contains("does not begin"), "{err}");
    }

    /// `list` renders unit rows and every `warning` line from each trail: the
    /// trail is the only place a success-path capacity warning survives.
    #[test]
    fn the_listing_shows_units_and_their_capacity_warnings() {
        let raw = "unit\tbuzz-acp@a1b2c3d4e5f6.service\tactive\tdeadbeef\tok\n\
                   warning\twarning capacity: adding buzz-acp@a1b2c3d4e5f6.service (2G) may cause OOM kills.\n\
                   unit\tbuzz-acp@ffffffffffff.service\tinactive\tcafebabe\tok\n";
        let rendered = render_listing(raw);
        assert!(rendered.contains("buzz-acp@a1b2c3d4e5f6.service"));
        assert!(rendered.contains("active"));
        assert!(rendered.contains("deadbeef"));
        assert!(rendered.contains("may cause OOM kills"));
        assert!(rendered.contains("buzz-acp@ffffffffffff.service"));
    }

    #[test]
    fn an_empty_listing_says_so_rather_than_printing_nothing() {
        assert!(render_listing("").contains("no agents"));
    }

    /// P2-2: an agent whose env file was deleted out of band is still running
    /// and still holds a secret. Keying `list` off `/etc/buzz/acp-*.env` alone
    /// made it invisible here and un-removable there — the operator's only
    /// reclamation path lying to them in a reachable state.
    #[test]
    fn an_agent_whose_env_file_is_gone_is_still_listed_and_still_actionable() {
        let rendered =
            render_listing("unit\tbuzz-acp@a1b2c3d4e5f6.service\tactive\tdeadbeef\tno-env\n");
        assert!(rendered.contains("buzz-acp@a1b2c3d4e5f6.service"));
        assert!(
            rendered.contains("deadbeef"),
            "the pubkey survives on a sibling file: {rendered}"
        );
        assert!(rendered.contains("no environment file"), "{rendered}");
        assert!(rendered.contains("`remove` still works"), "{rendered}");
    }

    /// …and when *no* per-agent file carries a marker, the row still appears
    /// rather than being silently skipped.
    #[test]
    fn an_unmarked_instance_is_reported_not_hidden() {
        let rendered = render_listing("unit\tbuzz-acp@a1b2c3d4e5f6.service\tactive\t\tunmarked\n");
        assert!(rendered.contains("buzz-acp@a1b2c3d4e5f6.service"));
        assert!(rendered.contains("<pubkey unknown>"), "{rendered}");
        assert!(rendered.contains(MANAGED_BY), "{rendered}");
    }

    /// P2-1: the writer and the reader, wired together. Both were previously
    /// tested against hand-typed fixtures that happened to agree on the
    /// `warning ` prefix, so a rename on either side would have left every test
    /// green and the operator with no way to see an over-capacity deploy. This
    /// feeds `capacity::trail_record`'s **real** output through the shape
    /// `listing_script` emits and into the real reader.
    #[test]
    fn a_real_capacity_warning_survives_the_writer_reader_round_trip() {
        let unit = "buzz-acp@a1b2c3d4e5f6.service";
        let warnings = crate::capacity::warning_lines(
            crate::capacity::GIB,
            crate::capacity::GIB,
            unit,
            crate::capacity::GIB,
        );
        assert!(!warnings.is_empty(), "this fixture must overcommit");
        let record = crate::capacity::trail_record(
            "2026-08-05T09:14:02Z",
            "3f9c1a04",
            &"a".repeat(64),
            &warnings,
        );

        // Exactly what `listing_script` produces from that trail: the unit row,
        // then every line the remote `grep '^warning '` matched, tab-prefixed.
        let mut raw = format!("unit\t{unit}\tactive\t{}\tok\n", "ab".repeat(32));
        for line in record.lines().filter(|l| l.starts_with("warning ")) {
            raw.push_str(&format!("warning\t{line}\n"));
        }

        let rendered = render_listing(&raw);
        for warning in &warnings {
            assert!(
                rendered.contains(warning.as_str()),
                "the reader dropped {warning:?}:\n{rendered}"
            );
        }
        assert!(rendered.contains("may cause OOM kills"), "{rendered}");
        assert!(rendered.contains("e2-standard-4"), "{rendered}");
    }

    /// The enumeration must not be the env glob alone, or the ghost above is
    /// unreachable no matter how well `render_listing` renders it.
    #[test]
    fn the_listing_script_enumerates_units_as_well_as_env_files() {
        let script = listing_script();
        assert!(script.contains("/etc/buzz/acp-*.env"), "{script}");
        assert!(script.contains("systemctl list-units"), "{script}");
        assert!(script.contains("systemctl list-unit-files"), "{script}");
        assert!(script.contains("buzz-acp@*.service.d"), "{script}");
        // P1-1: a prior-version agent must remain listable. An exact
        // `# binding-version: N` match made a version bump hide every agent
        // already on the box behind `<pubkey unknown>`.
        assert!(
            script.contains(&format!("-le {}", naming::BINDING_VERSION_NUM)),
            "{script}"
        );
    }

    /// Enumerated paths only. A drop-in directory is where an operator keeps
    /// `override.conf`; deleting the directory is a fence-shaped hole.
    #[test]
    fn the_removal_script_deletes_named_files_and_never_a_directory_tree() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
        for path in [
            names.env_path(),
            names.trail_path(),
            names.dropin_path(),
            names.secret_dropin_path(),
        ] {
            assert!(script.contains(&sq(&path)), "{path} is not deleted by name");
        }
        assert!(
            !script.contains("rm -rf"),
            "a directory tree must never be removed"
        );
        assert!(
            script.contains("rmdir"),
            "empty drop-in directories are tidied"
        );
        // Shared artifacts belong to every agent and are never touched.
        for shared in crate::observe::SHARED_PATHS {
            assert!(!script.contains(shared), "{shared} must survive a remove");
        }
    }

    /// P1-4: each deletion is vetoed by the header of the file *it* deletes,
    /// in the same shell as the deletion. Authorizing four `rm`s from one
    /// sibling's header is "delete these paths if one of them is marked".
    #[test]
    fn every_deletion_is_fenced_on_the_file_it_deletes() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
        for required in [
            naming::header_line("managed-by", MANAGED_BY),
            naming::header_line("agent-pubkey-full", &pubkey),
        ] {
            assert!(
                script.contains(&sq(&required)),
                "the fence omits {required:?}"
            );
        }
        assert!(
            script.contains(r#"head -n 4 "$p""#),
            "the fence must read the file being deleted: {script}"
        );
        assert!(script.contains(r#"rm -f "$p""#), "{script}");
        assert!(
            script.contains("kept $p"),
            "a file that fails the fence must be reported, not silently skipped"
        );
        // `create-intent` changes on every legitimate reconfiguration, so a
        // fence that required it would refuse a file this agent wrote itself.
        assert!(!script.contains("create-intent"), "{script}");
    }

    /// P1-3, the delete half. `grep -c -F -x -e a -e b -e c` compared against
    /// `3` counts matching input *lines*, not distinct matched patterns, so a
    /// header whose first lines repeat `# managed-by:` reaches the count while
    /// carrying no `# agent-pubkey-full:` at all — and the veto then
    /// authorizes deleting a file that does not carry this agent's identity.
    /// Each needle gets its own test, and the first miss returns.
    #[test]
    fn a_repeated_marker_line_does_not_authorize_a_delete() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
        assert!(
            !script.contains("grep -c"),
            "counting lines instead of patterns is the defect: {script}"
        );
        assert_eq!(
            script.matches("grep -Fqx").count(),
            2,
            "one independent check per needle: {script}"
        );
        assert!(
            script.contains(&format!(
                "grep -Fqx -- {}",
                sq(&naming::header_line("agent-pubkey-full", &pubkey))
            )),
            "the identity line must be asserted on its own: {script}"
        );
        // The binding version is an ordering, not a needle: a prior-version
        // file is this provider's own work, and `remove` must still delete it.
        assert!(
            script.contains(&format!("-le {}", naming::BINDING_VERSION_NUM)),
            "{script}"
        );
        assert!(
            !script.contains(&sq(&naming::header_line(
                "binding-version",
                naming::BINDING_VERSION
            ))),
            "an exact binding-version needle locks the operator out of a \
             prior-version agent: {script}"
        );
    }

    /// One row as the pre-stop scan reports it.
    fn scanned(path: &str, marker: Option<AgentMarker>) -> AgentFileState {
        AgentFileState {
            path: path.to_string(),
            present: marker.is_some(),
            ownership: if marker.is_some() {
                Ownership::Ours
            } else {
                Ownership::NotOurs
            },
            marker,
        }
    }

    fn our_marker(pubkey: &str) -> Option<AgentMarker> {
        Some(AgentMarker {
            pubkey_full: pubkey.to_string(),
            create_intent: "ci".to_string(),
        })
    }

    /// P1-2: `remove` may stop a unit only once it has proven the unit is this
    /// agent's. The env file is the artifact most likely to be missing, so the
    /// gate reads all four and any one of them is enough.
    #[test]
    fn an_env_absent_agent_with_a_marked_sibling_is_removable() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let files = [
            scanned(&names.env_path(), None),
            scanned(&names.dropin_path(), None),
            scanned(&names.secret_dropin_path(), None),
            scanned(&names.trail_path(), our_marker(&pubkey)),
        ];
        verify_removable(&files, &pubkey, &names)
            .expect("one marked sibling is full-identity evidence");
    }

    /// …and with nothing carrying this pubkey, the refusal arrives before
    /// anything is stopped. `--pubkey` sharing its first 12 hex with the unit
    /// id is not evidence — that is the collision the full pubkey closes — and
    /// this gate is a pure function precisely so it can refuse without a
    /// transport, which is what makes "nothing was stopped" structural rather
    /// than a promise.
    #[test]
    fn an_agent_with_no_matching_marker_is_refused_before_anything_stops() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let sibling = Some(AgentMarker {
            pubkey_full: format!("a1b2c3d4e5f6{}", "f".repeat(52)),
            create_intent: "ci".to_string(),
        });
        let files = [
            scanned(&names.env_path(), None),
            scanned(&names.dropin_path(), sibling),
            scanned(&names.secret_dropin_path(), None),
            scanned(&names.trail_path(), None),
        ];
        let err = verify_removable(&files, &pubkey, &names)
            .expect_err("a 12-hex prefix match must not authorize a stop");
        assert!(err.contains(&names.env_path()), "{err}");
        assert!(err.contains("Nothing was stopped"), "{err}");
        assert!(
            err.contains("systemctl") && err.contains(&names.secret_name()),
            "a refusal with no way forward is how an operator reaches for \
             rm -rf: {err}"
        );
    }

    /// P1-1: a prior-version agent must still be removable. Treating an older
    /// `binding-version` as foreign closed the operator's only reclamation
    /// path for every agent this provider itself deployed before the bump.
    #[test]
    fn a_prior_version_agent_is_still_removable() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let older = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 0\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        assert_eq!(agent_ownership(&older), Ownership::OursButOlder(0));
        let file = AgentFileState {
            path: names.env_path(),
            present: true,
            ownership: agent_ownership(&older),
            marker: AgentMarker::parse(&older),
        };
        verify_removable(&[file], &pubkey, &names)
            .expect("this provider's own prior-version agent is removable");
    }

    /// A *newer* binding version is the refusal the version rule reserves:
    /// deleting an artifact whose layout this build does not understand is
    /// destroying a newer provider's work, not reclaiming our own.
    #[test]
    fn a_future_version_agent_is_not_removable_by_this_build() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let newer = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 99\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        assert_eq!(agent_ownership(&newer), Ownership::OursButNewer(99));
        assert!(AgentMarker::parse(&newer).is_none(), "{newer}");
        let file = AgentFileState {
            path: names.env_path(),
            present: true,
            ownership: agent_ownership(&newer),
            marker: AgentMarker::parse(&newer),
        };
        assert!(verify_removable(&[file], &pubkey, &names).is_err());
    }

    /// The pre-stop scan reads every per-agent artifact in one shell, and it
    /// reads them with the *observer's* emitter — a second emitter of the same
    /// row shape is a second thing to keep in step with the parser. It must
    /// also touch no `systemctl` verb: it is the thing that decides whether
    /// stopping is allowed.
    #[test]
    fn the_ownership_scan_reads_all_four_artifacts_and_stops_nothing() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = ownership_scan_script(&names);
        for path in crate::observe::agent_paths(&names) {
            assert!(script.contains(&sq(&path)), "{path} is not scanned");
        }
        assert!(!script.contains("systemctl"), "{script}");
        assert!(!script.contains("rm -f"), "{script}");
    }

    /// Round 4's P1-2, the case the version rule existed for and got wrong.
    /// A half-migrated agent — an env file this build owns, for this pubkey,
    /// beside a drop-in a *newer* provider wrote — used to pass the gate,
    /// because the gate authorised on "any artifact carries a matching
    /// marker" and `AgentMarker::parse` yields nothing for `OursButNewer`, so
    /// the newer sibling was simply looked past. `remove` then destroyed the
    /// secret and ran a script whose first act is `systemctl disable --now`:
    /// the newer deployment was stopped and its key destroyed, and only then
    /// were its *files* politely kept. The gate must refuse.
    #[test]
    fn a_half_migrated_agent_is_refused_before_anything_stops() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let newer = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 99\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        let files = [
            // Ours, this build's own layout, and unambiguously this agent's.
            scanned(&names.env_path(), our_marker(&pubkey)),
            AgentFileState {
                path: names.dropin_path(),
                present: true,
                ownership: agent_ownership(&newer),
                marker: AgentMarker::parse(&newer),
            },
            scanned(&names.secret_dropin_path(), None),
            scanned(&names.trail_path(), None),
        ];
        let err = verify_removable(&files, &pubkey, &names)
            .expect_err("a newer sibling must block the whole removal");
        assert!(err.contains(&names.dropin_path()), "{err}");
        assert!(
            err.contains("99"),
            "the refusal must name the version: {err}"
        );
        assert!(err.contains("Nothing was stopped"), "{err}");
        assert!(
            !err.contains("somebody else"),
            "a newer build of this provider is not a stranger: {err}"
        );
    }

    /// …and a uniform prior-version fleet is still removable, so the stricter
    /// gate did not close the reclamation path round 3's P1-1 opened.
    #[test]
    fn a_uniform_prior_version_fleet_is_still_removable() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let older = format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: 0\n\
             # agent-pubkey-full: {pubkey}\n# create-intent: ci\n"
        );
        let at_version_zero = |path: String| AgentFileState {
            path,
            present: true,
            ownership: agent_ownership(&older),
            marker: AgentMarker::parse(&older),
        };
        let files: Vec<AgentFileState> = crate::observe::agent_paths(&names)
            .into_iter()
            .map(at_version_zero)
            .collect();
        verify_removable(&files, &pubkey, &names)
            .expect("a uniform prior-version agent is this provider's own work");
    }

    /// Round 4's P1-1, the `remove` half. The removal script is the **root**
    /// half only — `Remote::run_fenced` supplies the elevation, the `flock`
    /// and the ownership proof — so it must carry no `set` line and no `sudo`
    /// of its own, or it would run privileged commands outside the wrapper
    /// that proves the lease.
    #[test]
    fn the_removal_script_is_the_root_half_of_a_fenced_shell() {
        let pubkey = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        let names = Names::from_pubkey_hex(&pubkey).unwrap();
        let script = removal_script(&names, &pubkey);
        assert!(
            !script.contains("sudo"),
            "the wrapper elevates once: {script}"
        );
        assert!(
            !script.contains("set -"),
            "the wrapper sets the shell: {script}"
        );
        assert!(script.starts_with("marker_ok()"), "{script}");
    }
}
