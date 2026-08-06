//! The `gcloud compute ssh` transport (spec §Transport, §Remote Artifacts).
//!
//! Every file body travels on **stdin**. Nothing sensitive is ever formatted
//! into a command string: argv is visible in `ps` on the instance and lands in
//! shell history, and the desktop's redaction can reach neither.
//!
//! `gcloud compute ssh` execs a real `ssh` with the remote command as trailing
//! argv, and `ssh` forwards local stdin to it — measured on this host, 30
//! bytes in and a matching md5 out. That is what makes the stdin install path
//! sound with no `scp` staging and no remote temp file.

use crate::naming::{BINDING_VERSION, BINDING_VERSION_NUM, MANAGED_BY};
use crate::render::RemoteFile;
use buzz_backend_core::identity::new_generation;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Directories prepended to `PATH` before the first `gcloud` spawn.
///
/// The provider is exec'd by a Tauri app inheriting launchd's minimal
/// `/usr/bin:/bin:/usr/sbin:/sbin`, which contains none of the places `gcloud`
/// installs to. Same fix and same cause as
/// `crates/buzz-backend-kubernetes/src/client.rs:12-19`.
const PATH_PREPEND: [&str; 2] = ["/opt/homebrew/bin", "/usr/local/bin"];

/// "This path is present but is not this agent's." Not a transport failure,
/// and must not read as one.
pub const OWNERSHIP_REFUSED: i32 = 76;
/// "Another deploy of this agent holds the instance lease."
pub const LOCK_UNAVAILABLE: i32 = 75;
/// "The authorizing marker moved between the observation and the write."
pub const MARKER_CHANGED: i32 = 77;
/// "The agent started between the observation and the stop."
pub const AGENT_STARTED: i32 = 78;

/// How many leading lines of a file can hold a marker header.
///
/// Four, not three: a per-agent header is four lines starting at line 1, while
/// a shared header is three lines starting at line 2 when a shebang precedes
/// it. One bound covers both, because the checks count exact whole-line
/// matches rather than comparing a fixed slice.
pub const MARKER_SCAN_LINES: usize = 4;

/// One completed `gcloud` invocation.
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

impl Output {
    /// Did the process exit 0? Every caller must consult this: a `gcloud`
    /// that fails prints nothing useful on stdout, and treating an empty
    /// stdout as an empty result is how an auth failure becomes a silent
    /// success.
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// The one capability `secrets` needs from a transport.
///
/// A trait rather than the concrete `Remote` because the ownership discipline
/// `secrets` enforces is a property of the **command sequence** — describe,
/// verify, mutate, describe, verify, mutate — and a sequence can only be tested
/// by recording it. `Remote` is the sole production implementation.
pub trait Gcloud {
    fn gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String>;
}

/// A bound instance this provider can run commands on.
pub struct Remote {
    project: String,
    zone: String,
    instance: String,
    token: String,
}

/// Quote a value for a single-quoted POSIX shell context.
pub fn sq(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The private directory both deploy-lease files live in.
///
/// Not `/run/lock` directly. `/run` is the right filesystem — a tmpfs systemd
/// recreates on every boot, so a lease can never outlive the reboot that made
/// its holder irrelevant — but `/run/lock` is world-readable and, on several
/// distributions, group-writable, so a predictable `<agent>.owner` path there
/// is a record an unprivileged local user can watch and, in the worst case,
/// pre-create with contents of their choosing. `0700 root:root` puts the
/// record where exactly the identity that enforces it can read or write it.
///
/// The *shape* of a lease lives in this module and its *policy* lives in
/// `reconcile`, and the split is deliberate: every mutating script this module
/// renders has to carry the ownership proof inside its own shell, which makes
/// the proof a transport concern; how long a lease lives, when it is taken and
/// when an abandoned one may be stolen are questions about deploys, which
/// makes them the reconciler's.
pub(crate) const LEASE_DIR: &str = "/run/buzz-backend-gcp";

/// How long to wait for the lease's `flock`. Every critical section under it
/// is a handful of local file operations — never a network read — so anything
/// longer means a wedged holder rather than a busy one.
pub(crate) const LEASE_FLOCK_WAIT_SECONDS: u64 = 5;

/// Where one agent's deploy lease lives: `(lock, owner)`.
///
/// `agent` is the 12-lowercase-hex instance name derived from the pubkey
/// (`naming::Names::instance`) — **not** the GCE instance this `Remote` is
/// bound to — and the closed grammar it comes from is what makes it safe to
/// interpolate into a path.
pub(crate) fn lease_paths(agent: &str) -> (String, String) {
    (
        format!("{LEASE_DIR}/{agent}.lock"),
        format!("{LEASE_DIR}/{agent}.owner"),
    )
}

/// Evidence that the caller holds an agent's deploy lease.
///
/// One method, and exactly one implementor: `reconcile::DeployLease`, whose
/// only constructor writes the owner record first. Every mutating entry point
/// below takes `&dyn Held`, so "this write happens under a lease" is something
/// the signature enforces rather than something a comment asks for — the same
/// discipline round 3 applied to the authoritative observation, applied to the
/// writes. Adding a second implementor is a deliberate act with a compiler
/// error's worth of friction, which is the point.
pub(crate) trait Held {
    /// The 12-lowercase-hex agent whose lease is held.
    fn agent(&self) -> &str;
}

/// The first thing inside every mutating shell: prove the owner record still
/// names this process, then push its expiry out.
///
/// This is round 4's P1-1 in four lines. Renewing at phase boundaries proved
/// only that the lease was ours *at the boundary*; the write that followed
/// carried no lease check at all, because `marker_fn` proves provenance and
/// `owner_marker` deliberately carries neither the create-intent nor the
/// token. A holder that stalled past the TTL could therefore be legitimately
/// overtaken and still land its `mv` on the winner's files. Here the proof and
/// the mutation are one shell under one `flock`, and the record can only be
/// changed under that same `flock`, so no takeover can interleave between
/// them: either it completes first and this gate refuses, or this shell holds
/// the lock and the rival's `flock -w` times out.
///
/// It refreshes as well as verifies, which is why `DeployLease::renew` no
/// longer runs at every phase boundary — a window made of fenced mutations
/// renews itself, and the one stretch that is not (the Secret Manager calls,
/// which leave the instance entirely) keeps an explicit renewal.
///
/// [`LOCK_UNAVAILABLE`] for every failure, because the operator's remedy is
/// the same in each case: another operation owns this agent right now.
pub(crate) fn lease_gate(owner: &str, token: &str) -> String {
    format!(
        "now=$(date +%s)\n\
         [ -f {owner} ] || exit {busy}\n\
         [ \"$(cut -d' ' -f1 {owner})\" = {token} ] || exit {busy}\n\
         printf '%s %s\\n' {token} \"$now\" > {owner}\n",
        owner = sq(owner),
        token = sq(token),
        busy = LOCK_UNAVAILABLE,
    )
}

/// Wrap a **root** script so it runs only while this process still holds
/// `agent`'s deploy lease — the proof and the mutation in one shell, under one
/// `flock`.
///
/// `sudo -n flock … sh -c` rather than `sudo -n sh -c 'exec 9>…'`: [`LEASE_DIR`]
/// is `0700 root:root`, so the lock cannot be opened without elevating first,
/// and `flock`'s command form elevates **once** for the whole critical section
/// instead of once per command inside it. `-E` makes a lock we could not take
/// exit [`LOCK_UNAVAILABLE`] rather than the `1` that a hundred other things
/// also return. This is the single shape every critical section in this
/// binding uses — acquire, renew, release, each install, the append, the
/// fenced stop, the start and the removal are the same wrapper with a
/// different body.
///
/// `root_script` carries no `sudo -n` and no `set` line of its own: everything
/// inside the wrapper is already root, and a second `sudo` there is a second
/// thing to get wrong. It runs under `/bin/sh` (dash on Debian and Ubuntu
/// images), so no `pipefail`, no `[[`, no arrays — the outer script keeps
/// those.
///
/// The body is `sq`-wrapped, so every single quote it carries appears as
/// `'\''` in the emitted script. Tests that match on a quoted needle inside it
/// have to account for that; the `nested` helper in Tasks 9 and 12 is that
/// accounting, written down rather than worked around by matching only on
/// quote-free fragments.
pub(crate) fn under_lease(agent: &str, token: &str, root_script: &str) -> String {
    let (lock, owner) = lease_paths(agent);
    let inner = format!(
        "set -u\n{gate}{root_script}",
        gate = lease_gate(&owner, token),
    );
    format!(
        "sudo -n flock -w {wait} -E {busy} {lock} sh -c {inner}\n",
        wait = LEASE_FLOCK_WAIT_SECONDS,
        busy = LOCK_UNAVAILABLE,
        lock = sq(&lock),
        inner = sq(&inner),
    )
}

/// The refusal for a mutation whose lease could not be proven in its own shell.
///
/// One sentence for both ways it fails — the record names somebody else, or
/// the `flock` itself could not be taken within [`LEASE_FLOCK_WAIT_SECONDS`] —
/// because the outcome is identical (nothing was written) and so is the
/// remedy. It must not read like [`Remote::not_ours`]: that one tells the
/// operator to move a file aside, and following that advice when the real
/// cause is a concurrent deploy is how a healthy artifact gets deleted.
pub(crate) fn lease_lost(target: &str) -> String {
    format!(
        "the deploy lease for {target} was not held at the instant the write \
         reached the instance: another operation has taken it over, or it \
         expired while this one was stalled. Nothing was written, and \
         {target} was left exactly as it was. Re-run once the other operation \
         finishes."
    )
}

/// Compute the new `PATH` value: `gcloud` directories first, inherited entries
/// after, in order. Pure, so the ordering is testable without mutating the
/// process environment.
fn prepended_path(home: Option<&Path>, existing: &OsStr) -> Option<OsString> {
    let mut dirs: Vec<PathBuf> = PATH_PREPEND.iter().map(PathBuf::from).collect();
    if let Some(home) = home {
        dirs.push(home.join(".local/bin"));
    }
    // An empty inherited PATH splits into one empty entry, which POSIX
    // resolves as the current directory — never a place `gcloud` may be found.
    // Drop empties rather than propagate them.
    dirs.extend(std::env::split_paths(existing).filter(|p| !p.as_os_str().is_empty()));
    std::env::join_paths(dirs).ok()
}

/// Prepend the `gcloud` directories to this process's own `PATH`.
///
/// Modifying the provider's environment is sound here: one process per
/// operation, called before any child exists, and the only child that reads it
/// is the `gcloud` this exists for.
fn prepend_gcloud_path() {
    let home = std::env::var_os("HOME");
    let existing = std::env::var_os("PATH").unwrap_or_default();
    if let Some(joined) = prepended_path(home.as_ref().map(Path::new), &existing) {
        std::env::set_var("PATH", joined);
    }
}

/// Is `command` an executable somewhere on the current `PATH`?
fn resolves_on_path(command: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(command).is_file()))
        .unwrap_or(false)
}

/// The refusal for a `gcloud` that still does not resolve — never a bare
/// `NotFound`, whose cause has nothing to do with GCP.
fn gcloud_not_found() -> String {
    format!(
        "gcloud was not found. This provider is launched by the desktop app, \
         which inherits a minimal PATH, so {} and $HOME/.local/bin are searched \
         in addition to the inherited one. Install the Google Cloud CLI into \
         one of those directories, run `gcloud auth login`, and restart Buzz \
         Desktop.",
        PATH_PREPEND.join(", ")
    )
}

/// The `marker_ok` shell function: does the header captured in `$h` carry
/// every line of `required`, at a binding version this build may act on?
/// Exit 0 for yes, 1 for no.
///
/// One definition, `pub(crate)`, called by this module's install guard and by
/// Task 13's per-file delete veto — because both used to ask the question the
/// same wrong way. `grep -c -F -x -e a -e b -e c` compared against `3` counts
/// matching input **lines**, not distinct matched patterns, so a header whose
/// first three lines are `# managed-by: …` twice and `# binding-version: …`
/// once reaches the count while carrying no `# agent-pubkey-full:` at all, and
/// the guard then authorizes overwriting or deleting a file that does not
/// carry the tuple. Each needle is asserted on its own here, and the first
/// miss returns.
///
/// The binding version is deliberately **not** one of the needles. It is
/// compared as an ordering, `-le BINDING_VERSION_NUM`: a file written by an
/// older build of this provider is an authorised upgrade target, so requiring
/// an exact `# binding-version: N` line would make the very install that
/// upgrades a file be refused by that file's own fence. A non-numeric or newer
/// version is a refusal — a layout this build cannot reason about must not be
/// rewritten.
pub(crate) fn marker_fn(required: &[String]) -> String {
    let checks: String = required
        .iter()
        .map(|line| {
            format!(
                "printf '%s\\n' \"$h\" | grep -Fqx -- {} || return 1\n",
                sq(line)
            )
        })
        .collect();
    format!(
        "marker_ok() {{\n\
         {checks}\
         v=$(printf '%s\\n' \"$h\" | sed -n 's/^# binding-version: //p' | head -n 1)\n\
         case \"$v\" in ''|*[!0-9]*) return 1 ;; esac\n\
         [ \"$v\" -le {version} ] || return 1\n\
         return 0\n\
         }}\n",
        checks = checks,
        version = BINDING_VERSION_NUM,
    )
}

/// The shell fragment that refuses to touch an existing file whose own header
/// is not ours.
///
/// `head -n MARKER_SCAN_LINES` rather than an exact slice: a shared artifact
/// carries a shebang on line 1, so its three header lines sit at 2-4, while a
/// per-agent artifact's four start at line 1. Matching exact whole lines
/// anywhere in that window makes the check independent of which.
///
/// The refusal carries no message. The caller knows the path, the reason and
/// which of several operations is speaking; the script knows none of that, and
/// a generic sentence from the wrong layer is worse than a number.
///
/// No `sudo -n` of its own: this fragment only ever appears inside
/// [`under_lease`]'s `sudo -n flock … sh -c`, which is already root. One
/// elevation for the whole critical section is also what lets the lock be
/// opened at all — [`LEASE_DIR`] is `0700 root:root`.
///
/// An empty `required` means unguarded, which `render::plan` never produces —
/// that invariant is asserted where it is established (Task 7), not defended
/// again here.
fn marker_guard(path: &str, required: &[String]) -> String {
    if required.is_empty() {
        return String::new();
    }
    format!(
        "{marker_ok}\
         if test -e {path}; then\n\
         h=$(head -n {scan} {path} || true)\n\
         marker_ok || exit {refused}\n\
         fi\n",
        marker_ok = marker_fn(required),
        path = sq(path),
        scan = MARKER_SCAN_LINES,
        refused = OWNERSHIP_REFUSED,
    )
}

/// The remote script that installs one file: body from stdin, atomically, and
/// only over a target whose own marker says it is ours — while this process
/// still holds the agent's deploy lease.
///
/// Four properties, each load-bearing:
///
/// * **stdin is drained first, and before the lock is taken.** The body
///   reaches the staging path *before* anything can refuse, so a refusal
///   cannot close the pipe under a local `write_all` still in flight and turn
///   a clean refusal into a transport error — and the `flock` is never held
///   across a read that depends on the network, so a rival's acquire waits on
///   three local file operations rather than on a body transfer.
/// * **The target is never observed half-written.** `mv` within one directory
///   is a `rename(2)`: the target goes from old bytes to new with nothing in
///   between. Without this a dropped connection leaves a truncated file with no
///   complete marker, which the guard must then refuse forever — P1-9 and P1-4
///   are only safe together.
/// * **The guard runs in the same shell as the write.** An ownership check
///   performed in an earlier round trip is a TOCTOU with a four-round-trip
///   window; here it is one `rename`.
/// * **So does the lease proof.** Round 4's P1-1: the marker guard establishes
///   *provenance* — this provider, this agent, a binding version we may act on
///   — and says nothing about whether we still hold the lease, so a stalled
///   holder whose lease had been taken over could satisfy it and `mv` a stale
///   render over the winner's files. [`under_lease`] wraps the check-and-mv
///   pair in one `flock`, and the owner record can only change under that same
///   `flock`, so a takeover cannot interleave between them.
///
/// The staging path carries the per-process token, so two providers installing
/// the same shared artifact at the same moment cannot collide on it, and the
/// `trap` removes it on every exit path including both refusals.
fn install_script(file: &RemoteFile, agent: &str, token: &str) -> String {
    let parent = Path::new(&file.path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string());
    let staged = sq(&format!("{}.{token}.tmp", file.path));
    let critical = format!(
        "set -e\n\
         {guard}\
         mv -f {staged} {path}\n",
        guard = marker_guard(&file.path, &file.owner_marker),
        staged = staged,
        path = sq(&file.path),
    );
    format!(
        "set -euo pipefail\n\
         sudo -n mkdir -p {parent}\n\
         trap \"sudo -n rm -f {staged}\" EXIT\n\
         sudo -n install -m {mode} /dev/stdin {staged}\n\
         {fenced}\
         trap - EXIT\n",
        parent = sq(&parent),
        staged = staged,
        mode = file.mode,
        fenced = under_lease(agent, token, &critical),
    )
}

/// The remote script that appends one record to a file, creating it with
/// `file.body` — its marker header — when absent.
///
/// The header is a marker: pubkey, binding version, create-intent, all public,
/// so passing it in argv is safe. The *record* travels on stdin along with
/// everything a capacity warning might carry.
///
/// Fenced like an install — by the target's own marker and by the lease — but
/// not staged: an append has no half-written-target failure mode, and the
/// record is a few hundred bytes, well inside a pipe buffer, so the whole
/// thing fits inside the critical section without the `flock` ever waiting on
/// the network.
fn append_script(file: &RemoteFile, agent: &str, token: &str) -> String {
    let critical = format!(
        "set -e\n\
         {guard}\
         if [ ! -e {path} ]; then \
           printf '%s' {header} | install -m {mode} /dev/stdin {path}; \
         fi\n\
         tee -a {path} > /dev/null\n",
        guard = marker_guard(&file.path, &file.owner_marker),
        path = sq(&file.path),
        mode = file.mode,
        header = sq(&file.body),
    );
    format!(
        "set -euo pipefail\n{}",
        under_lease(agent, token, &critical)
    )
}

/// The full `gcloud` argv for running `script` on the instance over IAP.
///
/// Pure, so the two properties that matter — the tunnel is used, and no
/// `StrictHostKeyChecking` option is passed — are asserted without a network.
fn ssh_argv(project: &str, zone: &str, instance: &str, script: &str) -> Vec<String> {
    vec![
        "compute".to_string(),
        "ssh".to_string(),
        instance.to_string(),
        format!("--project={project}"),
        format!("--zone={zone}"),
        "--tunnel-through-iap".to_string(),
        "--quiet".to_string(),
        "--command".to_string(),
        script.to_string(),
        // Trailing options are handed to the real `ssh`. Deliberately no
        // `-o StrictHostKeyChecking`: gcloud already selects `yes` against
        // ~/.ssh/google_compute_known_hosts, keyed by HostKeyAlias.
        "--".to_string(),
        "-o".to_string(),
        "ConnectTimeout=20".to_string(),
    ]
}

impl Gcloud for Remote {
    /// Invoke `gcloud`, optionally piping `stdin`. Never logs `stdin`.
    fn gcloud(&self, args: &[&str], stdin: Option<&str>) -> Result<Output, String> {
        let mut child = Command::new("gcloud")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{} ({e})", gcloud_not_found()))?;
        if let Some(body) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| "gcloud stdin was not available".to_string())?;
            // A remote script that refuses before reading closes the pipe, so a
            // `BrokenPipe` here is that refusal arriving early — not a transport
            // failure. The exit code and stderr collected below are what report
            // it, and returning an IO error instead would bury the real reason.
            // Rust sets SIGPIPE to ignore at startup, so this surfaces as an
            // `Err` rather than killing the process. Any other IO error is real.
            if let Err(e) = pipe.write_all(body.as_bytes()) {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err(format!("writing to gcloud stdin failed: {e}"));
                }
            }
            // Dropped explicitly: the child waits for EOF, and a pipe held open
            // by a named binding would deadlock `wait_with_output`.
            drop(pipe);
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for gcloud failed: {e}"))?;
        Ok(Output {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code().unwrap_or(-1),
        })
    }
}

impl Remote {
    /// Bind to an instance, resolving `gcloud` first.
    ///
    /// The `PATH` prepend and the resolution probe live here so there is
    /// exactly one place they can be forgotten, and so a missing `gcloud` is a
    /// named refusal rather than a `NotFound` from some later spawn.
    pub fn new(project: &str, zone: &str, instance: &str) -> Result<Self, String> {
        prepend_gcloud_path();
        if !resolves_on_path("gcloud") {
            return Err(gcloud_not_found());
        }
        Ok(Self {
            project: project.to_string(),
            zone: zone.to_string(),
            instance: instance.to_string(),
            // One per provider process, which is one per operation.
            token: new_generation(),
        })
    }

    /// This process's token, mixed into every staging path and into the deploy
    /// lease record, so two concurrent providers can neither collide on a
    /// staging path nor release each other's lease.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Run a shell script on the instance over IAP.
    pub fn run(&self, script: &str) -> Result<Output, String> {
        self.run_with_stdin(script, None)
    }

    fn run_with_stdin(&self, script: &str, stdin: Option<&str>) -> Result<Output, String> {
        let argv = ssh_argv(&self.project, &self.zone, &self.instance, script);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.gcloud(&borrowed, stdin)
    }

    /// The refusal for a target that exists and is not this agent's.
    ///
    /// "at a binding version this build may act on" rather than "at binding
    /// version N": the guard admits an *older* version — that is the upgrade
    /// path — and refuses a newer or foreign one, so naming this build's exact
    /// version would describe a check the script does not perform.
    fn not_ours(&self, path: &str, verb: &str) -> String {
        format!(
            "{path} is present on the instance but does not carry this agent's \
             {MANAGED_BY} marker at a binding version this build may act on \
             (this build writes {BINDING_VERSION}; a newer one is refused \
             rather than downgraded). Refusing to {verb} a file this provider \
             did not write for this agent — it was left exactly as it was. \
             Move it aside, or run `buzz-backend-gcp list` to see which agent \
             owns it."
        )
    }

    /// Install one file, body on stdin, atomically, behind its own marker
    /// guard **and** the deploy lease.
    ///
    /// `lease` is not decoration and it is not a `&str`: the only implementor
    /// of [`Held`] is `reconcile::DeployLease`, whose sole constructor writes
    /// the owner record first, so "this write happens under a lease" is a
    /// thing the signature says rather than a thing a comment hopes.
    /// [`LOCK_UNAVAILABLE`] and [`OWNERSHIP_REFUSED`] earn different
    /// sentences: one tells the operator to re-run, the other tells them to
    /// move a file aside, and acting on the wrong one deletes a healthy file.
    pub(crate) fn install(&self, file: &RemoteFile, lease: &dyn Held) -> Result<(), String> {
        let script = install_script(file, lease.agent(), &self.token);
        let out = self.run_with_stdin(&script, Some(&file.body))?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(lease_lost(&file.path));
        }
        if out.code == OWNERSHIP_REFUSED {
            return Err(self.not_ours(&file.path, "overwrite"));
        }
        if !out.ok() {
            // `file.body` is deliberately absent from this message.
            return Err(format!(
                "installing {} failed (exit {}): {}",
                file.path,
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    /// Append one record, creating the file with its marker header when absent.
    pub(crate) fn append(
        &self,
        file: &RemoteFile,
        record: &str,
        lease: &dyn Held,
    ) -> Result<(), String> {
        let script = append_script(file, lease.agent(), &self.token);
        let out = self.run_with_stdin(&script, Some(record))?;
        if out.code == LOCK_UNAVAILABLE {
            return Err(lease_lost(&file.path));
        }
        if out.code == OWNERSHIP_REFUSED {
            return Err(self.not_ours(&file.path, "append a deploy record to"));
        }
        if !out.ok() {
            return Err(format!(
                "appending to {} failed (exit {}): {}",
                file.path,
                out.code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    /// Run a **root** script on the instance under this agent's deploy lease.
    ///
    /// The counterpart to [`Remote::run`] for anything that mutates and is not
    /// a file install: the fenced stop, the start, and `operator`'s removal
    /// script. Callers write plain root commands — no `set` line, no `sudo -n`
    /// — and [`under_lease`] supplies the elevation, the `flock` and the
    /// ownership proof. The exit code reaches the caller untouched, because
    /// each of those three speaks its own vocabulary on top of
    /// [`LOCK_UNAVAILABLE`].
    pub(crate) fn run_fenced(&self, lease: &dyn Held, root_script: &str) -> Result<Output, String> {
        self.run(&format!(
            "set -uo pipefail\n{}",
            under_lease(lease.agent(), &self.token, root_script)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{header_line, SHARED_SCOPE};
    use std::ffi::OsString;

    /// The 12-lowercase-hex agent whose lease the fenced scripts prove. It is
    /// only ever interpolated into the two lease paths, so any value the
    /// naming grammar can produce does.
    const AGENT: &str = "a1b2c3d4e5f6";

    /// The two identity lines a per-agent target must already carry.
    ///
    /// `create-intent` is absent because it changes on every legitimate
    /// reconfiguration, so requiring it would refuse a file this agent wrote.
    /// `binding-version` is absent for a different reason: `marker_ok`
    /// compares it as an *ordering*, so a file written by an older build of
    /// this provider can be upgraded rather than refused by its own fence.
    fn marker_lines() -> Vec<String> {
        vec![
            header_line("managed-by", MANAGED_BY),
            header_line("agent-pubkey-full", &"ab".repeat(32)),
        ]
    }

    fn file(path: &str, mode: &'static str, body: &str) -> RemoteFile {
        RemoteFile {
            path: path.to_string(),
            mode,
            body: body.to_string(),
            owner_marker: marker_lines(),
        }
    }

    /// A needle as it appears once a critical section has been `sq`-wrapped
    /// for `sh -c`: every single quote becomes `'\''`. Asserting on the
    /// wrapped form is the honest way to check a nested script — the
    /// alternative is asserting only on fragments that happen to carry no
    /// quotes, which silently stops covering the interesting ones.
    fn nested(fragment: &str) -> String {
        fragment.replace('\'', r"'\''")
    }

    #[test]
    fn the_install_command_never_carries_the_body() {
        let script = install_script(
            &file("/etc/buzz/acp-abc.env", "0600", "SUPER_SENSITIVE=1\n"),
            AGENT,
            "t0ken",
        );
        assert!(script.contains("/dev/stdin"));
        assert!(script.contains("'/etc/buzz/acp-abc.env'"));
        assert!(script.contains("-m 0600"));
        assert!(
            !script.contains("SUPER_SENSITIVE"),
            "the body must travel on stdin, never in the command"
        );
    }

    /// P1-9: a dropped connection must never leave a fragment at the target
    /// path. Stage with the final mode, then `mv` — a rename within one
    /// directory, so the target goes from old bytes to new with nothing in
    /// between.
    #[test]
    fn an_install_stages_and_renames_rather_than_writing_in_place() {
        let script = install_script(
            &file("/etc/buzz/acp-abc.env", "0600", "X=1\n"),
            AGENT,
            "t0ken",
        );
        assert!(
            script.contains(&sq("/etc/buzz/acp-abc.env.t0ken.tmp")),
            "{script}"
        );
        assert!(
            script.contains("sudo -n install -m 0600 /dev/stdin"),
            "{script}"
        );
        assert!(script.contains(&nested("mv -f")), "{script}");
        let staged = script.find("install -m").expect("the staged write");
        let rename = script.find("mv -f").expect("the rename");
        assert!(
            staged < rename,
            "the body is written before it is renamed: {script}"
        );
        // The staging path carries the per-process token, so two providers
        // installing the same shared artifact cannot collide on it.
        assert!(script.contains("t0ken"), "{script}");
        assert!(
            script.contains("trap"),
            "a refusal must not leak the staged file"
        );
    }

    /// P1-4: the target's own marker vetoes the write, in the same shell as the
    /// write — and stdin is drained before the veto can fire, so a clean
    /// refusal never surfaces as a broken pipe.
    #[test]
    fn an_install_refuses_a_target_carrying_somebody_elses_marker() {
        let script = install_script(
            &file("/etc/buzz/acp-abc.env", "0600", "X=1\n"),
            AGENT,
            "t0ken",
        );
        for required in marker_lines() {
            assert!(
                script.contains(&nested(&sq(&required))),
                "the guard omits {required:?}"
            );
        }
        assert!(script.contains(&OWNERSHIP_REFUSED.to_string()), "{script}");
        assert!(
            !script.contains("create-intent"),
            "requiring the intent would refuse a file this agent wrote: {script}"
        );
        let drained = script.find("/dev/stdin").expect("the staged write");
        let guard = script.find("marker_ok ||").expect("the ownership guard");
        let rename = script.find("mv -f").expect("the rename");
        assert!(
            drained < guard && guard < rename,
            "drain, then check, then rename: {script}"
        );
    }

    /// P1-3. The guard used to be `grep -c -F -x -e a -e b -e c` compared
    /// against `3`, and `grep -c` counts matching input **lines**, not
    /// distinct matched patterns. A header whose first lines repeat
    /// `# managed-by:` and `# binding-version:` therefore reached the expected
    /// count while carrying no `# agent-pubkey-full:` at all — so the guard
    /// authorized overwriting a file that never named this agent, which is the
    /// "a marker-looking file authorises the wrong file" hole the deleted
    /// tamper check was supposed to have closed. Each needle is asserted on
    /// its own now, and the first miss returns.
    #[test]
    fn a_header_that_repeats_one_marker_line_does_not_satisfy_the_guard() {
        let script = install_script(
            &file("/etc/buzz/acp-abc.env", "0600", "X=1\n"),
            AGENT,
            "t0ken",
        );
        assert!(
            !script.contains("grep -c"),
            "counting lines instead of patterns is the defect: {script}"
        );
        assert_eq!(
            script.matches("grep -Fqx").count(),
            marker_lines().len(),
            "one independent check per needle: {script}"
        );
        for line in marker_lines() {
            assert!(
                script.contains(&nested(&format!("grep -Fqx -- {}", sq(&line)))),
                "{line:?} is not asserted on its own: {script}"
            );
        }

        // The shared tier is the same function with a different needle set, so
        // a header that repeats `# managed-by:` and omits `# scope:` fails for
        // the same reason.
        let shared = marker_guard(
            "/usr/local/sbin/buzz-acp-fetch-key",
            &[
                header_line("managed-by", MANAGED_BY),
                header_line("scope", SHARED_SCOPE),
            ],
        );
        assert_eq!(shared.matches("grep -Fqx").count(), 2, "{shared}");
        assert!(
            shared.contains(&format!(
                "grep -Fqx -- {}",
                sq(&header_line("scope", SHARED_SCOPE))
            )),
            "{shared}"
        );
    }

    /// P1-1's install half: the binding version is compared as an ordering, so
    /// the very install that upgrades a prior-version file is not refused by
    /// that file's own fence — and a *newer* one still is.
    #[test]
    fn the_guard_admits_an_older_binding_version_and_refuses_a_newer_one() {
        let script = install_script(
            &file("/etc/buzz/acp-abc.env", "0600", "X=1\n"),
            AGENT,
            "t0ken",
        );
        assert!(
            script.contains(&format!("-le {BINDING_VERSION_NUM}")),
            "{script}"
        );
        assert!(
            !script.contains(&sq(&header_line("binding-version", BINDING_VERSION))),
            "an exact binding-version needle is the upgrade lockout: {script}"
        );
        // A version that is not a number describes no layout to order against.
        assert!(script.contains("[!0-9]"), "{script}");
    }

    /// Every privileged step is non-interactive, and there are exactly two of
    /// them: the staging write outside the lock, and the one `sudo -n flock`
    /// that elevates the whole critical section. A bare `sudo` on a prompting
    /// host would consume the piped body as keystrokes and write a truncated
    /// root-owned unit file.
    #[test]
    fn every_privileged_step_is_non_interactive() {
        let script = install_script(
            &file(
                "/etc/systemd/system/buzz-acp@abc.service.d/agent.conf",
                "0644",
                "",
            ),
            AGENT,
            "t0ken",
        );
        assert!(script.contains("sudo -n mkdir -p '/etc/systemd/system/buzz-acp@abc.service.d'"));
        assert!(script.contains("sudo -n install"));
        assert!(script.contains("sudo -n flock"));
        for bare in ["sudo mkdir", "sudo install", "sudo flock", "sudo mv"] {
            assert!(
                !script.contains(bare),
                "a privileged step without -n can prompt: {bare}"
            );
        }
        // Inside the wrapper everything is root already, so a nested `sudo`
        // would be a second thing to get wrong — and on a host whose sudoers
        // does not let root sudo, a second failure mode for no benefit.
        let inner = script.find("sh -c '").expect("the critical section");
        assert!(
            !script[inner..].contains("sudo"),
            "the critical section must not re-elevate: {script}"
        );
    }

    #[test]
    fn the_append_script_creates_the_file_once_then_appends_behind_the_same_fence() {
        let script = append_script(
            &file("/etc/buzz/acp-abc.trail", "0644", "# managed-by: x\n"),
            AGENT,
            "t0ken",
        );
        assert!(
            script.contains(&nested("if [ ! -e '/etc/buzz/acp-abc.trail' ]")),
            "{script}"
        );
        assert!(
            script.contains(&nested(
                "install -m 0644 /dev/stdin '/etc/buzz/acp-abc.trail'"
            )),
            "{script}"
        );
        assert!(
            script.contains(&nested("tee -a '/etc/buzz/acp-abc.trail'")),
            "{script}"
        );
        // A trail that is not ours must not be appended to either.
        assert!(script.contains(&OWNERSHIP_REFUSED.to_string()), "{script}");
        // …and neither must one whose lease has moved on.
        assert!(script.contains(&LOCK_UNAVAILABLE.to_string()), "{script}");
    }

    /// Round 4's P1-1. The marker guard proves *provenance*; it says nothing
    /// about whether this process still holds the lease, so a stalled holder
    /// that had been legitimately overtaken could satisfy it and `mv` a stale
    /// render over the winner's files. The proof and the mutation now share
    /// one `flock`, which is the only arrangement a takeover cannot slip
    /// between: changing the owner record needs the same lock.
    #[test]
    fn an_install_proves_the_lease_in_the_same_shell_as_the_rename() {
        let script = install_script(
            &file("/etc/buzz/acp-abc.env", "0600", "X=1\n"),
            AGENT,
            "t0ken",
        );
        let (lock, owner) = lease_paths(AGENT);
        assert!(script.contains(&sq(&lock)), "no lock is taken: {script}");
        assert!(
            script.contains("sudo -n flock -w"),
            "the critical section is not elevated as one: {script}"
        );
        assert!(
            script.contains(&nested(&sq(&owner))),
            "the owner record is not read: {script}"
        );
        assert!(script.contains(&LOCK_UNAVAILABLE.to_string()), "{script}");

        // Drain, then lock, then prove, then check the marker, then rename.
        // The drain is outside the lock deliberately: holding it across a read
        // that waits on the network would block a rival's acquire for as long
        // as the body takes to arrive.
        let drained = script.find("/dev/stdin").expect("the staged write");
        let lock_at = script.find("flock -w").expect("the lock");
        let gate = script.find("cut -d").expect("the lease proof");
        let guard = script.find("marker_ok ||").expect("the ownership guard");
        let rename = script.find("mv -f").expect("the rename");
        assert!(
            drained < lock_at && lock_at < gate && gate < guard && guard < rename,
            "drain, lock, prove the lease, check the marker, rename: {script}"
        );
        assert_eq!(
            script.matches("sh -c '").count(),
            1,
            "a second shell is a second chance to lose the lease: {script}"
        );
    }

    /// `gcloud` already selects `StrictHostKeyChecking=yes` against its own
    /// known-hosts file, keyed by `HostKeyAlias` rather than by IP. Passing
    /// `no` would be a strict *downgrade* of a check that is already correct —
    /// while installing root-owned unit files over that same channel.
    #[test]
    fn the_ssh_argv_never_downgrades_host_key_checking() {
        let argv = ssh_argv("proj", "zone-a", "inst", "true");
        assert!(
            !argv.iter().any(|a| a.contains("StrictHostKeyChecking")),
            "the provider must pass no StrictHostKeyChecking option at all"
        );
        assert!(argv.iter().any(|a| a == "--tunnel-through-iap"));
        assert!(argv.iter().any(|a| a == "--project=proj"));
        assert!(argv.iter().any(|a| a == "--zone=zone-a"));
        assert!(argv.iter().any(|a| a == "inst"));
        // The script reaches the remote as `--command`, so stdin stays free
        // for the file body.
        let command = argv
            .iter()
            .position(|a| a == "--command")
            .expect("--command");
        assert_eq!(argv[command + 1], "true");
    }

    #[test]
    fn single_quoting_survives_an_embedded_quote() {
        assert_eq!(sq("plain"), "'plain'");
        assert_eq!(sq("it's"), r"'it'\''s'");
    }

    #[test]
    fn the_prepended_path_puts_the_gcloud_directories_first() {
        let home = std::path::PathBuf::from("/Users/x");
        let joined =
            prepended_path(Some(home.as_path()), &OsString::from("/usr/bin:/bin")).expect("join");
        let dirs: Vec<String> = std::env::split_paths(&joined)
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            dirs,
            [
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/Users/x/.local/bin",
                "/usr/bin",
                "/bin"
            ]
        );
    }

    /// An empty inherited `PATH` splits into one empty entry, which POSIX
    /// resolves as the current directory — never a place `gcloud` may be found.
    #[test]
    fn empty_path_entries_are_dropped_not_propagated() {
        let joined = prepended_path(None, &OsString::from("")).expect("join");
        let dirs: Vec<String> = std::env::split_paths(&joined)
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(dirs, ["/opt/homebrew/bin", "/usr/local/bin"]);
    }

    /// A bare `NotFound` from `Command::spawn` tells the operator nothing
    /// actionable, and the cause has nothing to do with GCP.
    #[test]
    fn the_not_found_error_names_the_remedy() {
        let message = gcloud_not_found();
        assert!(message.contains("gcloud"));
        assert!(message.contains("/opt/homebrew/bin"));
        assert!(
            message.contains("Google Cloud CLI"),
            "the operator needs to know what to install"
        );
    }
}
