//! Reading remote state (spec §Deploy Reconciliation step 1).
//!
//! Two independent facts, deliberately two types: what **systemd** reports
//! about the units, and what our **markers** say about ownership. Deriving one
//! from the other is how a real unit with no env file classifies as "absent"
//! and gets provider files installed around it.
//!
//! Ownership is recorded per artifact, not per agent. Four files are written by
//! a replace and deleted by a remove, so one shared verdict would authorize
//! destroying three files nothing ever looked at.

use crate::capacity::parse_reported_bytes;
use crate::config::parse_memory_max;
use crate::naming::{
    agent_ownership, header_line, shared_ownership, AgentMarker, Names, Ownership,
};
use crate::remote::{sq, Remote, MARKER_SCAN_LINES};

/// The three artifacts every instance shares. Order is fixed so the observer's
/// output and the renderer's plan line up by index as well as by path.
pub const SHARED_PATHS: [&str; 3] = [
    "/etc/systemd/system/buzz-acp@.service",
    "/etc/systemd/system/buzz-acp-secret@.service",
    "/usr/local/sbin/buzz-acp-fetch-key",
];

/// The four artifacts belonging to exactly one agent, in one fixed order shared
/// by the observer script, its parser, and `remove`.
///
/// The env file is first, and [`MarkerState`] keeps it in its own field: it is
/// the artifact a deploy *classifies on*, because it is the one whose marker
/// records what the previous deploy intended.
///
/// That does **not** mean its siblings are never read for intent — they were
/// not, and round 4's P1-3 is what that cost. An install torn between the env
/// write and a later per-agent write leaves the env marker carrying the new
/// create-intent beside siblings carrying the old one, all of them still ours
/// and still this agent's, and `classify` called it healthy and restarted the
/// unit against stale drop-ins. `reconcile::classify` now reads every
/// sibling's `create_intent` and lets `RestartSame` stand only when all four
/// agree with the env file; the env file's primacy is that it supplies the
/// intent the others are compared against, not that the others are ignored.
pub fn agent_paths(names: &Names) -> [String; 4] {
    [
        names.env_path(),
        names.dropin_path(),
        names.secret_dropin_path(),
        names.trail_path(),
    ]
}

/// What systemd reports about this agent's unit — independent of any file this
/// provider wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemdState {
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub main_pid: u32,
}

impl SystemdState {
    /// Does systemd know about **this instance**?
    ///
    /// Deliberately not `LoadState`: once the template `buzz-acp@.service`
    /// exists, `systemctl show buzz-acp@<anything>.service` reports
    /// `LoadState=loaded` for every instance name. An install symlink
    /// (`UnitFileState=enabled`) or a live job is the real evidence.
    pub fn instance_known(&self) -> bool {
        self.unit_file_state == "enabled" || !matches!(self.active_state.as_str(), "" | "inactive")
    }

    /// Is the harness process confirmed running? I4's "live" means *started*,
    /// not that systemd accepted the unit body.
    pub fn running(&self) -> bool {
        self.active_state == "active" && self.main_pid > 0
    }
}

/// One per-agent artifact as it exists on the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFileState {
    pub path: String,
    pub present: bool,
    /// What **this file's own** header says about who wrote it, and at which
    /// binding version. [`Ownership::OursButOlder`] is an authorised upgrade
    /// target; [`Ownership::OursButNewer`] and [`Ownership::NotOurs`] are
    /// refusals, and they are separate states because a newer build of this
    /// provider is not a stranger and must not be described as one.
    pub ownership: Ownership,
    /// The identity half of the same header: which agent, and what intent.
    ///
    /// Independent of `ownership`, not a restatement of it — a file can carry
    /// our marker at our version and still have no `agent-pubkey-full` line,
    /// which is its own refusal with its own message. The implication runs one
    /// way: `Some` is only ever produced for an actionable `ownership`,
    /// because [`AgentMarker::parse`] checks that first.
    pub marker: Option<AgentMarker>,
}

/// One shared artifact as it exists on the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedFileState {
    pub path: String,
    pub present: bool,
    /// What the file's provider-level header says. Ours at this version or an
    /// older one takes the ordinary write-if-different path; a newer one and
    /// an absent marker are both refusals, for different reasons.
    pub ownership: Ownership,
    /// SHA-256 of the file's **whole** contents, header included.
    ///
    /// Compared against the digest of the exact bytes this provider would
    /// render ([`crate::render::SharedArtifact::sha256`]). Both sides are
    /// hashes of real bytes, so there is nothing here for a file to claim about
    /// itself and nothing to strip before hashing.
    pub sha256: String,
}

/// What our markers say — independent of systemd.
#[derive(Debug, Clone, Default)]
pub struct MarkerState {
    /// The env file.
    pub env: AgentFileState,
    /// The agent drop-in, the fetcher drop-in, and the deploy trail, in
    /// [`agent_paths`] order after the env file.
    pub siblings: Vec<AgentFileState>,
    pub shared: Vec<SharedFileState>,
}

impl MarkerState {
    /// Every per-agent artifact, env file first.
    pub fn agent_files(&self) -> impl Iterator<Item = &AgentFileState> {
        std::iter::once(&self.env).chain(self.siblings.iter())
    }
}

/// Everything one reconciliation pass needs, read in a single round trip.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    pub systemd: SystemdState,
    pub markers: MarkerState,
    /// The requested harness binary exists and is executable in
    /// `/usr/local/bin` on the instance.
    pub harness_installed: bool,
    /// Summed `MemoryMax` of every *other* marked agent plus the standing
    /// `buzz-acp.service`.
    pub reserved_bytes: u64,
    pub available_bytes: u64,
}

/// One round trip that collects everything the reconciler needs.
pub fn look(remote: &Remote, names: &Names, harness: &str) -> Result<Observation, String> {
    let out = remote.run(&observe_script(names, harness))?;
    if !out.ok() {
        return Err(format!(
            "observing {} failed (exit {}): {}",
            names.unit(),
            out.code,
            out.stderr.trim()
        ));
    }
    let observation = parse_observation(&out.stdout, &names.dropin_path());
    // A short observation is a malformed one, and a malformed observation reads
    // as "nothing of ours is here" — which classifies as `Create` and installs
    // over a live agent. Four rows, or nothing happens.
    let expected = agent_paths(names).len();
    let seen = observation.markers.agent_files().count();
    if seen != expected {
        return Err(format!(
            "the observer reported {seen} of {expected} per-agent artifacts for \
             {}. Refusing to act on a partial observation.",
            names.unit()
        ));
    }
    Ok(observation)
}

/// The `field` helper both row emitters need: read one `# <name>: ` value out
/// of `$h`, the first few lines of whatever file the loop is currently on.
///
/// `pub(crate)` and a `const` rather than an inline fragment because Task 13's
/// pre-stop ownership scan reuses [`agent_file_rows`], and a helper defined in
/// one script and called from another is the kind of coupling that breaks
/// silently.
pub(crate) const FIELD_HELPER: &str =
    "field() { printf '%s\\n' \"$h\" | sed -n \"s/^# $1: //p\" | head -n 1; }\n";

/// The shell that emits one
/// `path|present|managed-by|binding-version|agent-pubkey-full|create-intent`
/// row per per-agent artifact.
///
/// Factored out of [`observe_script`] and `pub(crate)` because `remove`
/// (Task 13) needs exactly these rows and nothing else: a second emitter of
/// the same shape would be a second thing to keep in step with
/// [`parse_agent_file_row`], and `deploy` and `remove` disagreeing about what
/// a header says is precisely the failure the marker exists to prevent.
/// Assumes [`FIELD_HELPER`] is already defined in the surrounding script.
pub(crate) fn agent_file_rows(names: &Names) -> String {
    format!(
        "for p in {agent_files}; do \
           if sudo -n test -e \"$p\"; then \
             h=$(sudo -n head -n {scan} \"$p\"); \
             printf '%s|present|%s|%s|%s|%s\\n' \"$p\" \"$(field managed-by)\" \
               \"$(field binding-version)\" \"$(field agent-pubkey-full)\" \
               \"$(field create-intent)\"; \
           else \
             printf '%s|absent||||\\n' \"$p\"; \
           fi; \
         done\n",
        agent_files = agent_paths(names)
            .iter()
            .map(|p| sq(p))
            .collect::<Vec<_>>()
            .join(" "),
        scan = MARKER_SCAN_LINES,
    )
}

/// The observer script. Sectioned so the parser is a pure function of text.
///
/// Emitting the header *values* as one `|`-separated row keeps each section
/// line-oriented, and a value that itself contains a `|` is truncated at it,
/// which makes the reassembled header fail to match — the fail-closed
/// direction. Nothing here decides ownership; that is `naming::agent_ownership`
/// / `AgentMarker::parse` and `naming::shared_ownership`, in Rust, for both
/// tiers.
fn observe_script(names: &Names, harness: &str) -> String {
    format!(
        "set -uo pipefail\n\
         {field}\
         echo '---UNIT---'\n\
         systemctl show {unit} -p LoadState -p ActiveState -p SubState \
             -p UnitFileState -p MainPID 2>/dev/null || true\n\
         echo '---AGENTFILES---'\n\
         {agent_rows}\
         echo '---SHARED---'\n\
         for p in {shared}; do \
           if sudo -n test -e \"$p\"; then \
             s=$(sudo -n sha256sum \"$p\" | cut -d' ' -f1); \
             h=$(sudo -n head -n {scan} \"$p\"); \
             printf '%s|present|%s|%s|%s|%s\\n' \"$p\" \"$(field managed-by)\" \
               \"$(field binding-version)\" \"$(field scope)\" \"$s\"; \
           else \
             printf '%s|absent||||\\n' \"$p\"; \
           fi; \
         done\n\
         echo '---RESERVED---'\n\
         for f in /etc/systemd/system/buzz-acp@*.service.d/agent.conf; do \
           [ -e \"$f\" ] || continue; \
           v=$(sudo -n sed -n 's/^MemoryMax=//p' \"$f\" | head -n 1); \
           printf '%s=%s\\n' \"$f\" \"$v\"; \
         done\n\
         echo '---STANDING---'\n\
         systemctl show buzz-acp.service -p MemoryMax --value 2>/dev/null || true\n\
         echo '---AVAILABLE---'\n\
         awk '/^MemAvailable:/ {{print $2}}' /proc/meminfo\n\
         echo '---HARNESS---'\n\
         test -x {harness_path} && echo yes || echo no\n\
         echo '---END---'\n",
        field = FIELD_HELPER,
        unit = sq(&names.unit()),
        agent_rows = agent_file_rows(names),
        shared = SHARED_PATHS
            .iter()
            .map(|p| sq(p))
            .collect::<Vec<_>>()
            .join(" "),
        scan = MARKER_SCAN_LINES,
        harness_path = sq(&format!("/usr/local/bin/{harness}")),
    )
}

/// Extract one `---NAME---` section body.
///
/// `pub(crate)` because `reconcile` drives scripts of the same sectioned shape;
/// two copies of a text splitter would be two places to get the terminator
/// wrong.
pub(crate) fn section<'a>(body: &'a str, name: &str) -> &'a str {
    let opener = format!("---{name}---\n");
    let Some(rest) = body.split(opener.as_str()).nth(1) else {
        return "";
    };
    rest.split("---").next().unwrap_or("")
}

/// Read one `Key=value` line out of a `systemctl show` block.
pub(crate) fn property<'a>(block: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    block
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or("")
        .trim()
}

/// Decode one `path|present|managed-by|binding-version|pubkey|intent` row.
///
/// The four header values are reassembled into the lines they came from and
/// handed to [`agent_ownership`] and [`AgentMarker::parse`], so "is this ours"
/// is decided by exactly one pair of functions for the bytes this provider
/// renders and the bytes it reads back. `pub(crate)` because Task 13's
/// pre-stop scan parses the same rows.
pub(crate) fn parse_agent_file_row(line: &str) -> AgentFileState {
    let mut parts = line.split('|');
    let path = parts.next().unwrap_or("").to_string();
    let present = parts.next().unwrap_or("") == "present";
    let header = format!(
        "{}\n{}\n{}\n{}\n",
        header_line("managed-by", parts.next().unwrap_or("").trim()),
        header_line("binding-version", parts.next().unwrap_or("").trim()),
        header_line("agent-pubkey-full", parts.next().unwrap_or("").trim()),
        header_line("create-intent", parts.next().unwrap_or("").trim()),
    );
    AgentFileState {
        path,
        present,
        // An absent file carries no marker of any kind, whatever the rest of
        // the row says — the row for an absent file is all-empty fields, but
        // being explicit here keeps the invariant local rather than implied.
        ownership: if present {
            agent_ownership(&header)
        } else {
            Ownership::NotOurs
        },
        marker: present.then(|| AgentMarker::parse(&header)).flatten(),
    }
}

/// Decode one `path|present|managed-by|binding-version|scope|sha256` row.
///
/// Same shape as [`parse_agent_file_row`] and the same discipline: the header
/// values are reassembled and handed to the one function that also judges the
/// bytes this provider renders, so "is this ours" has a single definition per
/// tier rather than one in Rust and one in shell.
fn parse_shared_file_row(line: &str) -> SharedFileState {
    let mut parts = line.split('|');
    let path = parts.next().unwrap_or("").to_string();
    let present = parts.next().unwrap_or("") == "present";
    let header = format!(
        "{}\n{}\n{}\n",
        header_line("managed-by", parts.next().unwrap_or("").trim()),
        header_line("binding-version", parts.next().unwrap_or("").trim()),
        header_line("scope", parts.next().unwrap_or("").trim()),
    );
    SharedFileState {
        path,
        present,
        ownership: if present {
            shared_ownership(&header)
        } else {
            Ownership::NotOurs
        },
        sha256: parts.next().unwrap_or("").trim().to_string(),
    }
}

/// Decode the observer script's output.
///
/// `own_dropin` is this agent's own drop-in path, excluded from the reserved
/// total: a redeploy would otherwise count the memory it is about to rewrite.
pub fn parse_observation(stdout: &str, own_dropin: &str) -> Observation {
    let unit = section(stdout, "UNIT");
    let systemd = SystemdState {
        load_state: property(unit, "LoadState").to_string(),
        active_state: property(unit, "ActiveState").to_string(),
        sub_state: property(unit, "SubState").to_string(),
        unit_file_state: property(unit, "UnitFileState").to_string(),
        main_pid: property(unit, "MainPID").parse().unwrap_or(0),
    };

    let mut agent_files: Vec<AgentFileState> = section(stdout, "AGENTFILES")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_agent_file_row)
        .collect();
    // `agent_paths` puts the env file first. An empty section yields a default
    // absent env file rather than a panic; `look` refuses on the row count.
    let env = if agent_files.is_empty() {
        AgentFileState::default()
    } else {
        agent_files.remove(0)
    };

    let shared = section(stdout, "SHARED")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_shared_file_row)
        .collect();

    let reserved_from_agents: u64 = section(stdout, "RESERVED")
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(path, _)| *path != own_dropin)
        // Our own drop-ins carry the operator's spelling (`2G`), which is the
        // closed input grammar — not systemd's byte echo.
        .filter_map(|(_, value)| parse_memory_max(value.trim()).ok())
        .sum();
    let standing = parse_reported_bytes(section(stdout, "STANDING")).unwrap_or(0);

    let available_kb: u64 = section(stdout, "AVAILABLE").trim().parse().unwrap_or(0);

    Observation {
        systemd,
        markers: MarkerState {
            env,
            siblings: agent_files,
            shared,
        },
        harness_installed: section(stdout, "HARNESS").trim() == "yes",
        reserved_bytes: reserved_from_agents.saturating_add(standing),
        available_bytes: available_kb.saturating_mul(1024),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{BINDING_VERSION, MANAGED_BY, SHARED_SCOPE};

    const INSTANCE: &str = "a1b2c3d4e5f6";
    const OWN_DROPIN: &str = "/etc/systemd/system/buzz-acp@a1b2c3d4e5f6.service.d/agent.conf";
    /// A row body for a file that is not there. Both tiers carry four header
    /// fields — `managed-by`, `binding-version`, then `agent-pubkey-full` and
    /// `create-intent` for a per-agent row or `scope` and the digest for a
    /// shared one — so one spelling serves both.
    const ABSENT: &str = "absent||||";

    fn pubkey() -> String {
        "ab".repeat(32)
    }

    /// A row body for a present file carrying our full per-agent marker.
    fn marked() -> String {
        format!("present|{MANAGED_BY}|{BINDING_VERSION}|{}|ci", pubkey())
    }

    /// The four per-agent rows the observer emits, in `agent_paths` order.
    fn agent_rows(env: &str, dropin: &str, secret_dropin: &str, trail: &str) -> String {
        format!(
            "/etc/buzz/acp-{INSTANCE}.env|{env}\n\
             {OWN_DROPIN}|{dropin}\n\
             /etc/systemd/system/buzz-acp-secret@{INSTANCE}.service.d/agent.conf|{secret_dropin}\n\
             /etc/buzz/acp-{INSTANCE}.trail|{trail}\n"
        )
    }

    fn sample(unit: &str, agent_files: &str, shared: &str, reserved: &str) -> String {
        format!(
            "---UNIT---\n{unit}\
             ---AGENTFILES---\n{agent_files}\
             ---SHARED---\n{shared}\
             ---RESERVED---\n{reserved}\
             ---STANDING---\ninfinity\n\
             ---AVAILABLE---\n2831156\n\
             ---HARNESS---\nyes\n\
             ---END---\n"
        )
    }

    fn all_shared_marked() -> String {
        SHARED_PATHS
            .iter()
            .map(|p| {
                format!("{p}|present|{MANAGED_BY}|{BINDING_VERSION}|{SHARED_SCOPE}|hash-{p}\n")
            })
            .collect()
    }

    /// A row body for a present file carrying our per-agent marker at an
    /// arbitrary binding version, so the ordering rule can be exercised now —
    /// the bump that creates a real prior version is exactly the moment nobody
    /// will re-derive it.
    fn marked_at(version: &str) -> String {
        format!("present|{MANAGED_BY}|{version}|{}|ci", pubkey())
    }

    #[test]
    fn a_running_instance_parses_as_live_and_owned() {
        let out = sample(
            "LoadState=loaded\nActiveState=active\nSubState=running\n\
             UnitFileState=enabled\nMainPID=4242\n",
            &agent_rows(&marked(), &marked(), &marked(), &marked()),
            &all_shared_marked(),
            &format!("{OWN_DROPIN}=2G\n/etc/systemd/system/buzz-acp@ffffffffffff.service.d/agent.conf=1G\n"),
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.systemd.instance_known());
        assert!(o.systemd.running());
        assert!(o.markers.env.present);
        assert!(o.markers.env.marker.is_some());
        assert!(o.markers.agent_files().all(|f| f.marker.is_some()));
        assert!(o.harness_installed);
        // Our own drop-in is excluded, or a redeploy would double-count itself.
        assert_eq!(o.reserved_bytes, 1024 * 1024 * 1024);
        assert_eq!(o.available_bytes, 2_831_156 * 1024);
        assert!(o
            .markers
            .shared
            .iter()
            .all(|s| s.present && s.ownership == Ownership::Ours));
    }

    /// A template unit makes `systemctl show` report `LoadState=loaded` for
    /// every instance name, so `LoadState` alone must never mean "this
    /// instance exists".
    #[test]
    fn a_loaded_template_is_not_evidence_that_this_instance_exists() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=disabled\nMainPID=0\n",
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(!o.systemd.instance_known());
        assert!(!o.systemd.running());
        assert!(!o.markers.env.present);
    }

    /// A failed unit is very much this instance: it has to be observable, or
    /// the reconciler classifies a broken agent as absent and installs over it.
    #[test]
    fn a_failed_instance_is_known() {
        let out = sample(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\n\
             UnitFileState=enabled\nMainPID=0\n",
            &agent_rows(&marked(), ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.systemd.instance_known());
        assert!(!o.systemd.running());
    }

    /// `active` with no main PID is not started. I4's "live" means the harness
    /// process is confirmed running, not that systemd accepted the unit.
    #[test]
    fn active_without_a_main_pid_is_not_running() {
        let out = sample(
            "LoadState=loaded\nActiveState=active\nSubState=running\n\
             UnitFileState=enabled\nMainPID=0\n",
            &agent_rows(&marked(), ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        );
        assert!(!parse_observation(&out, OWN_DROPIN).systemd.running());
    }

    #[test]
    fn an_absent_agent_parses_as_absent() {
        let out = sample(
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=\nMainPID=0\n",
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
            &SHARED_PATHS
                .iter()
                .map(|p| format!("{p}|{ABSENT}\n"))
                .collect::<String>(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(!o.systemd.instance_known());
        assert!(o
            .markers
            .agent_files()
            .all(|f| !f.present && f.marker.is_none()));
        assert!(o
            .markers
            .shared
            .iter()
            .all(|s| !s.present && s.ownership == Ownership::NotOurs));
        assert_eq!(o.reserved_bytes, 0);
    }

    #[test]
    fn an_env_file_without_our_marker_is_present_but_unowned() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=enabled\nMainPID=0\n",
            &agent_rows("present||||", ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert!(o.markers.env.present);
        assert!(o.markers.env.marker.is_none());
    }

    /// P1-1's observation half. A version this build supersedes must read as
    /// *ours, one layout behind* — with its identity intact, because `remove`
    /// needs that pubkey — and a version it does not understand must read as
    /// neither ours nor anonymous.
    #[test]
    fn a_row_reports_an_older_version_as_ours_and_a_newer_one_as_not() {
        let unit = "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
                    UnitFileState=enabled\nMainPID=0\n";
        let older = parse_observation(
            &sample(
                unit,
                &agent_rows(&marked_at("0"), ABSENT, ABSENT, ABSENT),
                &all_shared_marked(),
                "",
            ),
            OWN_DROPIN,
        );
        assert_eq!(older.markers.env.ownership, Ownership::OursButOlder(0));
        assert_eq!(
            older
                .markers
                .env
                .marker
                .as_ref()
                .map(|m| m.pubkey_full.clone()),
            Some(pubkey()),
            "an upgrade target must keep the identity remove acts on"
        );

        let newer = parse_observation(
            &sample(
                unit,
                &agent_rows(&marked_at("99"), ABSENT, ABSENT, ABSENT),
                &all_shared_marked(),
                "",
            ),
            OWN_DROPIN,
        );
        assert_eq!(newer.markers.env.ownership, Ownership::OursButNewer(99));
        assert!(
            newer.markers.env.marker.is_none(),
            "a layout this build cannot read yields no marker to act on"
        );
    }

    /// P1-4's observation half: four artifacts, four independent verdicts. A
    /// marked env file beside an unmarked drop-in has to read as exactly that,
    /// or the fence downstream has nothing to refuse on.
    #[test]
    fn each_per_agent_artifact_reports_its_own_marker() {
        let foreign = format!(
            "present|{MANAGED_BY}|{BINDING_VERSION}|{}|ci",
            "ff".repeat(32)
        );
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=enabled\nMainPID=0\n",
            &agent_rows(&marked(), "present||||", &foreign, ABSENT),
            &all_shared_marked(),
            "",
        );
        let o = parse_observation(&out, OWN_DROPIN);
        assert_eq!(o.markers.agent_files().count(), 4);
        assert!(o.markers.env.marker.is_some());
        assert!(o.markers.siblings[0].present, "the drop-in is there");
        assert!(
            o.markers.siblings[0].marker.is_none(),
            "…and carries no marker of ours, which must be visible on its own row"
        );
        assert_eq!(
            o.markers.siblings[1]
                .marker
                .as_ref()
                .map(|m| m.pubkey_full.as_str()),
            Some("ff".repeat(32).as_str()),
            "a sibling belonging to another agent keeps its own identity"
        );
        assert!(!o.markers.siblings[2].present);
    }

    /// A shared file with our name and no provider marker is somebody else's.
    /// There is deliberately no third state: nothing in the file claims what
    /// its own content should be, so "edited underneath us" is not a verdict
    /// this observer can reach — or should try to.
    #[test]
    fn a_shared_file_without_the_provider_marker_is_reported_unmarked() {
        let shared = format!(
            "{}|present||||deadbeef\n\
             {}|present|{MANAGED_BY}|{BINDING_VERSION}|{SHARED_SCOPE}|h\n\
             {}|present|{MANAGED_BY}|{BINDING_VERSION}|{SHARED_SCOPE}|h\n",
            SHARED_PATHS[0], SHARED_PATHS[1], SHARED_PATHS[2]
        );
        let o = parse_observation(
            &sample(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
                 UnitFileState=disabled\nMainPID=0\n",
                &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
                &shared,
                "",
            ),
            OWN_DROPIN,
        );
        assert!(o.markers.shared[0].present);
        assert_eq!(o.markers.shared[0].ownership, Ownership::NotOurs);
        assert_eq!(o.markers.shared[0].sha256, "deadbeef");
        assert_eq!(o.markers.shared[1].ownership, Ownership::Ours);
    }

    #[test]
    fn a_missing_harness_is_observed() {
        let out = sample(
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=\nMainPID=0\n",
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        )
        .replace("---HARNESS---\nyes\n", "---HARNESS---\nno\n");
        assert!(!parse_observation(&out, OWN_DROPIN).harness_installed);
    }

    /// The standing `buzz-acp.service` counts toward reserved memory when it
    /// declares a bound, and contributes nothing when it says `infinity`.
    #[test]
    fn the_standing_unit_contributes_its_declared_bound() {
        let out = sample(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
             UnitFileState=disabled\nMainPID=0\n",
            &agent_rows(ABSENT, ABSENT, ABSENT, ABSENT),
            &all_shared_marked(),
            "",
        )
        .replace("---STANDING---\ninfinity\n", "---STANDING---\n536870912\n");
        assert_eq!(
            parse_observation(&out, OWN_DROPIN).reserved_bytes,
            512 * 1024 * 1024
        );
    }

    /// The script has to read all four per-agent artifacts and hash each shared
    /// file **whole**. A script that read only the env file would leave the
    /// per-artifact fence with nothing to fence on, and one that stripped a
    /// header before hashing would be the deleted tamper check growing back.
    #[test]
    fn the_observer_reads_every_artifact_and_hashes_shared_files_whole() {
        let names = Names::from_pubkey_hex(&format!("{INSTANCE}{}", "0".repeat(52))).unwrap();
        let script = observe_script(&names, "codex-acp");
        for path in agent_paths(&names) {
            assert!(script.contains(&sq(&path)), "{path} is never read");
        }
        assert!(script.contains("sha256sum"), "{script}");
        assert!(
            !script.contains("content-hash"),
            "nothing reads a digest back out of a file any more"
        );
        assert!(
            !script.contains(",+3d"),
            "the GNU-sed marker strip went with it"
        );
    }

    /// Both marker headers must fit inside the window this observer scans. The
    /// worst case is the fetcher script, whose shebang pushes its three-line
    /// provider header down to lines 2-4. If a header ever grows, this fails
    /// here rather than as a deploy refusing a file it wrote itself.
    #[test]
    fn every_marker_header_fits_the_scan_window() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "ci".to_string(),
        }
        .render();
        assert!(agent.lines().count() <= MARKER_SCAN_LINES, "{agent}");
        let shared = crate::naming::shared_marker();
        assert!(
            shared.lines().count() < MARKER_SCAN_LINES,
            "a shebang sits above this header: {shared}"
        );
    }
}
