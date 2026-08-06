//! Object naming and the two management-marker tiers
//! (spec §Naming and the Management Marker).
//!
//! Names come from [`AgentIdentity`], which can only be constructed by
//! decoding the nsec — so a caller-supplied pubkey or a mutable display name
//! can never reach a path this provider writes to or deletes.
//!
//! The provider-level marker deliberately carries **no content digest**. An
//! earlier revision stored one and had the observer recompute it with the
//! header stripped: the strip was a GNU-`sed` range that deleted every matching
//! block anywhere in the file, the presence of the digest line alone was read
//! as ownership, and a future `binding-version` hashed differently and read as
//! tampering — an unrecoverable upgrade lockout. All three follow from one
//! thing: a digest a file declares about itself cannot detect an editor who can
//! also edit the digest. The mechanism was deleted rather than repaired, and
//! the job it should have been doing is done by comparing the installed bytes
//! against the bytes this provider would render, hashed independently on each
//! side (`observe.rs`, `reconcile::shared_writes`).
//!
//! Deleting that check removed the *tamper* half of the upgrade lockout. The
//! other half lived here, in a boolean that conjoined `managed-by` with an
//! **exact** `binding-version`: on the first bump, every artifact this provider
//! had ever written read as "present and not ours", `deploy` refused to upgrade
//! it and `remove` refused to delete it, and the operator was told their own
//! agent was somebody else's file. Ownership is therefore [`Ownership`], a
//! four-state verdict — and an *older* version is an authorised upgrade target
//! everywhere in this binding, not a refusal.

use buzz_backend_core::identity::AgentIdentity;
use sha2::{Digest, Sha256};

/// The management marker's identity half. **No destructive action may touch a
/// file lacking the marker of its own tier** — that is the auto-repair fence.
pub const MANAGED_BY: &str = "buzz-backend-gcp";

/// Schema version of the artifact layout, as it appears in a header line and
/// in a Secret Manager label. Bump when the unit/env shape changes in a way an
/// older provider would mishandle — and bump [`BINDING_VERSION_NUM`] with it.
pub const BINDING_VERSION: &str = "1";

/// The same value as [`BINDING_VERSION`], as a number.
///
/// Ownership is an *ordering* question — is this artifact older than us, ours,
/// or newer — and a string comparison cannot answer it. This is also the value
/// the shell readers compare against with `-le`
/// (`remote::marker_fn`, `reconcile::fenced_stop_script`,
/// `operator::listing_script`), so the two spellings must agree;
/// `the_two_spellings_of_the_binding_version_agree` asserts it.
pub const BINDING_VERSION_NUM: u32 = 1;

/// The `scope:` value that distinguishes a provider-level marker from a
/// per-agent one. Present on shared artifacts, absent from per-agent ones.
pub const SHARED_SCOPE: &str = "provider-shared";

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Render one `# <name>: <value>` header line, without its newline.
///
/// One function, so the writer and every reader agree byte for byte: the
/// observer's `grep -F -x`, the install guard, and `remove`'s fence all match
/// against strings this produces. A hand-rolled `format!` elsewhere would be a
/// second spelling nobody notices until a deploy refuses a file it wrote.
pub fn header_line(name: &str, value: &str) -> String {
    format!("# {name}: {value}")
}

/// Every path and name one agent implies.
#[derive(Debug, Clone)]
pub struct Names {
    instance: String,
}

impl Names {
    /// Derive every name from a provider-decoded identity.
    pub fn new(identity: &AgentIdentity) -> Self {
        Self {
            instance: identity.short12().to_string(),
        }
    }

    /// The systemd instance name, i.e. what `%i` expands to.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Full agent unit name — also the `agent_id` returned to the desktop.
    pub fn unit(&self) -> String {
        format!("buzz-acp@{}.service", self.instance)
    }

    /// The per-instance key-fetcher unit the agent unit `Requires=`.
    pub fn secret_unit(&self) -> String {
        format!("buzz-acp-secret@{}.service", self.instance)
    }

    /// Allowlisted environment, 0600 root, on the persistent boot disk.
    pub fn env_path(&self) -> String {
        format!("/etc/buzz/acp-{}.env", self.instance)
    }

    /// The durable deploy trail, 0644 root (spec §Capacity).
    pub fn trail_path(&self) -> String {
        format!("/etc/buzz/acp-{}.trail", self.instance)
    }

    /// Drop-in directory for the agent unit. An operator may keep their own
    /// files here, which is why `remove` never deletes the directory itself.
    pub fn dropin_dir(&self) -> String {
        format!("/etc/systemd/system/buzz-acp@{}.service.d", self.instance)
    }

    /// This provider's drop-in on the agent unit: `MemoryMax` and `CPUQuota`.
    pub fn dropin_path(&self) -> String {
        format!("{}/agent.conf", self.dropin_dir())
    }

    /// Drop-in directory for the fetcher unit.
    pub fn secret_dropin_dir(&self) -> String {
        format!(
            "/etc/systemd/system/buzz-acp-secret@{}.service.d",
            self.instance
        )
    }

    /// This provider's drop-in on the fetcher unit: the project and secret
    /// name the shared fetcher script reads from its environment.
    pub fn secret_dropin_path(&self) -> String {
        format!("{}/agent.conf", self.secret_dropin_dir())
    }

    /// Secret Manager resource name. Its payload is the whole
    /// secret-classified environment, not just the key.
    pub fn secret_name(&self) -> String {
        format!("buzz-agent-{}-private-key", self.instance)
    }

    /// Derive every name from an **operator-supplied** full pubkey.
    ///
    /// `deploy` never uses this: it decodes the nsec and takes the identity
    /// route above. `remove` has to, because the operator holds no key — only
    /// the pubkey `list` printed. This is the single entry point where a
    /// caller-supplied identity becomes a path, so the shape is checked here
    /// and nowhere else.
    pub fn from_pubkey_hex(pubkey_hex: &str) -> Result<Self, String> {
        Ok(Self {
            instance: normalize_pubkey(pubkey_hex)?[..12].to_string(),
        })
    }
}

/// Validate and normalize an operator-supplied full pubkey to 64 lowercase hex.
///
/// Uppercase input is folded rather than refused — a pubkey copied out of a
/// UI is routinely uppercase, and the marker comparison downstream is exact,
/// so normalizing here is what keeps `remove` usable without weakening it.
pub fn normalize_pubkey(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{value:?} is not a 64-character hex agent pubkey. Copy the value \
             `buzz-backend-gcp list` prints for the agent you mean to remove."
        ));
    }
    Ok(normalized)
}

/// Read one `# <name>: <value>` header field out of a file body.
fn header_field(body: &str, name: &str) -> Option<String> {
    let prefix = format!("# {name}: ");
    body.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(|value| value.trim().to_string())
}

/// How an artifact's own marker relates to **this** build.
///
/// Four states rather than a boolean, and the reason is the upgrade path.
/// [`BINDING_VERSION`] is documented as "bump when the unit/env shape changes"
/// — a designed-for event — so the version an artifact carries is routinely
/// *older* than the one deciding what to do with it. Collapsing that into "not
/// ours" made every artifact written before a bump read as a foreign file:
/// `classify` refused, so `deploy` could not upgrade it, and
/// `verify_removable` refused identically, so `remove` could not tear it down.
/// The agent became unmanageable in both directions.
///
/// `OursButNewer` is a separate state from `NotOurs` even though both refuse,
/// because the sentences differ and the difference matters: one says "upgrade
/// this provider", the other says "somebody else's file is in the way".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Ownership {
    /// This provider, at exactly this binding version.
    Ours,
    /// This provider, at an **older** binding version. An authorised upgrade
    /// target: per-agent artifacts are replaced, shared ones are rewritten when
    /// their bytes differ, Secret Manager labels are rolled forward, and
    /// `remove` may still delete.
    OursButOlder(u32),
    /// This provider, at a **newer** binding version. A refusal: a build that
    /// cannot reason about a layout must not overwrite or delete it.
    OursButNewer(u32),
    /// A foreign `managed-by`, a version that is not a decimal number, or no
    /// marker at all.
    #[default]
    NotOurs,
}

impl Ownership {
    /// May this build write, replace, or delete the artifact?
    ///
    /// The single predicate every caller uses, so "may we act" has one
    /// definition. True for [`Ownership::Ours`] and [`Ownership::OursButOlder`]
    /// only — an upgrade is an action, not a refusal.
    pub fn actionable(self) -> bool {
        matches!(self, Ownership::Ours | Ownership::OursButOlder(_))
    }
}

/// The one rule that turns a `managed-by` / `binding-version` pair into a
/// verdict.
///
/// Fed by both file-header tiers below **and** by Secret Manager's two labels
/// (`secrets::verify_owned`), so the four states mean the same thing on every
/// storage medium this binding uses rather than one thing per medium.
///
/// A version that does not parse as a `u32` is [`Ownership::NotOurs`]: it
/// describes no layout to order against, and guessing is how a downgrade
/// silently destroys a newer provider's work.
pub fn ownership_of(managed_by: Option<&str>, binding_version: Option<&str>) -> Ownership {
    if managed_by != Some(MANAGED_BY) {
        return Ownership::NotOurs;
    }
    match binding_version.and_then(|value| value.parse::<u32>().ok()) {
        Some(version) if version == BINDING_VERSION_NUM => Ownership::Ours,
        Some(version) if version < BINDING_VERSION_NUM => Ownership::OursButOlder(version),
        Some(version) => Ownership::OursButNewer(version),
        None => Ownership::NotOurs,
    }
}

/// Ownership of a **per-agent** artifact, read from its own header.
///
/// A header declaring a `scope` is a shared one at a per-agent path, which is
/// not ours *at this tier* — the tiers must not be readable as each other.
pub fn agent_ownership(body: &str) -> Ownership {
    if header_field(body, "scope").is_some() {
        return Ownership::NotOurs;
    }
    ownership_of(
        header_field(body, "managed-by").as_deref(),
        header_field(body, "binding-version").as_deref(),
    )
}

/// Ownership of a **shared** artifact, read from its own header.
///
/// The whole question about a shared file: [`Ownership::actionable`] licenses a
/// rewrite when the bytes differ, and the two refusing states each earn their
/// own message. A per-agent header answers [`Ownership::NotOurs`] because it
/// declares no scope.
pub fn shared_ownership(body: &str) -> Ownership {
    if header_field(body, "scope").as_deref() != Some(SHARED_SCOPE) {
        return Ownership::NotOurs;
    }
    ownership_of(
        header_field(body, "managed-by").as_deref(),
        header_field(body, "binding-version").as_deref(),
    )
}

/// The header written into every artifact that belongs to exactly one agent:
/// the env file, both drop-ins, and the deploy trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMarker {
    /// Full 64-hex pubkey. The 12-hex instance name is only
    /// collision-*resistant*; this is what makes acting on it safe.
    pub pubkey_full: String,
    /// Fingerprint of the rendered spec, for divergence detection.
    pub create_intent: String,
}

impl AgentMarker {
    /// The four-line header, exactly as it appears at the top of the file.
    ///
    /// Four contiguous lines beginning with `# managed-by: `, which is what
    /// lets every reader take the first `remote::MARKER_SCAN_LINES` of a file
    /// and have the whole marker.
    pub fn render(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n",
            header_line("managed-by", MANAGED_BY),
            header_line("binding-version", BINDING_VERSION),
            header_line("agent-pubkey-full", &self.pubkey_full),
            header_line("create-intent", &self.create_intent),
        )
    }

    /// Parse a per-agent marker from a file body.
    ///
    /// `None` means "there is nothing here this build may act on, at this
    /// tier" — a refusal to act, never a licence to overwrite. That covers a
    /// foreign or future [`agent_ownership`], a shared artifact's header
    /// (which declares a scope), and a header of ours that carries no identity
    /// lines. An **older** binding version parses normally, and must: `remove`
    /// acts on the pubkey a prior-version artifact carries, and
    /// `FencedReplace` rewrites the file that carries it.
    ///
    /// That last point is the compatibility floor. A future bump may add or
    /// reshape header lines freely, but it must keep `# agent-pubkey-full:`
    /// and `# create-intent:` spelled exactly as they are, or this function
    /// stops recognising the previous release's artifacts and the lockout
    /// comes straight back.
    pub fn parse(body: &str) -> Option<Self> {
        if !agent_ownership(body).actionable() {
            return None;
        }
        Some(Self {
            pubkey_full: header_field(body, "agent-pubkey-full")?,
            create_intent: header_field(body, "create-intent")?,
        })
    }
}

/// The provider-level header written into every artifact shared by all
/// instances: the two template units and the fetcher script.
///
/// Three lines, and deliberately nothing more. It states exactly what is true —
/// this provider wrote it, at this binding version, for every instance — and
/// **nothing that is not**: no pubkey and no create-intent, because a shared
/// file belongs to no single agent, and no content digest, for the reason in
/// the module preamble.
pub fn shared_marker() -> String {
    format!(
        "{}\n{}\n{}\n",
        header_line("managed-by", MANAGED_BY),
        header_line("binding-version", BINDING_VERSION),
        header_line("scope", SHARED_SCOPE),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture nsec from the shared golden payloads.
    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    fn identity() -> AgentIdentity {
        AgentIdentity::from_nsec(NSEC).unwrap()
    }

    #[test]
    fn every_path_is_derived_from_the_pubkey_not_a_display_name() {
        let id = identity();
        let n = Names::new(&id);
        let s = id.short12();
        assert_eq!(n.instance(), s);
        assert_eq!(n.unit(), format!("buzz-acp@{s}.service"));
        assert_eq!(n.secret_unit(), format!("buzz-acp-secret@{s}.service"));
        assert_eq!(n.env_path(), format!("/etc/buzz/acp-{s}.env"));
        assert_eq!(n.trail_path(), format!("/etc/buzz/acp-{s}.trail"));
        assert_eq!(
            n.dropin_path(),
            format!("/etc/systemd/system/buzz-acp@{s}.service.d/agent.conf")
        );
        assert_eq!(
            n.secret_dropin_path(),
            format!("/etc/systemd/system/buzz-acp-secret@{s}.service.d/agent.conf")
        );
        assert_eq!(n.secret_name(), format!("buzz-agent-{s}-private-key"));
    }

    /// The instance name is what `%i` expands to, what the fetcher script's
    /// shape check enforces, and what the deploy lease path is built from, so
    /// it must be exactly 12 lowercase hex.
    #[test]
    fn the_instance_name_is_twelve_lowercase_hex() {
        let n = Names::new(&identity());
        assert_eq!(n.instance().len(), 12);
        assert!(n
            .instance()
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn a_per_agent_marker_round_trips() {
        let m = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "c0ffee".to_string(),
        };
        assert_eq!(AgentMarker::parse(&m.render()).expect("parses"), m);
    }

    /// The provider-level marker states exactly three things: this provider
    /// wrote the file, at this binding version, for every instance. It carries
    /// no agent identity because a shared file belongs to no agent — and no
    /// content digest, because a claim a file makes about its own contents is
    /// worth exactly what its writer is worth.
    #[test]
    fn the_provider_marker_says_only_what_is_true() {
        let header = shared_marker();
        assert_eq!(shared_ownership(&header), Ownership::Ours);
        assert!(header.contains(&header_line("managed-by", MANAGED_BY)));
        assert!(header.contains(&header_line("binding-version", BINDING_VERSION)));
        assert!(header.contains(&header_line("scope", SHARED_SCOPE)));
        for absent in ["content-hash", "agent-pubkey", "create-intent"] {
            assert!(
                !header.contains(absent),
                "the shared marker claims {absent}"
            );
        }
    }

    /// The two spellings of the binding version must agree, or the header a
    /// file carries and the number every ordering compares against describe
    /// different releases — and the one place that shows up is an upgrade.
    #[test]
    fn the_two_spellings_of_the_binding_version_agree() {
        assert_eq!(BINDING_VERSION.parse::<u32>(), Ok(BINDING_VERSION_NUM));
    }

    /// The tiers must not be readable as each other. A shared file read as
    /// per-agent would hand a fence an identity that is not there; a per-agent
    /// file read as shared would let a shared-file rule act on one agent's file.
    #[test]
    fn the_two_tiers_do_not_parse_as_one_another() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "c0ffee".to_string(),
        }
        .render();
        let shared = shared_marker();
        assert_eq!(shared_ownership(&agent), Ownership::NotOurs);
        assert_eq!(agent_ownership(&shared), Ownership::NotOurs);
        assert!(AgentMarker::parse(&shared).is_none());
    }

    #[test]
    fn an_unmarked_file_yields_no_marker_of_either_tier() {
        let body = "# just some file\nFOO=bar\n";
        assert!(AgentMarker::parse(body).is_none());
        assert_eq!(agent_ownership(body), Ownership::NotOurs);
        assert_eq!(shared_ownership(body), Ownership::NotOurs);
    }

    /// A per-agent header at an arbitrary binding version. Version 0 never
    /// shipped, but the ordering rule has to be exercised *now*: the bump that
    /// creates a real prior version is exactly the moment nobody will go back
    /// and re-derive what should happen to the artifacts already on the box.
    fn agent_header_at(version: &str) -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: {version}\n\
             # agent-pubkey-full: {}\n# create-intent: ci\n",
            "ab".repeat(32)
        )
    }

    fn shared_header_at(version: &str) -> String {
        format!(
            "# managed-by: {MANAGED_BY}\n# binding-version: {version}\n\
             # scope: {SHARED_SCOPE}\n"
        )
    }

    /// P1-1. An **older** binding version is this provider's own work at a
    /// layout this build supersedes — an authorised upgrade target at both
    /// tiers, with its identity intact, because `remove` acts on that pubkey
    /// and `FencedReplace` rewrites the file that carries it. Reading it as
    /// "not ours" is what made a version bump lock the operator out of
    /// `deploy` *and* `remove` for every agent already installed.
    #[test]
    fn an_older_binding_version_is_ours_and_an_upgrade_target() {
        let body = agent_header_at("0");
        assert_eq!(agent_ownership(&body), Ownership::OursButOlder(0));
        assert!(agent_ownership(&body).actionable());
        let marker = AgentMarker::parse(&body).expect("an upgrade target keeps its identity");
        assert_eq!(marker.pubkey_full, "ab".repeat(32));

        let shared = shared_header_at("0");
        assert_eq!(shared_ownership(&shared), Ownership::OursButOlder(0));
        assert!(shared_ownership(&shared).actionable());
    }

    /// …and a **future** one is the refusal the rule reserves, at both tiers.
    /// The layout it describes is one this build cannot reason about, so
    /// overwriting or deleting it would destroy a newer provider's work — and
    /// it must be a *distinct* state from "somebody else's file", or the
    /// refusal tells the operator their own newer agent is foreign.
    #[test]
    fn a_future_binding_version_is_refused_at_both_tiers() {
        let body = agent_header_at("99");
        assert_eq!(agent_ownership(&body), Ownership::OursButNewer(99));
        assert!(!agent_ownership(&body).actionable());
        assert!(
            AgentMarker::parse(&body).is_none(),
            "a layout this build cannot read must yield nothing to act on"
        );
        assert_eq!(
            shared_ownership(&shared_header_at("99")),
            Ownership::OursButNewer(99)
        );
    }

    /// A version that is not a decimal number describes no layout to order
    /// against. Fail closed rather than guessing.
    #[test]
    fn a_binding_version_that_is_not_a_number_is_not_ours() {
        for version in ["", "1.0", "v1", "one", "-1", "0x1"] {
            assert_eq!(
                agent_ownership(&agent_header_at(version)),
                Ownership::NotOurs,
                "binding-version {version:?} was ordered against ours"
            );
            assert_eq!(
                shared_ownership(&shared_header_at(version)),
                Ownership::NotOurs,
                "binding-version {version:?} was ordered against ours"
            );
        }
    }

    #[test]
    fn a_marker_from_another_tool_is_not_ours() {
        let body = format!(
            "# managed-by: some-other-tool\n# binding-version: {BINDING_VERSION}\n\
             # agent-pubkey-full: {}\n# create-intent: ci\n",
            "ab".repeat(32)
        );
        assert!(AgentMarker::parse(&body).is_none());
        assert_eq!(agent_ownership(&body), Ownership::NotOurs);
        // …and a foreign file that merely declares our scope is still not ours.
        let scoped = format!(
            "# managed-by: some-other-tool\n# binding-version: {BINDING_VERSION}\n\
             # scope: {SHARED_SCOPE}\n"
        );
        assert_eq!(shared_ownership(&scoped), Ownership::NotOurs);
    }

    /// A file plainly ours that names no agent is neither ownable nor
    /// anonymous: `agent_ownership` says ours, `parse` says nothing to act on,
    /// and the caller owes the operator a different sentence from "somebody
    /// else's file".
    #[test]
    fn our_marker_without_an_identity_yields_ownership_but_no_marker() {
        let body = format!("# managed-by: {MANAGED_BY}\n# binding-version: {BINDING_VERSION}\n");
        assert_eq!(agent_ownership(&body), Ownership::Ours);
        assert!(AgentMarker::parse(&body).is_none());
    }

    /// `remove` names its target by pubkey, because the operator holds no
    /// key. Validation happens once, here, before the value can become a path.
    #[test]
    fn an_operator_supplied_pubkey_is_validated_then_folded() {
        let upper = "AB".repeat(32);
        assert_eq!(
            normalize_pubkey(&format!("  {upper}\n")).unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(
            Names::from_pubkey_hex(&upper).unwrap().instance(),
            "abababababab"
        );
        for bad in ["", "abc", &"ab".repeat(33), &format!("{}z", "a".repeat(63))] {
            assert!(
                normalize_pubkey(bad).is_err(),
                "accepted a malformed pubkey {bad:?}"
            );
            assert!(Names::from_pubkey_hex(bad).is_err());
        }
    }

    /// Both routes must land on the same names, or `remove` could target a
    /// path `deploy` never wrote.
    #[test]
    fn the_two_name_routes_agree() {
        let id = identity();
        let from_key = Names::new(&id);
        let from_pubkey = Names::from_pubkey_hex(id.pubkey_hex()).unwrap();
        assert_eq!(from_key.env_path(), from_pubkey.env_path());
        assert_eq!(from_key.unit(), from_pubkey.unit());
        assert_eq!(from_key.secret_name(), from_pubkey.secret_name());
        assert_eq!(from_key.dropin_path(), from_pubkey.dropin_path());
        assert_eq!(from_key.trail_path(), from_pubkey.trail_path());
    }

    /// Every header line is produced by `header_line`, and every reader — the
    /// observer's `grep -F -x`, the install guard, `remove`'s fence — matches
    /// those exact strings. A hand-rolled `format!` anywhere else would be a
    /// second spelling nobody notices until a deploy refuses a file it wrote.
    #[test]
    fn each_tier_renders_the_header_shape_its_readers_expect() {
        let agent = AgentMarker {
            pubkey_full: "ab".repeat(32),
            create_intent: "ci".to_string(),
        }
        .render();
        let shared = shared_marker();
        assert_eq!(agent.lines().count(), 4, "{agent}");
        assert_eq!(shared.lines().count(), 3, "{shared}");
        for header in [&agent, &shared] {
            assert!(header.starts_with(&header_line("managed-by", MANAGED_BY)));
            assert!(header.ends_with('\n'));
            for line in header.lines() {
                let (name, value) = line
                    .strip_prefix("# ")
                    .and_then(|rest| rest.split_once(": "))
                    .unwrap_or_else(|| panic!("{line:?} is not a header line"));
                assert_eq!(line, header_line(name, value));
            }
        }
    }
}
