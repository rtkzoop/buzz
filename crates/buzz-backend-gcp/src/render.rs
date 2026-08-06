//! Pure rendering of the remote artifacts (spec §Remote Artifacts).
//!
//! No IO: a payload in, the exact bytes of every file out. Every
//! conformance-critical decision — supervision policy, the secret split, both
//! marker tiers, the fence each file carries into its own install — is visible
//! here and testable without touching GCP.

use crate::config::ProviderConfig;
use crate::naming::{
    header_line, sha256_hex, shared_marker, AgentMarker, Names, MANAGED_BY, SHARED_SCOPE,
};
use buzz_backend_core::env::{build_env, AuthoritativeInputs, START_NONCE_KEY};
use buzz_backend_core::identity::AgentIdentity;
use buzz_backend_core::wire::AgentPayload;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Secret Manager's hard cap on a single version's payload, 64 KiB
/// (<https://cloud.google.com/secret-manager/quotas>).
///
/// Enforced in [`plan`], on `secret_body()` only. The on-disk half is
/// deliberately uncapped — a systemd `EnvironmentFile` on a 38 GB boot disk
/// has no such boundary, which is why this binding passes
/// `max_env_bytes: None` to `build_env` — but the secret-classified half is
/// uploaded as one version, and a payload over this is rejected by the API.
/// The check lives in the pure phase because `secrets::store` is the *fourth*
/// mutation of a deploy: failing there leaves the shared templates installed
/// and possibly an empty secret resource created, for a condition that was
/// knowable offline.
pub const SECRET_MANAGER_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// The **only** environment keys that may live on the persistent boot disk.
///
/// An allowlist, not a denylist: the default is *secret*, so a new
/// authoritative key added to `buzz_backend_core::env` lands on the safe side
/// without anyone remembering to classify it. Note that
/// `buzz_backend_core::env::AUTHORITATIVE_KEYS` is **not** this list — three
/// of its twelve entries are credentials.
///
/// Each entry is non-secret for a stated reason: a public endpoint, a public
/// nostr pubkey, a binary name already visible in `ps` and in the unit file,
/// argv already visible in `ps`, a mode name, a list of public pubkeys, an
/// integer number of seconds, and a per-attempt correlator that authorizes
/// nothing and is already in the journal.
pub const NON_SECRET_KEYS: [&str; 9] = [
    "BUZZ_ACP_AGENT_ARGS",
    "BUZZ_ACP_AGENT_COMMAND",
    "BUZZ_ACP_AGENT_OWNER",
    "BUZZ_ACP_EXIT_AFTER_INACTIVITY",
    "BUZZ_ACP_MCP_COMMAND",
    "BUZZ_ACP_RESPOND_TO",
    "BUZZ_ACP_RESPOND_TO_ALLOWLIST",
    "BUZZ_MANAGED_AGENT_START_NONCE",
    "BUZZ_RELAY_URL",
];

/// Where the instance keeps harness binaries.
///
/// Task 12 verifies `<HARNESS_DIR>/<basename>` with `test -x` before deploying
/// and `launch.command` is rewritten to that same absolute path, so the check
/// and the exec name one file rather than both resolving a bare name against
/// systemd's `PATH` — which searches `/usr/local/sbin` first.
const HARNESS_DIR: &str = "/usr/local/bin";

/// The harness `buzz-acp` execs when the payload names none.
///
/// `goose`, not `buzz-acp`: `BUZZ_ACP_AGENT_COMMAND` defaults to `goose` in the
/// harness's own CLI (`crates/buzz-acp/src/config.rs:190-192`), and `buzz-acp`
/// is the supervisor that execs it, not the child. Naming the supervisor here
/// would make the installation check verify a binary that is certainly present
/// while the one that actually runs is missing.
pub const DEFAULT_HARNESS: &str = "goose";

/// A file to install on the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    pub path: String,
    /// Octal mode string passed to `install -m`.
    pub mode: &'static str,
    pub body: String,
    /// The header lines the **installed** file must already carry if it exists.
    ///
    /// Attached at render time rather than passed to `Remote::install`, because
    /// the renderer is the only place that knows each file's tier and this
    /// agent's pubkey — and because a fence that travels with the file cannot
    /// be forgotten at one of several call sites.
    ///
    /// These are the tier's **identity** lines and nothing else. `create-intent`
    /// is excluded because it changes on every legitimate reconfiguration, so
    /// requiring it would refuse a file this agent wrote yesterday.
    /// `binding-version` is excluded because `remote::marker_fn` compares it as
    /// an *ordering* rather than matching it as a literal line: an artifact
    /// written by an older build of this provider is an authorised upgrade
    /// target, and an exact needle would have the install that upgrades a file
    /// be refused by that file's own fence.
    pub owner_marker: Vec<String>,
}

/// A shared artifact plus the digest of the exact bytes it installs.
///
/// The digest is **not** written into the file and makes no claim about it: it
/// is how the reconciler answers "is what is on the instance already
/// byte-identical to what I would write?" without shipping the body twice. The
/// instance answers with `sha256sum` over the whole file and the two are
/// compared, so both sides are hashes of real bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedArtifact {
    pub file: RemoteFile,
    /// SHA-256 of `file.body` in full, marker header included.
    pub sha256: String,
}

/// Everything one deploy needs to write.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Files belonging to exactly this agent. Rewritten by a create or a
    /// fenced replace.
    pub per_agent: Vec<RemoteFile>,
    /// Files shared by every instance. Written only when absent, or when the
    /// installed bytes differ from what this provider would render.
    pub shared: Vec<SharedArtifact>,
    /// The Secret Manager payload. Never written to a file this provider
    /// installs, never logged, redacted by `dry-run`.
    pub secret_env: BTreeMap<String, String>,
    /// Fingerprint of everything that decides the unit's behavior, excluding
    /// the generation and every secret *value* — though a digest of the secret
    /// body is included, so a rotated credential is a divergence.
    pub create_intent: String,
    /// The deploy trail. `body` is the four-line marker header the file gets
    /// when it does not exist yet; records are **appended** to it, so it is
    /// never installed like the others and does not live in `per_agent`.
    pub trail: RemoteFile,
}

impl Plan {
    /// The exact bytes uploaded as the secret version.
    pub fn secret_body(&self) -> String {
        env_file_body(&self.secret_env, "")
    }

    /// The same document with every value replaced and every key intact —
    /// the form `dry-run` prints.
    pub fn redacted_secret_body(&self) -> String {
        let mut out = String::new();
        for key in self.secret_env.keys() {
            out.push_str(key);
            out.push_str("=[REDACTED]\n");
        }
        out
    }
}

/// Quote a value for a systemd `EnvironmentFile`.
///
/// systemd accepts double-quoted values with backslash escapes. Quoting
/// unconditionally is simpler to reason about than deciding per value and
/// costs nothing. Raw newlines are refused upstream rather than escaped here,
/// because a multi-line `EnvironmentFile` value is exactly the ambiguity this
/// binding declines to introduce into a file systemd parses.
fn quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn env_file_body(env: &BTreeMap<String, String>, header: &str) -> String {
    let mut out = String::from(header);
    for (key, value) in env {
        out.push_str(key);
        out.push('=');
        out.push_str(&quote(value));
        out.push('\n');
    }
    out
}

/// The header lines a per-agent target must already carry, if it exists at all.
///
/// Identity only. The binding version is checked by `remote::marker_fn` as an
/// ordering rather than matched as a literal line, so that an artifact written
/// by an older build of this provider is an upgrade target instead of a file
/// its own fence refuses.
fn agent_owner_marker(pubkey_full: &str) -> Vec<String> {
    vec![
        header_line("managed-by", MANAGED_BY),
        header_line("agent-pubkey-full", pubkey_full),
    ]
}

/// The header lines a shared target must already carry, if it exists at all.
/// Same rule as [`agent_owner_marker`] for the binding version.
fn shared_owner_marker() -> Vec<String> {
    vec![
        header_line("managed-by", MANAGED_BY),
        header_line("scope", SHARED_SCOPE),
    ]
}

/// Build a shared artifact: stamp the provider-level marker onto it, then hash
/// the exact bytes that will land on disk.
///
/// `prologue` is content that must precede the header — a shebang, which the
/// kernel only honors on line 1. It is inside the hashed bytes like everything
/// else, because the hash covers the file rather than a chosen part of it.
fn shared_artifact(
    path: &str,
    mode: &'static str,
    prologue: &str,
    content: &str,
) -> SharedArtifact {
    let body = format!("{prologue}{}{content}", shared_marker());
    let sha256 = sha256_hex(body.as_bytes());
    SharedArtifact {
        file: RemoteFile {
            path: path.to_string(),
            mode,
            body,
            owner_marker: shared_owner_marker(),
        },
        sha256,
    }
}

/// The bare binary name inside a `launch.command`, or the harness's own default
/// when the payload names none or names only a directory.
fn basename_or_default(command: Option<&str>) -> String {
    command
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .and_then(|command| command.rsplit('/').next())
        .filter(|basename| !basename.is_empty())
        .unwrap_or(DEFAULT_HARNESS)
        .to_string()
}

/// The harness binary this agent needs, as a bare name.
///
/// `launch.command` is resolved against the **desktop's** PATH; on the VM that
/// path is meaningless, so only the basename carries over. Task 12 uses this to
/// decide which `/usr/local/bin/<name>` must exist before the deploy proceeds.
pub fn harness_basename(agent: &AgentPayload) -> String {
    basename_or_default(agent.launch.as_ref().and_then(|l| l.command.as_deref()))
}

/// A copy of `agent` whose `launch.command` is the **instance's** spelling of
/// the harness.
///
/// The desktop deliberately preserves an explicit host path
/// (`desktop/src-tauri/src/managed_agents/discovery.rs:443-449`), `build_env`
/// writes `launch.command` through unchanged
/// (`crates/buzz-backend-kubernetes/src/env.rs:254-259`), and `buzz-acp` execs
/// that exact string (`crates/buzz-acp/src/acp.rs:451-459`). Left alone,
/// `/opt/homebrew/bin/codex-acp` passes the installation check for `codex-acp`
/// and then fails at exec on Debian.
///
/// Rewritten **here**, before `build_env` reads it, rather than by patching the
/// rendered map afterwards: a second consumer of `launch.command` added to
/// `build_env` later would escape a post-hoc fix and cannot escape this one.
///
/// A payload with no launch block at all is left untouched — inventing one
/// would change owner resolution — so it reaches the harness's own default,
/// which is the same binary `harness_basename` names.
fn with_instance_harness(agent: &AgentPayload) -> AgentPayload {
    let mut agent = agent.clone();
    if let Some(launch) = agent.launch.as_mut() {
        let basename = basename_or_default(launch.command.as_deref());
        launch.command = Some(format!("{HARNESS_DIR}/{basename}"));
    }
    agent
}

/// Render every artifact for one deploy.
pub fn plan(
    agent: &AgentPayload,
    cfg: &ProviderConfig,
    names: &Names,
    identity: &AgentIdentity,
    generation: &str,
) -> Result<Plan, String> {
    // v1 supervises bounded lifetimes only. `inactivity_seconds: 0` is a legal,
    // blessed request, but honoring it needs `Restart=on-failure`, which
    // `docs/remote-agents.md` withholds until the harness clean-exit contract
    // is pinned (Known Defect 6): an undefended exit convention would let the
    // supervisor restart agents that exited on purpose, violating I5. When the
    // contract lands this becomes a one-line change.
    let Some(inactivity) = cfg.inactivity_seconds else {
        return Err(
            "deploy refused: provider_config.inactivity_seconds is 0 (indefinite \
             lifetime), which this binding does not support yet: it requires \
             Restart=on-failure, and docs/remote-agents.md withholds that until \
             the harness clean-exit contract is pinned (Known Defect 6). Set a \
             positive number of seconds."
                .to_string(),
        );
    };

    // Before `build_env`, so no consumer of `launch.command` — this one or a
    // future one — can observe the desktop's path.
    let agent = with_instance_harness(agent);

    let env = build_env(
        &agent,
        AuthoritativeInputs {
            generation,
            inactivity_seconds: Some(inactivity),
            // A systemd `EnvironmentFile` on a 38 GB disk has no meaningful cap.
            max_env_bytes: None,
        },
    )?;

    // Both destinations are files systemd parses line by line, so a raw
    // newline in a value is the same class of defect as §Value grammars —
    // refused, not escaped, and never echoed.
    for (key, value) in &env {
        if value.contains('\n') || value.contains('\r') {
            return Err(format!(
                "deploy refused: the value of {key} contains a line break. Both \
                 environment destinations are files systemd parses line by line, \
                 so such a value cannot be represented unambiguously. The value \
                 is not echoed."
            ));
        }
    }

    // Split by sensitivity. Precedence is already resolved, so this moves
    // values without changing them, and both files are `EnvironmentFile=`
    // entries on the same unit — so no value and no precedence changes.
    let mut disk_env: BTreeMap<String, String> = BTreeMap::new();
    let mut secret_env: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in env {
        if NON_SECRET_KEYS.contains(&key.as_str()) {
            disk_env.insert(key, value);
        } else {
            secret_env.insert(key, value);
        }
    }
    let secret_body = env_file_body(&secret_env, "");

    // The on-disk half has no cap — a systemd `EnvironmentFile` on a 38 GB
    // boot disk is bounded by the disk, which is why `max_env_bytes` above is
    // `None`. The secret half does: it is uploaded as one Secret Manager
    // version, and a version payload is capped at 64 KiB. Refusing here, in
    // the pure phase, is what keeps that from surfacing inside
    // `secrets::store` — the fourth mutation of a deploy, by which point the
    // shared templates are installed and the secret resource may already
    // exist. The refusal names sizes only: [L2] item 5 forbids echoing a
    // secret-classified value, and the oversized one is by definition secret.
    if secret_body.len() > SECRET_MANAGER_MAX_PAYLOAD_BYTES {
        return Err(format!(
            "deploy refused: this agent's secret-classified environment renders \
             to {} bytes, and Secret Manager caps one version's payload at \
             {SECRET_MANAGER_MAX_PAYLOAD_BYTES} bytes. Nothing was changed. \
             Move the oversized value off the agent payload — a file on the \
             instance, or a secret the harness fetches itself. No value is \
             echoed here.",
            secret_body.len()
        ));
    }

    let shared = vec![
        shared_artifact(
            "/etc/systemd/system/buzz-acp@.service",
            "0644",
            "",
            AGENT_UNIT,
        ),
        shared_artifact(
            "/etc/systemd/system/buzz-acp-secret@.service",
            "0644",
            "",
            FETCHER_UNIT,
        ),
        shared_artifact(
            "/usr/local/sbin/buzz-acp-fetch-key",
            "0755",
            "#!/bin/bash\n",
            FETCH_KEY_SCRIPT,
        ),
    ];

    // The intent fingerprint covers everything that decides the unit's
    // behavior, and deliberately excludes one thing: the generation, which
    // changes on every attempt, so including it would make every deploy look
    // divergent.
    let mut hasher = Sha256::new();
    let mut feed = |label: &str, value: &str| {
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    };
    for (key, value) in &disk_env {
        if key == START_NONCE_KEY {
            continue;
        }
        feed("disk-key", key);
        feed("disk-value", value);
    }
    // Secret keys *and* values, as one digest. The values must not be
    // reconstructible from a marker any reader of a 0644 file can see — but
    // leaving them out of the fingerprint entirely is what let a rotated
    // credential classify as `RestartSame`, which skips `secrets::store` and
    // restarts the agent against the previous secret version. A digest carries
    // the divergence without carrying the material: confirming a guess against
    // it requires already knowing the nsec the body contains.
    feed("secret-digest", &sha256_hex(secret_body.as_bytes()));
    feed("memory_max", &cfg.memory_max);
    feed("cpu_quota", &cfg.cpu_quota);
    feed("project", &cfg.project);
    feed("secret-name", &names.secret_name());
    for artifact in &shared {
        feed("shared", &artifact.sha256);
    }
    let create_intent = hex::encode(hasher.finalize());

    let marker = AgentMarker {
        pubkey_full: identity.pubkey_hex().to_string(),
        create_intent: create_intent.clone(),
    }
    .render();
    let owner_marker = agent_owner_marker(identity.pubkey_hex());

    let per_agent = vec![
        RemoteFile {
            path: names.env_path(),
            mode: "0600",
            body: env_file_body(&disk_env, &marker),
            owner_marker: owner_marker.clone(),
        },
        RemoteFile {
            path: names.dropin_path(),
            mode: "0644",
            body: format!(
                "{marker}[Service]\nMemoryMax={}\nCPUQuota={}\n",
                cfg.memory_max, cfg.cpu_quota
            ),
            owner_marker: owner_marker.clone(),
        },
        RemoteFile {
            path: names.secret_dropin_path(),
            mode: "0644",
            // The fetcher's two inputs. They live here, per agent, rather than
            // in the shared script, because a shared artifact carries no
            // per-agent data — see the tier rules in `naming.rs`. Both values
            // are safe unquoted because both come from closed grammars:
            // `project` from `config::parse_resource_name`, the secret name
            // from the 12-hex instance.
            body: format!(
                "{marker}[Service]\n\
                 Environment=BUZZ_GCP_PROJECT={}\n\
                 Environment=BUZZ_GCP_SECRET={}\n",
                cfg.project,
                names.secret_name()
            ),
            owner_marker: owner_marker.clone(),
        },
    ];

    Ok(Plan {
        per_agent,
        shared,
        secret_env,
        create_intent,
        trail: RemoteFile {
            path: names.trail_path(),
            mode: "0644",
            body: marker,
            owner_marker,
        },
    })
}

/// The operator-facing render of a plan, with every secret-classified value
/// replaced by `[REDACTED]`.
///
/// This is the binding's secret-classification audit: the on-disk env file is
/// printed **verbatim** because every value in it is allowlisted by
/// construction — if a non-allowlisted key appears there, that *is* the
/// finding — and the Secret Manager payload is printed keys-only, so a human
/// can confirm the allowlist held for one particular payload.
#[allow(dead_code)] // Called once the operator dry-run path renders a plan for review.
pub fn dry_run_report(plan: &Plan, names: &Names, trail_record: &str) -> String {
    let mut out = format!(
        "agent_id: {}\nsecret:   {}\n",
        names.unit(),
        names.secret_name()
    );
    for file in &plan.per_agent {
        out.push_str(&format!("\n=== {} (mode {}) ===\n", file.path, file.mode));
        out.push_str(&file.body);
    }
    for artifact in &plan.shared {
        out.push_str(&format!(
            "\n=== {} (mode {}, provider-shared) ===\n",
            artifact.file.path, artifact.file.mode
        ));
        out.push_str(&artifact.file.body);
    }
    out.push_str(&format!(
        "\n=== {} (mode {}) ===\n",
        plan.trail.path, plan.trail.mode
    ));
    out.push_str(&plan.trail.body);
    out.push_str(trail_record);
    out.push_str(&format!(
        "\n=== secretmanager://{} (values redacted) ===\n",
        names.secret_name()
    ));
    out.push_str(&plan.redacted_secret_body());
    out
}

/// The shared agent unit.
///
/// Mirrors the hardened unit the deployment already runs, with three
/// deliberate differences: `Restart=no` (I5 — a supervisor must never
/// resurrect an intentional exit), `TimeoutStopSec=120` (I3 — room for
/// in-flight drain, presence→offline, and a graceful relay close before
/// SIGKILL), and the second `EnvironmentFile` holding the tmpfs-materialized
/// secret environment. `MemoryMax`/`CPUQuota` live in the per-instance drop-in
/// so they are configurable.
const AGENT_UNIT: &str = "\
[Unit]
Description=Buzz ACP agent harness (%i)
After=network-online.target buzz-block-metadata-agent.service buzz-acp-secret@%i.service
Wants=network-online.target
Requires=buzz-block-metadata-agent.service buzz-acp-secret@%i.service

[Service]
Type=simple
User=buzzacp
Group=buzzacp
WorkingDirectory=/var/lib/buzzacp
EnvironmentFile=/etc/buzz/acp-%i.env
EnvironmentFile=/run/buzz-acp-%i/secret.env
ExecStart=/usr/local/bin/buzz-acp
Restart=no
TimeoutStopSec=120
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/buzzacp
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=169.254.169.254/32
TasksMax=512
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
";

/// The shared key-fetcher unit.
///
/// A separate unit rather than an `ExecStartPre=+` on the agent unit, because
/// that unit's `IPAddressDeny=169.254.169.254/32` is a **cgroup-wide** BPF
/// filter: it blocks every process in the unit including one running as root,
/// so a metadata-authenticated gcloud call cannot live inside it.
///
/// `RuntimeDirectoryMode=0750` root:root is correct and must not be widened.
/// systemd's *manager* reads `EnvironmentFile=` as root before dropping to
/// `User=buzzacp` — proven on this host by the running `buzz-acp.service`,
/// which has `User=buzzacp` and `EnvironmentFile=/etc/buzz/acp.env` at mode
/// 0600 root:root and starts. The agent *process* therefore never needs to
/// traverse this directory itself, and 0750 root:root is what stops it.
///
/// It carries every sandbox directive the agent unit does, with exactly three
/// deliberate differences:
///
/// * **No `IPAddressDeny`** — the absence is this unit's entire reason to exist.
/// * **`CapabilityBoundingSet=CAP_CHOWN`, not empty.** The fetched file is
///   `chown`ed to `buzzacp` so the manager can hand it to the agent unit as an
///   `EnvironmentFile=`; with an empty bounding set that `chown` fails with
///   EPERM even as root, and the agent starts *without* `BUZZ_AUTH_TAG` — a
///   failure that looks nothing like a permissions error. One capability, for
///   one syscall, and the script is ordered so no second one is needed.
/// * **`ReadWritePaths=-/run/buzz-acp-%i`, not `/var/lib/buzzacp`.** Scoped to
///   this instance's own runtime directory and nothing else. The `-` prefix
///   tolerates the path not existing yet when the mount namespace is built;
///   `RuntimeDirectory=` creates it for this unit either way.
const FETCHER_UNIT: &str = "\
[Unit]
Description=Materialize the Buzz agent secret environment for %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
RuntimeDirectory=buzz-acp-%i
RuntimeDirectoryMode=0750
ExecStart=/usr/local/sbin/buzz-acp-fetch-key %i
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=CAP_CHOWN
AmbientCapabilities=
ReadWritePaths=-/run/buzz-acp-%i
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
TasksMax=128
StandardOutput=journal
StandardError=journal
";

/// The shared fetcher script — the highest-privilege code this design
/// installs, so every guard is explicit rather than left to the implementer.
///
/// `BUZZ_GCP_PROJECT` and `BUZZ_GCP_SECRET` arrive from the per-agent drop-in
/// on `buzz-acp-secret@<instance>.service`, and neither is defaulted. An
/// omitted `--project` works today only because the VM happens to carry
/// `core/project=zoop-innovation` in its gcloud config; a
/// `gcloud config unset project`, a different service account, or a VM rebuilt
/// from a changed image turns that into `latest` resolved against the wrong
/// project or none at all.
const FETCH_KEY_SCRIPT: &str = r#"# Materialize one agent's secret environment onto tmpfs.
set -euo pipefail

# A script run by systemd inherits systemd's environment, not a login shell's.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Invoked with zero arguments — a hand-typed `systemctl start
# buzz-acp-secret@` — this would otherwise write to `/run/buzz-acp-/secret.env`.
if [ "$#" -eq 1 ]; then
  instance="$1"
else
  echo "buzz-acp-fetch-key: exactly one instance argument is required" >&2
  exit 2
fi

# %i is a systemd instance name and reaches this script unescaped. The naming
# rule derives exactly 12 lowercase hex, so anything else is not one of ours
# and must not become a Secret Manager name or a filesystem path.
if ! [[ "$instance" =~ ^[0-9a-f]{12}$ ]]; then
  echo "buzz-acp-fetch-key: instance name is not 12 lowercase hex characters" >&2
  exit 2
fi

: "${BUZZ_GCP_PROJECT:?buzz-acp-fetch-key: BUZZ_GCP_PROJECT is not set}"
: "${BUZZ_GCP_SECRET:?buzz-acp-fetch-key: BUZZ_GCP_SECRET is not set}"

dir="/run/buzz-acp-$instance"
out="$dir/secret.env"
tmp="$dir/secret.env.tmp"

umask 077
trap 'rm -f "$tmp"' EXIT

# Filled while it is still root-owned and writable, then tightened, then handed
# over, then renamed. That order is what keeps this unit's capability set at
# exactly CAP_CHOWN: creating the file 0400 buzzacp *first* would make the
# redirect below fail with EACCES for a root process without CAP_DAC_OVERRIDE,
# and chmod after chown would need CAP_FOWNER. `mv` within one tmpfs is a
# rename, so the agent unit never observes a half-written file — and a partial
# secret.env is not a truncated key, it is an EnvironmentFile missing its later
# lines, which for this binding's allowlist means an agent that starts *without*
# BUZZ_AUTH_TAG and fails identity assembly for a reason that looks nothing like
# a write error. The fetched value is never echoed: the journal is output, and
# L2 item 5 forbids secret material there.
install -m 0600 /dev/null "$tmp"
gcloud secrets versions access latest \
  --project="$BUZZ_GCP_PROJECT" \
  --secret="$BUZZ_GCP_SECRET" > "$tmp"
chmod 0400 "$tmp"
chown buzzacp:buzzacp "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{shared_ownership, Ownership, BINDING_VERSION};
    use buzz_backend_core::wire::DeployRequest;

    /// A second valid nsec, for the cross-agent shared-artifact test.
    ///
    /// Substituted from the plan's literal value, which failed its own bech32
    /// checksum — `AgentIdentity::from_nsec` rejected it as undecodable. This
    /// is a genuine, distinct key (secret `0x42`×32), so the test still
    /// exercises two different identities rendering identical shared artifacts.
    const OTHER_NSEC: &str = "nsec1gfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpqucsp2m";

    fn request() -> DeployRequest {
        let raw = buzz_backend_core::harness::fixture("deploy-full-launch.request.json");
        serde_json::from_str(&raw).expect("the shared full-launch payload parses")
    }

    fn gcp_config() -> ProviderConfig {
        ProviderConfig::parse(&serde_json::json!({})).unwrap()
    }

    fn names_for(req: &DeployRequest) -> Names {
        Names::new(&AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap())
    }

    fn plan_for(req: &DeployRequest) -> Plan {
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef").expect("renders")
    }

    /// Look a per-agent file up by its **exact** path: both drop-ins end in
    /// `.service.d/agent.conf`, so a suffix match would silently pick one.
    fn per_agent<'a>(plan: &'a Plan, path: &str) -> &'a str {
        &plan
            .per_agent
            .iter()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("no per-agent file at {path}"))
            .body
    }

    fn shared<'a>(plan: &'a Plan, suffix: &str) -> &'a str {
        &plan
            .shared
            .iter()
            .find(|a| a.file.path.ends_with(suffix))
            .unwrap_or_else(|| panic!("no shared artifact ending in {suffix}"))
            .file
            .body
    }

    #[test]
    fn the_unit_never_restarts_an_intentional_exit() {
        let p = plan_for(&request());
        let unit = shared(&p, "/buzz-acp@.service");
        assert!(
            unit.contains("\nRestart=no\n"),
            "bounded lifetime is Restart=no"
        );
        assert!(
            !unit.contains("Restart=always") && !unit.contains("Restart=on-failure"),
            "[L1] item 5: a supervisor must never resurrect an intentional clean exit"
        );
    }

    #[test]
    fn the_harness_receives_the_termination_signal_directly() {
        let p = plan_for(&request());
        let unit = shared(&p, "/buzz-acp@.service");
        // No shell wrapper: a wrapper would swallow SIGTERM ([L1] item 3).
        assert!(unit.contains("\nExecStart=/usr/local/bin/buzz-acp\n"));
        assert!(unit.contains("\nTimeoutStopSec=120\n"));
    }

    /// P2-4: Task 14's `[L3]` section and the README both enumerate this unit's
    /// sandbox directives, and a directive that is documented but absent is
    /// worse than one that is neither. The only omission is `IPAddressDeny`,
    /// whose absence is this unit's entire reason to exist.
    #[test]
    fn the_fetcher_unit_carries_every_directive_the_docs_claim() {
        let p = plan_for(&request());
        let unit = shared(&p, "/buzz-acp-secret@.service");
        for directive in [
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "RestrictSUIDSGID=true",
            "RestrictRealtime=true",
            "LockPersonality=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "\nAmbientCapabilities=\n",
            "\nTasksMax=128\n",
            "RuntimeDirectoryMode=0750",
            "ReadWritePaths=-/run/buzz-acp-%i",
        ] {
            assert!(
                unit.contains(directive),
                "the fetcher unit lacks {directive}"
            );
        }
        // Exactly one capability, and it is the one `chown buzzacp` needs.
        assert!(
            unit.contains("\nCapabilityBoundingSet=CAP_CHOWN\n"),
            "{unit}"
        );
        assert!(
            !unit.contains("ReadWritePaths=/run\n"),
            "the whole of /run is not this unit's runtime directory"
        );
        assert!(
            !unit.contains("IPAddressDeny"),
            "IPAddressDeny would block the metadata fetch this unit exists to perform"
        );
    }

    #[test]
    fn the_fetcher_script_checks_its_argument_before_using_it() {
        let p = plan_for(&request());
        let script = shared(&p, "/buzz-acp-fetch-key");
        assert!(
            script.starts_with("#!/bin/bash\n"),
            "must start with a shebang"
        );
        assert!(script.contains("set -euo pipefail"));
        assert!(script.contains(r#"[ "$#" -eq 1 ]"#), "arity check");
        assert!(script.contains("^[0-9a-f]{12}$"), "instance shape check");
        assert!(
            script.contains("--project="),
            "explicit project, never ambient"
        );
        assert!(script.contains("secret.env.tmp"), "atomic temp file");
        assert!(script.contains("mv -f"), "rename into place");
        // Written as root, then tightened, then handed over — which is what
        // keeps `CapabilityBoundingSet=` down to CAP_CHOWN.
        assert!(script.contains("chown buzzacp:buzzacp"), "{script}");
        assert!(
            script.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            "a script run by systemd inherits systemd's environment, not a shell's"
        );
    }

    #[test]
    fn the_project_reaches_the_fetcher_through_a_per_agent_dropin() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = ProviderConfig::parse(&serde_json::json!({"project": "other-project"})).unwrap();
        let p = plan(&req.agent, &cfg, &names, &identity, "deadbeef").unwrap();
        let dropin = per_agent(&p, &names.secret_dropin_path());
        assert!(dropin.contains("Environment=BUZZ_GCP_PROJECT=other-project"));
        assert!(dropin.contains(&format!(
            "Environment=BUZZ_GCP_SECRET={}",
            names.secret_name()
        )));
        // …and the shared script stays identical for every agent and project.
        assert!(!shared(&p, "/buzz-acp-fetch-key").contains("other-project"));
    }

    /// P1-3: this drop-in is a **root-installed** unit file and `project`
    /// reaches it as an `Environment=` value, which systemd parses for
    /// whitespace, quotes and `%` specifiers. Task 4's closed grammar is what
    /// makes the interpolation safe; this asserts the rendered value cannot be
    /// anything the parser would treat specially, so the two stay in step.
    #[test]
    fn the_fetcher_dropin_environment_values_carry_no_systemd_metacharacters() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let p = plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef").unwrap();
        let dropin = per_agent(&p, &names.secret_dropin_path());
        let assignments: Vec<&str> = dropin
            .lines()
            .filter_map(|line| line.strip_prefix("Environment="))
            .collect();
        assert_eq!(assignments.len(), 2, "{dropin}");
        for assignment in assignments {
            let (_, value) = assignment
                .split_once('=')
                .expect("an Environment= line is NAME=VALUE");
            assert!(
                value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{assignment} carries a character systemd's Environment= parser \
                 treats specially"
            );
        }
    }

    #[test]
    fn an_owner_is_always_present_in_the_environment() {
        let req = request();
        let p = plan_for(&req);
        let env = per_agent(&p, &names_for(&req).env_path());
        assert!(
            p.secret_body().contains("BUZZ_AUTH_TAG=") || env.contains("BUZZ_ACP_AGENT_OWNER="),
            "without an owner the harness cannot match !shutdown"
        );
    }

    #[test]
    fn the_dropin_carries_the_configured_limits() {
        let req = request();
        let p = plan_for(&req);
        let dropin = per_agent(&p, &names_for(&req).dropin_path());
        assert!(dropin.contains("\nMemoryMax=2G\n"));
        assert!(dropin.contains("\nCPUQuota=150%\n"));
    }

    /// Design §Testing's secret-leak test, defined over **every**
    /// secret-classified value rather than only the nsec. The old nsec-only
    /// grep is what let this class of defect through: it passes while four
    /// tokens leak.
    #[test]
    fn no_secret_classified_value_reaches_any_artifact() {
        let mut req = request();
        let launch = req
            .agent
            .launch
            .as_mut()
            .expect("the fixture has a launch block");
        launch
            .env
            .insert("ANTHROPIC_API_KEY".into(), "sk-ant-LEAK-ME-0001".into());
        launch
            .policy_env
            .insert("SOME_NEW_TOKEN".into(), "tok-LEAK-ME-0002".into());
        req.agent.auth_tag = Some("tag-LEAK-ME-0003".into());

        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let p = plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef").unwrap();
        let warnings = crate::capacity::warning_lines(
            1024 * 1024 * 1024,
            1024 * 1024 * 1024,
            &names.unit(),
            2 * 1024 * 1024 * 1024,
        );
        let record = crate::capacity::trail_record(
            "2026-08-05T09:14:02Z",
            "deadbeef",
            &p.create_intent,
            &warnings,
        );
        let report = dry_run_report(&p, &names, &record);

        let leaked = [
            req.agent.private_key_nsec.as_str(),
            "sk-ant-LEAK-ME-0001",
            "tok-LEAK-ME-0002",
            "tag-LEAK-ME-0003",
        ];
        let mut surfaces: Vec<(String, &str)> = Vec::new();
        for f in &p.per_agent {
            surfaces.push((f.path.clone(), f.body.as_str()));
        }
        for a in &p.shared {
            surfaces.push((a.file.path.clone(), a.file.body.as_str()));
        }
        surfaces.push(("trail header".into(), p.trail.body.as_str()));
        surfaces.push(("trail record".into(), record.as_str()));
        surfaces.push(("dry-run report".into(), report.as_str()));
        // The intent now covers a *digest* of the secret payload; a digest of a
        // value is not the value, and this is where that stops being a claim.
        surfaces.push(("create-intent".into(), p.create_intent.as_str()));
        for warning in &warnings {
            surfaces.push(("stderr warning".into(), warning.as_str()));
        }

        for (where_, text) in surfaces {
            for value in leaked {
                assert!(
                    !text.contains(value),
                    "{where_} leaked a secret-classified value"
                );
            }
        }

        // …and every one of their keys must be in the Secret Manager payload.
        for key in [
            "BUZZ_PRIVATE_KEY",
            "NOSTR_PRIVATE_KEY",
            "BUZZ_AUTH_TAG",
            "ANTHROPIC_API_KEY",
            "SOME_NEW_TOKEN",
        ] {
            assert!(
                p.secret_env.contains_key(key),
                "{key} was not classified as secret"
            );
        }
        let secret = p.secret_body();
        for value in leaked {
            assert!(secret.contains(value), "the secret payload lost a value");
        }
    }

    /// The on-disk env file holds allowlisted keys and nothing else — if a
    /// non-allowlisted key appears there, that *is* the finding.
    #[test]
    fn the_on_disk_env_file_holds_only_allowlisted_keys() {
        let req = request();
        let p = plan_for(&req);
        for line in per_agent(&p, &names_for(&req).env_path()).lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let key = line.split('=').next().unwrap_or_default();
            assert!(
                NON_SECRET_KEYS.contains(&key),
                "{key} is on the boot disk but is not allowlisted"
            );
        }
    }

    #[test]
    fn dry_run_redacts_every_secret_value_but_keeps_the_keys() {
        let req = request();
        let names = names_for(&req);
        let p = plan_for(&req);
        let report = dry_run_report(&p, &names, "deploy T generation=g intent=i\n");
        assert!(report.contains("BUZZ_PRIVATE_KEY=[REDACTED]"));
        assert!(report.contains("NOSTR_PRIVATE_KEY=[REDACTED]"));
        assert!(!report.contains("nsec1"));
        // The on-disk file is printed verbatim, because every value in it is
        // allowlisted by construction.
        assert!(report.contains("BUZZ_RELAY_URL=\"wss://relay.example\""));
    }

    /// Per-agent artifacts carry the per-agent marker; shared artifacts carry
    /// the provider-level marker and **no** pubkey or intent. This replaces
    /// `every_installed_file_carries_the_marker`, which asserted the wrong
    /// invariant — one enforceable only by making the shared marker a lie.
    #[test]
    fn every_installed_file_carries_the_marker_of_its_own_tier() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let p = plan_for(&req);

        for f in p.per_agent.iter().chain(std::iter::once(&p.trail)) {
            let marker = AgentMarker::parse(&f.body)
                .unwrap_or_else(|| panic!("{} carries no per-agent marker", f.path));
            assert_eq!(marker.pubkey_full, identity.pubkey_hex());
            assert_eq!(marker.create_intent, p.create_intent);
            assert_eq!(shared_ownership(&f.body), Ownership::NotOurs);
        }

        for a in &p.shared {
            assert!(
                shared_ownership(&a.file.body) == Ownership::Ours,
                "{} carries no provider-level marker at this binding version",
                a.file.path
            );
            assert!(
                AgentMarker::parse(&a.file.body).is_none(),
                "{} claims an agent identity it cannot have",
                a.file.path
            );
            assert!(
                !a.file.body.contains(identity.pubkey_hex()),
                "{} embeds an agent pubkey",
                a.file.path
            );
            assert!(
                !a.file.body.contains(&p.create_intent),
                "{} embeds an agent create-intent",
                a.file.path
            );
        }
    }

    /// P1-4 and P1-9 are only safe if the fence travels with the file: every
    /// installed artifact declares the header its target must already carry,
    /// so `Remote::install` cannot be called unguarded. And the declared lines
    /// must be lines of the body we are about to write, or the next deploy
    /// would refuse the file this one just installed.
    #[test]
    fn every_rendered_file_declares_the_marker_its_target_must_carry() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let p = plan_for(&req);

        // The tier's identity lines, and nothing else. `binding-version` is
        // absent deliberately: `remote::marker_fn` compares it as an ordering,
        // so an exact needle would make the install that upgrades a
        // prior-version file be refused by that file's own fence.
        let agent_lines = [
            format!("# managed-by: {MANAGED_BY}"),
            format!("# agent-pubkey-full: {}", identity.pubkey_hex()),
        ];
        for f in p.per_agent.iter().chain(std::iter::once(&p.trail)) {
            assert_eq!(f.owner_marker, agent_lines, "{}", f.path);
            for line in &f.owner_marker {
                assert!(
                    f.body.lines().any(|l| l == line),
                    "{} would refuse itself on the next deploy: no {line:?}",
                    f.path
                );
            }
            // …and the version is still *written*, because the reader that
            // orders it has to have something to read.
            assert!(f
                .body
                .lines()
                .any(|l| l == format!("# binding-version: {BINDING_VERSION}")));
        }

        let shared_lines = [
            format!("# managed-by: {MANAGED_BY}"),
            format!("# scope: {SHARED_SCOPE}"),
        ];
        for a in &p.shared {
            assert_eq!(a.file.owner_marker, shared_lines, "{}", a.file.path);
            for line in &a.file.owner_marker {
                assert!(
                    a.file.body.lines().any(|l| l == line),
                    "{} would refuse itself on the next deploy: no {line:?}",
                    a.file.path
                );
            }
            assert!(a
                .file
                .body
                .lines()
                .any(|l| l == format!("# binding-version: {BINDING_VERSION}")));
        }
    }

    /// Two different agents must render byte-identical shared artifacts, or
    /// the "zero mutation, shared files included" no-op is unreachable.
    #[test]
    fn shared_artifacts_are_identical_across_agents() {
        let a = plan_for(&request());
        let mut req = request();
        req.agent.private_key_nsec = OTHER_NSEC.to_string();
        let b = plan_for(&req);

        let digest = |p: &Plan| -> Vec<(String, String, String)> {
            p.shared
                .iter()
                .map(|s| (s.file.path.clone(), s.sha256.clone(), s.file.body.clone()))
                .collect()
        };
        assert_eq!(digest(&a), digest(&b));
    }

    /// The digest the reconciler compares must be the digest of the exact bytes
    /// that land on disk — header included, nothing stripped. The instance
    /// answers with `sha256sum` over the whole file, so any asymmetry here
    /// rewrites all three shared artifacts on every deploy.
    #[test]
    fn a_shared_artifact_digest_covers_the_exact_bytes_installed() {
        for a in &plan_for(&request()).shared {
            assert_eq!(
                sha256_hex(a.file.body.as_bytes()),
                a.sha256,
                "{} declares a digest of something other than itself",
                a.file.path
            );
        }
    }

    #[test]
    fn env_values_are_quoted_so_spaces_survive_systemd_parsing() {
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .policy_env
            .insert("BUZZ_ACP_SESSION_TITLE".into(), "a b".into());
        let p = plan_for(&req);
        // BUZZ_ACP_SESSION_TITLE is not allowlisted, so it lands in the secret
        // payload — where the same quoting rule applies.
        assert!(p.secret_body().contains("BUZZ_ACP_SESSION_TITLE=\"a b\""));
    }

    #[test]
    fn an_env_value_containing_a_newline_is_refused() {
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .env
            .insert("MULTILINE".into(), "a\nb".into());
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let err = plan(&req.agent, &gcp_config(), &names, &identity, "deadbeef")
            .expect_err("a raw newline in an EnvironmentFile value must be refused");
        assert!(err.contains("MULTILINE"), "{err}");
        assert!(!err.contains("a\nb"), "the refusal must not echo the value");
    }

    #[test]
    fn a_divergent_spec_produces_a_different_create_intent() {
        let a = plan_for(&request());
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .policy_env
            .insert("BUZZ_ACP_MODEL".into(), "different".into());
        assert_ne!(a.create_intent, plan_for(&req).create_intent);
    }

    /// The generation must not perturb the intent, or every deploy would look
    /// divergent and the reconciler would replace a healthy unit on each
    /// Start. `BUZZ_MANAGED_AGENT_START_NONCE` *is* the generation and lives
    /// in the on-disk environment, so the intent feed must skip it by name.
    #[test]
    fn the_generation_does_not_perturb_the_create_intent() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = gcp_config();
        let a = plan(&req.agent, &cfg, &names, &identity, "aaaaaaaa").unwrap();
        let b = plan(&req.agent, &cfg, &names, &identity, "bbbbbbbb").unwrap();
        assert_eq!(a.create_intent, b.create_intent);
        assert_ne!(
            per_agent(&a, &names.env_path()),
            per_agent(&b, &names.env_path()),
            "the nonce still has to reach the agent"
        );
    }

    /// A different memory limit is a different unit, so it must diverge.
    #[test]
    fn a_changed_resource_limit_diverges_the_intent() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let a = plan(&req.agent, &gcp_config(), &names, &identity, "g").unwrap();
        let cfg = ProviderConfig::parse(&serde_json::json!({"memory_max": "1G"})).unwrap();
        let b = plan(&req.agent, &cfg, &names, &identity, "g").unwrap();
        assert_ne!(a.create_intent, b.create_intent);
    }

    /// P1-7: a rotated credential must diverge the intent. Otherwise the
    /// reconciler classifies it `RestartSame`, skips `secrets::store`, and
    /// restarts the agent against the previous secret version — a successful
    /// restart for the operator and the old identity for the relay.
    #[test]
    fn a_rotated_credential_diverges_the_intent_without_exposing_it() {
        let a = plan_for(&request());
        let mut rotated = request();
        rotated.agent.auth_tag = Some("tag-ROTATED-0001".into());
        let b = plan_for(&rotated);
        assert_ne!(
            a.create_intent, b.create_intent,
            "a rotated auth_tag must not look like the same deploy"
        );
        assert!(!b.create_intent.contains("ROTATED"));
        for f in b.per_agent.iter().chain(std::iter::once(&b.trail)) {
            assert!(!f.body.contains("tag-ROTATED-0001"), "{}", f.path);
        }
        // A key added to the payload diverges it too — the digest covers the
        // whole body, so the key set comes along for free.
        let mut renamed = request();
        renamed
            .agent
            .launch
            .as_mut()
            .unwrap()
            .env
            .insert("OPENAI_API_KEY".into(), "sk-x".into());
        assert_ne!(a.create_intent, plan_for(&renamed).create_intent);
    }

    /// P2-4 (round 3): the case above covers a changed value and an added key.
    /// The one it misses is a value that changes **side** — allowlisted on one
    /// deploy, secret-classified on the next — with the key set and the value
    /// multiset both unchanged. That is not hypothetical: it is what editing
    /// `NON_SECRET_KEYS` does to every agent already deployed, and the two
    /// deploys are genuinely different, because one writes the value into a
    /// 0600 file on the persistent boot disk and the other into Secret
    /// Manager. A fingerprint that hashed the whole environment *before* the
    /// split would call them identical, classify `RestartSame`, and never
    /// re-store the secret.
    #[test]
    fn a_value_that_changes_side_diverges_the_intent() {
        // `BUZZ_ACP_AGENT_ARGS` is allowlisted and comes from `launch.args`;
        // `TEAM_TOKEN` is not allowlisted, so it is secret-classified. Swap
        // which value each carries and nothing else moves.
        let side = |args: &str, token: &str| {
            let mut req = request();
            let launch = req.agent.launch.as_mut().unwrap();
            launch.args = vec![args.to_string()];
            launch.env.insert("TEAM_TOKEN".into(), token.to_string());
            plan_for(&req)
        };
        let a = side("SIDEONE", "SIDETWO");
        let b = side("SIDETWO", "SIDEONE");

        // Same two values, opposite halves of the split.
        assert!(a.secret_body().contains("SIDETWO") && !a.secret_body().contains("SIDEONE"));
        assert!(b.secret_body().contains("SIDEONE") && !b.secret_body().contains("SIDETWO"));
        assert_ne!(
            a.create_intent, b.create_intent,
            "the fingerprint must be side-aware, not merely content-aware"
        );
        for intent in [&a.create_intent, &b.create_intent] {
            assert!(
                !intent.contains("SIDE"),
                "the intent leaks a value: {intent}"
            );
        }
    }

    /// P2-2 (round 3): `max_env_bytes: None` says the *core* imposes no cap,
    /// not that none applies. The secret half travels as one Secret Manager
    /// version, and a version payload is capped at 64 KiB, so an environment
    /// the core accepts can still be undeployable — and it must be refused
    /// here, in the pure phase, rather than in `secrets::store` after the
    /// shared templates are already installed.
    #[test]
    fn a_secret_payload_over_secret_managers_cap_is_refused_before_any_mutation() {
        let huge = "x".repeat(SECRET_MANAGER_MAX_PAYLOAD_BYTES);
        let mut req = request();
        req.agent
            .launch
            .as_mut()
            .unwrap()
            .env
            .insert("HUGE_API_KEY".into(), huge.clone());
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let err = plan(&req.agent, &gcp_config(), &names, &identity, "g")
            .expect_err("64 KiB is Secret Manager's hard cap on a version payload");
        assert!(err.contains("Secret Manager"), "{err}");
        assert!(
            err.contains(&SECRET_MANAGER_MAX_PAYLOAD_BYTES.to_string()),
            "the refusal must state the cap: {err}"
        );
        // [L2] item 5: a refusal about a secret value must not echo it.
        assert!(!err.contains(&huge), "the refusal echoes the value");
        assert!(
            !err.contains(&"x".repeat(64)),
            "the refusal echoes the value"
        );
    }

    /// …and the same size on the **allowlisted** half is fine, which is the
    /// whole point of putting the cap on `secret_body()` rather than on the
    /// environment: the boot disk has no such boundary.
    #[test]
    fn an_oversized_allowlisted_value_is_not_capped() {
        let mut req = request();
        req.agent.launch.as_mut().unwrap().args =
            vec!["y".repeat(SECRET_MANAGER_MAX_PAYLOAD_BYTES)];
        let p = plan_for(&req);
        assert!(p.secret_body().len() <= SECRET_MANAGER_MAX_PAYLOAD_BYTES);
        assert!(
            per_agent(&p, &names_for(&req).env_path()).len() > SECRET_MANAGER_MAX_PAYLOAD_BYTES
        );
    }

    /// v1 ships bounded lifetimes only, and the refusal must name the
    /// prerequisite rather than silently downgrading the request.
    #[test]
    fn the_indefinite_lifetime_is_refused_with_its_prerequisite_named() {
        let req = request();
        let identity = AgentIdentity::from_nsec(&req.agent.private_key_nsec).unwrap();
        let names = Names::new(&identity);
        let cfg = ProviderConfig::parse(&serde_json::json!({"inactivity_seconds": 0})).unwrap();
        let err = plan(&req.agent, &cfg, &names, &identity, "deadbeef").expect_err("refused");
        assert!(err.contains("indefinite lifetime"));
        assert!(err.contains("clean-exit contract"));
    }

    /// `launch.command` is resolved against the *desktop's* PATH, so only its
    /// basename is meaningful on the instance — and the default is what
    /// `buzz-acp` actually execs when nothing is named. That is `goose`
    /// (`crates/buzz-acp/src/config.rs:190-192`), **not** `buzz-acp`, which is
    /// the supervisor doing the exec'ing.
    #[test]
    fn the_harness_command_falls_back_to_the_harnesss_own_default() {
        let mut req = request();
        req.agent.launch.as_mut().unwrap().command = Some("/opt/homebrew/bin/codex-acp".into());
        assert_eq!(harness_basename(&req.agent), "codex-acp");
        req.agent.launch.as_mut().unwrap().command = None;
        assert_eq!(harness_basename(&req.agent), DEFAULT_HARNESS);
        assert_eq!(DEFAULT_HARNESS, "goose");
        // A payload naming nothing still gets an explicit, absolute command, so
        // Task 12's `test -x` and the harness's exec name the same file rather
        // than both resolving a bare name against systemd's PATH.
        let p = plan_for(&req);
        assert!(
            per_agent(&p, &names_for(&req).env_path())
                .contains("BUZZ_ACP_AGENT_COMMAND=\"/usr/local/bin/goose\""),
            "{}",
            per_agent(&p, &names_for(&req).env_path())
        );
    }

    /// P1-1: the *rendered environment* must carry the instance's spelling of
    /// the harness, never the desktop's. A host path here passes the
    /// installation check for its basename and then fails at exec on the VM.
    #[test]
    fn the_env_carries_the_instance_path_never_the_desktop_one() {
        let mut req = request();
        req.agent.launch.as_mut().unwrap().command = Some("/opt/homebrew/bin/codex-acp".into());
        let names = names_for(&req);
        let p = plan_for(&req);
        let env = per_agent(&p, &names.env_path());
        assert!(
            env.contains("BUZZ_ACP_AGENT_COMMAND=\"/usr/local/bin/codex-acp\""),
            "{env}"
        );

        let record = crate::capacity::trail_record("t", "g", &p.create_intent, &[]);
        let report = dry_run_report(&p, &names, &record);
        let secret = p.secret_body();
        let mut surfaces: Vec<&str> = p.per_agent.iter().map(|f| f.body.as_str()).collect();
        surfaces.extend(p.shared.iter().map(|a| a.file.body.as_str()));
        surfaces.push(p.trail.body.as_str());
        surfaces.push(secret.as_str());
        surfaces.push(report.as_str());
        for text in surfaces {
            assert!(
                !text.contains("/opt/homebrew"),
                "the desktop's path reached the instance"
            );
        }
    }
}
