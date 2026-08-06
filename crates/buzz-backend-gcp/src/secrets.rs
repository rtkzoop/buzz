//! Agent secret storage in Secret Manager (spec §Secret Manager ownership).
//!
//! The payload is the whole secret-classified environment, not just the key,
//! and it reaches `gcloud` on **stdin** — never as an argv element.
//!
//! The secret is the one artifact that does not live on the instance, so its
//! marker cannot be a header comment: it is labels plus an annotation, written
//! at create time and **verified before every add-version, IAM binding, and
//! delete**. Name collision is not ownership.

use crate::naming::{ownership_of, Ownership, BINDING_VERSION, MANAGED_BY};
use crate::remote::{Gcloud, Output};

/// Label key carrying the marker's identity half.
const LABEL_MANAGED_BY: &str = "managed_by";
/// Label key carrying the marker's schema half.
const LABEL_BINDING_VERSION: &str = "binding_version";
/// Label key carrying the truncated, *selectable* identity.
const LABEL_AGENT_PUBKEY: &str = "agent_pubkey";
/// Annotation key carrying the full pubkey — 64 chars, over the 63-char cap
/// on a label value, and the operand every destructive fence compares against.
const ANNOTATION_PUBKEY_FULL: &str = "agent-pubkey-full";

/// The `--labels` argument value for `gcloud secrets create`.
///
/// Labels are the half that must be *selectable*, which is what lets `list`
/// enumerate our secrets server-side with
/// `--filter="labels.managed_by=buzz-backend-gcp"`. `pubkey_full` must
/// already be 64 lowercase hex; the truncation below is by `chars()` so the
/// function is total for any input rather than panicking on a short or
/// non-ASCII one.
#[allow(dead_code)] // Called once secrets::store writes labels on create/update.
pub fn labels_for(pubkey_full: &str) -> String {
    let selector: String = pubkey_full.chars().take(32).collect();
    format!(
        "{LABEL_MANAGED_BY}={MANAGED_BY},\
         {LABEL_BINDING_VERSION}={BINDING_VERSION},\
         {LABEL_AGENT_PUBKEY}={selector}"
    )
}

/// The `--set-annotations` argument value for `gcloud secrets create`.
#[allow(dead_code)] // Called once secrets::store stamps the full-pubkey annotation on create.
pub fn annotations_for(pubkey_full: &str) -> String {
    format!("{ANNOTATION_PUBKEY_FULL}={pubkey_full}")
}

/// Fail-closed ownership gate over `gcloud secrets describe --format=json`.
///
/// Requires **both** marker halves *and* a full-pubkey match, mirroring
/// `secret_is_ours` in the Kubernetes binding (`observe.rs:64-67`). Pure, so
/// every branch is tested without a project.
///
/// The two labels go through [`ownership_of`], the same rule the file-header
/// tiers use, so "ours / ours-but-older / ours-but-newer / not ours" has one
/// definition in this binding rather than one per storage medium. `Ok` carries
/// the verdict because the caller has to act on it: `OursButOlder` means the
/// labels need rolling forward before anything else happens.
#[allow(dead_code)] // Called once secrets::{store,destroy} fence every mutation.
pub fn verify_owned(
    described: &serde_json::Value,
    pubkey_full: &str,
    name: &str,
) -> Result<Ownership, String> {
    let label = |key: &str| {
        described
            .get("labels")
            .and_then(|labels| labels.get(key))
            .and_then(serde_json::Value::as_str)
    };
    let ownership = ownership_of(label(LABEL_MANAGED_BY), label(LABEL_BINDING_VERSION));
    match ownership {
        Ownership::Ours | Ownership::OursButOlder(_) => {}
        Ownership::OursButNewer(found) => {
            return Err(format!(
                "secret {name} was created by a newer {MANAGED_BY} (binding \
                 version {found}; this build writes {BINDING_VERSION}). \
                 Refusing to write a version into, or delete, a secret whose \
                 layout this build does not understand. Upgrade this provider."
            ))
        }
        Ownership::NotOurs => {
            return Err(format!(
                "secret {name} already exists but is not managed by \
                 {MANAGED_BY} at a binding version this build recognises. \
                 Refusing to modify a secret this provider did not create — \
                 rename or delete it, or point this agent at a different \
                 instance."
            ))
        }
    }
    let annotated = described
        .get("annotations")
        .and_then(|annotations| annotations.get(ANNOTATION_PUBKEY_FULL))
        .and_then(serde_json::Value::as_str);
    match annotated {
        Some(pubkey) if pubkey == pubkey_full => Ok(ownership),
        Some(pubkey) => Err(format!(
            "secret {name} belongs to pubkey {pubkey}, not {pubkey_full}. The \
             12-hex name is collision-resistant, not collision-free; refusing \
             rather than overwriting another agent's key."
        )),
        None => Err(format!(
            "secret {name} carries no {ANNOTATION_PUBKEY_FULL} annotation, so \
             which agent it belongs to cannot be established. Refusing."
        )),
    }
}

/// Read a secret's metadata. `Ok(None)` means it does not exist.
#[allow(dead_code)] // Called once secrets::{store,destroy,describe_owned} read metadata before mutate.
pub fn describe(
    remote: &dyn Gcloud,
    project: &str,
    name: &str,
) -> Result<Option<serde_json::Value>, String> {
    let out = remote.gcloud(
        &[
            "secrets",
            "describe",
            name,
            "--project",
            project,
            "--format=json",
        ],
        None,
    )?;
    if !out.ok() {
        if out.stderr.contains("NOT_FOUND") || out.stderr.contains("was not found") {
            return Ok(None);
        }
        return Err(format!(
            "describing secret {name} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    serde_json::from_str(&out.stdout)
        .map(Some)
        .map_err(|e| format!("could not parse the description of secret {name}: {e}"))
}

/// Read the secret and verify our marker, as one step, immediately before a
/// mutation.
///
/// Every mutation in this module is preceded by this call with **nothing** in
/// between. A single verification at the top of `store` authorized an
/// add-version and an IAM grant that happened one and two API round trips
/// later, and a name-matching secret swapped into that window receives this
/// agent's whole environment or hands the VM `secretAccessor` on a resource we
/// no longer own.
///
/// A secret that vanished between two checks is a refusal, not a create: this
/// is only reached on a path that has already established it exists.
fn describe_owned(
    remote: &dyn Gcloud,
    project: &str,
    name: &str,
    pubkey_full: &str,
) -> Result<Ownership, String> {
    let Some(described) = describe(remote, project, name)? else {
        return Err(format!(
            "secret {name} disappeared between two checks in this deploy. \
             Nothing further was changed; run the deploy again."
        ));
    };
    verify_owned(&described, pubkey_full, name)
}

/// Does this `gcloud secrets create` failure mean somebody else won the race?
///
/// Two spellings because `gcloud` surfaces the API status on some paths and a
/// prose message on others. Matching either is what keeps a lost race
/// convergent instead of turning it into a hard failure.
fn already_exists(out: &Output) -> bool {
    out.stderr.contains("ALREADY_EXISTS") || out.stderr.contains("already exists")
}

/// Create-if-absent behind the ownership gate, then add a version carrying
/// `body`, then grant the instance service account read access.
///
/// Idempotent: versions are cheap, and adding one is the only way to guarantee
/// the latest value matches this deploy. Both mutations are individually
/// fenced — see `describe_owned`.
#[allow(dead_code)] // Called once reconcile::deploy uploads the secret-classified environment.
pub fn store(
    remote: &dyn Gcloud,
    project: &str,
    name: &str,
    pubkey_full: &str,
    body: &str,
    service_account: &str,
) -> Result<(), String> {
    match describe(remote, project, name)? {
        Some(existing) => {
            // Verified here. On the steady-state path nothing at all separates
            // this check from the `versions add` below — that is the invariant
            // round 2's P1-5 established and the sequence test asserts.
            if let Ownership::OursButOlder(from) = verify_owned(&existing, pubkey_full, name)? {
                // Ours, one layout back. Roll the marker forward *first*, so a
                // deploy interrupted after this point leaves a secret the next
                // run reads as `Ours` rather than repeating the upgrade.
                // Nothing separates this mutation from the check above either.
                let labels = labels_for(pubkey_full);
                let out = remote.gcloud(
                    &[
                        "secrets",
                        "update",
                        name,
                        "--project",
                        project,
                        "--update-labels",
                        &labels,
                    ],
                    None,
                )?;
                if !out.ok() {
                    return Err(format!(
                        "rolling secret {name} forward from binding version \
                         {from} to {BINDING_VERSION} failed (exit {}): {}",
                        out.code,
                        out.stderr.trim()
                    ));
                }
                // A full API round trip now separates the verification above
                // from the add below, so the add gets its own re-read. On the
                // steady-state path this costs nothing, because it does not run.
                describe_owned(remote, project, name, pubkey_full)?;
            }
        }
        None => {
            let labels = labels_for(pubkey_full);
            let annotations = annotations_for(pubkey_full);
            let out = remote.gcloud(
                &[
                    "secrets",
                    "create",
                    name,
                    "--project",
                    project,
                    "--replication-policy",
                    "automatic",
                    "--labels",
                    &labels,
                    "--set-annotations",
                    &annotations,
                ],
                None,
            )?;
            // A failed create is not decisive. Two concurrent deploys can both
            // observe "absent", and the loser must converge by re-entry rather
            // than fail. `ALREADY_EXISTS` says somebody won; the marker on what
            // they created is what decides whether we may proceed, and reading
            // it is the very next thing that happens.
            if !out.ok() && !already_exists(&out) {
                return Err(format!(
                    "creating secret {name} failed (exit {}): {}",
                    out.code,
                    out.stderr.trim()
                ));
            }
            describe_owned(remote, project, name, pubkey_full)?;
        }
    }

    let out = remote.gcloud(
        &[
            "secrets",
            "versions",
            "add",
            name,
            "--project",
            project,
            "--data-file=-",
        ],
        Some(body),
    )?;
    if !out.ok() {
        // stderr can echo the request body on some failures; report only the
        // code and the name (L2 item 5).
        return Err(format!(
            "adding a version to secret {name} failed with exit {}",
            out.code
        ));
    }

    // The IAM grant is a second mutation and gets its own re-read: a full API
    // round trip separates it from the check above.
    describe_owned(remote, project, name, pubkey_full)?;
    let member = format!("serviceAccount:{service_account}");
    let out = remote.gcloud(
        &[
            "secrets",
            "add-iam-policy-binding",
            name,
            "--project",
            project,
            "--member",
            &member,
            "--role",
            "roles/secretmanager.secretAccessor",
        ],
        None,
    )?;
    if !out.ok() {
        return Err(format!(
            "granting {service_account} access to secret {name} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    Ok(())
}

/// Delete the secret and every version, behind the same ownership gate.
///
/// Delete-of-absent is success ([L2] item 4), which is what makes an
/// interrupted `remove` idempotent.
#[allow(dead_code)] // Called once reconcile::remove / operator destroy tears the secret down.
pub fn destroy(
    remote: &dyn Gcloud,
    project: &str,
    name: &str,
    pubkey_full: &str,
) -> Result<(), String> {
    let Some(existing) = describe(remote, project, name)? else {
        return Ok(());
    };
    // The same describe-and-verify `describe_owned` performs, inlined so the
    // absent case above costs no second round trip. Nothing separates this
    // check from the delete it authorizes.
    verify_owned(&existing, pubkey_full, name)?;
    let out = remote.gcloud(
        &["secrets", "delete", name, "--project", project, "--quiet"],
        None,
    )?;
    if out.ok() || out.stderr.contains("NOT_FOUND") {
        return Ok(());
    }
    Err(format!(
        "deleting secret {name} failed (exit {}): {}",
        out.code,
        out.stderr.trim()
    ))
}

/// The instance's attached service account — the identity the fetcher unit
/// authenticates as, and the only principal granted access to the secret.
#[allow(dead_code)] // Called once reconcile::deploy resolves the VM identity before secrets::store.
pub fn instance_service_account(
    remote: &dyn Gcloud,
    project: &str,
    zone: &str,
    instance: &str,
) -> Result<String, String> {
    let out = remote.gcloud(
        &[
            "compute",
            "instances",
            "describe",
            instance,
            "--project",
            project,
            "--zone",
            zone,
            "--format",
            "value(serviceAccounts[0].email)",
        ],
        None,
    )?;
    if !out.ok() {
        return Err(format!(
            "describing instance {instance} failed (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    let email = out.stdout.trim().to_string();
    if email.is_empty() {
        return Err(format!(
            "{instance} has no attached service account, so the fetcher unit \
             would have no identity to read the secret with"
        ));
    }
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_backend_core::identity::AgentIdentity;
    use serde_json::json;

    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    fn pubkey() -> String {
        AgentIdentity::from_nsec(NSEC)
            .unwrap()
            .pubkey_hex()
            .to_string()
    }

    fn described(pubkey: &str) -> serde_json::Value {
        json!({
            "name": "projects/p/secrets/buzz-agent-abc-private-key",
            "labels": {
                "managed_by": MANAGED_BY,
                "binding_version": BINDING_VERSION,
                "agent_pubkey": &pubkey[..32],
            },
            "annotations": { "agent-pubkey-full": pubkey }
        })
    }

    #[test]
    fn labels_carry_the_marker_and_the_selectable_identity() {
        let pubkey = pubkey();
        let labels = labels_for(&pubkey);
        assert!(labels.contains(&format!("managed_by={MANAGED_BY}")));
        assert!(labels.contains(&format!("binding_version={BINDING_VERSION}")));
        assert!(labels.contains(&format!("agent_pubkey={}", &pubkey[..32])));
        // GCP label values allow only lowercase letters, digits, `-` and `_`.
        assert!(labels
            .split(',')
            .filter_map(|pair| pair.split('=').nth(1))
            .all(|v| v
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')));
        // The full pubkey is 64 chars, over the 63-char label-value cap, so it
        // is an annotation instead.
        assert!(!labels.contains(&pubkey));
        assert!(annotations_for(&pubkey).contains(&pubkey));
    }

    #[test]
    fn a_fully_marked_secret_is_ours() {
        let pubkey = pubkey();
        assert_eq!(
            verify_owned(&described(&pubkey), &pubkey, "s").expect("ours"),
            Ownership::Ours
        );
    }

    /// An object that merely matches our schema fails closed: the marker is
    /// what asserts protocol ownership, and labels alone do not.
    #[test]
    fn an_unmarked_secret_is_a_refusal_never_a_takeover() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]
            .as_object_mut()
            .unwrap()
            .remove("managed_by");
        let err = verify_owned(&secret, &pubkey, "s").expect_err("must refuse");
        assert!(err.contains("not managed by"), "{err}");
    }

    /// P1-1, the Secret Manager half: an older binding version is this
    /// provider's own secret at a layout this build supersedes. Refusing it
    /// stranded every existing agent's secret behind a version bump — the
    /// deploy could not add a version and `remove` could not delete it.
    #[test]
    fn a_secret_from_an_older_binding_version_is_an_upgrade_target() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]["binding_version"] = json!("0");
        assert_eq!(
            verify_owned(&secret, &pubkey, "s").expect("ours, one release back"),
            Ownership::OursButOlder(0)
        );
    }

    /// …and a *newer* one is the refusal that reserves, naming the version so
    /// the operator is not told their own secret is foreign.
    #[test]
    fn a_secret_from_a_future_binding_version_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]["binding_version"] = json!("99");
        let err = verify_owned(&secret, &pubkey, "s").expect_err("must refuse");
        assert!(err.contains("99"), "{err}");
        assert!(err.contains("newer"), "{err}");
        assert!(!err.contains("not managed by"), "{err}");
    }

    /// A `binding_version` label that is not a number describes no layout at
    /// all, so it cannot be ordered against ours. Fail closed.
    #[test]
    fn a_non_numeric_binding_version_label_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"]["binding_version"] = json!("1.0");
        assert!(verify_owned(&secret, &pubkey, "s").is_err());
    }

    /// The 12-hex name is collision-*resistant*, not collision-free, so the
    /// full-pubkey annotation is what makes acting on the name safe.
    #[test]
    fn a_short_name_collision_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["annotations"]["agent-pubkey-full"] = json!("ff".repeat(32));
        let err = verify_owned(&secret, &pubkey, "s").expect_err("must refuse");
        assert!(err.contains("belongs to pubkey"), "{err}");
    }

    #[test]
    fn a_secret_with_no_annotation_at_all_is_a_refusal() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret.as_object_mut().unwrap().remove("annotations");
        assert!(verify_owned(&secret, &pubkey, "s").is_err());
    }

    /// The refusal must name the conflicting resource so the operator can go
    /// look at it, but must never echo any payload.
    #[test]
    fn the_refusal_names_the_secret() {
        let pubkey = pubkey();
        let mut secret = described(&pubkey);
        secret["labels"] = json!({});
        let err =
            verify_owned(&secret, &pubkey, "buzz-agent-abc-private-key").expect_err("must refuse");
        assert!(err.contains("buzz-agent-abc-private-key"), "{err}");
    }

    /// A fake transport that records every `gcloud` invocation and answers
    /// `secrets describe` from a queue the test controls. The last queued
    /// answer repeats, so a test only has to spell out the entries that differ.
    struct Recorder {
        /// One entry per `secrets describe`, in order. `None` is NOT_FOUND.
        describes: std::cell::RefCell<std::collections::VecDeque<Option<serde_json::Value>>>,
        /// stderr for `secrets create`, so a lost create race is expressible.
        create_stderr: String,
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl Recorder {
        fn new(describes: Vec<Option<serde_json::Value>>) -> Self {
            Self {
                describes: std::cell::RefCell::new(describes.into()),
                create_stderr: String::new(),
                calls: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn losing_the_create_race(describes: Vec<Option<serde_json::Value>>) -> Self {
            Self {
                create_stderr:
                    "ERROR: (gcloud.secrets.create) ALREADY_EXISTS: Secret already exists"
                        .to_string(),
                ..Self::new(describes)
            }
        }

        /// The verbs, in the order they were invoked.
        fn sequence(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Gcloud for Recorder {
        fn gcloud(&self, args: &[&str], _stdin: Option<&str>) -> Result<Output, String> {
            let verb = match args {
                ["secrets", "describe", ..] => "describe",
                ["secrets", "create", ..] => "create",
                ["secrets", "update", ..] => "update",
                ["secrets", "versions", "add", ..] => "versions add",
                ["secrets", "add-iam-policy-binding", ..] => "add-iam-policy-binding",
                ["secrets", "delete", ..] => "delete",
                _ => "other",
            };
            self.calls.borrow_mut().push(verb.to_string());
            let mut out = Output {
                stdout: String::new(),
                stderr: String::new(),
                code: 0,
            };
            match verb {
                "describe" => {
                    let mut queue = self.describes.borrow_mut();
                    let answer = if queue.len() > 1 {
                        queue.pop_front().flatten()
                    } else {
                        queue.front().cloned().flatten()
                    };
                    match answer {
                        Some(value) => out.stdout = value.to_string(),
                        None => {
                            out.code = 1;
                            out.stderr = "NOT_FOUND: Secret [s] not found.".to_string();
                        }
                    }
                }
                "create" if !self.create_stderr.is_empty() => {
                    out.code = 1;
                    out.stderr = self.create_stderr.clone();
                }
                _ => {}
            }
            Ok(out)
        }
    }

    /// P1-5: `store` verified ownership once and then performed two mutations.
    /// Every mutation must be immediately preceded by a describe whose marker
    /// still matches — a property of the sequence, invisible to any test of
    /// `verify_owned` alone.
    #[test]
    fn every_mutation_is_immediately_preceded_by_a_describe_and_verify() {
        let pubkey = pubkey();
        let fake = Recorder::new(vec![Some(described(&pubkey))]);
        store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect("an owned secret stores");
        assert_eq!(
            fake.sequence(),
            [
                "describe",
                "versions add",
                "describe",
                "add-iam-policy-binding"
            ]
        );
    }

    /// P1-1's sequence half. A secret at an older binding version is rolled
    /// forward *before* the new version is added, so a deploy interrupted
    /// after the label update leaves a secret the next run reads as `Ours`
    /// rather than repeating the upgrade. The re-read between the update and
    /// the add is not optional: a full API round trip now separates the
    /// verification from the mutation it authorizes.
    #[test]
    fn a_secret_from_an_older_binding_version_is_rolled_forward() {
        let pubkey = pubkey();
        let mut older = described(&pubkey);
        older["labels"]["binding_version"] = json!("0");
        // Older on the first look, current on every look after the update.
        let fake = Recorder::new(vec![Some(older), Some(described(&pubkey))]);
        store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect("this provider's own prior-version secret is an upgrade target");
        assert_eq!(
            fake.sequence(),
            [
                "describe",
                "update",
                "describe",
                "versions add",
                "describe",
                "add-iam-policy-binding"
            ]
        );
    }

    /// The attack that sequence prevents: ownership holds when the version is
    /// added and has moved by the time the IAM grant would be issued. The VM
    /// service account must not be granted read access to somebody else's key.
    #[test]
    fn a_secret_swapped_before_the_iam_grant_is_refused() {
        let pubkey = pubkey();
        let mut stolen = described(&pubkey);
        stolen["annotations"]["agent-pubkey-full"] = json!("ff".repeat(32));
        let fake = Recorder::new(vec![Some(described(&pubkey)), Some(stolen)]);
        let err = store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect_err("a secret that changed hands must not be granted away");
        assert!(err.contains("belongs to pubkey"), "{err}");
        assert!(
            !fake
                .sequence()
                .contains(&"add-iam-policy-binding".to_string()),
            "the grant must never have been issued: {:?}",
            fake.sequence()
        );
    }

    /// The loser of a create race converges by re-entry rather than failing —
    /// which is what this binding's residual-risk note already promises.
    #[test]
    fn a_lost_create_race_is_re_read_and_verified_rather_than_failed() {
        let pubkey = pubkey();
        // Absent on the first look, then present and ours: the winner was
        // another deploy of this same agent.
        let fake = Recorder::losing_the_create_race(vec![None, Some(described(&pubkey))]);
        store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect("losing a create race must converge, not fail");
        assert_eq!(
            fake.sequence(),
            [
                "describe",
                "create",
                "describe",
                "versions add",
                "describe",
                "add-iam-policy-binding"
            ]
        );
    }

    /// …and losing it to something that is *not* ours is still a refusal: the
    /// winner's marker is what decides, not the fact that we lost.
    #[test]
    fn a_create_race_lost_to_a_foreign_secret_is_refused() {
        let pubkey = pubkey();
        let mut foreign = described(&pubkey);
        foreign["labels"] = json!({});
        let fake = Recorder::losing_the_create_race(vec![None, Some(foreign)]);
        let err = store(
            &fake,
            "p",
            "s",
            &pubkey,
            "BODY\n",
            "vm@p.iam.gserviceaccount.com",
        )
        .expect_err("the winner's marker decides");
        assert!(err.contains("not managed by"), "{err}");
        assert!(!fake.sequence().contains(&"versions add".to_string()));
    }

    /// Delete is irreversible, so its describe-and-verify sits immediately
    /// before it with nothing in between.
    #[test]
    fn destroy_verifies_immediately_before_the_delete() {
        let pubkey = pubkey();
        let fake = Recorder::new(vec![Some(described(&pubkey))]);
        destroy(&fake, "p", "s", &pubkey).expect("an owned secret is deleted");
        assert_eq!(fake.sequence(), ["describe", "delete"]);
    }

    /// Delete-of-absent is success ([L2] item 4) and must not reach the delete.
    #[test]
    fn destroying_an_absent_secret_is_success_and_mutates_nothing() {
        let fake = Recorder::new(vec![None]);
        destroy(&fake, "p", "s", &pubkey()).expect("delete-of-absent is success");
        assert_eq!(fake.sequence(), ["describe"]);
    }
}
