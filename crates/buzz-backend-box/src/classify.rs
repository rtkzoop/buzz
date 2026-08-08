//! Pure Box lifecycle classification.
//!
//! This module contains no HTTP or filesystem access. [`classify`] accepts a
//! verified observation and the freshly computed non-secret launch intent, then
//! returns one action for the reconciler. In particular, destructive actions
//! carry the exact observation snapshot that authorized them.

use crate::api::{BoxRecord, BoxState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed management marker written by the Box provisioner.
pub const MANAGED_BY: &str = "buzz-backend-box";
/// Current ownership-marker binding version.
pub const BINDING_VERSION: u32 = 1;

/// State of the fixed in-Box systemd service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServiceState {
    /// The service is active and must never be restarted by deploy.
    Active,
    /// The service is installed but inactive.
    Inactive,
    /// systemd reported a failed unit.
    Failed,
    /// The service state could not be read safely.
    #[default]
    Unknown,
    /// The unit is not installed yet.
    Missing,
}

/// Harness lifecycle facts decoded from non-secret state markers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HarnessState {
    /// No service or state marker could be settled.
    #[default]
    Unknown,
    /// No harness invocation has ever reached its started marker.
    NeverStartedRecoverable,
    /// Startup evidence proves the provider-owned Box cannot start as-is.
    NeverStartedBroken,
    /// The harness is currently live.
    Live,
    /// The previous stop was intentional and explicit Start may relaunch it.
    ExitedIntentional,
    /// The harness exited abnormally and this explicit Start may relaunch it.
    ExitedAbnormal,
}

/// Intent recorded by the launcher when a service stops.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StopIntent {
    /// No stop marker was found.
    #[default]
    None,
    /// The owner or provider intentionally stopped the service.
    External,
    /// The launcher stopped the Box after a normal or abnormal child exit.
    SelfStop,
    /// A prior invocation recorded an abnormal exit.
    Abnormal,
    /// A marker existed but did not contain a recognized value.
    Unknown,
}

/// Bounded presence information used as supporting liveness evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PresenceState {
    /// Fresh relay presence was observed.
    Fresh,
    /// Presence is absent or too old to use as positive evidence.
    #[default]
    Stale,
    /// Presence was not queried for this observation.
    Unknown,
}

/// A non-secret SHA-256 launch-intent fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Build a fingerprint from canonical, non-secret bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    /// Build a fingerprint from a recorded marker value without interpreting
    /// it. Malformed old values compare as divergence, which is fail-closed.
    pub fn from_recorded(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return the hexadecimal fingerprint value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only constructor that makes matrix fixtures easy to read.
    #[cfg(test)]
    pub fn for_test(seed: &str) -> Self {
        Self(format!("test-{seed}"))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The verified ownership marker read from a Box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipMarker {
    /// Full 64-character Nostr public key.
    pub pubkey: String,
    /// Provider management marker.
    pub managed_by: String,
    /// Marker binding version.
    pub binding_version: u32,
}

/// A complete observation snapshot that passed ownership verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBox {
    /// Box platform record at the time of observation.
    pub box_record: BoxRecord,
    /// Fixed service state.
    pub service: ServiceState,
    /// Decoded harness state.
    pub harness: HarnessState,
    /// Stop-intent marker state.
    pub stop_intent: StopIntent,
    /// Launch intent recorded in the Box, if present.
    pub launch_intent: Option<Fingerprint>,
    /// Supporting relay presence state.
    pub presence: PresenceState,
    /// Verified ownership marker.
    pub ownership: OwnershipMarker,
}

impl VerifiedBox {
    /// Return the stable Box id used as the provider protocol `agent_id`.
    pub fn id(&self) -> &str {
        &self.box_record.id
    }
}

/// Why classification returned an immediate report instead of a mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassificationError {
    /// The Box is in an API error state with no safe automatic recovery.
    BoxError,
    /// Observation data is incomplete or ambiguous.
    AmbiguousObservation,
}

/// Pure reconciliation action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// No verified Box exists at the deterministic identity.
    Create,
    /// Continue polling a Box whose lifecycle is still settling.
    Observe { box_id: String },
    /// Strict no-op on a live harness.
    NoOp { agent_id: String },
    /// Resume an archived Box, then provision and launch it.
    Resume { box_id: String },
    /// Wait for an in-flight archive to finish before re-entering.
    AwaitArchived { box_id: String },
    /// Launch on an existing inactive Box. The optional prior failure is
    /// reportable but never authorizes a destructive operation.
    Launch {
        box_id: String,
        prior_failure: Option<StopIntent>,
    },
    /// Fenced archive/replace authorized by this exact observation snapshot.
    FencedReplace {
        box_id: String,
        observation: Box<VerifiedBox>,
    },
    /// Return a bounded actionable condition.
    Report {
        box_id: String,
        error: ClassificationError,
    },
}

/// Apply the Box state × harness/service × intent table.
pub fn classify(observed: Option<&VerifiedBox>, desired: &Fingerprint) -> Action {
    let Some(box_) = observed else {
        return Action::Create;
    };

    match &box_.box_record.state {
        BoxState::Init | BoxState::Provisioning | BoxState::Provisioned | BoxState::Cloning => {
            Action::Observe {
                box_id: box_.box_record.id.clone(),
            }
        }
        BoxState::Archiving => Action::AwaitArchived {
            box_id: box_.box_record.id.clone(),
        },
        BoxState::Archived => Action::Resume {
            box_id: box_.box_record.id.clone(),
        },
        BoxState::Error | BoxState::Unknown(_) => Action::Report {
            box_id: box_.box_record.id.clone(),
            error: ClassificationError::BoxError,
        },
        BoxState::Ready | BoxState::Idle | BoxState::Running => {
            // Service activity wins over every intent comparison. A stale
            // relay presence must not cause a live harness to be recycled.
            if box_.service == ServiceState::Active || box_.harness == HarnessState::Live {
                return Action::NoOp {
                    agent_id: box_.box_record.id.clone(),
                };
            }

            match box_.harness {
                HarnessState::NeverStartedBroken => Action::FencedReplace {
                    box_id: box_.box_record.id.clone(),
                    observation: Box::new(box_.clone()),
                },
                HarnessState::NeverStartedRecoverable => {
                    if box_.launch_intent.as_ref() == Some(desired) {
                        Action::Observe {
                            box_id: box_.box_record.id.clone(),
                        }
                    } else {
                        Action::FencedReplace {
                            box_id: box_.box_record.id.clone(),
                            observation: Box::new(box_.clone()),
                        }
                    }
                }
                HarnessState::ExitedIntentional => Action::Launch {
                    box_id: box_.box_record.id.clone(),
                    prior_failure: Some(StopIntent::External),
                },
                HarnessState::ExitedAbnormal => Action::Launch {
                    box_id: box_.box_record.id.clone(),
                    prior_failure: Some(StopIntent::Abnormal),
                },
                HarnessState::Unknown => Action::Report {
                    box_id: box_.box_record.id.clone(),
                    error: ClassificationError::AmbiguousObservation,
                },
                HarnessState::Live => Action::NoOp {
                    agent_id: box_.box_record.id.clone(),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(state: BoxState) -> BoxRecord {
        BoxRecord {
            id: "box-1".to_string(),
            state,
            subdomain: Some("buzz-default-agent".to_string()),
            name: None,
            updated_at: Some("v1".to_string()),
        }
    }

    fn verified(state: BoxState, harness: HarnessState, service: ServiceState) -> VerifiedBox {
        VerifiedBox {
            box_record: record(state),
            service,
            harness,
            stop_intent: StopIntent::None,
            launch_intent: Some(Fingerprint::for_test("same")),
            presence: PresenceState::Fresh,
            ownership: OwnershipMarker {
                pubkey: "a".repeat(64),
                managed_by: MANAGED_BY.to_string(),
                binding_version: BINDING_VERSION,
            },
        }
    }

    #[test]
    fn absent_creates() {
        assert_eq!(
            classify(None, &Fingerprint::for_test("same")),
            Action::Create
        );
    }

    #[test]
    fn every_settling_state_observes() {
        for state in [
            BoxState::Init,
            BoxState::Provisioning,
            BoxState::Provisioned,
            BoxState::Cloning,
        ] {
            let observation = verified(state, HarnessState::Unknown, ServiceState::Unknown);
            assert_eq!(
                classify(Some(&observation), &Fingerprint::for_test("same")),
                Action::Observe {
                    box_id: "box-1".to_string()
                }
            );
        }
    }

    #[test]
    fn archived_resumes_and_archiving_awaits() {
        let archived = verified(
            BoxState::Archived,
            HarnessState::Unknown,
            ServiceState::Unknown,
        );
        assert_eq!(
            classify(Some(&archived), &Fingerprint::for_test("same")),
            Action::Resume {
                box_id: "box-1".to_string()
            }
        );
        let archiving = verified(
            BoxState::Archiving,
            HarnessState::Unknown,
            ServiceState::Unknown,
        );
        assert_eq!(
            classify(Some(&archiving), &Fingerprint::for_test("same")),
            Action::AwaitArchived {
                box_id: "box-1".to_string()
            }
        );
    }

    #[test]
    fn error_and_unknown_states_report() {
        for state in [BoxState::Error, BoxState::Unknown("future".to_string())] {
            let observation = verified(state, HarnessState::Unknown, ServiceState::Unknown);
            assert_eq!(
                classify(Some(&observation), &Fingerprint::for_test("same")),
                Action::Report {
                    box_id: "box-1".to_string(),
                    error: ClassificationError::BoxError
                }
            );
        }
    }

    #[test]
    fn live_service_is_strict_noop_for_every_ready_state() {
        for state in [BoxState::Ready, BoxState::Idle, BoxState::Running] {
            let observation = verified(state, HarnessState::Live, ServiceState::Active);
            let mut divergent = observation.clone();
            divergent.launch_intent = Some(Fingerprint::for_test("old"));
            assert_eq!(
                classify(Some(&divergent), &Fingerprint::for_test("new")),
                Action::NoOp {
                    agent_id: "box-1".to_string()
                }
            );
        }
    }

    #[test]
    fn live_harness_is_noop_even_when_service_probe_is_not_active() {
        for service in [
            ServiceState::Inactive,
            ServiceState::Failed,
            ServiceState::Unknown,
        ] {
            let observation = verified(BoxState::Ready, HarnessState::Live, service);
            assert_eq!(
                classify(Some(&observation), &Fingerprint::for_test("new")),
                Action::NoOp {
                    agent_id: "box-1".to_string()
                }
            );
        }
    }

    #[test]
    fn active_service_is_noop_even_when_harness_marker_is_ambiguous() {
        for state in [BoxState::Ready, BoxState::Idle, BoxState::Running] {
            let observation = verified(state, HarnessState::Unknown, ServiceState::Active);
            assert_eq!(
                classify(Some(&observation), &Fingerprint::for_test("new")),
                Action::NoOp {
                    agent_id: "box-1".to_string()
                }
            );
        }
    }

    #[test]
    fn inactive_ready_states_launch_after_intentional_stop() {
        for state in [BoxState::Ready, BoxState::Idle, BoxState::Running] {
            let mut observation = verified(
                state,
                HarnessState::ExitedIntentional,
                ServiceState::Inactive,
            );
            observation.stop_intent = StopIntent::External;
            assert!(matches!(
                classify(Some(&observation), &Fingerprint::for_test("new")),
                Action::Launch {
                    prior_failure: Some(StopIntent::External),
                    ..
                }
            ));
        }
    }

    #[test]
    fn ready_state_matrix_covers_all_inactive_harness_rows() {
        for state in [BoxState::Ready, BoxState::Idle, BoxState::Running] {
            let same = verified(
                state.clone(),
                HarnessState::NeverStartedRecoverable,
                ServiceState::Inactive,
            );
            assert!(matches!(
                classify(Some(&same), &Fingerprint::for_test("same")),
                Action::Observe { .. }
            ));

            let mut divergent = same.clone();
            divergent.launch_intent = Some(Fingerprint::for_test("old"));
            assert!(matches!(
                classify(Some(&divergent), &Fingerprint::for_test("new")),
                Action::FencedReplace { .. }
            ));

            let broken = verified(
                state.clone(),
                HarnessState::NeverStartedBroken,
                ServiceState::Failed,
            );
            assert!(matches!(
                classify(Some(&broken), &Fingerprint::for_test("new")),
                Action::FencedReplace { .. }
            ));

            let abnormal = verified(
                state.clone(),
                HarnessState::ExitedAbnormal,
                ServiceState::Failed,
            );
            assert!(matches!(
                classify(Some(&abnormal), &Fingerprint::for_test("new")),
                Action::Launch { .. }
            ));

            let ambiguous = verified(state, HarnessState::Unknown, ServiceState::Unknown);
            assert!(matches!(
                classify(Some(&ambiguous), &Fingerprint::for_test("new")),
                Action::Report {
                    error: ClassificationError::AmbiguousObservation,
                    ..
                }
            ));
        }
    }

    #[test]
    fn live_service_remains_noop_with_stale_presence() {
        let mut observation = verified(BoxState::Ready, HarnessState::Live, ServiceState::Active);
        observation.presence = PresenceState::Stale;
        assert_eq!(
            classify(Some(&observation), &Fingerprint::for_test("new")),
            Action::NoOp {
                agent_id: "box-1".to_string()
            }
        );
    }

    #[test]
    fn intentional_and_abnormal_stops_launch() {
        let mut intentional = verified(
            BoxState::Ready,
            HarnessState::ExitedIntentional,
            ServiceState::Inactive,
        );
        intentional.stop_intent = StopIntent::External;
        assert!(matches!(
            classify(Some(&intentional), &Fingerprint::for_test("same")),
            Action::Launch {
                prior_failure: Some(StopIntent::External),
                ..
            }
        ));

        let mut abnormal = verified(
            BoxState::Idle,
            HarnessState::ExitedAbnormal,
            ServiceState::Failed,
        );
        abnormal.stop_intent = StopIntent::Abnormal;
        assert!(matches!(
            classify(Some(&abnormal), &Fingerprint::for_test("same")),
            Action::Launch {
                prior_failure: Some(StopIntent::Abnormal),
                ..
            }
        ));
    }

    #[test]
    fn never_started_same_intent_observes_without_age_recycling() {
        let observation = verified(
            BoxState::Ready,
            HarnessState::NeverStartedRecoverable,
            ServiceState::Inactive,
        );
        assert_eq!(
            classify(Some(&observation), &Fingerprint::for_test("same")),
            Action::Observe {
                box_id: "box-1".to_string()
            }
        );
    }

    #[test]
    fn never_started_divergence_and_broken_state_are_fenced() {
        for harness in [
            HarnessState::NeverStartedRecoverable,
            HarnessState::NeverStartedBroken,
        ] {
            let mut observation = verified(BoxState::Ready, harness, ServiceState::Inactive);
            if harness == HarnessState::NeverStartedRecoverable {
                observation.launch_intent = Some(Fingerprint::for_test("old"));
            }
            let action = classify(Some(&observation), &Fingerprint::for_test("new"));
            match action {
                Action::FencedReplace {
                    observation: snapshot,
                    ..
                } => {
                    assert_eq!(snapshot.box_record.updated_at, Some("v1".to_string()));
                }
                other => panic!("expected fenced replace, got {other:?}"),
            }
        }
    }

    #[test]
    fn ambiguous_inactive_observation_reports() {
        let observation = verified(
            BoxState::Ready,
            HarnessState::Unknown,
            ServiceState::Unknown,
        );
        assert_eq!(
            classify(Some(&observation), &Fingerprint::for_test("same")),
            Action::Report {
                box_id: "box-1".to_string(),
                error: ClassificationError::AmbiguousObservation
            }
        );
    }
}
