//! Trusted observation of Box lifecycle and in-Box harness state.
//!
//! A Box record is not enough to classify: `idle` and `running` describe only
//! first-class Box prompts, not arbitrary processes. This module reads the
//! provider-owned marker and fixed service state through the Box file/command
//! APIs. Unverified Boxes return `None` and cannot reach [`crate::classify`].

use crate::api::{BoxApi, BoxApiError, BoxRecord, CommandRequest};
use crate::classify::{
    Fingerprint, HarnessState, OwnershipMarker, PresenceState, ServiceState, StopIntent,
    BINDING_VERSION, MANAGED_BY,
};
use crate::naming::AgentIdentity;
use serde::Deserialize;
use thiserror::Error;

/// Root-owned marker describing provider ownership.
pub const OWNERSHIP_MARKER_PATH: &str = "/var/lib/buzz-agent/ownership.json";
/// Non-secret state written by the launcher.
pub const STATE_MARKER_PATH: &str = "/var/lib/buzz-agent/state.json";
/// Stop-intent marker consulted after resume.
pub const STOP_INTENT_PATH: &str = "/var/lib/buzz-agent/stop-intent";
/// Non-secret launch-intent fingerprint.
pub const LAUNCH_INTENT_PATH: &str = "/var/lib/buzz-agent/launch-intent.sha256";
/// Fixed systemd unit supervised by the provider.
pub const SERVICE_UNIT: &str = "buzz-agent.service";

/// Observation failures with raw Box output excluded from the error surface.
#[derive(Debug, Error)]
pub enum ObserveError {
    /// The Box API could not be queried.
    #[error("Box observation API call failed: {0}")]
    Api(#[from] BoxApiError),
    /// A marker existed but could not be decoded into the provider contract.
    #[error("Box ownership or state marker was malformed")]
    MalformedMarker,
    /// The service command returned an unusable state.
    #[error("Box service state was ambiguous")]
    AmbiguousService,
}

#[derive(Debug, Default, Deserialize)]
struct RawOwnershipMarker {
    #[serde(default)]
    pubkey: Option<String>,
    #[serde(default, alias = "agent_pubkey")]
    agent_pubkey: Option<String>,
    #[serde(default, alias = "managedBy")]
    managed_by: Option<String>,
    #[serde(default, alias = "bindingVersion")]
    binding_version: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct RawStateMarker {
    #[serde(default)]
    started: bool,
    #[serde(default)]
    startup: Option<String>,
    #[serde(default, alias = "stopIntent")]
    stop_intent: Option<String>,
}

/// Verify the full ownership marker against the derived identity.
pub fn verify_ownership_marker(marker: &str, identity: &AgentIdentity) -> Option<OwnershipMarker> {
    let marker: RawOwnershipMarker = serde_json::from_str(marker).ok()?;
    let pubkey = marker.pubkey.or(marker.agent_pubkey)?;
    let managed_by = marker.managed_by?;
    let binding_version = marker.binding_version?;
    if pubkey != identity.pubkey_hex()
        || managed_by != MANAGED_BY
        || binding_version != BINDING_VERSION
    {
        return None;
    }
    Some(OwnershipMarker {
        pubkey,
        managed_by,
        binding_version,
    })
}

/// Gather and verify one Box observation.
///
/// `Ok(None)` is the explicit unverified result. Callers must not turn it into
/// an absent/verified observation and must not classify or mutate that Box.
pub async fn observe_box(
    api: &BoxApi,
    box_record: BoxRecord,
    identity: &AgentIdentity,
) -> Result<Option<crate::classify::VerifiedBox>, ObserveError> {
    let Some(ownership_text) =
        read_optional_file(api, &box_record.id, OWNERSHIP_MARKER_PATH).await?
    else {
        return Ok(None);
    };
    let Some(ownership) = verify_ownership_marker(&ownership_text, identity) else {
        return Ok(None);
    };

    let service = observe_service(api, &box_record.id).await?;
    let state_marker = read_optional_file(api, &box_record.id, STATE_MARKER_PATH).await?;
    let stop_marker = read_optional_file(api, &box_record.id, STOP_INTENT_PATH).await?;
    let launch_intent = read_optional_file(api, &box_record.id, LAUNCH_INTENT_PATH)
        .await?
        .map(|value| Fingerprint::from_recorded(value.trim().to_string()));
    let (harness, stop_intent) =
        decode_harness(service, state_marker.as_deref(), stop_marker.as_deref());

    Ok(Some(crate::classify::VerifiedBox {
        box_record,
        service,
        harness,
        stop_intent,
        launch_intent,
        presence: PresenceState::Unknown,
        ownership,
    }))
}

async fn observe_service(api: &BoxApi, box_id: &str) -> Result<ServiceState, ObserveError> {
    let result = api
        .execute(
            box_id,
            &CommandRequest {
                command: format!("systemctl is-active {SERVICE_UNIT}"),
                cwd: None,
                timeout_seconds: Some(10),
            },
        )
        .await?;
    let state = result.stdout.trim();
    Ok(match state {
        "active" => ServiceState::Active,
        "inactive" | "deactivating" => ServiceState::Inactive,
        "failed" => ServiceState::Failed,
        "unknown" | "" => ServiceState::Unknown,
        _ => ServiceState::Unknown,
    })
}

fn decode_harness(
    service: ServiceState,
    state_marker: Option<&str>,
    stop_marker: Option<&str>,
) -> (HarnessState, StopIntent) {
    if service == ServiceState::Active {
        return (HarnessState::Live, StopIntent::None);
    }

    let stop_intent = stop_marker
        .and_then(parse_stop_intent)
        .or_else(|| {
            state_marker
                .and_then(|value| serde_json::from_str::<RawStateMarker>(value).ok())
                .and_then(|marker| marker.stop_intent.as_deref().and_then(parse_stop_intent))
        })
        .unwrap_or(StopIntent::None);

    if stop_intent == StopIntent::External {
        return (HarnessState::ExitedIntentional, stop_intent);
    }
    if matches!(stop_intent, StopIntent::Abnormal | StopIntent::SelfStop) {
        return (HarnessState::ExitedAbnormal, stop_intent);
    }

    let Some(state_marker) = state_marker else {
        return (HarnessState::NeverStartedRecoverable, stop_intent);
    };
    let Ok(marker) = serde_json::from_str::<RawStateMarker>(state_marker) else {
        return (HarnessState::Unknown, StopIntent::Unknown);
    };
    if marker.started {
        return (HarnessState::ExitedAbnormal, stop_intent);
    }
    if marker.startup.as_deref() == Some("broken") {
        return (HarnessState::NeverStartedBroken, stop_intent);
    }
    (HarnessState::NeverStartedRecoverable, stop_intent)
}

fn parse_stop_intent(value: &str) -> Option<StopIntent> {
    match value.trim().to_ascii_lowercase().as_str() {
        "external" | "intentional" => Some(StopIntent::External),
        "self" | "self-stop" => Some(StopIntent::SelfStop),
        "abnormal" | "failure" => Some(StopIntent::Abnormal),
        _ => None,
    }
}

async fn read_optional_file(
    api: &BoxApi,
    box_id: &str,
    path: &str,
) -> Result<Option<String>, ObserveError> {
    match api.read_file(box_id, path, Some("utf8")).await {
        Ok(file) => Ok(Some(file.content)),
        Err(BoxApiError::Http { status: 404, .. }) => Ok(None),
        Err(error) => Err(ObserveError::Api(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::nips::nip19::ToBech32;

    fn identity() -> AgentIdentity {
        let keys = nostr::Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("key should encode");
        AgentIdentity::from_nsec(&nsec).expect("generated key should decode")
    }

    #[test]
    fn ownership_requires_full_pubkey_marker_and_binding() {
        let identity = identity();
        let good = serde_json::json!({
            "agent_pubkey": identity.pubkey_hex(),
            "managedBy": MANAGED_BY,
            "bindingVersion": BINDING_VERSION
        });
        assert!(verify_ownership_marker(&good.to_string(), &identity).is_some());

        for bad in [
            serde_json::json!({"agent_pubkey":"short","managedBy":MANAGED_BY,"bindingVersion":BINDING_VERSION}),
            serde_json::json!({"agent_pubkey":identity.pubkey_hex(),"managedBy":"other","bindingVersion":BINDING_VERSION}),
            serde_json::json!({"agent_pubkey":identity.pubkey_hex(),"managedBy":MANAGED_BY,"bindingVersion":99}),
        ] {
            assert!(verify_ownership_marker(&bad.to_string(), &identity).is_none());
        }
    }

    #[test]
    fn service_activity_wins_and_marker_values_decode() {
        let (harness, intent) = decode_harness(ServiceState::Active, None, Some("external"));
        assert_eq!(harness, HarnessState::Live);
        assert_eq!(intent, StopIntent::None);

        let (harness, intent) = decode_harness(
            ServiceState::Inactive,
            Some(r#"{"started":false,"startup":"broken"}"#),
            None,
        );
        assert_eq!(harness, HarnessState::NeverStartedBroken);
        assert_eq!(intent, StopIntent::None);

        let (harness, intent) = decode_harness(ServiceState::Inactive, None, Some("external"));
        assert_eq!(harness, HarnessState::ExitedIntentional);
        assert_eq!(intent, StopIntent::External);
    }
}
