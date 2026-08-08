//! Ordered Box deployment reconciliation.
//!
//! The loop follows the provider contract: derive identity and prepare the
//! environment before network I/O, resolve ambient credentials, locate by the
//! deterministic subdomain, verify ownership, classify, act, and re-observe.
//! Secret installation remains behind [`Provisioner`] for Task C.

use crate::api::{
    resolve_ambient_credential, BoxApi, BoxApiError, BoxRecord, BoxState, CreateBoxRequest,
    ResumeBoxRequest, UpdateBoxRequest,
};
use crate::classify::{classify, Action, ClassificationError, Fingerprint, HarnessState};
use crate::config::{self, ProviderConfig};
use crate::naming::AgentIdentity;
use crate::observe::{observe_box, ObserveError};
use crate::redact::Redactor;
use crate::wire::{AgentPayload, DeployRequest};
use serde_json::Map;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// The reconciliation operation deadline required by the provider contract.
pub const OPERATION_DEADLINE: Duration = Duration::from_secs(600);
/// Poll interval required by the provider contract.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

const AUTHORITATIVE_ENV_KEYS: &[&str] = &[
    "BUZZ_RELAY_URL",
    "BUZZ_PRIVATE_KEY",
    "NOSTR_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
    "BUZZ_ACP_AGENT_OWNER",
    "BUZZ_OWNER_PUBKEY",
    "BUZZ_ACP_AGENT_COMMAND",
    "BUZZ_AGENT_COMMAND",
    "BUZZ_ACP_AGENT_ARGS",
    "BUZZ_AGENT_ARGS",
    "BUZZ_ACP_MCP_COMMAND",
    "BUZZ_ACP_RESPOND_TO",
    "BUZZ_ACP_RESPOND_TO_ALLOWLIST",
    "BUZZ_ACP_EXIT_AFTER_INACTIVITY",
    "BUZZ_INACTIVITY_SECONDS",
    "BUZZ_AGENT_PUBKEY",
    "BUZZ_MANAGED_AGENT_START_NONCE",
];
const FORBIDDEN_ENV_KEY: &str = "BUZZ_ACP_NO_PRESENCE";

fn is_posix_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(character) if character == '_' || character.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn nonempty_trimmed(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

/// Prepared, non-network deployment context.
#[derive(Clone, Debug)]
pub struct PreparedDeploy {
    /// Derived Nostr identity.
    pub identity: AgentIdentity,
    /// Validated provider configuration.
    pub config: ProviderConfig,
    /// Full launch environment for the future Task C provisioner.
    pub env: BTreeMap<String, String>,
    /// Provider-local redaction set.
    pub redactor: Redactor,
    /// Non-secret launch-intent fingerprint.
    pub launch_intent: Fingerprint,
    /// Deterministic Box subdomain.
    pub subdomain: String,
}

/// Prepare identity, environment, redaction, and non-secret intent without
/// reading or mutating the Box API.
pub fn prepare_deploy(request: &DeployRequest) -> Result<PreparedDeploy, ReconcileError> {
    let identity = AgentIdentity::from_nsec(&request.agent.private_key_nsec)
        .map_err(ReconcileError::InvalidRequest)?;
    let config = config::parse(&request.provider_config).map_err(ReconcileError::InvalidRequest)?;
    let mut env = build_environment(&request.agent, &config)?;
    env.insert(
        "BUZZ_MANAGED_AGENT_START_NONCE".to_string(),
        launch_nonce(identity.pubkey_hex()),
    );
    let mut redaction_values = request.agent.env_vars.values().cloned().collect::<Vec<_>>();
    if let Some(launch) = &request.agent.launch {
        redaction_values.extend(launch.env.values().cloned());
        redaction_values.extend(launch.policy_env.values().cloned());
    }
    redaction_values.extend(env.values().cloned());
    redaction_values.push(request.agent.private_key_nsec.clone());
    if let Some(auth_tag) = &request.agent.auth_tag {
        redaction_values.push(auth_tag.clone());
    }
    redaction_values.push(request.agent.relay_url.clone());
    let redactor = Redactor::from_values(redaction_values);
    let launch_intent = build_launch_intent(&identity, &config, env.keys().cloned())?;
    let subdomain = identity.subdomain(&config.scope);
    Ok(PreparedDeploy {
        identity,
        config,
        env,
        redactor,
        launch_intent,
        subdomain,
    })
}

fn launch_nonce(pubkey: &str) -> String {
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos().to_string(),
        Err(_) => "0".to_string(),
    };
    let mut input = String::with_capacity(pubkey.len() + timestamp.len() + 24);
    input.push_str(pubkey);
    input.push(':');
    input.push_str(&timestamp);
    input.push(':');
    input.push_str(&std::process::id().to_string());
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn build_environment(
    agent: &AgentPayload,
    config: &ProviderConfig,
) -> Result<BTreeMap<String, String>, ReconcileError> {
    let mut env = BTreeMap::new();
    if let Some(launch) = &agent.launch {
        env.extend(launch.policy_env.clone());
        env.extend(launch.env.clone());
    } else {
        env.extend(agent.env_vars.clone());
    }

    // Validate lower tiers before clearing authoritative keys. This keeps the
    // provider deterministic across Box images and rejects the only forbidden
    // liveness override instead of allowing it to be masked accidentally.
    for key in env.keys() {
        if !is_posix_env_key(key) {
            return Err(ReconcileError::InvalidRequest(format!(
                "env key {key:?} is not a POSIX environment variable name \
                 ([A-Za-z_][A-Za-z0-9_]*)"
            )));
        }
        if key.eq_ignore_ascii_case(FORBIDDEN_ENV_KEY) {
            return Err(ReconcileError::InvalidRequest(format!(
                "{FORBIDDEN_ENV_KEY} must not be set: presence is the only \
                 remote liveness signal"
            )));
        }
    }

    // A missing authoritative value must clear a lower-tier spoof. Plain
    // overwrite is insufficient for optional auth, command, and policy keys.
    for key in AUTHORITATIVE_ENV_KEYS {
        env.remove(*key);
    }

    let Some(relay_url) = nonempty_trimmed(&agent.relay_url) else {
        return Err(ReconcileError::InvalidRequest(
            "relay_url must not be empty".to_string(),
        ));
    };
    env.insert("BUZZ_RELAY_URL".to_string(), relay_url.to_string());
    env.insert(
        "BUZZ_PRIVATE_KEY".to_string(),
        agent.private_key_nsec.clone(),
    );
    env.insert(
        "NOSTR_PRIVATE_KEY".to_string(),
        agent.private_key_nsec.clone(),
    );

    let auth_tag = agent.auth_tag.as_deref().and_then(nonempty_trimmed);
    let owner = agent
        .launch
        .as_ref()
        .and_then(|launch| launch.owner_pubkey.as_deref())
        .and_then(nonempty_trimmed);
    if auth_tag.is_none() && owner.is_none() {
        return Err(ReconcileError::InvalidRequest(
            "neither auth_tag nor launch.owner_pubkey resolved: the agent \
             could not honor !shutdown"
                .to_string(),
        ));
    }
    if let Some(auth_tag) = auth_tag {
        env.insert("BUZZ_AUTH_TAG".to_string(), auth_tag.to_string());
    }
    if let Some(owner) = owner {
        env.insert("BUZZ_ACP_AGENT_OWNER".to_string(), owner.to_string());
    }

    if let Some(launch) = &agent.launch {
        if let Some(command) = launch.command.as_deref().filter(|value| !value.is_empty()) {
            env.insert("BUZZ_ACP_AGENT_COMMAND".to_string(), command.to_string());
        }
        if !launch.args.is_empty() {
            env.insert("BUZZ_ACP_AGENT_ARGS".to_string(), launch.args.join(","));
        }
    }
    env.insert(
        "BUZZ_ACP_MCP_COMMAND".to_string(),
        "buzz-dev-mcp".to_string(),
    );
    if let Some(respond_to) = agent
        .respond_to
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        if !matches!(respond_to, "owner-only" | "allowlist" | "anyone" | "nobody") {
            return Err(ReconcileError::InvalidRequest(format!(
                "respond_to {respond_to:?} is not a supported harness mode"
            )));
        }
        if respond_to == "allowlist"
            && agent
                .respond_to_allowlist
                .as_ref()
                .is_none_or(Vec::is_empty)
        {
            return Err(ReconcileError::InvalidRequest(
                "respond_to allowlist requires at least one pubkey".to_string(),
            ));
        }
        env.insert("BUZZ_ACP_RESPOND_TO".to_string(), respond_to.to_string());
    }
    if let Some(allowlist) = agent
        .respond_to_allowlist
        .as_ref()
        .filter(|entries| !entries.is_empty())
    {
        env.insert(
            "BUZZ_ACP_RESPOND_TO_ALLOWLIST".to_string(),
            allowlist.join(","),
        );
    }
    env.insert(
        "BUZZ_ACP_EXIT_AFTER_INACTIVITY".to_string(),
        config.inactivity_seconds.to_string(),
    );
    Ok(env)
}

fn build_launch_intent(
    identity: &AgentIdentity,
    config: &ProviderConfig,
    keys: impl IntoIterator<Item = String>,
) -> Result<Fingerprint, ReconcileError> {
    let mut env_keys: Vec<String> = keys.into_iter().collect();
    env_keys.sort();
    let value = serde_json::json!({
        "schema": 1,
        "agent_pubkey": identity.pubkey_hex(),
        "box_machine_type": config.machine_type.as_str(),
        "disk_mode": config.workspace_mode.as_str(),
        "image_digest": config.image.as_str(),
        "service_unit_version": 1,
        "restart_policy": "no",
        "termination_timeout_seconds": 120,
        "env_keys": env_keys,
        "workspace_mode": config.workspace_mode.as_str()
    });
    let bytes = serde_json::to_vec(&value).map_err(|_| {
        ReconcileError::InvalidRequest("launch intent is not serializable".to_string())
    })?;
    Ok(Fingerprint::from_canonical_bytes(&bytes))
}

/// Typed error returned by the Box provisioner.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProvisionError {
    /// A bounded, already-redacted provisioning failure.
    #[error("Box provisioning failed: {0}")]
    Failed(String),
}

/// Inputs supplied to a provisioner after ownership has been claimed.
pub struct ProvisionRequest<'a> {
    /// Authenticated Box client for commands, files, and marker reads.
    pub api: &'a BoxApi,
    /// Claimed Box record.
    pub box_record: &'a BoxRecord,
    /// Prepared deployment context, including secrets held only in memory.
    pub prepared: &'a PreparedDeploy,
    /// Absolute reconciliation deadline shared with the caller.
    pub deadline: Instant,
    /// Poll interval selected by the reconciliation caller.
    pub poll_interval: Duration,
}

/// The seam for Task C secret injection, service installation, and launch.
#[allow(async_fn_in_trait)]
pub trait Provisioner {
    /// Provision and start the fixed service inside a verified claimed Box.
    async fn provision(&self, request: ProvisionRequest<'_>) -> Result<(), ProvisionError>;
}

/// Reconciliation timing overrides, with production defaults of 600 seconds
/// and 2 seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileOptions {
    /// Overall operation deadline.
    pub deadline: Duration,
    /// Poll interval between read-only observations.
    pub poll_interval: Duration,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self {
            deadline: OPERATION_DEADLINE,
            poll_interval: POLL_INTERVAL,
        }
    }
}

/// Errors returned by the ordered reconciliation loop.
#[derive(Debug, Error)]
pub enum ReconcileError {
    /// Input validation or identity derivation failed before network I/O.
    #[error("invalid Box deploy request: {0}")]
    InvalidRequest(String),
    /// Ambient credentials were absent or unusable.
    #[error("Box credentials unavailable: {0}")]
    Credentials(#[source] BoxApiError),
    /// Box API operation failed after redaction.
    #[error("Box API operation failed: {0}")]
    Api(String),
    /// Observation failed after redaction.
    #[error("Box observation failed: {0}")]
    Observation(String),
    /// A deterministic-name Box existed but did not prove ownership.
    #[error("deterministic Box exists but failed ownership verification")]
    UnverifiedBox,
    /// The operation reached its deadline without a confirmed started service.
    #[error("Box deploy timed out while observing {box_id}: {state}")]
    Timeout { box_id: String, state: String },
    /// Classification returned a safe immediate report.
    #[error("Box deploy reported {box_id}: {reason}")]
    Report {
        box_id: String,
        reason: &'static str,
    },
    /// Provisioning is intentionally deferred to Task C.
    #[error("{0}")]
    Provision(#[from] ProvisionError),
}

/// Deploy using ambient credentials and an optional test endpoint override.
pub async fn deploy(
    request: &DeployRequest,
    provisioner: &impl Provisioner,
) -> Result<String, ReconcileError> {
    let prepared = prepare_deploy(request)?;
    let credential = resolve_ambient_credential().map_err(ReconcileError::Credentials)?;
    let base_url = std::env::var("BOX_API_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| crate::api::DEFAULT_BASE_URL.to_string());
    let api = BoxApi::with_base_url(base_url, credential, crate::api::DEFAULT_REQUEST_TIMEOUT)
        .map_err(ReconcileError::Credentials)?;
    reconcile(&api, &prepared, provisioner, ReconcileOptions::default()).await
}

/// Run reconciliation with a caller-supplied client, useful for fake-server
/// tests and embedders that manage credential resolution themselves.
pub async fn reconcile(
    api: &BoxApi,
    prepared: &PreparedDeploy,
    provisioner: &impl Provisioner,
    options: ReconcileOptions,
) -> Result<String, ReconcileError> {
    let started = Instant::now();
    let mut last_state = "absent".to_string();
    loop {
        if started.elapsed() >= options.deadline {
            return Err(ReconcileError::Timeout {
                box_id: last_state.clone(),
                state: prepared.redactor.redact(&last_state),
            });
        }

        let records = api
            .list_all(None)
            .await
            .map_err(|error| api_error(api, prepared, error))?;
        let record = records
            .into_iter()
            .find(|record| record.subdomain.as_deref() == Some(prepared.subdomain.as_str()));

        let observed = match record {
            None => None,
            Some(record) => {
                last_state = record.state.as_str().to_string();
                let id = record.id.clone();
                match observe_box(api, record, &prepared.identity)
                    .await
                    .map_err(|error| observe_error(api, prepared, error))?
                {
                    Some(observed) => Some(observed),
                    None => {
                        let _ = id;
                        return Err(ReconcileError::UnverifiedBox);
                    }
                }
            }
        };

        if let Some(observed) = &observed {
            last_state = observed.box_record.state.as_str().to_string();
        }
        let action = classify(observed.as_ref(), &prepared.launch_intent);
        match action {
            Action::Create => {
                let candidate = create_candidate(api, prepared).await?;
                let ready = wait_for_ready(api, &candidate.id, prepared, options, started).await?;
                match claim_candidate(api, &ready, prepared, options, started).await? {
                    ClaimOutcome::Claimed(claimed) => {
                        // The candidate is now claimed, but no secrets have
                        // crossed the API boundary. Task C owns this seam.
                        provisioner
                            .provision(ProvisionRequest {
                                api,
                                box_record: &claimed,
                                prepared,
                                deadline: started + options.deadline,
                                poll_interval: options.poll_interval,
                            })
                            .await?;
                        return reobserve_until_started(
                            api,
                            prepared,
                            provisioner,
                            &claimed.id,
                            options,
                            started,
                        )
                        .await;
                    }
                    ClaimOutcome::Lost => {
                        stop_candidate(api, &ready.id, prepared, options, started).await?;
                        return await_claim_winner(api, prepared, options, started).await;
                    }
                }
            }
            Action::Observe { box_id } => {
                last_state = box_id;
                sleep_until_next(options.poll_interval).await;
            }
            Action::NoOp { agent_id } => return Ok(agent_id),
            Action::Resume { box_id } => {
                let resumed = api
                    .resume(
                        &box_id,
                        &ResumeBoxRequest {
                            machine_type: Some(prepared.config.machine_type.as_str().to_string()),
                            no_env: Some(true),
                        },
                    )
                    .await
                    .map_err(|error| api_error(api, prepared, error))?;
                let ready = wait_for_ready(api, &resumed.id, prepared, options, started).await?;
                provisioner
                    .provision(ProvisionRequest {
                        api,
                        box_record: &ready,
                        prepared,
                        deadline: started + options.deadline,
                        poll_interval: options.poll_interval,
                    })
                    .await?;
                return reobserve_until_started(
                    api,
                    prepared,
                    provisioner,
                    &ready.id,
                    options,
                    started,
                )
                .await;
            }
            Action::AwaitArchived { box_id } => {
                wait_for_archived(api, &box_id, prepared, options, started).await?;
            }
            Action::Launch { box_id, .. } => {
                let record = api
                    .get(&box_id)
                    .await
                    .map_err(|error| api_error(api, prepared, error))?;
                provisioner
                    .provision(ProvisionRequest {
                        api,
                        box_record: &record,
                        prepared,
                        deadline: started + options.deadline,
                        poll_interval: options.poll_interval,
                    })
                    .await?;
                return reobserve_until_started(
                    api,
                    prepared,
                    provisioner,
                    &box_id,
                    options,
                    started,
                )
                .await;
            }
            Action::FencedReplace {
                box_id,
                observation,
            } => {
                // A Box created by this call is never re-entered through this
                // action: successful claim immediately enters the provisioner
                // seam, and claim loss exits to winner adoption.
                let current = match observe_for_fence(api, &box_id, prepared).await? {
                    Some(current) => current,
                    None => continue,
                };
                if !same_observation_fence(&current, &observation) {
                    continue;
                }
                stop_candidate(api, &box_id, prepared, options, started).await?;
            }
            Action::Report { box_id, error } => {
                let reason = match error {
                    ClassificationError::BoxError => "Box is in an API error state",
                    ClassificationError::AmbiguousObservation => "service observation is ambiguous",
                };
                return Err(ReconcileError::Report { box_id, reason });
            }
        }
    }
}

async fn create_candidate(
    api: &BoxApi,
    prepared: &PreparedDeploy,
) -> Result<BoxRecord, ReconcileError> {
    api.create(&CreateBoxRequest {
        no_env: true,
        ttl_seconds: None,
        machine_type: prepared.config.machine_type.as_str().to_string(),
        env: Map::new(),
    })
    .await
    .map_err(|error| api_error(api, prepared, error))
}

enum ClaimOutcome {
    Claimed(BoxRecord),
    Lost,
}

async fn claim_candidate(
    api: &BoxApi,
    ready: &BoxRecord,
    prepared: &PreparedDeploy,
    options: ReconcileOptions,
    started: Instant,
) -> Result<ClaimOutcome, ReconcileError> {
    let request = UpdateBoxRequest {
        subdomain: prepared.subdomain.clone(),
    };
    loop {
        check_deadline(
            started,
            options,
            &ready.id,
            "claiming deterministic subdomain",
        )?;
        match api.update(&ready.id, &request).await {
            Ok(claimed) => return Ok(ClaimOutcome::Claimed(claimed)),
            Err(error) if is_gateway_retry(&error) || is_rate_limited(&error) => {
                sleep_until_next(retry_delay(&error, options.poll_interval)).await;
            }
            Err(error) if is_claim_loss(&error) => return Ok(ClaimOutcome::Lost),
            Err(error) if is_unknown_claim_4xx(&error) => {
                let holder = api
                    .list_all(None)
                    .await
                    .map_err(|verify_error| api_error(api, prepared, verify_error))?
                    .into_iter()
                    .find(|record| {
                        record.subdomain.as_deref() == Some(prepared.subdomain.as_str())
                    });
                return Ok(match holder {
                    Some(record) if record.id == ready.id => ClaimOutcome::Claimed(record),
                    Some(_) | None => ClaimOutcome::Lost,
                });
            }
            Err(error) => return Err(api_error(api, prepared, error)),
        }
    }
}

async fn wait_for_ready(
    api: &BoxApi,
    box_id: &str,
    prepared: &PreparedDeploy,
    options: ReconcileOptions,
    started: Instant,
) -> Result<BoxRecord, ReconcileError> {
    loop {
        check_deadline(started, options, box_id, "waiting for Box readiness")?;
        let record = api
            .get(box_id)
            .await
            .map_err(|error| api_error(api, prepared, error))?;
        if record.state.is_ready() {
            return Ok(record);
        }
        match &record.state {
            BoxState::Error | BoxState::Unknown(_) => {
                return Err(ReconcileError::Report {
                    box_id: box_id.to_string(),
                    reason: "Box did not reach a usable state",
                });
            }
            _ => sleep_until_next(options.poll_interval).await,
        }
    }
}

async fn stop_candidate(
    api: &BoxApi,
    box_id: &str,
    prepared: &PreparedDeploy,
    options: ReconcileOptions,
    started: Instant,
) -> Result<(), ReconcileError> {
    match api.stop(box_id).await {
        Ok(_) | Err(BoxApiError::Http { status: 404, .. }) => {}
        Err(error) => return Err(api_error(api, prepared, error)),
    }
    wait_for_archived(api, box_id, prepared, options, started).await
}

async fn wait_for_archived(
    api: &BoxApi,
    box_id: &str,
    prepared: &PreparedDeploy,
    options: ReconcileOptions,
    started: Instant,
) -> Result<(), ReconcileError> {
    loop {
        check_deadline(started, options, box_id, "waiting for Box archive")?;
        let record = match api.get(box_id).await {
            Ok(record) => record,
            Err(BoxApiError::Http { status: 404, .. }) => return Ok(()),
            Err(error) => return Err(api_error(api, prepared, error)),
        };
        match record.state {
            BoxState::Archived => return Ok(()),
            BoxState::Error | BoxState::Unknown(_) => {
                return Err(ReconcileError::Report {
                    box_id: box_id.to_string(),
                    reason: "Box archive entered an error state",
                });
            }
            _ => sleep_until_next(options.poll_interval).await,
        }
    }
}

async fn await_claim_winner(
    api: &BoxApi,
    prepared: &PreparedDeploy,
    options: ReconcileOptions,
    started: Instant,
) -> Result<String, ReconcileError> {
    loop {
        check_deadline(started, options, "claim-winner", "waiting for claim winner")?;
        let records = api
            .list_all(None)
            .await
            .map_err(|error| api_error(api, prepared, error))?;
        if let Some(record) = records
            .into_iter()
            .find(|record| record.subdomain.as_deref() == Some(prepared.subdomain.as_str()))
        {
            let id = record.id.clone();
            let observed = observe_box(api, record, &prepared.identity)
                .await
                .map_err(|error| observe_error(api, prepared, error))?;
            let Some(observed) = observed else {
                return Err(ReconcileError::UnverifiedBox);
            };
            if observed.service == crate::classify::ServiceState::Active
                || observed.harness == HarnessState::Live
            {
                return Ok(id);
            }
        }
        sleep_until_next(options.poll_interval).await;
    }
}

async fn reobserve_until_started(
    api: &BoxApi,
    prepared: &PreparedDeploy,
    _provisioner: &impl Provisioner,
    box_id: &str,
    options: ReconcileOptions,
    started: Instant,
) -> Result<String, ReconcileError> {
    loop {
        check_deadline(started, options, box_id, "waiting for service start")?;
        let record = api
            .get(box_id)
            .await
            .map_err(|error| api_error(api, prepared, error))?;
        let observed = observe_box(api, record, &prepared.identity)
            .await
            .map_err(|error| observe_error(api, prepared, error))?;
        let Some(observed) = observed else {
            return Err(ReconcileError::UnverifiedBox);
        };
        if observed.service == crate::classify::ServiceState::Active
            || observed.harness == HarnessState::Live
        {
            return Ok(box_id.to_string());
        }
        sleep_until_next(options.poll_interval).await;
    }
}

fn same_fence(current: &BoxRecord, observed: &BoxRecord) -> bool {
    current.id == observed.id
        && current.state == observed.state
        && current.subdomain == observed.subdomain
        && current.name == observed.name
        && current.updated_at == observed.updated_at
}

async fn observe_for_fence(
    api: &BoxApi,
    box_id: &str,
    prepared: &PreparedDeploy,
) -> Result<Option<crate::classify::VerifiedBox>, ReconcileError> {
    let record = match api.get(box_id).await {
        Ok(record) => record,
        Err(BoxApiError::Http { status: 404, .. }) => return Ok(None),
        Err(error) => return Err(api_error(api, prepared, error)),
    };
    observe_box(api, record, &prepared.identity)
        .await
        .map_err(|error| observe_error(api, prepared, error))
}

fn same_observation_fence(
    current: &crate::classify::VerifiedBox,
    observed: &crate::classify::VerifiedBox,
) -> bool {
    same_fence(&current.box_record, &observed.box_record)
        && current.service == observed.service
        && current.harness == observed.harness
        && current.stop_intent == observed.stop_intent
        && current.launch_intent == observed.launch_intent
        && current.ownership == observed.ownership
}

fn is_gateway_retry(error: &BoxApiError) -> bool {
    matches!(
        error,
        BoxApiError::Http {
            status: 502,
            code,
            ..
        } if code == "gateway_error"
    )
}

fn is_rate_limited(error: &BoxApiError) -> bool {
    matches!(error, BoxApiError::RateLimited { .. })
        || matches!(error, BoxApiError::Http { status: 429, .. })
}

fn retry_delay(error: &BoxApiError, poll_interval: Duration) -> Duration {
    let retry_after = match error {
        BoxApiError::RateLimited {
            retry_after_seconds,
            ..
        } => retry_after_seconds.map(Duration::from_secs),
        _ => None,
    };
    retry_after.unwrap_or(poll_interval).max(poll_interval)
}

fn is_claim_loss(error: &BoxApiError) -> bool {
    match error {
        BoxApiError::Http { status: 409, .. } => true,
        BoxApiError::Http {
            status: 400, code, ..
        } => {
            let code = code.to_ascii_lowercase();
            code.contains("conflict")
                || code.contains("already_exists")
                || code.contains("already-taken")
                || code.contains("duplicate")
        }
        _ => false,
    }
}

fn is_unknown_claim_4xx(error: &BoxApiError) -> bool {
    matches!(error, BoxApiError::Http { status, .. } if (400..500).contains(status) && *status != 401 && *status != 402)
}

fn check_deadline(
    started: Instant,
    options: ReconcileOptions,
    box_id: &str,
    state: &str,
) -> Result<(), ReconcileError> {
    if started.elapsed() >= options.deadline {
        return Err(ReconcileError::Timeout {
            box_id: box_id.to_string(),
            state: state.to_string(),
        });
    }
    Ok(())
}

async fn sleep_until_next(duration: Duration) {
    tokio::time::sleep(duration).await;
}

fn api_error(api: &BoxApi, prepared: &PreparedDeploy, error: BoxApiError) -> ReconcileError {
    let redactor = prepared
        .redactor
        .clone()
        .with_value(api.credential_for_redaction().to_string());
    ReconcileError::Api(redactor.redact(&error.to_string()))
}

fn observe_error(api: &BoxApi, prepared: &PreparedDeploy, error: ObserveError) -> ReconcileError {
    let redactor = prepared
        .redactor
        .clone()
        .with_value(api.credential_for_redaction().to_string());
    ReconcileError::Observation(redactor.redact(&error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::AgentPayload;
    use nostr::nips::nip19::ToBech32;
    use serde_json::Value;

    fn request() -> DeployRequest {
        let keys = nostr::Keys::generate();
        let private_key_nsec = keys.secret_key().to_bech32().expect("key should encode");
        DeployRequest {
            agent: AgentPayload {
                relay_url: "wss://relay.example".to_string(),
                private_key_nsec,
                auth_tag: Some("auth-secret".to_string()),
                respond_to: None,
                respond_to_allowlist: None,
                env_vars: BTreeMap::from([(String::from("MODEL_KEY"), String::from("secret"))]),
                launch: None,
            },
            provider_config: Value::Null,
        }
    }

    #[test]
    fn preparation_derives_identity_and_redacts_before_network() {
        let prepared = prepare_deploy(&request()).expect("fixture nsec should parse");
        assert_eq!(
            prepared.env.get("BUZZ_RELAY_URL"),
            Some(&"wss://relay.example".to_string())
        );
        assert_eq!(prepared.env.get("MODEL_KEY"), Some(&"secret".to_string()));
        assert_eq!(
            prepared.redactor.redact("auth-secret and secret"),
            "[redacted] and [redacted]"
        );
        assert_eq!(prepared.subdomain, prepared.identity.subdomain("default"));
        assert_eq!(prepared.launch_intent.as_str().len(), 64);
    }

    #[test]
    fn redaction_is_bounded_and_handles_token_prefixes() {
        let redactor = Redactor::from_values(["secret-value".to_string()]);
        let text = redactor.redact("secret-value ghp_abcdefghijklmnopqrstuvwxyz");
        assert_eq!(text, "[redacted] [redacted]");
    }

    #[test]
    fn authoritative_env_keys_clear_lower_tier_spoofs_when_values_are_absent() {
        let mut request = request();
        request.agent.auth_tag = None;
        request.agent.launch = Some(crate::wire::LaunchBlock {
            command: None,
            args: Vec::new(),
            env: BTreeMap::from([
                ("BUZZ_AUTH_TAG".to_string(), "spoofed".to_string()),
                ("BUZZ_ACP_AGENT_COMMAND".to_string(), "spoofed".to_string()),
                ("BUZZ_ACP_RESPOND_TO".to_string(), "spoofed".to_string()),
                ("BUZZ_ACP_NO_PRESENCE".to_string(), "1".to_string()),
            ]),
            policy_env: BTreeMap::new(),
            owner_pubkey: Some("owner".to_string()),
        });
        let error = prepare_deploy(&request).expect_err("presence suppression must be rejected");
        assert!(error.to_string().contains("BUZZ_ACP_NO_PRESENCE"));

        request
            .agent
            .launch
            .as_mut()
            .expect("launch exists")
            .env
            .remove("BUZZ_ACP_NO_PRESENCE");
        let prepared = prepare_deploy(&request).expect("remaining env should prepare");
        assert!(!prepared.env.contains_key("BUZZ_AUTH_TAG"));
        assert!(!prepared.env.contains_key("BUZZ_ACP_AGENT_COMMAND"));
        assert_eq!(
            prepared.env.get("BUZZ_ACP_AGENT_OWNER"),
            Some(&"owner".to_string())
        );
    }

    #[test]
    fn env_keys_must_be_posix_names() {
        let mut request = request();
        request
            .agent
            .env_vars
            .insert("not.posix".to_string(), "x".to_string());
        let error = prepare_deploy(&request).expect_err("invalid env names must fail closed");
        assert!(error.to_string().contains("not.posix"));
    }

    #[test]
    fn only_conflict_claim_errors_are_claim_loss() {
        let rate_limited = BoxApiError::RateLimited {
            code: "start_limit_reached".to_string(),
            retry_after_seconds: None,
            request_id: None,
        };
        let unauthorized = BoxApiError::Http {
            status: 401,
            code: "unauthorized".to_string(),
            message: "no".to_string(),
            request_id: None,
        };
        let billing = BoxApiError::Http {
            status: 402,
            code: "payment_required".to_string(),
            message: "no".to_string(),
            request_id: None,
        };
        let conflict = BoxApiError::Http {
            status: 409,
            code: "conflict".to_string(),
            message: "no".to_string(),
            request_id: None,
        };
        let bad_conflict = BoxApiError::Http {
            status: 400,
            code: "subdomain_conflict".to_string(),
            message: "no".to_string(),
            request_id: None,
        };
        assert!(!is_claim_loss(&rate_limited));
        assert!(!is_claim_loss(&unauthorized));
        assert!(!is_claim_loss(&billing));
        assert!(is_claim_loss(&conflict));
        assert!(is_claim_loss(&bad_conflict));
    }
}
