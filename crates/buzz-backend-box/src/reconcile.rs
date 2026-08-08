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
use crate::wire::{AgentPayload, DeployRequest};
use serde_json::Map;
use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};
use thiserror::Error;

/// The reconciliation operation deadline required by the provider contract.
pub const OPERATION_DEADLINE: Duration = Duration::from_secs(600);
/// Poll interval required by the provider contract.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Provider-local bounded redaction seam. Task C will replace this with the
/// complete shared secret redactor, but all Task B error paths already pass
/// through this boundary.
#[derive(Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Redactor")
            .field("secret_count", &self.secrets.len())
            .finish()
    }
}

impl Redactor {
    /// Build a redactor from non-empty secret values, longest first.
    pub fn from_values(values: impl IntoIterator<Item = String>) -> Self {
        let mut secrets: Vec<String> = values
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect();
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        secrets.dedup();
        Self { secrets }
    }

    /// Add one credential value to the redaction set.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        let value = value.into();
        if !value.is_empty() {
            self.secrets.push(value);
            self.secrets
                .sort_by_key(|entry| std::cmp::Reverse(entry.len()));
            self.secrets.dedup();
        }
        self
    }

    /// Replace known secrets and token-shaped prefixes in untrusted text.
    pub fn redact(&self, input: &str) -> String {
        let mut output = input.to_string();
        for secret in &self.secrets {
            output = output.replace(secret, "[redacted]");
        }
        for prefix in [
            "nsec1",
            "sprt_tok_",
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "ghr_",
            "github_pat_",
        ] {
            output = redact_token_prefix(&output, prefix);
        }
        output
            .chars()
            .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
            .take(512)
            .collect()
    }
}

fn redact_token_prefix(input: &str, prefix: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(index) = remaining.find(prefix) {
        output.push_str(&remaining[..index]);
        let token = &remaining[index..];
        let end = token.find(char::is_whitespace).unwrap_or(token.len());
        output.push_str("[redacted]");
        remaining = &token[end..];
    }
    output.push_str(remaining);
    output
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
    let env = build_environment(&request.agent, &identity, &config)?;
    let redactor = Redactor::from_values(
        env.values()
            .cloned()
            .chain(std::iter::once(request.agent.private_key_nsec.clone()))
            .chain(request.agent.auth_tag.clone())
            .collect::<Vec<_>>(),
    );
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

fn build_environment(
    agent: &AgentPayload,
    identity: &AgentIdentity,
    config: &ProviderConfig,
) -> Result<BTreeMap<String, String>, ReconcileError> {
    let mut env = BTreeMap::new();
    if let Some(launch) = &agent.launch {
        env.extend(launch.policy_env.clone());
        env.extend(launch.env.clone());
    } else {
        env.extend(agent.env_vars.clone());
    }
    env.insert("BUZZ_RELAY_URL".to_string(), agent.relay_url.clone());
    env.insert(
        "BUZZ_PRIVATE_KEY".to_string(),
        agent.private_key_nsec.clone(),
    );
    env.insert(
        "NOSTR_PRIVATE_KEY".to_string(),
        agent.private_key_nsec.clone(),
    );
    if let Some(auth_tag) = &agent.auth_tag {
        env.insert("BUZZ_AUTH_TAG".to_string(), auth_tag.clone());
    }
    if let Some(owner) = agent
        .launch
        .as_ref()
        .and_then(|launch| launch.owner_pubkey.clone())
    {
        env.insert("BUZZ_OWNER_PUBKEY".to_string(), owner);
    }
    env.insert(
        "BUZZ_INACTIVITY_SECONDS".to_string(),
        config.inactivity_seconds.to_string(),
    );
    env.insert(
        "BUZZ_AGENT_PUBKEY".to_string(),
        identity.pubkey_hex().to_string(),
    );
    if let Some(launch) = &agent.launch {
        if let Some(command) = &launch.command {
            env.insert("BUZZ_AGENT_COMMAND".to_string(), command.clone());
        }
        if !launch.args.is_empty() {
            let args = serde_json::to_string(&launch.args).map_err(|_| {
                ReconcileError::InvalidRequest("launch args are not serializable".to_string())
            })?;
            env.insert("BUZZ_AGENT_ARGS".to_string(), args);
        }
    }
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

/// Typed error returned by the Task B provisioner seam.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProvisionError {
    /// Secret injection and service installation belong to Task C.
    #[error("Box provisioning is not yet implemented; secret injection and service installation are Task C")]
    NotYetImplemented,
    /// A future provisioner may return a bounded safe message.
    #[error("Box provisioning failed: {0}")]
    Failed(String),
}

/// Inputs supplied to a provisioner after ownership has been claimed.
pub struct ProvisionRequest<'a> {
    /// Claimed Box record.
    pub box_record: &'a BoxRecord,
    /// Prepared deployment context, including secrets held only in memory.
    pub prepared: &'a PreparedDeploy,
}

/// The seam for Task C secret injection, service installation, and launch.
#[allow(async_fn_in_trait)]
pub trait Provisioner {
    /// Provision and start the fixed service inside a verified claimed Box.
    async fn provision(&self, request: ProvisionRequest<'_>) -> Result<(), ProvisionError>;
}

/// Task B's truthful stub provisioner.
#[derive(Clone, Copy, Debug, Default)]
pub struct StubProvisioner;

impl Provisioner for StubProvisioner {
    async fn provision(&self, _request: ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        Err(ProvisionError::NotYetImplemented)
    }
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
            .map_err(|error| api_error(prepared, error))?;
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
                    .map_err(|error| observe_error(prepared, error))?
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
                match api
                    .update(
                        &ready.id,
                        &UpdateBoxRequest {
                            subdomain: prepared.subdomain.clone(),
                        },
                    )
                    .await
                {
                    Ok(claimed) => {
                        // The candidate is now claimed, but no secrets have
                        // crossed the API boundary. Task C owns this seam.
                        provisioner
                            .provision(ProvisionRequest {
                                box_record: &claimed,
                                prepared,
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
                    Err(error) if is_claim_loss(&error) => {
                        stop_candidate(api, &ready.id, prepared, options, started).await?;
                        return await_claim_winner(api, prepared, options, started).await;
                    }
                    Err(error) => return Err(api_error(prepared, error)),
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
                    .map_err(|error| api_error(prepared, error))?;
                let ready = wait_for_ready(api, &resumed.id, prepared, options, started).await?;
                provisioner
                    .provision(ProvisionRequest {
                        box_record: &ready,
                        prepared,
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
                    .map_err(|error| api_error(prepared, error))?;
                provisioner
                    .provision(ProvisionRequest {
                        box_record: &record,
                        prepared,
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
                let current = api
                    .get(&box_id)
                    .await
                    .map_err(|error| api_error(prepared, error))?;
                if !same_fence(&current, &observation.box_record) {
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
    .map_err(|error| api_error(prepared, error))
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
            .map_err(|error| api_error(prepared, error))?;
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
    let _ = api
        .stop(box_id)
        .await
        .map_err(|error| api_error(prepared, error))?;
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
        let record = api
            .get(box_id)
            .await
            .map_err(|error| api_error(prepared, error))?;
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
            .map_err(|error| api_error(prepared, error))?;
        if let Some(record) = records
            .into_iter()
            .find(|record| record.subdomain.as_deref() == Some(prepared.subdomain.as_str()))
        {
            let id = record.id.clone();
            let observed = observe_box(api, record, &prepared.identity)
                .await
                .map_err(|error| observe_error(prepared, error))?;
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
            .map_err(|error| api_error(prepared, error))?;
        let observed = observe_box(api, record, &prepared.identity)
            .await
            .map_err(|error| observe_error(prepared, error))?;
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
        && current.updated_at == observed.updated_at
}

fn is_claim_loss(error: &BoxApiError) -> bool {
    error
        .status()
        .is_some_and(|status| (400..=599).contains(&status))
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

fn api_error(prepared: &PreparedDeploy, error: BoxApiError) -> ReconcileError {
    ReconcileError::Api(prepared.redactor.redact(&error.to_string()))
}

fn observe_error(prepared: &PreparedDeploy, error: ObserveError) -> ReconcileError {
    ReconcileError::Observation(prepared.redactor.redact(&error.to_string()))
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
}
