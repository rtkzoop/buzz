//! Explicitly gated ASCII Box platform validation.
//!
//! This binary is a manual operator spike, not part of the provider runtime. It
//! never performs a Box API request unless the caller supplies both an ambient
//! `BOX_API_KEY` and `--confirm-live`. `--dry-run` and `--help` are local-only.

use buzz_backend_box::api::{
    BoxApi, BoxApiError, BoxRecord, BoxState, CommandRequest, CreateBoxRequest, ResumeBoxRequest,
    UpdateBoxRequest, WriteFileRequest, DEFAULT_BASE_URL,
};
use buzz_backend_box::config::DEFAULT_IMAGE;
use buzz_backend_box::redact::Redactor;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[cfg(test)]
use std::collections::BTreeSet;

const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_SAFETY_GATE: i32 = 3;
const EXIT_CHECK_FAILURE: i32 = 4;
const CREATE_TTL_SECONDS: u64 = 900;
const READY_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Group {
    Limits,
    NoEnvSelfStop,
    SubdomainRace,
    FileModeOutputCaps,
    DockerSnapshotResume,
    Network,
    All,
}

impl Group {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "limits" => Self::Limits,
            "no-env-self-stop" => Self::NoEnvSelfStop,
            "subdomain-race" => Self::SubdomainRace,
            "file-mode-output-caps" => Self::FileModeOutputCaps,
            "docker-snapshot-resume" => Self::DockerSnapshotResume,
            "network" => Self::Network,
            "all" => Self::All,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Limits => "limits",
            Self::NoEnvSelfStop => "no-env-self-stop",
            Self::SubdomainRace => "subdomain-race",
            Self::FileModeOutputCaps => "file-mode-output-caps",
            Self::DockerSnapshotResume => "docker-snapshot-resume",
            Self::Network => "network",
            Self::All => "all",
        }
    }

    fn mutates(self) -> bool {
        !matches!(self, Self::Limits)
    }

    fn groups(self) -> &'static [Self] {
        match self {
            Self::All => &[
                Self::Limits,
                Self::NoEnvSelfStop,
                Self::SubdomainRace,
                Self::FileModeOutputCaps,
                Self::DockerSnapshotResume,
                Self::Network,
            ],
            group => match group {
                Self::Limits => &[Self::Limits],
                Self::NoEnvSelfStop => &[Self::NoEnvSelfStop],
                Self::SubdomainRace => &[Self::SubdomainRace],
                Self::FileModeOutputCaps => &[Self::FileModeOutputCaps],
                Self::DockerSnapshotResume => &[Self::DockerSnapshotResume],
                Self::Network => &[Self::Network],
                Self::All => unreachable!("all is handled above"),
            },
        }
    }
}

#[derive(Debug)]
struct Args {
    group: Group,
    dry_run: bool,
    confirm_live: bool,
}

enum ParseResult {
    Help,
    Run(Args),
    Error(String),
}

fn parse_args() -> ParseResult {
    let mut group = None;
    let mut dry_run = false;
    let mut confirm_live = false;

    for argument in env::args().skip(1) {
        match argument.as_str() {
            "--help" | "-h" => return ParseResult::Help,
            "--dry-run" => dry_run = true,
            "--confirm-live" => confirm_live = true,
            value if value.starts_with('-') => {
                return ParseResult::Error(format!("unknown option {value:?}"));
            }
            value => {
                if group
                    .replace(Group::parse(value).ok_or_else(|| {
                        format!(
                            "unknown check group {value:?}; use --help for the supported groups"
                        )
                    }))
                    .is_some()
                {
                    return ParseResult::Error(
                        "more than one check group was supplied".to_string(),
                    );
                }
            }
        }
    }

    match group {
        Some(Ok(group)) => ParseResult::Run(Args {
            group,
            dry_run,
            confirm_live,
        }),
        Some(Err(error)) => ParseResult::Error(error),
        None => ParseResult::Error("a check group is required; use --help for usage".to_string()),
    }
}

fn usage() -> &'static str {
    "Usage: box-live-spike [--dry-run] [--confirm-live] <group>\n\nGroups:\n  limits\n  no-env-self-stop\n  subdomain-race\n  file-mode-output-caps\n  docker-snapshot-resume\n  network\n  all\n\nSafety:\n  --dry-run       Print planned API calls as JSON; never reads credentials or uses the network.\n  --confirm-live  Required with BOX_API_KEY for any group that creates, stops, or resumes Boxes.\n\nExit codes:\n  0 completed or dry-run, 2 usage error, 3 safety gate blocked, 4 completed with a failed check.\n\nThe live spike is intentionally never invoked by provider deploys or release jobs."
}

#[derive(Clone, Debug, Serialize)]
struct Mutation {
    method: &'static str,
    path: &'static str,
    purpose: &'static str,
}

fn planned_mutations(group: Group) -> Vec<Mutation> {
    let mut mutations = Vec::new();
    for item in group.groups() {
        let item_mutations: &[Mutation] = match item {
            Group::Limits => &[],
            Group::NoEnvSelfStop => &[
                Mutation {
                    method: "POST",
                    path: "/boxes",
                    purpose: "create a noEnv candidate with a short safety TTL",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/commands",
                    purpose: "inspect noEnv isolation and run box stop self",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/stop",
                    purpose: "stop/archive the candidate during cleanup",
                },
            ],
            Group::SubdomainRace => &[
                Mutation {
                    method: "POST",
                    path: "/boxes",
                    purpose: "create candidate A",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes",
                    purpose: "create candidate B",
                },
                Mutation {
                    method: "PATCH",
                    path: "/boxes/{candidate-a}",
                    purpose: "concurrently claim one deterministic subdomain",
                },
                Mutation {
                    method: "PATCH",
                    path: "/boxes/{candidate-b}",
                    purpose: "concurrently claim one deterministic subdomain",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/stop",
                    purpose: "stop/archive both candidates during cleanup",
                },
            ],
            Group::FileModeOutputCaps => &[
                Mutation {
                    method: "POST",
                    path: "/boxes",
                    purpose: "create a noEnv candidate",
                },
                Mutation {
                    method: "PUT",
                    path: "/boxes/{candidate}/files",
                    purpose: "write a sentinel file for mode verification",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/commands",
                    purpose: "chmod 600 and generate bounded stdout/stderr",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/stop",
                    purpose: "stop/archive the candidate during cleanup",
                },
            ],
            Group::DockerSnapshotResume => &[
                Mutation {
                    method: "POST",
                    path: "/boxes",
                    purpose: "create a noEnv Docker candidate",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/commands",
                    purpose: "inspect Docker before snapshot",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/stop",
                    purpose: "archive the candidate for snapshot testing",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/resume",
                    purpose: "resume the archived candidate",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/stop",
                    purpose: "stop/archive the candidate during cleanup",
                },
            ],
            Group::Network => &[
                Mutation {
                    method: "POST",
                    path: "/boxes",
                    purpose: "create a noEnv network candidate",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/commands",
                    purpose: "probe HTTPS and dedicated IPv4 from inside",
                },
                Mutation {
                    method: "POST",
                    path: "/boxes/{candidate}/stop",
                    purpose: "stop/archive the candidate during cleanup",
                },
            ],
            Group::All => &[],
        };
        mutations.extend_from_slice(item_mutations);
    }
    mutations
}

fn planned_reads(group: Group) -> Vec<Mutation> {
    let mut reads = Vec::new();
    for item in group.groups() {
        if matches!(item, Group::Limits) {
            reads.push(Mutation {
                method: "GET",
                path: "/limits",
                purpose: "read current account and start limits",
            });
        }
    }
    reads
}

#[derive(Debug, Serialize)]
struct CheckRecord {
    check: String,
    status: String,
    manual_check_required: bool,
    http_status: Option<u16>,
    error_code: Option<String>,
    box_ids: Vec<String>,
    duration_ms: u128,
    evidence: Value,
    error: Option<String>,
}

fn pass(check: &str, started: Instant, box_ids: Vec<String>, evidence: Value) -> CheckRecord {
    CheckRecord {
        check: check.to_string(),
        status: "pass".to_string(),
        manual_check_required: false,
        http_status: None,
        error_code: None,
        box_ids,
        duration_ms: started.elapsed().as_millis(),
        evidence,
        error: None,
    }
}

fn unverified(check: &str, started: Instant, evidence: Value) -> CheckRecord {
    CheckRecord {
        check: check.to_string(),
        status: "unverified".to_string(),
        manual_check_required: true,
        http_status: None,
        error_code: None,
        box_ids: Vec::new(),
        duration_ms: started.elapsed().as_millis(),
        evidence,
        error: None,
    }
}

struct UnverifiedDetails {
    box_ids: Vec<String>,
    evidence: Value,
    http_status: Option<u16>,
    error_code: Option<String>,
    error: Option<String>,
}

fn unverified_with_details(
    check: &str,
    started: Instant,
    details: UnverifiedDetails,
    redactor: &Redactor,
) -> CheckRecord {
    CheckRecord {
        check: check.to_string(),
        status: "unverified".to_string(),
        manual_check_required: true,
        http_status: details.http_status,
        error_code: details.error_code,
        box_ids: details.box_ids,
        duration_ms: started.elapsed().as_millis(),
        evidence: details.evidence,
        error: details.error.as_deref().map(|value| redactor.redact(value)),
    }
}

fn failure(
    check: &str,
    started: Instant,
    box_ids: Vec<String>,
    error: &str,
    http_status: Option<u16>,
    error_code: Option<String>,
    redactor: &Redactor,
) -> CheckRecord {
    CheckRecord {
        check: check.to_string(),
        status: "fail".to_string(),
        manual_check_required: false,
        http_status,
        error_code,
        box_ids,
        duration_ms: started.elapsed().as_millis(),
        evidence: Value::Null,
        error: Some(redactor.redact(error)),
    }
}

fn api_failure(
    check: &str,
    started: Instant,
    box_ids: Vec<String>,
    error: &BoxApiError,
    redactor: &Redactor,
) -> CheckRecord {
    let (status, code) = match error {
        BoxApiError::Http { status, code, .. } => (Some(*status), Some(code.clone())),
        BoxApiError::RateLimited { code, .. } => (Some(429), Some(code.clone())),
        _ => (error.status(), None),
    };
    failure(
        check,
        started,
        box_ids,
        &error.to_string(),
        status,
        code,
        redactor,
    )
}

fn command_evidence(result: &buzz_backend_box::api::CommandResult) -> Value {
    json!({
        "success": result.success,
        "exit_code": result.exit_code,
        "signal": result.signal,
        "stdout_bytes": result.stdout.len(),
        "stderr_bytes": result.stderr.len(),
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "timed_out": result.timed_out,
    })
}

fn record_command(
    check: &str,
    started: Instant,
    box_id: &str,
    result: &buzz_backend_box::api::CommandResult,
    redactor: &Redactor,
) -> CheckRecord {
    if result.success && !result.timed_out {
        return pass(
            check,
            started,
            vec![box_id.to_string()],
            command_evidence(result),
        );
    }
    failure(
        check,
        started,
        vec![box_id.to_string()],
        &format!(
            "Box command failed with exit_code={:?}, signal={:?}",
            result.exit_code, result.signal
        ),
        None,
        None,
        redactor,
    )
}

fn record_output_caps(
    check: &str,
    started: Instant,
    box_id: &str,
    result: &buzz_backend_box::api::CommandResult,
    redactor: &Redactor,
) -> CheckRecord {
    if !result.success || result.timed_out {
        return record_command(check, started, box_id, result, redactor);
    }

    let observed = command_evidence(result);
    if result.stdout_truncated && result.stderr_truncated {
        return pass(check, started, vec![box_id.to_string()], observed);
    }

    unverified_with_details(
        check,
        started,
        UnverifiedDetails {
            box_ids: vec![box_id.to_string()],
            evidence: json!({
                "observed": observed,
                "reason": "The API returned no explicit truncation marker for both streams; record the platform cap manually before treating this as verified.",
            }),
            http_status: None,
            error_code: Some("output_cap_unverified".to_string()),
            error: None,
        },
        redactor,
    )
}

fn command_unavailable(exit_code: i32) -> bool {
    matches!(exit_code, 125 | 127)
}

struct CandidateGuard<'a> {
    api: &'a BoxApi,
    ids: Vec<String>,
    redactor: Redactor,
}

impl<'a> CandidateGuard<'a> {
    fn new(api: &'a BoxApi, redactor: Redactor) -> Self {
        Self {
            api,
            ids: Vec::new(),
            redactor,
        }
    }

    fn add(&mut self, id: String) {
        self.ids.push(id);
    }

    async fn cleanup(&self) -> Vec<CheckRecord> {
        let mut checks = Vec::new();
        for id in &self.ids {
            let started = Instant::now();
            match self.api.get(id).await {
                Ok(record) if matches!(record.state, BoxState::Archived | BoxState::Archiving) => {
                    checks.push(pass(
                        "cleanup-stop-archive",
                        started,
                        vec![id.clone()],
                        json!({
                            "state": record.state.as_str(),
                            "action": "already-stopping-or-archived"
                        }),
                    ));
                }
                Ok(record) => match self.api.stop(id).await {
                    Ok(stopped) => checks.push(pass(
                        "cleanup-stop-archive",
                        started,
                        vec![id.clone()],
                        json!({
                            "prior_state": record.state.as_str(),
                            "result_state": stopped.state.as_str(),
                            "action": "stop/archive",
                        }),
                    )),
                    Err(error) => checks.push(api_failure(
                        "cleanup-stop-archive",
                        started,
                        vec![id.clone()],
                        &error,
                        &self.redactor,
                    )),
                },
                Err(error) => checks.push(api_failure(
                    "cleanup-observe-candidate",
                    started,
                    vec![id.clone()],
                    &error,
                    &self.redactor,
                )),
            }
        }
        checks
    }
}

#[derive(Debug)]
enum SpikeFailure {
    Api(BoxApiError),
    Timeout,
}

impl SpikeFailure {
    fn message(&self) -> String {
        match self {
            Self::Api(error) => error.to_string(),
            Self::Timeout => {
                format!("Box did not reach a command-ready state within {READY_TIMEOUT:?}")
            }
        }
    }

    fn status(&self) -> Option<u16> {
        match self {
            Self::Api(error) => error.status(),
            Self::Timeout => None,
        }
    }
}

async fn create_ready(
    api: &BoxApi,
    guard: &mut CandidateGuard<'_>,
) -> Result<BoxRecord, SpikeFailure> {
    let request = CreateBoxRequest {
        no_env: true,
        ttl_seconds: Some(CREATE_TTL_SECONDS),
        machine_type: "small".to_string(),
        env: Map::new(),
    };
    let record = api.create(&request).await.map_err(SpikeFailure::Api)?;
    guard.add(record.id.clone());
    wait_ready(api, &record.id).await
}

async fn wait_ready(api: &BoxApi, box_id: &str) -> Result<BoxRecord, SpikeFailure> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let record = api.get(box_id).await.map_err(SpikeFailure::Api)?;
        if record.state.is_ready() {
            return Ok(record);
        }
        if Instant::now() >= deadline {
            return Err(SpikeFailure::Timeout);
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_archived(api: &BoxApi, box_id: &str) -> Result<BoxRecord, SpikeFailure> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let record = api.get(box_id).await.map_err(SpikeFailure::Api)?;
        if record.state == BoxState::Archived {
            return Ok(record);
        }
        if Instant::now() >= deadline {
            return Err(SpikeFailure::Timeout);
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn create_error_record(
    check: &str,
    started: Instant,
    spike_failure: &SpikeFailure,
    ids: Vec<String>,
    redactor: &Redactor,
) -> CheckRecord {
    let (status, code) = match spike_failure {
        SpikeFailure::Api(error) => match error {
            BoxApiError::Http { code, .. } => (spike_failure.status(), Some(code.clone())),
            BoxApiError::RateLimited { code, .. } => (Some(429), Some(code.clone())),
            _ => (spike_failure.status(), None),
        },
        SpikeFailure::Timeout => (None, Some("ready_timeout".to_string())),
    };
    failure(
        check,
        started,
        ids,
        &spike_failure.message(),
        status,
        code,
        redactor,
    )
}

async fn run_limits(api: &BoxApi, redactor: &Redactor) -> Vec<CheckRecord> {
    let started = Instant::now();
    let mut checks = Vec::new();
    match api.limits().await {
        Ok(limits) => checks.push(pass(
            "limits",
            started,
            Vec::new(),
            json!({
                "account_state": limits.account_state,
                "active": limits.active,
                "max_active": limits.max_active,
                "starts_per_minute": limits.starts_per_minute,
                "balance_present": limits.balance.is_some(),
            }),
        )),
        Err(error) => checks.push(api_failure("limits", started, Vec::new(), &error, redactor)),
    }
    checks.push(unverified(
        "limits-start-accounting",
        Instant::now(),
        json!({
            "manual_check_required": true,
            "reason": "Confirm create, fork, and resume each consume one start against the account ceilings without performing an unapproved mutation.",
            "documented_ceiling": {"starts_per_hour": 600, "starts_per_day": 1500},
        }),
    ));
    checks
}

async fn run_no_env_self_stop(api: &BoxApi, redactor: &Redactor) -> Vec<CheckRecord> {
    let mut checks = Vec::new();
    let mut guard = CandidateGuard::new(api, redactor.clone());
    let create_started = Instant::now();
    let candidate = match create_ready(api, &mut guard).await {
        Ok(record) => record,
        Err(error) => {
            checks.push(create_error_record(
                "no-env-create-ready",
                create_started,
                &error,
                guard.ids.clone(),
                redactor,
            ));
            checks.extend(guard.cleanup().await);
            return checks;
        }
    };
    checks.push(pass(
        "no-env-create-ready",
        create_started,
        vec![candidate.id.clone()],
        json!({"state": candidate.state.as_str(), "no_env": true}),
    ));

    let inspect_started = Instant::now();
    let inspect = api
        .execute(
            &candidate.id,
            &CommandRequest {
                command: "test -z \"${BOX_API_KEY+x}\" && test ! -e \"$HOME/.config/ascii/box/config.json\" && command -v box >/dev/null".to_string(),
                cwd: None,
                timeout_seconds: Some(30),
            },
        )
        .await;
    match inspect {
        Ok(result)
            if result
                .exit_code
                .is_some_and(command_unavailable) => checks.push(unverified(
            "no-env-identity-inventory",
            inspect_started,
            json!({"reason": "Box CLI was not installed in the candidate; inspect env and credential file manually."}),
        )),
        Ok(result) => checks.push(record_command(
            "no-env-identity-inventory",
            inspect_started,
            &candidate.id,
            &result,
            redactor,
        )),
        Err(error) => checks.push(api_failure(
            "no-env-identity-inventory",
            inspect_started,
            vec![candidate.id.clone()],
            &error,
            redactor,
        )),
    }

    let denied_started = Instant::now();
    let denied = api
        .execute(
            &candidate.id,
            &CommandRequest {
                command: "if ! command -v box >/dev/null; then exit 125; fi; if box list >/dev/null 2>&1; then exit 1; fi; exit 0".to_string(),
                cwd: None,
                timeout_seconds: Some(30),
            },
        )
        .await;
    match denied {
        Ok(result)
            if result
                .exit_code
                .is_some_and(command_unavailable) => checks.push(unverified(
            "no-env-account-operation-denied",
            denied_started,
            json!({"reason": "Box CLI was not installed in the candidate; account-operation denial requires manual confirmation."}),
        )),
        Ok(result) => checks.push(record_command(
            "no-env-account-operation-denied",
            denied_started,
            &candidate.id,
            &result,
            redactor,
        )),
        Err(error) => checks.push(api_failure(
            "no-env-account-operation-denied",
            denied_started,
            vec![candidate.id.clone()],
            &error,
            redactor,
        )),
    }

    let self_stop_started = Instant::now();
    let self_stop = api
        .execute(
            &candidate.id,
            &CommandRequest {
                command: "box stop self".to_string(),
                cwd: None,
                timeout_seconds: Some(60),
            },
        )
        .await;
    match self_stop {
        Ok(result)
            if result
                .exit_code
                .is_some_and(command_unavailable) => checks.push(unverified(
            "no-env-self-stop",
            self_stop_started,
            json!({"reason": "Box CLI was not installed in the candidate; self-stop requires manual confirmation."}),
        )),
        Ok(result) => checks.push(record_command(
            "no-env-self-stop",
            self_stop_started,
            &candidate.id,
            &result,
            redactor,
        )),
        Err(error) => checks.push(api_failure(
            "no-env-self-stop",
            self_stop_started,
            vec![candidate.id.clone()],
            &error,
            redactor,
        )),
    }
    checks.extend(guard.cleanup().await);
    checks
}

fn race_subdomain() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let digest = hex::encode(Sha256::digest(now.as_bytes()));
    format!("buzz-live-{}", &digest[..12])
}

async fn run_subdomain_race(api: &BoxApi, redactor: &Redactor) -> Vec<CheckRecord> {
    let mut checks = Vec::new();
    let mut guard = CandidateGuard::new(api, redactor.clone());
    let create_started = Instant::now();
    let first = match create_ready(api, &mut guard).await {
        Ok(record) => record,
        Err(error) => {
            checks.push(create_error_record(
                "subdomain-race-create-a",
                create_started,
                &error,
                guard.ids.clone(),
                redactor,
            ));
            checks.extend(guard.cleanup().await);
            return checks;
        }
    };
    let second = match create_ready(api, &mut guard).await {
        Ok(record) => record,
        Err(error) => {
            checks.push(create_error_record(
                "subdomain-race-create-b",
                create_started,
                &error,
                guard.ids.clone(),
                redactor,
            ));
            checks.extend(guard.cleanup().await);
            return checks;
        }
    };
    checks.push(pass(
        "subdomain-race-create-ready",
        create_started,
        vec![first.id.clone(), second.id.clone()],
        json!({"candidate_count": 2}),
    ));

    let subdomain = race_subdomain();
    let claim_started = Instant::now();
    let left_request = UpdateBoxRequest {
        subdomain: subdomain.clone(),
    };
    let right_request = UpdateBoxRequest {
        subdomain: subdomain.clone(),
    };
    let (left, right) = tokio::join!(
        api.update(&first.id, &left_request),
        api.update(&second.id, &right_request)
    );
    let left_ok = left.is_ok();
    let right_ok = right.is_ok();
    let mut box_ids = vec![first.id.clone(), second.id.clone()];
    let mut errors = Vec::new();
    for result in [left.as_ref(), right.as_ref()] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.len() == 1 && left_ok != right_ok {
        let error = errors[0];
        let (status, code) = match error {
            BoxApiError::Http { status, code, .. } => (Some(*status), Some(code.clone())),
            BoxApiError::RateLimited { code, .. } => (Some(429), Some(code.clone())),
            _ => (error.status(), None),
        };
        checks.push(unverified_with_details(
            "subdomain-race-claim",
            claim_started,
            UnverifiedDetails {
                box_ids: std::mem::take(&mut box_ids),
                evidence: json!({
                    "subdomain": subdomain,
                    "candidate_a_succeeded": left_ok,
                    "candidate_b_succeeded": right_ok,
                    "reason": "One claim succeeded and one failed, but the public API does not document atomic conflict semantics or guarantee the loser response shape.",
                }),
                http_status: status,
                error_code: code,
                error: Some(format!("one claim succeeded and one claim failed: {error}")),
            },
            redactor,
        ));
    } else if left_ok || right_ok {
        checks.push(unverified(
            "subdomain-race-claim",
            claim_started,
            json!({
                "subdomain": subdomain,
                "candidate_a_succeeded": left_ok,
                "candidate_b_succeeded": right_ok,
                "reason": "The public API does not document atomic conflict semantics; inspect the loser response and post-claim usability manually.",
            }),
        ));
    } else {
        checks.push(failure(
            "subdomain-race-claim",
            claim_started,
            box_ids,
            "both concurrent subdomain claims failed",
            None,
            Some("claim_failed".to_string()),
            redactor,
        ));
    }
    checks.extend(guard.cleanup().await);
    checks
}

async fn run_file_mode_output_caps(api: &BoxApi, redactor: &Redactor) -> Vec<CheckRecord> {
    let mut checks = Vec::new();
    let sentinel = format!("buzz-live-spike-sentinel-{}", std::process::id());
    let local_redactor = redactor.clone().with_value(sentinel.clone());
    let mut guard = CandidateGuard::new(api, local_redactor.clone());
    let create_started = Instant::now();
    let candidate = match create_ready(api, &mut guard).await {
        Ok(record) => record,
        Err(error) => {
            checks.push(create_error_record(
                "file-mode-output-create-ready",
                create_started,
                &error,
                guard.ids.clone(),
                &local_redactor,
            ));
            checks.extend(guard.cleanup().await);
            return checks;
        }
    };
    checks.push(pass(
        "file-mode-output-create-ready",
        create_started,
        vec![candidate.id.clone()],
        json!({"state": candidate.state.as_str()}),
    ));

    let write_started = Instant::now();
    match api
        .write_file(
            &candidate.id,
            &WriteFileRequest {
                path: "run/buzz-live-spike/sentinel".to_string(),
                content: sentinel,
                encoding: "utf8".to_string(),
            },
        )
        .await
    {
        Ok(result) => checks.push(pass(
            "secret-file-write",
            write_started,
            vec![candidate.id.clone()],
            json!({"path": result.path, "secret_value_emitted": false}),
        )),
        Err(error) => checks.push(api_failure(
            "secret-file-write",
            write_started,
            vec![candidate.id.clone()],
            &error,
            &local_redactor,
        )),
    }

    let mode_started = Instant::now();
    let mode = api
        .execute(
            &candidate.id,
            &CommandRequest {
                command: "chmod 600 run/buzz-live-spike/sentinel && stat -c '%a' run/buzz-live-spike/sentinel".to_string(),
                cwd: None,
                timeout_seconds: Some(30),
            },
        )
        .await;
    match mode {
        Ok(result) if result.success && result.stdout.trim() == "600" => checks.push(pass(
            "secret-file-mode-0600",
            mode_started,
            vec![candidate.id.clone()],
            json!({"mode": "600", "stdout_emitted": false}),
        )),
        Ok(result) => checks.push(failure(
            "secret-file-mode-0600",
            mode_started,
            vec![candidate.id.clone()],
            &format!("mode command returned {:?}", result.exit_code),
            None,
            None,
            &local_redactor,
        )),
        Err(error) => checks.push(api_failure(
            "secret-file-mode-0600",
            mode_started,
            vec![candidate.id.clone()],
            &error,
            &local_redactor,
        )),
    }

    let output_started = Instant::now();
    match api
        .execute(
            &candidate.id,
            &CommandRequest {
                command: "printf '%*s' 2000000 x; printf '%*s' 2000000 x >&2".to_string(),
                cwd: None,
                timeout_seconds: Some(60),
            },
        )
        .await
    {
        Ok(result) => checks.push(record_output_caps(
            "command-output-caps",
            output_started,
            &candidate.id,
            &result,
            &local_redactor,
        )),
        Err(error) => checks.push(api_failure(
            "command-output-caps",
            output_started,
            vec![candidate.id.clone()],
            &error,
            &local_redactor,
        )),
    }
    checks.push(unverified(
        "secret-not-in-api-logs",
        Instant::now(),
        json!({"reason": "Confirm API-side request logs and snapshots do not retain the sentinel or command arguments."}),
    ));
    checks.push(unverified(
        "command-timeout-above-60-seconds",
        Instant::now(),
        json!({"reason": "The typed client clamps timeoutSeconds to the documented 1..60 range; validate rejection of larger raw API values manually."}),
    ));
    checks.extend(guard.cleanup().await);
    checks
}

async fn run_docker_snapshot_resume(api: &BoxApi, redactor: &Redactor) -> Vec<CheckRecord> {
    let mut checks = Vec::new();
    let mut guard = CandidateGuard::new(api, redactor.clone());
    let create_started = Instant::now();
    let candidate = match create_ready(api, &mut guard).await {
        Ok(record) => record,
        Err(error) => {
            checks.push(create_error_record(
                "docker-snapshot-create-ready",
                create_started,
                &error,
                guard.ids.clone(),
                redactor,
            ));
            checks.extend(guard.cleanup().await);
            return checks;
        }
    };
    checks.push(pass(
        "docker-snapshot-create-ready",
        create_started,
        vec![candidate.id.clone()],
        json!({"state": candidate.state.as_str()}),
    ));

    let before_started = Instant::now();
    match api
        .execute(
            &candidate.id,
            &CommandRequest {
                command: format!("docker version --format '{{{{.Server.Version}}}}' && docker image inspect {DEFAULT_IMAGE:?} >/dev/null"),
                cwd: None,
                timeout_seconds: Some(60),
            },
        )
        .await
    {
        Ok(result) => checks.push(record_command(
            "docker-image-before-snapshot",
            before_started,
            &candidate.id,
            &result,
            redactor,
        )),
        Err(error) => checks.push(api_failure(
            "docker-image-before-snapshot",
            before_started,
            vec![candidate.id.clone()],
            &error,
            redactor,
        )),
    }

    let stop_started = Instant::now();
    let stopped = match api.stop(&candidate.id).await {
        Ok(record) => {
            checks.push(pass(
                "docker-snapshot-stop",
                stop_started,
                vec![candidate.id.clone()],
                json!({"state": record.state.as_str(), "action": "stop/archive"}),
            ));
            true
        }
        Err(error) => {
            checks.push(api_failure(
                "docker-snapshot-stop",
                stop_started,
                vec![candidate.id.clone()],
                &error,
                redactor,
            ));
            false
        }
    };

    if stopped {
        let archive_started = Instant::now();
        match wait_archived(api, &candidate.id).await {
            Ok(record) => checks.push(pass(
                "docker-snapshot-archived",
                archive_started,
                vec![candidate.id.clone()],
                json!({"state": record.state.as_str()}),
            )),
            Err(error) => {
                checks.push(create_error_record(
                    "docker-snapshot-archived",
                    archive_started,
                    &error,
                    vec![candidate.id.clone()],
                    redactor,
                ));
                checks.extend(guard.cleanup().await);
                return checks;
            }
        }
    } else {
        checks.extend(guard.cleanup().await);
        return checks;
    }

    let resume_started = Instant::now();
    match api
        .resume(
            &candidate.id,
            &ResumeBoxRequest {
                machine_type: None,
                no_env: Some(true),
            },
        )
        .await
    {
        Ok(record) => {
            checks.push(pass(
                "docker-snapshot-resume",
                resume_started,
                vec![candidate.id.clone()],
                json!({"state": record.state.as_str()}),
            ));
            match wait_ready(api, &candidate.id).await {
                Ok(_) => {
                    let after_started = Instant::now();
                    match api
                        .execute(
                            &candidate.id,
                            &CommandRequest {
                                command: format!(
                                    "docker image inspect {DEFAULT_IMAGE:?} >/dev/null"
                                ),
                                cwd: None,
                                timeout_seconds: Some(60),
                            },
                        )
                        .await
                    {
                        Ok(result) => checks.push(record_command(
                            "docker-image-after-resume",
                            after_started,
                            &candidate.id,
                            &result,
                            redactor,
                        )),
                        Err(error) => checks.push(api_failure(
                            "docker-image-after-resume",
                            after_started,
                            vec![candidate.id.clone()],
                            &error,
                            redactor,
                        )),
                    }
                }
                Err(error) => checks.push(create_error_record(
                    "docker-resume-ready",
                    Instant::now(),
                    &error,
                    vec![candidate.id.clone()],
                    redactor,
                )),
            }
        }
        Err(error) => checks.push(api_failure(
            "docker-snapshot-resume",
            resume_started,
            vec![candidate.id.clone()],
            &error,
            redactor,
        )),
    }
    checks.push(unverified(
        "docker-private-registry-auth",
        Instant::now(),
        json!({"reason": "Use a disposable private registry credential and inspect the resumed snapshot; never place the credential in BOX_API_KEY or output."}),
    ));
    checks.push(unverified(
        "docker-digest-and-fork",
        Instant::now(),
        json!({"reason": "Confirm immutable digest pull and fork image/layer behavior against the approved image. The typed client intentionally has no fork operation."}),
    ));
    checks.extend(guard.cleanup().await);
    checks
}

async fn run_network(api: &BoxApi, redactor: &Redactor) -> Vec<CheckRecord> {
    let mut checks = Vec::new();
    let mut guard = CandidateGuard::new(api, redactor.clone());
    let create_started = Instant::now();
    let candidate = match create_ready(api, &mut guard).await {
        Ok(record) => record,
        Err(error) => {
            checks.push(create_error_record(
                "network-create-ready",
                create_started,
                &error,
                guard.ids.clone(),
                redactor,
            ));
            checks.extend(guard.cleanup().await);
            return checks;
        }
    };
    checks.push(pass(
        "network-create-ready",
        create_started,
        vec![candidate.id.clone()],
        json!({"state": candidate.state.as_str()}),
    ));

    let https_started = Instant::now();
    match api
        .execute(
            &candidate.id,
            &CommandRequest {
                command: "curl --fail --silent --show-error --max-time 15 https://ascii.dev >/dev/null && ip -4 addr show".to_string(),
                cwd: None,
                timeout_seconds: Some(30),
            },
        )
        .await
    {
        Ok(result) => checks.push(record_command(
            "network-https-and-ipv4",
            https_started,
            &candidate.id,
            &result,
            redactor,
        )),
        Err(error) => checks.push(api_failure(
            "network-https-and-ipv4",
            https_started,
            vec![candidate.id.clone()],
            &error,
            redactor,
        )),
    }
    checks.push(unverified(
        "network-wss-relay",
        Instant::now(),
        json!({"reason": "Supply the actual Buzz relay URL and confirm long-lived outbound WSS plus reconnect after resume."}),
    ));
    checks.push(unverified(
        "network-model-provider-https",
        Instant::now(),
        json!({"reason": "Confirm outbound HTTPS to the configured model provider from the deployed account and region."}),
    ));
    checks.extend(guard.cleanup().await);
    checks
}

async fn run_live(group: Group, api: &BoxApi, redactor: &Redactor) -> (Value, i32) {
    let mut checks = Vec::new();
    for item in group.groups() {
        let mut item_checks = match item {
            Group::Limits => run_limits(api, redactor).await,
            Group::NoEnvSelfStop => run_no_env_self_stop(api, redactor).await,
            Group::SubdomainRace => run_subdomain_race(api, redactor).await,
            Group::FileModeOutputCaps => run_file_mode_output_caps(api, redactor).await,
            Group::DockerSnapshotResume => run_docker_snapshot_resume(api, redactor).await,
            Group::Network => run_network(api, redactor).await,
            Group::All => Vec::new(),
        };
        checks.append(&mut item_checks);
    }
    let failed = checks.iter().any(|check| check.status == "fail");
    (
        json!({
            "mode": "live",
            "group": group.name(),
            "network_io": true,
            "status": "completed",
            "checks": checks,
        }),
        if failed { EXIT_CHECK_FAILURE } else { EXIT_OK },
    )
}

fn gate_error(group: Group, missing: Vec<&str>) -> (Value, i32) {
    (
        json!({
            "mode": "live",
            "group": group.name(),
            "status": "blocked",
            "network_io": false,
            "missing": missing,
            "error_code": "safety_gate",
            "error": "No Box API request was made. Supply the required safety gates before a live check.",
        }),
        EXIT_SAFETY_GATE,
    )
}

fn dry_run(group: Group) -> (Value, i32) {
    (
        json!({
            "mode": "dry-run",
            "group": group.name(),
            "status": "planned",
            "network_io": false,
            "planned_reads": planned_reads(group),
            "planned_mutations": planned_mutations(group),
            "cleanup_policy": "stop/archive only; never force-stop or hard-delete",
        }),
        EXIT_OK,
    )
}

async fn execute(args: Args) -> (Value, i32) {
    if args.dry_run {
        return dry_run(args.group);
    }

    let mut missing = Vec::new();
    let api_key = env::var("BOX_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if api_key.is_none() {
        missing.push("BOX_API_KEY");
    }
    if args.group.mutates() && !args.confirm_live {
        missing.push("--confirm-live");
    }
    if !missing.is_empty() {
        return gate_error(args.group, missing);
    }

    let key = match api_key {
        Some(key) => key,
        None => return gate_error(args.group, vec!["BOX_API_KEY"]),
    };
    let redactor = Redactor::from_values(vec![key.clone()]);
    let api = match BoxApi::with_api_key(DEFAULT_BASE_URL, key, Duration::from_secs(30)) {
        Ok(api) => api,
        Err(error) => {
            return (
                json!({
                    "mode": "live",
                    "group": args.group.name(),
                    "status": "blocked",
                    "network_io": false,
                    "error_code": "client_construction",
                    "error": redactor.redact(&error.to_string()),
                }),
                EXIT_SAFETY_GATE,
            )
        }
    };
    run_live(args.group, &api, &redactor).await
}

fn print_json(value: &Value) {
    match serde_json::to_string_pretty(value) {
        Ok(output) => println!("{output}"),
        Err(_) => println!("{{\"status\":\"fail\",\"error_code\":\"json_serialization\"}}"),
    }
}

#[tokio::main]
async fn main() {
    let (value, code) = match parse_args() {
        ParseResult::Help => {
            println!("{}", usage());
            (Value::Null, EXIT_OK)
        }
        ParseResult::Error(error) => (
            json!({
                "mode": "local",
                "status": "blocked",
                "network_io": false,
                "error_code": "usage",
                "error": error,
            }),
            EXIT_USAGE,
        ),
        ParseResult::Run(args) => execute(args).await,
    };
    if !value.is_null() {
        print_json(&value);
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_not_available_exit_codes_are_manual_checks() {
        assert!(command_unavailable(125));
        assert!(command_unavailable(127));
        assert!(!command_unavailable(1));
    }

    #[test]
    fn dry_run_all_contains_every_mutating_group() {
        let names = planned_mutations(Group::All)
            .iter()
            .map(|mutation| mutation.purpose)
            .collect::<BTreeSet<_>>();
        assert!(names.iter().any(|value| value.contains("noEnv")));
        assert!(names.iter().any(|value| value.contains("subdomain")));
        assert!(names.iter().any(|value| value.contains("Docker")));
    }

    #[test]
    fn race_subdomain_is_box_safe_and_deterministic_for_one_run() {
        let value = race_subdomain();
        assert!((3..=40).contains(&value.len()));
        assert!(value.chars().all(|character| character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '-'));
        assert!(!value.contains("--"));
    }

    #[test]
    fn output_caps_without_platform_truncation_are_manual_not_pass() {
        let result = buzz_backend_box::api::CommandResult {
            success: true,
            stdout: "stdout".to_string(),
            stderr: "stderr".to_string(),
            ..Default::default()
        };
        let record = record_output_caps(
            "command-output-caps",
            Instant::now(),
            "box-1",
            &result,
            &Redactor::default(),
        );

        assert_eq!(record.status, "unverified");
        assert!(record.manual_check_required);
    }

    #[test]
    fn output_caps_are_pass_only_when_both_streams_are_marked_truncated() {
        let result = buzz_backend_box::api::CommandResult {
            success: true,
            stdout_truncated: true,
            stderr_truncated: true,
            ..Default::default()
        };
        let record = record_output_caps(
            "command-output-caps",
            Instant::now(),
            "box-1",
            &result,
            &Redactor::default(),
        );

        assert_eq!(record.status, "pass");
        assert!(!record.manual_check_required);
    }

    #[test]
    fn error_records_redact_api_keys_and_sentinels() {
        let api_key = "box-live-spike-api-key";
        let sentinel = "box-live-spike-sentinel";
        let redactor = Redactor::from_values(vec![api_key.to_string(), sentinel.to_string()]);
        let record = failure(
            "redaction",
            Instant::now(),
            Vec::new(),
            &format!("{api_key} {sentinel}"),
            None,
            None,
            &redactor,
        );
        let serialized = serde_json::to_string(&record).expect("record should serialize");

        assert!(!serialized.contains(api_key));
        assert!(!serialized.contains(sentinel));
        assert!(serialized.matches("[redacted]").count() >= 2);
    }
}
