use axum::extract::{Path, State as AxumState};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use buzz_backend_box::api::{
    BoxApi, BoxApiError, BoxRecord, BoxState, CommandRequest, ListBoxesQuery,
};
use buzz_backend_box::classify::{
    classify, Action, Fingerprint, HarnessState, OwnershipMarker, PresenceState, ServiceState,
    StopIntent, BINDING_VERSION, MANAGED_BY,
};
use buzz_backend_box::naming::AgentIdentity;
use buzz_backend_box::observe::{observe_box, LAUNCH_INTENT_PATH, OWNERSHIP_MARKER_PATH};
use buzz_backend_box::provision::BoxProvisioner;
use buzz_backend_box::reconcile::{
    prepare_deploy, reconcile, ProvisionRequest, Provisioner, ReconcileError, ReconcileOptions,
};
use buzz_backend_box::wire::{AgentPayload, DeployRequest};
use nostr::nips::nip19::ToBech32;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

type ServiceResult = (bool, i32, String, bool);
type FileWrite = (String, String, String);
type CommandFailure = (String, String);

#[derive(Clone, Default)]
struct FakeState {
    boxes: Arc<Mutex<HashMap<String, BoxRecord>>>,
    files: Arc<Mutex<HashMap<(String, String), String>>>,
    claim_conflict: Arc<Mutex<bool>>,
    claim_error: Arc<Mutex<Option<(u16, String)>>>,
    reveal_winner_on_claim_error: Arc<Mutex<bool>>,
    hide_winner: Arc<Mutex<bool>>,
    rate_limited: Arc<Mutex<bool>>,
    list_error_message: Arc<Mutex<Option<String>>>,
    list_count: Arc<Mutex<u64>>,
    create_count: Arc<Mutex<u64>>,
    stop_count: Arc<Mutex<u64>>,
    injected_files: Arc<Mutex<Vec<String>>>,
    file_writes: Arc<Mutex<Vec<FileWrite>>>,
    commands: Arc<Mutex<Vec<String>>>,
    operations: Arc<Mutex<Vec<String>>>,
    command_failure: Arc<Mutex<Option<CommandFailure>>>,
    command_timeouts: Arc<Mutex<Vec<u64>>>,
    service_active: Arc<Mutex<bool>>,
    service_active_after_resume: Arc<Mutex<bool>>,
    service_results: Arc<Mutex<Vec<ServiceResult>>>,
    read_paths: Arc<Mutex<Vec<String>>>,
    candidate_ownership_marker: Arc<Mutex<Option<String>>>,
}

#[derive(Clone, Default)]
struct RecordingProvisioner {
    calls: Arc<Mutex<Vec<String>>>,
}

impl Provisioner for RecordingProvisioner {
    async fn provision(
        &self,
        request: ProvisionRequest<'_>,
    ) -> Result<(), buzz_backend_box::reconcile::ProvisionError> {
        self.calls.lock().await.push(request.box_record.id.clone());
        Ok(())
    }
}

fn envelope(kind: &str, payload: Value) -> Json<Value> {
    Json(json!({"ok": true, "type": kind, "data": payload}))
}

fn api_error(status: StatusCode, code: &str) -> impl IntoResponse {
    api_error_with_message(status, code, "server detail is untrusted")
}

fn api_error_with_message(status: StatusCode, code: &str, message: &str) -> impl IntoResponse {
    (
        status,
        Json(json!({
            "ok": false,
            "status": status.as_u16(),
            "code": code,
            "message": message,
            "error": message,
            "requestId": "fake-request"
        })),
    )
}

async fn list_boxes(AxumState(state): AxumState<FakeState>) -> impl IntoResponse {
    *state.list_count.lock().await += 1;
    if let Some(message) = state.list_error_message.lock().await.clone() {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &message).into_response();
    }
    if *state.rate_limited.lock().await {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
    }
    let hide_winner = *state.hide_winner.lock().await;
    let boxes: Vec<BoxRecord> = state
        .boxes
        .lock()
        .await
        .values()
        .filter(|record| !(hide_winner && record.id == "winner"))
        .cloned()
        .collect();
    envelope(
        "box.list",
        json!({"boxes": boxes, "pageInfo": {"nextCursor": null}}),
    )
    .into_response()
}

async fn get_box(
    AxumState(state): AxumState<FakeState>,
    Path(box_id): Path<String>,
) -> impl IntoResponse {
    let boxes = state.boxes.lock().await;
    match boxes.get(&box_id) {
        Some(record) => envelope("box.get", json!({"box": record})).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "not_found").into_response(),
    }
}

async fn create_box(
    AxumState(state): AxumState<FakeState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    assert_eq!(body["noEnv"], true);
    assert_eq!(body["env"], json!({}));
    let mut count = state.create_count.lock().await;
    *count += 1;
    let id = format!("candidate-{count}");
    let record = BoxRecord {
        id: id.clone(),
        state: BoxState::Ready,
        subdomain: None,
        name: None,
        updated_at: Some(format!("created-{count}")),
    };
    state.boxes.lock().await.insert(id, record.clone());
    envelope("box.created", json!({"box": record})).into_response()
}

async fn update_box(
    AxumState(state): AxumState<FakeState>,
    Path(box_id): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if let Some((status, code)) = state.claim_error.lock().await.take() {
        if *state.reveal_winner_on_claim_error.lock().await {
            *state.hide_winner.lock().await = false;
        }
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return api_error(status, &code).into_response();
    }
    if *state.claim_conflict.lock().await {
        *state.claim_conflict.lock().await = false;
        *state.hide_winner.lock().await = false;
        return api_error(StatusCode::CONFLICT, "conflict").into_response();
    }
    let mut boxes = state.boxes.lock().await;
    let Some(record) = boxes.get_mut(&box_id) else {
        return api_error(StatusCode::NOT_FOUND, "not_found").into_response();
    };
    record.subdomain = body["subdomain"].as_str().map(str::to_string);
    if let Some(marker) = state.candidate_ownership_marker.lock().await.clone() {
        state.files.lock().await.insert(
            (
                box_id.clone(),
                "var/lib/buzz-agent/ownership.json".to_string(),
            ),
            marker,
        );
    }
    envelope("box.updated", json!({"box": record})).into_response()
}

async fn stop_box(
    AxumState(state): AxumState<FakeState>,
    Path(box_id): Path<String>,
) -> impl IntoResponse {
    *state.stop_count.lock().await += 1;
    let mut boxes = state.boxes.lock().await;
    let Some(record) = boxes.get_mut(&box_id) else {
        return api_error(StatusCode::NOT_FOUND, "not_found").into_response();
    };
    record.state = BoxState::Archived;
    envelope("box.stopping", json!({"box": record})).into_response()
}

async fn resume_box(
    AxumState(state): AxumState<FakeState>,
    Path(box_id): Path<String>,
    Json(_body): Json<Value>,
) -> impl IntoResponse {
    let mut boxes = state.boxes.lock().await;
    let Some(record) = boxes.get_mut(&box_id) else {
        return api_error(StatusCode::NOT_FOUND, "not_found").into_response();
    };
    record.state = BoxState::Ready;
    *state.service_active_after_resume.lock().await = true;
    envelope("box.resuming", json!({"box": record})).into_response()
}

async fn execute_command(
    AxumState(state): AxumState<FakeState>,
    Path(box_id): Path<String>,
    Json(body): Json<CommandRequest>,
) -> impl IntoResponse {
    state.commands.lock().await.push(body.command.clone());
    state
        .operations
        .lock()
        .await
        .push(format!("command:{}", body.command));
    state
        .command_timeouts
        .lock()
        .await
        .push(body.timeout_seconds.unwrap_or_default());
    let failure = {
        let mut configured = state.command_failure.lock().await;
        if configured
            .as_ref()
            .is_some_and(|(needle, _)| body.command.contains(needle))
        {
            configured.take()
        } else {
            None
        }
    };
    if let Some((_, stderr)) = failure {
        return envelope(
            "command.finished",
            json!({"success": false, "exitCode": 1, "stdout": "", "stderr": stderr, "timedOut": false, "stdoutTruncated": false, "stderrTruncated": false}),
        )
        .into_response();
    }
    if let Some((success, exit_code, stdout, timed_out)) = {
        let mut results = state.service_results.lock().await;
        (!results.is_empty()).then(|| results.remove(0))
    } {
        return envelope(
            "command.finished",
            json!({"success": success, "exitCode": exit_code, "stdout": stdout, "stderr": "", "timedOut": timed_out, "stdoutTruncated": false, "stderrTruncated": false}),
        )
        .into_response();
    }
    if body.command.contains("systemctl start buzz-agent.service") {
        *state.service_active.lock().await = true;
        state.files.lock().await.insert(
            (box_id.clone(), "run/buzz-agent/env-consumed".to_string()),
            "consumed".to_string(),
        );
        state.files.lock().await.insert(
            (box_id.clone(), "var/lib/buzz-agent/state.json".to_string()),
            json!({"started": true, "startup": "ready"}).to_string(),
        );
    }
    if body.command.contains("image-pull.status") {
        return envelope(
            "command.finished",
            json!({"success": true, "exitCode": 0, "stdout": "ready", "stderr": "", "timedOut": false, "stdoutTruncated": false, "stderrTruncated": false}),
        )
        .into_response();
    }
    if body
        .command
        .contains("stat -c '%u:%g:%a' /run/buzz-agent/env.pending")
    {
        return envelope(
            "command.finished",
            json!({"success": true, "exitCode": 0, "stdout": "0:0:600", "stderr": "", "timedOut": false, "stdoutTruncated": false, "stderrTruncated": false}),
        )
        .into_response();
    }
    if body.command.contains("rm -f /run/buzz-agent/env.pending") {
        let mut files = state.files.lock().await;
        files.remove(&(box_id.clone(), "run/buzz-agent/env.pending".to_string()));
        files.remove(&(box_id, "run/buzz-agent/env-consumed".to_string()));
    }
    let active =
        *state.service_active.lock().await || *state.service_active_after_resume.lock().await;
    let stdout = if active || body.command.contains("is-active") {
        "active"
    } else {
        "inactive"
    };
    envelope(
        "command.finished",
        json!({"success": true, "exitCode": 0, "stdout": stdout, "stderr": "", "timedOut": false, "stdoutTruncated": false, "stderrTruncated": false}),
    )
    .into_response()
}

async fn read_file(
    AxumState(state): AxumState<FakeState>,
    Path(box_id): Path<String>,
    query: axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let path = query.get("path").cloned().unwrap_or_default();
    state.read_paths.lock().await.push(path.clone());
    let files = state.files.lock().await;
    match files.get(&(box_id, path)) {
        Some(content) => envelope(
            "file.read",
            json!({"path": query.get("path"), "content": content, "encoding": "utf8"}),
        )
        .into_response(),
        None => api_error(StatusCode::NOT_FOUND, "not_found").into_response(),
    }
}

async fn write_file(
    AxumState(state): AxumState<FakeState>,
    Path(box_id): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let path = body["path"].as_str().unwrap_or("unknown").to_string();
    let content = body["content"].as_str().unwrap_or("unknown").to_string();
    let encoding = body["encoding"].as_str().unwrap_or("utf8").to_string();
    state.injected_files.lock().await.push(content.clone());
    state
        .file_writes
        .lock()
        .await
        .push((path.clone(), content.clone(), encoding.clone()));
    state.operations.lock().await.push(format!("file:{path}"));
    let stored_content = if encoding == "base64" {
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(&content)
                .unwrap_or_default(),
        )
        .unwrap_or_default()
    } else {
        content
    };
    state
        .files
        .lock()
        .await
        .insert((box_id, path.clone()), stored_content);
    envelope("file.written", json!({"path": path})).into_response()
}

async fn limits(AxumState(_state): AxumState<FakeState>) -> impl IntoResponse {
    envelope(
        "limits",
        json!({
            "accountState": "active",
            "active": 1,
            "maxActive": 4,
            "startsPerMinute": 5,
            "balance": "test"
        }),
    )
    .into_response()
}

fn router(state: FakeState) -> Router {
    Router::new()
        .route("/boxes", get(list_boxes).post(create_box))
        .route("/boxes/{box_id}", get(get_box).patch(update_box))
        .route("/boxes/{box_id}/stop", post(stop_box))
        .route("/boxes/{box_id}/resume", post(resume_box))
        .route("/boxes/{box_id}/commands", post(execute_command))
        .route("/boxes/{box_id}/files", get(read_file).put(write_file))
        .route("/limits", get(limits))
        .with_state(state)
}

async fn server(state: FakeState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake server should bind");
    let address = listener
        .local_addr()
        .expect("fake server should have an address");
    let task = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .await
            .expect("fake server should serve");
    });
    (format!("http://{address}"), task)
}

fn identity_and_request() -> (AgentIdentity, DeployRequest) {
    let keys = nostr::Keys::generate();
    let nsec = keys.secret_key().to_bech32().expect("key should encode");
    let identity = AgentIdentity::from_nsec(&nsec).expect("key should decode");
    let request = DeployRequest {
        agent: AgentPayload {
            relay_url: "wss://relay.example".to_string(),
            private_key_nsec: nsec,
            auth_tag: Some("auth-secret".to_string()),
            respond_to: None,
            respond_to_allowlist: None,
            env_vars: BTreeMap::from([(String::from("MODEL_KEY"), String::from("model-secret"))]),
            launch: None,
        },
        provider_config: Value::Null,
    };
    (identity, request)
}

fn owned_record(id: &str, state: BoxState, subdomain: String) -> BoxRecord {
    BoxRecord {
        id: id.to_string(),
        state,
        subdomain: Some(subdomain),
        name: None,
        updated_at: Some("v1".to_string()),
    }
}

async fn seed_owned_box(state: &FakeState, record: &BoxRecord, identity: &AgentIdentity) {
    state
        .boxes
        .lock()
        .await
        .insert(record.id.clone(), record.clone());
    state.files.lock().await.insert(
        (
            record.id.clone(),
            "var/lib/buzz-agent/ownership.json".to_string(),
        ),
        json!({"agent_pubkey": identity.pubkey_hex(), "managedBy": MANAGED_BY, "bindingVersion": BINDING_VERSION}).to_string(),
    );
}

#[tokio::test]
async fn live_owned_box_is_strict_noop_and_does_not_provision() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let record = owned_record("live-box", BoxState::Ready, prepared.subdomain.clone());
    seed_owned_box(&state, &record, &identity).await;
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let provisioner = RecordingProvisioner::default();

    let result = reconcile(
        &api,
        &prepared,
        &provisioner,
        ReconcileOptions {
            deadline: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("live Box should be a no-op");
    assert_eq!(result, "live-box");
    assert!(provisioner.calls.lock().await.is_empty());
    server_task.abort();
}

#[tokio::test]
async fn provisioning_box_observes_until_deadline_without_recycling() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let record = owned_record(
        "provisioning-box",
        BoxState::Provisioning,
        prepared.subdomain.clone(),
    );
    seed_owned_box(&state, &record, &identity).await;
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let result = reconcile(
        &api,
        &prepared,
        &RecordingProvisioner::default(),
        ReconcileOptions {
            deadline: Duration::from_millis(25),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await;
    assert!(matches!(result, Err(ReconcileError::Timeout { .. })));
    assert_eq!(*state.stop_count.lock().await, 0);
    server_task.abort();
}

#[tokio::test]
async fn archived_box_resumes_then_reaches_provisioner_seam() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let record = owned_record(
        "archived-box",
        BoxState::Archived,
        prepared.subdomain.clone(),
    );
    seed_owned_box(&state, &record, &identity).await;
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let provisioner = RecordingProvisioner::default();
    let result = reconcile(
        &api,
        &prepared,
        &provisioner,
        ReconcileOptions {
            deadline: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("fake provisioner starts the service");
    assert_eq!(result, "archived-box");
    assert_eq!(provisioner.calls.lock().await.as_slice(), ["archived-box"]);
    server_task.abort();
}

#[tokio::test]
async fn claim_loser_stops_candidate_and_adopts_live_winner_without_injection() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    *state.claim_conflict.lock().await = true;
    *state.hide_winner.lock().await = true;
    let winner = owned_record("winner", BoxState::Ready, prepared.subdomain.clone());
    seed_owned_box(&state, &winner, &identity).await;
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let provisioner = RecordingProvisioner::default();
    let result = reconcile(
        &api,
        &prepared,
        &provisioner,
        ReconcileOptions {
            deadline: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("claim loser should adopt winner");
    assert_eq!(result, "winner");
    assert_eq!(*state.stop_count.lock().await, 1);
    assert!(provisioner.calls.lock().await.is_empty());
    assert!(state.injected_files.lock().await.is_empty());
    server_task.abort();
}

#[tokio::test]
async fn rate_limit_error_is_typed_and_contains_no_raw_server_detail() {
    let state = FakeState::default();
    *state.rate_limited.lock().await = true;
    let (base_url, server_task) = server(state).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let error = api
        .list(&ListBoxesQuery::default())
        .await
        .expect_err("fake server should rate limit");
    assert!(matches!(error, BoxApiError::RateLimited { ref code, .. } if code == "rate_limited"));
    assert!(!error.to_string().contains("server detail"));
    server_task.abort();
}

#[tokio::test]
async fn file_and_limits_operations_return_typed_values() {
    let (base_url, server_task) = server(FakeState::default()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let write = api
        .write_file(
            "box-1",
            &buzz_backend_box::api::WriteFileRequest {
                path: "/tmp/test".to_string(),
                content: "safe".to_string(),
                encoding: "utf8".to_string(),
            },
        )
        .await
        .expect("file write should parse");
    assert_eq!(write.path.as_deref(), Some("/tmp/test"));
    let read = api
        .read_file("box-1", "/tmp/test", Some("utf8"))
        .await
        .expect("file read should parse");
    assert_eq!(read.content, "safe");
    let limits = api.limits().await.expect("limits should parse");
    assert_eq!(limits.active, Some(1));
    assert_eq!(limits.max_active, Some(4));
    server_task.abort();
}

#[tokio::test]
async fn failed_service_command_with_active_stdout_is_not_live() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let record = owned_record(
        "failed-command",
        BoxState::Ready,
        prepared.subdomain.clone(),
    );
    seed_owned_box(&state, &record, &identity).await;
    state
        .service_results
        .lock()
        .await
        .push((false, 1, "active".to_string(), false));
    let (base_url, server_task) = server(state).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");

    let observed = observe_box(&api, record, &identity)
        .await
        .expect("observation should complete")
        .expect("ownership should verify");
    assert_eq!(observed.service, ServiceState::Unknown);
    assert_ne!(observed.harness, HarnessState::Live);
    server_task.abort();
}

#[tokio::test]
async fn timed_out_service_command_with_active_stdout_is_not_live() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let record = owned_record(
        "timed-out-command",
        BoxState::Ready,
        prepared.subdomain.clone(),
    );
    seed_owned_box(&state, &record, &identity).await;
    state
        .service_results
        .lock()
        .await
        .push((true, 0, "active".to_string(), true));
    let (base_url, server_task) = server(state).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");

    let observed = observe_box(&api, record, &identity)
        .await
        .expect("observation should complete")
        .expect("ownership should verify");
    assert_eq!(observed.service, ServiceState::Unknown);
    assert_ne!(observed.harness, HarnessState::Live);
    server_task.abort();
}

#[tokio::test]
async fn fenced_stop_reobserves_before_archiving() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let record = owned_record("fenced-box", BoxState::Ready, prepared.subdomain.clone());
    seed_owned_box(&state, &record, &identity).await;
    state.service_results.lock().await.extend([
        (true, 0, "inactive".to_string(), false),
        (true, 0, "active".to_string(), false),
    ]);
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let result = reconcile(
        &api,
        &prepared,
        &RecordingProvisioner::default(),
        ReconcileOptions {
            deadline: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("changed observation should re-enter and converge");
    assert_eq!(result, "fenced-box");
    assert_eq!(*state.stop_count.lock().await, 0);
    server_task.abort();
}

#[tokio::test]
async fn gateway_error_retries_the_same_subdomain_claim() {
    let state = FakeState::default();
    *state.claim_error.lock().await = Some((502, "gateway_error".to_string()));
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    *state.candidate_ownership_marker.lock().await = Some(
        json!({"agent_pubkey": identity.pubkey_hex(), "managedBy": MANAGED_BY, "bindingVersion": BINDING_VERSION}).to_string(),
    );
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let provisioner = RecordingProvisioner::default();
    let result = reconcile(
        &api,
        &prepared,
        &provisioner,
        ReconcileOptions {
            deadline: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("gateway route activation should be retried");
    assert_eq!(result, "candidate-1");
    assert_eq!(provisioner.calls.lock().await.as_slice(), ["candidate-1"]);
    assert_eq!(*state.stop_count.lock().await, 0);
    server_task.abort();
}

#[tokio::test]
async fn rate_limited_claim_retries_without_losing_candidate() {
    let state = FakeState::default();
    *state.claim_error.lock().await = Some((429, "start_limit_reached".to_string()));
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    *state.candidate_ownership_marker.lock().await = Some(
        json!({"agent_pubkey": identity.pubkey_hex(), "managedBy": MANAGED_BY, "bindingVersion": BINDING_VERSION}).to_string(),
    );
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let result = reconcile(
        &api,
        &prepared,
        &RecordingProvisioner::default(),
        ReconcileOptions {
            deadline: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("rate-limited claim should be retried");
    assert_eq!(result, "candidate-1");
    assert_eq!(*state.stop_count.lock().await, 0);
    server_task.abort();
}

#[tokio::test]
async fn unknown_claim_error_verifies_winner_before_stopping_candidate() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    *state.claim_error.lock().await = Some((400, "validation_failed".to_string()));
    *state.reveal_winner_on_claim_error.lock().await = true;
    *state.hide_winner.lock().await = true;
    let winner = owned_record("winner", BoxState::Ready, prepared.subdomain.clone());
    seed_owned_box(&state, &winner, &identity).await;
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let result = reconcile(
        &api,
        &prepared,
        &RecordingProvisioner::default(),
        ReconcileOptions {
            deadline: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("verified winner should be adopted");
    assert_eq!(result, "winner");
    assert_eq!(*state.stop_count.lock().await, 1);
    assert!(*state.list_count.lock().await >= 3);
    server_task.abort();
}

#[tokio::test]
async fn auth_claim_error_is_actionable_and_does_not_stop_candidate() {
    let state = FakeState::default();
    *state.claim_error.lock().await = Some((401, "unauthorized".to_string()));
    let (_, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let error = reconcile(
        &api,
        &prepared,
        &RecordingProvisioner::default(),
        ReconcileOptions {
            deadline: Duration::from_millis(50),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect_err("authentication failure should be actionable");
    assert!(matches!(error, ReconcileError::Api(message) if message.contains("401")));
    assert_eq!(*state.stop_count.lock().await, 0);
    server_task.abort();
}

#[tokio::test]
async fn ambient_box_key_is_redacted_from_api_errors() {
    let state = FakeState::default();
    *state.list_error_message.lock().await = Some("BOX_KEY_fake-key-123".to_string());
    let (_, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let (base_url, server_task) = server(state).await;
    let api = BoxApi::with_api_key(base_url, "fake-key-123", Duration::from_secs(2))
        .expect("client should build");
    let error = reconcile(
        &api,
        &prepared,
        &RecordingProvisioner::default(),
        ReconcileOptions {
            deadline: Duration::from_millis(50),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect_err("fake server should return an API error");
    let rendered = error.to_string();
    assert!(
        !rendered.contains("fake-key-123"),
        "leaked error: {rendered}"
    );
    assert!(
        rendered.contains("[redacted]"),
        "rendered provisioning error: {rendered}"
    );
    server_task.abort();
}

#[tokio::test]
async fn marker_files_use_relative_box_workdir_paths() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let record = owned_record("relative-box", BoxState::Ready, prepared.subdomain.clone());
    state
        .boxes
        .lock()
        .await
        .insert(record.id.clone(), record.clone());
    state.files.lock().await.insert(
        (
            record.id.clone(),
            "var/lib/buzz-agent/ownership.json".to_string(),
        ),
        json!({"agent_pubkey": identity.pubkey_hex(), "managedBy": MANAGED_BY, "bindingVersion": BINDING_VERSION}).to_string(),
    );
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");
    let observed = observe_box(&api, record, &identity)
        .await
        .expect("relative marker read should complete")
        .expect("relative marker should verify ownership");
    assert_eq!(observed.id(), "relative-box");
    assert!(state
        .read_paths
        .lock()
        .await
        .iter()
        .all(|path| !path.starts_with('/')));
    server_task.abort();
}

#[tokio::test]
async fn real_provisioner_writes_secure_assets_injects_env_and_round_trips_to_noop() {
    let (identity, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");

    let result = reconcile(
        &api,
        &prepared,
        &BoxProvisioner,
        ReconcileOptions {
            deadline: Duration::from_secs(2),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect("real provisioner should confirm startup");
    assert_eq!(result, "candidate-1");

    let commands = state.commands.lock().await.clone();
    assert_eq!(
        commands.len(),
        13,
        "unexpected command sequence: {commands:?}"
    );
    assert!(commands[0].starts_with("install -d "));
    assert!(commands[1].starts_with("chown root:root /etc/systemd/system"));
    assert_eq!(commands[2], "systemctl daemon-reload");
    assert_eq!(commands[3], "systemctl enable buzz-agent.service");
    assert!(commands[4].contains("nohup sh -c"));
    assert!(commands[4].contains("docker pull --quiet"));
    assert_eq!(
        commands[5],
        "cat /var/lib/buzz-agent/image-pull.status 2>/dev/null || printf pending"
    );
    assert_eq!(
        commands[6],
        "install -o root -g root -m 666 /dev/null /run/buzz-agent/env-consumed"
    );
    assert!(commands[7].contains("chown root:root /run/buzz-agent/env.pending"));
    assert!(commands[8].contains("/var/lib/buzz-agent/stop-intent"));
    assert!(commands[8].contains("/var/lib/buzz-agent/state.json"));
    assert_eq!(commands[9], "systemctl start buzz-agent.service");
    assert_eq!(commands[10], "systemctl is-active buzz-agent.service");
    assert_eq!(
        commands[11],
        "rm -f /run/buzz-agent/env.pending /run/buzz-agent/env-consumed"
    );
    assert_eq!(commands[12], "systemctl is-active buzz-agent.service");

    let mut forbidden_values = prepared.env.values().cloned().collect::<Vec<_>>();
    forbidden_values.push(request.agent.private_key_nsec.clone());
    if let Some(auth_tag) = request.agent.auth_tag.clone() {
        forbidden_values.push(auth_tag);
    }
    for command in &commands {
        assert!(!command.contains("--env-file"));
        for value in &forbidden_values {
            assert!(
                !value.is_empty() && !command.contains(value),
                "secret in command: {command}"
            );
        }
    }
    assert!(state
        .command_timeouts
        .lock()
        .await
        .iter()
        .all(|timeout| *timeout <= 60));

    let writes = state.file_writes.lock().await.clone();
    assert_eq!(writes.len(), 11, "unexpected file writes: {writes:?}");
    assert!(writes.iter().all(|(path, _, _)| !path.starts_with('/')));
    let (_, env_payload, encoding) = writes
        .iter()
        .find(|(path, _, _)| path == "run/buzz-agent/env.pending")
        .expect("pending environment should be written");
    assert_eq!(encoding, "base64");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(env_payload)
        .expect("environment payload should be base64");
    assert_eq!(
        decoded,
        serde_json::to_vec(&prepared.env).expect("env should serialize canonically")
    );
    let auth_index = writes
        .iter()
        .position(|(path, _, _)| path == "run/buzz-agent/launch-authorized")
        .expect("launch authorization marker should be written");
    let env_index = writes
        .iter()
        .position(|(path, _, _)| path == "run/buzz-agent/env.pending")
        .expect("pending environment should be written");
    assert!(
        auth_index > env_index,
        "authorization must follow env setup"
    );
    assert_eq!(
        writes[auth_index].1,
        format!(
            "{}\n",
            prepared
                .env
                .get("BUZZ_MANAGED_AGENT_START_NONCE")
                .expect("launch nonce should be present")
        )
    );
    let operations = state.operations.lock().await.clone();
    let authorization_operation = operations
        .iter()
        .position(|operation| operation == "file:run/buzz-agent/launch-authorized")
        .expect("authorization operation should be recorded");
    let start_operation = operations
        .iter()
        .position(|operation| operation == "command:systemctl start buzz-agent.service")
        .expect("systemd start operation should be recorded");
    assert_eq!(
        authorization_operation + 1,
        start_operation,
        "launch authorization must be the final operation before systemd start: {operations:?}"
    );

    let files = state.files.lock().await.clone();
    assert!(!files.contains_key(&(
        "candidate-1".to_string(),
        "run/buzz-agent/env.pending".to_string()
    )));
    assert!(!files.contains_key(&(
        "candidate-1".to_string(),
        "run/buzz-agent/env-consumed".to_string()
    )));
    let ownership: Value = serde_json::from_str(
        files
            .get(&("candidate-1".to_string(), OWNERSHIP_MARKER_PATH.to_string()))
            .expect("ownership marker should be present"),
    )
    .expect("ownership marker should be JSON");
    assert_eq!(ownership["pubkey"], identity.pubkey_hex());
    assert_eq!(ownership["managed_by"], MANAGED_BY);
    assert_eq!(ownership["binding_version"], BINDING_VERSION);
    let expected_launch_intent = format!("{}\n", prepared.launch_intent.as_str());
    assert_eq!(
        files
            .get(&("candidate-1".to_string(), LAUNCH_INTENT_PATH.to_string()))
            .map(String::as_str),
        Some(expected_launch_intent.as_str())
    );

    let record = state
        .boxes
        .lock()
        .await
        .get("candidate-1")
        .cloned()
        .expect("candidate should remain present");
    let observed = observe_box(&api, record, &identity)
        .await
        .expect("round-trip observation should succeed")
        .expect("ownership should be verified");
    assert_eq!(
        observed.launch_intent.as_ref(),
        Some(&prepared.launch_intent)
    );
    assert_eq!(
        classify(Some(&observed), &prepared.launch_intent),
        Action::NoOp {
            agent_id: "candidate-1".to_string()
        }
    );
    server_task.abort();
}

#[tokio::test]
async fn provisioning_failure_redacts_error_and_removes_pending_secret_file() {
    let (_, request) = identity_and_request();
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    *state.command_failure.lock().await = Some((
        "systemctl start buzz-agent.service".to_string(),
        "startup failed while handling model-secret".to_string(),
    ));
    let (base_url, server_task) = server(state.clone()).await;
    let api = BoxApi::with_api_key(base_url, "fake-key", Duration::from_secs(2))
        .expect("client should build");

    let error = reconcile(
        &api,
        &prepared,
        &BoxProvisioner,
        ReconcileOptions {
            deadline: Duration::from_secs(2),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect_err("failed start should surface as a provisioning error");
    let rendered = error.to_string();
    for secret in [
        "model-secret",
        "auth-secret",
        request.agent.private_key_nsec.as_str(),
    ] {
        assert!(
            !rendered.contains(secret),
            "secret leaked in error: {rendered}"
        );
    }
    assert!(
        rendered.contains("[redacted]"),
        "rendered provisioning error: {rendered}"
    );
    assert!(state.commands.lock().await.last().is_some_and(
        |command| command == "rm -f /run/buzz-agent/env.pending /run/buzz-agent/env-consumed"
    ));
    assert!(!state.files.lock().await.contains_key(&(
        "candidate-1".to_string(),
        "run/buzz-agent/env.pending".to_string()
    )));
    server_task.abort();
}

#[tokio::test]
async fn provisioning_stderr_redacts_discarded_environment_tiers() {
    let (_, mut request) = identity_and_request();
    request.agent.env_vars.insert(
        "LEGACY_DISCARDED_SENTINEL".to_string(),
        "legacy-discarded-secret".to_string(),
    );
    request.agent.auth_tag = None;
    request.agent.launch = Some(buzz_backend_box::wire::LaunchBlock {
        command: None,
        args: Vec::new(),
        env: BTreeMap::from([
            (
                "BUZZ_AUTH_TAG".to_string(),
                "stripped-authoritative-secret".to_string(),
            ),
            (
                "LAUNCH_DISCARDED_SENTINEL".to_string(),
                "launch-secret".to_string(),
            ),
        ]),
        policy_env: BTreeMap::from([(
            "POLICY_DISCARDED_SENTINEL".to_string(),
            "policy-secret".to_string(),
        )]),
        owner_pubkey: Some("owner".to_string()),
    });
    let prepared = prepare_deploy(&request).expect("request should prepare");
    let state = FakeState::default();
    *state.command_failure.lock().await = Some((
        "systemctl start buzz-agent.service".to_string(),
        "startup failed: legacy-discarded-secret stripped-authoritative-secret launch-secret policy-secret fake-key-123".to_string(),
    ));
    let (base_url, server_task) = server(state).await;
    let api = BoxApi::with_api_key(base_url, "fake-key-123", Duration::from_secs(2))
        .expect("client should build");

    let error = reconcile(
        &api,
        &prepared,
        &BoxProvisioner,
        ReconcileOptions {
            deadline: Duration::from_secs(2),
            poll_interval: Duration::from_millis(1),
        },
    )
    .await
    .expect_err("failed start should surface as a provisioning error");
    let rendered = error.to_string();
    for secret in [
        "legacy-discarded-secret",
        "stripped-authoritative-secret",
        "launch-secret",
        "policy-secret",
        "fake-key-123",
    ] {
        assert!(
            !rendered.contains(secret),
            "secret leaked in error: {rendered}"
        );
    }
    assert!(
        rendered.contains("[redacted]"),
        "rendered error: {rendered}"
    );
    server_task.abort();
}

#[test]
fn classifier_fences_only_the_snapshot_that_authorized_replacement() {
    let observation = buzz_backend_box::classify::VerifiedBox {
        box_record: owned_record("box", BoxState::Ready, "buzz-box".to_string()),
        service: ServiceState::Inactive,
        harness: HarnessState::NeverStartedRecoverable,
        stop_intent: StopIntent::None,
        launch_intent: Some(Fingerprint::from_recorded("old")),
        presence: PresenceState::Stale,
        ownership: OwnershipMarker {
            pubkey: "a".repeat(64),
            managed_by: MANAGED_BY.to_string(),
            binding_version: BINDING_VERSION,
        },
    };
    match classify(Some(&observation), &Fingerprint::from_recorded("new")) {
        Action::FencedReplace {
            observation: snapshot,
            ..
        } => assert_eq!(*snapshot, observation),
        other => panic!("expected fenced replacement, got {other:?}"),
    }
}
