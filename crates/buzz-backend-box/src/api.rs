//! Typed client for the ASCII Box API v1.
//!
//! The API is deliberately kept at the edge of the provider. HTTP status and
//! the documented response envelope are interpreted here, while observation
//! and reconciliation consume typed, redacted values only.

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// The documented ASCII Box API base URL.
pub const DEFAULT_BASE_URL: &str = "https://ascii.dev/api/box/v1";
/// The default per-request timeout. Reconciliation has its own larger
/// deadline, but no individual provider call may wait indefinitely.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const CLI_CREDENTIAL_PATH: &str = ".config/ascii/box/config.json";

/// A source from which a Box API bearer credential can be obtained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialSource {
    /// Read `BOX_API_KEY` from the provider process environment.
    Environment,
    /// Read a token from an explicit Box CLI credential file.
    CliFile(PathBuf),
    /// A test or embedding supplied credential.
    Explicit,
}

/// A resolved bearer credential.
///
/// The token is intentionally not included in the `Debug` or `Display`
/// output. Callers should pass it directly to [`BoxApi::with_base_url`].
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedCredential {
    token: String,
    source: CredentialSource,
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedCredential")
            .field("source", &self.source)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl ResolvedCredential {
    /// Construct a credential supplied by an embedding or a test.
    pub fn explicit(token: impl Into<String>) -> Result<Self, BoxApiError> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err(BoxApiError::MissingCredential);
        }
        Ok(Self {
            token,
            source: CredentialSource::Explicit,
        })
    }

    /// Return the credential source without exposing the secret.
    pub fn source(&self) -> &CredentialSource {
        &self.source
    }

    /// Return the secret for authenticated HTTP request construction.
    fn token(&self) -> &str {
        &self.token
    }
}

/// Resolve the ambient provider credential: environment first, then the Box
/// CLI credential file at `~/.config/ascii/box/config.json`.
pub fn resolve_ambient_credential() -> Result<ResolvedCredential, BoxApiError> {
    if let Some(token) = std::env::var_os("BOX_API_KEY") {
        let token = token.to_string_lossy().trim().to_string();
        if !token.is_empty() {
            return Ok(ResolvedCredential {
                token,
                source: CredentialSource::Environment,
            });
        }
    }

    let home = std::env::var_os("HOME").ok_or(BoxApiError::MissingCredential)?;
    let path = PathBuf::from(home).join(CLI_CREDENTIAL_PATH);
    resolve_cli_credential_file(&path)
}

/// Resolve a Box CLI credential file. This function is public so tests and
/// embedders can exercise credential fallback without mutating process env.
pub fn resolve_cli_credential_file(path: &Path) -> Result<ResolvedCredential, BoxApiError> {
    let bytes = std::fs::read(path).map_err(|error| BoxApiError::CredentialFile {
        path: path.display().to_string(),
        detail: sanitize_detail(&error.to_string()),
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| BoxApiError::CredentialFile {
        path: path.display().to_string(),
        detail: "credential file is not valid JSON".to_string(),
    })?;

    let token = ["apiKey", "api_key", "accessToken", "access_token", "token"]
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| BoxApiError::CredentialFile {
            path: path.display().to_string(),
            detail: "credential file does not contain a supported token field".to_string(),
        })?;

    Ok(ResolvedCredential {
        token,
        source: CredentialSource::CliFile(path.to_path_buf()),
    })
}

/// The lifecycle states documented by ASCII Box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoxState {
    /// Box has been accepted but initialization has not started.
    Init,
    /// Box machine provisioning is in progress.
    Provisioning,
    /// Box resources have been provisioned.
    Provisioned,
    /// Snapshot cloning is in progress.
    Cloning,
    /// Box is ready for commands.
    Ready,
    /// Box is ready and not running a first-class Box prompt.
    Idle,
    /// Box is running a first-class Box prompt.
    Running,
    /// Box snapshot/archive is in progress.
    Archiving,
    /// Box is stopped and its latest snapshot is available.
    Archived,
    /// Box reached a provider-visible terminal error state.
    Error,
    /// A future API state that this provider does not yet understand.
    Unknown(String),
}

impl BoxState {
    /// Whether commands can safely be issued to the Box.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready | Self::Idle | Self::Running)
    }

    /// Return the wire spelling, preserving unknown future values.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Init => "init",
            Self::Provisioning => "provisioning",
            Self::Provisioned => "provisioned",
            Self::Cloning => "cloning",
            Self::Ready => "ready",
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Archiving => "archiving",
            Self::Archived => "archived",
            Self::Error => "error",
            Self::Unknown(value) => value,
        }
    }
}

impl<'de> Deserialize<'de> for BoxState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "init" => Self::Init,
            "provisioning" => Self::Provisioning,
            "provisioned" => Self::Provisioned,
            "cloning" => Self::Cloning,
            "ready" => Self::Ready,
            "idle" => Self::Idle,
            "running" => Self::Running,
            "archiving" => Self::Archiving,
            "archived" => Self::Archived,
            "error" => Self::Error,
            _ => Self::Unknown(value.chars().take(64).collect()),
        })
    }
}

impl Serialize for BoxState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// A typed Box returned by create, list, get, update, stop, and resume.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BoxRecord {
    /// Stable Box identifier.
    pub id: String,
    /// Current platform lifecycle state.
    pub state: BoxState,
    /// Claimed public subdomain, when present.
    #[serde(default)]
    pub subdomain: Option<String>,
    /// Optional platform display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Server-provided update marker when available.
    #[serde(default, alias = "updatedAt")]
    pub updated_at: Option<String>,
}

/// Request body for `POST /boxes`.
#[derive(Clone, Debug, Serialize)]
pub struct CreateBoxRequest {
    /// Whether account environment and credentials are withheld.
    #[serde(rename = "noEnv")]
    pub no_env: bool,
    /// Optional auto-stop TTL in seconds. `None` disables the platform TTL.
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: Option<u64>,
    /// Box machine size: `small`, `default`, or `large`.
    #[serde(rename = "type")]
    pub machine_type: String,
    /// Explicit non-secret environment values, normally empty for candidates.
    pub env: Map<String, Value>,
}

/// Request body for `PATCH /boxes/{boxId}`.
#[derive(Clone, Debug, Serialize)]
pub struct UpdateBoxRequest {
    /// The globally unique subdomain to claim.
    pub subdomain: String,
}

/// Request body for `POST /boxes/{boxId}/resume`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ResumeBoxRequest {
    /// Optional machine size during resume.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub machine_type: Option<String>,
    /// Keep the restored Box no-env.
    #[serde(rename = "noEnv", skip_serializing_if = "Option::is_none")]
    pub no_env: Option<bool>,
}

/// Query parameters for `GET /boxes`.
#[derive(Clone, Debug, Default)]
pub struct ListBoxesQuery {
    /// Comma-separated lifecycle state filter.
    pub state: Option<String>,
    /// Opaque cursor returned by the prior page.
    pub cursor: Option<String>,
    /// Page size, bounded by the API to 200.
    pub limit: Option<u16>,
}

/// A page returned by `GET /boxes`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoxListPage {
    /// Boxes in this page.
    pub boxes: Vec<BoxRecord>,
    /// Cursor for the next page, if any.
    pub next_cursor: Option<String>,
}

/// A command request for `POST /boxes/{boxId}/commands`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommandRequest {
    /// Shell command interpreted by the Box command API.
    pub command: String,
    /// Optional relative working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Command timeout, constrained by the API to 1 through 60 seconds.
    #[serde(rename = "timeoutSeconds", skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

/// The bounded result of a synchronous Box command.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct CommandResult {
    /// Whether the command completed successfully.
    #[serde(default)]
    pub success: bool,
    /// Process exit code, when one was available.
    #[serde(rename = "exitCode", default)]
    pub exit_code: Option<i32>,
    /// Signal name or number, when terminated by a signal.
    #[serde(default)]
    pub signal: Option<String>,
    /// Captured stdout. Callers must treat this as untrusted.
    #[serde(default)]
    pub stdout: String,
    /// Captured stderr. Callers must treat this as untrusted.
    #[serde(default)]
    pub stderr: String,
    /// Whether stdout was truncated by the platform.
    #[serde(rename = "stdoutTruncated", default)]
    pub stdout_truncated: bool,
    /// Whether stderr was truncated by the platform.
    #[serde(rename = "stderrTruncated", default)]
    pub stderr_truncated: bool,
    /// Whether the command exceeded its timeout.
    #[serde(rename = "timedOut", default)]
    pub timed_out: bool,
}

/// Request body for `PUT /boxes/{boxId}/files`.
#[derive(Clone, Debug, Serialize)]
pub struct WriteFileRequest {
    /// Relative path inside the Box work directory.
    pub path: String,
    /// File content in the selected encoding.
    pub content: String,
    /// `utf8` or `base64`.
    #[serde(default = "default_utf8")]
    pub encoding: String,
}

/// File contents returned by `GET /boxes/{boxId}/files`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct ReadFileResponse {
    /// Relative path that was read.
    #[serde(default)]
    pub path: String,
    /// File contents in the selected encoding.
    #[serde(default)]
    pub content: String,
    /// Encoding used by the response.
    #[serde(default = "default_utf8")]
    pub encoding: String,
}

/// Acknowledgement returned by `PUT /boxes/{boxId}/files`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct WriteFileResponse {
    /// Relative path accepted by the Box API.
    #[serde(default)]
    pub path: Option<String>,
}

/// Account limits returned by `GET /limits`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct BoxLimits {
    /// Account status, when supplied by the API.
    #[serde(default, alias = "accountState")]
    pub account_state: Option<String>,
    /// Current active Box count.
    #[serde(default)]
    pub active: Option<u64>,
    /// Maximum concurrent active Boxes.
    #[serde(default, alias = "maxActive")]
    pub max_active: Option<u64>,
    /// Start rate or quota description.
    #[serde(default, alias = "startsPerMinute")]
    pub starts_per_minute: Option<u64>,
    /// Current balance, represented as an API string when available.
    #[serde(default)]
    pub balance: Option<String>,
}

fn default_utf8() -> String {
    "utf8".to_string()
}

/// Errors produced by credential resolution, HTTP transport, or Box's typed
/// error envelope.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BoxApiError {
    /// No ambient or explicit credential was available.
    #[error("BOX_API_KEY is not set and the Box CLI credential file was not usable")]
    MissingCredential,
    /// The CLI credential file could not be read or parsed.
    #[error("could not read Box CLI credential file {path}: {detail}")]
    CredentialFile { path: String, detail: String },
    /// The request could not be sent or its response could not be read.
    #[error("Box API transport failure ({kind})")]
    Transport { kind: String },
    /// The per-call timeout elapsed.
    #[error("Box API request timed out")]
    Timeout,
    /// The API returned a documented rate-limit response.
    #[error("Box API rate limit reached ({code})")]
    RateLimited {
        /// Machine-readable API code.
        code: String,
        /// Optional server retry hint.
        retry_after_seconds: Option<u64>,
        /// Request correlation id, if present.
        request_id: Option<String>,
    },
    /// The API returned a structured non-success response.
    #[error("Box API request failed with HTTP {status} ({code})")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Machine-readable API error code.
        code: String,
        /// Sanitized, bounded human-readable detail.
        message: String,
        /// Request correlation id, if present.
        request_id: Option<String>,
    },
    /// The server returned a success status without the required envelope.
    #[error("Box API returned an invalid success envelope")]
    InvalidEnvelope,
    /// A successful response did not contain the expected typed payload.
    #[error("Box API response did not contain the expected {resource} payload")]
    InvalidPayload {
        /// Expected payload name.
        resource: &'static str,
    },
}

impl BoxApiError {
    /// Whether this error represents a 4xx/5xx response that may have lost a
    /// subdomain claim. The API has not published atomic conflict semantics,
    /// so reconciliation treats every HTTP error from PATCH as claim loss.
    pub fn is_http_failure(&self) -> bool {
        matches!(self, Self::Http { .. } | Self::RateLimited { .. })
    }

    /// Return the HTTP status when this is a structured API response.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }
}

/// A small, authenticated, timeout-bounded Box API client.
#[derive(Clone)]
pub struct BoxApi {
    http: reqwest::Client,
    base_url: String,
    credential: ResolvedCredential,
}

impl fmt::Debug for BoxApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxApi")
            .field("base_url", &self.base_url)
            .field("credential", &self.credential)
            .finish()
    }
}

impl BoxApi {
    /// Build a client using ambient credentials and the production endpoint.
    pub fn from_ambient() -> Result<Self, BoxApiError> {
        Self::with_base_url(
            DEFAULT_BASE_URL,
            resolve_ambient_credential()?,
            DEFAULT_REQUEST_TIMEOUT,
        )
    }

    /// Build a client with an explicit token and overridable endpoint.
    pub fn with_api_key(
        base_url: impl Into<String>,
        token: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, BoxApiError> {
        Self::with_base_url(base_url, ResolvedCredential::explicit(token)?, timeout)
    }

    /// Build a client from a resolved credential.
    pub fn with_base_url(
        base_url: impl Into<String>,
        credential: ResolvedCredential,
        timeout: Duration,
    ) -> Result<Self, BoxApiError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(BoxApiError::Transport {
                kind: "Box API base URL is empty".to_string(),
            });
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| BoxApiError::Transport {
                kind: "could not construct HTTP client".to_string(),
            })?;
        Ok(Self {
            http,
            base_url,
            credential,
        })
    }

    /// Return the configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Create a no-env or explicitly configured Box.
    pub async fn create(&self, request: &CreateBoxRequest) -> Result<BoxRecord, BoxApiError> {
        let value = self
            .send_json(Method::POST, "/boxes", Some(request), None)
            .await?;
        extract_box(&value)
    }

    /// List one page of Boxes with optional state and cursor filters.
    pub async fn list(&self, query: &ListBoxesQuery) -> Result<BoxListPage, BoxApiError> {
        let mut params = Vec::new();
        if let Some(state) = query.state.as_deref() {
            params.push(("state", state.to_string()));
        }
        if let Some(cursor) = query.cursor.as_deref() {
            params.push(("cursor", cursor.to_string()));
        }
        if let Some(limit) = query.limit {
            params.push(("limit", limit.to_string()));
        }
        let value = self
            .send_json(Method::GET, "/boxes", None::<&Value>, Some(&params))
            .await?;
        extract_box_page(&value)
    }

    /// List all pages, preserving the requested lifecycle state filter.
    pub async fn list_all(&self, state: Option<&str>) -> Result<Vec<BoxRecord>, BoxApiError> {
        let mut boxes = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .list(&ListBoxesQuery {
                    state: state.map(str::to_string),
                    cursor,
                    limit: Some(200),
                })
                .await?;
            boxes.extend(page.boxes);
            match page.next_cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => break,
            }
        }
        Ok(boxes)
    }

    /// Fetch one Box by id.
    pub async fn get(&self, box_id: &str) -> Result<BoxRecord, BoxApiError> {
        let value = self
            .send_json(
                Method::GET,
                &format!("/boxes/{box_id}"),
                None::<&Value>,
                None,
            )
            .await?;
        extract_box(&value)
    }

    /// Update the deterministic subdomain claim.
    pub async fn update(
        &self,
        box_id: &str,
        request: &UpdateBoxRequest,
    ) -> Result<BoxRecord, BoxApiError> {
        let value = self
            .send_json(
                Method::PATCH,
                &format!("/boxes/{box_id}"),
                Some(request),
                None,
            )
            .await?;
        extract_box(&value)
    }

    /// Begin stopping and archiving a Box.
    pub async fn stop(&self, box_id: &str) -> Result<BoxRecord, BoxApiError> {
        let value = self
            .send_json(
                Method::POST,
                &format!("/boxes/{box_id}/stop"),
                Some(&Value::Object(Map::new())),
                None,
            )
            .await?;
        extract_box(&value)
    }

    /// Resume an archived Box.
    pub async fn resume(
        &self,
        box_id: &str,
        request: &ResumeBoxRequest,
    ) -> Result<BoxRecord, BoxApiError> {
        let value = self
            .send_json(
                Method::POST,
                &format!("/boxes/{box_id}/resume"),
                Some(request),
                None,
            )
            .await?;
        extract_box(&value)
    }

    /// Execute a bounded command inside a Box.
    pub async fn execute(
        &self,
        box_id: &str,
        request: &CommandRequest,
    ) -> Result<CommandResult, BoxApiError> {
        let value = self
            .send_json(
                Method::POST,
                &format!("/boxes/{box_id}/commands"),
                Some(request),
                None,
            )
            .await?;
        extract_payload(&value, "command", "commandResult")
    }

    /// Write a UTF-8 or base64 file inside a Box.
    pub async fn write_file(
        &self,
        box_id: &str,
        request: &WriteFileRequest,
    ) -> Result<WriteFileResponse, BoxApiError> {
        let value = self
            .send_json(
                Method::PUT,
                &format!("/boxes/{box_id}/files"),
                Some(request),
                None,
            )
            .await?;
        extract_payload(&value, "file", "writeFile")
    }

    /// Read a UTF-8 or base64 file inside a Box.
    pub async fn read_file(
        &self,
        box_id: &str,
        path: &str,
        encoding: Option<&str>,
    ) -> Result<ReadFileResponse, BoxApiError> {
        let mut params = vec![("path", path.to_string())];
        if let Some(encoding) = encoding {
            params.push(("encoding", encoding.to_string()));
        }
        let value = self
            .send_json(
                Method::GET,
                &format!("/boxes/{box_id}/files"),
                None::<&Value>,
                Some(&params),
            )
            .await?;
        extract_payload(&value, "file", "readFile")
    }

    /// Fetch current account and machine-start limits.
    pub async fn limits(&self) -> Result<BoxLimits, BoxApiError> {
        let value = self
            .send_json(Method::GET, "/limits", None::<&Value>, None)
            .await?;
        extract_payload(&value, "limits", "limits")
    }

    async fn send_json<T: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        query: Option<&[(&str, String)]>,
    ) -> Result<Value, BoxApiError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(self.credential.token());
        if let Some(body) = body {
            request = request.json(body);
        }
        if let Some(query) = query {
            request = request.query(query);
        }
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() {
                BoxApiError::Timeout
            } else {
                BoxApiError::Transport {
                    kind: sanitize_detail(&error.to_string()),
                }
            }
        })?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        let bytes = response
            .bytes()
            .await
            .map_err(|error| BoxApiError::Transport {
                kind: sanitize_detail(&error.to_string()),
            })?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| BoxApiError::InvalidEnvelope)?;
        if !status.is_success() || value.get("ok") == Some(&Value::Bool(false)) {
            return Err(parse_error(status, &value, retry_after));
        }
        if value.get("ok") != Some(&Value::Bool(true)) {
            return Err(BoxApiError::InvalidEnvelope);
        }
        Ok(value)
    }
}

fn extract_box(value: &Value) -> Result<BoxRecord, BoxApiError> {
    extract_payload(value, "box", "box")
}

fn extract_box_page(value: &Value) -> Result<BoxListPage, BoxApiError> {
    let source = value.get("data").unwrap_or(value);
    let boxes_value = source
        .get("boxes")
        .or_else(|| value.get("boxes"))
        .ok_or(BoxApiError::InvalidPayload { resource: "boxes" })?;
    let boxes = serde_json::from_value(boxes_value.clone())
        .map_err(|_| BoxApiError::InvalidPayload { resource: "boxes" })?;
    let next_cursor = source
        .get("pageInfo")
        .and_then(|page| page.get("nextCursor"))
        .or_else(|| {
            value
                .get("pageInfo")
                .and_then(|page| page.get("nextCursor"))
        })
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(BoxListPage { boxes, next_cursor })
}

fn extract_payload<T: DeserializeOwned>(
    value: &Value,
    field: &'static str,
    resource: &'static str,
) -> Result<T, BoxApiError> {
    let source = value
        .get(field)
        .or_else(|| value.get("data").and_then(|data| data.get(field)))
        .or_else(|| value.get("data"))
        .or_else(|| value.get("result"));
    source
        .cloned()
        .ok_or(BoxApiError::InvalidPayload { resource })
        .and_then(|payload| {
            serde_json::from_value(payload).map_err(|_| BoxApiError::InvalidPayload { resource })
        })
}

fn parse_error(status: StatusCode, value: &Value, retry_after: Option<u64>) -> BoxApiError {
    let code = value
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("http_error")
        .to_string();
    let message = value
        .get("message")
        .or_else(|| value.get("error"))
        .and_then(Value::as_str)
        .map(sanitize_detail)
        .unwrap_or_else(|| "Box API returned an error".to_string());
    let request_id = value
        .get("requestId")
        .and_then(Value::as_str)
        .map(sanitize_detail);
    if status == StatusCode::TOO_MANY_REQUESTS
        || code == "rate_limited"
        || code == "start_limit_reached"
    {
        return BoxApiError::RateLimited {
            code,
            retry_after_seconds: retry_after,
            request_id,
        };
    }
    BoxApiError::Http {
        status: status.as_u16(),
        code,
        message,
        request_id,
    }
}

fn sanitize_detail(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(256)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_all_documented_states_and_preserves_unknown() {
        let values = [
            ("init", BoxState::Init),
            ("provisioning", BoxState::Provisioning),
            ("provisioned", BoxState::Provisioned),
            ("cloning", BoxState::Cloning),
            ("ready", BoxState::Ready),
            ("idle", BoxState::Idle),
            ("running", BoxState::Running),
            ("archiving", BoxState::Archiving),
            ("archived", BoxState::Archived),
            ("error", BoxState::Error),
            ("future", BoxState::Unknown("future".to_string())),
        ];
        for (raw, expected) in values {
            let actual: BoxState =
                serde_json::from_str(&format!("\"{raw}\"")).expect("state JSON should parse");
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn cli_credential_resolution_never_leaks_token_in_debug() {
        let path = std::env::temp_dir().join(format!("buzz-box-credential-{}", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("temporary credential file should open");
        writeln!(file, "{{\"apiKey\":\"secret-token\"}}").expect("fixture should write");
        let credential = resolve_cli_credential_file(&path).expect("credential should parse");
        let debug = format!("{credential:?}");
        assert!(!debug.contains("secret-token"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rate_limit_codes_are_typed() {
        let error = parse_error(
            StatusCode::TOO_MANY_REQUESTS,
            &serde_json::json!({
                "ok": false,
                "code": "start_limit_reached",
                "message": "too many starts",
                "requestId": "req-1"
            }),
            Some(7),
        );
        assert_eq!(
            error,
            BoxApiError::RateLimited {
                code: "start_limit_reached".to_string(),
                retry_after_seconds: Some(7),
                request_id: Some("req-1".to_string())
            }
        );
    }

    #[test]
    fn error_detail_is_bounded_and_control_free() {
        let error = parse_error(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"code":"bad","message":"secret\u{0000}\n"}),
            None,
        );
        match error {
            BoxApiError::Http { message, .. } => assert_eq!(message, "secret\n"),
            _ => panic!("expected HTTP error"),
        }
    }
}
