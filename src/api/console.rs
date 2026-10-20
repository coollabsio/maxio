use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use futures::TryStreamExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};

use crate::auth::signature_v4;
use crate::server::AppState;
use crate::storage::filesystem::FilesystemStorage;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "maxio_session";

/// Sessions logout has already accepted. The set is written to the data
/// directory so a restart does not make a revoked cookie valid again.
///
/// `{data_dir}/.maxio-revoked-sessions.ready` is created with the revocation
/// file on first start. A later process that finds the marker but no readable
/// revocation file treats every session issued at or before that start as
/// revoked. A data directory that has neither file has no prior revocations.
#[derive(Clone)]
pub struct RevokedSessions {
    path: Option<std::path::PathBuf>,
    /// jti → unix expiry. Expired entries are dropped on load and on revoke.
    entries: Arc<Mutex<HashMap<String, i64>>>,
    /// Sessions with `issued_at <= not_before` are rejected. Set when the
    /// revocation file is missing after first start, or is unreadable or corrupt.
    not_before: Arc<Mutex<Option<i64>>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RevocationFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_before: Option<i64>,
    #[serde(default)]
    entries: Vec<RevocationEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RevocationEntry {
    jti: String,
    expires_at: i64,
}

const REVOKED_SESSIONS_FILE: &str = ".maxio-revoked-sessions.json";
const REVOKED_SESSIONS_MARKER: &str = ".maxio-revoked-sessions.ready";

enum LoadedRevocations {
    Missing,
    Unreadable(String),
    Corrupt(String),
    Ready(RevocationFile),
}

impl RevokedSessions {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            path: None,
            entries: Arc::new(Mutex::new(HashMap::new())),
            not_before: Arc::new(Mutex::new(None)),
        }
    }

    /// Load `{data_dir}/.maxio-revoked-sessions.json`, dropping expired rows.
    ///
    /// The first successful open writes an empty revocation file and a marker.
    /// A missing, unreadable, or corrupt file after that marker exists fails
    /// closed: `not_before` is this process's start time.
    pub async fn open(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join(REVOKED_SESSIONS_FILE);
        let marker = data_dir.join(REVOKED_SESSIONS_MARKER);
        let now = chrono::Utc::now().timestamp();
        let loaded = load_revocation_file(&path).await;
        let marker_exists = tokio::fs::try_exists(&marker).await.unwrap_or(false);

        let (map, not_before, write, failed_closed) = match loaded {
            LoadedRevocations::Ready(file) => {
                let mut map: HashMap<String, i64> = file
                    .entries
                    .into_iter()
                    .map(|entry| (entry.jti, entry.expires_at))
                    .collect();
                let before = map.len();
                map.retain(|_, exp| *exp > now);
                let pruned = map.len() != before;
                (map, file.not_before, pruned || !marker_exists, false)
            }
            LoadedRevocations::Missing if !marker_exists => (HashMap::new(), None, true, false),
            LoadedRevocations::Missing => {
                tracing::warn!("{}", revocation_deleted_warning(&path, &marker));
                (HashMap::new(), Some(now), true, true)
            }
            LoadedRevocations::Unreadable(err) => {
                tracing::warn!(
                    "{}",
                    revocation_fail_closed_warning(&path, &format!("unreadable ({err})"))
                );
                (HashMap::new(), Some(now), true, true)
            }
            LoadedRevocations::Corrupt(err) => {
                tracing::warn!(
                    "{}",
                    revocation_fail_closed_warning(&path, &format!("corrupt ({err})"))
                );
                (HashMap::new(), Some(now), true, true)
            }
        };

        let store = Self {
            path: Some(path),
            entries: Arc::new(Mutex::new(map)),
            not_before: Arc::new(Mutex::new(not_before)),
        };
        if write {
            if let Err(err) = store.persist().await {
                if failed_closed {
                    tracing::error!(
                        "failed to record the session epoch in {}: {err}. Sessions issued at or before this process start stay revoked until the process exits.",
                        store
                            .path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    );
                } else {
                    tracing::error!(
                        "failed to create the revoked-sessions file {}: {err}. A later logout cannot be saved until this path is writable.",
                        store
                            .path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    );
                }
            }
        }
        store
    }

    /// Unix time at or before which issued sessions are rejected.
    pub fn session_epoch(&self) -> Option<i64> {
        match self.not_before.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Record a logout. The session is revoked in memory even when the file
    /// cannot be replaced. The error is the write failure.
    pub async fn revoke(&self, jti: &str, expires_at: i64) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp();
        {
            let mut guard = match self.entries.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.retain(|_, exp| *exp > now);
            guard.insert(jti.to_string(), expires_at);
        }
        if let Err(err) = self.persist().await {
            let where_ = self
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| REVOKED_SESSIONS_FILE.to_string());
            tracing::error!(
                "failed to write revoked sessions to {where_}: {err}. The session is revoked in this process only."
            );
            return Err(err);
        }
        Ok(())
    }

    pub fn contains(&self, jti: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(jti).is_some_and(|exp| *exp > now)
    }

    /// True when this cookie was logged out or was issued at or before a
    /// fail-closed session epoch.
    pub fn rejects(&self, issued_at: i64, jti: &str) -> bool {
        if self.session_epoch().is_some_and(|cut| issued_at <= cut) {
            return true;
        }
        self.contains(jti)
    }

    async fn persist(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let (entries, not_before) = {
            let guard = match self.entries.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let not_before = match self.not_before.lock() {
                Ok(guard) => *guard,
                Err(poisoned) => *poisoned.into_inner(),
            };
            let entries = guard
                .iter()
                .map(|(jti, expires_at)| RevocationEntry {
                    jti: jti.clone(),
                    expires_at: *expires_at,
                })
                .collect();
            (entries, not_before)
        };
        let body = serde_json::to_vec_pretty(&RevocationFile {
            not_before,
            entries,
        })
        .map_err(|err| err.to_string())?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|err| err.to_string())?;
        }
        let tmp = path.with_extension("json.tmp");
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }
        {
            use tokio::io::AsyncWriteExt;
            let mut file = opts
                .open(&tmp)
                .await
                .map_err(|err| format!("cannot write {}: {err}", tmp.display()))?;
            file.write_all(&body)
                .await
                .map_err(|err| format!("cannot write {}: {err}", tmp.display()))?;
            file.sync_all()
                .await
                .map_err(|err| format!("cannot sync {}: {err}", tmp.display()))?;
        }
        tokio::fs::rename(&tmp, path).await.map_err(|err| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot replace {}: {err}", path.display())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|err| format!("cannot set permissions on {}: {err}", path.display()))?;
        }
        let marker = path.with_file_name(REVOKED_SESSIONS_MARKER);
        if !tokio::fs::try_exists(&marker).await.unwrap_or(false) {
            let mut marker_opts = tokio::fs::OpenOptions::new();
            marker_opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                marker_opts.mode(0o600);
            }
            marker_opts.open(&marker).await.map_err(|err| {
                format!(
                    "cannot write session-store marker {}: {err}",
                    marker.display()
                )
            })?;
        }
        Ok(())
    }
}

fn revocation_fail_closed_warning(path: &std::path::Path, reason: &str) -> String {
    format!(
        "revoked-sessions file {} is {reason}. Failing closed: every console session issued at or before this process start is revoked",
        path.display()
    )
}

fn revocation_deleted_warning(path: &std::path::Path, marker: &std::path::Path) -> String {
    format!(
        "revoked-sessions file {} is missing, but {} shows this data directory already had a session store. Failing closed: every console session issued at or before this process start is revoked",
        path.display(),
        marker.display()
    )
}

async fn load_revocation_file(path: &std::path::Path) -> LoadedRevocations {
    match tokio::fs::metadata(path).await {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => LoadedRevocations::Missing,
        Err(err) => LoadedRevocations::Unreadable(err.to_string()),
        Ok(meta) if meta.is_dir() => {
            LoadedRevocations::Unreadable("path is a directory".to_string())
        }
        Ok(_) => match tokio::fs::read_to_string(path).await {
            Err(err) => LoadedRevocations::Unreadable(err.to_string()),
            Ok(raw) => match serde_json::from_str::<RevocationFile>(&raw) {
                Ok(file) => LoadedRevocations::Ready(file),
                Err(err) => LoadedRevocations::Corrupt(err.to_string()),
            },
        },
    }
}
const TOKEN_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60; // 7 days

const RATE_LIMIT_MAX: u32 = 10;
const RATE_LIMIT_WINDOW_SECS: u64 = 300; // 5 minutes

struct Bucket {
    count: u32,
    window_start: Instant,
}

pub struct LoginRateLimiter {
    buckets: std::sync::Mutex<HashMap<String, Bucket>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns `Some(retry_after_secs)` if the IP is rate-limited, `None` if allowed.
    /// Increments the counter on every call (success and failure both count).
    pub fn check_and_increment(&self, ip: &str) -> Option<u64> {
        let mut map = self.buckets.lock().unwrap();
        let now = Instant::now();

        // Prune expired entries to prevent unbounded memory growth
        map.retain(|_, b| {
            now.duration_since(b.window_start).as_secs() < RATE_LIMIT_WINDOW_SECS * 2
        });

        let bucket = map.entry(ip.to_string()).or_insert(Bucket {
            count: 0,
            window_start: now,
        });

        if now.duration_since(bucket.window_start).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            bucket.count = 0;
            bucket.window_start = now;
        }

        bucket.count += 1;

        if bucket.count > RATE_LIMIT_MAX {
            let remaining = RATE_LIMIT_WINDOW_SECS
                .saturating_sub(now.duration_since(bucket.window_start).as_secs());
            Some(remaining.max(1))
        } else {
            None
        }
    }
}

fn extract_client_ip(headers: &HeaderMap, addr: &SocketAddr) -> String {
    let _ = headers;
    // Public console: do not trust spoofable X-Forwarded-For unless/until a
    // trusted-proxy allowlist is configured. Use the connected peer IP.
    addr.ip().to_string()
}

fn extract_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with(&format!("{}=", COOKIE_NAME)))
                .map(|c| c[COOKIE_NAME.len() + 1..].to_string())
        })
}

fn make_cookie(value: &str, max_age: i64, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };

    format!(
        "{}={}; Path=/maxio; HttpOnly; SameSite=Strict; Max-Age={}{}",
        COOKIE_NAME, value, max_age, secure_flag
    )
}

#[derive(Serialize, ToSchema)]
pub struct OkResponse {
    ok: bool,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    ok: bool,
    root: bool,
    iam_admin: bool,
    /// `root`, `user`, or `service`.
    kind: String,
    user_name: Option<String>,
    label: Option<String>,
    access_key_id: String,
}

fn session_response(identity: &crate::iam::ConsoleIdentity) -> SessionResponse {
    SessionResponse {
        ok: true,
        root: identity.authenticated.principal.is_root(),
        iam_admin: identity.iam_admin,
        kind: identity.kind.to_string(),
        user_name: identity.user_name.clone(),
        label: identity.label.clone(),
        access_key_id: identity.access_key_id.clone(),
    }
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    error: String,
}

/// Raw object bytes (upload body and download response).
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
#[allow(dead_code)]
pub struct BinaryBody(Vec<u8>);

fn ok() -> Response {
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

async fn console_auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(token) = extract_cookie(request.headers()) else {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    if let Some(parsed) = crate::iam::session::parse_token(&token) {
        if state
            .revoked_sessions
            .rejects(parsed.issued_at, parsed.revocation_id())
        {
            return error(StatusCode::UNAUTHORIZED, "Not authenticated");
        }
    }
    let identity = match crate::iam::console_from_token(&state.config, &token).await {
        Ok(identity) => identity,
        Err(()) => return error(StatusCode::UNAUTHORIZED, "Not authenticated"),
    };
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let method = request.method().to_string();
    if let Err(err) = crate::api::authz::authorize_console(
        &state,
        &identity.authenticated.principal,
        &method,
        &path,
        &query,
    )
    .await
    {
        let status = err.code.status_code();
        return error(status, err.message);
    }
    let mut request = request;
    request
        .extensions_mut()
        .insert(identity.authenticated.clone());
    next.run(request).await
}

#[derive(Serialize, ToSchema)]
pub struct ServerVersion {
    version: &'static str,
}

#[utoipa::path(
    get,
    path = "/maxio/api/version",
    operation_id = "getServerVersion",
    tag = "meta",
    responses(
        (status = 200, description = "Running server version", body = ServerVersion),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn server_version() -> Json<ServerVersion> {
    Json(ServerVersion {
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    access_key: String,
    secret_key: String,
}

#[utoipa::path(
    post,
    path = "/maxio/api/auth/login",
    operation_id = "login",
    tag = "auth",
    security(()),
    request_body = LoginRequest,
    responses(
        (status = 200, body = SessionResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 403, description = "Access key or user is disabled", body = ErrorResponse),
        (status = 429, description = "Too many login attempts", body = ErrorResponse),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let ip = extract_client_ip(&headers, &addr);

    if let Some(retry_after) = state.login_rate_limiter.check_and_increment(&ip) {
        return (
            [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
            error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts. Try again later.",
            ),
        )
            .into_response();
    }

    let identity = match crate::iam::login(&state.config, &body.access_key, &body.secret_key).await
    {
        Ok(identity) => identity,
        Err(crate::iam::LoginError::Disabled) => {
            return error(
                StatusCode::FORBIDDEN,
                "This access key is inactive or the user is disabled",
            );
        }
        Err(crate::iam::LoginError::Invalid) => {
            return error(StatusCode::UNAUTHORIZED, "Invalid credentials");
        }
    };
    let token = match crate::iam::issue_session_token(&state.config, &identity).await {
        Ok(token) => token,
        Err(()) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Could not start session"),
    };
    let cookie = make_cookie(
        &token,
        TOKEN_MAX_AGE_SECS,
        console_cookie_secure(&state.config, &headers),
    );

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Set-Cookie", cookie.parse().unwrap());
    (resp_headers, Json(session_response(&identity))).into_response()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CapabilityParams {
    /// When set, `putObject` and `deleteObject` are evaluated under this prefix.
    bucket: Option<String>,
    prefix: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    create_bucket: bool,
    delete_bucket: bool,
    put_object: bool,
    delete_object: bool,
}

#[utoipa::path(
    get,
    path = "/maxio/api/auth/capabilities",
    operation_id = "getCapabilities",
    tag = "auth",
    params(CapabilityParams),
    responses((status = 200, body = Capabilities))
)]
pub async fn capabilities(
    State(state): State<AppState>,
    authn: Option<axum::extract::Extension<crate::iam::Authenticated>>,
    Query(params): Query<CapabilityParams>,
) -> Response {
    let Some(axum::extract::Extension(authn)) = authn else {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    match crate::iam::console_capabilities(
        &state.config,
        &authn.principal,
        params.bucket.as_deref(),
        params.prefix.as_deref(),
    )
    .await
    {
        Ok(caps) => (
            StatusCode::OK,
            Json(Capabilities {
                create_bucket: caps.create_bucket,
                delete_bucket: caps.delete_bucket,
                put_object: caps.put_object,
                delete_object: caps.delete_object,
            }),
        )
            .into_response(),
        Err(err) => internal(err),
    }
}

#[utoipa::path(
    get,
    path = "/maxio/api/auth/check",
    operation_id = "checkAuth",
    tag = "auth",
    security(()),
    responses(
        (status = 200, body = SessionResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn check(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = extract_cookie(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    if let Some(parsed) = crate::iam::session::parse_token(&token) {
        if state
            .revoked_sessions
            .rejects(parsed.issued_at, parsed.revocation_id())
        {
            return error(StatusCode::UNAUTHORIZED, "Not authenticated");
        }
    }
    match crate::iam::console_from_token(&state.config, &token).await {
        Ok(identity) => (StatusCode::OK, Json(session_response(&identity))).into_response(),
        Err(()) => error(StatusCode::UNAUTHORIZED, "Not authenticated"),
    }
}

#[utoipa::path(
    post,
    path = "/maxio/api/auth/logout",
    operation_id = "logout",
    tag = "auth",
    responses(
        (status = 200, body = OkResponse),
        (status = 500, description = "The session was revoked in memory but could not be saved", body = ErrorResponse)
    )
)]
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut saved = true;
    if let Some(token) = extract_cookie(&headers) {
        if let Some(parsed) = crate::iam::session::parse_token(&token) {
            let expires_at = parsed
                .issued_at
                .saturating_add(crate::iam::session::TOKEN_MAX_AGE_SECS);
            if let Err(err) = state
                .revoked_sessions
                .revoke(parsed.revocation_id(), expires_at)
                .await
            {
                tracing::error!(
                    "logout revoked the session in memory but could not save it: {err}"
                );
                saved = false;
            }
        }
    }
    let cookie = make_cookie("", 0, console_cookie_secure(&state.config, &headers));
    if saved {
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("Set-Cookie", cookie.parse().unwrap());
        return (resp_headers, ok()).into_response();
    }
    let mut resp = error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "session was revoked in memory but could not be saved",
    );
    if let Ok(value) = cookie.parse() {
        resp.headers_mut().insert("Set-Cookie", value);
    }
    resp
}

async fn console_csrf_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let mutating = matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    );
    if mutating {
        let headers = request.headers();
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let origin = headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .or_else(|| headers.get("referer").and_then(|v| v.to_str().ok()));
        if let Some(origin) = origin {
            if !same_origin_host(origin, host) && !dev_loopback_origin_allowed(&state, origin, host)
            {
                return error(StatusCode::FORBIDDEN, "CSRF origin check failed");
            }
        }
    }
    let mut response = next.run(request).await;
    apply_security_headers(response.headers_mut());
    response
}

fn same_origin_host(origin_or_referer: &str, host: &str) -> bool {
    origin_host(origin_or_referer)
        .map(|h| h.eq_ignore_ascii_case(host))
        .unwrap_or(false)
}

fn dev_loopback_origin_allowed(state: &AppState, origin_or_referer: &str, host: &str) -> bool {
    state.config.allow_insecure_dev
        && origin_host(origin_or_referer)
            .map(|origin_host| is_loopback_host(origin_host) && is_loopback_host(host))
            .unwrap_or(false)
}

fn origin_host(origin_or_referer: &str) -> Option<&str> {
    origin_or_referer
        .strip_prefix("https://")
        .or_else(|| origin_or_referer.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
}

/// Whether the console session cookie should carry `Secure`.
///
/// `Secure` is required when the browser is on HTTPS (`X-Forwarded-Proto: https`)
/// and for any non-loopback host. Plain HTTP to `localhost` / `127.0.0.1` / `::1`
/// omits it: browsers drop `Secure` cookies on `http://` pages, so the flag would
/// only break the documented local login. It does not make a public HTTP console
/// store a session — that still needs TLS or `MAXIO_SECURE_COOKIES=false`.
/// `--allow-insecure-dev` also omits `Secure` on every host.
fn console_cookie_secure(config: &crate::config::Config, headers: &HeaderMap) -> bool {
    if !config.secure_cookies || config.allow_insecure_dev {
        return false;
    }
    if forwarded_proto_is_https(headers) {
        return true;
    }
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    !is_loopback_host(host)
}

/// First entry of `X-Forwarded-Proto` (proxies may send `https,http`).
fn forwarded_proto_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("https"))
}

fn is_loopback_host(host_with_optional_port: &str) -> bool {
    let host = host_with_optional_port
        .strip_prefix('[')
        .and_then(|rest| rest.split(']').next())
        .unwrap_or_else(|| {
            host_with_optional_port
                .split(':')
                .next()
                .unwrap_or(host_with_optional_port)
        });

    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "same-origin".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BucketSummary {
    name: String,
    created_at: String,
    versioning: bool,
    encryption: bool,
    /// Anonymous GetObject allowed (bucket policy).
    public_read: bool,
    /// Anonymous ListBucket allowed (bucket policy).
    public_list: bool,
    /// Number of bucket tags.
    tag_count: u32,
    /// Caller may call DeleteBucket on this bucket.
    can_delete: bool,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BucketListResponse {
    buckets: Vec<BucketSummary>,
    /// Caller may create a bucket.
    create_bucket: bool,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets",
    operation_id = "listBuckets",
    tag = "buckets",
    responses(
        (status = 200, body = BucketListResponse),
        (status = 500, body = ErrorResponse),
    )
)]
pub async fn list_buckets(
    State(state): State<AppState>,
    authn: Option<axum::extract::Extension<crate::iam::Authenticated>>,
) -> Response {
    let Some(axum::extract::Extension(authn)) = authn else {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    match state.storage.list_buckets().await {
        Ok(buckets) => {
            let mut visible = Vec::new();
            for bucket in buckets {
                match crate::iam::bucket_visible(&state.config, &authn.principal, &bucket.name)
                    .await
                {
                    Ok(true) => visible.push(bucket),
                    Ok(false) => {}
                    Err(err) => return internal(err),
                }
            }
            let create_bucket =
                match crate::iam::console_capabilities(&state.config, &authn.principal, None, None)
                    .await
                {
                    Ok(caps) => caps.create_bucket,
                    Err(err) => return internal(err),
                };
            let mut buckets = Vec::with_capacity(visible.len());
            for b in visible {
                let can_delete = match crate::iam::console_capabilities(
                    &state.config,
                    &authn.principal,
                    Some(&b.name),
                    None,
                )
                .await
                {
                    Ok(caps) => caps.delete_bucket,
                    Err(err) => return internal(err),
                };
                buckets.push(BucketSummary {
                    name: b.name,
                    created_at: b.created_at,
                    versioning: b.versioning,
                    encryption: b.encryption_config.is_some(),
                    public_read: b.public_read,
                    public_list: b.public_list,
                    tag_count: b.tags.as_ref().map_or(0, |t| t.len() as u32),
                    can_delete,
                });
            }
            (
                StatusCode::OK,
                Json(BucketListResponse {
                    buckets,
                    create_bucket,
                }),
            )
                .into_response()
        }
        Err(e) => internal(e),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateBucketRequest {
    name: String,
}

#[utoipa::path(
    post,
    path = "/maxio/api/buckets",
    operation_id = "createBucket",
    tag = "buckets",
    request_body = CreateBucketRequest,
    responses(
        (status = 200, body = OkResponse),
        (status = 400, description = "Invalid bucket name", body = ErrorResponse),
        (status = 409, description = "Bucket already exists", body = ErrorResponse),
    )
)]
pub async fn create_bucket(
    State(state): State<AppState>,
    authn: Option<axum::extract::Extension<crate::iam::Authenticated>>,
    Json(body): Json<CreateBucketRequest>,
) -> Response {
    let Some(axum::extract::Extension(authn)) = authn else {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    if let Some(reason) = crate::storage::bucket_name_error(&body.name) {
        return error(StatusCode::BAD_REQUEST, reason);
    }
    if let Err(err) = crate::api::authz::authorize_s3(
        &state,
        &authn.principal,
        "s3:CreateBucket",
        &body.name,
        None,
        None,
    )
    .await
    {
        return error(err.code.status_code(), err.message);
    }
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let meta = crate::storage::BucketMeta {
        name: body.name.clone(),
        created_at: now,
        region: state.config.region.clone(),
        versioning: false,
        cors_rules: None,
        encryption_config: None,
        public_read: false,
        public_list: false,
        versioning_suspended: false,
        tags: None,
        lifecycle: None,
    };

    match state.storage.create_bucket(&meta).await {
        Ok(true) => ok(),
        Ok(false) => error(StatusCode::CONFLICT, "Bucket already exists"),
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    delete,
    path = "/maxio/api/buckets/{bucket}",
    operation_id = "deleteBucket",
    tag = "buckets",
    params(("bucket" = String, Path)),
    responses(
        (status = 200, body = OkResponse),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
        (status = 409, description = "Bucket is not empty", body = ErrorResponse),
    )
)]
pub async fn delete_bucket_api(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Response {
    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => ok(),
        Ok(false) => error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(crate::storage::StorageError::BucketNotEmpty) => {
            error(StatusCode::CONFLICT, "Bucket is not empty")
        }
        Err(e) => internal(e),
    }
}

/// Returns an error response unless the bucket exists.
async fn require_bucket(state: &AppState, bucket: &str) -> Result<(), Response> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(error(StatusCode::NOT_FOUND, "Bucket not found")),
        Err(e) => Err(internal(e)),
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListObjectsParams {
    prefix: Option<String>,
    /// Defaults to `/`.
    delimiter: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectSummary {
    key: String,
    size: u64,
    last_modified: String,
    etag: String,
    content_type: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectListResponse {
    files: Vec<ObjectSummary>,
    prefixes: Vec<String>,
    /// Prefixes that only contain a folder marker.
    empty_prefixes: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/objects",
    operation_id = "listObjects",
    tag = "objects",
    params(("bucket" = String, Path), ListObjectsParams),
    responses(
        (status = 200, body = ObjectListResponse),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsParams>,
) -> Response {
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }

    let prefix = params.prefix.unwrap_or_default();
    let delimiter = params.delimiter.unwrap_or_else(|| "/".to_string());

    let all_objects = match state.storage.list_objects(&bucket, &prefix).await {
        Ok(objects) => objects,
        Err(e) => return internal(e),
    };

    let mut files = Vec::new();
    let mut prefix_set = BTreeSet::new();

    for obj in &all_objects {
        let suffix = &obj.key[prefix.len()..];
        if let Some(pos) = suffix.find(delimiter.as_str()) {
            let common = format!("{}{}", prefix, &suffix[..pos + delimiter.len()]);
            prefix_set.insert(common);
        } else if !obj.key.ends_with('/') {
            files.push(ObjectSummary {
                key: obj.key.clone(),
                size: obj.size,
                last_modified: obj.last_modified.clone(),
                etag: obj.etag.clone(),
                content_type: obj.content_type.clone(),
            });
        }
    }

    // Determine which prefixes are empty (only contain a folder marker, no real objects)
    let empty_prefixes = prefix_set
        .iter()
        .filter(|p| {
            !all_objects
                .iter()
                .any(|obj| obj.key.starts_with(p.as_str()) && obj.key != **p)
        })
        .cloned()
        .collect();

    (
        StatusCode::OK,
        Json(ObjectListResponse {
            files,
            prefixes: prefix_set.into_iter().collect(),
            empty_prefixes,
        }),
    )
        .into_response()
}

#[derive(Serialize, ToSchema)]
pub struct UploadResponse {
    ok: bool,
    etag: String,
    size: u64,
}

#[utoipa::path(
    put,
    path = "/maxio/api/buckets/{bucket}/upload/{key}",
    operation_id = "uploadObject",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
    ),
    request_body(content = BinaryBody, content_type = "application/octet-stream"),
    responses(
        (status = 200, body = UploadResponse),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn upload_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let stream = body.into_data_stream();
    let reader = tokio_util::io::StreamReader::new(
        stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );

    let encryption = match bucket_default_encryption(&state, &bucket).await {
        Ok(encryption) => encryption,
        Err(resp) => return resp,
    };

    match state
        .storage
        .put_object(
            &bucket,
            &key,
            content_type,
            Box::pin(reader),
            None,
            encryption,
        )
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(UploadResponse {
                ok: true,
                etag: result.etag,
                size: result.size,
            }),
        )
            .into_response(),
        Err(e) => {
            if matches!(e, crate::storage::StorageError::EntityTooLarge) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "upload exceeds the maximum object size",
                );
            }
            internal(e)
        }
    }
}

async fn bucket_default_encryption(
    state: &AppState,
    bucket: &str,
) -> Result<Option<crate::storage::EncryptionRequest>, Response> {
    match state.storage.get_bucket_encryption(bucket).await {
        Ok(Some(cfg)) => Ok(Some(crate::api::object::encryption_from_bucket_default(
            &cfg,
        ))),
        Ok(None) => Ok(None),
        Err(e) => Err(internal(format!("failed to read bucket encryption: {}", e))),
    }
}

#[utoipa::path(
    delete,
    path = "/maxio/api/buckets/{bucket}/objects/{key}",
    operation_id = "deleteObject",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
    ),
    responses(
        (status = 200, body = OkResponse),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn delete_object_api(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }

    match state.storage.delete_object(&bucket, &key).await {
        Ok(_) => {
            match preserve_empty_parent_folder_after_object_delete(&state.storage, &bucket, &key)
                .await
            {
                Ok(()) => ok(),
                Err(e) => internal(e),
            }
        }
        Err(e) => internal(e),
    }
}

fn parent_folder_prefix_for_deleted_object(key: &str) -> Option<String> {
    if key.ends_with('/') {
        return None;
    }
    key.rfind('/')
        .map(|idx| key[..=idx].to_string())
        .filter(|prefix| !prefix.is_empty())
}

async fn preserve_empty_parent_folder_after_object_delete(
    storage: &FilesystemStorage,
    bucket: &str,
    key: &str,
) -> Result<(), String> {
    let Some(parent_prefix) = parent_folder_prefix_for_deleted_object(key) else {
        return Ok(());
    };

    let remaining = storage
        .list_objects(bucket, &parent_prefix)
        .await
        .map_err(|e| e.to_string())?;

    let parent_still_exists = remaining
        .iter()
        .any(|obj| obj.key == parent_prefix || obj.key.starts_with(&parent_prefix));
    if parent_still_exists {
        return Ok(());
    }

    storage
        .put_object(
            bucket,
            &parent_prefix,
            "application/x-directory",
            Box::pin(tokio::io::empty()),
            None,
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/download/{key}",
    operation_id = "downloadObject",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
    ),
    responses(
        (status = 200, body = BinaryBody, content_type = "application/octet-stream"),
        (status = 404, description = "Object not found", body = ErrorResponse),
    )
)]
pub async fn download_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    match state.storage.get_object(&bucket, &key, None).await {
        Ok((reader, meta)) => attachment_response(&key, reader, &meta),
        Err(_) => error(StatusCode::NOT_FOUND, "Object not found"),
    }
}

fn attachment_response(
    key: &str,
    reader: crate::storage::ByteStream,
    meta: &crate::storage::ObjectMeta,
) -> Response {
    let filename = key.rsplit('/').next().unwrap_or(key);
    let safe_filename = sanitize_filename(filename);
    let stream = tokio_util::io::ReaderStream::with_capacity(reader, 256 * 1024);
    let body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", safe_filename),
        )
        .body(body)
        .unwrap()
        .into_response()
}

/// Sanitize a filename for use in Content-Disposition headers.
/// Removes characters that could enable header injection.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '"' && *c != '\\' && *c != '\r' && *c != '\n')
        .collect()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PresignParams {
    /// Expiry in seconds. Defaults to 3600, max 604800.
    expires: Option<u64>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PresignResponse {
    url: String,
    expires_in: u64,
}

async fn signing_credentials(
    state: &AppState,
    principal: &crate::iam::Principal,
) -> Result<(String, String), Response> {
    if principal.is_root() {
        return Ok((
            state.config.access_key.clone(),
            state.config.secret_key.clone(),
        ));
    }
    let access_key_id = principal
        .access_key_id(&state.config.access_key)
        .to_string();
    let store = match crate::iam::store::store_for(&state.config).await {
        Ok(store) => store,
        Err(err) => return Err(internal(err)),
    };
    match store.lookup_key(&access_key_id).await {
        Some(key) => Ok((access_key_id, key.secret)),
        None => Err(error(
            StatusCode::UNAUTHORIZED,
            "Access key no longer exists",
        )),
    }
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/presign/{key}",
    operation_id = "presignObject",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
        PresignParams,
    ),
    responses(
        (status = 200, body = PresignResponse),
        (status = 404, description = "Object not found", body = ErrorResponse),
    )
)]
pub async fn presign_object(
    State(state): State<AppState>,
    authn: Option<axum::extract::Extension<crate::iam::Authenticated>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PresignParams>,
    headers: HeaderMap,
) -> Response {
    let Some(axum::extract::Extension(authn)) = authn else {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    // Verify object exists
    if state.storage.head_object(&bucket, &key).await.is_err() {
        return error(StatusCode::NOT_FOUND, "Object not found");
    }

    let expires_secs = params.expires.unwrap_or(3600).min(604800);

    // Determine the host from the request
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:9000");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let region = &state.config.region;
    let (access_key, secret_key) = match signing_credentials(&state, &authn.principal).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let credential = format!("{}/{}/{}/s3/aws4_request", access_key, date_stamp, region);

    const S3_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    let encode =
        |s: &str| -> String { percent_encoding::utf8_percent_encode(s, S3_ENCODE).to_string() };

    // URI-encode each path segment per AWS SigV4 spec. The bucket/key values
    // arrive decoded from Axum's Path extractor, so we must encode them for
    // both the canonical request and the presigned URL.
    let encoded_key: String = key
        .split('/')
        .map(|s| encode(s))
        .collect::<Vec<_>>()
        .join("/");
    let path = format!("/{}/{}", encode(&bucket), encoded_key);

    // Build query string params (sorted alphabetically, excluding Signature)
    let qs_params = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential.clone()),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires_secs.to_string()),
        ("X-Amz-SignedHeaders", "host".to_string()),
    ];

    let canonical_qs: String = qs_params
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = format!("host:{}\n", host);
    let canonical_request = format!(
        "GET\n{}\n{}\n{}\nhost\nUNSIGNED-PAYLOAD",
        path, canonical_qs, canonical_headers
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope, canonical_hash
    );

    let signing_key = signature_v4::derive_signing_key(&secret_key, &date_stamp, region);

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // Determine scheme
    let scheme = if headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "https")
        .unwrap_or(false)
    {
        "https"
    } else {
        "http"
    };

    let url = format!(
        "{}://{}{}?{}&X-Amz-Signature={}",
        scheme, host, path, canonical_qs, signature
    );

    (
        StatusCode::OK,
        Json(PresignResponse {
            url,
            expires_in: expires_secs,
        }),
    )
        .into_response()
}

#[derive(Deserialize, ToSchema)]
pub struct CreateFolderRequest {
    name: String,
}

#[utoipa::path(
    post,
    path = "/maxio/api/buckets/{bucket}/folders",
    operation_id = "createFolder",
    tag = "objects",
    params(("bucket" = String, Path)),
    request_body = CreateFolderRequest,
    responses(
        (status = 200, body = OkResponse),
        (status = 400, description = "Folder name is required", body = ErrorResponse),
    )
)]
pub async fn create_folder(
    State(state): State<AppState>,
    authn: Option<axum::extract::Extension<crate::iam::Authenticated>>,
    Path(bucket): Path<String>,
    Json(body): Json<CreateFolderRequest>,
) -> Response {
    let Some(axum::extract::Extension(authn)) = authn else {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    let name = body.name.trim().trim_matches('/');
    if name.is_empty() {
        return error(StatusCode::BAD_REQUEST, "Folder name is required");
    }

    let key = format!("{}/", name);
    if let Err(err) = crate::api::authz::authorize_s3(
        &state,
        &authn.principal,
        "s3:PutObject",
        &bucket,
        Some(&key),
        None,
    )
    .await
    {
        return error(err.code.status_code(), err.message);
    }
    let encryption = match bucket_default_encryption(&state, &bucket).await {
        Ok(encryption) => encryption,
        Err(resp) => return resp,
    };
    match state
        .storage
        .put_object(
            &bucket,
            &key,
            "application/x-directory",
            Box::pin(tokio::io::empty()),
            None,
            encryption,
        )
        .await
    {
        Ok(_) => ok(),
        Err(e) => internal(e),
    }
}

#[derive(Serialize, ToSchema)]
pub struct EnabledResponse {
    enabled: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct SetEnabledRequest {
    enabled: bool,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/versioning",
    operation_id = "getVersioning",
    tag = "settings",
    params(("bucket" = String, Path)),
    responses((status = 200, body = EnabledResponse))
)]
pub async fn get_versioning(State(state): State<AppState>, Path(bucket): Path<String>) -> Response {
    match state.storage.is_versioned(&bucket).await {
        Ok(enabled) => (StatusCode::OK, Json(EnabledResponse { enabled })).into_response(),
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    put,
    path = "/maxio/api/buckets/{bucket}/versioning",
    operation_id = "setVersioning",
    tag = "settings",
    params(("bucket" = String, Path)),
    request_body = SetEnabledRequest,
    responses((status = 200, body = OkResponse))
)]
pub async fn set_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<SetEnabledRequest>,
) -> Response {
    match state.storage.set_versioning(&bucket, body.enabled).await {
        Ok(()) => ok(),
        Err(e) => internal(e),
    }
}

#[derive(Serialize, ToSchema)]
pub struct EncryptionResponse {
    enabled: bool,
    #[schema(required = true)]
    algorithm: Option<String>,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/encryption",
    operation_id = "getEncryption",
    tag = "settings",
    params(("bucket" = String, Path)),
    responses((status = 200, body = EncryptionResponse))
)]
pub async fn get_encryption(State(state): State<AppState>, Path(bucket): Path<String>) -> Response {
    match state.storage.get_bucket_encryption(&bucket).await {
        Ok(cfg) => (
            StatusCode::OK,
            Json(EncryptionResponse {
                enabled: cfg.is_some(),
                algorithm: cfg.map(|cfg| cfg.sse_algorithm),
            }),
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    put,
    path = "/maxio/api/buckets/{bucket}/encryption",
    operation_id = "setEncryption",
    tag = "settings",
    params(("bucket" = String, Path)),
    request_body = SetEnabledRequest,
    responses((status = 200, body = OkResponse))
)]
pub async fn set_encryption(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<SetEnabledRequest>,
) -> Response {
    let result = if body.enabled {
        let cfg = crate::storage::BucketEncryptionConfig {
            sse_algorithm: "AES256".to_string(),
        };
        state.storage.put_bucket_encryption(&bucket, cfg).await
    } else {
        state.storage.delete_bucket_encryption(&bucket).await
    };
    match result {
        Ok(()) => ok(),
        Err(e) => internal(e),
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PublicAccess {
    read: bool,
    list: bool,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/public",
    operation_id = "getPublicAccess",
    tag = "settings",
    params(("bucket" = String, Path)),
    responses((status = 200, body = PublicAccess))
)]
pub async fn get_public(State(state): State<AppState>, Path(bucket): Path<String>) -> Response {
    match state.storage.get_bucket_public(&bucket).await {
        Ok((read, list)) => (StatusCode::OK, Json(PublicAccess { read, list })).into_response(),
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    put,
    path = "/maxio/api/buckets/{bucket}/public",
    operation_id = "setPublicAccess",
    tag = "settings",
    params(("bucket" = String, Path)),
    request_body = PublicAccess,
    responses((status = 200, body = OkResponse))
)]
pub async fn set_public(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<PublicAccess>,
) -> Response {
    match state
        .storage
        .set_bucket_public(&bucket, body.read, body.list)
        .await
    {
        Ok(()) => ok(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListVersionsParams {
    key: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectVersion {
    #[schema(required = true)]
    version_id: Option<String>,
    last_modified: String,
    size: u64,
    etag: String,
    is_delete_marker: bool,
}

#[derive(Serialize, ToSchema)]
pub struct VersionListResponse {
    versions: Vec<ObjectVersion>,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/versions",
    operation_id = "listVersions",
    tag = "versions",
    params(("bucket" = String, Path), ListVersionsParams),
    responses((status = 200, body = VersionListResponse))
)]
pub async fn list_versions(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListVersionsParams>,
) -> Response {
    let all = match state
        .storage
        .list_object_versions(&bucket, &params.key)
        .await
    {
        Ok(v) => v,
        Err(e) => return internal(e),
    };

    // Filter to only versions matching this exact key
    let versions = all
        .into_iter()
        .filter(|v| v.key == params.key)
        .map(|v| ObjectVersion {
            version_id: v.version_id,
            last_modified: v.last_modified,
            size: v.size,
            etag: v.etag,
            is_delete_marker: v.is_delete_marker,
        })
        .collect();

    (StatusCode::OK, Json(VersionListResponse { versions })).into_response()
}

#[utoipa::path(
    delete,
    path = "/maxio/api/buckets/{bucket}/versions/{versionId}/objects/{key}",
    operation_id = "deleteVersion",
    tag = "versions",
    params(
        ("bucket" = String, Path),
        ("versionId" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
    ),
    responses((status = 200, body = OkResponse))
)]
pub async fn delete_version(
    State(state): State<AppState>,
    Path((bucket, version_id, key)): Path<(String, String, String)>,
) -> Response {
    match state
        .storage
        .delete_object_version(&bucket, &key, &version_id)
        .await
    {
        Ok(_) => ok(),
        Err(crate::storage::StorageError::InvalidKey(msg)) => error(StatusCode::BAD_REQUEST, msg),
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/versions/{versionId}/download/{key}",
    operation_id = "downloadVersion",
    tag = "versions",
    params(
        ("bucket" = String, Path),
        ("versionId" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
    ),
    responses(
        (status = 200, body = BinaryBody, content_type = "application/octet-stream"),
        (status = 404, description = "Version not found", body = ErrorResponse),
    )
)]
pub async fn download_version(
    State(state): State<AppState>,
    Path((bucket, version_id, key)): Path<(String, String, String)>,
) -> Response {
    match state
        .storage
        .get_object_version(&bucket, &key, &version_id, None)
        .await
    {
        Ok((reader, meta)) => attachment_response(&key, reader, &meta),
        Err(_) => error(StatusCode::NOT_FOUND, "Version not found"),
    }
}

// --- Object details, tags, bucket tags, policy view, version restore ---------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct VersionParams {
    /// Target a specific version instead of the current object.
    version_id: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct TagEntry {
    key: String,
    value: String,
}

/// A tag set (`GET` response and `PUT` body). An empty list clears the tags.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct TagSetBody {
    tags: Vec<TagEntry>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum StorageFormat {
    /// Single object file. Encryption is reported separately. A key that is also
    /// a prefix stores this file at `{key}/.maxio.object` (`inlinePayload`).
    Plain,
    /// Split into checksummed chunks.
    Chunked,
    /// Chunked with erasure-coding parity shards.
    Erasure,
}

#[derive(Serialize, ToSchema)]
pub struct ObjectChecksum {
    /// `CRC32`, `CRC32C`, `CRC64NVME`, `SHA1` or `SHA256`.
    algorithm: String,
    #[schema(required = true)]
    value: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub enum EncryptionModeName {
    #[serde(rename = "SSE-S3")]
    SseS3,
    #[serde(rename = "SSE-C")]
    SseC,
}

/// Server-side encryption summary. Key material is never exposed.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectEncryption {
    mode: EncryptionModeName,
    /// Master key id that wraps the object key (SSE-S3 only).
    #[schema(required = true)]
    key_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectInfo {
    key: String,
    size: u64,
    etag: String,
    content_type: String,
    last_modified: String,
    #[schema(required = true)]
    version_id: Option<String>,
    is_delete_marker: bool,
    storage_format: StorageFormat,
    /// Bytes are at `{key}/.maxio.object` because this key is also a prefix.
    inline_payload: bool,
    /// Number of parts for multipart uploads.
    #[schema(required = true)]
    part_count: Option<u32>,
    #[schema(required = true)]
    checksum: Option<ObjectChecksum>,
    #[schema(required = true)]
    encryption: Option<ObjectEncryption>,
    /// User-defined `x-amz-meta-*` metadata (names without the prefix).
    user_metadata: std::collections::BTreeMap<String, String>,
    #[schema(required = true)]
    cache_control: Option<String>,
    #[schema(required = true)]
    content_disposition: Option<String>,
    #[schema(required = true)]
    content_encoding: Option<String>,
    #[schema(required = true)]
    content_language: Option<String>,
    #[schema(required = true)]
    expires: Option<String>,
    tags: Vec<TagEntry>,
}

fn sorted_tags<I: IntoIterator<Item = (String, String)>>(tags: I) -> Vec<TagEntry> {
    let mut out: Vec<TagEntry> = tags
        .into_iter()
        .map(|(key, value)| TagEntry { key, value })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

fn object_info(meta: crate::storage::ObjectMeta, inline_payload: bool) -> ObjectInfo {
    use crate::storage::EncryptionMode;
    let storage_format = match meta.storage_format.as_deref() {
        None => StorageFormat::Plain,
        Some("chunked-v2") => StorageFormat::Erasure,
        Some(_) => StorageFormat::Chunked,
    };
    let checksum = meta.checksum_algorithm.map(|algo| ObjectChecksum {
        algorithm: format!("{:?}", algo),
        value: meta.checksum_value.clone(),
    });
    let encryption = meta.encryption.as_ref().map(|enc| match enc.mode {
        EncryptionMode::SseS3 => ObjectEncryption {
            mode: EncryptionModeName::SseS3,
            key_id: enc.key_id.clone(),
        },
        EncryptionMode::SseC => ObjectEncryption {
            mode: EncryptionModeName::SseC,
            key_id: None,
        },
    });
    ObjectInfo {
        part_count: meta.part_sizes.as_ref().map(|p| p.len() as u32),
        storage_format,
        inline_payload,
        checksum,
        encryption,
        user_metadata: meta.metadata.user_metadata.unwrap_or_default(),
        tags: sorted_tags(meta.tags.unwrap_or_default()),
        key: meta.key,
        size: meta.size,
        etag: meta.etag,
        content_type: meta.content_type,
        last_modified: meta.last_modified,
        version_id: meta.version_id,
        is_delete_marker: meta.is_delete_marker,
        cache_control: meta.metadata.cache_control,
        content_disposition: meta.metadata.content_disposition,
        content_encoding: meta.metadata.content_encoding,
        content_language: meta.metadata.content_language,
        expires: meta.metadata.expires,
    }
}

fn object_storage_error(e: crate::storage::StorageError) -> Response {
    use crate::storage::StorageError;
    match e {
        StorageError::NotFound(_) => error(StatusCode::NOT_FOUND, "Object not found"),
        StorageError::VersionNotFound(_) => error(StatusCode::NOT_FOUND, "Version not found"),
        StorageError::InvalidKey(msg) => error(StatusCode::BAD_REQUEST, msg),
        e => internal(e),
    }
}

/// Metadata of the current object, or of `version_id`. The live sidecar wins
/// when it is that version (it carries the freshest tags).
async fn resolve_object_meta(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<crate::storage::ObjectMeta, Response> {
    require_bucket(state, bucket).await?;
    let current = match state.storage.head_object(bucket, key).await {
        Ok(meta) => Some(meta),
        Err(crate::storage::StorageError::NotFound(_)) => None,
        Err(e) => return Err(object_storage_error(e)),
    };
    match version_id {
        None => current
            .filter(|m| !m.is_delete_marker)
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Object not found")),
        Some(vid) => {
            if let Some(cur) = current.filter(|m| m.version_id.as_deref().unwrap_or("null") == vid)
            {
                return Ok(cur);
            }
            state
                .storage
                .version_meta(bucket, key, vid)
                .await
                .map_err(object_storage_error)
        }
    }
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/object-info/{key}",
    operation_id = "getObjectInfo",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
        VersionParams,
    ),
    responses(
        (status = 200, body = ObjectInfo),
        (status = 400, description = "Invalid version id", body = ErrorResponse),
        (status = 404, description = "Object or version not found", body = ErrorResponse),
    )
)]
pub async fn get_object_info(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<VersionParams>,
) -> Response {
    match resolve_object_meta(&state, &bucket, &key, params.version_id.as_deref()).await {
        Ok(meta) => {
            let inline_payload = if params.version_id.is_some() {
                false
            } else {
                state.storage.object_inline_payload(&bucket, &key).await
            };
            (StatusCode::OK, Json(object_info(meta, inline_payload))).into_response()
        }
        Err(resp) => resp,
    }
}

/// Validate a console tag set with the S3 tagging limits.
fn validate_tag_set(
    tags: Vec<TagEntry>,
    max: usize,
    reject_aws_prefix: bool,
) -> Result<Vec<(String, String)>, String> {
    crate::storage::validate_tags(
        tags.iter().map(|t| (t.key.as_str(), t.value.as_str())),
        max,
        reject_aws_prefix,
    )
    .map_err(|e| e.message)?;
    Ok(tags.into_iter().map(|t| (t.key, t.value)).collect())
}

const OBJECT_TAGS_MAX: usize = 10;
const BUCKET_TAGS_MAX: usize = 50;

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/object-tags/{key}",
    operation_id = "getObjectTags",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
        VersionParams,
    ),
    responses(
        (status = 200, body = TagSetBody),
        (status = 400, description = "Invalid version id or delete marker", body = ErrorResponse),
        (status = 404, description = "Object or version not found", body = ErrorResponse),
    )
)]
pub async fn get_object_tags(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<VersionParams>,
) -> Response {
    match resolve_object_meta(&state, &bucket, &key, params.version_id.as_deref()).await {
        Ok(meta) if meta.is_delete_marker => {
            error(StatusCode::BAD_REQUEST, "Delete markers have no tags")
        }
        Ok(meta) => (
            StatusCode::OK,
            Json(TagSetBody {
                tags: sorted_tags(meta.tags.unwrap_or_default()),
            }),
        )
            .into_response(),
        Err(resp) => resp,
    }
}

#[utoipa::path(
    put,
    path = "/maxio/api/buckets/{bucket}/object-tags/{key}",
    operation_id = "setObjectTags",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
        VersionParams,
    ),
    request_body = TagSetBody,
    responses(
        (status = 200, body = OkResponse),
        (status = 400, description = "Invalid tags or version id", body = ErrorResponse),
        (status = 404, description = "Object or version not found", body = ErrorResponse),
    )
)]
pub async fn set_object_tags(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<VersionParams>,
    Json(body): Json<TagSetBody>,
) -> Response {
    let tags: HashMap<String, String> = match validate_tag_set(body.tags, OBJECT_TAGS_MAX, false) {
        Ok(tags) => tags.into_iter().collect(),
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    let meta = match resolve_object_meta(&state, &bucket, &key, params.version_id.as_deref()).await
    {
        Ok(meta) if meta.is_delete_marker => {
            return error(StatusCode::BAD_REQUEST, "Delete markers have no tags");
        }
        Ok(meta) => meta,
        Err(resp) => return resp,
    };
    // Versioned objects keep the version sidecar in sync with the live one.
    let result = match params.version_id.or(meta.version_id) {
        Some(vid) => {
            state
                .storage
                .put_object_version_tagging(&bucket, &key, &vid, tags)
                .await
        }
        None => state.storage.put_object_tagging(&bucket, &key, tags).await,
    };
    match result {
        Ok(()) => ok(),
        Err(e) => object_storage_error(e),
    }
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/tags",
    operation_id = "getBucketTags",
    tag = "settings",
    params(("bucket" = String, Path)),
    responses(
        (status = 200, body = TagSetBody),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn get_bucket_tags(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Response {
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }
    match state.storage.get_bucket_meta(&bucket).await {
        Ok(meta) => (
            StatusCode::OK,
            Json(TagSetBody {
                tags: sorted_tags(meta.tags.unwrap_or_default()),
            }),
        )
            .into_response(),
        Err(crate::storage::StorageError::NotFound(_)) => {
            error(StatusCode::NOT_FOUND, "Bucket not found")
        }
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    put,
    path = "/maxio/api/buckets/{bucket}/tags",
    operation_id = "setBucketTags",
    tag = "settings",
    params(("bucket" = String, Path)),
    request_body = TagSetBody,
    responses(
        (status = 200, body = OkResponse),
        (status = 400, description = "Invalid tags", body = ErrorResponse),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn set_bucket_tags(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<TagSetBody>,
) -> Response {
    let tags: std::collections::BTreeMap<String, String> =
        match validate_tag_set(body.tags, BUCKET_TAGS_MAX, true) {
            Ok(tags) => tags.into_iter().collect(),
            Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
        };
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }
    match state
        .storage
        .set_bucket_tags(&bucket, (!tags.is_empty()).then_some(tags))
        .await
    {
        Ok(()) => ok(),
        Err(e) => internal(e),
    }
}

#[derive(Serialize, ToSchema)]
pub struct BucketPolicyResponse {
    /// The bucket policy JSON exactly as S3 `GET ?policy` returns it; `null`
    /// when the bucket has no anonymous access.
    #[schema(required = true)]
    policy: Option<String>,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/policy",
    operation_id = "getBucketPolicy",
    tag = "settings",
    params(("bucket" = String, Path)),
    responses(
        (status = 200, body = BucketPolicyResponse),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn get_bucket_policy_view(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Response {
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }
    let policy = match crate::api::bucket::get_bucket_policy(state.clone(), bucket).await {
        Ok(resp) => match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(e) => return internal(e),
        },
        Err(e) if matches!(e.code, crate::error::S3ErrorCode::NoSuchBucketPolicy) => None,
        Err(e) if matches!(e.code, crate::error::S3ErrorCode::NoSuchBucket) => {
            return error(StatusCode::NOT_FOUND, "Bucket not found");
        }
        Err(e) => return internal(e.message),
    };
    (StatusCode::OK, Json(BucketPolicyResponse { policy })).into_response()
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestoreVersionResponse {
    /// Version id of the new current version (`null` when versioning is off).
    #[schema(required = true)]
    version_id: Option<String>,
}

#[utoipa::path(
    post,
    path = "/maxio/api/buckets/{bucket}/versions/{versionId}/restore/{key}",
    operation_id = "restoreVersion",
    tag = "versions",
    params(
        ("bucket" = String, Path),
        ("versionId" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
    ),
    responses(
        (status = 200, body = RestoreVersionResponse),
        (status = 400, description = "Invalid version id, delete marker or SSE-C object", body = ErrorResponse),
        (status = 404, description = "Version not found", body = ErrorResponse),
    )
)]
pub async fn restore_version(
    State(state): State<AppState>,
    Path((bucket, version_id, key)): Path<(String, String, String)>,
) -> Response {
    // Copy the version (content, content type, metadata, tags) on top of the
    // key, like CopyObject with a source versionId.
    let src_meta = match resolve_object_meta(&state, &bucket, &key, Some(&version_id)).await {
        Ok(meta) => meta,
        Err(resp) => return resp,
    };
    if src_meta.is_delete_marker {
        return error(StatusCode::BAD_REQUEST, "Delete markers cannot be restored");
    }
    let src_encryption = src_meta.encryption.as_ref().map(|e| e.mode.clone());
    if src_encryption == Some(crate::storage::EncryptionMode::SseC) {
        return error(
            StatusCode::BAD_REQUEST,
            "SSE-C objects need the customer key",
        );
    }

    let reader = match state
        .storage
        .get_object_version(&bucket, &key, &version_id, None)
        .await
    {
        Ok((reader, _)) => reader,
        Err(e) => return object_storage_error(e),
    };

    let encryption = if src_encryption == Some(crate::storage::EncryptionMode::SseS3) {
        Some(crate::storage::EncryptionRequest::sse_s3())
    } else {
        match bucket_default_encryption(&state, &bucket).await {
            Ok(encryption) => encryption,
            Err(resp) => return resp,
        }
    };
    let opts = crate::storage::PutOptions {
        metadata: src_meta.metadata.clone(),
        tags: src_meta.tags.clone(),
        precondition: None,
    };
    let checksum = src_meta.checksum_algorithm.map(|algo| (algo, None));
    match state
        .storage
        .put_object_with(
            &bucket,
            &key,
            &src_meta.content_type,
            reader,
            checksum,
            encryption,
            &opts,
        )
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(RestoreVersionResponse {
                version_id: result.version_id,
            }),
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

/// A bucket lifecycle configuration (`GET` response and `PUT` body). An
/// empty list removes the configuration.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct LifecycleConfigBody {
    rules: Vec<crate::storage::lifecycle::LifecycleRule>,
}

#[utoipa::path(
    get,
    path = "/maxio/api/buckets/{bucket}/lifecycle",
    operation_id = "getBucketLifecycle",
    tag = "settings",
    params(("bucket" = String, Path)),
    responses(
        (status = 200, body = LifecycleConfigBody),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn get_bucket_lifecycle_api(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Response {
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }
    match state.storage.get_bucket_lifecycle(&bucket).await {
        Ok(rules) => (
            StatusCode::OK,
            Json(LifecycleConfigBody {
                rules: rules.unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(crate::storage::StorageError::NotFound(_)) => {
            error(StatusCode::NOT_FOUND, "Bucket not found")
        }
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    put,
    path = "/maxio/api/buckets/{bucket}/lifecycle",
    operation_id = "setBucketLifecycle",
    tag = "settings",
    params(("bucket" = String, Path)),
    request_body = LifecycleConfigBody,
    responses(
        (status = 200, description = "The stored rules (IDs generated, dates normalized)", body = LifecycleConfigBody),
        (status = 400, description = "Invalid lifecycle rules", body = ErrorResponse),
        (status = 404, description = "Bucket not found", body = ErrorResponse),
    )
)]
pub async fn set_bucket_lifecycle_api(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<LifecycleConfigBody>,
) -> Response {
    if let Err(resp) = require_bucket(&state, &bucket).await {
        return resp;
    }
    let mut rules = body.rules;
    if !rules.is_empty() {
        if let Err(e) = crate::storage::lifecycle::validate_rules(&mut rules) {
            return error(StatusCode::BAD_REQUEST, e.message);
        }
    }
    match state
        .storage
        .set_bucket_lifecycle(&bucket, Some(rules.clone()))
        .await
    {
        Ok(()) => (StatusCode::OK, Json(LifecycleConfigBody { rules })).into_response(),
        Err(crate::storage::StorageError::NotFound(_)) => {
            error(StatusCode::NOT_FOUND, "Bucket not found")
        }
        Err(e) => internal(e),
    }
}

pub fn console_router(state: AppState) -> Router<AppState> {
    let json_body_limit = DefaultBodyLimit::max(state.config.max_console_body_bytes);

    let public = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/check", get(check))
        .layer(json_body_limit);

    let protected_limited = Router::new()
        .route("/version", get(server_version))
        .route("/auth/logout", post(logout))
        .route("/auth/capabilities", get(capabilities))
        .route("/buckets", get(list_buckets))
        .route("/buckets", post(create_bucket))
        .route("/buckets/{bucket}", delete(delete_bucket_api))
        .route("/buckets/{bucket}/folders", post(create_folder))
        .route("/buckets/{bucket}/objects", get(list_objects))
        .route(
            "/buckets/{bucket}/objects/{*key}",
            delete(delete_object_api),
        )
        .route("/buckets/{bucket}/download/{*key}", get(download_object))
        .route("/buckets/{bucket}/presign/{*key}", get(presign_object))
        .route("/buckets/{bucket}/versioning", get(get_versioning))
        .route("/buckets/{bucket}/versioning", put(set_versioning))
        .route("/buckets/{bucket}/encryption", get(get_encryption))
        .route("/buckets/{bucket}/encryption", put(set_encryption))
        .route("/buckets/{bucket}/public", get(get_public))
        .route("/buckets/{bucket}/public", put(set_public))
        .route("/buckets/{bucket}/versions", get(list_versions))
        .route(
            "/buckets/{bucket}/versions/{version_id}/objects/{*key}",
            delete(delete_version),
        )
        .route(
            "/buckets/{bucket}/versions/{version_id}/download/{*key}",
            get(download_version),
        )
        .route(
            "/buckets/{bucket}/versions/{version_id}/restore/{*key}",
            post(restore_version),
        )
        .route("/buckets/{bucket}/object-info/{*key}", get(get_object_info))
        .route(
            "/buckets/{bucket}/object-tags/{*key}",
            get(get_object_tags).put(set_object_tags),
        )
        .route(
            "/buckets/{bucket}/tags",
            get(get_bucket_tags).put(set_bucket_tags),
        )
        .route("/buckets/{bucket}/policy", get(get_bucket_policy_view))
        .route(
            "/buckets/{bucket}/lifecycle",
            get(get_bucket_lifecycle_api).put(set_bucket_lifecycle_api),
        )
        .layer(json_body_limit);

    let protected_streaming =
        Router::new().route("/buckets/{bucket}/upload/{*key}", put(upload_object));

    let protected = protected_limited
        .merge(protected_streaming)
        .merge(super::iam_console::routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            console_csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state,
            console_auth_middleware,
        ));

    public
        .merge(protected)
        .layer(axum::middleware::from_fn(console_no_store))
}

async fn console_no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::storage::keys::Keyring;
    use crate::storage::{BucketMeta, ByteStream};

    use super::*;

    async fn test_storage(data_dir: &str) -> Result<FilesystemStorage, Box<dyn std::error::Error>> {
        let keyring = Arc::new(Keyring::load(data_dir, None).await?);
        Ok(FilesystemStorage::new(data_dir, false, 10 * 1024 * 1024, 0, keyring).await?)
    }

    async fn create_test_bucket(storage: &FilesystemStorage, bucket: &str) {
        storage
            .create_bucket(&BucketMeta {
                name: bucket.to_string(),
                created_at: "2026-05-18T00:00:00.000Z".to_string(),
                region: "us-east-1".to_string(),
                versioning: false,
                cors_rules: None,
                encryption_config: None,
                public_read: false,
                public_list: false,
                versioning_suspended: false,
                tags: None,
                lifecycle: None,
            })
            .await
            .unwrap();
    }

    fn bytes(data: &'static [u8]) -> ByteStream {
        Box::pin(data)
    }

    #[test]
    fn parent_folder_prefix_ignores_root_files_and_folder_markers() {
        assert_eq!(parent_folder_prefix_for_deleted_object("file.txt"), None);
        assert_eq!(parent_folder_prefix_for_deleted_object("folder/"), None);
        assert_eq!(
            parent_folder_prefix_for_deleted_object("folder/file.txt"),
            Some("folder/".to_string())
        );
        assert_eq!(
            parent_folder_prefix_for_deleted_object("a/b/file.txt"),
            Some("a/b/".to_string())
        );
    }

    #[tokio::test]
    async fn deleting_last_console_file_preserves_parent_folder_marker() {
        let temp = tempfile::tempdir().unwrap();
        let storage = test_storage(temp.path().to_str().unwrap()).await.unwrap();
        create_test_bucket(&storage, "bucket").await;

        storage
            .put_object(
                "bucket",
                "folder/file.txt",
                "text/plain",
                bytes(b"hello"),
                None,
                None,
            )
            .await
            .unwrap();

        storage
            .delete_object("bucket", "folder/file.txt")
            .await
            .unwrap();
        preserve_empty_parent_folder_after_object_delete(&storage, "bucket", "folder/file.txt")
            .await
            .unwrap();

        let objects = storage.list_objects("bucket", "folder/").await.unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].key, "folder/");
        assert_eq!(objects[0].content_type, "application/x-directory");
    }

    #[tokio::test]
    async fn deleting_folder_marker_does_not_recreate_it() {
        let temp = tempfile::tempdir().unwrap();
        let storage = test_storage(temp.path().to_str().unwrap()).await.unwrap();
        create_test_bucket(&storage, "bucket").await;

        storage
            .put_object(
                "bucket",
                "folder/",
                "application/x-directory",
                Box::pin(tokio::io::empty()),
                None,
                None,
            )
            .await
            .unwrap();

        storage.delete_object("bucket", "folder/").await.unwrap();
        preserve_empty_parent_folder_after_object_delete(&storage, "bucket", "folder/")
            .await
            .unwrap();

        let objects = storage.list_objects("bucket", "folder/").await.unwrap();
        assert!(objects.is_empty());
    }

    fn cookie_config(secure_cookies: bool, allow_insecure_dev: bool) -> crate::config::Config {
        crate::config::Config {
            port: 9000,
            address: "0.0.0.0".into(),
            data_dir: "./data".into(),
            access_key: "test-access".into(),
            secret_key: "test-credential".into(),
            region: "us-east-1".into(),
            master_key: None,
            master_key_file: None,
            allow_missing_master_key: false,
            allow_insecure_dev,
            secure_cookies,
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
            default_buckets: String::new(),
            max_console_body_bytes: 1024 * 1024,
            ..Default::default()
        }
    }

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::HeaderName::try_from(*name).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }

    #[test]
    fn loopback_http_console_cookie_is_not_secure() {
        let config = cookie_config(true, false);
        for host in ["localhost:9000", "127.0.0.1:9000", "[::1]:9000"] {
            let headers = header_map(&[("host", host)]);
            assert!(
                !console_cookie_secure(&config, &headers),
                "{host} should omit Secure"
            );
        }
    }

    #[test]
    fn https_and_non_loopback_console_cookies_are_secure() {
        let config = cookie_config(true, false);
        assert!(console_cookie_secure(
            &config,
            &header_map(&[("host", "storage.example.com")])
        ));
        assert!(console_cookie_secure(
            &config,
            &header_map(&[("host", "localhost:9000"), ("x-forwarded-proto", "https")])
        ));
        assert!(console_cookie_secure(
            &config,
            &header_map(&[
                ("host", "storage.example.com"),
                ("x-forwarded-proto", "https,http")
            ])
        ));
        assert!(console_cookie_secure(&config, &header_map(&[])));
    }

    #[test]
    fn insecure_dev_and_secure_cookies_false_omit_secure_everywhere() {
        let insecure = cookie_config(true, true);
        let opted_out = cookie_config(false, false);
        let public_host = header_map(&[("host", "storage.example.com")]);
        assert!(!console_cookie_secure(&insecure, &public_host));
        assert!(!console_cookie_secure(&opted_out, &public_host));
    }

    fn revocation_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(".maxio-revoked-sessions.json")
    }

    fn marker_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(".maxio-revoked-sessions.ready")
    }

    #[test]
    fn revocation_warnings_name_the_fail_closed_epoch() {
        let path = std::path::Path::new("/data/.maxio-revoked-sessions.json");
        let marker = std::path::Path::new("/data/.maxio-revoked-sessions.ready");
        let corrupt = revocation_fail_closed_warning(path, "corrupt (expected value)");
        assert!(corrupt.contains("Failing closed"), "{corrupt}");
        assert!(corrupt.contains("issued at or before"), "{corrupt}");
        assert!(corrupt.contains(path.to_str().unwrap()), "{corrupt}");
        let deleted = revocation_deleted_warning(path, marker);
        assert!(deleted.contains("Failing closed"), "{deleted}");
        assert!(deleted.contains("already had a session store"), "{deleted}");
        assert!(deleted.contains(marker.to_str().unwrap()), "{deleted}");
    }

    #[tokio::test]
    async fn first_open_writes_an_empty_store_and_does_not_revoke() {
        let temp = tempfile::tempdir().unwrap();
        let store = RevokedSessions::open(temp.path()).await;
        assert!(store.session_epoch().is_none());
        assert!(revocation_path(temp.path()).is_file());
        assert!(marker_path(temp.path()).is_file());
        let raw = std::fs::read_to_string(revocation_path(temp.path())).unwrap();
        let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(file["entries"].as_array().unwrap().is_empty(), "{raw}");
        assert!(file.get("not_before").is_none(), "{raw}");
        let now = chrono::Utc::now().timestamp();
        assert!(!store.rejects(now - 60, "never-issued"));

        let again = RevokedSessions::open(temp.path()).await;
        assert!(again.session_epoch().is_none());
        assert!(!again.rejects(now - 60, "never-issued"));
    }

    #[tokio::test]
    async fn deleted_revocation_file_fails_closed_and_keeps_the_epoch() {
        let temp = tempfile::tempdir().unwrap();
        RevokedSessions::open(temp.path()).await;
        std::fs::remove_file(revocation_path(temp.path())).unwrap();
        assert!(marker_path(temp.path()).is_file());

        let closed = RevokedSessions::open(temp.path()).await;
        let epoch = closed
            .session_epoch()
            .expect("deleted file must set an epoch");
        assert!(closed.rejects(epoch, "old-session"));
        assert!(closed.rejects(epoch - 10, "older-session"));
        assert!(!closed.rejects(epoch + 2, "fresh-session"));
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(revocation_path(temp.path())).unwrap())
                .unwrap();
        assert_eq!(saved["not_before"], epoch);

        let reloaded = RevokedSessions::open(temp.path()).await;
        assert_eq!(reloaded.session_epoch(), Some(epoch));
        assert!(reloaded.rejects(epoch, "old-session"));
        assert!(!reloaded.rejects(epoch + 2, "fresh-session"));
    }

    #[tokio::test]
    async fn corrupt_or_directory_revocation_file_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        RevokedSessions::open(temp.path()).await;
        std::fs::write(revocation_path(temp.path()), b"{not-json").unwrap();
        let corrupt = RevokedSessions::open(temp.path()).await;
        let epoch = corrupt
            .session_epoch()
            .expect("corrupt file must set an epoch");
        assert!(corrupt.rejects(epoch, "any"));
        assert!(!corrupt.rejects(epoch + 5, "later"));

        let blocked = tempfile::tempdir().unwrap();
        RevokedSessions::open(blocked.path()).await;
        std::fs::remove_file(revocation_path(blocked.path())).unwrap();
        std::fs::create_dir(revocation_path(blocked.path())).unwrap();
        let dir_store = RevokedSessions::open(blocked.path()).await;
        let dir_epoch = dir_store
            .session_epoch()
            .expect("directory must set an epoch");
        assert!(dir_store.rejects(dir_epoch, "any"));
        let err = dir_store.revoke("logged-out", dir_epoch + 10_000).await;
        assert!(err.is_err(), "replacing a directory must fail the write");
        assert!(
            dir_store.rejects(dir_epoch + 5, "logged-out"),
            "the logout stays revoked in memory"
        );
        assert!(!dir_store.rejects(dir_epoch + 5, "other-session"));
    }

    #[tokio::test]
    async fn legacy_revocation_file_without_epoch_still_loads() {
        let temp = tempfile::tempdir().unwrap();
        let future = chrono::Utc::now().timestamp() + 86_400;
        std::fs::write(
            revocation_path(temp.path()),
            format!(r#"{{"entries":[{{"jti":"old","expires_at":{future}}}]}}"#),
        )
        .unwrap();
        let store = RevokedSessions::open(temp.path()).await;
        assert!(store.session_epoch().is_none());
        assert!(store.rejects(1, "old"));
        assert!(!store.rejects(1, "new"));
        assert!(marker_path(temp.path()).is_file());
    }
}
