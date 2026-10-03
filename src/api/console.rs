use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
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

fn generate_token(access_key: &str, secret_key: &str, issued_at: i64) -> String {
    let issued_hex = format!("{:x}", issued_at);
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(format!("{}:{}", access_key, issued_hex).as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{}.{}", issued_hex, sig)
}

fn verify_token(token: &str, access_key: &str, secret_key: &str) -> bool {
    let Some((issued_hex, signature)) = token.split_once('.') else {
        return false;
    };

    let Ok(issued_at) = i64::from_str_radix(issued_hex, 16) else {
        return false;
    };

    let now = chrono::Utc::now().timestamp();
    if now - issued_at > TOKEN_MAX_AGE_SECS || issued_at > now + 60 {
        return false;
    }

    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(format!("{}:{}", access_key, issued_hex).as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    constant_time_eq(signature.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        COOKIE_NAME, value, max_age, secure_flag
    )
}

#[derive(Serialize, ToSchema)]
pub struct OkResponse {
    ok: bool,
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
    let authenticated = extract_cookie(request.headers())
        .map(|token| verify_token(&token, &state.config.access_key, &state.config.secret_key))
        .unwrap_or(false);

    if !authenticated {
        return error(StatusCode::UNAUTHORIZED, "Not authenticated");
    }
    next.run(request).await
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    access_key: String,
    secret_key: String,
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    operation_id = "login",
    tag = "auth",
    security(()),
    request_body = LoginRequest,
    responses(
        (status = 200, body = OkResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
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

    // Use constant-time comparison to prevent timing side-channel attacks
    let key_match = constant_time_eq(
        body.access_key.as_bytes(),
        state.config.access_key.as_bytes(),
    );
    let secret_match = constant_time_eq(
        body.secret_key.as_bytes(),
        state.config.secret_key.as_bytes(),
    );
    if !key_match || !secret_match {
        return error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }

    let now = chrono::Utc::now().timestamp();
    let token = generate_token(&state.config.access_key, &state.config.secret_key, now);
    let cookie = make_cookie(
        &token,
        TOKEN_MAX_AGE_SECS,
        state.config.secure_cookies && !state.config.allow_insecure_dev,
    );

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Set-Cookie", cookie.parse().unwrap());
    (resp_headers, ok()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/auth/check",
    operation_id = "checkAuth",
    tag = "auth",
    security(()),
    responses(
        (status = 200, body = OkResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn check(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let authenticated = extract_cookie(&headers)
        .map(|token| verify_token(&token, &state.config.access_key, &state.config.secret_key))
        .unwrap_or(false);

    if authenticated {
        ok()
    } else {
        error(StatusCode::UNAUTHORIZED, "Not authenticated")
    }
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    operation_id = "logout",
    tag = "auth",
    responses((status = 200, body = OkResponse))
)]
pub async fn logout(State(state): State<AppState>) -> Response {
    let cookie = make_cookie(
        "",
        0,
        state.config.secure_cookies && !state.config.allow_insecure_dev,
    );
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Set-Cookie", cookie.parse().unwrap());
    (resp_headers, ok()).into_response()
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
}

#[derive(Serialize, ToSchema)]
pub struct BucketListResponse {
    buckets: Vec<BucketSummary>,
}

#[utoipa::path(
    get,
    path = "/api/buckets",
    operation_id = "listBuckets",
    tag = "buckets",
    responses(
        (status = 200, body = BucketListResponse),
        (status = 500, body = ErrorResponse),
    )
)]
pub async fn list_buckets(State(state): State<AppState>) -> Response {
    match state.storage.list_buckets().await {
        Ok(buckets) => {
            let buckets = buckets
                .into_iter()
                .map(|b| BucketSummary {
                    name: b.name,
                    created_at: b.created_at,
                    versioning: b.versioning,
                    encryption: b.encryption_config.is_some(),
                })
                .collect();
            (StatusCode::OK, Json(BucketListResponse { buckets })).into_response()
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
    path = "/api/buckets",
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
    Json(body): Json<CreateBucketRequest>,
) -> Response {
    if let Some(reason) = crate::storage::bucket_name_error(&body.name) {
        return error(StatusCode::BAD_REQUEST, reason);
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
    };

    match state.storage.create_bucket(&meta).await {
        Ok(true) => ok(),
        Ok(false) => error(StatusCode::CONFLICT, "Bucket already exists"),
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    delete,
    path = "/api/buckets/{bucket}",
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
    path = "/api/buckets/{bucket}/objects",
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
    path = "/api/buckets/{bucket}/upload/{key}",
    operation_id = "uploadObject",
    tag = "objects",
    params(
        ("bucket" = String, Path),
        ("key" = String, Path, description = "Object key; may contain `/`"),
    ),
    request_body(content = BinaryBody, content_type = "application/octet-stream"),
    responses(
        (status = 200, body = UploadResponse),
        (status = 400, description = "Invalid user metadata (x-amz-meta-*)", body = ErrorResponse),
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

    // This handler already reads S3-style request headers, so honour
    // `x-amz-meta-*` here too rather than accepting and discarding it.
    let user_metadata = match crate::api::object::extract_user_metadata(&headers) {
        Ok(m) => m,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.message),
    };

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
            user_metadata,
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
        Err(e) => internal(e),
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
    path = "/api/buckets/{bucket}/objects/{key}",
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
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[utoipa::path(
    get,
    path = "/api/buckets/{bucket}/download/{key}",
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

#[utoipa::path(
    get,
    path = "/api/buckets/{bucket}/presign/{key}",
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
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PresignParams>,
    headers: HeaderMap,
) -> Response {
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
    let access_key = &state.config.access_key;

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

    let signing_key =
        signature_v4::derive_signing_key(&state.config.secret_key, &date_stamp, region);

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
    path = "/api/buckets/{bucket}/folders",
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
    Path(bucket): Path<String>,
    Json(body): Json<CreateFolderRequest>,
) -> Response {
    let name = body.name.trim().trim_matches('/');
    if name.is_empty() {
        return error(StatusCode::BAD_REQUEST, "Folder name is required");
    }

    let key = format!("{}/", name);
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
            None,
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
    path = "/api/buckets/{bucket}/versioning",
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
    path = "/api/buckets/{bucket}/versioning",
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
    path = "/api/buckets/{bucket}/encryption",
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
    path = "/api/buckets/{bucket}/encryption",
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
    path = "/api/buckets/{bucket}/public",
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
    path = "/api/buckets/{bucket}/public",
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
    path = "/api/buckets/{bucket}/versions",
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
    path = "/api/buckets/{bucket}/versions/{versionId}/objects/{key}",
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
        Err(e) => internal(e),
    }
}

#[utoipa::path(
    get,
    path = "/api/buckets/{bucket}/versions/{versionId}/download/{key}",
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

pub fn console_router(state: AppState) -> Router<AppState> {
    let json_body_limit = DefaultBodyLimit::max(state.config.max_console_body_bytes);

    let public = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/check", get(check))
        .layer(json_body_limit);

    let protected_limited = Router::new()
        .route("/auth/logout", post(logout))
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
        .layer(json_body_limit);

    let protected_streaming =
        Router::new().route("/buckets/{bucket}/upload/{*key}", put(upload_object));

    let protected = protected_limited
        .merge(protected_streaming)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            console_csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state,
            console_auth_middleware,
        ));

    public.merge(protected)
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
}
