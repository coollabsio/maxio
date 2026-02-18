use std::collections::BTreeSet;

use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use futures::TryStreamExt;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::auth::signature_v4;
use crate::server::AppState;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "maxio_session";
const TOKEN_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60; // 7 days

fn generate_token(access_key: &str, secret_key: &str, issued_at: i64) -> String {
    let issued_hex = format!("{:x}", issued_at);
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .expect("HMAC can take key of any size");
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

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(format!("{}:{}", access_key, issued_hex).as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    signature == expected
}

fn extract_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with(&format!("{}=", COOKIE_NAME)))
                .map(|c| c[COOKIE_NAME.len() + 1..].to_string())
        })
}

fn make_cookie(value: &str, max_age: i64, request_headers: &HeaderMap) -> String {
    let is_secure = request_headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "https")
        .unwrap_or(false);

    let secure_flag = if is_secure { "; Secure" } else { "" };

    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        COOKIE_NAME, value, max_age, secure_flag
    )
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
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response();
    }
    next.run(request).await
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    access_key: String,
    secret_key: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    if body.access_key != state.config.access_key || body.secret_key != state.config.secret_key {
        return (StatusCode::UNAUTHORIZED, HeaderMap::new(), Json(serde_json::json!({"error": "Invalid credentials"})));
    }

    let now = chrono::Utc::now().timestamp();
    let token = generate_token(&state.config.access_key, &state.config.secret_key, now);
    let cookie = make_cookie(&token, TOKEN_MAX_AGE_SECS, &headers);

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Set-Cookie", cookie.parse().unwrap());

    (StatusCode::OK, resp_headers, Json(serde_json::json!({"ok": true})))
}

pub async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let authenticated = extract_cookie(&headers)
        .map(|token| verify_token(&token, &state.config.access_key, &state.config.secret_key))
        .unwrap_or(false);

    if authenticated {
        (StatusCode::OK, Json(serde_json::json!({"ok": true})))
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"})))
    }
}

pub async fn logout(headers: HeaderMap) -> impl IntoResponse {
    let cookie = make_cookie("", 0, &headers);
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Set-Cookie", cookie.parse().unwrap());
    (StatusCode::OK, resp_headers, Json(serde_json::json!({"ok": true})))
}

pub async fn list_buckets(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.storage.list_buckets().await {
        Ok(buckets) => {
            let list: Vec<serde_json::Value> = buckets.into_iter().map(|b| {
                serde_json::json!({ "name": b.name, "createdAt": b.created_at })
            }).collect();
            (StatusCode::OK, Json(serde_json::json!({ "buckets": list }))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct CreateBucketRequest {
    name: String,
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Json(body): Json<CreateBucketRequest>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let meta = crate::storage::BucketMeta {
        name: body.name.clone(),
        created_at: now,
        region: state.config.region.clone(),
    };

    match state.storage.create_bucket(&meta).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Ok(false) => (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Bucket already exists"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

pub async fn delete_bucket_api(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> impl IntoResponse {
    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Bucket not found"}))).into_response(),
        Err(crate::storage::StorageError::BucketNotEmpty) => {
            (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Bucket is not empty"}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct ListObjectsParams {
    prefix: Option<String>,
    delimiter: Option<String>,
}

pub async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsParams>,
) -> impl IntoResponse {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Bucket not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }

    let prefix = params.prefix.unwrap_or_default();
    let delimiter = params.delimiter.unwrap_or_else(|| "/".to_string());

    let all_objects = match state.storage.list_objects(&bucket, &prefix).await {
        Ok(objects) => objects,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    };

    let mut files = Vec::new();
    let mut prefix_set = BTreeSet::new();

    for obj in &all_objects {
        let suffix = &obj.key[prefix.len()..];
        if let Some(pos) = suffix.find(delimiter.as_str()) {
            let common = format!("{}{}", prefix, &suffix[..pos + delimiter.len()]);
            prefix_set.insert(common);
        } else if !obj.key.ends_with('/') {
            files.push(serde_json::json!({
                "key": obj.key,
                "size": obj.size,
                "lastModified": obj.last_modified,
                "etag": obj.etag,
            }));
        }
    }

    // Determine which prefixes are empty (only contain a folder marker, no real objects)
    let mut empty_prefixes: Vec<&String> = Vec::new();
    for p in &prefix_set {
        let has_children = all_objects.iter().any(|obj| {
            obj.key.starts_with(p.as_str()) && obj.key != *p
        });
        if !has_children {
            empty_prefixes.push(p);
        }
    }

    let prefixes: Vec<&String> = prefix_set.iter().collect();

    (StatusCode::OK, Json(serde_json::json!({
        "files": files,
        "prefixes": prefixes,
        "emptyPrefixes": empty_prefixes,
    }))).into_response()
}

pub async fn upload_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> impl IntoResponse {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Bucket not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let stream = body.into_data_stream();
    let reader = tokio_util::io::StreamReader::new(
        stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );

    match state.storage.put_object(&bucket, &key, content_type, Box::pin(reader)).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "etag": result.etag,
            "size": result.size,
        }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

pub async fn delete_object_api(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.storage.delete_object(&bucket, &key).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

pub async fn download_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    let (reader, meta) = match state.storage.get_object(&bucket, &key).await {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Object not found"}))).into_response();
        }
    };

    let filename = key.rsplit('/').next().unwrap_or(&key);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header("Content-Disposition", format!("attachment; filename=\"{}\"", filename))
        .body(body)
        .unwrap()
        .into_response()
}

#[derive(serde::Deserialize)]
pub struct PresignParams {
    expires: Option<u64>,
}

pub async fn presign_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PresignParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Verify object exists
    match state.storage.head_object(&bucket, &key).await {
        Ok(_) => {}
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Object not found"})),
            )
                .into_response()
        }
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
    let path = format!("/{}/{}", bucket, key);

    // Build query string params (sorted alphabetically, excluding Signature)
    let qs_params = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential.clone()),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires_secs.to_string()),
        ("X-Amz-SignedHeaders", "host".to_string()),
    ];

    const S3_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    let encode =
        |s: &str| -> String { percent_encoding::utf8_percent_encode(s, S3_ENCODE).to_string() };

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

    let presigned_url = format!(
        "{}://{}{}?{}&X-Amz-Signature={}",
        scheme, host, path, canonical_qs, signature
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "url": presigned_url,
            "expiresIn": expires_secs,
        })),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub struct CreateFolderRequest {
    name: String,
}

pub async fn create_folder(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<CreateFolderRequest>,
) -> impl IntoResponse {
    let name = body.name.trim().trim_matches('/');
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Folder name is required"})),
        )
            .into_response();
    }

    let key = format!("{}/", name);
    match state.storage.put_object(&bucket, &key, "application/x-directory", Box::pin(tokio::io::empty())).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub fn console_router(state: AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/check", get(check));

    let protected = Router::new()
        .route("/auth/logout", post(logout))
        .route("/buckets", get(list_buckets))
        .route("/buckets", post(create_bucket))
        .route("/buckets/{bucket}", delete(delete_bucket_api))
        .route("/buckets/{bucket}/folders", post(create_folder))
        .route("/buckets/{bucket}/objects", get(list_objects))
        .route("/buckets/{bucket}/objects/{*key}", delete(delete_object_api))
        .route("/buckets/{bucket}/upload/{*key}", put(upload_object))
        .route("/buckets/{bucket}/download/{*key}", get(download_object))
        .route("/buckets/{bucket}/presign/{*key}", get(presign_object))
        .layer(axum::middleware::from_fn_with_state(
            state,
            console_auth_middleware,
        ));

    public.merge(protected)
}
