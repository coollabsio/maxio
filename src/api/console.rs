use std::collections::BTreeSet;

use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

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
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    if body.access_key != state.config.access_key || body.secret_key != state.config.secret_key {
        return (StatusCode::UNAUTHORIZED, HeaderMap::new(), Json(serde_json::json!({"error": "Invalid credentials"})));
    }

    let now = chrono::Utc::now().timestamp();
    let token = generate_token(&state.config.access_key, &state.config.secret_key, now);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        COOKIE_NAME, token, TOKEN_MAX_AGE_SECS
    );

    let mut headers = HeaderMap::new();
    headers.insert("Set-Cookie", cookie.parse().unwrap());

    (StatusCode::OK, headers, Json(serde_json::json!({"ok": true})))
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

pub async fn logout() -> impl IntoResponse {
    let cookie = format!("{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0", COOKIE_NAME);
    let mut headers = HeaderMap::new();
    headers.insert("Set-Cookie", cookie.parse().unwrap());
    (StatusCode::OK, headers, Json(serde_json::json!({"ok": true})))
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
pub struct ListObjectsParams {
    prefix: Option<String>,
    delimiter: Option<String>,
}

pub async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsParams>,
) -> impl IntoResponse {
    if !state.storage.head_bucket(&bucket).await {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Bucket not found"}))).into_response();
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
        } else {
            files.push(serde_json::json!({
                "key": obj.key,
                "size": obj.size,
                "lastModified": obj.last_modified,
                "etag": obj.etag,
            }));
        }
    }

    let prefixes: Vec<&String> = prefix_set.iter().collect();

    (StatusCode::OK, Json(serde_json::json!({
        "files": files,
        "prefixes": prefixes,
    }))).into_response()
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

pub fn console_router(state: AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/check", get(check));

    let protected = Router::new()
        .route("/auth/logout", post(logout))
        .route("/buckets", get(list_buckets))
        .route("/buckets/{bucket}/objects", get(list_objects))
        .route("/buckets/{bucket}/download/{*key}", get(download_object))
        .layer(axum::middleware::from_fn_with_state(
            state,
            console_auth_middleware,
        ));

    public.merge(protected)
}
