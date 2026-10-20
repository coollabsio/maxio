use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::routing::get;
use serde::Serialize;
use std::sync::Arc;

use crate::api::console::{LoginRateLimiter, console_router};
use crate::api::cors::cors_middleware;
use crate::api::router::s3_router;
use crate::auth::middleware::auth_middleware;
use crate::config::Config;
use crate::embedded::ui_handler;
use crate::storage::filesystem::FilesystemStorage;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<FilesystemStorage>,
    pub config: Arc<Config>,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
}

pub fn build_router(state: AppState) -> Router {
    let s3_routes = s3_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            cors_middleware,
        ));

    Router::new()
        .nest("/api", console_router(state.clone()))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/readyz", get(readyz))
        // MinIO-compatible probes (GET and HEAD, unauthenticated). Registered
        // here, outside the S3 router, so the SigV4 auth layer never runs.
        // These stay empty 200s; `/healthz` carries the version body.
        .route("/minio/health/live", get(live))
        .route("/minio/health/ready", get(readyz))
        .route("/minio/health/cluster", get(readyz))
        .route("/ui", get(redirect_to_ui_root))
        .route("/ui/", get(ui_handler))
        .route("/ui/{*path}", get(ui_handler))
        .merge(s3_routes)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(axum::middleware::from_fn(request_id_middleware))
        .with_state(state)
}

/// `/ui` -> `/ui/` (keeps the query), so the console has one canonical base URL.
async fn redirect_to_ui_root(uri: axum::http::Uri) -> axum::response::Redirect {
    match uri.query() {
        Some(query) => axum::response::Redirect::permanent(&format!("/ui/?{query}")),
        None => axum::response::Redirect::permanent("/ui/"),
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: VERSION,
    })
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse { version: VERSION })
}

async fn live() -> StatusCode {
    StatusCode::OK
}

async fn readyz(State(_state): State<AppState>) -> StatusCode {
    StatusCode::OK
}

async fn request_id_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(request).await;
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("x-amz-request-id", value);
    }
    response
}

async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.entry(header::CONTENT_SECURITY_POLICY).or_insert_with(|| {
        HeaderValue::from_static("default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'")
    });
    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers
        .entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    headers
        .entry("permissions-policy")
        .or_insert(HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=()",
        ));
    response
}
