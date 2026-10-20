//! Request caps that keep one client from exhausting the process.
//!
//! Size limits are enforced in the storage write path (and from declared
//! `Content-Length`). These layers cover header size, in-flight requests, and
//! how long one request may run.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::HeaderValue;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::error::S3Error;

pub fn is_health_path(path: &str) -> bool {
    matches!(
        path,
        "/healthz"
            | "/readyz"
            | "/minio/health/live"
            | "/minio/health/ready"
            | "/minio/health/cluster"
    )
}

fn with_retry_after(error: S3Error) -> Response {
    let mut response = error.into_response();
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("1"));
    response
}

pub async fn limit_headers(
    State(max_bytes): State<usize>,
    request: Request,
    next: Next,
) -> Response {
    let total: usize = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    if total > max_bytes {
        return S3Error::invalid_argument("Request headers exceed the maximum allowed size")
            .into_response();
    }
    next.run(request).await
}

pub async fn limit_inflight(
    State(slots): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    if is_health_path(request.uri().path()) {
        return next.run(request).await;
    }
    let Ok(_permit) = slots.clone().try_acquire_owned() else {
        return with_retry_after(S3Error::slow_down());
    };
    next.run(request).await
}

pub async fn limit_request_time(
    State(timeout): State<Duration>,
    request: Request,
    next: Next,
) -> Response {
    if is_health_path(request.uri().path()) {
        return next.run(request).await;
    }
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => S3Error::request_timeout().into_response(),
    }
}
