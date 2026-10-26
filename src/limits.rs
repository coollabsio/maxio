//! Request caps that keep one client from exhausting the process.
//!
//! Size limits are enforced in the storage write path (and from declared
//! `Content-Length`). These layers cover header size, in-flight requests, and
//! how long one request may run.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, Method};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::error::S3Error;
use crate::vhost::SignedRequestPath;

/// Which unauthenticated probe a path is, before method and virtual-host checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HealthProbe {
    /// Process is answering. Does not touch the data directory.
    Live,
    /// Data directory can be read.
    Ready,
    /// MinIO cluster write probe. Single node: same as [`HealthProbe::Ready`],
    /// except `?maintenance=true` is 412 while the node is up.
    Cluster,
    /// MinIO cluster read probe. Single node: same as [`HealthProbe::Ready`].
    ClusterRead,
}

pub(crate) fn health_probe_path(path: &str) -> Option<HealthProbe> {
    match path {
        "/maxio/health/live" | "/minio/health/live" => Some(HealthProbe::Live),
        "/maxio/health/ready" | "/minio/health/ready" => Some(HealthProbe::Ready),
        "/minio/health/cluster" => Some(HealthProbe::Cluster),
        "/minio/health/cluster/read" => Some(HealthProbe::ClusterRead),
        _ => None,
    }
}

/// `GET`/`HEAD` of a health URL on the service host.
///
/// A virtual-hosted request is rewritten onto `/{bucket}/...` before routing
/// and is an object, even when that path is `/minio/health/live`. Other
/// methods stay on the S3 router so a bucket named `minio` can still store
/// those keys.
pub(crate) fn health_probe(request: &Request) -> Option<HealthProbe> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return None;
    }
    if request.extensions().get::<SignedRequestPath>().is_some() {
        return None;
    }
    health_probe_path(request.uri().path())
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
    if health_probe(&request).is_some() {
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
    if health_probe(&request).is_some() {
        return next.run(request).await;
    }
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => S3Error::request_timeout().into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn both_health_families_are_probes() {
        for path in [
            "/maxio/health/live",
            "/maxio/health/ready",
            "/minio/health/live",
            "/minio/health/ready",
            "/minio/health/cluster",
            "/minio/health/cluster/read",
        ] {
            assert!(health_probe_path(path).is_some(), "{path}");
            assert!(health_probe(&request("GET", path)).is_some(), "{path}");
            assert!(health_probe(&request("HEAD", path)).is_some(), "{path}");
            assert!(
                health_probe(&request("PUT", path)).is_none(),
                "{path} writes stay on S3"
            );
        }
        assert_eq!(
            health_probe(&request("GET", "/minio/health/cluster")),
            Some(HealthProbe::Cluster)
        );
        assert_eq!(
            health_probe(&request("GET", "/minio/health/cluster/read")),
            Some(HealthProbe::ClusterRead)
        );
    }

    #[test]
    fn other_paths_and_virtual_hosts_are_not_probes() {
        for path in [
            "/readyz",
            "/healthz",
            "/version",
            "/minio/health",
            "/minio/health/live/",
            "/minio/health/cluster/write",
            "/minio/health/cluster/ready",
            "/photos/minio/health/live",
        ] {
            assert!(health_probe(&request("GET", path)).is_none(), "{path}");
        }

        let mut rewritten = request("GET", "/minio/health/live");
        rewritten
            .extensions_mut()
            .insert(SignedRequestPath("/health/live".to_string()));
        assert!(health_probe(&rewritten).is_none());
    }
}
