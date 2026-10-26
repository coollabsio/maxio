use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Semaphore;
use tower::Service;

use crate::api::authz::s3_authz_middleware;
use crate::api::console::{LoginRateLimiter, console_router};
use crate::api::cors::cors_middleware;
use crate::api::router::s3_router;
use crate::auth::middleware::auth_middleware;
use crate::config::Config;
use crate::embedded::ui_handler;
use crate::error::S3Error;
use crate::limits::{limit_headers, limit_inflight, limit_request_time};
use crate::storage::filesystem::FilesystemStorage;
use crate::vhost;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<FilesystemStorage>,
    pub config: Arc<Config>,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    /// Console cookies rejected after logout. The token itself is stateless.
    pub revoked_sessions: Arc<crate::api::console::RevokedSessions>,
}

/// Router plus the pre-routing virtual-host rewrite.
///
/// The rewrite has to run before [`Router`] matches, so it cannot be a normal
/// Axum layer. [`AppService::into_make_service_with_connect_info`] keeps
/// [`ConnectInfo`](axum::extract::ConnectInfo) working for the console.
#[derive(Clone)]
pub struct AppService {
    router: Router,
    domains: Arc<[String]>,
}

impl AppService {
    pub fn into_make_service_with_connect_info<C>(
        self,
    ) -> axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Self, C> {
        use axum::ServiceExt;
        <Self as ServiceExt<Request<Body>>>::into_make_service_with_connect_info(self)
    }
}

impl AppService {
    /// `domains` empty leaves every host on path-style.
    pub fn new(router: Router, domains: Vec<String>) -> Self {
        Self {
            router,
            domains: domains.into(),
        }
    }
}

impl From<Router> for AppService {
    fn from(router: Router) -> Self {
        Self::new(router, Vec::new())
    }
}

impl Service<Request<Body>> for AppService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Router as Service<Request<Body>>>::poll_ready(&mut self.router, cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        // `maxio.<domain>` is the reserved service host, not an S3 bucket.
        if let Some(bucket) = vhost::reserved_service_bucket(&request, &self.domains) {
            let response = S3Error::invalid_bucket_name(&bucket).into_response();
            return Box::pin(std::future::ready(Ok(response)));
        }
        vhost::apply(&mut request, &self.domains);
        Box::pin(<Router as Service<Request<Body>>>::call(
            &mut self.router,
            request,
        ))
    }
}

fn insert_security_headers(headers: &mut axum::http::HeaderMap) {
    headers.entry(header::CONTENT_SECURITY_POLICY).or_insert_with(|| {
        HeaderValue::from_static("default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' https: data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'self' blob:; form-action 'self'")
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
}

pub fn build_router(state: AppState) -> AppService {
    let domains: Arc<[String]> = vhost::parse_domains(&state.config.domain)
        .expect("virtual-host domains")
        .into();
    let max_header_bytes = state.config.max_header_bytes;
    let request_timeout = Duration::from_secs(state.config.request_timeout_secs);
    let max_inflight = state.config.max_concurrent_requests;
    let s3_routes = s3_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            s3_authz_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            cors_middleware,
        ));

    let mut router = Router::new()
        .nest("/maxio/api", console_router(state.clone()))
        // `/ui` is not a static route. Browser GET/HEAD is the console; every
        // other request, including bucket `ui`, falls through to S3.
        .merge(s3_routes)
        // Probes sit in front of S3 so they stay unauthenticated. Only
        // path-style GET/HEAD matches; a virtual-hosted rewrite and every
        // other method fall through. `/healthz`, `/readyz`, and `/version`
        // stay ordinary bucket paths.
        .layer(from_fn_with_state(state.clone(), health_probe_middleware))
        .layer(axum::middleware::from_fn(console_ui_middleware))
        .layer(from_fn_with_state(max_header_bytes, limit_headers));

    if !request_timeout.is_zero() {
        router = router.layer(from_fn_with_state(request_timeout, limit_request_time));
    }
    if max_inflight > 0 {
        let slots = Arc::new(Semaphore::new(max_inflight));
        router = router.layer(from_fn_with_state(slots, limit_inflight));
    }

    let router = router
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(axum::middleware::from_fn(request_id_middleware))
        .with_state(state);

    AppService { router, domains }
}

/// Serve the console for an unauthenticated browser GET/HEAD of `/ui`.
///
/// Bucket `ui` is reserved, so a query string is still the SPA. Only a SigV4
/// `Authorization` header or `X-Amz-*` presign query is S3 (and then fails
/// `InvalidBucketName`).
async fn console_ui_middleware(
    request: Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !is_browser_console_request(&request) {
        return next.run(request).await;
    }
    let head = request.method() == Method::HEAD;
    let uri = request.uri().clone();
    let mut response = if uri.path() == "/ui" {
        redirect_to_ui_root(uri).await.into_response()
    } else {
        ui_handler(uri).await
    };
    if head {
        *response.body_mut() = Body::empty();
    }
    response
}

/// True for GET/HEAD `/ui` and `/ui/...` that are not S3.
fn is_browser_console_request(request: &Request) -> bool {
    let path = request.uri().path();
    if path != "/ui" && !path.starts_with("/ui/") {
        return false;
    }
    // Virtual-hosted `ui.<domain>` was rewritten onto this path.
    if request
        .extensions()
        .get::<vhost::SignedRequestPath>()
        .is_some()
    {
        return false;
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return false;
    }
    if request.headers().contains_key(header::AUTHORIZATION) {
        return false;
    }
    // Header names are lowercase. A SigV4 header is not a browser page load.
    if request
        .headers()
        .keys()
        .any(|name| name.as_str().starts_with("x-amz-"))
    {
        return false;
    }
    !query_has_presign(request.uri().query().unwrap_or(""))
}

fn query_has_presign(query: &str) -> bool {
    query.split('&').any(|pair| {
        let key = pair.split('=').next().unwrap_or(pair);
        key.len() >= 6 && key[..6].eq_ignore_ascii_case("x-amz-")
    })
}

/// `/ui` -> `/ui/` (keeps the query), so the console has one canonical base URL.
async fn redirect_to_ui_root(uri: axum::http::Uri) -> axum::response::Redirect {
    match uri.query() {
        Some(query) => axum::response::Redirect::permanent(&format!("/ui/?{query}")),
        None => axum::response::Redirect::permanent("/ui/"),
    }
}

#[derive(serde::Serialize)]
struct HealthBody {
    status: &'static str,
}

fn health_json(status: &'static str, code: StatusCode) -> axum::response::Response {
    let mut response = (code, Json(HealthBody { status })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn query_flag(query: Option<&str>, name: &str) -> bool {
    query.is_some_and(|query| {
        query.split('&').any(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            key == name && value == "true"
        })
    })
}

async fn data_dir_readable(state: &AppState) -> bool {
    let data_dir = std::path::Path::new(&state.config.data_dir);
    tokio::fs::read_dir(data_dir).await.is_ok()
        && tokio::fs::read_dir(data_dir.join("buckets")).await.is_ok()
}

async fn ready_response(state: &AppState) -> axum::response::Response {
    if data_dir_readable(state).await {
        health_json("ok", StatusCode::OK)
    } else {
        health_json("unavailable", StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// `GET`/`HEAD` liveness and readiness for `/maxio/health/*` and `/minio/health/*`.
///
/// The body is status only. MinIO's cluster probes follow readiness on this
/// single-node build. `?maintenance=true` on `/minio/health/cluster` is 412
/// while the node is up: taking the only node down loses the service (`mc ready
/// --maintenance`, not the default Coolify check).
async fn health_probe_middleware(
    State(state): State<AppState>,
    request: Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let Some(probe) = crate::limits::health_probe(&request) else {
        return next.run(request).await;
    };
    let head = request.method() == Method::HEAD;
    let response = match probe {
        crate::limits::HealthProbe::Live => health_json("ok", StatusCode::OK),
        crate::limits::HealthProbe::Ready | crate::limits::HealthProbe::ClusterRead => {
            ready_response(&state).await
        }
        crate::limits::HealthProbe::Cluster if query_flag(request.uri().query(), "maintenance") => {
            if data_dir_readable(&state).await {
                health_json("unavailable", StatusCode::PRECONDITION_FAILED)
            } else {
                health_json("unavailable", StatusCode::SERVICE_UNAVAILABLE)
            }
        }
        crate::limits::HealthProbe::Cluster => ready_response(&state).await,
    };
    if head {
        let mut response = response;
        *response.body_mut() = Body::empty();
        response
    } else {
        response
    }
}

async fn request_id_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(request).await;
    // Error bodies already carry the id they put in `<RequestId>`. Replacing
    // it makes the header disagree with the XML (clients compare the two).
    if !response.headers().contains_key("x-amz-request-id") {
        if let Ok(value) = request_id.parse() {
            response.headers_mut().insert("x-amz-request-id", value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhost::SignedRequestPath;

    fn request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn browser_get_and_head_of_ui_are_the_console() {
        assert!(is_browser_console_request(&request("GET", "/ui")));
        assert!(is_browser_console_request(&request("HEAD", "/ui/")));
        assert!(is_browser_console_request(&request(
            "GET",
            "/ui/buckets/photos?prefix=2026%2F"
        )));
        assert!(is_browser_console_request(&request(
            "GET",
            "/ui?versioning"
        )));
        assert!(is_browser_console_request(&request(
            "GET",
            "/ui/?list-type=2&prefix=photos"
        )));
        assert!(is_browser_console_request(&request(
            "GET",
            "/ui/assets/index-abc.js"
        )));
    }

    #[test]
    fn signed_presigned_and_s3_queries_are_not_the_console() {
        let mut signed = request("GET", "/ui/note.txt");
        signed.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=a"),
        );
        assert!(!is_browser_console_request(&signed));

        let mut amz = request("GET", "/ui/note.txt");
        amz.headers_mut().insert(
            "x-amz-content-sha256",
            HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
        assert!(!is_browser_console_request(&amz));

        assert!(!is_browser_console_request(&request(
            "GET",
            "/ui/note.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=ab"
        )));
        assert!(!is_browser_console_request(&request("PUT", "/ui/note.txt")));
        assert!(!is_browser_console_request(&request(
            "GET",
            "/maxio/api/version"
        )));

        let mut virtual_host = request("GET", "/ui/note.txt");
        virtual_host
            .extensions_mut()
            .insert(SignedRequestPath("/note.txt".to_string()));
        assert!(!is_browser_console_request(&virtual_host));
    }
}

async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    insert_security_headers(response.headers_mut());
    response
}
