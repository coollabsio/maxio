use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use http::Method;
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
use crate::limits::{limit_headers, limit_inflight, limit_request_time};
use crate::storage::filesystem::FilesystemStorage;
use crate::vhost;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<FilesystemStorage>,
    pub config: Arc<Config>,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
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
        // Probe only. A signed request, a query (`?versioning`), or a
        // virtual-hosted bucket named healthz is an S3 call.
        if is_health_probe(&request, &self.domains) {
            let response = health_probe_response(request.method());
            return Box::pin(std::future::ready(Ok(response)));
        }
        vhost::apply(&mut request, &self.domains);
        Box::pin(<Router as Service<Request<Body>>>::call(
            &mut self.router,
            request,
        ))
    }
}

/// Unauthenticated `GET` or `HEAD /healthz` with no query and no virtual-host bucket.
fn is_health_probe(request: &Request<Body>, domains: &[String]) -> bool {
    let method = request.method();
    if *method != Method::GET && *method != Method::HEAD {
        return false;
    }
    let uri = request.uri();
    if uri.path() != "/healthz" || uri.query().is_some() {
        return false;
    }
    if request.headers().contains_key(http::header::AUTHORIZATION) {
        return false;
    }
    !vhost::host_is_bucket(request, domains)
}

fn health_probe_response(method: &Method) -> axum::response::Response {
    let body = if *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(format!(r#"{{"status":"ok","version":"{VERSION}"}}"#))
    };
    let mut response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("health probe response");
    insert_security_headers(response.headers_mut());
    response
}

fn insert_security_headers(headers: &mut axum::http::HeaderMap) {
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
        .nest("/api", console_router(state.clone()))
        .route("/readyz", get(readyz))
        // MinIO-compatible probes (GET and HEAD, unauthenticated). Registered
        // here, outside the S3 router, so the SigV4 auth layer never runs.
        // `/healthz` is not a route: AppService answers the probe only for an
        // unauthenticated GET/HEAD with no query and no virtual-host bucket.
        // Everything else, including bucket `healthz`, is S3.
        .route("/minio/health/live", get(live))
        .route("/minio/health/ready", get(readyz))
        .route("/minio/health/cluster", get(readyz))
        .route("/ui", get(redirect_to_ui_root))
        .route("/ui/", get(ui_handler))
        .route("/ui/{*path}", get(ui_handler))
        .merge(s3_routes)
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

/// `/ui` -> `/ui/` (keeps the query), so the console has one canonical base URL.
async fn redirect_to_ui_root(uri: axum::http::Uri) -> axum::response::Redirect {
    match uri.query() {
        Some(query) => axum::response::Redirect::permanent(&format!("/ui/?{query}")),
        None => axum::response::Redirect::permanent("/ui/"),
    }
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
    // Error bodies already carry the id they put in `<RequestId>`. Replacing
    // it makes the header disagree with the XML (clients compare the two).
    if !response.headers().contains_key("x-amz-request-id") {
        if let Ok(value) = request_id.parse() {
            response.headers_mut().insert("x-amz-request-id", value);
        }
    }
    response
}

async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    insert_security_headers(response.headers_mut());
    response
}
