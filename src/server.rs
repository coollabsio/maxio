use axum::Router;
use axum::routing::get;
use std::sync::Arc;

use crate::api::console::console_router;
use crate::api::router::s3_router;
use crate::auth::middleware::auth_middleware;
use crate::config::Config;
use crate::embedded::ui_handler;
use crate::storage::filesystem::FilesystemStorage;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<FilesystemStorage>,
    pub config: Arc<Config>,
}

pub fn build_router(state: AppState) -> Router {
    let s3_routes = s3_router().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_middleware,
    ));

    Router::new()
        .nest("/api", console_router(state.clone()))
        .route("/ui", get(ui_handler))
        .route("/ui/", get(ui_handler))
        .route("/ui/{*path}", get(ui_handler))
        .merge(s3_routes)
        .with_state(state)
}
