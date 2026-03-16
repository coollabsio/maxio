use axum::{
    Router,
    body::Body,
    response::Response,
    routing::{delete, get, head, options, post, put},
};
use http::StatusCode;

use crate::server::AppState;

use super::{bucket, list, object};

/// Dummy OPTIONS handler — the real preflight logic runs in the CORS middleware.
async fn options_handler() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

pub fn s3_router() -> Router<AppState> {
    Router::new()
        .route("/", get(bucket::list_buckets))
        // Bucket routes — with and without trailing slash
        .route("/{bucket}", put(bucket::handle_bucket_put))
        .route("/{bucket}/", put(bucket::handle_bucket_put))
        .route("/{bucket}", head(bucket::head_bucket))
        .route("/{bucket}/", head(bucket::head_bucket))
        .route("/{bucket}", delete(bucket::delete_bucket))
        .route("/{bucket}/", delete(bucket::delete_bucket))
        .route("/{bucket}", get(list::handle_bucket_get))
        .route("/{bucket}/", get(list::handle_bucket_get))
        .route("/{bucket}", options(options_handler))
        .route("/{bucket}/", options(options_handler))
        // POST for DeleteObjects (multi-object delete)
        .route("/{bucket}", post(object::delete_objects))
        .route("/{bucket}/", post(object::delete_objects))
        // Object routes
        .route("/{bucket}/{*key}", post(object::post_object))
        .route("/{bucket}/{*key}", put(object::put_object))
        .route("/{bucket}/{*key}", get(object::get_object))
        .route("/{bucket}/{*key}", head(object::head_object))
        .route("/{bucket}/{*key}", delete(object::delete_object))
        .route("/{bucket}/{*key}", options(options_handler))
}
