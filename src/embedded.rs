use axum::http::{Uri, header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "ui/dist"]
struct UiAssets;

pub async fn ui_handler(uri: Uri) -> Response {
    let path = uri.path().strip_prefix("/ui").unwrap_or(uri.path());
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match UiAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();

            let hash = file.metadata.sha256_hash();
            let etag = hex::encode(&hash[..8]);

            let cache_control = if path == "index.html" {
                "no-store, must-revalidate"
            } else {
                "public, max-age=31536000, immutable"
            };

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, mime.as_ref().to_string()),
                    (header::ETAG, format!("\"{etag}\"")),
                    (header::CACHE_CONTROL, cache_control.to_string()),
                ],
                file.data,
            )
                .into_response()
        }
        None => match UiAssets::get("index.html") {
            Some(index) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
                 (header::CACHE_CONTROL, "no-store, must-revalidate".to_string())],
                index.data,
            )
                .into_response(),
            None => (
                StatusCode::SERVICE_UNAVAILABLE,
                "UI not built. Run: cd ui && bun run build",
            )
                .into_response(),
        },
    }
}
