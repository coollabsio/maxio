use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "ui/dist"]
struct UiAssets;

pub async fn ui_handler(uri: Uri) -> Response {
    let path = uri.path().strip_prefix("/ui").unwrap_or(uri.path());
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    let requested_file = UiAssets::get(path);
    let missing_asset = requested_file.is_none()
        && path
            .rsplit('/')
            .next()
            .is_some_and(|segment| segment.contains('.'));

    match requested_file.map(|file| (file, path)).or_else(|| {
        (!missing_asset)
            .then(|| UiAssets::get("index.html").map(|file| (file, "index.html")))
            .flatten()
    }) {
        Some((file, served_path)) => {
            let mime = mime_guess::from_path(served_path).first_or_octet_stream();
            let hash = file.metadata.sha256_hash();
            let etag = hex::encode(&hash[..8]);
            let cache_control = cache_control(served_path);

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
        None if missing_asset => (StatusCode::NOT_FOUND, "Asset not found").into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "UI not built. Run: cd ui && bun run build",
        )
            .into_response(),
    }
}

/// Vite puts content-hashed files in `assets/`; everything else keeps its name between builds.
fn cache_control(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "no-store, must-revalidate"
    } else if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

#[cfg(test)]
mod tests {
    use super::cache_control;

    #[test]
    fn only_hashed_assets_are_cached_forever() {
        assert_eq!(
            cache_control("assets/index-Buc3FXVi.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control("index.html"), "no-store, must-revalidate");
        // Icons and the manifest keep their names across builds: revalidate them.
        for path in ["manifest.webmanifest", "icon-512.png", "logo.svg"] {
            assert_eq!(cache_control(path), "no-cache", "{path}");
        }
    }
}
