//! OpenAPI document for the web console API (`/api/*`).
//!
//! `maxio openapi --output ui/src/api/generated/openapi.json` writes it; the UI
//! generates its typed client from that file (`just api`).

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::api::console;

#[derive(OpenApi)]
#[openapi(
    info(title = "MaxIO Console API", version = "maxio-console-v1"),
    security(("cookieAuth" = [])),
    modifiers(&CookieAuth),
    paths(
        console::login,
        console::check,
        console::logout,
        console::list_buckets,
        console::create_bucket,
        console::delete_bucket_api,
        console::create_folder,
        console::list_objects,
        console::delete_object_api,
        console::upload_object,
        console::download_object,
        console::presign_object,
        console::get_versioning,
        console::set_versioning,
        console::get_encryption,
        console::set_encryption,
        console::get_public,
        console::set_public,
        console::list_versions,
        console::delete_version,
        console::download_version,
    )
)]
struct ApiDocument;

struct CookieAuth;

impl Modify for CookieAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "cookieAuth",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("maxio_session"))),
            );
    }
}

pub fn openapi_json() -> String {
    let mut json = ApiDocument::openapi()
        .to_pretty_json()
        .expect("OpenAPI document serializes");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_lists_every_console_operation() {
        let doc: serde_json::Value = serde_json::from_str(&openapi_json()).unwrap();
        let mut ids: Vec<&str> = doc["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|item| item.as_object().unwrap().values())
            .filter_map(|op| op["operationId"].as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            [
                "checkAuth",
                "createBucket",
                "createFolder",
                "deleteBucket",
                "deleteObject",
                "deleteVersion",
                "downloadObject",
                "downloadVersion",
                "getEncryption",
                "getPublicAccess",
                "getVersioning",
                "listBuckets",
                "listObjects",
                "listVersions",
                "login",
                "logout",
                "presignObject",
                "setEncryption",
                "setPublicAccess",
                "setVersioning",
                "uploadObject",
            ]
        );
    }

    #[test]
    fn login_and_check_are_public() {
        let doc: serde_json::Value = serde_json::from_str(&openapi_json()).unwrap();
        for (path, method) in [("/api/auth/login", "post"), ("/api/auth/check", "get")] {
            assert_eq!(
                doc["paths"][path][method]["security"],
                serde_json::json!([{}])
            );
        }
        assert_eq!(doc["security"], serde_json::json!([{ "cookieAuth": [] }]));
    }
}
