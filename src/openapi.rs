//! OpenAPI document for the web console API (`/api/*`).
//!
//! `maxio openapi --output ui/src/api/generated/openapi.json` writes it; the UI
//! generates its typed client from that file (`just api`).

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::api::{console, iam_console};

#[derive(OpenApi)]
#[openapi(
    info(title = "MaxIO Console API", version = "maxio-console-v1"),
    security(("cookieAuth" = [])),
    modifiers(&CookieAuth),
    paths(
        console::server_version,
        console::login,
        console::check,
        console::capabilities,
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
        console::restore_version,
        console::get_object_info,
        console::get_object_tags,
        console::set_object_tags,
        console::get_bucket_tags,
        console::set_bucket_tags,
        console::get_bucket_policy_view,
        console::get_bucket_lifecycle_api,
        console::set_bucket_lifecycle_api,
        iam_console::list_users,
        iam_console::create_user,
        iam_console::get_user,
        iam_console::delete_user,
        iam_console::set_user_status,
        iam_console::list_keys,
        iam_console::create_key,
        iam_console::set_key_status,
        iam_console::delete_key,
        iam_console::list_service_keys,
        iam_console::create_service_key,
        iam_console::set_service_key_status,
        iam_console::delete_service_key,
        iam_console::list_policies,
        iam_console::create_policy,
        iam_console::get_policy,
        iam_console::update_policy,
        iam_console::delete_policy,
        iam_console::attach_policy,
        iam_console::detach_policy,
        iam_console::put_inline,
        iam_console::delete_inline,
        iam_console::preview_policy,
        iam_console::validate_policy,
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
                "attachUserPolicy",
                "checkAuth",
                "createAccessKey",
                "createBucket",
                "createFolder",
                "createIamPolicy",
                "createIamUser",
                "createServiceKey",
                "deleteAccessKey",
                "deleteBucket",
                "deleteIamPolicy",
                "deleteIamUser",
                "deleteInlineUserPolicy",
                "deleteObject",
                "deleteServiceKey",
                "deleteVersion",
                "detachUserPolicy",
                "downloadObject",
                "downloadVersion",
                "getBucketLifecycle",
                "getBucketPolicy",
                "getBucketTags",
                "getCapabilities",
                "getEncryption",
                "getIamPolicy",
                "getIamUser",
                "getObjectInfo",
                "getObjectTags",
                "getPublicAccess",
                "getServerVersion",
                "getVersioning",
                "listAccessKeys",
                "listBuckets",
                "listIamPolicies",
                "listIamUsers",
                "listObjects",
                "listServiceKeys",
                "listVersions",
                "login",
                "logout",
                "presignObject",
                "previewIamPolicy",
                "putInlineUserPolicy",
                "restoreVersion",
                "setAccessKeyStatus",
                "setBucketLifecycle",
                "setBucketTags",
                "setEncryption",
                "setIamUserStatus",
                "setObjectTags",
                "setPublicAccess",
                "setServiceKeyStatus",
                "setVersioning",
                "updateIamPolicy",
                "uploadObject",
                "validateIamPolicy",
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
