//! JSON admin API for the web console (`/api/iam/*`).
//!
//! Root, and any principal whose policies allow the matching `iam:*` action,
//! may call these routes. Secrets are returned only from the create-key
//! responses.

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Router, routing::delete};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::iam::policy::{self, PolicyDocument};
use crate::iam::store::{self, IamError, KeyStatus};
use crate::server::AppState;

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    error: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InlinePolicyView {
    name: String,
    document_json: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    name: String,
    user_id: String,
    enabled: bool,
    created_at: String,
    key_count: usize,
    attached_policies: Vec<String>,
    inline_policies: Vec<InlinePolicyView>,
}

#[derive(Serialize, ToSchema)]
pub struct UserListResponse {
    users: Vec<UserView>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateUserBody {
    name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct EnabledBody {
    enabled: bool,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    access_key_id: String,
    user_name: Option<String>,
    label: String,
    status: String,
    created_at: String,
    has_policy: bool,
    /// Set when the key has its own policy. That policy only narrows the user.
    policy_summary: Option<String>,
    policy_json: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct KeyListResponse {
    keys: Vec<KeyView>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreatedKeyResponse {
    access_key_id: String,
    secret_access_key: String,
    created_at: String,
    status: String,
    /// Policy saved with this key, when the request included a scope or document.
    document_json: Option<String>,
}

fn default_key_only() -> bool {
    true
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyBody {
    /// Bucket names. Empty with `access` set means every bucket.
    #[serde(default)]
    buckets: Vec<String>,
    #[serde(default)]
    prefix: String,
    /// `read`, `write`, `readwrite`, or `admin`.
    access: Option<String>,
    /// Omitted means true. The scope is stored on this key only. `false` is rejected: creating a key never grants the user.
    #[serde(default = "default_key_only")]
    #[schema(default = true)]
    key_only: bool,
    /// Raw policy JSON. Used instead of `access` when set.
    document_json: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct KeyStatusBody {
    status: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyView {
    name: String,
    description: String,
    builtin: bool,
    created_at: String,
    updated_at: String,
    document_json: String,
}

#[derive(Serialize, ToSchema)]
pub struct PolicyListResponse {
    policies: Vec<PolicyView>,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyWriteBody {
    name: String,
    #[serde(default)]
    description: String,
    document_json: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyUpdateBody {
    #[serde(default)]
    description: Option<String>,
    document_json: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AttachBody {
    name: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocumentBody {
    document_json: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreviewBody {
    #[serde(default)]
    buckets: Vec<String>,
    #[serde(default)]
    prefix: String,
    access: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocumentResponse {
    document_json: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceKeyBody {
    name: String,
    #[serde(default)]
    buckets: Vec<String>,
    #[serde(default)]
    prefix: String,
    access: Option<String>,
    document_json: Option<String>,
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

fn iam_err(err: IamError) -> Response {
    error(err.status_code(), err.to_string())
}

fn json_doc(doc: &PolicyDocument) -> Result<String, IamError> {
    serde_json::to_string_pretty(doc).map_err(|err| IamError::Invalid(err.to_string()))
}

fn user_view(user: store::UserInfo) -> Result<UserView, IamError> {
    let mut inline_policies = Vec::new();
    for inline in user.inline_policies {
        inline_policies.push(InlinePolicyView {
            name: inline.name,
            document_json: json_doc(&inline.document)?,
        });
    }
    Ok(UserView {
        name: user.name,
        user_id: user.user_id,
        enabled: user.enabled,
        created_at: user.created_at,
        key_count: user.key_count,
        attached_policies: user.attached_policies,
        inline_policies,
    })
}

fn key_view(key: store::KeyInfo) -> KeyView {
    KeyView {
        access_key_id: key.access_key_id,
        user_name: key.user_name,
        label: key.label,
        status: key.status.as_str().to_string(),
        created_at: key.created_at,
        has_policy: key.has_policy,
        policy_summary: key.policy_summary,
        policy_json: key.policy_json,
    }
}

fn policy_view(policy: store::ManagedPolicyInfo) -> Result<PolicyView, IamError> {
    Ok(PolicyView {
        name: policy.name,
        description: policy.description,
        builtin: policy.builtin,
        created_at: policy.created_at,
        updated_at: policy.updated_at,
        document_json: json_doc(&policy.document)?,
    })
}

async fn open_store(state: &AppState) -> Result<std::sync::Arc<store::IamStore>, Response> {
    store::store_for(&state.config).await.map_err(iam_err)
}

fn scope_or_document(
    body_access: Option<&str>,
    buckets: &[String],
    prefix: &str,
    document_json: Option<&str>,
) -> Result<Option<PolicyDocument>, IamError> {
    if let Some(json) = document_json {
        return Ok(Some(
            policy::parse_policy_str(json).map_err(IamError::Invalid)?,
        ));
    }
    if let Some(access) = body_access {
        for bucket in buckets {
            if !crate::storage::is_valid_bucket_name(bucket) {
                return Err(IamError::Invalid(format!("invalid bucket name: {bucket}")));
            }
        }
        if prefix.contains('\0') || prefix.contains("..") {
            return Err(IamError::Invalid("invalid prefix".into()));
        }
        return Ok(Some(policy::policy_for_scope(
            buckets,
            prefix,
            policy::ScopeAccess::parse(access).map_err(IamError::Invalid)?,
        )));
    }
    Ok(None)
}

#[utoipa::path(
    get,
    path = "/api/iam/users",
    operation_id = "listIamUsers",
    tag = "iam",
    responses((status = 200, body = UserListResponse), (status = 403, body = ErrorBody))
)]
pub async fn list_users(State(state): State<AppState>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store
        .list_users()
        .await
        .into_iter()
        .map(user_view)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(users) => (StatusCode::OK, Json(UserListResponse { users })).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    post,
    path = "/api/iam/users",
    operation_id = "createIamUser",
    tag = "iam",
    request_body = CreateUserBody,
    responses((status = 200, body = UserView), (status = 409, body = ErrorBody))
)]
pub async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.create_user(body.name.trim()).await {
        Ok(user) => match user_view(user) {
            Ok(view) => (StatusCode::OK, Json(view)).into_response(),
            Err(err) => iam_err(err),
        },
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    get,
    path = "/api/iam/users/{name}",
    operation_id = "getIamUser",
    tag = "iam",
    params(("name" = String, Path)),
    responses((status = 200, body = UserView), (status = 404, body = ErrorBody))
)]
pub async fn get_user(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.get_user(&name).await.and_then(user_view) {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    delete,
    path = "/api/iam/users/{name}",
    operation_id = "deleteIamUser",
    tag = "iam",
    params(("name" = String, Path)),
    responses((status = 200, description = "User, keys, and inline policies removed"))
)]
pub async fn delete_user(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.delete_user(&name, true).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    put,
    path = "/api/iam/users/{name}/status",
    operation_id = "setIamUserStatus",
    tag = "iam",
    params(("name" = String, Path)),
    request_body = EnabledBody,
    responses((status = 200, body = UserView))
)]
pub async fn set_user_status(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<EnabledBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store
        .set_user_enabled(&name, body.enabled)
        .await
        .and_then(user_view)
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    get,
    path = "/api/iam/users/{name}/keys",
    operation_id = "listAccessKeys",
    tag = "iam",
    params(("name" = String, Path)),
    responses((status = 200, body = KeyListResponse))
)]
pub async fn list_keys(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.list_access_keys(&name).await {
        Ok(keys) => (
            StatusCode::OK,
            Json(KeyListResponse {
                keys: keys.into_iter().map(key_view).collect(),
            }),
        )
            .into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    post,
    path = "/api/iam/users/{name}/keys",
    operation_id = "createAccessKey",
    tag = "iam",
    params(("name" = String, Path)),
    request_body = CreateKeyBody,
    responses((status = 200, description = "Secret is returned once", body = CreatedKeyResponse))
)]
pub async fn create_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<CreateKeyBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let document = match scope_or_document(
        body.access.as_deref(),
        &body.buckets,
        &body.prefix,
        body.document_json.as_deref(),
    ) {
        Ok(document) => document,
        Err(err) => return iam_err(err),
    };
    if !body.key_only {
        return error(
            StatusCode::BAD_REQUEST,
            "Creating an access key cannot add permissions to the user. Grant scope with an inline or managed policy, then create the key.",
        );
    }
    let document_json = document.as_ref().and_then(|doc| json_doc(doc).ok());
    match store.create_access_key(&name, document).await {
        Ok(created) => (
            StatusCode::OK,
            Json(CreatedKeyResponse {
                access_key_id: created.info.access_key_id,
                secret_access_key: created.secret,
                created_at: created.info.created_at,
                status: created.info.status.as_str().to_string(),
                document_json,
            }),
        )
            .into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    put,
    path = "/api/iam/users/{name}/keys/{id}",
    operation_id = "setAccessKeyStatus",
    tag = "iam",
    params(("name" = String, Path), ("id" = String, Path)),
    request_body = KeyStatusBody,
    responses((status = 200, body = KeyView))
)]
pub async fn set_key_status(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, String)>,
    Json(body): Json<KeyStatusBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let status = match KeyStatus::parse(&body.status) {
        Ok(status) => status,
        Err(err) => return iam_err(err),
    };
    match store.update_access_key(Some(&name), &id, status).await {
        Ok(key) => (StatusCode::OK, Json(key_view(key))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    delete,
    path = "/api/iam/users/{name}/keys/{id}",
    operation_id = "deleteAccessKey",
    tag = "iam",
    params(("name" = String, Path), ("id" = String, Path)),
    responses((status = 200, description = "Key deleted"))
)]
pub async fn delete_key(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.delete_access_key(Some(&name), &id).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    get,
    path = "/api/iam/service-keys",
    operation_id = "listServiceKeys",
    tag = "iam",
    responses((status = 200, body = KeyListResponse))
)]
pub async fn list_service_keys(State(state): State<AppState>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let keys = store.list_service_keys().await;
    (
        StatusCode::OK,
        Json(KeyListResponse {
            keys: keys.into_iter().map(key_view).collect(),
        }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/api/iam/service-keys",
    operation_id = "createServiceKey",
    tag = "iam",
    request_body = ServiceKeyBody,
    responses((status = 200, body = CreatedKeyResponse))
)]
pub async fn create_service_key(
    State(state): State<AppState>,
    Json(body): Json<ServiceKeyBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let document = match scope_or_document(
        body.access.as_deref(),
        &body.buckets,
        &body.prefix,
        body.document_json.as_deref(),
    ) {
        Ok(Some(document)) => document,
        Ok(None) => {
            return error(
                StatusCode::BAD_REQUEST,
                "a service key needs an access scope or a policy document",
            );
        }
        Err(err) => return iam_err(err),
    };
    let document_json = json_doc(&document).ok();
    match store.create_service_key(body.name.trim(), document).await {
        Ok(created) => (
            StatusCode::OK,
            Json(CreatedKeyResponse {
                access_key_id: created.info.access_key_id,
                secret_access_key: created.secret,
                created_at: created.info.created_at,
                status: created.info.status.as_str().to_string(),
                document_json,
            }),
        )
            .into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    put,
    path = "/api/iam/service-keys/{id}",
    operation_id = "setServiceKeyStatus",
    tag = "iam",
    params(("id" = String, Path)),
    request_body = KeyStatusBody,
    responses((status = 200, body = KeyView))
)]
pub async fn set_service_key_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<KeyStatusBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let status = match KeyStatus::parse(&body.status) {
        Ok(status) => status,
        Err(err) => return iam_err(err),
    };
    match store.update_access_key(None, &id, status).await {
        Ok(key) => (StatusCode::OK, Json(key_view(key))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    delete,
    path = "/api/iam/service-keys/{id}",
    operation_id = "deleteServiceKey",
    tag = "iam",
    params(("id" = String, Path)),
    responses((status = 200, description = "Service key deleted"))
)]
pub async fn delete_service_key(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.delete_access_key(None, &id).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    get,
    path = "/api/iam/policies",
    operation_id = "listIamPolicies",
    tag = "iam",
    responses((status = 200, body = PolicyListResponse))
)]
pub async fn list_policies(State(state): State<AppState>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store
        .list_policies()
        .await
        .into_iter()
        .map(policy_view)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(policies) => (StatusCode::OK, Json(PolicyListResponse { policies })).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    post,
    path = "/api/iam/policies",
    operation_id = "createIamPolicy",
    tag = "iam",
    request_body = PolicyWriteBody,
    responses((status = 200, body = PolicyView))
)]
pub async fn create_policy(
    State(state): State<AppState>,
    Json(body): Json<PolicyWriteBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let document = match policy::parse_policy_str(&body.document_json) {
        Ok(document) => document,
        Err(err) => return error(StatusCode::BAD_REQUEST, err),
    };
    match store
        .create_policy(body.name.trim(), &body.description, document)
        .await
        .and_then(policy_view)
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    get,
    path = "/api/iam/policies/{name}",
    operation_id = "getIamPolicy",
    tag = "iam",
    params(("name" = String, Path)),
    responses((status = 200, body = PolicyView))
)]
pub async fn get_policy(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.get_policy(&name).await.and_then(policy_view) {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    put,
    path = "/api/iam/policies/{name}",
    operation_id = "updateIamPolicy",
    tag = "iam",
    params(("name" = String, Path)),
    request_body = PolicyUpdateBody,
    responses((status = 200, body = PolicyView))
)]
pub async fn update_policy(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<PolicyUpdateBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let document = match policy::parse_policy_str(&body.document_json) {
        Ok(document) => document,
        Err(err) => return error(StatusCode::BAD_REQUEST, err),
    };
    match store
        .update_policy(&name, body.description.as_deref(), document)
        .await
        .and_then(policy_view)
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    delete,
    path = "/api/iam/policies/{name}",
    operation_id = "deleteIamPolicy",
    tag = "iam",
    params(("name" = String, Path)),
    responses((status = 200, description = "Custom policy deleted"))
)]
pub async fn delete_policy(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.delete_policy(&name).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    post,
    path = "/api/iam/users/{name}/policies",
    operation_id = "attachUserPolicy",
    tag = "iam",
    params(("name" = String, Path)),
    request_body = AttachBody,
    responses((status = 200, description = "Policy attached"))
)]
pub async fn attach_policy(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<AttachBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.attach_policy(&name, body.name.trim()).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    delete,
    path = "/api/iam/users/{name}/policies/{policy}",
    operation_id = "detachUserPolicy",
    tag = "iam",
    params(("name" = String, Path), ("policy" = String, Path)),
    responses((status = 200, description = "Policy detached"))
)]
pub async fn detach_policy(
    State(state): State<AppState>,
    Path((name, policy)): Path<(String, String)>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.detach_policy(&name, &policy).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    put,
    path = "/api/iam/users/{name}/inline/{policy}",
    operation_id = "putInlineUserPolicy",
    tag = "iam",
    params(("name" = String, Path), ("policy" = String, Path)),
    request_body = DocumentBody,
    responses((status = 200, description = "Inline policy saved"))
)]
pub async fn put_inline(
    State(state): State<AppState>,
    Path((name, policy)): Path<(String, String)>,
    Json(body): Json<DocumentBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    let document = match policy::parse_policy_str(&body.document_json) {
        Ok(document) => document,
        Err(err) => return error(StatusCode::BAD_REQUEST, err),
    };
    match store.put_inline_policy(&name, &policy, document).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    delete,
    path = "/api/iam/users/{name}/inline/{policy}",
    operation_id = "deleteInlineUserPolicy",
    tag = "iam",
    params(("name" = String, Path), ("policy" = String, Path)),
    responses((status = 200, description = "Inline policy deleted"))
)]
pub async fn delete_inline(
    State(state): State<AppState>,
    Path((name, policy)): Path<(String, String)>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store.delete_inline_policy(&name, &policy).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    post,
    path = "/api/iam/preview",
    operation_id = "previewIamPolicy",
    tag = "iam",
    request_body = PreviewBody,
    responses((status = 200, body = DocumentResponse))
)]
pub async fn preview_policy(
    State(state): State<AppState>,
    Json(body): Json<PreviewBody>,
) -> Response {
    let store = match open_store(&state).await {
        Ok(store) => store,
        Err(resp) => return resp,
    };
    match store
        .preview_scope(&body.buckets, &body.prefix, &body.access)
        .await
    {
        Ok(document) => match json_doc(&document) {
            Ok(document_json) => {
                (StatusCode::OK, Json(DocumentResponse { document_json })).into_response()
            }
            Err(err) => iam_err(err),
        },
        Err(err) => iam_err(err),
    }
}

#[utoipa::path(
    post,
    path = "/api/iam/validate",
    operation_id = "validateIamPolicy",
    tag = "iam",
    request_body = DocumentBody,
    responses((status = 200, body = DocumentResponse), (status = 400, body = ErrorBody))
)]
pub async fn validate_policy(Json(body): Json<DocumentBody>) -> Response {
    match policy::parse_policy_str(&body.document_json) {
        Ok(document) => match json_doc(&document) {
            Ok(document_json) => {
                (StatusCode::OK, Json(DocumentResponse { document_json })).into_response()
            }
            Err(err) => iam_err(err),
        },
        Err(err) => error(StatusCode::BAD_REQUEST, err),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/iam/users", get(list_users).post(create_user))
        .route("/iam/users/{name}", get(get_user).delete(delete_user))
        .route("/iam/users/{name}/status", put(set_user_status))
        .route("/iam/users/{name}/keys", get(list_keys).post(create_key))
        .route(
            "/iam/users/{name}/keys/{id}",
            put(set_key_status).delete(delete_key),
        )
        .route("/iam/users/{name}/policies", post(attach_policy))
        .route("/iam/users/{name}/policies/{policy}", delete(detach_policy))
        .route(
            "/iam/users/{name}/inline/{policy}",
            put(put_inline).delete(delete_inline),
        )
        .route(
            "/iam/service-keys",
            get(list_service_keys).post(create_service_key),
        )
        .route(
            "/iam/service-keys/{id}",
            put(set_service_key_status).delete(delete_service_key),
        )
        .route("/iam/policies", get(list_policies).post(create_policy))
        .route(
            "/iam/policies/{name}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route("/iam/preview", post(preview_policy))
        .route("/iam/validate", post(validate_policy))
}
