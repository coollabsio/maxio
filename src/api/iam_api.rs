//! A subset of the AWS IAM query API (`POST /` with `Action=...`).
//!
//! `aws iam --endpoint-url http://host:port` signs with service `iam` and posts
//! form fields. Supported actions: users, access keys, inline policies, and
//! managed policies. Groups, roles, and account aliases are not implemented.
//! Enable and disable of a user is console-only (`iam:UpdateUser` on
//! `/maxio/api/iam/users/{name}/status`); AWS IAM has no DisableUser action.

use std::collections::HashMap;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error::S3Error;
use crate::iam::policy::{self, PolicyDocument};
use crate::iam::store::{self, IamError, IamStore, KeyStatus};
use crate::iam::{self, Authenticated, Principal};
use crate::server::AppState;

const BODY_MAX: usize = 1024 * 1024;

pub async fn handle(State(state): State<AppState>, request: Request) -> Result<Response, S3Error> {
    let authn = request
        .extensions()
        .get::<Authenticated>()
        .cloned()
        .ok_or_else(|| S3Error::access_denied("Access Denied"))?;
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, BODY_MAX)
        .await
        .map_err(|_| S3Error::invalid_argument("IAM request body is too large"))?;
    let text = String::from_utf8_lossy(&bytes);
    let mut form = query_map(parts.uri.query().unwrap_or(""));
    for (key, value) in query_map(&text) {
        form.insert(key, value);
    }
    let action = form
        .get("Action")
        .cloned()
        .ok_or_else(|| S3Error::invalid_argument("Missing IAM Action"))?;
    if let Err(err) = authorize(&state, &authn.principal, &action).await {
        return Ok(iam_error(err));
    }
    let store = match store::store_for(&state.config).await {
        Ok(store) => store,
        Err(err) => return Ok(iam_error(err)),
    };
    match dispatch(&store, &authn.principal, &action, &form).await {
        Ok(body) => Ok(xml_ok(&action, &body)),
        Err(err) => Ok(iam_error(err)),
    }
}

async fn authorize(state: &AppState, principal: &Principal, action: &str) -> Result<(), IamError> {
    if principal.is_root() {
        return Ok(());
    }
    let iam_action = format!("iam:{action}");
    let allowed = iam::identity_allows(
        &state.config,
        principal,
        &iam_action,
        "*",
        None,
        false,
        false,
    )
    .await?;
    if allowed {
        Ok(())
    } else {
        Err(IamError::Invalid("Access denied".into()))
    }
}

async fn dispatch(
    store: &IamStore,
    principal: &Principal,
    action: &str,
    form: &HashMap<String, String>,
) -> Result<String, IamError> {
    match action {
        "CreateUser" => {
            let name = required(form, "UserName")?;
            let user = store.create_user(&name).await?;
            Ok(user_xml(&user.name, &user.user_id, &user.created_at))
        }
        "GetUser" => {
            let name = form
                .get("UserName")
                .cloned()
                .or_else(|| calling_user(principal))
                .ok_or_else(|| IamError::Invalid("UserName is required for the root key".into()))?;
            let user = store.get_user(&name).await?;
            Ok(user_xml(&user.name, &user.user_id, &user.created_at))
        }
        "ListUsers" => {
            let mut members = String::new();
            for user in store.list_users().await {
                members.push_str("<member>");
                members.push_str(&user_inner(&user.name, &user.user_id, &user.created_at));
                members.push_str("</member>");
            }
            Ok(format!(
                "<Users>{members}</Users><IsTruncated>false</IsTruncated>"
            ))
        }
        "DeleteUser" => {
            let name = required(form, "UserName")?;
            store.delete_user(&name, false).await?;
            Ok(String::new())
        }
        "CreateAccessKey" => {
            let name = form
                .get("UserName")
                .cloned()
                .or_else(|| calling_user(principal))
                .ok_or_else(|| IamError::Invalid("UserName is required for the root key".into()))?;
            let created = store.create_access_key(&name, None).await?;
            Ok(access_key_xml(&created, true))
        }
        "ListAccessKeys" => {
            let name = form
                .get("UserName")
                .cloned()
                .or_else(|| calling_user(principal))
                .ok_or_else(|| IamError::Invalid("UserName is required for the root key".into()))?;
            let mut members = String::new();
            for key in store.list_access_keys(&name).await? {
                members.push_str("<member>");
                members.push_str(&access_key_inner(
                    &name,
                    &key.access_key_id,
                    key.status.as_str(),
                    &key.created_at,
                    None,
                ));
                members.push_str("</member>");
            }
            Ok(format!(
                "<AccessKeyMetadata>{members}</AccessKeyMetadata><IsTruncated>false</IsTruncated>"
            ))
        }
        "UpdateAccessKey" => {
            let id = required(form, "AccessKeyId")?;
            let status = KeyStatus::parse(&required(form, "Status")?)?;
            if let Some(name) = form.get("UserName") {
                store.update_access_key(Some(name), &id, status).await?;
            } else {
                store.update_key_by_id(&id, status).await?;
            }
            Ok(String::new())
        }
        "DeleteAccessKey" => {
            let id = required(form, "AccessKeyId")?;
            if let Some(name) = form.get("UserName") {
                store.delete_access_key(Some(name), &id).await?;
            } else {
                store.delete_key_by_id(&id).await?;
            }
            Ok(String::new())
        }
        "PutUserPolicy" => {
            let user = required(form, "UserName")?;
            let policy = required(form, "PolicyName")?;
            let document = parse_document(&required(form, "PolicyDocument")?)?;
            store.put_inline_policy(&user, &policy, document).await?;
            Ok(String::new())
        }
        "GetUserPolicy" => {
            let user = required(form, "UserName")?;
            let policy = required(form, "PolicyName")?;
            let document = store.get_inline_policy(&user, &policy).await?;
            let json = document.to_canonical_json().map_err(IamError::Invalid)?;
            Ok(format!(
                "<UserName>{}</UserName><PolicyName>{}</PolicyName><PolicyDocument>{}</PolicyDocument>",
                xesc(&user),
                xesc(&policy),
                xesc(&json)
            ))
        }
        "DeleteUserPolicy" => {
            let user = required(form, "UserName")?;
            let policy = required(form, "PolicyName")?;
            store.delete_inline_policy(&user, &policy).await?;
            Ok(String::new())
        }
        "ListUserPolicies" => {
            let user = required(form, "UserName")?;
            let mut members = String::new();
            for name in store.list_inline_names(&user).await? {
                members.push_str(&format!("<member>{}</member>", xesc(&name)));
            }
            Ok(format!(
                "<PolicyNames>{members}</PolicyNames><IsTruncated>false</IsTruncated>"
            ))
        }
        "CreatePolicy" => {
            let name = required(form, "PolicyName")?;
            let description = form.get("Description").cloned().unwrap_or_default();
            let document = parse_document(&required(form, "PolicyDocument")?)?;
            let policy = store.create_policy(&name, &description, document).await?;
            Ok(managed_xml(
                &policy.name,
                &policy.description,
                &policy.created_at,
                &policy.updated_at,
            ))
        }
        "GetPolicy" => {
            let name = policy_name(form)?;
            let policy = store.get_policy(&name).await?;
            Ok(managed_xml(
                &policy.name,
                &policy.description,
                &policy.created_at,
                &policy.updated_at,
            ))
        }
        "ListPolicies" => {
            let mut members = String::new();
            for policy in store.list_policies().await {
                members.push_str("<member>");
                members.push_str(&managed_inner(
                    &policy.name,
                    &policy.description,
                    &policy.created_at,
                    &policy.updated_at,
                ));
                members.push_str("</member>");
            }
            Ok(format!(
                "<Policies>{members}</Policies><IsTruncated>false</IsTruncated>"
            ))
        }
        "DeletePolicy" => {
            let name = policy_name(form)?;
            store.delete_policy(&name).await?;
            Ok(String::new())
        }
        "CreatePolicyVersion" => {
            let name = policy_name(form)?;
            let document = parse_document(&required(form, "PolicyDocument")?)?;
            store.update_policy(&name, None, document).await?;
            Ok("<PolicyVersion><VersionId>v1</VersionId><IsDefaultVersion>true</IsDefaultVersion></PolicyVersion>".into())
        }
        "GetPolicyVersion" | "ListPolicyVersions" => {
            let name = policy_name(form)?;
            let policy = store.get_policy(&name).await?;
            let json = policy
                .document
                .to_canonical_json()
                .map_err(IamError::Invalid)?;
            let version = format!(
                "<VersionId>v1</VersionId><IsDefaultVersion>true</IsDefaultVersion><Document>{}</Document><CreateDate>{}</CreateDate>",
                xesc(&json),
                xesc(&policy.updated_at)
            );
            if action == "GetPolicyVersion" {
                Ok(format!("<PolicyVersion>{version}</PolicyVersion>"))
            } else {
                Ok(format!(
                    "<Versions><member>{version}</member></Versions><IsTruncated>false</IsTruncated>"
                ))
            }
        }
        "AttachUserPolicy" => {
            let user = required(form, "UserName")?;
            let name = policy_name(form)?;
            store.attach_policy(&user, &name).await?;
            Ok(String::new())
        }
        "DetachUserPolicy" => {
            let user = required(form, "UserName")?;
            let name = policy_name(form)?;
            store.detach_policy(&user, &name).await?;
            Ok(String::new())
        }
        "ListAttachedUserPolicies" => {
            let user = required(form, "UserName")?;
            let mut members = String::new();
            for name in store.list_attached(&user).await? {
                let policy = store.get_policy(&name).await?;
                members.push_str(&format!(
                    "<member><PolicyName>{}</PolicyName><PolicyArn>{}</PolicyArn></member>",
                    xesc(&policy.name),
                    xesc(&iam::policy_arn(&policy.name))
                ));
            }
            Ok(format!(
                "<AttachedPolicies>{members}</AttachedPolicies><IsTruncated>false</IsTruncated>"
            ))
        }
        _ => Err(IamError::Invalid(format!(
            "IAM action {action} is not implemented"
        ))),
    }
}

fn calling_user(principal: &Principal) -> Option<String> {
    match principal {
        Principal::User { name, .. } => Some(name.clone()),
        Principal::Root | Principal::Service { .. } | Principal::Anonymous => None,
    }
}

fn required(form: &HashMap<String, String>, name: &str) -> Result<String, IamError> {
    form.get(name)
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| IamError::Invalid(format!("missing {name}")))
}

fn policy_name(form: &HashMap<String, String>) -> Result<String, IamError> {
    if let Some(arn) = form.get("PolicyArn") {
        return iam::parse_policy_name(arn)
            .map(str::to_string)
            .ok_or_else(|| IamError::Invalid(format!("invalid policy ARN: {arn}")));
    }
    required(form, "PolicyName")
}

fn parse_document(text: &str) -> Result<PolicyDocument, IamError> {
    policy::parse_policy_str(text).map_err(IamError::Invalid)
}

fn user_xml(name: &str, id: &str, created: &str) -> String {
    format!("<User>{}</User>", user_inner(name, id, created))
}

fn user_inner(name: &str, id: &str, created: &str) -> String {
    format!(
        "<Path>/</Path><UserName>{}</UserName><UserId>{}</UserId><Arn>{}</Arn><CreateDate>{}</CreateDate>",
        xesc(name),
        xesc(id),
        xesc(&iam::user_arn(name)),
        xesc(created)
    )
}

fn access_key_xml(created: &store::CreatedKey, with_secret: bool) -> String {
    let secret = with_secret.then_some(created.secret.as_str());
    format!(
        "<AccessKey>{}</AccessKey>",
        access_key_inner(
            created.info.user_name.as_deref().unwrap_or(""),
            &created.info.access_key_id,
            created.info.status.as_str(),
            &created.info.created_at,
            secret,
        )
    )
}

fn access_key_inner(
    user: &str,
    id: &str,
    status: &str,
    created: &str,
    secret: Option<&str>,
) -> String {
    let secret_xml = secret
        .map(|secret| format!("<SecretAccessKey>{}</SecretAccessKey>", xesc(secret)))
        .unwrap_or_default();
    format!(
        "<UserName>{}</UserName><AccessKeyId>{}</AccessKeyId><Status>{}</Status><CreateDate>{}</CreateDate>{secret_xml}",
        xesc(user),
        xesc(id),
        xesc(status),
        xesc(created)
    )
}

fn managed_xml(name: &str, description: &str, created: &str, updated: &str) -> String {
    format!(
        "<Policy>{}</Policy>",
        managed_inner(name, description, created, updated)
    )
}

fn managed_inner(name: &str, description: &str, created: &str, updated: &str) -> String {
    format!(
        "<PolicyName>{}</PolicyName><PolicyId>{}</PolicyId><Arn>{}</Arn><Path>/</Path><DefaultVersionId>v1</DefaultVersionId><AttachmentCount>0</AttachmentCount><IsAttachable>true</IsAttachable><Description>{}</Description><CreateDate>{}</CreateDate><UpdateDate>{}</UpdateDate>",
        xesc(name),
        xesc(&format!("MXIP{name}")),
        xesc(&iam::policy_arn(name)),
        xesc(description),
        xesc(created),
        xesc(updated)
    )
}

fn xml_ok(action: &str, inner: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<{action}Response xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><{action}Result>{inner}</{action}Result><ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>",
        uuid::Uuid::new_v4().simple()
    );
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "text/xml")],
        body,
    )
        .into_response()
}

fn iam_error(err: IamError) -> Response {
    let (status, code) = match &err {
        IamError::Invalid(message) if message == "Access denied" => {
            (StatusCode::FORBIDDEN, "AccessDenied")
        }
        IamError::Invalid(message) if message.starts_with("malformed policy") => {
            (StatusCode::BAD_REQUEST, "MalformedPolicyDocument")
        }
        other => (other.status_code(), other.iam_code()),
    };
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Type>Sender</Type><Code>{code}</Code><Message>{}</Message></Error><RequestId>{}</RequestId></ErrorResponse>",
        xesc(&err.to_string()),
        uuid::Uuid::new_v4().simple()
    );
    (status, [(http::header::CONTENT_TYPE, "text/xml")], body).into_response()
}

fn xesc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn query_map(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in text.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_form(key);
        let value = decode_form(value);
        if !key.is_empty() {
            map.insert(key, value);
        }
    }
    map
}

fn decode_form(value: &str) -> String {
    let spaced = value.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced)
        .decode_utf8_lossy()
        .into_owned()
}
