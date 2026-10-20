//! Maps an authenticated S3 request to IAM actions and enforces them.
//!
//! Root is allowed through. Anonymous requests were already limited to public
//! reads by the auth middleware. Every other principal must pass policy
//! evaluation. `POST /` is the IAM query API; that handler checks `iam:*`.

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::HeaderMap;
use percent_encoding::percent_decode_str;

use crate::error::S3Error;
use crate::iam::{self, Authenticated, Principal};
use crate::server::AppState;

use super::object::{parse_copy_source, parse_delete_request};

const DELETE_BODY_MAX: usize = 2 * 1024 * 1024;

struct Check {
    action: String,
    resource: String,
    prefix: Option<String>,
    bucket: Option<String>,
}

enum Requirement {
    Allow,
    /// `POST /` IAM query protocol. The handler enforces `iam:<Action>`.
    IamApi,
    Checks(Vec<Check>),
}

pub async fn s3_authz_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, S3Error> {
    let Some(authn) = request.extensions().get::<Authenticated>().cloned() else {
        return Err(S3Error::access_denied("Access Denied"));
    };
    if matches!(authn.principal, Principal::Root | Principal::Anonymous) {
        return Ok(next.run(request).await);
    }

    let method = request.method().clone();
    if method == http::Method::OPTIONS {
        return Ok(next.run(request).await);
    }
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();

    let (parts, body) = request.into_parts();
    let (requirement, body) = if is_delete_objects(method.as_str(), &path, &query) {
        let bytes = axum::body::to_bytes(body, DELETE_BODY_MAX)
            .await
            .map_err(|_| S3Error::malformed_xml())?;
        let requirement = delete_objects_requirement(&path, &bytes)?;
        (requirement, Body::from(bytes))
    } else {
        (required(&method, &path, &query, &parts.headers)?, body)
    };
    enforce(&state, &authn.principal, requirement).await?;
    Ok(next.run(Request::from_parts(parts, body)).await)
}

async fn enforce(
    state: &AppState,
    principal: &Principal,
    requirement: Requirement,
) -> Result<(), S3Error> {
    let checks = match requirement {
        Requirement::Allow | Requirement::IamApi => return Ok(()),
        Requirement::Checks(checks) => checks,
    };
    for check in checks {
        let (public_read, public_list) = match &check.bucket {
            Some(bucket) => state
                .storage
                .get_bucket_public(bucket)
                .await
                .unwrap_or((false, false)),
            None => (false, false),
        };
        iam::authorize(
            &state.config,
            principal,
            &check.action,
            &check.resource,
            check.prefix.as_deref(),
            public_read,
            public_list,
        )
        .await?;
    }
    Ok(())
}

fn is_delete_objects(method: &str, path: &str, query: &str) -> bool {
    if method != "POST" {
        return false;
    }
    let segments = decode_path(path);
    segments.len() == 1 && query_map(query).contains_key("delete")
}

fn delete_objects_requirement(path: &str, body: &[u8]) -> Result<Requirement, S3Error> {
    let bucket = decode_path(path).into_iter().next().unwrap_or_default();
    let Ok(text) = std::str::from_utf8(body) else {
        return Ok(Requirement::Allow);
    };
    let Ok((targets, _)) = parse_delete_request(text) else {
        return Ok(Requirement::Allow);
    };
    let mut checks = Vec::new();
    for target in targets {
        reject_reserved_object_key(&target.key)?;
        let action = if target.version_id.is_some() {
            "s3:DeleteObjectVersion"
        } else {
            "s3:DeleteObject"
        };
        checks.push(Check {
            action: action.to_string(),
            resource: iam::policy::object_arn(&bucket, &target.key),
            prefix: None,
            bucket: Some(bucket.clone()),
        });
    }
    Ok(Requirement::Checks(checks))
}

fn reject_reserved_object_key(key: &str) -> Result<(), S3Error> {
    if let Some(message) = crate::storage::filesystem::reserved_key_message(key) {
        return Err(S3Error::invalid_argument(&message));
    }
    Ok(())
}

fn required(
    method: &http::Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
) -> Result<Requirement, S3Error> {
    let segments = decode_path(path);
    let q = query_map(query);
    let method = method.as_str();
    if segments.is_empty() {
        return Ok(match method {
            "GET" | "HEAD" => Requirement::Checks(vec![Check {
                action: "s3:ListAllMyBuckets".into(),
                resource: "*".into(),
                prefix: None,
                bucket: None,
            }]),
            "POST" => Requirement::IamApi,
            _ => Requirement::Allow,
        });
    }

    let bucket = segments[0].clone();
    if segments.len() == 1 {
        return Ok(Requirement::Checks(bucket_checks(method, &bucket, &q)));
    }
    let key = segments[1..].join("/");
    Ok(Requirement::Checks(object_checks(
        method, &bucket, &key, &q, headers,
    )?))
}

fn bucket_checks(method: &str, bucket: &str, q: &HashMap<String, String>) -> Vec<Check> {
    let arn = iam::policy::bucket_arn(bucket);
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let action = match method {
        "GET" | "HEAD" => bucket_read_action(q),
        "PUT" => bucket_put_action(q),
        "DELETE" => bucket_delete_action(q),
        "POST" if q.contains_key("delete") => "s3:DeleteObject",
        _ => "s3:ListBucket",
    };
    let list = matches!(
        action,
        "s3:ListBucket" | "s3:ListBucketVersions" | "s3:ListBucketMultipartUploads"
    );
    vec![Check {
        action: action.to_string(),
        resource: arn,
        prefix: list.then_some(prefix),
        bucket: Some(bucket.to_string()),
    }]
}

fn bucket_read_action(q: &HashMap<String, String>) -> &'static str {
    for (flag, action) in [
        ("location", "s3:GetBucketLocation"),
        ("acl", "s3:GetBucketAcl"),
        ("cors", "s3:GetBucketCors"),
        ("encryption", "s3:GetEncryptionConfiguration"),
        ("policy", "s3:GetBucketPolicy"),
        ("policyStatus", "s3:GetBucketPolicyStatus"),
        ("tagging", "s3:GetBucketTagging"),
        ("lifecycle", "s3:GetLifecycleConfiguration"),
        ("versioning", "s3:GetBucketVersioning"),
        ("versions", "s3:ListBucketVersions"),
        ("uploads", "s3:ListBucketMultipartUploads"),
        ("logging", "s3:GetBucketLogging"),
        ("notification", "s3:GetBucketNotification"),
        ("requestPayment", "s3:GetBucketRequestPayment"),
        ("accelerate", "s3:GetAccelerateConfiguration"),
        ("object-lock", "s3:GetBucketObjectLockConfiguration"),
        ("website", "s3:GetBucketWebsite"),
        ("replication", "s3:GetReplicationConfiguration"),
        ("ownershipControls", "s3:GetBucketOwnershipControls"),
        ("publicAccessBlock", "s3:GetBucketPublicAccessBlock"),
    ] {
        if q.contains_key(flag) {
            return action;
        }
    }
    "s3:ListBucket"
}

fn bucket_put_action(q: &HashMap<String, String>) -> &'static str {
    for (flag, action) in [
        ("versioning", "s3:PutBucketVersioning"),
        ("cors", "s3:PutBucketCors"),
        ("encryption", "s3:PutEncryptionConfiguration"),
        ("policy", "s3:PutBucketPolicy"),
        ("acl", "s3:PutBucketAcl"),
        ("tagging", "s3:PutBucketTagging"),
        ("lifecycle", "s3:PutLifecycleConfiguration"),
    ] {
        if q.contains_key(flag) {
            return action;
        }
    }
    "s3:CreateBucket"
}

fn bucket_delete_action(q: &HashMap<String, String>) -> &'static str {
    for (flag, action) in [
        ("cors", "s3:PutBucketCors"),
        ("encryption", "s3:PutEncryptionConfiguration"),
        ("policy", "s3:DeleteBucketPolicy"),
        ("tagging", "s3:PutBucketTagging"),
        ("lifecycle", "s3:PutLifecycleConfiguration"),
    ] {
        if q.contains_key(flag) {
            return action;
        }
    }
    "s3:DeleteBucket"
}

fn object_checks(
    method: &str,
    bucket: &str,
    key: &str,
    q: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Vec<Check>, S3Error> {
    reject_reserved_object_key(key)?;
    let resource = iam::policy::object_arn(bucket, key);
    let version = q.contains_key("versionId");
    let mut checks = Vec::new();
    let action = match method {
        "GET" | "HEAD" => object_read_action(q, version),
        "PUT" => {
            if headers.contains_key("x-amz-copy-source") {
                checks.extend(copy_source_checks(headers)?);
            }
            object_put_action(q)
        }
        "DELETE" => object_delete_action(q, version),
        "POST" => "s3:PutObject",
        _ => "s3:GetObject",
    };
    checks.push(Check {
        action: action.to_string(),
        resource,
        prefix: None,
        bucket: Some(bucket.to_string()),
    });
    Ok(checks)
}

fn object_read_action(q: &HashMap<String, String>, version: bool) -> &'static str {
    if q.contains_key("acl") {
        return "s3:GetObjectAcl";
    }
    if q.contains_key("tagging") {
        return "s3:GetObjectTagging";
    }
    if q.contains_key("attributes") {
        return "s3:GetObjectAttributes";
    }
    if q.contains_key("uploadId") {
        return "s3:ListMultipartUploadParts";
    }
    if q.contains_key("retention") {
        return "s3:GetObjectRetention";
    }
    if q.contains_key("legal-hold") {
        return "s3:GetObjectLegalHold";
    }
    if version {
        "s3:GetObjectVersion"
    } else {
        "s3:GetObject"
    }
}

fn object_put_action(q: &HashMap<String, String>) -> &'static str {
    if q.contains_key("acl") {
        return "s3:PutObjectAcl";
    }
    if q.contains_key("tagging") {
        return "s3:PutObjectTagging";
    }
    if q.contains_key("retention") {
        return "s3:PutObjectRetention";
    }
    if q.contains_key("legal-hold") {
        return "s3:PutObjectLegalHold";
    }
    "s3:PutObject"
}

fn object_delete_action(q: &HashMap<String, String>, version: bool) -> &'static str {
    if q.contains_key("tagging") {
        return "s3:DeleteObjectTagging";
    }
    if q.contains_key("uploadId") {
        return "s3:AbortMultipartUpload";
    }
    if version {
        "s3:DeleteObjectVersion"
    } else {
        "s3:DeleteObject"
    }
}

fn copy_source_checks(headers: &HeaderMap) -> Result<Vec<Check>, S3Error> {
    if !headers.contains_key("x-amz-copy-source") {
        return Ok(Vec::new());
    }
    let source = parse_copy_source(headers)?;
    reject_reserved_object_key(&source.key)?;
    let action = if source.version_id.is_some() {
        "s3:GetObjectVersion"
    } else {
        "s3:GetObject"
    };
    Ok(vec![Check {
        action: action.to_string(),
        resource: iam::policy::object_arn(&source.bucket, &source.key),
        prefix: None,
        bucket: Some(source.bucket),
    }])
}

fn decode_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| percent_decode_str(s).decode_utf8_lossy().into_owned())
        .collect()
}

fn query_map(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_str(key).decode_utf8_lossy().into_owned();
        let value = percent_decode_str(value).decode_utf8_lossy().into_owned();
        map.insert(key, value);
    }
    map
}

/// Console routes the handler must authorize after it has read the body.
#[derive(Debug, PartialEq, Eq)]
pub enum ConsoleGate {
    /// Identity is allowed to run the route.
    Allow,
    /// `POST /buckets` and folder creation: the handler checks the final name.
    Defer,
}

/// Authorize one console API route. `path` may be `/buckets/...` or `/api/buckets/...`.
pub async fn authorize_console(
    state: &AppState,
    principal: &Principal,
    method: &str,
    path: &str,
    query: &str,
) -> Result<ConsoleGate, S3Error> {
    if principal.is_root() {
        return Ok(ConsoleGate::Allow);
    }
    let path = path
        .strip_prefix("/api")
        .unwrap_or(path)
        .trim_end_matches('/');
    let q = query_map(query);
    if path == "/auth/logout"
        || (path == "/version" && method == "GET")
        || (path == "/buckets" && method == "GET")
        || (path == "/auth/capabilities" && method == "GET")
    {
        return Ok(ConsoleGate::Allow);
    }
    if path == "/buckets" && method == "POST" {
        return Ok(ConsoleGate::Defer);
    }
    if let Some(rest) = path.strip_prefix("/iam/") {
        let action = console_iam_action(method, rest)
            .ok_or_else(|| S3Error::access_denied("Access Denied"))?;
        return iam_console_action(state, principal, action).await;
    }
    if let Some(rest) = path.strip_prefix("/buckets/") {
        return console_bucket(state, principal, method, rest, &q).await;
    }
    Err(S3Error::access_denied("Access Denied"))
}

async fn iam_console_action(
    state: &AppState,
    principal: &Principal,
    action: &str,
) -> Result<ConsoleGate, S3Error> {
    iam::authorize(&state.config, principal, action, "*", None, false, false).await?;
    Ok(ConsoleGate::Allow)
}

fn console_iam_action(method: &str, rest: &str) -> Option<&'static str> {
    let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    Some(match (method, parts.as_slice()) {
        ("GET", ["users"]) => "iam:ListUsers",
        ("POST", ["users"]) => "iam:CreateUser",
        ("GET", ["users", _]) => "iam:GetUser",
        ("DELETE", ["users", _]) => "iam:DeleteUser",
        ("PUT", ["users", _, "status"]) => "iam:UpdateUser",
        ("GET", ["users", _, "keys"]) => "iam:ListAccessKeys",
        ("POST", ["users", _, "keys"]) => "iam:CreateAccessKey",
        ("PUT", ["users", _, "keys", _]) => "iam:UpdateAccessKey",
        ("DELETE", ["users", _, "keys", _]) => "iam:DeleteAccessKey",
        ("POST", ["users", _, "policies"]) => "iam:AttachUserPolicy",
        ("DELETE", ["users", _, "policies", _]) => "iam:DetachUserPolicy",
        ("PUT", ["users", _, "inline", _]) => "iam:PutUserPolicy",
        ("DELETE", ["users", _, "inline", _]) => "iam:DeleteUserPolicy",
        ("GET", ["service-keys"]) => "iam:ListAccessKeys",
        ("POST", ["service-keys"]) => "iam:CreateAccessKey",
        ("PUT", ["service-keys", _]) => "iam:UpdateAccessKey",
        ("DELETE", ["service-keys", _]) => "iam:DeleteAccessKey",
        ("GET", ["policies"]) => "iam:ListPolicies",
        ("POST", ["policies"]) => "iam:CreatePolicy",
        ("GET", ["policies", _]) => "iam:GetPolicy",
        ("PUT", ["policies", _]) => "iam:CreatePolicyVersion",
        ("DELETE", ["policies", _]) => "iam:DeletePolicy",
        ("POST", ["preview"]) => "iam:CreateAccessKey",
        ("POST", ["validate"]) => "iam:CreatePolicy",
        _ => return None,
    })
}

async fn console_bucket(
    state: &AppState,
    principal: &Principal,
    method: &str,
    rest: &str,
    q: &HashMap<String, String>,
) -> Result<ConsoleGate, S3Error> {
    let (bucket, after) = match rest.split_once('/') {
        Some((bucket, after)) => (decode_component(bucket), after),
        None => {
            if method == "DELETE" {
                authorize_s3(
                    state,
                    principal,
                    "s3:DeleteBucket",
                    &decode_component(rest),
                    None,
                    None,
                )
                .await?;
                return Ok(ConsoleGate::Allow);
            }
            return Err(S3Error::access_denied("Access Denied"));
        }
    };
    if after == "folders" && method == "POST" {
        return Ok(ConsoleGate::Defer);
    }
    let (action, key, prefix, extra): (&str, Option<String>, Option<String>, Option<&str>) =
        match (method, after) {
            ("GET", "objects") => (
                "s3:ListBucket",
                None,
                Some(q.get("prefix").cloned().unwrap_or_default()),
                None,
            ),
            ("DELETE", rest) if rest.starts_with("objects/") => (
                "s3:DeleteObject",
                Some(decode_component(&after["objects/".len()..])),
                None,
                None,
            ),
            ("PUT", rest) if rest.starts_with("upload/") => (
                "s3:PutObject",
                Some(decode_component(&after["upload/".len()..])),
                None,
                None,
            ),
            ("GET", rest) if rest.starts_with("download/") => (
                "s3:GetObject",
                Some(decode_component(&after["download/".len()..])),
                None,
                None,
            ),
            ("GET", rest) if rest.starts_with("presign/") => (
                "s3:GetObject",
                Some(decode_component(&after["presign/".len()..])),
                None,
                None,
            ),
            ("GET", "versioning") => ("s3:GetBucketVersioning", None, None, None),
            ("PUT", "versioning") => ("s3:PutBucketVersioning", None, None, None),
            ("GET", "encryption") => ("s3:GetEncryptionConfiguration", None, None, None),
            ("PUT", "encryption") => ("s3:PutEncryptionConfiguration", None, None, None),
            ("GET", "public") => ("s3:GetBucketPolicy", None, None, None),
            ("PUT", "public") => ("s3:PutBucketPolicy", None, None, None),
            ("GET", "versions") => (
                "s3:ListBucketVersions",
                None,
                q.get("key").cloned().or_else(|| Some(String::new())),
                None,
            ),
            ("GET", "tags") => ("s3:GetBucketTagging", None, None, None),
            ("PUT", "tags") => ("s3:PutBucketTagging", None, None, None),
            ("GET", "policy") => ("s3:GetBucketPolicy", None, None, None),
            ("GET", "lifecycle") => ("s3:GetLifecycleConfiguration", None, None, None),
            ("PUT", "lifecycle") => ("s3:PutLifecycleConfiguration", None, None, None),
            ("GET", rest) if rest.starts_with("object-info/") => (
                "s3:GetObject",
                Some(decode_component(&after["object-info/".len()..])),
                None,
                None,
            ),
            ("GET", rest) if rest.starts_with("object-tags/") => (
                "s3:GetObjectTagging",
                Some(decode_component(&after["object-tags/".len()..])),
                None,
                None,
            ),
            ("PUT", rest) if rest.starts_with("object-tags/") => (
                "s3:PutObjectTagging",
                Some(decode_component(&after["object-tags/".len()..])),
                None,
                None,
            ),
            _ => return version_route(state, principal, method, &bucket, after).await,
        };
    let key_ref = key.as_deref();
    authorize_s3(
        state,
        principal,
        action,
        &bucket,
        key_ref,
        prefix.as_deref(),
    )
    .await?;
    if let Some(extra) = extra {
        authorize_s3(state, principal, extra, &bucket, key_ref, None).await?;
    }
    Ok(ConsoleGate::Allow)
}

async fn version_route(
    state: &AppState,
    principal: &Principal,
    method: &str,
    bucket: &str,
    after: &str,
) -> Result<ConsoleGate, S3Error> {
    let mut parts = after.splitn(4, '/');
    let versions = parts.next();
    let version_id = parts.next();
    let kind = parts.next();
    let key = parts.next().map(decode_component);
    if versions != Some("versions") || version_id.is_none() || key.is_none() {
        return Err(S3Error::access_denied("Access Denied"));
    }
    let key = key.unwrap();
    let (action, extra) = match (method, kind) {
        ("DELETE", Some("objects")) => ("s3:DeleteObjectVersion", None),
        ("GET", Some("download")) => ("s3:GetObjectVersion", None),
        ("POST", Some("restore")) => ("s3:GetObjectVersion", Some("s3:PutObject")),
        _ => return Err(S3Error::access_denied("Access Denied")),
    };
    authorize_s3(state, principal, action, bucket, Some(&key), None).await?;
    if let Some(extra) = extra {
        authorize_s3(state, principal, extra, bucket, Some(&key), None).await?;
    }
    Ok(ConsoleGate::Allow)
}

fn decode_component(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

/// Used by console handlers that learn the resource only after reading the body.
pub async fn authorize_s3(
    state: &AppState,
    principal: &Principal,
    action: &str,
    bucket: &str,
    key: Option<&str>,
    prefix: Option<&str>,
) -> Result<(), S3Error> {
    if let Some(key) = key {
        reject_reserved_object_key(key)?;
    }
    let resource = match key {
        Some(key) => iam::policy::object_arn(bucket, key),
        None => iam::policy::bucket_arn(bucket),
    };
    let (public_read, public_list) = state
        .storage
        .get_bucket_public(bucket)
        .await
        .unwrap_or((false, false));
    iam::authorize(
        &state.config,
        principal,
        action,
        &resource,
        prefix,
        public_read,
        public_list,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions(method: &str, path: &str, query: &str) -> Vec<String> {
        let requirement =
            required(&method.parse().unwrap(), path, query, &HeaderMap::new()).unwrap();
        match requirement {
            Requirement::Checks(checks) => checks.into_iter().map(|c| c.action).collect(),
            Requirement::IamApi => vec!["iam-api".into()],
            Requirement::Allow => vec!["allow".into()],
        }
    }

    #[test]
    fn reserved_object_key_is_rejected_before_authorization() {
        let err = required(
            &http::Method::PUT,
            "/pics/.maxio.object",
            "",
            &HeaderMap::new(),
        )
        .err()
        .expect("reserved key");
        assert_eq!(err.code.status_code(), http::StatusCode::BAD_REQUEST);
        assert!(
            err.message
                .contains("collides with an internal storage name")
        );
        let err = required(
            &http::Method::PUT,
            "/pics/docs/.maxio-tmp-crash",
            "",
            &HeaderMap::new(),
        )
        .err()
        .expect("reserved key");
        assert_eq!(err.code.status_code(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn maps_bucket_and_object_operations() {
        assert_eq!(actions("GET", "/", ""), vec!["s3:ListAllMyBuckets"]);
        assert_eq!(actions("POST", "/", ""), vec!["iam-api"]);
        assert_eq!(actions("PUT", "/pics", ""), vec!["s3:CreateBucket"]);
        assert_eq!(actions("DELETE", "/pics", ""), vec!["s3:DeleteBucket"]);
        assert_eq!(
            actions("GET", "/pics", "prefix=albums/"),
            vec!["s3:ListBucket"]
        );
        assert_eq!(
            actions("GET", "/pics", "versioning"),
            vec!["s3:GetBucketVersioning"]
        );
        assert_eq!(
            actions("PUT", "/pics", "encryption"),
            vec!["s3:PutEncryptionConfiguration"]
        );
        assert_eq!(
            actions("DELETE", "/pics", "policy"),
            vec!["s3:DeleteBucketPolicy"]
        );
        assert_eq!(
            actions("GET", "/pics/albums/a.jpg", ""),
            vec!["s3:GetObject"]
        );
        assert_eq!(
            actions("GET", "/pics/a.jpg", "versionId=1"),
            vec!["s3:GetObjectVersion"]
        );
        assert_eq!(
            actions("PUT", "/pics/a.jpg", "uploadId=u&partNumber=1"),
            vec!["s3:PutObject"]
        );
        assert_eq!(
            actions("DELETE", "/pics/a.jpg", "uploadId=u"),
            vec!["s3:AbortMultipartUpload"]
        );
        assert_eq!(
            actions("POST", "/pics/a.jpg", "uploads"),
            vec!["s3:PutObject"]
        );
        assert_eq!(
            actions("GET", "/pics/a.jpg", "tagging"),
            vec!["s3:GetObjectTagging"]
        );
    }

    #[test]
    fn copy_source_requires_get_on_the_source_object() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-copy-source", "/other/src.txt".parse().unwrap());
        let requirement =
            required(&"PUT".parse().unwrap(), "/pics/dest.txt", "", &headers).unwrap();
        let Requirement::Checks(checks) = requirement else {
            panic!("expected checks");
        };
        assert_eq!(checks[0].action, "s3:GetObject");
        assert_eq!(checks[0].resource, "arn:aws:s3:::other/src.txt");
        assert_eq!(checks[1].action, "s3:PutObject");
        assert_eq!(checks[1].resource, "arn:aws:s3:::pics/dest.txt");
    }

    #[test]
    fn list_prefix_is_passed_to_the_condition() {
        let requirement = required(
            &"GET".parse().unwrap(),
            "/pics",
            "list-type=2&prefix=albums%2F",
            &HeaderMap::new(),
        )
        .unwrap();
        let Requirement::Checks(checks) = requirement else {
            panic!("expected checks");
        };
        assert_eq!(checks[0].prefix.as_deref(), Some("albums/"));
        assert_eq!(checks[0].resource, "arn:aws:s3:::pics");
    }

    #[test]
    fn delete_objects_checks_each_key() {
        let xml = r#"<Delete><Object><Key>a.txt</Key></Object><Object><Key>b.txt</Key><VersionId>v1</VersionId></Object></Delete>"#;
        let requirement = delete_objects_requirement("/pics", xml.as_bytes()).unwrap();
        let Requirement::Checks(checks) = requirement else {
            panic!("expected checks");
        };
        assert_eq!(checks[0].action, "s3:DeleteObject");
        assert_eq!(checks[0].resource, "arn:aws:s3:::pics/a.txt");
        assert_eq!(checks[1].action, "s3:DeleteObjectVersion");
        assert_eq!(checks[1].resource, "arn:aws:s3:::pics/b.txt");
    }

    #[test]
    fn malformed_delete_is_left_to_the_handler() {
        let requirement = delete_objects_requirement("/pics", b"not-xml").unwrap();
        assert!(matches!(requirement, Requirement::Allow));
    }
}
