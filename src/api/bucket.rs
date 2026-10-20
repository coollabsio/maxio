use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::error::{S3Error, S3ErrorCode};
use crate::server::AppState;
use crate::storage::{
    BucketEncryptionConfig, BucketMeta, CorsRule, StorageError, is_valid_bucket_name,
};
use crate::xml::{response::to_xml, types::*};
use serde::Deserialize;

pub async fn list_buckets(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    let mut buckets = state
        .storage
        .list_buckets()
        .await
        .map_err(|e| S3Error::internal(e))?;

    if let Some(prefix) = params.get("prefix") {
        buckets.retain(|b| b.name.starts_with(prefix));
    }
    if let Some(token) = params.get("continuation-token").filter(|t| !t.is_empty()) {
        buckets.retain(|b| b.name.as_str() > token.as_str());
    }
    let max_buckets = match params.get("max-buckets") {
        None => None,
        Some(raw) => {
            let n: i64 = raw
                .parse()
                .map_err(|_| S3Error::invalid_argument("Invalid value for max-buckets"))?;
            if !(1..=10_000).contains(&n) {
                return Err(S3Error::invalid_argument(
                    "max-buckets must be between 1 and 10000",
                ));
            }
            Some(n as usize)
        }
    };
    let continuation = match max_buckets {
        Some(max) if buckets.len() > max => {
            buckets.truncate(max);
            buckets.last().map(|b| b.name.clone())
        }
        _ => None,
    };

    let result = ListAllMyBucketsResult {
        owner: owner(),
        buckets: Buckets {
            bucket: buckets
                .into_iter()
                .map(|b| BucketEntry {
                    name: b.name,
                    creation_date: b.created_at,
                })
                .collect(),
        },
        prefix: params.get("prefix").cloned().filter(|p| !p.is_empty()),
        continuation_token: continuation,
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    validate_bucket_name(&bucket)?;
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| S3Error::malformed_xml())?;
    let text = String::from_utf8_lossy(&bytes);
    if let Some(constraint) = location_constraint_value(&text) {
        // us-east-1 rejects any LocationConstraint, including itself.
        // Every other region must name this server's region.
        let ok = state.config.region != "us-east-1" && constraint == state.config.region;
        if !ok {
            return Err(S3Error::illegal_location_constraint());
        }
    }

    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let meta = BucketMeta {
        name: bucket.clone(),
        created_at: now,
        region: state.config.region.clone(),
        versioning: false,
        cors_rules: None,
        encryption_config: None,
        public_read: false,
        public_list: false,
        versioning_suspended: false,
        tags: None,
        lifecycle: None,
    };

    let created = state
        .storage
        .create_bucket(&meta)
        .await
        .map_err(|e| S3Error::internal(e))?;

    if !created {
        // In us-east-1, recreating a bucket you already own is success.
        // Other regions return BucketAlreadyOwnedByYou.
        if state.config.region == "us-east-1" {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Location", format!("/{bucket}"))
                .header("x-amz-bucket-region", state.config.region.as_str())
                .body(Body::empty())
                .unwrap());
        }
        return Err(S3Error::bucket_already_owned(&bucket));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Location", format!("/{}", bucket))
        .body(Body::empty())
        .unwrap())
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(StorageError::InvalidKey(_)) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("x-amz-bucket-region", &*state.config.region)
        .body(Body::empty())
        .unwrap())
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    match bucket_subresource(&params) {
        None => {}
        Some("cors") => return delete_bucket_cors(state, bucket).await,
        Some("encryption") => return delete_bucket_encryption(state, bucket).await,
        Some("policy") => {
            require_bucket(&state, &bucket).await?;
            state
                .storage
                .set_bucket_public(&bucket, false, false)
                .await
                .map_err(S3Error::internal)?;
            return Ok(no_content());
        }
        Some("tagging") => {
            require_bucket(&state, &bucket).await?;
            state
                .storage
                .set_bucket_tags(&bucket, None)
                .await
                .map_err(S3Error::internal)?;
            return Ok(no_content());
        }
        Some("lifecycle") => {
            return super::lifecycle::delete_bucket_lifecycle(state, bucket).await;
        }
        // Nothing is ever stored for these, so deleting is a no-op.
        Some("website" | "replication" | "ownershipControls" | "publicAccessBlock") => {
            require_bucket(&state, &bucket).await?;
            return Ok(no_content());
        }
        Some(sub) => return Err(unsupported_subresource("DELETE", sub)),
    }
    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap()),
        Ok(false) => Err(S3Error::no_such_bucket(&bucket)),
        Err(StorageError::BucketNotEmpty) => Err(S3Error::bucket_not_empty(&bucket)),
        Err(e) => Err(S3Error::internal(e)),
    }
}

pub async fn handle_bucket_put(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match bucket_subresource(&params) {
        None => create_bucket(State(state), Path(bucket), body).await,
        Some("versioning") => put_bucket_versioning(State(state), Path(bucket), body).await,
        Some("cors") => put_bucket_cors(state, bucket, body).await,
        Some("encryption") => put_bucket_encryption(state, bucket, body).await,
        Some("policy") => put_bucket_policy(state, bucket, body).await,
        Some("acl") => put_bucket_acl(state, bucket, &headers, body).await,
        Some("tagging") => put_bucket_tagging(state, bucket, body).await,
        Some("lifecycle") => {
            super::lifecycle::put_bucket_lifecycle(state, bucket, &headers, body).await
        }
        Some(sub) => Err(unsupported_subresource("PUT", sub)),
    }
}

/// POST on a bucket is only DeleteObjects (`?delete`).
pub async fn handle_bucket_post(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match bucket_subresource(&params) {
        Some("delete") => {
            super::object::delete_objects(State(state), Path(bucket), headers, body).await
        }
        Some(sub) => Err(unsupported_subresource("POST", sub)),
        None => Err(S3Error::not_implemented(
            "POST on a bucket without ?delete (browser-based POST upload) is not implemented",
        )),
    }
}

async fn put_bucket_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let body_bytes = axum::body::to_bytes(body, 1024 * 64)
        .await
        .map_err(|e| S3Error::internal(e))?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Parse <VersioningConfiguration><Status>Enabled|Suspended</Status></VersioningConfiguration>
    let enabled = match extract_xml_tag(&body_str, "Status").as_deref() {
        Some("Enabled") => true,
        Some("Suspended") => false,
        _ => return Err(S3Error::malformed_xml()),
    };

    state
        .storage
        .set_versioning(&bucket, enabled)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

pub async fn get_bucket_versioning(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let meta = state
        .storage
        .get_bucket_meta(&bucket)
        .await
        .map_err(S3Error::internal)?;

    let result = VersioningConfiguration {
        status: if meta.versioning {
            Some("Enabled".to_string())
        } else if meta.versioning_suspended {
            Some("Suspended".to_string())
        } else {
            None
        },
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn put_bucket_cors(
    state: AppState,
    bucket: String,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let body_bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|e| S3Error::internal(e))?;

    let config: CorsConfiguration = quick_xml::de::from_str(&String::from_utf8_lossy(&body_bytes))
        .map_err(|_| S3Error::malformed_xml())?;

    if config.rules.len() > 100 {
        return Err(S3Error::invalid_argument(
            "CORS configuration cannot have more than 100 rules",
        ));
    }
    for rule in &config.rules {
        if rule.allowed_origins.is_empty() || rule.allowed_methods.is_empty() {
            return Err(S3Error::malformed_xml());
        }
        for method in &rule.allowed_methods {
            match method.as_str() {
                "GET" | "PUT" | "POST" | "DELETE" | "HEAD" => {}
                _ => {
                    return Err(S3Error::invalid_argument(&format!(
                        "Invalid HTTP method in CORS rule: {}",
                        method
                    )));
                }
            }
        }
    }

    let rules: Vec<CorsRule> = config
        .rules
        .into_iter()
        .map(|r| CorsRule {
            allowed_origins: r.allowed_origins,
            allowed_methods: r.allowed_methods,
            allowed_headers: r.allowed_headers,
            expose_headers: r.expose_headers,
            max_age_seconds: r.max_age_seconds,
        })
        .collect();

    state
        .storage
        .put_bucket_cors(&bucket, rules)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

pub async fn get_bucket_cors(state: AppState, bucket: String) -> Result<Response<Body>, S3Error> {
    let rules = state
        .storage
        .get_bucket_cors(&bucket)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            e => S3Error::internal(e),
        })?;

    let rules = rules.ok_or_else(|| S3Error::no_such_cors_configuration())?;

    let config = CorsConfiguration {
        rules: rules
            .into_iter()
            .map(|r| crate::xml::types::CorsRuleXml {
                allowed_origins: r.allowed_origins,
                allowed_methods: r.allowed_methods,
                allowed_headers: r.allowed_headers,
                expose_headers: r.expose_headers,
                max_age_seconds: r.max_age_seconds,
            })
            .collect(),
    };

    let xml = to_xml(&config).map_err(|e| S3Error::internal(e))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn delete_bucket_cors(state: AppState, bucket: String) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    state
        .storage
        .delete_bucket_cors(&bucket)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

// --- Bucket default encryption ---------------------------------------------

async fn put_bucket_encryption(
    state: AppState,
    bucket: String,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let body_bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(S3Error::internal)?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Minimal XML parsing: <ServerSideEncryptionConfiguration><Rule>
    //   <ApplyServerSideEncryptionByDefault>
    //     <SSEAlgorithm>AES256</SSEAlgorithm>
    //   </ApplyServerSideEncryptionByDefault>
    // </Rule></ServerSideEncryptionConfiguration>
    let sse_algorithm =
        extract_xml_tag(&body_str, "SSEAlgorithm").ok_or_else(S3Error::malformed_xml)?;
    if sse_algorithm != "AES256" {
        return Err(S3Error::invalid_encryption_algorithm());
    }
    let cfg = BucketEncryptionConfig { sse_algorithm };
    state
        .storage
        .put_bucket_encryption(&bucket, cfg)
        .await
        .map_err(S3Error::internal)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

pub async fn get_bucket_encryption(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let cfg = state
        .storage
        .get_bucket_encryption(&bucket)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            e => S3Error::internal(e),
        })?;
    let cfg = cfg.ok_or_else(|| S3Error::no_such_bucket_encryption(&bucket))?;

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ServerSideEncryptionConfiguration>\
         <Rule><ApplyServerSideEncryptionByDefault>\
         <SSEAlgorithm>{}</SSEAlgorithm>\
         </ApplyServerSideEncryptionByDefault></Rule>\
         </ServerSideEncryptionConfiguration>",
        cfg.sse_algorithm
    );
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn delete_bucket_encryption(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }
    state
        .storage
        .delete_bucket_encryption(&bucket)
        .await
        .map_err(S3Error::internal)?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml[start..start + end].trim().to_string())
}

/// Text inside `<LocationConstraint>`, if the element is present and non-empty.
fn location_constraint_value(body: &str) -> Option<String> {
    let start = body.find("<LocationConstraint")?;
    let rest = &body[start..];
    let open_end = rest.find('>')?;
    let inner = &rest[open_end + 1..];
    let close = inner.find("</LocationConstraint>")?;
    let value = inner[..close].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn validate_bucket_name(name: &str) -> Result<(), S3Error> {
    if is_valid_bucket_name(name) {
        Ok(())
    } else {
        Err(S3Error::invalid_bucket_name(name))
    }
}

// --- Bucket subresources -----------------------------------------------------

pub const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Owner ID / DisplayName reported for every bucket and object.
pub const OWNER_ID: &str = "maxio";

pub(super) fn owner() -> Owner {
    Owner {
        id: OWNER_ID.to_string(),
        display_name: OWNER_ID.to_string(),
    }
}

/// Known S3 bucket subresource query parameters. A request carrying any of
/// these is a subresource operation and must never fall through to the
/// plain bucket operation (create / delete / list).
const BUCKET_SUBRESOURCES: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "cors",
    "delete",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "lifecycle",
    "location",
    "logging",
    "metadataConfiguration",
    "metadataInventoryTable",
    "metadataJournalTable",
    "metadataTable",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "restore",
    "select",
    "session",
    "tagging",
    "torrent",
    "uploads",
    "versioning",
    "versions",
    "website",
];

/// The subresource named in the query string, if any.
pub fn bucket_subresource(params: &HashMap<String, String>) -> Option<&'static str> {
    BUCKET_SUBRESOURCES
        .iter()
        .copied()
        .find(|s| params.contains_key(*s))
}

fn unsupported_subresource(method: &str, sub: &str) -> S3Error {
    S3Error::not_implemented(&format!(
        "{} on the bucket ?{} subresource is not implemented",
        method, sub
    ))
}

/// `NoSuchBucket` unless `bucket` exists (invalid names count as missing).
pub(super) async fn require_bucket(state: &AppState, bucket: &str) -> Result<(), S3Error> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) | Err(StorageError::InvalidKey(_)) => Err(S3Error::no_such_bucket(bucket)),
        Err(e) => Err(S3Error::internal(e)),
    }
}

fn no_content() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap()
}

fn xml_response(xml: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

fn xml_doc(body: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", body)
}

/// GET for bucket subresources not handled directly in `list.rs`. The caller
/// has already verified that the bucket exists.
pub async fn get_bucket_subresource(
    state: AppState,
    bucket: String,
    sub: &str,
) -> Result<Response<Body>, S3Error> {
    let not_found = |code: S3ErrorCode, msg: &str| Err(S3Error::bucket_error(code, &bucket, msg));
    match sub {
        "policy" => get_bucket_policy(state, bucket).await,
        "policyStatus" => {
            let (read, list) = bucket_public_flags(&state, &bucket).await?;
            Ok(xml_response(xml_doc(&format!(
                "<PolicyStatus xmlns=\"{}\"><IsPublic>{}</IsPublic></PolicyStatus>",
                S3_XMLNS,
                read || list
            ))))
        }
        "acl" => get_bucket_acl(state, bucket).await,
        "tagging" => get_bucket_tagging(state, bucket).await,
        "lifecycle" => super::lifecycle::get_bucket_lifecycle(state, bucket).await,
        "object-lock" => not_found(
            S3ErrorCode::ObjectLockConfigurationNotFound,
            "Object Lock configuration does not exist for this bucket",
        ),
        "website" => not_found(
            S3ErrorCode::NoSuchWebsiteConfiguration,
            "The specified bucket does not have a website configuration",
        ),
        "replication" => not_found(
            S3ErrorCode::ReplicationConfigurationNotFound,
            "The replication configuration was not found",
        ),
        "ownershipControls" => not_found(
            S3ErrorCode::OwnershipControlsNotFound,
            "The bucket ownership controls were not found",
        ),
        "publicAccessBlock" => not_found(
            S3ErrorCode::NoSuchPublicAccessBlockConfiguration,
            "The public access block configuration was not found",
        ),
        "logging" => Ok(xml_response(xml_doc(&format!(
            "<BucketLoggingStatus xmlns=\"{}\"/>",
            S3_XMLNS
        )))),
        "notification" => Ok(xml_response(xml_doc(&format!(
            "<NotificationConfiguration xmlns=\"{}\"/>",
            S3_XMLNS
        )))),
        "requestPayment" => Ok(xml_response(xml_doc(&format!(
            "<RequestPaymentConfiguration xmlns=\"{}\"><Payer>BucketOwner</Payer></RequestPaymentConfiguration>",
            S3_XMLNS
        )))),
        "accelerate" => Ok(xml_response(xml_doc(&format!(
            "<AccelerateConfiguration xmlns=\"{}\"/>",
            S3_XMLNS
        )))),
        _ => Err(unsupported_subresource("GET", sub)),
    }
}

async fn bucket_public_flags(state: &AppState, bucket: &str) -> Result<(bool, bool), S3Error> {
    state
        .storage
        .get_bucket_public(bucket)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
            e => S3Error::internal(e),
        })
}

// --- Bucket policy (mapped onto the anonymous read/list flags) -------------

const POLICY_BODY_MAX: usize = 20 * 1024;

fn unsupported_policy(detail: &str) -> S3Error {
    S3Error::not_implemented(&format!(
        "Unsupported bucket policy: {}. MaxIO only supports anonymous read-only policies: \
         Effect Allow, Principal \"*\", s3:GetObject on arn:aws:s3:::<bucket>/* and/or \
         s3:ListBucket (plus s3:GetBucketLocation, s3:ListBucketMultipartUploads) on \
         arn:aws:s3:::<bucket>",
        detail
    ))
}

/// A JSON string or array of strings.
fn string_list(v: &serde_json::Value, field: &str) -> Result<Vec<String>, S3Error> {
    match v {
        serde_json::Value::String(s) => Ok(vec![s.clone()]),
        serde_json::Value::Array(items) if !items.is_empty() => items
            .iter()
            .map(|i| {
                i.as_str().map(str::to_string).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::MalformedPolicy,
                        &format!("{} must contain strings", field),
                    )
                })
            })
            .collect(),
        _ => Err(S3Error::new(
            S3ErrorCode::MalformedPolicy,
            &format!("{} must be a string or a non-empty array of strings", field),
        )),
    }
}

fn is_anonymous_principal(p: &serde_json::Value) -> bool {
    match p {
        serde_json::Value::String(s) => s == "*",
        serde_json::Value::Object(m) => {
            m.len() == 1
                && match m.get("AWS") {
                    Some(serde_json::Value::String(s)) => s == "*",
                    Some(serde_json::Value::Array(a)) => {
                        !a.is_empty() && a.iter().all(|i| i.as_str() == Some("*"))
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

/// Parse a bucket policy into `(public_read, public_list)`.
fn parse_bucket_policy(bucket: &str, body: &[u8]) -> Result<(bool, bool), S3Error> {
    let doc: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        S3Error::new(
            S3ErrorCode::MalformedPolicy,
            &format!("Policy is not valid JSON: {}", e),
        )
    })?;
    let doc = doc.as_object().ok_or_else(|| {
        S3Error::new(S3ErrorCode::MalformedPolicy, "Policy must be a JSON object")
    })?;
    if let Some(version) = doc.get("Version") {
        match version.as_str() {
            Some("2012-10-17") | Some("2008-10-17") => {}
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MalformedPolicy,
                    "Unsupported policy Version",
                ));
            }
        }
    }
    for key in doc.keys() {
        if !matches!(key.as_str(), "Version" | "Id" | "Statement") {
            return Err(S3Error::new(
                S3ErrorCode::MalformedPolicy,
                &format!("Unknown policy field {}", key),
            ));
        }
    }
    let statements = match doc.get("Statement") {
        Some(serde_json::Value::Array(a)) if !a.is_empty() => a.iter().collect::<Vec<_>>(),
        Some(s @ serde_json::Value::Object(_)) => vec![s],
        _ => {
            return Err(S3Error::new(
                S3ErrorCode::MalformedPolicy,
                "Policy has no Statement",
            ));
        }
    };

    let bucket_arn = format!("arn:aws:s3:::{}", bucket);
    let objects_arn = format!("arn:aws:s3:::{}/*", bucket);
    let (mut read, mut list) = (false, false);

    for stmt in statements {
        let stmt = stmt.as_object().ok_or_else(|| {
            S3Error::new(S3ErrorCode::MalformedPolicy, "Statement must be an object")
        })?;
        for key in stmt.keys() {
            match key.as_str() {
                "Sid" | "Effect" | "Principal" | "Action" | "Resource" => {}
                "Condition" | "NotAction" | "NotPrincipal" | "NotResource" => {
                    return Err(unsupported_policy(&format!("{} is not supported", key)));
                }
                _ => {
                    return Err(S3Error::new(
                        S3ErrorCode::MalformedPolicy,
                        &format!("Unknown statement field {}", key),
                    ));
                }
            }
        }
        match stmt.get("Effect").and_then(|e| e.as_str()) {
            Some("Allow") => {}
            Some("Deny") => return Err(unsupported_policy("Deny statements are not supported")),
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MalformedPolicy,
                    "Statement Effect must be Allow or Deny",
                ));
            }
        }
        let principal = stmt.get("Principal").ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::MalformedPolicy,
                "Statement is missing Principal",
            )
        })?;
        if !is_anonymous_principal(principal) {
            return Err(unsupported_policy(
                "only the anonymous principal \"*\" is supported",
            ));
        }
        let actions = string_list(
            stmt.get("Action").ok_or_else(|| {
                S3Error::new(S3ErrorCode::MalformedPolicy, "Statement is missing Action")
            })?,
            "Action",
        )?;
        let resources = string_list(
            stmt.get("Resource").ok_or_else(|| {
                S3Error::new(
                    S3ErrorCode::MalformedPolicy,
                    "Statement is missing Resource",
                )
            })?,
            "Resource",
        )?;
        for r in &resources {
            if *r != bucket_arn && *r != objects_arn {
                return Err(unsupported_policy(&format!(
                    "resource {} is not supported",
                    r
                )));
            }
        }
        let on_bucket = resources.contains(&bucket_arn);
        let on_objects = resources.contains(&objects_arn);
        for action in &actions {
            match action.as_str() {
                "s3:GetObject" if on_objects => read = true,
                "s3:ListBucket" if on_bucket => list = true,
                "s3:GetBucketLocation" | "s3:ListBucketMultipartUploads" if on_bucket => {}
                _ => {
                    return Err(unsupported_policy(&format!(
                        "action {} on {:?} is not supported",
                        action, resources
                    )));
                }
            }
        }
    }
    Ok((read, list))
}

async fn put_bucket_policy(
    state: AppState,
    bucket: String,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    let body_bytes = axum::body::to_bytes(body, POLICY_BODY_MAX)
        .await
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::MalformedPolicy,
                "Policy exceeds the maximum allowed size",
            )
        })?;
    let (read, list) = parse_bucket_policy(&bucket, &body_bytes)?;
    if !read && !list {
        return Err(unsupported_policy(
            "policy grants neither s3:GetObject nor s3:ListBucket",
        ));
    }
    state
        .storage
        .set_bucket_public(&bucket, read, list)
        .await
        .map_err(S3Error::internal)?;
    Ok(no_content())
}

pub(crate) async fn get_bucket_policy(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let (read, list) = bucket_public_flags(&state, &bucket).await?;
    if !read && !list {
        return Err(S3Error::bucket_error(
            S3ErrorCode::NoSuchBucketPolicy,
            &bucket,
            "The bucket policy does not exist",
        ));
    }
    // Same shape as MinIO's canned policies so `mc anonymous get` recognises it.
    let mut statements = Vec::new();
    if list {
        statements.push(serde_json::json!({
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [format!("arn:aws:s3:::{}", bucket)],
        }));
    }
    if read {
        statements.push(serde_json::json!({
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetObject"],
            "Resource": [format!("arn:aws:s3:::{}/*", bucket)],
        }));
    }
    let policy = serde_json::json!({"Version": "2012-10-17", "Statement": statements});
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(policy.to_string()))
        .unwrap())
}

// --- Bucket ACL (read-only view; only "private" can be set) -----------------

const ALL_USERS_URI: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

async fn get_bucket_acl(state: AppState, bucket: String) -> Result<Response<Body>, S3Error> {
    let (_, list) = bucket_public_flags(&state, &bucket).await?;
    // A bucket-level READ grant means "list objects", which is what the
    // anonymous list flag allows.
    let public_grant = if list {
        format!(
            "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
             xsi:type=\"Group\"><URI>{}</URI></Grantee><Permission>READ</Permission></Grant>",
            ALL_USERS_URI
        )
    } else {
        String::new()
    };
    Ok(xml_response(acl_xml(&public_grant)))
}

/// `AccessControlPolicy` document: the owner's FULL_CONTROL grant plus
/// `extra_grants` (raw `<Grant>` XML).
pub(super) fn acl_xml(extra_grants: &str) -> String {
    let owner = format!("<ID>{0}</ID><DisplayName>{0}</DisplayName>", OWNER_ID);
    xml_doc(&format!(
        "<AccessControlPolicy xmlns=\"{ns}\"><Owner>{owner}</Owner><AccessControlList>\
         <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xsi:type=\"CanonicalUser\">{owner}</Grantee><Permission>FULL_CONTROL</Permission></Grant>\
         {extra_grants}</AccessControlList></AccessControlPolicy>",
        ns = S3_XMLNS,
    ))
}

const ACL_BODY_MAX: usize = 64 * 1024;

#[derive(Deserialize)]
struct AclPolicyXml {
    #[serde(rename = "AccessControlList")]
    list: AclListXml,
}

#[derive(Deserialize)]
struct AclListXml {
    #[serde(rename = "Grant", default)]
    grants: Vec<AclGrantXml>,
}

#[derive(Deserialize)]
struct AclGrantXml {
    #[serde(rename = "Grantee")]
    grantee: AclGranteeXml,
    #[serde(rename = "Permission")]
    permission: String,
}

#[derive(Deserialize)]
struct AclGranteeXml {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "URI")]
    uri: Option<String>,
    #[serde(rename = "EmailAddress")]
    email: Option<String>,
}

/// PutBucketAcl / PutObjectAcl: only "private" is accepted — `x-amz-acl:
/// private`, or a body whose only grant is the owner's FULL_CONTROL.
pub(super) async fn check_private_acl(headers: &HeaderMap, body: Body) -> Result<(), S3Error> {
    let not_supported = || {
        S3Error::not_implemented(
            "MaxIO only supports the private ACL; use a bucket policy for anonymous access",
        )
    };
    if headers
        .keys()
        .any(|k| k.as_str().starts_with("x-amz-grant-"))
    {
        return Err(not_supported());
    }
    if let Some(acl) = headers.get("x-amz-acl") {
        return match acl.to_str().map(str::trim) {
            Ok("private") => Ok(()),
            _ => Err(not_supported()),
        };
    }
    let bytes = axum::body::to_bytes(body, ACL_BODY_MAX)
        .await
        .map_err(|_| S3Error::malformed_xml())?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(S3Error::invalid_argument(
            "PutAcl requires an x-amz-acl header or an AccessControlPolicy body",
        ));
    }
    let policy: AclPolicyXml = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| quick_xml::de::from_str(s).ok())
        .ok_or_else(S3Error::malformed_xml)?;
    match policy.list.grants.as_slice() {
        [g] if g.permission == "FULL_CONTROL"
            && g.grantee.id.as_deref() == Some(OWNER_ID)
            && g.grantee.uri.is_none()
            && g.grantee.email.is_none() =>
        {
            Ok(())
        }
        _ => Err(not_supported()),
    }
}

async fn put_bucket_acl(
    state: AppState,
    bucket: String,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    check_private_acl(headers, body).await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

// --- Bucket tagging ---------------------------------------------------------

const BUCKET_TAGGING_BODY_MAX: usize = 64 * 1024;
const BUCKET_TAGS_MAX: usize = 50;

async fn put_bucket_tagging(
    state: AppState,
    bucket: String,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    let body_bytes = axum::body::to_bytes(body, BUCKET_TAGGING_BODY_MAX)
        .await
        .map_err(|_| S3Error::malformed_xml())?;
    let tagging: Tagging = quick_xml::de::from_str(&String::from_utf8_lossy(&body_bytes))
        .map_err(|_| S3Error::malformed_xml())?;

    let tags = tagging.tag_set.tags;
    crate::storage::validate_tags(
        tags.iter().map(|t| (t.key.as_str(), t.value.as_str())),
        BUCKET_TAGS_MAX,
        true,
    )?;
    let map: std::collections::BTreeMap<String, String> =
        tags.into_iter().map(|t| (t.key, t.value)).collect();

    state
        .storage
        .set_bucket_tags(&bucket, (!map.is_empty()).then_some(map))
        .await
        .map_err(S3Error::internal)?;
    Ok(no_content())
}

async fn get_bucket_tagging(state: AppState, bucket: String) -> Result<Response<Body>, S3Error> {
    let meta = state
        .storage
        .get_bucket_meta(&bucket)
        .await
        .map_err(S3Error::internal)?;
    let tags = meta.tags.filter(|t| !t.is_empty()).ok_or_else(|| {
        S3Error::bucket_error(
            S3ErrorCode::NoSuchTagSet,
            &bucket,
            "The TagSet does not exist",
        )
    })?;
    let tagging = Tagging {
        tag_set: TagSet {
            tags: tags
                .into_iter()
                .map(|(key, value)| Tag { key, value })
                .collect(),
        },
    };
    let xml = to_xml(&tagging).map_err(S3Error::internal)?;
    Ok(xml_response(xml))
}
