use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::collections::{BTreeMap, HashMap};
use tokio_util::io::ReaderStream;

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{
    BucketEncryptionConfig, ChecksumAlgorithm, EncryptionMode, EncryptionRequest, PutOptions,
    StorageError, StoredObjectMetadata, UploadEncryptionSpec, WritePrecondition,
};
use crate::xml::{
    response::to_xml,
    types::{CopyObjectResult, CopyPartResult, Tag, TagSet, Tagging},
};

use super::multipart;

/// Parse SSE request headers into an EncryptionRequest + optional customer key.
/// Returns `Ok(None)` if no SSE headers are present.
pub(crate) fn extract_sse_request(
    headers: &HeaderMap,
) -> Result<Option<EncryptionRequest>, S3Error> {
    // SSE-C: customer-supplied key
    if let Some(algo) = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok())
    {
        if algo != "AES256" {
            return Err(S3Error::invalid_encryption_algorithm());
        }
        let key_b64 = headers
            .get("x-amz-server-side-encryption-customer-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                S3Error::invalid_argument("missing x-amz-server-side-encryption-customer-key")
            })?;
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|_| S3Error::invalid_argument("invalid SSE-C key base64"))?;
        if raw.len() != 32 {
            return Err(S3Error::invalid_argument("SSE-C key must be 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        // Validate optional MD5
        if let Some(md5_b64) = headers
            .get("x-amz-server-side-encryption-customer-key-md5")
            .and_then(|v| v.to_str().ok())
        {
            use md5::Digest;
            let computed = base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&key));
            if computed != md5_b64 {
                return Err(S3Error::invalid_argument("SSE-C key MD5 mismatch"));
            }
        }
        return Ok(Some(EncryptionRequest::sse_c(key)));
    }

    // SSE-S3
    if let Some(sse) = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
    {
        return match sse {
            "AES256" => Ok(Some(EncryptionRequest::sse_s3())),
            _ => Err(S3Error::invalid_encryption_algorithm()),
        };
    }
    Ok(None)
}

/// Extract a CopyObject source SSE-C key from the `x-amz-copy-source-server-side-encryption-customer-*` headers.
pub(crate) fn extract_copy_source_customer_key(
    headers: &HeaderMap,
) -> Result<Option<[u8; 32]>, S3Error> {
    let algo = match headers
        .get("x-amz-copy-source-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok())
    {
        Some(a) => a,
        None => return Ok(None),
    };
    if algo != "AES256" {
        return Err(S3Error::invalid_encryption_algorithm());
    }
    let key_b64 = headers
        .get("x-amz-copy-source-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            S3Error::invalid_argument(
                "missing x-amz-copy-source-server-side-encryption-customer-key",
            )
        })?;
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| S3Error::invalid_argument("invalid copy-source SSE-C key base64"))?;
    if raw.len() != 32 {
        return Err(S3Error::invalid_argument(
            "copy-source SSE-C key must be 32 bytes",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Ok(Some(key))
}

/// Extract only a customer-supplied SSE-C key for GET/HEAD/CopyObject source paths.
pub(crate) fn extract_customer_key(headers: &HeaderMap) -> Result<Option<[u8; 32]>, S3Error> {
    let algo = match headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok())
    {
        Some(a) => a,
        None => return Ok(None),
    };
    if algo != "AES256" {
        return Err(S3Error::invalid_encryption_algorithm());
    }
    let key_b64 = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            S3Error::invalid_argument("missing x-amz-server-side-encryption-customer-key")
        })?;
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| S3Error::invalid_argument("invalid SSE-C key base64"))?;
    if raw.len() != 32 {
        return Err(S3Error::invalid_argument("SSE-C key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Ok(Some(key))
}

/// Build an EncryptionRequest from a bucket-level default encryption config.
pub(crate) fn encryption_from_bucket_default(_cfg: &BucketEncryptionConfig) -> EncryptionRequest {
    EncryptionRequest::sse_s3()
}

/// Convert an EncryptionRequest into the compact UploadEncryptionSpec that is
/// persisted for the duration of a multipart upload.
pub(crate) fn spec_from_request(req: &EncryptionRequest) -> UploadEncryptionSpec {
    let customer_key_md5 = req.customer_key.as_ref().map(|ck| {
        use base64::Engine;
        use md5::Digest;
        base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&**ck))
    });
    UploadEncryptionSpec {
        mode: req.mode.clone(),
        customer_key_md5,
        upload_dek_wrapped: None,
        upload_dek_wrap_nonce: None,
        upload_dek_key_id: None,
        // Populated inside `create_multipart_upload` alongside the wrapped DEK.
        upload_nonce_prefix: String::new(),
    }
}

/// Attach SSE response headers to match the encryption that was applied.
pub(crate) fn add_sse_headers(
    mut builder: http::response::Builder,
    enc: &Option<crate::storage::EncryptionMeta>,
) -> http::response::Builder {
    if let Some(em) = enc {
        match em.mode {
            EncryptionMode::SseS3 => {
                builder = builder.header("x-amz-server-side-encryption", "AES256");
            }
            EncryptionMode::SseC => {
                builder =
                    builder.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                if let Some(ref md5) = em.customer_key_md5 {
                    builder = builder.header(
                        "x-amz-server-side-encryption-customer-key-md5",
                        md5.as_str(),
                    );
                }
            }
        }
    }
    builder
}

/// Extract checksum algorithm and optional expected value from request headers.
pub(crate) fn extract_checksum(headers: &HeaderMap) -> Option<(ChecksumAlgorithm, Option<String>)> {
    let pairs = [
        ("x-amz-checksum-crc32", ChecksumAlgorithm::CRC32),
        ("x-amz-checksum-crc32c", ChecksumAlgorithm::CRC32C),
        ("x-amz-checksum-crc64nvme", ChecksumAlgorithm::CRC64NVME),
        ("x-amz-checksum-sha1", ChecksumAlgorithm::SHA1),
        ("x-amz-checksum-sha256", ChecksumAlgorithm::SHA256),
    ];

    // Check for a value header first (implies the algorithm)
    for (header, algo) in &pairs {
        if let Some(val) = headers.get(*header).and_then(|v| v.to_str().ok()) {
            return Some((*algo, Some(val.to_string())));
        }
    }

    // Fall back to algorithm-only header (compute but don't validate)
    headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
        .and_then(ChecksumAlgorithm::from_header_str)
        .map(|algo| (algo, None))
        // aws-chunked trailer checksum: validated by the decoder, computed and
        // recorded by storage.
        .or_else(|| super::chunked::trailer_checksum_algorithm(headers).map(|algo| (algo, None)))
}

// ── Object metadata, tagging header, preconditions, subresources ────────────

/// S3 limit for the summed byte length of user-metadata names + values.
const USER_METADATA_LIMIT: usize = 2 * 1024;

/// All values of a (possibly repeated) header joined with `,`, as S3 does.
fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_string())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

/// Drop the `aws-chunked` transfer token from a Content-Encoding value.
/// Returns `None` when nothing else remains.
pub(crate) fn strip_aws_chunked(value: &str) -> Option<String> {
    let rest: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    if rest.is_empty() {
        None
    } else {
        Some(rest.join(", "))
    }
}

/// Collect `x-amz-meta-*`, Cache-Control, Content-Disposition,
/// Content-Encoding, Content-Language and Expires from request headers.
pub(crate) fn extract_object_metadata(
    headers: &HeaderMap,
) -> Result<StoredObjectMetadata, S3Error> {
    let mut user = BTreeMap::new();
    let mut total = 0usize;
    for name in headers.keys() {
        if let Some(suffix) = name.as_str().strip_prefix("x-amz-meta-") {
            let value = header_string(headers, name.as_str()).unwrap_or_default();
            total += suffix.len() + value.len();
            user.insert(suffix.to_string(), value);
        }
    }
    if total > USER_METADATA_LIMIT {
        return Err(S3Error::metadata_too_large());
    }
    Ok(StoredObjectMetadata {
        user_metadata: (!user.is_empty()).then_some(user),
        cache_control: header_string(headers, "cache-control"),
        content_disposition: header_string(headers, "content-disposition"),
        content_encoding: header_string(headers, "content-encoding")
            .and_then(|v| strip_aws_chunked(&v)),
        content_language: header_string(headers, "content-language"),
        expires: header_string(headers, "expires"),
    })
}

fn decode_tag_component(raw: &str) -> Result<String, S3Error> {
    percent_encoding::percent_decode_str(&raw.replace('+', " "))
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| S3Error::invalid_tag("The x-amz-tagging header is not valid URL encoding"))
}

/// Same limits as PutObjectTagging.
/// Object tag sets: at most 10 tags; violations are `InvalidArgument`.
fn validate_tags(tags: &HashMap<String, String>) -> Result<(), S3Error> {
    let pairs = tags.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    crate::storage::validate_tags(pairs, 10, false)
        .map_err(|e| S3Error::invalid_argument(&e.message))
}

/// Parse `x-amz-tagging: k1=v1&k2=v2` (URL-encoded query form).
pub(crate) fn parse_tagging_header(
    headers: &HeaderMap,
) -> Result<Option<HashMap<String, String>>, S3Error> {
    let Some(raw) = headers.get("x-amz-tagging") else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| S3Error::invalid_tag("The x-amz-tagging header is not valid"))?;
    let mut tags = HashMap::new();
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_tag_component(k)?;
        let value = decode_tag_component(v)?;
        if tags.insert(key, value).is_some() {
            return Err(S3Error::invalid_tag(
                "Cannot provide multiple Tags with the same key",
            ));
        }
    }
    validate_tags(&tags)?;
    Ok(Some(tags))
}

/// `If-None-Match: *` / `If-Match: <etag>` on writes.
pub(crate) fn extract_write_precondition(
    headers: &HeaderMap,
) -> Result<Option<WritePrecondition>, S3Error> {
    if let Some(v) = headers.get("if-none-match") {
        let v = v.to_str().unwrap_or_default().trim();
        if v == "*" {
            return Ok(Some(WritePrecondition::IfNoneMatchAny));
        }
        return Err(S3Error::not_implemented(
            "If-None-Match on writes only supports the value *",
        ));
    }
    if let Some(v) = headers.get("if-match") {
        let v = v
            .to_str()
            .map_err(|_| S3Error::invalid_argument("invalid If-Match header"))?;
        return Ok(Some(WritePrecondition::IfMatch(v.trim().to_string())));
    }
    Ok(None)
}

/// Parse and validate a `Content-MD5` header (InvalidDigest when malformed).
pub(crate) fn parse_content_md5(headers: &HeaderMap) -> Result<Option<[u8; 16]>, S3Error> {
    let Some(raw) = headers.get("content-md5") else {
        return Ok(None);
    };
    use base64::Engine;
    let decoded = raw
        .to_str()
        .ok()
        .and_then(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
        })
        .ok_or_else(S3Error::invalid_digest)?;
    let digest: [u8; 16] = decoded.try_into().map_err(|_| S3Error::invalid_digest())?;
    Ok(Some(digest))
}

/// Check a fully buffered body against its `Content-MD5` header, if any.
pub(crate) fn verify_content_md5(headers: &HeaderMap, body: &[u8]) -> Result<(), S3Error> {
    use md5::Digest;
    match parse_content_md5(headers)? {
        Some(expected) if md5::Md5::digest(body).as_slice() != expected => {
            Err(S3Error::bad_digest())
        }
        _ => Ok(()),
    }
}

/// Marker error raised by [`Md5VerifyingReader`] at EOF on a digest mismatch.
#[derive(Debug)]
pub(crate) struct ContentMd5Mismatch;

impl std::fmt::Display for ContentMd5Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Content-MD5 mismatch")
    }
}

impl std::error::Error for ContentMd5Mismatch {}

/// Streaming Content-MD5 check: hashes bytes as they pass and fails the
/// final read (before storage publishes anything) when the digest differs.
pub(crate) struct Md5VerifyingReader {
    inner: crate::storage::ByteStream,
    hasher: md5::Md5,
    expected: [u8; 16],
    checked: bool,
}

impl Md5VerifyingReader {
    pub(crate) fn wrap(
        inner: crate::storage::ByteStream,
        expected: Option<[u8; 16]>,
    ) -> crate::storage::ByteStream {
        match expected {
            None => inner,
            Some(expected) => {
                use md5::Digest;
                Box::pin(Self {
                    inner,
                    hasher: md5::Md5::new(),
                    expected,
                    checked: false,
                })
            }
        }
    }
}

impl tokio::io::AsyncRead for Md5VerifyingReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use md5::Digest;
        let before = buf.filled().len();
        let this = &mut *self;
        match this.inner.as_mut().poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let new = &buf.filled()[before..];
                if !new.is_empty() {
                    this.hasher.update(new);
                } else if buf.remaining() > 0 && !this.checked {
                    this.checked = true;
                    if this.hasher.clone().finalize().as_slice() != this.expected {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            ContentMd5Mismatch,
                        )));
                    }
                }
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

fn bucket_name_from_storage_msg(msg: &str) -> &str {
    msg.split_once(':')
        .map(|(_, name)| name.trim())
        .filter(|name| !name.is_empty())
        .unwrap_or(msg)
}

/// True when a storage error was produced by a Content-MD5 mismatch.
pub(crate) fn is_content_md5_mismatch(err: &StorageError) -> bool {
    matches!(err, StorageError::Io(io)
        if io.get_ref().is_some_and(|inner| inner.is::<ContentMd5Mismatch>()))
}

/// Map storage errors for object writes (PutObject / CopyObject).
fn map_put_error(e: StorageError, key: &str) -> S3Error {
    if is_content_md5_mismatch(&e) {
        return S3Error::bad_digest();
    }
    match e {
        StorageError::InvalidKey(msg) if msg.starts_with("invalid bucket name") => {
            S3Error::invalid_bucket_name(bucket_name_from_storage_msg(&msg))
        }
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        StorageError::ChecksumMismatch(_) => S3Error::bad_checksum("x-amz-checksum"),
        StorageError::EncryptionError(msg) => S3Error::invalid_argument(&msg),
        StorageError::IntegrityError(msg) => S3Error::invalid_argument(&msg),
        StorageError::PreconditionFailed => S3Error::precondition_failed(),
        StorageError::NotFound(_) => S3Error::no_such_key(key),
        StorageError::EntityTooLarge => S3Error::entity_too_large(),
        _ => S3Error::internal(e),
    }
}

/// Map storage errors for object reads.
fn map_read_error(e: StorageError, key: &str, version_id: Option<&str>) -> S3Error {
    match e {
        StorageError::VersionNotFound(v) => S3Error::no_such_version(version_id.unwrap_or(&v)),
        StorageError::NotFound(_) => S3Error::no_such_key(key),
        StorageError::InvalidKey(msg) if msg.starts_with("invalid bucket name") => {
            S3Error::invalid_bucket_name(bucket_name_from_storage_msg(&msg))
        }
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        StorageError::DecryptionError(msg) => S3Error::invalid_argument(&msg),
        StorageError::IntegrityError(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(e),
    }
}

/// Query parameters on object requests that are not unsupported subresources.
fn is_known_object_param(name: &str) -> bool {
    matches!(
        name,
        "tagging"
            | "uploadId"
            | "partNumber"
            | "versionId"
            | "uploads"
            | "x-id"
            | "acl"
            | "attributes"
            | "retention"
            | "legal-hold"
            | "max-parts"
            | "part-number-marker"
            | "encoding-type"
    ) || name.starts_with("response-")
        || name.to_ascii_lowercase().starts_with("x-amz-")
}

/// Known S3 object subresources MaxIO does not implement.
const UNSUPPORTED_OBJECT_SUBRESOURCES: &[&str] = &[
    "torrent",
    "restore",
    "select",
    "select-type",
    "renameObject",
    "lambda",
    "website",
    "policy",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjectMethod {
    Get,
    Head,
    Put,
    Delete,
}

/// Reject subresources we do not implement with 501 so a request like
/// `PUT ?torrent` can never fall through to the default (overwrite) action.
fn reject_unsupported_subresource(
    params: &HashMap<String, String>,
    method: ObjectMethod,
) -> Result<(), S3Error> {
    for (name, value) in params {
        let unsupported = if is_known_object_param(name) {
            // Valid only for some methods.
            match name.as_str() {
                "acl" | "retention" | "legal-hold" => {
                    matches!(method, ObjectMethod::Delete | ObjectMethod::Head)
                }
                "attributes" => method != ObjectMethod::Get,
                _ => false,
            }
        } else {
            UNSUPPORTED_OBJECT_SUBRESOURCES.contains(&name.as_str()) || value.is_empty()
        };
        if unsupported {
            return Err(S3Error::not_implemented(&format!(
                "The {} subresource is not implemented for this method",
                name
            )));
        }
    }
    // Multipart parameters that do not select a PUT/DELETE action must not
    // fall through to overwriting or deleting the object.
    if matches!(method, ObjectMethod::Put | ObjectMethod::Delete) {
        if params.contains_key("uploads") {
            return Err(S3Error::method_not_allowed(
                "The specified method is not allowed against this resource.",
            ));
        }
        if !params.contains_key("uploadId") {
            if let Some(name) = ["partNumber", "max-parts", "part-number-marker"]
                .into_iter()
                .find(|p| params.contains_key(*p))
            {
                return Err(S3Error::invalid_request(&format!(
                    "{} requires an uploadId",
                    name
                )));
            }
        }
    }
    Ok(())
}

fn object_lock_not_configured() -> S3Error {
    S3Error::invalid_request("Bucket is missing Object Lock Configuration")
}

/// response-* query overrides → response header name.
const RESPONSE_OVERRIDES: &[(&str, &str)] = &[
    ("response-content-type", "content-type"),
    ("response-content-language", "content-language"),
    ("response-expires", "expires"),
    ("response-cache-control", "cache-control"),
    ("response-content-disposition", "content-disposition"),
    ("response-content-encoding", "content-encoding"),
];

fn insert_header(h: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (
        http::header::HeaderName::from_bytes(name.as_bytes()),
        http::HeaderValue::from_bytes(value.as_bytes()),
    ) {
        h.insert(n, v);
    }
}

/// Every header describing a stored object (GET/HEAD and their range /
/// partNumber variants), with `response-*` overrides applied last.
fn object_headers(
    meta: &crate::storage::ObjectMeta,
    params: &HashMap<String, String>,
) -> HeaderMap {
    let mut h = HeaderMap::new();
    insert_header(&mut h, "content-type", &meta.content_type);
    insert_header(&mut h, "etag", &meta.etag);
    insert_header(&mut h, "last-modified", &to_http_date(&meta.last_modified));
    insert_header(&mut h, "accept-ranges", "bytes");
    if let Some(vid) = &meta.version_id {
        insert_header(&mut h, "x-amz-version-id", vid);
    }
    if let (Some(algo), Some(val)) = (&meta.checksum_algorithm, &meta.checksum_value) {
        insert_header(&mut h, algo.header_name(), val);
    }
    if let Some(em) = &meta.encryption {
        match em.mode {
            EncryptionMode::SseS3 => {
                insert_header(&mut h, "x-amz-server-side-encryption", "AES256")
            }
            EncryptionMode::SseC => {
                insert_header(
                    &mut h,
                    "x-amz-server-side-encryption-customer-algorithm",
                    "AES256",
                );
                if let Some(md5) = &em.customer_key_md5 {
                    insert_header(&mut h, "x-amz-server-side-encryption-customer-key-md5", md5);
                }
            }
        }
    }
    if let Some(user) = &meta.metadata.user_metadata {
        for (k, v) in user {
            insert_header(&mut h, &format!("x-amz-meta-{}", k), v);
        }
    }
    for (name, value) in [
        ("cache-control", &meta.metadata.cache_control),
        ("content-disposition", &meta.metadata.content_disposition),
        ("content-encoding", &meta.metadata.content_encoding),
        ("content-language", &meta.metadata.content_language),
        ("expires", &meta.metadata.expires),
    ] {
        if let Some(v) = value {
            insert_header(&mut h, name, v);
        }
    }
    if let Some(tags) = meta.tags.as_ref().filter(|t| !t.is_empty()) {
        insert_header(&mut h, "x-amz-tagging-count", &tags.len().to_string());
    }
    for (param, header) in RESPONSE_OVERRIDES {
        if let Some(v) = params.get(*param) {
            insert_header(&mut h, header, v);
        }
    }
    h
}

fn builder_with(status: StatusCode, headers: HeaderMap) -> http::response::Builder {
    let mut builder = Response::builder().status(status);
    if let Some(h) = builder.headers_mut() {
        h.extend(headers);
    }
    builder
}

/// 404 NoSuchKey / 405 MethodNotAllowed carrying the delete-marker headers.
fn delete_marker_response(err: S3Error, version_id: &str, is_head: bool) -> Response<Body> {
    use axum::response::IntoResponse;
    let mut resp = err.into_response();
    let h = resp.headers_mut();
    insert_header(h, "x-amz-delete-marker", "true");
    insert_header(h, "x-amz-version-id", version_id);
    if is_head {
        *resp.body_mut() = Body::empty();
    }
    resp
}

/// Outcome of resolving the metadata a GET/HEAD addresses.
enum Resolved {
    Meta(Box<crate::storage::ObjectMeta>),
    Early(Response<Body>),
}

/// Resolve current or versioned object metadata, translating delete markers
/// into the S3 responses (404 + marker headers, or 405 for a marker version).
async fn resolve_object_meta(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    is_head: bool,
) -> Result<Resolved, S3Error> {
    match version_id {
        Some(vid) => {
            let meta = state
                .storage
                .version_meta(bucket, key, vid)
                .await
                .map_err(|e| map_read_error(e, key, Some(vid)))?;
            if meta.is_delete_marker {
                return Ok(Resolved::Early(delete_marker_response(
                    S3Error::method_not_allowed(
                        "The specified method is not allowed against this resource.",
                    ),
                    vid,
                    is_head,
                )));
            }
            Ok(Resolved::Meta(Box::new(meta)))
        }
        None => match state.storage.head_object(bucket, key).await {
            Ok(meta) => Ok(Resolved::Meta(Box::new(meta))),
            Err(StorageError::NotFound(_)) => {
                if let Ok(Some(marker)) = state.storage.current_delete_marker(bucket, key).await {
                    return Ok(Resolved::Early(delete_marker_response(
                        S3Error::no_such_key(key),
                        &marker,
                        is_head,
                    )));
                }
                Err(S3Error::no_such_key(key))
            }
            Err(e) => Err(map_read_error(e, key, None)),
        },
    }
}

/// (offset, length, parts_count) of `partNumber` within `meta`.
fn part_range(
    meta: &crate::storage::ObjectMeta,
    part_num_str: &str,
) -> Result<(u64, u64, usize), S3Error> {
    let part_num: u32 = part_num_str
        .parse()
        .map_err(|_| S3Error::invalid_argument("invalid partNumber"))?;
    let part_sizes = meta
        .part_sizes
        .as_ref()
        .ok_or_else(|| S3Error::invalid_argument("object is not a multipart upload"))?;
    let idx = (part_num as usize)
        .checked_sub(1)
        .ok_or_else(|| S3Error::invalid_argument("partNumber must be >= 1"))?;
    if idx >= part_sizes.len() {
        return Err(S3Error::invalid_argument("partNumber exceeds total parts"));
    }
    let offset: u64 = part_sizes[..idx].iter().sum();
    Ok((offset, part_sizes[idx], part_sizes.len()))
}

async fn ensure_object_exists(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<crate::storage::ObjectMeta, S3Error> {
    super::bucket::require_bucket(state, bucket).await?;
    match resolve_object_meta(state, bucket, key, version_id, false).await? {
        Resolved::Meta(m) => Ok(*m),
        Resolved::Early(_) => match version_id {
            Some(_) => Err(S3Error::method_not_allowed(
                "The specified method is not allowed against this resource.",
            )),
            None => Err(S3Error::no_such_key(key)),
        },
    }
}

async fn get_object_acl(
    state: &AppState,
    bucket: &str,
    key: &str,
    params: &HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let meta = ensure_object_exists(
        state,
        bucket,
        key,
        params.get("versionId").map(String::as_str),
    )
    .await?;
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    Ok(builder
        .body(Body::from(super::bucket::acl_xml("")))
        .unwrap())
}

/// Only the owner-only (private) ACL is supported.
async fn put_object_acl(
    state: &AppState,
    bucket: &str,
    key: &str,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    ensure_object_exists(
        state,
        bucket,
        key,
        params.get("versionId").map(String::as_str),
    )
    .await?;
    super::bucket::check_private_acl(headers, body).await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

/// GetObjectAttributes (`GET ?attributes`).
async fn get_object_attributes(
    state: &AppState,
    bucket: &str,
    key: &str,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let requested: Vec<String> = headers
        .get_all("x-amz-object-attributes")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if requested.is_empty() {
        return Err(S3Error::invalid_argument(
            "The x-amz-object-attributes header specifying the attributes to be retrieved is either missing or empty",
        ));
    }
    const VALID: &[&str] = &[
        "ETag",
        "Checksum",
        "ObjectParts",
        "StorageClass",
        "ObjectSize",
    ];
    if let Some(bad) = requested.iter().find(|r| !VALID.contains(&r.as_str())) {
        return Err(S3Error::invalid_argument(&format!(
            "Invalid attribute name specified: {}",
            bad
        )));
    }
    super::bucket::require_bucket(state, bucket).await?;
    let meta = match resolve_object_meta(
        state,
        bucket,
        key,
        params.get("versionId").map(String::as_str),
        false,
    )
    .await?
    {
        Resolved::Meta(m) => *m,
        Resolved::Early(resp) => return Ok(resp),
    };
    let wants = |name: &str| requested.iter().any(|r| r == name);
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <GetObjectAttributesResponse xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    if wants("ETag") {
        xml.push_str(&format!(
            "<ETag>{}</ETag>",
            quick_xml::escape::escape(meta.etag.trim_matches('"'))
        ));
    }
    if wants("Checksum") {
        if let (Some(algo), Some(val)) = (&meta.checksum_algorithm, &meta.checksum_value) {
            let tag = match algo {
                ChecksumAlgorithm::CRC32 => "ChecksumCRC32",
                ChecksumAlgorithm::CRC32C => "ChecksumCRC32C",
                ChecksumAlgorithm::CRC64NVME => "ChecksumCRC64NVME",
                ChecksumAlgorithm::SHA1 => "ChecksumSHA1",
                ChecksumAlgorithm::SHA256 => "ChecksumSHA256",
            };
            // Composite multipart checksums are stored as `<b64>-<parts>`.
            let value = val.split('-').next().unwrap_or(val);
            xml.push_str(&format!("<Checksum><{tag}>{value}</{tag}></Checksum>"));
        }
    }
    if wants("ObjectParts") {
        if let Some(parts) = &meta.part_sizes {
            xml.push_str(&format!(
                "<ObjectParts><TotalPartsCount>{}</TotalPartsCount></ObjectParts>",
                parts.len()
            ));
        }
    }
    if wants("StorageClass") {
        xml.push_str("<StorageClass>STANDARD</StorageClass>");
    }
    if wants("ObjectSize") {
        xml.push_str(&format!("<ObjectSize>{}</ObjectSize>", meta.size));
    }
    xml.push_str("</GetObjectAttributesResponse>");

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("Last-Modified", to_http_date(&meta.last_modified));
    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    Ok(builder.body(Body::from(xml)).unwrap())
}

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    reject_unsupported_subresource(&params, ObjectMethod::Put)?;
    if params.contains_key("retention") || params.contains_key("legal-hold") {
        return Err(object_lock_not_configured());
    }
    if params.contains_key("acl") {
        return put_object_acl(&state, &bucket, &key, &params, &headers, body).await;
    }

    if params.contains_key("uploadId") && headers.contains_key("x-amz-copy-source") {
        return upload_part_copy(State(state), Path((bucket, key)), Query(params), headers).await;
    }

    if headers.contains_key("x-amz-copy-source") {
        return copy_object(State(state), Path((bucket, key)), headers).await;
    }

    if params.contains_key("tagging") {
        return put_object_tagging(State(state), Path((bucket, key)), body).await;
    }

    // UploadPart shares this route. Its cap is max-part-size, applied in
    // `upload_part`. Checking max-object-size here rejects every part of a
    // multipart upload that is larger than a single PUT.
    if params.contains_key("uploadId") {
        return multipart::upload_part(
            State(state),
            Path((bucket, key)),
            Query(params),
            headers,
            body,
        )
        .await;
    }

    reject_oversized_body(&headers, state.config.max_object_size)?;

    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::from_bucket_storage(e, &bucket)),
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let opts = PutOptions {
        metadata: extract_object_metadata(&headers)?,
        tags: parse_tagging_header(&headers)?,
        precondition: extract_write_precondition(&headers)?,
    };

    // Content-MD5 is verified while streaming; a mismatch fails the final
    // read, before storage publishes anything.
    let content_md5 = parse_content_md5(&headers)?;
    let reader = Md5VerifyingReader::wrap(body_to_reader(&headers, body).await?, content_md5);

    let checksum = extract_checksum(&headers);

    // Resolve encryption: explicit request headers win over bucket default.
    let mut encryption = extract_sse_request(&headers)?;
    if encryption.is_none() {
        match state.storage.get_bucket_encryption(&bucket).await {
            Ok(Some(cfg)) => encryption = Some(encryption_from_bucket_default(&cfg)),
            Ok(None) => {}
            Err(e) => return Err(S3Error::from_bucket_storage(e, &bucket)),
        }
    }
    let applied_mode = encryption.as_ref().map(|e| e.mode.clone());
    let applied_ck_md5 = encryption.as_ref().and_then(|e| {
        e.customer_key.as_ref().map(|ck| {
            use base64::Engine;
            use md5::Digest;
            base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&**ck))
        })
    });

    let result = state
        .storage
        .put_object_with(
            &bucket,
            &key,
            content_type,
            reader,
            checksum,
            encryption,
            &opts,
        )
        .await
        .map_err(|e| map_put_error(e, &key))?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &result.etag);
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    if let (Some(algo), Some(val)) = (&result.checksum_algorithm, &result.checksum_value) {
        builder = builder.header(algo.header_name(), val.as_str());
    }
    // Echo SSE headers matching what was applied.
    match applied_mode {
        Some(EncryptionMode::SseS3) => {
            builder = builder.header("x-amz-server-side-encryption", "AES256");
        }
        Some(EncryptionMode::SseC) => {
            builder = builder.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
            if let Some(md5) = applied_ck_md5 {
                builder = builder.header("x-amz-server-side-encryption-customer-key-md5", md5);
            }
        }
        None => {}
    }
    Ok(builder.body(Body::empty()).unwrap())
}

/// Parsed `x-amz-copy-source`: bucket, key and optional `?versionId=`.
struct CopySource {
    bucket: String,
    key: String,
    version_id: Option<String>,
}

/// Parse `x-amz-copy-source` (`[/]bucket/key[?versionId=X]`, URL-encoded).
/// The query is split off before decoding so an encoded `?` (`%3F`) stays
/// part of the key.
fn parse_copy_source(headers: &HeaderMap) -> Result<CopySource, S3Error> {
    let copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source header"))?;

    let (path, query) = match copy_source.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (copy_source, None),
    };
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| S3Error::invalid_argument("invalid x-amz-copy-source encoding"))?;
    let trimmed = decoded.trim_start_matches('/');
    let (src_bucket, src_key) = trimmed
        .split_once('/')
        .filter(|(b, k)| !b.is_empty() && !k.is_empty())
        .ok_or_else(|| S3Error::invalid_argument("invalid x-amz-copy-source format"))?;

    let mut version_id = None;
    if let Some(query) = query {
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if name == "versionId" {
                let value = percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .map_err(|_| S3Error::invalid_argument("invalid copy source versionId"))?;
                if value.is_empty() {
                    return Err(S3Error::invalid_argument("empty copy source versionId"));
                }
                version_id = Some(value.into_owned());
            } else {
                return Err(S3Error::invalid_argument(
                    "unsupported query parameter in x-amz-copy-source",
                ));
            }
        }
    }
    Ok(CopySource {
        bucket: src_bucket.to_string(),
        key: src_key.to_string(),
        version_id,
    })
}

/// Source metadata for CopyObject / UploadPartCopy (version-aware), with the
/// `x-amz-copy-source-if-*` preconditions applied.
async fn copy_source_meta(
    state: &AppState,
    src: &CopySource,
    headers: &HeaderMap,
) -> Result<crate::storage::ObjectMeta, S3Error> {
    let meta = match &src.version_id {
        Some(vid) => {
            let meta = state
                .storage
                .version_meta(&src.bucket, &src.key, vid)
                .await
                .map_err(|e| map_read_error(e, &src.key, Some(vid)))?;
            if meta.is_delete_marker {
                return Err(S3Error::invalid_request(
                    "The source of a copy request may not specifically refer to a delete marker by version id.",
                ));
            }
            meta
        }
        None => state
            .storage
            .head_object(&src.bucket, &src.key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&src.key),
                other => map_read_error(other, &src.key, None),
            })?,
    };
    if check_conditions_with_prefix(headers, &meta, "x-amz-copy-source-").is_some() {
        return Err(S3Error::precondition_failed());
    }
    Ok(meta)
}

/// Parse `x-amz-copy-source-range: bytes=start-end` into (start, end) inclusive.
fn parse_copy_source_range(
    headers: &HeaderMap,
    src_size: u64,
) -> Result<Option<(u64, u64)>, S3Error> {
    let header = match headers
        .get("x-amz-copy-source-range")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return Ok(None),
    };
    let spec = header
        .strip_prefix("bytes=")
        .ok_or_else(|| S3Error::invalid_argument("invalid x-amz-copy-source-range format"))?;
    let (start_str, end_str) = spec
        .split_once('-')
        .ok_or_else(|| S3Error::invalid_argument("invalid x-amz-copy-source-range format"))?;
    let start: u64 = start_str
        .parse()
        .map_err(|_| S3Error::invalid_argument("invalid range start"))?;
    let end: u64 = end_str
        .parse()
        .map_err(|_| S3Error::invalid_argument("invalid range end"))?;
    if start > end || end >= src_size {
        return Err(S3Error::invalid_range());
    }
    Ok(Some((start, end)))
}

async fn upload_part_copy(
    State(state): State<AppState>,
    Path((bucket, _key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let src = parse_copy_source(&headers)?;

    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
    let part_number = params
        .get("partNumber")
        .ok_or_else(|| S3Error::invalid_argument("missing partNumber"))?
        .parse::<u32>()
        .map_err(|_| S3Error::invalid_part("invalid part number"))?;

    super::bucket::require_bucket(&state, &bucket).await?;

    // Source metadata first: validates preconditions and the range before
    // any data is opened.
    let src_meta = copy_source_meta(&state, &src, &headers).await?;
    let range = parse_copy_source_range(&headers, src_meta.size)?;

    let src_ck = extract_customer_key(&headers)?;
    let (src_bucket, src_key) = (src.bucket.as_str(), src.key.as_str());
    let vid = src.version_id.as_deref();
    let opened = match (range, vid) {
        (None, None) => state.storage.get_object(src_bucket, src_key, src_ck).await,
        (None, Some(v)) => {
            state
                .storage
                .get_object_version(src_bucket, src_key, v, src_ck)
                .await
        }
        (Some((start, end)), None) => {
            state
                .storage
                .get_object_range(src_bucket, src_key, start, end - start + 1, src_ck)
                .await
        }
        (Some((start, end)), Some(v)) => {
            state
                .storage
                .get_object_version_range(src_bucket, src_key, v, start, end - start + 1, src_ck)
                .await
        }
    };
    let (reader, _) = opened.map_err(|e| map_read_error(e, src_key, vid))?;

    let checksum = extract_checksum(&headers);
    let dst_ck = extract_customer_key(&headers)?;
    let part = state
        .storage
        .upload_part(&bucket, upload_id, part_number, reader, checksum, dst_ck)
        .await
        .map_err(multipart::map_storage_err)?;

    let xml = to_xml(&CopyPartResult {
        etag: part.etag,
        last_modified: src_meta.last_modified,
    })
    .map_err(S3Error::internal)?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    if let Some(v) = &src_meta.version_id {
        builder = builder.header("x-amz-copy-source-version-id", v.as_str());
    }
    Ok(builder.body(Body::from(xml)).unwrap())
}

async fn copy_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let src = parse_copy_source(&headers)?;

    // Validate destination bucket
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::from_bucket_storage(e, &bucket)),
    }

    let directive = headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("COPY");
    if directive != "COPY" && directive != "REPLACE" {
        return Err(S3Error::invalid_argument(
            "invalid x-amz-metadata-directive",
        ));
    }
    let tagging_directive = headers
        .get("x-amz-tagging-directive")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("COPY");
    if tagging_directive != "COPY" && tagging_directive != "REPLACE" {
        return Err(S3Error::invalid_argument("invalid x-amz-tagging-directive"));
    }
    let replace_metadata = if directive == "REPLACE" {
        Some(extract_object_metadata(&headers)?)
    } else {
        None
    };
    let replace_tags = if tagging_directive == "REPLACE" {
        Some(parse_tagging_header(&headers)?.unwrap_or_default())
    } else {
        None
    };
    let precondition = extract_write_precondition(&headers)?;

    // Preconditions are evaluated on the source metadata before reading.
    copy_source_meta(&state, &src, &headers).await?;

    // Get source object. SSE-C copy source key arrives in copy-source-* headers.
    let src_ck = extract_copy_source_customer_key(&headers)?;
    let opened = match &src.version_id {
        Some(vid) => {
            state
                .storage
                .get_object_version(&src.bucket, &src.key, vid, src_ck)
                .await
        }
        None => {
            state
                .storage
                .get_object(&src.bucket, &src.key, src_ck)
                .await
        }
    };
    let (reader, src_meta) =
        opened.map_err(|e| map_read_error(e, &src.key, src.version_id.as_deref()))?;
    if src_meta.size > state.config.max_object_size {
        return Err(S3Error::entity_too_large());
    }
    // The object may have changed between the precondition check and open.
    if check_conditions_with_prefix(&headers, &src_meta, "x-amz-copy-source-").is_some() {
        return Err(S3Error::precondition_failed());
    }

    let (content_type, metadata) = match replace_metadata {
        None => (src_meta.content_type.clone(), src_meta.metadata.clone()),
        Some(m) => (
            headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string(),
            m,
        ),
    };
    let tags = match replace_tags {
        Some(t) => Some(t),
        None => src_meta.tags.clone(),
    };

    // Propagate source checksum algorithm so it's recomputed during copy
    let checksum = src_meta.checksum_algorithm.map(|algo| (algo, None));

    // Destination may request its own SSE; fall back to bucket default.
    let mut encryption = extract_sse_request(&headers)?;
    if encryption.is_none() {
        if let Ok(Some(cfg)) = state.storage.get_bucket_encryption(&bucket).await {
            encryption = Some(encryption_from_bucket_default(&cfg));
        }
    }

    let opts = PutOptions {
        metadata,
        tags,
        precondition,
    };
    let result = state
        .storage
        .put_object_with(
            &bucket,
            &key,
            &content_type,
            reader,
            checksum,
            encryption,
            &opts,
        )
        .await
        .map_err(|e| map_put_error(e, &key))?;

    // Destination metadata for LastModified / SSE (version-aware so a
    // concurrent overwrite cannot leak into this response).
    let dst_meta = match &result.version_id {
        Some(vid) => state.storage.version_meta(&bucket, &key, vid).await,
        None => state.storage.head_object(&bucket, &key).await,
    }
    .map_err(S3Error::internal)?;

    let xml = to_xml(&CopyObjectResult {
        etag: result.etag,
        last_modified: dst_meta.last_modified,
    })
    .map_err(S3Error::internal)?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    if let Some(vid) = &src_meta.version_id {
        builder = builder.header("x-amz-copy-source-version-id", vid.as_str());
    }
    builder = add_sse_headers(builder, &dst_meta.encryption);
    Ok(builder.body(Body::from(xml)).unwrap())
}

/// Convert ISO 8601 timestamp to HTTP date (RFC 7231) for Last-Modified header.
fn to_http_date(iso: &str) -> String {
    chrono::DateTime::parse_from_str(iso, "%Y-%m-%dT%H:%M:%S%.3fZ")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(iso))
        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|_| iso.to_string())
}

// ── Conditional request header evaluation ────────────────────────────────────

enum ConditionalResult {
    NotModified,
    PreconditionFailed,
}

/// Returns true if `header_value` (the value of If-Match or If-None-Match)
/// matches `object_etag`. Handles `*`, quoted/unquoted ETags, and
/// comma-separated lists.
fn etag_matches(header_value: &str, object_etag: &str) -> bool {
    let value = header_value.trim();
    if value == "*" {
        return true;
    }
    let obj = object_etag.trim_matches('"');
    for part in value.split(',') {
        if part.trim().trim_matches('"') == obj {
            return true;
        }
    }
    false
}

/// Parse an RFC 7231 HTTP-date string (e.g. "Sun, 06 Nov 1994 08:49:37 GMT").
/// Returns None on invalid input — callers silently skip the condition.
fn parse_http_date(s: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc2822(s).ok()
}

/// Parse the ISO 8601 timestamp stored in ObjectMeta.last_modified.
fn parse_object_date(iso: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_str(iso, "%Y-%m-%dT%H:%M:%S%.3fZ")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(iso))
        .ok()
}

/// Evaluate conditional request headers against object metadata, following
/// S3/RFC 7232 precedence rules. Returns Some(result) if the request should
/// be short-circuited, or None if it should proceed normally.
fn check_conditions(
    headers: &HeaderMap,
    meta: &crate::storage::ObjectMeta,
) -> Option<ConditionalResult> {
    check_conditions_with_prefix(headers, meta, "")
}

/// `check_conditions` over `{prefix}if-match` etc. — the prefix is
/// `x-amz-copy-source-` for CopyObject / UploadPartCopy source checks.
fn check_conditions_with_prefix(
    headers: &HeaderMap,
    meta: &crate::storage::ObjectMeta,
    prefix: &str,
) -> Option<ConditionalResult> {
    let get = |name: &str| {
        headers
            .get(format!("{}{}", prefix, name).as_str())
            .and_then(|v| v.to_str().ok())
    };
    let if_match = get("if-match");
    let if_none_match = get("if-none-match");
    let if_modified_since = get("if-modified-since");
    let if_unmodified_since = get("if-unmodified-since");

    // Step 1: If-Match
    if let Some(value) = if_match {
        if !etag_matches(value, &meta.etag) {
            return Some(ConditionalResult::PreconditionFailed);
        }
        // ETag matched — If-Unmodified-Since is skipped per RFC 7232 §6
    } else if let Some(value) = if_unmodified_since {
        // Step 2: If-Unmodified-Since (only when If-Match is absent)
        if let (Some(threshold), Some(obj_date)) = (
            parse_http_date(value),
            parse_object_date(&meta.last_modified),
        ) {
            if obj_date > threshold {
                return Some(ConditionalResult::PreconditionFailed);
            }
        }
    }

    // Step 3: If-None-Match
    if let Some(value) = if_none_match {
        if etag_matches(value, &meta.etag) {
            return Some(ConditionalResult::NotModified);
        }
        // Present but no match — If-Modified-Since is skipped per RFC 7232 §6
    } else if let Some(value) = if_modified_since {
        // Step 4: If-Modified-Since (only when If-None-Match is absent)
        if let (Some(threshold), Some(obj_date)) = (
            parse_http_date(value),
            parse_object_date(&meta.last_modified),
        ) {
            if obj_date <= threshold {
                return Some(ConditionalResult::NotModified);
            }
        }
    }

    None
}

fn not_modified_response(meta: &crate::storage::ObjectMeta) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified))
        .body(Body::empty())
        .unwrap()
}

/// Parse an HTTP Range header value into (start, end_inclusive) byte positions.
/// Returns Ok(Some((start, end))) for valid ranges, Ok(None) for unparseable/ignored,
/// Err(()) for syntactically valid but unsatisfiable ranges.
fn parse_range(header: &str, file_size: u64) -> Result<Option<(u64, u64)>, ()> {
    let header = header.trim();
    let spec = match header.strip_prefix("bytes=") {
        Some(s) => s.trim(),
        None => return Ok(None),
    };
    // S3 doesn't support multi-range
    if spec.contains(',') {
        return Ok(None);
    }
    let (start_str, end_str) = match spec.split_once('-') {
        Some(parts) => parts,
        None => return Ok(None),
    };

    if file_size == 0 {
        return Err(());
    }

    if start_str.is_empty() {
        // Suffix: bytes=-N
        let suffix: u64 = end_str.parse().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        let start = file_size.saturating_sub(suffix);
        Ok(Some((start, file_size - 1)))
    } else if end_str.is_empty() {
        // Open end: bytes=N-
        let start: u64 = start_str.parse().map_err(|_| ())?;
        if start >= file_size {
            return Err(());
        }
        Ok(Some((start, file_size - 1)))
    } else {
        // Explicit: bytes=N-M
        let start: u64 = start_str.parse().map_err(|_| ())?;
        let end: u64 = end_str.parse().map_err(|_| ())?;
        if start >= file_size {
            return Err(());
        }
        let end = end.min(file_size - 1);
        if start > end {
            return Err(());
        }
        Ok(Some((start, end)))
    }
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    reject_unsupported_subresource(&params, ObjectMethod::Get)?;
    if params.contains_key("retention") || params.contains_key("legal-hold") {
        return Err(object_lock_not_configured());
    }
    if params.contains_key("acl") {
        return get_object_acl(&state, &bucket, &key, &params).await;
    }
    if params.contains_key("attributes") {
        return get_object_attributes(&state, &bucket, &key, &params, &headers).await;
    }

    if params.contains_key("tagging") {
        return get_object_tagging(State(state), Path((bucket, key))).await;
    }

    if params.contains_key("uploadId") {
        return multipart::list_parts(State(state), Path((bucket, key)), Query(params)).await;
    }

    let customer_key = extract_customer_key(&headers)?;
    let version_id = params.get("versionId").map(String::as_str);

    let meta = match resolve_object_meta(&state, &bucket, &key, version_id, false).await? {
        Resolved::Meta(m) => *m,
        Resolved::Early(resp) => return Ok(resp),
    };

    // Conditional headers apply to every GET flavour (full, range, part).
    if let Some(result) = check_conditions(&headers, &meta) {
        return match result {
            ConditionalResult::NotModified => Ok(not_modified_response(&meta)),
            ConditionalResult::PreconditionFailed => Err(S3Error::precondition_failed()),
        };
    }

    // (offset, length, parts_count) for partNumber / Range requests.
    let selection: Option<(u64, u64, Option<usize>)> =
        if let Some(part_num_str) = params.get("partNumber") {
            let (offset, length, count) = part_range(&meta, part_num_str)?;
            Some((offset, length, Some(count)))
        } else if let Some(range_str) = headers.get("range").and_then(|v| v.to_str().ok()) {
            match parse_range(range_str, meta.size) {
                Ok(Some((start, end))) => Some((start, end - start + 1, None)),
                // Unparseable or multi-range — fall through to full 200
                Ok(None) => None,
                Err(()) => return Err(S3Error::invalid_range()),
            }
        } else {
            None
        };

    let opened = match (selection, version_id) {
        (Some((offset, length, _)), None) => {
            state
                .storage
                .get_object_range(&bucket, &key, offset, length, customer_key)
                .await
        }
        (Some((offset, length, _)), Some(vid)) => {
            state
                .storage
                .get_object_version_range(&bucket, &key, vid, offset, length, customer_key)
                .await
        }
        (None, None) => state.storage.get_object(&bucket, &key, customer_key).await,
        (None, Some(vid)) => {
            state
                .storage
                .get_object_version(&bucket, &key, vid, customer_key)
                .await
        }
    };
    let (reader, meta) = opened.map_err(|e| map_read_error(e, &key, version_id))?;

    // The object may have been replaced between resolving and opening it.
    if let Some(result) = check_conditions(&headers, &meta) {
        drop(reader);
        return match result {
            ConditionalResult::NotModified => Ok(not_modified_response(&meta)),
            ConditionalResult::PreconditionFailed => Err(S3Error::precondition_failed()),
        };
    }

    let stream = ReaderStream::with_capacity(reader, 256 * 1024);
    let body = Body::from_stream(stream);
    let mut hdrs = object_headers(&meta, &params);
    // A full-object checksum does not describe a partial body; SDKs would
    // validate it against the returned bytes and fail.
    if let (Some((_, length, _)), Some(algo)) = (selection, &meta.checksum_algorithm) {
        if length < meta.size {
            hdrs.remove(algo.header_name());
        }
    }

    let builder = match selection {
        Some((offset, length, parts)) => {
            let mut b = builder_with(StatusCode::PARTIAL_CONTENT, hdrs)
                .header("Content-Length", length.to_string())
                .header(
                    "Content-Range",
                    format!(
                        "bytes {}-{}/{}",
                        offset,
                        (offset + length).saturating_sub(1),
                        meta.size
                    ),
                );
            if let Some(count) = parts {
                b = b.header("x-amz-mp-parts-count", count.to_string());
            }
            b
        }
        None => builder_with(StatusCode::OK, hdrs).header("Content-Length", meta.size.to_string()),
    };
    Ok(builder.body(body).unwrap())
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    reject_unsupported_subresource(&params, ObjectMethod::Head)?;
    let version_id = params.get("versionId").map(String::as_str);
    let meta = match resolve_object_meta(&state, &bucket, &key, version_id, true).await? {
        Resolved::Meta(m) => *m,
        Resolved::Early(resp) => return Ok(resp),
    };

    if let Some(result) = check_conditions(&headers, &meta) {
        return match result {
            ConditionalResult::NotModified => Ok(not_modified_response(&meta)),
            ConditionalResult::PreconditionFailed => Err(S3Error::precondition_failed()),
        };
    }

    let hdrs = object_headers(&meta, &params);
    if let Some(part_num_str) = params.get("partNumber") {
        let (offset, length, total_parts) = part_range(&meta, part_num_str)?;
        let builder = builder_with(StatusCode::PARTIAL_CONTENT, hdrs)
            .header("Content-Length", length.to_string())
            .header(
                "Content-Range",
                format!(
                    "bytes {}-{}/{}",
                    offset,
                    (offset + length).saturating_sub(1),
                    meta.size
                ),
            )
            .header("x-amz-mp-parts-count", total_parts.to_string());
        return Ok(builder.body(Body::empty()).unwrap());
    }

    let builder =
        builder_with(StatusCode::OK, hdrs).header("Content-Length", meta.size.to_string());
    Ok(builder.body(Body::empty()).unwrap())
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    reject_unsupported_subresource(&params, ObjectMethod::Delete)?;
    if params.contains_key("tagging") {
        return delete_object_tagging(State(state), Path((bucket, key))).await;
    }

    if params.contains_key("uploadId") {
        return multipart::abort_multipart_upload(State(state), Path((bucket, key)), Query(params))
            .await;
    }

    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::from_bucket_storage(e, &bucket)),
    }

    // Permanent version deletion
    if let Some(version_id) = params.get("versionId") {
        let deleted_meta = state
            .storage
            .delete_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?;

        let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
        builder = builder.header("x-amz-version-id", version_id.as_str());
        if deleted_meta.is_delete_marker {
            builder = builder.header("x-amz-delete-marker", "true");
        }
        return Ok(builder.body(Body::empty()).unwrap());
    }

    let result = state
        .storage
        .delete_object(&bucket, &key)
        .await
        .map_err(S3Error::internal)?;

    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    if result.is_delete_marker {
        builder = builder.header("x-amz-delete-marker", "true");
    }
    Ok(builder.body(Body::empty()).unwrap())
}

pub async fn post_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("uploads") {
        return multipart::create_multipart_upload(State(state), Path((bucket, key)), headers)
            .await;
    }
    if params.contains_key("uploadId") {
        return multipart::complete_multipart_upload(
            State(state),
            Path((bucket, key)),
            Query(params),
            headers,
            body,
        )
        .await;
    }
    Err(S3Error::not_implemented(
        "Unsupported POST object operation",
    ))
}

const DELETE_BODY_MAX: usize = 2 * 1024 * 1024;
const DELETE_OBJECTS_MAX: usize = 1000;

/// One `<Object>` entry of a DeleteObjects request.
struct DeleteTarget {
    key: String,
    version_id: Option<String>,
}

/// Parse `<Delete><Quiet/><Object><Key/><VersionId/></Object>…</Delete>`.
/// Event-based on purpose: quick-xml's serde deserializer trims text, which
/// would corrupt keys with leading/trailing whitespace.
fn parse_delete_request(xml: &str) -> Result<(Vec<DeleteTarget>, bool), S3Error> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut targets = Vec::new();
    let mut quiet = false;
    let mut key: Option<String> = None;
    let mut version_id: Option<String> = None;
    let mut text = String::new();
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) => {
                let name = e.local_name().as_ref().to_vec();
                if name == b"Object" {
                    key = None;
                    version_id = None;
                }
                text.clear();
                path.push(name);
            }
            Ok(quick_xml::events::Event::Empty(e)) => {
                if e.local_name().as_ref() == b"Object" {
                    return Err(S3Error::malformed_xml());
                }
            }
            Ok(quick_xml::events::Event::Text(t)) => {
                text.push_str(&t.unescape().map_err(|_| S3Error::malformed_xml())?);
            }
            Ok(quick_xml::events::Event::CData(t)) => {
                text.push_str(&String::from_utf8_lossy(&t.into_inner()));
            }
            Ok(quick_xml::events::Event::End(_)) => {
                let name = path.pop().unwrap_or_default();
                let in_object = path.last().is_some_and(|p| p == b"Object");
                match name.as_slice() {
                    b"Key" if in_object => key = Some(std::mem::take(&mut text)),
                    b"VersionId" if in_object => {
                        let v = std::mem::take(&mut text);
                        version_id = Some(v.trim().to_string()).filter(|v| !v.is_empty());
                    }
                    b"Quiet" if path.last().is_some_and(|p| p == b"Delete") => {
                        quiet = text.trim().eq_ignore_ascii_case("true");
                    }
                    b"Object" => {
                        let key = key.take().filter(|k| !k.is_empty());
                        let key = key.ok_or_else(S3Error::malformed_xml)?;
                        targets.push(DeleteTarget {
                            key,
                            version_id: version_id.take(),
                        });
                        if targets.len() > DELETE_OBJECTS_MAX {
                            return Err(S3Error::malformed_xml());
                        }
                    }
                    _ => {}
                }
                text.clear();
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
    }
    if targets.is_empty() {
        return Err(S3Error::malformed_xml());
    }
    Ok((targets, quiet))
}

/// DeleteObjects with Content-MD5 validation, per-version deletes and Quiet.
pub async fn delete_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::from_bucket_storage(e, &bucket)),
    }

    let bytes = axum::body::to_bytes(body, DELETE_BODY_MAX)
        .await
        .map_err(|_| S3Error::malformed_xml())?;
    verify_content_md5(&headers, &bytes)?;
    let body_str = std::str::from_utf8(&bytes).map_err(|_| S3Error::malformed_xml())?;
    let (targets, quiet) = parse_delete_request(body_str)?;

    let mut set = tokio::task::JoinSet::new();
    for (idx, target) in targets.into_iter().enumerate() {
        let storage = state.storage.clone();
        let bucket = bucket.clone();
        set.spawn(async move {
            let outcome = match &target.version_id {
                Some(vid) => match storage
                    .delete_object_version(&bucket, &target.key, vid)
                    .await
                {
                    // (version_id, delete_marker, delete_marker_version_id)
                    Ok(meta) => Ok((
                        Some(vid.clone()),
                        meta.is_delete_marker,
                        meta.is_delete_marker.then(|| vid.clone()),
                    )),
                    // S3 reports deleting a non-existent version as success.
                    Err(StorageError::VersionNotFound(_)) | Err(StorageError::NotFound(_)) => {
                        Ok((Some(vid.clone()), false, None))
                    }
                    Err(e) => Err(e),
                },
                None => storage.delete_object(&bucket, &target.key).await.map(|dr| {
                    if dr.is_delete_marker {
                        (None, true, dr.version_id)
                    } else {
                        (dr.version_id, false, None)
                    }
                }),
            };
            (idx, target, outcome)
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = set.join_next().await {
        results.push(joined.map_err(S3Error::internal)?);
    }
    results.sort_by_key(|(idx, _, _)| *idx);

    let esc = |s: &str| quick_xml::escape::escape(s).into_owned();
    let mut deleted_xml = String::new();
    let mut error_xml = String::new();
    for (_, target, outcome) in results {
        match outcome {
            Ok((version_id, delete_marker, marker_vid)) => {
                if quiet {
                    continue;
                }
                deleted_xml.push_str(&format!("<Deleted><Key>{}</Key>", esc(&target.key)));
                if let Some(vid) = version_id {
                    deleted_xml.push_str(&format!("<VersionId>{}</VersionId>", esc(&vid)));
                }
                if delete_marker {
                    deleted_xml.push_str("<DeleteMarker>true</DeleteMarker>");
                }
                if let Some(mvid) = marker_vid {
                    deleted_xml.push_str(&format!(
                        "<DeleteMarkerVersionId>{}</DeleteMarkerVersionId>",
                        esc(&mvid)
                    ));
                }
                deleted_xml.push_str("</Deleted>");
            }
            Err(e) => {
                let (code, message) = match &e {
                    StorageError::InvalidKey(msg) => ("InvalidArgument", msg.clone()),
                    _ => {
                        tracing::error!("DeleteObjects {}: {}", target.key, e);
                        (
                            "InternalError",
                            "We encountered an internal error. Please try again.".to_string(),
                        )
                    }
                };
                error_xml.push_str(&format!("<Error><Key>{}</Key>", esc(&target.key)));
                if let Some(vid) = &target.version_id {
                    error_xml.push_str(&format!("<VersionId>{}</VersionId>", esc(vid)));
                }
                error_xml.push_str(&format!(
                    "<Code>{}</Code><Message>{}</Message></Error>",
                    code,
                    esc(&message)
                ));
            }
        }
    }

    let response_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}{}</DeleteResult>",
        deleted_xml, error_xml
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(response_xml))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ObjectMeta;

    fn make_meta(etag: &str, last_modified: &str) -> ObjectMeta {
        ObjectMeta {
            key: "test.txt".into(),
            size: 42,
            etag: etag.to_string(),
            content_type: "text/plain".into(),
            last_modified: last_modified.to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
            tags: None,
            part_sizes: None,
            encryption: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_delete_request() {
        let (t, quiet) = parse_delete_request(
            "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Quiet>true</Quiet>\
             <Object><Key> sp &amp; ce </Key></Object>\
             <Object><Key><![CDATA[c<d]]></Key><VersionId> v1 </VersionId></Object></Delete>",
        )
        .unwrap();
        assert!(quiet);
        assert_eq!(t[0].key, " sp & ce ");
        assert_eq!(t[0].version_id, None);
        assert_eq!(t[1].key, "c<d");
        assert_eq!(t[1].version_id.as_deref(), Some("v1"));
        let (_, quiet) =
            parse_delete_request("<Delete><Object><Key>a</Key></Object></Delete>").unwrap();
        assert!(!quiet);
        for bad in [
            "<Delete></Delete>",
            "<Delete><Object/></Delete>",
            "<Delete><Object><Key></Key></Object></Delete>",
            "<Delete><Object><Key>a</Key></Delete>",
            "not xml",
        ] {
            assert!(parse_delete_request(bad).is_err(), "{bad}");
        }
        let many = format!(
            "<Delete>{}</Delete>",
            "<Object><Key>k</Key></Object>".repeat(DELETE_OBJECTS_MAX + 1)
        );
        assert!(parse_delete_request(&many).is_err());
    }

    #[test]
    fn test_strip_aws_chunked() {
        assert_eq!(strip_aws_chunked("aws-chunked"), None);
        assert_eq!(strip_aws_chunked("aws-chunked, gzip"), Some("gzip".into()));
        assert_eq!(
            strip_aws_chunked("gzip,AWS-CHUNKED,br"),
            Some("gzip, br".into())
        );
    }

    // ── etag_matches ────────────────────────────────────────────────────────

    #[test]
    fn test_etag_matches_exact_quoted() {
        assert!(etag_matches("\"abc123\"", "\"abc123\""));
    }

    #[test]
    fn test_etag_matches_unquoted_header() {
        assert!(etag_matches("abc123", "\"abc123\""));
    }

    #[test]
    fn test_etag_matches_wildcard() {
        assert!(etag_matches("*", "\"anything\""));
    }

    #[test]
    fn test_etag_matches_comma_list() {
        assert!(etag_matches("\"aaa\", \"bbb\", \"abc123\"", "\"abc123\""));
    }

    #[test]
    fn test_etag_no_match() {
        assert!(!etag_matches("\"wrong\"", "\"abc123\""));
    }

    // ── check_conditions ────────────────────────────────────────────────────

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    const ETAG: &str = "\"abc123\"";
    // A past date so objects modified "now" are always newer than it
    const OLD_DATE: &str = "Mon, 01 Jan 2024 00:00:00 GMT";
    // A future date so objects are always older
    const FUTURE_DATE: &str = "Thu, 01 Jan 2099 00:00:00 GMT";
    const LAST_MODIFIED: &str = "2025-06-01T12:00:00.000Z";

    #[test]
    fn test_if_match_passes_returns_none() {
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-match", ETAG)]);
        assert!(matches!(check_conditions(&h, &meta), None));
    }

    #[test]
    fn test_if_match_fails_returns_412() {
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-match", "\"wrong\"")]);
        assert!(matches!(
            check_conditions(&h, &meta),
            Some(ConditionalResult::PreconditionFailed)
        ));
    }

    #[test]
    fn test_if_none_match_hit_returns_304() {
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-none-match", ETAG)]);
        assert!(matches!(
            check_conditions(&h, &meta),
            Some(ConditionalResult::NotModified)
        ));
    }

    #[test]
    fn test_if_none_match_miss_returns_none() {
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-none-match", "\"other\"")]);
        assert!(matches!(check_conditions(&h, &meta), None));
    }

    #[test]
    fn test_if_modified_since_not_modified_returns_304() {
        // Object was last modified 2025-06-01; threshold is in the future → not modified
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-modified-since", FUTURE_DATE)]);
        assert!(matches!(
            check_conditions(&h, &meta),
            Some(ConditionalResult::NotModified)
        ));
    }

    #[test]
    fn test_if_modified_since_was_modified_returns_none() {
        // Object was last modified 2025-06-01; threshold is in the past → was modified
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-modified-since", OLD_DATE)]);
        assert!(matches!(check_conditions(&h, &meta), None));
    }

    #[test]
    fn test_if_unmodified_since_unmodified_returns_none() {
        // Object was last modified 2025-06-01; threshold is in the future → still matches
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-unmodified-since", FUTURE_DATE)]);
        assert!(matches!(check_conditions(&h, &meta), None));
    }

    #[test]
    fn test_if_unmodified_since_was_modified_returns_412() {
        // Object was last modified 2025-06-01; threshold is in the past → modified after
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-unmodified-since", OLD_DATE)]);
        assert!(matches!(
            check_conditions(&h, &meta),
            Some(ConditionalResult::PreconditionFailed)
        ));
    }

    #[test]
    fn test_if_match_suppresses_if_unmodified_since() {
        // If-Match passes → If-Unmodified-Since must be skipped even if it would fail
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-match", ETAG), ("if-unmodified-since", OLD_DATE)]);
        assert!(matches!(check_conditions(&h, &meta), None));
    }

    #[test]
    fn test_if_none_match_suppresses_if_modified_since() {
        // If-None-Match present but no match → If-Modified-Since must be skipped
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[
            ("if-none-match", "\"other\""),
            ("if-modified-since", FUTURE_DATE),
        ]);
        assert!(matches!(check_conditions(&h, &meta), None));
    }

    #[test]
    fn test_invalid_date_silently_ignored() {
        let meta = make_meta(ETAG, LAST_MODIFIED);
        let h = headers_with(&[("if-modified-since", "not-a-date")]);
        assert!(matches!(check_conditions(&h, &meta), None));
    }
}

/// Reject a body whose declared length already exceeds `max`.
/// `x-amz-decoded-content-length` is the object size for aws-chunked uploads;
/// otherwise `Content-Length` is used. Chunked bodies with no length are
/// enforced while the bytes are written.
pub(crate) fn reject_oversized_body(headers: &HeaderMap, max: u64) -> Result<(), S3Error> {
    let raw = headers
        .get("x-amz-decoded-content-length")
        .or_else(|| headers.get(http::header::CONTENT_LENGTH));
    let Some(raw) = raw else {
        return Ok(());
    };
    let text = raw
        .to_str()
        .map_err(|_| S3Error::invalid_argument("invalid content length"))?;
    let len: u64 = text
        .parse()
        .map_err(|_| S3Error::invalid_argument("invalid content length"))?;
    if len > max {
        return Err(S3Error::entity_too_large());
    }
    Ok(())
}

/// Request body → reader. aws-chunked decoding (signature/checksum
/// verification) happens in the auth middleware; see `super::chunked`.
pub(crate) async fn body_to_reader(
    headers: &HeaderMap,
    body: Body,
) -> Result<std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>, S3Error> {
    super::chunked::body_to_reader(headers, body).await
}

const TAGGING_BODY_MAX: usize = 64 * 1024;

pub async fn get_object_tagging(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response<Body>, S3Error> {
    let tags = state
        .storage
        .get_object_tagging(&bucket, &key)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_key(&key),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            _ => S3Error::internal(e),
        })?;

    let mut tag_entries: Vec<Tag> = tags
        .into_iter()
        .map(|(k, v)| Tag { key: k, value: v })
        .collect();
    tag_entries.sort_by(|a, b| a.key.cmp(&b.key));

    let tagging = Tagging {
        tag_set: TagSet { tags: tag_entries },
    };
    let xml = to_xml(&tagging).map_err(S3Error::internal)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

pub async fn put_object_tagging(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    let bytes = axum::body::to_bytes(body, TAGGING_BODY_MAX)
        .await
        .map_err(|e| S3Error::internal(e))?;
    let body_str = String::from_utf8_lossy(&bytes);

    let mut tags = HashMap::new();
    let mut reader = quick_xml::Reader::from_str(&body_str);
    reader.config_mut().trim_text(true);
    let mut current_key: Option<String> = None;
    let mut in_key = false;
    let mut in_value = false;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) => match e.name().as_ref() {
                b"Key" => in_key = true,
                b"Value" => in_value = true,
                _ => {}
            },
            Ok(quick_xml::events::Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().into_owned();
                if in_key {
                    current_key = Some(text);
                    in_key = false;
                } else if in_value {
                    if let Some(k) = current_key.take() {
                        tags.insert(k, text);
                    }
                    in_value = false;
                }
            }
            Ok(quick_xml::events::Event::End(e)) => match e.name().as_ref() {
                b"Key" => in_key = false,
                b"Value" => in_value = false,
                _ => {}
            },
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
    }

    validate_tags(&tags)?;

    state
        .storage
        .put_object_tagging(&bucket, &key, tags)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_key(&key),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            _ => S3Error::internal(e),
        })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

pub async fn delete_object_tagging(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response<Body>, S3Error> {
    state
        .storage
        .delete_object_tagging(&bucket, &key)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_key(&key),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            _ => S3Error::internal(e),
        })?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}
