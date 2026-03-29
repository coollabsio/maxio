use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use futures::TryStreamExt;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio_util::io::ReaderStream;

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{ChecksumAlgorithm, StorageError};
use crate::xml::{response::to_xml, types::{CopyObjectResult, CopyPartResult, Tag, TagSet, Tagging}};

use super::multipart;

/// Extract checksum algorithm and optional expected value from request headers.
pub(crate) fn extract_checksum(headers: &HeaderMap) -> Option<(ChecksumAlgorithm, Option<String>)> {
    let pairs = [
        ("x-amz-checksum-crc32", ChecksumAlgorithm::CRC32),
        ("x-amz-checksum-crc32c", ChecksumAlgorithm::CRC32C),
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
}

fn add_checksum_header(
    builder: http::response::Builder,
    meta: &crate::storage::ObjectMeta,
) -> http::response::Builder {
    if let (Some(algo), Some(val)) = (&meta.checksum_algorithm, &meta.checksum_value) {
        builder.header(algo.header_name(), val.as_str())
    } else {
        builder
    }
}

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("uploadId") && headers.contains_key("x-amz-copy-source") {
        return upload_part_copy(State(state), Path((bucket, key)), Query(params), headers).await;
    }

    if headers.contains_key("x-amz-copy-source") {
        return copy_object(State(state), Path((bucket, key)), headers).await;
    }

    if params.contains_key("tagging") {
        return put_object_tagging(State(state), Path((bucket, key)), body).await;
    }

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

    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let mut reader = body_to_reader(&headers, body).await?;

    // If Content-MD5 is provided, buffer the body and verify before writing
    let content_md5 = headers
        .get("content-md5")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(ref expected_md5) = content_md5 {
        use md5::Digest;
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.map_err(S3Error::internal)?;
        let computed_hash = md5::Md5::digest(&buf);
        use base64::Engine;
        let computed_md5 = base64::engine::general_purpose::STANDARD.encode(computed_hash);
        if computed_md5 != *expected_md5 {
            return Err(S3Error::bad_digest());
        }
        reader = Box::pin(std::io::Cursor::new(buf));
    }

    let checksum = extract_checksum(&headers);

    let result = state
        .storage
        .put_object(&bucket, &key, content_type, reader, checksum)
        .await
        .map_err(|e| match e {
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            StorageError::ChecksumMismatch(_) => S3Error::bad_checksum("x-amz-checksum"),
            _ => S3Error::internal(e),
        })?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &result.etag)
        .header("Content-Length", result.size.to_string());
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    if let (Some(algo), Some(val)) = (&result.checksum_algorithm, &result.checksum_value) {
        builder = builder.header(algo.header_name(), val.as_str());
    }
    Ok(builder.body(Body::empty()).unwrap())
}

struct CopySource {
    bucket: String,
    key: String,
    version_id: Option<String>,
}

/// Parse the `x-amz-copy-source` header into bucket/key and optional versionId.
fn parse_copy_source(headers: &HeaderMap) -> Result<CopySource, S3Error> {
    let copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source header"))?;

    let (raw_path, raw_query) = copy_source.split_once('?').unwrap_or((copy_source, ""));
    let version_id = raw_query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key != "versionId" {
            return None;
        }
        percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .ok()
            .map(|value| value.into_owned())
    });

    let decoded = percent_encoding::percent_decode_str(raw_path)
        .decode_utf8()
        .map_err(|_| S3Error::invalid_argument("invalid x-amz-copy-source encoding"))?;
    let trimmed = decoded.trim_start_matches('/');
    let (src_bucket, src_key) = trimmed
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("invalid x-amz-copy-source format"))?;
    Ok(CopySource {
        bucket: src_bucket.to_string(),
        key: src_key.to_string(),
        version_id,
    })
}

/// Parse `x-amz-copy-source-range: bytes=start-end` into (start, end) inclusive.
fn parse_copy_source_range(headers: &HeaderMap, src_size: u64) -> Result<Option<(u64, u64)>, S3Error> {
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
    let copy_source = parse_copy_source(&headers)?;
    let src_bucket = copy_source.bucket;
    let src_key = copy_source.key;
    let src_version_id = copy_source.version_id;

    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
    let part_number = params
        .get("partNumber")
        .ok_or_else(|| S3Error::invalid_argument("missing partNumber"))?
        .parse::<u32>()
        .map_err(|_| S3Error::invalid_part("invalid part number"))?;

    multipart::ensure_bucket_exists(&state, &bucket).await?;

    // Get source metadata first to validate range before opening the file
    let src_meta = if let Some(version_id) = src_version_id.as_deref() {
        state
            .storage
            .head_object_version(&src_bucket, &src_key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                StorageError::NotFound(_) => S3Error::no_such_key(&src_key),
                _ => S3Error::internal(e),
            })?
    } else {
        state
            .storage
            .head_object(&src_bucket, &src_key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&src_key),
                _ => S3Error::internal(e),
            })?
    };

    let range = parse_copy_source_range(&headers, src_meta.size)?;

    let reader = match range {
        None => {
            let (r, _) = if let Some(version_id) = src_version_id.as_deref() {
                state
                    .storage
                    .get_object_version(&src_bucket, &src_key, version_id)
                    .await
                    .map_err(|e| match e {
                        StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                        StorageError::NotFound(_) => S3Error::no_such_key(&src_key),
                        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                        _ => S3Error::internal(e),
                    })?
            } else {
                state
                    .storage
                    .get_object(&src_bucket, &src_key)
                    .await
                    .map_err(|e| match e {
                        StorageError::NotFound(_) => S3Error::no_such_key(&src_key),
                        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                        _ => S3Error::internal(e),
                    })?
            };
            r
        }
        Some((start, end)) => {
            let (r, _) = if let Some(version_id) = src_version_id.as_deref() {
                state
                    .storage
                    .get_object_version_range(&src_bucket, &src_key, version_id, start, end - start + 1)
                    .await
                    .map_err(|e| match e {
                        StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                        StorageError::NotFound(_) => S3Error::no_such_key(&src_key),
                        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                        _ => S3Error::internal(e),
                    })?
            } else {
                state
                    .storage
                    .get_object_range(&src_bucket, &src_key, start, end - start + 1)
                    .await
                    .map_err(|e| match e {
                        StorageError::NotFound(_) => S3Error::no_such_key(&src_key),
                        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                        _ => S3Error::internal(e),
                    })?
            };
            r
        }
    };

    let checksum = extract_checksum(&headers);
    let part = state
        .storage
        .upload_part(&bucket, upload_id, part_number, reader, checksum)
        .await
        .map_err(multipart::map_storage_err)?;

    let xml = to_xml(&CopyPartResult {
        etag: part.etag,
        last_modified: src_meta.last_modified,
    })
    .map_err(S3Error::internal)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn copy_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let copy_source = parse_copy_source(&headers)?;
    let src_bucket = copy_source.bucket;
    let src_key = copy_source.key;
    let src_version_id = copy_source.version_id;
    let (src_bucket, src_key) = (src_bucket.as_str(), src_key.as_str());

    // Validate destination bucket
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    // Get source object
    let (reader, src_meta) = if let Some(version_id) = src_version_id.as_deref() {
        state
            .storage
            .get_object_version(src_bucket, src_key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                StorageError::NotFound(_) => S3Error::no_such_key(src_key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    } else {
        state
            .storage
            .get_object(src_bucket, src_key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(src_key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    };

    // Determine content-type based on metadata directive
    let directive = headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("COPY");

    let content_type = match directive {
        "COPY" => src_meta.content_type.clone(),
        "REPLACE" => headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string(),
        _ => return Err(S3Error::invalid_argument("invalid x-amz-metadata-directive")),
    };

    // Propagate source checksum algorithm so it's recomputed during copy
    let checksum = src_meta.checksum_algorithm.map(|algo| (algo, None));

    // Write destination
    let result = state
        .storage
        .put_object(&bucket, &key, &content_type, reader, checksum)
        .await
        .map_err(|e| match e {
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            _ => S3Error::internal(e),
        })?;

    // Get destination metadata for LastModified
    let dst_meta = state
        .storage
        .head_object(&bucket, &key)
        .await
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
    let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
    let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());
    let if_modified_since = headers.get("if-modified-since").and_then(|v| v.to_str().ok());
    let if_unmodified_since = headers
        .get("if-unmodified-since")
        .and_then(|v| v.to_str().ok());

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
    if params.contains_key("tagging") {
        return get_object_tagging(State(state), Path((bucket, key))).await;
    }

    if params.contains_key("uploadId") {
        return multipart::list_parts(State(state), Path((bucket, key)), Query(params)).await;
    }

    if let Some(part_num_str) = params.get("partNumber") {
        let part_num: u32 = part_num_str
            .parse()
            .map_err(|_| S3Error::invalid_argument("invalid partNumber"))?;
        let meta = state
            .storage
            .head_object(&bucket, &key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?;
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
        let length = part_sizes[idx];
        let total_parts = part_sizes.len();

        let (reader, _) = state
            .storage
            .get_object_range(&bucket, &key, offset, length)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                _ => S3Error::internal(e),
            })?;

        let stream = ReaderStream::with_capacity(reader, 256 * 1024);
        let body = Body::from_stream(stream);
        return Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("Content-Type", &meta.content_type)
            .header("Content-Length", length.to_string())
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", offset, offset + length - 1, meta.size),
            )
            .header("ETag", &meta.etag)
            .header("Last-Modified", to_http_date(&meta.last_modified))
            .header("x-amz-mp-parts-count", total_parts.to_string())
            .body(body)
            .unwrap());
    }

    let range_header = headers
        .get("range")
        .and_then(|v| v.to_str().ok());

    if let Some(range_str) = range_header {
        let meta = state
            .storage
            .head_object(&bucket, &key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?;

        // Evaluate conditional headers before streaming any bytes
        if let Some(result) = check_conditions(&headers, &meta) {
            return match result {
                ConditionalResult::NotModified => Ok(not_modified_response(&meta)),
                ConditionalResult::PreconditionFailed => Err(S3Error::precondition_failed()),
            };
        }

        match parse_range(range_str, meta.size) {
            Ok(Some((start, end))) => {
                let length = end - start + 1;
                let (reader, _) = state
                    .storage
                    .get_object_range(&bucket, &key, start, length)
                    .await
                    .map_err(|e| match e {
                        StorageError::NotFound(_) => S3Error::no_such_key(&key),
                        _ => S3Error::internal(e),
                    })?;

                let stream = ReaderStream::with_capacity(reader, 256 * 1024);
                let body = Body::from_stream(stream);

                return Ok(Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header("Content-Type", &meta.content_type)
                    .header("Content-Length", length.to_string())
                    .header("Content-Range", format!("bytes {}-{}/{}", start, end, meta.size))
                    .header("Accept-Ranges", "bytes")
                    .header("ETag", &meta.etag)
                    .header("Last-Modified", to_http_date(&meta.last_modified))
                    .body(body)
                    .unwrap());
            }
            Ok(None) => {
                // Unparseable or multi-range — fall through to full 200
            }
            Err(()) => {
                return Err(S3Error::invalid_range());
            }
        }
    }

    let (reader, meta) = if let Some(version_id) = params.get("versionId") {
        state
            .storage
            .get_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    } else {
        state
            .storage
            .get_object(&bucket, &key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    };

    // Evaluate conditional headers before opening the stream
    if let Some(result) = check_conditions(&headers, &meta) {
        drop(reader);
        return match result {
            ConditionalResult::NotModified => Ok(not_modified_response(&meta)),
            ConditionalResult::PreconditionFailed => Err(S3Error::precondition_failed()),
        };
    }

    let stream = ReaderStream::with_capacity(reader, 256 * 1024);
    let body = Body::from_stream(stream);

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header("Accept-Ranges", "bytes")
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified));
    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    builder = add_checksum_header(builder, &meta);
    Ok(builder.body(body).unwrap())
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let meta = if let Some(version_id) = params.get("versionId") {
        state
            .storage
            .head_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    } else {
        state
            .storage
            .head_object(&bucket, &key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    };

    if let Some(result) = check_conditions(&headers, &meta) {
        return match result {
            ConditionalResult::NotModified => Ok(not_modified_response(&meta)),
            ConditionalResult::PreconditionFailed => Err(S3Error::precondition_failed()),
        };
    }

    if let Some(part_num_str) = params.get("partNumber") {
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
        let length = part_sizes[idx];
        let total_parts = part_sizes.len();

        let mut builder = Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("Content-Type", &meta.content_type)
            .header("Content-Length", length.to_string())
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", offset, offset + length - 1, meta.size),
            )
            .header("ETag", &meta.etag)
            .header("Last-Modified", to_http_date(&meta.last_modified))
            .header("x-amz-mp-parts-count", total_parts.to_string());
        if let Some(vid) = &meta.version_id {
            builder = builder.header("x-amz-version-id", vid.as_str());
        }
        return Ok(builder.body(Body::empty()).unwrap());
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified))
        .header("Accept-Ranges", "bytes");
    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    builder = add_checksum_header(builder, &meta);
    Ok(builder.body(Body::empty()).unwrap())
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("tagging") {
        return delete_object_tagging(State(state), Path((bucket, key))).await;
    }

    if params.contains_key("uploadId") {
        return multipart::abort_multipart_upload(State(state), Path((bucket, key)), Query(params))
            .await;
    }

    // Permanent version deletion
    if let Some(version_id) = params.get("versionId") {
        let deleted_meta = state
            .storage
            .delete_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                _ => S3Error::internal(e),
            })?;

        let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
        builder = builder.header("x-amz-version-id", version_id.as_str());
        if deleted_meta.is_delete_marker {
            builder = builder.header("x-amz-delete-marker", "true");
        }
        return Ok(builder.body(Body::empty()).unwrap());
    }

    let result = state.storage.delete_object(&bucket, &key).await
        .map_err(|e| S3Error::internal(e))?;

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
        return multipart::create_multipart_upload(State(state), Path((bucket, key)), headers).await;
    }
    if params.contains_key("uploadId") {
        return multipart::complete_multipart_upload(
            State(state),
            Path((bucket, key)),
            Query(params),
            body,
        )
        .await;
    }
    Err(S3Error::not_implemented("Unsupported POST object operation"))
}

const DELETE_BODY_MAX: usize = 1024 * 1024;

/// Handle POST /{bucket}?delete — multi-object delete (DeleteObjects API).
pub async fn delete_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    let bytes = axum::body::to_bytes(body, DELETE_BODY_MAX)
        .await
        .map_err(|e| S3Error::internal(e))?;
    let body_str = String::from_utf8_lossy(&bytes);

    let mut keys = Vec::new();
    let mut reader = quick_xml::Reader::from_str(&body_str);
    reader.config_mut().trim_text(true);
    let mut in_key = false;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Key" => {
                in_key = true;
            }
            Ok(quick_xml::events::Event::Text(e)) if in_key => {
                keys.push(e.unescape().unwrap_or_default().into_owned());
                in_key = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Key" => {
                in_key = false;
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
    }

    let mut set = tokio::task::JoinSet::new();
    for key in keys {
        let storage = state.storage.clone();
        let bucket = bucket.clone();
        set.spawn(async move {
            let result = storage.delete_object(&bucket, &key).await;
            (key, result)
        });
    }

    let mut deleted_xml = String::new();
    let mut error_xml = String::new();
    while let Some(result) = set.join_next().await {
        if let Ok((key, delete_result)) = result {
            match delete_result {
                Ok(dr) => {
                    let mut entry = format!(
                        "<Deleted><Key>{}</Key>",
                        quick_xml::escape::escape(&key)
                    );
                    if let Some(vid) = &dr.version_id {
                        entry.push_str(&format!("<VersionId>{}</VersionId>", vid));
                    }
                    if dr.is_delete_marker {
                        entry.push_str("<DeleteMarker>true</DeleteMarker>");
                    }
                    entry.push_str("</Deleted>");
                    deleted_xml.push_str(&entry);
                }
                Err(e) => {
                    error_xml.push_str(&format!(
                        "<Error><Key>{}</Key><Code>InternalError</Code><Message>{}</Message></Error>",
                        quick_xml::escape::escape(&key),
                        quick_xml::escape::escape(&e.to_string())
                    ));
                }
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
        }
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

pub(crate) async fn body_to_reader(
    headers: &HeaderMap,
    body: Body,
) -> Result<std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>, S3Error> {
    let is_aws_chunked = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        == Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD");

    let stream = body.into_data_stream();
    let raw_reader = tokio_util::io::StreamReader::new(
        stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );

    if is_aws_chunked {
        let mut buf_reader = tokio::io::BufReader::new(raw_reader);
        let mut decoded = Vec::new();
        loop {
            let mut line = String::new();
            let n = buf_reader
                .read_line(&mut line)
                .await
                .map_err(S3Error::internal)?;
            if n == 0 {
                break;
            }
            let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
            let size_str = line.split(';').next().unwrap_or("0");
            let chunk_size = usize::from_str_radix(size_str.trim(), 16)
                .map_err(|_| S3Error::internal("invalid chunk size"))?;
            if chunk_size == 0 {
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            buf_reader
                .read_exact(&mut chunk)
                .await
                .map_err(S3Error::internal)?;
            decoded.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            let _ = buf_reader.read_exact(&mut crlf).await;
        }
        Ok(Box::pin(std::io::Cursor::new(decoded)))
    } else {
        Ok(Box::pin(raw_reader))
    }
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

    let tagging = Tagging { tag_set: TagSet { tags: tag_entries } };
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

    if tags.len() > 10 {
        return Err(S3Error::invalid_argument("Object tags cannot exceed 10 entries"));
    }
    for (k, v) in &tags {
        if k.len() > 128 {
            return Err(S3Error::invalid_argument("Tag key exceeds maximum length of 128 characters"));
        }
        if v.len() > 256 {
            return Err(S3Error::invalid_argument("Tag value exceeds maximum length of 256 characters"));
        }
    }

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
