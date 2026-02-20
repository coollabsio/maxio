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
use crate::xml::{response::to_xml, types::CopyObjectResult};

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
    if headers.contains_key("x-amz-copy-source") {
        return copy_object(State(state), Path((bucket, key)), headers).await;
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

async fn copy_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source header"))?;

    let decoded = percent_encoding::percent_decode_str(copy_source)
        .decode_utf8()
        .map_err(|_| S3Error::invalid_argument("invalid x-amz-copy-source encoding"))?;
    let trimmed = decoded.trim_start_matches('/');
    let (src_bucket, src_key) = trimmed
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("invalid x-amz-copy-source format"))?;

    // Validate destination bucket
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    // Get source object
    let (reader, src_meta) = state
        .storage
        .get_object(src_bucket, src_key)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_key(src_key),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            _ => S3Error::internal(e),
        })?;

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
    if params.contains_key("uploadId") {
        return multipart::list_parts(State(state), Path((bucket, key)), Query(params)).await;
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

                let stream = ReaderStream::new(reader);
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

    let stream = ReaderStream::new(reader);
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
