use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{ChecksumAlgorithm, ChecksumType, StorageError};
use crate::xml::{response::to_xml, types::*};

use super::bucket::require_bucket;
use super::object::{
    Md5VerifyingReader, add_checksum_headers, body_to_reader, encryption_from_bucket_default,
    extract_checksum, extract_checksum_type, extract_customer_key, extract_object_metadata,
    extract_sse_request, extract_write_precondition, is_content_md5_mismatch, parse_content_md5,
    parse_tagging_header, reject_oversized_body, resolve_multipart_checksum_type,
    spec_from_request,
};

const COMPLETE_BODY_MAX: usize = 1024 * 1024;

pub async fn create_multipart_upload(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    crate::storage::filesystem::reject_writable_key(&key).map_err(map_storage_err)?;

    let object_metadata = extract_object_metadata(&headers)?;
    let tags = parse_tagging_header(&headers)?;
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let checksum_algorithm = headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
        .and_then(ChecksumAlgorithm::from_header_str);
    let checksum_type =
        resolve_multipart_checksum_type(checksum_algorithm, extract_checksum_type(&headers)?)?;

    // Resolve encryption spec at upload-create time (explicit > bucket default).
    let mut encryption = extract_sse_request(&headers)?;
    if encryption.is_none() {
        if let Ok(Some(cfg)) = state.storage.get_bucket_encryption(&bucket).await {
            encryption = Some(encryption_from_bucket_default(&cfg));
        }
    }
    let encryption_spec = encryption.as_ref().map(spec_from_request);
    let applied_mode = encryption.as_ref().map(|e| e.mode.clone());

    let upload = state
        .storage
        .create_multipart_upload(
            &bucket,
            &key,
            content_type,
            checksum_algorithm,
            checksum_type,
            encryption_spec,
            object_metadata,
            tags,
        )
        .await
        .map_err(map_storage_err)?;

    let xml = to_xml(&InitiateMultipartUploadResult {
        bucket,
        key,
        upload_id: upload.upload_id,
    })
    .map_err(S3Error::internal)?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    if let Some(algo) = checksum_algorithm {
        builder = builder.header("x-amz-checksum-algorithm", algo.as_str());
    }
    if let Some(ty) = checksum_type {
        builder = builder.header("x-amz-checksum-type", ty.header_value());
    }
    match applied_mode {
        Some(crate::storage::EncryptionMode::SseS3) => {
            builder = builder.header("x-amz-server-side-encryption", "AES256");
        }
        Some(crate::storage::EncryptionMode::SseC) => {
            builder = builder.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
        }
        None => {}
    }
    Ok(builder.body(Body::from(xml)).unwrap())
}

pub async fn upload_part(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    crate::storage::filesystem::reject_writable_key(&key).map_err(map_storage_err)?;

    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
    let part_number = params
        .get("partNumber")
        .ok_or_else(|| S3Error::invalid_argument("missing partNumber"))?
        .parse::<u32>()
        .map_err(|_| S3Error::invalid_part("invalid part number"))?;

    reject_oversized_body(&headers, state.config.max_part_size)?;
    let checksum = extract_checksum(&headers);
    let customer_key = extract_customer_key(&headers)?;
    // Content-MD5 is checked while the part streams to its temp file; a
    // mismatch fails before the part is published.
    let content_md5 = parse_content_md5(&headers)?;
    let reader = Md5VerifyingReader::wrap(body_to_reader(&headers, body).await?, content_md5);
    let part = state
        .storage
        .upload_part(
            &bucket,
            upload_id,
            part_number,
            reader,
            checksum,
            customer_key,
        )
        .await
        .map_err(|e| {
            if is_content_md5_mismatch(&e) {
                S3Error::bad_digest()
            } else {
                map_storage_err(e)
            }
        })?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &part.etag);
    if let (Some(algo), Some(val)) = (&part.checksum_algorithm, &part.checksum_value) {
        builder = builder.header(algo.header_name(), val.as_str());
    }
    Ok(builder.body(Body::empty()).unwrap())
}

pub async fn complete_multipart_upload(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    crate::storage::filesystem::reject_writable_key(&key).map_err(map_storage_err)?;
    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    let bytes = axum::body::to_bytes(body, COMPLETE_BODY_MAX)
        .await
        .map_err(S3Error::internal)?;
    let body_str = String::from_utf8_lossy(&bytes);
    let parts = parse_complete_parts(&body_str)?;
    if parts.is_empty() {
        return Err(S3Error::malformed_xml());
    }

    // SSE-C customer key, if the upload was SSE-C, arrives here again.
    let customer_key = extract_customer_key(&headers)?;
    let precondition = extract_write_precondition(&headers)?;
    let requested_type = extract_checksum_type(&headers)?;
    // UploadPart does not take x-amz-checksum-type (a part checksum is the
    // part bytes). CompleteMultipartUpload does: it must match the type fixed
    // at CreateMultipartUpload, and an optional checksum header is the object
    // digest to verify.
    let requested_checksum =
        extract_checksum(&headers).and_then(|(algo, value)| value.map(|value| (algo, value)));

    let result = state
        .storage
        .complete_multipart_upload(
            &bucket,
            upload_id,
            &parts,
            customer_key,
            precondition.as_ref(),
            requested_type,
            requested_checksum,
        )
        .await
        .map_err(|e| match e {
            StorageError::PreconditionFailed => S3Error::precondition_failed(),
            StorageError::NotFound(_) if precondition.is_some() => S3Error::no_such_key(&key),
            other => map_storage_err(other),
        })?;

    let checksums = checksum_xml_fields(
        result.checksum_algorithm,
        result.checksum_value.as_deref(),
        result.checksum_type,
    );
    let xml = to_xml(&CompleteMultipartUploadResult {
        location: format!("/{}/{}", bucket, key),
        bucket,
        key,
        etag: result.etag,
        checksum_crc32: checksums.crc32,
        checksum_crc32c: checksums.crc32c,
        checksum_crc64nvme: checksums.crc64nvme,
        checksum_sha1: checksums.sha1,
        checksum_sha256: checksums.sha256,
        checksum_type: checksums.checksum_type,
    })
    .map_err(S3Error::internal)?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    builder = add_checksum_headers(
        builder,
        result.checksum_algorithm,
        result.checksum_value.as_deref(),
        result.checksum_type,
    );
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    Ok(builder.body(Body::from(xml)).unwrap())
}

pub async fn abort_multipart_upload(
    State(state): State<AppState>,
    Path((bucket, _key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    state
        .storage
        .abort_multipart_upload(&bucket, upload_id)
        .await
        .map_err(map_storage_err)?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

pub async fn list_parts(
    State(state): State<AppState>,
    Path((bucket, _key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;
    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    let (upload, parts) = state
        .storage
        .list_parts(&bucket, upload_id)
        .await
        .map_err(map_storage_err)?;

    let checksum_algorithm = upload
        .checksum_algorithm
        .map(|algo| algo.as_str().to_string());
    let checksum_type = upload
        .resolved_checksum_type()
        .map(|ty| ty.header_value().to_string());
    let xml = to_xml(&ListPartsResult {
        bucket,
        key: upload.key,
        upload_id: upload_id.clone(),
        checksum_algorithm,
        checksum_type,
        is_truncated: false,
        parts: parts
            .into_iter()
            .map(|p| PartEntry {
                part_number: p.part_number,
                last_modified: p.last_modified,
                etag: p.etag,
                size: p.size,
            })
            .collect(),
    })
    .map_err(S3Error::internal)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

pub async fn list_multipart_uploads(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    require_bucket(&state, &bucket).await?;

    let uploads = state
        .storage
        .list_multipart_uploads(&bucket)
        .await
        .map_err(map_storage_err)?;

    let xml = to_xml(&ListMultipartUploadsResult {
        bucket,
        is_truncated: false,
        uploads: uploads
            .into_iter()
            .map(|u| MultipartUploadEntry {
                key: u.key,
                upload_id: u.upload_id,
                initiated: u.initiated,
            })
            .collect(),
    })
    .map_err(S3Error::internal)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

struct ChecksumXmlFields {
    crc32: Option<String>,
    crc32c: Option<String>,
    crc64nvme: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    checksum_type: Option<String>,
}

fn checksum_xml_fields(
    algorithm: Option<ChecksumAlgorithm>,
    value: Option<&str>,
    checksum_type: Option<ChecksumType>,
) -> ChecksumXmlFields {
    let mut fields = ChecksumXmlFields {
        crc32: None,
        crc32c: None,
        crc64nvme: None,
        sha1: None,
        sha256: None,
        checksum_type: None,
    };
    let (Some(algo), Some(value)) = (algorithm, value) else {
        return fields;
    };
    let value = value.to_string();
    match algo {
        ChecksumAlgorithm::CRC32 => fields.crc32 = Some(value),
        ChecksumAlgorithm::CRC32C => fields.crc32c = Some(value),
        ChecksumAlgorithm::CRC64NVME => fields.crc64nvme = Some(value),
        ChecksumAlgorithm::SHA1 => fields.sha1 = Some(value),
        ChecksumAlgorithm::SHA256 => fields.sha256 = Some(value),
    }
    fields.checksum_type = checksum_type.map(|ty| ty.header_value().to_string());
    fields
}

pub(super) fn map_storage_err(err: StorageError) -> S3Error {
    match err {
        StorageError::ChecksumMismatch(msg) if msg.starts_with("type:") => S3Error::new(
            crate::error::S3ErrorCode::BadDigest,
            "The checksum type you specified did not match the checksum type specified in CreateMultipartUpload.",
        ),
        StorageError::ChecksumMismatch(_) => S3Error::bad_checksum("x-amz-checksum"),
        StorageError::InvalidKey(msg) if msg.contains("checksum algorithm") => {
            S3Error::invalid_request(&msg)
        }
        StorageError::UploadNotFound(upload_id) => S3Error::no_such_upload(&upload_id),
        StorageError::InvalidPartOrder => S3Error::invalid_part_order(),
        StorageError::EntityTooLarge => S3Error::entity_too_large(),
        StorageError::InvalidKey(msg) if msg.contains("part too small") => {
            S3Error::entity_too_small()
        }
        StorageError::InvalidKey(msg) if msg.contains("collides with an internal storage name") => {
            S3Error::invalid_argument(&msg)
        }
        StorageError::InvalidKey(msg)
            if msg.contains("part")
                || msg.contains("etag")
                || msg.contains("upload")
                || msg.contains("at least one") =>
        {
            S3Error::invalid_part(&msg)
        }
        StorageError::InvalidKey(msg) if msg.starts_with("invalid bucket name") => {
            let name = msg
                .split_once(':')
                .map(|(_, name)| name.trim())
                .filter(|name| !name.is_empty())
                .unwrap_or(msg.as_str());
            S3Error::invalid_bucket_name(name)
        }
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        StorageError::EncryptionError(msg) => S3Error::invalid_argument(&msg),
        StorageError::DecryptionError(msg) => S3Error::invalid_argument(&msg),
        StorageError::IntegrityError(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

fn parse_complete_parts(xml: &str) -> Result<Vec<(u32, String)>, S3Error> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut parts = Vec::new();
    let mut in_part = false;
    let mut in_part_number = false;
    let mut in_etag = false;
    let mut part_number: Option<u32> = None;
    let mut etag: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) => match e.name().as_ref() {
                b"Part" => {
                    in_part = true;
                    part_number = None;
                    etag = None;
                }
                b"PartNumber" if in_part => in_part_number = true,
                b"ETag" if in_part => in_etag = true,
                _ => {}
            },
            Ok(quick_xml::events::Event::Text(e)) => {
                if in_part_number {
                    let value = e
                        .unescape()
                        .map_err(|_| S3Error::malformed_xml())?
                        .into_owned();
                    part_number = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| S3Error::invalid_part("invalid part number"))?,
                    );
                    in_part_number = false;
                } else if in_etag {
                    let value = e
                        .unescape()
                        .map_err(|_| S3Error::malformed_xml())?
                        .into_owned();
                    let normalized = if value.starts_with('"') && value.ends_with('"') {
                        value
                    } else {
                        format!("\"{}\"", value)
                    };
                    etag = Some(normalized);
                    in_etag = false;
                }
            }
            Ok(quick_xml::events::Event::End(e)) => match e.name().as_ref() {
                b"PartNumber" => in_part_number = false,
                b"ETag" => in_etag = false,
                b"Part" => {
                    let n = part_number.ok_or_else(S3Error::malformed_xml)?;
                    let tag = etag.clone().ok_or_else(S3Error::malformed_xml)?;
                    parts.push((n, tag));
                    in_part = false;
                }
                _ => {}
            },
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
    }

    Ok(parts)
}
