use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use futures::TryStreamExt;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio_util::io::ReaderStream;

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::StorageError;

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if !state.storage.head_bucket(&bucket).await {
        return Err(S3Error::no_such_bucket(&bucket));
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let is_aws_chunked = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        == Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD");

    let stream = body.into_data_stream();
    let raw_reader = tokio_util::io::StreamReader::new(
        stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );

    let reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> = if is_aws_chunked {
        // Decode AWS chunked encoding: each chunk is "hex_size;chunk-signature=...\r\nDATA\r\n"
        let mut buf_reader = tokio::io::BufReader::new(raw_reader);
        let mut decoded = Vec::new();
        loop {
            let mut line = String::new();
            let n = buf_reader.read_line(&mut line).await.map_err(|e| S3Error::internal(e))?;
            if n == 0 {
                break;
            }
            let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
            let size_str = line.split(';').next().unwrap_or("0");
            let chunk_size =
                usize::from_str_radix(size_str.trim(), 16).map_err(|_| S3Error::internal("invalid chunk size"))?;
            if chunk_size == 0 {
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            buf_reader.read_exact(&mut chunk).await.map_err(|e| S3Error::internal(e))?;
            decoded.extend_from_slice(&chunk);
            // Consume trailing \r\n
            let mut crlf = [0u8; 2];
            let _ = buf_reader.read_exact(&mut crlf).await;
        }
        Box::pin(std::io::Cursor::new(decoded))
    } else {
        Box::pin(raw_reader)
    };

    let result = state
        .storage
        .put_object(&bucket, &key, content_type, reader)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &result.etag)
        .body(Body::empty())
        .unwrap())
}

/// Convert ISO 8601 timestamp to HTTP date (RFC 7231) for Last-Modified header.
fn to_http_date(iso: &str) -> String {
    chrono::DateTime::parse_from_str(iso, "%Y-%m-%dT%H:%M:%S%.3fZ")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(iso))
        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|_| iso.to_string())
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response<Body>, S3Error> {
    let (reader, meta) = state
        .storage
        .get_object(&bucket, &key)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_key(&key),
            _ => S3Error::internal(e),
        })?;

    let stream = ReaderStream::new(reader);
    let body = Body::from_stream(stream);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified))
        .body(body)
        .unwrap())
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response<Body>, S3Error> {
    let meta = state
        .storage
        .head_object(&bucket, &key)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_key(&key),
            _ => S3Error::internal(e),
        })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified))
        .body(Body::empty())
        .unwrap())
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response<Body>, S3Error> {
    let _ = state.storage.delete_object(&bucket, &key).await;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

/// Handle POST /{bucket}?delete — multi-object delete (DeleteObjects API).
pub async fn delete_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    // Parse the XML body to get the list of keys to delete
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .map_err(|e| S3Error::internal(e))?;
    let body_str = String::from_utf8_lossy(&bytes);

    // Simple XML parsing: extract all <Key>...</Key> values
    let mut keys = Vec::new();
    for segment in body_str.split("<Key>").skip(1) {
        if let Some(key) = segment.split("</Key>").next() {
            keys.push(key.to_string());
        }
    }

    // Delete objects concurrently
    let mut set = tokio::task::JoinSet::new();
    for key in keys.clone() {
        let storage = state.storage.clone();
        let bucket = bucket.clone();
        set.spawn(async move {
            let _ = storage.delete_object(&bucket, &key).await;
            key
        });
    }

    let mut deleted_xml = String::new();
    while let Some(result) = set.join_next().await {
        if let Ok(key) = result {
            deleted_xml.push_str(&format!(
                "<Deleted><Key>{}</Key></Deleted>",
                quick_xml::escape::escape(&key)
            ));
        }
    }

    let response_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}</DeleteResult>",
        deleted_xml
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(response_xml))
        .unwrap())
}
