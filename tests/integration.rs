use maxio::config::Config;
use maxio::server::{self, AppState};
use maxio::storage::filesystem::FilesystemStorage;
use std::sync::Arc;
use tempfile::TempDir;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const ACCESS_KEY: &str = "minioadmin";
const SECRET_KEY: &str = "minioadmin";
const REGION: &str = "us-east-1";

/// Spin up a test server on a random port, return the base URL.
async fn start_server() -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let storage = FilesystemStorage::new(&data_dir).await.unwrap();

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, tmp)
}

/// Sign a request with AWS Signature V4.
fn sign_request(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = hex::encode(Sha256::digest(body));

    headers.push(("host".to_string(), host_header.clone()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));

    // Sort signed headers
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    // Normalize query string: sort params and ensure key=value format
    let canonical_qs = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("").to_string();
                let val = parts.next().unwrap_or("").to_string();
                (key, val)
            })
            .collect();
        pairs.sort();
        pairs.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&")
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_qs, canonical_headers, signed_headers_str, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    // Derive signing key
    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );
    headers.push(("authorization".to_string(), auth));
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Sign a request using comma-only separators (no spaces), like mc does.
fn sign_request_compact(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    // Reuse the same signing logic but produce compact auth header
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = hex::encode(Sha256::digest(body));

    headers.push(("host".to_string(), host_header.clone()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));

    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_qs = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("").to_string();
                let val = parts.next().unwrap_or("").to_string();
                (key, val)
            })
            .collect();
        pairs.sort();
        pairs.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&")
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_qs, canonical_headers, signed_headers_str, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // Compact format: no spaces after commas (like mc sends)
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );
    headers.push(("authorization".to_string(), auth));
}

/// Build a signed request and send it.
async fn s3_request(
    method: &str,
    url: &str,
    body: Vec<u8>,
) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Sign and send a request with extra headers (e.g. x-amz-copy-source).
async fn s3_request_with_headers(
    method: &str,
    url: &str,
    body: Vec<u8>,
    extra_headers: Vec<(&str, &str)>,
) -> reqwest::Response {
    let mut headers: Vec<(String, String)> = extra_headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Build a signed request with compact auth header (no spaces after commas).
async fn s3_request_compact(
    method: &str,
    url: &str,
    body: Vec<u8>,
) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request_compact(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Build a PUT request with STREAMING-AWS4-HMAC-SHA256-PAYLOAD (AWS chunked encoding).
async fn s3_put_chunked(
    url: &str,
    data: &[u8],
) -> reqwest::Response {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    // For streaming, the payload hash is the literal string
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let mut sign_headers = vec![
        ("host".to_string(), host_header.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
        ("x-amz-decoded-content-length".to_string(), data.len().to_string()),
    ];
    sign_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = sign_headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = sign_headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        "PUT", path, query, canonical_headers, signed_headers_str, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let seed_signature = hex::encode(mac.finalize().into_bytes());

    // Compact auth header (no spaces)
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, seed_signature
    );

    // Build AWS chunked body: "<hex_size>;chunk-signature=<sig>\r\n<data>\r\n0;chunk-signature=<sig>\r\n"
    // For simplicity, compute chunk signatures with a dummy (real mc would chain them)
    let chunk_sig = "0".repeat(64); // placeholder — server doesn't verify chunk sigs
    let mut chunked_body = Vec::new();
    chunked_body.extend_from_slice(
        format!("{:x};chunk-signature={}\r\n", data.len(), chunk_sig).as_bytes(),
    );
    chunked_body.extend_from_slice(data);
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(
        format!("0;chunk-signature={}\r\n", chunk_sig).as_bytes(),
    );

    client()
        .put(url)
        .header("host", &host_header)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", data.len().to_string())
        .header("authorization", &auth)
        .header("content-type", "application/octet-stream")
        .body(chunked_body)
        .send()
        .await
        .unwrap()
}

fn extract_xml_tag(body: &str, tag: &str) -> Option<String> {
    let start = format!("<{}>", tag);
    let end = format!("</{}>", tag);
    let from = body.find(&start)? + start.len();
    let to = body[from..].find(&end)? + from;
    Some(body[from..to].to_string())
}


// ---- Tests ----

#[tokio::test]
async fn test_auth_rejects_bad_key() {
    let (base_url, _tmp) = start_server().await;

    // Request with no auth header
    let resp = client().get(&base_url).send().await.unwrap();
    assert_eq!(resp.status(), 403);

    // Request with garbage auth
    let resp = client()
        .get(&base_url)
        .header("authorization", "garbage")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_auth_accepts_valid_signature() {
    let (base_url, _tmp) = start_server().await;
    let resp = s3_request("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_create_bucket() {
    let (base_url, _tmp) = start_server().await;

    // Create bucket
    let resp = s3_request("PUT", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Head bucket should succeed
    let resp = s3_request("HEAD", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_create_bucket_duplicate() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request("PUT", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Creating same bucket again should fail
    let resp = s3_request("PUT", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn test_head_bucket_not_found() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request("HEAD", &format!("{}/nonexistent", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_list_buckets() {
    let (base_url, _tmp) = start_server().await;

    // Create two buckets
    s3_request("PUT", &format!("{}/alpha", base_url), vec![]).await;
    s3_request("PUT", &format!("{}/beta", base_url), vec![]).await;

    // List
    let resp = s3_request("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Name>alpha</Name>"));
    assert!(body.contains("<Name>beta</Name>"));
}

#[tokio::test]
async fn test_delete_bucket() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/to-delete", base_url), vec![]).await;

    let resp = s3_request("DELETE", &format!("{}/to-delete", base_url), vec![]).await;
    assert_eq!(resp.status(), 204);

    // Should be gone
    let resp = s3_request("HEAD", &format!("{}/to-delete", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_put_and_get_object() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let data = b"hello maxio".to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/mybucket/test.txt", base_url),
        data.clone(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("etag"));

    // Get it back
    let resp = s3_request("GET", &format!("{}/mybucket/test.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), b"hello maxio");
}

#[tokio::test]
async fn test_head_object() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"data".to_vec(),
    )
    .await;

    let resp = s3_request("HEAD", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-length").unwrap(), "4");
}

#[tokio::test]
async fn test_delete_object() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"data".to_vec(),
    )
    .await;

    let resp = s3_request("DELETE", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 204);

    // Should be gone
    let resp = s3_request("GET", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_list_objects() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/a.txt", base_url),
        b"aaa".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/b.txt", base_url),
        b"bbb".to_vec(),
    )
    .await;

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));
    assert!(body.contains("<KeyCount>2</KeyCount>"));
}

// ---- New tests for findings ----

#[tokio::test]
async fn test_auth_compact_header_no_spaces() {
    // mc sends Authorization header with commas but no spaces:
    // Credential=...,SignedHeaders=...,Signature=...
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request_compact("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Also test PUT bucket with compact header
    let resp = s3_request_compact("PUT", &format!("{}/compact-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_last_modified_http_date_format() {
    // Last-Modified header must be RFC 7231 format: "Tue, 17 Feb 2026 22:17:45 GMT"
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"data".to_vec(),
    )
    .await;

    // HEAD should return RFC 7231 Last-Modified
    let resp = s3_request("HEAD", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let last_modified = resp.headers().get("last-modified").unwrap().to_str().unwrap();
    // Should match pattern like "Mon, 17 Feb 2026 22:17:45 GMT"
    assert!(last_modified.ends_with(" GMT"), "Last-Modified should end with GMT: {}", last_modified);
    assert!(last_modified.contains(", "), "Last-Modified should contain comma-space: {}", last_modified);
    // Must NOT be ISO 8601 (no "T" between date and time digits)
    assert!(!last_modified.contains("T0"), "Last-Modified must not be ISO 8601: {}", last_modified);
    assert!(!last_modified.contains("T1"), "Last-Modified must not be ISO 8601: {}", last_modified);
    assert!(!last_modified.contains("T2"), "Last-Modified must not be ISO 8601: {}", last_modified);

    // GET should also return RFC 7231 Last-Modified
    let resp = s3_request("GET", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    let last_modified = resp.headers().get("last-modified").unwrap().to_str().unwrap();
    assert!(last_modified.ends_with(" GMT"));
    // Verify it parses as HTTP date (day-of-week, DD Mon YYYY HH:MM:SS GMT)
    assert!(last_modified.len() > 25, "Last-Modified should be full HTTP date: {}", last_modified);
}

#[tokio::test]
async fn test_put_object_aws_chunked_encoding() {
    // mc sends uploads with x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
    // and the body is in AWS chunked format
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let data = b"hello chunked world";
    let resp = s3_put_chunked(
        &format!("{}/mybucket/chunked.txt", base_url),
        data,
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("etag"));

    // Verify the stored content is decoded (no chunk framing)
    let resp = s3_request("GET", &format!("{}/mybucket/chunked.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), data, "Chunked upload content should be decoded");
}

#[tokio::test]
async fn test_put_object_response_headers() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // PUT should return ETag
    let resp = s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"test data".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let etag = resp.headers().get("etag").unwrap().to_str().unwrap();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "ETag should be quoted: {}", etag);

    // HEAD should return Content-Type, Content-Length, ETag, Last-Modified
    let resp = s3_request("HEAD", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert!(resp.headers().contains_key("content-type"));
    assert!(resp.headers().contains_key("content-length"));
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
    assert_eq!(resp.headers().get("content-length").unwrap(), "9");

    // GET should also have these headers
    let resp = s3_request("GET", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert!(resp.headers().contains_key("content-type"));
    assert!(resp.headers().contains_key("content-length"));
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
}

#[tokio::test]
async fn test_delete_objects_batch() {
    // mc uses POST /{bucket}?delete to delete objects (DeleteObjects API)
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request("PUT", &format!("{}/mybucket/a.txt", base_url), b"aaa".to_vec()).await;
    s3_request("PUT", &format!("{}/mybucket/b.txt", base_url), b"bbb".to_vec()).await;
    s3_request("PUT", &format!("{}/mybucket/c.txt", base_url), b"ccc".to_vec()).await;

    // Batch delete a.txt and b.txt
    let delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>a.txt</Key></Object>
  <Object><Key>b.txt</Key></Object>
</Delete>"#;

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Deleted>"), "Response should contain Deleted elements");
    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));

    // Verify a.txt and b.txt are gone
    let resp = s3_request("GET", &format!("{}/mybucket/a.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
    let resp = s3_request("GET", &format!("{}/mybucket/b.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);

    // c.txt should still exist
    let resp = s3_request("GET", &format!("{}/mybucket/c.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_trailing_slash_bucket_routes() {
    // mc sends PUT /bucket/ (with trailing slash)
    let (base_url, _tmp) = start_server().await;

    // Create with trailing slash
    let resp = s3_request("PUT", &format!("{}/mybucket/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // HEAD with trailing slash
    let resp = s3_request("HEAD", &format!("{}/mybucket/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // GET (list) with trailing slash
    let resp = s3_request("GET", &format!("{}/mybucket/?list-type=2", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // DELETE with trailing slash
    let resp = s3_request("DELETE", &format!("{}/mybucket/", base_url), vec![]).await;
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_chunked_upload_interrupted_then_retry() {
    // Simulate: send a truncated/incomplete chunked upload, then retry with a valid one.
    // The server should not leave corrupt data from the partial upload, and the retry
    // should succeed with correct content.
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let url = format!("{}/mybucket/interrupted.txt", base_url);

    // Build a truncated chunked body: valid first chunk header but missing data/terminator.
    // This simulates a client that starts uploading and then drops the connection.
    let parsed = reqwest::Url::parse(&url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let mut sign_headers = vec![
        ("host".to_string(), host_header.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
        ("x-amz-decoded-content-length".to_string(), "1000".to_string()),
    ];
    sign_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = sign_headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");
    let canonical_headers: String = sign_headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        "PUT", path, "", canonical_headers, signed_headers_str, payload_hash
    );
    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );

    // Send a truncated chunked body: claims 1000 bytes but only sends a partial chunk
    let chunk_sig = "0".repeat(64);
    let truncated_body = format!("3e8;chunk-signature={}\r\npartial data only", chunk_sig);

    // This request should fail (connection reset / error) since we promised 1000 bytes
    // but sent far fewer. We don't care about the exact error, just that it doesn't
    // leave the server in a broken state.
    let _ = client()
        .put(&url)
        .header("host", &host_header)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", "1000")
        .header("authorization", &auth)
        .header("content-type", "application/octet-stream")
        .body(truncated_body.into_bytes())
        .send()
        .await;

    // Small delay to let server finish processing
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Now do a proper chunked upload to the same key — this MUST succeed
    let good_data = b"hello after interrupted upload";
    let resp = s3_put_chunked(&url, good_data).await;
    assert_eq!(resp.status(), 200, "Retry upload after interrupted should succeed");

    // Verify content is from the successful retry, not the partial upload
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        good_data,
        "Content should be from the retry, not the interrupted upload"
    );
}

#[tokio::test]
async fn test_chunked_upload_multi_chunk() {
    // Test chunked upload with multiple chunks (not just one chunk + terminator)
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let url = format!("{}/mybucket/multichunk.txt", base_url);
    let parsed = reqwest::Url::parse(&url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();

    let chunk1 = b"first chunk data ";
    let chunk2 = b"second chunk data ";
    let chunk3 = b"third chunk data";
    let total_len = chunk1.len() + chunk2.len() + chunk3.len();

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let mut sign_headers = vec![
        ("host".to_string(), host_header.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
        ("x-amz-decoded-content-length".to_string(), total_len.to_string()),
    ];
    sign_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = sign_headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");
    let canonical_headers: String = sign_headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        "PUT", path, "", canonical_headers, signed_headers_str, payload_hash
    );
    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );

    // Build multi-chunk body
    let chunk_sig = "0".repeat(64);
    let mut chunked_body = Vec::new();
    for chunk_data in [&chunk1[..], &chunk2[..], &chunk3[..]] {
        chunked_body.extend_from_slice(
            format!("{:x};chunk-signature={}\r\n", chunk_data.len(), chunk_sig).as_bytes(),
        );
        chunked_body.extend_from_slice(chunk_data);
        chunked_body.extend_from_slice(b"\r\n");
    }
    // Terminating chunk
    chunked_body.extend_from_slice(
        format!("0;chunk-signature={}\r\n", chunk_sig).as_bytes(),
    );

    let resp = client()
        .put(&url)
        .header("host", &host_header)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", total_len.to_string())
        .header("authorization", &auth)
        .header("content-type", "application/octet-stream")
        .body(chunked_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Verify all chunks were concatenated correctly
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let expected = b"first chunk data second chunk data third chunk data";
    assert_eq!(body.as_ref(), expected, "Multi-chunk content should be concatenated");

    // Verify content-length matches
    let resp = s3_request("HEAD", &url, vec![]).await;
    assert_eq!(
        resp.headers().get("content-length").unwrap(),
        &total_len.to_string()
    );
}

#[tokio::test]
async fn test_multipart_create_upload() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request("POST", &format!("{}/mybucket/large.bin?uploads=", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_tag(&body, "UploadId").unwrap();
    assert!(!upload_id.is_empty());
}

#[tokio::test]
async fn test_multipart_upload_part() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/large.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let resp = s3_request(
        "PUT",
        &format!("{}/mybucket/large.bin?partNumber=1&uploadId={}", base_url, upload_id),
        b"part-one".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let etag = resp.headers().get("etag").unwrap().to_str().unwrap();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
}

#[tokio::test]
async fn test_multipart_complete() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/large.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = b"tail".to_vec();
    let r1 = s3_request(
        "PUT",
        &format!("{}/mybucket/large.bin?partNumber=1&uploadId={}", base_url, upload_id),
        p1.clone(),
    )
    .await;
    let e1 = r1.headers().get("etag").unwrap().to_str().unwrap().to_string();
    let r2 = s3_request(
        "PUT",
        &format!("{}/mybucket/large.bin?partNumber=2&uploadId={}", base_url, upload_id),
        p2.clone(),
    )
    .await;
    let e2 = r2.headers().get("etag").unwrap().to_str().unwrap().to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    let get = s3_request("GET", &format!("{}/mybucket/large.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    let mut expected = p1;
    expected.extend_from_slice(&p2);
    assert_eq!(body.as_ref(), expected.as_slice());
}

#[tokio::test]
async fn test_multipart_complete_part_too_small() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/large.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let r1 = s3_request(
        "PUT",
        &format!("{}/mybucket/large.bin?partNumber=1&uploadId={}", base_url, upload_id),
        b"tiny".to_vec(),
    )
    .await;
    let e1 = r1.headers().get("etag").unwrap().to_str().unwrap().to_string();
    let r2 = s3_request(
        "PUT",
        &format!("{}/mybucket/large.bin?partNumber=2&uploadId={}", base_url, upload_id),
        b"tail".to_vec(),
    )
    .await;
    let e2 = r2.headers().get("etag").unwrap().to_str().unwrap().to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 400);
    let body = complete.text().await.unwrap();
    assert!(body.contains("<Code>EntityTooSmall</Code>"));
}

#[tokio::test]
async fn test_multipart_abort() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/large.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let abort = s3_request(
        "DELETE",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        vec![],
    )
    .await;
    assert_eq!(abort.status(), 204);
}

#[tokio::test]
async fn test_multipart_list_parts() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/large.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    s3_request(
        "PUT",
        &format!("{}/mybucket/large.bin?partNumber=1&uploadId={}", base_url, upload_id),
        b"part-one".to_vec(),
    )
    .await;

    let list = s3_request(
        "GET",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        vec![],
    )
    .await;
    assert_eq!(list.status(), 200);
    let body = list.text().await.unwrap();
    assert!(body.contains("<PartNumber>1</PartNumber>"));
}

#[tokio::test]
async fn test_multipart_list_uploads() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/large.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let list = s3_request("GET", &format!("{}/mybucket?uploads=", base_url), vec![]).await;
    assert_eq!(list.status(), 200);
    let body = list.text().await.unwrap();
    assert!(body.contains(&upload_id));
    assert!(body.contains("<Key>large.bin</Key>"));
}

#[tokio::test]
async fn test_multipart_no_such_upload() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket/missing.bin?uploadId=does-not-exist", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchUpload</Code>"));
}

#[tokio::test]
async fn test_multipart_excluded_from_list_objects() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/in-progress.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();
    s3_request(
        "PUT",
        &format!(
            "{}/mybucket/in-progress.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        b"partial".to_vec(),
    )
    .await;

    let list = s3_request("GET", &format!("{}/mybucket?list-type=2", base_url), vec![]).await;
    assert_eq!(list.status(), 200);
    let body = list.text().await.unwrap();
    assert!(!body.contains("in-progress.bin"));
}

#[tokio::test]
async fn test_multipart_etag_format() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request("POST", &format!("{}/mybucket/etag.bin?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = b"tail".to_vec();
    let r1 = s3_request(
        "PUT",
        &format!("{}/mybucket/etag.bin?partNumber=1&uploadId={}", base_url, upload_id),
        p1,
    )
    .await;
    let e1 = r1.headers().get("etag").unwrap().to_str().unwrap().to_string();
    let r2 = s3_request(
        "PUT",
        &format!("{}/mybucket/etag.bin?partNumber=2&uploadId={}", base_url, upload_id),
        p2,
    )
    .await;
    let e2 = r2.headers().get("etag").unwrap().to_str().unwrap().to_string();
    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/etag.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    let body = complete.text().await.unwrap();
    let etag = extract_xml_tag(&body, "ETag").unwrap();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    assert!(etag.contains("-2"));
}

#[tokio::test]
async fn test_copy_object_basic() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Upload source object
    s3_request("PUT", &format!("{}/mybucket/src.txt", base_url), b"copy me".to_vec()).await;

    // Copy to new key in same bucket
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/mybucket/src.txt")],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<CopyObjectResult>"));
    assert!(body.contains("<ETag>"));
    assert!(body.contains("<LastModified>"));

    // Verify destination content matches source
    let resp = s3_request("GET", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let content = resp.bytes().await.unwrap();
    assert_eq!(content.as_ref(), b"copy me");
}

#[tokio::test]
async fn test_copy_object_cross_bucket() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/src-bucket", base_url), vec![]).await;
    s3_request("PUT", &format!("{}/dst-bucket", base_url), vec![]).await;

    s3_request("PUT", &format!("{}/src-bucket/file.txt", base_url), b"cross bucket".to_vec()).await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/dst-bucket/file.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/src-bucket/file.txt")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request("GET", &format!("{}/dst-bucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"cross bucket");
}

#[tokio::test]
async fn test_copy_object_metadata_copy() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Upload with specific content-type
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"hello".to_vec(),
        vec![("content-type", "text/plain")],
    )
    .await;

    // Copy with default COPY directive
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/mybucket/src.txt")],
    )
    .await;

    // HEAD destination — content-type should be preserved
    let resp = s3_request("HEAD", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(
        resp.headers().get("content-type").unwrap().to_str().unwrap(),
        "text/plain"
    );
}

#[tokio::test]
async fn test_copy_object_metadata_replace() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"hello".to_vec(),
        vec![("content-type", "text/plain")],
    )
    .await;

    // Copy with REPLACE directive and new content-type
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/mybucket/src.txt"),
            ("x-amz-metadata-directive", "REPLACE"),
            ("content-type", "application/json"),
        ],
    )
    .await;

    let resp = s3_request("HEAD", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(
        resp.headers().get("content-type").unwrap().to_str().unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn test_copy_object_source_not_found() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/mybucket/nonexistent.txt")],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchKey</Code>"));
}

#[tokio::test]
async fn test_copy_object_no_leading_slash() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request("PUT", &format!("{}/mybucket/src.txt", base_url), b"no slash".to_vec()).await;

    // Copy source without leading slash
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "mybucket/src.txt")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request("GET", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"no slash");
}

/// Generate a presigned URL for the given method/path.
fn presign_url(base_url: &str, method: &str, path: &str, expires_secs: u64) -> String {
    let parsed = reqwest::Url::parse(&format!("{}{}", base_url, path)).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{}/{}/{}/s3/aws4_request", ACCESS_KEY, date_stamp, REGION);

    let mut qs_params = vec![
        ("X-Amz-Algorithm".to_string(), "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential".to_string(), credential.clone()),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    qs_params.sort();

    let canonical_qs: String = qs_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode_s3(k), percent_encode_s3(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = format!("host:{}\n", host_header);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\nhost\nUNSIGNED-PAYLOAD",
        method, path, canonical_qs, canonical_headers
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    format!("{}{}?{}&X-Amz-Signature={}", base_url, path, canonical_qs, signature)
}

fn percent_encode_s3(input: &str) -> String {
    const S3_URI_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(input, S3_URI_ENCODE).to_string()
}

#[tokio::test]
async fn test_presigned_get_object() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let body = b"presigned test content";
    let url = format!("{}/presign-bucket/test.txt", base_url);
    s3_request("PUT", &url, body.to_vec()).await;

    let presigned = presign_url(&base_url, "GET", "/presign-bucket/test.txt", 300);
    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
}

#[tokio::test]
async fn test_presigned_put_object() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-put-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let presigned = presign_url(&base_url, "PUT", "/presign-put-bucket/uploaded.txt", 300);
    let body = b"uploaded via presigned PUT";
    let resp = client().put(&presigned).body(body.to_vec()).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let url = format!("{}/presign-put-bucket/uploaded.txt", base_url);
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
}

#[tokio::test]
async fn test_presigned_head_object() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-head-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let url = format!("{}/presign-head-bucket/test.txt", base_url);
    s3_request("PUT", &url, b"head test".to_vec()).await;

    let presigned = presign_url(&base_url, "HEAD", "/presign-head-bucket/test.txt", 300);
    let resp = client().head(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-length").unwrap().to_str().unwrap(), "9");
}

#[tokio::test]
async fn test_presigned_expired_url() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-expire-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;
    let url = format!("{}/presign-expire-bucket/test.txt", base_url);
    s3_request("PUT", &url, b"data".to_vec()).await;

    // Manually craft a presigned URL with a timestamp from 2 hours ago
    let parsed = reqwest::Url::parse(&format!("{}/presign-expire-bucket/test.txt", base_url)).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);

    let past = chrono::Utc::now() - chrono::Duration::hours(2);
    let date_stamp = past.format("%Y%m%d").to_string();
    let amz_date = past.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{}/{}/{}/s3/aws4_request", ACCESS_KEY, date_stamp, REGION);

    let mut qs_params = vec![
        ("X-Amz-Algorithm".to_string(), "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential".to_string(), credential.clone()),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), "60".to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    qs_params.sort();
    let canonical_qs: String = qs_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode_s3(k), percent_encode_s3(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "GET\n/presign-expire-bucket/test.txt\n{}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
        canonical_qs, host_header
    );
    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let presigned = format!(
        "{}/presign-expire-bucket/test.txt?{}&X-Amz-Signature={}",
        base_url, canonical_qs, signature
    );

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Request has expired"));
}

#[tokio::test]
async fn test_presigned_bad_signature() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-bad-sig-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let mut presigned = presign_url(&base_url, "GET", "/presign-bad-sig-bucket/test.txt", 300);
    let last = presigned.pop().unwrap();
    presigned.push(if last == 'a' { 'b' } else { 'a' });

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
}

// ── Range request tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_get_object_range_first_bytes() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=0-499")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "500");
    assert_eq!(resp.headers()["content-range"], "bytes 0-499/1000");
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[0..500]);
}

#[tokio::test]
async fn test_get_object_range_middle_bytes() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-mid-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-mid-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-mid-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=10-19")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "10");
    assert_eq!(resp.headers()["content-range"], "bytes 10-19/100");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[10..20]);
}

#[tokio::test]
async fn test_get_object_range_suffix() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-sfx-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0u16..1000).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-sfx-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-sfx-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=-100")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "100");
    assert_eq!(resp.headers()["content-range"], "bytes 900-999/1000");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[900..1000]);
}

#[tokio::test]
async fn test_get_object_range_open_end() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-open-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0u16..1000).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-open-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-open-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=500-")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "500");
    assert_eq!(resp.headers()["content-range"], "bytes 500-999/1000");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[500..1000]);
}

#[tokio::test]
async fn test_get_object_range_clamp_beyond_end() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-clamp-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-clamp-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-clamp-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=0-9999")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "100");
    assert_eq!(resp.headers()["content-range"], "bytes 0-99/100");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[..]);
}

#[tokio::test]
async fn test_get_object_range_invalid_416() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-416-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-416-bucket/file.bin", base_url),
        content,
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-416-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=5000-6000")],
    )
    .await;

    assert_eq!(resp.status(), 416);
}

#[tokio::test]
async fn test_get_object_no_range_has_accept_ranges() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-ar-bucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/range-ar-bucket/file.txt", base_url),
        b"hello".to_vec(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-ar-bucket/file.txt", base_url),
        vec![],
        vec![],
    )
    .await;

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
}

#[tokio::test]
async fn test_get_object_range_preserves_headers() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-hdr-bucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/range-hdr-bucket/file.txt", base_url),
        b"hello world".to_vec(),
        vec![("content-type", "text/plain")],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-hdr-bucket/file.txt", base_url),
        vec![],
        vec![("range", "bytes=0-4")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
    assert!(resp.headers().contains_key("content-type"));
}

#[tokio::test]
async fn test_head_object_accept_ranges() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-head-bucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/range-head-bucket/file.txt", base_url),
        b"hello".to_vec(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "HEAD",
        &format!("{}/range-head-bucket/file.txt", base_url),
        vec![],
        vec![],
    )
    .await;

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
}

#[tokio::test]
async fn test_put_folder_marker() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Create folder marker via PutObject with trailing slash
    let resp = s3_request("PUT", &format!("{}/mybucket/photos/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Folder should appear in ListObjectsV2 as a CommonPrefix
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2&delimiter=%2F", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Prefix>photos/</Prefix>"), "body: {}", body);

    // HeadObject on the folder marker should return 200
    let resp = s3_request("HEAD", &format!("{}/mybucket/photos/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_folder_marker_with_children() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Create folder marker
    s3_request("PUT", &format!("{}/mybucket/docs/", base_url), vec![]).await;

    // Upload object inside it
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/docs/readme.txt", base_url),
        b"hello".to_vec(),
        vec![],
    )
    .await;

    // List at root — should see "docs/" as CommonPrefix
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2&delimiter=%2F", base_url),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Prefix>docs/</Prefix>"), "body: {}", body);
    assert!(!body.contains("readme.txt"), "readme.txt should not appear at root");

    // List inside docs/ — should see readme.txt
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2&prefix=docs%2F&delimiter=%2F", base_url),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>docs/readme.txt</Key>"), "body: {}", body);

    // Delete folder marker — the child object should still exist
    s3_request("DELETE", &format!("{}/mybucket/docs/", base_url), vec![]).await;
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket/docs/readme.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_delete_folder_marker() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Create and then delete folder marker
    s3_request("PUT", &format!("{}/mybucket/empty-dir/", base_url), vec![]).await;
    s3_request("DELETE", &format!("{}/mybucket/empty-dir/", base_url), vec![]).await;

    // HeadObject should now return 404
    let resp = s3_request("HEAD", &format!("{}/mybucket/empty-dir/", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}
