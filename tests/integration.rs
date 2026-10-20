#![allow(
    clippy::needless_borrows_for_generic_args,
    clippy::useless_vec,
    clippy::needless_range_loop,
    clippy::manual_repeat_n
)]

use maxio::config::Config;
use maxio::server::{self, AppState};
use maxio::storage::filesystem::FilesystemStorage;
use maxio::storage::keys::Keyring;
use std::sync::Arc;
use tempfile::TempDir;

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const ACCESS_KEY: &str = "maxioadmin";
const SECRET_KEY: &str = "maxioadmin";
const REGION: &str = "us-east-1";

/// Spin up a test server on a random port, return the base URL.
async fn start_server() -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
        master_key: None,
        master_key_file: None,
        allow_missing_master_key: false,
        allow_insecure_dev: true,
        secure_cookies: false,
        erasure_coding: false,
        chunk_size: 10 * 1024 * 1024,
        parity_shards: 0,
        default_buckets: String::new(),
        max_console_body_bytes: 1024 * 1024,
        ..Config::default()
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

/// Server with explicit console credentials and cookie settings.
/// `secure_cookies` is the production default (`true`); `allow_insecure_dev` is off.
async fn start_server_with_keys(
    access_key: &str,
    secret_key: &str,
    secure_cookies: bool,
    allow_insecure_dev: bool,
) -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
        region: REGION.to_string(),
        master_key: None,
        master_key_file: None,
        allow_missing_master_key: false,
        allow_insecure_dev,
        secure_cookies,
        erasure_coding: false,
        chunk_size: 10 * 1024 * 1024,
        parity_shards: 0,
        default_buckets: String::new(),
        max_console_body_bytes: 1024 * 1024,
        ..Config::default()
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

/// Server with explicit single-PUT and multipart-part caps. Storage and the
/// HTTP check must agree, matching `main`.
async fn start_server_with_size_limits(max_object: u64, max_part: u64) -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let mut storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();
    storage.set_upload_limits(max_object, max_part, u64::MAX);

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
        master_key: None,
        allow_insecure_dev: true,
        secure_cookies: false,
        erasure_coding: false,
        chunk_size: 10 * 1024 * 1024,
        parity_shards: 0,
        default_buckets: String::new(),
        max_console_body_bytes: 1024 * 1024,
        max_object_size: max_object,
        max_part_size: max_part,
        ..Config::default()
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

/// Sign a request with AWS Signature V4.
fn sign_request(method: &str, url: &str, headers: &mut Vec<(String, String)>, body: &[u8]) {
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
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
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

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );
    headers.push(("authorization".to_string(), auth));
}

// ---- Default buckets tests ----

async fn start_server_with_default_buckets(default_buckets: &str) -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();

    maxio::storage::provision_default_buckets(&storage, default_buckets, REGION).await;

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir: data_dir.clone(),
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
        master_key: None,
        master_key_file: None,
        allow_missing_master_key: false,
        allow_insecure_dev: true,
        secure_cookies: false,
        erasure_coding: false,
        chunk_size: 10 * 1024 * 1024,
        parity_shards: 0,
        default_buckets: default_buckets.to_string(),
        max_console_body_bytes: 1024 * 1024,
        ..Config::default()
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

#[tokio::test]
async fn test_default_buckets_created_on_boot() {
    let (base_url, _tmp) = start_server_with_default_buckets("alpha,beta,gamma").await;

    // All buckets should exist
    let resp = s3_request("HEAD", &format!("{}/alpha", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let resp = s3_request("HEAD", &format!("{}/beta", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let resp = s3_request("HEAD", &format!("{}/gamma", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // List should include default buckets
    let resp = s3_request("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Name>alpha</Name>"));
    assert!(body.contains("<Name>beta</Name>"));
    assert!(body.contains("<Name>gamma</Name>"));
}

#[tokio::test]
async fn test_default_buckets_skip_existing() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();

    // First provision: creates the bucket
    maxio::storage::provision_default_buckets(&storage, "existing", REGION).await;
    // Second provision: must be idempotent — no error, no duplicate
    maxio::storage::provision_default_buckets(&storage, "existing", REGION).await;

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir: data_dir.clone(),
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
        master_key: None,
        master_key_file: None,
        allow_missing_master_key: false,
        allow_insecure_dev: true,
        secure_cookies: false,
        erasure_coding: false,
        chunk_size: 10 * 1024 * 1024,
        parity_shards: 0,
        default_buckets: String::new(),
        max_console_body_bytes: 1024 * 1024,
        ..Config::default()
    };
    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let resp = s3_request("HEAD", &format!("{}/existing", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Name>existing</Name>"));
}

#[tokio::test]
async fn test_default_buckets_skips_invalid_names() {
    let (base_url, _tmp) =
        start_server_with_default_buckets("INVALID,valid,b..a,a.-b,a-.b,192.168.0.1").await;

    for bucket in ["INVALID", "b..a", "a.-b", "a-.b", "192.168.0.1"] {
        let resp = s3_request("HEAD", &format!("{}/{}", base_url, bucket), vec![]).await;
        assert_eq!(
            resp.status(),
            400,
            "{bucket} should be skipped and rejected as InvalidBucketName"
        );
    }

    let resp = s3_request("HEAD", &format!("{}/valid", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_empty_default_buckets() {
    let (base_url, _tmp) = start_server_with_default_buckets("").await;

    // No default buckets should exist
    let resp = s3_request("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("<Name>"), "No buckets should be listed");
}

#[tokio::test]
async fn test_default_buckets_single() {
    let (base_url, _tmp) = start_server_with_default_buckets("only-one").await;

    let resp = s3_request("HEAD", &format!("{}/only-one", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Sign a request using comma-only separators (no spaces), like mc does.
fn sign_request_compact(method: &str, url: &str, headers: &mut Vec<(String, String)>, body: &[u8]) {
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
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
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
async fn s3_request(method: &str, url: &str, body: Vec<u8>) -> reqwest::Response {
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

/// Like s3_request but returns Result instead of panicking on send errors.
async fn s3_request_result(
    method: &str,
    url: &str,
    body: Vec<u8>,
) -> Result<reqwest::Response, reqwest::Error> {
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

    builder.send().await
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
async fn s3_request_compact(method: &str, url: &str, body: Vec<u8>) -> reqwest::Response {
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
async fn s3_put_chunked(url: &str, data: &[u8]) -> reqwest::Response {
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
        (
            "x-amz-decoded-content-length".to_string(),
            data.len().to_string(),
        ),
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
    // with real chained chunk signatures (the server verifies them).
    let signer = StreamSigner {
        signing_key: signing_key.to_vec(),
        amz_date: amz_date.clone(),
        scope: scope.clone(),
        seed_signature: seed_signature.clone(),
    };
    let chunk_sig = signer.chunk_signature(&seed_signature, data);
    let final_sig = signer.chunk_signature(&chunk_sig, b"");
    let mut chunked_body = Vec::new();
    chunked_body.extend_from_slice(
        format!("{:x};chunk-signature={}\r\n", data.len(), chunk_sig).as_bytes(),
    );
    chunked_body.extend_from_slice(data);
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(format!("0;chunk-signature={}\r\n", final_sig).as_bytes());

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
async fn test_healthz_is_public_and_returns_ok() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_version_endpoint_reports_package_version() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{base_url}/version"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_readyz_is_public_and_returns_ok() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/readyz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_security_headers_are_applied() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csp.contains("font-src 'self' data:"),
        "embedded Geist fonts are same-origin files or data: URIs: {csp}"
    );
    assert!(csp.contains("script-src 'self' 'unsafe-inline'"), "{csp}");
    assert!(
        !csp.contains("script-src 'self' 'unsafe-inline' data:"),
        "font data: URIs must not widen script-src: {csp}"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
}

#[tokio::test]
async fn console_login_on_loopback_http_omits_secure_and_authenticates() {
    let (base_url, _tmp) =
        start_server_with_keys("test-access", "test-credential", true, false).await;
    let resp = client()
        .post(format!("{base_url}/api/auth/login"))
        .json(&serde_json::json!({
            "accessKey": "test-access",
            "secretKey": "test-credential"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        !set_cookie.to_ascii_lowercase().contains("secure"),
        "loopback HTTP login must store a cookie: {set_cookie}"
    );
    let session = set_cookie
        .strip_prefix("maxio_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let check = client()
        .get(format!("{base_url}/api/auth/check"))
        .header("cookie", format!("maxio_session={session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(check.status(), 200);
}

#[tokio::test]
async fn console_login_marks_cookie_secure_for_https_and_public_hosts() {
    let (base_url, _tmp) =
        start_server_with_keys("test-access", "test-credential", true, false).await;
    let https = client()
        .post(format!("{base_url}/api/auth/login"))
        .header("x-forwarded-proto", "https")
        .json(&serde_json::json!({
            "accessKey": "test-access",
            "secretKey": "test-credential"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(https.status(), 200);
    let https_cookie = https.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(
        https_cookie.contains("Secure"),
        "HTTPS proxy login should mark the cookie Secure: {https_cookie}"
    );

    let public_host = client()
        .post(format!("{base_url}/api/auth/login"))
        .header("host", "storage.example.com")
        .json(&serde_json::json!({
            "accessKey": "test-access",
            "secretKey": "test-credential"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(public_host.status(), 200);
    let public_cookie = public_host
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        public_cookie.contains("Secure"),
        "non-loopback HTTP must not mint a browser-stored session: {public_cookie}"
    );
}

#[tokio::test]
async fn test_ui_deep_link_uses_spa_fallback() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/ui/buckets/example/settings", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/html")
    );
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store, must-revalidate"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("MaxIO"));
}

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

/// The AWS CRT client signs `content-length: 0` on GET; Go reverse proxies
/// (Caddy, Traefik) drop that header for bodyless requests. The signature
/// must still verify, as on MinIO.
#[tokio::test]
async fn test_auth_accepts_signed_content_length_dropped_by_proxy() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);
    let mut headers = vec![("content-length".to_string(), "0".to_string())];
    sign_request("GET", &url, &mut headers, &[]);

    let mut builder = client().get(&url);
    for (k, v) in headers.iter().filter(|(k, _)| k != "content-length") {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder.send().await.unwrap();
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
async fn test_create_bucket_rejects_canonical_invalid_names() {
    let (base_url, _tmp) = start_server().await;

    for bucket in ["c", "ab", "a.-b", "a-.b", "192.168.0.1"] {
        let resp = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
        assert_eq!(resp.status(), 400, "{bucket} should be rejected");
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("<Code>InvalidBucketName</Code>"),
            "{bucket} should return InvalidBucketName, got {body}"
        );
    }

    for (method, path) in [
        ("GET", "/c"),
        ("HEAD", "/c"),
        ("DELETE", "/c"),
        ("PUT", "/c/object.txt"),
        ("GET", "/c/object.txt"),
    ] {
        let resp = s3_request(method, &format!("{base_url}{path}"), vec![]).await;
        assert_eq!(resp.status(), 400, "{method} {path} should be 400");
        if method != "HEAD" {
            let body = resp.text().await.unwrap();
            assert!(
                body.contains("<Code>InvalidBucketName</Code>"),
                "{method} {path} should return InvalidBucketName, got {body}"
            );
        }
    }
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

// Regression: delete_bucket must succeed after full object lifecycle
// (put + delete) even when metadata sidecars or empty dirs remain.
#[tokio::test]
async fn test_delete_bucket_after_object_lifecycle() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/bucket-one", base_url), vec![]).await;
    let r = s3_request(
        "PUT",
        &format!("{}/bucket-one/f.txt", base_url),
        b"x".to_vec(),
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = s3_request("DELETE", &format!("{}/bucket-one/f.txt", base_url), vec![]).await;
    assert_eq!(r.status(), 204);

    let r = s3_request("DELETE", &format!("{}/bucket-one", base_url), vec![]).await;
    assert_eq!(
        r.status(),
        204,
        "bucket delete should succeed after object removed"
    );

    let r = s3_request("HEAD", &format!("{}/bucket-one", base_url), vec![]).await;
    assert_eq!(r.status(), 404);
}

// Regression: nested keys leave deep directory trees; delete_bucket must
// sweep empty parents.
#[tokio::test]
async fn test_delete_bucket_with_nested_path() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/bucket-two", base_url), vec![]).await;
    let r = s3_request(
        "PUT",
        &format!("{}/bucket-two/a/b/c/d.txt", base_url),
        b"y".to_vec(),
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = s3_request(
        "DELETE",
        &format!("{}/bucket-two/a/b/c/d.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(r.status(), 204);

    let r = s3_request("DELETE", &format!("{}/bucket-two", base_url), vec![]).await;
    assert_eq!(
        r.status(),
        204,
        "bucket delete should sweep empty nested dirs"
    );
}

// Ensure we did not weaken the real emptiness check.
#[tokio::test]
async fn test_delete_bucket_rejects_real_object() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/bucket-three", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/bucket-three/stay.txt", base_url),
        b"z".to_vec(),
    )
    .await;

    let r = s3_request("DELETE", &format!("{}/bucket-three", base_url), vec![]).await;
    assert_eq!(r.status(), 409);

    // Bucket still exists.
    let r = s3_request("HEAD", &format!("{}/bucket-three", base_url), vec![]).await;
    assert_eq!(r.status(), 200);
}

// Regression: stale nested `.versions/` dir (from past versioning state)
// must not block bucket deletion. Exercised directly against the storage
// layer so the test does not depend on the S3 versioning API.
#[tokio::test]
async fn test_delete_bucket_sweeps_nested_versions() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();

    storage
        .create_bucket(&maxio::storage::BucketMeta {
            name: "leftover".to_string(),
            created_at: "2026-04-16T00:00:00.000Z".to_string(),
            region: "us-east-1".to_string(),
            versioning: false,
            cors_rules: None,
            encryption_config: None,
            public_read: false,
            public_list: false,
            versioning_suspended: false,
            tags: None,
            lifecycle: None,
        })
        .await
        .unwrap();

    // Simulate an orphan `.versions/` dir deep in the tree plus a stray
    // `.meta.json` sidecar.
    let bucket_root = tmp.path().join("buckets").join("leftover");
    let stale_versions = bucket_root.join("photos").join(".versions");
    tokio::fs::create_dir_all(&stale_versions).await.unwrap();
    tokio::fs::write(bucket_root.join("orphan.txt.meta.json"), b"{}")
        .await
        .unwrap();

    let deleted = storage.delete_bucket("leftover").await.unwrap();
    assert!(
        deleted,
        "delete_bucket should succeed on sweepable artifacts"
    );
    assert!(!tokio::fs::try_exists(&bucket_root).await.unwrap());
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
async fn test_delete_object_missing_bucket_returns_404() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request(
        "DELETE",
        &format!("{}/missing-bucket/file.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("NoSuchBucket"), "body: {}", body);
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

    let resp = s3_request("GET", &format!("{}/mybucket?list-type=2", base_url), vec![]).await;
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
    let last_modified = resp
        .headers()
        .get("last-modified")
        .unwrap()
        .to_str()
        .unwrap();
    // Should match pattern like "Mon, 17 Feb 2026 22:17:45 GMT"
    assert!(
        last_modified.ends_with(" GMT"),
        "Last-Modified should end with GMT: {}",
        last_modified
    );
    assert!(
        last_modified.contains(", "),
        "Last-Modified should contain comma-space: {}",
        last_modified
    );
    // Must NOT be ISO 8601 (no "T" between date and time digits)
    assert!(
        !last_modified.contains("T0"),
        "Last-Modified must not be ISO 8601: {}",
        last_modified
    );
    assert!(
        !last_modified.contains("T1"),
        "Last-Modified must not be ISO 8601: {}",
        last_modified
    );
    assert!(
        !last_modified.contains("T2"),
        "Last-Modified must not be ISO 8601: {}",
        last_modified
    );

    // GET should also return RFC 7231 Last-Modified
    let resp = s3_request("GET", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    let last_modified = resp
        .headers()
        .get("last-modified")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(last_modified.ends_with(" GMT"));
    // Verify it parses as HTTP date (day-of-week, DD Mon YYYY HH:MM:SS GMT)
    assert!(
        last_modified.len() > 25,
        "Last-Modified should be full HTTP date: {}",
        last_modified
    );
}

#[tokio::test]
async fn test_put_object_aws_chunked_encoding() {
    // mc sends uploads with x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
    // and the body is in AWS chunked format
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let data = b"hello chunked world";
    let resp = s3_put_chunked(&format!("{}/mybucket/chunked.txt", base_url), data).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("etag"));

    // Verify the stored content is decoded (no chunk framing)
    let resp = s3_request("GET", &format!("{}/mybucket/chunked.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        data,
        "Chunked upload content should be decoded"
    );
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
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "ETag should be quoted: {}",
        etag
    );

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
    s3_request(
        "PUT",
        &format!("{}/mybucket/c.txt", base_url),
        b"ccc".to_vec(),
    )
    .await;

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
    assert!(
        body.contains("<Deleted>"),
        "Response should contain Deleted elements"
    );
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
async fn test_delete_objects_batch_missing_bucket_returns_404() {
    let (base_url, _tmp) = start_server().await;

    let delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>a.txt</Key></Object>
</Delete>"#;

    let resp = s3_request(
        "POST",
        &format!("{}/missing-bucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("NoSuchBucket"), "body: {}", body);
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
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket/?list-type=2", base_url),
        vec![],
    )
    .await;
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
        (
            "x-amz-decoded-content-length".to_string(),
            "1000".to_string(),
        ),
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
    assert_eq!(
        resp.status(),
        200,
        "Retry upload after interrupted should succeed"
    );

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
        (
            "x-amz-decoded-content-length".to_string(),
            total_len.to_string(),
        ),
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

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );

    // Build multi-chunk body with real chained chunk signatures
    let signer = StreamSigner {
        signing_key: signing_key.to_vec(),
        amz_date: amz_date.clone(),
        scope: scope.clone(),
        seed_signature: signature.clone(),
    };
    let mut prev_sig = signature.clone();
    let mut chunked_body = Vec::new();
    for chunk_data in [&chunk1[..], &chunk2[..], &chunk3[..]] {
        let chunk_sig = signer.chunk_signature(&prev_sig, chunk_data);
        chunked_body.extend_from_slice(
            format!("{:x};chunk-signature={}\r\n", chunk_data.len(), chunk_sig).as_bytes(),
        );
        chunked_body.extend_from_slice(chunk_data);
        chunked_body.extend_from_slice(b"\r\n");
        prev_sig = chunk_sig;
    }
    // Terminating chunk
    let final_sig = signer.chunk_signature(&prev_sig, b"");
    chunked_body.extend_from_slice(format!("0;chunk-signature={}\r\n", final_sig).as_bytes());

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
    assert_eq!(
        body.as_ref(),
        expected,
        "Multi-chunk content should be concatenated"
    );

    // Verify content-length matches
    let resp = s3_request("HEAD", &url, vec![]).await;
    assert_eq!(
        resp.headers().get("content-length").unwrap(),
        &total_len.to_string()
    );
}

#[tokio::test]
async fn test_upload_part_uses_part_limit_not_object_limit() {
    // A part may be larger than a single PUT. 16 bytes sits between the two caps.
    let (base_url, _tmp) = start_server_with_size_limits(8, 32).await;
    s3_request("PUT", &format!("{base_url}/bkt"), vec![]).await;

    let too_big_for_put = s3_request("PUT", &format!("{base_url}/bkt/obj"), vec![b'a'; 16]).await;
    assert_eq!(too_big_for_put.status(), 400);
    let put_body = too_big_for_put.text().await.unwrap();
    assert!(
        put_body.contains("EntityTooLarge"),
        "single PUT over max-object-size: {put_body}"
    );

    let small_put = s3_request("PUT", &format!("{base_url}/bkt/ok"), vec![b'a'; 4]).await;
    assert_eq!(small_put.status(), 200);

    let create = s3_request(
        "POST",
        &format!("{base_url}/bkt/multi.bin?uploads="),
        vec![],
    )
    .await;
    assert_eq!(create.status(), 200);
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let part = s3_request(
        "PUT",
        &format!("{base_url}/bkt/multi.bin?partNumber=1&uploadId={upload_id}"),
        vec![b'b'; 16],
    )
    .await;
    assert_eq!(
        part.status(),
        200,
        "part under max-part-size must be accepted"
    );
    let part_body = part.text().await.unwrap();
    assert!(
        !part_body.contains("EntityTooLarge"),
        "UploadPart must not use max-object-size: {part_body}"
    );

    let over_part = s3_request(
        "PUT",
        &format!("{base_url}/bkt/multi.bin?partNumber=2&uploadId={upload_id}"),
        vec![b'c'; 40],
    )
    .await;
    assert_eq!(over_part.status(), 400);
    let over_body = over_part.text().await.unwrap();
    assert!(
        over_body.contains("EntityTooLarge"),
        "part over max-part-size: {over_body}"
    );
}

#[tokio::test]
async fn test_multipart_create_upload() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_tag(&body, "UploadId").unwrap();
    assert!(!upload_id.is_empty());
}

#[tokio::test]
async fn test_multipart_upload_part() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let resp = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
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
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = b"tail".to_vec();
    let r1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        p1.clone(),
    )
    .await;
    let e1 = r1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        p2.clone(),
    )
    .await;
    let e2 = r2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

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
async fn test_multipart_get_part_number() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/parts.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'A'; 5 * 1024 * 1024];
    let p2 = vec![b'B'; 3 * 1024 * 1024];
    let r1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/parts.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        p1.clone(),
    )
    .await;
    let e1 = r1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/parts.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        p2.clone(),
    )
    .await;
    let e2 = r2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/parts.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    // GET partNumber=1 should return only part 1 data
    let get_p1 = s3_request(
        "GET",
        &format!("{}/mybucket/parts.bin?partNumber=1", base_url),
        vec![],
    )
    .await;
    assert_eq!(get_p1.status(), 206);
    assert_eq!(
        get_p1.headers().get("content-length").unwrap(),
        &(5 * 1024 * 1024).to_string()
    );
    assert_eq!(get_p1.headers().get("x-amz-mp-parts-count").unwrap(), "2");
    let body1 = get_p1.bytes().await.unwrap();
    assert_eq!(body1.len(), 5 * 1024 * 1024);
    assert!(body1.iter().all(|&b| b == b'A'));

    // GET partNumber=2 should return only part 2 data
    let get_p2 = s3_request(
        "GET",
        &format!("{}/mybucket/parts.bin?partNumber=2", base_url),
        vec![],
    )
    .await;
    assert_eq!(get_p2.status(), 206);
    assert_eq!(
        get_p2.headers().get("content-length").unwrap(),
        &(3 * 1024 * 1024).to_string()
    );
    let body2 = get_p2.bytes().await.unwrap();
    assert_eq!(body2.len(), 3 * 1024 * 1024);
    assert!(body2.iter().all(|&b| b == b'B'));

    // HEAD partNumber=1 should return part-specific headers
    let head_p1 = s3_request(
        "HEAD",
        &format!("{}/mybucket/parts.bin?partNumber=1", base_url),
        vec![],
    )
    .await;
    assert_eq!(head_p1.status(), 206);
    assert_eq!(
        head_p1.headers().get("content-length").unwrap(),
        &(5 * 1024 * 1024).to_string()
    );
    assert_eq!(head_p1.headers().get("x-amz-mp-parts-count").unwrap(), "2");
}

#[tokio::test]
async fn test_multipart_complete_part_too_small() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let r1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        b"tiny".to_vec(),
    )
    .await;
    let e1 = r1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        b"tail".to_vec(),
    )
    .await;
    let e2 = r2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

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
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
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
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
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
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
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
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/in-progress.bin?uploads=", base_url),
        vec![],
    )
    .await;
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
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/etag.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = b"tail".to_vec();
    let r1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/etag.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        p1,
    )
    .await;
    let e1 = r1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/etag.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        p2,
    )
    .await;
    let e2 = r2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
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
    s3_request(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"copy me".to_vec(),
    )
    .await;

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

    s3_request(
        "PUT",
        &format!("{}/src-bucket/file.txt", base_url),
        b"cross bucket".to_vec(),
    )
    .await;

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
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
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
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
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
    s3_request(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"no slash".to_vec(),
    )
    .await;

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
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
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

    format!(
        "{}{}?{}&X-Amz-Signature={}",
        base_url, path, canonical_qs, signature
    )
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
    let resp = client()
        .put(&presigned)
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
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
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "9"
    );
}

#[tokio::test]
async fn test_presigned_expired_url() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-expire-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;
    let url = format!("{}/presign-expire-bucket/test.txt", base_url);
    s3_request("PUT", &url, b"data".to_vec()).await;

    // Manually craft a presigned URL with a timestamp from 2 hours ago
    let parsed =
        reqwest::Url::parse(&format!("{}/presign-expire-bucket/test.txt", base_url)).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);

    let past = chrono::Utc::now() - chrono::Duration::hours(2);
    let date_stamp = past.format("%Y%m%d").to_string();
    let amz_date = past.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{}/{}/{}/s3/aws4_request", ACCESS_KEY, date_stamp, REGION);

    let mut qs_params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
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

// ── Console presign endpoint tests ───────────────────────────────────

/// Helper: login via console API and return the session cookie value.
async fn console_login(base_url: &str) -> String {
    let resp = client()
        .post(&format!("{}/api/auth/login", base_url))
        .json(&serde_json::json!({"accessKey": ACCESS_KEY, "secretKey": SECRET_KEY}))
        .send()
        .await
        .unwrap();
    if resp.status() != 200 {
        let status = resp.status();
        let body = resp.text().await.unwrap();
        panic!("login failed with status {}: {}", status, body);
    }
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("login should set cookie")
        .to_str()
        .unwrap()
        .to_string();
    // Extract value from "maxio_session=VALUE; ..."
    let value = set_cookie
        .strip_prefix("maxio_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    value.to_string()
}

#[tokio::test]
async fn test_console_mutation_allows_dev_loopback_origin_via_vite_proxy() {
    let (base_url, _tmp) = start_server().await;
    let session = console_login(&base_url).await;

    let resp = client()
        .post(format!("{}/api/buckets", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .header("origin", "http://127.0.0.1:5173")
        .json(&serde_json::json!({ "name": "dev-origin-bucket" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "body: {}", resp.text().await.unwrap());
}

#[tokio::test]
async fn test_console_mutation_rejects_cross_site_origin() {
    let (base_url, _tmp) = start_server().await;
    let session = console_login(&base_url).await;

    let resp = client()
        .post(format!("{}/api/buckets", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .header("origin", "http://evil.example")
        .json(&serde_json::json!({ "name": "evil-origin-bucket" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_console_delete_object_missing_bucket_returns_404() {
    let (base_url, _tmp) = start_server().await;
    let session = console_login(&base_url).await;

    let resp = client()
        .delete(&format!(
            "{}/api/buckets/missing-bucket/objects/file.txt",
            base_url
        ))
        .header("cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Bucket not found");
}

#[tokio::test]
async fn test_console_presign_simple_key() {
    let (base_url, _tmp) = start_server().await;

    // Create bucket and upload object via S3 API
    s3_request("PUT", &format!("{}/cpresign-bucket", base_url), vec![]).await;
    let body = b"console presign test";
    s3_request(
        "PUT",
        &format!("{}/cpresign-bucket/test.txt", base_url),
        body.to_vec(),
    )
    .await;

    // Login to console API
    let session = console_login(&base_url).await;

    // Generate presigned URL via console endpoint
    let resp = client()
        .get(&format!(
            "{}/api/buckets/cpresign-bucket/presign/test.txt?expires=300",
            base_url
        ))
        .header("Cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    let presigned_url = json["url"]
        .as_str()
        .expect("response should have url field");

    // Fetch the presigned URL without any auth — should succeed
    let resp = client().get(presigned_url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "presigned URL should return 200, got {}",
        resp.status()
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
}

#[tokio::test]
async fn test_console_presign_key_with_spaces() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/cpresign-space", base_url), vec![]).await;
    let body = b"file with spaces";
    // Upload with a key containing spaces (URL-encoded in the request)
    s3_request(
        "PUT",
        &format!("{}/cpresign-space/my%20file.txt", base_url),
        body.to_vec(),
    )
    .await;

    let session = console_login(&base_url).await;

    // Request presigned URL for the key with spaces (URL-encoded in the API path)
    let resp = client()
        .get(&format!(
            "{}/api/buckets/cpresign-space/presign/my%20file.txt?expires=300",
            base_url
        ))
        .header("Cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    let presigned_url = json["url"]
        .as_str()
        .expect("response should have url field");

    let resp = client().get(presigned_url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "presigned URL for key with spaces should return 200, got {}",
        resp.status()
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
}

#[tokio::test]
async fn test_console_presign_nested_key() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/cpresign-nested", base_url), vec![]).await;
    let body = b"nested key content";
    s3_request(
        "PUT",
        &format!("{}/cpresign-nested/folder/sub/file.txt", base_url),
        body.to_vec(),
    )
    .await;

    let session = console_login(&base_url).await;

    let resp = client()
        .get(&format!(
            "{}/api/buckets/cpresign-nested/presign/folder/sub/file.txt?expires=300",
            base_url
        ))
        .header("Cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    let presigned_url = json["url"]
        .as_str()
        .expect("response should have url field");

    let resp = client().get(presigned_url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "presigned URL for nested key should return 200, got {}",
        resp.status()
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
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
    assert!(
        !body.contains("readme.txt"),
        "readme.txt should not appear at root"
    );

    // List inside docs/ — should see readme.txt
    let resp = s3_request(
        "GET",
        &format!(
            "{}/mybucket?list-type=2&prefix=docs%2F&delimiter=%2F",
            base_url
        ),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<Key>docs/readme.txt</Key>"),
        "body: {}",
        body
    );

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
    s3_request(
        "DELETE",
        &format!("{}/mybucket/empty-dir/", base_url),
        vec![],
    )
    .await;

    // HeadObject should now return 404
    let resp = s3_request("HEAD", &format!("{}/mybucket/empty-dir/", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

// --- Erasure Coding Tests ---

/// Start a server with erasure coding enabled (small chunk size for testing).
async fn start_server_ec() -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    // Use 1KB chunk size for easy multi-chunk testing
    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, true, 1024, 0, keyring)
        .await
        .unwrap();

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
        master_key: None,
        master_key_file: None,
        allow_missing_master_key: false,
        allow_insecure_dev: true,
        secure_cookies: false,
        erasure_coding: true,
        chunk_size: 1024,
        parity_shards: 0,
        default_buckets: String::new(),
        max_console_body_bytes: 1024 * 1024,
        ..Config::default()
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

#[tokio::test]
async fn test_ec_put_and_get_object() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    // Upload 3KB of data (should create 3 chunks with 1KB chunk size)
    let data = vec![0x42u8; 3 * 1024];
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/bigfile.bin", base_url),
        data.clone(),
        vec![],
    )
    .await;

    // GET should return identical data
    let resp = s3_request(
        "GET",
        &format!("{}/testbucket/bigfile.bin", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), 3 * 1024);
    assert_eq!(&body[..], &data[..]);
}

#[tokio::test]
async fn test_ec_small_object() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    // Upload less than one chunk
    let data = b"small data".to_vec();
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/small.txt", base_url),
        data.clone(),
        vec![],
    )
    .await;

    let resp = s3_request("GET", &format!("{}/testbucket/small.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &data[..]);
}

#[tokio::test]
async fn test_ec_range_request() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    // 3KB of sequential bytes so we can verify exact ranges
    let data: Vec<u8> = (0..3072).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/rangetest.bin", base_url),
        data.clone(),
        vec![],
    )
    .await;

    // Range spanning chunk boundary (bytes 500-1500, crosses from chunk 0 to chunk 1)
    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/testbucket/rangetest.bin", base_url),
        vec![],
        vec![("Range", "bytes=500-1499")],
    )
    .await;
    assert_eq!(resp.status(), 206);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), 1000);
    assert_eq!(&body[..], &data[500..1500]);
}

#[tokio::test]
async fn test_ec_delete_object() {
    let (base_url, tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/todelete.txt", base_url),
        b"delete me".to_vec(),
        vec![],
    )
    .await;

    // Verify .ec directory exists
    let ec_dir = tmp.path().join("buckets/testbucket/todelete.txt.ec");
    assert!(ec_dir.exists(), "EC dir should exist after PUT");

    s3_request(
        "DELETE",
        &format!("{}/testbucket/todelete.txt", base_url),
        vec![],
    )
    .await;

    assert!(!ec_dir.exists(), "EC dir should be removed after DELETE");
    let resp = s3_request(
        "GET",
        &format!("{}/testbucket/todelete.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_ec_etag_matches_flat_file() {
    // Verify that EC objects produce the same ETag as flat-file objects
    let (base_url_flat, _tmp1) = start_server().await;
    let (base_url_ec, _tmp2) = start_server_ec().await;

    for base in [&base_url_flat, &base_url_ec] {
        s3_request("PUT", &format!("{}/testbucket", base), vec![]).await;
    }

    let data = b"hello world etag test".to_vec();
    let resp_flat = s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/etagtest.txt", base_url_flat),
        data.clone(),
        vec![],
    )
    .await;
    let resp_ec = s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/etagtest.txt", base_url_ec),
        data.clone(),
        vec![],
    )
    .await;

    let etag_flat = resp_flat
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let etag_ec = resp_ec
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        etag_flat, etag_ec,
        "ETags should match between flat and EC storage"
    );
}

#[tokio::test]
async fn test_ec_bitrot_detection() {
    let (base_url, tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/corrupt.bin", base_url),
        vec![0xAA; 2048],
        vec![],
    )
    .await;

    // Corrupt chunk 0 on disk
    let chunk_path = tmp.path().join("buckets/testbucket/corrupt.bin.ec/000000");
    std::fs::write(&chunk_path, vec![0xFF; 1024]).unwrap();

    // GET should fail — either a 500 response or a connection error
    // (the error may occur mid-stream after headers are sent)
    let url = format!("{}/testbucket/corrupt.bin", base_url);
    let result = s3_request_result("GET", &url, vec![]).await;
    match result {
        Ok(resp) => {
            // If we get a response, reading the body should fail or status should be 500
            if resp.status() == 200 {
                let body_result = resp.bytes().await;
                assert!(
                    body_result.is_err() || body_result.unwrap() != vec![0xAA; 2048],
                    "Should not return original uncorrupted data"
                );
            }
        }
        Err(_) => {
            // Connection error is expected — chunk verification failed mid-stream
        }
    }
}

#[tokio::test]
async fn test_ec_list_objects() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/file1.txt", base_url),
        b"one".to_vec(),
        vec![],
    )
    .await;
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/file2.txt", base_url),
        b"two".to_vec(),
        vec![],
    )
    .await;

    let resp = s3_request(
        "GET",
        &format!("{}/testbucket?list-type=2", base_url),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>file1.txt</Key>"), "body: {}", body);
    assert!(body.contains("<Key>file2.txt</Key>"), "body: {}", body);
    // .ec directories should NOT appear as objects
    assert!(
        !body.contains(".ec"),
        "body should not contain .ec: {}",
        body
    );
}

// --- Checksum tests ---

#[tokio::test]
async fn test_put_object_with_crc32_checksum() {
    let (base_url, _tmp) = start_server().await;

    // Create bucket
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    // Compute CRC32 of body
    let body = b"hello checksum world";
    let crc = crc32fast::hash(body);
    let crc_b64 = base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes());

    // PUT with correct checksum
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/test.txt", base_url),
        body.to_vec(),
        vec![("x-amz-checksum-crc32", &crc_b64)],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );

    // GET should return the checksum header
    let resp = s3_request(
        "GET",
        &format!("{}/checksum-bucket/test.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );

    // HEAD should also return it
    let resp = s3_request(
        "HEAD",
        &format!("{}/checksum-bucket/test.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );
}

#[tokio::test]
async fn test_put_object_with_wrong_checksum() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    // Send a wrong CRC32 value
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/bad.txt", base_url),
        b"some data".to_vec(),
        vec![("x-amz-checksum-crc32", "AAAAAAAA")],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("BadDigest"),
        "expected BadDigest error: {}",
        body
    );
}

/// AWS CLI v2 / SDKs default to CRC64NVME and send it as a plain header over
/// HTTP. A wrong value must be rejected; a right one stored and returned.
#[tokio::test]
async fn test_put_object_with_crc64nvme_checksum() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;
    let url = format!("{}/checksum-bucket/crc64.txt", base_url);

    let resp = s3_request_with_headers(
        "PUT",
        &url,
        b"123456789".to_vec(),
        vec![("x-amz-checksum-crc64nvme", "AAAAAAAAAAA=")],
    )
    .await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("BadDigest"));

    // CRC-64/NVME check value of "123456789" is 0xAE8B14860A799888.
    let resp = s3_request_with_headers(
        "PUT",
        &url,
        b"123456789".to_vec(),
        vec![("x-amz-checksum-crc64nvme", "rosUhgp5mIg=")],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-amz-checksum-crc64nvme").unwrap(),
        "rosUhgp5mIg="
    );

    let resp = s3_request("HEAD", &url, vec![]).await;
    assert_eq!(
        resp.headers().get("x-amz-checksum-crc64nvme").unwrap(),
        "rosUhgp5mIg="
    );
}

/// A full-object checksum must not be sent with a partial body: SDKs validate
/// it against the bytes received and fail ranged reads.
#[tokio::test]
async fn test_range_get_omits_full_object_checksum() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;
    let url = format!("{}/checksum-bucket/ranged.txt", base_url);
    let resp = s3_request_with_headers(
        "PUT",
        &url,
        b"hello checksum world".to_vec(),
        vec![("x-amz-checksum-algorithm", "CRC32")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request_with_headers("GET", &url, vec![], vec![("range", "bytes=0-4")]).await;
    assert_eq!(resp.status(), 206);
    assert!(resp.headers().get("x-amz-checksum-crc32").is_none());
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"hello");

    // A range covering the whole object still carries it.
    let resp = s3_request_with_headers("GET", &url, vec![], vec![("range", "bytes=0-")]).await;
    assert!(resp.headers().get("x-amz-checksum-crc32").is_some());
}

#[tokio::test]
async fn test_put_object_with_algorithm_only() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    let body_bytes = b"compute my checksum please";

    // Send only the algorithm header, no value — server should compute
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/algo-only.txt", base_url),
        body_bytes.to_vec(),
        vec![("x-amz-checksum-algorithm", "CRC32C")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Verify a CRC32C header was returned
    let checksum = resp
        .headers()
        .get("x-amz-checksum-crc32c")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!checksum.is_empty());

    // Verify it's the correct value
    let expected_crc = crc32c::crc32c(body_bytes);
    let expected_b64 = base64::engine::general_purpose::STANDARD.encode(expected_crc.to_be_bytes());
    assert_eq!(checksum, expected_b64);
}

#[tokio::test]
async fn test_put_object_no_checksum_backward_compat() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/no-checksum.txt", base_url),
        b"plain old upload".to_vec(),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);

    // No checksum headers should be in the response
    assert!(resp.headers().get("x-amz-checksum-crc32").is_none());
    assert!(resp.headers().get("x-amz-checksum-crc32c").is_none());
    assert!(resp.headers().get("x-amz-checksum-sha1").is_none());
    assert!(resp.headers().get("x-amz-checksum-sha256").is_none());
}

#[tokio::test]
async fn test_put_object_with_sha256_checksum() {
    use base64::Engine;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    let body = b"sha256 test data";
    let hash = <sha2::Sha256 as sha2::Digest>::digest(body);
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/sha256.txt", base_url),
        body.to_vec(),
        vec![("x-amz-checksum-sha256", &hash_b64)],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-sha256")
            .unwrap()
            .to_str()
            .unwrap(),
        hash_b64
    );
}

// --- Parity / Reed-Solomon Tests ---

/// Start a server with erasure coding + parity enabled (small chunks for testing).
async fn start_server_parity(parity_shards: u32) -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    // 100-byte chunks for easy multi-chunk testing
    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, true, 100, parity_shards, keyring)
        .await
        .unwrap();

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
        master_key: None,
        master_key_file: None,
        allow_missing_master_key: false,
        allow_insecure_dev: true,
        secure_cookies: false,
        erasure_coding: true,
        chunk_size: 100,
        parity_shards,
        default_buckets: String::new(),
        max_console_body_bytes: 1024 * 1024,
        ..Config::default()
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

#[tokio::test]
async fn test_parity_write_creates_parity_chunks() {
    let (base_url, tmp) = start_server_parity(2).await;

    // Create bucket
    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    // Write 350 bytes → 4 data chunks (100+100+100+50) + 2 parity
    let data = vec![0xABu8; 350];
    s3_request("PUT", &format!("{}/parity-test/file.bin", base_url), data).await;

    // Check the .ec directory
    let ec_dir = tmp.path().join("buckets/parity-test/file.bin.ec");
    assert!(ec_dir.is_dir());

    // Should have 6 chunk files + manifest.json = 7 entries
    let entries: Vec<_> = std::fs::read_dir(&ec_dir).unwrap().collect();
    assert_eq!(entries.len(), 7, "expected 4 data + 2 parity + 1 manifest");

    // Verify manifest
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ec_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"], 2);
    assert_eq!(manifest["chunk_count"], 4);
    assert_eq!(manifest["parity_shards"], 2);
    assert_eq!(manifest["chunks"].as_array().unwrap().len(), 6);

    // Verify parity chunks have kind: "parity"
    let chunks = manifest["chunks"].as_array().unwrap();
    for i in 0..4 {
        // data chunks should not have "kind" field (skipped when data) or be "data"
        let kind = chunks[i].get("kind");
        assert!(kind.is_none() || kind.unwrap() == "data");
    }
    assert_eq!(chunks[4]["kind"], "parity");
    assert_eq!(chunks[5]["kind"], "parity");
}

#[tokio::test]
async fn test_parity_read_healthy() {
    let (base_url, _tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0xCDu8; 350];
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    let resp = s3_request("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_recovery_corrupted_chunk() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0xEFu8; 350];
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    // Corrupt data chunk 1 (overwrite with zeros)
    let chunk_path = tmp.path().join("buckets/parity-test/file.bin.ec/000001");
    std::fs::write(&chunk_path, vec![0u8; 100]).unwrap();

    // Read should still succeed via RS recovery
    let resp = s3_request("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_recovery_missing_chunk() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0x42u8; 350];
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    // Delete data chunk 0
    let chunk_path = tmp.path().join("buckets/parity-test/file.bin.ec/000000");
    std::fs::remove_file(&chunk_path).unwrap();

    let resp = s3_request("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_too_many_failures() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0x77u8; 350];
    s3_request("PUT", &format!("{}/parity-test/file.bin", base_url), data).await;

    // Delete 3 chunks (more than m=2 parity can handle)
    for i in 0..3 {
        let chunk_path = tmp
            .path()
            .join(format!("buckets/parity-test/file.bin.ec/{:06}", i));
        std::fs::remove_file(&chunk_path).unwrap();
    }

    // The server will return an error or drop the connection when RS recovery fails.
    // Since the object is streamed, the error may manifest as a connection reset
    // rather than a clean HTTP error status.
    let result =
        s3_request_result("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    match result {
        Err(_) => {} // Connection error — expected
        Ok(resp) => {
            // Either a server error status, or streaming started but body will be incomplete
            if resp.status() == 200 {
                let body_result = resp.bytes().await;
                assert!(body_result.is_err() || body_result.unwrap().len() != 350);
            } else {
                assert!(resp.status().is_server_error());
            }
        }
    }
}

#[tokio::test]
async fn test_parity_range_read_degraded() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    // Create data with distinct bytes per chunk for easy verification
    let mut data = Vec::new();
    for i in 0u8..4 {
        let chunk_len = if i < 3 { 100 } else { 50 };
        data.extend(std::iter::repeat(i + 1).take(chunk_len));
    }
    assert_eq!(data.len(), 350);
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    // Corrupt chunk 1
    let chunk_path = tmp.path().join("buckets/parity-test/file.bin.ec/000001");
    std::fs::write(&chunk_path, vec![0u8; 100]).unwrap();

    // Range read spanning chunk 0 and chunk 1 (bytes 50-149)
    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/parity-test/file.bin", base_url),
        vec![],
        vec![("range", "bytes=50-149")],
    )
    .await;
    assert_eq!(resp.status(), 206);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[50..150]);
}

#[tokio::test]
async fn test_parity_backward_compat_v1_manifest() {
    // EC without parity should still work (v1 manifest, no parity fields)
    let (base_url, _tmp) = start_server_ec().await;

    s3_request("PUT", &format!("{}/compat-test", base_url), vec![]).await;

    let data = vec![0xAAu8; 2048];
    s3_request(
        "PUT",
        &format!("{}/compat-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    let resp = s3_request("GET", &format!("{}/compat-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_empty_object() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    // Empty object — should skip parity
    s3_request(
        "PUT",
        &format!("{}/parity-test/empty.bin", base_url),
        vec![],
    )
    .await;

    let ec_dir = tmp.path().join("buckets/parity-test/empty.bin.ec");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ec_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"], 1); // no parity for empty
    assert!(manifest.get("parity_shards").is_none() || manifest["parity_shards"].is_null());

    let resp = s3_request(
        "GET",
        &format!("{}/parity-test/empty.bin", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().len(), 0);
}

// ── Object Tagging ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_put_and_get_object_tagging() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/tag-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/tag-bucket/obj.txt", base),
        b"hello".to_vec(),
    )
    .await;

    let tagging_xml = r#"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag><Tag><Key>team</Key><Value>platform</Value></Tag></TagSet></Tagging>"#;
    let resp = s3_request(
        "PUT",
        &format!("{}/tag-bucket/obj.txt?tagging", base),
        tagging_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request(
        "GET",
        &format!("{}/tag-bucket/obj.txt?tagging", base),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>env</Key>"));
    assert!(body.contains("<Value>prod</Value>"));
    assert!(body.contains("<Key>team</Key>"));
    assert!(body.contains("<Value>platform</Value>"));
}

#[tokio::test]
async fn test_get_object_tagging_no_tags() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/notag-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/notag-bucket/obj.txt", base),
        b"hello".to_vec(),
    )
    .await;

    let resp = s3_request(
        "GET",
        &format!("{}/notag-bucket/obj.txt?tagging", base),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Tagging>") || body.contains("<TagSet"));
    assert!(!body.contains("<Tag>"));
}

#[tokio::test]
async fn test_delete_object_tagging() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/deltag-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/deltag-bucket/obj.txt", base),
        b"hello".to_vec(),
    )
    .await;

    let tagging_xml =
        r#"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>"#;
    s3_request(
        "PUT",
        &format!("{}/deltag-bucket/obj.txt?tagging", base),
        tagging_xml.as_bytes().to_vec(),
    )
    .await;

    let resp = s3_request(
        "DELETE",
        &format!("{}/deltag-bucket/obj.txt?tagging", base),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = s3_request(
        "GET",
        &format!("{}/deltag-bucket/obj.txt?tagging", base),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("<Tag>"));
}

#[tokio::test]
async fn test_get_object_tagging_no_such_key() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/nsk-bucket", base), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/nsk-bucket/nonexistent.txt?tagging", base),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("NoSuchKey"));
}

#[tokio::test]
async fn test_put_object_tagging_too_many_tags() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/manytagbucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/manytagbucket/obj.txt", base),
        b"data".to_vec(),
    )
    .await;

    let tags: String = (1..=11)
        .map(|i| format!("<Tag><Key>key{}</Key><Value>val{}</Value></Tag>", i, i))
        .collect();
    let tagging_xml = format!("<Tagging><TagSet>{}</TagSet></Tagging>", tags);
    let resp = s3_request(
        "PUT",
        &format!("{}/manytagbucket/obj.txt?tagging", base),
        tagging_xml.into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("InvalidArgument"));
}

#[tokio::test]
async fn test_put_object_tagging_key_too_long() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/longtag-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/longtag-bucket/obj.txt", base),
        b"data".to_vec(),
    )
    .await;

    let long_key = "k".repeat(129);
    let tagging_xml = format!(
        "<Tagging><TagSet><Tag><Key>{}</Key><Value>v</Value></Tag></TagSet></Tagging>",
        long_key
    );
    let resp = s3_request(
        "PUT",
        &format!("{}/longtag-bucket/obj.txt?tagging", base),
        tagging_xml.into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("InvalidArgument"));
}

#[tokio::test]
async fn test_put_object_tagging_value_too_long() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/longval-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/longval-bucket/obj.txt", base),
        b"data".to_vec(),
    )
    .await;

    let long_val = "v".repeat(257);
    let tagging_xml = format!(
        "<Tagging><TagSet><Tag><Key>k</Key><Value>{}</Value></Tag></TagSet></Tagging>",
        long_val
    );
    let resp = s3_request(
        "PUT",
        &format!("{}/longval-bucket/obj.txt?tagging", base),
        tagging_xml.into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("InvalidArgument"));
}

// UploadPartCopy: copy entire source object as a multipart part
#[tokio::test]
async fn test_upload_part_copy_full() {
    let (base, _tmp) = start_server().await;

    // Create source bucket and object
    s3_request("PUT", &format!("{}/src-upc", base), vec![]).await;
    let src_data: Vec<u8> = (0u8..255).cycle().take(5 * 1024 * 1024).collect(); // 5 MiB
    s3_request(
        "PUT",
        &format!("{}/src-upc/source.bin", base),
        src_data.clone(),
    )
    .await;

    // Create destination bucket and start multipart upload
    s3_request("PUT", &format!("{}/dst-upc", base), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/dst-upc/dest.bin?uploads=", base),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    // UploadPartCopy: copy full source as part 1
    let resp = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/dst-upc/dest.bin?partNumber=1&uploadId={}",
            base, upload_id
        ),
        vec![],
        vec![("x-amz-copy-source", "/src-upc/source.bin")],
    )
    .await;
    assert_eq!(resp.status(), 200, "upload_part_copy should return 200");
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<CopyPartResult>"),
        "response should be CopyPartResult XML, got: {}",
        body
    );
    let etag = extract_xml_tag(&body, "ETag").unwrap();
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "ETag should be quoted"
    );

    // Complete the multipart upload
    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!("{}/dst-upc/dest.bin?uploadId={}", base, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    // Verify content matches source
    let get = s3_request("GET", &format!("{}/dst-upc/dest.bin", base), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().as_ref(), src_data.as_slice());
}

// UploadPartCopy: copy a byte range from source object as a multipart part
#[tokio::test]
async fn test_upload_part_copy_range() {
    let (base, _tmp) = start_server().await;

    // Create source with known content
    s3_request("PUT", &format!("{}/src-upcr", base), vec![]).await;
    // part1: 5 MiB of 'A', part2: 1 KiB of 'B'
    let part1: Vec<u8> = vec![b'A'; 5 * 1024 * 1024];
    let part2: Vec<u8> = vec![b'B'; 1024];
    let mut src_data = part1.clone();
    src_data.extend_from_slice(&part2);
    s3_request(
        "PUT",
        &format!("{}/src-upcr/source.bin", base),
        src_data.clone(),
    )
    .await;

    // Create destination and start multipart upload
    s3_request("PUT", &format!("{}/dst-upcr", base), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/dst-upcr/dest.bin?uploads=", base),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    // Part 1: bytes 0 to (5MiB - 1)
    let r1 = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/dst-upcr/dest.bin?partNumber=1&uploadId={}",
            base, upload_id
        ),
        vec![],
        vec![
            ("x-amz-copy-source", "/src-upcr/source.bin"),
            (
                "x-amz-copy-source-range",
                &format!("bytes=0-{}", 5 * 1024 * 1024 - 1),
            ),
        ],
    )
    .await;
    assert_eq!(r1.status(), 200);
    let body1 = r1.text().await.unwrap();
    assert!(body1.contains("<CopyPartResult>"));
    let e1 = extract_xml_tag(&body1, "ETag").unwrap();

    // Part 2: remaining bytes
    let r2 = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/dst-upcr/dest.bin?partNumber=2&uploadId={}",
            base, upload_id
        ),
        vec![],
        vec![
            ("x-amz-copy-source", "/src-upcr/source.bin"),
            (
                "x-amz-copy-source-range",
                &format!("bytes={}-{}", 5 * 1024 * 1024, src_data.len() - 1),
            ),
        ],
    )
    .await;
    assert_eq!(r2.status(), 200);
    let body2 = r2.text().await.unwrap();
    assert!(body2.contains("<CopyPartResult>"));
    let e2 = extract_xml_tag(&body2, "ETag").unwrap();

    // Complete
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
            <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
            <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
        </CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/dst-upcr/dest.bin?uploadId={}", base, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    // Verify reconstructed content matches original source
    let get = s3_request("GET", &format!("{}/dst-upcr/dest.bin", base), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().as_ref(), src_data.as_slice());
}

// ---- CORS API tests ----

const CORS_XML_WILDCARD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedHeader>*</AllowedHeader>
    <MaxAgeSeconds>3600</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>"#;

const CORS_XML_EXACT_ORIGIN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>http://example.com</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
  </CORSRule>
</CORSConfiguration>"#;

#[tokio::test]
async fn test_put_get_delete_bucket_cors() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cors-bucket", base), vec![]).await;

    // GetBucketCors on bucket with no CORS → 404 NoSuchCORSConfiguration
    let resp = s3_request("GET", &format!("{}/cors-bucket?cors", base), vec![]).await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("NoSuchCORSConfiguration"));

    // PutBucketCors
    let resp = s3_request(
        "PUT",
        &format!("{}/cors-bucket?cors", base),
        CORS_XML_WILDCARD.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // GetBucketCors → should return config
    let resp = s3_request("GET", &format!("{}/cors-bucket?cors", base), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("CORSConfiguration"));
    assert!(body.contains("AllowedMethod"));
    assert!(body.contains("GET"));

    // DeleteBucketCors
    let resp = s3_request("DELETE", &format!("{}/cors-bucket?cors", base), vec![]).await;
    assert_eq!(resp.status(), 204);

    // GetBucketCors after delete → 404 again
    let resp = s3_request("GET", &format!("{}/cors-bucket?cors", base), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_put_cors_invalid_method() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cors-invalid", base), vec![]).await;

    let bad_cors = r#"<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>PATCH</AllowedMethod>
  </CORSRule>
</CORSConfiguration>"#;

    let resp = s3_request(
        "PUT",
        &format!("{}/cors-invalid?cors", base),
        bad_cors.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("InvalidArgument"));
}

#[tokio::test]
async fn test_cors_preflight_allowed() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/preflight-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/preflight-bucket?cors", base),
        CORS_XML_WILDCARD.as_bytes().to_vec(),
    )
    .await;

    // OPTIONS preflight — should return 200 with CORS headers
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/preflight-bucket/file.txt", base),
        )
        .header("Origin", "http://example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let headers = resp.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
    assert!(headers.contains_key("access-control-allow-methods"));
}

#[tokio::test]
async fn test_cors_preflight_no_config_returns_403() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/no-cors-bucket", base), vec![]).await;

    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/no-cors-bucket/file.txt", base),
        )
        .header("Origin", "http://example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_cors_preflight_unmatched_origin_returns_403() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/exact-origin-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/exact-origin-bucket?cors", base),
        CORS_XML_EXACT_ORIGIN.as_bytes().to_vec(),
    )
    .await;

    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/exact-origin-bucket/file.txt", base),
        )
        .header("Origin", "http://other.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_cors_normal_request_gets_headers() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cors-normal-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/cors-normal-bucket/obj.txt", base),
        b"hello".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/cors-normal-bucket?cors", base),
        CORS_XML_WILDCARD.as_bytes().to_vec(),
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/cors-normal-bucket/obj.txt", base),
        vec![],
        vec![("origin", "http://example.com")],
    )
    .await;

    assert_eq!(resp.status(), 200);
    let headers = resp.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "http://example.com"
    );
}

#[tokio::test]
async fn test_cors_no_origin_no_cors_headers() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cors-noorigin-bucket", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/cors-noorigin-bucket/obj.txt", base),
        b"hello".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/cors-noorigin-bucket?cors", base),
        CORS_XML_WILDCARD.as_bytes().to_vec(),
    )
    .await;

    let resp = s3_request(
        "GET",
        &format!("{}/cors-noorigin-bucket/obj.txt", base),
        vec![],
    )
    .await;

    assert_eq!(resp.status(), 200);
    assert!(!resp.headers().contains_key("access-control-allow-origin"));
}

// ─── Server-Side Encryption tests ────────────────────────────────────────────

/// SSE-S3: round-trip with server-managed key, verify echoed headers and that
/// on-disk contents differ from plaintext.
#[tokio::test]
async fn test_sse_s3_put_get_roundtrip() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sse-s3-bucket", base_url), vec![]).await;

    let plaintext = b"hello SSE-S3 encrypted world".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/sse-s3-bucket/foo.txt", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256"),
        "PUT must echo x-amz-server-side-encryption: AES256"
    );

    // HEAD echoes the header
    let head = s3_request(
        "HEAD",
        &format!("{}/sse-s3-bucket/foo.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(head.status(), 200);
    assert_eq!(
        head.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256"),
    );
    assert_eq!(
        head.headers().get("content-length").unwrap(),
        &plaintext.len().to_string()
    );

    // GET round-trips
    let get = s3_request(
        "GET",
        &format!("{}/sse-s3-bucket/foo.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(body.as_ref(), plaintext.as_slice());

    // On-disk bytes must not be plaintext
    let on_disk = std::fs::read(tmp.path().join("buckets/sse-s3-bucket/foo.txt")).unwrap();
    assert_ne!(
        on_disk, plaintext,
        "on-disk must be ciphertext, not plaintext"
    );
    assert!(
        on_disk.len() >= plaintext.len() + 12 + 16,
        "ciphertext must include 12B nonce + 16B tag overhead"
    );

    // Sidecar carries encryption block
    let meta_json =
        std::fs::read_to_string(tmp.path().join("buckets/sse-s3-bucket/foo.txt.meta.json"))
            .unwrap();
    assert!(meta_json.contains("\"mode\": \"sse_s3\""));
    assert!(meta_json.contains("\"algorithm\": \"AES256\""));
    assert!(meta_json.contains("\"wrapped_dek\""));
}

/// SSE-S3 overwrite: replacing an encrypted object must publish data and
/// metadata consistently, use a fresh DEK, and leave the latest object readable.
#[tokio::test]
async fn test_sse_s3_encrypted_overwrite_rekeys_and_reads_latest() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sse-overwrite", base_url), vec![]).await;

    let first = b"first encrypted body".to_vec();
    let put1 = s3_request_with_headers(
        "PUT",
        &format!("{}/sse-overwrite/o.bin", base_url),
        first,
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put1.status(), 200);

    let meta_path = tmp.path().join("buckets/sse-overwrite/o.bin.meta.json");
    let meta1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    let wrapped1 = meta1["encryption"]["wrapped_dek"]
        .as_str()
        .unwrap()
        .to_string();

    let second = b"second encrypted body is the current value".to_vec();
    let put2 = s3_request_with_headers(
        "PUT",
        &format!("{}/sse-overwrite/o.bin", base_url),
        second.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put2.status(), 200);

    let meta2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    let wrapped2 = meta2["encryption"]["wrapped_dek"].as_str().unwrap();
    assert_ne!(wrapped1, wrapped2, "overwrite must use a fresh object DEK");

    let get = s3_request("GET", &format!("{}/sse-overwrite/o.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().as_ref(), second.as_slice());
}

/// SSE-S3: Range GET across frame boundary translates plaintext offset → ciphertext frame.
#[tokio::test]
async fn test_sse_s3_range_read() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sse-range", base_url), vec![]).await;

    // 128 KiB = 2 full 64 KiB frames, so a cross-frame range actually crosses
    let mut plaintext = Vec::with_capacity(128 * 1024);
    for i in 0..128 * 1024u32 {
        plaintext.push((i % 251) as u8);
    }
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/sse-range/big.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    // Full download
    let full = s3_request("GET", &format!("{}/sse-range/big.bin", base_url), vec![])
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(full.as_ref(), plaintext.as_slice(), "full SSE-S3 roundtrip");

    // Range within first frame
    let range1 = s3_request_with_headers(
        "GET",
        &format!("{}/sse-range/big.bin", base_url),
        vec![],
        vec![("range", "bytes=100-199")],
    )
    .await;
    assert_eq!(range1.status(), 206);
    assert_eq!(
        range1.bytes().await.unwrap().as_ref(),
        &plaintext[100..=199]
    );

    // Range crossing frame boundary (64KiB = 65536)
    let range2 = s3_request_with_headers(
        "GET",
        &format!("{}/sse-range/big.bin", base_url),
        vec![],
        vec![("range", "bytes=65000-66000")],
    )
    .await;
    assert_eq!(range2.status(), 206);
    assert_eq!(
        range2.bytes().await.unwrap().as_ref(),
        &plaintext[65000..=66000]
    );

    // Suffix range
    let range3 = s3_request_with_headers(
        "GET",
        &format!("{}/sse-range/big.bin", base_url),
        vec![],
        vec![("range", "bytes=-1024")],
    )
    .await;
    assert_eq!(range3.status(), 206);
    assert_eq!(
        range3.bytes().await.unwrap().as_ref(),
        &plaintext[plaintext.len() - 1024..]
    );
}

/// SSE-C: round-trip with customer-supplied key; wrong key fails; missing key fails.
#[tokio::test]
async fn test_sse_c_requires_matching_key() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sse-c-bucket", base_url), vec![]).await;

    let key = [0x42u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_b64 = b64.encode(key);
    let key_md5 = b64.encode(md5::Md5::digest(&key));

    let plaintext = b"hello SSE-C".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/sse-c-bucket/obj", base_url),
        plaintext.clone(),
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_md5),
        ],
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers()
            .get("x-amz-server-side-encryption-customer-algorithm")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );

    // GET without customer key headers → error (bytes ≠ plaintext since not decrypted)
    let get_no_key = s3_request("GET", &format!("{}/sse-c-bucket/obj", base_url), vec![]).await;
    assert_ne!(
        get_no_key.status(),
        200,
        "SSE-C GET without customer key must not succeed"
    );

    // GET with wrong key → error
    let wrong = [0x00u8; 32];
    let wrong_b64 = b64.encode(wrong);
    let wrong_md5 = b64.encode(md5::Md5::digest(&wrong));
    let get_wrong = s3_request_with_headers(
        "GET",
        &format!("{}/sse-c-bucket/obj", base_url),
        vec![],
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &wrong_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &wrong_md5),
        ],
    )
    .await;
    assert_ne!(get_wrong.status(), 200);

    // GET with correct key succeeds
    let get_ok = s3_request_with_headers(
        "GET",
        &format!("{}/sse-c-bucket/obj", base_url),
        vec![],
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_md5),
        ],
    )
    .await;
    assert_eq!(get_ok.status(), 200);
    assert_eq!(get_ok.bytes().await.unwrap().as_ref(), plaintext.as_slice());
}

/// Bucket default encryption: plain PUT inherits SSE-S3 from bucket config.
#[tokio::test]
async fn test_bucket_default_encryption_inherits() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/def-enc", base_url), vec![]).await;

    // put-bucket-encryption (AES256)
    let cfg_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <ServerSideEncryptionConfiguration>\
        <Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>\
        </ApplyServerSideEncryptionByDefault></Rule>\
        </ServerSideEncryptionConfiguration>";
    let put_cfg = s3_request(
        "PUT",
        &format!("{}/def-enc?encryption", base_url),
        cfg_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(put_cfg.status(), 200);

    // get-bucket-encryption roundtrips AES256
    let get_cfg = s3_request("GET", &format!("{}/def-enc?encryption", base_url), vec![]).await;
    assert_eq!(get_cfg.status(), 200);
    let xml_body = get_cfg.text().await.unwrap();
    assert!(xml_body.contains("<SSEAlgorithm>AES256</SSEAlgorithm>"));

    // Plain PUT (no SSE header) → encrypted via bucket default
    let put = s3_request(
        "PUT",
        &format!("{}/def-enc/auto.txt", base_url),
        b"inherited".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );

    let meta_json =
        std::fs::read_to_string(tmp.path().join("buckets/def-enc/auto.txt.meta.json")).unwrap();
    assert!(meta_json.contains("\"mode\": \"sse_s3\""));

    // delete-bucket-encryption
    let del = s3_request(
        "DELETE",
        &format!("{}/def-enc?encryption", base_url),
        vec![],
    )
    .await;
    assert_eq!(del.status(), 204);

    // get-bucket-encryption → 404 after delete
    let get2 = s3_request("GET", &format!("{}/def-enc?encryption", base_url), vec![]).await;
    assert_eq!(get2.status(), 404);
}

/// SSE-KMS: header is rejected with InvalidEncryptionAlgorithm (feature removed).
#[tokio::test]
async fn test_sse_kms_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/kms-bucket", base_url), vec![]).await;

    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/kms-bucket/obj", base_url),
        b"payload".to_vec(),
        vec![("x-amz-server-side-encryption", "aws:kms")],
    )
    .await;
    assert_eq!(put.status(), 400);
    let body = put.text().await.unwrap();
    assert!(
        body.contains("InvalidEncryptionAlgorithmError"),
        "body: {}",
        body
    );
    assert!(body.contains("AES256"), "body: {}", body);
}

/// PutBucketEncryption with aws:kms is rejected (AES256 only).
#[tokio::test]
async fn test_put_bucket_encryption_kms_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/kms-def", base_url), vec![]).await;

    let xml_body = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <ServerSideEncryptionConfiguration>\
        <Rule><ApplyServerSideEncryptionByDefault>\
        <SSEAlgorithm>aws:kms</SSEAlgorithm>\
        </ApplyServerSideEncryptionByDefault></Rule>\
        </ServerSideEncryptionConfiguration>"
        .to_vec();
    let resp = s3_request("PUT", &format!("{}/kms-def?encryption", base_url), xml_body).await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("InvalidEncryptionAlgorithmError"),
        "body: {}",
        body
    );
}

/// Keyring rotate: old objects stay decryptable, new objects use the new key.
#[tokio::test]
async fn test_keyring_rotate_preserves_old_objects() {
    use maxio::storage::keys;

    let (base_url, tmp) = start_server().await;
    let data_dir = tmp.path().to_str().unwrap().to_string();

    s3_request("PUT", &format!("{}/rotate-bucket", base_url), vec![]).await;

    // PUT object under original key
    let old_plaintext = b"encrypted with old key".to_vec();
    let put_old = s3_request_with_headers(
        "PUT",
        &format!("{}/rotate-bucket/old.txt", base_url),
        old_plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put_old.status(), 200);

    let meta_old_before =
        std::fs::read_to_string(tmp.path().join("buckets/rotate-bucket/old.txt.meta.json"))
            .unwrap();

    // Rotate (server still running — mutates .maxio-keys.json on disk).
    let result = keys::rotate(&data_dir).await.unwrap();
    let previous_id = result
        .previous_active_id
        .expect("keyring was bootstrapped, so a previous active key must exist");
    assert_ne!(result.new_active_id, previous_id);
    assert_eq!(result.total_keys, 2);

    // Old-object metadata untouched: still references the old key id.
    let meta_old_after =
        std::fs::read_to_string(tmp.path().join("buckets/rotate-bucket/old.txt.meta.json"))
            .unwrap();
    assert_eq!(meta_old_before, meta_old_after);
    assert!(
        meta_old_after.contains(&previous_id),
        "old object should still reference previous key_id {}: {}",
        previous_id,
        meta_old_after
    );

    // Old object still decrypts (server keyring was loaded with the original key;
    // rotation only changes the on-disk file, so we exercise that explicitly via
    // a second reload below). The live server still reads it correctly because
    // the old key is in its in-memory ring.
    let get_old = s3_request(
        "GET",
        &format!("{}/rotate-bucket/old.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(get_old.status(), 200);
    assert_eq!(
        get_old.bytes().await.unwrap().as_ref(),
        old_plaintext.as_slice()
    );

    // Reload keyring from disk — simulates a server restart after rotation.
    let reloaded = keys::Keyring::load(&data_dir, None).await.unwrap();
    assert_eq!(reloaded.active_id(), result.new_active_id);

    // Both keys must be retained in the reloaded ring, so unwrap of existing
    // objects still works. Verify by round-tripping the stored EncryptionMeta.
    #[derive(serde::Deserialize)]
    struct Meta {
        encryption: EncMeta,
    }
    #[derive(serde::Deserialize)]
    struct EncMeta {
        key_id: String,
        wrapped_dek: String,
        wrap_nonce: String,
    }
    let parsed: Meta = serde_json::from_str(&meta_old_after).unwrap();
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(&parsed.encryption.wrapped_dek)
        .unwrap();
    let wrap_nonce = base64::engine::general_purpose::STANDARD
        .decode(&parsed.encryption.wrap_nonce)
        .unwrap();
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&wrap_nonce);
    reloaded
        .unwrap_dek(&parsed.encryption.key_id, &wrapped, &nonce_arr)
        .expect("reloaded keyring should still unwrap DEKs wrapped with the old key");

    // Rotating a second time bumps count to 3 and demotes the current active.
    let r2 = keys::rotate(&data_dir).await.unwrap();
    assert_eq!(
        r2.previous_active_id.as_deref(),
        Some(result.new_active_id.as_str())
    );
    assert_eq!(r2.total_keys, 3);
}

/// A restart must not mint a new master key over SSE-S3 objects, and the same
/// key supplied from outside the data directory must still decrypt them.
#[tokio::test]
async fn test_missing_master_key_refuses_restart_external_key_recovers() {
    use maxio::storage::keys::{Keyring, LoadOptions};

    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{base_url}/key-safety"), vec![]).await;
    let plaintext = b"sse-s3 survives a restart".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{base_url}/key-safety/secret.txt"),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    let get = s3_request("GET", &format!("{base_url}/key-safety/secret.txt"), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().as_ref(), plaintext.as_slice());

    let keyring_path = tmp.path().join(".maxio-keys.json");
    let saved_keyring = std::fs::read(&keyring_path).unwrap();
    let meta_path = tmp.path().join("buckets/key-safety/secret.txt.meta.json");
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    let key_id = meta["encryption"]["key_id"].as_str().unwrap().to_string();
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(meta["encryption"]["wrapped_dek"].as_str().unwrap())
        .unwrap();
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(meta["encryption"]["wrap_nonce"].as_str().unwrap())
        .unwrap();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let copy = TempDir::new().unwrap();
    copy_path(tmp.path(), copy.path());
    let copy_dir = copy.path().to_str().unwrap().to_string();
    std::fs::remove_file(copy.path().join(".maxio-keys.json")).unwrap();

    let missing = Keyring::load(&copy_dir, None)
        .await
        .err()
        .expect("missing keyring must refuse to start");
    assert!(
        missing
            .to_string()
            .contains("Refusing to generate a new master key"),
        "unexpected error: {missing}"
    );
    assert!(
        !copy.path().join(".maxio-keys.json").exists(),
        "refused startup must not create a replacement key"
    );

    let saved: serde_json::Value = serde_json::from_slice(&saved_keyring).unwrap();
    let b64 = saved["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["active"].as_bool() == Some(true))
        .unwrap()["key_b64"]
        .as_str()
        .unwrap()
        .to_string();

    let wrong = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
    let wrong_err = Keyring::load(&copy_dir, Some(&wrong))
        .await
        .err()
        .expect("wrong external key must refuse to start");
    assert!(
        wrong_err.to_string().contains(&key_id),
        "unexpected error: {wrong_err}"
    );

    let recovered = Keyring::load(&copy_dir, Some(&b64)).await.unwrap();
    assert_eq!(recovered.active_id(), key_id);
    let dek = recovered
        .unwrap_dek(&key_id, &wrapped, &nonce)
        .expect("external key must unwrap the DEK");
    assert_eq!(dek.len(), 32);
    assert!(!copy.path().join(".maxio-keys.json").exists());

    // Dropping the check file as well as the keyring still refuses, because
    // the object sidecar names the key id.
    let bare = TempDir::new().unwrap();
    copy_path(tmp.path(), bare.path());
    std::fs::remove_file(bare.path().join(".maxio-keys.json")).unwrap();
    std::fs::remove_file(bare.path().join(".maxio-key-check.json")).unwrap();
    let scanned = Keyring::load(bare.path().to_str().unwrap(), None)
        .await
        .err()
        .expect("scanning SSE-S3 metadata must refuse to bootstrap");
    assert!(
        scanned.to_string().contains(&key_id),
        "unexpected error: {scanned}"
    );
    assert!(!bare.path().join(".maxio-keys.json").exists());

    let abandoned = Keyring::load_with(
        bare.path().to_str().unwrap(),
        LoadOptions {
            master_key_b64: None,
            allow_missing_master_key: true,
        },
    )
    .await
    .unwrap();
    assert_ne!(abandoned.active_id(), key_id);
    assert!(
        abandoned
            .unwrap_dek(&key_id, &wrapped, &nonce)
            .unwrap_err()
            .to_string()
            .contains("not found in keyring")
    );

    // The live server still has the original key in memory.
    let get_again = s3_request("GET", &format!("{base_url}/key-safety/secret.txt"), vec![]).await;
    assert_eq!(get_again.status(), 200);
    assert_eq!(
        get_again.bytes().await.unwrap().as_ref(),
        plaintext.as_slice()
    );
}

fn copy_path(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type().unwrap();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            copy_path(&entry.path(), &to);
        } else if ft.is_file() {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Invalid SSE algorithm is rejected.
#[tokio::test]
async fn test_invalid_sse_algorithm_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/bad-enc", base_url), vec![]).await;

    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/bad-enc/obj", base_url),
        b"x".to_vec(),
        vec![("x-amz-server-side-encryption", "RC4")],
    )
    .await;
    assert_ne!(put.status(), 200);
    let body = put.text().await.unwrap();
    assert!(
        body.contains("InvalidEncryptionAlgorithm"),
        "body: {}",
        body
    );
}

/// If bucket encryption config cannot be read (corrupted .bucket.json),
/// PUT without explicit SSE headers must fail closed (500) — never silently
/// fall back to plaintext. Object must NOT be written.
#[tokio::test]
async fn test_put_object_fails_when_bucket_encryption_unreadable() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/corrupt-enc", base_url), vec![]).await;

    // Corrupt the bucket metadata so get_bucket_encryption returns Err
    let meta_path = tmp.path().join("buckets/corrupt-enc/.bucket.json");
    std::fs::write(&meta_path, b"{ not valid json").unwrap();

    // Plain PUT (no SSE header) → must 500, not silently store plaintext
    let put = s3_request(
        "PUT",
        &format!("{}/corrupt-enc/safe.txt", base_url),
        b"should-not-be-written".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 500);
    let body = put.text().await.unwrap();
    assert!(body.contains("InternalError"), "body: {}", body);

    // Object file must NOT exist on disk
    let obj_path = tmp.path().join("buckets/corrupt-enc/safe.txt");
    assert!(
        !obj_path.exists(),
        "object must not be written when encryption config read fails"
    );
}

/// Console API upload must fail closed (500) when bucket encryption config
/// cannot be read. Object file must NOT be written.
#[tokio::test]
async fn test_console_upload_fails_when_bucket_encryption_unreadable() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/console-corrupt", base_url), vec![]).await;

    // Corrupt bucket metadata
    let meta_path = tmp.path().join("buckets/console-corrupt/.bucket.json");
    std::fs::write(&meta_path, b"not { valid json").unwrap();

    let session = console_login(&base_url).await;
    let resp = client()
        .put(&format!(
            "{}/api/buckets/console-corrupt/upload/safe.txt",
            base_url
        ))
        .header("cookie", format!("maxio_session={}", session))
        .body(b"should-not-be-written".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);
    let body: serde_json::Value = resp.json().await.unwrap();
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err.contains("failed to read bucket encryption"),
        "unexpected error: {}",
        err
    );

    let obj_path = tmp.path().join("buckets/console-corrupt/safe.txt");
    assert!(
        !obj_path.exists(),
        "object must not be written when encryption config read fails"
    );
}

/// Console API create_folder must fail closed (500) when bucket encryption
/// config cannot be read. Folder marker must NOT be written.
#[tokio::test]
async fn test_console_create_folder_fails_when_bucket_encryption_unreadable() {
    let (base_url, tmp) = start_server().await;
    s3_request(
        "PUT",
        &format!("{}/console-corrupt-folder", base_url),
        vec![],
    )
    .await;

    let meta_path = tmp
        .path()
        .join("buckets/console-corrupt-folder/.bucket.json");
    std::fs::write(&meta_path, b"not { valid json").unwrap();

    let session = console_login(&base_url).await;
    let resp = client()
        .post(&format!(
            "{}/api/buckets/console-corrupt-folder/folders",
            base_url
        ))
        .header("cookie", format!("maxio_session={}", session))
        .json(&serde_json::json!({"name": "newdir"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);
    let body: serde_json::Value = resp.json().await.unwrap();
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err.contains("failed to read bucket encryption"),
        "unexpected error: {}",
        err
    );

    let folder_marker = tmp.path().join("buckets/console-corrupt-folder/newdir/");
    assert!(
        !folder_marker.exists(),
        "folder marker must not be written when encryption config read fails"
    );
}

/// Console API GET/PUT /api/buckets/{b}/encryption round-trips bucket default
/// encryption config. Toggles enable → disable and verifies both the response
/// body and the on-disk `.bucket.json` state.
#[tokio::test]
async fn test_console_bucket_encryption_endpoint_roundtrip() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cenc-1", base_url), vec![]).await;
    let session = console_login(&base_url).await;

    // Initial GET → disabled
    let resp = client()
        .get(&format!("{}/api/buckets/cenc-1/encryption", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], false);
    assert!(body["algorithm"].is_null());
    assert!(body["kmsMasterKeyId"].is_null());

    // PUT {enabled: true}
    let resp = client()
        .put(&format!("{}/api/buckets/cenc-1/encryption", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);

    // GET → enabled + AES256
    let resp = client()
        .get(&format!("{}/api/buckets/cenc-1/encryption", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["algorithm"], "AES256");
    assert!(body["kmsMasterKeyId"].is_null());

    // On-disk persistence
    let meta = std::fs::read_to_string(tmp.path().join("buckets/cenc-1/.bucket.json")).unwrap();
    assert!(
        meta.contains("\"sse_algorithm\": \"AES256\""),
        "bucket meta missing sse_algorithm: {}",
        meta
    );

    // PUT {enabled: false}
    let resp = client()
        .put(&format!("{}/api/buckets/cenc-1/encryption", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET → disabled again
    let resp = client()
        .get(&format!("{}/api/buckets/cenc-1/encryption", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], false);

    // encryption_config removed from bucket meta
    let meta = std::fs::read_to_string(tmp.path().join("buckets/cenc-1/.bucket.json")).unwrap();
    assert!(
        !meta.contains("encryption_config"),
        "encryption_config should be removed after disable: {}",
        meta
    );
}

/// Console API upload (`PUT /api/buckets/{b}/upload/{key}`) honors the
/// bucket's default encryption config. Previously the handler passed `None`
/// to `put_object`, bypassing the bucket default and writing plaintext.
#[tokio::test]
async fn test_console_upload_honors_bucket_default_encryption() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cenc-up", base_url), vec![]).await;
    let session = console_login(&base_url).await;

    // Enable default encryption via console API
    let resp = client()
        .put(&format!("{}/api/buckets/cenc-up/encryption", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Upload via console API
    let marker = b"plaintext-marker-AAAA".to_vec();
    let resp = client()
        .put(&format!(
            "{}/api/buckets/cenc-up/upload/hello.txt",
            base_url
        ))
        .header("cookie", format!("maxio_session={}", session))
        .body(marker.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Raw on-disk bytes must NOT contain the plaintext marker
    let on_disk = std::fs::read(tmp.path().join("buckets/cenc-up/hello.txt")).unwrap();
    assert!(
        on_disk
            .windows(marker.len())
            .all(|w| w != marker.as_slice()),
        "on-disk bytes should be ciphertext, found plaintext marker"
    );

    // Sidecar records SSE-S3 mode
    let meta_json =
        std::fs::read_to_string(tmp.path().join("buckets/cenc-up/hello.txt.meta.json")).unwrap();
    assert!(
        meta_json.contains("\"mode\": \"sse_s3\""),
        "sidecar missing sse_s3 mode: {}",
        meta_json
    );

    // Download via console API returns plaintext
    let resp = client()
        .get(&format!(
            "{}/api/buckets/cenc-up/download/hello.txt",
            base_url
        ))
        .header("cookie", format!("maxio_session={}", session))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(downloaded.as_ref(), marker.as_slice());
}

/// Console API `POST /api/buckets/{b}/folders` resolves bucket default
/// encryption without crashing when encryption is enabled. Folder markers
/// are zero-byte objects so no ciphertext assertion is possible; this is a
/// regression guard for the `create_folder` encryption-lookup fix.
#[tokio::test]
async fn test_console_create_folder_succeeds_with_bucket_default_encryption() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cenc-fold", base_url), vec![]).await;
    let session = console_login(&base_url).await;

    // Enable default encryption
    let resp = client()
        .put(&format!("{}/api/buckets/cenc-fold/encryption", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Create folder
    let resp = client()
        .post(&format!("{}/api/buckets/cenc-fold/folders", base_url))
        .header("cookie", format!("maxio_session={}", session))
        .json(&serde_json::json!({"name": "sub"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);

    // Folder marker persists on disk
    let marker_meta = tmp.path().join("buckets/cenc-fold/sub/.folder.meta.json");
    assert!(
        marker_meta.exists(),
        "folder marker sidecar missing: {:?}",
        marker_meta
    );
}

// --- Public bucket access ---

fn set_public_on_disk(tmp: &TempDir, bucket: &str, read: bool, list: bool) {
    let meta_path = tmp.path().join("buckets").join(bucket).join(".bucket.json");
    let data = std::fs::read_to_string(&meta_path).unwrap();
    let mut meta: serde_json::Value = serde_json::from_str(&data).unwrap();
    meta["public_read"] = serde_json::Value::Bool(read);
    meta["public_list"] = serde_json::Value::Bool(list);
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
}

#[tokio::test]
async fn test_public_bucket_anonymous_get() {
    let (base_url, tmp) = start_server().await;

    // Create bucket + upload an object with signed requests.
    let resp = s3_request("PUT", &format!("{}/pub-bkt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    let body = b"hello public".to_vec();
    let resp = s3_request("PUT", &format!("{}/pub-bkt/hello.txt", base_url), body).await;
    assert_eq!(resp.status(), 200);

    // Anonymous GET should be 403 before enabling public_read.
    let resp = client()
        .get(&format!("{}/pub-bkt/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Flip public_read on.
    set_public_on_disk(&tmp, "pub-bkt", true, false);

    // Anonymous GET now succeeds.
    let resp = client()
        .get(&format!("{}/pub-bkt/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"hello public");

    // Anonymous HEAD also succeeds.
    let resp = client()
        .head(&format!("{}/pub-bkt/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Anonymous list is still blocked (public_list still false).
    let resp = client()
        .get(&format!("{}/pub-bkt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Writes remain blocked.
    let resp = client()
        .put(&format!("{}/pub-bkt/blocked.txt", base_url))
        .body("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = client()
        .delete(&format!("{}/pub-bkt/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_public_bucket_list_toggle() {
    let (base_url, tmp) = start_server().await;

    let resp = s3_request("PUT", &format!("{}/pub-list", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let resp = s3_request(
        "PUT",
        &format!("{}/pub-list/a.txt", base_url),
        b"a".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // public_list off → anonymous list rejected.
    let resp = client()
        .get(&format!("{}/pub-list/?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Enable public_list, keep public_read off.
    set_public_on_disk(&tmp, "pub-list", false, true);

    let resp = client()
        .get(&format!("{}/pub-list/?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("a.txt"), "list body missing key: {}", body);

    // Object GET still blocked because public_read is false.
    let resp = client()
        .get(&format!("{}/pub-list/a.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_public_bucket_rejects_mutating_query() {
    let (base_url, tmp) = start_server().await;

    let resp = s3_request("PUT", &format!("{}/pub-mut", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Public read fully enabled.
    set_public_on_disk(&tmp, "pub-mut", true, true);

    // Anonymous GET ?versioning is a bucket sub-resource read that we deliberately block.
    let resp = client()
        .get(&format!("{}/pub-mut?versioning", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Anonymous POST ?delete remains blocked regardless of method.
    let resp = client()
        .post(&format!("{}/pub-mut?delete", base_url))
        .body("<Delete/>")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Any other subresource (old versions, config reads) also needs auth.
    for query in [
        "versions",
        "policyStatus",
        "lifecycle",
        "uploads",
        "object-lock",
    ] {
        let resp = client()
            .get(&format!("{}/pub-mut?{}", base_url, query))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "anonymous ?{query}");
    }
    let resp = client()
        .get(&format!("{}/pub-mut/key?versionId=abc", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Plain listing with list parameters stays public.
    let resp = client()
        .get(&format!(
            "{}/pub-mut?list-type=2&prefix=a&delimiter=/&max-keys=5",
            base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption hardening (Task 1 + Task 2)
// ─────────────────────────────────────────────────────────────────────────────

/// Sidecar MAC detects tampering with the object's `size` field.
#[tokio::test]
async fn test_sse_s3_sidecar_mac_catches_size_tamper() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mac-bucket", base_url), vec![]).await;

    let plaintext = b"hello integrity-bound world".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/mac-bucket/obj.txt", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    // Tamper: shrink size by 1 byte in the sidecar.
    let meta_path = tmp.path().join("buckets/mac-bucket/obj.txt.meta.json");
    let meta_str = std::fs::read_to_string(&meta_path).unwrap();
    let mut meta: serde_json::Value = serde_json::from_str(&meta_str).unwrap();
    let original = meta["size"].as_u64().unwrap();
    meta["size"] = serde_json::json!(original - 1);
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

    let get = s3_request("GET", &format!("{}/mac-bucket/obj.txt", base_url), vec![]).await;
    assert_eq!(get.status(), 400, "size tamper must be rejected by MAC");
    let body = get.text().await.unwrap();
    assert!(
        body.contains("sidecar_mac") || body.contains("integrity"),
        "body: {}",
        body
    );
}

/// Sidecar MAC detects wrapped_dek swap between two SSE-S3 objects.
#[tokio::test]
async fn test_sse_s3_sidecar_mac_catches_wrapped_dek_swap() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/swap-bucket", base_url), vec![]).await;

    for name in ["a.txt", "b.txt"] {
        let put = s3_request_with_headers(
            "PUT",
            &format!("{}/swap-bucket/{}", base_url, name),
            format!("payload-{}", name).into_bytes(),
            vec![("x-amz-server-side-encryption", "AES256")],
        )
        .await;
        assert_eq!(put.status(), 200);
    }

    let meta_a_path = tmp.path().join("buckets/swap-bucket/a.txt.meta.json");
    let meta_b_path = tmp.path().join("buckets/swap-bucket/b.txt.meta.json");
    let meta_a_str = std::fs::read_to_string(&meta_a_path).unwrap();
    let meta_b_str = std::fs::read_to_string(&meta_b_path).unwrap();
    let mut meta_a: serde_json::Value = serde_json::from_str(&meta_a_str).unwrap();
    let meta_b: serde_json::Value = serde_json::from_str(&meta_b_str).unwrap();

    // Copy b's wrapped_dek + wrap_nonce into a's sidecar (leaving a's data intact).
    meta_a["encryption"]["wrapped_dek"] = meta_b["encryption"]["wrapped_dek"].clone();
    meta_a["encryption"]["wrap_nonce"] = meta_b["encryption"]["wrap_nonce"].clone();
    std::fs::write(&meta_a_path, serde_json::to_string_pretty(&meta_a).unwrap()).unwrap();

    let get = s3_request("GET", &format!("{}/swap-bucket/a.txt", base_url), vec![]).await;
    assert_eq!(
        get.status(),
        400,
        "wrapped_dek swap must be rejected by MAC"
    );
}

/// AAD binds to bucket/key: copying the ciphertext file of object A onto the
/// path of object B (same bucket) must not decrypt cleanly under B's sidecar.
#[tokio::test]
async fn test_sse_s3_aad_catches_cross_key_ciphertext_swap() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/aad-bucket", base_url), vec![]).await;

    let plaintext = b"aad cross key test 0123456789abcdef".to_vec();
    for name in ["left.bin", "right.bin"] {
        let put = s3_request_with_headers(
            "PUT",
            &format!("{}/aad-bucket/{}", base_url, name),
            plaintext.clone(),
            vec![("x-amz-server-side-encryption", "AES256")],
        )
        .await;
        assert_eq!(put.status(), 200);
    }

    // Overwrite left.bin's ciphertext bytes with right.bin's — same DEK/nonce_prefix
    // they do not share (fresh per object), so this really exercises the AAD binding.
    let left_data_path = tmp.path().join("buckets/aad-bucket/left.bin");
    let right_data_path = tmp.path().join("buckets/aad-bucket/right.bin");
    let right_bytes = std::fs::read(&right_data_path).unwrap();
    std::fs::write(&left_data_path, &right_bytes).unwrap();

    let get_result =
        s3_request_result("GET", &format!("{}/aad-bucket/left.bin", base_url), vec![]).await;
    // Decryptor may fail before headers or mid-stream. The invariant we care
    // about is that the attacker's swapped ciphertext never yields valid
    // plaintext under the victim's sidecar.
    match get_result {
        Err(_) => {}
        Ok(get) => {
            let body_result = get.bytes().await;
            let retrieved = body_result.unwrap_or_default();
            assert_ne!(
                retrieved.as_ref(),
                plaintext.as_slice(),
                "cross-key ciphertext must not authenticate under victim's key/AAD"
            );
        }
    }
}

/// Multipart SSE-S3: part files on disk contain ciphertext (nonce at offset 0),
/// not plaintext. Confirms Task 2 encrypts parts before they touch disk.
#[tokio::test]
async fn test_multipart_sse_s3_parts_encrypted_on_disk() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mp-sse", base_url), vec![]).await;

    // Create multipart upload with SSE-S3.
    let init = s3_request_with_headers(
        "POST",
        &format!("{}/mp-sse/big.bin?uploads", base_url),
        vec![],
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(init.status(), 200);
    let init_body = init.text().await.unwrap();
    let upload_id = init_body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("UploadId in response")
        .to_string();

    // Upload one part with a distinctive plaintext pattern.
    let pattern: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let part_url = format!(
        "{}/mp-sse/big.bin?partNumber=1&uploadId={}",
        base_url, upload_id
    );
    let put_part = s3_request("PUT", &part_url, pattern.clone()).await;
    assert_eq!(put_part.status(), 200);
    let etag = put_part
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // On-disk part file: first 12 bytes should be nonce (not plaintext pattern),
    // and the whole file must NOT equal the plaintext.
    let part_path = tmp
        .path()
        .join(format!("buckets/mp-sse/.uploads/{}/1", upload_id));
    let on_disk = std::fs::read(&part_path).unwrap();
    assert_ne!(on_disk, pattern, "part file must be ciphertext on disk");
    assert!(
        on_disk.len() >= pattern.len() + 12 + 16,
        "ciphertext must include nonce + GCM tag overhead"
    );

    // Complete and verify round-trip.
    let complete_body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mp-sse/big.bin?uploadId={}", base_url, upload_id),
        complete_body.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    let get = s3_request("GET", &format!("{}/mp-sse/big.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(body.as_ref(), pattern.as_slice(), "round-trip bytes match");
}

/// Multipart SSE-C: initializing with one key and completing with a different
/// one yields HTTP 400 and explicit "SSE-C key changed" error. Without this
/// check, the server would silently accept the swap and re-encrypt with the
/// new key — corrupting the trust model.
#[tokio::test]
async fn test_multipart_sse_c_key_change_rejected() {
    use base64::Engine;
    use md5::Digest;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mp-ssec", base_url), vec![]).await;

    let key_a = [0x42u8; 32];
    let key_b = [0x99u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_a_b64 = b64.encode(key_a);
    let key_a_md5 = b64.encode(md5::Md5::digest(key_a));
    let key_b_b64 = b64.encode(key_b);
    let key_b_md5 = b64.encode(md5::Md5::digest(key_b));

    let init = s3_request_with_headers(
        "POST",
        &format!("{}/mp-ssec/o.bin?uploads", base_url),
        vec![],
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_a_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_a_md5),
        ],
    )
    .await;
    assert_eq!(init.status(), 200);
    let init_body = init.text().await.unwrap();
    let upload_id = init_body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("UploadId in response")
        .to_string();

    let pattern: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let put_part = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/mp-ssec/o.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        pattern,
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_a_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_a_md5),
        ],
    )
    .await;
    assert_eq!(put_part.status(), 200);
    let etag = put_part
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Complete with the WRONG key — must be rejected.
    let complete_body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request_with_headers(
        "POST",
        &format!("{}/mp-ssec/o.bin?uploadId={}", base_url, upload_id),
        complete_body.into_bytes(),
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_b_md5),
        ],
    )
    .await;
    assert_eq!(complete.status(), 400);
    let body = complete.text().await.unwrap();
    assert!(
        body.contains("SSE-C key changed") || body.contains("MD5 mismatch"),
        "body: {}",
        body
    );

    // Failed CompleteMultipartUpload must preserve the upload for retry/abort.
    let list_parts = s3_request(
        "GET",
        &format!("{}/mp-ssec/o.bin?uploadId={}", base_url, upload_id),
        vec![],
    )
    .await;
    assert_eq!(list_parts.status(), 200);
}

/// Multipart SSE-C positive path: same customer key on Create, UploadPart,
/// Complete, and GET must round-trip. Missing key on GET must fail.
#[tokio::test]
async fn test_multipart_sse_c_roundtrip_with_matching_key() {
    use base64::Engine;
    use md5::Digest;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mp-ssec-ok", base_url), vec![]).await;

    let key = [0x5Au8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_b64 = b64.encode(key);
    let key_md5 = b64.encode(md5::Md5::digest(key));
    let headers = vec![
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        (
            "x-amz-server-side-encryption-customer-key",
            key_b64.as_str(),
        ),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            key_md5.as_str(),
        ),
    ];

    let init = s3_request_with_headers(
        "POST",
        &format!("{}/mp-ssec-ok/o.bin?uploads", base_url),
        vec![],
        headers.clone(),
    )
    .await;
    assert_eq!(init.status(), 200);
    let init_body = init.text().await.unwrap();
    let upload_id = init_body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("UploadId")
        .to_string();

    let plaintext: Vec<u8> = (0..256_000u32).map(|i| (i % 251) as u8).collect();
    let put_part = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/mp-ssec-ok/o.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        plaintext.clone(),
        headers.clone(),
    )
    .await;
    assert_eq!(put_part.status(), 200);
    let etag = put_part
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let complete_body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request_with_headers(
        "POST",
        &format!("{}/mp-ssec-ok/o.bin?uploadId={}", base_url, upload_id),
        complete_body.into_bytes(),
        headers.clone(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    let missing_key = s3_request("GET", &format!("{}/mp-ssec-ok/o.bin", base_url), vec![]).await;
    assert_ne!(missing_key.status(), 200);

    let get = s3_request_with_headers(
        "GET",
        &format!("{}/mp-ssec-ok/o.bin", base_url),
        vec![],
        headers,
    )
    .await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().to_vec(), plaintext);
}

/// SSE-C headers on a non-SSE object → 400 InvalidArgument (matches AWS).
#[tokio::test]
async fn test_sse_c_headers_on_plaintext_rejected() {
    use base64::Engine;
    use md5::Digest;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/plain-bucket", base_url), vec![]).await;

    let put = s3_request(
        "PUT",
        &format!("{}/plain-bucket/plain.txt", base_url),
        b"no encryption here".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);

    let key = [0x55u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_b64 = b64.encode(key);
    let key_md5 = b64.encode(md5::Md5::digest(key));

    let get = s3_request_with_headers(
        "GET",
        &format!("{}/plain-bucket/plain.txt", base_url),
        vec![],
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_md5),
        ],
    )
    .await;
    assert_eq!(get.status(), 400);
    let body = get.text().await.unwrap();
    assert!(body.contains("SSE-C headers supplied"), "body: {}", body);
}

/// Multipart `part.encrypted` flag flipped in on-disk meta is caught at
/// `Complete` — prevents "part meta says plaintext, ciphertext on disk gets
/// served as plaintext bytes" attack.
#[tokio::test]
async fn test_multipart_part_encrypted_flag_tamper_rejected() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/part-flip", base_url), vec![]).await;

    let init = s3_request_with_headers(
        "POST",
        &format!("{}/part-flip/o.bin?uploads", base_url),
        vec![],
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(init.status(), 200);
    let init_body = init.text().await.unwrap();
    let upload_id = init_body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("UploadId")
        .to_string();

    let pattern: Vec<u8> = vec![0xABu8; 5 * 1024 * 1024];
    let put_part = s3_request(
        "PUT",
        &format!(
            "{}/part-flip/o.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        pattern,
    )
    .await;
    assert_eq!(put_part.status(), 200);
    let etag = put_part
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Flip `encrypted: true` → `false` in part meta.
    let part_meta_path = tmp.path().join(format!(
        "buckets/part-flip/.uploads/{}/1.meta.json",
        upload_id
    ));
    let pm_str = std::fs::read_to_string(&part_meta_path).unwrap();
    let mut pm: serde_json::Value = serde_json::from_str(&pm_str).unwrap();
    pm["encrypted"] = serde_json::json!(false);
    std::fs::write(&part_meta_path, serde_json::to_string_pretty(&pm).unwrap()).unwrap();

    let complete_body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!("{}/part-flip/o.bin?uploadId={}", base_url, upload_id),
        complete_body.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 400);
    let body = complete.text().await.unwrap();
    assert!(body.contains("encryption flag"), "body: {}", body);
}

/// Versioned SSE-S3: ?versionId GET decrypts correctly (Task 2 fix — previously
/// returned raw ciphertext).
#[tokio::test]
async fn test_sse_s3_versioned_get_decrypts() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/ver-sse", base_url), vec![]).await;
    // Enable versioning.
    let vxml =
        b"<?xml version=\"1.0\"?><VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
            .to_vec();
    s3_request("PUT", &format!("{}/ver-sse?versioning", base_url), vxml).await;

    let plaintext = b"versioned encrypted payload".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/ver-sse/v.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);
    let version_id = put
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Overwrite with a second version so the first becomes historical.
    s3_request_with_headers(
        "PUT",
        &format!("{}/ver-sse/v.bin", base_url),
        b"replacement".to_vec(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;

    // GET by explicit versionId — must decrypt, not return ciphertext.
    let get = s3_request(
        "GET",
        &format!("{}/ver-sse/v.bin?versionId={}", base_url, version_id),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        plaintext.as_slice(),
        "versioned GET must decrypt"
    );
}

/// Multipart SSE-C: UploadPart with a mismatched customer key is rejected on
/// the part upload itself (not just at Complete). Closes the "keyA init, keyB
/// upload" gap alongside the Complete check.
#[tokio::test]
async fn test_multipart_sse_c_part_key_mismatch_rejected() {
    use base64::Engine;
    use md5::Digest;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mp-ssec-part", base_url), vec![]).await;

    let key_a = [0x11u8; 32];
    let key_b = [0xEEu8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_a_b64 = b64.encode(key_a);
    let key_a_md5 = b64.encode(md5::Md5::digest(key_a));
    let key_b_b64 = b64.encode(key_b);
    let key_b_md5 = b64.encode(md5::Md5::digest(key_b));

    let init = s3_request_with_headers(
        "POST",
        &format!("{}/mp-ssec-part/o.bin?uploads", base_url),
        vec![],
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_a_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_a_md5),
        ],
    )
    .await;
    assert_eq!(init.status(), 200);
    let init_body = init.text().await.unwrap();
    let upload_id = init_body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("UploadId in response")
        .to_string();

    // UploadPart with key B → must be rejected.
    let pattern: Vec<u8> = vec![0u8; 5 * 1024 * 1024];
    let put_part = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/mp-ssec-part/o.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        pattern,
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_b_md5),
        ],
    )
    .await;
    assert_eq!(put_part.status(), 400);
    let body = put_part.text().await.unwrap();
    assert!(body.contains("MD5 mismatch"), "body: {}", body);
}

/// Tampering with `chunk_size` in the sidecar changes frame boundary math on
/// reads. The sidecar MAC covers `chunk_size`, so the attack is rejected
/// before any ciphertext is read.
#[tokio::test]
async fn test_sse_s3_chunk_size_tamper_rejected() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/chunk-tamper", base_url), vec![]).await;

    let plaintext = b"chunk-size tamper probe".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/chunk-tamper/x.bin", base_url),
        plaintext,
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    let meta_path = tmp.path().join("buckets/chunk-tamper/x.bin.meta.json");
    let meta_str = std::fs::read_to_string(&meta_path).unwrap();
    let mut meta: serde_json::Value = serde_json::from_str(&meta_str).unwrap();
    meta["encryption"]["chunk_size"] = serde_json::json!(128u32);
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

    let get = s3_request("GET", &format!("{}/chunk-tamper/x.bin", base_url), vec![]).await;
    assert_eq!(
        get.status(),
        400,
        "chunk_size tamper must be caught by sidecar MAC"
    );
}

/// Tampering with `version_id` in the sidecar changes the AAD input used for
/// frame decryption. Even if the MAC did not cover it (which it does), the
/// GCM auth tag binds to the original version_id via the AAD scheme.
#[tokio::test]
async fn test_sse_s3_version_id_tamper_rejected() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/vid-tamper", base_url), vec![]).await;
    let vxml =
        b"<?xml version=\"1.0\"?><VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
            .to_vec();
    s3_request("PUT", &format!("{}/vid-tamper?versioning", base_url), vxml).await;

    let plaintext = b"version-id-tamper probe".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/vid-tamper/x.bin", base_url),
        plaintext,
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    let meta_path = tmp.path().join("buckets/vid-tamper/x.bin.meta.json");
    let meta_str = std::fs::read_to_string(&meta_path).unwrap();
    let mut meta: serde_json::Value = serde_json::from_str(&meta_str).unwrap();
    meta["version_id"] = serde_json::json!("FORGED_VERSION_ID");
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

    let get = s3_request("GET", &format!("{}/vid-tamper/x.bin", base_url), vec![]).await;
    assert_eq!(
        get.status(),
        400,
        "version_id tamper must be caught (MAC and/or AAD)"
    );
}

/// Swapping ciphertext between two versions of the same key still fails: the
/// AAD builder captures the *current* version's `version_id`, so a file
/// written under a different version_id cannot authenticate.
#[tokio::test]
async fn test_sse_s3_cross_version_ciphertext_swap_rejected() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/ver-swap", base_url), vec![]).await;
    let vxml =
        b"<?xml version=\"1.0\"?><VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
            .to_vec();
    s3_request("PUT", &format!("{}/ver-swap?versioning", base_url), vxml).await;

    // Write two versions, equal length so a byte-swap does not change file size.
    let plaintext_a = vec![0xAAu8; 4096];
    let plaintext_b = vec![0xBBu8; 4096];
    let put_a = s3_request_with_headers(
        "PUT",
        &format!("{}/ver-swap/k.bin", base_url),
        plaintext_a.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put_a.status(), 200);
    let vid_a = put_a
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let put_b = s3_request_with_headers(
        "PUT",
        &format!("{}/ver-swap/k.bin", base_url),
        plaintext_b.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put_b.status(), 200);
    let vid_b = put_b
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Overwrite version A's data file with version B's ciphertext bytes.
    let ver_a_data = tmp
        .path()
        .join(format!("buckets/ver-swap/.versions/k.bin/{}.data", vid_a));
    let ver_b_data = tmp
        .path()
        .join(format!("buckets/ver-swap/.versions/k.bin/{}.data", vid_b));
    let b_bytes = std::fs::read(&ver_b_data).unwrap();
    std::fs::write(&ver_a_data, &b_bytes).unwrap();

    // Depending on timing the server may abort the connection before OR after
    // the response headers, so a transport-level send error is itself a valid
    // rejection. Only when a response arrives do we inspect the bytes.
    let get = s3_request_result(
        "GET",
        &format!("{}/ver-swap/k.bin?versionId={}", base_url, vid_a),
        vec![],
    )
    .await;
    if let Ok(resp) = get {
        // Decryptor fails mid-stream on AAD mismatch; assertion: bytes returned
        // do NOT equal plaintext_a (the attacker's goal was to substitute B's
        // data for A's without detection).
        let body = resp.bytes().await.unwrap_or_default();
        assert_ne!(
            body.as_ref(),
            plaintext_a.as_slice(),
            "cross-version ciphertext swap must not authenticate"
        );
        assert_ne!(
            body.as_ref(),
            plaintext_b.as_slice(),
            "cross-version swap must not yield B's plaintext either"
        );
    }
}

/// 0-byte SSE-S3 object: PUT + GET round-trip. Sidecar MAC + AAD path must
/// handle the empty-frame edge case without erroring.
#[tokio::test]
async fn test_sse_s3_empty_object_round_trip() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/empty-sse", base_url), vec![]).await;

    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/empty-sse/zero.bin", base_url),
        vec![],
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    // On-disk data file must be 0 bytes (no frames emitted for empty input).
    let on_disk = std::fs::read(tmp.path().join("buckets/empty-sse/zero.bin")).unwrap();
    assert_eq!(on_disk.len(), 0, "empty SSE object writes no frames");

    // Sidecar still carries encryption block + MAC.
    let meta_str =
        std::fs::read_to_string(tmp.path().join("buckets/empty-sse/zero.bin.meta.json")).unwrap();
    assert!(meta_str.contains("\"sidecar_mac\""));

    let get = s3_request("GET", &format!("{}/empty-sse/zero.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.headers().get("content-length").unwrap(), "0");
    let body = get.bytes().await.unwrap();
    assert_eq!(body.len(), 0, "GET must return 0 bytes");
}

/// Erasure coding + SSE compose via encrypt-then-EC: ciphertext is chunked and
/// (optionally) parity-encoded. PUT must succeed, on-disk chunks must be
/// ciphertext (not plaintext), and GET must return the original plaintext.
#[tokio::test]
async fn test_ec_plus_encryption_roundtrip() {
    let (base_url, tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/ec-enc", base_url), vec![]).await;

    let plaintext = b"ec-plus-sse composes via encrypt-then-EC".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-enc/x.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256"),
    );

    // On-disk chunk 000000 should be ciphertext (at minimum not a prefix match).
    let chunk = tmp.path().join("buckets/ec-enc/x.bin.ec/000000");
    let disk = std::fs::read(&chunk).expect("read chunk 000000");
    assert_ne!(
        &disk[..plaintext.len().min(disk.len())],
        &plaintext[..plaintext.len().min(disk.len())],
        "EC chunk contains plaintext — encryption did not run"
    );

    let get = s3_request("GET", &format!("{}/ec-enc/x.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    let got = get.bytes().await.unwrap().to_vec();
    assert_eq!(got, plaintext);
}

/// EC + SSE overwrite: replacement must atomically swap the EC chunk directory
/// and sidecar together enough that the latest object remains decryptable.
#[tokio::test]
async fn test_ec_plus_encryption_overwrite_reads_latest() {
    let (base_url, tmp) = start_server_ec_parity(1024, 0).await;
    s3_request("PUT", &format!("{}/ec-enc-overwrite", base_url), vec![]).await;

    let first: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let put1 = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-enc-overwrite/o.bin", base_url),
        first,
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put1.status(), 200);

    let meta_path = tmp.path().join("buckets/ec-enc-overwrite/o.bin.meta.json");
    let meta1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    let nonce1 = meta1["encryption"]["nonce_prefix"]
        .as_str()
        .unwrap()
        .to_string();

    let second: Vec<u8> = (0..75_000u32)
        .map(|i| (i.wrapping_mul(17) % 256) as u8)
        .collect();
    let put2 = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-enc-overwrite/o.bin", base_url),
        second.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put2.status(), 200);

    let meta2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_ne!(
        nonce1,
        meta2["encryption"]["nonce_prefix"].as_str().unwrap(),
        "overwrite must publish fresh encryption metadata"
    );

    let get = s3_request(
        "GET",
        &format!("{}/ec-enc-overwrite/o.bin", base_url),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().to_vec(), second);
}

async fn start_server_ec_parity(chunk_size: u64, parity_shards: u32) -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, true, chunk_size, parity_shards, keyring)
        .await
        .unwrap();

    let config = Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        region: REGION.to_string(),
        master_key: None,
        master_key_file: None,
        allow_missing_master_key: false,
        allow_insecure_dev: true,
        secure_cookies: false,
        erasure_coding: true,
        chunk_size,
        parity_shards,
        default_buckets: String::new(),
        max_console_body_bytes: 1024 * 1024,
        ..Config::default()
    };

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

/// EC + SSE-S3 with a payload large enough to span several 64 KiB frames and
/// several 1 KiB EC chunks. Frame boundaries crossing chunk boundaries is the
/// interesting composition case — RS has to reassemble ciphertext byte-exact
/// before AEAD tags verify.
#[tokio::test]
async fn test_ec_plus_encryption_multi_frame_roundtrip() {
    let (base_url, _tmp) = start_server_ec_parity(1024, 0).await;
    s3_request("PUT", &format!("{}/ec-enc-multi", base_url), vec![]).await;

    // ~200 KiB of deterministic pseudo-random bytes → ~3 frames and ~200 chunks.
    let plaintext: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(31) % 256) as u8)
        .collect();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-enc-multi/big.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    let get = s3_request("GET", &format!("{}/ec-enc-multi/big.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().to_vec(), plaintext);
}

/// EC + SSE-S3 range read across a chunk boundary.
#[tokio::test]
async fn test_ec_plus_encryption_range_read() {
    let (base_url, _tmp) = start_server_ec_parity(1024, 0).await;
    s3_request("PUT", &format!("{}/ec-enc-range", base_url), vec![]).await;

    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-enc-range/f.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    let range_start = 70_000u64;
    let range_end = 80_000u64;
    let got = s3_request_with_headers(
        "GET",
        &format!("{}/ec-enc-range/f.bin", base_url),
        vec![],
        vec![("range", &format!("bytes={}-{}", range_start, range_end))],
    )
    .await;
    assert_eq!(got.status(), 206);
    let body = got.bytes().await.unwrap().to_vec();
    assert_eq!(body, plaintext[range_start as usize..=range_end as usize]);
}

/// EC + SSE-S3 + parity: corrupt one data chunk on disk, GET must still succeed
/// via Reed-Solomon reconstruction and AEAD tag verification must pass over
/// the reconstructed ciphertext.
#[tokio::test]
async fn test_ec_plus_encryption_parity_recovers_corruption() {
    let (base_url, tmp) = start_server_ec_parity(1024, 2).await;
    s3_request("PUT", &format!("{}/ec-enc-rs", base_url), vec![]).await;

    let plaintext: Vec<u8> = (0..50_000u32).map(|i| (i % 256) as u8).collect();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-enc-rs/r.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    // Zero out chunk 000001. Two parity shards remain so reconstruction succeeds.
    let chunk = tmp.path().join("buckets/ec-enc-rs/r.bin.ec/000001");
    let sz = std::fs::metadata(&chunk).unwrap().len() as usize;
    std::fs::write(&chunk, vec![0u8; sz]).unwrap();

    let get = s3_request("GET", &format!("{}/ec-enc-rs/r.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().to_vec(), plaintext);
}

/// Even if chunk-level SHA-256 is updated to match tampered ciphertext, the
/// per-frame AEAD tag must still reject. This is the composition security
/// invariant: encryption is the authoritative integrity check.
#[tokio::test]
async fn test_ec_plus_encryption_aead_catches_manifest_bypass() {
    let (base_url, tmp) = start_server_ec_parity(1024, 0).await;
    s3_request("PUT", &format!("{}/ec-enc-aead", base_url), vec![]).await;

    let plaintext: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-enc-aead/a.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    // Flip a byte in chunk 0 and update manifest's SHA for that chunk so the
    // chunk-reader integrity check accepts the tampered data. AEAD must still
    // reject because the ciphertext bytes no longer match the GCM tag.
    let chunk_path = tmp.path().join("buckets/ec-enc-aead/a.bin.ec/000000");
    let mut chunk = std::fs::read(&chunk_path).unwrap();
    chunk[50] ^= 0xFF;
    std::fs::write(&chunk_path, &chunk).unwrap();

    let manifest_path = tmp
        .path()
        .join("buckets/ec-enc-aead/a.bin.ec/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let new_sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&chunk));
    manifest["chunks"][0]["sha256"] = serde_json::Value::String(new_sha);
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // AEAD failures abort mid-stream, which reqwest surfaces as an
    // IncompleteMessage connection error. Any of three outcomes are acceptable
    // so long as we do NOT get the original plaintext back.
    let url = format!("{}/ec-enc-aead/a.bin", base_url);
    let mut headers: Vec<(String, String)> = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);
    let client = client();
    let mut builder = client.get(&url);
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    match builder.send().await {
        Err(_) => {} // Connection dropped mid-stream — AEAD caught it.
        Ok(resp) => {
            let status = resp.status();
            let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            assert!(
                !status.is_success() || body != plaintext,
                "AEAD did not catch tampering: status={}, body len={}",
                status,
                body.len()
            );
        }
    }
}

/// EC + bucket-default SSE: PUT without SSE header should still store ciphertext
/// chunks (policy inherited from bucket encryption config).
#[tokio::test]
async fn test_ec_plus_bucket_default_encryption() {
    let (base_url, tmp) = start_server_ec_parity(1024, 0).await;
    s3_request("PUT", &format!("{}/ec-default", base_url), vec![]).await;

    // Configure bucket default encryption (AES256).
    let cfg = r#"<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"#;
    let resp = s3_request(
        "PUT",
        &format!("{}/ec-default?encryption", base_url),
        cfg.as_bytes().to_vec(),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "put-bucket-encryption: {}",
        resp.status()
    );

    let plaintext = b"bucket default EC-SSE".to_vec();
    let put = s3_request(
        "PUT",
        &format!("{}/ec-default/d.bin", base_url),
        plaintext.clone(),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256"),
        "PUT response missing x-amz-server-side-encryption"
    );

    let chunk = tmp.path().join("buckets/ec-default/d.bin.ec/000000");
    let disk = std::fs::read(&chunk).expect("chunk 000000");
    assert_ne!(
        &disk[..plaintext.len().min(disk.len())],
        &plaintext[..plaintext.len().min(disk.len())],
        "bucket-default did not encrypt the EC chunk"
    );

    let get = s3_request("GET", &format!("{}/ec-default/d.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().to_vec(), plaintext);
}

// ─── Presigned URL + SSE ────────────────────────────────────────────────────

/// Presigned GET on an SSE-S3 object: server unwraps DEK transparently, no
/// extra headers required from caller.
#[tokio::test]
async fn test_presigned_get_sse_s3_object() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/presign-sse-s3", base_url), vec![]).await;

    let plaintext = b"presigned + SSE-S3".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/presign-sse-s3/o.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put.status(), 200);

    let presigned = presign_url(&base_url, "GET", "/presign-sse-s3/o.bin", 300);
    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), plaintext.as_slice());
}

/// Presigned GET on an SSE-C object: customer-key headers must accompany the
/// GET even when the URL itself is presigned. Without them, the server cannot
/// decrypt → non-200.
#[tokio::test]
async fn test_presigned_get_sse_c_requires_key_header() {
    use base64::Engine;
    use md5::Digest;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/presign-sse-c", base_url), vec![]).await;

    let key = [0x33u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_b64 = b64.encode(key);
    let key_md5 = b64.encode(md5::Md5::digest(key));

    let plaintext = b"presigned + SSE-C".to_vec();
    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/presign-sse-c/o.bin", base_url),
        plaintext.clone(),
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_md5),
        ],
    )
    .await;
    assert_eq!(put.status(), 200);

    let presigned = presign_url(&base_url, "GET", "/presign-sse-c/o.bin", 300);

    // No customer key headers → must NOT decrypt successfully.
    let resp_no_key = client().get(&presigned).send().await.unwrap();
    let no_key_body = resp_no_key.bytes().await.unwrap_or_default();
    assert_ne!(
        no_key_body.as_ref(),
        plaintext.as_slice(),
        "presigned SSE-C GET without customer key must not return plaintext"
    );

    // With matching customer key headers → 200 + plaintext.
    let resp_ok = client()
        .get(&presigned)
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), 200);
    assert_eq!(
        resp_ok.bytes().await.unwrap().as_ref(),
        plaintext.as_slice()
    );
}

/// Presigned HEAD on an SSE-S3 object reports the encryption mode in response
/// headers without needing extra request headers.
#[tokio::test]
async fn test_presigned_head_sse_s3_object() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/presign-head-sse", base_url), vec![]).await;

    let plaintext = b"hello".to_vec();
    s3_request_with_headers(
        "PUT",
        &format!("{}/presign-head-sse/o.bin", base_url),
        plaintext,
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;

    let presigned = presign_url(&base_url, "HEAD", "/presign-head-sse/o.bin", 300);
    let resp = client().head(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );
}

// ─── CopyObject + SSE ───────────────────────────────────────────────────────

/// Copy plaintext source → SSE-S3 destination by attaching SSE header on the
/// copy request. Destination must be encrypted on disk and decrypt on GET.
#[tokio::test]
async fn test_copy_object_plaintext_to_sse_s3() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cp-pt-sse", base_url), vec![]).await;

    let plaintext = b"plaintext source body".to_vec();
    s3_request(
        "PUT",
        &format!("{}/cp-pt-sse/src.bin", base_url),
        plaintext.clone(),
    )
    .await;

    let copy = s3_request_with_headers(
        "PUT",
        &format!("{}/cp-pt-sse/dst.bin", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/cp-pt-sse/src.bin"),
            ("x-amz-server-side-encryption", "AES256"),
        ],
    )
    .await;
    assert_eq!(copy.status(), 200);

    // Destination sidecar carries SSE-S3 metadata.
    let dst_meta =
        std::fs::read_to_string(tmp.path().join("buckets/cp-pt-sse/dst.bin.meta.json")).unwrap();
    assert!(
        dst_meta.contains("\"mode\": \"sse_s3\""),
        "dst meta: {}",
        dst_meta
    );

    // Source sidecar has no encryption block.
    let src_meta =
        std::fs::read_to_string(tmp.path().join("buckets/cp-pt-sse/src.bin.meta.json")).unwrap();
    assert!(
        !src_meta.contains("\"mode\": \"sse_s3\""),
        "src must remain plaintext"
    );

    let get = s3_request("GET", &format!("{}/cp-pt-sse/dst.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().as_ref(), plaintext.as_slice());
}

/// Copy SSE-S3 source → SSE-S3 destination: each object must use a fresh DEK.
/// Compares the wrapped_dek field in the two sidecars to prove re-keying.
#[tokio::test]
async fn test_copy_object_sse_s3_to_sse_s3_rekeys() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cp-sse-sse", base_url), vec![]).await;

    let plaintext: Vec<u8> = (0..8192u32).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/cp-sse-sse/src.bin", base_url),
        plaintext.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;

    let copy = s3_request_with_headers(
        "PUT",
        &format!("{}/cp-sse-sse/dst.bin", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/cp-sse-sse/src.bin"),
            ("x-amz-server-side-encryption", "AES256"),
        ],
    )
    .await;
    assert_eq!(copy.status(), 200);

    let src_meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join("buckets/cp-sse-sse/src.bin.meta.json")).unwrap(),
    )
    .unwrap();
    let dst_meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join("buckets/cp-sse-sse/dst.bin.meta.json")).unwrap(),
    )
    .unwrap();
    let src_dek = src_meta["encryption"]["wrapped_dek"]
        .as_str()
        .expect("src wrapped_dek");
    let dst_dek = dst_meta["encryption"]["wrapped_dek"]
        .as_str()
        .expect("dst wrapped_dek");
    assert_ne!(
        src_dek, dst_dek,
        "copy must generate a fresh DEK on the destination"
    );

    let get = s3_request("GET", &format!("{}/cp-sse-sse/dst.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().to_vec(), plaintext);
}

/// Copy SSE-C key A source → SSE-C key B destination: source key supplied via
/// copy-source-* headers, dest key via standard SSE-C headers. GET with key B
/// succeeds; GET with key A on the destination fails.
#[tokio::test]
async fn test_copy_object_sse_c_to_sse_c_different_key() {
    use base64::Engine;
    use md5::Digest;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cp-ssec", base_url), vec![]).await;

    let key_a = [0x11u8; 32];
    let key_b = [0xEEu8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_a_b64 = b64.encode(key_a);
    let key_a_md5 = b64.encode(md5::Md5::digest(key_a));
    let key_b_b64 = b64.encode(key_b);
    let key_b_md5 = b64.encode(md5::Md5::digest(key_b));

    let plaintext = b"copy me with a different key".to_vec();
    s3_request_with_headers(
        "PUT",
        &format!("{}/cp-ssec/src.bin", base_url),
        plaintext.clone(),
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_a_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_a_md5),
        ],
    )
    .await;

    let copy = s3_request_with_headers(
        "PUT",
        &format!("{}/cp-ssec/dst.bin", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/cp-ssec/src.bin"),
            (
                "x-amz-copy-source-server-side-encryption-customer-algorithm",
                "AES256",
            ),
            (
                "x-amz-copy-source-server-side-encryption-customer-key",
                &key_a_b64,
            ),
            (
                "x-amz-copy-source-server-side-encryption-customer-key-md5",
                &key_a_md5,
            ),
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_b_md5),
        ],
    )
    .await;
    assert_eq!(copy.status(), 200);

    // GET destination with key B → plaintext.
    let get_ok = s3_request_with_headers(
        "GET",
        &format!("{}/cp-ssec/dst.bin", base_url),
        vec![],
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_b_md5),
        ],
    )
    .await;
    assert_eq!(get_ok.status(), 200);
    assert_eq!(get_ok.bytes().await.unwrap().as_ref(), plaintext.as_slice());

    // GET destination with key A → must fail (dest is encrypted under key B).
    let get_wrong = s3_request_with_headers(
        "GET",
        &format!("{}/cp-ssec/dst.bin", base_url),
        vec![],
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_a_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_a_md5),
        ],
    )
    .await;
    assert_ne!(get_wrong.status(), 200);
}

/// Copy SSE-C source with the WRONG copy-source key fails — server cannot
/// decrypt the source so the copy must abort, not silently return ciphertext.
#[tokio::test]
async fn test_copy_object_sse_c_wrong_source_key_fails() {
    use base64::Engine;
    use md5::Digest;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/cp-ssec-bad", base_url), vec![]).await;

    let key_a = [0x77u8; 32];
    let key_x = [0x00u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_a_b64 = b64.encode(key_a);
    let key_a_md5 = b64.encode(md5::Md5::digest(key_a));
    let key_x_b64 = b64.encode(key_x);
    let key_x_md5 = b64.encode(md5::Md5::digest(key_x));

    s3_request_with_headers(
        "PUT",
        &format!("{}/cp-ssec-bad/src.bin", base_url),
        b"sensitive data".to_vec(),
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_a_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_a_md5),
        ],
    )
    .await;

    let missing_key_copy = s3_request_with_headers(
        "PUT",
        &format!("{}/cp-ssec-bad/missing-key-dst.bin", base_url),
        vec![],
        vec![("x-amz-copy-source", "/cp-ssec-bad/src.bin")],
    )
    .await;
    assert_eq!(
        missing_key_copy.status(),
        400,
        "copy without source SSE-C key should be a client error, not InternalError"
    );
    let body = missing_key_copy.text().await.unwrap();
    assert!(
        body.contains("SSE-C: customer key required"),
        "body: {}",
        body
    );

    let copy = s3_request_with_headers(
        "PUT",
        &format!("{}/cp-ssec-bad/dst.bin", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/cp-ssec-bad/src.bin"),
            (
                "x-amz-copy-source-server-side-encryption-customer-algorithm",
                "AES256",
            ),
            (
                "x-amz-copy-source-server-side-encryption-customer-key",
                &key_x_b64,
            ),
            (
                "x-amz-copy-source-server-side-encryption-customer-key-md5",
                &key_x_md5,
            ),
        ],
    )
    .await;
    assert_ne!(
        copy.status(),
        200,
        "copy with wrong source SSE-C key must not succeed"
    );
}

// ─── UploadPartCopy + SSE ───────────────────────────────────────────────────

/// UploadPartCopy from an SSE-S3 source into a non-encrypted multipart upload.
/// The server must decrypt the source before staging the part, so the final
/// destination object is plaintext bytes that match the original input.
#[tokio::test]
async fn test_upload_part_copy_sse_s3_source() {
    let (base, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/upc-sse-src", base), vec![]).await;
    let src_data: Vec<u8> = (0u8..255).cycle().take(5 * 1024 * 1024).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/upc-sse-src/source.bin", base),
        src_data.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;

    s3_request("PUT", &format!("{}/upc-sse-dst", base), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/upc-sse-dst/dest.bin?uploads=", base),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let resp = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/upc-sse-dst/dest.bin?partNumber=1&uploadId={}",
            base, upload_id
        ),
        vec![],
        vec![("x-amz-copy-source", "/upc-sse-src/source.bin")],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let etag = extract_xml_tag(&resp.text().await.unwrap(), "ETag").unwrap();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!("{}/upc-sse-dst/dest.bin?uploadId={}", base, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    let get = s3_request("GET", &format!("{}/upc-sse-dst/dest.bin", base), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().as_ref(), src_data.as_slice());
}

/// UploadPartCopy from a plaintext source into an SSE-S3 multipart upload.
/// Destination object must end up encrypted on disk and decrypt on GET.
#[tokio::test]
async fn test_upload_part_copy_into_sse_s3_dest() {
    let (base, tmp) = start_server().await;

    s3_request("PUT", &format!("{}/upc-pt-src", base), vec![]).await;
    let src_data: Vec<u8> = (0u8..255).cycle().take(5 * 1024 * 1024).collect();
    s3_request(
        "PUT",
        &format!("{}/upc-pt-src/source.bin", base),
        src_data.clone(),
    )
    .await;

    s3_request("PUT", &format!("{}/upc-pt-dst", base), vec![]).await;
    let create = s3_request_with_headers(
        "POST",
        &format!("{}/upc-pt-dst/dest.bin?uploads=", base),
        vec![],
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let resp = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/upc-pt-dst/dest.bin?partNumber=1&uploadId={}",
            base, upload_id
        ),
        vec![],
        vec![("x-amz-copy-source", "/upc-pt-src/source.bin")],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let etag = extract_xml_tag(&resp.text().await.unwrap(), "ETag").unwrap();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!("{}/upc-pt-dst/dest.bin?uploadId={}", base, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    let dst_meta =
        std::fs::read_to_string(tmp.path().join("buckets/upc-pt-dst/dest.bin.meta.json")).unwrap();
    assert!(
        dst_meta.contains("\"mode\": \"sse_s3\""),
        "dst meta missing sse_s3: {}",
        dst_meta
    );

    let get = s3_request("GET", &format!("{}/upc-pt-dst/dest.bin", base), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(
        get.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );
    assert_eq!(get.bytes().await.unwrap().as_ref(), src_data.as_slice());
}

// ─── EC + SSE cross-object chunk swap ───────────────────────────────────────

/// AAD must bind ciphertext to the object identity. Even if RS reconstruction
/// produces a syntactically valid frame, the GCM tag must reject when the
/// ciphertext belongs to a different object.
#[tokio::test]
async fn test_ec_plus_encryption_chunk_swap_rejected() {
    let (base_url, tmp) = start_server_ec_parity(1024, 0).await;
    s3_request("PUT", &format!("{}/ec-aad-swap", base_url), vec![]).await;

    // Equal-length plaintexts so cross-object byte-for-byte chunk swaps are
    // possible without changing file sizes.
    let plaintext_a: Vec<u8> = (0..8_000u32).map(|i| (i % 251) as u8).collect();
    let plaintext_b: Vec<u8> = (0..8_000u32).map(|i| ((i + 7) % 241) as u8).collect();

    let put_a = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-aad-swap/a.bin", base_url),
        plaintext_a.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put_a.status(), 200);
    let put_b = s3_request_with_headers(
        "PUT",
        &format!("{}/ec-aad-swap/b.bin", base_url),
        plaintext_b.clone(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(put_b.status(), 200);

    // Replace b's chunk 000000 with a's chunk 000000.
    let chunk_a = tmp.path().join("buckets/ec-aad-swap/a.bin.ec/000000");
    let chunk_b = tmp.path().join("buckets/ec-aad-swap/b.bin.ec/000000");
    let a_bytes = std::fs::read(&chunk_a).expect("read a chunk 0");
    std::fs::write(&chunk_b, &a_bytes).unwrap();

    // GET b → AEAD must reject; outcome is either non-200, a connection drop,
    // or partial bytes that do not equal plaintext_b. Crucially, the response
    // must NOT be plaintext_a (would mean the swap succeeded undetected).
    let url = format!("{}/ec-aad-swap/b.bin", base_url);
    let mut headers: Vec<(String, String)> = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);
    let mut builder = client().get(&url);
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    match builder.send().await {
        Err(_) => {} // Stream torn down mid-flight.
        Ok(resp) => {
            let status = resp.status();
            let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            assert_ne!(
                body, plaintext_a,
                "cross-object chunk swap must not yield A's plaintext"
            );
            assert!(
                !status.is_success() || body != plaintext_b,
                "cross-object chunk swap must not yield B's plaintext either"
            );
        }
    }
}

// --- Data-safety regression tests (stable-release hardening) ---

fn test_bucket_meta(name: &str) -> maxio::storage::BucketMeta {
    maxio::storage::BucketMeta {
        name: name.to_string(),
        created_at: "2026-01-01T00:00:00.000Z".to_string(),
        region: "us-east-1".to_string(),
        versioning: false,
        cors_rules: None,
        encryption_config: None,
        public_read: false,
        public_list: false,
        versioning_suspended: false,
        tags: None,
        lifecycle: None,
    }
}

/// Enabling versioning must protect the pre-versioning object: an overwrite
/// must archive it as the "null" version instead of destroying it.
#[tokio::test]
async fn test_null_version_preserved_on_overwrite() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/nullver", base_url), vec![]).await;

    let original = b"pre-versioning content".to_vec();
    let put = s3_request(
        "PUT",
        &format!("{}/nullver/doc.txt", base_url),
        original.clone(),
    )
    .await;
    assert_eq!(put.status(), 200);

    let vxml = b"<?xml version=\"1.0\"?><VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/nullver?versioning", base_url), vxml).await;

    let put2 = s3_request(
        "PUT",
        &format!("{}/nullver/doc.txt", base_url),
        b"new versioned content".to_vec(),
    )
    .await;
    assert_eq!(put2.status(), 200);

    // Current object is the new content.
    let get = s3_request("GET", &format!("{}/nullver/doc.txt", base_url), vec![]).await;
    assert_eq!(
        get.bytes().await.unwrap().as_ref(),
        b"new versioned content"
    );

    // The pre-versioning object must still be retrievable as version "null".
    let get_null = s3_request(
        "GET",
        &format!("{}/nullver/doc.txt?versionId=null", base_url),
        vec![],
    )
    .await;
    assert_eq!(get_null.status(), 200, "null version must be preserved");
    assert_eq!(
        get_null.bytes().await.unwrap().as_ref(),
        original.as_slice()
    );
}

/// Deleting the newest version must fall back to the archived null version,
/// restoring the pre-versioning object as current.
#[tokio::test]
async fn test_null_version_restored_after_newest_version_deleted() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/nullrestore", base_url), vec![]).await;

    let original = b"original null-version bytes".to_vec();
    s3_request(
        "PUT",
        &format!("{}/nullrestore/doc.txt", base_url),
        original.clone(),
    )
    .await;

    let vxml = b"<?xml version=\"1.0\"?><VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/nullrestore?versioning", base_url), vxml).await;

    let put2 = s3_request(
        "PUT",
        &format!("{}/nullrestore/doc.txt", base_url),
        b"v2 bytes".to_vec(),
    )
    .await;
    let vid2 = put2
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let del = s3_request(
        "DELETE",
        &format!("{}/nullrestore/doc.txt?versionId={}", base_url, vid2),
        vec![],
    )
    .await;
    assert!(
        del.status().is_success(),
        "delete of v2 failed: {}",
        del.status()
    );

    // The null version must be promoted back to current.
    let get = s3_request("GET", &format!("{}/nullrestore/doc.txt", base_url), vec![]).await;
    assert_eq!(
        get.status(),
        200,
        "null version must be restored as current"
    );
    assert_eq!(get.bytes().await.unwrap().as_ref(), original.as_slice());
}

/// Deleting a versioned object (delete marker) must preserve the
/// pre-versioning object as the retrievable "null" version.
#[tokio::test]
async fn test_null_version_preserved_on_delete_marker() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/nulldel", base_url), vec![]).await;

    let original = b"protect me".to_vec();
    s3_request(
        "PUT",
        &format!("{}/nulldel/doc.txt", base_url),
        original.clone(),
    )
    .await;

    let vxml = b"<?xml version=\"1.0\"?><VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/nulldel?versioning", base_url), vxml).await;

    // Simple delete → delete marker.
    let del = s3_request("DELETE", &format!("{}/nulldel/doc.txt", base_url), vec![]).await;
    assert!(del.status().is_success());

    // Current GET is a 404 (delete marker) ...
    let get = s3_request("GET", &format!("{}/nulldel/doc.txt", base_url), vec![]).await;
    assert_eq!(get.status(), 404);

    // ... but the null version still holds the data.
    let get_null = s3_request(
        "GET",
        &format!("{}/nulldel/doc.txt?versionId=null", base_url),
        vec![],
    )
    .await;
    assert_eq!(
        get_null.status(),
        200,
        "delete marker must not destroy the null version"
    );
    assert_eq!(
        get_null.bytes().await.unwrap().as_ref(),
        original.as_slice()
    );
}

/// CompleteMultipartUpload with parts out of ascending order must be rejected
/// with InvalidPartOrder, like AWS S3 — not concatenated in client order.
#[tokio::test]
async fn test_multipart_invalid_part_order_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/order.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = b"tail".to_vec();
    let e1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/order.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        p1,
    )
    .await
    .headers()
    .get("etag")
    .unwrap()
    .to_str()
    .unwrap()
    .to_string();
    let e2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/order.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        p2,
    )
    .await
    .headers()
    .get("etag")
    .unwrap()
    .to_str()
    .unwrap()
    .to_string();

    // Parts listed as 2, 1 — must be rejected.
    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e2, e1
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/order.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 400);
    let body = complete.text().await.unwrap();
    assert!(
        body.contains("InvalidPartOrder"),
        "expected InvalidPartOrder, got: {}",
        body
    );

    // Duplicate part numbers must be rejected too.
    let dup_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e1
    );
    let dup = s3_request(
        "POST",
        &format!("{}/mybucket/order.bin?uploadId={}", base_url, upload_id),
        dup_xml.into_bytes(),
    )
    .await;
    assert_eq!(dup.status(), 400);
}

/// A part file whose bytes were corrupted on disk (same size, valid sidecar)
/// must fail CompleteMultipartUpload instead of producing a silently corrupt
/// object with a "matching" composite ETag.
#[tokio::test]
async fn test_multipart_complete_rejects_tampered_part() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/tamper.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = vec![b'b'; 1024];
    let e1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/tamper.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        p1,
    )
    .await
    .headers()
    .get("etag")
    .unwrap()
    .to_str()
    .unwrap()
    .to_string();
    let e2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/tamper.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        p2,
    )
    .await
    .headers()
    .get("etag")
    .unwrap()
    .to_str()
    .unwrap()
    .to_string();

    // Corrupt part 2 on disk: same length, different bytes → sidecar ETag no
    // longer matches the data.
    let part2_path = tmp
        .path()
        .join(format!("buckets/mybucket/.uploads/{}/2", upload_id));
    std::fs::write(&part2_path, vec![b'X'; 1024]).unwrap();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/tamper.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(
        complete.status(),
        400,
        "tampered part must fail Complete, not corrupt the object"
    );

    // No object must have been published.
    let get = s3_request("GET", &format!("{}/mybucket/tamper.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 404);
}

/// Hammer one key with concurrent overwrites of different sizes; the final
/// object must be exactly one of the payloads, never a torn mix of one
/// writer's data with another writer's metadata.
#[tokio::test]
async fn test_concurrent_puts_same_key_stay_consistent() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/racebucket", base_url), vec![]).await;

    let payload_a = vec![b'a'; 300 * 1024]; // above the small-object threshold
    let payload_b = vec![b'b'; 100 * 1024]; // below it

    let mut handles = Vec::new();
    for i in 0..8 {
        let url = format!("{}/racebucket/contended.bin", base_url);
        let body = if i % 2 == 0 {
            payload_a.clone()
        } else {
            payload_b.clone()
        };
        handles.push(tokio::spawn(async move {
            let resp = s3_request("PUT", &url, body).await;
            assert_eq!(resp.status(), 200);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let get = s3_request(
        "GET",
        &format!("{}/racebucket/contended.bin", base_url),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 200);
    let content_length: usize = get
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body = get.bytes().await.unwrap();
    assert_eq!(
        content_length,
        body.len(),
        "Content-Length must match the actual body"
    );
    assert!(
        body.as_ref() == payload_a.as_slice() || body.as_ref() == payload_b.as_slice(),
        "object must be exactly one writer's payload, got {} bytes",
        body.len()
    );
}

/// Housekeeping must never delete the temp file of an in-flight (young) write.
#[tokio::test]
async fn test_housekeeping_keeps_fresh_temp_files() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();
    storage
        .create_bucket(&test_bucket_meta("fresh"))
        .await
        .unwrap();

    let temp_path = tmp
        .path()
        .join("buckets/fresh/.maxio-tmp-11111111-2222-3333-4444-555555555555");
    std::fs::write(&temp_path, b"in-flight upload bytes").unwrap();

    storage.housekeeping_sweep(chrono::Duration::days(7)).await;
    assert!(
        temp_path.exists(),
        "young temp file of an in-flight write must survive the sweep"
    );
}

/// Housekeeping must restore a crash-stranded EC publish backup when the
/// original path is missing (the publish died mid-swap).
#[tokio::test]
async fn test_housekeeping_restores_stranded_backup() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
    let storage = FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
        .await
        .unwrap();
    storage
        .create_bucket(&test_bucket_meta("bak"))
        .await
        .unwrap();

    // Simulate: publish moved `obj.ec` aside as `.maxio-bak-obj.ec` and then
    // crashed before renaming the new dir in.
    let backup = tmp.path().join("buckets/bak/.maxio-bak-obj.bin.ec");
    std::fs::create_dir_all(&backup).unwrap();
    std::fs::write(backup.join("000000"), b"committed chunk data").unwrap();
    // Age the backup past the 1-hour recovery gate.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
    let times = std::fs::FileTimes::new().set_modified(old);
    std::fs::File::open(&backup)
        .unwrap()
        .set_times(times)
        .unwrap();

    storage.housekeeping_sweep(chrono::Duration::days(7)).await;

    let restored = tmp.path().join("buckets/bak/obj.bin.ec");
    assert!(
        restored.is_dir(),
        "stranded backup must be restored to the original path"
    );
    assert_eq!(
        std::fs::read(restored.join("000000")).unwrap(),
        b"committed chunk data"
    );
    assert!(!backup.exists(), "backup name must be gone after restore");
}

/// An empty `delimiter=` query parameter means "no delimiter" (AWS semantics).
/// mc sends `delimiter=` on recursive listings; it must list all keys instead
/// of collapsing everything into one empty CommonPrefix.
#[tokio::test]
async fn test_list_objects_empty_delimiter_means_no_delimiter() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/listbucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/listbucket/a/b/one.txt", base_url),
        b"1".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/listbucket/two.txt", base_url),
        b"2".to_vec(),
    )
    .await;

    let resp = s3_request(
        "GET",
        &format!("{}/listbucket/?delimiter=&list-type=2&prefix=", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>a/b/one.txt</Key>"), "body: {}", body);
    assert!(body.contains("<Key>two.txt</Key>"), "body: {}", body);
    assert!(
        !body.contains("<CommonPrefixes>"),
        "empty delimiter must not produce CommonPrefixes: {}",
        body
    );
}

/// A crash-leftover `.maxio-tmp-*` file must not block DeleteBucket.
#[tokio::test]
async fn test_delete_bucket_ignores_crash_leftover_temps() {
    let (base_url, tmp) = start_server().await;
    s3_request("PUT", &format!("{}/crashbucket", base_url), vec![]).await;

    // Simulate a temp file stranded by a crashed PUT.
    std::fs::write(
        tmp.path()
            .join("buckets/crashbucket/.maxio-tmp-dead-beef-dead-beef"),
        b"partial bytes from a crashed write",
    )
    .unwrap();

    let del = s3_request("DELETE", &format!("{}/crashbucket", base_url), vec![]).await;
    assert_eq!(
        del.status(),
        204,
        "crash leftovers must not block bucket deletion"
    );
    let head = s3_request("HEAD", &format!("{}/crashbucket", base_url), vec![]).await;
    assert_eq!(head.status(), 404);
}

#[tokio::test]
async fn test_ui_without_trailing_slash_redirects_to_ui_root() {
    let (base_url, _tmp) = start_server().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    for (path, location) in [("/ui", "/ui/"), ("/ui?next=x", "/ui/?next=x")] {
        let resp = client
            .get(format!("{}{}", base_url, path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 308, "{path}");
        assert_eq!(resp.headers()["location"], location, "{path}");
    }
}

// ---- bucket subresources (agent A) ----

fn a_all_tags(body: &str, tag: &str) -> Vec<String> {
    let start = format!("<{}>", tag);
    let end = format!("</{}>", tag);
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find(&start) {
        let from = i + start.len();
        let Some(j) = rest[from..].find(&end) else {
            break;
        };
        out.push(rest[from..from + j].to_string());
        rest = &rest[from + j + end.len()..];
    }
    out
}

fn a_common_prefixes(body: &str) -> Vec<String> {
    a_all_tags(body, "CommonPrefixes")
        .iter()
        .filter_map(|cp| extract_xml_tag(cp, "Prefix"))
        .collect()
}

fn a_contents_keys(body: &str) -> Vec<String> {
    a_all_tags(body, "Contents")
        .iter()
        .filter_map(|c| extract_xml_tag(c, "Key"))
        .collect()
}

#[tokio::test]
async fn test_a_unknown_bucket_subresources_never_fall_through() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/subres", base), vec![]).await;
    s3_request("PUT", &format!("{}/subres/keep.txt", base), b"x".to_vec()).await;

    for (method, q, status) in [
        ("DELETE", "lifecycle", 204),
        ("DELETE", "website", 204),
        ("DELETE", "replication", 204),
        ("DELETE", "ownershipControls", 204),
        ("DELETE", "publicAccessBlock", 204),
        ("DELETE", "analytics", 501),
        ("DELETE", "inventory", 501),
        ("DELETE", "object-lock", 501),
        ("PUT", "lifecycle", 400), // implemented: empty body is MalformedXML
        ("PUT", "analytics", 501),
        ("PUT", "website", 501),
        ("PUT", "object-lock", 501),
        ("GET", "analytics", 501),
        ("GET", "metrics", 501),
        ("GET", "delete", 501),
    ] {
        let resp = s3_request(method, &format!("{}/subres?{}", base, q), vec![]).await;
        assert_eq!(resp.status(), status, "{} ?{}", method, q);
        if status == 501 {
            let body = resp.text().await.unwrap();
            assert!(body.contains("<Code>NotImplemented</Code>"), "{}", body);
        }
    }

    // POST without ?delete must not run DeleteObjects.
    let body = b"<Delete><Object><Key>keep.txt</Key></Object></Delete>".to_vec();
    let resp = s3_request("POST", &format!("{}/subres", base), body).await;
    assert_eq!(resp.status(), 501);

    // Bucket and object survived everything.
    let resp = s3_request("HEAD", &format!("{}/subres", base), vec![]).await;
    assert_eq!(resp.status(), 200);
    let resp = s3_request("GET", &format!("{}/subres/keep.txt", base), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_a_terraform_bucket_reads() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/tfreads", base), vec![]).await;

    for (q, status, needle) in [
        (
            "lifecycle",
            404,
            "<Code>NoSuchLifecycleConfiguration</Code>",
        ),
        (
            "object-lock",
            404,
            "<Code>ObjectLockConfigurationNotFoundError</Code>",
        ),
        ("website", 404, "<Code>NoSuchWebsiteConfiguration</Code>"),
        (
            "replication",
            404,
            "<Code>ReplicationConfigurationNotFoundError</Code>",
        ),
        (
            "ownershipControls",
            404,
            "<Code>OwnershipControlsNotFoundError</Code>",
        ),
        (
            "publicAccessBlock",
            404,
            "<Code>NoSuchPublicAccessBlockConfiguration</Code>",
        ),
        (
            "logging",
            200,
            "<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"",
        ),
        (
            "notification",
            200,
            "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"",
        ),
        ("requestPayment", 200, "<Payer>BucketOwner</Payer>"),
        (
            "accelerate",
            200,
            "<AccelerateConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"",
        ),
        ("tagging", 404, "<Code>NoSuchTagSet</Code>"),
        ("policy", 404, "<Code>NoSuchBucketPolicy</Code>"),
    ] {
        let resp = s3_request("GET", &format!("{}/tfreads?{}", base, q), vec![]).await;
        assert_eq!(resp.status(), status, "GET ?{}", q);
        let body = resp.text().await.unwrap();
        assert!(body.contains(needle), "GET ?{}: {}", q, body);
    }

    // Missing bucket still reports NoSuchBucket for subresources.
    let resp = s3_request("GET", &format!("{}/nobucket-a?lifecycle", base), vec![]).await;
    assert_eq!(resp.status(), 404);
    assert!(resp.text().await.unwrap().contains("NoSuchBucket"));
    let resp = s3_request("DELETE", &format!("{}/nobucket-a?lifecycle", base), vec![]).await;
    assert_eq!(resp.status(), 404);
}

fn a_mc_download_policy(bucket: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetBucketLocation"],"Resource":["arn:aws:s3:::{b}"]}},{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::{b}"]}},{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::{b}/*"]}}]}}"#,
        b = bucket
    )
}

#[tokio::test]
async fn test_a_bucket_policy_maps_to_public_flags() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/polb", base), vec![]).await;
    s3_request("PUT", &format!("{}/polb/o.txt", base), b"hi".to_vec()).await;

    let resp = s3_request("GET", &format!("{}/polb?policyStatus", base), vec![]).await;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<IsPublic>false</IsPublic>")
    );

    let anon = client()
        .get(format!("{}/polb/o.txt", base))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 403);

    // Invalid JSON
    let resp = s3_request("PUT", &format!("{}/polb?policy", base), b"{nope".to_vec()).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("MalformedPolicy"));

    // Write access is not expressible -> 501, nothing changes.
    let rw = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::polb/*"]}]}"#;
    let resp = s3_request(
        "PUT",
        &format!("{}/polb?policy", base),
        rw.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 501);
    let resp = s3_request("GET", &format!("{}/polb?policy", base), vec![]).await;
    assert_eq!(resp.status(), 404);

    // Deny / prefix resource / condition -> 501
    for bad in [
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polb/*"}]}"#,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polb/private/*"}]}"#,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:root"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::polb/*"}]}"#,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::polb","Condition":{"StringEquals":{"s3:prefix":["a"]}}}]}"#,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::otherbucket/*"}]}"#,
    ] {
        let resp = s3_request(
            "PUT",
            &format!("{}/polb?policy", base),
            bad.as_bytes().to_vec(),
        )
        .await;
        assert_eq!(resp.status(), 501, "{}", bad);
    }

    // mc anonymous set download
    let resp = s3_request(
        "PUT",
        &format!("{}/polb?policy", base),
        a_mc_download_policy("polb").into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = s3_request("GET", &format!("{}/polb?policy", base), vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");
    let json: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(json["Version"], "2012-10-17");
    let text = json.to_string();
    assert!(text.contains("s3:GetObject") && text.contains("s3:ListBucket"));
    assert!(text.contains("arn:aws:s3:::polb/*"));

    let resp = s3_request("GET", &format!("{}/polb?policyStatus", base), vec![]).await;
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<IsPublic>true</IsPublic>")
    );

    let anon = client()
        .get(format!("{}/polb/o.txt", base))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 200);
    let anon = client().get(format!("{}/polb", base)).send().await.unwrap();
    assert_eq!(anon.status(), 200);

    // Read-only (GetObject only) policy with string principal/action/resource.
    let ro = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::polb/*"}}"#;
    let resp = s3_request(
        "PUT",
        &format!("{}/polb?policy", base),
        ro.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 204);
    let anon = client().get(format!("{}/polb", base)).send().await.unwrap();
    assert_eq!(anon.status(), 403);
    let anon = client()
        .get(format!("{}/polb/o.txt", base))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 200);

    let resp = s3_request("DELETE", &format!("{}/polb?policy", base), vec![]).await;
    assert_eq!(resp.status(), 204);
    let resp = s3_request("GET", &format!("{}/polb?policy", base), vec![]).await;
    assert_eq!(resp.status(), 404);
    assert!(resp.text().await.unwrap().contains("NoSuchBucketPolicy"));
    let anon = client()
        .get(format!("{}/polb/o.txt", base))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 403);
}

#[tokio::test]
async fn test_a_bucket_acl() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/aclb", base), vec![]).await;

    let resp = s3_request("GET", &format!("{}/aclb?acl", base), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""),
        "{}",
        body
    );
    assert!(body.contains("<ID>maxio</ID>"));
    assert!(body.contains("<Permission>FULL_CONTROL</Permission>"));
    assert!(!body.contains("AllUsers"));

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/aclb?acl", base),
        vec![],
        vec![("x-amz-acl", "private")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    let owner_only = r#"<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>maxio</ID><DisplayName>maxio</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>maxio</ID><DisplayName>maxio</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>"#;
    let resp = s3_request(
        "PUT",
        &format!("{}/aclb?acl", base),
        owner_only.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/aclb?acl", base),
        vec![],
        vec![("x-amz-acl", "public-read")],
    )
    .await;
    assert_eq!(resp.status(), 501);

    let public = r#"<AccessControlPolicy><Owner><ID>maxio</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>maxio</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>"#;
    let resp = s3_request(
        "PUT",
        &format!("{}/aclb?acl", base),
        public.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 501);

    // Public list via policy shows up as an AllUsers READ grant.
    s3_request(
        "PUT",
        &format!("{}/aclb?policy", base),
        a_mc_download_policy("aclb").into_bytes(),
    )
    .await;
    let resp = s3_request("GET", &format!("{}/aclb?acl", base), vec![]).await;
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("http://acs.amazonaws.com/groups/global/AllUsers"),
        "{}",
        body
    );
}

#[tokio::test]
async fn test_a_bucket_tagging() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/tagb", base), vec![]).await;

    let resp = s3_request("GET", &format!("{}/tagb?tagging", base), vec![]).await;
    assert_eq!(resp.status(), 404);
    assert!(resp.text().await.unwrap().contains("NoSuchTagSet"));

    let xml = "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag><Tag><Key>team</Key><Value>a&amp;b</Value></Tag></TagSet></Tagging>";
    let resp = s3_request(
        "PUT",
        &format!("{}/tagb?tagging", base),
        xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = s3_request("GET", &format!("{}/tagb?tagging", base), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<Key>env</Key><Value>prod</Value>"),
        "{}",
        body
    );
    assert!(body.contains("<Value>a&amp;b</Value>"), "{}", body);

    // Too many tags
    let mut many = String::from("<Tagging><TagSet>");
    for i in 0..51 {
        many.push_str(&format!("<Tag><Key>k{}</Key><Value>v</Value></Tag>", i));
    }
    many.push_str("</TagSet></Tagging>");
    let resp = s3_request("PUT", &format!("{}/tagb?tagging", base), many.into_bytes()).await;
    assert_eq!(resp.status(), 400);

    // Duplicate keys
    let dup = "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>a</Key><Value>2</Value></Tag></TagSet></Tagging>";
    let resp = s3_request(
        "PUT",
        &format!("{}/tagb?tagging", base),
        dup.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 400);

    // Malformed
    let resp = s3_request(
        "PUT",
        &format!("{}/tagb?tagging", base),
        b"<Tagging><TagSet>".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 400);

    // Old tags remain after rejected updates.
    let resp = s3_request("GET", &format!("{}/tagb?tagging", base), vec![]).await;
    assert!(resp.text().await.unwrap().contains("<Key>env</Key>"));

    let resp = s3_request("DELETE", &format!("{}/tagb?tagging", base), vec![]).await;
    assert_eq!(resp.status(), 204);
    let resp = s3_request("GET", &format!("{}/tagb?tagging", base), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_a_versioning_suspended_status() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/vsusp", base), vec![]).await;

    let resp = s3_request("GET", &format!("{}/vsusp?versioning", base), vec![]).await;
    assert!(!resp.text().await.unwrap().contains("<Status>"));

    let enable =
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/vsusp?versioning", base), enable).await;
    let resp = s3_request("GET", &format!("{}/vsusp?versioning", base), vec![]).await;
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<Status>Enabled</Status>")
    );

    let suspend =
        b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>".to_vec();
    let resp = s3_request("PUT", &format!("{}/vsusp?versioning", base), suspend).await;
    assert_eq!(resp.status(), 200);
    let resp = s3_request("GET", &format!("{}/vsusp?versioning", base), vec![]).await;
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<Status>Suspended</Status>")
    );

    let resp = s3_request(
        "PUT",
        &format!("{}/vsusp?versioning", base),
        b"<VersioningConfiguration/>".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

/// S3 interleaves `<Version>` and `<DeleteMarker>` in key order, newest
/// first; minio-go (`mc ls --versions`) relies on it.
#[tokio::test]
async fn test_list_object_versions_interleaves_delete_markers() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lvi", base), vec![]).await;
    let enable =
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/lvi?versioning", base), enable).await;
    s3_request("PUT", &format!("{}/lvi/f", base), b"1".to_vec()).await;
    s3_request("DELETE", &format!("{}/lvi/f", base), vec![]).await;
    s3_request("PUT", &format!("{}/lvi/g", base), b"2".to_vec()).await;

    let body = s3_request("GET", &format!("{}/lvi?versions", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    let marker = body.find("<DeleteMarker>").expect("delete marker");
    let version_f = body.find("<Version><Key>f</Key>").expect("version f");
    let version_g = body.find("<Version><Key>g</Key>").expect("version g");
    assert!(marker < version_f && version_f < version_g, "{}", body);
}

#[tokio::test]
async fn test_a_list_object_versions_pagination() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lvp", base), vec![]).await;
    let enable =
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/lvp?versioning", base), enable).await;

    for (key, n) in [("a.txt", 3), ("dir/x", 1), ("dir/y", 2), ("z.txt", 1)] {
        for i in 0..n {
            s3_request(
                "PUT",
                &format!("{}/lvp/{}", base, key),
                format!("{}", i).into_bytes(),
            )
            .await;
        }
    }

    // Prefix filter
    let resp = s3_request(
        "GET",
        &format!("{}/lvp?versions&prefix=dir%2F", base),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert_eq!(a_all_tags(&body, "Version").len(), 3, "{}", body);

    // Delimiter rolls dir/ up into a CommonPrefix.
    let resp = s3_request(
        "GET",
        &format!("{}/lvp?versions&delimiter=%2F", base),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert_eq!(
        a_common_prefixes(&body),
        vec!["dir/".to_string()],
        "{}",
        body
    );
    assert_eq!(a_all_tags(&body, "Version").len(), 4, "{}", body);
    assert!(body.contains("<Delimiter>/</Delimiter>"));

    // Page with max-keys=2 across everything, collecting (key, version) pairs.
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut key_marker = String::new();
    let mut vid_marker = String::new();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages < 20);
        let mut url = format!("{}/lvp?versions&max-keys=2", base);
        if !key_marker.is_empty() {
            url.push_str(&format!("&key-marker={}", percent_encode_s3(&key_marker)));
        }
        if !vid_marker.is_empty() {
            url.push_str(&format!(
                "&version-id-marker={}",
                percent_encode_s3(&vid_marker)
            ));
        }
        let body = s3_request("GET", &url, vec![]).await.text().await.unwrap();
        assert!(body.contains("<MaxKeys>2</MaxKeys>"));
        let versions = a_all_tags(&body, "Version");
        assert!(versions.len() <= 2);
        for v in &versions {
            seen.push((
                extract_xml_tag(v, "Key").unwrap(),
                extract_xml_tag(v, "VersionId").unwrap(),
            ));
        }
        if extract_xml_tag(&body, "IsTruncated").as_deref() != Some("true") {
            break;
        }
        key_marker = extract_xml_tag(&body, "NextKeyMarker").unwrap();
        vid_marker = extract_xml_tag(&body, "NextVersionIdMarker").unwrap_or_default();
    }
    assert_eq!(seen.len(), 7, "{:?}", seen);
    let keys: Vec<&str> = seen.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "a.txt", "a.txt", "a.txt", "dir/x", "dir/y", "dir/y", "z.txt"
        ]
    );
    let mut uniq = seen.clone();
    uniq.dedup();
    assert_eq!(uniq.len(), 7);

    // Newest first: the first a.txt version is the latest.
    let body = s3_request("GET", &format!("{}/lvp?versions&max-keys=1", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert!(body.contains("<IsLatest>true</IsLatest>"), "{}", body);

    // Delimiter + max-keys=1 paging: CommonPrefix appears once.
    let mut cps = Vec::new();
    let mut n_versions = 0;
    let mut key_marker = String::new();
    let mut vid_marker = String::new();
    for _ in 0..20 {
        let mut url = format!("{}/lvp?versions&delimiter=%2F&max-keys=1", base);
        if !key_marker.is_empty() {
            url.push_str(&format!("&key-marker={}", percent_encode_s3(&key_marker)));
        }
        if !vid_marker.is_empty() {
            url.push_str(&format!(
                "&version-id-marker={}",
                percent_encode_s3(&vid_marker)
            ));
        }
        let body = s3_request("GET", &url, vec![]).await.text().await.unwrap();
        cps.extend(a_common_prefixes(&body));
        n_versions += a_all_tags(&body, "Version").len();
        if extract_xml_tag(&body, "IsTruncated").as_deref() != Some("true") {
            break;
        }
        key_marker = extract_xml_tag(&body, "NextKeyMarker").unwrap();
        vid_marker = extract_xml_tag(&body, "NextVersionIdMarker").unwrap_or_default();
    }
    assert_eq!(cps, vec!["dir/".to_string()]);
    assert_eq!(n_versions, 4);
}

async fn a_seed_delimiter_bucket(base: &str, bucket: &str) {
    s3_request("PUT", &format!("{}/{}", base, bucket), vec![]).await;
    for key in ["a.txt", "b/1", "b/2", "b/3", "c.txt", "d/1"] {
        s3_request(
            "PUT",
            &format!("{}/{}/{}", base, bucket, key),
            b"x".to_vec(),
        )
        .await;
    }
}

#[tokio::test]
async fn test_a_list_v2_delimiter_pagination() {
    let (base, _tmp) = start_server().await;
    a_seed_delimiter_bucket(&base, "ldv2").await;

    let mut items = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..20 {
        let mut url = format!("{}/ldv2?list-type=2&delimiter=%2F&max-keys=1", base);
        if let Some(t) = &token {
            url.push_str(&format!("&continuation-token={}", percent_encode_s3(t)));
        }
        let body = s3_request("GET", &url, vec![]).await.text().await.unwrap();
        let keys = a_contents_keys(&body);
        let cps = a_common_prefixes(&body);
        assert_eq!(keys.len() + cps.len(), 1, "{}", body);
        assert_eq!(extract_xml_tag(&body, "KeyCount").as_deref(), Some("1"));
        items.extend(keys);
        items.extend(cps);
        if extract_xml_tag(&body, "IsTruncated").as_deref() != Some("true") {
            break;
        }
        token = extract_xml_tag(&body, "NextContinuationToken");
    }
    assert_eq!(items, vec!["a.txt", "b/", "c.txt", "d/"]);

    // max-keys=2: Contents + CommonPrefixes count together.
    let body = s3_request(
        "GET",
        &format!("{}/ldv2?list-type=2&delimiter=%2F&max-keys=2", base),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert_eq!(a_contents_keys(&body), vec!["a.txt"]);
    assert_eq!(a_common_prefixes(&body), vec!["b/"]);
    assert!(body.contains("<IsTruncated>true</IsTruncated>"));

    // start-after inside a common prefix does not repeat it.
    let body = s3_request(
        "GET",
        &format!("{}/ldv2?list-type=2&delimiter=%2F&start-after=b%2F1", base),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert_eq!(a_common_prefixes(&body), vec!["d/"]);
    assert_eq!(a_contents_keys(&body), vec!["c.txt"]);
}

#[tokio::test]
async fn test_a_list_v1_delimiter_pagination() {
    let (base, _tmp) = start_server().await;
    a_seed_delimiter_bucket(&base, "ldv1").await;

    let mut items = Vec::new();
    let mut marker: Option<String> = None;
    for _ in 0..20 {
        let mut url = format!("{}/ldv1?delimiter=%2F&max-keys=1", base);
        if let Some(m) = &marker {
            url.push_str(&format!("&marker={}", percent_encode_s3(m)));
        }
        let body = s3_request("GET", &url, vec![]).await.text().await.unwrap();
        let keys = a_contents_keys(&body);
        let cps = a_common_prefixes(&body);
        assert_eq!(keys.len() + cps.len(), 1, "{}", body);
        items.extend(keys);
        items.extend(cps);
        if extract_xml_tag(&body, "IsTruncated").as_deref() != Some("true") {
            break;
        }
        marker = extract_xml_tag(&body, "NextMarker");
    }
    assert_eq!(items, vec!["a.txt", "b/", "c.txt", "d/"]);

    // Listing inside a prefix whose folder marker equals the prefix.
    s3_request("PUT", &format!("{}/ldv1/b/", base), vec![]).await;
    let body = s3_request(
        "GET",
        &format!("{}/ldv1?prefix=b%2F&delimiter=%2F&marker=b%2F", base),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert_eq!(a_contents_keys(&body), vec!["b/1", "b/2", "b/3"]);
}

#[tokio::test]
async fn test_a_list_encoding_type_and_fetch_owner() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/encb", base), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/encb/dir%20x/sp%20ace%2Bplus.txt", base),
        b"x".to_vec(),
    )
    .await;
    s3_request("PUT", &format!("{}/encb/top%20file", base), b"x".to_vec()).await;

    let body = s3_request(
        "GET",
        &format!("{}/encb?list-type=2&encoding-type=url", base),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(
        body.contains("<EncodingType>url</EncodingType>"),
        "{}",
        body
    );
    assert!(
        body.contains("<Key>dir%20x/sp%20ace%2Bplus.txt</Key>"),
        "{}",
        body
    );
    assert!(!body.contains("<Owner>"));

    let body = s3_request(
        "GET",
        &format!("{}/encb?list-type=2&encoding-type=url&delimiter=%2F", base),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert_eq!(a_common_prefixes(&body), vec!["dir%20x/"]);
    assert_eq!(a_contents_keys(&body), vec!["top%20file"]);

    let body = s3_request(
        "GET",
        &format!("{}/encb?list-type=2&fetch-owner=true", base),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(
        body.contains("<Owner><ID>maxio</ID><DisplayName>maxio</DisplayName></Owner>"),
        "{}",
        body
    );
    assert!(body.contains("<Key>top file</Key>"));

    let body = s3_request("GET", &format!("{}/encb?encoding-type=url", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("<EncodingType>url</EncodingType>"),
        "{}",
        body
    );
    assert!(body.contains("<Key>top%20file</Key>"), "{}", body);

    let resp = s3_request(
        "GET",
        &format!("{}/encb?list-type=2&encoding-type=bogus", base),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_a_minio_health_endpoints() {
    let (base, _tmp) = start_server().await;
    for path in [
        "/minio/health/live",
        "/minio/health/ready",
        "/minio/health/cluster",
    ] {
        let resp = client()
            .get(format!("{}{}", base, path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "GET {}", path);
        let resp = client()
            .head(format!("{}{}", base, path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "HEAD {}", path);
    }
}

// ---- streaming chunked uploads (agent B) ----

/// Signing material for building aws-chunked bodies in tests.
struct StreamSigner {
    signing_key: Vec<u8>,
    amz_date: String,
    scope: String,
    seed_signature: String,
}

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

impl StreamSigner {
    fn hmac_hex(&self, data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).unwrap();
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn chunk_signature(&self, prev: &str, data: &[u8]) -> String {
        self.hmac_hex(&format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.amz_date,
            self.scope,
            prev,
            EMPTY_SHA256,
            hex::encode(Sha256::digest(data))
        ))
    }

    fn trailer_signature(&self, prev: &str, trailer_lines: &str) -> String {
        self.hmac_hex(&format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.amz_date,
            self.scope,
            prev,
            hex::encode(Sha256::digest(trailer_lines.as_bytes()))
        ))
    }

    /// Signed aws-chunked body. `trailer` = (header-name, value) for the -TRAILER variant.
    /// `corrupt_chunk` flips the signature of that chunk index.
    fn signed_body(
        &self,
        chunks: &[&[u8]],
        trailer: Option<(&str, &str)>,
        corrupt_chunk: Option<usize>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = self.seed_signature.clone();
        let all: Vec<&[u8]> = chunks
            .iter()
            .copied()
            .chain(std::iter::once(&b""[..]))
            .collect();
        for (i, data) in all.iter().enumerate() {
            let mut sig = self.chunk_signature(&prev, data);
            prev = sig.clone();
            if corrupt_chunk == Some(i) {
                sig = "f".repeat(64);
            }
            out.extend_from_slice(
                format!("{:x};chunk-signature={}\r\n", data.len(), sig).as_bytes(),
            );
            if !data.is_empty() {
                out.extend_from_slice(data);
                out.extend_from_slice(b"\r\n");
            }
        }
        if let Some((name, value)) = trailer {
            let line = format!("{}:{}\n", name, value);
            let tsig = self.trailer_signature(&prev, &line);
            out.extend_from_slice(format!("{}:{}\r\n", name, value).as_bytes());
            out.extend_from_slice(format!("x-amz-trailer-signature:{}\r\n", tsig).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

/// Unsigned aws-chunked body with an optional trailer.
fn unsigned_trailer_body(chunks: &[&[u8]], trailer: Option<(&str, &str)>) -> Vec<u8> {
    let mut out = Vec::new();
    for data in chunks {
        out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    if let Some((name, value)) = trailer {
        out.extend_from_slice(format!("{}:{}\r\n", name, value).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn crc32_b64(data: &[u8]) -> String {
    b64(&crc32fast::hash(data).to_be_bytes())
}

/// Send a streaming PUT. `extra` headers are signed. The body is produced by
/// `build` once the seed signature is known.
async fn streaming_put(
    method: &str,
    url: &str,
    content_sha256: &str,
    extra: Vec<(&str, String)>,
    build: impl FnOnce(&StreamSigner) -> Vec<u8>,
) -> reqwest::Response {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host_header = format!("{}:{}", parsed.host_str().unwrap(), parsed.port().unwrap());
    let path = parsed.path().to_string();
    let query = parsed.query().unwrap_or("").to_string();

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), host_header),
        ("x-amz-content-sha256".into(), content_sha256.into()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    for (k, v) in extra {
        headers.push((k.to_string(), v));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let signed_headers_str = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();
    let mut qs_pairs: Vec<&str> = query.split('&').filter(|s| !s.is_empty()).collect();
    qs_pairs.sort();
    let canonical_qs = qs_pairs.join("&");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_qs, canonical_headers, signed_headers_str, content_sha256
    );
    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let mut key = format!("AWS4{}", SECRET_KEY).into_bytes();
    for part in [date_stamp.as_str(), REGION, "s3", "aws4_request"] {
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(part.as_bytes());
        key = mac.finalize().into_bytes().to_vec();
    }
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let seed_signature = hex::encode(mac.finalize().into_bytes());

    let signer = StreamSigner {
        signing_key: key,
        amz_date,
        scope: scope.clone(),
        seed_signature: seed_signature.clone(),
    };
    let body = build(&signer);

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, seed_signature
    );
    let mut req = match method {
        "PUT" => client().put(url),
        "POST" => client().post(url),
        _ => panic!("unsupported"),
    };
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    req.header("authorization", auth)
        .body(body)
        .send()
        .await
        .unwrap()
}

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[tokio::test]
async fn test_streaming_signed_payload_verifies_and_roundtrips() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sbucket", base_url), vec![]).await;
    let url = format!("{}/sbucket/signed.bin", base_url);
    let data = patterned(150_000);
    let chunks: Vec<&[u8]> = data.chunks(65_536).collect();

    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        vec![
            ("content-encoding", "aws-chunked".into()),
            ("x-amz-decoded-content-length", data.len().to_string()),
        ],
        |s| s.signed_body(&chunks, None, None),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-encoding")
            .map(|v| !v.to_str().unwrap().contains("aws-chunked"))
            .unwrap_or(true),
        "aws-chunked must not be persisted as Content-Encoding"
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &data[..]);
}

#[tokio::test]
async fn test_streaming_signed_payload_bad_chunk_signature_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sbucket", base_url), vec![]).await;
    let url = format!("{}/sbucket/tampered.bin", base_url);
    let data = patterned(100_000);
    let chunks: Vec<&[u8]> = data.chunks(65_536).collect();

    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        vec![("x-amz-decoded-content-length", data.len().to_string())],
        |s| s.signed_body(&chunks, None, Some(1)),
    )
    .await;
    assert_eq!(resp.status(), 403);
    assert!(resp.text().await.unwrap().contains("SignatureDoesNotMatch"));

    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 404, "object must not be stored");
}

#[tokio::test]
async fn test_streaming_signed_final_chunk_signature_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sbucket", base_url), vec![]).await;
    let url = format!("{}/sbucket/tampered-final.bin", base_url);
    let data = patterned(1000);

    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        vec![("x-amz-decoded-content-length", data.len().to_string())],
        |s| s.signed_body(&[&data], None, Some(1)),
    )
    .await;
    assert_eq!(resp.status(), 403);
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_streaming_signed_trailer_roundtrip_and_bad_trailer_signature() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/sbucket", base_url), vec![]).await;
    let data = patterned(70_000);
    let chunks: Vec<&[u8]> = data.chunks(65_536).collect();
    let sha = b64(&Sha256::digest(&data));

    let url = format!("{}/sbucket/signed-trailer.bin", base_url);
    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        vec![
            ("content-encoding", "aws-chunked".into()),
            ("x-amz-decoded-content-length", data.len().to_string()),
            ("x-amz-trailer", "x-amz-checksum-sha256".into()),
        ],
        |s| s.signed_body(&chunks, Some(("x-amz-checksum-sha256", &sha)), None),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-sha256")
            .map(|v| v.to_str().unwrap().to_string()),
        Some(sha.clone())
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &data[..]);

    // Tampered trailer signature
    let url = format!("{}/sbucket/signed-trailer-bad.bin", base_url);
    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        vec![
            ("x-amz-decoded-content-length", data.len().to_string()),
            ("x-amz-trailer", "x-amz-checksum-sha256".into()),
        ],
        |s| {
            let body = s.signed_body(&chunks, Some(("x-amz-checksum-sha256", &sha)), None);
            let marker = b"x-amz-trailer-signature:";
            let idx = body
                .windows(marker.len())
                .rposition(|w| w == marker)
                .unwrap()
                + marker.len();
            let mut body = body;
            body[idx] = if body[idx] == b'0' { b'1' } else { b'0' };
            body
        },
    )
    .await;
    assert_eq!(resp.status(), 403);
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_streaming_unsigned_trailer_crc32_roundtrip() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/ubucket", base_url), vec![]).await;
    let url = format!("{}/ubucket/unsigned.bin", base_url);
    let data = patterned(200_000);
    let chunks: Vec<&[u8]> = data.chunks(65_536).collect();
    let crc = crc32_b64(&data);

    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        vec![
            ("content-encoding", "aws-chunked".into()),
            ("x-amz-decoded-content-length", data.len().to_string()),
            ("x-amz-trailer", "x-amz-checksum-crc32".into()),
            ("x-amz-sdk-checksum-algorithm", "CRC32".into()),
        ],
        |_| unsigned_trailer_body(&chunks, Some(("x-amz-checksum-crc32", &crc))),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .map(|v| v.to_str().unwrap().to_string()),
        Some(crc)
    );
    assert!(
        resp.headers()
            .get("content-encoding")
            .map(|v| !v.to_str().unwrap().contains("aws-chunked"))
            .unwrap_or(true)
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &data[..]);
}

#[tokio::test]
async fn test_streaming_unsigned_trailer_bad_checksum_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/ubucket", base_url), vec![]).await;
    let url = format!("{}/ubucket/badsum.bin", base_url);
    let data = patterned(10_000);
    let wrong = crc32_b64(b"something else");

    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        vec![
            ("x-amz-decoded-content-length", data.len().to_string()),
            ("x-amz-trailer", "x-amz-checksum-crc32".into()),
        ],
        |_| unsigned_trailer_body(&[&data], Some(("x-amz-checksum-crc32", &wrong))),
    )
    .await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("BadDigest"));
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_streaming_unsigned_trailer_missing_declared_trailer_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/ubucket", base_url), vec![]).await;
    let url = format!("{}/ubucket/notrailer.bin", base_url);
    let data = patterned(500);
    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        vec![("x-amz-trailer", "x-amz-checksum-crc32c".into())],
        |_| unsigned_trailer_body(&[&data], None),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_streaming_decoded_length_mismatch_is_incomplete_body() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/ubucket", base_url), vec![]).await;
    let url = format!("{}/ubucket/short.bin", base_url);
    let data = patterned(1000);
    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        vec![("x-amz-decoded-content-length", "2000".into())],
        |_| unsigned_trailer_body(&[&data], None),
    )
    .await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("IncompleteBody"));
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_streaming_truncated_body_is_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/ubucket", base_url), vec![]).await;
    let url = format!("{}/ubucket/trunc.bin", base_url);
    let resp = streaming_put(
        "PUT",
        &url,
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        vec![],
        |_| b"400\r\nonly a few bytes".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("IncompleteBody"));
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_streaming_unsigned_trailer_upload_part() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mpbucket", base_url), vec![]).await;
    let key_url = format!("{}/mpbucket/multi.bin", base_url);

    let resp = s3_request("POST", &format!("{}?uploads", key_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let upload_id = extract_xml_tag(&resp.text().await.unwrap(), "UploadId").unwrap();

    let part1 = patterned(5 * 1024 * 1024);
    let part2 = patterned(1234);
    let mut etags = Vec::new();
    for (n, part) in [(1, &part1), (2, &part2)] {
        let chunks: Vec<&[u8]> = part.chunks(65_536).collect();
        let crc = crc32_b64(part);
        let resp = streaming_put(
            "PUT",
            &format!("{}?partNumber={}&uploadId={}", key_url, n, upload_id),
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            vec![
                ("content-encoding", "aws-chunked".into()),
                ("x-amz-decoded-content-length", part.len().to_string()),
                ("x-amz-trailer", "x-amz-checksum-crc32".into()),
            ],
            |_| unsigned_trailer_body(&chunks, Some(("x-amz-checksum-crc32", &crc))),
        )
        .await;
        assert_eq!(resp.status(), 200);
        etags.push(
            resp.headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );
    }

    // A tampered part must be rejected and not replace part 2.
    let bad_crc = crc32_b64(b"nope");
    let resp = streaming_put(
        "PUT",
        &format!("{}?partNumber=2&uploadId={}", key_url, upload_id),
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        vec![("x-amz-trailer", "x-amz-checksum-crc32".into())],
        |_| unsigned_trailer_body(&[b"garbage"], Some(("x-amz-checksum-crc32", &bad_crc))),
    )
    .await;
    assert_eq!(resp.status(), 400);

    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let resp = s3_request(
        "POST",
        &format!("{}?uploadId={}", key_url, upload_id),
        complete.into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request("GET", &key_url, vec![]).await;
    let body = resp.bytes().await.unwrap();
    let mut expected = part1.clone();
    expected.extend_from_slice(&part2);
    assert_eq!(body.len(), expected.len());
    assert!(body.as_ref() == &expected[..]);
}

// ---- object-level S3 (agent C) ----

async fn c_setup(base_url: &str, bucket: &str, versioned: bool) {
    let r = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(r.status(), 200);
    if versioned {
        enable_versioning(base_url, bucket).await;
    }
}

fn c_header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string())
}

async fn c_put(base_url: &str, path: &str, body: &[u8]) -> reqwest::Response {
    s3_request("PUT", &format!("{}/{}", base_url, path), body.to_vec()).await
}

async fn c_get_body(base_url: &str, path: &str) -> (u16, Vec<u8>) {
    let r = s3_request("GET", &format!("{}/{}", base_url, path), vec![]).await;
    let status = r.status().as_u16();
    (status, r.bytes().await.unwrap().to_vec())
}

#[tokio::test]
async fn test_c_object_subresources_never_overwrite_or_leak_body() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "subres", false).await;
    assert_eq!(
        c_put(&base_url, "subres/obj.txt", b"hello").await.status(),
        200
    );

    // Object Lock subresources: bucket has no Object Lock configuration.
    for sub in ["retention", "legal-hold"] {
        let url = format!("{}/subres/obj.txt?{}", base_url, sub);
        let put = s3_request("PUT", &url, b"<Retention/>".to_vec()).await;
        assert_eq!(put.status(), 400, "PUT ?{sub}");
        let body = put.text().await.unwrap();
        assert!(body.contains("<Code>InvalidRequest</Code>"), "{body}");
        assert!(body.contains("Object Lock Configuration"), "{body}");
        let get = s3_request("GET", &url, vec![]).await;
        assert_eq!(get.status(), 400, "GET ?{sub}");
    }

    // ACL: private / owner-only accepted, anything else 501.
    let acl_url = format!("{}/subres/obj.txt?acl", base_url);
    let r = s3_request_with_headers("PUT", &acl_url, vec![], vec![("x-amz-acl", "private")]).await;
    assert_eq!(r.status(), 200);
    let r =
        s3_request_with_headers("PUT", &acl_url, vec![], vec![("x-amz-acl", "public-read")]).await;
    assert_eq!(r.status(), 501);
    let owner_only = b"<AccessControlPolicy><Owner><ID>maxio</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>maxio</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>".to_vec();
    let r = s3_request("PUT", &acl_url, owner_only).await;
    assert_eq!(r.status(), 200);
    let public = b"<AccessControlPolicy><Owner><ID>maxio</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>".to_vec();
    let r = s3_request("PUT", &acl_url, public).await;
    assert_eq!(r.status(), 501);

    let get_acl = s3_request("GET", &acl_url, vec![]).await;
    assert_eq!(get_acl.status(), 200);
    let acl = get_acl.text().await.unwrap();
    assert!(acl.contains("<AccessControlPolicy"), "{acl}");
    assert!(acl.contains("<ID>maxio</ID>"), "{acl}");
    assert!(acl.contains("FULL_CONTROL"), "{acl}");
    assert!(!acl.contains("hello"));

    // ACL on a missing key is NoSuchKey.
    let r = s3_request("GET", &format!("{}/subres/missing?acl", base_url), vec![]).await;
    assert_eq!(r.status(), 404);

    // Unknown subresources are rejected on every method, never falling through.
    for (method, sub) in [
        ("PUT", "torrent"),
        ("GET", "torrent"),
        ("HEAD", "torrent"),
        ("DELETE", "restore"),
        ("PUT", "renameObject"),
        ("DELETE", "acl"),
    ] {
        let url = format!("{}/subres/obj.txt?{}", base_url, sub);
        let r = s3_request(
            method,
            &url,
            if method == "PUT" {
                b"xx".to_vec()
            } else {
                vec![]
            },
        )
        .await;
        assert_eq!(r.status(), 501, "{method} ?{sub}");
    }

    // Object is intact.
    let (status, body) = c_get_body(&base_url, "subres/obj.txt").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");

    // x-id (added by AWS SDKs) is not a subresource.
    let (status, body) = c_get_body(&base_url, "subres/obj.txt?x-id=GetObject").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");
}

#[tokio::test]
async fn test_c_get_object_attributes() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "attrs", true).await;
    let v1 = s3_request_with_headers(
        "PUT",
        &format!("{}/attrs/a.txt", base_url),
        b"first".to_vec(),
        vec![("x-amz-checksum-algorithm", "CRC32")],
    )
    .await;
    assert_eq!(v1.status(), 200);
    let v1_id = c_header(&v1, "x-amz-version-id").unwrap();
    let crc = c_header(&v1, "x-amz-checksum-crc32").unwrap();
    assert_eq!(
        c_put(&base_url, "attrs/a.txt", b"second!").await.status(),
        200
    );

    let url = format!("{}/attrs/a.txt?attributes", base_url);
    let r = s3_request_with_headers(
        "GET",
        &url,
        vec![],
        vec![(
            "x-amz-object-attributes",
            "ETag,ObjectSize,StorageClass,Checksum",
        )],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert!(c_header(&r, "x-amz-version-id").is_some());
    let body = r.text().await.unwrap();
    assert!(body.contains("<GetObjectAttributesResponse"), "{body}");
    assert!(body.contains("<ObjectSize>7</ObjectSize>"), "{body}");
    assert!(
        body.contains("<StorageClass>STANDARD</StorageClass>"),
        "{body}"
    );
    assert!(!body.contains("second!"));

    let r = s3_request_with_headers(
        "GET",
        &format!("{}/attrs/a.txt?attributes&versionId={}", base_url, v1_id),
        vec![],
        vec![("x-amz-object-attributes", "ETag,ObjectSize,Checksum")],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        c_header(&r, "x-amz-version-id").as_deref(),
        Some(v1_id.as_str())
    );
    let body = r.text().await.unwrap();
    assert!(body.contains("<ObjectSize>5</ObjectSize>"), "{body}");
    assert!(
        body.contains(&format!("<ChecksumCRC32>{}</ChecksumCRC32>", crc)),
        "{body}"
    );
    use md5::Digest as _;
    let etag = hex::encode(md5::Md5::digest(b"first"));
    assert!(body.contains(&format!("<ETag>{}</ETag>", etag)), "{body}");
    assert!(
        !body.contains("<StorageClass>"),
        "only requested attrs: {body}"
    );

    // Missing header is rejected.
    let r = s3_request("GET", &url, vec![]).await;
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn test_c_user_metadata_and_standard_headers_roundtrip() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "meta", false).await;
    let url = format!("{}/meta/doc.txt", base_url);
    let put = s3_request_with_headers(
        "PUT",
        &url,
        b"0123456789".to_vec(),
        vec![
            ("x-amz-meta-Color", "Blue Sky"),
            ("x-amz-meta-count", "42"),
            ("content-type", "text/plain"),
            ("cache-control", "max-age=60"),
            ("content-disposition", "attachment; filename=\"doc.txt\""),
            ("content-encoding", "x-custom"),
            ("content-language", "de-DE"),
            ("expires", "Thu, 01 Jan 2099 00:00:00 GMT"),
        ],
    )
    .await;
    assert_eq!(put.status(), 200);

    let check = |r: &reqwest::Response| {
        assert_eq!(c_header(r, "x-amz-meta-color").as_deref(), Some("Blue Sky"));
        assert_eq!(c_header(r, "x-amz-meta-count").as_deref(), Some("42"));
        assert_eq!(c_header(r, "content-type").as_deref(), Some("text/plain"));
        assert_eq!(c_header(r, "cache-control").as_deref(), Some("max-age=60"));
        assert_eq!(
            c_header(r, "content-disposition").as_deref(),
            Some("attachment; filename=\"doc.txt\"")
        );
        assert_eq!(c_header(r, "content-encoding").as_deref(), Some("x-custom"));
        assert_eq!(c_header(r, "content-language").as_deref(), Some("de-DE"));
        assert_eq!(
            c_header(r, "expires").as_deref(),
            Some("Thu, 01 Jan 2099 00:00:00 GMT")
        );
    };
    let head = s3_request("HEAD", &url, vec![]).await;
    assert_eq!(head.status(), 200);
    check(&head);
    let get = s3_request("GET", &url, vec![]).await;
    assert_eq!(get.status(), 200);
    check(&get);
    let range = s3_request_with_headers("GET", &url, vec![], vec![("range", "bytes=2-4")]).await;
    assert_eq!(range.status(), 206);
    check(&range);
    assert_eq!(range.bytes().await.unwrap().as_ref(), b"234");

    // 2 KB user-metadata limit.
    let big = "a".repeat(2100);
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/meta/big.txt", base_url),
        b"x".to_vec(),
        vec![("x-amz-meta-big", big.as_str())],
    )
    .await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("MetadataTooLarge"));
    let r = s3_request("HEAD", &format!("{}/meta/big.txt", base_url), vec![]).await;
    assert_eq!(r.status(), 404);
}

async fn c_multipart_upload(
    base_url: &str,
    path: &str,
    create_headers: Vec<(&str, &str)>,
    data: &[u8],
    complete_headers: Vec<(&str, &str)>,
) -> reqwest::Response {
    let create = s3_request_with_headers(
        "POST",
        &format!("{}/{}?uploads=", base_url, path),
        vec![],
        create_headers,
    )
    .await;
    assert_eq!(create.status(), 200);
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();
    let part = s3_request(
        "PUT",
        &format!("{}/{}?partNumber=1&uploadId={}", base_url, path, upload_id),
        data.to_vec(),
    )
    .await;
    assert_eq!(part.status(), 200);
    let etag = c_header(&part, "etag").unwrap();
    let xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    s3_request_with_headers(
        "POST",
        &format!("{}/{}?uploadId={}", base_url, path, upload_id),
        xml.into_bytes(),
        complete_headers,
    )
    .await
}

#[tokio::test]
async fn test_c_multipart_persists_metadata_and_tagging() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "mpmeta", false).await;
    let done = c_multipart_upload(
        &base_url,
        "mpmeta/big.bin",
        vec![
            ("x-amz-meta-origin", "camera"),
            ("cache-control", "no-cache"),
            ("content-type", "image/jpeg"),
            ("x-amz-tagging", "project=alpha&team=media%20ops"),
        ],
        b"multipart-body",
        vec![],
    )
    .await;
    assert_eq!(done.status(), 200);
    let head = s3_request("HEAD", &format!("{}/mpmeta/big.bin", base_url), vec![]).await;
    assert_eq!(head.status(), 200);
    assert_eq!(
        c_header(&head, "x-amz-meta-origin").as_deref(),
        Some("camera")
    );
    assert_eq!(
        c_header(&head, "cache-control").as_deref(),
        Some("no-cache")
    );
    assert_eq!(
        c_header(&head, "content-type").as_deref(),
        Some("image/jpeg")
    );
    let tags = s3_request(
        "GET",
        &format!("{}/mpmeta/big.bin?tagging", base_url),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(
        tags.contains("<Key>project</Key><Value>alpha</Value>"),
        "{tags}"
    );
    assert!(
        tags.contains("<Key>team</Key><Value>media ops</Value>"),
        "{tags}"
    );
}

#[tokio::test]
async fn test_c_put_object_tagging_header() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "tagh", false).await;
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/tagh/a.txt", base_url),
        b"a".to_vec(),
        vec![("x-amz-tagging", "k1=v1&k2=")],
    )
    .await;
    assert_eq!(r.status(), 200);
    let tags = s3_request("GET", &format!("{}/tagh/a.txt?tagging", base_url), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert!(tags.contains("<Key>k1</Key><Value>v1</Value>"), "{tags}");
    assert!(tags.contains("<Key>k2</Key>"), "{tags}");

    let eleven: Vec<String> = (0..11).map(|i| format!("k{i}=v")).collect();
    let eleven = eleven.join("&");
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/tagh/b.txt", base_url),
        b"b".to_vec(),
        vec![("x-amz-tagging", eleven.as_str())],
    )
    .await;
    assert_eq!(r.status(), 400);
    let r = s3_request("HEAD", &format!("{}/tagh/b.txt", base_url), vec![]).await;
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn test_c_copy_object_metadata_and_tagging_directives() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "cpmeta", false).await;
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/cpmeta/src.txt", base_url),
        b"source".to_vec(),
        vec![
            ("x-amz-meta-a", "1"),
            ("content-type", "text/plain"),
            ("content-language", "en"),
            ("x-amz-tagging", "t=src"),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);

    // COPY (default): everything from the source.
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/cpmeta/copy.txt", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/cpmeta/src.txt"),
            ("x-amz-meta-ignored", "x"),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    let head = s3_request("HEAD", &format!("{}/cpmeta/copy.txt", base_url), vec![]).await;
    assert_eq!(c_header(&head, "x-amz-meta-a").as_deref(), Some("1"));
    assert_eq!(c_header(&head, "x-amz-meta-ignored"), None);
    assert_eq!(c_header(&head, "content-language").as_deref(), Some("en"));
    assert_eq!(
        c_header(&head, "content-type").as_deref(),
        Some("text/plain")
    );
    let tags = s3_request(
        "GET",
        &format!("{}/cpmeta/copy.txt?tagging", base_url),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(tags.contains("<Key>t</Key><Value>src</Value>"), "{tags}");

    // REPLACE: everything from the request.
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/cpmeta/replace.txt", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/cpmeta/src.txt"),
            ("x-amz-metadata-directive", "REPLACE"),
            ("x-amz-meta-b", "2"),
            ("content-type", "application/json"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "t=new"),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    let head = s3_request("HEAD", &format!("{}/cpmeta/replace.txt", base_url), vec![]).await;
    assert_eq!(c_header(&head, "x-amz-meta-a"), None);
    assert_eq!(c_header(&head, "x-amz-meta-b").as_deref(), Some("2"));
    assert_eq!(c_header(&head, "content-language"), None);
    assert_eq!(
        c_header(&head, "content-type").as_deref(),
        Some("application/json")
    );
    let tags = s3_request(
        "GET",
        &format!("{}/cpmeta/replace.txt?tagging", base_url),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(tags.contains("<Key>t</Key><Value>new</Value>"), "{tags}");
}

#[tokio::test]
async fn test_c_conditional_put_object() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "condput", false).await;
    let url = format!("{}/condput/k.txt", base_url);

    let r =
        s3_request_with_headers("PUT", &url, b"one".to_vec(), vec![("if-none-match", "*")]).await;
    assert_eq!(r.status(), 200);
    let etag = c_header(&r, "etag").unwrap();
    let r =
        s3_request_with_headers("PUT", &url, b"two".to_vec(), vec![("if-none-match", "*")]).await;
    assert_eq!(r.status(), 412);
    let r = s3_request_with_headers(
        "PUT",
        &url,
        b"two".to_vec(),
        vec![("if-match", "\"00000000000000000000000000000000\"")],
    )
    .await;
    assert_eq!(r.status(), 412);
    assert_eq!(c_get_body(&base_url, "condput/k.txt").await.1, b"one");
    let r = s3_request_with_headers("PUT", &url, b"two".to_vec(), vec![("if-match", &etag)]).await;
    assert_eq!(r.status(), 200);
    assert_eq!(c_get_body(&base_url, "condput/k.txt").await.1, b"two");
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/condput/absent.txt", base_url),
        b"x".to_vec(),
        vec![("if-match", &etag)],
    )
    .await;
    assert_eq!(r.status(), 404);

    // Concurrent If-None-Match: * — exactly one winner.
    let mut set = tokio::task::JoinSet::new();
    for i in 0..12 {
        let url = format!("{}/condput/race.txt", base_url);
        set.spawn(async move {
            let body = format!("writer-{i}").into_bytes();
            s3_request_with_headers("PUT", &url, body, vec![("if-none-match", "*")])
                .await
                .status()
                .as_u16()
        });
    }
    let mut ok = 0;
    let mut failed = 0;
    while let Some(res) = set.join_next().await {
        match res.unwrap() {
            200 => ok += 1,
            412 => failed += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(failed, 11);
}

#[tokio::test]
async fn test_c_conditional_put_after_delete_marker() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "condver", true).await;
    let url = format!("{}/condver/k.txt", base_url);
    assert_eq!(c_put(&base_url, "condver/k.txt", b"v1").await.status(), 200);
    let d = s3_request("DELETE", &url, vec![]).await;
    assert_eq!(d.status(), 204);
    let r =
        s3_request_with_headers("PUT", &url, b"v2".to_vec(), vec![("if-none-match", "*")]).await;
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn test_c_conditional_complete_multipart() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "condmp", false).await;
    assert_eq!(
        c_put(&base_url, "condmp/k.bin", b"exists").await.status(),
        200
    );
    let r = c_multipart_upload(
        &base_url,
        "condmp/k.bin",
        vec![],
        b"new data",
        vec![("if-none-match", "*")],
    )
    .await;
    assert_eq!(r.status(), 412);
    assert_eq!(c_get_body(&base_url, "condmp/k.bin").await.1, b"exists");
    let r = c_multipart_upload(
        &base_url,
        "condmp/new.bin",
        vec![],
        b"new data",
        vec![("if-none-match", "*")],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(c_get_body(&base_url, "condmp/new.bin").await.1, b"new data");
}

#[tokio::test]
async fn test_c_copy_source_conditionals() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "cpcond", false).await;
    let put = c_put(&base_url, "cpcond/src.txt", b"source").await;
    let etag = c_header(&put, "etag").unwrap();
    let dst = format!("{}/cpcond/dst.txt", base_url);
    let cases: Vec<(&str, String, u16)> = vec![
        ("x-amz-copy-source-if-match", "\"deadbeef\"".into(), 412),
        ("x-amz-copy-source-if-none-match", etag.clone(), 412),
        (
            "x-amz-copy-source-if-unmodified-since",
            "Mon, 01 Jan 2001 00:00:00 GMT".into(),
            412,
        ),
        (
            "x-amz-copy-source-if-modified-since",
            "Thu, 01 Jan 2099 00:00:00 GMT".into(),
            412,
        ),
        ("x-amz-copy-source-if-match", etag.clone(), 200),
    ];
    for (h, v, expected) in cases {
        let r = s3_request_with_headers(
            "PUT",
            &dst,
            vec![],
            vec![("x-amz-copy-source", "/cpcond/src.txt"), (h, v.as_str())],
        )
        .await;
        assert_eq!(r.status().as_u16(), expected, "{h}: {v}");
    }

    // UploadPartCopy honours the same headers.
    let create = s3_request(
        "POST",
        &format!("{}/cpcond/mp.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();
    let part_url = format!(
        "{}/cpcond/mp.bin?partNumber=1&uploadId={}",
        base_url, upload_id
    );
    let r = s3_request_with_headers(
        "PUT",
        &part_url,
        vec![],
        vec![
            ("x-amz-copy-source", "/cpcond/src.txt"),
            ("x-amz-copy-source-if-match", "\"deadbeef\""),
        ],
    )
    .await;
    assert_eq!(r.status(), 412);
    let r = s3_request_with_headers(
        "PUT",
        &part_url,
        vec![],
        vec![
            ("x-amz-copy-source", "/cpcond/src.txt"),
            ("x-amz-copy-source-if-match", etag.as_str()),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn test_c_get_response_header_overrides() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "overrides", false).await;
    assert_eq!(
        c_put(&base_url, "overrides/a.txt", b"abcdef")
            .await
            .status(),
        200
    );
    let url = format!(
        "{}/overrides/a.txt?response-content-type=text%2Fhtml&response-cache-control=no-store&response-content-disposition=attachment&response-content-language=fr&response-expires=Thu%2C%2001%20Jan%202099%2000%3A00%3A00%20GMT&response-content-encoding=identity",
        base_url
    );
    let check = |r: &reqwest::Response| {
        assert_eq!(c_header(r, "content-type").as_deref(), Some("text/html"));
        assert_eq!(c_header(r, "cache-control").as_deref(), Some("no-store"));
        assert_eq!(
            c_header(r, "content-disposition").as_deref(),
            Some("attachment")
        );
        assert_eq!(c_header(r, "content-language").as_deref(), Some("fr"));
        assert_eq!(c_header(r, "content-encoding").as_deref(), Some("identity"));
        assert_eq!(
            c_header(r, "expires").as_deref(),
            Some("Thu, 01 Jan 2099 00:00:00 GMT")
        );
    };
    let r = s3_request("GET", &url, vec![]).await;
    assert_eq!(r.status(), 200);
    check(&r);
    let r = s3_request_with_headers("GET", &url, vec![], vec![("range", "bytes=1-2")]).await;
    assert_eq!(r.status(), 206);
    check(&r);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"bc");
}

fn c_delete_xml(objects: &[(&str, Option<&str>)], quiet: bool) -> Vec<u8> {
    let mut xml = String::from("<Delete>");
    if quiet {
        xml.push_str("<Quiet>true</Quiet>");
    }
    for (k, v) in objects {
        xml.push_str(&format!("<Object><Key>{}</Key>", k));
        if let Some(v) = v {
            xml.push_str(&format!("<VersionId>{}</VersionId>", v));
        }
        xml.push_str("</Object>");
    }
    xml.push_str("</Delete>");
    xml.into_bytes()
}

#[tokio::test]
async fn test_c_delete_objects_versions_and_quiet() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "delv", true).await;
    let v1 = c_header(
        &c_put(&base_url, "delv/k.txt", b"one").await,
        "x-amz-version-id",
    )
    .unwrap();
    let v2 = c_header(
        &c_put(&base_url, "delv/k.txt", b"two").await,
        "x-amz-version-id",
    )
    .unwrap();
    let del_url = format!("{}/delv?delete", base_url);

    // Delete the specific (old) version.
    let body = c_delete_xml(&[("k.txt", Some(v1.as_str()))], false);
    let md5 = b64(&md5::Md5::digest(&body));
    let r =
        s3_request_with_headers("POST", &del_url, body, vec![("content-md5", md5.as_str())]).await;
    assert_eq!(r.status(), 200);
    let text = r.text().await.unwrap();
    assert!(
        text.contains(&format!(
            "<Deleted><Key>k.txt</Key><VersionId>{}</VersionId>",
            v1
        )),
        "{text}"
    );
    let r = s3_request(
        "GET",
        &format!("{}/delv/k.txt?versionId={}", base_url, v1),
        vec![],
    )
    .await;
    assert_eq!(r.status(), 404);
    assert_eq!(c_get_body(&base_url, "delv/k.txt").await.1, b"two");

    // Delete without version creates a delete marker.
    let r = s3_request("POST", &del_url, c_delete_xml(&[("k.txt", None)], false)).await;
    let text = r.text().await.unwrap();
    assert!(text.contains("<DeleteMarker>true</DeleteMarker>"), "{text}");
    let marker = extract_xml_tag(&text, "DeleteMarkerVersionId").expect(&text);
    assert_eq!(c_get_body(&base_url, "delv/k.txt").await.0, 404);

    // Deleting the delete marker by version restores v2.
    let r = s3_request(
        "POST",
        &del_url,
        c_delete_xml(&[("k.txt", Some(marker.as_str()))], false),
    )
    .await;
    let text = r.text().await.unwrap();
    assert!(text.contains("<DeleteMarker>true</DeleteMarker>"), "{text}");
    assert!(
        text.contains(&format!(
            "<DeleteMarkerVersionId>{}</DeleteMarkerVersionId>",
            marker
        )),
        "{text}"
    );
    assert_eq!(c_get_body(&base_url, "delv/k.txt").await.1, b"two");

    // Quiet mode reports only errors; a missing version is not an error.
    let r = s3_request(
        "POST",
        &del_url,
        c_delete_xml(&[("k.txt", Some(v2.as_str())), ("nope.txt", None)], true),
    )
    .await;
    assert_eq!(r.status(), 200);
    let text = r.text().await.unwrap();
    assert!(!text.contains("<Deleted>"), "{text}");
    assert!(!text.contains("<Error>"), "{text}");
    assert_eq!(c_get_body(&base_url, "delv/k.txt").await.0, 404);

    // Bad Content-MD5.
    let body = c_delete_xml(&[("k.txt", None)], false);
    let r = s3_request_with_headers(
        "POST",
        &del_url,
        body,
        vec![("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")],
    )
    .await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("BadDigest"));

    // More than 1000 keys.
    let keys: Vec<String> = (0..1001).map(|i| format!("k{i}")).collect();
    let objs: Vec<(&str, Option<&str>)> = keys.iter().map(|k| (k.as_str(), None)).collect();
    let r = s3_request("POST", &del_url, c_delete_xml(&objs, false)).await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("MalformedXML"));
}

#[tokio::test]
async fn test_c_copy_source_version_id() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "cpver", true).await;
    let v1 = c_header(
        &c_put(&base_url, "cpver/dir/a%20b.txt", b"one").await,
        "x-amz-version-id",
    )
    .unwrap();
    assert_eq!(
        c_put(&base_url, "cpver/dir/a%20b.txt", b"two")
            .await
            .status(),
        200
    );

    let src = format!("/cpver/dir/a%20b.txt?versionId={}", v1);
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/cpver/copy.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", src.as_str())],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        c_header(&r, "x-amz-copy-source-version-id").as_deref(),
        Some(v1.as_str())
    );
    assert_eq!(c_get_body(&base_url, "cpver/copy.txt").await.1, b"one");

    // UploadPartCopy with a version.
    let create = s3_request(
        "POST",
        &format!("{}/cpver/mp.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();
    let r = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/cpver/mp.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        vec![],
        vec![
            ("x-amz-copy-source", src.as_str()),
            ("x-amz-copy-source-range", "bytes=0-1"),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        c_header(&r, "x-amz-copy-source-version-id").as_deref(),
        Some(v1.as_str())
    );
    let parts = s3_request(
        "GET",
        &format!("{}/cpver/mp.bin?uploadId={}", base_url, upload_id),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(parts.contains("<Size>2</Size>"), "{parts}");
}

#[tokio::test]
async fn test_c_range_and_part_number_honour_version_id() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "rngver", true).await;
    let v1 = c_header(
        &c_put(&base_url, "rngver/k", b"0123456789").await,
        "x-amz-version-id",
    )
    .unwrap();
    assert_eq!(
        c_put(&base_url, "rngver/k", b"abcdefghij").await.status(),
        200
    );
    let r = s3_request_with_headers(
        "GET",
        &format!("{}/rngver/k?versionId={}", base_url, v1),
        vec![],
        vec![("range", "bytes=0-3")],
    )
    .await;
    assert_eq!(r.status(), 206);
    assert_eq!(
        c_header(&r, "x-amz-version-id").as_deref(),
        Some(v1.as_str())
    );
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"0123");

    // Multipart version + partNumber.
    let done = c_multipart_upload(&base_url, "rngver/mp", vec![], b"mp-v1", vec![]).await;
    assert_eq!(done.status(), 200);
    let head = s3_request("HEAD", &format!("{}/rngver/mp", base_url), vec![]).await;
    let mp_v1 = c_header(&head, "x-amz-version-id").unwrap();
    let mp_etag = c_header(&head, "etag").unwrap();
    assert_eq!(
        c_put(&base_url, "rngver/mp", b"plain-v2").await.status(),
        200
    );
    let part_url = format!("{}/rngver/mp?partNumber=1&versionId={}", base_url, mp_v1);
    let r = s3_request("GET", &part_url, vec![]).await;
    assert_eq!(r.status(), 206);
    assert_eq!(
        c_header(&r, "x-amz-version-id").as_deref(),
        Some(mp_v1.as_str())
    );
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"mp-v1");
    let r = s3_request("HEAD", &part_url, vec![]).await;
    assert_eq!(r.status(), 206);
    assert_eq!(
        c_header(&r, "x-amz-version-id").as_deref(),
        Some(mp_v1.as_str())
    );
    // Conditional headers apply to partNumber GET.
    let r =
        s3_request_with_headers("GET", &part_url, vec![], vec![("if-none-match", &mp_etag)]).await;
    assert_eq!(r.status(), 304);
    let r = s3_request_with_headers("GET", &part_url, vec![], vec![("if-match", "\"nope\"")]).await;
    assert_eq!(r.status(), 412);
}

#[tokio::test]
async fn test_c_get_head_delete_marker() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "dmark", true).await;
    assert_eq!(c_put(&base_url, "dmark/k", b"data").await.status(), 200);
    let d = s3_request("DELETE", &format!("{}/dmark/k", base_url), vec![]).await;
    let marker = c_header(&d, "x-amz-version-id").unwrap();

    for method in ["GET", "HEAD"] {
        let r = s3_request(method, &format!("{}/dmark/k", base_url), vec![]).await;
        assert_eq!(r.status(), 404, "{method}");
        assert_eq!(c_header(&r, "x-amz-delete-marker").as_deref(), Some("true"));
        assert_eq!(
            c_header(&r, "x-amz-version-id").as_deref(),
            Some(marker.as_str())
        );
        let r = s3_request(
            method,
            &format!("{}/dmark/k?versionId={}", base_url, marker),
            vec![],
        )
        .await;
        assert_eq!(r.status(), 405, "{method} versionId=marker");
        assert_eq!(c_header(&r, "x-amz-delete-marker").as_deref(), Some("true"));
        assert_eq!(
            c_header(&r, "x-amz-version-id").as_deref(),
            Some(marker.as_str())
        );
    }
    // Plain missing keys carry no delete-marker header.
    let r = s3_request("GET", &format!("{}/dmark/none", base_url), vec![]).await;
    assert_eq!(r.status(), 404);
    assert_eq!(c_header(&r, "x-amz-delete-marker"), None);
}

#[tokio::test]
async fn test_c_upload_part_content_md5() {
    let (base_url, _tmp) = start_server().await;
    c_setup(&base_url, "partmd5", false).await;
    let create = s3_request("POST", &format!("{}/partmd5/k?uploads=", base_url), vec![]).await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();
    let url = format!("{}/partmd5/k?partNumber=1&uploadId={}", base_url, upload_id);
    let data = b"part data".to_vec();

    let r = s3_request_with_headers(
        "PUT",
        &url,
        data.clone(),
        vec![("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")],
    )
    .await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("BadDigest"));
    let r =
        s3_request_with_headers("PUT", &url, data.clone(), vec![("content-md5", "not-md5!")]).await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("InvalidDigest"));
    // No part was recorded by the failed attempts.
    let parts = s3_request(
        "GET",
        &format!("{}/partmd5/k?uploadId={}", base_url, upload_id),
        vec![],
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(!parts.contains("<Part>"), "{parts}");

    let md5 = b64(&md5::Md5::digest(&data));
    let r = s3_request_with_headers(
        "PUT",
        &url,
        data.clone(),
        vec![("content-md5", md5.as_str())],
    )
    .await;
    assert_eq!(r.status(), 200);

    // PutObject keeps validating Content-MD5 too.
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/partmd5/plain", base_url),
        data.clone(),
        vec![("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")],
    )
    .await;
    assert_eq!(r.status(), 400);
    let r = s3_request("HEAD", &format!("{}/partmd5/plain", base_url), vec![]).await;
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn test_c_ec_paths_keep_metadata_preconditions_and_version_ranges() {
    let (base_url, _tmp) = start_server_ec_parity(4, 1).await;
    c_setup(&base_url, "ecmeta", true).await;
    for sse in [None, Some("AES256")] {
        let key = if sse.is_some() {
            "enc.txt"
        } else {
            "plain.txt"
        };
        let url = format!("{}/ecmeta/{}", base_url, key);
        let mut hdrs = vec![
            ("x-amz-meta-kind", "ec"),
            ("content-language", "nl"),
            ("x-amz-tagging", "a=b"),
            ("if-none-match", "*"),
        ];
        if let Some(alg) = sse {
            hdrs.push(("x-amz-server-side-encryption", alg));
        }
        let r = s3_request_with_headers("PUT", &url, b"0123456789".to_vec(), hdrs.clone()).await;
        assert_eq!(r.status(), 200, "{key}");
        let v1 = c_header(&r, "x-amz-version-id").unwrap();
        let r = s3_request_with_headers("PUT", &url, b"zzzzzzzzzz".to_vec(), hdrs).await;
        assert_eq!(r.status(), 412, "{key}");
        let mut h2 = vec![];
        if let Some(alg) = sse {
            h2.push(("x-amz-server-side-encryption", alg));
        }
        assert_eq!(
            s3_request_with_headers("PUT", &url, b"abcdefghij".to_vec(), h2)
                .await
                .status(),
            200
        );

        let r = s3_request_with_headers(
            "GET",
            &format!("{}?versionId={}", url, v1),
            vec![],
            vec![("range", "bytes=3-8")],
        )
        .await;
        assert_eq!(r.status(), 206, "{key}");
        assert_eq!(c_header(&r, "x-amz-meta-kind").as_deref(), Some("ec"));
        assert_eq!(c_header(&r, "content-language").as_deref(), Some("nl"));
        assert_eq!(c_header(&r, "x-amz-tagging-count").as_deref(), Some("1"));
        assert_eq!(r.bytes().await.unwrap().as_ref(), b"345678", "{key}");
    }
}

// ── Regression: version id path traversal ────────────────────────────

/// Enable versioning and create versions of `a` so `.versions/a/` exists.
async fn enable_versioning_and_seed(base: &str, bucket: &str) {
    enable_versioning(base, bucket).await;
    for body in [b"a1", b"a2"] {
        s3_request("PUT", &format!("{}/{}/a", base, bucket), body.to_vec()).await;
    }
}

/// Assert it is intact (data + sidecar).
async fn assert_victim_intact(base: &str, bucket: &str) {
    let r = s3_request("GET", &format!("{}/{}/victim", base, bucket), vec![]).await;
    assert_eq!(r.status(), 200, "victim object must survive");
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"victim bytes");
}

#[tokio::test]
async fn test_version_id_traversal_rejected_s3_delete_and_get() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/vtrav", base), vec![]).await;
    enable_versioning_and_seed(&base, "vtrav").await;
    s3_request(
        "PUT",
        &format!("{}/vtrav/victim", base),
        b"victim bytes".to_vec(),
    )
    .await;

    let r = s3_request(
        "DELETE",
        &format!("{}/vtrav/a?versionId=..%2F..%2Fvictim", base),
        vec![],
    )
    .await;
    assert_eq!(r.status(), 400);
    let body = r.text().await.unwrap();
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{}", body);
    assert!(body.contains("Invalid version id specified"), "{}", body);
    assert_victim_intact(&base, "vtrav").await;

    for vid in ["..%2F..%2Fvictim", "a%5Cb", "..", ""] {
        let r = s3_request(
            "GET",
            &format!("{}/vtrav/a?versionId={}", base, vid),
            vec![],
        )
        .await;
        assert_eq!(r.status(), 400, "GET versionId={}", vid);
        let r = s3_request(
            "HEAD",
            &format!("{}/vtrav/a?versionId={}", base, vid),
            vec![],
        )
        .await;
        assert_eq!(r.status(), 400, "HEAD versionId={}", vid);
    }
    assert_victim_intact(&base, "vtrav").await;
}

#[tokio::test]
async fn test_version_id_traversal_rejected_delete_objects() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/vtravb", base), vec![]).await;
    enable_versioning_and_seed(&base, "vtravb").await;
    s3_request(
        "PUT",
        &format!("{}/vtravb/victim", base),
        b"victim bytes".to_vec(),
    )
    .await;
    let xml =
        r#"<Delete><Object><Key>a</Key><VersionId>../../victim</VersionId></Object></Delete>"#;
    let r = s3_request(
        "POST",
        &format!("{}/vtravb?delete", base),
        xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(r.status(), 200);
    let body = r.text().await.unwrap();
    assert!(body.contains("<Error>"), "{}", body);
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{}", body);
    assert!(!body.contains("<Deleted>"), "{}", body);
    assert_victim_intact(&base, "vtravb").await;
}

#[tokio::test]
async fn test_version_id_traversal_rejected_console() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/vtravc", base), vec![]).await;
    enable_versioning_and_seed(&base, "vtravc").await;
    s3_request(
        "PUT",
        &format!("{}/vtravc/victim", base),
        b"victim bytes".to_vec(),
    )
    .await;
    let cookie = console_login(&base).await;
    let r = client()
        .delete(&format!(
            "{}/api/buckets/vtravc/versions/..%2F..%2Fvictim/objects/a",
            base
        ))
        .header("cookie", format!("maxio_session={}", cookie))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = client()
        .get(&format!(
            "{}/api/buckets/vtravc/versions/..%2F..%2Fvictim/download/a",
            base
        ))
        .header("cookie", format!("maxio_session={}", cookie))
        .send()
        .await
        .unwrap();
    assert!(!r.status().is_success());
    assert_victim_intact(&base, "vtravc").await;
}

// ── Regression: suspended-versioning null object survives version delete ──

#[tokio::test]
async fn test_suspended_null_object_survives_other_version_delete() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/susnull", base), vec![]).await;
    let enable =
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/susnull?versioning", base), enable).await;
    let url = format!("{}/susnull/k", base);
    s3_request("PUT", &url, b"v1".to_vec()).await;
    let r = s3_request("PUT", &url, b"v2".to_vec()).await;
    let v2 = c_header(&r, "x-amz-version-id").unwrap();
    let suspend =
        b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>".to_vec();
    s3_request("PUT", &format!("{}/susnull?versioning", base), suspend).await;
    s3_request("PUT", &url, b"NULL".to_vec()).await;

    // The null version is current and listed as such.
    let body = s3_request("GET", &format!("{}/susnull?versions", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("<VersionId>null</VersionId><IsLatest>true</IsLatest>"),
        "{}",
        body
    );

    let r = s3_request("DELETE", &format!("{}?versionId={}", url, v2), vec![]).await;
    assert_eq!(r.status(), 204);
    let r = s3_request("GET", &url, vec![]).await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.bytes().await.unwrap().as_ref(),
        b"NULL",
        "null object lost"
    );

    let body = s3_request("GET", &format!("{}/susnull?versions", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(body.matches("<Version>").count(), 2, "{}", body);
    assert!(
        body.contains("<VersionId>null</VersionId><IsLatest>true</IsLatest>"),
        "{}",
        body
    );

    // Deleting the null version promotes the newest remaining one (v1).
    let r = s3_request("DELETE", &format!("{}?versionId=null", url), vec![]).await;
    assert_eq!(r.status(), 204);
    let r = s3_request("GET", &url, vec![]).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"v1");
}

// ── Regression: multipart params must not fall through to PUT/DELETE ──

#[tokio::test]
async fn test_misplaced_multipart_params_do_not_touch_object() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mpfall", base), vec![]).await;
    let url = format!("{}/mpfall/k", base);
    s3_request("PUT", &url, b"original".to_vec()).await;

    for (method, query, status) in [
        ("PUT", "uploads", 405),
        ("PUT", "partNumber=1", 400),
        ("PUT", "max-parts=5", 400),
        ("PUT", "part-number-marker=1", 400),
        ("DELETE", "uploads", 405),
        ("DELETE", "partNumber=1", 400),
        ("DELETE", "max-parts=5", 400),
    ] {
        let r = s3_request(method, &format!("{}?{}", url, query), b"clobber".to_vec()).await;
        assert_eq!(r.status(), status, "{} ?{}", method, query);
        let r = s3_request("GET", &url, vec![]).await;
        assert_eq!(r.status(), 200, "{} ?{} touched object", method, query);
        assert_eq!(r.bytes().await.unwrap().as_ref(), b"original");
    }
}

// ---- console object details/tags (agent K) ----

async fn console_json(
    method: &str,
    base: &str,
    path: &str,
    session: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let url = format!("{}{}", base, path);
    let mut b = match method {
        "GET" => client().get(url),
        "PUT" => client().put(url),
        "POST" => client().post(url),
        _ => panic!("unsupported method"),
    }
    .header("cookie", format!("maxio_session={}", session));
    if let Some(body) = body {
        b = b.json(&body);
    }
    let resp = b.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn tag_pairs(v: &serde_json::Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = v["tags"]
        .as_array()
        .unwrap_or_else(|| panic!("no tags array: {}", v))
        .iter()
        .map(|t| {
            (
                t["key"].as_str().unwrap().to_string(),
                t["value"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    out.sort();
    out
}

async fn enable_versioning(base: &str, bucket: &str) {
    let enable =
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec();
    let r = s3_request("PUT", &format!("{}/{}?versioning", base, bucket), enable).await;
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn test_console_new_endpoints_require_auth() {
    let (base, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/kauth", base), vec![]).await;
    s3_request("PUT", &format!("{}/kauth/a.txt", base), b"x".to_vec()).await;
    for (method, path) in [
        ("GET", "object-info/a.txt"),
        ("GET", "object-tags/a.txt"),
        ("GET", "tags"),
        ("GET", "policy"),
        ("GET", "lifecycle"),
        ("PUT", "object-tags/a.txt"),
        ("PUT", "tags"),
        ("PUT", "lifecycle"),
        ("POST", "versions/1-ab/restore/a.txt"),
    ] {
        let r = client()
            .request(
                method.parse().unwrap(),
                format!("{}/api/buckets/kauth/{}", base, path),
            )
            .json(&serde_json::json!({ "tags": [], "rules": [] }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "{} {}", method, path);
    }
}

#[tokio::test]
async fn test_console_object_info_returns_metadata() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/kinfo", base), vec![]).await;
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/kinfo/dir/report.txt", base),
        b"hello info".to_vec(),
        vec![
            ("content-type", "text/plain"),
            ("x-amz-meta-owner", "alice"),
            ("cache-control", "max-age=60"),
            ("content-disposition", "inline"),
            ("x-amz-tagging", "env=prod&team=core"),
            ("x-amz-checksum-algorithm", "CRC32"),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);

    let (status, info) = console_json(
        "GET",
        &base,
        "/api/buckets/kinfo/object-info/dir/report.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200, "{}", info);
    assert_eq!(info["key"], "dir/report.txt");
    assert_eq!(info["size"], 10);
    assert_eq!(info["contentType"], "text/plain");
    assert!(info["etag"].as_str().unwrap().len() > 10);
    assert!(info["lastModified"].is_string());
    assert!(info["versionId"].is_null());
    assert_eq!(info["isDeleteMarker"], false);
    assert_eq!(info["storageFormat"], "plain");
    assert!(info["partCount"].is_null());
    assert_eq!(info["userMetadata"]["owner"], "alice");
    assert_eq!(info["cacheControl"], "max-age=60");
    assert_eq!(info["contentDisposition"], "inline");
    assert!(info["contentEncoding"].is_null());
    assert!(info["contentLanguage"].is_null());
    assert!(info["expires"].is_null());
    assert!(info["encryption"].is_null());
    assert_eq!(
        tag_pairs(&info),
        vec![
            ("env".to_string(), "prod".to_string()),
            ("team".to_string(), "core".to_string())
        ]
    );
    if !info["checksum"].is_null() {
        assert_eq!(info["checksum"]["algorithm"], "CRC32");
        assert!(info["checksum"]["value"].is_string());
    }

    // Missing object -> 404 JSON
    let (status, body) = console_json(
        "GET",
        &base,
        "/api/buckets/kinfo/object-info/nope.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);
    assert!(body["error"].is_string());

    // Missing bucket -> 404
    let (status, _) = console_json(
        "GET",
        &base,
        "/api/buckets/kinfo-missing/object-info/a",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_console_object_info_encryption_and_versions() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/kenc", base), vec![]).await;

    // SSE-S3
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/kenc/s3.txt", base),
        b"secret".to_vec(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(r.status(), 200);
    let (status, info) = console_json(
        "GET",
        &base,
        "/api/buckets/kenc/object-info/s3.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200, "{}", info);
    assert_eq!(info["encryption"]["mode"], "SSE-S3");
    assert_eq!(info["size"], 6);
    let raw = info.to_string();
    assert!(!raw.contains("wrappedDek") && !raw.contains("wrapped_dek"));

    // SSE-C: metadata without the key
    let key = [0x42u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_b64 = b64.encode(key);
    let key_md5 = b64.encode(md5::Md5::digest(key));
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/kenc/c.txt", base),
        b"customer".to_vec(),
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_md5),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    let (status, info) = console_json(
        "GET",
        &base,
        "/api/buckets/kenc/object-info/c.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200, "{}", info);
    assert_eq!(info["encryption"]["mode"], "SSE-C");
    assert!(!info.to_string().contains(&key_md5));

    // Versioned: ?versionId= selects an older version
    s3_request("PUT", &format!("{}/kver", base), vec![]).await;
    enable_versioning(&base, "kver").await;
    let r = s3_request("PUT", &format!("{}/kver/f", base), b"one".to_vec()).await;
    let v1 = c_header(&r, "x-amz-version-id").unwrap();
    s3_request("PUT", &format!("{}/kver/f", base), b"three".to_vec()).await;
    let (status, info) = console_json(
        "GET",
        &base,
        &format!("/api/buckets/kver/object-info/f?versionId={}", v1),
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200, "{}", info);
    assert_eq!(info["size"], 3);
    assert_eq!(info["versionId"], v1.as_str());
    let (status, info) = console_json(
        "GET",
        &base,
        "/api/buckets/kver/object-info/f",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(info["size"], 5);

    // Bad version id -> 400, unknown well-formed version id -> 404
    let (status, _) = console_json(
        "GET",
        &base,
        "/api/buckets/kver/object-info/f?versionId=../x",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = console_json(
        "GET",
        &base,
        "/api/buckets/kver/object-info/f?versionId=123-abc",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_console_object_tags_roundtrip_and_validation() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/ktags", base), vec![]).await;
    s3_request("PUT", &format!("{}/ktags/a/b.txt", base), b"x".to_vec()).await;
    let path = "/api/buckets/ktags/object-tags/a/b.txt";

    let (status, body) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(status, 200, "{}", body);
    assert!(tag_pairs(&body).is_empty());

    let (status, body) = console_json(
        "PUT",
        &base,
        path,
        &session,
        Some(serde_json::json!({ "tags": [
            { "key": "env", "value": "dev" },
            { "key": "owner", "value": "" }
        ] })),
    )
    .await;
    assert_eq!(status, 200, "{}", body);
    let (_, body) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(
        tag_pairs(&body),
        vec![
            ("env".to_string(), "dev".to_string()),
            ("owner".to_string(), "".to_string())
        ]
    );
    // Visible through S3 GetObjectTagging too
    let xml = s3_request("GET", &format!("{}/ktags/a/b.txt?tagging", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert!(xml.contains("<Key>env</Key>"), "{}", xml);

    let too_many: Vec<_> = (0..11)
        .map(|i| serde_json::json!({ "key": format!("k{}", i), "value": "v" }))
        .collect();
    let long_key = "k".repeat(129);
    let long_val = "v".repeat(257);
    for tags in [
        serde_json::json!(too_many),
        serde_json::json!([{ "key": "", "value": "v" }]),
        serde_json::json!([{ "key": long_key, "value": "v" }]),
        serde_json::json!([{ "key": "k", "value": long_val }]),
        serde_json::json!([{ "key": "k", "value": "1" }, { "key": "k", "value": "2" }]),
    ] {
        let (status, body) = console_json(
            "PUT",
            &base,
            path,
            &session,
            Some(serde_json::json!({ "tags": tags })),
        )
        .await;
        assert_eq!(status, 400, "{}", body);
        assert!(body["error"].is_string());
    }

    // Empty array clears the tag set
    let (status, _) = console_json(
        "PUT",
        &base,
        path,
        &session,
        Some(serde_json::json!({ "tags": [] })),
    )
    .await;
    assert_eq!(status, 200);
    let (_, body) = console_json("GET", &base, path, &session, None).await;
    assert!(tag_pairs(&body).is_empty());

    // Missing object -> 404
    let (status, _) = console_json(
        "GET",
        &base,
        "/api/buckets/ktags/object-tags/missing",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = console_json(
        "PUT",
        &base,
        "/api/buckets/ktags/object-tags/missing",
        &session,
        Some(serde_json::json!({ "tags": [] })),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_console_object_tags_on_versions() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/kvtags", base), vec![]).await;
    enable_versioning(&base, "kvtags").await;
    let r = s3_request("PUT", &format!("{}/kvtags/f", base), b"one".to_vec()).await;
    let v1 = c_header(&r, "x-amz-version-id").unwrap();
    s3_request("PUT", &format!("{}/kvtags/f", base), b"two".to_vec()).await;

    let v1_path = format!("/api/buckets/kvtags/object-tags/f?versionId={}", v1);
    let (status, body) = console_json(
        "PUT",
        &base,
        &v1_path,
        &session,
        Some(serde_json::json!({ "tags": [{ "key": "old", "value": "yes" }] })),
    )
    .await;
    assert_eq!(status, 200, "{}", body);
    let (_, body) = console_json("GET", &base, &v1_path, &session, None).await;
    assert_eq!(
        tag_pairs(&body),
        vec![("old".to_string(), "yes".to_string())]
    );
    // The current version is untouched
    let (_, body) = console_json(
        "GET",
        &base,
        "/api/buckets/kvtags/object-tags/f",
        &session,
        None,
    )
    .await;
    assert!(tag_pairs(&body).is_empty());

    // Tagging the current version is visible both with and without versionId
    let (status, _) = console_json(
        "PUT",
        &base,
        "/api/buckets/kvtags/object-tags/f",
        &session,
        Some(serde_json::json!({ "tags": [{ "key": "cur", "value": "1" }] })),
    )
    .await;
    assert_eq!(status, 200);
    let (_, info) = console_json(
        "GET",
        &base,
        "/api/buckets/kvtags/object-info/f",
        &session,
        None,
    )
    .await;
    let cur = info["versionId"].as_str().unwrap().to_string();
    let (_, body) = console_json(
        "GET",
        &base,
        &format!("/api/buckets/kvtags/object-tags/f?versionId={}", cur),
        &session,
        None,
    )
    .await;
    assert_eq!(tag_pairs(&body), vec![("cur".to_string(), "1".to_string())]);

    let (status, _) = console_json(
        "PUT",
        &base,
        "/api/buckets/kvtags/object-tags/f?versionId=bad/id",
        &session,
        Some(serde_json::json!({ "tags": [] })),
    )
    .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn test_console_bucket_tags_roundtrip_and_validation() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/kbtags", base), vec![]).await;
    let path = "/api/buckets/kbtags/tags";

    let (status, body) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(status, 200, "{}", body);
    assert!(tag_pairs(&body).is_empty());

    let (status, body) = console_json(
        "PUT",
        &base,
        path,
        &session,
        Some(serde_json::json!({ "tags": [
            { "key": "cost-center", "value": "42" },
            { "key": "env", "value": "prod" }
        ] })),
    )
    .await;
    assert_eq!(status, 200, "{}", body);
    let (_, body) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(
        tag_pairs(&body),
        vec![
            ("cost-center".to_string(), "42".to_string()),
            ("env".to_string(), "prod".to_string())
        ]
    );
    let xml = s3_request("GET", &format!("{}/kbtags?tagging", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert!(xml.contains("<Key>cost-center</Key>"), "{}", xml);

    // Bucket list carries tagCount
    let (_, list) = console_json("GET", &base, "/api/buckets", &session, None).await;
    let b = list["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "kbtags")
        .unwrap();
    assert_eq!(b["tagCount"], 2);

    let too_many: Vec<_> = (0..51)
        .map(|i| serde_json::json!({ "key": format!("k{}", i), "value": "v" }))
        .collect();
    for tags in [
        serde_json::json!(too_many),
        serde_json::json!([{ "key": "", "value": "v" }]),
        serde_json::json!([{ "key": "k".repeat(129), "value": "v" }]),
        serde_json::json!([{ "key": "k", "value": "v".repeat(257) }]),
        serde_json::json!([{ "key": "aws:x", "value": "v" }]),
        serde_json::json!([{ "key": "k", "value": "1" }, { "key": "k", "value": "2" }]),
    ] {
        let (status, body) = console_json(
            "PUT",
            &base,
            path,
            &session,
            Some(serde_json::json!({ "tags": tags })),
        )
        .await;
        assert_eq!(status, 400, "{}", body);
        assert!(body["error"].is_string());
    }

    // Empty array deletes the tag set
    let (status, _) = console_json(
        "PUT",
        &base,
        path,
        &session,
        Some(serde_json::json!({ "tags": [] })),
    )
    .await;
    assert_eq!(status, 200);
    let (_, body) = console_json("GET", &base, path, &session, None).await;
    assert!(tag_pairs(&body).is_empty());
    let r = s3_request("GET", &format!("{}/kbtags?tagging", base), vec![]).await;
    assert_eq!(r.status(), 404);

    let (status, _) = console_json(
        "GET",
        &base,
        "/api/buckets/kbtags-missing/tags",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_console_bucket_policy_view_and_bucket_summary_flags() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/kpolicy", base), vec![]).await;

    let (status, body) =
        console_json("GET", &base, "/api/buckets/kpolicy/policy", &session, None).await;
    assert_eq!(status, 200, "{}", body);
    assert!(body["policy"].is_null(), "{}", body);

    let (status, _) = console_json(
        "PUT",
        &base,
        "/api/buckets/kpolicy/public",
        &session,
        Some(serde_json::json!({ "read": true, "list": false })),
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) =
        console_json("GET", &base, "/api/buckets/kpolicy/policy", &session, None).await;
    assert_eq!(status, 200);
    let policy_str = body["policy"].as_str().expect("policy string");
    let s3_policy = s3_request("GET", &format!("{}/kpolicy?policy", base), vec![])
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(policy_str, s3_policy);
    let policy: serde_json::Value = serde_json::from_str(policy_str).unwrap();
    assert!(policy.to_string().contains("s3:GetObject"));
    assert!(!policy.to_string().contains("s3:ListBucket"));

    let (_, list) = console_json("GET", &base, "/api/buckets", &session, None).await;
    let b = list["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "kpolicy")
        .unwrap();
    assert_eq!(b["publicRead"], true);
    assert_eq!(b["publicList"], false);
    assert_eq!(b["tagCount"], 0);

    let (status, _) = console_json(
        "GET",
        &base,
        "/api/buckets/kpolicy-missing/policy",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_console_list_objects_includes_content_type() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/kctype", base), vec![]).await;
    s3_request_with_headers(
        "PUT",
        &format!("{}/kctype/page.html", base),
        b"<p>".to_vec(),
        vec![("content-type", "text/html")],
    )
    .await;
    let (status, body) =
        console_json("GET", &base, "/api/buckets/kctype/objects", &session, None).await;
    assert_eq!(status, 200);
    assert_eq!(body["files"][0]["contentType"], "text/html");
}

#[tokio::test]
async fn test_console_restore_version_roundtrip() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/krestore", base), vec![]).await;
    enable_versioning(&base, "krestore").await;
    let url = format!("{}/krestore/docs/f.txt", base);
    let r = s3_request_with_headers(
        "PUT",
        &url,
        b"version one".to_vec(),
        vec![
            ("content-type", "text/plain"),
            ("x-amz-meta-rev", "1"),
            ("x-amz-tagging", "rev=1"),
        ],
    )
    .await;
    let v1 = c_header(&r, "x-amz-version-id").unwrap();
    let r = s3_request_with_headers(
        "PUT",
        &url,
        b"version two!".to_vec(),
        vec![("content-type", "application/json")],
    )
    .await;
    let v2 = c_header(&r, "x-amz-version-id").unwrap();

    let (status, body) = console_json(
        "POST",
        &base,
        &format!("/api/buckets/krestore/versions/{}/restore/docs/f.txt", v1),
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200, "{}", body);
    let new_vid = body["versionId"].as_str().expect("versionId").to_string();
    assert_ne!(new_vid, v1);
    assert_ne!(new_vid, v2);

    let r = s3_request("GET", &url, vec![]).await;
    assert_eq!(r.status(), 200);
    assert_eq!(c_header(&r, "content-type").as_deref(), Some("text/plain"));
    assert_eq!(c_header(&r, "x-amz-meta-rev").as_deref(), Some("1"));
    assert_eq!(
        c_header(&r, "x-amz-version-id").as_deref(),
        Some(new_vid.as_str())
    );
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"version one");

    let (_, info) = console_json(
        "GET",
        &base,
        "/api/buckets/krestore/object-info/docs/f.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(tag_pairs(&info), vec![("rev".to_string(), "1".to_string())]);

    let (_, versions) = console_json(
        "GET",
        &base,
        "/api/buckets/krestore/versions?key=docs/f.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(
        versions["versions"].as_array().unwrap().len(),
        3,
        "{}",
        versions
    );

    // Invalid version id -> 400; unknown -> 404
    let (status, _) = console_json(
        "POST",
        &base,
        "/api/buckets/krestore/versions/not-a-version/restore/docs/f.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = console_json(
        "POST",
        &base,
        "/api/buckets/krestore/versions/1-abc/restore/docs/f.txt",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);

    // Delete marker cannot be restored
    let r = s3_request("DELETE", &url, vec![]).await;
    let marker = c_header(&r, "x-amz-version-id").unwrap();
    let (status, body) = console_json(
        "POST",
        &base,
        &format!(
            "/api/buckets/krestore/versions/{}/restore/docs/f.txt",
            marker
        ),
        &session,
        None,
    )
    .await;
    assert_eq!(status, 400, "{}", body);
    // Restoring an older version after a delete brings the object back
    let (status, _) = console_json(
        "POST",
        &base,
        &format!("/api/buckets/krestore/versions/{}/restore/docs/f.txt", v2),
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let r = s3_request("GET", &url, vec![]).await;
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"version two!");
}

#[tokio::test]
async fn test_console_restore_version_encryption() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/krenc", base), vec![]).await;
    enable_versioning(&base, "krenc").await;

    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/krenc/s3", base),
        b"sse one".to_vec(),
        vec![("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    let v1 = c_header(&r, "x-amz-version-id").unwrap();
    s3_request("PUT", &format!("{}/krenc/s3", base), b"plain".to_vec()).await;
    let (status, body) = console_json(
        "POST",
        &base,
        &format!("/api/buckets/krenc/versions/{}/restore/s3", v1),
        &session,
        None,
    )
    .await;
    assert_eq!(status, 200, "{}", body);
    let r = s3_request("GET", &format!("{}/krenc/s3", base), vec![]).await;
    assert_eq!(
        c_header(&r, "x-amz-server-side-encryption").as_deref(),
        Some("AES256")
    );
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"sse one");

    let key = [0x24u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_b64 = b64.encode(key);
    let key_md5 = b64.encode(md5::Md5::digest(key));
    let r = s3_request_with_headers(
        "PUT",
        &format!("{}/krenc/c", base),
        b"cust".to_vec(),
        vec![
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", &key_b64),
            ("x-amz-server-side-encryption-customer-key-md5", &key_md5),
        ],
    )
    .await;
    let vc = c_header(&r, "x-amz-version-id").unwrap();
    let (status, body) = console_json(
        "POST",
        &base,
        &format!("/api/buckets/krenc/versions/{}/restore/c", vc),
        &session,
        None,
    )
    .await;
    assert_eq!(status, 400, "{}", body);
    assert_eq!(body["error"], "SSE-C objects need the customer key");
}

// ---- lifecycle (agent L) ----

mod lifecycle_l {
    use super::*;
    use maxio::storage::lifecycle::{LifecycleStats, run_lifecycle};

    const LC_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

    fn lc_doc(rules: &str) -> Vec<u8> {
        format!(
            "<LifecycleConfiguration xmlns=\"{}\">{}</LifecycleConfiguration>",
            LC_XMLNS, rules
        )
        .into_bytes()
    }

    /// Second storage handle on the server's data dir, used to run the
    /// lifecycle engine directly with an injected clock.
    async fn engine_storage(tmp: &TempDir) -> FilesystemStorage {
        let data_dir = tmp.path().to_str().unwrap().to_string();
        let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
        FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0, keyring)
            .await
            .unwrap()
    }

    async fn run_at(tmp: &TempDir, now: chrono::DateTime<chrono::Utc>) -> LifecycleStats {
        let storage = engine_storage(tmp).await;
        run_lifecycle(&storage, now).await
    }

    fn days(n: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::days(n)
    }

    async fn put_lc(base: &str, bucket: &str, rules: &str) {
        let r = s3_request(
            "PUT",
            &format!("{}/{}?lifecycle", base, bucket),
            lc_doc(rules),
        )
        .await;
        let status = r.status();
        let body = r.text().await.unwrap();
        assert_eq!(status, 200, "PutBucketLifecycleConfiguration: {}", body);
    }

    async fn status_of(url: &str) -> u16 {
        s3_request("GET", url, vec![]).await.status().as_u16()
    }

    async fn version_count(base: &str, bucket: &str, prefix: &str) -> (usize, usize) {
        let body = s3_request(
            "GET",
            &format!("{}/{}?versions&prefix={}", base, bucket, prefix),
            vec![],
        )
        .await
        .text()
        .await
        .unwrap();
        (
            body.matches("<Version>").count(),
            body.matches("<DeleteMarker>").count(),
        )
    }

    // --- S3 API ---

    #[tokio::test]
    async fn test_l_lifecycle_put_get_delete_roundtrip() {
        let (base, _tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcrt", base), vec![]).await;
        let url = format!("{}/lcrt?lifecycle", base);

        let rules = "<Rule><ID>logs</ID><Filter><And><Prefix>logs/</Prefix>\
            <Tag><Key>tier</Key><Value>tmp</Value></Tag>\
            <ObjectSizeGreaterThan>10</ObjectSizeGreaterThan>\
            <ObjectSizeLessThan>1000</ObjectSizeLessThan></And></Filter>\
            <Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule>\
            <Rule><ID>versions</ID><Filter><Prefix>docs/</Prefix></Filter><Status>Disabled</Status>\
            <NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays>\
            <NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration>\
            <AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation>\
            </AbortIncompleteMultipartUpload></Rule>\
            <Rule><ID>dm</ID><Filter></Filter><Status>Enabled</Status>\
            <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>\
            <Rule><ID>date</ID><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>\
            <Status>Enabled</Status><Expiration><Date>2030-01-01T00:00:00Z</Date></Expiration></Rule>";
        let r = s3_request("PUT", &url, lc_doc(rules)).await;
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.headers()
                .get("x-amz-transition-default-minimum-object-size")
                .and_then(|v| v.to_str().ok()),
            Some("all_storage_classes_128K")
        );

        let r = s3_request("GET", &url, vec![]).await;
        assert_eq!(r.status(), 200);
        let body = r.text().await.unwrap();
        for needle in [
            "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "<ID>logs</ID>",
            "<And><Prefix>logs/</Prefix><Tag><Key>tier</Key><Value>tmp</Value></Tag>\
             <ObjectSizeGreaterThan>10</ObjectSizeGreaterThan>\
             <ObjectSizeLessThan>1000</ObjectSizeLessThan></And>",
            "<Expiration><Days>30</Days></Expiration>",
            "<Status>Disabled</Status>",
            "<Filter><Prefix>docs/</Prefix></Filter>",
            "<NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays>\
             <NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration>",
            "<AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation>\
             </AbortIncompleteMultipartUpload>",
            "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>",
            "<Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>",
            "<Date>2030-01-01T00:00:00.000Z</Date>",
        ] {
            assert!(body.contains(needle), "missing {} in {}", needle, body);
        }

        // Replacing the configuration (mc ilm style: empty prefix filter, no
        // ID → one is generated; legacy top-level <Prefix> form).
        let rules = "<Rule><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>\
            <Expiration><Days>1</Days></Expiration></Rule>\
            <Rule><ID>legacy</ID><Prefix>old/</Prefix><Status>Enabled</Status>\
            <Expiration><Days>2</Days></Expiration></Rule>";
        put_lc(&base, "lcrt", rules).await;
        let body = s3_request("GET", &url, vec![]).await.text().await.unwrap();
        assert_eq!(body.matches("<Rule>").count(), 2, "{}", body);
        assert!(
            !body.contains("<ID>logs</ID>"),
            "old config must be replaced"
        );
        let first_id = extract_xml_tag(&body, "ID").unwrap();
        assert!(!first_id.is_empty() && first_id.len() <= 255, "{}", body);
        assert!(body.contains("<Prefix>old/</Prefix>"), "{}", body);

        let r = s3_request("DELETE", &url, vec![]).await;
        assert_eq!(r.status(), 204);
        let r = s3_request("GET", &url, vec![]).await;
        assert_eq!(r.status(), 404);
        assert!(
            r.text()
                .await
                .unwrap()
                .contains("<Code>NoSuchLifecycleConfiguration</Code>")
        );
        // Deleting again is still 204.
        let r = s3_request("DELETE", &url, vec![]).await;
        assert_eq!(r.status(), 204);
    }

    #[tokio::test]
    async fn test_l_lifecycle_missing_bucket() {
        let (base, _tmp) = start_server().await;
        let url = format!("{}/nolcbucket?lifecycle", base);
        let r = s3_request(
            "PUT",
            &url,
            lc_doc("<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>"),
        )
        .await;
        assert_eq!(r.status(), 404);
        assert!(r.text().await.unwrap().contains("NoSuchBucket"));
        assert_eq!(status_of(&url).await, 404);
        let r = s3_request("DELETE", &url, vec![]).await;
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn test_l_lifecycle_validation_errors() {
        let (base, _tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcval", base), vec![]).await;
        let url = format!("{}/lcval?lifecycle", base);
        let exp1 = "<Expiration><Days>1</Days></Expiration>";
        let long_id = "x".repeat(256);
        let too_many: String = (0..1001)
            .map(|i| {
                format!(
                    "<Rule><ID>r{}</ID><Filter/><Status>Enabled</Status>{}</Rule>",
                    i, exp1
                )
            })
            .collect();
        let cases: Vec<(String, u16, &str)> = vec![
            ("not xml".into(), 400, "MalformedXML"),
            (String::new(), 400, "MalformedXML"),
            // no rules
            (
                String::from_utf8(lc_doc("")).unwrap(),
                400,
                "MalformedXML",
            ),
            (
                String::from_utf8(lc_doc(&too_many)).unwrap(),
                400,
                "MalformedXML",
            ),
            // missing / bad status
            (
                String::from_utf8(lc_doc(&format!("<Rule><ID>a</ID><Filter/>{}</Rule>", exp1)))
                    .unwrap(),
                400,
                "MalformedXML",
            ),
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>a</ID><Filter/><Status>On</Status>{}</Rule>",
                    exp1
                )))
                .unwrap(),
                400,
                "MalformedXML",
            ),
            // no action
            (
                String::from_utf8(lc_doc("<Rule><ID>a</ID><Filter/><Status>Enabled</Status></Rule>"))
                    .unwrap(),
                400,
                "InvalidRequest",
            ),
            // duplicate IDs
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status>{e}</Rule>\
                     <Rule><ID>a</ID><Filter/><Status>Enabled</Status>{e}</Rule>",
                    e = exp1
                )))
                .unwrap(),
                400,
                "InvalidArgument",
            ),
            // ID too long
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>{}</ID><Filter/><Status>Enabled</Status>{}</Rule>",
                    long_id, exp1
                )))
                .unwrap(),
                400,
                "InvalidArgument",
            ),
            // Days must be positive
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>0</Days></Expiration></Rule>",
                ))
                .unwrap(),
                400,
                "InvalidArgument",
            ),
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>-3</Days></Expiration></Rule>",
                ))
                .unwrap(),
                400,
                "InvalidArgument",
            ),
            // Date must be midnight UTC
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Date>2030-01-01T10:00:00Z</Date></Expiration></Rule>",
                ))
                .unwrap(),
                400,
                "InvalidArgument",
            ),
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Date>tomorrow</Date></Expiration></Rule>",
                ))
                .unwrap(),
                400,
                "InvalidArgument",
            ),
            // Days and Date together
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days><Date>2030-01-01T00:00:00Z</Date></Expiration></Rule>",
                ))
                .unwrap(),
                400,
                "MalformedXML",
            ),
            // ExpiredObjectDeleteMarker with Days
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>",
                ))
                .unwrap(),
                400,
                "MalformedXML",
            ),
            // two filter conditions without <And>
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>a</ID><Filter><Prefix>a/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled</Status>{}</Rule>",
                    exp1
                )))
                .unwrap(),
                400,
                "MalformedXML",
            ),
            // both legacy Prefix and Filter
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>a</ID><Prefix>a/</Prefix><Filter><Prefix>a/</Prefix></Filter><Status>Enabled</Status>{}</Rule>",
                    exp1
                )))
                .unwrap(),
                400,
                "MalformedXML",
            ),
            // size range inverted
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>a</ID><Filter><And><ObjectSizeGreaterThan>100</ObjectSizeGreaterThan><ObjectSizeLessThan>50</ObjectSizeLessThan></And></Filter><Status>Enabled</Status>{}</Rule>",
                    exp1
                )))
                .unwrap(),
                400,
                "InvalidRequest",
            ),
            // duplicate tag keys in And
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>a</ID><Filter><And><Tag><Key>k</Key><Value>1</Value></Tag><Tag><Key>k</Key><Value>2</Value></Tag></And></Filter><Status>Enabled</Status>{}</Rule>",
                    exp1
                )))
                .unwrap(),
                400,
                "InvalidRequest",
            ),
            // tag filter + AbortIncompleteMultipartUpload
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>",
                ))
                .unwrap(),
                400,
                "InvalidRequest",
            ),
            // MinIO extension elements are not part of the S3 schema
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><DelMarkerExpiration><Days>1</Days></DelMarkerExpiration></Rule>",
                ))
                .unwrap(),
                400,
                "MalformedXML",
            ),
            // NewerNoncurrentVersions out of range
            (
                String::from_utf8(lc_doc(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>101</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>",
                ))
                .unwrap(),
                400,
                "InvalidArgument",
            ),
            // unknown element
            (
                String::from_utf8(lc_doc(&format!(
                    "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Bogus>1</Bogus>{}</Rule>",
                    exp1
                )))
                .unwrap(),
                400,
                "MalformedXML",
            ),
        ];
        for (body, status, code) in cases {
            let r = s3_request("PUT", &url, body.clone().into_bytes()).await;
            let got = r.status().as_u16();
            let text = r.text().await.unwrap();
            let shown: String = body.chars().take(300).collect();
            assert_eq!(got, status, "{} -> {}", shown, text);
            assert!(
                text.contains(&format!("<Code>{}</Code>", code)),
                "expected {} for {}: {}",
                code,
                shown,
                text
            );
        }
        // Nothing was stored.
        assert_eq!(status_of(&url).await, 404);
    }

    #[tokio::test]
    async fn test_l_lifecycle_transition_not_implemented() {
        let (base, _tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lctr", base), vec![]).await;
        let url = format!("{}/lctr?lifecycle", base);
        for rule in [
            "<Rule><ID>t</ID><Filter/><Status>Enabled</Status><Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition></Rule>",
            "<Rule><ID>t</ID><Filter/><Status>Enabled</Status><NoncurrentVersionTransition><NoncurrentDays>30</NoncurrentDays><StorageClass>GLACIER</StorageClass></NoncurrentVersionTransition></Rule>",
        ] {
            let r = s3_request("PUT", &url, lc_doc(rule)).await;
            assert_eq!(r.status(), 501, "{}", rule);
            assert!(
                r.text()
                    .await
                    .unwrap()
                    .contains("<Code>NotImplemented</Code>")
            );
        }
        assert_eq!(status_of(&url).await, 404);
    }

    #[tokio::test]
    async fn test_l_lifecycle_content_md5() {
        let (base, _tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcmd5", base), vec![]).await;
        let url = format!("{}/lcmd5?lifecycle", base);
        let body = lc_doc(
            "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>",
        );
        let wrong = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let r =
            s3_request_with_headers("PUT", &url, body.clone(), vec![("content-md5", &wrong)]).await;
        assert_eq!(r.status(), 400);
        assert!(r.text().await.unwrap().contains("BadDigest"));
        let r =
            s3_request_with_headers("PUT", &url, body.clone(), vec![("content-md5", "!!")]).await;
        assert_eq!(r.status(), 400);
        assert!(r.text().await.unwrap().contains("InvalidDigest"));
        let good = base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&body));
        let r = s3_request_with_headers("PUT", &url, body, vec![("content-md5", &good)]).await;
        assert_eq!(r.status(), 200);
    }

    // --- Engine ---

    #[tokio::test]
    async fn test_l_engine_expire_days_non_versioned() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcexp", base), vec![]).await;
        for key in ["logs/a.txt", "logs/deep/b.txt", "keep/c.txt", "logsx"] {
            s3_request("PUT", &format!("{}/lcexp/{}", base, key), b"data".to_vec()).await;
        }
        put_lc(
            &base,
            "lcexp",
            "<Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>\
             <Expiration><Days>1</Days></Expiration></Rule>",
        )
        .await;

        // Days=1 expires at midnight UTC of (creation day + 2): never within
        // the first 24h, always after 48h.
        let stats = run_at(&tmp, days(1)).await;
        assert_eq!(stats.expired_objects, 0);
        assert_eq!(status_of(&format!("{}/lcexp/logs/a.txt", base)).await, 200);

        let stats = run_at(&tmp, days(2)).await;
        assert_eq!(stats.expired_objects, 2, "{:?}", stats);
        assert_eq!(status_of(&format!("{}/lcexp/logs/a.txt", base)).await, 404);
        assert_eq!(
            status_of(&format!("{}/lcexp/logs/deep/b.txt", base)).await,
            404
        );
        assert_eq!(status_of(&format!("{}/lcexp/keep/c.txt", base)).await, 200);
        assert_eq!(status_of(&format!("{}/lcexp/logsx", base)).await, 200);
        // Non-versioned: no versions or markers left behind.
        assert_eq!(version_count(&base, "lcexp", "logs/").await, (0, 0));
    }

    #[tokio::test]
    async fn test_l_engine_expire_by_date() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcdate", base), vec![]).await;
        s3_request("PUT", &format!("{}/lcdate/a", base), b"x".to_vec()).await;
        s3_request("PUT", &format!("{}/lcdate/old/b", base), b"x".to_vec()).await;
        let tomorrow = (chrono::Utc::now() + chrono::Duration::days(1))
            .format("%Y-%m-%dT00:00:00Z")
            .to_string();
        put_lc(
            &base,
            "lcdate",
            &format!(
                "<Rule><ID>future</ID><Filter><Prefix>a</Prefix></Filter><Status>Enabled</Status>\
                 <Expiration><Date>{}</Date></Expiration></Rule>\
                 <Rule><ID>past</ID><Filter><Prefix>old/</Prefix></Filter><Status>Enabled</Status>\
                 <Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule>",
                tomorrow
            ),
        )
        .await;
        let stats = run_at(&tmp, chrono::Utc::now()).await;
        assert_eq!(stats.expired_objects, 1);
        assert_eq!(status_of(&format!("{}/lcdate/a", base)).await, 200);
        assert_eq!(status_of(&format!("{}/lcdate/old/b", base)).await, 404);

        let at = chrono::DateTime::parse_from_rfc3339(&tomorrow)
            .unwrap()
            .with_timezone(&chrono::Utc);
        let stats = run_at(&tmp, at).await;
        assert_eq!(stats.expired_objects, 1);
        assert_eq!(status_of(&format!("{}/lcdate/a", base)).await, 404);
    }

    #[tokio::test]
    async fn test_l_engine_tag_and_size_filters() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcflt", base), vec![]).await;
        let put_tagged = |key: &'static str, body: Vec<u8>, tags: &'static str| {
            let url = format!("{}/lcflt/{}", base, key);
            async move {
                let r =
                    s3_request_with_headers("PUT", &url, body, vec![("x-amz-tagging", tags)]).await;
                assert_eq!(r.status(), 200);
            }
        };
        put_tagged("t/both", b"x".to_vec(), "a=1&b=2").await;
        put_tagged("t/one", b"x".to_vec(), "a=1").await;
        put_tagged("t/wrong", b"x".to_vec(), "a=2&b=2").await;
        put_tagged("s/small", vec![0u8; 5], "z=z").await;
        put_tagged("s/mid", vec![0u8; 50], "z=z").await;
        put_tagged("s/edge", vec![0u8; 10], "z=z").await;
        put_tagged("s/big", vec![0u8; 500], "z=z").await;
        put_lc(
            &base,
            "lcflt",
            "<Rule><ID>tags</ID><Filter><And><Prefix>t/</Prefix>\
             <Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value>2</Value></Tag>\
             </And></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
             <Rule><ID>size</ID><Filter><And><Prefix>s/</Prefix>\
             <ObjectSizeGreaterThan>10</ObjectSizeGreaterThan>\
             <ObjectSizeLessThan>100</ObjectSizeLessThan></And></Filter>\
             <Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
             <Rule><ID>big</ID><Filter><ObjectSizeGreaterThan>400</ObjectSizeGreaterThan></Filter>\
             <Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>",
        )
        .await;
        let stats = run_at(&tmp, days(3)).await;
        assert_eq!(stats.expired_objects, 3, "{:?}", stats);
        for (key, status) in [
            ("t/both", 404),
            ("t/one", 200),
            ("t/wrong", 200),
            ("s/small", 200),
            ("s/edge", 200),
            ("s/mid", 404),
            ("s/big", 404),
        ] {
            assert_eq!(
                status_of(&format!("{}/lcflt/{}", base, key)).await,
                status,
                "{}",
                key
            );
        }
    }

    #[tokio::test]
    async fn test_l_engine_disabled_rule_does_nothing() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcdis", base), vec![]).await;
        s3_request("PUT", &format!("{}/lcdis/a", base), b"x".to_vec()).await;
        put_lc(
            &base,
            "lcdis",
            "<Rule><ID>off</ID><Filter/><Status>Disabled</Status>\
             <Expiration><Days>1</Days></Expiration>\
             <AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation>\
             </AbortIncompleteMultipartUpload></Rule>",
        )
        .await;
        let r = s3_request("POST", &format!("{}/lcdis/up?uploads", base), vec![]).await;
        assert_eq!(r.status(), 200);
        let stats = run_at(&tmp, days(100)).await;
        assert_eq!(stats, LifecycleStats::default());
        assert_eq!(status_of(&format!("{}/lcdis/a", base)).await, 200);
        let body = s3_request("GET", &format!("{}/lcdis?uploads", base), vec![])
            .await
            .text()
            .await
            .unwrap();
        assert_eq!(body.matches("<Upload>").count(), 1);
    }

    #[tokio::test]
    async fn test_l_engine_versioned_bucket_gets_delete_marker() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcver", base), vec![]).await;
        enable_versioning(&base, "lcver").await;
        s3_request("PUT", &format!("{}/lcver/doc", base), b"v1".to_vec()).await;
        put_lc(
            &base,
            "lcver",
            "<Rule><ID>e</ID><Filter/><Status>Enabled</Status>\
             <Expiration><Days>1</Days></Expiration></Rule>",
        )
        .await;
        let stats = run_at(&tmp, days(3)).await;
        assert_eq!(stats.expired_objects, 1);
        assert_eq!(status_of(&format!("{}/lcver/doc", base)).await, 404);
        // The data survives as a noncurrent version behind a delete marker.
        assert_eq!(version_count(&base, "lcver", "doc").await, (1, 1));
        // A second run does nothing: the current version is a marker.
        let stats = run_at(&tmp, days(3)).await;
        assert_eq!(stats, LifecycleStats::default());
        assert_eq!(version_count(&base, "lcver", "doc").await, (1, 1));
    }

    #[tokio::test]
    async fn test_l_engine_noncurrent_expiration_keeps_newer_versions() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcnc", base), vec![]).await;
        enable_versioning(&base, "lcnc").await;
        for v in ["v1", "v2", "v3", "v4"] {
            s3_request("PUT", &format!("{}/lcnc/k", base), v.as_bytes().to_vec()).await;
        }
        for v in ["v1", "v2"] {
            s3_request("PUT", &format!("{}/lcnc/gone", base), v.as_bytes().to_vec()).await;
        }
        s3_request("DELETE", &format!("{}/lcnc/gone", base), vec![]).await;
        put_lc(
            &base,
            "lcnc",
            "<Rule><ID>nc</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>\
             <NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays>\
             <NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>",
        )
        .await;
        // Too early: nothing became noncurrent long enough ago.
        let stats = run_at(&tmp, days(1)).await;
        assert_eq!(stats.noncurrent_versions_expired, 0);

        let stats = run_at(&tmp, days(3)).await;
        // k: v1, v2 expire (v3 is kept as the newest noncurrent);
        // gone: v1 expires (v2 is kept behind the delete marker).
        assert_eq!(stats.noncurrent_versions_expired, 3, "{:?}", stats);
        assert_eq!(version_count(&base, "lcnc", "k").await, (2, 0));
        let r = s3_request("GET", &format!("{}/lcnc/k", base), vec![]).await;
        assert_eq!(r.status(), 200);
        assert_eq!(r.bytes().await.unwrap().as_ref(), b"v4");
        // The delete marker must stay current — removing an older version
        // must not resurrect v2.
        assert_eq!(version_count(&base, "lcnc", "gone").await, (1, 1));
        assert_eq!(status_of(&format!("{}/lcnc/gone", base)).await, 404);
    }

    #[tokio::test]
    async fn test_l_engine_noncurrent_days_only() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcnd", base), vec![]).await;
        enable_versioning(&base, "lcnd").await;
        for v in ["v1", "v2", "v3"] {
            s3_request("PUT", &format!("{}/lcnd/k", base), v.as_bytes().to_vec()).await;
        }
        put_lc(
            &base,
            "lcnd",
            "<Rule><ID>nc</ID><Filter/><Status>Enabled</Status>\
             <NoncurrentVersionExpiration><NoncurrentDays>2</NoncurrentDays>\
             </NoncurrentVersionExpiration></Rule>",
        )
        .await;
        let stats = run_at(&tmp, days(4)).await;
        assert_eq!(stats.noncurrent_versions_expired, 2);
        assert_eq!(version_count(&base, "lcnd", "k").await, (1, 0));
        let r = s3_request("GET", &format!("{}/lcnd/k", base), vec![]).await;
        assert_eq!(r.bytes().await.unwrap().as_ref(), b"v3");
    }

    #[tokio::test]
    async fn test_l_engine_expired_delete_marker_cleanup() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcdm", base), vec![]).await;
        enable_versioning(&base, "lcdm").await;
        // Lone marker (no versions at all).
        s3_request("DELETE", &format!("{}/lcdm/lone", base), vec![]).await;
        // Marker with a noncurrent version that must keep it alive.
        s3_request("PUT", &format!("{}/lcdm/kept", base), b"v1".to_vec()).await;
        s3_request("DELETE", &format!("{}/lcdm/kept", base), vec![]).await;
        assert_eq!(version_count(&base, "lcdm", "").await, (1, 2));
        put_lc(
            &base,
            "lcdm",
            "<Rule><ID>dm</ID><Filter/><Status>Enabled</Status>\
             <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>",
        )
        .await;
        let stats = run_at(&tmp, chrono::Utc::now()).await;
        assert_eq!(stats.delete_markers_removed, 1, "{:?}", stats);
        assert_eq!(version_count(&base, "lcdm", "lone").await, (0, 0));
        assert_eq!(version_count(&base, "lcdm", "kept").await, (1, 1));

        // Combined with noncurrent expiration the marker goes away once its
        // last noncurrent version expired (same run).
        put_lc(
            &base,
            "lcdm",
            "<Rule><ID>dm</ID><Filter/><Status>Enabled</Status>\
             <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>\
             <NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>",
        )
        .await;
        let stats = run_at(&tmp, days(3)).await;
        assert_eq!(stats.noncurrent_versions_expired, 1, "{:?}", stats);
        assert_eq!(stats.delete_markers_removed, 1, "{:?}", stats);
        assert_eq!(version_count(&base, "lcdm", "").await, (0, 0));
    }

    #[tokio::test]
    async fn test_l_engine_abort_incomplete_multipart() {
        let (base, tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcmpu", base), vec![]).await;
        for key in ["tmp/a", "other/b"] {
            let r = s3_request("POST", &format!("{}/lcmpu/{}?uploads", base, key), vec![]).await;
            assert_eq!(r.status(), 200);
        }
        put_lc(
            &base,
            "lcmpu",
            "<Rule><ID>mpu</ID><Filter><Prefix>tmp/</Prefix></Filter><Status>Enabled</Status>\
             <AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation>\
             </AbortIncompleteMultipartUpload></Rule>",
        )
        .await;
        let stats = run_at(&tmp, days(1)).await;
        assert_eq!(stats.uploads_aborted, 0);
        let stats = run_at(&tmp, days(2)).await;
        assert_eq!(stats.uploads_aborted, 1);
        let body = s3_request("GET", &format!("{}/lcmpu?uploads", base), vec![])
            .await
            .text()
            .await
            .unwrap();
        assert_eq!(body.matches("<Upload>").count(), 1, "{}", body);
        assert!(body.contains("<Key>other/b</Key>"), "{}", body);
    }

    /// Permanently deleting an older version while a delete marker is the
    /// current version must not resurrect the next-older version.
    #[tokio::test]
    async fn test_l_delete_old_version_keeps_delete_marker_current() {
        let (base, _tmp) = start_server().await;
        s3_request("PUT", &format!("{}/lcres", base), vec![]).await;
        enable_versioning(&base, "lcres").await;
        let url = format!("{}/lcres/k", base);
        let r = s3_request("PUT", &url, b"v1".to_vec()).await;
        let v1 = r.headers()["x-amz-version-id"]
            .to_str()
            .unwrap()
            .to_string();
        s3_request("PUT", &url, b"v2".to_vec()).await;
        s3_request("DELETE", &url, vec![]).await;
        assert_eq!(status_of(&url).await, 404);
        let r = s3_request("DELETE", &format!("{}?versionId={}", url, v1), vec![]).await;
        assert_eq!(r.status(), 204);
        assert_eq!(
            status_of(&url).await,
            404,
            "v2 must stay hidden behind the marker"
        );
        let list = s3_request("GET", &format!("{}/lcres?list-type=2", base), vec![])
            .await
            .text()
            .await
            .unwrap();
        assert!(!list.contains("<Key>k</Key>"), "{}", list);
    }

    /// Erasure-coded and SSE-S3 objects expire through the regular storage
    /// delete path, leaving no chunk dirs behind.
    #[tokio::test]
    async fn test_l_engine_expires_ec_and_encrypted_objects() {
        use maxio::storage::lifecycle::{
            LifecycleExpiration, LifecycleFilter, LifecycleRule, LifecycleStatus,
        };
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().to_str().unwrap().to_string();
        let keyring = Arc::new(Keyring::load(&data_dir, None).await.unwrap());
        let storage = FilesystemStorage::new(&data_dir, true, 1024, 1, keyring)
            .await
            .unwrap();
        storage
            .create_bucket(&test_bucket_meta("lcec"))
            .await
            .unwrap();
        let body = vec![7u8; 3000];
        storage
            .put_object(
                "lcec",
                "ec/plain.bin",
                "application/octet-stream",
                Box::pin(std::io::Cursor::new(body.clone())),
                None,
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "lcec",
                "ec/sse.bin",
                "application/octet-stream",
                Box::pin(std::io::Cursor::new(body)),
                None,
                Some(maxio::storage::EncryptionRequest::sse_s3()),
            )
            .await
            .unwrap();
        storage
            .set_bucket_lifecycle(
                "lcec",
                Some(vec![LifecycleRule {
                    id: "ec".into(),
                    status: LifecycleStatus::Enabled,
                    filter: LifecycleFilter::default(),
                    expiration: Some(LifecycleExpiration {
                        days: Some(1),
                        ..Default::default()
                    }),
                    noncurrent_version_expiration: None,
                    abort_incomplete_multipart_upload: None,
                }]),
            )
            .await
            .unwrap();
        let stats = run_lifecycle(&storage, days(3)).await;
        assert_eq!(stats.expired_objects, 2, "{:?}", stats);
        assert_eq!(stats.errors, 0);
        assert!(storage.list_objects("lcec", "").await.unwrap().is_empty());
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path().join("buckets/lcec"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n != ".bucket.json")
            .collect();
        assert!(leftovers.is_empty(), "{:?}", leftovers);
    }

    #[tokio::test]
    async fn test_l_storage_api_json_shape() {
        use maxio::storage::lifecycle::LifecycleRule;
        let tmp = TempDir::new().unwrap();
        let storage = engine_storage(&tmp).await;
        storage
            .create_bucket(&test_bucket_meta("lcjson"))
            .await
            .unwrap();
        assert!(
            storage
                .get_bucket_lifecycle("lcjson")
                .await
                .unwrap()
                .is_none()
        );
        let rules: Vec<LifecycleRule> = serde_json::from_value(serde_json::json!([{
            "id": "r1",
            "status": "Enabled",
            "filter": { "prefix": "logs/", "tags": [{ "key": "a", "value": "b" }],
                        "objectSizeGreaterThan": 1 },
            "expiration": { "days": 30 },
            "noncurrentVersionExpiration": { "noncurrentDays": 7, "newerNoncurrentVersions": 2 },
            "abortIncompleteMultipartUpload": { "daysAfterInitiation": 3 }
        }]))
        .unwrap();
        storage
            .set_bucket_lifecycle("lcjson", Some(rules.clone()))
            .await
            .unwrap();
        // Other bucket config updates must not drop the lifecycle config.
        storage.set_versioning("lcjson", true).await.unwrap();
        assert_eq!(
            storage.get_bucket_lifecycle("lcjson").await.unwrap(),
            Some(rules)
        );
        storage.set_bucket_lifecycle("lcjson", None).await.unwrap();
        assert!(
            storage
                .get_bucket_lifecycle("lcjson")
                .await
                .unwrap()
                .is_none()
        );
        assert!(storage.get_bucket_lifecycle("nope-bucket").await.is_err());
    }
}

// ---- console lifecycle (agent U) ----

#[tokio::test]
async fn test_console_lifecycle_roundtrip() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/ulc", base), vec![]).await;
    let path = "/api/buckets/ulc/lifecycle";

    let (status, body) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(status, 200, "{}", body);
    assert_eq!(body["rules"], serde_json::json!([]));

    let (status, body) = console_json(
        "PUT",
        &base,
        path,
        &session,
        Some(serde_json::json!({ "rules": [
            {
                "status": "Enabled",
                "filter": { "prefix": "logs/" },
                "expiration": { "days": 30 },
                "abortIncompleteMultipartUpload": { "daysAfterInitiation": 3 }
            },
            {
                "id": "old-versions",
                "status": "Disabled",
                "expiration": { "date": "2030-01-01" },
                "noncurrentVersionExpiration": { "noncurrentDays": 7, "newerNoncurrentVersions": 2 }
            }
        ] })),
    )
    .await;
    assert_eq!(status, 200, "{}", body);
    let rules = body["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    let generated = rules[0]["id"].as_str().unwrap();
    assert!(!generated.is_empty(), "missing generated id: {}", body);
    assert_eq!(rules[1]["id"], "old-versions");
    // Dates are normalized to the canonical ISO form.
    assert_eq!(
        rules[1]["expiration"]["date"], "2030-01-01T00:00:00.000Z",
        "{}",
        body
    );

    let (status, got) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(status, 200);
    assert_eq!(got, body);

    // Visible through the S3 API too.
    let r = s3_request("GET", &format!("{}/ulc?lifecycle", base), vec![]).await;
    assert_eq!(r.status(), 200);
    let xml = r.text().await.unwrap();
    assert!(xml.contains("<ID>old-versions</ID>"), "{}", xml);
    assert!(xml.contains("<Prefix>logs/</Prefix>"), "{}", xml);

    let (status, _) = console_json(
        "GET",
        &base,
        "/api/buckets/ulc-missing/lifecycle",
        &session,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_console_lifecycle_validation_error() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/ulcval", base), vec![]).await;
    let path = "/api/buckets/ulcval/lifecycle";
    for rules in [
        // no action
        serde_json::json!([{ "status": "Enabled" }]),
        // days + date
        serde_json::json!([{ "status": "Enabled", "expiration": { "days": 1, "date": "2030-01-01" } }]),
        // zero days
        serde_json::json!([{ "status": "Enabled", "expiration": { "days": 0 } }]),
        // duplicate ids
        serde_json::json!([
            { "id": "a", "status": "Enabled", "expiration": { "days": 1 } },
            { "id": "a", "status": "Enabled", "expiration": { "days": 2 } }
        ]),
        // date not at midnight
        serde_json::json!([{ "status": "Enabled", "expiration": { "date": "2030-01-01T10:00:00Z" } }]),
    ] {
        let (status, body) = console_json(
            "PUT",
            &base,
            path,
            &session,
            Some(serde_json::json!({ "rules": rules })),
        )
        .await;
        assert_eq!(status, 400, "{}", body);
        assert!(body["error"].is_string(), "{}", body);
    }
    // Nothing was stored.
    let (_, body) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(body["rules"], serde_json::json!([]));

    let (status, _) = console_json(
        "PUT",
        &base,
        "/api/buckets/ulcval-missing/lifecycle",
        &session,
        Some(serde_json::json!({ "rules": [] })),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_console_lifecycle_empty_deletes() {
    let (base, _tmp) = start_server().await;
    let session = console_login(&base).await;
    s3_request("PUT", &format!("{}/ulcdel", base), vec![]).await;
    let path = "/api/buckets/ulcdel/lifecycle";
    let (status, _) = console_json(
        "PUT",
        &base,
        path,
        &session,
        Some(serde_json::json!({ "rules": [
            { "status": "Enabled", "expiration": { "days": 5 } }
        ] })),
    )
    .await;
    assert_eq!(status, 200);
    let r = s3_request("GET", &format!("{}/ulcdel?lifecycle", base), vec![]).await;
    assert_eq!(r.status(), 200);

    let (status, body) = console_json(
        "PUT",
        &base,
        path,
        &session,
        Some(serde_json::json!({ "rules": [] })),
    )
    .await;
    assert_eq!(status, 200, "{}", body);
    assert_eq!(body["rules"], serde_json::json!([]));
    let (_, body) = console_json("GET", &base, path, &session, None).await;
    assert_eq!(body["rules"], serde_json::json!([]));
    let r = s3_request("GET", &format!("{}/ulcdel?lifecycle", base), vec![]).await;
    assert_eq!(r.status(), 404);
}
