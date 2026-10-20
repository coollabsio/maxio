//! Virtual-hosted-style addressing (`<bucket>.<domain>/<key>`) next to path-style.
//!
//! DNS for `*.localhost` is not required: the client pins those names to the
//! test listener. Host mismatch cases (uppercase, `X-Forwarded-Host`) are sent
//! as raw HTTP so the `Host` header is exactly the one under test.

use std::net::SocketAddr;
use std::time::Duration;

use hmac::{Hmac, Mac};
use maxio::config::Config;
use maxio::server::{self, AppState};
use maxio::storage::filesystem::FilesystemStorage;
use maxio::storage::keys::Keyring;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type HmacSha256 = Hmac<Sha256>;

const ACCESS_KEY: &str = "maxioadmin";
const SECRET_KEY: &str = "maxioadmin";
const REGION: &str = "us-east-1";

struct Running {
    base: String,
    port: u16,
    _tmp: TempDir,
}

async fn start(domain: &str) -> Running {
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
        domain: domain.to_string(),
        ..Config::default()
    };
    let revoked_sessions = Arc::new(
        maxio::api::console::RevokedSessions::open(std::path::Path::new(&config.data_dir)).await,
    );
    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
        login_rate_limiter: Arc::new(maxio::api::console::LoginRateLimiter::new()),
        revoked_sessions,
    };
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Running {
        base: format!("http://127.0.0.1:{port}"),
        port,
        _tmp: tmp,
    }
}

fn http_client(port: u16, hosts: &[&str]) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().no_proxy();
    for host in hosts {
        builder = builder.resolve(host, SocketAddr::from(([127, 0, 0, 1], port)));
    }
    builder.build().unwrap()
}

fn sign_request(method: &str, url: &str, headers: &mut Vec<(String, String)>, body: &[u8]) {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{host}:{port}");
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");
    sign_explicit(method, &host_header, path, query, headers, body);
}

fn sign_explicit(
    method: &str,
    host_header: &str,
    path: &str,
    query: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload_hash = hex::encode(Sha256::digest(body));

    headers.push(("host".to_string(), host_header.to_string()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers_str = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let canonical_qs = canonical_query(query);
    let canonical_request = format!(
        "{method}\n{path}\n{canonical_qs}\n{canonical_headers}\n{signed_headers_str}\n{payload_hash}"
    );
    let scope = format!("{date_stamp}/{REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let signature = hmac_hex(
        signing_key(&date_stamp).as_slice(),
        string_to_sign.as_bytes(),
    );
    headers.push((
        "authorization".to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, SignedHeaders={signed_headers_str}, Signature={signature}"
        ),
    ));
}

fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let mut parts = pair.splitn(2, '=');
            (
                parts.next().unwrap_or("").to_string(),
                parts.next().unwrap_or("").to_string(),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn signing_key(date_stamp: &str) -> Vec<u8> {
    let key = format!("AWS4{SECRET_KEY}");
    let date_key = hmac_raw(key.as_bytes(), date_stamp.as_bytes());
    let date_region = hmac_raw(&date_key, REGION.as_bytes());
    let date_region_service = hmac_raw(&date_region, b"s3");
    hmac_raw(&date_region_service, b"aws4_request")
}

fn hmac_raw(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_raw(key, data))
}

fn percent_encode_s3(input: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(input, SET).to_string()
}

fn presign(host_header: &str, method: &str, path: &str) -> String {
    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{ACCESS_KEY}/{date_stamp}/{REGION}/s3/aws4_request");
    let mut pairs = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", "300".to_string()),
        ("X-Amz-SignedHeaders", "host".to_string()),
    ];
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_qs = pairs
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode_s3(key), percent_encode_s3(value)))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_request =
        format!("{method}\n{path}\n{canonical_qs}\nhost:{host_header}\n\nhost\nUNSIGNED-PAYLOAD");
    let scope = format!("{date_stamp}/{REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let signature = hmac_hex(
        signing_key(&date_stamp).as_slice(),
        string_to_sign.as_bytes(),
    );
    format!("{canonical_qs}&X-Amz-Signature={signature}")
}

async fn call(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    body: Vec<u8>,
    extra: &[(&str, &str)],
) -> reqwest::Response {
    let mut headers: Vec<(String, String)> = extra
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    sign_request(method, url, &mut headers, &body);
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        other => panic!("unsupported method {other}"),
    };
    for (name, value) in &headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if !body.is_empty() {
        builder = builder.body(body);
    }
    builder.send().await.unwrap()
}

async fn call_status(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    body: Vec<u8>,
    extra: &[(&str, &str)],
) -> (u16, String) {
    let response = call(client, method, url, body, extra).await;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    (status, text)
}

fn vurl(host: &str, port: u16, path_and_query: &str) -> String {
    format!("http://{host}:{port}{path_and_query}")
}

fn xml_tag(body: &str, tag: &str) -> String {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let from = body
        .find(&start)
        .unwrap_or_else(|| panic!("missing {tag} in {body}"));
    let rest = &body[from + start.len()..];
    let to = rest
        .find(&end)
        .unwrap_or_else(|| panic!("missing end {tag} in {body}"));
    rest[..to].to_string()
}

async fn raw_http(port: u16, message: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(message).await.unwrap();
    // Half-closing the write side makes hyper drop the response. Read until the
    // server closes (`Connection: close`) or the declared body has arrived.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        if response_complete(&buf) {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(err)) => panic!("read failed: {err}"),
            Err(_) if !buf.is_empty() => break,
            Err(_) => panic!("timed out waiting for a response"),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    (status, text)
}

fn response_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    if let Some(line) = headers
        .lines()
        .find(|line| line.starts_with("content-length:"))
    {
        let len: usize = line["content-length:".len()..].trim().parse().unwrap_or(0);
        return buf.len() >= header_end + 4 + len;
    }
    false
}

fn raw_message(method: &str, target: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut message = format!("{method} {target} HTTP/1.1\r\n");
    for (name, value) in headers {
        message.push_str(&format!("{name}: {value}\r\n"));
    }
    message.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    let mut bytes = message.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[tokio::test]
async fn domain_unset_keeps_path_style_and_health() {
    let server = start("").await;
    let client = http_client(server.port, &[]);

    let (status, _) = call_status(
        &client,
        "PUT",
        &format!("{}/plain-bucket", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = call_status(
        &client,
        "PUT",
        &format!("{}/plain-bucket/note.txt", server.base),
        b"path".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let response = call(
        &client,
        "GET",
        &format!("{}/plain-bucket/note.txt", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"path");

    // A bucket-shaped Host is ignored until a domain is configured.
    let (status, body) = raw_http(
        server.port,
        b"GET /maxio/health/live HTTP/1.1\r\nhost: photos.localhost\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("<Code>"));
}

#[tokio::test]
async fn virtual_and_path_style_round_trip() {
    let server = start("localhost").await;
    let host = "photos.localhost";
    let client = http_client(server.port, &[host]);

    let (status, body) =
        call_status(&client, "PUT", &vurl(host, server.port, "/"), vec![], &[]).await;
    assert_eq!(status, 200, "{body}");

    let (status, _) = call_status(
        &client,
        "HEAD",
        &format!("{}/photos", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl(host, server.port, "/album/pic.txt"),
        b"from-virtual".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let response = call(
        &client,
        "GET",
        &format!("{}/photos/album/pic.txt", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"from-virtual");

    let (status, body) = call_status(
        &client,
        "PUT",
        &format!("{}/photos/album/other.txt", server.base),
        b"from-path".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let response = call(
        &client,
        "GET",
        &vurl(host, server.port, "/album/other.txt"),
        vec![],
        &[],
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"from-path");

    let (status, listing) = call_status(
        &client,
        "GET",
        &vurl(host, server.port, "/?list-type=2&prefix=album%2F"),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{listing}");
    assert!(listing.contains("<Key>album/pic.txt</Key>"), "{listing}");
    assert!(listing.contains("<Key>album/other.txt</Key>"), "{listing}");
    assert!(listing.contains("<Name>photos</Name>"), "{listing}");

    let buckets = call(&client, "GET", &format!("{}/", server.base), vec![], &[])
        .await
        .text()
        .await
        .unwrap();
    assert!(buckets.contains("<Name>photos</Name>"), "{buckets}");
}

#[tokio::test]
async fn virtual_multipart_copy_presign_and_subresources() {
    let server = start("localhost").await;
    let host = "media.localhost";
    let client = http_client(server.port, &[host]);
    let anon = http_client(server.port, &[host]);

    let (status, body) =
        call_status(&client, "PUT", &vurl(host, server.port, "/"), vec![], &[]).await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl(host, server.port, "/src.txt"),
        b"copy-me".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl(host, server.port, "/dst.txt"),
        vec![],
        &[("x-amz-copy-source", "/media/src.txt")],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("<LastModified>"), "{body}");
    let copied = call(
        &client,
        "GET",
        &vurl(host, server.port, "/dst.txt"),
        vec![],
        &[],
    )
    .await
    .bytes()
    .await
    .unwrap();
    assert_eq!(copied.as_ref(), b"copy-me");

    let (status, created) = call_status(
        &client,
        "POST",
        &vurl(host, server.port, "/large.bin?uploads="),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{created}");
    let upload_id = xml_tag(&created, "UploadId");
    let part = call(
        &client,
        "PUT",
        &vurl(
            host,
            server.port,
            &format!("/large.bin?partNumber=1&uploadId={upload_id}"),
        ),
        b"part-body".to_vec(),
        &[],
    )
    .await;
    assert_eq!(part.status(), 200);
    let etag = part
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let (status, body) = call_status(
        &client,
        "POST",
        &vurl(
            host,
            server.port,
            &format!("/large.bin?uploadId={upload_id}"),
        ),
        complete.into_bytes(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let object = call(
        &client,
        "GET",
        &format!("{}/media/large.bin", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(object.bytes().await.unwrap().as_ref(), b"part-body");

    let tagging =
        "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>";
    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl(host, server.port, "/?tagging"),
        tagging.as_bytes().to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (status, body) = call_status(
        &client,
        "GET",
        &vurl(host, server.port, "/?tagging"),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("<Key>env</Key>"), "{body}");

    let lifecycle = "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl(host, server.port, "/?lifecycle"),
        lifecycle.as_bytes().to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call_status(
        &client,
        "GET",
        &vurl(host, server.port, "/?lifecycle"),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("<ID>logs</ID>"), "{body}");
    assert!(body.contains("<Days>30</Days>"), "{body}");

    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::media/*"}]}"#;
    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl(host, server.port, "/?policy"),
        policy.as_bytes().to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (status, body) = call_status(
        &client,
        "GET",
        &vurl(host, server.port, "/?policy"),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("s3:GetObject"), "{body}");

    let public = anon
        .get(vurl(host, server.port, "/src.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(public.status(), 200);
    assert_eq!(public.bytes().await.unwrap().as_ref(), b"copy-me");

    let (status, location) = call_status(
        &client,
        "GET",
        &vurl(host, server.port, "/?location"),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{location}");
    // us-east-1 is an empty LocationConstraint, the same as AWS.
    assert!(location.contains("<LocationConstraint"), "{location}");
    assert!(!location.contains(&format!(">{REGION}<")), "{location}");

    let virtual_qs = presign(&format!("{host}:{}", server.port), "GET", "/src.txt");
    let presigned = anon
        .get(vurl(host, server.port, &format!("/src.txt?{virtual_qs}")))
        .send()
        .await
        .unwrap();
    assert_eq!(presigned.status(), 200);
    assert_eq!(presigned.bytes().await.unwrap().as_ref(), b"copy-me");

    let path_qs = presign(
        &format!("127.0.0.1:{}", server.port),
        "GET",
        "/media/dst.txt",
    );
    let presigned = anon
        .get(format!("{}/media/dst.txt?{path_qs}", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(presigned.status(), 200);
    assert_eq!(presigned.bytes().await.unwrap().as_ref(), b"copy-me");
}

#[tokio::test]
async fn dotted_bucket_uppercase_host_and_service_routes() {
    let server = start("localhost").await;
    let host = "my.bucket.localhost";
    let client = http_client(server.port, &[host, "photos.localhost"]);

    let (status, body) = call_status(
        &client,
        "PUT",
        &format!("{}/my.bucket", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl(host, server.port, "/nested/file.txt"),
        b"dotted".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let response = call(
        &client,
        "GET",
        &format!("{}/my.bucket/nested/file.txt", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"dotted");

    let (status, body) = call_status(
        &client,
        "PUT",
        &format!("{}/photos", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call_status(
        &client,
        "PUT",
        &format!("{}/photos/healthz", server.base),
        b"object-not-probe".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // SigV4 keeps the Host value's case. The bucket label is matched in lowercase.
    let mut headers = Vec::new();
    sign_explicit(
        "GET",
        &format!("My.Bucket.LocalHost:{}", server.port),
        "/nested/file.txt",
        "",
        &mut headers,
        b"",
    );
    let (status, body) = raw_http(
        server.port,
        &raw_message("GET", "/nested/file.txt", &headers, b""),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("dotted"), "{body}");

    let health = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("{}/maxio/health/live", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body = health.text().await.unwrap();
    assert!(health_body.contains("\"status\":\"ok\""), "{health_body}");
    assert!(!health_body.contains("\"version\""), "{health_body}");

    for path in ["/maxio/health/ready"] {
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("{}{path}", server.base))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{path}");
    }

    let console = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("{}/maxio/api/auth/check", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(console.status(), 401);
    let console_body = console.text().await.unwrap();
    assert!(console_body.contains("Not authenticated"), "{console_body}");

    let ui = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("{}/ui/", server.base))
        .send()
        .await
        .unwrap();
    let ui_status = ui.status().as_u16();
    let ui_body = ui.text().await.unwrap();
    assert!(
        ui_status == 200 || ui_status == 503,
        "console route returned {ui_status}: {ui_body}"
    );
    assert!(!ui_body.contains("<Code>"), "{ui_body}");

    let mut headers = Vec::new();
    sign_explicit(
        "GET",
        &format!("photos.localhost:{}", server.port),
        "/healthz",
        "",
        &mut headers,
        b"",
    );
    let (status, body) =
        raw_http(server.port, &raw_message("GET", "/healthz", &headers, b"")).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("object-not-probe"), "{body}");

    let (status, body) = raw_http(
        server.port,
        &format!(
            "GET /maxio/api/auth/check HTTP/1.1\r\nhost: photos.localhost:{}\r\nconnection: close\r\n\r\n",
            server.port
        )
        .into_bytes(),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("<Code>"), "{body}");
    assert!(!body.contains("Not authenticated"), "{body}");
}

#[tokio::test]
async fn forwarded_host_and_longest_domain() {
    let server = start("example.test,s3.example.test").await;
    let client = http_client(
        server.port,
        &[
            "photos.example.test",
            "album.s3.example.test",
            "album.example.test",
        ],
    );

    let (status, body) = call_status(
        &client,
        "PUT",
        &format!("{}/photos", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let mut headers = Vec::new();
    sign_explicit(
        "PUT",
        &format!("photos.example.test:{}", server.port),
        "/hello.txt",
        "",
        &mut headers,
        b"via-proxy",
    );
    // Drop the signed host value and send the internal Host plus X-Forwarded-Host.
    headers.retain(|(name, _)| name != "host");
    headers.insert(
        0,
        ("host".to_string(), format!("127.0.0.1:{}", server.port)),
    );
    headers.insert(
        1,
        (
            "x-forwarded-host".to_string(),
            format!("photos.example.test:{}", server.port),
        ),
    );
    let (status, body) = raw_http(
        server.port,
        &raw_message("PUT", "/hello.txt", &headers, b"via-proxy"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let stored = call(
        &client,
        "GET",
        &format!("{}/photos/hello.txt", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(stored.bytes().await.unwrap().as_ref(), b"via-proxy");

    let (status, _) = call_status(
        &client,
        "PUT",
        &format!("{}/victim", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = call_status(
        &client,
        "PUT",
        &format!("{}/other", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200);

    let mut attack = Vec::new();
    sign_explicit(
        "PUT",
        &format!("127.0.0.1:{}", server.port),
        "/victim/secret",
        "",
        &mut attack,
        b"nope",
    );
    attack.insert(
        0,
        (
            "x-forwarded-host".to_string(),
            format!("other.example.test:{}", server.port),
        ),
    );
    let (status, body) = raw_http(
        server.port,
        &raw_message("PUT", "/victim/secret", &attack, b"nope"),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("SignatureDoesNotMatch"), "{body}");
    for key in ["/victim/secret", "/other/secret", "/other/victim/secret"] {
        let (status, _) = call_status(
            &client,
            "GET",
            &format!("{}{key}", server.base),
            vec![],
            &[],
        )
        .await;
        assert_eq!(status, 404, "{key}");
    }

    let (status, body) = raw_http(
        server.port,
        &format!(
            "GET /maxio/health/live HTTP/1.1\r\nhost: example.test:{}\r\nx-forwarded-host: photos.example.test\r\nconnection: close\r\n\r\n",
            server.port
        )
        .into_bytes(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("<Code>"), "{body}");

    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl("album.s3.example.test", server.port, "/"),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call_status(
        &client,
        "PUT",
        &vurl("album.s3.example.test", server.port, "/pic.jpg"),
        b"longest".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let response = call(
        &client,
        "GET",
        &format!("{}/album/pic.jpg", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"longest");
    let (status, _) = call_status(
        &client,
        "HEAD",
        &format!("{}/album.s3", server.base),
        vec![],
        &[],
    )
    .await;
    assert_eq!(status, 404);

    let (status, body) = raw_http(
        server.port,
        b"GET /ui/ HTTP/1.1\r\nhost: s3.example.test\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status == 200 || status == 503,
        "service host /ui/ returned {status}: {body}"
    );
    assert!(!body.contains("<Code>"), "{body}");
}

#[tokio::test]
async fn buckets_named_version_and_healthz_work_on_virtual_host() {
    let server = start("localhost").await;
    let hosts = [
        "version.localhost",
        "healthz.localhost",
        "api.localhost",
        "readyz.localhost",
    ];
    let client = http_client(server.port, &hosts);

    for bucket in ["version", "healthz", "api", "readyz"] {
        let host = format!("{bucket}.localhost");
        let root = vurl(&host, server.port, "/");
        let (status, body) = call_status(&client, "PUT", &root, vec![], &[]).await;
        assert_eq!(status, 200, "{bucket} create: {body}");

        let key = vurl(&host, server.port, "/note.txt");
        let (status, body) = call_status(&client, "PUT", &key, b"vhost-probe".to_vec(), &[]).await;
        assert_eq!(status, 200, "{bucket} put: {body}");

        let (status, body) = call_status(&client, "GET", &key, vec![], &[]).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, "vhost-probe");

        let (status, body) = call_status(&client, "GET", &root, vec![], &[]).await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("note.txt"), "{body}");
        assert!(
            !body.contains("\"status\":\"ok\""),
            "virtual-hosted list must not be the health probe: {body}"
        );

        let versioning = vurl(&host, server.port, "/?versioning");
        let (status, body) = call_status(&client, "GET", &versioning, vec![], &[]).await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("VersioningConfiguration"), "{body}");

        let (status, _) = call_status(&client, "DELETE", &key, vec![], &[]).await;
        assert_eq!(status, 204, "{bucket} delete object");
        let (status, body) = call_status(&client, "DELETE", &root, vec![], &[]).await;
        assert_eq!(status, 204, "{bucket} delete bucket: {body}");
    }

    let health = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("{}/maxio/health/live", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body = health.text().await.unwrap();
    assert!(health_body.contains("\"status\":\"ok\""), "{health_body}");
    assert!(!health_body.contains("\"version\""), "{health_body}");

    let reserved = http_client(server.port, &["maxio.localhost", "ui.localhost"]);
    for bucket in ["maxio", "ui"] {
        let (status, body) = call_status(
            &reserved,
            "PUT",
            &vurl(&format!("{bucket}.localhost"), server.port, "/"),
            vec![],
            &[],
        )
        .await;
        assert_eq!(status, 400, "{bucket}: {body}");
        assert!(body.contains("InvalidBucketName"), "{body}");
    }
}
