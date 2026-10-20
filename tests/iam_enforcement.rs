//! IAM enforcement against a live server: scoped keys, presign, copy, and the
//! IAM query API.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use maxio::config::Config;
use maxio::server::{self, AppState};
use maxio::storage::filesystem::FilesystemStorage;
use maxio::storage::keys::Keyring;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

type HmacSha256 = Hmac<Sha256>;

const ROOT_KEY: &str = "maxioadmin";
const ROOT_SECRET: &str = "maxioadmin";
const REGION: &str = "us-east-1";

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
        access_key: ROOT_KEY.to_string(),
        secret_key: ROOT_SECRET.to_string(),
        region: REGION.to_string(),
        master_key: None,
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
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (base, tmp)
}

fn sign(
    method: &str,
    url: &str,
    access_key: &str,
    secret: &str,
    service: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = format!("{}:{}", parsed.host_str().unwrap(), parsed.port().unwrap());
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");
    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload_hash = hex::encode(Sha256::digest(body));
    headers.push(("host".into(), host));
    headers.push(("x-amz-date".into(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".into(), payload_hash.clone()));
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let signed = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();
    let canonical =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let scope = format!("{date_stamp}/{REGION}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let mut mac = HmacSha256::new_from_slice(format!("AWS4{secret}").as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&region_key).unwrap();
    mac.update(service.as_bytes());
    let service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    headers.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
        ),
    ));
}

async fn call(
    method: &str,
    url: &str,
    access_key: &str,
    secret: &str,
    service: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> reqwest::Response {
    let mut headers = extra
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect::<Vec<_>>();
    sign(method, url, access_key, secret, service, &mut headers, body);
    let client = reqwest::Client::new();
    let mut req = client.request(method.parse().unwrap(), url);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    req.body(body.to_vec()).send().await.unwrap()
}

async fn console_login(base: &str, access: &str, secret: &str) -> (u16, String, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/maxio/api/auth/login"))
        .json(&serde_json::json!({ "accessKey": access, "secretKey": secret }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim_start_matches("maxio_session=")
        .to_string();
    let body = resp
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::json!({}));
    (status, cookie, body)
}

fn text_between<'a>(xml: &'a str, tag: &str) -> &'a str {
    let start = xml.find(&format!("<{tag}>")).expect(tag) + tag.len() + 2;
    let end = xml.find(&format!("</{tag}>")).expect(tag);
    &xml[start..end]
}

#[tokio::test]
async fn scoped_key_allows_reads_and_denies_writes() {
    let (base, _tmp) = start_server().await;
    let put = call(
        "PUT",
        &format!("{base}/pics"),
        ROOT_KEY,
        ROOT_SECRET,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(put.status(), 200);
    let put = call(
        "PUT",
        &format!("{base}/pics/albums/a.txt"),
        ROOT_KEY,
        ROOT_SECRET,
        "s3",
        b"hello",
        &[("content-type", "text/plain")],
    )
    .await;
    assert_eq!(put.status(), 200);
    let put = call(
        "PUT",
        &format!("{base}/other"),
        ROOT_KEY,
        ROOT_SECRET,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(put.status(), 200);

    let (status, cookie, session) = console_login(&base, ROOT_KEY, ROOT_SECRET).await;
    assert_eq!(status, 200);
    assert_eq!(session["root"], true);
    assert_eq!(session["iamAdmin"], true);

    let client = reqwest::Client::new();
    let created = client
        .post(format!("{base}/maxio/api/iam/users"))
        .header("cookie", format!("maxio_session={cookie}"))
        .json(&serde_json::json!({ "name": "alice" }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200, "{}", created.text().await.unwrap());

    // The user can read and write the whole bucket. The key below only narrows
    // that to read access under pics/albums/. Creating a key does not grant the user.
    let user_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:PutObject","s3:DeleteObject","s3:ListBucket","s3:GetBucketLocation"],"Resource":["arn:aws:s3:::pics","arn:aws:s3:::pics/*"]}]}"#;
    let granted = client
        .put(format!(
            "{base}/maxio/api/iam/users/alice/inline/pics-readwrite"
        ))
        .header("cookie", format!("maxio_session={cookie}"))
        .json(&serde_json::json!({ "documentJson": user_policy }))
        .send()
        .await
        .unwrap();
    assert_eq!(granted.status(), 200, "{}", granted.text().await.unwrap());

    let key = client
        .post(format!("{base}/maxio/api/iam/users/alice/keys"))
        .header("cookie", format!("maxio_session={cookie}"))
        .json(&serde_json::json!({
            "buckets": ["pics"],
            "prefix": "albums",
            "access": "read"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(key.status(), 200, "{}", key.text().await.unwrap());
    let key: serde_json::Value = key.json().await.unwrap();
    let access = key["accessKeyId"].as_str().unwrap().to_string();
    let secret = key["secretAccessKey"].as_str().unwrap().to_string();
    assert!(secret.starts_with("mxsk_"));

    let get = call(
        "GET",
        &format!("{base}/pics/albums/a.txt"),
        &access,
        &secret,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.text().await.unwrap(), "hello");

    let denied = call(
        "PUT",
        &format!("{base}/pics/albums/b.txt"),
        &access,
        &secret,
        "s3",
        b"nope",
        &[],
    )
    .await;
    assert_eq!(denied.status(), 403);
    assert!(denied.text().await.unwrap().contains("AccessDenied"));

    let other = call(
        "GET",
        &format!("{base}/other"),
        &access,
        &secret,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(other.status(), 403);

    let list_root = call("GET", &base, &access, &secret, "s3", b"", &[]).await;
    assert_eq!(list_root.status(), 403);

    let (login_status, user_cookie, user_session) = console_login(&base, &access, &secret).await;
    assert_eq!(login_status, 200);
    assert_eq!(user_session["kind"], "user");
    assert_eq!(user_session["userName"], "alice");
    assert_eq!(user_session["iamAdmin"], false);
    let buckets = client
        .get(format!("{base}/maxio/api/buckets"))
        .header("cookie", format!("maxio_session={user_cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(buckets.status(), 200, "{}", buckets.text().await.unwrap());
    let buckets: serde_json::Value = buckets.json().await.unwrap();
    let names: Vec<_> = buckets["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["pics"]);

    let download = client
        .get(format!(
            "{base}/maxio/api/buckets/pics/download/albums/a.txt"
        ))
        .header("cookie", format!("maxio_session={user_cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(download.text().await.unwrap(), "hello");

    let upload = client
        .put(format!("{base}/maxio/api/buckets/pics/upload/albums/b.txt"))
        .header("cookie", format!("maxio_session={user_cookie}"))
        .body("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), 403);

    let users = client
        .get(format!("{base}/maxio/api/iam/users"))
        .header("cookie", format!("maxio_session={user_cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(users.status(), 403);
}

#[tokio::test]
async fn inactive_and_deleted_keys_fail_and_copy_checks_source() {
    let (base, _tmp) = start_server().await;
    for bucket in ["src", "dst"] {
        assert_eq!(
            call(
                "PUT",
                &format!("{base}/{bucket}"),
                ROOT_KEY,
                ROOT_SECRET,
                "s3",
                b"",
                &[]
            )
            .await
            .status(),
            200
        );
    }
    assert_eq!(
        call(
            "PUT",
            &format!("{base}/src/file.txt"),
            ROOT_KEY,
            ROOT_SECRET,
            "s3",
            b"data",
            &[]
        )
        .await
        .status(),
        200
    );

    let iam = call(
        "POST",
        &base,
        ROOT_KEY,
        ROOT_SECRET,
        "iam",
        b"Action=CreateUser&UserName=bob",
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    let iam_status = iam.status();
    let iam_body = iam.text().await.unwrap();
    assert_eq!(iam_status, 200, "{iam_body}");
    assert!(iam_body.contains("<UserName>bob</UserName>"));

    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::dst/*","arn:aws:s3:::src/file.txt"]}]}"#;
    let form = format!(
        "Action=PutUserPolicy&UserName=bob&PolicyName=scope&PolicyDocument={}",
        urlencoding(policy)
    );
    let put_policy = call(
        "POST",
        &base,
        ROOT_KEY,
        ROOT_SECRET,
        "iam",
        form.as_bytes(),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(
        put_policy.status(),
        200,
        "{}",
        put_policy.text().await.unwrap()
    );

    let created = call(
        "POST",
        &base,
        ROOT_KEY,
        ROOT_SECRET,
        "iam",
        b"Action=CreateAccessKey&UserName=bob",
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    let created_status = created.status();
    let xml = created.text().await.unwrap();
    assert_eq!(created_status, 200, "{xml}");
    let access = text_between(&xml, "AccessKeyId").to_string();
    let secret = text_between(&xml, "SecretAccessKey").to_string();

    let copy = call(
        "PUT",
        &format!("{base}/dst/copy.txt"),
        &access,
        &secret,
        "s3",
        b"",
        &[("x-amz-copy-source", "/src/file.txt")],
    )
    .await;
    assert_eq!(copy.status(), 200, "{}", copy.text().await.unwrap());

    let forbidden_copy = call(
        "PUT",
        &format!("{base}/dst/nope.txt"),
        &access,
        &secret,
        "s3",
        b"",
        &[("x-amz-copy-source", "/src/missing-perm.txt")],
    )
    .await;
    // Source object does not exist, but the key also lacks GetObject on that key.
    assert_eq!(forbidden_copy.status(), 403);

    let update =
        format!("Action=UpdateAccessKey&UserName=bob&AccessKeyId={access}&Status=Inactive");
    assert_eq!(
        call(
            "POST",
            &base,
            ROOT_KEY,
            ROOT_SECRET,
            "iam",
            update.as_bytes(),
            &[("content-type", "application/x-www-form-urlencoded")]
        )
        .await
        .status(),
        200
    );
    let inactive = call(
        "GET",
        &format!("{base}/src/file.txt"),
        &access,
        &secret,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(inactive.status(), 403);

    let (disabled_login, _, _) = console_login(&base, &access, &secret).await;
    assert_eq!(disabled_login, 403);

    let delete = format!("Action=DeleteAccessKey&UserName=bob&AccessKeyId={access}");
    assert_eq!(
        call(
            "POST",
            &base,
            ROOT_KEY,
            ROOT_SECRET,
            "iam",
            delete.as_bytes(),
            &[("content-type", "application/x-www-form-urlencoded")]
        )
        .await
        .status(),
        200
    );
    let gone = call(
        "GET",
        &format!("{base}/src/file.txt"),
        &access,
        &secret,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(gone.status(), 403);
    assert!(gone.text().await.unwrap().contains("InvalidAccessKeyId"));
}

#[tokio::test]
async fn explicit_deny_beats_public_bucket_policy() {
    let (base, _tmp) = start_server().await;
    assert_eq!(
        call(
            "PUT",
            &format!("{base}/pub"),
            ROOT_KEY,
            ROOT_SECRET,
            "s3",
            b"",
            &[]
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        call(
            "PUT",
            &format!("{base}/pub/a.txt"),
            ROOT_KEY,
            ROOT_SECRET,
            "s3",
            b"public",
            &[]
        )
        .await
        .status(),
        200
    );
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}"#;
    let put_policy = call(
        "PUT",
        &format!("{base}/pub?policy="),
        ROOT_KEY,
        ROOT_SECRET,
        "s3",
        policy.as_bytes(),
        &[],
    )
    .await;
    let policy_status = put_policy.status();
    assert!(
        policy_status.is_success(),
        "put bucket policy status {policy_status}: {}",
        put_policy.text().await.unwrap()
    );

    let anon = reqwest::get(format!("{base}/pub/a.txt")).await.unwrap();
    assert_eq!(anon.status(), 200);

    let (status, cookie, _) = console_login(&base, ROOT_KEY, ROOT_SECRET).await;
    assert_eq!(status, 200);
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .post(format!("{base}/maxio/api/iam/users"))
            .header("cookie", format!("maxio_session={cookie}"))
            .json(&serde_json::json!({ "name": "carol" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let deny = r#"{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}"#;
    let key = client
        .post(format!("{base}/maxio/api/iam/users/carol/keys"))
        .header("cookie", format!("maxio_session={cookie}"))
        .json(&serde_json::json!({ "documentJson": deny, "keyOnly": true }))
        .send()
        .await
        .unwrap();
    // A deny-only key policy does not grant, and the user has no allow, so the
    // public bucket policy would otherwise allow the read. The explicit deny wins.
    // keyOnly with only a deny still stores that deny on the key. The user has
    // no allow, so identity is implicit deny plus explicit deny.
    assert_eq!(key.status(), 200, "{}", key.text().await.unwrap());
    let key: serde_json::Value = key.json().await.unwrap();
    let access = key["accessKeyId"].as_str().unwrap();
    let secret = key["secretAccessKey"].as_str().unwrap();
    let got = call(
        "GET",
        &format!("{base}/pub/a.txt"),
        access,
        secret,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(got.status(), 403);
}

#[tokio::test]
async fn create_key_scope_does_not_grant_the_user() {
    let (base, _tmp) = start_server().await;
    assert_eq!(
        call(
            "PUT",
            &format!("{base}/photos"),
            ROOT_KEY,
            ROOT_SECRET,
            "s3",
            b"",
            &[]
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        call(
            "PUT",
            &format!("{base}/photos/uploads/a.txt"),
            ROOT_KEY,
            ROOT_SECRET,
            "s3",
            b"pic",
            &[]
        )
        .await
        .status(),
        200
    );
    let (status, cookie, _) = console_login(&base, ROOT_KEY, ROOT_SECRET).await;
    assert_eq!(status, 200);
    let client = reqwest::Client::new();
    let cookie = format!("maxio_session={cookie}");
    assert_eq!(
        client
            .post(format!("{base}/maxio/api/iam/users"))
            .header("cookie", &cookie)
            .json(&serde_json::json!({ "name": "bob" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let read = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::photos/*"}]}"#;
    assert_eq!(
        client
            .put(format!("{base}/maxio/api/iam/users/bob/inline/read"))
            .header("cookie", &cookie)
            .json(&serde_json::json!({ "documentJson": read }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let first = client
        .post(format!("{base}/maxio/api/iam/users/bob/keys"))
        .header("cookie", &cookie)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200, "{}", first.text().await.unwrap());
    let first: serde_json::Value = first.json().await.unwrap();
    let first_id = first["accessKeyId"].as_str().unwrap();
    let first_secret = first["secretAccessKey"].as_str().unwrap();

    let second = client
        .post(format!("{base}/maxio/api/iam/users/bob/keys"))
        .header("cookie", &cookie)
        .json(&serde_json::json!({
            "buckets": ["photos"],
            "prefix": "uploads/",
            "access": "write"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 200, "{}", second.text().await.unwrap());
    let second: serde_json::Value = second.json().await.unwrap();
    let second_doc = second["documentJson"].as_str().unwrap();
    assert!(second_doc.contains("uploads/*"), "{second_doc}");
    assert!(!second_doc.replace("uploads/*", "").contains("uploads*"));

    let user = client
        .get(format!("{base}/maxio/api/iam/users/bob"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let inline = user["inlinePolicies"].as_array().unwrap();
    assert_eq!(inline.len(), 1, "{user}");
    assert_eq!(inline[0]["name"], "read");

    let keys = client
        .get(format!("{base}/maxio/api/iam/users/bob/keys"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let second_id = second["accessKeyId"].as_str().unwrap();
    let listed = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["accessKeyId"] == second_id)
        .unwrap();
    let summary = listed["policySummary"].as_str().unwrap();
    assert!(summary.contains("uploads/*"), "{summary}");

    let read_ok = call(
        "GET",
        &format!("{base}/photos/uploads/a.txt"),
        first_id,
        first_secret,
        "s3",
        b"",
        &[],
    )
    .await;
    assert_eq!(read_ok.status(), 200);
    let widened = call(
        "PUT",
        &format!("{base}/photos/uploads/new.txt"),
        first_id,
        first_secret,
        "s3",
        b"nope",
        &[],
    )
    .await;
    assert_eq!(widened.status(), 403);

    let rejected = client
        .post(format!("{base}/maxio/api/iam/users/bob/keys"))
        .header("cookie", &cookie)
        .json(&serde_json::json!({
            "buckets": ["finance"],
            "prefix": "uploads/",
            "access": "read",
            "keyOnly": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 400, "{}", rejected.text().await.unwrap());
    let user = client
        .get(format!("{base}/maxio/api/iam/users/bob"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(user["inlinePolicies"].as_array().unwrap().len(), 1);
}

fn urlencoding(value: &str) -> String {
    let engine = percent_encoding::NON_ALPHANUMERIC;
    percent_encoding::utf8_percent_encode(value, engine).to_string()
}
