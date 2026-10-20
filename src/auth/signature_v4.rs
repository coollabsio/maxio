use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Characters that do NOT get percent-encoded in S3 SigV4 canonical URI.
/// Per AWS spec: A-Z, a-z, 0-9, '-', '_', '.', '~'
const S3_URI_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub struct ParsedAuth {
    pub access_key: String,
    pub date: String,
    pub region: String,
    /// Credential-scope service (`s3` or `iam`).
    pub service: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

/// Context needed to verify per-chunk signatures of a
/// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]` body. Built by the auth
/// middleware after the request (seed) signature has been verified and
/// inserted into the request extensions.
#[derive(Clone)]
pub struct StreamingSigningContext {
    pub signing_key: Vec<u8>,
    /// Request timestamp (`x-amz-date`, `YYYYMMDDTHHMMSSZ`).
    pub timestamp: String,
    /// Credential scope `date/region/s3/aws4_request`.
    pub scope: String,
    /// Signature of the request headers; seeds the chunk signature chain.
    pub seed_signature: String,
}

impl std::fmt::Debug for StreamingSigningContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingSigningContext")
            .field("signing_key", &"<redacted>")
            .field("timestamp", &self.timestamp)
            .field("scope", &self.scope)
            .finish()
    }
}

impl StreamingSigningContext {
    pub fn new(secret_key: &str, parsed: &ParsedAuth, timestamp: &str) -> Self {
        Self {
            signing_key: derive_signing_key(secret_key, &parsed.date, &parsed.region),
            timestamp: timestamp.to_string(),
            scope: format!("{}/{}/s3/aws4_request", parsed.date, parsed.region),
            seed_signature: parsed.signature.to_ascii_lowercase(),
        }
    }

    pub fn hmac_hex(&self, string_to_sign: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).unwrap();
        mac.update(string_to_sign.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

pub fn parse_authorization_header(header: &str) -> Result<ParsedAuth, &'static str> {
    let header = header
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or("Invalid auth algorithm")?;

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;

    // Split on "," — some clients use ", " (with space), others use "," (no space)
    for part in header.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("Credential=") {
            credential = Some(val);
        } else if let Some(val) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(val);
        } else if let Some(val) = part.strip_prefix("Signature=") {
            signature = Some(val);
        }
    }

    let credential = credential.ok_or("Missing Credential")?;
    let signed_headers = signed_headers.ok_or("Missing SignedHeaders")?;
    let signature = signature.ok_or("Missing Signature")?;

    let cred_parts: Vec<&str> = credential.splitn(5, '/').collect();
    if cred_parts.len() != 5 {
        return Err("Invalid Credential format");
    }

    Ok(ParsedAuth {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        service: cred_parts[3].to_string(),
        signed_headers: signed_headers.split(';').map(|s| s.to_string()).collect(),
        signature: signature.to_string(),
    })
}

pub fn verify_signature(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &HeaderMap,
    parsed: &ParsedAuth,
    secret_key: &str,
) -> bool {
    verify_signature_with_payload(method, uri, query_string, headers, parsed, secret_key, None)
}

/// `payload_hash` overrides `x-amz-content-sha256`. IAM signs the SHA-256 of
/// the body without sending that header; S3 sends the header or `UNSIGNED-PAYLOAD`.
pub fn verify_signature_with_payload(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &HeaderMap,
    parsed: &ParsedAuth,
    secret_key: &str,
    payload_hash: Option<&str>,
) -> bool {
    let canonical_request =
        build_canonical_request(method, uri, query_string, headers, parsed, payload_hash);

    tracing::debug!("Canonical request:\n{}", canonical_request);

    let timestamp = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let string_to_sign = build_string_to_sign(&canonical_request, timestamp, parsed);

    tracing::debug!("String to sign:\n{}", string_to_sign);

    let signing_key =
        derive_signing_key_with_service(secret_key, &parsed.date, &parsed.region, &parsed.service);

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());

    tracing::debug!("Computed signature: {}", computed);
    tracing::debug!("Provided signature: {}", parsed.signature);

    constant_time_eq(computed.as_bytes(), parsed.signature.as_bytes())
}

/// Parse presigned URL query parameters into auth components.
/// Returns (ParsedAuth, timestamp, expires_seconds).
pub fn parse_presigned_query(query: &str) -> Result<(ParsedAuth, String, u64), &'static str> {
    let mut algorithm = None;
    let mut credential = None;
    let mut date = None;
    let mut expires = None;
    let mut signed_headers = None;
    let mut signature = None;

    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        match key {
            "X-Amz-Algorithm" => algorithm = Some(val),
            "X-Amz-Credential" => credential = Some(val),
            "X-Amz-Date" => date = Some(val),
            "X-Amz-Expires" => expires = Some(val),
            "X-Amz-SignedHeaders" => signed_headers = Some(val),
            "X-Amz-Signature" => signature = Some(val),
            _ => {}
        }
    }

    let algorithm = algorithm.ok_or("Missing X-Amz-Algorithm")?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err("Invalid X-Amz-Algorithm");
    }

    let credential = credential.ok_or("Missing X-Amz-Credential")?;
    let timestamp = date.ok_or("Missing X-Amz-Date")?.to_string();
    let expires_str = expires.ok_or("Missing X-Amz-Expires")?;
    let signed_headers = signed_headers.ok_or("Missing X-Amz-SignedHeaders")?;
    let signature = signature.ok_or("Missing X-Amz-Signature")?;

    let expires_secs: u64 = expires_str.parse().map_err(|_| "Invalid X-Amz-Expires")?;
    if expires_secs > 604800 {
        return Err("X-Amz-Expires exceeds maximum of 604800 seconds");
    }

    // Credential is URL-encoded: access_key%2Fdate%2Fregion%2Fs3%2Faws4_request
    let credential_decoded = percent_encoding::percent_decode_str(credential)
        .decode_utf8()
        .map_err(|_| "Invalid Credential encoding")?;
    let cred_parts: Vec<&str> = credential_decoded.splitn(5, '/').collect();
    if cred_parts.len() != 5 {
        return Err("Invalid Credential format");
    }

    let parsed = ParsedAuth {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        service: cred_parts[3].to_string(),
        signed_headers: signed_headers.split(';').map(|s| s.to_string()).collect(),
        signature: signature.to_string(),
    };

    Ok((parsed, timestamp, expires_secs))
}

/// Verify a presigned URL signature.
pub fn verify_presigned_signature(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &HeaderMap,
    parsed: &ParsedAuth,
    timestamp: &str,
    secret_key: &str,
) -> bool {
    // Build canonical query string excluding X-Amz-Signature
    let filtered_qs: String = query_string
        .split('&')
        .filter(|pair| !pair.starts_with("X-Amz-Signature="))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_uri = canonical_uri(uri);
    let canonical_qs = canonical_query_string(&filtered_qs);
    let canonical_hdrs = canonical_headers(headers, &parsed.signed_headers);
    let signed_headers = parsed.signed_headers.join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
        method, canonical_uri, canonical_qs, canonical_hdrs, signed_headers
    );

    tracing::debug!("Presigned canonical request:\n{}", canonical_request);

    let string_to_sign = build_string_to_sign(&canonical_request, timestamp, parsed);

    tracing::debug!("Presigned string to sign:\n{}", string_to_sign);

    let signing_key =
        derive_signing_key_with_service(secret_key, &parsed.date, &parsed.region, &parsed.service);

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());

    tracing::debug!("Computed signature: {}", computed);
    tracing::debug!("Provided signature: {}", parsed.signature);

    constant_time_eq(computed.as_bytes(), parsed.signature.as_bytes())
}

fn build_canonical_request(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &HeaderMap,
    parsed: &ParsedAuth,
    payload_hash: Option<&str>,
) -> String {
    let canonical_uri = canonical_uri(uri);
    let canonical_qs = canonical_query_string(query_string);
    let canonical_headers = canonical_headers(headers, &parsed.signed_headers);
    let signed_headers = parsed.signed_headers.join(";");

    let payload_hash_owned;
    let payload_hash = match payload_hash {
        Some(hash) => hash,
        None => {
            payload_hash_owned = headers
                .get("x-amz-content-sha256")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("UNSIGNED-PAYLOAD")
                .to_string();
            payload_hash_owned.as_str()
        }
    };

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_qs, canonical_headers, signed_headers, payload_hash
    )
}

fn canonical_uri(uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or("/");
    if path.is_empty() || path == "/" {
        return "/".to_string();
    }
    // Decode first (path arrives percent-encoded from HTTP), then re-encode
    // to normalize per AWS SigV4 spec. Without decoding first, already-encoded
    // characters like %20 would be double-encoded to %2520.
    let segments: Vec<String> = path
        .split('/')
        .map(|s| {
            let decoded = percent_encoding::percent_decode_str(s).decode_utf8_lossy();
            percent_encoding::utf8_percent_encode(&decoded, S3_URI_ENCODE).to_string()
        })
        .collect();
    segments.join("/")
}

fn canonical_query_string(qs: &str) -> String {
    if qs.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = qs
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("").to_string();
            let val = parts.next().unwrap_or("").to_string();
            // Decode first (values arrive already percent-encoded from HTTP),
            // then re-encode to normalize per AWS SigV4 spec.
            let key_decoded = percent_encoding::percent_decode_str(&key)
                .decode_utf8_lossy()
                .into_owned();
            let val_decoded = percent_encoding::percent_decode_str(&val)
                .decode_utf8_lossy()
                .into_owned();
            (key_decoded, val_decoded)
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent_encoding::utf8_percent_encode(k, S3_URI_ENCODE),
                percent_encoding::utf8_percent_encode(v, S3_URI_ENCODE)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// HTTP/1 header values are ISO-8859-1. SigV4 hashes a Unicode canonical
/// request as UTF-8, so each header byte becomes the character with that
/// code point (`0xE9` → `é`, not a UTF-8 decode failure).
pub fn header_value_latin1(value: &http::HeaderValue) -> String {
    value.as_bytes().iter().map(|&b| b as char).collect()
}

fn canonical_headers(headers: &HeaderMap, signed_headers: &[String]) -> String {
    let mut result = String::new();
    for name in signed_headers {
        // Collect all values for this header (there can be multiple)
        let values: Vec<String> = headers
            .get_all(name.as_str())
            .iter()
            .map(header_value_latin1)
            .collect();
        let mut value = values.join(",");
        // A signed `content-length: 0` is dropped by Go reverse proxies on
        // bodyless requests (AWS CRT signs it on GET). Like MinIO, fall back
        // to the implied length of a request without a body.
        if values.is_empty()
            && name.eq_ignore_ascii_case("content-length")
            && !headers.contains_key(http::header::TRANSFER_ENCODING)
        {
            value = "0".to_string();
        }
        // Header name is used as supplied in SignedHeaders. AWS SigV4
        // mandates clients send these lowercase; the value lookup below is
        // case-insensitive regardless.
        result.push_str(name);
        result.push(':');
        result.push_str(value.trim());
        result.push('\n');
    }
    result
}

fn build_string_to_sign(canonical_request: &str, timestamp: &str, parsed: &ParsedAuth) -> String {
    let scope = format!(
        "{}/{}/{}/aws4_request",
        parsed.date, parsed.region, parsed.service
    );

    let hash = Sha256::digest(canonical_request.as_bytes());
    let canonical_hash = hex::encode(hash);

    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, scope, canonical_hash
    )
}

pub fn derive_signing_key(secret_key: &str, date: &str, region: &str) -> Vec<u8> {
    derive_signing_key_with_service(secret_key, date, region, "s3")
}

pub fn derive_signing_key_with_service(
    secret_key: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let key = format!("AWS4{}", secret_key);

    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date.as_bytes());
    let date_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(region.as_bytes());
    let date_region_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(service.as_bytes());
    let date_region_service_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    mac.finalize().into_bytes().to_vec()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
