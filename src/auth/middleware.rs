use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use chrono::{NaiveDateTime, Utc};

use crate::error::S3Error;
use crate::server::AppState;

use super::signature_v4;

pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, S3Error> {
    let method = request.method().as_str().to_string();
    let uri = request.uri().to_string();

    tracing::debug!("{} {}", method, uri);

    let query = request.uri().query().unwrap_or("").to_string();

    // Detect presigned URL by presence of X-Amz-Signature in query string
    if query.contains("X-Amz-Signature=") {
        return handle_presigned(&state, &method, &query, request, next).await;
    }

    let auth_header = match request.headers().get("authorization") {
        Some(h) => h
            .to_str()
            .map_err(|_| S3Error::access_denied("Invalid Authorization header"))?,
        None => {
            tracing::debug!("No Authorization header present");
            return Err(S3Error::access_denied("Missing Authorization header"));
        }
    };

    tracing::debug!("Authorization: {}", auth_header);

    let parsed = signature_v4::parse_authorization_header(auth_header)
        .map_err(|e| S3Error::access_denied(e))?;

    tracing::debug!(
        "Parsed: access_key={}, date={}, region={}, signed_headers={:?}",
        parsed.access_key,
        parsed.date,
        parsed.region,
        parsed.signed_headers
    );

    if parsed.access_key != state.config.access_key {
        tracing::debug!(
            "Access key mismatch: got '{}', expected '{}'",
            parsed.access_key,
            state.config.access_key
        );
        return Err(S3Error::invalid_access_key());
    }

    if parsed.region != state.config.region {
        tracing::debug!(
            "Region mismatch: got '{}', expected '{}'",
            parsed.region,
            state.config.region
        );
        return Err(S3Error::access_denied("Invalid region in credential scope"));
    }

    // Validate request timestamp is within ±15 minutes (AWS SigV4 spec)
    let amz_date = request
        .headers()
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Ok(request_time) = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ") {
        let now = Utc::now().naive_utc();
        let skew = (now - request_time).num_seconds().unsigned_abs();
        if skew > 15 * 60 {
            tracing::debug!(
                "Request timestamp skew too large: {}s (max 900s)",
                skew
            );
            return Err(S3Error::access_denied(
                "RequestTimeTooSkewed: The difference between the request time and the current time is too large.",
            ));
        }
    } else {
        return Err(S3Error::access_denied("Invalid or missing X-Amz-Date header"));
    }

    let path = request.uri().path().to_string();

    tracing::debug!("Verifying signature for {} {} ?{}", method, path, query);

    for h in &parsed.signed_headers {
        let val = request
            .headers()
            .get(h.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>");
        tracing::debug!("  signed header '{}': '{}'", h, val);
    }

    let valid = signature_v4::verify_signature(
        &method,
        &path,
        &query,
        request.headers(),
        &parsed,
        &state.config.secret_key,
    );

    if !valid {
        tracing::debug!("Signature verification FAILED");
        return Err(S3Error::signature_mismatch());
    }

    tracing::debug!("Signature verification OK");
    let response = next.run(request).await;
    tracing::debug!("{} {} -> {}", method, uri, response.status());
    Ok(response)
}

async fn handle_presigned(
    state: &AppState,
    method: &str,
    query: &str,
    request: Request,
    next: Next,
) -> Result<Response, S3Error> {
    tracing::debug!("Presigned URL detected");

    let (parsed, timestamp, expires_secs) = signature_v4::parse_presigned_query(query)
        .map_err(|e| S3Error::access_denied(e))?;

    if parsed.access_key != state.config.access_key {
        return Err(S3Error::invalid_access_key());
    }

    if parsed.region != state.config.region {
        return Err(S3Error::access_denied("Invalid region in credential scope"));
    }

    // Check expiration
    let issued_at = NaiveDateTime::parse_from_str(&timestamp, "%Y%m%dT%H%M%SZ")
        .map_err(|_| S3Error::access_denied("Invalid X-Amz-Date format"))?;
    let expires_at = issued_at
        + chrono::Duration::seconds(expires_secs as i64);
    let now = Utc::now().naive_utc();

    if now > expires_at {
        tracing::debug!("Presigned URL expired: issued={}, expires={}, now={}", issued_at, expires_at, now);
        return Err(S3Error::expired_presigned_url());
    }

    let path = request.uri().path().to_string();

    tracing::debug!("Verifying presigned signature for {} {} ?{}", method, path, query);

    let valid = signature_v4::verify_presigned_signature(
        method,
        &path,
        query,
        request.headers(),
        &parsed,
        &timestamp,
        &state.config.secret_key,
    );

    if !valid {
        tracing::debug!("Presigned signature verification FAILED");
        return Err(S3Error::signature_mismatch());
    }

    tracing::debug!("Presigned signature verification OK");
    let response = next.run(request).await;
    Ok(response)
}
