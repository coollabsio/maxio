use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use crate::{server::AppState, storage::CorsRule};

/// Extract bucket name from the request path.
/// Returns None for /api/*, /ui/*, and root /.
fn extract_bucket_from_path(path: &str) -> Option<&str> {
    let path = path.strip_prefix('/')?;
    if path.is_empty() {
        return None;
    }
    let bucket = path.split('/').next()?;
    if bucket.is_empty() || bucket == "api" || bucket == "ui" {
        return None;
    }
    Some(bucket)
}

/// Returns true if origin matches the pattern (exact or wildcard "*").
fn origin_matches(pattern: &str, origin: &str) -> bool {
    pattern == "*" || pattern == origin
}

/// Returns true if header is in the allowed list (supports wildcard "*").
fn header_allowed(allowed: &[String], header: &str) -> bool {
    allowed
        .iter()
        .any(|h| h == "*" || h.eq_ignore_ascii_case(header))
}

/// Find the first CORS rule that matches the given origin and method.
fn find_matching_rule<'a>(
    rules: &'a [CorsRule],
    origin: &str,
    method: &str,
) -> Option<&'a CorsRule> {
    rules.iter().find(|rule| {
        let origin_ok = rule
            .allowed_origins
            .iter()
            .any(|p| origin_matches(p, origin));
        let method_ok = rule.allowed_methods.iter().any(|m| m == method);
        origin_ok && method_ok
    })
}

/// Append CORS headers to a response header map based on a matched rule.
fn apply_cors_headers(headers: &mut HeaderMap, rule: &CorsRule, origin: &str) {
    if let Ok(val) = HeaderValue::from_str(origin) {
        headers.insert("access-control-allow-origin", val);
    }
    headers.insert("vary", HeaderValue::from_static("Origin"));

    if !rule.allowed_methods.is_empty() {
        let methods = rule.allowed_methods.join(", ");
        if let Ok(val) = HeaderValue::from_str(&methods) {
            headers.insert("access-control-allow-methods", val);
        }
    }
    if !rule.allowed_headers.is_empty() {
        let hdrs = rule.allowed_headers.join(", ");
        if let Ok(val) = HeaderValue::from_str(&hdrs) {
            headers.insert("access-control-allow-headers", val);
        }
    }
    if !rule.expose_headers.is_empty() {
        let hdrs = rule.expose_headers.join(", ");
        if let Ok(val) = HeaderValue::from_str(&hdrs) {
            headers.insert("access-control-expose-headers", val);
        }
    }
    if let Some(max_age) = rule.max_age_seconds {
        if let Ok(val) = HeaderValue::from_str(&max_age.to_string()) {
            headers.insert("access-control-max-age", val);
        }
    }
}

pub async fn cors_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // If no Origin header, not a CORS request — pass through.
    let origin = match request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
    {
        Some(o) => o.to_string(),
        None => return next.run(request).await,
    };

    let path = request.uri().path().to_string();
    let bucket = match extract_bucket_from_path(&path) {
        Some(b) => b.to_string(),
        None => return next.run(request).await,
    };

    // Load CORS rules for this bucket.
    let rules = match state.storage.get_bucket_cors(&bucket).await {
        Ok(Some(rules)) => rules,
        _ => {
            // No CORS config or storage error — deny preflight, pass through for normal requests.
            if request.method() == Method::OPTIONS {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::empty())
                    .unwrap();
            }
            return next.run(request).await;
        }
    };

    if request.method() == Method::OPTIONS {
        // Preflight request: check Access-Control-Request-Method + Origin.
        let request_method = request
            .headers()
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if let Some(rule) = find_matching_rule(&rules, &origin, &request_method) {
            // Validate Access-Control-Request-Headers if present.
            let request_headers_ok = request
                .headers()
                .get("access-control-request-headers")
                .and_then(|v| v.to_str().ok())
                .map(|hdrs| {
                    hdrs.split(',')
                        .map(|h| h.trim())
                        .all(|h| header_allowed(&rule.allowed_headers, h))
                })
                .unwrap_or(true);

            if request_headers_ok {
                let mut response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .unwrap();
                apply_cors_headers(response.headers_mut(), rule, &origin);
                return response;
            }
        }

        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::empty())
            .unwrap();
    }

    // Normal request: find matching rule for actual method.
    let method_str = request.method().as_str().to_string();
    let rule_match = find_matching_rule(&rules, &origin, &method_str).cloned();

    let mut response = next.run(request).await;

    if let Some(rule) = rule_match {
        apply_cors_headers(response.headers_mut(), &rule, &origin);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CorsRule;

    fn make_rule(origins: &[&str], methods: &[&str]) -> CorsRule {
        CorsRule {
            allowed_origins: origins.iter().map(|s| s.to_string()).collect(),
            allowed_methods: methods.iter().map(|s| s.to_string()).collect(),
            allowed_headers: vec![],
            expose_headers: vec![],
            max_age_seconds: None,
        }
    }

    #[test]
    fn test_extract_bucket_from_path() {
        assert_eq!(extract_bucket_from_path("/my-bucket"), Some("my-bucket"));
        assert_eq!(
            extract_bucket_from_path("/my-bucket/key/path"),
            Some("my-bucket")
        );
        assert_eq!(extract_bucket_from_path("/"), None);
        assert_eq!(extract_bucket_from_path("/api/buckets"), None);
        assert_eq!(extract_bucket_from_path("/ui/index.html"), None);
    }

    #[test]
    fn test_origin_matches() {
        assert!(origin_matches("*", "http://example.com"));
        assert!(origin_matches("http://example.com", "http://example.com"));
        assert!(!origin_matches("http://other.com", "http://example.com"));
    }

    #[test]
    fn test_find_matching_rule_wildcard_origin() {
        let rules = vec![make_rule(&["*"], &["GET", "PUT"])];
        assert!(find_matching_rule(&rules, "http://example.com", "GET").is_some());
        assert!(find_matching_rule(&rules, "http://example.com", "DELETE").is_none());
    }

    #[test]
    fn test_find_matching_rule_exact_origin() {
        let rules = vec![make_rule(&["http://example.com"], &["GET"])];
        assert!(find_matching_rule(&rules, "http://example.com", "GET").is_some());
        assert!(find_matching_rule(&rules, "http://other.com", "GET").is_none());
    }

    #[test]
    fn test_find_matching_rule_no_rules() {
        let rules: Vec<CorsRule> = vec![];
        assert!(find_matching_rule(&rules, "http://example.com", "GET").is_none());
    }
}
