//! Virtual-hosted-style bucket addressing (`<bucket>.<domain>/<key>`).
//!
//! When one or more base domains are configured, a request whose host is
//! `<bucket>.<domain>` (port ignored, case-insensitive) is rewritten to the
//! path-style route `/{bucket}/<key>` before the router matches. The original
//! path is kept on the request so SigV4 still verifies the path and `Host`
//! the client signed. Hosts that are not a bucket under a configured domain,
//! including the bare domain, an IP, or any host when no domain is set, are
//! left on path-style routing.

use axum::extract::Request;
use http::{HeaderValue, Uri, header};

use crate::storage::is_valid_bucket_name;

/// Path the client addressed, saved before a virtual-host rewrite prefixes the bucket.
/// SigV4 must use this path; handlers see the rewritten path-style URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedRequestPath(pub(crate) String);

/// Parse `--domain` / `MAXIO_DOMAIN` (comma-separated). Empty input disables
/// virtual-hosted-style. `*.example.com` is accepted as `example.com`.
pub(crate) fn parse_domains(raw: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    if raw.trim().is_empty() {
        return Ok(out);
    }
    for piece in raw.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let domain = normalize_domain(piece).ok_or_else(|| {
            format!(
                "invalid virtual-host domain '{piece}'. Pass a hostname such as s3.example.com \
                 (comma-separated to allow more than one)."
            )
        })?;
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    Ok(out)
}

fn normalize_domain(raw: &str) -> Option<String> {
    let mut domain = raw.trim().trim_matches('"').to_ascii_lowercase();
    if let Some(stripped) = domain.strip_prefix("*.") {
        domain = stripped.to_string();
    }
    domain = domain.trim_end_matches('.').to_string();
    if let Some((name, port)) = domain.rsplit_once(':') {
        if !name.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            domain = name.to_string();
        }
    }
    if domain.is_empty() || domain.len() > 253 || domain.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    if domain.starts_with('.')
        || domain.starts_with('-')
        || domain.ends_with('-')
        || domain.contains("..")
    {
        return None;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    Some(domain)
}

enum HostClass {
    /// `<bucket>.<configured-domain>` and `bucket` is a valid S3 bucket name.
    Bucket(String),
    /// Host is exactly a configured base domain.
    Base,
    Other,
}

/// Rewrite a virtual-hosted request onto the path-style router.
///
/// `Host` wins when it already names a bucket or a configured base domain.
/// `X-Forwarded-Host` is consulted only when `Host` is neither (a proxy that
/// replaced `Host` with an internal address). In that case the forwarded value
/// becomes the `Host` header so signature verification uses the host the
/// client signed, which is the same host used to choose the bucket.
pub(crate) fn apply(request: &mut Request, domains: &[String]) {
    if domains.is_empty() {
        return;
    }

    let host_header = request_host(request);
    match classify(&host_header, domains) {
        HostClass::Bucket(bucket) => rewrite(request, &bucket),
        HostClass::Base => {}
        HostClass::Other => {
            let Some(forwarded) = forwarded_host(request) else {
                return;
            };
            let HostClass::Bucket(bucket) = classify(&forwarded, domains) else {
                return;
            };
            let Ok(value) = HeaderValue::try_from(forwarded.as_str()) else {
                return;
            };
            request.headers_mut().insert(header::HOST, value);
            rewrite(request, &bucket);
        }
    }
}

fn request_host(request: &Request) -> String {
    if let Some(value) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    {
        if !value.is_empty() {
            return value.to_string();
        }
    }
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .unwrap_or_default()
}

fn forwarded_host(request: &Request) -> Option<String> {
    let raw = request
        .headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())?;
    let first = raw.split(',').next()?.trim().trim_matches('"');
    if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

fn classify(hostport: &str, domains: &[String]) -> HostClass {
    let host = hostname(hostport);
    if host.is_empty() {
        return HostClass::Other;
    }
    // A configured domain is the service host (path-style, console, health),
    // even when a shorter configured domain would otherwise treat it as a bucket.
    if domains.iter().any(|domain| domain == &host) {
        return HostClass::Base;
    }

    let mut best: Option<(usize, String)> = None;
    for domain in domains {
        let suffix = format!(".{domain}");
        let Some(bucket) = host.strip_suffix(&suffix) else {
            continue;
        };
        if bucket.is_empty() || bucket.starts_with('.') || bucket.ends_with('.') {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(length, _)| domain.len() > *length)
        {
            best = Some((domain.len(), bucket.to_string()));
        }
    }

    match best {
        Some((_, bucket)) if is_valid_bucket_name(&bucket) => HostClass::Bucket(bucket),
        _ => HostClass::Other,
    }
}

fn hostname(hostport: &str) -> String {
    let hostport = hostport.trim().trim_matches('"');
    let name = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split_once(']')
            .map(|(addr, _)| addr)
            .unwrap_or(hostport)
    } else if let Some((name, port)) = hostport.rsplit_once(':') {
        if !name.is_empty() && !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            name
        } else {
            hostport
        }
    } else {
        hostport
    };
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn rewrite(request: &mut Request, bucket: &str) {
    let original = request.uri().path().to_string();
    let new_path = prefix_bucket(&original, bucket);
    let Some(uri) = replace_path(request.uri(), &new_path) else {
        tracing::warn!(bucket, "virtual-host path rewrite failed");
        return;
    };
    *request.uri_mut() = uri;
    request.extensions_mut().insert(SignedRequestPath(original));
    tracing::debug!(bucket, path = %new_path, "virtual-hosted request");
}

fn prefix_bucket(path: &str, bucket: &str) -> String {
    if path.is_empty() || path == "/" {
        format!("/{bucket}")
    } else if let Some(rest) = path.strip_prefix('/') {
        format!("/{bucket}/{rest}")
    } else {
        format!("/{bucket}/{path}")
    }
}

fn replace_path(uri: &Uri, new_path: &str) -> Option<Uri> {
    let path_and_query = match uri.query() {
        Some(query) => format!("{new_path}?{query}"),
        None => new_path.to_string(),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse::<http::uri::PathAndQuery>().ok()?);
    Uri::from_parts(parts).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;

    fn domains(raw: &str) -> Vec<String> {
        parse_domains(raw).unwrap()
    }

    fn host_request(host: &str, path: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn parses_comma_separated_domains() {
        assert!(parse_domains("").unwrap().is_empty());
        assert!(parse_domains("  ,  ").unwrap().is_empty());
        assert_eq!(
            domains(" localhost, *.S3.Example.COM. ,localhost ,s3.example.com:9000 "),
            vec!["localhost".to_string(), "s3.example.com".to_string()]
        );
    }

    #[test]
    fn rejects_invalid_domains() {
        for raw in [
            "http://s3.example.com",
            "not a domain",
            "-bad.example",
            "1.2.3.4",
            "*.",
            "",
        ] {
            if raw.is_empty() {
                assert!(parse_domains(raw).unwrap().is_empty());
            } else {
                assert!(parse_domains(raw).is_err(), "{raw}");
            }
        }
    }

    #[test]
    fn rewrites_bucket_host_and_keeps_signed_path() {
        let mut request = host_request(
            "My.Bucket.Example.TEST:9000",
            "/folder/a%20b.txt?list-type=2",
        );
        apply(&mut request, &domains("example.test"));
        assert_eq!(request.uri().path(), "/my.bucket/folder/a%20b.txt");
        assert_eq!(request.uri().query(), Some("list-type=2"));
        assert_eq!(
            request.extensions().get::<SignedRequestPath>().unwrap().0,
            "/folder/a%20b.txt"
        );
        assert_eq!(
            request.headers().get(header::HOST).unwrap(),
            "My.Bucket.Example.TEST:9000"
        );
    }

    #[test]
    fn root_on_bucket_host_is_the_bucket() {
        let mut request = host_request("photos.localhost.", "/");
        apply(&mut request, &domains("localhost"));
        assert_eq!(request.uri(), "/photos");
        assert_eq!(
            request.extensions().get::<SignedRequestPath>().unwrap().0,
            "/"
        );
    }

    #[test]
    fn base_domain_and_unknown_hosts_stay_path_style() {
        for host in [
            "localhost:9000",
            "example.test",
            "127.0.0.1:9000",
            "[::1]:9000",
        ] {
            let mut request = host_request(host, "/healthz");
            apply(&mut request, &domains("localhost,example.test"));
            assert_eq!(request.uri().path(), "/healthz", "{host}");
            assert!(request.extensions().get::<SignedRequestPath>().is_none());
        }
    }

    #[test]
    fn disabled_when_no_domain_is_configured() {
        let mut request = host_request("photos.localhost", "/pic.jpg");
        apply(&mut request, &[]);
        assert_eq!(request.uri().path(), "/pic.jpg");
    }

    #[test]
    fn invalid_bucket_labels_are_not_virtual_hosts() {
        for host in [
            "ab.example.test",
            "192.168.0.1.example.test",
            ".hidden.example.test",
        ] {
            let mut request = host_request(host, "/healthz");
            apply(&mut request, &domains("example.test"));
            assert_eq!(request.uri().path(), "/healthz", "{host}");
        }
    }

    #[test]
    fn longest_configured_domain_wins() {
        let configured = domains("example.test,s3.example.test");

        let mut nested = host_request("album.s3.example.test", "/pic.jpg");
        apply(&mut nested, &configured);
        assert_eq!(nested.uri().path(), "/album/pic.jpg");

        let mut service = host_request("s3.example.test", "/ui/");
        apply(&mut service, &configured);
        assert_eq!(service.uri().path(), "/ui/");

        let mut shorter = host_request("album.example.test", "/pic.jpg");
        apply(&mut shorter, &configured);
        assert_eq!(shorter.uri().path(), "/album/pic.jpg");
    }

    #[test]
    fn forwarded_host_used_only_when_host_is_not_a_configured_domain() {
        let configured = domains("example.test");

        let mut proxied = host_request("127.0.0.1:9000", "/pic.jpg?tagging");
        proxied.headers_mut().insert(
            "x-forwarded-host",
            HeaderValue::from_static("photos.example.test:443, proxy.internal"),
        );
        apply(&mut proxied, &configured);
        assert_eq!(proxied.uri().path(), "/photos/pic.jpg");
        assert_eq!(proxied.uri().query(), Some("tagging"));
        assert_eq!(
            proxied.headers().get(header::HOST).unwrap(),
            "photos.example.test:443"
        );
        assert_eq!(
            proxied.extensions().get::<SignedRequestPath>().unwrap().0,
            "/pic.jpg"
        );

        let mut base = host_request("example.test", "/healthz");
        base.headers_mut().insert(
            "x-forwarded-host",
            HeaderValue::from_static("photos.example.test"),
        );
        apply(&mut base, &configured);
        assert_eq!(base.uri().path(), "/healthz");
        assert_eq!(base.headers().get(header::HOST).unwrap(), "example.test");

        let mut direct = host_request("photos.example.test", "/pic.jpg");
        direct.headers_mut().insert(
            "x-forwarded-host",
            HeaderValue::from_static("other.example.test"),
        );
        apply(&mut direct, &configured);
        assert_eq!(direct.uri().path(), "/photos/pic.jpg");
        assert_eq!(
            direct.headers().get(header::HOST).unwrap(),
            "photos.example.test"
        );
    }
}
