use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    response::Response,
};
use http::StatusCode;

use super::{bucket, multipart};
use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::ObjectMeta;
use crate::xml::{response::to_xml, types::*};

pub async fn handle_bucket_get(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    tracing::debug!("GET /{} params={:?}", bucket, params);

    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::from_bucket_storage(e, &bucket)),
    }

    match bucket::bucket_subresource(&params) {
        None => {}
        Some("uploads") => {
            return multipart::list_multipart_uploads(State(state), Path(bucket)).await;
        }
        Some("versioning") => return bucket::get_bucket_versioning(state, bucket).await,
        Some("cors") => return bucket::get_bucket_cors(state, bucket).await,
        Some("encryption") => return bucket::get_bucket_encryption(state, bucket).await,
        Some("versions") => return list_object_versions(state, bucket, params).await,
        Some("location") => {
            tracing::debug!("GetBucketLocation for {}", bucket);
            // us-east-1 is the empty constraint. Any other region is named.
            let body = if state.config.region == "us-east-1" {
                String::new()
            } else {
                quick_xml::escape::escape(&state.config.region).into_owned()
            };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <LocationConstraint xmlns=\"{}\">{body}</LocationConstraint>",
                bucket::S3_XMLNS,
            );
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap());
        }
        Some(sub) => return bucket::get_bucket_subresource(state, bucket, sub).await,
    }

    if params.get("list-type").map(|v| v.as_str()) == Some("2") {
        list_objects_v2(state, bucket, params).await
    } else {
        list_objects_v1(state, bucket, params).await
    }
}

/// Parse the `max-keys` query parameter. Returns an `InvalidArgument` error
/// for non-numeric or negative values; clamps valid values to 0..=1000.
fn parse_max_keys(params: &HashMap<String, String>) -> Result<usize, S3Error> {
    match params.get("max-keys") {
        None => Ok(1000),
        Some(raw) => {
            let n: i64 = raw
                .parse()
                .map_err(|_| S3Error::invalid_argument("Invalid value for max-keys"))?;
            if n < 0 {
                return Err(S3Error::invalid_argument("Invalid value for max-keys"));
            }
            Ok((n as usize).min(1000))
        }
    }
}

/// Parse `encoding-type`. Only `url` is valid (case-insensitive).
fn parse_encoding_type(params: &HashMap<String, String>) -> Result<bool, S3Error> {
    match params.get("encoding-type").map(|v| v.as_str()) {
        None | Some("") => Ok(false),
        Some(v) if v.eq_ignore_ascii_case("url") => Ok(true),
        Some(_) => Err(S3Error::invalid_argument(
            "Invalid Encoding Method specified in Request",
        )),
    }
}

/// S3 `encoding-type=url`: percent-encode everything except unreserved chars and `/`.
fn encode_name(s: &str, url: bool) -> String {
    const S3_NAME_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~')
        .remove(b'/');
    if url {
        percent_encoding::utf8_percent_encode(s, S3_NAME_ENCODE).to_string()
    } else {
        s.to_string()
    }
}

fn encoding_type_echo(url: bool) -> Option<String> {
    url.then(|| "url".to_string())
}

/// The common prefix `key` rolls up into under `prefix` + `delimiter`, if any.
fn common_prefix_of(key: &str, prefix: &str, delimiter: Option<&str>) -> Option<String> {
    let delim = delimiter?;
    let suffix = key.get(prefix.len()..)?;
    suffix
        .find(delim)
        .map(|pos| format!("{}{}", prefix, &suffix[..pos + delim.len()]))
}

enum Entry<'a> {
    Object(&'a ObjectMeta),
    Prefix(String),
}

impl Entry<'_> {
    /// Marker value that resumes the listing right after this entry.
    fn marker(&self) -> String {
        match self {
            Entry::Object(o) => o.key.clone(),
            Entry::Prefix(p) => p.clone(),
        }
    }
}

/// Build one page from `objects` (sorted by key, already positioned after
/// `marker`). Contents and CommonPrefixes count together against
/// `max_keys`; a common prefix is emitted once and skipped entirely when it
/// sorts at or before `marker` (i.e. it was returned on an earlier page).
fn paginate<'a>(
    objects: impl Iterator<Item = &'a ObjectMeta>,
    prefix: &str,
    delimiter: Option<&str>,
    marker: Option<&str>,
    max_keys: usize,
) -> (Vec<Entry<'a>>, bool) {
    let mut entries: Vec<Entry<'a>> = Vec::new();
    let mut last_prefix: Option<String> = None;
    let mut is_truncated = false;
    for obj in objects {
        let cp = common_prefix_of(&obj.key, prefix, delimiter);
        if let Some(cp) = &cp {
            if marker.is_some_and(|m| cp.as_str() <= m) || last_prefix.as_ref() == Some(cp) {
                continue;
            }
        }
        if entries.len() >= max_keys {
            is_truncated = max_keys > 0;
            break;
        }
        match cp {
            Some(cp) => {
                last_prefix = Some(cp.clone());
                entries.push(Entry::Prefix(cp));
            }
            None => entries.push(Entry::Object(obj)),
        }
    }
    (entries, is_truncated)
}

fn split_entries(
    entries: &[Entry<'_>],
    url: bool,
    with_owner: bool,
) -> (Vec<ObjectEntry>, Vec<CommonPrefix>) {
    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for e in entries {
        match e {
            Entry::Object(o) => contents.push(ObjectEntry {
                key: encode_name(&o.key, url),
                last_modified: o.last_modified.clone(),
                etag: o.etag.clone(),
                size: o.size,
                storage_class: "STANDARD".to_string(),
                owner: with_owner.then(bucket::owner),
            }),
            Entry::Prefix(p) => common_prefixes.push(CommonPrefix {
                prefix: encode_name(p, url),
            }),
        }
    }
    (contents, common_prefixes)
}

async fn list_objects_v2(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    // AWS semantics: an empty `delimiter=` parameter means "no delimiter".
    let delimiter = params.get("delimiter").cloned().filter(|d| !d.is_empty());
    let max_keys = parse_max_keys(&params)?;
    let url = parse_encoding_type(&params)?;
    let fetch_owner = params.get("fetch-owner").map(|v| v.as_str()) == Some("true");
    let start_after = params.get("start-after").cloned();
    let continuation_token = params.get("continuation-token").cloned();

    let effective_start = match &continuation_token {
        Some(t) => {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(t)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| {
                    S3Error::invalid_argument("The continuation token provided is incorrect")
                })?;
            Some(decoded)
        }
        None => start_after.clone(),
    };

    let all_objects = state
        .storage
        .list_objects(&bucket, &prefix)
        .await
        .map_err(S3Error::internal)?;

    let start = effective_start.as_deref();
    let (entries, is_truncated) = paginate(
        all_objects
            .iter()
            .filter(|o| start.is_none_or(|s| o.key.as_str() > s)),
        &prefix,
        delimiter.as_deref(),
        start,
        max_keys,
    );

    let next_token = if is_truncated {
        entries.last().map(|e| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(e.marker())
        })
    } else {
        None
    };

    let (contents, common_prefixes) = split_entries(&entries, url, fetch_owner);

    let result = ListBucketResult {
        name: bucket,
        prefix: encode_name(&prefix, url),
        key_count: entries.len() as i32,
        max_keys: max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        continuation_token,
        next_continuation_token: next_token,
        delimiter: delimiter.map(|d| encode_name(&d, url)),
        start_after: start_after.map(|s| encode_name(&s, url)),
        encoding_type: encoding_type_echo(url),
    };

    let xml = to_xml(&result).map_err(S3Error::internal)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn list_objects_v1(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    // AWS semantics: an empty `delimiter=` parameter means "no delimiter".
    let delimiter = params.get("delimiter").cloned().filter(|d| !d.is_empty());
    let max_keys = parse_max_keys(&params)?;
    let url = parse_encoding_type(&params)?;
    let marker = params.get("marker").cloned().filter(|m| !m.is_empty());

    let all_objects = state
        .storage
        .list_objects(&bucket, &prefix)
        .await
        .map_err(S3Error::internal)?;

    let start = marker.as_deref();
    let (entries, is_truncated) = paginate(
        all_objects
            .iter()
            .filter(|o| start.is_none_or(|s| o.key.as_str() > s)),
        &prefix,
        delimiter.as_deref(),
        start,
        max_keys,
    );

    let next_marker = if is_truncated {
        entries.last().map(|e| encode_name(&e.marker(), url))
    } else {
        None
    };

    // V1 always includes Owner in Contents (AWS behaviour).
    let (contents, common_prefixes) = split_entries(&entries, url, true);

    let result = ListBucketResultV1 {
        name: bucket,
        prefix: encode_name(&prefix, url),
        marker: encode_name(marker.as_deref().unwrap_or_default(), url),
        next_marker,
        max_keys: max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        delimiter: delimiter.map(|d| encode_name(&d, url)),
        encoding_type: encoding_type_echo(url),
    };

    let xml = to_xml(&result).map_err(S3Error::internal)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

fn version_id_of(v: &ObjectMeta) -> &str {
    v.version_id.as_deref().unwrap_or("null")
}

async fn list_object_versions(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = params.get("delimiter").cloned().filter(|d| !d.is_empty());
    let max_keys = parse_max_keys(&params)?;
    let url = parse_encoding_type(&params)?;
    let key_marker = params.get("key-marker").cloned().filter(|m| !m.is_empty());
    let version_id_marker = params
        .get("version-id-marker")
        .cloned()
        .filter(|m| !m.is_empty());

    // Sorted by key ascending, versions newest first within a key.
    let all_versions = state
        .storage
        .list_object_versions(&bucket, &prefix)
        .await
        .map_err(S3Error::internal)?;

    // The first entry per key is the latest.
    let mut latest_per_key: HashMap<&str, &str> = HashMap::new();
    for v in &all_versions {
        latest_per_key
            .entry(v.key.as_str())
            .or_insert(version_id_of(v));
    }

    // Position after (key-marker, version-id-marker). Without a version-id
    // marker every version of key-marker is skipped.
    let mut passed_version_marker = false;
    let positioned = all_versions.iter().filter(|v| {
        let Some(km) = key_marker.as_deref() else {
            return true;
        };
        match v.key.as_str().cmp(km) {
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => match version_id_marker.as_deref() {
                None => false,
                Some(_) if passed_version_marker => true,
                Some(vm) => {
                    passed_version_marker = version_id_of(v) == vm;
                    false
                }
            },
        }
    });

    let (entries, is_truncated) = paginate(
        positioned,
        &prefix,
        delimiter.as_deref(),
        key_marker.as_deref(),
        max_keys,
    );

    let (next_key_marker, next_version_id_marker) = match entries.last() {
        Some(Entry::Object(v)) if is_truncated => (
            Some(encode_name(&v.key, url)),
            Some(version_id_of(v).to_string()),
        ),
        Some(Entry::Prefix(p)) if is_truncated => (Some(encode_name(p, url)), None),
        _ => (None, None),
    };

    let mut version_entries = Vec::new();
    let mut common_prefixes = Vec::new();
    for e in &entries {
        let v = match e {
            Entry::Object(v) => v,
            Entry::Prefix(p) => {
                common_prefixes.push(CommonPrefix {
                    prefix: encode_name(p, url),
                });
                continue;
            }
        };
        let vid = version_id_of(v);
        let is_latest = latest_per_key.get(v.key.as_str()) == Some(&vid);
        if v.is_delete_marker {
            version_entries.push(VersionListEntry::DeleteMarker(DeleteMarkerEntry {
                key: encode_name(&v.key, url),
                version_id: vid.to_string(),
                is_latest,
                last_modified: v.last_modified.clone(),
                owner: bucket::owner(),
            }));
        } else {
            version_entries.push(VersionListEntry::Version(VersionEntry {
                key: encode_name(&v.key, url),
                version_id: vid.to_string(),
                is_latest,
                last_modified: v.last_modified.clone(),
                etag: v.etag.clone(),
                size: v.size,
                storage_class: "STANDARD".to_string(),
                owner: bucket::owner(),
            }));
        }
    }

    let result = ListVersionsResult {
        name: bucket,
        prefix: encode_name(&prefix, url),
        key_marker: encode_name(key_marker.as_deref().unwrap_or_default(), url),
        version_id_marker: version_id_marker.unwrap_or_default(),
        next_key_marker,
        next_version_id_marker,
        max_keys: max_keys as i32,
        delimiter: delimiter.map(|d| encode_name(&d, url)),
        encoding_type: encoding_type_echo(url),
        is_truncated,
        entries: version_entries,
        common_prefixes,
    };

    let xml = to_xml(&result).map_err(S3Error::internal)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}
