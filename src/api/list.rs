use std::collections::{BTreeSet, HashMap};

use axum::{
    body::Body,
    extract::{Path, Query, State},
    response::Response,
};
use http::StatusCode;

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::ObjectMeta;
use crate::xml::{response::to_xml, types::*};
use super::multipart;

pub async fn handle_bucket_get(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    tracing::debug!("GET /{} params={:?}", bucket, params);

    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    if params.contains_key("uploads") {
        return multipart::list_multipart_uploads(State(state), Path(bucket)).await;
    }

    if params.contains_key("versioning") {
        return super::bucket::get_bucket_versioning(state, bucket).await;
    }

    if params.contains_key("cors") {
        return super::bucket::get_bucket_cors(state, bucket).await;
    }

    if params.contains_key("versions") {
        return list_object_versions(state, bucket, params).await;
    }

    // Handle ?location query (GetBucketLocation)
    if params.contains_key("location") {
        tracing::debug!("GetBucketLocation for {}", bucket);
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <LocationConstraint>{}</LocationConstraint>",
            state.config.region
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/xml")
            .body(Body::from(xml))
            .unwrap());
    }

    if params.get("list-type").map(|v| v.as_str()) == Some("2") {
        list_objects_v2(state, bucket, params).await
    } else {
        list_objects_v1(state, bucket, params).await
    }
}

async fn list_objects_v2(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = params.get("delimiter").cloned();
    let max_keys: usize = params
        .get("max-keys")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .min(1000);
    let start_after = params.get("start-after").cloned();
    let continuation_token = params.get("continuation-token").cloned();

    let effective_start = continuation_token
        .as_ref()
        .and_then(|t| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(t)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
        })
        .or(start_after.clone());

    let all_objects = state
        .storage
        .list_objects(&bucket, &prefix)
        .await
        .map_err(|e| S3Error::internal(e))?;

    let filtered: Vec<&ObjectMeta> = all_objects
        .iter()
        .filter(|o| {
            if let Some(ref start) = effective_start {
                o.key.as_str() > start.as_str()
            } else {
                true
            }
        })
        .collect();

    let is_truncated = filtered.len() > max_keys;
    let page: Vec<&ObjectMeta> = filtered.into_iter().take(max_keys).collect();

    let (contents, common_prefixes) = split_by_delimiter(&page, &prefix, &delimiter);

    let next_token = if is_truncated {
        page.last().map(|o| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&o.key)
        })
    } else {
        None
    };

    let result = ListBucketResult {
        name: bucket,
        prefix,
        key_count: contents.len() as i32 + common_prefixes.len() as i32,
        max_keys: max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        continuation_token,
        next_continuation_token: next_token,
        delimiter,
        start_after,
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;

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
    let delimiter = params.get("delimiter").cloned();
    let max_keys: usize = params
        .get("max-keys")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .min(1000);
    let marker = params.get("marker").cloned();

    let all_objects = state
        .storage
        .list_objects(&bucket, &prefix)
        .await
        .map_err(|e| S3Error::internal(e))?;

    let filtered: Vec<&ObjectMeta> = all_objects
        .iter()
        .filter(|o| {
            if let Some(ref m) = marker {
                o.key.as_str() > m.as_str()
            } else {
                true
            }
        })
        .collect();

    let is_truncated = filtered.len() > max_keys;
    let page: Vec<&ObjectMeta> = filtered.into_iter().take(max_keys).collect();

    let (contents, common_prefixes) = split_by_delimiter(&page, &prefix, &delimiter);

    let next_marker = if is_truncated {
        page.last().map(|o| o.key.clone())
    } else {
        None
    };

    let result = ListBucketResultV1 {
        name: bucket,
        prefix,
        marker: marker.unwrap_or_default(),
        next_marker,
        max_keys: max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        delimiter,
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

fn split_by_delimiter(
    page: &[&ObjectMeta],
    prefix: &str,
    delimiter: &Option<String>,
) -> (Vec<ObjectEntry>, Vec<CommonPrefix>) {
    if let Some(delim) = delimiter {
        let mut contents = Vec::new();
        let mut prefix_set = BTreeSet::new();

        for obj in page {
            let suffix = &obj.key[prefix.len()..];
            if let Some(pos) = suffix.find(delim.as_str()) {
                let common = format!("{}{}", prefix, &suffix[..pos + delim.len()]);
                prefix_set.insert(common);
            } else {
                contents.push(ObjectEntry {
                    key: obj.key.clone(),
                    last_modified: obj.last_modified.clone(),
                    etag: obj.etag.clone(),
                    size: obj.size,
                    storage_class: "STANDARD".to_string(),
                });
            }
        }

        let cp: Vec<CommonPrefix> = prefix_set
            .into_iter()
            .map(|p| CommonPrefix { prefix: p })
            .collect();

        (contents, cp)
    } else {
        (
            page.iter()
                .map(|o| ObjectEntry {
                    key: o.key.clone(),
                    last_modified: o.last_modified.clone(),
                    etag: o.etag.clone(),
                    size: o.size,
                    storage_class: "STANDARD".to_string(),
                })
                .collect(),
            vec![],
        )
    }
}

async fn list_object_versions(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let prefix = params.get("prefix").cloned().unwrap_or_default();

    let all_versions = state
        .storage
        .list_object_versions(&bucket, &prefix)
        .await
        .map_err(|e| S3Error::internal(e))?;

    // Determine which version is latest per key (first in list since sorted newest-first per key)
    let mut latest_per_key: HashMap<String, String> = HashMap::new();
    for v in &all_versions {
        if let Some(vid) = &v.version_id {
            latest_per_key
                .entry(v.key.clone())
                .or_insert_with(|| vid.clone());
        }
    }

    let mut versions = Vec::new();
    let mut delete_markers = Vec::new();

    for v in &all_versions {
        let vid = v.version_id.as_deref().unwrap_or("null");
        let is_latest = latest_per_key.get(&v.key).is_some_and(|latest| latest == vid);
        if v.is_delete_marker {
            delete_markers.push(DeleteMarkerEntry {
                key: v.key.clone(),
                version_id: vid.to_string(),
                is_latest,
                last_modified: v.last_modified.clone(),
            });
        } else {
            versions.push(VersionEntry {
                key: v.key.clone(),
                version_id: vid.to_string(),
                is_latest,
                last_modified: v.last_modified.clone(),
                etag: v.etag.clone(),
                size: v.size,
                storage_class: "STANDARD".to_string(),
            });
        }
    }

    let result = ListVersionsResult {
        name: bucket,
        prefix,
        key_marker: String::new(),
        version_id_marker: String::new(),
        max_keys: 1000,
        is_truncated: false,
        versions,
        delete_markers,
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}
