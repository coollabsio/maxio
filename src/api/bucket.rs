use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
};

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{BucketMeta, CorsRule, StorageError};
use crate::xml::{response::to_xml, types::*};

pub async fn list_buckets(State(state): State<AppState>) -> Result<Response<Body>, S3Error> {
    let buckets = state
        .storage
        .list_buckets()
        .await
        .map_err(|e| S3Error::internal(e))?;

    let result = ListAllMyBucketsResult {
        owner: Owner {
            id: "maxio".to_string(),
            display_name: "maxio".to_string(),
        },
        buckets: Buckets {
            bucket: buckets
                .into_iter()
                .map(|b| BucketEntry {
                    name: b.name,
                    creation_date: b.created_at,
                })
                .collect(),
        },
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    validate_bucket_name(&bucket)?;

    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let meta = BucketMeta {
        name: bucket.clone(),
        created_at: now,
        region: state.config.region.clone(),
        versioning: false,
        cors_rules: None,
    };

    let created = state
        .storage
        .create_bucket(&meta)
        .await
        .map_err(|e| S3Error::internal(e))?;

    if !created {
        return Err(S3Error::bucket_already_owned(&bucket));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Location", format!("/{}", bucket))
        .body(Body::empty())
        .unwrap())
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("x-amz-bucket-region", &*state.config.region)
        .body(Body::empty())
        .unwrap())
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("cors") {
        return delete_bucket_cors(state, bucket).await;
    }
    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap()),
        Ok(false) => Err(S3Error::no_such_bucket(&bucket)),
        Err(StorageError::BucketNotEmpty) => Err(S3Error::bucket_not_empty(&bucket)),
        Err(e) => Err(S3Error::internal(e)),
    }
}

pub async fn handle_bucket_put(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("versioning") {
        return put_bucket_versioning(State(state), Path(bucket), body).await;
    }
    if params.contains_key("cors") {
        return put_bucket_cors(state, bucket, body).await;
    }
    create_bucket(State(state), Path(bucket)).await
}

async fn put_bucket_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let body_bytes = axum::body::to_bytes(body, 1024 * 64)
        .await
        .map_err(|e| S3Error::internal(e))?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Parse <VersioningConfiguration><Status>Enabled|Suspended</Status></VersioningConfiguration>
    let enabled = if body_str.contains("<Status>Enabled</Status>") {
        true
    } else if body_str.contains("<Status>Suspended</Status>") {
        false
    } else {
        false
    };

    state
        .storage
        .set_versioning(&bucket, enabled)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

pub async fn get_bucket_versioning(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let versioned = state
        .storage
        .is_versioned(&bucket)
        .await
        .map_err(|e| S3Error::internal(e))?;

    let result = VersioningConfiguration {
        status: if versioned {
            Some("Enabled".to_string())
        } else {
            None
        },
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn put_bucket_cors(
    state: AppState,
    bucket: String,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let body_bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|e| S3Error::internal(e))?;

    let config: CorsConfiguration = quick_xml::de::from_str(&String::from_utf8_lossy(&body_bytes))
        .map_err(|_| S3Error::malformed_xml())?;

    if config.rules.len() > 100 {
        return Err(S3Error::invalid_argument(
            "CORS configuration cannot have more than 100 rules",
        ));
    }
    for rule in &config.rules {
        if rule.allowed_origins.is_empty() || rule.allowed_methods.is_empty() {
            return Err(S3Error::malformed_xml());
        }
        for method in &rule.allowed_methods {
            match method.as_str() {
                "GET" | "PUT" | "POST" | "DELETE" | "HEAD" => {}
                _ => {
                    return Err(S3Error::invalid_argument(&format!(
                        "Invalid HTTP method in CORS rule: {}",
                        method
                    )))
                }
            }
        }
    }

    let rules: Vec<CorsRule> = config
        .rules
        .into_iter()
        .map(|r| CorsRule {
            allowed_origins: r.allowed_origins,
            allowed_methods: r.allowed_methods,
            allowed_headers: r.allowed_headers,
            expose_headers: r.expose_headers,
            max_age_seconds: r.max_age_seconds,
        })
        .collect();

    state
        .storage
        .put_bucket_cors(&bucket, rules)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

pub async fn get_bucket_cors(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let rules = state
        .storage
        .get_bucket_cors(&bucket)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            e => S3Error::internal(e),
        })?;

    let rules = rules.ok_or_else(|| S3Error::no_such_cors_configuration())?;

    let config = CorsConfiguration {
        rules: rules
            .into_iter()
            .map(|r| crate::xml::types::CorsRuleXml {
                allowed_origins: r.allowed_origins,
                allowed_methods: r.allowed_methods,
                allowed_headers: r.allowed_headers,
                expose_headers: r.expose_headers,
                max_age_seconds: r.max_age_seconds,
            })
            .collect(),
    };

    let xml = to_xml(&config).map_err(|e| S3Error::internal(e))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn delete_bucket_cors(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    state
        .storage
        .delete_bucket_cors(&bucket)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

fn validate_bucket_name(name: &str) -> Result<(), S3Error> {
    if name.len() < 3 || name.len() > 63 {
        return Err(S3Error::invalid_bucket_name(name));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Err(S3Error::invalid_bucket_name(name));
    }
    if !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        return Err(S3Error::invalid_bucket_name(name));
    }
    Ok(())
}
