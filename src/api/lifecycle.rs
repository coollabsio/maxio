//! S3 bucket lifecycle API: `PUT/GET/DELETE /{bucket}?lifecycle`.
//!
//! Parses the `LifecycleConfiguration` XML into the storage-level
//! [`LifecycleRule`] types (shared with the console API), validates it like
//! S3 and renders it back. Transitions need storage classes MaxIO does not
//! have, so they are rejected with `501 NotImplemented`; other unknown
//! elements (e.g. MinIO extensions) are `MalformedXML`.

use axum::body::Body;
use http::{HeaderMap, Response, StatusCode};
use quick_xml::escape::escape;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::error::{S3Error, S3ErrorCode};
use crate::server::AppState;
use crate::storage::StorageError;
use crate::storage::lifecycle::{
    AbortIncompleteMultipartUpload, LifecycleExpiration, LifecycleFilter, LifecycleRule,
    LifecycleStatus, LifecycleTag, NoncurrentVersionExpiration, validate_rules,
};

const LIFECYCLE_BODY_MAX: usize = 2 * 1024 * 1024;
const TRANSITION_DEFAULT_HEADER: &str = "x-amz-transition-default-minimum-object-size";
const TRANSITION_DEFAULT: &str = "all_storage_classes_128K";

#[derive(Deserialize)]
struct XmlConfig {
    #[serde(rename = "Rule", default)]
    rules: Vec<XmlRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XmlRule {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "Filter")]
    filter: Option<XmlFilter>,
    #[serde(rename = "Expiration")]
    expiration: Option<XmlExpiration>,
    #[serde(rename = "NoncurrentVersionExpiration")]
    noncurrent_version_expiration: Option<XmlNoncurrentExpiration>,
    #[serde(rename = "AbortIncompleteMultipartUpload")]
    abort_incomplete_multipart_upload: Option<XmlAbort>,
    #[serde(rename = "Transition", default)]
    transition: Vec<IgnoredAny>,
    #[serde(rename = "NoncurrentVersionTransition", default)]
    noncurrent_version_transition: Vec<IgnoredAny>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct XmlFilter {
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "Tag", default)]
    tags: Vec<XmlTag>,
    #[serde(rename = "And")]
    and: Option<XmlAnd>,
    #[serde(rename = "ObjectSizeGreaterThan")]
    size_gt: Option<i64>,
    #[serde(rename = "ObjectSizeLessThan")]
    size_lt: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct XmlAnd {
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "Tag", default)]
    tags: Vec<XmlTag>,
    #[serde(rename = "ObjectSizeGreaterThan")]
    size_gt: Option<i64>,
    #[serde(rename = "ObjectSizeLessThan")]
    size_lt: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XmlTag {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value")]
    value: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XmlExpiration {
    #[serde(rename = "Days")]
    days: Option<i64>,
    #[serde(rename = "Date")]
    date: Option<String>,
    #[serde(rename = "ExpiredObjectDeleteMarker")]
    expired_object_delete_marker: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XmlNoncurrentExpiration {
    #[serde(rename = "NoncurrentDays")]
    noncurrent_days: Option<i64>,
    #[serde(rename = "NewerNoncurrentVersions")]
    newer_noncurrent_versions: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XmlAbort {
    #[serde(rename = "DaysAfterInitiation")]
    days_after_initiation: Option<i64>,
}

/// A positive (`allow_zero` = non-negative) day / count value.
fn non_negative(v: i64, field: &str, allow_zero: bool) -> Result<u32, S3Error> {
    if v < 0 || (!allow_zero && v == 0) || v > u32::MAX as i64 {
        return Err(S3Error::invalid_argument(&format!(
            "'{}' must be a positive integer",
            field
        )));
    }
    Ok(v as u32)
}

fn size_bound(v: Option<i64>, field: &str) -> Result<Option<u64>, S3Error> {
    match v {
        None => Ok(None),
        Some(n) if n < 0 => Err(S3Error::invalid_argument(&format!(
            "'{}' must be a non-negative integer",
            field
        ))),
        Some(n) => Ok(Some(n as u64)),
    }
}

fn tags(xml: Vec<XmlTag>) -> Vec<LifecycleTag> {
    xml.into_iter()
        .map(|t| LifecycleTag {
            key: t.key,
            value: t.value.unwrap_or_default(),
        })
        .collect()
}

fn convert_filter(f: XmlFilter) -> Result<LifecycleFilter, S3Error> {
    let singles = f.prefix.is_some() as usize
        + f.tags.len()
        + f.size_gt.is_some() as usize
        + f.size_lt.is_some() as usize;
    if let Some(and) = f.and {
        if singles > 0 {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "Filter can contain only one of Prefix, Tag, ObjectSizeGreaterThan, \
                 ObjectSizeLessThan or And",
            ));
        }
        return Ok(LifecycleFilter {
            prefix: and.prefix.unwrap_or_default(),
            tags: tags(and.tags),
            object_size_greater_than: size_bound(and.size_gt, "ObjectSizeGreaterThan")?,
            object_size_less_than: size_bound(and.size_lt, "ObjectSizeLessThan")?,
        });
    }
    if singles > 1 {
        return Err(S3Error::new(
            S3ErrorCode::MalformedXML,
            "Multiple filter conditions must be wrapped in an And element",
        ));
    }
    Ok(LifecycleFilter {
        prefix: f.prefix.unwrap_or_default(),
        tags: tags(f.tags),
        object_size_greater_than: size_bound(f.size_gt, "ObjectSizeGreaterThan")?,
        object_size_less_than: size_bound(f.size_lt, "ObjectSizeLessThan")?,
    })
}

/// Parse + validate a `LifecycleConfiguration` document.
pub fn parse_lifecycle_xml(body: &str) -> Result<Vec<LifecycleRule>, S3Error> {
    if body.trim().is_empty() {
        return Err(S3Error::new(
            S3ErrorCode::MalformedXML,
            "The lifecycle configuration body is empty",
        ));
    }
    let config: XmlConfig = quick_xml::de::from_str(body).map_err(|e| {
        tracing::debug!("lifecycle XML parse error: {}", e);
        S3Error::new(S3ErrorCode::MalformedXML, "The XML you provided was not well-formed or did not validate against our published schema")
    })?;

    let mut rules = Vec::with_capacity(config.rules.len());
    for r in config.rules {
        if !r.transition.is_empty() || !r.noncurrent_version_transition.is_empty() {
            return Err(S3Error::not_implemented(
                "Lifecycle transitions are not supported: MaxIO has a single storage class",
            ));
        }
        let status = match r.status.as_deref() {
            Some("Enabled") => LifecycleStatus::Enabled,
            Some("Disabled") => LifecycleStatus::Disabled,
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MalformedXML,
                    "Rule Status must be Enabled or Disabled",
                ));
            }
        };
        let filter = match (r.prefix, r.filter) {
            (Some(_), Some(_)) => {
                return Err(S3Error::new(
                    S3ErrorCode::MalformedXML,
                    "A rule cannot have both a top-level Prefix and a Filter",
                ));
            }
            (Some(prefix), None) => LifecycleFilter {
                prefix,
                ..Default::default()
            },
            (None, Some(f)) => convert_filter(f)?,
            (None, None) => LifecycleFilter::default(),
        };
        let expiration = match r.expiration {
            None => None,
            Some(e) => Some(LifecycleExpiration {
                days: e.days.map(|d| non_negative(d, "Days", false)).transpose()?,
                date: e.date,
                expired_object_delete_marker: e.expired_object_delete_marker.unwrap_or(false),
            }),
        };
        let noncurrent_version_expiration = match r.noncurrent_version_expiration {
            None => None,
            Some(n) => Some(NoncurrentVersionExpiration {
                noncurrent_days: n
                    .noncurrent_days
                    .map(|d| non_negative(d, "NoncurrentDays", false))
                    .transpose()?,
                newer_noncurrent_versions: n
                    .newer_noncurrent_versions
                    .map(|d| non_negative(d, "NewerNoncurrentVersions", true))
                    .transpose()?,
            }),
        };
        let abort_incomplete_multipart_upload = match r.abort_incomplete_multipart_upload {
            None => None,
            Some(a) => Some(AbortIncompleteMultipartUpload {
                days_after_initiation: non_negative(
                    a.days_after_initiation.ok_or_else(|| {
                        S3Error::new(S3ErrorCode::MalformedXML, "DaysAfterInitiation is required")
                    })?,
                    "DaysAfterInitiation",
                    false,
                )?,
            }),
        };
        rules.push(LifecycleRule {
            id: r.id.unwrap_or_default().trim().to_string(),
            status,
            filter,
            expiration,
            noncurrent_version_expiration,
            abort_incomplete_multipart_upload,
        });
    }
    validate_rules(&mut rules)?;
    Ok(rules)
}

fn push_tag(out: &mut String, t: &LifecycleTag) {
    out.push_str("<Tag><Key>");
    out.push_str(&escape(t.key.as_str()));
    out.push_str("</Key><Value>");
    out.push_str(&escape(t.value.as_str()));
    out.push_str("</Value></Tag>");
}

fn render_filter(out: &mut String, f: &LifecycleFilter) {
    let conditions = (!f.prefix.is_empty()) as usize
        + f.tags.len()
        + f.object_size_greater_than.is_some() as usize
        + f.object_size_less_than.is_some() as usize;
    out.push_str("<Filter>");
    if conditions > 1 {
        out.push_str("<And>");
    }
    if !f.prefix.is_empty() || conditions == 0 {
        out.push_str("<Prefix>");
        out.push_str(&escape(f.prefix.as_str()));
        out.push_str("</Prefix>");
    }
    for t in &f.tags {
        push_tag(out, t);
    }
    if let Some(gt) = f.object_size_greater_than {
        out.push_str(&format!(
            "<ObjectSizeGreaterThan>{}</ObjectSizeGreaterThan>",
            gt
        ));
    }
    if let Some(lt) = f.object_size_less_than {
        out.push_str(&format!("<ObjectSizeLessThan>{}</ObjectSizeLessThan>", lt));
    }
    if conditions > 1 {
        out.push_str("</And>");
    }
    out.push_str("</Filter>");
}

/// Render rules as a `LifecycleConfiguration` document.
pub fn render_lifecycle_xml(rules: &[LifecycleRule]) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LifecycleConfiguration xmlns=\"{}\">",
        super::bucket::S3_XMLNS
    );
    for r in rules {
        out.push_str("<Rule><ID>");
        out.push_str(&escape(r.id.as_str()));
        out.push_str("</ID>");
        render_filter(&mut out, &r.filter);
        out.push_str(match r.status {
            LifecycleStatus::Enabled => "<Status>Enabled</Status>",
            LifecycleStatus::Disabled => "<Status>Disabled</Status>",
        });
        if let Some(e) = &r.expiration {
            out.push_str("<Expiration>");
            if let Some(d) = e.days {
                out.push_str(&format!("<Days>{}</Days>", d));
            }
            if let Some(d) = &e.date {
                out.push_str("<Date>");
                out.push_str(&escape(d.as_str()));
                out.push_str("</Date>");
            }
            if e.expired_object_delete_marker {
                out.push_str("<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>");
            }
            out.push_str("</Expiration>");
        }
        if let Some(n) = &r.noncurrent_version_expiration {
            out.push_str("<NoncurrentVersionExpiration>");
            if let Some(d) = n.noncurrent_days {
                out.push_str(&format!("<NoncurrentDays>{}</NoncurrentDays>", d));
            }
            if let Some(v) = n.newer_noncurrent_versions {
                out.push_str(&format!(
                    "<NewerNoncurrentVersions>{}</NewerNoncurrentVersions>",
                    v
                ));
            }
            out.push_str("</NoncurrentVersionExpiration>");
        }
        if let Some(a) = &r.abort_incomplete_multipart_upload {
            out.push_str(&format!(
                "<AbortIncompleteMultipartUpload><DaysAfterInitiation>{}</DaysAfterInitiation>\
                 </AbortIncompleteMultipartUpload>",
                a.days_after_initiation
            ));
        }
        out.push_str("</Rule>");
    }
    out.push_str("</LifecycleConfiguration>");
    out
}

fn storage_err(bucket: &str, e: StorageError) -> S3Error {
    match e {
        StorageError::NotFound(_) | StorageError::InvalidKey(_) => S3Error::no_such_bucket(bucket),
        e => S3Error::internal(e),
    }
}

/// PutBucketLifecycleConfiguration.
pub async fn put_bucket_lifecycle(
    state: AppState,
    bucket: String,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    super::bucket::require_bucket(&state, &bucket).await?;
    let bytes = axum::body::to_bytes(body, LIFECYCLE_BODY_MAX)
        .await
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::MalformedXML,
                "The lifecycle configuration is too large",
            )
        })?;
    super::object::verify_content_md5(headers, &bytes)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| S3Error::new(S3ErrorCode::MalformedXML, "Body is not UTF-8"))?;
    let rules = parse_lifecycle_xml(text)?;
    state
        .storage
        .set_bucket_lifecycle(&bucket, Some(rules))
        .await
        .map_err(|e| storage_err(&bucket, e))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(TRANSITION_DEFAULT_HEADER, TRANSITION_DEFAULT)
        .body(Body::empty())
        .unwrap())
}

/// GetBucketLifecycleConfiguration. The caller has verified the bucket.
pub async fn get_bucket_lifecycle(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let rules = state
        .storage
        .get_bucket_lifecycle(&bucket)
        .await
        .map_err(|e| storage_err(&bucket, e))?
        .ok_or_else(|| {
            S3Error::bucket_error(
                S3ErrorCode::NoSuchLifecycleConfiguration,
                &bucket,
                "The lifecycle configuration does not exist",
            )
        })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header(TRANSITION_DEFAULT_HEADER, TRANSITION_DEFAULT)
        .body(Body::from(render_lifecycle_xml(&rules)))
        .unwrap())
}

/// DeleteBucketLifecycle.
pub async fn delete_bucket_lifecycle(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    super::bucket::require_bucket(&state, &bucket).await?;
    state
        .storage
        .set_bucket_lifecycle(&bucket, None)
        .await
        .map_err(|e| storage_err(&bucket, e))?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(rules: &str) -> String {
        format!("<LifecycleConfiguration>{}</LifecycleConfiguration>", rules)
    }

    #[test]
    fn parses_mc_ilm_rule() {
        // What `mc ilm rule add --expire-days 7` (minio-go) sends.
        let rules = parse_lifecycle_xml(&doc(
            "<Rule><Expiration><Days>7</Days></Expiration><ID>cs1abc</ID>\
             <Filter><Prefix></Prefix></Filter><Status>Enabled</Status></Rule>",
        ))
        .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "cs1abc");
        assert_eq!(rules[0].filter, LifecycleFilter::default());
        assert_eq!(rules[0].expiration.as_ref().unwrap().days, Some(7));
    }

    #[test]
    fn parses_self_closing_filter_and_and_with_empty_prefix() {
        let rules = parse_lifecycle_xml(&doc("<Rule><ID>a</ID><Filter/><Status>Enabled</Status>\
             <Expiration><Days>1</Days></Expiration></Rule>\
             <Rule><ID>b</ID><Filter><And><Prefix></Prefix><Tag><Key>k</Key><Value>v</Value></Tag>\
             <Tag><Key>k2</Key><Value>v2</Value></Tag></And></Filter><Status>Enabled</Status>\
             <Expiration><Days>1</Days></Expiration></Rule>"))
        .unwrap();
        assert_eq!(rules[1].filter.tags.len(), 2);
        assert_eq!(rules[1].filter.prefix, "");
    }

    #[test]
    fn render_then_parse_round_trips() {
        let src = doc("<Rule><ID>x&amp;y</ID><Filter><And><Prefix>a/</Prefix>\
             <ObjectSizeGreaterThan>1</ObjectSizeGreaterThan></And></Filter>\
             <Status>Disabled</Status><Expiration><Date>2030-01-01T00:00:00Z</Date></Expiration>\
             <NoncurrentVersionExpiration><NoncurrentDays>3</NoncurrentDays></NoncurrentVersionExpiration>\
             <AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation>\
             </AbortIncompleteMultipartUpload></Rule>");
        let rules = parse_lifecycle_xml(&src).unwrap();
        let rendered = render_lifecycle_xml(&rules);
        assert!(rendered.contains("<ID>x&amp;y</ID>"), "{}", rendered);
        assert_eq!(parse_lifecycle_xml(&rendered).unwrap(), rules);
    }
}
