use axum::response::{IntoResponse, Response};
use http::StatusCode;

#[derive(Debug)]
pub struct S3Error {
    pub code: S3ErrorCode,
    pub message: String,
    pub resource: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum S3ErrorCode {
    AccessDenied,
    BadDigest,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    InternalError,
    InvalidAccessKeyId,
    InvalidArgument,
    InvalidBucketName,
    InvalidPart,
    InvalidPartNumber,
    InvalidPartOrder,
    IllegalLocationConstraint,
    MalformedXML,
    NoSuchBucket,
    NoSuchKey,
    NoSuchUpload,
    NoSuchVersion,
    InvalidRange,
    NotImplemented,
    EntityTooSmall,
    ExpiredPresignedUrl,
    NoSuchCORSConfiguration,
    PreconditionFailed,
    SignatureDoesNotMatch,
    InvalidEncryptionAlgorithm,
    ServerSideEncryptionConfigurationNotFound,
    IncompleteBody,
    InvalidRequest,
    NoSuchLifecycleConfiguration,
    ObjectLockConfigurationNotFound,
    NoSuchWebsiteConfiguration,
    ReplicationConfigurationNotFound,
    OwnershipControlsNotFound,
    NoSuchPublicAccessBlockConfiguration,
    NoSuchBucketPolicy,
    MalformedPolicy,
    NoSuchTagSet,
    InvalidTag,
    MetadataTooLarge,
    InvalidDigest,
    MethodNotAllowed,
}

impl S3ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccessDenied => "AccessDenied",
            Self::BadDigest => "BadDigest",
            Self::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::InternalError => "InternalError",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::InvalidArgument => "InvalidArgument",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidPart => "InvalidPart",
            Self::InvalidPartNumber => "InvalidPartNumber",
            Self::InvalidPartOrder => "InvalidPartOrder",
            Self::IllegalLocationConstraint => "IllegalLocationConstraintException",
            Self::MalformedXML => "MalformedXML",
            Self::NoSuchBucket => "NoSuchBucket",
            Self::NoSuchKey => "NoSuchKey",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::NoSuchVersion => "NoSuchVersion",
            Self::InvalidRange => "InvalidRange",
            Self::NotImplemented => "NotImplemented",
            Self::EntityTooSmall => "EntityTooSmall",
            Self::ExpiredPresignedUrl => "AccessDenied",
            Self::PreconditionFailed => "PreconditionFailed",
            Self::NoSuchCORSConfiguration => "NoSuchCORSConfiguration",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::InvalidEncryptionAlgorithm => "InvalidEncryptionAlgorithmError",
            Self::ServerSideEncryptionConfigurationNotFound => {
                "ServerSideEncryptionConfigurationNotFoundError"
            }
            Self::IncompleteBody => "IncompleteBody",
            Self::InvalidRequest => "InvalidRequest",
            Self::NoSuchLifecycleConfiguration => "NoSuchLifecycleConfiguration",
            Self::ObjectLockConfigurationNotFound => "ObjectLockConfigurationNotFoundError",
            Self::NoSuchWebsiteConfiguration => "NoSuchWebsiteConfiguration",
            Self::ReplicationConfigurationNotFound => "ReplicationConfigurationNotFoundError",
            Self::OwnershipControlsNotFound => "OwnershipControlsNotFoundError",
            Self::NoSuchPublicAccessBlockConfiguration => "NoSuchPublicAccessBlockConfiguration",
            Self::NoSuchBucketPolicy => "NoSuchBucketPolicy",
            Self::MalformedPolicy => "MalformedPolicy",
            Self::NoSuchTagSet => "NoSuchTagSet",
            Self::InvalidTag => "InvalidTag",
            Self::MetadataTooLarge => "MetadataTooLarge",
            Self::InvalidDigest => "InvalidDigest",
            Self::MethodNotAllowed => "MethodNotAllowed",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AccessDenied
            | Self::ExpiredPresignedUrl
            | Self::InvalidAccessKeyId
            | Self::SignatureDoesNotMatch => StatusCode::FORBIDDEN,
            Self::NoSuchBucket
            | Self::NoSuchKey
            | Self::NoSuchUpload
            | Self::NoSuchVersion
            | Self::NoSuchCORSConfiguration
            | Self::ServerSideEncryptionConfigurationNotFound
            | Self::NoSuchLifecycleConfiguration
            | Self::ObjectLockConfigurationNotFound
            | Self::NoSuchWebsiteConfiguration
            | Self::ReplicationConfigurationNotFound
            | Self::OwnershipControlsNotFound
            | Self::NoSuchPublicAccessBlockConfiguration
            | Self::NoSuchBucketPolicy
            | Self::NoSuchTagSet => StatusCode::NOT_FOUND,
            Self::BucketAlreadyOwnedByYou | Self::BucketNotEmpty => StatusCode::CONFLICT,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidRange | Self::InvalidPartNumber => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl S3Error {
    /// Error with a code and message and no resource.
    pub fn new(code: S3ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            resource: None,
        }
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!("Internal error: {}", err);
        Self {
            code: S3ErrorCode::InternalError,
            message: "We encountered an internal error. Please try again.".into(),
            resource: None,
        }
    }

    pub fn no_such_bucket(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchBucket,
            message: format!("The specified bucket does not exist: {}", bucket),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn no_such_key(key: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchKey,
            message: "The specified key does not exist.".into(),
            resource: Some(key.to_string()),
        }
    }

    pub fn no_such_upload(upload_id: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchUpload,
            message: "The specified multipart upload does not exist.".into(),
            resource: Some(upload_id.to_string()),
        }
    }

    pub fn bucket_already_owned(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::BucketAlreadyOwnedByYou,
            message: format!(
                "Your previous request to create the named bucket succeeded and you already own it: {}",
                bucket
            ),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn bucket_not_empty(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::BucketNotEmpty,
            message: "The bucket you tried to delete is not empty.".into(),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn invalid_bucket_name(name: &str) -> Self {
        Self {
            code: S3ErrorCode::InvalidBucketName,
            message: format!("The specified bucket is not valid: {}", name),
            resource: Some(format!("/{}", name)),
        }
    }

    pub fn invalid_argument(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::InvalidArgument,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn bad_digest() -> Self {
        Self {
            code: S3ErrorCode::BadDigest,
            message: "The Content-MD5 you specified did not match what we received.".into(),
            resource: None,
        }
    }

    pub fn bad_checksum(algo: &str) -> Self {
        Self {
            code: S3ErrorCode::BadDigest,
            message: format!(
                "The {} checksum you specified did not match what we received.",
                algo
            ),
            resource: None,
        }
    }

    pub fn incomplete_body(msg: &str) -> Self {
        Self::new(S3ErrorCode::IncompleteBody, msg)
    }

    pub fn invalid_request(msg: &str) -> Self {
        Self::new(S3ErrorCode::InvalidRequest, msg)
    }

    pub fn malformed_xml() -> Self {
        Self {
            code: S3ErrorCode::MalformedXML,
            message: "The XML you provided was not well-formed.".into(),
            resource: None,
        }
    }

    pub fn invalid_part_number() -> Self {
        Self::new(
            S3ErrorCode::InvalidPartNumber,
            "The requested part number is not satisfiable",
        )
    }

    pub fn illegal_location_constraint() -> Self {
        Self::new(
            S3ErrorCode::IllegalLocationConstraint,
            "The unspecified location constraint is incompatible for the region specific endpoint this request was sent to.",
        )
    }

    pub fn invalid_part(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::InvalidPart,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn invalid_part_order() -> Self {
        Self {
            code: S3ErrorCode::InvalidPartOrder,
            message: "The list of parts was not in ascending order. Parts must be ordered by part number.".into(),
            resource: None,
        }
    }

    pub fn entity_too_small() -> Self {
        Self {
            code: S3ErrorCode::EntityTooSmall,
            message: "Your proposed upload is smaller than the minimum allowed object size.".into(),
            resource: None,
        }
    }

    pub fn expired_presigned_url() -> Self {
        Self {
            code: S3ErrorCode::ExpiredPresignedUrl,
            message: "Request has expired".into(),
            resource: None,
        }
    }

    pub fn access_denied(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::AccessDenied,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn signature_mismatch() -> Self {
        Self {
            code: S3ErrorCode::SignatureDoesNotMatch,
            message:
                "The request signature we calculated does not match the signature you provided."
                    .into(),
            resource: None,
        }
    }

    pub fn invalid_access_key() -> Self {
        Self {
            code: S3ErrorCode::InvalidAccessKeyId,
            message: "The AWS Access Key Id you provided does not exist in our records.".into(),
            resource: None,
        }
    }

    pub fn no_such_version(version_id: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchVersion,
            message: "The specified version does not exist.".into(),
            resource: Some(version_id.to_string()),
        }
    }

    pub fn invalid_range() -> Self {
        Self {
            code: S3ErrorCode::InvalidRange,
            message: "The requested range is not satisfiable".into(),
            resource: None,
        }
    }

    pub fn not_implemented(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::NotImplemented,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn no_such_cors_configuration() -> Self {
        Self {
            code: S3ErrorCode::NoSuchCORSConfiguration,
            message: "The CORS configuration does not exist".into(),
            resource: None,
        }
    }

    pub fn precondition_failed() -> Self {
        Self {
            code: S3ErrorCode::PreconditionFailed,
            message: "At least one of the pre-conditions you specified did not hold.".into(),
            resource: None,
        }
    }

    pub fn invalid_encryption_algorithm() -> Self {
        Self {
            code: S3ErrorCode::InvalidEncryptionAlgorithm,
            message: "The encryption request you specified is not valid. Supported value: AES256."
                .into(),
            resource: None,
        }
    }

    pub fn no_such_bucket_encryption(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::ServerSideEncryptionConfigurationNotFound,
            message: "The server side encryption configuration was not found.".into(),
            resource: Some(format!("/{}", bucket)),
        }
    }

    /// Bucket-scoped error with a fixed code (missing subresource configs etc.).
    pub fn bucket_error(code: S3ErrorCode, bucket: &str, msg: &str) -> Self {
        Self {
            code,
            message: msg.to_string(),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn metadata_too_large() -> Self {
        Self::new(
            S3ErrorCode::MetadataTooLarge,
            "Your metadata headers exceed the maximum allowed metadata size.",
        )
    }

    pub fn invalid_digest() -> Self {
        Self::new(
            S3ErrorCode::InvalidDigest,
            "The Content-MD5 you specified is not valid.",
        )
    }

    pub fn method_not_allowed(msg: &str) -> Self {
        Self::new(S3ErrorCode::MethodNotAllowed, msg)
    }

    pub fn invalid_tag(msg: &str) -> Self {
        Self::new(S3ErrorCode::InvalidTag, msg)
    }
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        let resource = self.resource.as_deref().unwrap_or("");
        let request_id = uuid::Uuid::new_v4();
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Error>\
             <Code>{}</Code>\
             <Message>{}</Message>\
             <Resource>{}</Resource>\
             <RequestId>{}</RequestId>\
             </Error>",
            self.code.as_str(),
            quick_xml::escape::escape(&self.message),
            quick_xml::escape::escape(resource),
            request_id,
        );

        let status = self.code.status_code();
        let request_id = request_id.to_string();
        let mut response = Response::builder()
            .status(status)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", request_id);
        // A missing key is not a delete marker. Clients (and s3-tests) read
        // this header on the 404 to distinguish the two.
        if matches!(self.code, S3ErrorCode::NoSuchKey) {
            response = response.header("x-amz-delete-marker", "false");
        }
        response
            .body(axum::body::Body::from(xml))
            .expect("error response headers are valid")
    }
}
