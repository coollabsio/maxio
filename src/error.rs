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
    MalformedXML,
    NoSuchBucket,
    NoSuchKey,
    NoSuchUpload,
    InvalidRange,
    NotImplemented,
    EntityTooSmall,
    ExpiredPresignedUrl,
    SignatureDoesNotMatch,
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
            Self::MalformedXML => "MalformedXML",
            Self::NoSuchBucket => "NoSuchBucket",
            Self::NoSuchKey => "NoSuchKey",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::InvalidRange => "InvalidRange",
            Self::NotImplemented => "NotImplemented",
            Self::EntityTooSmall => "EntityTooSmall",
            Self::ExpiredPresignedUrl => "AccessDenied",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AccessDenied
            | Self::ExpiredPresignedUrl
            | Self::InvalidAccessKeyId
            | Self::SignatureDoesNotMatch => StatusCode::FORBIDDEN,
            Self::NoSuchBucket | Self::NoSuchKey | Self::NoSuchUpload => StatusCode::NOT_FOUND,
            Self::BucketAlreadyOwnedByYou | Self::BucketNotEmpty => StatusCode::CONFLICT,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidRange => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl S3Error {
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

    pub fn malformed_xml() -> Self {
        Self {
            code: S3ErrorCode::MalformedXML,
            message: "The XML you provided was not well-formed.".into(),
            resource: None,
        }
    }

    pub fn invalid_part(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::InvalidPart,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn entity_too_small() -> Self {
        Self {
            code: S3ErrorCode::EntityTooSmall,
            message:
                "Your proposed upload is smaller than the minimum allowed object size.".into(),
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
            message: "The request signature we calculated does not match the signature you provided."
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
            self.message,
            resource,
            request_id,
        );

        let status = self.code.status_code();
        (
            status,
            [
                ("content-type", "application/xml"),
                ("x-amz-request-id", &request_id.to_string()),
            ],
            xml,
        )
            .into_response()
    }
}
