pub mod chunk_reader;
pub mod crypto;
pub mod filesystem;
pub mod keys;
pub mod lifecycle;

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use tokio::io::AsyncRead;

pub type ByteStream = Pin<Box<dyn AsyncRead + Send>>;

pub fn validate_bucket_name(name: &str) -> Result<(), StorageError> {
    if is_valid_bucket_name(name) {
        Ok(())
    } else {
        Err(StorageError::InvalidKey(format!(
            "invalid bucket name: {name}"
        )))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    CRC32,
    CRC32C,
    CRC64NVME,
    SHA1,
    SHA256,
}

impl ChecksumAlgorithm {
    pub fn header_name(&self) -> &'static str {
        match self {
            Self::CRC32 => "x-amz-checksum-crc32",
            Self::CRC32C => "x-amz-checksum-crc32c",
            Self::CRC64NVME => "x-amz-checksum-crc64nvme",
            Self::SHA1 => "x-amz-checksum-sha1",
            Self::SHA256 => "x-amz-checksum-sha256",
        }
    }

    /// Parse an `x-amz-checksum-*` header name (case-insensitive).
    pub fn from_header_name(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        name.strip_prefix("x-amz-checksum-")
            .and_then(Self::from_header_str)
    }

    pub fn from_header_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "CRC32" => Some(Self::CRC32),
            "CRC32C" => Some(Self::CRC32C),
            "CRC64NVME" => Some(Self::CRC64NVME),
            "SHA1" => Some(Self::SHA1),
            "SHA256" => Some(Self::SHA256),
            _ => None,
        }
    }
}

/// Incremental hasher for any `ChecksumAlgorithm`; `finalize_base64` yields the
/// `x-amz-checksum-*` header value.
pub(crate) enum ChecksumHasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Crc64Nvme(u64),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl ChecksumHasher {
    pub(crate) fn new(algo: ChecksumAlgorithm) -> Self {
        match algo {
            ChecksumAlgorithm::CRC32 => Self::Crc32(crc32fast::Hasher::new()),
            ChecksumAlgorithm::CRC32C => Self::Crc32c(0),
            ChecksumAlgorithm::CRC64NVME => Self::Crc64Nvme(!0),
            ChecksumAlgorithm::SHA1 => Self::Sha1(<sha1::Sha1 as sha2::Digest>::new()),
            ChecksumAlgorithm::SHA256 => Self::Sha256(<sha2::Sha256 as sha2::Digest>::new()),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(data),
            Self::Crc32c(v) => *v = crc32c::crc32c_append(*v, data),
            Self::Crc64Nvme(v) => *v = crc64nvme_update(*v, data),
            Self::Sha1(h) => sha2::Digest::update(h, data),
            Self::Sha256(h) => sha2::Digest::update(h, data),
        }
    }

    pub(crate) fn finalize_base64(self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        match self {
            Self::Crc32(h) => b64.encode(h.finalize().to_be_bytes()),
            Self::Crc32c(v) => b64.encode(v.to_be_bytes()),
            Self::Crc64Nvme(v) => b64.encode((!v).to_be_bytes()),
            Self::Sha1(h) => b64.encode(sha2::Digest::finalize(h)),
            Self::Sha256(h) => b64.encode(sha2::Digest::finalize(h)),
        }
    }
}

/// CRC-64/NVME (reflected poly 0x9A6C9329AC4BC9B5, init/xorout all ones).
const CRC64NVME_TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x9A6C_9329_AC4B_C9B5
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn crc64nvme_update(mut crc: u64, data: &[u8]) -> u64 {
    for &b in data {
        crc = CRC64NVME_TABLE[((crc ^ b as u64) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// S3 tag-set rules shared by object, bucket, console and lifecycle-filter
/// tags: at most `max` tags, keys 1–128 chars, values ≤256 chars, unique keys,
/// and (bucket tags) no reserved `aws:` key prefix. Errors are `InvalidTag`.
pub fn validate_tags<'a>(
    tags: impl ExactSizeIterator<Item = (&'a str, &'a str)>,
    max: usize,
    reject_aws_prefix: bool,
) -> Result<(), crate::error::S3Error> {
    use crate::error::S3Error;
    if tags.len() > max {
        return Err(S3Error::invalid_tag(&format!(
            "Tags cannot exceed {max} entries"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for (key, value) in tags {
        if key.is_empty() || key.chars().count() > 128 {
            return Err(S3Error::invalid_tag(
                "Tag key must be between 1 and 128 characters",
            ));
        }
        if value.chars().count() > 256 {
            return Err(S3Error::invalid_tag(
                "Tag value exceeds maximum length of 256 characters",
            ));
        }
        if reject_aws_prefix && key.starts_with("aws:") {
            return Err(S3Error::invalid_tag(
                "Tag keys starting with aws: are reserved",
            ));
        }
        if !seen.insert(key) {
            return Err(S3Error::invalid_tag(
                "Cannot provide multiple Tags with the same key",
            ));
        }
    }
    Ok(())
}

pub struct PutResult {
    pub size: u64,
    pub etag: String,
    pub version_id: Option<String>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_value: Option<String>,
}

/// One directory level of a bucket's key namespace (see
/// `FilesystemStorage::list_key_dir`).
#[derive(Debug, Clone, Default)]
pub struct KeyDirListing {
    pub keys: Vec<String>,
    pub subdirs: Vec<String>,
}

pub struct DeleteResult {
    pub version_id: Option<String>,
    pub is_delete_marker: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsRule {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose_headers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketMeta {
    pub name: String,
    pub created_at: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub versioning: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors_rules: Option<Vec<CorsRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_config: Option<BucketEncryptionConfig>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub public_read: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub public_list: bool,
    /// Versioning was explicitly suspended (only meaningful when `versioning` is false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub versioning_suspended: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<std::collections::BTreeMap<String, String>>,
    /// Lifecycle rules (`PutBucketLifecycleConfiguration` / console).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<Vec<lifecycle::LifecycleRule>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_delete_marker: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_sizes: Option<Vec<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMeta>,
    /// Client-supplied metadata, stored as top-level sidecar fields.
    #[serde(flatten)]
    pub metadata: StoredObjectMetadata,
}

/// Object-level metadata supplied by the client at write time (PutObject,
/// CreateMultipartUpload, CopyObject) and returned on GET/HEAD.
/// `user_metadata` holds `x-amz-meta-*` (lower-cased names without the prefix).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredObjectMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

impl StoredObjectMetadata {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Condition evaluated atomically (under the per-key lock) right before a
/// write is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritePrecondition {
    /// `If-None-Match: *` — fail if a current (non-delete-marker) object exists.
    IfNoneMatchAny,
    /// `If-Match: <etag>` — fail if the current ETag differs; NotFound if absent.
    IfMatch(String),
}

/// Optional extras for an object write.
#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    pub metadata: StoredObjectMetadata,
    pub tags: Option<HashMap<String, String>>,
    pub precondition: Option<WritePrecondition>,
}

impl PutOptions {
    /// Copy metadata + tags into a freshly built sidecar.
    pub fn apply_to(&self, meta: &mut ObjectMeta) {
        meta.metadata = self.metadata.clone();
        meta.tags = self.tags.clone().filter(|t| !t.is_empty());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUploadMeta {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub content_type: String,
    pub initiated: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_spec: Option<UploadEncryptionSpec>,
    /// Metadata applied to the object on CompleteMultipartUpload.
    #[serde(default, skip_serializing_if = "StoredObjectMetadata::is_empty")]
    pub object_metadata: StoredObjectMetadata,
    /// Tags (`x-amz-tagging`) applied on CompleteMultipartUpload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartMeta {
    pub part_number: u32,
    pub etag: String,
    /// Plaintext byte length of the part (what the client uploaded).
    pub size: u64,
    pub last_modified: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_value: Option<String>,
    /// `true` when the on-disk part file is encrypted with an upload-scoped DEK.
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypted: bool,
    /// Disk size of the part including nonce + GCM tag overhead (encrypted only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChunkKind {
    Data,
    Parity,
}

impl Default for ChunkKind {
    fn default() -> Self {
        ChunkKind::Data
    }
}

impl ChunkKind {
    fn is_data(&self) -> bool {
        *self == ChunkKind::Data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkManifest {
    pub version: u32,
    /// Bytes the on-disk chunks stream. Ciphertext total when the companion
    /// ObjectMeta carries an `encryption` block, plaintext total otherwise.
    pub total_size: u64,
    pub chunk_size: u64,
    pub chunk_count: u32,
    pub chunks: Vec<ChunkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parity_shards: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_size: Option<u64>,
    /// Plaintext byte count for encrypted-EC objects; absent for plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub index: u32,
    pub size: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "ChunkKind::is_data")]
    pub kind: ChunkKind,
}

/// Encryption mode for server-side encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionMode {
    SseS3,
    SseC,
}

/// Encryption metadata stored per-object in the `.meta.json` sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMeta {
    /// "AES256"
    pub algorithm: String,
    pub mode: EncryptionMode,
    /// Master key ID used to wrap the DEK (SSE-S3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Base64-encoded wrapped (encrypted) DEK — absent for SSE-C
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_dek: Option<String>,
    /// Base64-encoded 12-byte nonce used when wrapping the DEK
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_nonce: Option<String>,
    /// Base64-encoded MD5 of the customer-supplied key (SSE-C only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_key_md5: Option<String>,
    /// Base64-encoded 4-byte per-object nonce prefix (informational)
    pub nonce_prefix: String,
    /// Plaintext bytes per frame (always FRAME_CHUNK_SIZE = 65536 in v1)
    pub chunk_size: u32,
    /// Hex-encoded HMAC-SHA256 of the immutable portion of `ObjectMeta` keyed
    /// by the DEK. Binds the sidecar to the object; tampering with `size`,
    /// `wrapped_dek`, `nonce_prefix`, `key`, etc. yields a MAC mismatch on GET.
    #[serde(default)]
    pub sidecar_mac: String,
}

/// Ephemeral encryption specification supplied by the API handler for a PUT.
/// The customer key (SSE-C) is held in a `Zeroizing` wrapper so it is scrubbed
/// from memory when the request is dropped.
pub struct EncryptionRequest {
    pub mode: EncryptionMode,
    /// Customer-supplied key (SSE-C only); never persisted, zeroed on drop.
    pub customer_key: Option<zeroize::Zeroizing<[u8; 32]>>,
}

impl EncryptionRequest {
    pub fn sse_s3() -> Self {
        Self {
            mode: EncryptionMode::SseS3,
            customer_key: None,
        }
    }
    pub fn sse_c(key: [u8; 32]) -> Self {
        Self {
            mode: EncryptionMode::SseC,
            customer_key: Some(zeroize::Zeroizing::new(key)),
        }
    }
}

/// Bucket-level default encryption configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketEncryptionConfig {
    /// Always "AES256"
    pub sse_algorithm: String,
}

/// Compact encryption specification stored in `MultipartUploadMeta` so that
/// `upload_part` and `complete_multipart_upload` can encrypt/decrypt parts
/// with an upload-scoped DEK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadEncryptionSpec {
    pub mode: EncryptionMode,
    /// SSE-C: base64 MD5 of customer key (for validation only; key not stored).
    /// Every `UploadPart` call must present a key that matches this MD5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_key_md5: Option<String>,
    /// SSE-S3: base64-encoded DEK wrapped by the active master, used to encrypt
    /// every part of this upload. `None` for SSE-C.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_dek_wrapped: Option<String>,
    /// Base64 12-byte GCM nonce used when wrapping the upload DEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_dek_wrap_nonce: Option<String>,
    /// ID of the master key that wrapped the upload DEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_dek_key_id: Option<String>,
    /// Base64 4-byte nonce prefix used for all frames across every part.
    pub upload_nonce_prefix: String,
}

/// Returns `true` if `name` is a valid S3 bucket name.
pub fn is_valid_bucket_name(name: &str) -> bool {
    bucket_name_error(name).is_none()
}

/// Explains why `name` is not a valid S3 bucket name, or `None` when it is valid.
pub fn bucket_name_error(name: &str) -> Option<&'static str> {
    if name.len() < 3 || name.len() > 63 {
        return Some("Bucket name must be 3-63 characters long.");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Some(
            "Bucket name may only contain lowercase letters, numbers, hyphens (-), and dots (.).",
        );
    }

    let first = name.chars().next().unwrap();
    let last = name.chars().last().unwrap();
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Some("Bucket name must start and end with a letter or number.");
    }

    if name.contains("..") || name.contains(".-") || name.contains("-.") {
        return Some("Bucket name must not contain two dots in a row or a dot next to a hyphen.");
    }

    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return Some(
            "Bucket name must not be formatted as an IP address (for example 192.168.5.4).",
        );
    }

    None
}

/// Create each bucket in `default_buckets` (comma-separated) if it does not
/// already exist. Invalid S3 names are logged and skipped; errors are non-fatal.
pub async fn provision_default_buckets(
    storage: &filesystem::FilesystemStorage,
    default_buckets: &str,
    region: &str,
) {
    if default_buckets.is_empty() {
        return;
    }
    for bucket_name in default_buckets.split(',') {
        let bucket_name = bucket_name.trim();
        if bucket_name.is_empty() {
            continue;
        }
        if !is_valid_bucket_name(bucket_name) {
            tracing::warn!("Skipping invalid default bucket name: '{}'", bucket_name);
            continue;
        }
        let meta = BucketMeta {
            name: bucket_name.to_string(),
            created_at: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            region: region.to_string(),
            versioning: false,
            cors_rules: None,
            encryption_config: None,
            public_read: false,
            public_list: false,
            versioning_suspended: false,
            tags: None,
            lifecycle: None,
        };
        match storage.create_bucket(&meta).await {
            Ok(true) => tracing::info!("Created default bucket: {}", bucket_name),
            Ok(false) => tracing::info!("Default bucket already exists: {}", bucket_name),
            Err(e) => tracing::warn!("Failed to create default bucket '{}': {}", bucket_name, e),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Bucket not empty")]
    BucketNotEmpty,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Multipart upload not found: {0}")]
    UploadNotFound(String),
    #[error("Parts are not in ascending order")]
    InvalidPartOrder,
    #[error("Version not found: {0}")]
    VersionNotFound(String),
    #[error("Checksum mismatch: {0}")]
    ChecksumMismatch(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Integrity error: {0}")]
    IntegrityError(String),
    #[error("Precondition failed")]
    PreconditionFailed,
}

#[cfg(test)]
mod validation_tests {
    use super::validate_bucket_name;

    #[test]
    fn rejects_path_like_bucket_names() {
        for name in [
            "../evil",
            "a/b",
            "ab",
            "evil..bucket",
            "Uppercase",
            "a.-b",
            "a-.b",
            "192.168.0.1",
        ] {
            assert!(
                validate_bucket_name(name).is_err(),
                "{name} should be invalid"
            );
        }
    }

    #[test]
    fn accepts_s3_style_bucket_name() {
        assert!(validate_bucket_name("prod-logs.2026").is_ok());
    }

    #[test]
    fn bucket_name_error_explains_each_rule() {
        use super::bucket_name_error;
        assert_eq!(bucket_name_error("prod-logs.2026"), None);
        for (name, expected) in [
            ("ab", "must be 3-63 characters long"),
            ("My-Bucket", "may only contain lowercase letters"),
            ("-bucket", "must start and end with a letter or number"),
            ("evil..bucket", "must not contain two dots in a row"),
            ("a.-b", "or a dot next to a hyphen"),
            ("192.168.0.1", "must not be formatted as an IP address"),
        ] {
            let reason = bucket_name_error(name).unwrap_or_default();
            assert!(reason.contains(expected), "{name}: got {reason:?}");
        }
    }
}

#[cfg(test)]
mod sidecar_format_tests {
    use super::ObjectMeta;

    /// The flattened `metadata` field must keep the pre-flatten on-disk layout
    /// (top-level keys, same order, absent when empty) — the SSE sidecar MAC
    /// is computed over this serialization.
    #[test]
    fn old_sidecar_json_round_trips_byte_for_byte() {
        let full = concat!(
            r#"{"key":"a/b.txt","size":5,"etag":"\"abc\"","content_type":"text/plain","#,
            r#""last_modified":"2026-01-01T00:00:00.000Z","version_id":"v1","#,
            r#""checksum_algorithm":"CRC32","checksum_value":"AAAAAA==","#,
            r#""encryption":{"algorithm":"AES256","mode":"sse_s3","key_id":"k1","#,
            r#""wrapped_dek":"d","wrap_nonce":"n","nonce_prefix":"p","chunk_size":65536,"#,
            r#""sidecar_mac":"m"},"user_metadata":{"a":"1","b":"2"},"#,
            r#""cache_control":"no-cache","content_disposition":"inline","#,
            r#""content_encoding":"gzip","content_language":"en","expires":"never"}"#
        );
        let minimal = concat!(
            r#"{"key":"k","size":0,"etag":"\"e\"","content_type":"application/octet-stream","#,
            r#""last_modified":"2026-01-01T00:00:00.000Z"}"#
        );
        for json in [full, minimal] {
            let meta: ObjectMeta = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&meta).unwrap(), json);
        }
        let meta: ObjectMeta = serde_json::from_str(full).unwrap();
        assert_eq!(meta.metadata.cache_control.as_deref(), Some("no-cache"));
        assert_eq!(meta.metadata.user_metadata.unwrap()["b"], "2");
    }
}
