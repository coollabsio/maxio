pub mod chunk_reader;
pub mod crypto;
pub mod filesystem;
pub mod keys;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use tokio::io::AsyncRead;

pub type ByteStream = Pin<Box<dyn AsyncRead + Send>>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    CRC32,
    CRC32C,
    SHA1,
    SHA256,
}

impl ChecksumAlgorithm {
    pub fn header_name(&self) -> &'static str {
        match self {
            Self::CRC32 => "x-amz-checksum-crc32",
            Self::CRC32C => "x-amz-checksum-crc32c",
            Self::SHA1 => "x-amz-checksum-sha1",
            Self::SHA256 => "x-amz-checksum-sha256",
        }
    }

    pub fn from_header_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "CRC32" => Some(Self::CRC32),
            "CRC32C" => Some(Self::CRC32C),
            "SHA1" => Some(Self::SHA1),
            "SHA256" => Some(Self::SHA256),
            _ => None,
        }
    }
}

pub struct PutResult {
    pub size: u64,
    pub etag: String,
    pub version_id: Option<String>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_value: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        Self { mode: EncryptionMode::SseS3, customer_key: None }
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
}
