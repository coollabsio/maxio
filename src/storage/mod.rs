pub mod chunk_reader;
pub mod filesystem;

use serde::{Deserialize, Serialize};
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
pub struct BucketMeta {
    pub name: String,
    pub created_at: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub versioning: bool,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartMeta {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub last_modified: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_value: Option<String>,
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
    pub total_size: u64,
    pub chunk_size: u64,
    pub chunk_count: u32,
    pub chunks: Vec<ChunkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parity_shards: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub index: u32,
    pub size: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "ChunkKind::is_data")]
    pub kind: ChunkKind,
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
}
