pub mod filesystem;

use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio::io::AsyncRead;

pub type ByteStream = Pin<Box<dyn AsyncRead + Send>>;

#[allow(dead_code)]
pub struct PutResult {
    pub size: u64,
    pub etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketMeta {
    pub name: String,
    pub created_at: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Not found: {0}")]
    NotFound(String),
}
