use super::chunk_reader::VerifiedChunkReader;
use super::crypto::{AadBuilder, FRAME_CHUNK_SIZE, FrameDecryptor};
use super::keys::Keyring;
use super::{
    BucketEncryptionConfig, BucketMeta, ByteStream, ChecksumAlgorithm, ChecksumHasher, ChunkInfo,
    ChunkKind, ChunkManifest, DeleteResult, EncryptionMeta, EncryptionMode, EncryptionRequest,
    MultipartUploadMeta, ObjectMeta, PartMeta, PutResult, StorageError, UploadEncryptionSpec,
    validate_bucket_name,
};
use super::{KeyDirListing, PutOptions, StoredObjectMetadata, WritePrecondition};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::Engine;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::RngExt;
use sha2::Sha256;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter};

type HmacSha256 = Hmac<Sha256>;

const IO_BUFFER_SIZE: usize = 256 * 1024;
const SMALL_OBJECT_THRESHOLD: u64 = 256 * 1024;

const KEY_LOCK_SHARDS: usize = 1024;
const BUCKET_LOCK_SHARDS: usize = 256;

const FAULT_NONE: u8 = 0;
const FAULT_BEFORE_PAYLOAD_RENAME: u8 = 1;
const FAULT_AFTER_PAYLOAD_RENAME: u8 = 2;

fn consume_fault(slot: &AtomicU8, point: u8) -> bool {
    slot.compare_exchange(point, FAULT_NONE, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CompletedUploadRecord {
    etag: String,
    size: u64,
    version_id: Option<String>,
    checksum_algorithm: Option<ChecksumAlgorithm>,
    checksum_value: Option<String>,
}

pub struct FilesystemStorage {
    buckets_dir: PathBuf,
    erasure_coding: bool,
    chunk_size: u64,
    parity_shards: u32,
    keyring: Arc<Keyring>,
    /// Sharded per-(bucket, key) mutexes. Serialize publish/delete/tag/version
    /// mutations of one object so concurrent writers cannot tear a data file
    /// from its sidecar. Sharded by hash — unrelated keys may share a shard,
    /// which affects only latency, never correctness.
    key_locks: Vec<tokio::sync::Mutex<()>>,
    /// Sharded per-bucket RwLocks. Object writes take a read guard; DeleteBucket
    /// and `.bucket.json` read-modify-write take a write guard. Lock order is
    /// always bucket guard first, then key guard.
    bucket_locks: Vec<tokio::sync::RwLock<()>>,
    /// Test fault point. Always `FAULT_NONE` in production; `arm_fault` is
    /// `cfg(test)` only. Kept on the struct so publish can fail one step
    /// without a process-global flag (tests run in parallel).
    fault: AtomicU8,
    max_object_size: u64,
    max_part_size: u64,
    max_multipart_object_size: u64,
}

fn shard_index(parts: &[&str], shards: usize) -> usize {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    (h.finish() as usize) % shards
}

/// Validate that an object key does not contain path traversal components.
fn validate_key_shape(key: &str) -> Result<(), StorageError> {
    if key.is_empty() {
        return Err(StorageError::InvalidKey("Key must not be empty".into()));
    }
    if key.len() > 1024 {
        return Err(StorageError::InvalidKey(
            "Key must not exceed 1024 bytes".into(),
        ));
    }
    let path = Path::new(key);
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(StorageError::InvalidKey(
                    "Key must not contain '..' path components".into(),
                ));
            }
            Component::RootDir => {
                return Err(StorageError::InvalidKey(
                    "Key must not be an absolute path".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), StorageError> {
    validate_key_shape(key)?;
    if let Some(name) = reserved_segment_in(key) {
        return Err(StorageError::InvalidKey(format!(
            "Key segment '{name}' collides with an internal storage name"
        )));
    }
    Ok(())
}

/// Reject key path segments that collide with internal on-disk names
/// (sidecars, bucket metadata, internal dirs, EC dirs, temp files, the
/// inline payload, and key-promotion directories and markers).
///
/// Comparison is ASCII case-insensitive so `p/.MAXIO.OBJECT` is rejected on
/// case-insensitive filesystems as well as on Linux.
pub(crate) fn is_reserved_segment(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(".meta.json")
        || name.ends_with(".ec")
        || name == ".bucket.json"
        || name == ".uploads"
        || name == ".versions"
        || name == ".folder"
        || name == ".maxio.object"
        || name == ".maxio-quarantine"
        || name.starts_with(".maxio-tmp-")
        || name.starts_with(".maxio-bak-")
        || name.starts_with(".maxio-promote-")
}

pub(crate) fn key_contains_reserved_segment(key: &str) -> bool {
    reserved_segment_in(key).is_some()
}

/// Error text for a key that uses an internal path segment. `None` when the
/// key is a normal object name. Callers reject this before authorization so
/// the response is `400 InvalidArgument` for every principal.
pub(crate) fn reserved_key_message(key: &str) -> Option<String> {
    reserved_segment_in(key)
        .map(|name| format!("Key segment '{name}' collides with an internal storage name"))
}

fn reserved_segment_in(key: &str) -> Option<String> {
    Path::new(key)
        .components()
        .find_map(|component| match component {
            Component::Normal(seg) => {
                let name = seg.to_string_lossy();
                if is_reserved_segment(&name) {
                    Some(name.into_owned())
                } else {
                    None
                }
            }
            _ => None,
        })
}

pub(crate) fn is_promote_dir_name(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with(".maxio-promote-")
}

/// A directory MaxIO may descend into while looking for objects whose keys
/// used a name this version now reserves. Upload and version stores have
/// their own scanners.
pub(crate) fn is_legacy_container(name: &str) -> bool {
    if !is_reserved_segment(name) || is_promote_dir_name(name) {
        return false;
    }
    let name = name.to_ascii_lowercase();
    !matches!(name.as_str(), ".uploads" | ".versions" | ".folder")
        && !name.starts_with(".maxio-tmp-")
        && !name.starts_with(".maxio-bak-")
        && !name.ends_with(".ec")
}

/// Reads of an internal name are `NoSuchKey`. The bytes, if any, belong to
/// MaxIO's layout (for example `p/.maxio.object` is the payload of key `p`).
fn validate_readable_key(key: &str) -> Result<(), StorageError> {
    if key_contains_reserved_segment(key) {
        return Err(StorageError::NotFound(key.to_string()));
    }
    validate_key(key)
}

/// Writes of an internal name are `InvalidArgument`.
pub(crate) fn reject_writable_key(key: &str) -> Result<(), StorageError> {
    validate_key(key)
}

/// Version ids are joined into filesystem paths, so accept only "null" or
/// the shape produced by `generate_version_id` (`{micros}-{hex}`).
fn validate_version_id(version_id: &str) -> Result<(), StorageError> {
    let valid = version_id == "null"
        || version_id.split_once('-').is_some_and(|(micros, suffix)| {
            !micros.is_empty()
                && !suffix.is_empty()
                && micros.bytes().all(|b| b.is_ascii_digit())
                && suffix
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
    if valid {
        Ok(())
    } else {
        Err(StorageError::InvalidKey(
            "Invalid version id specified".into(),
        ))
    }
}

fn validate_upload_id(upload_id: &str) -> Result<(), StorageError> {
    if upload_id.is_empty() {
        return Err(StorageError::UploadNotFound(upload_id.to_string()));
    }
    if upload_id.contains('/') || upload_id.contains('\\') || upload_id.contains("..") {
        return Err(StorageError::UploadNotFound(upload_id.to_string()));
    }
    Ok(())
}

/// Compute the 32-byte AAD for one frame of an object's ciphertext.
///
/// `aad = SHA-256(bucket || 0x00 || key || 0x00 || version_id || 0x00 || chunk_index_le_8B)`
///
/// Binds every GCM auth tag to object identity, detecting cross-object frame
/// swaps that would otherwise decrypt cleanly (same DEK + nonce + index).
fn build_frame_aad(bucket: &str, key: &str, version_id: Option<&str>, chunk_index: u64) -> Vec<u8> {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(bucket.as_bytes());
    hasher.update([0u8]);
    hasher.update(key.as_bytes());
    hasher.update([0u8]);
    hasher.update(version_id.unwrap_or("").as_bytes());
    hasher.update([0u8]);
    hasher.update(chunk_index.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Build an `AadBuilder` closure for object frames. Captures the identifiers so
/// the frame writer/reader can produce per-chunk AAD on demand.
pub(crate) fn object_aad_builder(bucket: &str, key: &str, version_id: Option<&str>) -> AadBuilder {
    let bucket = bucket.to_string();
    let key = key.to_string();
    let version_id = version_id.map(|v| v.to_string());
    Arc::new(move |chunk_index: u64| {
        build_frame_aad(&bucket, &key, version_id.as_deref(), chunk_index)
    })
}

/// Compute the 32-byte AAD for one frame of a multipart part's ciphertext.
///
/// `part_aad = SHA-256("PART" || 0x00 || upload_id || 0x00 || part_number_le_4B || 0x00 || chunk_index_le_8B)`
///
/// Binds part frames to the specific upload + part slot so they cannot be
/// shuffled between parts or other uploads without failing GCM authentication.
fn build_part_aad(upload_id: &str, part_number: u32, chunk_index: u64) -> Vec<u8> {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(b"PART");
    hasher.update([0u8]);
    hasher.update(upload_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(part_number.to_le_bytes());
    hasher.update([0u8]);
    hasher.update(chunk_index.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Closure form of `build_part_aad` for the frame decryptor on `Complete`.
fn part_aad_builder(upload_id: &str, part_number: u32) -> AadBuilder {
    let upload_id = upload_id.to_string();
    Arc::new(move |chunk_index: u64| build_part_aad(&upload_id, part_number, chunk_index))
}

/// Re-verify the bytes actually streamed out of a part file against the part's
/// recorded size and MD5 ETag. Catches a torn or stale part file (e.g. from a
/// crashed re-upload) before it is baked into a completed object whose
/// composite ETag would otherwise still "match".
fn verify_part_bytes(part: &PartMeta, bytes: u64, md5: Md5) -> Result<(), StorageError> {
    if bytes != part.size {
        return Err(StorageError::InvalidKey(format!(
            "part {} size mismatch: expected {} bytes, read {}",
            part.part_number, part.size, bytes
        )));
    }
    let actual = format!("\"{}\"", hex::encode(md5.finalize()));
    if actual != part.etag {
        return Err(StorageError::InvalidKey(format!(
            "part {} content does not match its etag — part file may be corrupt",
            part.part_number
        )));
    }
    Ok(())
}

/// Strip all mutable fields of `ObjectMeta` to produce the canonical input
/// that the sidecar MAC is computed over. Fields that MAY be edited after
/// initial write (tags, delete marker, `sidecar_mac` itself) are cleared so a
/// legitimate tag update does not invalidate the MAC.
fn mac_input(meta: &ObjectMeta) -> ObjectMeta {
    let mut m = meta.clone();
    m.tags = None;
    m.is_delete_marker = false;
    if let Some(ref mut e) = m.encryption {
        e.sidecar_mac = String::new();
    }
    m
}

/// Recursively sort all JSON object keys so that `serde_json::to_vec` produces
/// a deterministic byte stream. `ObjectMeta` contains `HashMap` fields whose
/// iteration order is not stable, so a canonical representation is required.
fn canonical_json_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonical_json_value(&m[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical_json_value).collect()),
        _ => v.clone(),
    }
}

/// Compute the hex-encoded HMAC-SHA256 over `mac_input(meta)` keyed by the DEK.
fn compute_sidecar_mac(dek: &[u8; 32], meta: &ObjectMeta) -> Result<String, StorageError> {
    let input = mac_input(meta);
    let value = serde_json::to_value(&input)?;
    let canonical = canonical_json_value(&value);
    let bytes = serde_json::to_vec(&canonical)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dek)
        .map_err(|_| StorageError::EncryptionError("hmac init failed".into()))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Verify the stored `sidecar_mac` against a freshly computed MAC. Used by the
/// read path before any ciphertext is decrypted.
fn verify_sidecar_mac(meta: &ObjectMeta, dek: &[u8; 32]) -> Result<(), StorageError> {
    let enc = meta
        .encryption
        .as_ref()
        .ok_or_else(|| StorageError::IntegrityError("object has no encryption metadata".into()))?;
    let expected = compute_sidecar_mac(dek, meta)?;
    if enc.sidecar_mac.is_empty() {
        return Err(StorageError::IntegrityError(
            "sidecar_mac missing — object may be tampered".into(),
        ));
    }
    if !constant_time_eq(expected.as_bytes(), enc.sidecar_mac.as_bytes()) {
        return Err(StorageError::IntegrityError(
            "sidecar_mac mismatch — object metadata has been tampered".into(),
        ));
    }
    Ok(())
}

/// Reject GET/HEAD requests that carry SSE-C headers but target an object that
/// was not encrypted. Matches AWS `InvalidRequest` behavior and prevents the
/// client from getting the false impression that SSE-C protected the response.
fn reject_sse_c_on_plaintext(
    meta: &ObjectMeta,
    has_customer_key: bool,
) -> Result<(), StorageError> {
    if has_customer_key && meta.encryption.is_none() {
        return Err(StorageError::DecryptionError(
            "SSE-C headers supplied but object is not encrypted".into(),
        ));
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl FilesystemStorage {
    pub async fn new(
        data_dir: &str,
        erasure_coding: bool,
        chunk_size: u64,
        parity_shards: u32,
        keyring: Arc<Keyring>,
    ) -> Result<Self, anyhow::Error> {
        let buckets_dir = Path::new(data_dir).join("buckets");
        fs::create_dir_all(&buckets_dir).await?;
        let storage = Self {
            buckets_dir,
            erasure_coding,
            chunk_size,
            parity_shards,
            keyring,
            key_locks: (0..KEY_LOCK_SHARDS).map(|_| Default::default()).collect(),
            bucket_locks: (0..BUCKET_LOCK_SHARDS)
                .map(|_| Default::default())
                .collect(),
            fault: AtomicU8::new(FAULT_NONE),
            max_object_size: u64::MAX,
            max_part_size: u64::MAX,
            max_multipart_object_size: u64::MAX,
        };
        // An older build allowed object keys this version reserves. Serving
        // them in place collides with the on-disk layout, so refuse before
        // any cleanup rewrites the directory.
        let legacy = find_legacy_reserved_keys(&storage.buckets_dir).await;
        if !legacy.is_empty() {
            return Err(anyhow::anyhow!(format_legacy_reserved_error(&legacy)));
        }
        let reserved = reserved_buckets_present(&storage.buckets_dir).await;
        if !reserved.is_empty() {
            return Err(anyhow::anyhow!(reserved_bucket_error(&reserved)));
        }
        // Nothing is in flight during construction, so crash leftovers (temp
        // files, stranded EC backups, half-finished key promotions, upload
        // dirs with no readable metadata) are safe to clear immediately. The
        // hourly sweep keeps an age gate so it cannot delete a live request's
        // temp file or promote directory.
        storage.startup_recover().await;
        Ok(storage)
    }

    /// Caps for a single PutObject, one multipart part, and an assembled
    /// multipart object. `u64::MAX` disables a cap. Set from server config.
    pub fn set_upload_limits(&mut self, max_object: u64, max_part: u64, max_multipart: u64) {
        self.max_object_size = max_object;
        self.max_part_size = max_part;
        self.max_multipart_object_size = max_multipart;
    }

    fn check_object_size(&self, size: u64) -> Result<(), StorageError> {
        if size > self.max_object_size {
            Err(StorageError::EntityTooLarge)
        } else {
            Ok(())
        }
    }

    fn check_part_size(&self, size: u64) -> Result<(), StorageError> {
        if size > self.max_part_size {
            Err(StorageError::EntityTooLarge)
        } else {
            Ok(())
        }
    }

    /// Test-only: the next publish fails once at `point` (`FAULT_*`).
    #[cfg(test)]
    fn arm_fault(&self, point: u8) {
        self.fault.store(point, Ordering::SeqCst);
    }

    async fn key_lock(&self, bucket: &str, key: &str) -> tokio::sync::MutexGuard<'_, ()> {
        self.key_locks[shard_index(&[bucket, key], KEY_LOCK_SHARDS)]
            .lock()
            .await
    }

    async fn bucket_read(&self, bucket: &str) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.bucket_locks[shard_index(&[bucket], BUCKET_LOCK_SHARDS)]
            .read()
            .await
    }

    async fn bucket_write(&self, bucket: &str) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.bucket_locks[shard_index(&[bucket], BUCKET_LOCK_SHARDS)]
            .write()
            .await
    }

    // --- Bucket operations ---

    pub async fn create_bucket(&self, meta: &BucketMeta) -> Result<bool, StorageError> {
        validate_bucket_name(&meta.name)?;
        let bucket_dir = self.buckets_dir.join(&meta.name);
        match fs::create_dir(&bucket_dir).await {
            Ok(()) => {
                let meta_path = bucket_dir.join(".bucket.json");
                let json = serde_json::to_string_pretty(meta)?;
                if let Err(e) = write_file_atomic(&meta_path, json.as_bytes()).await {
                    // Clean up the empty directory to avoid a half-created bucket
                    let _ = fs::remove_dir(&bucket_dir).await;
                    return Err(e);
                }
                sync_parent_dir(&bucket_dir).await?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn head_bucket(&self, name: &str) -> Result<bool, StorageError> {
        validate_bucket_name(name)?;
        Ok(fs::try_exists(self.buckets_dir.join(name).join(".bucket.json")).await?)
    }

    pub async fn delete_bucket(&self, name: &str) -> Result<bool, StorageError> {
        validate_bucket_name(name)?;
        // Write lock: no object publish (which holds a read guard) can
        // interleave between the emptiness check and the purge pass.
        let _bucket_guard = self.bucket_write(name).await;
        let bucket_dir = self.buckets_dir.join(name);
        if !fs::try_exists(&bucket_dir).await? {
            return Ok(false);
        }
        // Pass 1: read-only walk. Any real object (data file, `.folder`
        // marker, `.ec/` chunk dir) at any depth → BucketNotEmpty.
        if self.has_real_objects(&bucket_dir).await? {
            return Err(StorageError::BucketNotEmpty);
        }
        // Pass 2: purge sidecars (`*.meta.json`), internal dirs
        // (`.uploads`, `.versions`), and empty subdirs at any depth.
        self.purge_empty_bucket(&bucket_dir).await?;
        match fs::remove_dir(&bucket_dir).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                // Concurrent writer slipped a file in between passes.
                Err(StorageError::BucketNotEmpty)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Read-only check: does this bucket contain any real object data?
    fn has_real_objects<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = fs::read_dir(dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == ".bucket.json"
                    || name == ".uploads"
                    || name == ".versions"
                    || name.ends_with(".meta.json")
                    || name.starts_with(".maxio-tmp-")
                    || name.starts_with(".maxio-bak-")
                {
                    continue;
                }
                let ft = entry.file_type().await?;
                if ft.is_dir() && name.ends_with(".ec") {
                    return Ok(true);
                }
                if ft.is_dir() {
                    if self.has_real_objects(&entry.path()).await? {
                        return Ok(true);
                    }
                } else {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Post-order purge: remove sidecars / internal dirs at any depth and
    /// empty out every subdirectory. Must only run after
    /// `has_real_objects` returned `false`.
    fn purge_empty_bucket<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = fs::read_dir(dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name().to_string_lossy().to_string();
                let path = entry.path();
                let ft = entry.file_type().await?;

                if name == ".bucket.json"
                    || name == ".uploads"
                    || name == ".versions"
                    || name.ends_with(".meta.json")
                    || name.starts_with(".maxio-tmp-")
                    || name.starts_with(".maxio-bak-")
                {
                    if ft.is_dir() {
                        fs::remove_dir_all(&path).await?;
                    } else {
                        fs::remove_file(&path).await?;
                    }
                    continue;
                }

                if ft.is_dir() {
                    self.purge_empty_bucket(&path).await?;
                    fs::remove_dir(&path).await?;
                }
                // Non-sidecar regular files shouldn't exist here
                // (has_real_objects would have rejected) — skip defensively.
            }
            Ok(())
        })
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketMeta>, StorageError> {
        let mut buckets = Vec::new();
        let mut entries = fs::read_dir(&self.buckets_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let meta_path = entry.path().join(".bucket.json");
                if let Ok(data) = fs::read_to_string(&meta_path).await {
                    if let Ok(meta) = serde_json::from_str::<BucketMeta>(&data) {
                        buckets.push(meta);
                    }
                }
            }
        }
        buckets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(buckets)
    }

    // --- Object operations ---

    fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        if key.ends_with('/') {
            let dir = key.trim_end_matches('/');
            self.buckets_dir.join(bucket).join(dir).join(".folder")
        } else {
            self.buckets_dir.join(bucket).join(key)
        }
    }

    /// Where a plain object's bytes are written. A key that is also a prefix
    /// of other keys (`foo/bar` and `foo/bar/baz`) keeps its bytes at
    /// `{key}/.maxio.object` so the key can be both a file and a directory.
    async fn plain_object_write_path(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<PathBuf, StorageError> {
        let path = self.object_path(bucket, key);
        if key.ends_with('/') {
            if let Some(parent) = path.parent() {
                ensure_dir_preserving_objects(parent).await?;
            }
            return Ok(path);
        }
        if let Some(parent) = path.parent() {
            ensure_dir_preserving_objects(parent).await?;
        }
        match fs::metadata(&path).await {
            Ok(meta) if meta.is_dir() => Ok(path.join(INLINE_OBJECT_PAYLOAD)),
            _ => Ok(path),
        }
    }

    /// True when this key's bytes are at `{key}/.maxio.object` because the key
    /// is also a prefix of other keys.
    pub async fn object_inline_payload(&self, bucket: &str, key: &str) -> bool {
        if key.is_empty() || key.ends_with('/') {
            return false;
        }
        let path = self.plain_object_read_path(bucket, key).await;
        path.file_name().and_then(|name| name.to_str()) == Some(INLINE_OBJECT_PAYLOAD)
    }

    /// Path to read a plain object's bytes (the file, or the inline payload
    /// when the key is also a prefix).
    async fn plain_object_read_path(&self, bucket: &str, key: &str) -> PathBuf {
        let path = self.object_path(bucket, key);
        let inline = path.join(INLINE_OBJECT_PAYLOAD);
        if matches!(fs::metadata(&inline).await, Ok(m) if m.is_file()) {
            inline
        } else {
            path
        }
    }

    fn meta_path(&self, bucket: &str, key: &str) -> PathBuf {
        if key.ends_with('/') {
            let dir = key.trim_end_matches('/');
            self.buckets_dir
                .join(bucket)
                .join(dir)
                .join(".folder.meta.json")
        } else {
            self.buckets_dir
                .join(bucket)
                .join(format!("{}.meta.json", key))
        }
    }

    fn ec_dir(&self, bucket: &str, key: &str) -> PathBuf {
        self.buckets_dir.join(bucket).join(format!("{}.ec", key))
    }

    fn manifest_path(&self, bucket: &str, key: &str) -> PathBuf {
        self.ec_dir(bucket, key).join("manifest.json")
    }

    async fn is_chunked_path(ec_dir: &Path) -> bool {
        matches!(fs::metadata(ec_dir).await, Ok(m) if m.is_dir())
    }

    async fn read_manifest(&self, bucket: &str, key: &str) -> Result<ChunkManifest, StorageError> {
        let path = self.manifest_path(bucket, key);
        let data = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    fn uploads_dir(&self, bucket: &str) -> PathBuf {
        self.buckets_dir.join(bucket).join(".uploads")
    }

    fn upload_dir(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.uploads_dir(bucket).join(upload_id)
    }

    fn upload_meta_path(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.upload_dir(bucket, upload_id).join(".meta.json")
    }

    fn part_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        self.upload_dir(bucket, upload_id)
            .join(part_number.to_string())
    }

    fn part_meta_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        self.upload_dir(bucket, upload_id)
            .join(format!("{}.meta.json", part_number))
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
        encryption: Option<EncryptionRequest>,
    ) -> Result<PutResult, StorageError> {
        self.put_object_with(
            bucket,
            key,
            content_type,
            body,
            checksum,
            encryption,
            &PutOptions::default(),
        )
        .await
    }

    /// `put_object` plus user metadata / tags and an optional write
    /// precondition that is evaluated atomically under the per-key lock.
    pub async fn put_object_with(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        mut body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
        encryption: Option<EncryptionRequest>,
        opts: &PutOptions,
    ) -> Result<PutResult, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
        let precondition = opts.precondition.as_ref();

        // Folder marker: zero-byte object with key ending in /
        if key.ends_with('/') {
            return self.put_folder_marker(bucket, key, opts).await;
        }

        if self.erasure_coding {
            if let Some(req) = encryption {
                return self
                    .put_object_chunked_encrypted(
                        bucket,
                        key,
                        content_type,
                        body,
                        checksum,
                        req,
                        opts,
                    )
                    .await;
            }
            return self
                .put_object_chunked(
                    bucket,
                    key,
                    content_type,
                    body,
                    checksum.as_ref().map(|(a, _)| *a),
                    opts,
                )
                .await;
        }

        // Determine version_id up front so it can be folded into the AAD.
        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        // Prepare encryption metadata and cipher
        let mut enc_meta_opt: Option<EncryptionMeta> = match encryption {
            Some(ref req) => Some(
                self.prepare_encryption(req)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?,
            ),
            None => None,
        };
        let (cipher_opt, nonce_prefix, dek_opt) = if let Some(ref em) = enc_meta_opt {
            let dek = self
                .resolve_dek(
                    em,
                    encryption
                        .as_ref()
                        .and_then(|r| r.customer_key.as_ref().map(|k| **k)),
                )
                .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
            let b64 = base64::engine::general_purpose::STANDARD;
            let prefix_bytes = b64
                .decode(&em.nonce_prefix)
                .map_err(|_| StorageError::EncryptionError("invalid nonce_prefix".into()))?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
            (Some(cipher), prefix_bytes, Some(dek))
        } else {
            (None, Vec::new(), None)
        };

        let obj_path = self.plain_object_write_path(bucket, key).await?;

        let tmp_obj_path = temp_sibling_path(&obj_path);
        let mut tmp_obj_guard = TempPathGuard::file(tmp_obj_path.clone());
        let file = fs::File::create(&tmp_obj_path).await?;
        let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, file);
        let mut hasher = Md5::new();
        let mut checksum_hasher = checksum
            .as_ref()
            .map(|(algo, _)| ChecksumHasher::new(*algo));
        let mut size: u64 = 0;
        let mut buf = vec![0u8; IO_BUFFER_SIZE];
        let mut frame_buf: Vec<u8> = Vec::with_capacity(FRAME_CHUNK_SIZE);
        let mut chunk_index: u64 = 0;

        loop {
            let n = body.read(&mut buf).await?;
            if n == 0 {
                // flush remaining partial frame
                if let Some(ref cipher) = cipher_opt {
                    if !frame_buf.is_empty() {
                        let aad = build_frame_aad(bucket, key, version_id.as_deref(), chunk_index);
                        write_encrypted_frame(
                            &mut writer,
                            cipher,
                            &nonce_prefix,
                            chunk_index,
                            &frame_buf,
                            &aad,
                        )
                        .await?;
                    }
                }
                break;
            }
            hasher.update(&buf[..n]);
            if let Some(ref mut ch) = checksum_hasher {
                ch.update(&buf[..n]);
            }
            size += n as u64;
            self.check_object_size(size)?;
            if let Some(ref cipher) = cipher_opt {
                frame_buf.extend_from_slice(&buf[..n]);
                while frame_buf.len() >= FRAME_CHUNK_SIZE {
                    let frame_data: Vec<u8> = frame_buf.drain(..FRAME_CHUNK_SIZE).collect();
                    let aad = build_frame_aad(bucket, key, version_id.as_deref(), chunk_index);
                    write_encrypted_frame(
                        &mut writer,
                        cipher,
                        &nonce_prefix,
                        chunk_index,
                        &frame_data,
                        &aad,
                    )
                    .await?;
                    chunk_index += 1;
                }
            } else {
                writer.write_all(&buf[..n]).await?;
            }
        }
        writer.flush().await?;

        let etag = hex::encode(hasher.finalize());
        let etag_quoted = format!("\"{}\"", etag);

        // Validate and compute checksum
        let (checksum_algorithm, checksum_value) = if let Some((algo, expected)) = checksum {
            let computed = checksum_hasher.unwrap().finalize_base64();
            if let Some(expected_val) = expected {
                if computed != expected_val {
                    let _ = fs::remove_file(&tmp_obj_path).await;
                    return Err(StorageError::ChecksumMismatch(format!(
                        "expected {}, got {}",
                        expected_val, computed
                    )));
                }
            }
            (Some(algo), Some(computed))
        } else {
            (None, None)
        };

        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        // Fold the sidecar MAC into the encryption metadata now that every
        // immutable field (size/etag/version_id/etc.) is final.
        let mut meta = ObjectMeta {
            key: key.to_string(),
            size,
            etag: etag_quoted.clone(),
            content_type: content_type.to_string(),
            last_modified: now,
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
            tags: None,
            part_sizes: None,
            encryption: enc_meta_opt.take(),
            ..Default::default()
        };
        opts.apply_to(&mut meta);
        if let (Some(dek), Some(em)) = (dek_opt.as_ref(), meta.encryption.as_mut()) {
            em.sidecar_mac = String::new();
            let mac = compute_sidecar_mac(dek, &meta)?;
            meta.encryption.as_mut().unwrap().sidecar_mac = mac;
        }

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string_pretty(&meta)?;
        let tmp_meta_path = temp_sibling_path(&meta_path);
        let mut tmp_meta_guard = TempPathGuard::file(tmp_meta_path.clone());
        fs::write(&tmp_meta_path, json).await?;

        // Serialize the visible state change per key; the bucket read guard
        // keeps DeleteBucket from interleaving with the publish.
        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        self.ensure_bucket_exists(bucket).await?;
        self.check_write_precondition(bucket, key, precondition)
            .await?;
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                // Snapshot BEFORE publish, from the temp file, so a concurrent
                // or failed publish can never corrupt the version copy.
                // Archive a pre-versioning ("null") current object instead of
                // destroying it.
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version(bucket, key, &meta, &tmp_obj_path)
                    .await?;
            }
            publish_temp_payload_and_meta(
                &tmp_obj_path,
                &obj_path,
                false,
                &tmp_meta_path,
                &meta_path,
                &self.fault,
            )
            .await
        }
        .await;
        if let Err(e) = publish_result {
            if versioned {
                self.rollback_failed_versioned_publish(bucket, key, version_id.as_deref())
                    .await;
            }
            return Err(e);
        }
        tmp_obj_guard.disarm();
        tmp_meta_guard.disarm();
        // The same key may hold a stale EC payload from an earlier server
        // config; reads resolve EC first, so drop it.
        remove_dir_all_if_exists(&self.ec_dir(bucket, key)).await?;

        Ok(PutResult {
            size,
            etag: etag_quoted,
            version_id,
            checksum_algorithm,
            checksum_value,
        })
    }

    async fn put_object_chunked(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        mut body: ByteStream,
        checksum_algo: Option<ChecksumAlgorithm>,
        opts: &PutOptions,
    ) -> Result<PutResult, StorageError> {
        validate_bucket_name(bucket)?;
        let precondition = opts.precondition.as_ref();
        let ec_dir = self.ec_dir(bucket, key);
        let tmp_ec_dir = temp_sibling_path(&ec_dir);
        let mut tmp_ec_guard = TempPathGuard::dir(tmp_ec_dir.clone());
        if let Some(parent) = ec_dir.parent() {
            ensure_dir_preserving_objects(parent).await?;
        }
        fs::create_dir_all(&tmp_ec_dir).await?;

        let mut md5_hasher = Md5::new();
        let mut checksum_hasher = checksum_algo.map(ChecksumHasher::new);
        let mut total_size: u64 = 0;
        let mut chunks: Vec<ChunkInfo> = Vec::new();
        let mut chunk_index: u32 = 0;

        let mut read_buf = vec![0u8; IO_BUFFER_SIZE];
        let mut chunk_buf = Vec::with_capacity(self.chunk_size as usize);

        loop {
            let n = body.read(&mut read_buf).await?;
            if n == 0 {
                // Flush remaining chunk_buf
                if !chunk_buf.is_empty() {
                    let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_buf).await?;
                    chunks.push(ci);
                }
                break;
            }

            md5_hasher.update(&read_buf[..n]);
            if let Some(ref mut ch) = checksum_hasher {
                ch.update(&read_buf[..n]);
            }
            total_size += n as u64;
            self.check_object_size(total_size)?;
            chunk_buf.extend_from_slice(&read_buf[..n]);

            while chunk_buf.len() >= self.chunk_size as usize {
                let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
                let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_data).await?;
                chunks.push(ci);
                chunk_index += 1;
            }
        }

        // Handle empty object (zero chunks)
        if chunks.is_empty() {
            let ci = write_chunk_to_dir(&tmp_ec_dir, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;

        // Compute and write parity shards if configured (skip for empty objects)
        let has_parity = self.parity_shards > 0 && total_size > 0;
        if has_parity {
            let parity_infos = self
                .compute_and_write_parity_in_dir(&tmp_ec_dir, &chunks)
                .await?;
            chunks.extend(parity_infos);
        }

        let manifest = ChunkManifest {
            version: if has_parity { 2 } else { 1 },
            total_size,
            chunk_size: self.chunk_size,
            chunk_count: data_chunk_count,
            chunks,
            parity_shards: if has_parity {
                Some(self.parity_shards)
            } else {
                None
            },
            shard_size: if has_parity {
                Some(self.chunk_size)
            } else {
                None
            },
            plaintext_size: None,
        };
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        write_file_atomic(&tmp_ec_dir.join("manifest.json"), manifest_json.as_bytes()).await?;

        let etag = hex::encode(md5_hasher.finalize());
        let etag_quoted = format!("\"{}\"", etag);
        let checksum_value = checksum_hasher.map(|h| h.finalize_base64());

        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        let storage_format = if has_parity {
            "chunked-v2"
        } else {
            "chunked-v1"
        };
        let mut meta = ObjectMeta {
            key: key.to_string(),
            size: total_size,
            etag: etag_quoted.clone(),
            content_type: content_type.to_string(),
            last_modified: now,
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: Some(storage_format.to_string()),
            checksum_algorithm: checksum_algo,
            checksum_value: checksum_value.clone(),
            tags: None,
            part_sizes: None,
            encryption: None,
            ..Default::default()
        };
        opts.apply_to(&mut meta);

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let tmp_meta_path = temp_sibling_path(&meta_path);
        let mut tmp_meta_guard = TempPathGuard::file(tmp_meta_path.clone());
        fs::write(&tmp_meta_path, serde_json::to_string_pretty(&meta)?).await?;

        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        self.ensure_bucket_exists(bucket).await?;
        self.check_write_precondition(bucket, key, precondition)
            .await?;
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(
                &tmp_ec_dir,
                &ec_dir,
                true,
                &tmp_meta_path,
                &meta_path,
                &self.fault,
            )
            .await
        }
        .await;
        if let Err(e) = publish_result {
            if versioned {
                self.rollback_failed_versioned_publish(bucket, key, version_id.as_deref())
                    .await;
            }
            return Err(e);
        }
        tmp_ec_guard.disarm();
        tmp_meta_guard.disarm();
        remove_plain_payload(&self.object_path(bucket, key)).await?;

        Ok(PutResult {
            size: total_size,
            etag: etag_quoted,
            version_id,
            checksum_algorithm: checksum_algo,
            checksum_value,
        })
    }

    /// Encrypt-then-EC write path. Frames plaintext through AES-256-GCM (reusing
    /// the same 64 KiB frame format as non-EC SSE), then chunks the ciphertext
    /// stream into `self.chunk_size`-sized EC chunks. Frame boundaries are not
    /// aligned with chunk boundaries — RS reconstructs chunk bytes byte-exact,
    /// so frames re-emerge intact on read.
    async fn put_object_chunked_encrypted(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        mut body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
        encryption: EncryptionRequest,
        opts: &PutOptions,
    ) -> Result<PutResult, StorageError> {
        validate_bucket_name(bucket)?;
        let precondition = opts.precondition.as_ref();
        let ec_dir = self.ec_dir(bucket, key);
        let tmp_ec_dir = temp_sibling_path(&ec_dir);
        let mut tmp_ec_guard = TempPathGuard::dir(tmp_ec_dir.clone());
        if let Some(parent) = ec_dir.parent() {
            ensure_dir_preserving_objects(parent).await?;
        }
        fs::create_dir_all(&tmp_ec_dir).await?;

        // Version-id upfront: AAD binds to it, so we need it before the first
        // frame is encrypted.
        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        let enc_meta = self
            .prepare_encryption(&encryption)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        let dek = self
            .resolve_dek(&enc_meta, encryption.customer_key.as_ref().map(|k| **k))
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let prefix_bytes = b64
            .decode(&enc_meta.nonce_prefix)
            .map_err(|_| StorageError::EncryptionError("invalid nonce_prefix".into()))?;
        let nonce_prefix = prefix_bytes;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));

        let checksum_algo = checksum.as_ref().map(|(a, _)| *a);
        let expected_checksum = checksum.as_ref().and_then(|(_, v)| v.clone());
        let mut md5_hasher = Md5::new();
        let mut checksum_hasher = checksum_algo.map(ChecksumHasher::new);
        let mut plaintext_size: u64 = 0;
        let mut ct_size: u64 = 0;
        let mut chunks: Vec<ChunkInfo> = Vec::new();
        let mut chunk_index: u32 = 0;
        let mut frame_index: u64 = 0;
        let mut read_buf = vec![0u8; IO_BUFFER_SIZE];
        let mut frame_buf: Vec<u8> = Vec::with_capacity(FRAME_CHUNK_SIZE);
        let mut chunk_buf: Vec<u8> = Vec::with_capacity(self.chunk_size as usize);

        loop {
            let n = body.read(&mut read_buf).await?;
            if n == 0 {
                // Flush trailing partial frame.
                if !frame_buf.is_empty() {
                    let aad = build_frame_aad(bucket, key, version_id.as_deref(), frame_index);
                    let ct = encrypt_frame_to_vec(
                        &cipher,
                        &nonce_prefix,
                        frame_index,
                        &frame_buf,
                        &aad,
                    )?;
                    chunk_buf.extend_from_slice(&ct);
                    frame_buf.clear();
                }
                // Flush full chunks then any remainder.
                while chunk_buf.len() >= self.chunk_size as usize {
                    let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
                    ct_size += chunk_data.len() as u64;
                    let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_data).await?;
                    chunks.push(ci);
                    chunk_index += 1;
                }
                if !chunk_buf.is_empty() {
                    ct_size += chunk_buf.len() as u64;
                    let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_buf).await?;
                    chunks.push(ci);
                    chunk_buf.clear();
                }
                break;
            }
            md5_hasher.update(&read_buf[..n]);
            if let Some(ref mut ch) = checksum_hasher {
                ch.update(&read_buf[..n]);
            }
            plaintext_size += n as u64;
            self.check_object_size(plaintext_size)?;
            frame_buf.extend_from_slice(&read_buf[..n]);
            while frame_buf.len() >= FRAME_CHUNK_SIZE {
                let frame_data: Vec<u8> = frame_buf.drain(..FRAME_CHUNK_SIZE).collect();
                let aad = build_frame_aad(bucket, key, version_id.as_deref(), frame_index);
                let ct =
                    encrypt_frame_to_vec(&cipher, &nonce_prefix, frame_index, &frame_data, &aad)?;
                chunk_buf.extend_from_slice(&ct);
                frame_index += 1;
                while chunk_buf.len() >= self.chunk_size as usize {
                    let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
                    ct_size += chunk_data.len() as u64;
                    let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_data).await?;
                    chunks.push(ci);
                    chunk_index += 1;
                }
            }
        }

        // Preserve the existing EC invariant: at least one chunk on disk so the
        // manifest/chunk-reader path is consistent even for empty objects.
        if chunks.is_empty() {
            let ci = write_chunk_to_dir(&tmp_ec_dir, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;

        let has_parity = self.parity_shards > 0 && ct_size > 0;
        if has_parity {
            let parity_infos = self
                .compute_and_write_parity_in_dir(&tmp_ec_dir, &chunks)
                .await?;
            chunks.extend(parity_infos);
        }

        let manifest = ChunkManifest {
            version: if has_parity { 2 } else { 1 },
            total_size: ct_size,
            chunk_size: self.chunk_size,
            chunk_count: data_chunk_count,
            chunks,
            parity_shards: if has_parity {
                Some(self.parity_shards)
            } else {
                None
            },
            shard_size: if has_parity {
                Some(self.chunk_size)
            } else {
                None
            },
            plaintext_size: Some(plaintext_size),
        };
        write_file_atomic(
            &tmp_ec_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?.as_bytes(),
        )
        .await?;

        let etag = hex::encode(md5_hasher.finalize());
        let etag_quoted = format!("\"{}\"", etag);

        let (ck_algo, ck_val) = if let Some(algo) = checksum_algo {
            let computed = checksum_hasher.unwrap().finalize_base64();
            if let Some(expected) = expected_checksum {
                if computed != expected {
                    let _ = fs::remove_dir_all(&tmp_ec_dir).await;
                    return Err(StorageError::ChecksumMismatch(format!(
                        "expected {}, got {}",
                        expected, computed
                    )));
                }
            }
            (Some(algo), Some(computed))
        } else {
            (None, None)
        };

        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let storage_format = if has_parity {
            "chunked-v2"
        } else {
            "chunked-v1"
        };

        let mut meta = ObjectMeta {
            key: key.to_string(),
            size: plaintext_size,
            etag: etag_quoted.clone(),
            content_type: content_type.to_string(),
            last_modified: now,
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: Some(storage_format.to_string()),
            checksum_algorithm: ck_algo,
            checksum_value: ck_val.clone(),
            tags: None,
            part_sizes: None,
            encryption: Some(enc_meta),
            ..Default::default()
        };
        opts.apply_to(&mut meta);
        meta.encryption.as_mut().unwrap().sidecar_mac = String::new();
        let mac = compute_sidecar_mac(&dek, &meta)?;
        meta.encryption.as_mut().unwrap().sidecar_mac = mac;

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let tmp_meta_path = temp_sibling_path(&meta_path);
        let mut tmp_meta_guard = TempPathGuard::file(tmp_meta_path.clone());
        fs::write(&tmp_meta_path, serde_json::to_string_pretty(&meta)?).await?;

        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        self.ensure_bucket_exists(bucket).await?;
        self.check_write_precondition(bucket, key, precondition)
            .await?;
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(
                &tmp_ec_dir,
                &ec_dir,
                true,
                &tmp_meta_path,
                &meta_path,
                &self.fault,
            )
            .await
        }
        .await;
        if let Err(e) = publish_result {
            if versioned {
                self.rollback_failed_versioned_publish(bucket, key, version_id.as_deref())
                    .await;
            }
            return Err(e);
        }
        tmp_ec_guard.disarm();
        tmp_meta_guard.disarm();
        remove_plain_payload(&self.object_path(bucket, key)).await?;

        Ok(PutResult {
            size: plaintext_size,
            etag: etag_quoted,
            version_id,
            checksum_algorithm: ck_algo,
            checksum_value: ck_val,
        })
    }

    async fn compute_and_write_parity_in_dir(
        &self,
        dir: &Path,
        data_chunks: &[ChunkInfo],
    ) -> Result<Vec<ChunkInfo>, StorageError> {
        self.compute_and_write_parity_from(dir, data_chunks).await
    }

    async fn compute_and_write_parity_from(
        &self,
        dir: &Path,
        data_chunks: &[ChunkInfo],
    ) -> Result<Vec<ChunkInfo>, StorageError> {
        use reed_solomon_erasure::galois_8::ReedSolomon;

        let k = data_chunks.len();
        let m = self.parity_shards as usize;

        if k + m > 255 {
            return Err(StorageError::InvalidKey(format!(
                "too many shards: {} data + {} parity = {} > 255 (GF(2^8) limit). Increase --chunk-size",
                k,
                m,
                k + m
            )));
        }

        let shard_size = self.chunk_size as usize;
        let mut all_shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
        for ci in data_chunks {
            let path = dir.join(format!("{:06}", ci.index));
            let mut data = std::fs::read(&path).map_err(StorageError::Io)?;
            data.resize(shard_size, 0u8);
            all_shards.push(data);
        }
        for _ in 0..m {
            all_shards.push(vec![0u8; shard_size]);
        }
        let rs = ReedSolomon::new(k, m)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon init error: {e}")))?;
        rs.encode(&mut all_shards)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon encode error: {e}")))?;

        let mut parity_infos = Vec::with_capacity(m);
        for i in 0..m {
            let parity_index = k as u32 + i as u32;
            let shard = &all_shards[k + i];
            let path = dir.join(format!("{:06}", parity_index));
            parity_infos.push(
                write_chunk_file(&path, parity_index, shard)
                    .await?
                    .into_parity(),
            );
        }
        Ok(parity_infos)
    }
}

trait ChunkInfoExt {
    fn into_parity(self) -> ChunkInfo;
}

impl ChunkInfoExt for ChunkInfo {
    fn into_parity(mut self) -> ChunkInfo {
        self.kind = ChunkKind::Parity;
        self
    }
}

async fn write_chunk_to_dir(
    dir: &Path,
    index: u32,
    data: &[u8],
) -> Result<ChunkInfo, StorageError> {
    write_chunk_file(&dir.join(format!("{:06}", index)), index, data).await
}

async fn write_chunk_file(path: &Path, index: u32, data: &[u8]) -> Result<ChunkInfo, StorageError> {
    let sha256 = hex::encode(Sha256::digest(data));
    let mut file = fs::File::create(&path).await?;
    file.write_all(data).await?;
    file.sync_all().await?;
    Ok(ChunkInfo {
        index,
        size: data.len() as u64,
        sha256,
        kind: ChunkKind::Data,
    })
}

/// Payload file stored inside a key directory when that key is also a prefix.
pub(crate) const INLINE_OBJECT_PAYLOAD: &str = ".maxio.object";

/// Directory that holds a key's bytes while that key is promoted from a file
/// to a directory (`p` and `p/q` both exist). The suffix is a UUID; the
/// target file name lives in [`PROMOTE_TARGET_FILE`] so recovery does not
/// have to parse the directory name.
pub(crate) const PROMOTE_DIR_PREFIX: &str = ".maxio-promote-";

/// Single path component (the key's file name) this promote directory belongs
/// to. Written before the payload is unlinked.
pub(crate) const PROMOTE_TARGET_FILE: &str = ".maxio-promote-target";

/// Empty marker written only after the payload copy has been fsynced. Recovery
/// will not publish a promote directory that lacks it, unless the payload is
/// the original file renamed by an older build (no marker at all).
pub(crate) const PROMOTE_READY_FILE: &str = ".maxio-promote-ready";

/// Create `dir`, turning any file along the path into a directory that keeps
/// the object's bytes in `.maxio.object`. S3 keys are a flat namespace, so
/// `a/b` and `a/b/c` must both exist.
async fn ensure_dir_preserving_objects(dir: &Path) -> Result<(), StorageError> {
    let mut prefixes = Vec::new();
    let mut cur = PathBuf::new();
    for component in dir.components() {
        cur.push(component);
        prefixes.push(cur.clone());
    }
    for path in &prefixes {
        if let Ok(meta) = fs::metadata(path).await {
            if meta.is_file() {
                promote_file_to_directory(path).await?;
            }
        }
    }
    match fs::create_dir_all(dir).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists || e.raw_os_error() == Some(17) => {
            for path in &prefixes {
                if let Ok(meta) = fs::metadata(path).await {
                    if meta.is_file() {
                        promote_file_to_directory(path).await?;
                    }
                }
            }
            fs::create_dir_all(dir).await.map_err(StorageError::Io)
        }
        Err(e) => Err(StorageError::Io(e)),
    }
}

fn valid_promote_target(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && !name.contains('\n')
        && !name.contains('\r')
}

async fn duplicate_file(src: &Path, dest: &Path) -> Result<(), StorageError> {
    let src_pb = src.to_path_buf();
    let dest_pb = dest.to_path_buf();
    let linked = tokio::task::spawn_blocking(move || std::fs::hard_link(&src_pb, &dest_pb))
        .await
        .map_err(|e| {
            StorageError::Io(std::io::Error::other(format!(
                "promote hard link task failed: {e}"
            )))
        })?;
    if let Err(err) = linked {
        tracing::debug!("promote hard link failed ({err}); copying payload");
        fs::copy(src, dest).await.map_err(StorageError::Io)?;
    }
    // The directory entry (hard link) or the copied bytes must hit disk
    // before the original name is removed.
    sync_file(dest).await?;
    Ok(())
}

/// Turn the file at `path` into a directory whose bytes live in
/// `.maxio.object`, without a window where those bytes have no name.
///
/// The original file stays in place until a second copy has been fsynced and
/// a target marker names the destination. A crash before that unlink leaves
/// the original readable. A crash after it leaves `.maxio-promote-*/`, which
/// startup and `maxio check --repair` move back.
async fn promote_file_to_directory(path: &Path) -> Result<(), StorageError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Err(StorageError::Io(std::io::Error::other(
            "object path has no UTF-8 file name",
        )));
    };
    if !valid_promote_target(name) {
        return Err(StorageError::Io(std::io::Error::other(
            "object path is not a single file name",
        )));
    }

    let promote = parent.join(format!("{PROMOTE_DIR_PREFIX}{}", uuid::Uuid::new_v4()));
    fs::create_dir(&promote).await.map_err(StorageError::Io)?;
    // Armed until the copy is durable. Drop removes the directory if we fail
    // before the original name is unlinked.
    let mut guard = TempPathGuard::dir(promote.clone());

    write_file_atomic(&promote.join(PROMOTE_TARGET_FILE), name.as_bytes()).await?;
    duplicate_file(path, &promote.join(INLINE_OBJECT_PAYLOAD)).await?;
    sync_dir(&promote).await?;
    write_file_atomic(&promote.join(PROMOTE_READY_FILE), b"").await?;
    sync_dir(&promote).await?;

    // Past this point the promote directory is the crash copy. Do not let
    // the guard delete it if publishing fails.
    guard.disarm();
    if let Err(e) = fs::remove_file(path).await {
        let _ = fs::remove_dir_all(&promote).await;
        return Err(StorageError::Io(e));
    }
    sync_dir(parent).await?;
    if let Err(e) = publish_promoted(parent, &promote, name).await {
        // Bytes are only in the promote directory. Put them back at `name`
        // (or into `name/.maxio.object` if that directory now exists) so a
        // failed promote does not depend on a later restart.
        let _ = recover_promotes_in(parent, None).await;
        return Err(e);
    }
    Ok(())
}

async fn publish_promoted(parent: &Path, promote: &Path, name: &str) -> Result<(), StorageError> {
    let dest = parent.join(name);
    match fs::metadata(&dest).await {
        Ok(meta) if meta.is_dir() => {
            let inline = dest.join(INLINE_OBJECT_PAYLOAD);
            if fs::metadata(&inline)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                fs::remove_dir_all(promote)
                    .await
                    .map_err(StorageError::Io)?;
            } else {
                fs::rename(promote.join(INLINE_OBJECT_PAYLOAD), &inline)
                    .await
                    .map_err(StorageError::Io)?;
                sync_dir(&dest).await?;
                fs::remove_dir_all(promote)
                    .await
                    .map_err(StorageError::Io)?;
            }
            sync_dir(parent).await?;
        }
        Ok(meta) if meta.is_file() => {
            // A newer object landed at this name. Keep it.
            fs::remove_dir_all(promote)
                .await
                .map_err(StorageError::Io)?;
            sync_dir(parent).await?;
        }
        Ok(_) => {
            return Err(StorageError::Io(std::io::Error::other(
                "promote destination is not a file or directory",
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::rename(promote, &dest).await.map_err(StorageError::Io)?;
            sync_dir(parent).await?;
            let _ = fs::remove_file(dest.join(PROMOTE_TARGET_FILE)).await;
            let _ = fs::remove_file(dest.join(PROMOTE_READY_FILE)).await;
            let _ = sync_dir(&dest).await;
        }
        Err(e) => return Err(StorageError::Io(e)),
    }
    Ok(())
}

/// What recovery did with one `.maxio-promote-*` directory.
#[derive(Debug)]
pub(crate) struct PromoteOutcome {
    pub path: PathBuf,
    pub target: Option<String>,
    /// Bytes are reachable again and the promote directory is gone, or it
    /// held nothing worth keeping.
    pub resolved: bool,
    pub detail: String,
}

/// Restore or discard promote directories directly inside `dir`.
///
/// A `.maxio-promote-*` directory that contains no `*.meta.json` is MaxIO's
/// own crash leftover: empty directories are removed, a payload whose
/// original key is still present is removed as a duplicate, and a payload
/// whose original is missing is restored. A directory that contains a
/// sidecar is a legacy user key and is not touched.
///
/// `max_age` of `None` handles every directory (startup, `check --repair`).
/// `Some(secs)` skips a directory newer than that, so the hourly sweep cannot
/// race a promote that is still running.
pub(crate) async fn recover_promotes_in(dir: &Path, max_age: Option<u64>) -> Vec<PromoteOutcome> {
    let mut listed = match fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };
    let mut promotes = Vec::new();
    while let Ok(Some(entry)) = listed.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_promote_dir_name(&name) {
            continue;
        }
        if !matches!(entry.file_type().await, Ok(ft) if ft.is_dir()) {
            continue;
        }
        let path = entry.path();
        if !FilesystemStorage::is_stale(&path, max_age).await {
            continue;
        }
        if promote_dir_has_meta(&path).await {
            continue;
        }
        promotes.push(path);
    }

    let mut outcomes = Vec::new();
    for promote in promotes {
        outcomes.push(cleanup_promote_leftover(dir, &promote).await);
    }
    outcomes
}

/// True when `promote` contains an object sidecar anywhere inside it.
pub(crate) async fn promote_dir_has_meta(promote: &Path) -> bool {
    let mut stack = vec![promote.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut listed = match fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = listed.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".meta.json") {
                return true;
            }
            if matches!(entry.file_type().await, Ok(ft) if ft.is_dir()) {
                stack.push(entry.path());
            }
        }
    }
    false
}

/// How many legacy keys to name in a startup error or check report.
pub(crate) const LEGACY_KEY_LIST_LIMIT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyReservedKey {
    pub bucket: String,
    pub key: String,
}

/// Object keys from a pre-1.0 data directory that use a reserved path
/// segment. Detected by a real object sidecar (`*.meta.json`), not by
/// MaxIO crash leftovers (those have no sidecar).
pub(crate) async fn find_legacy_reserved_keys(buckets_dir: &Path) -> Vec<LegacyReservedKey> {
    let mut found = Vec::new();
    let mut buckets = match fs::read_dir(buckets_dir).await {
        Ok(rd) => rd,
        Err(_) => return found,
    };
    while let Ok(Some(bucket_entry)) = buckets.next_entry().await {
        if !matches!(bucket_entry.file_type().await, Ok(ft) if ft.is_dir()) {
            continue;
        }
        let bucket = bucket_entry.file_name().to_string_lossy().to_string();
        let mut stack = vec![(bucket_entry.path(), String::new())];
        while let Some((dir, rel)) = stack.pop() {
            let mut listed = match fs::read_dir(&dir).await {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            while let Ok(Some(entry)) = listed.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();
                let is_dir = matches!(entry.file_type().await, Ok(ft) if ft.is_dir());
                if is_dir {
                    let child_rel = if rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{rel}/{name}")
                    };
                    stack.push((entry.path(), child_rel));
                    continue;
                }
                if let Some(key) = object_key_for_sidecar(&rel, &name) {
                    if key_contains_reserved_segment(&key) {
                        found.push(LegacyReservedKey {
                            bucket: bucket.clone(),
                            key,
                        });
                    }
                }
            }
        }
    }
    found.sort_by(|a, b| (&a.bucket, &a.key).cmp(&(&b.bucket, &b.key)));
    found.dedup();
    found
}

/// Bucket directories whose names this version reserves (`maxio`, `ui`).
pub(crate) async fn reserved_buckets_present(buckets_dir: &Path) -> Vec<&'static str> {
    let mut found = Vec::new();
    for name in ["maxio", "ui"] {
        let path = buckets_dir.join(name);
        if matches!(tokio::fs::metadata(&path).await, Ok(meta) if meta.is_dir()) {
            found.push(name);
        }
    }
    found
}

pub(crate) fn reserved_bucket_error(names: &[&str]) -> String {
    let listed = match names {
        [name] => format!("a bucket named \"{name}\""),
        _ => {
            let quoted: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
            format!("buckets named {}", join_or(&quoted))
        }
    };
    format!(
        "refusing to start: this data directory contains {listed}, which this version of MaxIO reserves.\n\
         Start the previous MaxIO version on this data directory, move the objects out, and remove the bucket (for example `aws s3 rb`), then start this version."
    )
}

fn join_or(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [first, second] => format!("{first} or {second}"),
        _ => {
            let (last, rest) = items.split_last().unwrap();
            format!("{} or {last}", rest.join(", "))
        }
    }
}

pub(crate) fn format_legacy_reserved_error(keys: &[LegacyReservedKey]) -> String {
    let mut msg = String::from(
        "refusing to start: this data directory contains object keys that use names reserved by this version of MaxIO.\n\
         Start the previous MaxIO version on this data directory and rename or delete these keys (for example `aws s3 mv`), then start this version.",
    );
    let shown = keys.len().min(LEGACY_KEY_LIST_LIMIT);
    for key in keys.iter().take(shown) {
        msg.push_str(&format!("\n  {}/{}", key.bucket, key.key));
    }
    if keys.len() > shown {
        msg.push_str(&format!("\n  and {} more", keys.len() - shown));
    }
    msg
}

/// Map a sidecar file back to an object key. Upload metadata (`.meta.json`
/// inside an upload id directory) and version files are not object keys;
/// the object key is reconstructed for version sidecars.
fn object_key_for_sidecar(rel_dir: &str, filename: &str) -> Option<String> {
    if filename == ".meta.json" || !filename.ends_with(".meta.json") {
        return None;
    }
    let stem = filename.strip_suffix(".meta.json")?;
    if stem.is_empty() {
        return None;
    }
    let parts: Vec<&str> = rel_dir.split('/').filter(|s| !s.is_empty()).collect();
    if let Some(idx) = parts
        .iter()
        .rposition(|part| part.eq_ignore_ascii_case(".versions"))
    {
        let object_name = parts.get(idx + 1)?;
        let mut key_parts: Vec<&str> = parts[..idx].to_vec();
        key_parts.push(object_name);
        return Some(key_parts.join("/"));
    }
    if let Some(idx) = parts
        .iter()
        .rposition(|part| part.eq_ignore_ascii_case(".uploads"))
    {
        // `bucket/.uploads/{uploadId}/N.meta.json` is part metadata.
        // `bucket/.uploads/name.meta.json` would be a legacy object key.
        if idx + 1 != parts.len() {
            return None;
        }
    }
    if stem == ".folder" {
        if parts.is_empty() {
            return None;
        }
        return Some(format!("{}/", parts.join("/")));
    }
    if parts.is_empty() {
        Some(stem.to_string())
    } else {
        Some(format!("{}/{stem}", parts.join("/")))
    }
}

async fn cleanup_promote_leftover(parent: &Path, promote: &Path) -> PromoteOutcome {
    let mut has_payload = false;
    let mut only_promote_files = true;
    let mut listed = match fs::read_dir(promote).await {
        Ok(rd) => rd,
        Err(e) => {
            return promote_outcome(
                promote,
                None,
                false,
                format!("cannot read promote directory: {e}"),
            );
        }
    };
    while let Ok(Some(entry)) = listed.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = matches!(entry.file_type().await, Ok(ft) if ft.is_dir());
        if name == INLINE_OBJECT_PAYLOAD && !is_dir {
            has_payload = true;
            continue;
        }
        if !is_dir
            && (name == PROMOTE_TARGET_FILE
                || name == PROMOTE_READY_FILE
                || name.starts_with(".maxio-tmp-"))
        {
            continue;
        }
        only_promote_files = false;
    }
    if !only_promote_files {
        // No sidecar (the caller checked) but the shape is not one this
        // build writes. Leave it rather than delete an unknown tree.
        return promote_outcome(
            promote,
            None,
            false,
            "promote directory has unexpected contents and no sidecar; left untouched",
        );
    }
    if !has_payload {
        let removed = fs::remove_dir_all(promote).await.is_ok();
        let _ = sync_dir(parent).await;
        return promote_outcome(promote, None, removed, "removed empty promote directory");
    }
    if let Some(target) = read_promote_target(promote).await {
        let dest = parent.join(&target);
        let original_file = fs::metadata(&dest)
            .await
            .map(|meta| meta.is_file())
            .unwrap_or(false);
        let inline_present = fs::metadata(dest.join(INLINE_OBJECT_PAYLOAD))
            .await
            .map(|meta| meta.is_file())
            .unwrap_or(false);
        if original_file || inline_present {
            let removed = fs::remove_dir_all(promote).await.is_ok();
            let _ = sync_dir(parent).await;
            return promote_outcome(
                promote,
                Some(target),
                removed,
                "removed duplicate promote payload; original object is intact",
            );
        }
        return recover_marked_promote(parent, promote, &target).await;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata(promote.join(INLINE_OBJECT_PAYLOAD))
            .map(|meta| meta.nlink() > 1)
            .unwrap_or(false)
        {
            let removed = fs::remove_dir_all(promote).await.is_ok();
            let _ = sync_dir(parent).await;
            return promote_outcome(
                promote,
                None,
                removed,
                "removed hard-linked duplicate promote payload",
            );
        }
    }
    promote_outcome(
        promote,
        None,
        false,
        "promote payload has no target marker and is the only copy; left untouched",
    )
}

/// Promote directories in `dir` that are MaxIO leftovers (no object sidecar).
/// Does not change the disk.
pub(crate) async fn list_promotes(dir: &Path) -> Vec<(PathBuf, Option<String>)> {
    let mut listed = match fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };
    let mut found = Vec::new();
    while let Ok(Some(entry)) = listed.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_promote_dir_name(&name) {
            continue;
        }
        if !matches!(entry.file_type().await, Ok(ft) if ft.is_dir()) {
            continue;
        }
        let path = entry.path();
        if promote_dir_has_meta(&path).await {
            continue;
        }
        let target = read_promote_target(&path).await;
        found.push((path, target));
    }
    found
}

async fn read_promote_target(promote: &Path) -> Option<String> {
    let raw = fs::read(promote.join(PROMOTE_TARGET_FILE)).await.ok()?;
    let text = String::from_utf8(raw).ok()?;
    if !valid_promote_target(&text) {
        return None;
    }
    Some(text)
}

fn promote_outcome(
    path: &Path,
    target: Option<String>,
    resolved: bool,
    detail: impl Into<String>,
) -> PromoteOutcome {
    PromoteOutcome {
        path: path.to_path_buf(),
        target,
        resolved,
        detail: detail.into(),
    }
}

async fn promote_payload_ready(promote: &Path) -> bool {
    let ready = promote.join(PROMOTE_READY_FILE);
    let payload = promote.join(INLINE_OBJECT_PAYLOAD);
    fs::metadata(&ready)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
        && fs::metadata(&payload)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
}

async fn recover_marked_promote(dir: &Path, promote: &Path, target: &str) -> PromoteOutcome {
    let dest = dir.join(target);
    let original_file = fs::metadata(&dest)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false);
    let inline_present = fs::metadata(dest.join(INLINE_OBJECT_PAYLOAD))
        .await
        .map(|m| m.is_file())
        .unwrap_or(false);
    if original_file || inline_present {
        let removed = fs::remove_dir_all(promote).await.is_ok();
        let _ = sync_dir(dir).await;
        return promote_outcome(
            promote,
            Some(target.to_string()),
            removed,
            format!("original object {target} is already in place; promote directory removed"),
        );
    }
    if !promote_payload_ready(promote).await {
        return promote_outcome(
            promote,
            Some(target.to_string()),
            false,
            format!(
                "promote copy of {target} is incomplete and the original file is missing; sidecar kept"
            ),
        );
    }
    install_promote_payload(dir, promote, target).await
}

/// Move a complete `.maxio.object` out of `promote` to `target` or, when
/// `target` is already a directory, to `target/.maxio.object`.
async fn install_promote_payload(dir: &Path, promote: &Path, target: &str) -> PromoteOutcome {
    let dest = dir.join(target);
    let payload = promote.join(INLINE_OBJECT_PAYLOAD);
    let target_owned = target.to_string();
    match fs::metadata(&dest).await {
        Ok(meta) if meta.is_file() => {
            let removed = fs::remove_dir_all(promote).await.is_ok();
            let _ = sync_dir(dir).await;
            promote_outcome(
                promote,
                Some(target_owned),
                removed,
                format!("original file {target} is still present; promote directory removed"),
            )
        }
        Ok(meta) if meta.is_dir() => {
            let inline = dest.join(INLINE_OBJECT_PAYLOAD);
            if fs::metadata(&inline)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                let removed = fs::remove_dir_all(promote).await.is_ok();
                let _ = sync_dir(dir).await;
                return promote_outcome(
                    promote,
                    Some(target_owned),
                    removed,
                    format!(
                        "{target}/{INLINE_OBJECT_PAYLOAD} already exists; promote directory removed"
                    ),
                );
            }
            match fs::rename(&payload, &inline).await {
                Ok(()) => {
                    let _ = sync_dir(&dest).await;
                    let _ = fs::remove_dir_all(promote).await;
                    let _ = sync_dir(dir).await;
                    tracing::warn!("restored promote payload into {}", inline.display());
                    promote_outcome(
                        promote,
                        Some(target_owned),
                        true,
                        format!("restored payload into {target}/{INLINE_OBJECT_PAYLOAD}"),
                    )
                }
                Err(e) => promote_outcome(
                    promote,
                    Some(target_owned),
                    false,
                    format!("failed to restore payload into {}: {e}", inline.display()),
                ),
            }
        }
        Ok(_) => promote_outcome(
            promote,
            Some(target_owned),
            false,
            format!("promote destination {target} is not a file or directory"),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match fs::rename(&payload, &dest).await {
                Ok(()) => {
                    let _ = sync_dir(dir).await;
                    let _ = fs::remove_dir_all(promote).await;
                    let _ = sync_dir(dir).await;
                    tracing::warn!("restored promote payload back to {}", dest.display());
                    promote_outcome(
                        promote,
                        Some(target_owned),
                        true,
                        format!("restored payload back to {target}"),
                    )
                }
                Err(e) => promote_outcome(
                    promote,
                    Some(target_owned),
                    false,
                    format!("failed to restore payload to {}: {e}", dest.display()),
                ),
            }
        }
        Err(e) => promote_outcome(
            promote,
            Some(target_owned),
            false,
            format!("cannot stat promote destination {target}: {e}"),
        ),
    }
}

/// Remove a plain object payload. A directory that also holds child keys is
/// left in place; only `.maxio.object` is deleted.
async fn remove_plain_payload(path: &Path) -> Result<(), StorageError> {
    match fs::remove_file(path.join(INLINE_OBJECT_PAYLOAD)).await {
        Ok(()) => {}
        // NotFound: no inline payload. NotADirectory: `path` is a normal file,
        // so `{path}/.maxio.object` cannot exist.
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::NotADirectory => {}
        Err(e) => return Err(StorageError::Io(e)),
    }
    match fs::metadata(path).await {
        Ok(meta) if meta.is_file() => remove_file_if_exists(path).await?,
        Ok(meta) if meta.is_dir() => {
            let _ = fs::remove_dir(path).await;
        }
        _ => {}
    }
    Ok(())
}

fn temp_sibling_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".maxio-tmp-{}", uuid::Uuid::new_v4()))
}

/// Sibling backup path for `path` during a directory publish. The original
/// file name is embedded so housekeeping can restore an orphaned backup after
/// a crash (see `sweep_backup_files`).
fn backup_sibling_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    parent.join(format!(".maxio-bak-{}", name))
}

/// Best-effort: set `path`'s mtime to now. Used to stamp publish backups so
/// housekeeping's staleness gate works even though rename preserves mtime.
async fn touch_now(path: &Path) {
    let path = path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || {
        let times = std::fs::FileTimes::new().set_modified(std::time::SystemTime::now());
        std::fs::File::open(&path).and_then(|f| f.set_times(times))
    })
    .await;
    match res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("failed to touch backup mtime: {}", e),
        Err(e) => tracing::warn!("touch task failed: {}", e),
    }
}

/// Fsync an already-written file so its bytes are on stable storage before the
/// rename that publishes it. Without this, a power loss after the rename can
/// leave a zero-length or truncated file behind a successful response.
async fn sync_file(path: &Path) -> Result<(), StorageError> {
    let f = fs::File::open(path).await?;
    f.sync_all().await?;
    Ok(())
}

/// Fsync `dir` so its directory entries (renames, creates, unlinks) are on
/// stable storage. A failure is returned: the bytes may be durable while the
/// name that points at them is not.
async fn sync_dir(dir: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        if dir.as_os_str().is_empty() {
            return Ok(());
        }
        let dir = dir.to_path_buf();
        tokio::task::spawn_blocking(move || std::fs::File::open(&dir).and_then(|f| f.sync_all()))
            .await
            .map_err(|e| {
                StorageError::Io(std::io::Error::other(format!(
                    "directory fsync task failed: {e}"
                )))
            })?
            .map_err(StorageError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Fsync the parent directory of `path` so a completed rename itself survives
/// power loss.
async fn sync_parent_dir(path: &Path) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        sync_dir(parent).await?;
    }
    Ok(())
}

/// Durable atomic write for small metadata files (sidecars, `.bucket.json`,
/// version metadata, part metadata): temp sibling → fsync → rename over the
/// final path → parent-dir fsync. Readers see either the old or the new
/// complete file, never a torn one, and the result survives power loss.
pub(crate) async fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let tmp = temp_sibling_path(path);
    let mut guard = TempPathGuard::file(tmp.clone());
    let mut f = fs::File::create(&tmp).await?;
    f.write_all(bytes).await?;
    f.sync_all().await?;
    drop(f);
    fs::rename(&tmp, path).await?;
    guard.disarm();
    sync_parent_dir(path).await?;
    Ok(())
}

struct TempPathGuard {
    path: PathBuf,
    is_dir: bool,
    armed: bool,
}

impl TempPathGuard {
    fn file(path: PathBuf) -> Self {
        Self {
            path,
            is_dir: false,
            armed: true,
        }
    }

    fn dir(path: PathBuf) -> Self {
        Self {
            path,
            is_dir: true,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if self.armed {
            if self.is_dir {
                let _ = std::fs::remove_dir_all(&self.path);
            } else {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

async fn publish_temp_payload_and_meta(
    tmp_payload: &Path,
    final_payload: &Path,
    payload_is_dir: bool,
    tmp_meta: &Path,
    final_meta: &Path,
    fault: &AtomicU8,
) -> Result<(), StorageError> {
    if let Some(parent) = final_payload.parent() {
        fs::create_dir_all(parent).await?;
    }
    if let Some(parent) = final_meta.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Make the new bytes durable BEFORE they become visible. Directory
    // payloads (EC) are synced chunk-by-chunk at write time; the directory
    // entry itself still needs an fsync or a crash can publish a dir whose
    // chunk names never hit disk.
    if payload_is_dir {
        sync_dir(tmp_payload).await?;
    } else {
        sync_file(tmp_payload).await?;
    }
    sync_file(tmp_meta).await?;

    if consume_fault(fault, FAULT_BEFORE_PAYLOAD_RENAME) {
        return Err(StorageError::Io(std::io::Error::other(
            "injected fault before payload rename",
        )));
    }

    if payload_is_dir {
        // rename(2) cannot replace a non-empty directory, so the old EC dir is
        // moved aside first — under a name that encodes the original, so
        // housekeeping can restore it if a crash strands the publish here.
        let backup = if fs::try_exists(final_payload).await? {
            let b = backup_sibling_path(final_payload);
            remove_path_if_exists(&b, true).await;
            fs::rename(final_payload, &b).await?;
            // rename preserves the old dir's mtime; stamp the backup with NOW
            // so housekeeping's age gate measures time-since-publish-started,
            // not object age — otherwise the sweep could grab a live backup.
            touch_now(&b).await;
            Some(b)
        } else {
            None
        };
        if let Err(e) = fs::rename(tmp_payload, final_payload).await {
            restore_backup(final_payload, &backup, true).await;
            return Err(StorageError::Io(e));
        }
        if consume_fault(fault, FAULT_AFTER_PAYLOAD_RENAME) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected fault after payload rename",
            )));
        }
        if let Err(e) = fs::rename(tmp_meta, final_meta).await {
            remove_path_if_exists(final_payload, true).await;
            restore_backup(final_payload, &backup, true).await;
            return Err(StorageError::Io(e));
        }
        cleanup_backup(&backup, true).await;
    } else {
        // Plain files: rename atomically replaces the destination, so the old
        // object is never moved aside and can never be lost mid-publish.
        fs::rename(tmp_payload, final_payload).await?;
        if consume_fault(fault, FAULT_AFTER_PAYLOAD_RENAME) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected fault after payload rename",
            )));
        }
        if let Err(e) = fs::rename(tmp_meta, final_meta).await {
            // Same-directory rename only fails if the filesystem itself is
            // failing. The payload replace cannot be undone at this point, so
            // surface the torn data/sidecar state loudly.
            tracing::error!(
                "sidecar rename failed AFTER payload publish for {}: data and metadata are out of sync",
                final_payload.display()
            );
            return Err(StorageError::Io(e));
        }
    }

    sync_parent_dir(final_payload).await?;
    if final_meta.parent() != final_payload.parent() {
        sync_parent_dir(final_meta).await?;
    }
    Ok(())
}

async fn restore_backup(final_path: &Path, backup: &Option<PathBuf>, is_dir: bool) {
    if let Some(backup) = backup {
        remove_path_if_exists(final_path, is_dir).await;
        let _ = fs::rename(backup, final_path).await;
    }
}

async fn cleanup_backup(backup: &Option<PathBuf>, is_dir: bool) {
    if let Some(backup) = backup {
        remove_path_if_exists(backup, is_dir).await;
    }
}

async fn remove_path_if_exists(path: &Path, is_dir: bool) {
    if is_dir {
        let _ = fs::remove_dir_all(path).await;
    } else {
        let _ = fs::remove_file(path).await;
    }
}

impl FilesystemStorage {
    async fn complete_multipart_chunked(
        &self,
        bucket: &str,
        upload_id: &str,
        upload_meta: &MultipartUploadMeta,
        selected: &[PartMeta],
        precondition: Option<&WritePrecondition>,
    ) -> Result<PutResult, StorageError> {
        let key = &upload_meta.key;
        let ec_dir = self.ec_dir(bucket, key);
        let tmp_ec_dir = temp_sibling_path(&ec_dir);
        let mut tmp_ec_guard = TempPathGuard::dir(tmp_ec_dir.clone());
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::create_dir_all(&tmp_ec_dir).await?;
        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        let mut total_size = 0u64;
        let mut etag_hasher = Md5::new();
        let mut chunks: Vec<ChunkInfo> = Vec::new();
        let mut chunk_index: u32 = 0;
        let mut chunk_buf = Vec::with_capacity(self.chunk_size as usize);

        let mut buf = vec![0u8; IO_BUFFER_SIZE];
        for part in selected {
            let mut part_file =
                fs::File::open(self.part_path(bucket, upload_id, part.part_number)).await?;
            let mut part_md5 = Md5::new();
            let mut part_bytes: u64 = 0;
            loop {
                let n = part_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                part_md5.update(&buf[..n]);
                part_bytes += n as u64;
                total_size += n as u64;
                chunk_buf.extend_from_slice(&buf[..n]);

                while chunk_buf.len() >= self.chunk_size as usize {
                    let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
                    let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_data).await?;
                    chunks.push(ci);
                    chunk_index += 1;
                }
            }
            verify_part_bytes(part, part_bytes, part_md5)?;

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }

        // Flush remaining
        if !chunk_buf.is_empty() {
            let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_buf).await?;
            chunks.push(ci);
        }

        if chunks.is_empty() {
            let ci = write_chunk_to_dir(&tmp_ec_dir, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;

        // Compute and write parity shards if configured (skip for empty objects)
        let has_parity = self.parity_shards > 0 && total_size > 0;
        if has_parity {
            let parity_infos = self
                .compute_and_write_parity_in_dir(&tmp_ec_dir, &chunks)
                .await?;
            chunks.extend(parity_infos);
        }

        let manifest = ChunkManifest {
            version: if has_parity { 2 } else { 1 },
            total_size,
            chunk_size: self.chunk_size,
            chunk_count: data_chunk_count,
            chunks,
            parity_shards: if has_parity {
                Some(self.parity_shards)
            } else {
                None
            },
            shard_size: if has_parity {
                Some(self.chunk_size)
            } else {
                None
            },
            plaintext_size: None,
        };
        write_file_atomic(
            &tmp_ec_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?.as_bytes(),
        )
        .await?;

        let etag = format!(
            "\"{}-{}\"",
            hex::encode(etag_hasher.finalize()),
            selected.len()
        );

        // Compute composite checksum if algorithm was specified
        let (checksum_algorithm, checksum_value) =
            if let Some(algo) = upload_meta.checksum_algorithm {
                let b64 = base64::engine::general_purpose::STANDARD;
                let mut raw_checksums = Vec::new();
                for part in selected {
                    if let Some(ref val) = part.checksum_value {
                        if let Ok(raw) = b64.decode(val) {
                            raw_checksums.extend_from_slice(&raw);
                        }
                    }
                }
                if !raw_checksums.is_empty() {
                    let mut composite_hasher = ChecksumHasher::new(algo);
                    composite_hasher.update(&raw_checksums);
                    let composite =
                        format!("{}-{}", composite_hasher.finalize_base64(), selected.len());
                    (Some(algo), Some(composite))
                } else {
                    (Some(algo), None)
                }
            } else {
                (None, None)
            };

        let part_sizes: Vec<u64> = selected.iter().map(|p| p.size).collect();
        let storage_format = if has_parity {
            "chunked-v2"
        } else {
            "chunked-v1"
        };
        let mut object_meta = ObjectMeta {
            key: key.to_string(),
            size: total_size,
            etag: etag.clone(),
            content_type: upload_meta.content_type.clone(),
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: Some(storage_format.to_string()),
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
            tags: None,
            part_sizes: Some(part_sizes),
            encryption: None,
            ..Default::default()
        };
        apply_upload_metadata(upload_meta, &mut object_meta);

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let tmp_meta_path = temp_sibling_path(&meta_path);
        let mut tmp_meta_guard = TempPathGuard::file(tmp_meta_path.clone());
        fs::write(&tmp_meta_path, serde_json::to_string_pretty(&object_meta)?).await?;
        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        self.ensure_bucket_exists(bucket).await?;
        self.check_write_precondition(bucket, key, precondition)
            .await?;
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &object_meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(
                &tmp_ec_dir,
                &ec_dir,
                true,
                &tmp_meta_path,
                &meta_path,
                &self.fault,
            )
            .await
        }
        .await;
        if let Err(e) = publish_result {
            if versioned {
                self.rollback_failed_versioned_publish(bucket, key, version_id.as_deref())
                    .await;
            }
            return Err(e);
        }
        tmp_ec_guard.disarm();
        tmp_meta_guard.disarm();
        remove_plain_payload(&self.object_path(bucket, key)).await?;
        drop(_key_guard);
        drop(_bucket_guard);
        // Best-effort: the object is already durably published. A racing
        // Abort/housekeeping may have removed the upload dir — that must not
        // turn a successful complete into an error.
        if let Err(e) = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("failed to clean up upload dir {}: {}", upload_id, e);
            }
        }

        Ok(PutResult {
            size: total_size,
            etag,
            version_id,
            checksum_algorithm,
            checksum_value,
        })
    }

    /// Encrypt-then-EC multipart completion. Reads each part with the
    /// upload-scoped DEK (per `upload_meta.encryption_spec`), re-encrypts the
    /// recombined stream under a fresh per-object DEK using 64 KiB frames,
    /// chunks the ciphertext into EC chunks, writes parity.
    async fn complete_multipart_chunked_encrypted(
        &self,
        bucket: &str,
        upload_id: &str,
        upload_meta: &MultipartUploadMeta,
        selected: &[PartMeta],
        customer_key: Option<[u8; 32]>,
        precondition: Option<&WritePrecondition>,
    ) -> Result<PutResult, StorageError> {
        let key = upload_meta.key.as_str();
        let ec_dir = self.ec_dir(bucket, key);
        let tmp_ec_dir = temp_sibling_path(&ec_dir);
        let mut tmp_ec_guard = TempPathGuard::dir(tmp_ec_dir.clone());
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::create_dir_all(&tmp_ec_dir).await?;
        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        // Upload-scoped DEK used to decrypt each part on read.
        let upload_spec = upload_meta
            .encryption_spec
            .as_ref()
            .expect("complete_multipart_chunked_encrypted called without encryption_spec");
        let upload_dek = self.resolve_upload_dek(upload_spec, customer_key)?;

        // Fresh per-object encryption (distinct DEK from the upload DEK).
        let req = match upload_spec.mode {
            EncryptionMode::SseS3 => EncryptionRequest::sse_s3(),
            EncryptionMode::SseC => {
                let ck = customer_key.ok_or_else(|| {
                    StorageError::EncryptionError(
                        "SSE-C requires customer key on CompleteMultipartUpload".into(),
                    )
                })?;
                EncryptionRequest::sse_c(ck)
            }
        };
        let enc_meta = self
            .prepare_encryption(&req)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        let dek = self
            .resolve_dek(&enc_meta, customer_key)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let prefix_bytes = b64
            .decode(&enc_meta.nonce_prefix)
            .map_err(|_| StorageError::EncryptionError("invalid nonce_prefix".into()))?;
        let nonce_prefix = prefix_bytes;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));

        let mut total_plaintext: u64 = 0;
        let mut ct_size: u64 = 0;
        let mut etag_hasher = Md5::new();
        let mut chunks: Vec<ChunkInfo> = Vec::new();
        let mut chunk_index: u32 = 0;
        let mut frame_index: u64 = 0;
        let mut read_buf = vec![0u8; IO_BUFFER_SIZE];
        let mut frame_buf: Vec<u8> = Vec::with_capacity(FRAME_CHUNK_SIZE);
        let mut chunk_buf: Vec<u8> = Vec::with_capacity(self.chunk_size as usize);

        for part in selected {
            let part_path = self.part_path(bucket, upload_id, part.part_number);
            let mut part_stream: ByteStream = if part.encrypted {
                let file = fs::File::open(&part_path).await?;
                let aad = part_aad_builder(upload_id, part.part_number);
                Box::pin(FrameDecryptor::new(
                    Box::pin(file),
                    &upload_dek,
                    part.size,
                    FRAME_CHUNK_SIZE,
                    aad,
                ))
            } else {
                Box::pin(fs::File::open(&part_path).await?)
            };

            let mut part_md5 = Md5::new();
            let mut part_bytes: u64 = 0;
            loop {
                let n = part_stream.read(&mut read_buf).await?;
                if n == 0 {
                    break;
                }
                part_md5.update(&read_buf[..n]);
                part_bytes += n as u64;
                total_plaintext += n as u64;
                frame_buf.extend_from_slice(&read_buf[..n]);
                while frame_buf.len() >= FRAME_CHUNK_SIZE {
                    let frame_data: Vec<u8> = frame_buf.drain(..FRAME_CHUNK_SIZE).collect();
                    let aad = build_frame_aad(bucket, key, version_id.as_deref(), frame_index);
                    let ct = encrypt_frame_to_vec(
                        &cipher,
                        &nonce_prefix,
                        frame_index,
                        &frame_data,
                        &aad,
                    )?;
                    chunk_buf.extend_from_slice(&ct);
                    frame_index += 1;
                    while chunk_buf.len() >= self.chunk_size as usize {
                        let chunk_data: Vec<u8> =
                            chunk_buf.drain(..self.chunk_size as usize).collect();
                        ct_size += chunk_data.len() as u64;
                        let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_data).await?;
                        chunks.push(ci);
                        chunk_index += 1;
                    }
                }
            }
            verify_part_bytes(part, part_bytes, part_md5)?;

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }

        // Flush trailing partial frame + any remaining chunk_buf bytes.
        if !frame_buf.is_empty() {
            let aad = build_frame_aad(bucket, key, version_id.as_deref(), frame_index);
            let ct = encrypt_frame_to_vec(&cipher, &nonce_prefix, frame_index, &frame_buf, &aad)?;
            chunk_buf.extend_from_slice(&ct);
            frame_buf.clear();
        }
        while chunk_buf.len() >= self.chunk_size as usize {
            let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
            ct_size += chunk_data.len() as u64;
            let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_data).await?;
            chunks.push(ci);
            chunk_index += 1;
        }
        if !chunk_buf.is_empty() {
            ct_size += chunk_buf.len() as u64;
            let ci = write_chunk_to_dir(&tmp_ec_dir, chunk_index, &chunk_buf).await?;
            chunks.push(ci);
            chunk_buf.clear();
        }

        if chunks.is_empty() {
            let ci = write_chunk_to_dir(&tmp_ec_dir, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;
        let has_parity = self.parity_shards > 0 && ct_size > 0;
        if has_parity {
            let parity_infos = self
                .compute_and_write_parity_in_dir(&tmp_ec_dir, &chunks)
                .await?;
            chunks.extend(parity_infos);
        }

        let manifest = ChunkManifest {
            version: if has_parity { 2 } else { 1 },
            total_size: ct_size,
            chunk_size: self.chunk_size,
            chunk_count: data_chunk_count,
            chunks,
            parity_shards: if has_parity {
                Some(self.parity_shards)
            } else {
                None
            },
            shard_size: if has_parity {
                Some(self.chunk_size)
            } else {
                None
            },
            plaintext_size: Some(total_plaintext),
        };
        write_file_atomic(
            &tmp_ec_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?.as_bytes(),
        )
        .await?;

        let etag = format!(
            "\"{}-{}\"",
            hex::encode(etag_hasher.finalize()),
            selected.len()
        );

        let (checksum_algorithm, checksum_value) =
            if let Some(algo) = upload_meta.checksum_algorithm {
                let mut raw_checksums = Vec::new();
                for part in selected {
                    if let Some(ref val) = part.checksum_value {
                        if let Ok(raw) = b64.decode(val) {
                            raw_checksums.extend_from_slice(&raw);
                        }
                    }
                }
                if !raw_checksums.is_empty() {
                    let mut composite_hasher = ChecksumHasher::new(algo);
                    composite_hasher.update(&raw_checksums);
                    let composite =
                        format!("{}-{}", composite_hasher.finalize_base64(), selected.len());
                    (Some(algo), Some(composite))
                } else {
                    (Some(algo), None)
                }
            } else {
                (None, None)
            };

        let part_sizes: Vec<u64> = selected.iter().map(|p| p.size).collect();
        let storage_format = if has_parity {
            "chunked-v2"
        } else {
            "chunked-v1"
        };
        let mut object_meta = ObjectMeta {
            key: key.to_string(),
            size: total_plaintext,
            etag: etag.clone(),
            content_type: upload_meta.content_type.clone(),
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: Some(storage_format.to_string()),
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
            tags: None,
            part_sizes: Some(part_sizes),
            encryption: Some(enc_meta),
            ..Default::default()
        };
        apply_upload_metadata(upload_meta, &mut object_meta);
        object_meta.encryption.as_mut().unwrap().sidecar_mac = String::new();
        let mac = compute_sidecar_mac(&dek, &object_meta)?;
        object_meta.encryption.as_mut().unwrap().sidecar_mac = mac;

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let tmp_meta_path = temp_sibling_path(&meta_path);
        let mut tmp_meta_guard = TempPathGuard::file(tmp_meta_path.clone());
        fs::write(&tmp_meta_path, serde_json::to_string_pretty(&object_meta)?).await?;
        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        self.ensure_bucket_exists(bucket).await?;
        self.check_write_precondition(bucket, key, precondition)
            .await?;
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &object_meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(
                &tmp_ec_dir,
                &ec_dir,
                true,
                &tmp_meta_path,
                &meta_path,
                &self.fault,
            )
            .await
        }
        .await;
        if let Err(e) = publish_result {
            if versioned {
                self.rollback_failed_versioned_publish(bucket, key, version_id.as_deref())
                    .await;
            }
            return Err(e);
        }
        tmp_ec_guard.disarm();
        tmp_meta_guard.disarm();
        remove_plain_payload(&self.object_path(bucket, key)).await?;
        drop(_key_guard);
        drop(_bucket_guard);
        // Best-effort: the object is already durably published. A racing
        // Abort/housekeeping may have removed the upload dir — that must not
        // turn a successful complete into an error.
        if let Err(e) = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("failed to clean up upload dir {}: {}", upload_id, e);
            }
        }

        Ok(PutResult {
            size: total_plaintext,
            etag,
            version_id,
            checksum_algorithm,
            checksum_value,
        })
    }

    async fn put_folder_marker(
        &self,
        bucket: &str,
        key: &str,
        opts: &PutOptions,
    ) -> Result<PutResult, StorageError> {
        let _key_guard = self.key_lock(bucket, key).await;
        self.check_write_precondition(bucket, key, opts.precondition.as_ref())
            .await?;
        let folder_dir = self
            .buckets_dir
            .join(bucket)
            .join(key.trim_end_matches('/'));
        ensure_dir_preserving_objects(&folder_dir).await?;

        let marker_path = folder_dir.join(".folder");
        write_file_atomic(&marker_path, b"").await?;

        let etag = "\"d41d8cd98f00b204e9800998ecf8427e\"".to_string();
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let mut meta = ObjectMeta {
            key: key.to_string(),
            size: 0,
            etag: etag.clone(),
            content_type: "application/x-directory".to_string(),
            last_modified: now,
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
            tags: None,
            part_sizes: None,
            encryption: None,
            ..Default::default()
        };
        opts.apply_to(&mut meta);

        let meta_path = folder_dir.join(".folder.meta.json");
        let json = serde_json::to_string_pretty(&meta)?;
        write_file_atomic(&meta_path, json.as_bytes()).await?;

        Ok(PutResult {
            size: 0,
            etag,
            version_id: None,
            checksum_algorithm: None,
            checksum_value: None,
        })
    }

    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        customer_key: Option<[u8; 32]>,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        // Hold the key lock across the sidecar read + data-file open so the
        // meta and the opened fd always describe the same object generation.
        // The lock is released when this method returns; streaming continues
        // on the already-open handle.
        let _key_guard = self.key_lock(bucket, key).await;
        let meta = self.read_object_meta(bucket, key).await?;
        reject_sse_c_on_plaintext(&meta, customer_key.is_some())?;
        let ec_dir = self.ec_dir(bucket, key);
        if Self::is_chunked_path(&ec_dir).await {
            let manifest = self.read_manifest(bucket, key).await?;
            if let Some(ref enc_meta) = meta.encryption {
                let dek = self.resolve_dek(enc_meta, customer_key)?;
                verify_sidecar_mac(&meta, &dek)?;
                let frame_size = enc_meta.chunk_size as usize;
                let plaintext_size = meta.size;
                let aad_builder = object_aad_builder(bucket, key, meta.version_id.as_deref());
                let ct_reader = VerifiedChunkReader::new(ec_dir, manifest);
                let decryptor = FrameDecryptor::new(
                    Box::pin(ct_reader),
                    &dek,
                    plaintext_size,
                    frame_size,
                    aad_builder,
                );
                return Ok((Box::pin(decryptor), meta));
            }
            let reader = VerifiedChunkReader::new(ec_dir, manifest);
            return Ok((Box::pin(reader), meta));
        }
        let obj_path = self.plain_object_read_path(bucket, key).await;
        // Encrypted object — wrap in FrameDecryptor
        if let Some(ref enc_meta) = meta.encryption {
            let dek = self.resolve_dek(enc_meta, customer_key)?;
            verify_sidecar_mac(&meta, &dek)?;
            let chunk_size = enc_meta.chunk_size as usize;
            let plaintext_size = meta.size;
            let file = fs::File::open(&obj_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound(key.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            let aad_builder = object_aad_builder(bucket, key, meta.version_id.as_deref());
            let decryptor = FrameDecryptor::new(
                Box::pin(file),
                &dek,
                plaintext_size,
                chunk_size,
                aad_builder,
            );
            return Ok((Box::pin(decryptor), meta));
        }
        if meta.size <= SMALL_OBJECT_THRESHOLD {
            let data = fs::read(&obj_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound(key.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            return Ok((Box::pin(std::io::Cursor::new(data)), meta));
        }
        let file = fs::File::open(&obj_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
        Ok((Box::pin(reader), meta))
    }

    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        offset: u64,
        length: u64,
        customer_key: Option<[u8; 32]>,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        // Hold the key lock across the sidecar read + data-file open so the
        // meta and the opened fd always describe the same object generation.
        // The lock is released when this method returns; streaming continues
        // on the already-open handle.
        let _key_guard = self.key_lock(bucket, key).await;
        let meta = self.read_object_meta(bucket, key).await?;
        reject_sse_c_on_plaintext(&meta, customer_key.is_some())?;
        let ec_dir = self.ec_dir(bucket, key);
        let obj_path = self.plain_object_read_path(bucket, key).await;
        self.open_range_reader(
            bucket,
            key,
            meta,
            ec_dir,
            &obj_path,
            offset,
            length,
            customer_key,
        )
        .await
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        Ok(meta)
    }

    pub async fn get_object_tagging(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<std::collections::HashMap<String, String>, StorageError> {
        validate_readable_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        Ok(meta.tags.unwrap_or_default())
    }

    pub async fn put_object_tagging(
        &self,
        bucket: &str,
        key: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<(), StorageError> {
        validate_key(key)?;
        // Key lock: the sidecar rewrite must not interleave with a concurrent
        // PUT/DELETE of the same key (stale-meta writeback would detach the
        // sidecar from the data — fatal for encrypted objects).
        let _key_guard = self.key_lock(bucket, key).await;
        let mut meta = self.read_object_meta(bucket, key).await?;
        meta.tags = if tags.is_empty() { None } else { Some(tags) };
        let json = serde_json::to_string_pretty(&meta)?;
        write_file_atomic(&self.meta_path(bucket, key), json.as_bytes()).await?;
        Ok(())
    }

    pub async fn delete_object_tagging(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        validate_key(key)?;
        let _key_guard = self.key_lock(bucket, key).await;
        let mut meta = self.read_object_meta(bucket, key).await?;
        meta.tags = None;
        let json = serde_json::to_string_pretty(&meta)?;
        write_file_atomic(&self.meta_path(bucket, key), json.as_bytes()).await?;
        Ok(())
    }

    /// Replace the tag set of one specific version. When that version is
    /// also the current object, the live sidecar is updated too so both
    /// views agree. Delete markers have no tags (`NotFound`).
    pub async fn put_object_version_tagging(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<(), StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
        validate_version_id(version_id)?;
        let _key_guard = self.key_lock(bucket, key).await;
        let new_tags = if tags.is_empty() { None } else { Some(tags) };

        let ver_path = self.version_meta_path(bucket, key, version_id);
        let mut found = false;
        if fs::try_exists(&ver_path).await? {
            let mut meta: ObjectMeta = serde_json::from_str(&fs::read_to_string(&ver_path).await?)?;
            if meta.is_delete_marker {
                return Err(StorageError::NotFound(key.to_string()));
            }
            meta.tags = new_tags.clone();
            write_file_atomic(&ver_path, serde_json::to_string_pretty(&meta)?.as_bytes()).await?;
            found = true;
        }

        match self.read_object_meta(bucket, key).await {
            Ok(mut current)
                if !current.is_delete_marker
                    && current.version_id.as_deref().unwrap_or("null") == version_id =>
            {
                current.tags = new_tags;
                write_file_atomic(
                    &self.meta_path(bucket, key),
                    serde_json::to_string_pretty(&current)?.as_bytes(),
                )
                .await?;
                found = true;
            }
            Ok(_) | Err(StorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }

        if found {
            Ok(())
        } else {
            Err(StorageError::VersionNotFound(version_id.to_string()))
        }
    }

    pub async fn delete_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;

        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        self.delete_object_locked(bucket, key).await
    }

    /// Lifecycle expiration of the current version: delete `key` exactly like
    /// `delete_object` (delete marker when versioned), but only if the
    /// current version is still the one identified by `version_id` +
    /// `last_modified` and is not a delete marker. The check and the delete
    /// happen under the key lock, so a concurrent overwrite is never expired.
    /// Returns `None` when the precondition did not hold.
    pub async fn delete_object_if_current(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        last_modified: &str,
    ) -> Result<Option<DeleteResult>, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        match self.read_object_meta(bucket, key).await {
            Ok(m)
                if !m.is_delete_marker
                    && m.version_id.as_deref() == version_id
                    && m.last_modified == last_modified => {}
            Ok(_) | Err(StorageError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        }
        self.delete_object_locked(bucket, key).await.map(Some)
    }

    /// Body of `delete_object`. Caller must hold the bucket read guard and
    /// the key lock.
    async fn delete_object_locked(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
        let versioned = self.is_versioned(bucket).await?;
        if versioned {
            return self.write_delete_marker(bucket, key).await;
        }

        let obj_path = self.object_path(bucket, key);
        let meta_path = self.meta_path(bucket, key);
        let ec_dir = self.ec_dir(bucket, key);

        if !fs::try_exists(&meta_path).await?
            && !fs::try_exists(&obj_path).await?
            && !fs::try_exists(&ec_dir).await?
        {
            return Ok(DeleteResult {
                version_id: None,
                is_delete_marker: false,
            });
        }
        remove_plain_payload(&obj_path).await?;
        remove_file_if_exists(&meta_path).await?;
        remove_dir_all_if_exists(&ec_dir).await?;

        // Clean up empty parent directories (but not the bucket dir itself)
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut dir = obj_path.parent().map(|p| p.to_path_buf());
        while let Some(d) = dir {
            if d == bucket_dir {
                break;
            }
            match fs::remove_dir(&d).await {
                Ok(()) => {}
                Err(_) => break,
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }

        Ok(DeleteResult {
            version_id: None,
            is_delete_marker: false,
        })
    }

    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_bucket_name(bucket)?;
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut results = Vec::new();
        self.walk_dir(&bucket_dir, &bucket_dir, prefix, &mut results)
            .await?;
        results.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(results)
    }

    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        checksum_algorithm: Option<ChecksumAlgorithm>,
        encryption_spec: Option<UploadEncryptionSpec>,
        object_metadata: StoredObjectMetadata,
        tags: Option<HashMap<String, String>>,
    ) -> Result<MultipartUploadMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
        let upload_id = uuid::Uuid::new_v4().to_string();
        let upload_dir = self.upload_dir(bucket, &upload_id);
        fs::create_dir_all(&upload_dir).await?;

        // Augment the spec with an upload-scoped DEK so every UploadPart can
        // encrypt its bytes before they touch disk. SSE-C reuses the customer
        // key directly (never persisted); SSE-S3 wraps a fresh random DEK with
        // the active master.
        let encryption_spec = if let Some(mut spec) = encryption_spec {
            let b64 = base64::engine::general_purpose::STANDARD;
            let prefix = Keyring::generate_nonce_prefix8();
            spec.upload_nonce_prefix = b64.encode(prefix);
            if matches!(spec.mode, EncryptionMode::SseS3) {
                let dek = Keyring::generate_dek();
                let kid = self.keyring.active_id().to_string();
                let (wrapped, wrap_nonce) = self
                    .keyring
                    .wrap_dek(&kid, &dek)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
                spec.upload_dek_wrapped = Some(b64.encode(&wrapped));
                spec.upload_dek_wrap_nonce = Some(b64.encode(wrap_nonce));
                spec.upload_dek_key_id = Some(kid);
            }
            Some(spec)
        } else {
            None
        };

        let meta = MultipartUploadMeta {
            upload_id: upload_id.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_type: content_type.to_string(),
            initiated: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            checksum_algorithm,
            encryption_spec,
            object_metadata,
            tags: tags.filter(|t| !t.is_empty()),
        };

        let meta_json = serde_json::to_string_pretty(&meta)?;
        write_file_atomic(
            &self.upload_meta_path(bucket, &upload_id),
            meta_json.as_bytes(),
        )
        .await?;
        Ok(meta)
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        mut body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
        customer_key: Option<[u8; 32]>,
    ) -> Result<PartMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_upload_id(upload_id)?;
        if part_number == 0 || part_number > 10_000 {
            return Err(StorageError::InvalidKey(
                "part number must be 1..=10000".into(),
            ));
        }
        let upload_dir = self.upload_dir(bucket, upload_id);
        if !fs::try_exists(&upload_dir).await? {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let upload_meta = self.read_upload_meta(bucket, upload_id).await?;
        validate_key(&upload_meta.key)?;
        let (cipher_opt, nonce_prefix) = if let Some(ref spec) = upload_meta.encryption_spec {
            let dek = self.resolve_upload_dek(spec, customer_key)?;
            // Fresh random prefix PER UploadPart attempt: all parts share the
            // upload DEK, so reusing one prefix across parts (or across
            // retries of the same part number) would reuse AES-GCM nonces —
            // a fatal keystream/auth-key leak. The decryptor reads each nonce
            // from the frame header and validates only the frame index, so no
            // metadata needs to carry this prefix.
            let prefix_bytes = Keyring::generate_nonce_prefix8().to_vec();
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
            (Some(cipher), prefix_bytes)
        } else {
            (None, Vec::new())
        };

        let part_path = self.part_path(bucket, upload_id, part_number);
        let tmp_part_path = temp_sibling_path(&part_path);
        let mut tmp_part_guard = TempPathGuard::file(tmp_part_path.clone());
        let file = fs::File::create(&tmp_part_path).await?;
        let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, file);
        let mut hasher = Md5::new();
        let mut checksum_hasher = checksum
            .as_ref()
            .map(|(algo, _)| ChecksumHasher::new(*algo));
        let mut size: u64 = 0;
        let mut buf = vec![0u8; IO_BUFFER_SIZE];
        let mut frame_buf: Vec<u8> = Vec::with_capacity(FRAME_CHUNK_SIZE);
        let mut chunk_index: u64 = 0;

        loop {
            let n = body.read(&mut buf).await?;
            if n == 0 {
                if let Some(ref cipher) = cipher_opt {
                    if !frame_buf.is_empty() {
                        let aad = build_part_aad(upload_id, part_number, chunk_index);
                        write_encrypted_frame(
                            &mut writer,
                            cipher,
                            &nonce_prefix,
                            chunk_index,
                            &frame_buf,
                            &aad,
                        )
                        .await?;
                    }
                }
                break;
            }
            hasher.update(&buf[..n]);
            if let Some(ref mut ch) = checksum_hasher {
                ch.update(&buf[..n]);
            }
            size += n as u64;
            self.check_part_size(size)?;
            if let Some(ref cipher) = cipher_opt {
                frame_buf.extend_from_slice(&buf[..n]);
                while frame_buf.len() >= FRAME_CHUNK_SIZE {
                    let frame_data: Vec<u8> = frame_buf.drain(..FRAME_CHUNK_SIZE).collect();
                    let aad = build_part_aad(upload_id, part_number, chunk_index);
                    write_encrypted_frame(
                        &mut writer,
                        cipher,
                        &nonce_prefix,
                        chunk_index,
                        &frame_data,
                        &aad,
                    )
                    .await?;
                    chunk_index += 1;
                }
            } else {
                writer.write_all(&buf[..n]).await?;
            }
        }
        writer.flush().await?;
        writer.get_ref().sync_all().await?;

        // Validate and compute checksum
        let (checksum_algorithm, checksum_value) = if let Some((algo, expected)) = checksum {
            let computed = checksum_hasher.unwrap().finalize_base64();
            if let Some(expected_val) = expected {
                if computed != expected_val {
                    return Err(StorageError::ChecksumMismatch(format!(
                        "expected {}, got {}",
                        expected_val, computed
                    )));
                }
            }
            (Some(algo), Some(computed))
        } else {
            (None, None)
        };

        let encrypted = cipher_opt.is_some();
        let ciphertext_size = if encrypted {
            Some(fs::metadata(&tmp_part_path).await?.len())
        } else {
            None
        };

        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));
        let meta = PartMeta {
            part_number,
            etag,
            size,
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            checksum_algorithm,
            checksum_value,
            encrypted,
            ciphertext_size,
        };
        // Publish data, then sidecar — both atomic renames, so a retried part
        // upload replaces the previous attempt wholesale and can never leave a
        // truncated part behind a stale sidecar.
        fs::rename(&tmp_part_path, &part_path).await?;
        tmp_part_guard.disarm();
        sync_parent_dir(&part_path).await?;
        if let Err(e) = write_file_atomic(
            &self.part_meta_path(bucket, upload_id, part_number),
            serde_json::to_string_pretty(&meta)?.as_bytes(),
        )
        .await
        {
            // Remove both files so a stale sidecar from an earlier attempt
            // cannot pair with this orphaned data file at Complete time.
            let _ = fs::remove_file(&part_path).await;
            let _ = fs::remove_file(self.part_meta_path(bucket, upload_id, part_number)).await;
            return Err(e);
        }
        Ok(meta)
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[(u32, String)],
        customer_key: Option<[u8; 32]>,
        precondition: Option<&WritePrecondition>,
    ) -> Result<PutResult, StorageError> {
        validate_bucket_name(bucket)?;
        validate_upload_id(upload_id)?;
        if parts.is_empty() {
            return Err(StorageError::InvalidKey(
                "at least one part is required to complete upload".into(),
            ));
        }

        // AWS S3 semantics: part numbers must be strictly ascending — this
        // also rejects duplicates, which would silently double bytes.
        for pair in parts.windows(2) {
            if pair[1].0 <= pair[0].0 {
                return Err(StorageError::InvalidPartOrder);
            }
        }

        let upload_meta = match self.read_upload_meta(bucket, upload_id).await {
            Ok(meta) => meta,
            // A repeated CompleteMultipartUpload (client retry) returns the
            // same result instead of NoSuchUpload.
            Err(StorageError::UploadNotFound(_)) => {
                if let Some(done) = self.read_completed_upload(bucket, upload_id).await? {
                    return Ok(done);
                }
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }
            Err(e) => return Err(e),
        };
        validate_key(&upload_meta.key)?;
        let mut selected = Vec::with_capacity(parts.len());
        for (idx, (part_number, requested_etag)) in parts.iter().enumerate() {
            let meta = self.read_part_meta(bucket, upload_id, *part_number).await?;
            if meta.etag != *requested_etag {
                return Err(StorageError::InvalidKey(format!(
                    "etag mismatch for part {}",
                    part_number
                )));
            }
            if idx + 1 < parts.len() && meta.size < 5 * 1024 * 1024 {
                return Err(StorageError::InvalidKey("part too small".into()));
            }
            selected.push(meta);
        }
        let assembled = selected
            .iter()
            .fold(0u64, |acc, part| acc.saturating_add(part.size));
        if assembled > self.max_multipart_object_size {
            return Err(StorageError::EntityTooLarge);
        }

        if self.erasure_coding {
            if upload_meta.encryption_spec.is_some() {
                // SSE-C key continuity + per-part `encrypted` flag checks
                // belong with the encrypted multipart path even under EC.
                if let Some(ref spec) = upload_meta.encryption_spec {
                    if matches!(spec.mode, EncryptionMode::SseC) {
                        let ck = customer_key.ok_or_else(|| {
                            StorageError::EncryptionError(
                                "SSE-C requires customer key on CompleteMultipartUpload".into(),
                            )
                        })?;
                        if let Some(ref stored) = spec.customer_key_md5 {
                            let b64 = base64::engine::general_purpose::STANDARD;
                            let provided = b64.encode(Md5::digest(ck));
                            if provided != *stored {
                                return Err(StorageError::EncryptionError(
                                    "SSE-C key changed between Create and Complete".into(),
                                ));
                            }
                        }
                    }
                }
                let upload_is_encrypted = true;
                for part in &selected {
                    if part.encrypted != upload_is_encrypted {
                        return Err(StorageError::IntegrityError(format!(
                            "part {} encryption flag ({}) disagrees with upload spec ({}) — part meta may be tampered",
                            part.part_number, part.encrypted, upload_is_encrypted,
                        )));
                    }
                }
                let result = self
                    .complete_multipart_chunked_encrypted(
                        bucket,
                        upload_id,
                        &upload_meta,
                        &selected,
                        customer_key,
                        precondition,
                    )
                    .await?;
                self.remember_completed_upload(bucket, upload_id, &result)
                    .await;
                return Ok(result);
            }
            let result = self
                .complete_multipart_chunked(
                    bucket,
                    upload_id,
                    &upload_meta,
                    &selected,
                    precondition,
                )
                .await?;
            self.remember_completed_upload(bucket, upload_id, &result)
                .await;
            return Ok(result);
        }

        // If the upload was encrypted, verify the SSE-C key (if any) matches
        // the one declared at CreateMultipartUpload. This closes the "init with
        // key A, complete with key B" gap — without this check the final
        // object would be encrypted with the wrong key and the parts
        // (encrypted under the Create-time key) could not be decrypted
        // consistently anyway.
        if let Some(ref spec) = upload_meta.encryption_spec {
            if matches!(spec.mode, EncryptionMode::SseC) {
                let ck = customer_key.ok_or_else(|| {
                    StorageError::EncryptionError(
                        "SSE-C requires customer key on CompleteMultipartUpload".into(),
                    )
                })?;
                if let Some(ref stored) = spec.customer_key_md5 {
                    let b64 = base64::engine::general_purpose::STANDARD;
                    let provided = b64.encode(Md5::digest(ck));
                    if provided != *stored {
                        return Err(StorageError::EncryptionError(
                            "SSE-C key changed between Create and Complete".into(),
                        ));
                    }
                }
            }
        }

        // Cross-check each part's `encrypted` flag against the upload spec so
        // a flipped `encrypted: true → false` cannot coerce the server into
        // reading ciphertext as plaintext during concat. Both modes (always-on
        // or always-off) are enforced.
        let upload_is_encrypted = upload_meta.encryption_spec.is_some();
        for part in &selected {
            if part.encrypted != upload_is_encrypted {
                return Err(StorageError::IntegrityError(format!(
                    "part {} encryption flag ({}) disagrees with upload spec ({}) — part meta may be tampered",
                    part.part_number, part.encrypted, upload_is_encrypted,
                )));
            }
        }

        // Upload-scoped DEK used to decrypt every encrypted part on the way in.
        let upload_dek_opt: Option<[u8; 32]> = if let Some(ref spec) = upload_meta.encryption_spec {
            Some(self.resolve_upload_dek(spec, customer_key)?)
        } else {
            None
        };

        // Final object encryption (fresh DEK, distinct from the upload DEK).
        let enc_meta_opt: Option<EncryptionMeta> =
            if let Some(ref spec) = upload_meta.encryption_spec {
                let req = match spec.mode {
                    EncryptionMode::SseS3 => EncryptionRequest::sse_s3(),
                    EncryptionMode::SseC => {
                        let ck = customer_key.ok_or_else(|| {
                            StorageError::EncryptionError(
                                "SSE-C requires customer key on CompleteMultipartUpload".into(),
                            )
                        })?;
                        EncryptionRequest::sse_c(ck)
                    }
                };
                Some(
                    self.prepare_encryption(&req)
                        .map_err(|e| StorageError::EncryptionError(e.to_string()))?,
                )
            } else {
                None
            };

        let (cipher_opt, nonce_prefix, dek_opt) = if let Some(ref em) = enc_meta_opt {
            let dek = self.resolve_dek(em, customer_key)?;
            let b64 = base64::engine::general_purpose::STANDARD;
            let prefix_bytes = b64
                .decode(&em.nonce_prefix)
                .map_err(|_| StorageError::EncryptionError("invalid nonce_prefix".into()))?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
            (Some(cipher), prefix_bytes, Some(dek))
        } else {
            (None, Vec::new(), None)
        };

        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        let obj_path = self
            .plain_object_write_path(bucket, &upload_meta.key)
            .await?;
        let tmp_obj_path = temp_sibling_path(&obj_path);
        let mut tmp_obj_guard = TempPathGuard::file(tmp_obj_path.clone());
        let out = fs::File::create(&tmp_obj_path).await?;
        let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, out);
        let mut total_size = 0u64;
        let mut etag_hasher = Md5::new();
        let mut buf = vec![0u8; IO_BUFFER_SIZE];
        let mut frame_buf: Vec<u8> = Vec::with_capacity(FRAME_CHUNK_SIZE);
        let mut chunk_index: u64 = 0;
        let bucket_for_aad = bucket;
        let key_for_aad = upload_meta.key.as_str();

        for part in &selected {
            let part_path = self.part_path(bucket, upload_id, part.part_number);
            let mut part_stream: ByteStream = if part.encrypted {
                let dek = upload_dek_opt.as_ref().ok_or_else(|| {
                    StorageError::EncryptionError(
                        "encrypted part but upload spec has no DEK".into(),
                    )
                })?;
                let file = fs::File::open(&part_path).await?;
                let aad = part_aad_builder(upload_id, part.part_number);
                Box::pin(FrameDecryptor::new(
                    Box::pin(file),
                    dek,
                    part.size,
                    FRAME_CHUNK_SIZE,
                    aad,
                ))
            } else {
                Box::pin(fs::File::open(&part_path).await?)
            };
            let mut part_md5 = Md5::new();
            let mut part_bytes: u64 = 0;
            loop {
                let n = part_stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                part_md5.update(&buf[..n]);
                part_bytes += n as u64;
                total_size += n as u64;
                if let Some(ref cipher) = cipher_opt {
                    frame_buf.extend_from_slice(&buf[..n]);
                    while frame_buf.len() >= FRAME_CHUNK_SIZE {
                        let frame_data: Vec<u8> = frame_buf.drain(..FRAME_CHUNK_SIZE).collect();
                        let aad = build_frame_aad(
                            bucket_for_aad,
                            key_for_aad,
                            version_id.as_deref(),
                            chunk_index,
                        );
                        write_encrypted_frame(
                            &mut writer,
                            cipher,
                            &nonce_prefix,
                            chunk_index,
                            &frame_data,
                            &aad,
                        )
                        .await?;
                        chunk_index += 1;
                    }
                } else {
                    writer.write_all(&buf[..n]).await?;
                }
            }
            verify_part_bytes(part, part_bytes, part_md5)?;

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }
        // Flush trailing partial frame
        if let Some(ref cipher) = cipher_opt {
            if !frame_buf.is_empty() {
                let aad = build_frame_aad(
                    bucket_for_aad,
                    key_for_aad,
                    version_id.as_deref(),
                    chunk_index,
                );
                write_encrypted_frame(
                    &mut writer,
                    cipher,
                    &nonce_prefix,
                    chunk_index,
                    &frame_buf,
                    &aad,
                )
                .await?;
            }
        }
        writer.flush().await?;

        let etag = format!(
            "\"{}-{}\"",
            hex::encode(etag_hasher.finalize()),
            selected.len()
        );

        // Compute composite checksum if algorithm was specified
        let (checksum_algorithm, checksum_value) =
            if let Some(algo) = upload_meta.checksum_algorithm {
                let b64 = base64::engine::general_purpose::STANDARD;
                let mut raw_checksums = Vec::new();
                for part in &selected {
                    if let Some(ref val) = part.checksum_value {
                        if let Ok(raw) = b64.decode(val) {
                            raw_checksums.extend_from_slice(&raw);
                        }
                    }
                }
                if !raw_checksums.is_empty() {
                    let mut composite_hasher = ChecksumHasher::new(algo);
                    composite_hasher.update(&raw_checksums);
                    let composite =
                        format!("{}-{}", composite_hasher.finalize_base64(), selected.len());
                    (Some(algo), Some(composite))
                } else {
                    (Some(algo), None)
                }
            } else {
                (None, None)
            };

        let part_sizes: Vec<u64> = selected.iter().map(|p| p.size).collect();
        let mut object_meta = ObjectMeta {
            key: upload_meta.key.clone(),
            size: total_size,
            etag: etag.clone(),
            content_type: upload_meta.content_type,
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
            tags: upload_meta.tags,
            part_sizes: Some(part_sizes),
            encryption: enc_meta_opt,
            metadata: upload_meta.object_metadata,
        };
        if let (Some(dek), Some(em)) = (dek_opt.as_ref(), object_meta.encryption.as_mut()) {
            em.sidecar_mac = String::new();
            let mac = compute_sidecar_mac(dek, &object_meta)?;
            object_meta.encryption.as_mut().unwrap().sidecar_mac = mac;
        }
        let meta_path = self.meta_path(bucket, &upload_meta.key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let tmp_meta_path = temp_sibling_path(&meta_path);
        let mut tmp_meta_guard = TempPathGuard::file(tmp_meta_path.clone());
        fs::write(&tmp_meta_path, serde_json::to_string_pretty(&object_meta)?).await?;
        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, &upload_meta.key).await;
        self.ensure_bucket_exists(bucket).await?;
        self.check_write_precondition(bucket, &upload_meta.key, precondition)
            .await?;
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, &upload_meta.key)
                    .await?;
                self.write_version(bucket, &upload_meta.key, &object_meta, &tmp_obj_path)
                    .await?;
            }
            publish_temp_payload_and_meta(
                &tmp_obj_path,
                &obj_path,
                false,
                &tmp_meta_path,
                &meta_path,
                &self.fault,
            )
            .await
        }
        .await;
        if let Err(e) = publish_result {
            if versioned {
                self.rollback_failed_versioned_publish(
                    bucket,
                    &upload_meta.key,
                    version_id.as_deref(),
                )
                .await;
            }
            return Err(e);
        }
        tmp_obj_guard.disarm();
        tmp_meta_guard.disarm();
        remove_dir_all_if_exists(&self.ec_dir(bucket, &upload_meta.key)).await?;
        drop(_key_guard);
        drop(_bucket_guard);
        // Best-effort: the object is already durably published. A racing
        // Abort/housekeeping may have removed the upload dir — that must not
        // turn a successful complete into an error.
        if let Err(e) = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("failed to clean up upload dir {}: {}", upload_id, e);
            }
        }

        let result = PutResult {
            size: total_size,
            etag,
            version_id,
            checksum_algorithm,
            checksum_value,
        };
        self.remember_completed_upload(bucket, upload_id, &result)
            .await;
        Ok(result)
    }

    fn completed_upload_path(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.uploads_dir(bucket)
            .join(format!(".completed-{upload_id}.json"))
    }

    async fn remember_completed_upload(&self, bucket: &str, upload_id: &str, result: &PutResult) {
        let record = CompletedUploadRecord {
            etag: result.etag.clone(),
            size: result.size,
            version_id: result.version_id.clone(),
            checksum_algorithm: result.checksum_algorithm,
            checksum_value: result.checksum_value.clone(),
        };
        let Ok(json) = serde_json::to_string(&record) else {
            return;
        };
        let path = self.completed_upload_path(bucket, upload_id);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent).await;
        }
        let _ = fs::write(path, json).await;
    }

    async fn read_completed_upload(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<Option<PutResult>, StorageError> {
        let path = self.completed_upload_path(bucket, upload_id);
        let data = match fs::read(&path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StorageError::Io(e)),
        };
        let record: CompletedUploadRecord = serde_json::from_slice(&data)?;
        Ok(Some(PutResult {
            size: record.size,
            etag: record.etag,
            version_id: record.version_id,
            checksum_algorithm: record.checksum_algorithm,
            checksum_value: record.checksum_value,
        }))
    }

    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(), StorageError> {
        validate_bucket_name(bucket)?;
        validate_upload_id(upload_id)?;
        let upload_dir = self.upload_dir(bucket, upload_id);
        if !fs::try_exists(&upload_dir).await? {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }
        fs::remove_dir_all(upload_dir).await?;
        Ok(())
    }

    pub async fn list_parts(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(MultipartUploadMeta, Vec<PartMeta>), StorageError> {
        validate_bucket_name(bucket)?;
        validate_upload_id(upload_id)?;
        let meta = self.read_upload_meta(bucket, upload_id).await?;
        let upload_dir = self.upload_dir(bucket, upload_id);
        let mut entries = fs::read_dir(&upload_dir).await?;
        let mut parts = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".meta.json") || name == ".meta.json" {
                continue;
            }
            let data = fs::read_to_string(entry.path()).await?;
            if let Ok(pm) = serde_json::from_str::<PartMeta>(&data) {
                parts.push(pm);
            }
        }
        parts.sort_by_key(|p| p.part_number);
        Ok((meta, parts))
    }

    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<MultipartUploadMeta>, StorageError> {
        validate_bucket_name(bucket)?;
        let uploads_dir = self.uploads_dir(bucket);
        if !fs::try_exists(&uploads_dir).await? {
            return Ok(Vec::new());
        }
        let mut entries = fs::read_dir(&uploads_dir).await?;
        let mut uploads = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            let upload_id = entry.file_name().to_string_lossy().to_string();
            if let Ok(meta) = self.read_upload_meta(bucket, &upload_id).await {
                uploads.push(meta);
            }
        }
        uploads.sort_by(|a, b| a.initiated.cmp(&b.initiated));
        Ok(uploads)
    }

    /// Clear crash leftovers that cannot belong to a live request.
    ///
    /// Called from `new` (process start). Removes every `.maxio-tmp-*` and
    /// resolves every `.maxio-bak-*` immediately, restores object bytes left
    /// in `.maxio-promote-*` directories, and deletes multipart upload
    /// directories whose `.meta.json` is missing or unreadable. Uploads with
    /// valid metadata are left for the client to complete or abort; the hourly
    /// sweep removes those that stay idle for 7 days.
    ///
    /// Returns `(uploads_removed, artifacts_removed)`.
    pub async fn startup_recover(&self) -> (u64, u64) {
        let mut uploads_removed = 0u64;
        let mut artifacts = 0u64;
        let mut bucket_entries = match fs::read_dir(&self.buckets_dir).await {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!("startup recovery: cannot read buckets dir: {}", e);
                return (0, 0);
            }
        };
        while let Ok(Some(bucket_entry)) = bucket_entries.next_entry().await {
            if !matches!(bucket_entry.file_type().await, Ok(ft) if ft.is_dir()) {
                continue;
            }
            let bucket_dir = bucket_entry.path();
            let uploads_dir = bucket_dir.join(".uploads");
            if let Ok(mut uploads) = fs::read_dir(&uploads_dir).await {
                while let Ok(Some(up)) = uploads.next_entry().await {
                    if !matches!(up.file_type().await, Ok(ft) if ft.is_dir()) {
                        continue;
                    }
                    let meta_path = up.path().join(".meta.json");
                    let readable = match fs::read_to_string(&meta_path).await {
                        Ok(data) => serde_json::from_str::<MultipartUploadMeta>(&data).is_ok(),
                        Err(_) => false,
                    };
                    if readable {
                        continue;
                    }
                    match fs::remove_dir_all(up.path()).await {
                        Ok(()) => {
                            uploads_removed += 1;
                            tracing::warn!(
                                "startup recovery: removed multipart upload without readable metadata at {}",
                                up.path().display()
                            );
                        }
                        Err(e) => tracing::warn!(
                            "startup recovery: failed to remove upload {}: {}",
                            up.path().display(),
                            e
                        ),
                    }
                }
            }
            artifacts += Self::sweep_stale_artifacts(&bucket_dir, None, None).await;
        }
        if uploads_removed > 0 || artifacts > 0 {
            tracing::info!(
                "startup recovery: removed {} upload(s) without metadata, {} temp/backup artifact(s)",
                uploads_removed,
                artifacts
            );
        }
        (uploads_removed, artifacts)
    }

    /// Background housekeeping: abort multipart uploads whose `.meta.json`
    /// `initiated` timestamp is older than `stale_after`, and remove
    /// leftover `.maxio-tmp-*` files from crashed writes. Returns
    /// `(uploads_removed, temp_files_removed)`. Best-effort — errors on
    /// individual entries are logged and skipped, not propagated.
    pub async fn housekeeping_sweep(&self, stale_after: chrono::Duration) -> (u64, u64) {
        let now = chrono::Utc::now();
        let mut uploads_removed = 0u64;
        let mut temp_removed = 0u64;

        let mut bucket_entries = match fs::read_dir(&self.buckets_dir).await {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("housekeeping: cannot read buckets dir: {}", e);
                return (0, 0);
            }
        };

        while let Ok(Some(bucket_entry)) = bucket_entries.next_entry().await {
            if !matches!(bucket_entry.file_type().await, Ok(ft) if ft.is_dir()) {
                continue;
            }
            let bucket_dir = bucket_entry.path();

            // 1. Stale multipart uploads.
            let uploads_dir = bucket_dir.join(".uploads");
            if let Ok(mut uploads) = fs::read_dir(&uploads_dir).await {
                while let Ok(Some(up)) = uploads.next_entry().await {
                    if !matches!(up.file_type().await, Ok(ft) if ft.is_dir()) {
                        continue;
                    }
                    let meta_path = up.path().join(".meta.json");
                    let initiated = fs::read_to_string(&meta_path)
                        .await
                        .ok()
                        .and_then(|d| serde_json::from_str::<MultipartUploadMeta>(&d).ok())
                        .map(|m| m.initiated);
                    // Treat unreadable/missing meta as stale by directory mtime.
                    let mut age_ok = match initiated {
                        Some(ts) => chrono::DateTime::parse_from_rfc3339(&ts)
                            .map(|t| now.signed_duration_since(t.with_timezone(&chrono::Utc)))
                            .map(|age| age > stale_after)
                            .unwrap_or(true),
                        None => true,
                    };
                    // A slow-but-alive upload keeps writing parts; recent part
                    // activity vetoes removal so acked parts are never destroyed
                    // under a client that is still uploading.
                    if age_ok
                        && !Self::entry_older_than(
                            &up.path(),
                            stale_after.num_seconds().max(0) as u64,
                        )
                        .await
                    {
                        age_ok = false;
                    }
                    if age_ok {
                        match fs::remove_dir_all(up.path()).await {
                            Ok(()) => {
                                uploads_removed += 1;
                                tracing::info!(
                                    "housekeeping: aborted stale multipart upload {}",
                                    up.file_name().to_string_lossy()
                                );
                            }
                            Err(e) => tracing::warn!(
                                "housekeeping: failed to remove stale upload {}: {}",
                                up.path().display(),
                                e
                            ),
                        }
                    }
                }
            }

            // 2. Leftover temp/backup files from crashed writes, at any depth.
            //    Age-gated so an in-flight request's temp file is left alone.
            temp_removed +=
                Self::sweep_stale_artifacts(&bucket_dir, Some(24 * 3600), Some(3600)).await;
        }

        (uploads_removed, temp_removed)
    }

    /// `None` means "any age" (startup). `Some(secs)` is true only when mtime
    /// is strictly older than `secs`. Errs on the side of "not old" when a
    /// positive age is required, so a stat failure never deletes a live file.
    async fn is_stale(path: &Path, max_age: Option<u64>) -> bool {
        let Some(secs) = max_age else {
            return true;
        };
        Self::entry_older_than(path, secs).await
    }

    /// True if `path`'s mtime is older than `secs` seconds. Errs on the side
    /// of "not old" so nothing live is ever removed on a stat failure.
    async fn entry_older_than(path: &Path, secs: u64) -> bool {
        match fs::metadata(path).await.and_then(|m| m.modified()) {
            Ok(mtime) => match mtime.elapsed() {
                Ok(age) => age.as_secs() > secs,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    /// Recursively sweep crash leftovers under `dir`:
    /// * `.maxio-tmp-*` entries older than `temp_max_age` seconds are removed.
    ///   `None` removes them regardless of age (startup, when nothing is in
    ///   flight). The age gate matters while the server is running: an
    ///   in-flight upload keeps touching its temp file.
    /// * `.maxio-bak-<name>` entries older than `backup_max_age` (`None` = any
    ///   age) are crash-stranded EC publish backups: if `<name>` is missing
    ///   the publish died mid-swap and the backup IS the committed object —
    ///   restore it; if `<name>` exists the publish completed and the backup
    ///   is garbage.
    /// * `.maxio-promote-*` directories older than `backup_max_age` are
    ///   restored (payload back at the target key, or into `<key>/.maxio.object`
    ///   when that directory exists) or discarded when the original file is
    ///   still in place. The sweep does not recurse into them: the payload is
    ///   the object, not a temp file.
    fn sweep_stale_artifacts<'a>(
        dir: &'a Path,
        temp_max_age: Option<u64>,
        backup_max_age: Option<u64>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = u64> + Send + 'a>> {
        Box::pin(async move {
            let mut removed = 0u64;
            for outcome in recover_promotes_in(dir, backup_max_age).await {
                if outcome.resolved {
                    removed += 1;
                    tracing::info!(
                        "housekeeping: {} ({})",
                        outcome.detail,
                        outcome.path.display()
                    );
                } else {
                    tracing::warn!(
                        "housekeeping: {} ({})",
                        outcome.detail,
                        outcome.path.display()
                    );
                }
            }
            let mut entries = match fs::read_dir(dir).await {
                Ok(e) => e,
                Err(_) => return removed,
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();
                let path = entry.path();
                let is_dir = matches!(entry.file_type().await, Ok(ft) if ft.is_dir());

                if let Some(orig_name) = name.strip_prefix(".maxio-bak-") {
                    if orig_name.is_empty() || !Self::is_stale(&path, backup_max_age).await {
                        continue;
                    }
                    let orig = dir.join(orig_name);
                    // An `.ec` backup must not be restored over a key that has
                    // since been rewritten as a flat object (reads resolve EC
                    // first and would serve the stale shards).
                    let superseded_by_flat = match orig_name.strip_suffix(".ec") {
                        Some(flat) if !flat.is_empty() => {
                            fs::try_exists(dir.join(flat)).await.unwrap_or(false)
                        }
                        _ => false,
                    };
                    if superseded_by_flat || fs::try_exists(&orig).await.unwrap_or(true) {
                        let result = if is_dir {
                            fs::remove_dir_all(&path).await
                        } else {
                            fs::remove_file(&path).await
                        };
                        match result {
                            Ok(()) => {
                                removed += 1;
                                tracing::info!(
                                    "housekeeping: removed stale backup {}",
                                    path.display()
                                );
                            }
                            Err(e) => tracing::warn!(
                                "housekeeping: failed to remove backup {}: {}",
                                path.display(),
                                e
                            ),
                        }
                    } else {
                        match fs::rename(&path, &orig).await {
                            Ok(()) => tracing::warn!(
                                "housekeeping: restored {} from crash-stranded backup",
                                orig.display()
                            ),
                            Err(e) => tracing::warn!(
                                "housekeeping: failed to restore backup {}: {}",
                                path.display(),
                                e
                            ),
                        }
                    }
                    continue;
                }

                let marker_name = name.to_ascii_lowercase();
                if marker_name == PROMOTE_TARGET_FILE || marker_name == PROMOTE_READY_FILE {
                    // Markers left inside a published key directory after a
                    // crash between the rename and the marker cleanup. A
                    // sibling sidecar means this name is an object written
                    // before the segment was reserved; leave those bytes.
                    // The in-progress copies live inside `.maxio-promote-*`,
                    // which this sweep does not recurse into.
                    if fs::try_exists(dir.join(format!("{name}.meta.json")))
                        .await
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    if !Self::is_stale(&path, backup_max_age).await {
                        continue;
                    }
                    match fs::remove_file(&path).await {
                        Ok(()) => removed += 1,
                        Err(e) => tracing::warn!(
                            "housekeeping: failed to remove promote marker {}: {}",
                            path.display(),
                            e
                        ),
                    }
                    continue;
                }

                if is_dir && is_promote_dir_name(&name) {
                    continue;
                }

                if name.starts_with(".maxio-tmp-") {
                    if !Self::is_stale(&path, temp_max_age).await {
                        continue;
                    }
                    let result = if is_dir {
                        fs::remove_dir_all(&path).await
                    } else {
                        fs::remove_file(&path).await
                    };
                    match result {
                        Ok(()) => {
                            removed += 1;
                            tracing::info!(
                                "housekeeping: removed leftover temp {}",
                                path.display()
                            );
                        }
                        Err(e) => tracing::warn!(
                            "housekeeping: failed to remove temp {}: {}",
                            path.display(),
                            e
                        ),
                    }
                    continue;
                }

                if is_dir {
                    removed +=
                        Self::sweep_stale_artifacts(&path, temp_max_age, backup_max_age).await;
                }
            }
            removed
        })
    }

    // --- Internal helpers ---

    async fn read_object_meta(&self, bucket: &str, key: &str) -> Result<ObjectMeta, StorageError> {
        let meta_path = self.meta_path(bucket, key);
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    fn walk_dir<'a>(
        &'a self,
        base: &'a Path,
        dir: &'a Path,
        prefix: &'a str,
        results: &'a mut Vec<ObjectMeta>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = match fs::read_dir(dir).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let fname = entry.file_name().to_string_lossy().to_string();

                if fname.ends_with(".meta.json")
                    || fname == ".bucket.json"
                    || fname == ".uploads"
                    || fname == ".versions"
                    || fname == ".folder"
                    || fname == INLINE_OBJECT_PAYLOAD
                    || fname.starts_with(".maxio-tmp-")
                    || fname.starts_with(".maxio-promote-")
                    || fname.starts_with(".maxio-bak-")
                {
                    continue;
                }

                // EC chunk directory: derive the object key and read its metadata
                if fname.ends_with(".ec") && entry.file_type().await?.is_dir() {
                    if let Ok(rel) = path.strip_prefix(base) {
                        let rel_str = rel.to_string_lossy();
                        // Strip the .ec suffix to get the key
                        let key = rel_str.strip_suffix(".ec").unwrap_or(&rel_str).to_string();
                        if key.starts_with(prefix) {
                            if let Ok(meta) = self
                                .read_object_meta(base.file_name().unwrap().to_str().unwrap(), &key)
                                .await
                            {
                                results.push(meta);
                            }
                        }
                    }
                    continue;
                }

                if entry.file_type().await?.is_dir() {
                    // This directory is also an object (`foo/bar` plus `foo/bar/baz`).
                    let inline = path.join(INLINE_OBJECT_PAYLOAD);
                    if matches!(fs::metadata(&inline).await, Ok(m) if m.is_file()) {
                        if let Ok(rel) = path.strip_prefix(base) {
                            let key = rel.to_string_lossy().to_string();
                            if key.starts_with(prefix) {
                                if let Some(bucket_name) = base.file_name().and_then(|n| n.to_str())
                                {
                                    if let Ok(meta) = self.read_object_meta(bucket_name, &key).await
                                    {
                                        results.push(meta);
                                    }
                                }
                            }
                        }
                    }
                    // Check for folder marker inside this directory
                    let marker = path.join(".folder.meta.json");
                    if marker.exists() {
                        if let Ok(rel) = path.strip_prefix(base) {
                            let key = format!("{}/", rel.to_string_lossy());
                            if key.starts_with(prefix) {
                                if let Ok(data) = fs::read_to_string(&marker).await {
                                    if let Ok(meta) = serde_json::from_str::<ObjectMeta>(&data) {
                                        results.push(meta);
                                    }
                                }
                            }
                        }
                    }
                    self.walk_dir(base, &path, prefix, results).await?;
                } else {
                    if let Ok(rel) = path.strip_prefix(base) {
                        let key = rel.to_string_lossy().to_string();
                        if key.starts_with(prefix) {
                            if let Ok(meta) = self
                                .read_object_meta(base.file_name().unwrap().to_str().unwrap(), &key)
                                .await
                            {
                                results.push(meta);
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }

    async fn read_upload_meta(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<MultipartUploadMeta, StorageError> {
        let path = self.upload_meta_path(bucket, upload_id);
        let data = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::UploadNotFound(upload_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    async fn read_part_meta(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
    ) -> Result<PartMeta, StorageError> {
        let path = self.part_meta_path(bucket, upload_id, part_number);
        let data = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::InvalidKey(format!("missing part {}", part_number))
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    // --- Versioning ---

    fn generate_version_id() -> String {
        let micros = chrono::Utc::now().timestamp_micros() as u64;
        let rand_suffix: u32 = rand::rng().random();
        format!("{:016}-{:08x}", micros, rand_suffix)
    }

    /// Directory holding versions for a given key.
    /// For key `photos/vacation.jpg` → `{bucket}/photos/.versions/vacation.jpg/`
    fn versions_dir(&self, bucket: &str, key: &str) -> PathBuf {
        let key_path = Path::new(key);
        let parent = key_path.parent().unwrap_or(Path::new(""));
        let name = key_path.file_name().unwrap_or(std::ffi::OsStr::new(key));
        self.buckets_dir
            .join(bucket)
            .join(parent)
            .join(".versions")
            .join(name)
    }

    fn version_data_path(&self, bucket: &str, key: &str, version_id: &str) -> PathBuf {
        self.versions_dir(bucket, key)
            .join(format!("{}.data", version_id))
    }

    fn version_meta_path(&self, bucket: &str, key: &str, version_id: &str) -> PathBuf {
        self.versions_dir(bucket, key)
            .join(format!("{}.meta.json", version_id))
    }

    pub async fn is_versioned(&self, bucket: &str) -> Result<bool, StorageError> {
        validate_bucket_name(bucket)?;
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: BucketMeta = serde_json::from_str(&data)?;
        Ok(meta.versioning)
    }

    /// Locked, atomic read-modify-write of `.bucket.json`. The bucket write
    /// guard prevents lost updates from concurrent config changes; the atomic
    /// file write prevents readers from ever seeing a torn config (which
    /// would silently disable versioning protection).
    async fn update_bucket_meta<F>(&self, bucket: &str, mutate: F) -> Result<(), StorageError>
    where
        F: FnOnce(&mut BucketMeta),
    {
        validate_bucket_name(bucket)?;
        let _bucket_guard = self.bucket_write(bucket).await;
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        mutate(&mut meta);
        write_file_atomic(&meta_path, serde_json::to_string_pretty(&meta)?.as_bytes()).await?;
        Ok(())
    }

    pub async fn set_versioning(&self, bucket: &str, enabled: bool) -> Result<(), StorageError> {
        // S3-compatible suspension preserves historical versions. It only
        // changes how future writes/deletes are versioned.
        self.update_bucket_meta(bucket, |m| {
            m.versioning = enabled;
            m.versioning_suspended = !enabled;
        })
        .await
    }

    /// Read the bucket's `.bucket.json`.
    pub async fn get_bucket_meta(&self, bucket: &str) -> Result<BucketMeta, StorageError> {
        validate_bucket_name(bucket)?;
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Replace (Some) or clear (None) the bucket tag set.
    pub async fn set_bucket_tags(
        &self,
        bucket: &str,
        tags: Option<std::collections::BTreeMap<String, String>>,
    ) -> Result<(), StorageError> {
        self.update_bucket_meta(bucket, |m| m.tags = tags).await
    }

    pub async fn get_bucket_public(&self, bucket: &str) -> Result<(bool, bool), StorageError> {
        validate_bucket_name(bucket)?;
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: BucketMeta = serde_json::from_str(&data)?;
        Ok((meta.public_read, meta.public_list))
    }

    pub async fn set_bucket_public(
        &self,
        bucket: &str,
        read: bool,
        list: bool,
    ) -> Result<(), StorageError> {
        self.update_bucket_meta(bucket, |m| {
            m.public_read = read;
            m.public_list = list;
        })
        .await
    }

    pub async fn put_bucket_cors(
        &self,
        bucket: &str,
        rules: Vec<crate::storage::CorsRule>,
    ) -> Result<(), StorageError> {
        self.update_bucket_meta(bucket, |m| m.cors_rules = Some(rules))
            .await
    }

    pub async fn get_bucket_cors(
        &self,
        bucket: &str,
    ) -> Result<Option<Vec<crate::storage::CorsRule>>, StorageError> {
        validate_bucket_name(bucket)?;
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: BucketMeta = serde_json::from_str(&data)?;
        Ok(meta.cors_rules)
    }

    pub async fn delete_bucket_cors(&self, bucket: &str) -> Result<(), StorageError> {
        self.update_bucket_meta(bucket, |m| m.cors_rules = None)
            .await
    }

    // --- Bucket default encryption ---

    pub async fn put_bucket_encryption(
        &self,
        bucket: &str,
        config: BucketEncryptionConfig,
    ) -> Result<(), StorageError> {
        self.update_bucket_meta(bucket, |m| m.encryption_config = Some(config))
            .await
    }

    pub async fn get_bucket_encryption(
        &self,
        bucket: &str,
    ) -> Result<Option<BucketEncryptionConfig>, StorageError> {
        validate_bucket_name(bucket)?;
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: BucketMeta = serde_json::from_str(&data)?;
        Ok(meta.encryption_config)
    }

    pub async fn delete_bucket_encryption(&self, bucket: &str) -> Result<(), StorageError> {
        self.update_bucket_meta(bucket, |m| m.encryption_config = None)
            .await
    }

    // --- Bucket lifecycle ---

    /// Lifecycle rules of `bucket`, `None` when no configuration is set.
    /// `NotFound` when the bucket does not exist.
    pub async fn get_bucket_lifecycle(
        &self,
        bucket: &str,
    ) -> Result<Option<Vec<crate::storage::lifecycle::LifecycleRule>>, StorageError> {
        Ok(self
            .get_bucket_meta(bucket)
            .await?
            .lifecycle
            .filter(|r| !r.is_empty()))
    }

    /// Replace (`Some`) or remove (`None` / empty) the lifecycle rules. The
    /// rules are stored as given; validate them first with
    /// `storage::lifecycle::validate_rules`.
    pub async fn set_bucket_lifecycle(
        &self,
        bucket: &str,
        rules: Option<Vec<crate::storage::lifecycle::LifecycleRule>>,
    ) -> Result<(), StorageError> {
        let rules = rules.filter(|r| !r.is_empty());
        self.update_bucket_meta(bucket, |m| m.lifecycle = rules)
            .await
    }

    /// One directory level of the key namespace, for incremental walks
    /// (lifecycle). `dir` is `""` for the bucket root or a prefix ending in
    /// `/`. `keys` are the keys directly in `dir` that have a current object,
    /// a folder marker or stored versions (sorted, deduplicated); `subdirs`
    /// are child prefixes (`dir` + name + `/`). Internal entries are skipped.
    pub async fn list_key_dir(
        &self,
        bucket: &str,
        dir: &str,
    ) -> Result<KeyDirListing, StorageError> {
        validate_bucket_name(bucket)?;
        if !dir.is_empty() {
            validate_key(dir)?;
        }
        let path = self.buckets_dir.join(bucket).join(dir);
        let mut keys = std::collections::BTreeSet::new();
        let mut subdirs = Vec::new();
        let mut entries = match fs::read_dir(&path).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(KeyDirListing::default());
            }
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(".maxio-tmp-")
                || name.starts_with(".maxio-bak-")
                || name == ".bucket.json"
                || name == ".uploads"
            {
                continue;
            }
            let is_dir = entry.file_type().await?.is_dir();
            if name == ".folder.meta.json" {
                if !dir.is_empty() {
                    keys.insert(dir.to_string());
                }
            } else if let Some(k) = name.strip_suffix(".meta.json") {
                if !is_dir && !k.is_empty() {
                    keys.insert(format!("{}{}", dir, k));
                }
            } else if name == ".versions" && is_dir {
                let mut vers = fs::read_dir(entry.path()).await?;
                while let Some(v) = vers.next_entry().await? {
                    if v.file_type().await?.is_dir() {
                        keys.insert(format!("{}{}", dir, v.file_name().to_string_lossy()));
                    }
                }
            } else if is_dir && !name.ends_with(".ec") && name != ".folder" {
                subdirs.push(format!("{}{}/", dir, name));
            }
        }
        subdirs.sort();
        Ok(KeyDirListing {
            keys: keys.into_iter().collect(),
            subdirs,
        })
    }

    /// All versions of exactly one key, newest first: a top-level null
    /// version (pre-versioning or written while suspended) first, then the
    /// version store by id descending, the archived "null" version last.
    /// Delete markers included. Empty when the key does not exist.
    pub async fn list_key_versions(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        let mut out = Vec::new();
        match self.read_object_meta(bucket, key).await {
            Ok(m) if m.version_id.is_none() => out.push(m),
            Ok(_) | Err(StorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let ver_dir = self.versions_dir(bucket, key);
        let mut versions = Vec::new();
        match fs::read_dir(&ver_dir).await {
            Ok(mut entries) => {
                while let Some(entry) = entries.next_entry().await? {
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if !fname.ends_with(".meta.json") {
                        continue;
                    }
                    let data = match fs::read_to_string(entry.path()).await {
                        Ok(d) => d,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e.into()),
                    };
                    match serde_json::from_str::<ObjectMeta>(&data) {
                        // `a/` and `a` share a version dir; keep only this key.
                        Ok(m) if m.key == key => versions.push(m),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(
                            "skipping corrupt version sidecar {}: {}",
                            entry.path().display(),
                            e
                        ),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // Archived null version (no id) is the oldest; ids sort by time.
        versions.sort_by(|a, b| match (&a.version_id, &b.version_id) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(x), Some(y)) => y.cmp(x),
        });
        out.extend(versions);
        Ok(out)
    }

    // --- Encryption helpers ---

    fn prepare_encryption(&self, req: &EncryptionRequest) -> Result<EncryptionMeta, StorageError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        match req.mode {
            EncryptionMode::SseS3 => {
                let dek = Keyring::generate_dek();
                let nonce_prefix = Keyring::generate_nonce_prefix8();
                let key_id = self.keyring.active_id().to_string();
                let (wrapped_dek, wrap_nonce) = self
                    .keyring
                    .wrap_dek(&key_id, &dek)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
                Ok(EncryptionMeta {
                    algorithm: "AES256".to_string(),
                    mode: EncryptionMode::SseS3,
                    key_id: Some(key_id),
                    wrapped_dek: Some(b64.encode(&wrapped_dek)),
                    wrap_nonce: Some(b64.encode(wrap_nonce)),
                    customer_key_md5: None,
                    nonce_prefix: b64.encode(nonce_prefix),
                    chunk_size: FRAME_CHUNK_SIZE as u32,
                    sidecar_mac: String::new(),
                })
            }
            EncryptionMode::SseC => {
                let customer_key = req.customer_key.as_ref().ok_or_else(|| {
                    StorageError::EncryptionError("SSE-C requires customer key".into())
                })?;
                let dek = Keyring::generate_dek();
                let nonce_prefix = Keyring::generate_nonce_prefix8();
                let md5 = Md5::digest(&**customer_key);
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&**customer_key));
                let mut wrap_nonce = [0u8; 12];
                rand::rng().fill(&mut wrap_nonce[..]);
                let wrapped_dek = cipher
                    .encrypt(Nonce::from_slice(&wrap_nonce), dek.as_slice())
                    .map_err(|_| {
                        StorageError::EncryptionError("SSE-C DEK wrapping failed".into())
                    })?;
                Ok(EncryptionMeta {
                    algorithm: "AES256".to_string(),
                    mode: EncryptionMode::SseC,
                    key_id: None,
                    wrapped_dek: Some(b64.encode(&wrapped_dek)),
                    wrap_nonce: Some(b64.encode(wrap_nonce)),
                    customer_key_md5: Some(b64.encode(md5)),
                    nonce_prefix: b64.encode(nonce_prefix),
                    chunk_size: FRAME_CHUNK_SIZE as u32,
                    sidecar_mac: String::new(),
                })
            }
        }
    }

    /// Resolve the upload-scoped DEK for a multipart upload. SSE-S3 unwraps the
    /// stored wrapped DEK via the active keyring. SSE-C derives the DEK from the
    /// customer key supplied on each `UploadPart` / `Complete` call, and rejects
    /// mismatched keys (MD5 compared against the value pinned at
    /// `CreateMultipartUpload`).
    fn resolve_upload_dek(
        &self,
        spec: &UploadEncryptionSpec,
        customer_key: Option<[u8; 32]>,
    ) -> Result<[u8; 32], StorageError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        match spec.mode {
            EncryptionMode::SseC => {
                let ck = customer_key.ok_or_else(|| {
                    StorageError::EncryptionError("SSE-C multipart: customer key required".into())
                })?;
                if let Some(ref stored) = spec.customer_key_md5 {
                    let provided_md5 = Md5::digest(ck);
                    if b64.encode(provided_md5) != *stored {
                        return Err(StorageError::EncryptionError(
                            "SSE-C key MD5 mismatch".into(),
                        ));
                    }
                }
                Ok(ck)
            }
            EncryptionMode::SseS3 => {
                let wrapped_b64 = spec.upload_dek_wrapped.as_ref().ok_or_else(|| {
                    StorageError::EncryptionError("missing upload_dek_wrapped".into())
                })?;
                let nonce_b64 = spec.upload_dek_wrap_nonce.as_ref().ok_or_else(|| {
                    StorageError::EncryptionError("missing upload_dek_wrap_nonce".into())
                })?;
                let kid = spec.upload_dek_key_id.as_ref().ok_or_else(|| {
                    StorageError::EncryptionError("missing upload_dek_key_id".into())
                })?;
                let wrapped = b64.decode(wrapped_b64).map_err(|_| {
                    StorageError::EncryptionError("bad upload_dek_wrapped base64".into())
                })?;
                let nonce_bytes = b64.decode(nonce_b64).map_err(|_| {
                    StorageError::EncryptionError("bad upload_dek_wrap_nonce base64".into())
                })?;
                if nonce_bytes.len() != 12 {
                    return Err(StorageError::EncryptionError(
                        "upload_dek_wrap_nonce must be 12 bytes".into(),
                    ));
                }
                let mut nonce_arr = [0u8; 12];
                nonce_arr.copy_from_slice(&nonce_bytes);
                self.keyring
                    .unwrap_dek(kid, &wrapped, &nonce_arr)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))
            }
        }
    }

    fn resolve_dek(
        &self,
        enc_meta: &EncryptionMeta,
        customer_key: Option<[u8; 32]>,
    ) -> Result<[u8; 32], StorageError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        match enc_meta.mode {
            EncryptionMode::SseC => {
                let ck = customer_key.ok_or_else(|| {
                    StorageError::DecryptionError("SSE-C: customer key required".into())
                })?;
                // Validate MD5 if recorded.
                if let Some(ref stored_md5_b64) = enc_meta.customer_key_md5 {
                    let provided_md5 = Md5::digest(&ck);
                    let provided_b64 = b64.encode(provided_md5);
                    if &provided_b64 != stored_md5_b64 {
                        return Err(StorageError::DecryptionError(
                            "SSE-C: customer key MD5 mismatch".into(),
                        ));
                    }
                }
                let (Some(wrapped), Some(wrap_nonce)) =
                    (enc_meta.wrapped_dek.as_ref(), enc_meta.wrap_nonce.as_ref())
                else {
                    // Legacy MaxIO SSE-C objects used the customer key directly.
                    return Ok(ck);
                };
                let wrapped_bytes = b64
                    .decode(wrapped)
                    .map_err(|_| StorageError::DecryptionError("bad wrapped_dek base64".into()))?;
                let nonce_bytes = b64
                    .decode(wrap_nonce)
                    .map_err(|_| StorageError::DecryptionError("bad wrap_nonce base64".into()))?;
                if nonce_bytes.len() != 12 {
                    return Err(StorageError::DecryptionError(
                        "wrap_nonce must be 12 bytes".into(),
                    ));
                }
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&ck));
                let plaintext = cipher
                    .decrypt(Nonce::from_slice(&nonce_bytes), wrapped_bytes.as_slice())
                    .map_err(|_| StorageError::DecryptionError("SSE-C DEK unwrap failed".into()))?;
                if plaintext.len() != 32 {
                    return Err(StorageError::DecryptionError(
                        "SSE-C DEK length invalid".into(),
                    ));
                }
                let mut dek = [0u8; 32];
                dek.copy_from_slice(&plaintext);
                Ok(dek)
            }
            EncryptionMode::SseS3 => {
                let key_id = enc_meta
                    .key_id
                    .as_ref()
                    .ok_or_else(|| StorageError::DecryptionError("missing key_id".into()))?;
                let wrapped = enc_meta
                    .wrapped_dek
                    .as_ref()
                    .ok_or_else(|| StorageError::DecryptionError("missing wrapped_dek".into()))?;
                let wrap_nonce = enc_meta
                    .wrap_nonce
                    .as_ref()
                    .ok_or_else(|| StorageError::DecryptionError("missing wrap_nonce".into()))?;
                let wrapped_bytes = b64
                    .decode(wrapped)
                    .map_err(|_| StorageError::DecryptionError("bad wrapped_dek base64".into()))?;
                let nonce_bytes = b64
                    .decode(wrap_nonce)
                    .map_err(|_| StorageError::DecryptionError("bad wrap_nonce base64".into()))?;
                if nonce_bytes.len() != 12 {
                    return Err(StorageError::DecryptionError(
                        "wrap_nonce must be 12 bytes".into(),
                    ));
                }
                let mut nonce_arr = [0u8; 12];
                nonce_arr.copy_from_slice(&nonce_bytes);
                self.keyring
                    .unwrap_dek(key_id, &wrapped_bytes, &nonce_arr)
                    .map_err(|e| StorageError::DecryptionError(e.to_string()))
            }
        }
    }

    /// Verify the bucket still exists. Called inside publish critical sections
    /// so a racing DeleteBucket cannot strand a new object in a half-deleted
    /// bucket (`create_dir_all` would silently resurrect the directory).
    async fn ensure_bucket_exists(&self, bucket: &str) -> Result<(), StorageError> {
        if !fs::try_exists(self.buckets_dir.join(bucket).join(".bucket.json")).await? {
            return Err(StorageError::NotFound(bucket.to_string()));
        }
        Ok(())
    }

    /// If the current top-level object predates versioning (its sidecar has no
    /// version_id), MOVE it into the version store as the "null" version
    /// instead of destroying it on overwrite/delete. Matches S3: enabling
    /// versioning must protect pre-existing data. The sidecar is stored
    /// verbatim (version_id stays None) because the encryption AAD and sidecar
    /// MAC are bound to the original identity. Caller must hold the key lock.
    async fn archive_null_version_if_needed(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        let meta = match self.read_object_meta(bucket, key).await {
            Ok(m) => m,
            Err(StorageError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if meta.version_id.is_some() {
            return Ok(()); // already tracked in the version store
        }
        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;
        // Sidecar FIRST: if a crash interrupts the data move below, the
        // archived null version is already addressable, so the bytes stay
        // reachable via `?versionId=null` whichever side of the move they
        // ended up on.
        write_file_atomic(
            &ver_dir.join("null.meta.json"),
            serde_json::to_string_pretty(&meta)?.as_bytes(),
        )
        .await?;
        let ec_dir = self.ec_dir(bucket, key);
        if Self::is_chunked_path(&ec_dir).await {
            let dst = ver_dir.join("null.ec");
            remove_dir_all_if_exists(&dst).await?;
            fs::rename(&ec_dir, &dst).await?;
            sync_parent_dir(&dst).await?;
            sync_parent_dir(&ec_dir).await?;
        } else {
            let obj_path = self.plain_object_read_path(bucket, key).await;
            if matches!(fs::metadata(&obj_path).await, Ok(m) if m.is_file()) {
                let dst = ver_dir.join("null.data");
                fs::rename(&obj_path, &dst).await?;
                sync_parent_dir(&dst).await?;
                sync_parent_dir(&obj_path).await?;
            }
        }
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;
        sync_parent_dir(&self.meta_path(bucket, key)).await?;
        Ok(())
    }

    /// Roll back after a failed versioned publish: drop any phantom version
    /// files written for the failed PUT, then re-promote the newest intact
    /// version (possibly the just-archived null version) to current so a
    /// failed overwrite never leaves the object 404ing. Best-effort — the
    /// original error is what the caller returns. Caller must hold the key
    /// lock.
    async fn rollback_failed_versioned_publish(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) {
        if let Some(vid) = version_id {
            let ver_dir = self.versions_dir(bucket, key);
            let _ = fs::remove_file(ver_dir.join(format!("{}.data", vid))).await;
            let _ = fs::remove_file(ver_dir.join(format!("{}.meta.json", vid))).await;
            let _ = fs::remove_dir_all(ver_dir.join(format!("{}.ec", vid))).await;
        }
        if let Err(e) = self.update_current_version(bucket, key).await {
            tracing::warn!(
                "failed to restore current version of {}/{} after failed publish: {}",
                bucket,
                key,
                e
            );
        }
    }

    /// Write a new version to the `.versions/` directory. `data_path` is the
    /// not-yet-published temp payload, so the snapshot can never race a
    /// concurrent overwrite of the live path. Caller must hold the key lock.
    async fn write_version(
        &self,
        bucket: &str,
        key: &str,
        meta: &ObjectMeta,
        data_path: &Path,
    ) -> Result<(), StorageError> {
        let version_id = meta.version_id.as_ref().unwrap();
        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;

        // Copy data to version store, durably.
        let ver_data = ver_dir.join(format!("{}.data", version_id));
        fs::copy(data_path, &ver_data).await?;
        sync_file(&ver_data).await?;
        sync_parent_dir(&ver_data).await?;

        // Write version metadata (atomic: a crash can leave an orphan .data
        // file, but never a torn sidecar).
        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        write_file_atomic(&ver_meta, serde_json::to_string_pretty(meta)?.as_bytes()).await?;

        Ok(())
    }

    /// Write a new chunked version by copying `src_ec` (the not-yet-published
    /// temp EC dir) to `.versions/{key}/{version_id}.ec/`.
    async fn write_version_chunked(
        &self,
        bucket: &str,
        key: &str,
        meta: &ObjectMeta,
        src_ec: &Path,
    ) -> Result<(), StorageError> {
        let version_id = meta.version_id.as_ref().unwrap();
        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;

        let dst_ec = ver_dir.join(format!("{}.ec", version_id));
        fs::create_dir_all(&dst_ec).await?;
        let mut entries = fs::read_dir(src_ec).await?;
        while let Some(entry) = entries.next_entry().await? {
            let dest = dst_ec.join(entry.file_name());
            fs::copy(entry.path(), &dest).await?;
            sync_file(&dest).await?;
        }
        sync_dir(&dst_ec).await?;

        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        write_file_atomic(&ver_meta, serde_json::to_string_pretty(meta)?.as_bytes()).await?;

        Ok(())
    }

    /// Write a delete marker version and remove the top-level files.
    /// Caller must hold the key lock.
    async fn write_delete_marker(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
        // Protect a pre-versioning object before the top-level files go away.
        self.archive_null_version_if_needed(bucket, key).await?;
        let version_id = Self::generate_version_id();
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let marker_meta = ObjectMeta {
            key: key.to_string(),
            size: 0,
            etag: String::new(),
            content_type: String::new(),
            last_modified: now,
            version_id: Some(version_id.clone()),
            is_delete_marker: true,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
            tags: None,
            part_sizes: None,
            encryption: None,
            ..Default::default()
        };

        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;
        let ver_meta_path = ver_dir.join(format!("{}.meta.json", version_id));
        write_file_atomic(
            &ver_meta_path,
            serde_json::to_string_pretty(&marker_meta)?.as_bytes(),
        )
        .await?;

        // Remove top-level current files (the pre-versioning object, if any,
        // was already archived as the "null" version above).
        let _ = remove_plain_payload(&self.object_path(bucket, key)).await;
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;
        let _ = fs::remove_dir_all(self.ec_dir(bucket, key)).await;

        Ok(DeleteResult {
            version_id: Some(version_id),
            is_delete_marker: true,
        })
    }

    /// Scan versions for a key and update the top-level files to reflect the
    /// latest non-delete-marker version. Caller must hold the key lock.
    async fn update_current_version(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        let ver_dir = self.versions_dir(bucket, key);
        if !fs::try_exists(&ver_dir).await.unwrap_or(false) {
            // No versions left. A top-level object that carries a version id
            // is a copy of a version that was just removed — drop it. A
            // pre-versioning ("null") object stays.
            if let Ok(meta) = self.read_object_meta(bucket, key).await {
                if meta.version_id.is_some() {
                    let _ = remove_plain_payload(&self.object_path(bucket, key)).await;
                    let _ = fs::remove_file(self.meta_path(bucket, key)).await;
                    let _ = fs::remove_dir_all(self.ec_dir(bucket, key)).await;
                }
            }
            return Ok(());
        }
        // A top-level null-version object (written while versioning was
        // suspended) is never archived in .versions and is newer than every
        // archived version, so it stays current.
        if let Ok(meta) = self.read_object_meta(bucket, key).await {
            if meta.version_id.is_none() {
                return Ok(());
            }
        }

        // Collect version ids (sidecar filenames minus suffix). Timestamped
        // ids sort chronologically; the archived "null" version is by
        // definition the oldest.
        let mut version_ids = Vec::new();
        let mut entries = fs::read_dir(&ver_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let fname = entry.file_name().to_string_lossy().to_string();
            if let Some(vid) = fname.strip_suffix(".meta.json") {
                version_ids.push(vid.to_string());
            }
        }
        version_ids.sort_by(|a, b| match (a.as_str() == "null", b.as_str() == "null") {
            (true, false) => std::cmp::Ordering::Greater, // null last (oldest)
            (false, true) => std::cmp::Ordering::Less,
            _ => b.cmp(a), // newest first
        });

        for vid in &version_ids {
            let meta_path = ver_dir.join(format!("{}.meta.json", vid));
            // A corrupt or unreadable version sidecar must not block recovery
            // of older, intact versions.
            let meta: ObjectMeta = match fs::read_to_string(&meta_path).await {
                Ok(data) => match serde_json::from_str(&data) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(
                            "skipping corrupt version sidecar {}: {}",
                            meta_path.display(),
                            e
                        );
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "skipping unreadable version sidecar {}: {}",
                        meta_path.display(),
                        e
                    );
                    continue;
                }
            };
            if meta.is_delete_marker {
                // The newest version is a delete marker: the key has no
                // current object. Older versions must not be resurrected.
                break;
            }

            // Restore this version as current, via the same atomic + durable
            // publish path as a regular PUT.
            let obj_meta_path = self.meta_path(bucket, key);
            let tmp_meta = temp_sibling_path(&obj_meta_path);
            let mut tmp_meta_guard = TempPathGuard::file(tmp_meta.clone());
            fs::write(&tmp_meta, serde_json::to_string_pretty(&meta)?).await?;

            let ver_ec = ver_dir.join(format!("{}.ec", vid));
            if ver_ec.is_dir() {
                let dst_ec = self.ec_dir(bucket, key);
                let tmp_ec = temp_sibling_path(&dst_ec);
                let mut tmp_ec_guard = TempPathGuard::dir(tmp_ec.clone());
                fs::create_dir_all(&tmp_ec).await?;
                let mut ec_entries = fs::read_dir(&ver_ec).await?;
                while let Some(entry) = ec_entries.next_entry().await? {
                    let dest = tmp_ec.join(entry.file_name());
                    fs::copy(entry.path(), &dest).await?;
                    sync_file(&dest).await?;
                }
                publish_temp_payload_and_meta(
                    &tmp_ec,
                    &dst_ec,
                    true,
                    &tmp_meta,
                    &obj_meta_path,
                    &self.fault,
                )
                .await?;
                tmp_ec_guard.disarm();
                tmp_meta_guard.disarm();
                remove_plain_payload(&self.object_path(bucket, key)).await?;
            } else {
                let ver_data = ver_dir.join(format!("{}.data", vid));
                let obj_path = self.plain_object_write_path(bucket, key).await?;
                let tmp_data = temp_sibling_path(&obj_path);
                let mut tmp_data_guard = TempPathGuard::file(tmp_data.clone());
                fs::copy(&ver_data, &tmp_data).await?;
                publish_temp_payload_and_meta(
                    &tmp_data,
                    &obj_path,
                    false,
                    &tmp_meta,
                    &obj_meta_path,
                    &self.fault,
                )
                .await?;
                tmp_data_guard.disarm();
                tmp_meta_guard.disarm();
                remove_dir_all_if_exists(&self.ec_dir(bucket, key)).await?;
            }

            if vid == "null" {
                // The null version lives at the top level again; drop the
                // archived copy so it cannot be listed twice.
                let _ = fs::remove_file(ver_dir.join("null.data")).await;
                let _ = fs::remove_dir_all(ver_dir.join("null.ec")).await;
                let _ = fs::remove_file(ver_dir.join("null.meta.json")).await;
            }
            return Ok(());
        }

        // Newest version is a delete marker (or only markers remain) — remove top-level files
        let _ = remove_plain_payload(&self.object_path(bucket, key)).await;
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;
        let _ = fs::remove_dir_all(self.ec_dir(bucket, key)).await;
        Ok(())
    }

    pub async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        customer_key: Option<[u8; 32]>,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        validate_version_id(version_id)?;
        if version_id == "null"
            && !fs::try_exists(self.version_meta_path(bucket, key, "null")).await?
        {
            // No archived null version — the current object must be it.
            let (stream, meta) = self.get_object(bucket, key, customer_key).await?;
            if meta.version_id.is_some() {
                return Err(StorageError::VersionNotFound("null".into()));
            }
            return Ok((stream, meta));
        }
        let ver_meta_path = self.version_meta_path(bucket, key, version_id);
        let data = fs::read_to_string(&ver_meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: ObjectMeta = serde_json::from_str(&data)?;

        if meta.is_delete_marker {
            return Err(StorageError::NotFound(key.to_string()));
        }
        reject_sse_c_on_plaintext(&meta, customer_key.is_some())?;

        // Check for chunked version
        let ver_ec_dir = self
            .versions_dir(bucket, key)
            .join(format!("{}.ec", version_id));
        if ver_ec_dir.is_dir() {
            let manifest_path = ver_ec_dir.join("manifest.json");
            let manifest_data = fs::read_to_string(&manifest_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::VersionNotFound(version_id.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            let manifest: ChunkManifest = serde_json::from_str(&manifest_data)?;
            if let Some(ref enc_meta) = meta.encryption {
                let dek = self.resolve_dek(enc_meta, customer_key)?;
                verify_sidecar_mac(&meta, &dek)?;
                let frame_size = enc_meta.chunk_size as usize;
                let plaintext_size = meta.size;
                let aad_builder = object_aad_builder(bucket, key, meta.version_id.as_deref());
                let ct_reader = VerifiedChunkReader::new(ver_ec_dir, manifest);
                let decryptor = FrameDecryptor::new(
                    Box::pin(ct_reader),
                    &dek,
                    plaintext_size,
                    frame_size,
                    aad_builder,
                );
                return Ok((Box::pin(decryptor), meta));
            }
            let reader = VerifiedChunkReader::new(ver_ec_dir, manifest);
            return Ok((Box::pin(reader), meta));
        }

        let ver_data_path = self.version_data_path(bucket, key, version_id);

        // Encrypted version — resolve DEK, verify sidecar MAC, wrap in
        // FrameDecryptor with the same AAD scheme used for live GET so a
        // version file cannot be silently swapped across objects.
        if let Some(ref enc_meta) = meta.encryption {
            let dek = self.resolve_dek(enc_meta, customer_key)?;
            verify_sidecar_mac(&meta, &dek)?;
            let chunk_size = enc_meta.chunk_size as usize;
            let plaintext_size = meta.size;
            let file = fs::File::open(&ver_data_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::VersionNotFound(version_id.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            let aad_builder = object_aad_builder(bucket, key, meta.version_id.as_deref());
            let decryptor = FrameDecryptor::new(
                Box::pin(file),
                &dek,
                plaintext_size,
                chunk_size,
                aad_builder,
            );
            return Ok((Box::pin(decryptor), meta));
        }

        let file = fs::File::open(&ver_data_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok((
            Box::pin(BufReader::with_capacity(IO_BUFFER_SIZE, file)),
            meta,
        ))
    }

    pub async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
        validate_version_id(version_id)?;
        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;
        if version_id == "null" {
            let null_meta_path = self.version_meta_path(bucket, key, "null");
            if fs::try_exists(&null_meta_path).await? {
                // Archived null version: remove it from the store only — the
                // top-level object is a different (newer) version.
                let data = fs::read_to_string(&null_meta_path).await?;
                let meta: ObjectMeta = serde_json::from_str(&data)?;
                let _ = fs::remove_file(&null_meta_path).await;
                let _ = fs::remove_file(self.version_data_path(bucket, key, "null")).await;
                let _ = fs::remove_dir_all(self.versions_dir(bucket, key).join("null.ec")).await;
                return Ok(meta);
            }
            let meta = self.read_object_meta(bucket, key).await?;
            if meta.version_id.is_some() {
                return Err(StorageError::VersionNotFound("null".into()));
            }
            remove_plain_payload(&self.object_path(bucket, key)).await?;
            remove_file_if_exists(&self.meta_path(bucket, key)).await?;
            remove_dir_all_if_exists(&self.ec_dir(bucket, key)).await?;
            self.update_current_version(bucket, key).await?;
            return Ok(meta);
        }
        let ver_meta_path = self.version_meta_path(bucket, key, version_id);
        let data = fs::read_to_string(&ver_meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: ObjectMeta = serde_json::from_str(&data)?;

        // Remove version files
        let _ = fs::remove_file(&ver_meta_path).await;
        let ver_data_path = self.version_data_path(bucket, key, version_id);
        let _ = fs::remove_file(&ver_data_path).await;
        let ver_ec_dir = self
            .versions_dir(bucket, key)
            .join(format!("{}.ec", version_id));
        let _ = fs::remove_dir_all(&ver_ec_dir).await;

        // Clean up empty versions dir
        let ver_dir = self.versions_dir(bucket, key);
        let _ = fs::remove_dir(&ver_dir).await; // only succeeds if empty

        // Update current version (in case we deleted the latest or a delete marker)
        self.update_current_version(bucket, key).await?;

        Ok(meta)
    }

    pub async fn list_object_versions(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_bucket_name(bucket)?;
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut results = Vec::new();
        self.walk_versions(&bucket_dir, &bucket_dir, prefix, &mut results)
            .await?;
        // Sort by key, then by version_id descending (newest first per key);
        // an archived null version (no id) sorts last as the oldest.
        results.sort_by(|a, b| {
            a.key.cmp(&b.key).then_with(|| {
                let va = a.version_id.as_deref().unwrap_or("");
                let vb = b.version_id.as_deref().unwrap_or("");
                vb.cmp(va)
            })
        });
        // S3's suspended state can have a current "null" version outside
        // .versions. It is the newest version of its key, so list it first.
        for obj in self.list_objects(bucket, prefix).await? {
            if obj.version_id.is_none() {
                let pos = results.partition_point(|v| v.key < obj.key);
                results.insert(pos, obj);
            }
        }
        Ok(results)
    }

    fn walk_versions<'a>(
        &'a self,
        base: &'a Path,
        dir: &'a Path,
        prefix: &'a str,
        results: &'a mut Vec<ObjectMeta>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = match fs::read_dir(dir).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let fname = entry.file_name().to_string_lossy().to_string();

                if !entry.file_type().await?.is_dir() {
                    continue;
                }

                if fname == ".versions" {
                    // Scan all key dirs inside .versions
                    let mut key_dirs = match fs::read_dir(&path).await {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    while let Some(key_entry) = key_dirs.next_entry().await? {
                        if !key_entry.file_type().await?.is_dir() {
                            continue;
                        }
                        let key_name = key_entry.file_name().to_string_lossy().to_string();
                        // Reconstruct the object key from the directory structure
                        let parent_rel = dir.strip_prefix(base).unwrap_or(Path::new(""));
                        let key = if parent_rel.as_os_str().is_empty() {
                            key_name.clone()
                        } else {
                            format!("{}/{}", parent_rel.to_string_lossy(), key_name)
                        };
                        if !key.starts_with(prefix) {
                            continue;
                        }
                        // Read all version meta files in this key's version dir
                        let key_ver_dir = key_entry.path();
                        let mut ver_entries = match fs::read_dir(&key_ver_dir).await {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        while let Some(ve) = ver_entries.next_entry().await? {
                            let vf = ve.file_name().to_string_lossy().to_string();
                            if vf.ends_with(".meta.json") {
                                if let Ok(data) = fs::read_to_string(ve.path()).await {
                                    if let Ok(meta) = serde_json::from_str::<ObjectMeta>(&data) {
                                        results.push(meta);
                                    }
                                }
                            }
                        }
                    }
                } else if fname != ".uploads" && fname != ".bucket.json" {
                    self.walk_versions(base, &path, prefix, results).await?;
                }
            }
            Ok(())
        })
    }
}

/// Encrypt and write one frame: [nonce:12B][ciphertext||tag:16B]. The AAD
/// binds the frame to object identity (bucket/key/version/chunk_index).
async fn write_encrypted_frame(
    writer: &mut BufWriter<fs::File>,
    cipher: &Aes256Gcm,
    nonce_prefix: &[u8],
    chunk_index: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(), StorageError> {
    let nonce_bytes = make_frame_nonce(nonce_prefix, chunk_index)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| StorageError::EncryptionError("frame encryption failed".into()))?;
    writer.write_all(&nonce_bytes).await?;
    writer.write_all(&ciphertext).await?;
    Ok(())
}

/// Encrypt one frame and return the `[nonce || ciphertext || tag]` bytes. Used
/// by the EC+encryption write path, which buffers ciphertext in memory before
/// flushing chunk-sized slices to disk.
fn encrypt_frame_to_vec(
    cipher: &Aes256Gcm,
    nonce_prefix: &[u8],
    chunk_index: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let nonce_bytes = make_frame_nonce(nonce_prefix, chunk_index)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| StorageError::EncryptionError("frame encryption failed".into()))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn make_frame_nonce(prefix: &[u8], chunk_index: u64) -> Result<[u8; 12], StorageError> {
    let mut nonce = [0u8; 12];
    match prefix.len() {
        4 => {
            nonce[..4].copy_from_slice(prefix);
            nonce[4..].copy_from_slice(&chunk_index.to_le_bytes());
        }
        8 => {
            if chunk_index > u32::MAX as u64 {
                return Err(StorageError::EncryptionError(
                    "object has too many encrypted frames for nonce format".into(),
                ));
            }
            nonce[..8].copy_from_slice(prefix);
            nonce[8..].copy_from_slice(&(chunk_index as u32).to_le_bytes());
        }
        _ => {
            return Err(StorageError::EncryptionError(
                "nonce_prefix must be 4 or 8 bytes".into(),
            ));
        }
    }
    Ok(nonce)
}

async fn remove_file_if_exists(path: &Path) -> Result<(), StorageError> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StorageError::Io(e)),
    }
}

async fn remove_dir_all_if_exists(path: &Path) -> Result<(), StorageError> {
    match fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StorageError::Io(e)),
    }
}

// ---- object-level extensions: conditional writes, version reads, delete markers ----

/// Apply metadata + tags captured at CreateMultipartUpload to the final sidecar.
fn apply_upload_metadata(upload_meta: &MultipartUploadMeta, meta: &mut ObjectMeta) {
    meta.metadata = upload_meta.object_metadata.clone();
    meta.tags = upload_meta.tags.clone();
}

/// `If-Match` style comparison: `*`, quoted/unquoted, comma-separated lists.
fn etag_list_matches(header_value: &str, etag: &str) -> bool {
    let value = header_value.trim();
    if value == "*" {
        return true;
    }
    let etag = etag.trim_matches('"');
    value
        .split(',')
        .any(|part| part.trim().trim_start_matches("W/").trim_matches('"') == etag)
}

impl FilesystemStorage {
    /// Evaluate a write precondition against the current object. Caller must
    /// hold the key lock so the check and the publish are atomic.
    async fn check_write_precondition(
        &self,
        bucket: &str,
        key: &str,
        precondition: Option<&WritePrecondition>,
    ) -> Result<(), StorageError> {
        let Some(precondition) = precondition else {
            return Ok(());
        };
        let current = match self.read_object_meta(bucket, key).await {
            Ok(m) if !m.is_delete_marker => Some(m),
            Ok(_) | Err(StorageError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };
        match (precondition, current) {
            (WritePrecondition::IfNoneMatchAny, None) => Ok(()),
            (WritePrecondition::IfNoneMatchAny, Some(_)) => Err(StorageError::PreconditionFailed),
            (WritePrecondition::IfNoneMatch(_), None) => Ok(()),
            (WritePrecondition::IfNoneMatch(expected), Some(m)) => {
                if etag_list_matches(expected, &m.etag) {
                    Err(StorageError::PreconditionFailed)
                } else {
                    Ok(())
                }
            }
            (WritePrecondition::IfMatch(_), None) => Err(StorageError::NotFound(key.to_string())),
            (WritePrecondition::IfMatch(expected), Some(m)) => {
                if expected.trim() == "*" || etag_list_matches(expected, &m.etag) {
                    Ok(())
                } else {
                    Err(StorageError::PreconditionFailed)
                }
            }
        }
    }

    /// Open a ranged reader over an object payload located at `ec_dir` (EC)
    /// or `obj_path` (single file). `meta` must describe that payload.
    async fn open_range_reader(
        &self,
        bucket: &str,
        key: &str,
        meta: ObjectMeta,
        ec_dir: PathBuf,
        obj_path: &Path,
        offset: u64,
        length: u64,
        customer_key: Option<[u8; 32]>,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        if Self::is_chunked_path(&ec_dir).await {
            let manifest: ChunkManifest =
                match fs::read_to_string(ec_dir.join("manifest.json")).await {
                    Ok(data) => serde_json::from_str(&data)?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(StorageError::NotFound(key.to_string()));
                    }
                    Err(e) => return Err(StorageError::Io(e)),
                };
            if let Some(ref enc_meta) = meta.encryption {
                let dek = self.resolve_dek(enc_meta, customer_key)?;
                verify_sidecar_mac(&meta, &dek)?;
                let frame_size = enc_meta.chunk_size as usize;
                let ct_offset = FrameDecryptor::ciphertext_offset(frame_size, offset);
                let ct_total = manifest.total_size;
                let ct_length = ct_total.saturating_sub(ct_offset);
                let aad_builder = object_aad_builder(bucket, key, meta.version_id.as_deref());
                let ct_reader =
                    VerifiedChunkReader::with_range(ec_dir, manifest, ct_offset, ct_length);
                let decryptor = FrameDecryptor::for_range(
                    Box::pin(ct_reader),
                    &dek,
                    meta.size,
                    frame_size,
                    offset,
                    length,
                    aad_builder,
                );
                return Ok((Box::pin(decryptor), meta));
            }
            let reader = VerifiedChunkReader::with_range(ec_dir, manifest, offset, length);
            return Ok((Box::pin(reader), meta));
        }
        // Encrypted object — seek to frame boundary and wrap in ranged FrameDecryptor
        if let Some(ref enc_meta) = meta.encryption {
            let dek = self.resolve_dek(enc_meta, customer_key)?;
            verify_sidecar_mac(&meta, &dek)?;
            let chunk_size = enc_meta.chunk_size as usize;
            let ct_offset = FrameDecryptor::ciphertext_offset(chunk_size, offset);
            let mut file = fs::File::open(obj_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound(key.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            file.seek(std::io::SeekFrom::Start(ct_offset))
                .await
                .map_err(StorageError::Io)?;
            let aad_builder = object_aad_builder(bucket, key, meta.version_id.as_deref());
            let decryptor = FrameDecryptor::for_range(
                Box::pin(file),
                &dek,
                meta.size,
                chunk_size,
                offset,
                length,
                aad_builder,
            );
            return Ok((Box::pin(decryptor), meta));
        }
        if length <= SMALL_OBJECT_THRESHOLD {
            let mut file = fs::File::open(obj_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound(key.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(StorageError::Io)?;
            let mut data = vec![0u8; length as usize];
            file.read_exact(&mut data).await.map_err(StorageError::Io)?;
            return Ok((Box::pin(std::io::Cursor::new(data)), meta));
        }
        let mut file = fs::File::open(obj_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(StorageError::Io)?;
        let limited = file.take(length);
        let reader = BufReader::with_capacity(IO_BUFFER_SIZE, limited);
        Ok((Box::pin(reader), meta))
    }

    /// Read a version sidecar verbatim — delete markers included.
    pub async fn version_meta(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        validate_version_id(version_id)?;
        if version_id == "null"
            && !fs::try_exists(self.version_meta_path(bucket, key, "null")).await?
        {
            let meta = match self.read_object_meta(bucket, key).await {
                Ok(m) => m,
                Err(StorageError::NotFound(_)) => {
                    return Err(StorageError::VersionNotFound("null".into()));
                }
                Err(e) => return Err(e),
            };
            if meta.version_id.is_some() {
                return Err(StorageError::VersionNotFound("null".into()));
            }
            return Ok(meta);
        }
        let path = self.version_meta_path(bucket, key, version_id);
        let data = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    /// When `key` has no current object because its newest version is a
    /// delete marker, return that marker's version id.
    pub async fn current_delete_marker(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<String>, StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        match self.read_object_meta(bucket, key).await {
            Ok(m) if !m.is_delete_marker => return Ok(None),
            Ok(_) | Err(StorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let ver_dir = self.versions_dir(bucket, key);
        let mut entries = match fs::read_dir(&ver_dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut newest: Option<String> = None;
        while let Some(entry) = entries.next_entry().await? {
            let fname = entry.file_name().to_string_lossy().to_string();
            if let Some(vid) = fname.strip_suffix(".meta.json") {
                if vid == "null" {
                    continue; // the archived null version is always the oldest
                }
                if newest.as_deref().is_none_or(|n| vid > n) {
                    newest = Some(vid.to_string());
                }
            }
        }
        let Some(vid) = newest else {
            return Ok(None);
        };
        let meta = self.version_meta(bucket, key, &vid).await?;
        Ok(meta.is_delete_marker.then_some(vid))
    }

    /// Ranged read of a specific version (`get_object_range` for versions).
    pub async fn get_object_version_range(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        offset: u64,
        length: u64,
        customer_key: Option<[u8; 32]>,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validate_bucket_name(bucket)?;
        validate_readable_key(key)?;
        validate_version_id(version_id)?;
        if version_id == "null"
            && !fs::try_exists(self.version_meta_path(bucket, key, "null")).await?
        {
            let (stream, meta) = self
                .get_object_range(bucket, key, offset, length, customer_key)
                .await?;
            if meta.version_id.is_some() {
                return Err(StorageError::VersionNotFound("null".into()));
            }
            return Ok((stream, meta));
        }
        let meta = self.version_meta(bucket, key, version_id).await?;
        if meta.is_delete_marker {
            return Err(StorageError::NotFound(key.to_string()));
        }
        reject_sse_c_on_plaintext(&meta, customer_key.is_some())?;
        let ver_ec_dir = self
            .versions_dir(bucket, key)
            .join(format!("{}.ec", version_id));
        let data_path = self.version_data_path(bucket, key, version_id);
        self.open_range_reader(
            bucket,
            key,
            meta,
            ver_ec_dir,
            &data_path,
            offset,
            length,
            customer_key,
        )
        .await
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    use crate::storage::keys::Keyring;
    use crate::storage::{BucketMeta, ObjectMeta};
    use std::io::Cursor;
    use std::time::{Duration, SystemTime};
    use tokio::io::AsyncReadExt;

    async fn storage_at(dir: &std::path::Path) -> FilesystemStorage {
        let keyring = Arc::new(Keyring::load(dir.to_str().unwrap(), None).await.unwrap());
        FilesystemStorage::new(dir.to_str().unwrap(), false, 1024 * 1024, 0, keyring)
            .await
            .unwrap()
    }

    fn bucket_meta(name: &str) -> BucketMeta {
        BucketMeta {
            name: name.to_string(),
            created_at: "2020-01-01T00:00:00.000Z".into(),
            region: "us-east-1".into(),
            versioning: false,
            cors_rules: None,
            encryption_config: None,
            public_read: false,
            public_list: false,
            versioning_suspended: false,
            tags: None,
            lifecycle: None,
        }
    }

    async fn put(storage: &FilesystemStorage, key: &str, body: &[u8]) {
        storage
            .put_object(
                "bkt",
                key,
                "text/plain",
                Box::pin(Cursor::new(body.to_vec())),
                None,
                None,
            )
            .await
            .unwrap();
    }

    async fn read_obj(storage: &FilesystemStorage, key: &str) -> (Vec<u8>, u64) {
        let (mut reader, meta) = storage.get_object("bkt", key, None).await.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        (buf, meta.size)
    }

    fn count_named(dir: &std::path::Path, prefix: &str) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .count()
    }

    #[tokio::test]
    async fn fault_before_rename_keeps_the_previous_object() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        put(&storage, "a.txt", b"hello").await;

        storage.arm_fault(FAULT_BEFORE_PAYLOAD_RENAME);
        let err = match storage
            .put_object(
                "bkt",
                "a.txt",
                "text/plain",
                Box::pin(Cursor::new(b"hello world".to_vec())),
                None,
                None,
            )
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("put should fail before the payload is published"),
        };
        assert!(err.to_string().contains("injected fault"), "{err}");

        let (body, size) = read_obj(&storage, "a.txt").await;
        assert_eq!(body, b"hello");
        assert_eq!(size, 5);
        let bucket = tmp.path().join("buckets/bkt");
        assert_eq!(count_named(&bucket, ".maxio-tmp-"), 0);
    }

    #[tokio::test]
    async fn fault_after_rename_is_repaired_from_the_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        put(&storage, "a.txt", b"hello").await;

        storage.arm_fault(FAULT_AFTER_PAYLOAD_RENAME);
        let err = match storage
            .put_object(
                "bkt",
                "a.txt",
                "text/plain",
                Box::pin(Cursor::new(b"hello world".to_vec())),
                None,
                None,
            )
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("put should fail after the payload rename"),
        };
        assert!(err.to_string().contains("injected fault"), "{err}");

        let data = std::fs::read(tmp.path().join("buckets/bkt/a.txt")).unwrap();
        assert_eq!(data, b"hello world");
        let meta: ObjectMeta = serde_json::from_str(
            &std::fs::read_to_string(tmp.path().join("buckets/bkt/a.txt.meta.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(meta.size, 5, "old sidecar must stay until repair");

        let report = crate::storage::check::check(tmp.path(), true)
            .await
            .unwrap();
        assert!(
            report.issues.iter().any(|issue| issue.kind
                == crate::storage::check::IssueKind::SizeMismatch
                && issue.repaired),
            "{:?}",
            report.issues
        );
        let (body, size) = read_obj(&storage, "a.txt").await;
        assert_eq!(body, b"hello world");
        assert_eq!(size, 11);
    }

    #[tokio::test]
    async fn housekeeping_keeps_fresh_temps_and_startup_removes_them() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        let bucket = tmp.path().join("buckets/bkt");
        std::fs::create_dir_all(&bucket).unwrap();
        let fresh = bucket.join(".maxio-tmp-fresh");
        let old = bucket.join(".maxio-tmp-old");
        std::fs::write(&fresh, b"live").unwrap();
        std::fs::write(&old, b"stale").unwrap();
        let old_path = old.clone();
        std::fs::File::options()
            .write(true)
            .open(&old_path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(SystemTime::now() - Duration::from_secs(48 * 3600)),
            )
            .unwrap();

        let upload = bucket.join(".uploads/dead");
        std::fs::create_dir_all(&upload).unwrap();
        std::fs::write(upload.join("1"), b"part").unwrap();

        storage.housekeeping_sweep(chrono::Duration::days(7)).await;
        assert!(
            fresh.exists(),
            "in-flight temp must survive the hourly sweep"
        );
        assert!(!old.exists(), "day-old temp is crash debris");

        let (uploads, artifacts) = storage.startup_recover().await;
        assert!(!fresh.exists(), "startup has no in-flight writes");
        assert!(
            uploads >= 1,
            "upload without metadata is removed, got {uploads}"
        );
        assert!(
            artifacts >= 1,
            "fresh temp removed at startup, got {artifacts}"
        );
    }

    #[tokio::test]
    async fn put_over_the_object_cap_is_rejected_and_not_published() {
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = storage_at(tmp.path()).await;
        storage.set_upload_limits(4, 100, 150);
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        let err = storage
            .put_object(
                "bkt",
                "big.txt",
                "text/plain",
                Box::pin(Cursor::new(b"hello".to_vec())),
                None,
                None,
            )
            .await;
        assert!(matches!(err, Err(StorageError::EntityTooLarge)));
        assert!(storage.get_object("bkt", "big.txt", None).await.is_err());

        put(&storage, "ok.txt", b"hey").await;
        let (body, size) = read_obj(&storage, "ok.txt").await;
        assert_eq!(body, b"hey");
        assert_eq!(size, 3);
    }
}
