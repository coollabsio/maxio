use super::chunk_reader::VerifiedChunkReader;
use super::crypto::{AadBuilder, FRAME_CHUNK_SIZE, FrameDecryptor};
use super::keys::Keyring;
use super::{
    BucketEncryptionConfig, BucketMeta, ByteStream, ChecksumAlgorithm, ChunkInfo, ChunkKind,
    ChunkManifest, DeleteResult, EncryptionMeta, EncryptionMode, EncryptionRequest,
    MultipartUploadMeta, ObjectMeta, PartMeta, PutResult, StorageError, UploadEncryptionSpec,
    validate_bucket_name,
};
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
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter};

type HmacSha256 = Hmac<Sha256>;

const IO_BUFFER_SIZE: usize = 256 * 1024;
const SMALL_OBJECT_THRESHOLD: u64 = 256 * 1024;

enum ChecksumHasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl ChecksumHasher {
    fn new(algo: ChecksumAlgorithm) -> Self {
        match algo {
            ChecksumAlgorithm::CRC32 => Self::Crc32(crc32fast::Hasher::new()),
            ChecksumAlgorithm::CRC32C => Self::Crc32c(0),
            ChecksumAlgorithm::SHA1 => Self::Sha1(<sha1::Sha1 as Digest>::new()),
            ChecksumAlgorithm::SHA256 => Self::Sha256(<sha2::Sha256 as Digest>::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(data),
            Self::Crc32c(v) => *v = crc32c::crc32c_append(*v, data),
            Self::Sha1(h) => Digest::update(h, data),
            Self::Sha256(h) => Digest::update(h, data),
        }
    }

    fn finalize_base64(self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        match self {
            Self::Crc32(h) => b64.encode(h.finalize().to_be_bytes()),
            Self::Crc32c(v) => b64.encode(v.to_be_bytes()),
            Self::Sha1(h) => b64.encode(Digest::finalize(h)),
            Self::Sha256(h) => b64.encode(Digest::finalize(h)),
        }
    }
}

const KEY_LOCK_SHARDS: usize = 1024;
const BUCKET_LOCK_SHARDS: usize = 256;

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
fn validate_key(key: &str) -> Result<(), StorageError> {
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
            Component::Normal(seg) => {
                let name = seg.to_string_lossy();
                if is_reserved_segment(&name) {
                    return Err(StorageError::InvalidKey(format!(
                        "Key segment '{}' collides with an internal storage name",
                        name
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Reject key path segments that collide with internal on-disk names
/// (sidecars, bucket metadata, internal dirs, EC dirs, temp files).
fn is_reserved_segment(name: &str) -> bool {
    name.ends_with(".meta.json")
        || name.ends_with(".ec")
        || name == ".bucket.json"
        || name == ".uploads"
        || name == ".versions"
        || name == ".folder"
        || name.starts_with(".maxio-tmp-")
        || name.starts_with(".maxio-bak-")
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
fn object_aad_builder(bucket: &str, key: &str, version_id: Option<&str>) -> AadBuilder {
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
        Ok(Self {
            buckets_dir,
            erasure_coding,
            chunk_size,
            parity_shards,
            keyring,
            key_locks: (0..KEY_LOCK_SHARDS).map(|_| Default::default()).collect(),
            bucket_locks: (0..BUCKET_LOCK_SHARDS)
                .map(|_| Default::default())
                .collect(),
        })
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
                sync_parent_dir(&bucket_dir).await;
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
        mut body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
        encryption: Option<EncryptionRequest>,
        user_metadata: Option<HashMap<String, String>>,
    ) -> Result<PutResult, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;

        // Folder marker: zero-byte object with key ending in /
        if key.ends_with('/') {
            return self.put_folder_marker(bucket, key).await;
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
                        user_metadata,
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
                    user_metadata,
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

        let obj_path = self.object_path(bucket, key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }

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
            user_metadata,
            part_sizes: None,
            encryption: enc_meta_opt.take(),
        };
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
        user_metadata: Option<HashMap<String, String>>,
    ) -> Result<PutResult, StorageError> {
        validate_bucket_name(bucket)?;
        let ec_dir = self.ec_dir(bucket, key);
        let tmp_ec_dir = temp_sibling_path(&ec_dir);
        let mut tmp_ec_guard = TempPathGuard::dir(tmp_ec_dir.clone());
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
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
        let meta = ObjectMeta {
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
            user_metadata,
            part_sizes: None,
            encryption: None,
        };

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
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(&tmp_ec_dir, &ec_dir, true, &tmp_meta_path, &meta_path)
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
        remove_file_if_exists(&self.object_path(bucket, key)).await?;

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
        user_metadata: Option<HashMap<String, String>>,
    ) -> Result<PutResult, StorageError> {
        validate_bucket_name(bucket)?;
        let ec_dir = self.ec_dir(bucket, key);
        let tmp_ec_dir = temp_sibling_path(&ec_dir);
        let mut tmp_ec_guard = TempPathGuard::dir(tmp_ec_dir.clone());
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
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
            user_metadata,
            part_sizes: None,
            encryption: Some(enc_meta),
        };
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
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(&tmp_ec_dir, &ec_dir, true, &tmp_meta_path, &meta_path)
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
        remove_file_if_exists(&self.object_path(bucket, key)).await?;

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

/// Fsync the parent directory of `path` so a completed rename itself survives
/// power loss. Best-effort: a failure is logged, not propagated, because the
/// data blocks are already durable at this point.
async fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            let parent = parent.to_path_buf();
            let res = tokio::task::spawn_blocking(move || {
                std::fs::File::open(&parent).and_then(|f| f.sync_all())
            })
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!("directory fsync failed for {}: {}", path.display(), e)
                }
                Err(e) => tracing::warn!("directory fsync task failed: {}", e),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Durable atomic write for small metadata files (sidecars, `.bucket.json`,
/// version metadata, part metadata): temp sibling → fsync → rename over the
/// final path → parent-dir fsync. Readers see either the old or the new
/// complete file, never a torn one, and the result survives power loss.
async fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
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
    sync_parent_dir(path).await;
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
) -> Result<(), StorageError> {
    if let Some(parent) = final_payload.parent() {
        fs::create_dir_all(parent).await?;
    }
    if let Some(parent) = final_meta.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Make the new bytes durable BEFORE they become visible. Directory
    // payloads (EC) are synced chunk-by-chunk at write time.
    if !payload_is_dir {
        sync_file(tmp_payload).await?;
    }
    sync_file(tmp_meta).await?;

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

    sync_parent_dir(final_payload).await;
    if final_meta.parent() != final_payload.parent() {
        sync_parent_dir(final_meta).await;
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
        let object_meta = ObjectMeta {
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
            user_metadata: upload_meta.user_metadata.clone(),
            part_sizes: Some(part_sizes),
            encryption: None,
        };

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
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &object_meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(&tmp_ec_dir, &ec_dir, true, &tmp_meta_path, &meta_path)
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
        remove_file_if_exists(&self.object_path(bucket, key)).await?;
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
            user_metadata: upload_meta.user_metadata.clone(),
            part_sizes: Some(part_sizes),
            encryption: Some(enc_meta),
        };
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
        let publish_result: Result<(), StorageError> = async {
            if versioned {
                self.archive_null_version_if_needed(bucket, key).await?;
                self.write_version_chunked(bucket, key, &object_meta, &tmp_ec_dir)
                    .await?;
            }
            publish_temp_payload_and_meta(&tmp_ec_dir, &ec_dir, true, &tmp_meta_path, &meta_path)
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
        remove_file_if_exists(&self.object_path(bucket, key)).await?;
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

    async fn put_folder_marker(&self, bucket: &str, key: &str) -> Result<PutResult, StorageError> {
        let folder_dir = self
            .buckets_dir
            .join(bucket)
            .join(key.trim_end_matches('/'));
        fs::create_dir_all(&folder_dir).await?;

        let marker_path = folder_dir.join(".folder");
        fs::write(&marker_path, b"").await?;

        let etag = "\"d41d8cd98f00b204e9800998ecf8427e\"".to_string();
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let meta = ObjectMeta {
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
            user_metadata: None,
            part_sizes: None,
            encryption: None,
        };

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
        validate_key(key)?;
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
        let obj_path = self.object_path(bucket, key);
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
        validate_key(key)?;
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
        let obj_path = self.object_path(bucket, key);
        // Encrypted object — seek to frame boundary and wrap in ranged FrameDecryptor
        if let Some(ref enc_meta) = meta.encryption {
            let dek = self.resolve_dek(enc_meta, customer_key)?;
            verify_sidecar_mac(&meta, &dek)?;
            let chunk_size = enc_meta.chunk_size as usize;
            let ct_offset = FrameDecryptor::ciphertext_offset(chunk_size, offset);
            let mut file = fs::File::open(&obj_path).await.map_err(|e| {
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
            let mut file = fs::File::open(&obj_path).await.map_err(|e| {
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
        let mut file = fs::File::open(&obj_path).await.map_err(|e| {
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

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        Ok(meta)
    }

    pub async fn get_object_tagging(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<std::collections::HashMap<String, String>, StorageError> {
        validate_key(key)?;
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

    pub async fn delete_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;

        let _bucket_guard = self.bucket_read(bucket).await;
        let _key_guard = self.key_lock(bucket, key).await;

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
        remove_file_if_exists(&obj_path).await?;
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
        user_metadata: Option<HashMap<String, String>>,
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
            user_metadata,
            checksum_algorithm,
            encryption_spec,
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

        let upload_meta = self.read_upload_meta(bucket, upload_id).await?;
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
                return self
                    .complete_multipart_chunked_encrypted(
                        bucket,
                        upload_id,
                        &upload_meta,
                        &selected,
                        customer_key,
                    )
                    .await;
            }
            return self
                .complete_multipart_chunked(bucket, upload_id, &upload_meta, &selected)
                .await;
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

        let obj_path = self.object_path(bucket, &upload_meta.key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }
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
            tags: None,
            user_metadata: upload_meta.user_metadata,
            part_sizes: Some(part_sizes),
            encryption: enc_meta_opt,
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

        Ok(PutResult {
            size: total_size,
            etag,
            version_id,
            checksum_algorithm,
            checksum_value,
        })
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
            temp_removed += Self::sweep_stale_artifacts(&bucket_dir).await;
        }

        (uploads_removed, temp_removed)
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
    /// * `.maxio-tmp-*` entries older than `TEMP_STALE_AFTER_SECS` are removed.
    ///   The age gate matters: an in-flight upload keeps touching its temp
    ///   file, so a young temp may belong to a live request and must be kept.
    /// * `.maxio-bak-<name>` entries older than `BACKUP_STALE_AFTER_SECS` are
    ///   crash-stranded EC publish backups: if `<name>` is missing the publish
    ///   died mid-swap and the backup IS the committed object — restore it;
    ///   if `<name>` exists the publish completed and the backup is garbage.
    fn sweep_stale_artifacts(
        dir: &Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = u64> + Send + '_>> {
        const TEMP_STALE_AFTER_SECS: u64 = 24 * 3600;
        const BACKUP_STALE_AFTER_SECS: u64 = 3600;
        Box::pin(async move {
            let mut removed = 0u64;
            let mut entries = match fs::read_dir(dir).await {
                Ok(e) => e,
                Err(_) => return 0,
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();
                let path = entry.path();
                let is_dir = matches!(entry.file_type().await, Ok(ft) if ft.is_dir());

                if let Some(orig_name) = name.strip_prefix(".maxio-bak-") {
                    if orig_name.is_empty()
                        || !Self::entry_older_than(&path, BACKUP_STALE_AFTER_SECS).await
                    {
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

                if name.starts_with(".maxio-tmp-") {
                    if !Self::entry_older_than(&path, TEMP_STALE_AFTER_SECS).await {
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
                    removed += Self::sweep_stale_artifacts(&path).await;
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
        self.update_bucket_meta(bucket, |m| m.versioning = enabled)
            .await
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
        } else {
            let obj_path = self.object_path(bucket, key);
            if fs::try_exists(&obj_path).await? {
                fs::rename(&obj_path, ver_dir.join("null.data")).await?;
            }
        }
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;
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
            user_metadata: None,
            part_sizes: None,
            encryption: None,
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
        let _ = fs::remove_file(self.object_path(bucket, key)).await;
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
            return Ok(());
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
                continue;
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
                publish_temp_payload_and_meta(&tmp_ec, &dst_ec, true, &tmp_meta, &obj_meta_path)
                    .await?;
                tmp_ec_guard.disarm();
                tmp_meta_guard.disarm();
                remove_file_if_exists(&self.object_path(bucket, key)).await?;
            } else {
                let ver_data = ver_dir.join(format!("{}.data", vid));
                let obj_path = self.object_path(bucket, key);
                let tmp_data = temp_sibling_path(&obj_path);
                let mut tmp_data_guard = TempPathGuard::file(tmp_data.clone());
                fs::copy(&ver_data, &tmp_data).await?;
                publish_temp_payload_and_meta(
                    &tmp_data,
                    &obj_path,
                    false,
                    &tmp_meta,
                    &obj_meta_path,
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

        // All versions are delete markers — remove top-level files
        let _ = fs::remove_file(self.object_path(bucket, key)).await;
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
        validate_key(key)?;
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

    pub async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
        if version_id == "null"
            && !fs::try_exists(self.version_meta_path(bucket, key, "null")).await?
        {
            let meta = self.head_object(bucket, key).await?;
            if meta.version_id.is_some() {
                return Err(StorageError::VersionNotFound("null".into()));
            }
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
        if meta.is_delete_marker {
            return Err(StorageError::NotFound(key.to_string()));
        }
        Ok(meta)
    }

    pub async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validate_bucket_name(bucket)?;
        validate_key(key)?;
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
            remove_file_if_exists(&self.object_path(bucket, key)).await?;
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
        // S3's suspended state can have a current "null" version outside
        // .versions. Include it in version listings when present.
        for obj in self.list_objects(bucket, prefix).await? {
            if obj.version_id.is_none() {
                results.push(obj);
            }
        }
        // Sort by key, then by version_id descending (newest first per key)
        results.sort_by(|a, b| {
            a.key.cmp(&b.key).then_with(|| {
                let va = a.version_id.as_deref().unwrap_or("");
                let vb = b.version_id.as_deref().unwrap_or("");
                vb.cmp(va)
            })
        });
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
