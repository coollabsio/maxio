use super::chunk_reader::VerifiedChunkReader;
use super::crypto::{make_nonce, AadBuilder, FrameDecryptor, FRAME_CHUNK_SIZE};
use super::keys::Keyring;
use super::{
    BucketEncryptionConfig, BucketMeta, ByteStream, ChecksumAlgorithm, ChunkInfo, ChunkKind,
    ChunkManifest, DeleteResult, EncryptionMeta, EncryptionMode, EncryptionRequest,
    MultipartUploadMeta, ObjectMeta, PartMeta, PutResult, StorageError, UploadEncryptionSpec,
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

pub struct FilesystemStorage {
    buckets_dir: PathBuf,
    erasure_coding: bool,
    chunk_size: u64,
    parity_shards: u32,
    keyring: Arc<Keyring>,
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
            _ => {}
        }
    }
    Ok(())
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
    let enc = meta.encryption.as_ref().ok_or_else(|| {
        StorageError::IntegrityError("object has no encryption metadata".into())
    })?;
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
        })
    }

    // --- Bucket operations ---

    pub async fn create_bucket(&self, meta: &BucketMeta) -> Result<bool, StorageError> {
        let bucket_dir = self.buckets_dir.join(&meta.name);
        match fs::create_dir(&bucket_dir).await {
            Ok(()) => {
                let meta_path = bucket_dir.join(".bucket.json");
                let json = serde_json::to_string_pretty(meta)?;
                if let Err(e) = fs::write(&meta_path, json).await {
                    // Clean up the empty directory to avoid a half-created bucket
                    let _ = fs::remove_dir(&bucket_dir).await;
                    return Err(e.into());
                }
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn head_bucket(&self, name: &str) -> Result<bool, StorageError> {
        Ok(fs::try_exists(self.buckets_dir.join(name).join(".bucket.json")).await?)
    }

    pub async fn delete_bucket(&self, name: &str) -> Result<bool, StorageError> {
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

    fn chunk_path(&self, bucket: &str, key: &str, index: u32) -> PathBuf {
        self.ec_dir(bucket, key).join(format!("{:06}", index))
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
    ) -> Result<PutResult, StorageError> {
        validate_key(key)?;

        // Folder marker: zero-byte object with key ending in /
        if key.ends_with('/') {
            return self.put_folder_marker(bucket, key).await;
        }

        if self.erasure_coding {
            if encryption.is_some() {
                return Err(StorageError::EncryptionError(
                    "encryption + erasure coding not yet supported".into(),
                ));
            }
            return self
                .put_object_chunked(
                    bucket,
                    key,
                    content_type,
                    body,
                    checksum.as_ref().map(|(a, _)| *a),
                )
                .await;
        }

        // Determine version_id up front so it can be folded into the AAD.
        let versioned = self.is_versioned(bucket).await.unwrap_or(false);
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
            let mut prefix = [0u8; 4];
            prefix.copy_from_slice(&prefix_bytes);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
            (Some(cipher), prefix, Some(dek))
        } else {
            (None, [0u8; 4], None)
        };

        let obj_path = self.object_path(bucket, key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let file = fs::File::create(&obj_path).await?;
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
        fs::write(&meta_path, json).await?;

        if meta.encryption.is_some() {
            self.mark_bucket_encryption_required(bucket).await?;
        }

        if versioned {
            self.write_version(bucket, key, &meta, &obj_path).await?;
        }

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
    ) -> Result<PutResult, StorageError> {
        let ec_dir = self.ec_dir(bucket, key);
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::create_dir_all(&ec_dir).await?;

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
                    let ci = self
                        .write_chunk(bucket, key, chunk_index, &chunk_buf)
                        .await?;
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
                let ci = self
                    .write_chunk(bucket, key, chunk_index, &chunk_data)
                    .await?;
                chunks.push(ci);
                chunk_index += 1;
            }
        }

        // Handle empty object (zero chunks)
        if chunks.is_empty() {
            let ci = self.write_chunk(bucket, key, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;

        // Compute and write parity shards if configured (skip for empty objects)
        let has_parity = self.parity_shards > 0 && total_size > 0;
        if has_parity {
            let parity_infos = self.compute_and_write_parity(bucket, key, &chunks).await?;
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
        };
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(self.manifest_path(bucket, key), manifest_json).await?;

        let etag = hex::encode(md5_hasher.finalize());
        let etag_quoted = format!("\"{}\"", etag);
        let checksum_value = checksum_hasher.map(|h| h.finalize_base64());

        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let versioned = self.is_versioned(bucket).await.unwrap_or(false);
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
            part_sizes: None,
            encryption: None,
        };

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;

        if versioned {
            self.write_version_chunked(bucket, key, &meta).await?;
        }

        Ok(PutResult {
            size: total_size,
            etag: etag_quoted,
            version_id,
            checksum_algorithm: checksum_algo,
            checksum_value,
        })
    }

    async fn write_chunk(
        &self,
        bucket: &str,
        key: &str,
        index: u32,
        data: &[u8],
    ) -> Result<ChunkInfo, StorageError> {
        let path = self.chunk_path(bucket, key, index);
        let sha256 = hex::encode(Sha256::digest(data));
        let mut file = fs::File::create(&path).await?;
        file.write_all(data).await?;
        file.flush().await?;
        Ok(ChunkInfo {
            index,
            size: data.len() as u64,
            sha256,
            kind: ChunkKind::Data,
        })
    }

    /// Compute Reed-Solomon parity shards from the data chunks already on disk,
    /// write them as additional chunk files, and return their ChunkInfo entries.
    async fn compute_and_write_parity(
        &self,
        bucket: &str,
        key: &str,
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

        // Read data chunks from disk and pad to shard_size
        let mut all_shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
        for ci in data_chunks {
            let path = self.chunk_path(bucket, key, ci.index);
            let mut data = std::fs::read(&path).map_err(StorageError::Io)?;
            data.resize(shard_size, 0u8);
            all_shards.push(data);
        }

        // Allocate empty parity shards
        for _ in 0..m {
            all_shards.push(vec![0u8; shard_size]);
        }

        // Encode parity
        let rs = ReedSolomon::new(k, m)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon init error: {e}")))?;
        rs.encode(&mut all_shards)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon encode error: {e}")))?;

        // Write parity chunks to disk
        let mut parity_infos = Vec::with_capacity(m);
        for i in 0..m {
            let parity_index = k as u32 + i as u32;
            let shard = &all_shards[k + i];
            let sha256 = hex::encode(Sha256::digest(shard));
            let path = self.chunk_path(bucket, key, parity_index);
            let mut file = fs::File::create(&path).await?;
            file.write_all(shard).await?;
            file.flush().await?;
            parity_infos.push(ChunkInfo {
                index: parity_index,
                size: shard_size as u64,
                sha256,
                kind: ChunkKind::Parity,
            });
        }

        Ok(parity_infos)
    }

    async fn complete_multipart_chunked(
        &self,
        bucket: &str,
        upload_id: &str,
        upload_meta: &MultipartUploadMeta,
        selected: &[PartMeta],
    ) -> Result<PutResult, StorageError> {
        let key = &upload_meta.key;
        let ec_dir = self.ec_dir(bucket, key);
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::create_dir_all(&ec_dir).await?;

        let mut total_size = 0u64;
        let mut etag_hasher = Md5::new();
        let mut chunks: Vec<ChunkInfo> = Vec::new();
        let mut chunk_index: u32 = 0;
        let mut chunk_buf = Vec::with_capacity(self.chunk_size as usize);

        let mut buf = vec![0u8; IO_BUFFER_SIZE];
        for part in selected {
            let mut part_file =
                fs::File::open(self.part_path(bucket, upload_id, part.part_number)).await?;
            loop {
                let n = part_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                total_size += n as u64;
                chunk_buf.extend_from_slice(&buf[..n]);

                while chunk_buf.len() >= self.chunk_size as usize {
                    let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
                    let ci = self
                        .write_chunk(bucket, key, chunk_index, &chunk_data)
                        .await?;
                    chunks.push(ci);
                    chunk_index += 1;
                }
            }

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }

        // Flush remaining
        if !chunk_buf.is_empty() {
            let ci = self
                .write_chunk(bucket, key, chunk_index, &chunk_buf)
                .await?;
            chunks.push(ci);
        }

        if chunks.is_empty() {
            let ci = self.write_chunk(bucket, key, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;

        // Compute and write parity shards if configured (skip for empty objects)
        let has_parity = self.parity_shards > 0 && total_size > 0;
        if has_parity {
            let parity_infos = self.compute_and_write_parity(bucket, key, &chunks).await?;
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
        };
        fs::write(
            self.manifest_path(bucket, key),
            serde_json::to_string_pretty(&manifest)?,
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
            version_id: None,
            is_delete_marker: false,
            storage_format: Some(storage_format.to_string()),
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
            tags: None,
            part_sizes: Some(part_sizes),
            encryption: None,
        };

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&meta_path, serde_json::to_string_pretty(&object_meta)?).await?;
        let _ = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await;

        Ok(PutResult {
            size: total_size,
            etag,
            version_id: None,
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
            part_sizes: None,
            encryption: None,
        };

        let meta_path = folder_dir.join(".folder.meta.json");
        let json = serde_json::to_string_pretty(&meta)?;
        fs::write(&meta_path, json).await?;

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
        validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        self.check_encryption_required(bucket, &meta).await?;
        reject_sse_c_on_plaintext(&meta, customer_key.is_some())?;
        let ec_dir = self.ec_dir(bucket, key);
        if Self::is_chunked_path(&ec_dir).await {
            let manifest = self.read_manifest(bucket, key).await?;
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
        validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        self.check_encryption_required(bucket, &meta).await?;
        reject_sse_c_on_plaintext(&meta, customer_key.is_some())?;
        let ec_dir = self.ec_dir(bucket, key);
        if Self::is_chunked_path(&ec_dir).await {
            let manifest = self.read_manifest(bucket, key).await?;
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
        validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        self.check_encryption_required(bucket, &meta).await?;
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
        let mut meta = self.read_object_meta(bucket, key).await?;
        meta.tags = if tags.is_empty() { None } else { Some(tags) };
        let json = serde_json::to_string_pretty(&meta)?;
        fs::write(self.meta_path(bucket, key), json).await?;
        Ok(())
    }

    pub async fn delete_object_tagging(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        validate_key(key)?;
        let mut meta = self.read_object_meta(bucket, key).await?;
        meta.tags = None;
        let json = serde_json::to_string_pretty(&meta)?;
        fs::write(self.meta_path(bucket, key), json).await?;
        Ok(())
    }

    pub async fn delete_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
        validate_key(key)?;

        let versioned = self.is_versioned(bucket).await.unwrap_or(false);
        if versioned {
            return self.write_delete_marker(bucket, key).await;
        }

        let obj_path = self.object_path(bucket, key);
        let meta_path = self.meta_path(bucket, key);
        let ec_dir = self.ec_dir(bucket, key);

        let _ = fs::remove_file(&obj_path).await;
        let _ = fs::remove_file(&meta_path).await;
        let _ = fs::remove_dir_all(&ec_dir).await;

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
    ) -> Result<MultipartUploadMeta, StorageError> {
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
            let prefix = Keyring::generate_nonce_prefix();
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
        };

        let meta_json = serde_json::to_string_pretty(&meta)?;
        fs::write(self.upload_meta_path(bucket, &upload_id), meta_json).await?;
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
            let b64 = base64::engine::general_purpose::STANDARD;
            let dek = self.resolve_upload_dek(spec, customer_key)?;
            let prefix_bytes = b64
                .decode(&spec.upload_nonce_prefix)
                .map_err(|_| StorageError::EncryptionError("invalid upload_nonce_prefix".into()))?;
            if prefix_bytes.len() != 4 {
                return Err(StorageError::EncryptionError(
                    "upload_nonce_prefix must be 4 bytes".into(),
                ));
            }
            let mut prefix = [0u8; 4];
            prefix.copy_from_slice(&prefix_bytes);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
            (Some(cipher), prefix)
        } else {
            (None, [0u8; 4])
        };

        let part_path = self.part_path(bucket, upload_id, part_number);
        let file = fs::File::create(&part_path).await?;
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

        // Validate and compute checksum
        let (checksum_algorithm, checksum_value) = if let Some((algo, expected)) = checksum {
            let computed = checksum_hasher.unwrap().finalize_base64();
            if let Some(expected_val) = expected {
                if computed != expected_val {
                    let _ = fs::remove_file(&part_path).await;
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
            Some(fs::metadata(&part_path).await?.len())
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
        if let Err(e) = fs::write(
            self.part_meta_path(bucket, upload_id, part_number),
            serde_json::to_string_pretty(&meta)?,
        )
        .await
        {
            // Clean up orphaned part file on metadata write failure
            let _ = fs::remove_file(&part_path).await;
            return Err(e.into());
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
        validate_upload_id(upload_id)?;
        if parts.is_empty() {
            return Err(StorageError::InvalidKey(
                "at least one part is required to complete upload".into(),
            ));
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
                return Err(StorageError::EncryptionError(
                    "encryption + erasure coding not yet supported".into(),
                ));
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
        let upload_dek_opt: Option<[u8; 32]> =
            if let Some(ref spec) = upload_meta.encryption_spec {
                Some(self.resolve_upload_dek(spec, customer_key)?)
            } else {
                None
            };

        // Final object encryption (fresh DEK, distinct from the upload DEK).
        let enc_meta_opt: Option<EncryptionMeta> = if let Some(ref spec) = upload_meta.encryption_spec
        {
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
            let mut prefix = [0u8; 4];
            prefix.copy_from_slice(&prefix_bytes);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
            (Some(cipher), prefix, Some(dek))
        } else {
            (None, [0u8; 4], None)
        };

        let obj_path = self.object_path(bucket, &upload_meta.key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let out = fs::File::create(&obj_path).await?;
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
            loop {
                let n = part_stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                total_size += n as u64;
                if let Some(ref cipher) = cipher_opt {
                    frame_buf.extend_from_slice(&buf[..n]);
                    while frame_buf.len() >= FRAME_CHUNK_SIZE {
                        let frame_data: Vec<u8> =
                            frame_buf.drain(..FRAME_CHUNK_SIZE).collect();
                        let aad = build_frame_aad(bucket_for_aad, key_for_aad, None, chunk_index);
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

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }
        // Flush trailing partial frame
        if let Some(ref cipher) = cipher_opt {
            if !frame_buf.is_empty() {
                let aad = build_frame_aad(bucket_for_aad, key_for_aad, None, chunk_index);
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
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
            tags: None,
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
        fs::write(meta_path, serde_json::to_string_pretty(&object_meta)?).await?;
        if object_meta.encryption.is_some() {
            self.mark_bucket_encryption_required(bucket).await?;
        }
        let _ = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await;

        Ok(PutResult {
            size: total_size,
            etag,
            version_id: None,
            checksum_algorithm,
            checksum_value,
        })
    }

    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(), StorageError> {
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

    /// Read the sticky `encryption_required` flag; missing bucket → false.
    async fn is_encryption_required(&self, bucket: &str) -> bool {
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let Ok(data) = fs::read_to_string(&meta_path).await else {
            return false;
        };
        serde_json::from_str::<BucketMeta>(&data)
            .map(|m| m.encryption_required)
            .unwrap_or(false)
    }

    /// Enforce the bucket's sticky `encryption_required` flag: once an encrypted
    /// object has landed in a bucket, every subsequent GET/HEAD must see a
    /// populated `encryption` block. An attacker stripping the `encryption`
    /// field from the sidecar therefore fails closed instead of silently
    /// returning ciphertext bytes as plaintext.
    async fn check_encryption_required(
        &self,
        bucket: &str,
        meta: &ObjectMeta,
    ) -> Result<(), StorageError> {
        if meta.encryption.is_some() {
            return Ok(());
        }
        if self.is_encryption_required(bucket).await {
            return Err(StorageError::IntegrityError(
                "bucket requires encryption but object metadata is missing the encryption block — sidecar may be tampered".into(),
            ));
        }
        Ok(())
    }

    /// Flip the bucket's `encryption_required` flag to `true` if not already
    /// set. Called after every encrypted write so a subsequent sidecar strip
    /// cannot downgrade objects in that bucket.
    async fn mark_bucket_encryption_required(&self, bucket: &str) -> Result<(), StorageError> {
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = match fs::read_to_string(&meta_path).await {
            Ok(d) => d,
            Err(_) => return Ok(()),
        };
        let mut bm: BucketMeta = match serde_json::from_str(&data) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        if bm.encryption_required {
            return Ok(());
        }
        bm.encryption_required = true;
        let json = serde_json::to_string_pretty(&bm)?;
        fs::write(&meta_path, json).await?;
        Ok(())
    }

    pub async fn set_versioning(&self, bucket: &str, enabled: bool) -> Result<(), StorageError> {
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        let was_enabled = meta.versioning;
        meta.versioning = enabled;
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;

        // If disabling versioning, clean up old versions
        if was_enabled && !enabled {
            self.cleanup_versions(bucket).await?;
        }
        Ok(())
    }

    pub async fn get_bucket_public(&self, bucket: &str) -> Result<(bool, bool), StorageError> {
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
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        meta.public_read = read;
        meta.public_list = list;
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;
        Ok(())
    }

    pub async fn put_bucket_cors(
        &self,
        bucket: &str,
        rules: Vec<crate::storage::CorsRule>,
    ) -> Result<(), StorageError> {
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        meta.cors_rules = Some(rules);
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;
        Ok(())
    }

    pub async fn get_bucket_cors(
        &self,
        bucket: &str,
    ) -> Result<Option<Vec<crate::storage::CorsRule>>, StorageError> {
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
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        meta.cors_rules = None;
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;
        Ok(())
    }

    // --- Bucket default encryption ---

    pub async fn put_bucket_encryption(
        &self,
        bucket: &str,
        config: BucketEncryptionConfig,
    ) -> Result<(), StorageError> {
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        meta.encryption_config = Some(config);
        meta.encryption_required = true;
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;
        Ok(())
    }

    pub async fn get_bucket_encryption(
        &self,
        bucket: &str,
    ) -> Result<Option<BucketEncryptionConfig>, StorageError> {
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
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        meta.encryption_config = None;
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;
        Ok(())
    }

    // --- Encryption helpers ---

    fn prepare_encryption(
        &self,
        req: &EncryptionRequest,
    ) -> Result<EncryptionMeta, StorageError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        match req.mode {
            EncryptionMode::SseS3 => {
                let dek = Keyring::generate_dek();
                let nonce_prefix = Keyring::generate_nonce_prefix();
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
                let nonce_prefix = Keyring::generate_nonce_prefix();
                let md5 = Md5::digest(&**customer_key);
                // For SSE-C the "DEK" used per frame is the customer key itself;
                // no DEK is persisted. We still record nonce_prefix + key md5.
                Ok(EncryptionMeta {
                    algorithm: "AES256".to_string(),
                    mode: EncryptionMode::SseC,
                    key_id: None,
                    wrapped_dek: None,
                    wrap_nonce: None,
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
                    StorageError::EncryptionError(
                        "SSE-C multipart: customer key required".into(),
                    )
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
                Ok(ck)
            }
            EncryptionMode::SseS3 => {
                let key_id = enc_meta
                    .key_id
                    .as_ref()
                    .ok_or_else(|| StorageError::DecryptionError("missing key_id".into()))?;
                let wrapped = enc_meta.wrapped_dek.as_ref().ok_or_else(|| {
                    StorageError::DecryptionError("missing wrapped_dek".into())
                })?;
                let wrap_nonce = enc_meta.wrap_nonce.as_ref().ok_or_else(|| {
                    StorageError::DecryptionError("missing wrap_nonce".into())
                })?;
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

    /// Remove all `.versions/` directories in the bucket, keeping only current (top-level) files.
    /// Also remove any objects whose latest version was a delete marker (restore nothing).
    async fn cleanup_versions(&self, bucket: &str) -> Result<(), StorageError> {
        let bucket_dir = self.buckets_dir.join(bucket);
        self.cleanup_versions_recursive(&bucket_dir).await
    }

    fn cleanup_versions_recursive<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = match fs::read_dir(dir).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                let fname = entry.file_name().to_string_lossy().to_string();
                if entry.file_type().await?.is_dir() {
                    if fname == ".versions" {
                        fs::remove_dir_all(entry.path()).await?;
                    } else if fname != ".uploads" {
                        self.cleanup_versions_recursive(&entry.path()).await?;
                    }
                }
            }
            Ok(())
        })
    }

    /// Write a new version to the `.versions/` directory and update the current (top-level) files.
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

        // Copy data to version store
        let ver_data = ver_dir.join(format!("{}.data", version_id));
        fs::copy(data_path, &ver_data).await?;

        // Write version metadata
        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        fs::write(&ver_meta, serde_json::to_string_pretty(meta)?).await?;

        Ok(())
    }

    /// Write a new chunked version: copy .ec/ dir to .versions/{key}/{version_id}.ec/
    async fn write_version_chunked(
        &self,
        bucket: &str,
        key: &str,
        meta: &ObjectMeta,
    ) -> Result<(), StorageError> {
        let version_id = meta.version_id.as_ref().unwrap();
        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;

        // Copy the entire .ec/ directory
        let src_ec = self.ec_dir(bucket, key);
        let dst_ec = ver_dir.join(format!("{}.ec", version_id));
        fs::create_dir_all(&dst_ec).await?;
        let mut entries = fs::read_dir(&src_ec).await?;
        while let Some(entry) = entries.next_entry().await? {
            let dest = dst_ec.join(entry.file_name());
            fs::copy(entry.path(), &dest).await?;
        }

        // Write version metadata
        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        fs::write(&ver_meta, serde_json::to_string_pretty(meta)?).await?;

        Ok(())
    }

    /// Write a delete marker version and remove the top-level files.
    async fn write_delete_marker(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
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
        };

        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;
        let ver_meta_path = ver_dir.join(format!("{}.meta.json", version_id));
        fs::write(&ver_meta_path, serde_json::to_string_pretty(&marker_meta)?).await?;

        // Remove top-level current files
        let _ = fs::remove_file(self.object_path(bucket, key)).await;
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;
        let _ = fs::remove_dir_all(self.ec_dir(bucket, key)).await;

        Ok(DeleteResult {
            version_id: Some(version_id),
            is_delete_marker: true,
        })
    }

    /// Scan versions for a key and update the top-level files to reflect the latest non-delete-marker.
    async fn update_current_version(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        let ver_dir = self.versions_dir(bucket, key);
        if !fs::try_exists(&ver_dir).await.unwrap_or(false) {
            return Ok(());
        }

        // Find the latest non-delete-marker version (lexicographic sort = chronological)
        let mut versions = Vec::new();
        let mut entries = fs::read_dir(&ver_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.ends_with(".meta.json") {
                versions.push(fname);
            }
        }
        versions.sort();
        versions.reverse(); // newest first

        for meta_fname in &versions {
            let meta_path = ver_dir.join(meta_fname);
            let data = fs::read_to_string(&meta_path).await?;
            let meta: ObjectMeta = serde_json::from_str(&data)?;
            if !meta.is_delete_marker {
                // Restore this version as current
                let vid = meta.version_id.as_ref().unwrap();
                let obj_meta_path = self.meta_path(bucket, key);

                let ver_ec = ver_dir.join(format!("{}.ec", vid));
                if ver_ec.is_dir() {
                    // Restore chunked version
                    let dst_ec = self.ec_dir(bucket, key);
                    if let Some(parent) = dst_ec.parent() {
                        fs::create_dir_all(parent).await?;
                    }
                    let _ = fs::remove_dir_all(&dst_ec).await;
                    fs::create_dir_all(&dst_ec).await?;
                    let mut entries = fs::read_dir(&ver_ec).await?;
                    while let Some(entry) = entries.next_entry().await? {
                        fs::copy(entry.path(), dst_ec.join(entry.file_name())).await?;
                    }
                } else {
                    // Restore flat version
                    let ver_data = ver_dir.join(format!("{}.data", vid));
                    let obj_path = self.object_path(bucket, key);
                    if let Some(parent) = obj_path.parent() {
                        fs::create_dir_all(parent).await?;
                    }
                    fs::copy(&ver_data, &obj_path).await?;
                }

                if let Some(parent) = obj_meta_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                fs::write(&obj_meta_path, serde_json::to_string_pretty(&meta)?).await?;
                return Ok(());
            }
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
        validate_key(key)?;
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
        self.check_encryption_required(bucket, &meta).await?;
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
        validate_key(key)?;
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
        self.check_encryption_required(bucket, &meta).await?;
        Ok(meta)
    }

    pub async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validate_key(key)?;
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
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut results = Vec::new();
        self.walk_versions(&bucket_dir, &bucket_dir, prefix, &mut results)
            .await?;
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
    nonce_prefix: &[u8; 4],
    chunk_index: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(), StorageError> {
    let nonce_bytes = make_nonce(nonce_prefix, chunk_index);
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
