use super::{BucketMeta, ByteStream, DeleteResult, MultipartUploadMeta, ObjectMeta, PartMeta, PutResult, StorageError};
use md5::{Digest, Md5};
use rand::RngExt;
use std::path::{Component, Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};

pub struct FilesystemStorage {
    buckets_dir: PathBuf,
}

/// Validate that an object key does not contain path traversal components.
fn validate_key(key: &str) -> Result<(), StorageError> {
    if key.is_empty() {
        return Err(StorageError::InvalidKey("Key must not be empty".into()));
    }
    if key.len() > 1024 {
        return Err(StorageError::InvalidKey("Key must not exceed 1024 bytes".into()));
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

impl FilesystemStorage {
    pub async fn new(data_dir: &str) -> Result<Self, anyhow::Error> {
        let buckets_dir = Path::new(data_dir).join("buckets");
        fs::create_dir_all(&buckets_dir).await?;
        Ok(Self { buckets_dir })
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

        let has_objects = self.has_objects(&bucket_dir).await?;
        if has_objects {
            return Err(StorageError::BucketNotEmpty);
        }

        // Remove metadata and internal dirs before the bucket dir itself.
        // Use remove_dir (not remove_dir_all) for the bucket dir so it fails
        // atomically if a concurrent put_object added files in between.
        let _ = fs::remove_file(bucket_dir.join(".bucket.json")).await;
        let _ = fs::remove_dir_all(bucket_dir.join(".uploads")).await;
        let _ = fs::remove_dir_all(bucket_dir.join(".versions")).await;
        match fs::remove_dir(&bucket_dir).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                // A concurrent write added files — restore bucket metadata
                // and report not empty. Best-effort: if this fails, the bucket
                // is effectively deleted (head_bucket checks .bucket.json).
                let meta = BucketMeta {
                    name: name.to_string(),
                    created_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                    region: String::new(),
                    versioning: false,
                };
                let _ = fs::write(
                    bucket_dir.join(".bucket.json"),
                    serde_json::to_string_pretty(&meta).unwrap_or_default(),
                ).await;
                Err(StorageError::BucketNotEmpty)
            }
            Err(e) => Err(e.into()),
        }
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
    ) -> Result<PutResult, StorageError> {
        validate_key(key)?;

        // Folder marker: zero-byte object with key ending in /
        if key.ends_with('/') {
            return self.put_folder_marker(bucket, key).await;
        }

        let obj_path = self.object_path(bucket, key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = fs::File::create(&obj_path).await?;
        let mut hasher = Md5::new();
        let mut size: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = body.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
            tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n]).await?;
        }

        let etag = hex::encode(hasher.finalize());
        let etag_quoted = format!("\"{}\"", etag);

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let versioned = self.is_versioned(bucket).await.unwrap_or(false);
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        let meta = ObjectMeta {
            key: key.to_string(),
            size,
            etag: etag_quoted.clone(),
            content_type: content_type.to_string(),
            last_modified: now,
            version_id: version_id.clone(),
            is_delete_marker: false,
        };

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string_pretty(&meta)?;
        fs::write(&meta_path, json).await?;

        if versioned {
            self.write_version(bucket, key, &meta, &obj_path).await?;
        }

        Ok(PutResult {
            size,
            etag: etag_quoted,
            version_id,
        })
    }

    async fn put_folder_marker(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<PutResult, StorageError> {
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
        };

        let meta_path = folder_dir.join(".folder.meta.json");
        let json = serde_json::to_string_pretty(&meta)?;
        fs::write(&meta_path, json).await?;

        Ok(PutResult {
            size: 0,
            etag,
            version_id: None,
        })
    }

    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        let obj_path = self.object_path(bucket, key);
        let file = fs::File::open(&obj_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let reader = BufReader::new(file);
        Ok((Box::pin(reader), meta))
    }

    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        offset: u64,
        length: u64,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        let obj_path = self.object_path(bucket, key);
        let mut file = fs::File::open(&obj_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        file.seek(std::io::SeekFrom::Start(offset)).await.map_err(StorageError::Io)?;
        let limited = file.take(length);
        let reader = BufReader::new(limited);
        Ok((Box::pin(reader), meta))
    }

    pub async fn head_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validate_key(key)?;
        self.read_object_meta(bucket, key).await
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

        let _ = fs::remove_file(&obj_path).await;
        let _ = fs::remove_file(&meta_path).await;

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
    ) -> Result<MultipartUploadMeta, StorageError> {
        validate_key(key)?;
        let upload_id = uuid::Uuid::new_v4().to_string();
        let upload_dir = self.upload_dir(bucket, &upload_id);
        fs::create_dir_all(&upload_dir).await?;

        let meta = MultipartUploadMeta {
            upload_id: upload_id.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_type: content_type.to_string(),
            initiated: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
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
    ) -> Result<PartMeta, StorageError> {
        validate_upload_id(upload_id)?;
        if part_number == 0 || part_number > 10_000 {
            return Err(StorageError::InvalidKey("part number must be 1..=10000".into()));
        }
        let upload_dir = self.upload_dir(bucket, upload_id);
        if !fs::try_exists(&upload_dir).await? {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let part_path = self.part_path(bucket, upload_id, part_number);
        let mut file = fs::File::create(&part_path).await?;
        let mut hasher = Md5::new();
        let mut size: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = body.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).await?;
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        file.flush().await?;

        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));
        let meta = PartMeta {
            part_number,
            etag,
            size,
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
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

        let obj_path = self.object_path(bucket, &upload_meta.key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut out = fs::File::create(&obj_path).await?;
        let mut total_size = 0u64;
        let mut etag_hasher = Md5::new();

        for part in &selected {
            let mut part_file = fs::File::open(self.part_path(bucket, upload_id, part.part_number)).await?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = part_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n]).await?;
                total_size += n as u64;
            }

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }
        out.flush().await?;

        let etag = format!("\"{}-{}\"", hex::encode(etag_hasher.finalize()), selected.len());
        let object_meta = ObjectMeta {
            key: upload_meta.key.clone(),
            size: total_size,
            etag: etag.clone(),
            content_type: upload_meta.content_type,
            last_modified: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            version_id: None,
            is_delete_marker: false,
        };
        let meta_path = self.meta_path(bucket, &upload_meta.key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(meta_path, serde_json::to_string_pretty(&object_meta)?).await?;
        let _ = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await;

        Ok(PutResult {
            size: total_size,
            etag,
            version_id: None,
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

    fn has_objects<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = fs::read_dir(dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname == ".bucket.json"
                    || fname == ".uploads"
                    || fname == ".versions"
                    || fname.ends_with(".meta.json")
                {
                    continue;
                }
                if entry.file_type().await?.is_dir() {
                    if self.has_objects(&entry.path()).await? {
                        return Ok(true);
                    }
                } else {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    async fn read_object_meta(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<ObjectMeta, StorageError> {
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
                            if let Ok(meta) = self.read_object_meta(
                                base.file_name().unwrap().to_str().unwrap(),
                                &key,
                            ).await {
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

    pub async fn set_versioning(
        &self,
        bucket: &str,
        enabled: bool,
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
        let was_enabled = meta.versioning;
        meta.versioning = enabled;
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;

        // If disabling versioning, clean up old versions
        if was_enabled && !enabled {
            self.cleanup_versions(bucket).await?;
        }
        Ok(())
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
        };

        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;
        let ver_meta_path = ver_dir.join(format!("{}.meta.json", version_id));
        fs::write(&ver_meta_path, serde_json::to_string_pretty(&marker_meta)?).await?;

        // Remove top-level current files
        let _ = fs::remove_file(self.object_path(bucket, key)).await;
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;

        Ok(DeleteResult {
            version_id: Some(version_id),
            is_delete_marker: true,
        })
    }

    /// Scan versions for a key and update the top-level files to reflect the latest non-delete-marker.
    async fn update_current_version(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(), StorageError> {
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
                let ver_data = ver_dir.join(format!("{}.data", vid));
                let obj_path = self.object_path(bucket, key);
                let obj_meta_path = self.meta_path(bucket, key);
                if let Some(parent) = obj_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                fs::copy(&ver_data, &obj_path).await?;
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
        Ok(())
    }

    pub async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
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

        let ver_data_path = self.version_data_path(bucket, key, version_id);
        let file = fs::File::open(&ver_data_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok((Box::pin(BufReader::new(file)), meta))
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
