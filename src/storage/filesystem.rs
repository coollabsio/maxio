use super::{BucketMeta, ByteStream, ObjectMeta, PutResult, StorageError};
use md5::{Digest, Md5};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, BufReader};

pub struct FilesystemStorage {
    buckets_dir: PathBuf,
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
                fs::write(&meta_path, json).await?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn head_bucket(&self, name: &str) -> bool {
        fs::try_exists(self.buckets_dir.join(name).join(".bucket.json"))
            .await
            .unwrap_or(false)
    }

    pub async fn delete_bucket(&self, name: &str) -> Result<bool, StorageError> {
        let bucket_dir = self.buckets_dir.join(name);
        if !fs::try_exists(&bucket_dir).await.unwrap_or(false) {
            return Ok(false);
        }

        // Check if bucket has any objects (ignore .bucket.json and .meta.json files)
        let has_objects = self.has_objects(&bucket_dir).await?;
        if has_objects {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "BucketNotEmpty",
            )
            .into());
        }

        fs::remove_dir_all(&bucket_dir).await?;
        Ok(true)
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
        self.buckets_dir.join(bucket).join(key)
    }

    fn meta_path(&self, bucket: &str, key: &str) -> PathBuf {
        self.buckets_dir
            .join(bucket)
            .join(format!("{}.meta.json", key))
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        mut body: ByteStream,
    ) -> Result<PutResult, StorageError> {
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

        let meta = ObjectMeta {
            key: key.to_string(),
            size,
            etag: etag_quoted.clone(),
            content_type: content_type.to_string(),
            last_modified: now,
        };

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string_pretty(&meta)?;
        fs::write(&meta_path, json).await?;

        Ok(PutResult {
            size,
            etag: etag_quoted,
        })
    }

    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
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

    pub async fn head_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<ObjectMeta, StorageError> {
        self.read_object_meta(bucket, key).await
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
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
                Err(_) => break, // not empty or doesn't exist
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }

        Ok(())
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

    // --- Internal helpers ---

    /// Recursively check if a directory contains any non-metadata object files.
    fn has_objects<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = fs::read_dir(dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname == ".bucket.json" || fname.ends_with(".meta.json") {
                    continue;
                }
                if entry.file_type().await?.is_dir() {
                    if self.has_objects(&entry.path()).await? {
                        return Ok(true);
                    }
                } else {
                    // Found an actual object file
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

                // Skip metadata files and bucket meta
                if fname.ends_with(".meta.json") || fname == ".bucket.json" {
                    continue;
                }

                if entry.file_type().await?.is_dir() {
                    self.walk_dir(base, &path, prefix, results).await?;
                } else {
                    // Derive the S3 key from the relative path
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
}
