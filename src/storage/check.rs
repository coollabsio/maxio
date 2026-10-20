//! Offline scan of a data directory.
//!
//! `maxio check` reports objects and metadata that a crash can leave
//! inconsistent. `--repair` fixes only the cases where the bytes on disk are
//! enough to restore a consistent view: stale temps, stranded publish
//! backups, sidecars that do not match a plain object, upload debris, and
//! erasure-coded chunks that parity can rebuild.
//!
//! Run it while the server is stopped. A live server may be publishing the
//! same files this scan reads.

use super::chunk_reader::repair_chunk_file;
use super::filesystem::write_file_atomic;
use super::{
    BucketMeta, ChecksumAlgorithm, ChecksumHasher, ChunkKind, ChunkManifest, EncryptionMode,
    MultipartUploadMeta, ObjectMeta, PartMeta,
};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::path::Path;
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    StaleTemp,
    StaleBackup,
    OrphanData,
    OrphanMetadata,
    SizeMismatch,
    EtagMismatch,
    ChecksumMismatch,
    CorruptMetadata,
    MissingUploadMeta,
    OrphanPart,
    PartSizeMismatch,
    MissingChunk,
    ChunkChecksumMismatch,
    AmbiguousPayload,
    KeyringMissing,
}

impl IssueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleTemp => "stale-temp",
            Self::StaleBackup => "stale-backup",
            Self::OrphanData => "orphan-data",
            Self::OrphanMetadata => "orphan-metadata",
            Self::SizeMismatch => "size-mismatch",
            Self::EtagMismatch => "etag-mismatch",
            Self::ChecksumMismatch => "checksum-mismatch",
            Self::CorruptMetadata => "corrupt-metadata",
            Self::MissingUploadMeta => "missing-upload-meta",
            Self::OrphanPart => "orphan-part",
            Self::PartSizeMismatch => "part-size-mismatch",
            Self::MissingChunk => "missing-chunk",
            Self::ChunkChecksumMismatch => "chunk-checksum-mismatch",
            Self::AmbiguousPayload => "ambiguous-payload",
            Self::KeyringMissing => "keyring-missing",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Issue {
    pub kind: IssueKind,
    pub path: String,
    pub detail: String,
    pub repaired: bool,
}

#[derive(Debug, Default)]
pub struct CheckReport {
    pub issues: Vec<Issue>,
    pub objects_seen: u64,
}

impl CheckReport {
    pub fn unresolved(&self) -> usize {
        self.issues.iter().filter(|issue| !issue.repaired).count()
    }

    pub fn print(&self) {
        for issue in &self.issues {
            let action = if issue.repaired { "repaired" } else { "report" };
            println!(
                "{:<24} {:<22} {}  {}",
                action,
                issue.kind.as_str(),
                issue.path,
                issue.detail
            );
        }
        println!(
            "checked {} object(s), {} issue(s), {} unresolved",
            self.objects_seen,
            self.issues.len(),
            self.unresolved()
        );
    }

    fn push(&mut self, kind: IssueKind, path: &Path, detail: impl Into<String>, repaired: bool) {
        self.issues.push(Issue {
            kind,
            path: path.display().to_string(),
            detail: detail.into(),
            repaired,
        });
    }
}

pub async fn check(data_dir: &Path, repair: bool) -> anyhow::Result<CheckReport> {
    if !tokio::fs::try_exists(data_dir).await? {
        anyhow::bail!("data directory does not exist: {}", data_dir.display());
    }
    let mut report = CheckReport::default();
    let mut saw_sse_s3 = false;
    let buckets_dir = data_dir.join("buckets");
    if tokio::fs::try_exists(&buckets_dir).await? {
        let mut buckets = tokio::fs::read_dir(&buckets_dir).await?;
        while let Some(entry) = buckets.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                scan_bucket(&entry.path(), repair, &mut report, &mut saw_sse_s3).await?;
            }
        }
    }
    let keyring = data_dir.join(".maxio-keys.json");
    if saw_sse_s3 && !tokio::fs::try_exists(&keyring).await? {
        report.push(
            IssueKind::KeyringMissing,
            &keyring,
            "SSE-S3 objects are present but .maxio-keys.json is missing; their plaintext cannot be recovered",
            false,
        );
    }
    Ok(report)
}

async fn scan_bucket(
    bucket_dir: &Path,
    repair: bool,
    report: &mut CheckReport,
    saw_sse_s3: &mut bool,
) -> anyhow::Result<()> {
    let bucket_json = bucket_dir.join(".bucket.json");
    if tokio::fs::try_exists(&bucket_json).await? {
        let data = tokio::fs::read_to_string(&bucket_json).await?;
        if serde_json::from_str::<BucketMeta>(&data).is_err() {
            report.push(
                IssueKind::CorruptMetadata,
                &bucket_json,
                "bucket metadata is not valid JSON; left untouched",
                false,
            );
        }
    }

    let mut stack = vec![(bucket_dir.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut entries = Vec::new();
        let mut read = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!("check: cannot read {}: {}", dir.display(), e);
                continue;
            }
        };
        while let Some(entry) = read.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry.file_type().await?.is_dir();
            entries.push((name, entry.path(), is_dir));
        }

        for (name, path, is_dir) in &entries {
            if name.starts_with(".maxio-tmp-") {
                let repaired = if repair {
                    remove_path(path).await;
                    true
                } else {
                    false
                };
                report.push(
                    IssueKind::StaleTemp,
                    path,
                    "leftover temp file from a crashed write",
                    repaired,
                );
            } else if let Some(orig) = name.strip_prefix(".maxio-bak-") {
                repair_backup(&dir, orig, path, *is_dir, repair, report).await;
            }
        }

        if prefix.is_empty() {
            if let Some((_, path, _)) = entries.iter().find(|(n, _, _)| n == ".uploads") {
                scan_uploads(path, repair, report).await?;
            }
        }
        if let Some((_, path, _)) = entries.iter().find(|(n, _, d)| n == ".versions" && *d) {
            scan_versions(path, &prefix, repair, report, saw_sse_s3).await?;
        }

        let names: std::collections::HashSet<&str> =
            entries.iter().map(|(n, _, _)| n.as_str()).collect();

        for (name, path, is_dir) in &entries {
            if *is_dir || !name.ends_with(".meta.json") {
                continue;
            }
            if name == ".bucket.json" || name.starts_with(".maxio-") {
                continue;
            }
            let Some(stem) = name.strip_suffix(".meta.json") else {
                continue;
            };
            if stem.is_empty() {
                continue;
            }
            let (key, data_path) = if stem == ".folder" {
                (prefix.clone(), dir.join(".folder"))
            } else {
                (format!("{prefix}{stem}"), dir.join(stem))
            };
            let ec_path = dir.join(format!("{stem}.ec"));
            check_meta_pair(path, &data_path, &ec_path, &key, repair, report, saw_sse_s3).await?;
        }

        for (name, path, is_dir) in &entries {
            if *is_dir || name.ends_with(".meta.json") || name.ends_with(".ec") {
                continue;
            }
            if name.starts_with('.') && name != ".folder" {
                continue;
            }
            let meta_name = format!("{name}.meta.json");
            if names.contains(meta_name.as_str()) {
                continue;
            }
            let key = format!("{prefix}{name}");
            let repaired = if repair {
                let meta = synthesized_meta(&key, path).await?;
                write_file_atomic(
                    &dir.join(meta_name),
                    serde_json::to_string_pretty(&meta)?.as_bytes(),
                )
                .await?;
                true
            } else {
                false
            };
            report.push(
                IssueKind::OrphanData,
                path,
                format!("object bytes have no sidecar (key {key})"),
                repaired,
            );
            if repaired {
                report.objects_seen += 1;
            }
        }

        for (name, path, is_dir) in &entries {
            if !*is_dir {
                continue;
            }
            if name.starts_with('.') || name.ends_with(".ec") {
                continue;
            }
            stack.push((path.clone(), format!("{prefix}{name}/")));
        }
    }
    Ok(())
}

async fn check_meta_pair(
    meta_path: &Path,
    data_path: &Path,
    ec_path: &Path,
    key: &str,
    repair: bool,
    report: &mut CheckReport,
    saw_sse_s3: &mut bool,
) -> anyhow::Result<()> {
    let raw = match tokio::fs::read_to_string(meta_path).await {
        Ok(raw) => raw,
        Err(e) => {
            report.push(
                IssueKind::CorruptMetadata,
                meta_path,
                format!("unreadable sidecar: {e}"),
                false,
            );
            return Ok(());
        }
    };
    let mut meta: ObjectMeta = match serde_json::from_str(&raw) {
        Ok(meta) => meta,
        Err(e) => {
            let data_exists = tokio::fs::try_exists(data_path).await?;
            let repaired = if repair && data_exists && !tokio::fs::try_exists(ec_path).await? {
                let rebuilt = synthesized_meta(key, data_path).await?;
                write_file_atomic(
                    meta_path,
                    serde_json::to_string_pretty(&rebuilt)?.as_bytes(),
                )
                .await?;
                true
            } else if repair && !data_exists {
                let _ = tokio::fs::remove_file(meta_path).await;
                true
            } else {
                false
            };
            report.push(
                IssueKind::CorruptMetadata,
                meta_path,
                format!("sidecar JSON is invalid: {e}"),
                repaired,
            );
            return Ok(());
        }
    };

    if meta.encryption.as_ref().map(|e| e.mode.clone()) == Some(EncryptionMode::SseS3) {
        *saw_sse_s3 = true;
    }
    if meta.is_delete_marker {
        report.objects_seen += 1;
        return Ok(());
    }

    let encrypted = meta.encryption.is_some();
    let ec_exists = tokio::fs::try_exists(ec_path).await?;
    let data_exists = tokio::fs::try_exists(data_path).await?;
    let chunked = ec_exists
        || meta
            .storage_format
            .as_deref()
            .is_some_and(|fmt| fmt.starts_with("chunked"));

    if chunked && data_exists {
        report.push(
            IssueKind::AmbiguousPayload,
            data_path,
            "both a plain object and an erasure-coded directory exist; left untouched",
            false,
        );
    }

    if chunked {
        if !ec_exists {
            let repaired = if repair {
                let _ = tokio::fs::remove_file(meta_path).await;
                true
            } else {
                false
            };
            report.push(
                IssueKind::OrphanMetadata,
                meta_path,
                format!("sidecar for {key} has no erasure-coded payload"),
                repaired,
            );
            return Ok(());
        }
        report.objects_seen += 1;
        if !encrypted {
            check_ec_dir(ec_path, repair, report).await?;
        }
        return Ok(());
    }

    if !data_exists {
        let repaired = if repair {
            let _ = tokio::fs::remove_file(meta_path).await;
            true
        } else {
            false
        };
        report.push(
            IssueKind::OrphanMetadata,
            meta_path,
            format!("sidecar for {key} has no object bytes"),
            repaired,
        );
        return Ok(());
    }

    report.objects_seen += 1;
    if encrypted {
        return Ok(());
    }

    let file_len = tokio::fs::metadata(data_path).await?.len();
    let mut dirty = false;
    if file_len != meta.size {
        let repaired = repair;
        report.push(
            IssueKind::SizeMismatch,
            data_path,
            format!("sidecar size is {}, file is {file_len} bytes", meta.size),
            repaired,
        );
        if repair {
            meta.size = file_len;
            meta.etag = file_md5_quoted(data_path).await?;
            meta.part_sizes = None;
            dirty = true;
        }
    } else if !meta.etag.trim_matches('"').contains('-') {
        let etag = file_md5_quoted(data_path).await?;
        if etag != meta.etag {
            let repaired = repair;
            report.push(
                IssueKind::EtagMismatch,
                data_path,
                format!("sidecar etag is {}, file hashes to {etag}", meta.etag),
                repaired,
            );
            if repair {
                meta.etag = etag;
                dirty = true;
            }
        }
    }

    if let (Some(algo), Some(expected)) = (meta.checksum_algorithm, meta.checksum_value.clone()) {
        let actual = file_checksum(data_path, algo).await?;
        if actual != expected {
            let repaired = repair;
            report.push(
                IssueKind::ChecksumMismatch,
                data_path,
                format!("sidecar checksum is {expected}, file is {actual}"),
                repaired,
            );
            if repair {
                meta.checksum_value = Some(actual);
                dirty = true;
            }
        }
    }

    if dirty {
        write_file_atomic(meta_path, serde_json::to_string_pretty(&meta)?.as_bytes()).await?;
    }
    Ok(())
}

async fn check_ec_dir(
    ec_path: &Path,
    repair: bool,
    report: &mut CheckReport,
) -> anyhow::Result<()> {
    let manifest_path = ec_path.join("manifest.json");
    let raw = match tokio::fs::read_to_string(&manifest_path).await {
        Ok(raw) => raw,
        Err(e) => {
            report.push(
                IssueKind::CorruptMetadata,
                &manifest_path,
                format!("erasure-coded manifest is unreadable: {e}"),
                false,
            );
            return Ok(());
        }
    };
    let manifest: ChunkManifest = match serde_json::from_str(&raw) {
        Ok(m) => m,
        Err(e) => {
            report.push(
                IssueKind::CorruptMetadata,
                &manifest_path,
                format!("erasure-coded manifest is invalid: {e}"),
                false,
            );
            return Ok(());
        }
    };
    for chunk in &manifest.chunks {
        if chunk.kind == ChunkKind::Parity {
            continue;
        }
        let chunk_path = ec_path.join(format!("{:06}", chunk.index));
        let data = match tokio::fs::read(&chunk_path).await {
            Ok(data) => data,
            Err(_) => {
                let repaired = repair_chunk_if_possible(ec_path, &manifest, chunk.index, repair);
                report.push(
                    IssueKind::MissingChunk,
                    &chunk_path,
                    format!("chunk {} is missing", chunk.index),
                    repaired,
                );
                continue;
            }
        };
        let hash = hex::encode(Sha256::digest(&data));
        if data.len() as u64 != chunk.size || hash != chunk.sha256 {
            let repaired = repair_chunk_if_possible(ec_path, &manifest, chunk.index, repair);
            report.push(
                IssueKind::ChunkChecksumMismatch,
                &chunk_path,
                format!(
                    "chunk {} size/checksum does not match the manifest",
                    chunk.index
                ),
                repaired,
            );
        }
    }
    Ok(())
}

fn repair_chunk_if_possible(
    ec_path: &Path,
    manifest: &ChunkManifest,
    index: u32,
    repair: bool,
) -> bool {
    if !repair || manifest.parity_shards.unwrap_or(0) == 0 {
        return false;
    }
    repair_chunk_file(ec_path, manifest, index).is_ok()
}

async fn scan_uploads(
    uploads_dir: &Path,
    repair: bool,
    report: &mut CheckReport,
) -> anyhow::Result<()> {
    let mut uploads = match tokio::fs::read_dir(uploads_dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    while let Some(upload) = uploads.next_entry().await? {
        if !upload.file_type().await?.is_dir() {
            continue;
        }
        let dir = upload.path();
        let meta_path = dir.join(".meta.json");
        let readable = match tokio::fs::read_to_string(&meta_path).await {
            Ok(raw) => serde_json::from_str::<MultipartUploadMeta>(&raw).is_ok(),
            Err(_) => false,
        };
        if !readable {
            let repaired = if repair {
                let _ = tokio::fs::remove_dir_all(&dir).await;
                true
            } else {
                false
            };
            report.push(
                IssueKind::MissingUploadMeta,
                &dir,
                "multipart upload has no readable metadata and cannot be completed",
                repaired,
            );
            continue;
        }

        let mut names = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name().to_string_lossy().to_string());
        }
        let name_set: std::collections::HashSet<&str> = names.iter().map(String::as_str).collect();
        for name in &names {
            if name.starts_with('.') || name.ends_with(".meta.json") {
                continue;
            }
            if name.parse::<u32>().is_err() {
                continue;
            }
            let meta_name = format!("{name}.meta.json");
            let part_path = dir.join(name);
            if !name_set.contains(meta_name.as_str()) {
                let repaired = if repair {
                    let _ = tokio::fs::remove_file(&part_path).await;
                    true
                } else {
                    false
                };
                report.push(
                    IssueKind::OrphanPart,
                    &part_path,
                    "part bytes have no sidecar",
                    repaired,
                );
                continue;
            }
            let part_meta_path = dir.join(&meta_name);
            if let Ok(raw) = tokio::fs::read_to_string(&part_meta_path).await {
                if let Ok(mut part) = serde_json::from_str::<PartMeta>(&raw) {
                    if part.encrypted {
                        continue;
                    }
                    let len = tokio::fs::metadata(&part_path).await?.len();
                    if len != part.size {
                        let repaired = repair;
                        report.push(
                            IssueKind::PartSizeMismatch,
                            &part_path,
                            format!("part sidecar size is {}, file is {len} bytes", part.size),
                            repaired,
                        );
                        if repair {
                            part.size = len;
                            part.etag = file_md5_quoted(&part_path).await?;
                            write_file_atomic(
                                &part_meta_path,
                                serde_json::to_string_pretty(&part)?.as_bytes(),
                            )
                            .await?;
                        }
                    }
                }
            }
        }
        for name in &names {
            let Some(stem) = name.strip_suffix(".meta.json") else {
                continue;
            };
            if stem.is_empty() || stem.starts_with('.') || stem.parse::<u32>().is_err() {
                continue;
            }
            if !name_set.contains(stem) {
                let path = dir.join(name);
                let repaired = if repair {
                    let _ = tokio::fs::remove_file(&path).await;
                    true
                } else {
                    false
                };
                report.push(
                    IssueKind::OrphanPart,
                    &path,
                    "part sidecar has no bytes",
                    repaired,
                );
            }
        }
    }
    Ok(())
}

async fn scan_versions(
    versions_dir: &Path,
    prefix: &str,
    repair: bool,
    report: &mut CheckReport,
    saw_sse_s3: &mut bool,
) -> anyhow::Result<()> {
    let mut keys = match tokio::fs::read_dir(versions_dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    while let Some(key_dir) = keys.next_entry().await? {
        if !key_dir.file_type().await?.is_dir() {
            continue;
        }
        let name = key_dir.file_name().to_string_lossy().to_string();
        let key = format!("{prefix}{name}");
        let dir = key_dir.path();
        let mut entries = Vec::new();
        let mut read = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = read.next_entry().await? {
            entries.push((
                entry.file_name().to_string_lossy().to_string(),
                entry.path(),
                entry.file_type().await?.is_dir(),
            ));
        }
        let names: std::collections::HashSet<&str> =
            entries.iter().map(|(n, _, _)| n.as_str()).collect();
        for (name, path, is_dir) in &entries {
            if *is_dir || !name.ends_with(".meta.json") {
                continue;
            }
            let Some(stem) = name.strip_suffix(".meta.json") else {
                continue;
            };
            check_meta_pair(
                path,
                &dir.join(format!("{stem}.data")),
                &dir.join(format!("{stem}.ec")),
                &key,
                repair,
                report,
                saw_sse_s3,
            )
            .await?;
        }
        for (name, path, is_dir) in &entries {
            if *is_dir || !name.ends_with(".data") {
                continue;
            }
            let Some(stem) = name.strip_suffix(".data") else {
                continue;
            };
            if names.contains(format!("{stem}.meta.json").as_str()) {
                continue;
            }
            let repaired = if repair {
                let _ = tokio::fs::remove_file(path).await;
                true
            } else {
                false
            };
            report.push(
                IssueKind::OrphanData,
                path,
                format!("version bytes for {key} have no sidecar"),
                repaired,
            );
        }
    }
    Ok(())
}

async fn repair_backup(
    dir: &Path,
    orig_name: &str,
    backup: &Path,
    _is_dir: bool,
    repair: bool,
    report: &mut CheckReport,
) {
    if orig_name.is_empty() {
        return;
    }
    let orig = dir.join(orig_name);
    let superseded = match orig_name.strip_suffix(".ec") {
        Some(flat) if !flat.is_empty() => {
            tokio::fs::try_exists(dir.join(flat)).await.unwrap_or(false)
        }
        _ => false,
    };
    let orig_exists = tokio::fs::try_exists(&orig).await.unwrap_or(true);
    let restore = !superseded && !orig_exists;
    let detail = if restore {
        "publish crashed before the new payload was in place; backup is the previous object"
    } else {
        "publish finished; backup is leftover"
    };
    let mut repaired = false;
    if repair {
        if restore {
            repaired = tokio::fs::rename(backup, &orig).await.is_ok();
        } else {
            remove_path(backup).await;
            repaired = true;
        }
    }
    report.push(IssueKind::StaleBackup, backup, detail, repaired);
}

async fn remove_path(path: &Path) {
    if tokio::fs::metadata(path)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        let _ = tokio::fs::remove_dir_all(path).await;
    } else {
        let _ = tokio::fs::remove_file(path).await;
    }
}

async fn synthesized_meta(key: &str, data_path: &Path) -> anyhow::Result<ObjectMeta> {
    let len = tokio::fs::metadata(data_path).await?.len();
    Ok(ObjectMeta {
        key: key.to_string(),
        size: len,
        etag: file_md5_quoted(data_path).await?,
        content_type: if key.ends_with('/') {
            "application/x-directory".to_string()
        } else {
            "application/octet-stream".to_string()
        },
        last_modified: chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
        ..ObjectMeta::default()
    })
}

async fn file_md5_quoted(path: &Path) -> anyhow::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("\"{}\"", hex::encode(hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::filesystem::FilesystemStorage;
    use crate::storage::keys::Keyring;
    use crate::storage::{BucketMeta, ObjectMeta};
    use std::sync::Arc;

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

    #[tokio::test]
    async fn repairs_orphan_bytes_size_mismatch_and_upload_debris() {
        let tmp = tempfile::tempdir().unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        std::fs::create_dir_all(&bucket).unwrap();
        std::fs::write(
            bucket.join(".bucket.json"),
            serde_json::to_string(&bucket_meta("bkt")).unwrap(),
        )
        .unwrap();

        std::fs::write(bucket.join("orphan.bin"), b"orphan-bytes").unwrap();

        let stale = ObjectMeta {
            key: "sized.txt".into(),
            size: 2,
            etag: "\"00000000000000000000000000000000\"".into(),
            content_type: "text/plain".into(),
            last_modified: "2020-01-01T00:00:00.000Z".into(),
            ..ObjectMeta::default()
        };
        std::fs::write(bucket.join("sized.txt"), b"abcdef").unwrap();
        std::fs::write(
            bucket.join("sized.txt.meta.json"),
            serde_json::to_string_pretty(&stale).unwrap(),
        )
        .unwrap();

        std::fs::write(
            bucket.join("gone.txt.meta.json"),
            serde_json::to_string_pretty(&ObjectMeta {
                key: "gone.txt".into(),
                size: 1,
                etag: "\"x\"".into(),
                content_type: "text/plain".into(),
                last_modified: "2020-01-01T00:00:00.000Z".into(),
                ..ObjectMeta::default()
            })
            .unwrap(),
        )
        .unwrap();

        std::fs::create_dir_all(bucket.join(".uploads/no-meta")).unwrap();
        std::fs::write(bucket.join(".uploads/no-meta/1"), b"part").unwrap();
        std::fs::write(bucket.join(".maxio-tmp-crash"), b"partial").unwrap();

        let reported = check(tmp.path(), false).await.unwrap();
        assert!(reported.unresolved() >= 4, "{:?}", reported.issues);
        assert!(bucket.join(".maxio-tmp-crash").exists());

        let repaired = check(tmp.path(), true).await.unwrap();
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
        assert!(!bucket.join(".maxio-tmp-crash").exists());
        assert!(!bucket.join("gone.txt.meta.json").exists());
        assert!(!bucket.join(".uploads/no-meta").exists());

        let keyring = Arc::new(
            Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let storage =
            FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await
                .unwrap();
        let meta = storage.head_object("bkt", "orphan.bin").await.unwrap();
        assert_eq!(meta.size, b"orphan-bytes".len() as u64);
        let sized = storage.head_object("bkt", "sized.txt").await.unwrap();
        assert_eq!(sized.size, 6);
        assert!(storage.head_object("bkt", "gone.txt").await.is_err());
    }
}

async fn file_checksum(path: &Path, algo: ChecksumAlgorithm) -> anyhow::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = ChecksumHasher::new(algo);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_base64())
}
