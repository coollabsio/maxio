//! Offline scan of a data directory.
//!
//! `maxio check` reports objects and metadata that a crash can leave
//! inconsistent. `--repair` fixes only the cases where the bytes on disk are
//! enough to restore a consistent view: stale temps, stranded publish
//! backups, key promotions left in `.maxio-promote-*`, upload debris, and
//! erasure-coded chunks that parity can rebuild. Object bytes with no
//! sidecar are quarantined under `<data-dir>/.maxio-quarantine/` rather than
//! adopted: those bytes may be SSE-S3 ciphertext, and a plaintext sidecar
//! would serve them without encryption headers. A sidecar is never deleted
//! while a promote directory for that key still holds the bytes (the sidecar
//! is where an SSE-S3 wrapped data key lives).
//!
//! Run it while the server is stopped. A live server may be publishing the
//! same files this scan reads.

use super::chunk_reader::repair_chunk_file;
use super::filesystem::{
    INLINE_OBJECT_PAYLOAD, PROMOTE_READY_FILE, PROMOTE_TARGET_FILE, find_legacy_reserved_keys,
    is_legacy_container, is_promote_dir_name, key_contains_reserved_segment, list_promotes,
    promote_dir_has_meta, recover_promotes_in, write_file_atomic,
};
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
    /// External master key was not passed to this check. Not a failure.
    KeyringUnverified,
    /// `.maxio-promote-*` still holds object bytes from a key promotion.
    PromoteLeftover,
    /// Object written by an older build under a name this version reserves.
    LegacyReservedKey,
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
            Self::KeyringUnverified => "keyring-unverified",
            Self::PromoteLeftover => "promote-leftover",
            Self::LegacyReservedKey => "legacy-reserved-key",
        }
    }
}

fn legacy_key_detail(bucket: &str, key: &str) -> String {
    format!(
        "{bucket}/{key} uses a name reserved by this version of MaxIO. Start the previous MaxIO version on this data directory and rename or delete these keys (for example `aws s3 mv`), then start this version. check does not modify this object."
    )
}

/// Sidecars that must survive this scan because a promote directory may be
/// the only copy of their bytes.
struct SidecarGuard {
    targets: std::collections::HashSet<String>,
    /// A promote directory has bytes but no readable target name. Do not
    /// delete any sidecar in this directory that is missing its payload, and
    /// do not invent a plaintext sidecar for those bytes.
    protect_unmatched: bool,
}

impl SidecarGuard {
    fn keeps(&self, stem: &str) -> bool {
        self.protect_unmatched || self.targets.contains(stem)
    }
}

#[derive(Debug, Clone)]
pub struct Issue {
    pub kind: IssueKind,
    pub path: String,
    pub detail: String,
    pub repaired: bool,
    /// Printed, but does not fail the process. `--repair` does not apply.
    pub advisory: bool,
}

#[derive(Debug, Default)]
pub struct CheckReport {
    pub issues: Vec<Issue>,
    pub objects_seen: u64,
}

impl CheckReport {
    pub fn unresolved(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| !issue.advisory && !issue.repaired)
            .count()
    }

    pub fn print(&self) {
        for issue in &self.issues {
            let action = if issue.repaired {
                "repaired"
            } else if issue.advisory {
                "note"
            } else {
                "report"
            };
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
            advisory: false,
        });
    }

    fn note(&mut self, kind: IssueKind, path: &Path, detail: impl Into<String>) {
        self.issues.push(Issue {
            kind,
            path: path.display().to_string(),
            detail: detail.into(),
            repaired: false,
            advisory: true,
        });
    }
}

#[allow(dead_code)] // used by the library tests; the binary calls `check_with`
pub async fn check(data_dir: &Path, repair: bool) -> anyhow::Result<CheckReport> {
    check_with(data_dir, repair, None).await
}

/// `master_key_b64` is the canonical base64 key from [`super::keys::resolve_master_key`].
pub async fn check_with(
    data_dir: &Path,
    repair: bool,
    master_key_b64: Option<&str>,
) -> anyhow::Result<CheckReport> {
    if !tokio::fs::try_exists(data_dir).await? {
        anyhow::bail!("data directory does not exist: {}", data_dir.display());
    }
    if super::lock::is_locked(data_dir)? {
        if repair {
            anyhow::bail!(
                "refusing to repair {}: a maxio server holds {}/.maxio.lock. Stop the server first. --repair would delete temp files an in-flight upload still needs.",
                data_dir.display(),
                data_dir.display()
            );
        }
        eprintln!(
            "warning: a maxio server is using {}. This read-only check can race with in-flight writes. Stop the server before trusting the report or running --repair.",
            data_dir.display()
        );
    }
    let _repair_lock = if repair {
        Some(super::lock::acquire_exclusive(
            data_dir,
            super::lock::LockReason::Repair,
        )?)
    } else {
        None
    };
    // The marker is written only while this process holds the lock.
    if repair {
        super::format::ensure_current(data_dir).await?;
    }
    let mut report = CheckReport::default();
    let mut saw_sse_s3 = false;
    let buckets_dir = data_dir.join("buckets");
    for legacy in find_legacy_reserved_keys(&buckets_dir).await {
        report.push(
            IssueKind::LegacyReservedKey,
            &buckets_dir.join(&legacy.bucket).join(&legacy.key),
            legacy_key_detail(&legacy.bucket, &legacy.key),
            false,
        );
    }
    if tokio::fs::try_exists(&buckets_dir).await? {
        let mut buckets = tokio::fs::read_dir(&buckets_dir).await?;
        while let Some(entry) = buckets.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let bucket = entry.file_name().to_string_lossy().to_string();
                scan_bucket(
                    &entry.path(),
                    &bucket,
                    data_dir,
                    repair,
                    &mut report,
                    &mut saw_sse_s3,
                )
                .await?;
            }
        }
    }
    let _ = saw_sse_s3;
    note_master_key(data_dir, master_key_b64, &mut report).await?;
    Ok(report)
}

async fn note_master_key(
    data_dir: &Path,
    master_key_b64: Option<&str>,
    report: &mut CheckReport,
) -> anyhow::Result<()> {
    let data_dir_str = data_dir.to_string_lossy();
    match super::keys::assess_master_key(&data_dir_str, master_key_b64).await? {
        super::keys::MasterKeyAssessment::Satisfied => {}
        super::keys::MasterKeyAssessment::ExternalKeyUnverified { ids } => {
            report.note(
                IssueKind::KeyringUnverified,
                &data_dir.join(".maxio-key-check.json"),
                format!(
                    "SSE-S3 data was encrypted with an external master key (key ids: {}). Pass --master-key or --master-key-file, or set MAXIO_MASTER_KEY / MAXIO_MASTER_KEY_FILE, to verify it. No key was supplied to this check.",
                    ids.join(", ")
                ),
            );
        }
        super::keys::MasterKeyAssessment::Unrecoverable { detail } => {
            report.push(
                IssueKind::KeyringMissing,
                &data_dir.join(".maxio-keys.json"),
                detail,
                false,
            );
        }
    }
    Ok(())
}

async fn scan_bucket(
    bucket_dir: &Path,
    bucket: &str,
    data_dir: &Path,
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
        // Restore or record promote directories before any sidecar is judged
        // missing. Repair rewrites the directory, so the listing below sees
        // the restored file or `<key>/.maxio.object`.
        let guard = settle_promotes(&dir, repair, report).await;

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
            scan_versions(
                path, bucket_dir, bucket, data_dir, &prefix, repair, report, saw_sse_s3,
            )
            .await?;
        }

        for (name, path, is_dir) in &entries {
            if *is_dir || (*name != PROMOTE_TARGET_FILE && *name != PROMOTE_READY_FILE) {
                continue;
            }
            let sidecar = dir.join(format!("{name}.meta.json"));
            if tokio::fs::try_exists(&sidecar).await.unwrap_or(false) {
                continue;
            }
            let repaired = if repair {
                tokio::fs::remove_file(path).await.is_ok()
            } else {
                false
            };
            report.push(
                IssueKind::PromoteLeftover,
                path,
                "promote marker left inside a published key directory",
                repaired,
            );
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
            let key_for_reserve = if stem == ".folder" {
                prefix.clone()
            } else {
                format!("{prefix}{stem}")
            };
            // Reported by the legacy-key scan. Do not repair, quarantine, or
            // delete the sidecar.
            if key_contains_reserved_segment(&key_for_reserve) {
                continue;
            }
            let (key, data_path) = if stem == ".folder" {
                (prefix.clone(), dir.join(".folder"))
            } else {
                // Inline payload first. `p.meta.json` is a sibling of the
                // directory `p/`, so a scan that only stats `p` treats the
                // sidecar as orphan metadata and `--repair` deletes it.
                (format!("{prefix}{stem}"), inline_or_file(&dir, stem).await)
            };
            let ec_path = dir.join(format!("{stem}.ec"));
            check_meta_pair(
                path,
                &data_path,
                &ec_path,
                &key,
                PairFlags {
                    repair,
                    keep_sidecar: guard.keeps(stem),
                },
                report,
                saw_sse_s3,
            )
            .await?;
        }

        for (name, path, is_dir) in &entries {
            if *is_dir || name.ends_with(".meta.json") || name.ends_with(".ec") {
                continue;
            }
            if name.starts_with('.') && name != ".folder" {
                // `.maxio.object` is the payload of the directory's key, not
                // its own object. The parent directory's sidecar scan owns it.
                continue;
            }
            let meta_name = format!("{name}.meta.json");
            if names.contains(meta_name.as_str()) {
                continue;
            }
            let key = format!("{prefix}{name}");
            report_orphan(
                data_dir,
                bucket,
                bucket_dir,
                path,
                &key,
                repair,
                guard.keeps(name),
                report,
            )
            .await?;
        }

        for (name, path, is_dir) in &entries {
            if !*is_dir {
                continue;
            }
            if name.ends_with(".ec") {
                continue;
            }
            if name.starts_with('.') {
                // Older builds stored real objects under names this version
                // reserves. Descend so `check` can list them. An exact
                // promote leftover is not one of those objects.
                if is_promote_dir_name(name) {
                    // Leftovers with no sidecar are handled by promote
                    // recovery. Descend only when the directory holds a real
                    // object sidecar so those bytes are not treated as an
                    // inline payload.
                    if promote_dir_has_meta(path).await {
                        stack.push((path.clone(), format!("{prefix}{name}/")));
                    }
                } else if is_legacy_container(name) {
                    stack.push((path.clone(), format!("{prefix}{name}/")));
                }
                continue;
            }
            // Payload of a key that is also a prefix. Without a sidecar the
            // bytes may be ciphertext, so repair quarantines the file and
            // does not invent a plaintext object. `name/.maxio.object.meta.json`
            // is a legacy object whose key ends in `.maxio.object`, not the
            // inline payload of `name`.
            let legacy_inline = path.join(format!("{INLINE_OBJECT_PAYLOAD}.meta.json"));
            if tokio::fs::try_exists(&legacy_inline).await.unwrap_or(false) {
                stack.push((path.clone(), format!("{prefix}{name}/")));
                continue;
            }
            let inline = path.join(INLINE_OBJECT_PAYLOAD);
            if tokio::fs::metadata(&inline)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                let meta_name = format!("{name}.meta.json");
                let sidecar_on_disk = names.contains(meta_name.as_str())
                    || tokio::fs::try_exists(dir.join(&meta_name))
                        .await
                        .unwrap_or(false);
                if !sidecar_on_disk {
                    let key = format!("{prefix}{name}");
                    report_orphan(
                        data_dir,
                        bucket,
                        bucket_dir,
                        &inline,
                        &key,
                        repair,
                        guard.keeps(name),
                        report,
                    )
                    .await?;
                }
            }
            stack.push((path.clone(), format!("{prefix}{name}/")));
        }
    }
    Ok(())
}

struct PairFlags {
    repair: bool,
    keep_sidecar: bool,
}

async fn check_meta_pair(
    meta_path: &Path,
    data_path: &Path,
    ec_path: &Path,
    key: &str,
    flags: PairFlags,
    report: &mut CheckReport,
    saw_sse_s3: &mut bool,
) -> anyhow::Result<()> {
    let repair = flags.repair;
    let keep_sidecar = flags.keep_sidecar;
    if key_contains_reserved_segment(key) {
        return Ok(());
    }
    // Resolve `p/.maxio.object` before any decision to delete `p.meta.json`.
    // A directory at `p` is not the payload; opening it is EISDIR, and the
    // bytes (including SSE-S3 ciphertext) live in the inline file.
    let resolved = resolve_object_bytes(meta_path, data_path).await;
    let data_path = resolved.as_path();

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
            let data_exists = is_file(data_path).await;
            let repaired = if repair && data_exists && !tokio::fs::try_exists(ec_path).await? {
                // A readable encryption sidecar is returned before this branch.
                // Rebuilding from bytes is only for a corrupt plaintext sidecar.
                let rebuilt = synthesized_meta(key, data_path).await?;
                write_file_atomic(
                    meta_path,
                    serde_json::to_string_pretty(&rebuilt)?.as_bytes(),
                )
                .await?;
                true
            } else if repair && !data_exists && !keep_sidecar {
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
    let mut data_exists = tokio::fs::try_exists(data_path).await?;
    if data_exists {
        let is_file = tokio::fs::metadata(data_path)
            .await
            .map(|meta| meta.is_file())
            .unwrap_or(false);
        // A directory is a key prefix, not object bytes. Opening it is EISDIR.
        if !is_file {
            data_exists = false;
        }
    }
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
            let repaired = if repair && !keep_sidecar {
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
        // The promote-leftover finding already covers a key whose bytes are
        // parked in `.maxio-promote-*`. Deleting the sidecar here drops the
        // SSE-S3 wrapped DEK while the ciphertext still exists.
        if keep_sidecar {
            return Ok(());
        }
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
    bucket_dir: &Path,
    bucket: &str,
    data_dir: &Path,
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
                PairFlags {
                    repair,
                    keep_sidecar: false,
                },
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
            report_orphan(
                data_dir,
                bucket,
                bucket_dir,
                path,
                &format!("{key} version {stem}"),
                repair,
                false,
                report,
            )
            .await?;
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

async fn settle_promotes(dir: &Path, repair: bool, report: &mut CheckReport) -> SidecarGuard {
    let mut guard = SidecarGuard {
        targets: std::collections::HashSet::new(),
        protect_unmatched: false,
    };
    if repair {
        for outcome in recover_promotes_in(dir, None).await {
            if !outcome.resolved {
                match &outcome.target {
                    Some(target) => {
                        guard.targets.insert(target.clone());
                    }
                    None => guard.protect_unmatched = true,
                }
            }
            report.push(
                IssueKind::PromoteLeftover,
                &outcome.path,
                outcome.detail.clone(),
                outcome.resolved,
            );
        }
        return guard;
    }
    for (path, target) in list_promotes(dir).await {
        if let Some(name) = &target {
            guard.targets.insert(name.clone());
        }
        let has_payload = tokio::fs::metadata(path.join(INLINE_OBJECT_PAYLOAD))
            .await
            .map(|meta| meta.is_file())
            .unwrap_or(false);
        if target.is_none() && has_payload {
            guard.protect_unmatched = true;
        }
        let detail = match &target {
            Some(name) => format!("promote directory still holds object bytes for {name}"),
            None if has_payload => {
                "promote directory still holds object bytes and has no target marker".to_string()
            }
            None => "empty promote directory".to_string(),
        };
        report.push(IssueKind::PromoteLeftover, &path, detail, false);
    }
    guard
}

async fn inline_or_file(dir: &Path, stem: &str) -> std::path::PathBuf {
    let inline = dir.join(stem).join(INLINE_OBJECT_PAYLOAD);
    if is_file(&inline).await {
        inline
    } else {
        dir.join(stem)
    }
}

async fn resolve_object_bytes(meta_path: &Path, data_path: &Path) -> std::path::PathBuf {
    if is_file(data_path).await {
        return data_path.to_path_buf();
    }
    if let Some(inline) = inline_payload_for_meta(meta_path) {
        if is_file(&inline).await {
            return inline;
        }
    }
    data_path.to_path_buf()
}

fn inline_payload_for_meta(meta_path: &Path) -> Option<std::path::PathBuf> {
    let name = meta_path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".meta.json")?;
    if stem.is_empty() || stem == ".folder" || stem.starts_with('.') {
        return None;
    }
    let dir = meta_path.parent()?;
    Some(dir.join(stem).join(INLINE_OBJECT_PAYLOAD))
}

async fn is_file(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|meta| meta.is_file())
        .unwrap_or(false)
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

async fn report_orphan(
    data_dir: &Path,
    bucket: &str,
    bucket_dir: &Path,
    src: &Path,
    key: &str,
    repair: bool,
    blocked: bool,
    report: &mut CheckReport,
) -> anyhow::Result<()> {
    let (repaired, detail) = if blocked {
        (
            false,
            format!(
                "object bytes have no sidecar (key {key}); left in place because a promote directory may still hold this key"
            ),
        )
    } else if repair {
        match quarantine_file(data_dir, bucket, bucket_dir, src).await {
            Ok(dest) => (
                true,
                format!(
                    "object bytes have no sidecar (key {key}); quarantined at {} so they are not served as a plaintext object. Copy the file back by hand if you know which object it belongs to. MaxIO does not invent a sidecar, because the bytes may be SSE-S3 ciphertext.",
                    dest.display()
                ),
            ),
            Err(err) => (
                false,
                format!("object bytes have no sidecar (key {key}); quarantine failed: {err}"),
            ),
        }
    } else {
        (
            false,
            format!(
                "object bytes have no sidecar (key {key}); left in place. --repair moves them under .maxio-quarantine and does not invent a sidecar, because the bytes may be SSE-S3 ciphertext"
            ),
        )
    };
    report.push(IssueKind::OrphanData, src, detail, repaired);
    Ok(())
}

/// Move `src` to `<data-dir>/.maxio-quarantine/<bucket>/<path-within-bucket>`.
async fn quarantine_file(
    data_dir: &Path,
    bucket: &str,
    bucket_dir: &Path,
    src: &Path,
) -> anyhow::Result<std::path::PathBuf> {
    let rel = src.strip_prefix(bucket_dir).unwrap_or(src);
    let mut dest = data_dir.join(".maxio-quarantine").join(bucket).join(rel);
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if tokio::fs::try_exists(&dest).await? {
        let parent = dest
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| data_dir.to_path_buf());
        let stem = dest
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "orphan".to_string());
        for n in 1..1000 {
            let candidate = parent.join(format!("{stem}.{n}"));
            if !tokio::fs::try_exists(&candidate).await? {
                dest = candidate;
                break;
            }
        }
    }
    tokio::fs::rename(src, &dest).await?;
    // A sidecar is the wrapped SSE-S3 key. Move it with the bytes. Never
    // leave it behind for a later pass to delete.
    let mut sidecar_name = src.as_os_str().to_os_string();
    sidecar_name.push(".meta.json");
    let sidecar = std::path::PathBuf::from(sidecar_name);
    if tokio::fs::try_exists(&sidecar).await? {
        let mut side_dest = dest.as_os_str().to_os_string();
        side_dest.push(".meta.json");
        tokio::fs::rename(&sidecar, std::path::PathBuf::from(side_dest)).await?;
    }
    Ok(dest)
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
        assert!(!bucket.join("orphan.bin").exists());
        let quarantined = tmp.path().join(".maxio-quarantine/bkt/orphan.bin");
        assert_eq!(std::fs::read(&quarantined).unwrap(), b"orphan-bytes");
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::OrphanData
                    && issue.repaired
                    && issue.detail.contains("quarantined")
                    && issue.detail.contains("orphan.bin")
            }),
            "{:?}",
            repaired.issues
        );

        let keyring = Arc::new(
            Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let storage =
            FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await
                .unwrap();
        assert!(storage.head_object("bkt", "orphan.bin").await.is_err());
        let sized = storage.head_object("bkt", "sized.txt").await.unwrap();
        assert_eq!(sized.size, 6);
        assert!(storage.head_object("bkt", "gone.txt").await.is_err());
    }

    #[tokio::test]
    async fn prefix_key_plain_and_sse_s3_checks_clean_and_repair_keeps_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let keyring = Arc::new(
            Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let storage =
            FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await
                .unwrap();
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();

        let put = |key: &'static str, bytes: &'static [u8], sse: bool| {
            let storage = &storage;
            async move {
                storage
                    .put_object(
                        "bkt",
                        key,
                        "text/plain",
                        Box::pin(bytes),
                        None,
                        sse.then(crate::storage::EncryptionRequest::sse_s3),
                    )
                    .await
                    .unwrap();
            }
        };
        put("a", b"plain-a", false).await;
        put("a/b", b"plain-b", false).await;
        put("sa", b"sse-a", true).await;
        put("sa/b", b"sse-b", true).await;

        let bucket = tmp.path().join("buckets/bkt");
        assert!(
            bucket.join("a/.maxio.object").is_file(),
            "plain prefix payload"
        );
        assert!(
            bucket.join("sa/.maxio.object").is_file(),
            "sse prefix payload"
        );

        let clean = check(tmp.path(), false).await.unwrap();
        assert_eq!(clean.unresolved(), 0, "{:?}", clean.issues);
        let repaired = check(tmp.path(), true).await.unwrap();
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
        assert!(bucket.join("a/.maxio.object").is_file());
        assert!(bucket.join("sa/.maxio.object").is_file());
        let read = |key: &'static str| {
            let storage = &storage;
            async move {
                let (mut reader, _) = storage.get_object("bkt", key, None).await.unwrap();
                let mut buf = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
                    .await
                    .unwrap();
                buf
            }
        };
        assert_eq!(read("a/b").await, b"plain-b");
        assert_eq!(read("sa/b").await, b"sse-b");
        assert_eq!(read("a").await, b"plain-a");
        assert_eq!(read("sa").await, b"sse-a");

        // An inline payload with no sidecar is quarantined, not adopted as a
        // plaintext object. The SSE-S3 sibling keeps its wrapped key.
        std::fs::remove_file(bucket.join("a.meta.json")).unwrap();
        let plain_bytes = std::fs::read(bucket.join("a/.maxio.object")).unwrap();
        let missing = check(tmp.path(), false).await.unwrap();
        assert!(
            missing.issues.iter().any(|issue| {
                issue.kind == IssueKind::OrphanData && issue.detail.contains("key a")
            }),
            "{:?}",
            missing.issues
        );
        assert!(bucket.join("a/.maxio.object").is_file());
        let fixed = check(tmp.path(), true).await.unwrap();
        assert_eq!(fixed.unresolved(), 0, "{:?}", fixed.issues);
        assert!(!bucket.join("a.meta.json").exists());
        assert!(!bucket.join("a/.maxio.object").exists());
        let quarantined = tmp.path().join(".maxio-quarantine/bkt/a/.maxio.object");
        assert_eq!(std::fs::read(&quarantined).unwrap(), plain_bytes);
        assert!(storage.get_object("bkt", "a", None).await.is_err());
        let sse_meta = std::fs::read_to_string(bucket.join("sa.meta.json")).unwrap();
        assert!(
            sse_meta.contains("sse_s3") && sse_meta.contains("wrapped_dek"),
            "repair must not replace an SSE-S3 sidecar with a plaintext one: {sse_meta}"
        );
    }

    #[tokio::test]
    async fn sse_orphan_bytes_are_quarantined_not_adopted() {
        let tmp = tempfile::tempdir().unwrap();
        let keyring = Arc::new(
            Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let storage =
            FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await
                .unwrap();
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        let body = b"ciphertext-parent";
        storage
            .put_object(
                "bkt",
                "p",
                "text/plain",
                Box::pin(&body[..]),
                None,
                Some(crate::storage::EncryptionRequest::sse_s3()),
            )
            .await
            .unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        let cipher = std::fs::read(bucket.join("p")).unwrap();
        assert_ne!(cipher, body);
        std::fs::remove_file(bucket.join("p.meta.json")).unwrap();

        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::OrphanData
                    && issue.repaired
                    && issue.detail.contains("quarantined")
            }),
            "{:?}",
            repaired.issues
        );
        assert!(!bucket.join("p").exists());
        assert!(!bucket.join("p.meta.json").exists());
        assert_eq!(
            std::fs::read(tmp.path().join(".maxio-quarantine/bkt/p")).unwrap(),
            cipher
        );
        assert!(storage.get_object("bkt", "p", None).await.is_err());
    }

    #[tokio::test]
    async fn promote_markers_inside_a_published_key_are_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let keyring = Arc::new(
            Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let storage =
            FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await
                .unwrap();
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage
            .put_object(
                "bkt",
                "p",
                "text/plain",
                Box::pin(&b"parent"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "bkt",
                "p/q",
                "text/plain",
                Box::pin(&b"child"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        let ready = bucket.join("p/.maxio-promote-ready");
        let target = bucket.join("p/.maxio-promote-target");
        std::fs::write(&ready, b"").unwrap();
        std::fs::write(&target, b"p").unwrap();

        let reported = check(tmp.path(), false).await.unwrap();
        assert!(
            reported.unresolved() >= 2,
            "marker files must fail a clean check: {:?}",
            reported.issues
        );
        assert_eq!(
            reported
                .issues
                .iter()
                .filter(|issue| issue.kind == IssueKind::PromoteLeftover && !issue.repaired)
                .count(),
            2,
            "{:?}",
            reported.issues
        );
        assert!(ready.is_file() && target.is_file());

        let repaired = check(tmp.path(), true).await.unwrap();
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
        assert!(!ready.exists() && !target.exists());
        assert!(bucket.join("p/.maxio.object").is_file());
        let (mut reader, _) = storage.get_object("bkt", "p", None).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, b"parent");
    }

    /// Crash steps of `promote_file_to_directory`, left on disk.
    ///
    /// The original object is key `p`. A child `p/q` is what triggers the
    /// promote; these states are the disk after a crash at each step.
    #[derive(Clone, Copy, Debug)]
    enum PromoteCrash {
        /// Directory and target marker exist; payload not copied yet.
        TargetOnly,
        /// Payload copied, `.ready` not written, original file still there.
        CopiedNotReady,
        /// Copy fsynced and marked ready; original file not unlinked yet.
        ReadyOriginalRemains,
        /// Original unlinked; bytes only in the promote directory.
        Unlinked,
        /// Original unlinked and `p/` already exists (payload must go inline).
        DestDirectory,
    }

    impl PromoteCrash {
        fn label(self) -> &'static str {
            match self {
                Self::TargetOnly => "target-only",
                Self::CopiedNotReady => "copied",
                Self::ReadyOriginalRemains => "ready",
                Self::Unlinked => "unlinked",
                Self::DestDirectory => "dest-dir",
            }
        }
    }

    fn arrange_promote_crash(bucket: &std::path::Path, step: PromoteCrash) {
        use crate::storage::filesystem::{
            INLINE_OBJECT_PAYLOAD, PROMOTE_DIR_PREFIX, PROMOTE_READY_FILE, PROMOTE_TARGET_FILE,
        };
        let src = bucket.join("p");
        let bytes = std::fs::read(&src).expect("object p");
        let promote = bucket.join(format!("{PROMOTE_DIR_PREFIX}{}", step.label()));
        std::fs::create_dir(&promote).unwrap();
        let payload = promote.join(INLINE_OBJECT_PAYLOAD);
        match step {
            PromoteCrash::TargetOnly => {
                std::fs::write(promote.join(PROMOTE_TARGET_FILE), b"p").unwrap();
            }
            PromoteCrash::CopiedNotReady => {
                std::fs::write(promote.join(PROMOTE_TARGET_FILE), b"p").unwrap();
                std::fs::write(&payload, &bytes).unwrap();
            }
            PromoteCrash::ReadyOriginalRemains => {
                std::fs::write(promote.join(PROMOTE_TARGET_FILE), b"p").unwrap();
                std::fs::write(&payload, &bytes).unwrap();
                std::fs::write(promote.join(PROMOTE_READY_FILE), b"").unwrap();
            }
            PromoteCrash::Unlinked | PromoteCrash::DestDirectory => {
                std::fs::write(promote.join(PROMOTE_TARGET_FILE), b"p").unwrap();
                std::fs::write(&payload, &bytes).unwrap();
                std::fs::write(promote.join(PROMOTE_READY_FILE), b"").unwrap();
                std::fs::remove_file(&src).unwrap();
                if matches!(step, PromoteCrash::DestDirectory) {
                    std::fs::create_dir(&src).unwrap();
                }
            }
        }
    }

    fn promote_dirs(bucket: &std::path::Path) -> Vec<std::path::PathBuf> {
        use crate::storage::filesystem::PROMOTE_DIR_PREFIX;
        std::fs::read_dir(bucket)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(PROMOTE_DIR_PREFIX) && entry.path().is_dir() {
                    Some(entry.path())
                } else {
                    None
                }
            })
            .collect()
    }

    async fn read_key(storage: &FilesystemStorage, key: &str) -> Vec<u8> {
        let (mut reader, _) = storage.get_object("bkt", key, None).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        buf
    }

    async fn storage_at(dir: &std::path::Path) -> FilesystemStorage {
        let keyring = Arc::new(Keyring::load(dir.to_str().unwrap(), None).await.unwrap());
        FilesystemStorage::new(dir.to_str().unwrap(), false, 1024 * 1024, 0, keyring)
            .await
            .unwrap()
    }

    async fn put_p(storage: &FilesystemStorage, body: &'static [u8], sse: bool) {
        storage
            .put_object(
                "bkt",
                "p",
                "text/plain",
                Box::pin(body),
                None,
                sse.then(crate::storage::EncryptionRequest::sse_s3),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn promote_crash_each_step_restores_plain_and_sse_s3() {
        let plain = b"promote-plain-bytes";
        let secret = b"promote-sse-bytes";
        for sse in [false, true] {
            let body: &'static [u8] = if sse { secret } else { plain };
            for step in [
                PromoteCrash::TargetOnly,
                PromoteCrash::CopiedNotReady,
                PromoteCrash::ReadyOriginalRemains,
                PromoteCrash::Unlinked,
                PromoteCrash::DestDirectory,
            ] {
                // `check` must report the leftover and must not delete the
                // sidecar. `--repair` then makes GET return the same bytes.
                {
                    let tmp = tempfile::tempdir().unwrap();
                    let storage = storage_at(tmp.path()).await;
                    storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
                    put_p(&storage, body, sse).await;
                    let bucket = tmp.path().join("buckets/bkt");
                    arrange_promote_crash(&bucket, step);
                    let meta_path = bucket.join("p.meta.json");
                    let meta_before = std::fs::read(&meta_path).unwrap();
                    if sse {
                        let text = String::from_utf8_lossy(&meta_before);
                        assert!(
                            text.contains("sse_s3") && text.contains("wrapped_dek"),
                            "{text}"
                        );
                    }

                    let reported = check(tmp.path(), false).await.unwrap();
                    assert!(
                        reported.issues.iter().any(|issue| issue.kind
                            == IssueKind::PromoteLeftover
                            && !issue.repaired),
                        "{step:?} sse={sse} {:?}",
                        reported.issues
                    );
                    assert!(
                        !reported
                            .issues
                            .iter()
                            .any(|issue| issue.kind == IssueKind::OrphanMetadata),
                        "check must not treat the sidecar as orphan metadata: {step:?} {:?}",
                        reported.issues
                    );
                    assert_eq!(std::fs::read(&meta_path).unwrap(), meta_before);
                    assert_eq!(promote_dirs(&bucket).len(), 1);

                    let repaired = check(tmp.path(), true).await.unwrap();
                    assert!(
                        repaired
                            .issues
                            .iter()
                            .any(|issue| issue.kind == IssueKind::PromoteLeftover && issue.repaired),
                        "{step:?} sse={sse} {:?}",
                        repaired.issues
                    );
                    assert_eq!(
                        repaired.unresolved(),
                        0,
                        "{step:?} sse={sse} {:?}",
                        repaired.issues
                    );
                    assert_eq!(std::fs::read(&meta_path).unwrap(), meta_before);
                    assert!(promote_dirs(&bucket).is_empty(), "{step:?}");
                    assert_eq!(read_key(&storage, "p").await, body);
                }

                // Startup recovery of the same on-disk state.
                {
                    let tmp = tempfile::tempdir().unwrap();
                    let storage = storage_at(tmp.path()).await;
                    storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
                    put_p(&storage, body, sse).await;
                    let bucket = tmp.path().join("buckets/bkt");
                    arrange_promote_crash(&bucket, step);
                    let meta_before = std::fs::read(bucket.join("p.meta.json")).unwrap();
                    drop(storage);

                    let storage = storage_at(tmp.path()).await;
                    assert!(promote_dirs(&bucket).is_empty(), "{step:?} sse={sse}");
                    assert_eq!(
                        std::fs::read(bucket.join("p.meta.json")).unwrap(),
                        meta_before
                    );
                    assert_eq!(read_key(&storage, "p").await, body);

                    if matches!(step, PromoteCrash::Unlinked) {
                        storage
                            .put_object(
                                "bkt",
                                "p/q",
                                "text/plain",
                                Box::pin(&b"child"[..]),
                                None,
                                None,
                            )
                            .await
                            .unwrap();
                        assert_eq!(read_key(&storage, "p").await, body);
                        assert_eq!(read_key(&storage, "p/q").await, b"child");
                        assert!(
                            bucket
                                .join("p")
                                .join(super::super::filesystem::INLINE_OBJECT_PAYLOAD)
                                .is_file()
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn fresh_promote_survives_hourly_sweep_until_startup() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        put_p(&storage, b"still-here", false).await;
        let bucket = tmp.path().join("buckets/bkt");
        arrange_promote_crash(&bucket, PromoteCrash::Unlinked);
        let meta_before = std::fs::read(bucket.join("p.meta.json")).unwrap();

        storage.housekeeping_sweep(chrono::Duration::hours(1)).await;
        assert_eq!(
            promote_dirs(&bucket).len(),
            1,
            "hourly sweep must not race a fresh promote"
        );
        assert_eq!(
            std::fs::read(bucket.join("p.meta.json")).unwrap(),
            meta_before
        );
        assert!(storage.get_object("bkt", "p", None).await.is_err());

        storage.startup_recover().await;
        assert!(promote_dirs(&bucket).is_empty());
        assert_eq!(read_key(&storage, "p").await, b"still-here");
        assert_eq!(
            std::fs::read(bucket.join("p.meta.json")).unwrap(),
            meta_before
        );
    }

    #[tokio::test]
    async fn empty_and_duplicate_promote_dirs_are_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        put_p(&storage, b"keep-me", true).await;
        let bucket = tmp.path().join("buckets/bkt");
        let meta_before = std::fs::read(bucket.join("p.meta.json")).unwrap();
        let bytes_before = std::fs::read(bucket.join("p")).unwrap();
        let empty = bucket.join(".maxio-promote-empty");
        std::fs::create_dir(&empty).unwrap();
        let dup = bucket.join(".maxio-promote-dup");
        std::fs::create_dir(&dup).unwrap();
        std::fs::write(dup.join(".maxio-promote-target"), b"p").unwrap();
        std::fs::write(dup.join(".maxio.object"), &bytes_before).unwrap();

        let reported = check(tmp.path(), false).await.unwrap();
        assert!(
            reported
                .issues
                .iter()
                .any(|issue| issue.kind == IssueKind::PromoteLeftover
                    && issue.detail.contains("empty")),
            "{:?}",
            reported.issues
        );
        assert!(empty.exists() && dup.exists());
        assert_eq!(
            std::fs::read(bucket.join("p.meta.json")).unwrap(),
            meta_before
        );

        let repaired = check(tmp.path(), true).await.unwrap();
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
        assert!(!empty.exists(), "repair should remove an empty promote dir");
        assert!(!dup.exists(), "repair should drop a duplicate payload");
        assert_eq!(std::fs::read(bucket.join("p")).unwrap(), bytes_before);
        assert_eq!(
            std::fs::read(bucket.join("p.meta.json")).unwrap(),
            meta_before
        );

        std::fs::create_dir(&empty).unwrap();
        std::fs::create_dir(&dup).unwrap();
        std::fs::write(dup.join(".maxio-promote-target"), b"p").unwrap();
        std::fs::write(dup.join(".maxio.object"), &bytes_before).unwrap();
        drop(storage);
        let storage = storage_at(tmp.path()).await;
        assert!(!empty.exists());
        assert!(!dup.exists());
        assert_eq!(std::fs::read(bucket.join("p")).unwrap(), bytes_before);
        assert_eq!(
            std::fs::read(bucket.join("p.meta.json")).unwrap(),
            meta_before
        );
        assert_eq!(read_key(&storage, "p").await, b"keep-me");
    }

    fn tree_bytes(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .to_string();
                    out.push((rel, std::fs::read(&path).unwrap()));
                }
            }
        }
        walk(root, root, &mut out);
        out.sort();
        out
    }

    #[tokio::test]
    async fn legacy_reserved_keys_refuse_startup_and_repair_leaves_them() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        let specs = [
            (
                "s0",
                b"plain-photo".as_slice(),
                false,
                ".maxio-promote-photos/img.jpg",
            ),
            (
                "s1",
                b"sse-photo".as_slice(),
                true,
                ".maxio-promote-photos/sse.jpg",
            ),
            (
                "s2",
                b"plain-nested".as_slice(),
                false,
                "y/.maxio-promote-bar/file.txt",
            ),
            (
                "s3",
                b"sse-nested".as_slice(),
                true,
                "y/.maxio-promote-bar/sse.txt",
            ),
            ("s4", b"plain-inline".as_slice(), false, "a/.maxio.object"),
            ("s5", b"sse-inline".as_slice(), true, "b/.maxio.object"),
            ("s6", b"plain-quar".as_slice(), false, ".maxio-quarantine/f"),
            ("s7", b"sse-quar".as_slice(), true, ".maxio-quarantine/g"),
        ];
        for (src, body, sse, _dest) in specs {
            storage
                .put_object(
                    "bkt",
                    src,
                    "text/plain",
                    Box::pin(body),
                    None,
                    sse.then(crate::storage::EncryptionRequest::sse_s3),
                )
                .await
                .unwrap();
        }
        let bucket = tmp.path().join("buckets/bkt");
        for (src, _body, sse, dest) in specs {
            let src_data = bucket.join(src);
            let src_meta = bucket.join(format!("{src}.meta.json"));
            let dest_data = bucket.join(dest);
            let dest_meta = bucket.join(format!("{dest}.meta.json"));
            std::fs::create_dir_all(dest_data.parent().unwrap()).unwrap();
            std::fs::rename(&src_data, &dest_data).unwrap();
            let mut meta: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&src_meta).unwrap()).unwrap();
            meta["key"] = serde_json::Value::String(dest.to_string());
            let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap();
            std::fs::write(&dest_meta, &meta_bytes).unwrap();
            std::fs::remove_file(&src_meta).unwrap();
            if sse {
                let text = String::from_utf8_lossy(&meta_bytes);
                assert!(text.contains("wrapped_dek"), "{dest}: {text}");
            }
        }
        drop(storage);
        let buckets = tmp.path().join("buckets");
        let before = tree_bytes(&buckets);

        let keyring = Arc::new(
            Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let started =
            FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await;
        let err = match started {
            Err(err) => err,
            Ok(_) => panic!("legacy reserved keys must refuse startup"),
        };
        let message = err.to_string();
        assert!(
            message.contains("previous MaxIO version") && message.contains("aws s3 mv"),
            "{message}"
        );
        for (_src, _body, _sse, dest) in specs {
            assert!(
                message.contains(&format!("bkt/{dest}")),
                "startup error missing {dest}: {message}"
            );
        }
        assert_eq!(
            tree_bytes(&buckets),
            before,
            "startup must not modify the data dir"
        );

        let reported = check(tmp.path(), false).await.unwrap();
        for (_src, _body, _sse, dest) in specs {
            assert!(
                reported.issues.iter().any(|issue| {
                    issue.kind == IssueKind::LegacyReservedKey
                        && !issue.repaired
                        && issue.detail.contains(dest)
                        && issue.detail.contains("aws s3 mv")
                }),
                "check did not report {dest}: {:?}",
                reported.issues
            );
        }
        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.unresolved() >= specs.len(),
            "{:?}",
            repaired.issues
        );
        assert_eq!(
            tree_bytes(&buckets),
            before,
            "repair must not modify legacy keys"
        );
        assert!(
            repaired
                .issues
                .iter()
                .any(|issue| issue.kind == IssueKind::LegacyReservedKey && !issue.repaired),
            "{:?}",
            repaired.issues
        );
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

#[cfg(test)]
mod master_key_tests {
    use super::*;
    use crate::storage::keys::{Keyring, resolve_master_key};
    use crate::storage::{EncryptionMeta, EncryptionMode};
    use base64::Engine;

    fn encode_key(key: &[u8; 32]) -> String {
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    async fn external_dir(key: &[u8; 32]) -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().unwrap();
        let b64 = encode_key(key);
        let keyring = Keyring::load(tmp.path().to_str().unwrap(), Some(&b64))
            .await
            .unwrap();
        let id = keyring.active_id().to_string();
        let bucket = tmp.path().join("buckets/bkt");
        std::fs::create_dir_all(&bucket).unwrap();
        std::fs::write(bucket.join("a.txt"), b"").unwrap();
        let meta = ObjectMeta {
            key: "a.txt".into(),
            size: 0,
            etag: "\"d41d8cd98f00b204e9800998ecf8427e\"".into(),
            content_type: "application/octet-stream".into(),
            last_modified: "2020-01-01T00:00:00.000Z".into(),
            encryption: Some(EncryptionMeta {
                algorithm: "AES256".into(),
                mode: EncryptionMode::SseS3,
                key_id: Some(id),
                wrapped_dek: None,
                wrap_nonce: None,
                customer_key_md5: None,
                nonce_prefix: "AAAA".into(),
                chunk_size: 65536,
                sidecar_mac: String::new(),
            }),
            ..ObjectMeta::default()
        };
        std::fs::write(
            bucket.join("a.txt.meta.json"),
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();
        assert!(!tmp.path().join(".maxio-keys.json").exists());
        let check = std::fs::read_to_string(tmp.path().join(".maxio-key-check.json")).unwrap();
        assert!(
            check.contains("\"source\": \"external\""),
            "external key must be recorded in the check file: {check}"
        );
        (tmp, b64)
    }

    fn keyring_issues(report: &CheckReport) -> Vec<&Issue> {
        report
            .issues
            .iter()
            .filter(|issue| {
                matches!(
                    issue.kind,
                    IssueKind::KeyringMissing | IssueKind::KeyringUnverified
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn supplied_master_key_matches_external_key_check() {
        let key = [9u8; 32];
        let (tmp, b64) = external_dir(&key).await;
        let from_env = resolve_master_key(Some(&b64), None).await.unwrap().unwrap();
        let report = check_with(tmp.path(), false, Some(&from_env))
            .await
            .unwrap();
        assert!(
            keyring_issues(&report).is_empty(),
            "{:?}",
            keyring_issues(&report)
        );
        assert_eq!(report.unresolved(), 0);
    }

    #[tokio::test]
    async fn master_key_file_matches_external_key_check() {
        let key = [4u8; 32];
        let (tmp, b64) = external_dir(&key).await;
        let key_path = tmp.path().join("outside.key");
        std::fs::write(&key_path, format!("{b64}\n")).unwrap();
        let from_file = resolve_master_key(None, Some(&key_path))
            .await
            .unwrap()
            .unwrap();
        let report = check_with(tmp.path(), false, Some(&from_file))
            .await
            .unwrap();
        assert!(keyring_issues(&report).is_empty(), "{:?}", report.issues);
        assert_eq!(report.unresolved(), 0);
    }

    #[tokio::test]
    async fn external_key_check_without_a_key_is_a_note() {
        let key = [5u8; 32];
        let (tmp, _) = external_dir(&key).await;
        let report = check_with(tmp.path(), false, None).await.unwrap();
        assert_eq!(report.unresolved(), 0, "{:?}", report.issues);
        let notes = keyring_issues(&report);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].advisory);
        assert_eq!(notes[0].kind, IssueKind::KeyringUnverified);
        assert!(
            notes[0].detail.contains("--master-key"),
            "{}",
            notes[0].detail
        );
        assert!(
            !notes[0].detail.contains("cannot be recovered"),
            "{}",
            notes[0].detail
        );
    }

    #[tokio::test]
    async fn wrong_master_key_is_an_error() {
        let key = [6u8; 32];
        let (tmp, _) = external_dir(&key).await;
        let wrong = encode_key(&[8u8; 32]);
        let resolved = resolve_master_key(Some(&wrong), None)
            .await
            .unwrap()
            .unwrap();
        let report = check_with(tmp.path(), false, Some(&resolved))
            .await
            .unwrap();
        assert!(report.unresolved() >= 1, "{:?}", report.issues);
        let issues = keyring_issues(&report);
        assert!(
            issues.iter().any(|issue| {
                issue.kind == IssueKind::KeyringMissing
                    && !issue.advisory
                    && issue.detail.contains("does not match")
            }),
            "{:?}",
            report.issues
        );
    }

    #[tokio::test]
    async fn deleted_on_disk_keyring_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        Keyring::load(dir, None).await.unwrap();
        let check_json = std::fs::read_to_string(tmp.path().join(".maxio-key-check.json")).unwrap();
        assert!(
            check_json.contains("\"source\": \"on-disk\""),
            "on-disk keyring must be recorded in the check file: {check_json}"
        );
        let keyring_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(tmp.path().join(".maxio-keys.json")).unwrap(),
        )
        .unwrap();
        let saved = keyring_json["keys"][0]["key_b64"]
            .as_str()
            .unwrap()
            .to_string();
        std::fs::remove_file(tmp.path().join(".maxio-keys.json")).unwrap();
        let report = check(tmp.path(), false).await.unwrap();
        assert!(report.unresolved() >= 1, "{:?}", report.issues);
        let issues = keyring_issues(&report);
        assert!(
            issues.iter().any(|issue| {
                issue.kind == IssueKind::KeyringMissing
                    && !issue.advisory
                    && issue.detail.contains("cannot be recovered")
                    && issue.detail.contains(".maxio-keys.json")
            }),
            "{:?}",
            report.issues
        );
        assert!(
            !issues
                .iter()
                .any(|issue| issue.kind == IssueKind::KeyringUnverified),
            "{:?}",
            report.issues
        );

        let resolved = resolve_master_key(Some(&saved), None)
            .await
            .unwrap()
            .unwrap();
        let with_key = check_with(tmp.path(), false, Some(&resolved))
            .await
            .unwrap();
        assert!(
            keyring_issues(&with_key).is_empty(),
            "the original key still verifies after the file is gone: {:?}",
            with_key.issues
        );
        assert_eq!(with_key.unresolved(), 0);
    }

    #[tokio::test]
    async fn legacy_check_file_without_source_stays_a_note() {
        let key = [3u8; 32];
        let (tmp, _) = external_dir(&key).await;
        let path = tmp.path().join(".maxio-key-check.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove("source");
        std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
        let report = check(tmp.path(), false).await.unwrap();
        assert_eq!(report.unresolved(), 0, "{:?}", report.issues);
        let notes = keyring_issues(&report);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].kind, IssueKind::KeyringUnverified);
        assert!(notes[0].advisory);
    }

    #[tokio::test]
    async fn repair_refuses_while_the_data_dir_lock_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let _lock = crate::storage::lock::acquire_exclusive(
            tmp.path(),
            crate::storage::lock::LockReason::Serve,
        )
        .unwrap();
        let err = check(tmp.path(), true).await.unwrap_err();
        assert!(err.to_string().contains(".maxio.lock"), "{err}");
        let report = check(tmp.path(), false).await.unwrap();
        assert_eq!(report.unresolved(), 0);
    }

    #[tokio::test]
    async fn check_does_not_flag_iam_json() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        let kr = crate::storage::keys::Keyring::load(dir, None)
            .await
            .unwrap();
        let iam = format!(
            r#"{{"version":1,"users":[],"keys":[{{"secret":{{"keyId":"{}","nonce":"AA","ciphertext":"AA"}}}}],"policies":[]}}"#,
            kr.active_id()
        );
        std::fs::write(tmp.path().join("iam.json"), &iam).unwrap();
        let report = check(tmp.path(), true).await.unwrap();
        assert!(
            report.issues.iter().all(|issue| {
                !issue.path.contains("iam.json")
                    && !issue.detail.contains("iam.json")
                    && issue.kind != IssueKind::LegacyReservedKey
            }),
            "{:?}",
            report
                .issues
                .iter()
                .map(|issue| (
                    issue.kind.as_str(),
                    issue.path.clone(),
                    issue.detail.clone()
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(report.unresolved(), 0);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("iam.json")).unwrap(),
            iam
        );
        assert!(!tmp.path().join(".maxio-quarantine").exists());
        let legacy =
            crate::storage::filesystem::find_legacy_reserved_keys(&tmp.path().join("buckets"))
                .await;
        assert!(legacy.is_empty());
    }
}
