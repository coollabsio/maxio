//! Offline scan of a data directory.
//!
//! `maxio check` reports objects and metadata that a crash can leave
//! inconsistent. `--repair` fixes only the cases where the bytes on disk are
//! enough to restore a consistent view: stale temps, stranded publish
//! backups, key promotions left in `.maxio-promote-*`, upload debris, and
//! erasure-coded chunks that parity can rebuild. Object bytes with no
//! sidecar are quarantined under `<data-dir>/.maxio-quarantine/` rather than
//! adopted: those bytes may be SSE-S3 ciphertext, and a plaintext sidecar
//! would serve them without encryption headers. A checksum that does not match
//! the payload is the same kind of finding: `--repair` moves the object into
//! `.maxio-quarantine/` and does not rewrite the checksum. A single-part etag
//! (the MD5 of the object) is checked the same way when the sidecar has no
//! checksum. `--accept-current-checksums` with `--repair` records the payload's
//! checksum or single-part etag instead. A multipart etag (`-N`) is not the MD5
//! of the whole object: it is reported as unverifiable and left unchanged.
//! When the current bytes of a versioned object are quarantined and an intact
//! version remains, `--repair` copies that version back to the current object.
//! A sidecar is never deleted
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
use base64::Engine;
use md5::{Digest, Md5};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    /// Bucket directory `maxio` or `ui`, reserved by this version.
    ReservedBucket,
    /// The current object does not match the newest version (or a delete marker).
    CurrentVersionMismatch,
    /// Archived bytes of the current version are corrupt. The current object is intact.
    VersionArchiveCorrupt,
    /// Multipart etag (`-N`) is not the MD5 of the whole object. Informational.
    MultipartEtag,
    /// Two copies differ and neither can be positively verified.
    UnverifiableDivergence,
    /// Stored content hash does not match the file.
    ContentHashMismatch,
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
            Self::ReservedBucket => "reserved-bucket",
            Self::CurrentVersionMismatch => "current-version-mismatch",
            Self::VersionArchiveCorrupt => "version-archive",
            Self::MultipartEtag => "multipart-etag",
            Self::UnverifiableDivergence => "unverifiable-divergence",
            Self::ContentHashMismatch => "content-hash",
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

    /// Process exit text. `--repair` never tells the operator to run `--repair` again.
    pub fn failure_message(&self, repair: bool) -> String {
        let open: Vec<&Issue> = self
            .issues
            .iter()
            .filter(|issue| !issue.advisory && !issue.repaired)
            .collect();
        let mut notes = Vec::new();
        if open
            .iter()
            .any(|issue| issue.kind == IssueKind::KeyringMissing)
        {
            notes.push(
                "A missing or mismatched SSE-S3 master key cannot be cleared with --repair. Pass the original key with --master-key, --master-key-file, MAXIO_MASTER_KEY, or MAXIO_MASTER_KEY_FILE.".to_string(),
            );
        }
        if open
            .iter()
            .any(|issue| issue.kind == IssueKind::ReservedBucket)
        {
            notes.push(
                "A reserved bucket has to be emptied with the previous MaxIO version and removed (for example `aws s3 rb`). check does not delete it.".to_string(),
            );
        }
        if open
            .iter()
            .any(|issue| issue.kind == IssueKind::LegacyReservedKey)
        {
            notes.push(
                "An object key that uses a reserved name has to be renamed or deleted with the previous MaxIO version (for example `aws s3 mv`). check does not modify it.".to_string(),
            );
        }
        let manual = |kind: IssueKind| {
            matches!(
                kind,
                IssueKind::KeyringMissing
                    | IssueKind::ReservedBucket
                    | IssueKind::LegacyReservedKey
            )
        };
        let only_manual = open.iter().all(|issue| manual(issue.kind));
        if repair || only_manual {
            if notes.is_empty() {
                notes.push(
                    "The remaining issues need a manual fix. The report above names each path."
                        .to_string(),
                );
            }
            format!("{} unresolved issue(s). {}", open.len(), notes.join(" "))
        } else {
            notes.push("rerun with --repair for the cases MaxIO can fix safely".to_string());
            format!("{} unresolved issue(s); {}", open.len(), notes.join(" "))
        }
    }

    pub fn print(&self) {
        for issue in &self.issues {
            let action = if issue.repaired {
                "repaired"
            } else if issue.advisory {
                "info"
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
        let counted = self.issues.iter().filter(|issue| !issue.advisory).count();
        println!(
            "checked {} object(s), {} issue(s), {} unresolved",
            self.objects_seen,
            counted,
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
    check_with_opts(data_dir, repair, master_key_b64, false, false).await
}

/// `accept_current_checksums` records a mismatched payload's checksum instead of quarantining it.
pub async fn check_with_opts(
    data_dir: &Path,
    repair: bool,
    master_key_b64: Option<&str>,
    accept_current_checksums: bool,
    accept_unverifiable_current: bool,
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
    let keyring = if master_key_b64.is_some()
        || tokio::fs::try_exists(data_dir.join(".maxio-keys.json")).await?
    {
        super::keys::Keyring::load(data_dir.to_str().unwrap_or("."), master_key_b64)
            .await
            .ok()
            .map(Arc::new)
    } else {
        None
    };
    let buckets_dir = data_dir.join("buckets");
    for name in super::filesystem::reserved_buckets_present(&buckets_dir).await {
        report.push(
            IssueKind::ReservedBucket,
            &buckets_dir.join(name),
            &format!(
                "bucket name {name} is reserved. Start the previous MaxIO version on this data directory, move the objects out, and remove the bucket, then start this version. check does not remove it."
            ),
            false,
        );
    }
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
                    accept_current_checksums,
                    accept_unverifiable_current,
                    keyring.as_ref(),
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
    accept_current_checksums: bool,
    accept_unverifiable_current: bool,
    keyring: Option<&Arc<super::keys::Keyring>>,
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
                path,
                bucket_dir,
                bucket,
                data_dir,
                &prefix,
                repair,
                accept_current_checksums,
                keyring,
                report,
                saw_sse_s3,
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
                bucket_dir,
                bucket,
                data_dir,
                PairFlags {
                    repair,
                    keep_sidecar: guard.keeps(stem),
                    accept_current_checksums,
                },
                keyring,
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

        // After current objects are quarantined, put an intact version back
        // in place (or apply a newest delete marker). Running this earlier
        // would restore a payload that the etag check then quarantines.
        if let Some((_, path, _)) = entries.iter().find(|(n, _, d)| n == ".versions" && *d) {
            reconcile_versions_in(
                path,
                bucket_dir,
                bucket,
                data_dir,
                &prefix,
                repair,
                accept_current_checksums,
                accept_unverifiable_current,
                keyring,
                report,
            )
            .await?;
        }
    }
    Ok(())
}

struct PairFlags {
    repair: bool,
    keep_sidecar: bool,
    accept_current_checksums: bool,
}

async fn check_meta_pair(
    meta_path: &Path,
    data_path: &Path,
    ec_path: &Path,
    key: &str,
    bucket_dir: &Path,
    bucket: &str,
    data_dir: &Path,
    flags: PairFlags,
    keyring: Option<&Arc<super::keys::Keyring>>,
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
    let mut dirty = false;
    let file_len = tokio::fs::metadata(data_path).await?.len();
    // A crashed publish can leave a newer payload with the previous sidecar.
    // A size change is that case and is repaired below. A same-size content
    // hash miss is damage: do not adopt the bytes.
    let size_changed = !encrypted && file_len != meta.size;
    if !size_changed {
        if let Some(expected) = meta.content_sha256.clone() {
            let actual = match file_sha256_hex(data_path).await {
                Ok(actual) => actual,
                Err(err) => {
                    report.push(
                        IssueKind::ContentHashMismatch,
                        data_path,
                        format!("stored content hash could not be checked: {err}"),
                        false,
                    );
                    return Ok(());
                }
            };
            if actual != expected {
                if repair && flags.accept_current_checksums {
                    report.push(
                    IssueKind::ContentHashMismatch,
                    data_path,
                    format!(
                        "stored content hash is {expected}, file hashes to {actual}. Recorded the file hash because --accept-current-checksums was set."
                    ),
                    true,
                );
                    meta.content_sha256 = Some(actual);
                    dirty = true;
                } else if repair {
                    match quarantine_payload(data_dir, bucket, bucket_dir, data_path, meta_path)
                        .await
                    {
                        Ok(dest) => {
                            report.push(
                            IssueKind::ContentHashMismatch,
                            data_path,
                            format!(
                                "stored content hash is {expected}, file hashes to {actual}. Quarantined at {} without deleting the bytes.",
                                dest.display()
                            ),
                            true,
                        );
                        }
                        Err(err) => {
                            report.push(
                            IssueKind::ContentHashMismatch,
                            data_path,
                            format!(
                                "stored content hash is {expected}, file hashes to {actual}. Quarantine failed: {err}."
                            ),
                            false,
                        );
                        }
                    }
                    return Ok(());
                } else {
                    report.push(
                    IssueKind::ContentHashMismatch,
                    data_path,
                    format!(
                        "stored content hash is {expected}, file hashes to {actual}. The hash was not rewritten."
                    ),
                    false,
                );
                }
            }
        }
    }
    // Ciphertext length and MD5 are not the plaintext size and etag.
    if !encrypted {
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
                if etag_is_multipart(&meta.etag) {
                    report.note(
                        IssueKind::MultipartEtag,
                        data_path,
                        "multipart etag (not verifiable by MD5)",
                    );
                } else {
                    meta.etag = file_md5_quoted(data_path).await?;
                    meta.part_sizes = None;
                }
                meta.content_sha256 = Some(file_sha256_hex(data_path).await?);
                dirty = true;
            }
        } else if etag_is_multipart(&meta.etag) {
            if meta.checksum_algorithm.is_none() {
                report.note(
                    IssueKind::MultipartEtag,
                    data_path,
                    "multipart etag (not verifiable by MD5)",
                );
            }
        } else {
            let etag = file_md5_quoted(data_path).await?;
            if etag != meta.etag {
                if repair && flags.accept_current_checksums {
                    report.push(
                        IssueKind::EtagMismatch,
                        data_path,
                        format!(
                            "sidecar etag is {}, file hashes to {etag}. Recorded the payload etag because --accept-current-checksums was set.",
                            meta.etag
                        ),
                        true,
                    );
                    meta.etag = etag;
                    dirty = true;
                } else if repair {
                    match quarantine_payload(data_dir, bucket, bucket_dir, data_path, meta_path)
                        .await
                    {
                        Ok(dest) => {
                            report.push(
                                IssueKind::EtagMismatch,
                                data_path,
                                format!(
                                    "sidecar etag is {}, file hashes to {etag}. Quarantined at {} without deleting the bytes and without adopting the payload etag.",
                                    meta.etag,
                                    dest.display()
                                ),
                                true,
                            );
                        }
                        Err(err) => {
                            report.push(
                                IssueKind::EtagMismatch,
                                data_path,
                                format!(
                                    "sidecar etag is {}, file hashes to {etag}. Quarantine failed: {err}. The object was left in place and the etag was not rewritten.",
                                    meta.etag
                                ),
                                false,
                            );
                        }
                    }
                    return Ok(());
                } else {
                    report.push(
                        IssueKind::EtagMismatch,
                        data_path,
                        format!(
                            "sidecar etag is {}, file hashes to {etag}. The etag was not rewritten. --repair moves the object under .maxio-quarantine. --accept-current-checksums with --repair records the payload etag instead.",
                            meta.etag
                        ),
                        false,
                    );
                }
            }
        }
    }

    if let (Some(algo), Some(expected)) = (meta.checksum_algorithm, meta.checksum_value.clone()) {
        match payload_checksum(data_path, &meta, algo, bucket, key, keyring).await {
            Ok(actual) if actual == expected => {}
            Ok(actual) if repair && flags.accept_current_checksums => {
                report.push(
                    IssueKind::ChecksumMismatch,
                    data_path,
                    format!(
                        "sidecar checksum is {expected}, payload is {actual}. Recorded the payload checksum because --accept-current-checksums was set."
                    ),
                    true,
                );
                meta.checksum_value = Some(actual);
                dirty = true;
            }
            outcome => {
                let why = match outcome {
                    Ok(actual) => format!("sidecar checksum is {expected}, payload is {actual}"),
                    Err(err) => format!(
                        "sidecar checksum is {expected}, payload could not be verified: {err}"
                    ),
                };
                if repair && !flags.accept_current_checksums {
                    match quarantine_payload(data_dir, bucket, bucket_dir, data_path, meta_path)
                        .await
                    {
                        Ok(dest) => {
                            report.push(
                                IssueKind::ChecksumMismatch,
                                data_path,
                                format!(
                                    "{why}. Quarantined at {} without deleting the bytes and without adopting the payload checksum.",
                                    dest.display()
                                ),
                                true,
                            );
                        }
                        Err(err) => {
                            report.push(
                                IssueKind::ChecksumMismatch,
                                data_path,
                                format!("{why}. Quarantine failed: {err}. The object was left in place and the checksum was not rewritten."),
                                false,
                            );
                        }
                    }
                    return Ok(());
                }
                report.push(
                    IssueKind::ChecksumMismatch,
                    data_path,
                    format!(
                        "{why}. The checksum was not rewritten. --repair moves the object under .maxio-quarantine. --accept-current-checksums with --repair records the payload checksum instead."
                    ),
                    false,
                );
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
    accept_current_checksums: bool,
    keyring: Option<&Arc<super::keys::Keyring>>,
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
                bucket_dir,
                bucket,
                data_dir,
                PairFlags {
                    repair,
                    keep_sidecar: false,
                    accept_current_checksums,
                },
                keyring,
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

fn etag_is_multipart(etag: &str) -> bool {
    let bare = etag.trim_matches('"');
    let Some((hash, count)) = bare.rsplit_once('-') else {
        return false;
    };
    !hash.is_empty()
        && hash.chars().all(|c| c.is_ascii_hexdigit())
        && count.parse::<u32>().is_ok_and(|n| n >= 1)
}

async fn reconcile_versions_in(
    versions_dir: &Path,
    bucket_dir: &Path,
    bucket: &str,
    data_dir: &Path,
    prefix: &str,
    repair: bool,
    accept_current_checksums: bool,
    accept_unverifiable_current: bool,
    keyring: Option<&Arc<super::keys::Keyring>>,
    report: &mut CheckReport,
) -> anyhow::Result<()> {
    let mut keys = match tokio::fs::read_dir(versions_dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    while let Some(entry) = keys.next_entry().await? {
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let key = format!("{prefix}{name}");
        if key_contains_reserved_segment(&key) {
            continue;
        }
        reconcile_one_key(
            &entry.path(),
            bucket_dir,
            bucket,
            data_dir,
            &key,
            repair,
            accept_current_checksums,
            accept_unverifiable_current,
            keyring,
            report,
        )
        .await?;
    }
    Ok(())
}

enum CurrentExpectation {
    DeleteMarker { vid: String },
    Intact { vid: String, meta: Box<ObjectMeta> },
    NoIntactVersion,
}

async fn reconcile_one_key(
    ver_dir: &Path,
    bucket_dir: &Path,
    bucket: &str,
    data_dir: &Path,
    key: &str,
    repair: bool,
    accept_current_checksums: bool,
    accept_unverifiable_current: bool,
    keyring: Option<&Arc<super::keys::Keyring>>,
    report: &mut CheckReport,
) -> anyhow::Result<()> {
    let ids = list_version_ids(ver_dir).await?;
    let (plain, inline, meta_path, ec_path) = object_locations(bucket_dir, key);
    let data_path = current_data_path(&plain, &inline).await;
    let current_meta = read_object_meta(&meta_path).await;
    let current_intact = is_file(&data_path).await
        && sidecar_matches_payload(&data_path, &meta_path, bucket, key, keyring).await;
    // A null version (written while versioning was suspended, or before
    // versioning) is newer than every archived version. Keep it unless its
    // stored etag, checksum, or content hash positively fails. Unverifiable
    // is not a match, but it is also not permission to roll the key back.
    if is_file(&data_path).await
        && current_meta
            .as_ref()
            .is_some_and(|meta| meta.version_id.is_none() && !meta.is_delete_marker)
    {
        let verdict = payload_verdict(
            &data_path,
            current_meta.as_ref().unwrap(),
            bucket,
            key,
            keyring,
        )
        .await;
        if verdict != PayloadVerdict::Failed {
            return Ok(());
        }
    }
    if ids.is_empty() && !current_intact {
        return Ok(());
    }
    // `--repair` may already have quarantined a corrupt newest archive, so
    // the version id can be missing from `.versions` while the current object
    // still names it. That id stays the newest version.
    let newest = if current_intact {
        match current_meta
            .as_ref()
            .and_then(|meta| meta.version_id.clone())
        {
            Some(vid)
                if ids
                    .first()
                    .is_none_or(|id| vid == *id || version_is_newer(&vid, id)) =>
            {
                vid
            }
            _ => ids.first().cloned().unwrap_or_default(),
        }
    } else {
        ids.first().cloned().unwrap_or_default()
    };
    if newest.is_empty() {
        return Ok(());
    }
    let newest_meta = read_object_meta(&ver_dir.join(format!("{newest}.meta.json")))
        .await
        .or_else(|| {
            current_meta
                .as_ref()
                .filter(|meta| meta.version_id.as_deref() == Some(newest.as_str()))
                .cloned()
        });
    if let Some(newest_meta) = newest_meta {
        if !newest_meta.is_delete_marker
            && current_intact
            && current_meta
                .as_ref()
                .is_some_and(|meta| meta.version_id.as_deref() == Some(newest.as_str()))
        {
            let archive_matches = current_matches_version(&data_path, &meta_path, &newest, ver_dir)
                .await
                && version_payload_intact(ver_dir, &newest, &newest_meta, bucket, key, keyring)
                    .await;
            if archive_matches {
                return Ok(());
            }
            let detail = format!(
                "archived copy of version {newest} of {bucket}/{key} is corrupt or missing, but the current object matches its stored etag or checksum and is that version"
            );
            if !repair {
                report.push(
                    IssueKind::VersionArchiveCorrupt,
                    &ver_dir.join(format!("{newest}.data")),
                    format!(
                        "{detail}. Not modified. --repair quarantines only the corrupt version file and rebuilds the archived copy from the current object."
                    ),
                    false,
                );
                return Ok(());
            }
            let _ = quarantine_version_copy(data_dir, bucket, bucket_dir, ver_dir, &newest).await;
            let Some(current) = read_object_meta(&meta_path).await else {
                report.push(
                    IssueKind::VersionArchiveCorrupt,
                    &meta_path,
                    format!("{detail}. The current sidecar disappeared before the archive could be rebuilt."),
                    false,
                );
                return Ok(());
            };
            publish_version_from_current(ver_dir, &newest, &data_path, &current).await?;
            report.push(
                IssueKind::VersionArchiveCorrupt,
                &data_path,
                format!(
                    "{detail}. Rebuilt the archived copy from the current object. The current bytes were kept."
                ),
                true,
            );
            return Ok(());
        }
    }

    if is_file(&data_path).await
        && current_meta
            .as_ref()
            .is_some_and(|meta| meta.version_id.as_deref() == Some(newest.as_str()))
        && !current_intact
    {
        let meta = current_meta.as_ref().unwrap();
        if payload_verdict(&data_path, meta, bucket, key, keyring).await
            == PayloadVerdict::Unverifiable
        {
            let archive = ver_dir.join(format!("{newest}.data"));
            let same = is_file(&archive).await && files_same(&data_path, &archive).await;
            let archive_verified =
                match read_object_meta(&ver_dir.join(format!("{newest}.meta.json"))).await {
                    Some(archive_meta) if is_file(&archive).await => {
                        payload_verdict(&archive, &archive_meta, bucket, key, keyring).await
                            == PayloadVerdict::Verified
                    }
                    _ => false,
                };
            if !same && !archive_verified {
                let detail = format!(
                    "current object {bucket}/{key} and archived version {newest} differ and neither copy can be verified"
                );
                if repair && accept_unverifiable_current && meta.encryption.is_none() {
                    let hash = file_sha256_hex(&data_path).await?;
                    let mut adopted = meta.clone();
                    adopted.content_sha256 = Some(hash);
                    write_file_atomic(&meta_path, serde_json::to_vec_pretty(&adopted)?.as_slice())
                        .await
                        .map_err(|err| anyhow::anyhow!(err))?;
                    let _ = quarantine_version_copy(data_dir, bucket, bucket_dir, ver_dir, &newest)
                        .await;
                    publish_version_from_current(ver_dir, &newest, &data_path, &adopted).await?;
                    report.push(
                        IssueKind::UnverifiableDivergence,
                        &data_path,
                        format!(
                            "{detail}. Recorded a content hash of the current bytes and rebuilt the archive because --accept-unverifiable-current was set."
                        ),
                        true,
                    );
                } else {
                    report.push(
                        IssueKind::UnverifiableDivergence,
                        &data_path,
                        format!(
                            "{detail}. Not modified. --repair does not overwrite either copy. --accept-unverifiable-current with --repair records a content hash of the current bytes and rebuilds the archive from them."
                        ),
                        false,
                    );
                }
                return Ok(());
            }
        }
    }

    let expected = version_expectation(ver_dir, &ids, bucket, key, keyring).await?;
    let current_present = is_file(&data_path).await || is_file(&meta_path).await;
    match expected {
        CurrentExpectation::DeleteMarker { vid } => {
            if !current_present {
                return Ok(());
            }
            let detail = format!(
                "newest version {vid} of {bucket}/{key} is a delete marker, but a current object is still present"
            );
            if repair {
                remove_current_object(&plain, &inline, &meta_path, &ec_path).await;
                report.push(
                    IssueKind::CurrentVersionMismatch,
                    &meta_path,
                    format!("{detail}. Removed the current object so a plain GET stays deleted."),
                    true,
                );
            } else {
                report.push(
                    IssueKind::CurrentVersionMismatch,
                    &meta_path,
                    format!("{detail}. Not modified."),
                    false,
                );
            }
        }
        CurrentExpectation::Intact { vid, meta } => {
            if current_matches_version(&data_path, &meta_path, &vid, ver_dir).await {
                return Ok(());
            }
            if repair
                && accept_current_checksums
                && sidecar_matches_payload(&data_path, &meta_path, bucket, key, keyring).await
            {
                if let Some(current) = read_object_meta(&meta_path).await {
                    if current.version_id.as_deref() == Some(vid.as_str()) {
                        publish_version_from_current(ver_dir, &vid, &data_path, &current).await?;
                        report.push(
                            IssueKind::CurrentVersionMismatch,
                            &data_path,
                            format!(
                                "current object {bucket}/{key} was kept and version {vid} was updated from it because --accept-current-checksums was set."
                            ),
                            true,
                        );
                        return Ok(());
                    }
                }
            }
            let detail = if current_present {
                format!("current object {bucket}/{key} does not match intact version {vid}")
            } else {
                format!(
                    "current object {bucket}/{key} is missing while intact version {vid} is still stored"
                )
            };
            if !repair {
                report.push(
                    IssueKind::CurrentVersionMismatch,
                    &meta_path,
                    format!(
                        "{detail}. Not modified. --repair restores the current object from that version."
                    ),
                    false,
                );
                return Ok(());
            }
            let quarantined = if current_present && is_file(&data_path).await {
                match quarantine_payload(data_dir, bucket, bucket_dir, &data_path, &meta_path).await
                {
                    Ok(dest) => Some(dest),
                    Err(err) => {
                        report.push(
                            IssueKind::CurrentVersionMismatch,
                            &data_path,
                            format!(
                                "{detail}. Quarantine failed: {err}. The current object was left in place."
                            ),
                            false,
                        );
                        return Ok(());
                    }
                }
            } else {
                if current_present {
                    remove_current_object(&plain, &inline, &meta_path, &ec_path).await;
                }
                None
            };
            restore_version_payload(ver_dir, &vid, &meta, &data_path, &meta_path, &ec_path).await?;
            let action = match &quarantined {
                Some(dest) => format!(
                    "{detail}. Quarantined the current bytes at {} and restored the current object from version {vid}.",
                    dest.display()
                ),
                None => format!("{detail}. Restored the current object from version {vid}."),
            };
            report.push(IssueKind::CurrentVersionMismatch, &meta_path, action, true);
        }
        CurrentExpectation::NoIntactVersion => {
            if !current_present {
                report.push(
                    IssueKind::CurrentVersionMismatch,
                    &meta_path,
                    format!(
                        "current object {bucket}/{key} is missing and no intact version can restore it"
                    ),
                    false,
                );
            }
        }
    }
    Ok(())
}

async fn version_expectation(
    ver_dir: &Path,
    ids: &[String],
    bucket: &str,
    key: &str,
    keyring: Option<&Arc<super::keys::Keyring>>,
) -> anyhow::Result<CurrentExpectation> {
    for vid in ids {
        let meta_path = ver_dir.join(format!("{vid}.meta.json"));
        let Some(meta) = read_object_meta(&meta_path).await else {
            continue;
        };
        if meta.is_delete_marker {
            return Ok(CurrentExpectation::DeleteMarker { vid: vid.clone() });
        }
        if version_payload_intact(ver_dir, vid, &meta, bucket, key, keyring).await {
            return Ok(CurrentExpectation::Intact {
                vid: vid.clone(),
                meta: Box::new(meta),
            });
        }
    }
    Ok(CurrentExpectation::NoIntactVersion)
}

fn version_is_newer(a: &str, b: &str) -> bool {
    match (a == "null", b == "null") {
        (true, _) => false,
        (false, true) => true,
        _ => a > b,
    }
}

async fn list_version_ids(ver_dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut ids = Vec::new();
    let mut read = tokio::fs::read_dir(ver_dir).await?;
    while let Some(entry) = read.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(vid) = name.strip_suffix(".meta.json") {
            if !vid.is_empty() {
                ids.push(vid.to_string());
            }
        }
    }
    ids.sort_by(|a, b| match (a.as_str() == "null", b.as_str() == "null") {
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        _ => b.cmp(a),
    });
    Ok(ids)
}

fn object_locations(bucket_dir: &Path, key: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let key_path = Path::new(key);
    let parent = key_path.parent().unwrap_or(Path::new(""));
    let name = key_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| key.to_string());
    let dir = bucket_dir.join(parent);
    let plain = dir.join(&name);
    let inline = plain.join(INLINE_OBJECT_PAYLOAD);
    let meta = dir.join(format!("{name}.meta.json"));
    let ec = dir.join(format!("{name}.ec"));
    (plain, inline, meta, ec)
}

async fn current_data_path(plain: &Path, inline: &Path) -> std::path::PathBuf {
    if is_file(inline).await
        || tokio::fs::metadata(plain)
            .await
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
    {
        inline.to_path_buf()
    } else {
        plain.to_path_buf()
    }
}

async fn read_object_meta(path: &Path) -> Option<ObjectMeta> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    serde_json::from_str(&raw).ok()
}

async fn version_payload_intact(
    ver_dir: &Path,
    vid: &str,
    meta: &ObjectMeta,
    bucket: &str,
    key: &str,
    keyring: Option<&Arc<super::keys::Keyring>>,
) -> bool {
    let data = ver_dir.join(format!("{vid}.data"));
    let ec = ver_dir.join(format!("{vid}.ec"));
    let ec_exists = tokio::fs::metadata(&ec)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false);
    let data_exists = is_file(&data).await;
    if ec_exists && data_exists {
        return false;
    }
    if ec_exists {
        return tokio::fs::try_exists(ec.join("manifest.json"))
            .await
            .unwrap_or(false);
    }
    if !data_exists {
        return false;
    }
    payload_verdict(&data, meta, bucket, key, keyring).await == PayloadVerdict::Verified
}

async fn sidecar_matches_payload(
    data_path: &Path,
    meta_path: &Path,
    bucket: &str,
    key: &str,
    keyring: Option<&Arc<super::keys::Keyring>>,
) -> bool {
    if !is_file(data_path).await {
        return false;
    }
    let Some(meta) = read_object_meta(meta_path).await else {
        return false;
    };
    payload_verdict(data_path, &meta, bucket, key, keyring).await == PayloadVerdict::Verified
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadVerdict {
    /// Etag, checksum, or content hash matched the stored bytes.
    Verified,
    /// A stored check ran and did not match.
    Failed,
    /// No single-part MD5, checksum, or content hash can be checked.
    Unverifiable,
}

async fn payload_verdict(
    data_path: &Path,
    meta: &ObjectMeta,
    bucket: &str,
    key: &str,
    keyring: Option<&Arc<super::keys::Keyring>>,
) -> PayloadVerdict {
    if let Some(expected) = &meta.content_sha256 {
        return match file_sha256_hex(data_path).await {
            Ok(actual) if actual == *expected => PayloadVerdict::Verified,
            _ => PayloadVerdict::Failed,
        };
    }
    if let (Some(algo), Some(expected)) = (meta.checksum_algorithm, meta.checksum_value.as_deref())
    {
        return match payload_checksum(data_path, meta, algo, bucket, key, keyring).await {
            Ok(actual) if actual == expected => PayloadVerdict::Verified,
            Ok(_) => PayloadVerdict::Failed,
            Err(_) => PayloadVerdict::Unverifiable,
        };
    }
    if meta.encryption.is_some() || etag_is_multipart(&meta.etag) {
        return PayloadVerdict::Unverifiable;
    }
    let Ok(len) = tokio::fs::metadata(data_path).await.map(|m| m.len()) else {
        return PayloadVerdict::Failed;
    };
    if len != meta.size {
        return PayloadVerdict::Failed;
    }
    match file_md5_quoted(data_path).await {
        Ok(etag) if etag == meta.etag => PayloadVerdict::Verified,
        _ => PayloadVerdict::Failed,
    }
}

async fn files_same(left: &Path, right: &Path) -> bool {
    match (file_sha256_hex(left).await, file_sha256_hex(right).await) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

async fn file_sha256_hex(path: &Path) -> anyhow::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buf[..n]);
    }
    Ok(hex::encode(sha2::Digest::finalize(hasher)))
}

async fn current_matches_version(
    data_path: &Path,
    meta_path: &Path,
    vid: &str,
    ver_dir: &Path,
) -> bool {
    let Some(meta) = read_object_meta(meta_path).await else {
        return false;
    };
    if meta.version_id.as_deref() != Some(vid) {
        return false;
    }
    let ver_data = ver_dir.join(format!("{vid}.data"));
    let ver_ec = ver_dir.join(format!("{vid}.ec"));
    if tokio::fs::metadata(&ver_ec)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        return tokio::fs::try_exists(ver_ec.join("manifest.json"))
            .await
            .unwrap_or(false);
    }
    if !is_file(data_path).await || !is_file(&ver_data).await {
        return false;
    }
    match (
        file_md5_quoted(data_path).await,
        file_md5_quoted(&ver_data).await,
    ) {
        (Ok(current), Ok(archived)) => current == archived,
        _ => false,
    }
}

async fn remove_current_object(plain: &Path, inline: &Path, meta: &Path, ec: &Path) {
    if tokio::fs::metadata(plain)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        if is_file(inline).await {
            remove_path(inline).await;
        }
    } else if is_file(plain).await {
        remove_path(plain).await;
    }
    if is_file(meta).await {
        remove_path(meta).await;
    }
    if tokio::fs::metadata(ec)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        remove_path(ec).await;
    }
}

async fn quarantine_version_copy(
    data_dir: &Path,
    bucket: &str,
    bucket_dir: &Path,
    ver_dir: &Path,
    vid: &str,
) -> anyhow::Result<Option<PathBuf>> {
    let data = ver_dir.join(format!("{vid}.data"));
    let meta = ver_dir.join(format!("{vid}.meta.json"));
    let ec = ver_dir.join(format!("{vid}.ec"));
    if is_file(&data).await {
        let dest = quarantine_payload(data_dir, bucket, bucket_dir, &data, &meta).await?;
        return Ok(Some(dest));
    }
    if tokio::fs::metadata(&ec)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        let rel = ec.strip_prefix(bucket_dir).unwrap_or(&ec);
        let dest = data_dir.join(".maxio-quarantine").join(bucket).join(rel);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if tokio::fs::try_exists(&dest).await? {
            let _ = tokio::fs::remove_dir_all(&dest).await;
        }
        tokio::fs::rename(&ec, &dest).await?;
        if is_file(&meta).await {
            let meta_rel = meta.strip_prefix(bucket_dir).unwrap_or(&meta);
            let meta_dest = data_dir
                .join(".maxio-quarantine")
                .join(bucket)
                .join(meta_rel);
            if let Some(parent) = meta_dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::rename(&meta, &meta_dest).await?;
        }
        return Ok(Some(dest));
    }
    Ok(None)
}

async fn restore_version_payload(
    ver_dir: &Path,
    vid: &str,
    meta: &ObjectMeta,
    data_path: &Path,
    meta_path: &Path,
    ec_path: &Path,
) -> anyhow::Result<()> {
    let ver_data = ver_dir.join(format!("{vid}.data"));
    let ver_ec = ver_dir.join(format!("{vid}.ec"));
    if tokio::fs::metadata(&ver_ec)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        if tokio::fs::try_exists(ec_path).await.unwrap_or(false) {
            remove_path(ec_path).await;
        }
        copy_dir_all(&ver_ec, ec_path).await?;
        if is_file(data_path).await {
            remove_path(data_path).await;
        }
    } else {
        let dest = if tokio::fs::metadata(data_path)
            .await
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            data_path.join(INLINE_OBJECT_PAYLOAD)
        } else {
            data_path.to_path_buf()
        };
        copy_payload(&ver_data, &dest).await?;
        if tokio::fs::metadata(ec_path)
            .await
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            remove_path(ec_path).await;
        }
    }
    write_file_atomic(meta_path, serde_json::to_vec_pretty(meta)?.as_slice())
        .await
        .map_err(|err| anyhow::anyhow!(err))?;
    if vid == "null" {
        let _ = tokio::fs::remove_file(ver_dir.join("null.data")).await;
        let _ = tokio::fs::remove_dir_all(ver_dir.join("null.ec")).await;
        let _ = tokio::fs::remove_file(ver_dir.join("null.meta.json")).await;
    }
    Ok(())
}

async fn publish_version_from_current(
    ver_dir: &Path,
    vid: &str,
    current_data: &Path,
    current_meta: &ObjectMeta,
) -> anyhow::Result<()> {
    let ver_data = ver_dir.join(format!("{vid}.data"));
    let ver_ec = ver_dir.join(format!("{vid}.ec"));
    if tokio::fs::metadata(&ver_ec)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        anyhow::bail!("version {vid} is erasure-coded; its snapshot was not replaced");
    }
    copy_payload(current_data, &ver_data).await?;
    write_file_atomic(
        &ver_dir.join(format!("{vid}.meta.json")),
        serde_json::to_vec_pretty(current_meta)?.as_slice(),
    )
    .await
    .map_err(|err| anyhow::anyhow!(err))?;
    Ok(())
}

async fn copy_payload(src: &Path, dest: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = dest.with_extension("maxio-restore-tmp");
    tokio::fs::copy(src, &tmp).await?;
    tokio::fs::rename(&tmp, dest).await?;
    Ok(())
}

fn copy_dir_all<'a>(
    src: &'a Path,
    dest: &'a Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        tokio::fs::create_dir_all(dest).await?;
        let mut read = tokio::fs::read_dir(src).await?;
        while let Some(entry) = read.next_entry().await? {
            let to = dest.join(entry.file_name());
            if entry.file_type().await?.is_dir() {
                copy_dir_all(&entry.path(), &to).await?;
            } else {
                tokio::fs::copy(entry.path(), &to).await?;
            }
        }
        Ok(())
    })
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
    use md5::Digest;
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

    #[tokio::test]
    async fn existing_reserved_buckets_refuse_startup_and_check_leaves_them() {
        for name in ["maxio", "ui"] {
            let tmp = tempfile::tempdir().unwrap();
            let bucket = tmp.path().join("buckets").join(name);
            std::fs::create_dir_all(&bucket).unwrap();
            std::fs::write(
                bucket.join(".bucket.json"),
                format!("{{\"name\":\"{name}\"}}\n"),
            )
            .unwrap();
            let keyring = Arc::new(
                Keyring::load(tmp.path().to_str().unwrap(), None)
                    .await
                    .unwrap(),
            );
            let err =
                match FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0, keyring)
                    .await
                {
                    Err(err) => err.to_string(),
                    Ok(_) => panic!("startup should refuse a bucket named {name}"),
                };
            assert!(err.contains("refusing to start"), "{name}: {err}");
            assert!(err.contains(&format!("bucket named \"{name}\"")), "{err}");
            assert!(err.contains("previous MaxIO version"), "{err}");

            let report = check(tmp.path(), true).await.unwrap();
            assert!(
                report.issues.iter().any(|issue| {
                    issue.kind == IssueKind::ReservedBucket
                        && !issue.repaired
                        && issue.detail.contains(name)
                }),
                "{name}: {:?}",
                report.issues
            );
            assert!(bucket.join(".bucket.json").exists(), "{name}");
        }

        let tmp = tempfile::tempdir().unwrap();
        for name in ["maxio", "ui"] {
            let bucket = tmp.path().join("buckets").join(name);
            std::fs::create_dir_all(&bucket).unwrap();
        }
        let keyring = Arc::new(
            Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let err =
            match FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0, keyring)
                .await
            {
                Err(err) => err.to_string(),
                Ok(_) => panic!("startup should refuse both reserved buckets"),
            };
        assert!(err.contains("buckets named \"maxio\" or \"ui\""), "{err}");
    }

    #[test]
    fn repair_does_not_ask_to_rerun_repair() {
        let mut manual = CheckReport::default();
        manual.issues.push(Issue {
            kind: IssueKind::ReservedBucket,
            path: "buckets/ui".to_string(),
            detail: "bucket name ui is reserved".to_string(),
            repaired: false,
            advisory: false,
        });
        let repaired = manual.failure_message(true);
        assert!(!repaired.contains("rerun with --repair"), "{repaired}");
        assert!(repaired.contains("aws s3 rb"), "{repaired}");
        let read_only = manual.failure_message(false);
        assert!(!read_only.contains("rerun with --repair"), "{read_only}");

        let mut fixable = CheckReport::default();
        fixable.issues.push(Issue {
            kind: IssueKind::StaleTemp,
            path: "buckets/b/.maxio-tmp-x".to_string(),
            detail: "temp".to_string(),
            repaired: false,
            advisory: false,
        });
        let suggest = fixable.failure_message(false);
        assert!(suggest.contains("rerun with --repair"), "{suggest}");
        let after = fixable.failure_message(true);
        assert!(!after.contains("rerun with --repair"), "{after}");
        assert!(after.contains("manual fix"), "{after}");
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

    #[tokio::test]
    async fn checksum_mismatch_is_quarantined_not_adopted() {
        let tmp = tempfile::tempdir().unwrap();
        let keyring = Arc::new(
            crate::storage::keys::Keyring::load(tmp.path().to_str().unwrap(), None)
                .await
                .unwrap(),
        );
        let storage =
            FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await
                .unwrap();
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        let checksum = Some((crate::storage::ChecksumAlgorithm::CRC32, None));
        let put = |key: &'static str, body: &'static [u8], sse: bool| {
            let storage = &storage;
            let checksum = checksum.clone();
            async move {
                storage
                    .put_object(
                        "bkt",
                        key,
                        "text/plain",
                        Box::pin(body),
                        checksum,
                        sse.then(crate::storage::EncryptionRequest::sse_s3),
                    )
                    .await
                    .unwrap();
            }
        };
        put("plain.txt", b"plain-bytes", false).await;
        put("secret.txt", b"secret-bytes", true).await;
        put("dir", b"inline-bytes", false).await;
        put("dir/child.txt", b"child", false).await;

        let bucket = tmp.path().join("buckets/bkt");
        let flip = |path: &std::path::Path| {
            let mut bytes = std::fs::read(path).unwrap();
            bytes[0] ^= 0xff;
            std::fs::write(path, bytes).unwrap();
        };
        flip(&bucket.join("plain.txt"));
        flip(&bucket.join("secret.txt"));
        flip(&bucket.join("dir/.maxio.object"));
        let plain_sum = std::fs::read_to_string(bucket.join("plain.txt.meta.json")).unwrap();
        assert!(plain_sum.contains("checksum_value"));

        let reported = check(tmp.path(), false).await.unwrap();
        let mismatches: Vec<_> = reported
            .issues
            .iter()
            .filter(|issue| issue.kind == IssueKind::ChecksumMismatch)
            .collect();
        assert!(
            mismatches.len() >= 3,
            "expected plain, sse, and inline mismatches: {:?}",
            reported.issues
        );
        assert!(mismatches.iter().all(|issue| !issue.repaired));
        assert!(bucket.join("plain.txt").is_file());
        assert_eq!(
            std::fs::read_to_string(bucket.join("plain.txt.meta.json")).unwrap(),
            plain_sum,
            "a read-only check must not rewrite the checksum"
        );

        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired
                .issues
                .iter()
                .any(|issue| issue.kind == IssueKind::ContentHashMismatch
                    && issue.repaired
                    && issue.detail.contains("Quarantined")),
            "{:?}",
            repaired.issues
        );
        assert!(!bucket.join("plain.txt").exists());
        assert!(!bucket.join("secret.txt").exists());
        assert!(!bucket.join("dir/.maxio.object").exists());
        assert!(
            bucket.join("dir/child.txt").is_file(),
            "untampered child stays"
        );
        let quarantine = tmp.path().join(".maxio-quarantine/bkt");
        assert!(quarantine.join("plain.txt").is_file());
        assert!(quarantine.join("secret.txt").is_file());
        assert!(quarantine.join("dir/.maxio.object").is_file());
        let kept = std::fs::read_to_string(quarantine.join("plain.txt.meta.json")).unwrap();
        assert_eq!(kept, plain_sum);
        assert!(!kept.contains("adopt"), "{kept}");
    }

    fn flip_first_byte(path: &std::path::Path) -> Vec<u8> {
        let mut bytes = std::fs::read(path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(path, &bytes).unwrap();
        bytes
    }

    #[tokio::test]
    async fn single_part_etag_without_checksum_is_quarantined() {
        // curl and mc PUT an object with no checksum. The etag is the MD5.
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage
            .put_object(
                "bkt",
                "curl.txt",
                "text/plain",
                Box::pin(&b"curl-body"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "bkt",
                "mc.txt",
                "text/plain",
                Box::pin(&b"mc-body"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        let original_meta = std::fs::read_to_string(bucket.join("curl.txt.meta.json")).unwrap();
        assert!(
            !original_meta.contains("checksum_value"),
            "curl/mc objects store no checksum: {original_meta}"
        );
        let flipped = flip_first_byte(&bucket.join("curl.txt"));
        let reported = check(tmp.path(), false).await.unwrap();
        assert!(
            reported.issues.iter().any(|issue| {
                issue.kind == IssueKind::EtagMismatch && !issue.repaired && !issue.advisory
            }),
            "{:?}",
            reported.issues
        );
        assert_eq!(
            std::fs::read_to_string(bucket.join("curl.txt.meta.json")).unwrap(),
            original_meta,
            "a read-only check must not rewrite the etag"
        );

        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::ContentHashMismatch
                    && issue.repaired
                    && issue.detail.contains("Quarantined")
            }),
            "{:?}",
            repaired.issues
        );
        assert!(!bucket.join("curl.txt").exists());
        assert!(bucket.join("mc.txt").is_file(), "untampered object stays");
        let quarantine = tmp.path().join(".maxio-quarantine/bkt");
        assert_eq!(std::fs::read(quarantine.join("curl.txt")).unwrap(), flipped);
        let kept = std::fs::read_to_string(quarantine.join("curl.txt.meta.json")).unwrap();
        assert_eq!(kept, original_meta);
        assert!(
            repaired.unresolved() == 0,
            "quarantine resolves the etag mismatch: {:?}",
            repaired.issues
        );
    }

    #[tokio::test]
    async fn accept_current_checksums_records_single_part_etag() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage
            .put_object(
                "bkt",
                "note.txt",
                "text/plain",
                Box::pin(&b"note"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        flip_first_byte(&bucket.join("note.txt"));
        let repaired = check_with_opts(tmp.path(), true, None, true, false)
            .await
            .unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::EtagMismatch
                    && issue.repaired
                    && issue.detail.contains("--accept-current-checksums")
            }),
            "{:?}",
            repaired.issues
        );
        assert!(bucket.join("note.txt").is_file());
        assert!(!tmp.path().join(".maxio-quarantine").exists());
        let meta: ObjectMeta = serde_json::from_str(
            &std::fs::read_to_string(bucket.join("note.txt.meta.json")).unwrap(),
        )
        .unwrap();
        let file_md5 = format!(
            "\"{}\"",
            hex::encode(md5::Md5::digest(
                std::fs::read(bucket.join("note.txt")).unwrap()
            ))
        );
        assert_eq!(meta.etag, file_md5);
        let again = check(tmp.path(), false).await.unwrap();
        assert_eq!(again.unresolved(), 0, "{:?}", again.issues);
    }

    #[tokio::test]
    async fn data450_era_sidecar_etag_mismatch_is_quarantined() {
        // Pre-checksum sidecars stored only key, size, etag, content type, and mtime.
        let tmp = tempfile::tempdir().unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        std::fs::create_dir_all(&bucket).unwrap();
        let body = b"hello";
        std::fs::write(bucket.join("old.txt"), body).unwrap();
        let real = format!("\"{}\"", hex::encode(md5::Md5::digest(body)));
        let sidecar = r#"{"key":"old.txt","size":5,"etag":"\"00000000000000000000000000000000\"","content_type":"text/plain","last_modified":"2024-04-01T00:00:00.000Z"}"#;
        std::fs::write(bucket.join("old.txt.meta.json"), &sidecar).unwrap();
        assert_ne!(real, "\"00000000000000000000000000000000\"");

        let reported = check(tmp.path(), false).await.unwrap();
        assert!(
            reported.unresolved() >= 1,
            "data450-era etag mismatch must be reported: {:?}",
            reported.issues
        );
        assert_eq!(
            std::fs::read_to_string(bucket.join("old.txt.meta.json")).unwrap(),
            sidecar
        );

        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::EtagMismatch
                    && issue.repaired
                    && issue.detail.contains("Quarantined")
            }),
            "{:?}",
            repaired.issues
        );
        assert!(!bucket.join("old.txt").exists());
        let kept =
            std::fs::read_to_string(tmp.path().join(".maxio-quarantine/bkt/old.txt.meta.json"))
                .unwrap();
        assert!(
            kept.contains("00000000000000000000000000000000"),
            "repair must not adopt the corrupted etag: {kept}"
        );
        assert!(!kept.contains("checksum"), "{kept}");
    }

    #[tokio::test]
    async fn multipart_etag_is_unverifiable_and_not_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        std::fs::create_dir_all(&bucket).unwrap();
        let body = b"not-the-part-md5s";
        std::fs::write(bucket.join("multi.bin"), body).unwrap();
        let meta = ObjectMeta {
            key: "multi.bin".into(),
            size: body.len() as u64,
            etag: "\"0123456789abcdef0123456789abcdef-2\"".into(),
            content_type: "application/octet-stream".into(),
            last_modified: "2024-04-01T00:00:00.000Z".into(),
            ..ObjectMeta::default()
        };
        let sidecar = serde_json::to_vec_pretty(&meta).unwrap();
        std::fs::write(bucket.join("multi.bin.meta.json"), &sidecar).unwrap();

        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::MultipartEtag
                    && issue.advisory
                    && !issue.repaired
                    && issue.detail == "multipart etag (not verifiable by MD5)"
            }),
            "{:?}",
            repaired.issues
        );
        assert!(
            repaired
                .issues
                .iter()
                .all(|issue| issue.kind != IssueKind::EtagMismatch),
            "a multipart etag is not a mismatch: {:?}",
            repaired.issues
        );
        assert_eq!(
            std::fs::read(bucket.join("multi.bin.meta.json")).unwrap(),
            sidecar
        );
        assert_eq!(std::fs::read(bucket.join("multi.bin")).unwrap(), body);
        assert!(
            !tmp.path().join(".maxio-quarantine").exists(),
            "a multipart etag must not be quarantined just because it is not a whole-object MD5"
        );
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
    }

    async fn read_version(storage: &FilesystemStorage, key: &str, version_id: &str) -> Vec<u8> {
        let (mut reader, _) = storage
            .get_object_version("bkt", key, version_id, None)
            .await
            .unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        buf
    }

    #[tokio::test]
    async fn repair_restores_current_object_from_the_intact_version() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage.set_versioning("bkt", true).await.unwrap();
        storage
            .put_object(
                "bkt",
                "obj",
                "text/plain",
                Box::pin(&b"one"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "bkt",
                "obj",
                "text/plain",
                Box::pin(&b"two"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        let meta: ObjectMeta =
            serde_json::from_str(&std::fs::read_to_string(bucket.join("obj.meta.json")).unwrap())
                .unwrap();
        let vid = meta.version_id.clone().unwrap();
        let ver_data = bucket.join(".versions/obj").join(format!("{vid}.data"));
        assert_eq!(std::fs::read(&ver_data).unwrap(), b"two");
        let flipped = flip_first_byte(&bucket.join("obj"));
        assert_ne!(flipped, b"two");

        let reported = check(tmp.path(), false).await.unwrap();
        assert!(
            reported.issues.iter().any(|issue| {
                issue.kind == IssueKind::CurrentVersionMismatch && !issue.repaired
            }),
            "check must see the current/version split: {:?}",
            reported.issues
        );
        assert_eq!(std::fs::read(bucket.join("obj")).unwrap(), flipped);

        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::CurrentVersionMismatch
                    && issue.repaired
                    && issue.detail.to_lowercase().contains("restored")
            }),
            "{:?}",
            repaired.issues
        );
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
        assert_eq!(read_key(&storage, "obj").await, b"two");
        let listed = storage.list_objects("bkt", "").await.unwrap();
        assert!(
            listed.iter().any(|obj| obj.key == "obj"),
            "list-objects must show the restored current object: {listed:?}"
        );
        assert_eq!(read_version(&storage, "obj", &vid).await, b"two");
        let versions = storage.list_object_versions("bkt", "obj").await.unwrap();
        assert!(
            versions
                .iter()
                .any(|obj| obj.version_id.as_deref() == Some(vid.as_str())),
            "{versions:?}"
        );
        let again = check(tmp.path(), false).await.unwrap();
        assert_eq!(again.unresolved(), 0, "{:?}", again.issues);
    }

    #[tokio::test]
    async fn missing_current_version_is_reported_and_restored() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage.set_versioning("bkt", true).await.unwrap();
        storage
            .put_object(
                "bkt",
                "obj",
                "text/plain",
                Box::pin(&b"kept"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        std::fs::remove_file(bucket.join("obj")).unwrap();
        std::fs::remove_file(bucket.join("obj.meta.json")).unwrap();

        let reported = check(tmp.path(), false).await.unwrap();
        assert!(
            reported.issues.iter().any(|issue| {
                issue.kind == IssueKind::CurrentVersionMismatch
                    && !issue.repaired
                    && issue.detail.contains("missing")
            }),
            "{:?}",
            reported.issues
        );
        assert!(!bucket.join("obj").exists());

        let repaired = check(tmp.path(), true).await.unwrap();
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
        assert_eq!(read_key(&storage, "obj").await, b"kept");
        let listed = storage.list_objects("bkt", "").await.unwrap();
        assert!(listed.iter().any(|obj| obj.key == "obj"));
        let again = check(tmp.path(), false).await.unwrap();
        assert_eq!(again.unresolved(), 0, "{:?}", again.issues);
    }

    #[tokio::test]
    async fn newest_delete_marker_removes_a_stale_current_object() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage.set_versioning("bkt", true).await.unwrap();
        storage
            .put_object(
                "bkt",
                "obj",
                "text/plain",
                Box::pin(&b"gone"[..]),
                None,
                None,
            )
            .await
            .unwrap();
        let deleted = storage.delete_object("bkt", "obj").await.unwrap();
        assert!(deleted.is_delete_marker);
        let bucket = tmp.path().join("buckets/bkt");
        assert!(!bucket.join("obj").exists());
        let consistent = check(tmp.path(), false).await.unwrap();
        assert_eq!(consistent.unresolved(), 0, "{:?}", consistent.issues);

        let ver_dir = bucket.join(".versions/obj");
        let data_name = std::fs::read_dir(&ver_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .find(|name| name.ends_with(".data"))
            .expect("the put must leave a version payload");
        let vid = data_name.trim_end_matches(".data");
        std::fs::copy(ver_dir.join(&data_name), bucket.join("obj")).unwrap();
        std::fs::copy(
            ver_dir.join(format!("{vid}.meta.json")),
            bucket.join("obj.meta.json"),
        )
        .unwrap();

        let reported = check(tmp.path(), false).await.unwrap();
        assert!(
            reported.issues.iter().any(|issue| {
                issue.kind == IssueKind::CurrentVersionMismatch
                    && !issue.repaired
                    && issue.detail.contains("delete marker")
            }),
            "{:?}",
            reported.issues
        );
        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::CurrentVersionMismatch
                    && issue.repaired
                    && issue.detail.contains("delete marker")
            }),
            "{:?}",
            repaired.issues
        );
        assert!(!bucket.join("obj").exists());
        assert!(!bucket.join("obj.meta.json").exists());
        match storage.get_object("bkt", "obj", None).await {
            Err(crate::storage::StorageError::NotFound(_)) => {}
            Err(err) => panic!("deleted current object must be NotFound, got {err}"),
            Ok(_) => panic!("deleted current object must not be readable"),
        }
        let versions = storage.list_object_versions("bkt", "obj").await.unwrap();
        assert!(
            versions.iter().any(|obj| obj.is_delete_marker),
            "{versions:?}"
        );
        let again = check(tmp.path(), false).await.unwrap();
        assert_eq!(again.unresolved(), 0, "{:?}", again.issues);
    }

    fn newest_version_data(bucket: &std::path::Path, key: &str) -> std::path::PathBuf {
        let name = std::path::Path::new(key)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let dir = bucket.join(".versions").join(name);
        let mut ids = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter_map(|name| name.strip_suffix(".data").map(str::to_string))
            .collect::<Vec<_>>();
        ids.sort_by(|a, b| match (a.as_str() == "null", b.as_str() == "null") {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => b.cmp(a),
        });
        dir.join(format!("{}.data", ids[0]))
    }

    async fn put_bytes(storage: &FilesystemStorage, key: &str, body: &'static [u8], sse: bool) {
        storage
            .put_object(
                "bkt",
                key,
                "text/plain",
                Box::pin(body),
                None,
                sse.then(crate::storage::EncryptionRequest::sse_s3),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn corrupt_newest_archive_does_not_roll_back_an_intact_current() {
        for sse in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let storage = storage_at(tmp.path()).await;
            storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
            storage.set_versioning("bkt", true).await.unwrap();
            put_bytes(&storage, "obj", b"older-body", sse).await;
            put_bytes(&storage, "obj", b"newest-body", sse).await;
            let bucket = tmp.path().join("buckets/bkt");
            let current = std::fs::read(bucket.join("obj")).unwrap();
            let archive = newest_version_data(&bucket, "obj");
            let vid = archive
                .file_name()
                .unwrap()
                .to_string_lossy()
                .trim_end_matches(".data")
                .to_string();
            flip_first_byte(&archive);
            let reported = check(tmp.path(), false).await.unwrap();
            assert!(
                reported.issues.iter().any(|issue| {
                    issue.kind == IssueKind::VersionArchiveCorrupt
                        && !issue.repaired
                        && issue.detail.contains("current object matches")
                        && !issue.detail.contains("does not match intact version")
                }),
                "sse={sse} diagnosis: {:?}",
                reported.issues
            );
            assert!(
                reported
                    .issues
                    .iter()
                    .filter(|issue| issue.kind == IssueKind::CurrentVersionMismatch)
                    .all(|issue| !issue.detail.contains("does not match intact version")),
                "sse={sse} must not call an intact current a mismatch: {:?}",
                reported.issues
            );
            let repaired = check(tmp.path(), true).await.unwrap();
            assert_eq!(read_key(&storage, "obj").await, b"newest-body", "sse={sse}");
            assert_eq!(std::fs::read(bucket.join("obj")).unwrap(), current);
            assert_eq!(read_version(&storage, "obj", &vid).await, b"newest-body");
            let versions = storage.list_object_versions("bkt", "obj").await.unwrap();
            assert!(
                versions
                    .iter()
                    .any(|obj| obj.version_id.as_deref() == Some(vid.as_str())),
                "sse={sse} newest version vanished: {versions:?}"
            );
            assert_eq!(repaired.unresolved(), 0, "sse={sse} {:?}", repaired.issues);
        }
    }

    #[tokio::test]
    async fn suspended_null_current_is_not_replaced_by_an_older_version() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage.set_versioning("bkt", true).await.unwrap();
        put_bytes(&storage, "obj", b"sv1", false).await;
        put_bytes(&storage, "obj", b"sv2", false).await;
        storage.set_versioning("bkt", false).await.unwrap();
        put_bytes(&storage, "obj", b"sv3", false).await;
        let bucket = tmp.path().join("buckets/bkt");
        let archive = newest_version_data(&bucket, "obj");
        flip_first_byte(&archive);
        let repaired = check(tmp.path(), true).await.unwrap();
        assert_eq!(
            read_key(&storage, "obj").await,
            b"sv3",
            "repair rolled a suspended null write back: {:?}",
            repaired.issues
        );
        let again = check(tmp.path(), false).await.unwrap();
        assert_eq!(again.unresolved(), 0, "{:?}", again.issues);
    }

    fn copy_tree(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let to = dst.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &to);
            } else {
                std::fs::copy(entry.path(), &to).unwrap();
            }
        }
    }

    fn files_under(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                if entry.path().is_dir() {
                    walk(&entry.path(), out);
                } else {
                    out.push(entry.path());
                }
            }
        }
        walk(root, &mut out);
        out.sort();
        out
    }

    #[tokio::test]
    async fn single_file_corruption_never_serves_older_than_newest_intact() {
        let fixture = tempfile::tempdir().unwrap();
        let storage = storage_at(fixture.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage.set_versioning("bkt", true).await.unwrap();
        put_bytes(&storage, "obj", b"v1-body", false).await;
        put_bytes(&storage, "obj", b"v2-body", false).await;
        put_bytes(&storage, "obj", b"v3-body", false).await;
        drop(storage);
        let files = files_under(&fixture.path().join("buckets"));
        assert!(files.len() >= 4, "fixture should have several files");
        for file in files {
            let rel = file.strip_prefix(fixture.path()).unwrap().to_path_buf();
            let copy = tempfile::tempdir().unwrap();
            copy_tree(fixture.path(), copy.path());
            let target = copy.path().join(&rel);
            if std::fs::metadata(&target).unwrap().len() == 0 {
                std::fs::write(&target, b"x").unwrap();
            } else {
                flip_first_byte(&target);
            }
            let repaired = check(copy.path(), true).await;
            let opened = storage_at(copy.path()).await;
            let got = opened.get_object("bkt", "obj", None).await;
            let body = match got {
                Ok((mut reader, _)) => {
                    let mut buf = Vec::new();
                    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
                        .await
                        .unwrap();
                    buf
                }
                Err(err) => panic!(
                    "corrupting {} made GET fail ({err}); check result: {repaired:?}",
                    rel.display()
                ),
            };
            assert_eq!(
                body,
                b"v3-body",
                "corrupting {} made GET return older content: {body:?}\n{repaired:?}",
                rel.display()
            );
        }
    }

    fn write_legacy_multipart(dir: &std::path::Path, name: &str, body: &[u8], etag: &str) {
        std::fs::write(dir.join(name), body).unwrap();
        let meta = ObjectMeta {
            key: name.into(),
            size: body.len() as u64,
            etag: etag.into(),
            content_type: "application/octet-stream".into(),
            last_modified: "2024-04-01T00:00:00.000Z".into(),
            part_sizes: Some(vec![
                body.len() as u64 / 2,
                body.len() as u64 - body.len() as u64 / 2,
            ]),
            ..ObjectMeta::default()
        };
        std::fs::write(
            dir.join(format!("{name}.meta.json")),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn unverifiable_multipart_divergence_is_not_repaired() {
        let tmp = tempfile::tempdir().unwrap();
        let bucket = tmp.path().join("buckets/bkt");
        let ver = bucket.join(".versions/multi.bin");
        std::fs::create_dir_all(&ver).unwrap();
        let etag = "\"0123456789abcdef0123456789abcdef-2\"";
        let good = b"good-multipart-bytes";
        write_legacy_multipart(&bucket, "multi.bin", good, etag);
        std::fs::copy(bucket.join("multi.bin"), ver.join("vid.data")).unwrap();
        let mut version_meta: ObjectMeta =
            serde_json::from_slice(&std::fs::read(bucket.join("multi.bin.meta.json")).unwrap())
                .unwrap();
        version_meta.version_id = Some("vid".into());
        std::fs::write(
            ver.join("vid.meta.json"),
            serde_json::to_vec_pretty(&version_meta).unwrap(),
        )
        .unwrap();
        let current: ObjectMeta = version_meta.clone();
        std::fs::write(
            bucket.join("multi.bin.meta.json"),
            serde_json::to_vec_pretty(&current).unwrap(),
        )
        .unwrap();
        flip_first_byte(&bucket.join("multi.bin"));
        let corrupt = std::fs::read(bucket.join("multi.bin")).unwrap();
        let archive_before = std::fs::read(ver.join("vid.data")).unwrap();

        let repaired = check(tmp.path(), true).await.unwrap();
        assert!(
            repaired.issues.iter().any(|issue| {
                issue.kind == IssueKind::UnverifiableDivergence && !issue.repaired
            }),
            "{:?}",
            repaired.issues
        );
        assert_eq!(
            std::fs::read(ver.join("vid.data")).unwrap(),
            archive_before,
            "repair must not overwrite the intact archive with the corrupt current object"
        );
        assert_eq!(std::fs::read(bucket.join("multi.bin")).unwrap(), corrupt);
        assert!(
            repaired
                .issues
                .iter()
                .all(|issue| issue.kind != IssueKind::VersionArchiveCorrupt),
            "an unverifiable current must not be treated as the good copy: {:?}",
            repaired.issues
        );
        let _ = current;
    }

    #[tokio::test]
    async fn put_stores_content_hash_and_repair_restores_from_it() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_at(tmp.path()).await;
        storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
        storage.set_versioning("bkt", true).await.unwrap();
        put_bytes(&storage, "obj", b"hashed-body", false).await;
        let bucket = tmp.path().join("buckets/bkt");
        let meta: ObjectMeta =
            serde_json::from_str(&std::fs::read_to_string(bucket.join("obj.meta.json")).unwrap())
                .unwrap();
        assert!(
            meta.content_sha256
                .as_deref()
                .is_some_and(|hash| hash.len() == 64),
            "flat puts store a sha256 of the stored bytes: {meta:?}"
        );
        let vid = meta.version_id.clone().unwrap();
        flip_first_byte(&bucket.join("obj"));
        let repaired = check(tmp.path(), true).await.unwrap();
        assert_eq!(read_key(&storage, "obj").await, b"hashed-body");
        assert_eq!(read_version(&storage, "obj", &vid).await, b"hashed-body");
        assert!(
            repaired
                .issues
                .iter()
                .any(|issue| issue.kind == IssueKind::ContentHashMismatch && issue.repaired),
            "{:?}",
            repaired.issues
        );
        assert_eq!(repaired.unresolved(), 0, "{:?}", repaired.issues);
    }

    #[tokio::test]
    async fn corruption_sweep_versioned_unversioned_and_sse() {
        for (versioned, sse) in [(false, false), (false, true), (true, false), (true, true)] {
            let fixture = tempfile::tempdir().unwrap();
            let storage = storage_at(fixture.path()).await;
            storage.create_bucket(&bucket_meta("bkt")).await.unwrap();
            if versioned {
                storage.set_versioning("bkt", true).await.unwrap();
                put_bytes(&storage, "obj", b"older-sweep", sse).await;
            }
            put_bytes(&storage, "obj", b"newest-sweep", sse).await;
            drop(storage);
            for file in files_under(&fixture.path().join("buckets")) {
                let rel = file.strip_prefix(fixture.path()).unwrap().to_path_buf();
                let copy = tempfile::tempdir().unwrap();
                copy_tree(fixture.path(), copy.path());
                let target = copy.path().join(&rel);
                if std::fs::metadata(&target).unwrap().len() == 0 {
                    std::fs::write(&target, b"x").unwrap();
                } else {
                    flip_first_byte(&target);
                }
                let _ = check(copy.path(), true).await;
                let opened = storage_at(copy.path()).await;
                match opened.get_object("bkt", "obj", None).await {
                    Ok((mut reader, _)) => {
                        let mut buf = Vec::new();
                        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
                            .await
                            .unwrap();
                        assert_eq!(
                            buf,
                            b"newest-sweep",
                            "versioned={versioned} sse={sse} corrupting {} served {:?}\n",
                            rel.display(),
                            buf
                        );
                    }
                    Err(_) if !versioned => {}
                    Err(err) => panic!(
                        "versioned={versioned} sse={sse} corrupting {} lost the object ({err})",
                        rel.display()
                    ),
                }
            }
        }
    }
}

async fn payload_checksum(
    data_path: &Path,
    meta: &ObjectMeta,
    algo: ChecksumAlgorithm,
    bucket: &str,
    key: &str,
    keyring: Option<&Arc<super::keys::Keyring>>,
) -> Result<String, String> {
    if let Some(enc) = &meta.encryption {
        if enc.mode != EncryptionMode::SseS3 {
            return Err(
                "SSE-C payload cannot be checked without the customer key; it was left in place"
                    .into(),
            );
        }
        let Some(keyring) = keyring else {
            return Err("SSE-S3 master key is not loaded; the payload was left in place".into());
        };
        return checksum_sse_s3(data_path, meta, enc, algo, bucket, key, keyring).await;
    }
    file_checksum(data_path, algo)
        .await
        .map_err(|err| err.to_string())
}

async fn checksum_sse_s3(
    data_path: &Path,
    meta: &ObjectMeta,
    enc: &super::EncryptionMeta,
    algo: ChecksumAlgorithm,
    bucket: &str,
    key: &str,
    keyring: &super::keys::Keyring,
) -> Result<String, String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_id = enc.key_id.as_deref().ok_or("missing key_id")?;
    let wrapped = b64
        .decode(enc.wrapped_dek.as_deref().ok_or("missing wrapped_dek")?)
        .map_err(|err| err.to_string())?;
    let nonce_raw = b64
        .decode(enc.wrap_nonce.as_deref().ok_or("missing wrap_nonce")?)
        .map_err(|err| err.to_string())?;
    if nonce_raw.len() != 12 {
        return Err("wrap_nonce must be 12 bytes".into());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_raw);
    let dek = keyring
        .unwrap_dek(key_id, &wrapped, &nonce)
        .map_err(|err| err.to_string())?;
    let file = tokio::fs::File::open(data_path)
        .await
        .map_err(|err| err.to_string())?;
    let aad = super::filesystem::object_aad_builder(bucket, key, meta.version_id.as_deref());
    let mut dec = super::crypto::FrameDecryptor::new(
        Box::pin(file),
        &dek,
        meta.size,
        enc.chunk_size.max(1) as usize,
        aad,
    );
    let mut hasher = ChecksumHasher::new(algo);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = dec
            .read(&mut buf)
            .await
            .map_err(|err| format!("authentication failed ({err})"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_base64())
}

async fn quarantine_payload(
    data_dir: &Path,
    bucket: &str,
    bucket_dir: &Path,
    data_path: &Path,
    meta_path: &Path,
) -> anyhow::Result<std::path::PathBuf> {
    let rel = data_path.strip_prefix(bucket_dir).unwrap_or(data_path);
    let mut dest = data_dir.join(".maxio-quarantine").join(bucket).join(rel);
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if tokio::fs::try_exists(&dest).await? {
        let parent = dest
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| data_dir.to_path_buf());
        let stem = dest
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "object".to_string());
        for n in 1..1000 {
            let candidate = parent.join(format!("{stem}.{n}"));
            if !tokio::fs::try_exists(&candidate).await? {
                dest = candidate;
                break;
            }
        }
    }
    tokio::fs::rename(data_path, &dest).await?;
    if tokio::fs::try_exists(meta_path).await? {
        let meta_rel = meta_path.strip_prefix(bucket_dir).unwrap_or(meta_path);
        let meta_dest = data_dir
            .join(".maxio-quarantine")
            .join(bucket)
            .join(meta_rel);
        if let Some(parent) = meta_dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(meta_path, &meta_dest).await?;
    }
    Ok(dest)
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
