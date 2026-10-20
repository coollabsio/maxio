//! On-disk format version for a MaxIO data directory.
//!
//! The marker is `{data_dir}/.maxio-format`:
//!
//! ```json
//! { "version": 1 }
//! ```
//!
//! A missing marker is format 0. That covers a brand-new directory and any
//! directory created before the marker existed. Startup walks [`MIGRATIONS`]
//! until [`CURRENT_FORMAT_VERSION`] and writes the marker after each step.
//! A marker newer than this binary is a hard error: starting would risk
//! writing a layout this release does not understand.
//!
//! Add a future upgrade by appending one step whose `to` is `from + 1` and
//! bumping [`CURRENT_FORMAT_VERSION`]. The step's `apply` changes object data;
//! the framework writes the new version only after `apply` returns.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Layout this binary can read and write.
pub const CURRENT_FORMAT_VERSION: u32 = 1;

/// File name of the marker, relative to the data directory.
pub const FORMAT_FILENAME: &str = ".maxio-format";

/// One forward-only upgrade of the data directory.
///
/// `apply` must be safe to describe as "from -> to" and must not bump the
/// marker itself. Return `Err` to leave the directory on the previous version.
pub struct Migration {
    pub from: u32,
    pub to: u32,
    pub name: &'static str,
    pub apply: fn(&Path) -> Result<(), String>,
}

/// Registered upgrades. Format 1 introduced the marker without changing the
/// bucket or object layout, so the only step today is a no-op.
pub const MIGRATIONS: &[Migration] = &[Migration {
    from: 0,
    to: 1,
    name: "introduce-format-marker",
    apply: noop_migration,
}];

fn noop_migration(_data_dir: &Path) -> Result<(), String> {
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error(
        "refusing to start: data directory {path} uses on-disk format version {found}, \
         but this MaxIO release only understands version {supported}. \
         Install a newer MaxIO binary before opening this data directory"
    )]
    Newer {
        path: String,
        found: u32,
        supported: u32,
    },
    #[error("refusing to start: {path} is not a readable MaxIO format marker ({message})")]
    Invalid { path: String, message: String },
    #[error(
        "refusing to start: no migration from on-disk format {from} to {target} \
         (this release understands version {target})"
    )]
    NoMigration { from: u32, target: u32 },
    #[error("refusing to start: migration '{name}' ({from} -> {to}) failed: {message}")]
    Migration {
        name: &'static str,
        from: u32,
        to: u32,
        message: String,
    },
    #[error("failed to update the on-disk format marker: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct FormatFile {
    version: u32,
}

/// Create the data directory if needed, refuse a newer marker, and run any
/// pending migrations up to [`CURRENT_FORMAT_VERSION`].
pub async fn ensure_current(data_dir: impl AsRef<Path>) -> Result<u32, FormatError> {
    apply_migrations(data_dir.as_ref(), CURRENT_FORMAT_VERSION, MIGRATIONS).await
}

/// Migration engine used by [`ensure_current`]. Tests pass a private migration
/// list and target so the hooks can be exercised without bumping the real format.
pub async fn apply_migrations(
    data_dir: &Path,
    target: u32,
    migrations: &[Migration],
) -> Result<u32, FormatError> {
    tokio::fs::create_dir_all(data_dir).await?;
    let found = read_format_version(data_dir).await?;
    if found > target {
        return Err(FormatError::Newer {
            path: data_dir.display().to_string(),
            found,
            supported: target,
        });
    }

    let mut current = found;
    while current < target {
        let step = migrations
            .iter()
            .find(|migration| migration.from == current && migration.to == current + 1)
            .ok_or(FormatError::NoMigration {
                from: current,
                target,
            })?;
        if let Err(message) = (step.apply)(data_dir) {
            return Err(FormatError::Migration {
                name: step.name,
                from: step.from,
                to: step.to,
                message,
            });
        }
        current = step.to;
        write_format_version(data_dir, current).await?;
    }
    Ok(current)
}

async fn read_format_version(data_dir: &Path) -> Result<u32, FormatError> {
    let path = data_dir.join(FORMAT_FILENAME);
    match tokio::fs::read(&path).await {
        Ok(bytes) => parse_format_version(&path, &bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err.into()),
    }
}

fn parse_format_version(path: &Path, bytes: &[u8]) -> Result<u32, FormatError> {
    let marker: FormatFile = serde_json::from_slice(bytes).map_err(|err| FormatError::Invalid {
        path: path.display().to_string(),
        message: err.to_string(),
    })?;
    Ok(marker.version)
}

async fn write_format_version(data_dir: &Path, version: u32) -> Result<(), FormatError> {
    let path = data_dir.join(FORMAT_FILENAME);
    let tmp = temp_marker_path(data_dir);
    let _guard = TempFileGuard(tmp.clone());
    let mut body = serde_json::to_vec_pretty(&FormatFile { version })
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    body.push(b'\n');
    tokio::fs::write(&tmp, &body).await?;
    let file = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

fn temp_marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(format!(
        ".{FORMAT_FILENAME}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
}

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch_migrated(data_dir: &Path) -> Result<(), String> {
        std::fs::write(data_dir.join("migrated-to-2"), b"ok").map_err(|err| err.to_string())
    }

    fn fail_migration(_data_dir: &Path) -> Result<(), String> {
        Err("disk full".to_string())
    }

    async fn marker_bytes(dir: &Path) -> Option<Vec<u8>> {
        match tokio::fs::read(dir.join(FORMAT_FILENAME)).await {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => panic!("read marker: {err}"),
        }
    }

    #[tokio::test]
    async fn fresh_directory_runs_noop_migration_and_writes_current_marker() {
        let dir = tempfile::tempdir().unwrap();
        let version = ensure_current(dir.path()).await.unwrap();
        assert_eq!(version, CURRENT_FORMAT_VERSION);

        let raw = marker_bytes(dir.path()).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed["version"], CURRENT_FORMAT_VERSION);
        assert!(raw.ends_with(b"\n"));

        let again = ensure_current(dir.path()).await.unwrap();
        assert_eq!(again, CURRENT_FORMAT_VERSION);
        assert_eq!(marker_bytes(dir.path()).await.unwrap(), raw);
    }

    #[tokio::test]
    async fn existing_data_without_a_marker_is_stamped_and_left_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("buckets").join("logs");
        std::fs::create_dir_all(&bucket).unwrap();
        let meta = bucket.join(".bucket.json");
        std::fs::write(&meta, b"{\"name\":\"logs\"}\n").unwrap();

        let version = ensure_current(dir.path()).await.unwrap();
        assert_eq!(version, 1);
        assert_eq!(
            std::fs::read_to_string(meta).unwrap(),
            "{\"name\":\"logs\"}\n"
        );
    }

    #[tokio::test]
    async fn current_marker_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FORMAT_FILENAME);
        let original = b"{\"version\":1}\n";
        std::fs::write(&path, original).unwrap();

        assert_eq!(ensure_current(dir.path()).await.unwrap(), 1);
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[tokio::test]
    async fn newer_marker_refuses_to_start_without_changing_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FORMAT_FILENAME);
        let original = b"{\"version\":99,\"extra\":true}\n";
        std::fs::write(&path, original).unwrap();

        let err = ensure_current(dir.path()).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("refusing to start"), "{message}");
        assert!(message.contains("version 99"), "{message}");
        assert!(message.contains("version 1"), "{message}");
        assert!(
            message.contains(&dir.path().display().to_string()),
            "{message}"
        );
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[tokio::test]
    async fn corrupt_marker_refuses_to_start_without_replacing_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FORMAT_FILENAME);
        std::fs::write(&path, b"not-json").unwrap();

        let err = ensure_current(dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("refusing to start"), "{err}");
        assert_eq!(std::fs::read(path).unwrap(), b"not-json");
    }

    #[tokio::test]
    async fn migration_hooks_run_in_order_and_the_marker_follows_the_last_success() {
        let dir = tempfile::tempdir().unwrap();
        let migrations = [
            Migration {
                from: 0,
                to: 1,
                name: "introduce-format-marker",
                apply: noop_migration,
            },
            Migration {
                from: 1,
                to: 2,
                name: "touch-sentinel",
                apply: touch_migrated,
            },
        ];

        let version = apply_migrations(dir.path(), 2, &migrations).await.unwrap();
        assert_eq!(version, 2);
        assert_eq!(
            std::fs::read(dir.path().join("migrated-to-2")).unwrap(),
            b"ok"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&marker_bytes(dir.path()).await.unwrap()).unwrap();
        assert_eq!(parsed["version"], 2);
    }

    #[tokio::test]
    async fn failed_migration_does_not_advance_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let migrations = [Migration {
            from: 0,
            to: 1,
            name: "explode",
            apply: fail_migration,
        }];

        let err = apply_migrations(dir.path(), 1, &migrations)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("explode"), "{message}");
        assert!(message.contains("disk full"), "{message}");
        assert!(marker_bytes(dir.path()).await.is_none());
    }

    #[tokio::test]
    async fn missing_migration_step_keeps_the_last_successful_marker() {
        let dir = tempfile::tempdir().unwrap();
        let err = apply_migrations(dir.path(), 3, MIGRATIONS)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("no migration"), "{message}");
        assert!(message.contains("format 1"), "{message}");
        // 0 -> 1 succeeded and was committed. The missing 1 -> 2 step stops there.
        let parsed: serde_json::Value =
            serde_json::from_slice(&marker_bytes(dir.path()).await.unwrap()).unwrap();
        assert_eq!(parsed["version"], 1);
    }
}
