//! Exclusive advisory lock for a data directory.
//!
//! The server holds `<data-dir>/.maxio.lock` for its whole process lifetime.
//! `flock` is released when the file is closed, including when the process
//! crashes, so a restart is not blocked by a stale lock. `check --repair`,
//! `keyring rotate`, and `keyring merge` refuse to write while the lock is held.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

pub struct DataDirLock {
    _file: std::fs::File,
}

fn lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".maxio.lock")
}

fn open_lock_file(data_dir: &Path) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(data_dir)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path(data_dir))
}

/// Why this process wants the data-directory lock. The refusal names that reason.
#[derive(Clone, Copy)]
pub enum LockReason {
    /// A server is starting.
    Serve,
    /// `check --repair` is about to rewrite the data directory.
    Repair,
    /// `keyring rotate` is about to replace `.maxio-keys.json`.
    RotateKeyring,
    /// `keyring merge` is about to write `.maxio-keys.json`.
    MergeKeyring,
}

/// Shown when the first write into the data directory is denied.
pub const DATA_DIR_PERMISSION_HINT: &str = "The data directory is not writable by this process. In Docker the image runs as uid 999. Use a named volume (-v maxio-data:/data). For a bind mount, chown 999:999 <host-path>, or start the container with --user matching the directory owner.";

impl LockReason {
    fn refusal(self) -> &'static str {
        match self {
            Self::Serve => "Stop that server before starting another one on this data directory.",
            Self::Repair => "Stop that server before repairing.",
            Self::RotateKeyring => "Stop that server before rotating the keyring.",
            Self::MergeKeyring => "Stop that server before merging the keyring.",
        }
    }
}

fn explain_lock_io(data_dir: &Path, err: std::io::Error) -> anyhow::Error {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "failed to create the data-directory lock {}: {err}. {}",
            lock_path(data_dir).display(),
            DATA_DIR_PERMISSION_HINT
        )
    } else {
        anyhow::Error::from(err)
    }
}

/// Non-blocking exclusive lock. Fails if another live process already holds it.
pub fn acquire_exclusive(data_dir: &Path, reason: LockReason) -> anyhow::Result<DataDirLock> {
    let file = match open_lock_file(data_dir) {
        Ok(file) => file,
        Err(err) => return Err(explain_lock_io(data_dir, err)),
    };
    match file.try_lock() {
        Ok(()) => Ok(DataDirLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "data directory {} is in use by another maxio process ({}). {}",
            data_dir.display(),
            lock_path(data_dir).display(),
            reason.refusal()
        ),
        Err(std::fs::TryLockError::Error(err)) => Err(explain_lock_io(data_dir, err)),
    }
}

/// True when a live process holds the data-directory lock.
pub fn is_locked(data_dir: &Path) -> anyhow::Result<bool> {
    let path = lock_path(data_dir);
    if !path.exists() {
        return Ok(false);
    }
    let file = OpenOptions::new().read(true).write(true).open(&path)?;
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            Ok(false)
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(err)) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_lock_blocks_a_second_acquire_and_releases_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let first = acquire_exclusive(tmp.path(), LockReason::Serve).unwrap();
        let err = match acquire_exclusive(tmp.path(), LockReason::Serve) {
            Err(err) => err,
            Ok(_) => panic!("second acquire should fail while the first lock is held"),
        };
        let msg = err.to_string();
        assert!(msg.contains(".maxio.lock"), "{msg}");
        assert!(
            msg.contains("starting another one"),
            "a second server should not be told to repair or merge: {msg}"
        );
        assert!(!msg.contains("repairing"), "{msg}");
        assert!(is_locked(tmp.path()).unwrap());
        drop(first);
        assert!(!is_locked(tmp.path()).unwrap());
        let _second = acquire_exclusive(tmp.path(), LockReason::Serve).unwrap();
    }

    #[test]
    fn repair_and_merge_refusals_name_their_own_action() {
        let tmp = tempfile::tempdir().unwrap();
        let _held = acquire_exclusive(tmp.path(), LockReason::Serve).unwrap();
        let repair = match acquire_exclusive(tmp.path(), LockReason::Repair) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("repair acquire should fail while the lock is held"),
        };
        assert!(repair.contains("before repairing"), "{repair}");
        assert!(!repair.contains("merging the keyring"), "{repair}");
        let merge = match acquire_exclusive(tmp.path(), LockReason::MergeKeyring) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("merge acquire should fail while the lock is held"),
        };
        assert!(merge.contains("before merging the keyring"), "{merge}");
        assert!(!merge.contains("starting another"), "{merge}");
        let rotate = match acquire_exclusive(tmp.path(), LockReason::RotateKeyring) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("rotate acquire should fail while the lock is held"),
        };
        assert!(rotate.contains("rotating the keyring"), "{rotate}");
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_explains_data_dir_ownership() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir).unwrap();
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&dir, perms).unwrap();
        let err = match acquire_exclusive(&dir, LockReason::Serve) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("a read-only data directory must not accept the lock file"),
        };
        let mut restore = std::fs::metadata(&dir).unwrap().permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(&dir, restore).unwrap();
        assert!(err.contains("Permission denied"), "{err}");
        assert!(err.contains("uid 999"), "{err}");
        assert!(err.contains("chown 999:999"), "{err}");
        assert!(err.contains("--user"), "{err}");
        assert!(err.contains(".maxio.lock"), "{err}");
    }
}
