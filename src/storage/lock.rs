//! Exclusive advisory lock for a data directory.
//!
//! The server holds `<data-dir>/.maxio.lock` for its whole process lifetime.
//! `flock` is released when the file is closed, including when the process
//! crashes, so a restart is not blocked by a stale lock. `check --repair` and
//! `keyring merge` refuse to write while the lock is held.

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

/// Non-blocking exclusive lock. Fails if another live process already holds it.
pub fn acquire_exclusive(data_dir: &Path) -> anyhow::Result<DataDirLock> {
    let file = open_lock_file(data_dir)?;
    match file.try_lock() {
        Ok(()) => Ok(DataDirLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "data directory {} is in use by another maxio process ({}). Stop that server before repairing or merging the keyring.",
            data_dir.display(),
            lock_path(data_dir).display()
        ),
        Err(std::fs::TryLockError::Error(err)) => Err(err.into()),
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
        let first = acquire_exclusive(tmp.path()).unwrap();
        let err = match acquire_exclusive(tmp.path()) {
            Err(err) => err,
            Ok(_) => panic!("second acquire should fail while the first lock is held"),
        };
        assert!(err.to_string().contains(".maxio.lock"), "{err}");
        assert!(is_locked(tmp.path()).unwrap());
        drop(first);
        assert!(!is_locked(tmp.path()).unwrap());
        let _second = acquire_exclusive(tmp.path()).unwrap();
    }
}
