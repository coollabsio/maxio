//! Keyring management for SSE-S3 master keys.
//!
//! On startup, the keyring is loaded from two sources (merged):
//! 1. `MAXIO_MASTER_KEY` env var / CLI flag — base64-encoded 32-byte key; takes
//!    precedence and becomes the active key for new writes.
//! 2. `{data_dir}/.maxio-keys.json` — JSON array of persisted keys; used for
//!    unwrapping DEKs on existing objects.
//!
//! Key loss → SSE-S3 objects become unrecoverable.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::Engine;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::fs;
#[cfg(not(unix))]
use tracing::warn;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// ── Persisted key file format ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct KeyEntryJson {
    id: String,
    key_b64: String,
    created_at: String,
    active: bool,
}

#[derive(Serialize, Deserialize)]
struct KeyringFile {
    keys: Vec<KeyEntryJson>,
}

// ── Keyring ───────────────────────────────────────────────────────────────────

pub struct Keyring {
    /// All known keys indexed by id; used for unwrapping existing objects.
    keys: HashMap<String, [u8; 32]>,
    /// Id of the key used for new encryptions.
    active_id: String,
}

impl Keyring {
    /// Load (or bootstrap) the keyring.
    ///
    /// If `master_key_b64` is `Some`, that key is active and the keyring file
    /// (if present) is merged in for read-only unwrapping of old objects.
    /// If `master_key_b64` is `None`, the keyring file is loaded; it is
    /// created with a fresh random key if it doesn't exist yet.
    pub async fn load(data_dir: &str, master_key_b64: Option<&str>) -> anyhow::Result<Self> {
        let file_path = format!("{}/.maxio-keys.json", data_dir);
        let mut keys: HashMap<String, [u8; 32]> = HashMap::new();

        let active_id = if let Some(mk) = master_key_b64 {
            // --- env-var key path ---
            let raw = B64
                .decode(mk)
                .map_err(|_| anyhow::anyhow!("MAXIO_MASTER_KEY must be base64-encoded 32 bytes"))?;
            if raw.len() != 32 {
                anyhow::bail!("MAXIO_MASTER_KEY must be exactly 32 bytes when decoded");
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&raw);
            let id = key_id_from_bytes(&key_bytes);
            keys.insert(id.clone(), key_bytes);

            // Merge in keyring file for read-only access to old objects.
            if let Ok(data) = fs::read_to_string(&file_path).await {
                if let Ok(kr) = serde_json::from_str::<KeyringFile>(&data) {
                    for entry in kr.keys {
                        if let Ok(kb) = decode_32(&entry.key_b64) {
                            keys.entry(entry.id).or_insert(kb);
                        }
                    }
                }
            }
            id
        } else {
            // --- keyring file path ---
            let kr = match fs::read_to_string(&file_path).await {
                Ok(data) => serde_json::from_str::<KeyringFile>(&data)
                    .map_err(|e| anyhow::anyhow!("Failed to parse keyring file: {}", e))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Bootstrap: create a fresh key.
                    let mut new_key = [0u8; 32];
                    rand::rng().fill(&mut new_key[..]);
                    let id = key_id_from_bytes(&new_key);
                    let entry = KeyEntryJson {
                        key_b64: B64.encode(new_key),
                        id,
                        created_at: now_iso(),
                        active: true,
                    };
                    let kr = KeyringFile { keys: vec![entry] };
                    let json = serde_json::to_string_pretty(&kr)?;
                    write_keyring_atomic(&file_path, &json).await?;
                    kr
                }
                Err(e) => {
                    // Any other read error (EACCES, EIO, IsADirectory, ...) must
                    // NOT trigger bootstrap — that would rename a fresh keyring
                    // over the existing file and destroy every master key.
                    return Err(anyhow::anyhow!(
                        "Failed to read keyring file {}: {} — refusing to bootstrap over it; \
                         fix permissions or restore the file",
                        file_path,
                        e
                    ));
                }
            };

            let mut found_active: Option<String> = None;
            for entry in &kr.keys {
                if let Ok(kb) = decode_32(&entry.key_b64) {
                    keys.insert(entry.id.clone(), kb);
                    if entry.active {
                        found_active = Some(entry.id.clone());
                    }
                }
            }
            found_active.ok_or_else(|| anyhow::anyhow!("Keyring file has no active key"))?
        };

        Ok(Self { keys, active_id })
    }

    /// Id of the currently active wrapping key.
    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    /// Generate a fresh random 32-byte Data Encryption Key (DEK).
    pub fn generate_dek() -> [u8; 32] {
        let mut dek = [0u8; 32];
        rand::rng().fill(&mut dek[..]);
        dek
    }

    /// Generate a fresh random 8-byte per-object nonce prefix for new object frames.
    pub fn generate_nonce_prefix8() -> [u8; 8] {
        let mut prefix = [0u8; 8];
        rand::rng().fill(&mut prefix[..]);
        prefix
    }

    /// Wrap (encrypt) a DEK using the master key identified by `key_id`.
    /// Returns `(wrapped_ciphertext, 12-byte nonce)`.
    pub fn wrap_dek(&self, key_id: &str, dek: &[u8; 32]) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
        let master = self.get_key(key_id)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master));

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill(&mut nonce_bytes[..]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Bind the wrapped DEK to its key_id via AAD so a wrapped-DEK/nonce
        // pair from a different key context cannot be substituted undetected.
        let wrapped = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: dek.as_slice(),
                    aad: key_id.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("DEK wrapping failed"))?;

        Ok((wrapped, nonce_bytes))
    }

    /// Unwrap (decrypt) a DEK that was wrapped with the master key `key_id`.
    pub fn unwrap_dek(
        &self,
        key_id: &str,
        wrapped: &[u8],
        nonce: &[u8; 12],
    ) -> anyhow::Result<[u8; 32]> {
        let master = self.get_key(key_id)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master));
        let nonce = Nonce::from_slice(nonce);

        // New objects bind key_id as AAD; fall back to no-AAD for DEKs
        // wrapped before this binding was introduced (backward compatible).
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: wrapped,
                    aad: key_id.as_bytes(),
                },
            )
            .or_else(|_| cipher.decrypt(nonce, wrapped))
            .map_err(|_| anyhow::anyhow!("DEK unwrapping failed: authentication error"))?;

        if plaintext.len() != 32 {
            anyhow::bail!("Unwrapped DEK has wrong length: {}", plaintext.len());
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }

    fn get_key(&self, key_id: &str) -> anyhow::Result<&[u8; 32]> {
        self.keys
            .get(key_id)
            .ok_or_else(|| anyhow::anyhow!("Key '{}' not found in keyring; object may be unrecoverable — check your MAXIO_MASTER_KEY or keyring file", key_id))
    }
}

// ── Rotation ──────────────────────────────────────────────────────────────────

/// Rotate the keyring file: generate a new 32-byte master key, mark it active,
/// demote the previously-active key to `active: false` (retained so old objects
/// can still be decrypted). Returns the new active key id.
///
/// Before replacing the file, the previous keyring is copied to
/// `{data_dir}/.maxio-keys.json.bak` (overwriting any prior backup); if the
/// backup cannot be written the rotate aborts. The file itself is written
/// atomically and durably via a per-process temp file (created 0600 on Unix),
/// fsync, rename, and parent-directory fsync.
pub async fn rotate(data_dir: &str) -> anyhow::Result<RotateResult> {
    let file_path = format!("{}/.maxio-keys.json", data_dir);

    // Load existing. Only a missing file may start from an empty keyring — any
    // other read error (EACCES, EIO, ...) must abort, or rotate would write a
    // keyring containing only the new key and orphan every existing object.
    let (mut kr, original_exists) = match fs::read_to_string(&file_path).await {
        Ok(data) => (
            serde_json::from_str::<KeyringFile>(&data)
                .map_err(|e| anyhow::anyhow!("Failed to parse keyring file: {}", e))?,
            true,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (KeyringFile { keys: Vec::new() }, false)
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to read keyring file {}: {} — aborting rotate; \
                 fix permissions or restore the file",
                file_path,
                e
            ));
        }
    };

    // Capture previously-active id (if any) for the return payload.
    let previous_active = kr.keys.iter().find(|e| e.active).map(|e| e.id.clone());

    // Demote all existing keys
    for entry in kr.keys.iter_mut() {
        entry.active = false;
    }

    // Generate new key + id
    let mut new_key = [0u8; 32];
    rand::rng().fill(&mut new_key[..]);
    let new_id = key_id_from_bytes(&new_key);

    if kr.keys.iter().any(|e| e.id == new_id) {
        anyhow::bail!(
            "keyring rotate: generated key id {} already present (extremely unlikely)",
            new_id
        );
    }

    kr.keys.push(KeyEntryJson {
        key_b64: B64.encode(new_key),
        id: new_id.clone(),
        created_at: now_iso(),
        active: true,
    });

    // Backup the current keyring before replacing it. Mandatory: if the backup
    // cannot be written, abort the rotate rather than proceed without a safety
    // copy of the old master keys.
    if original_exists {
        let bak_path = format!("{}.bak", file_path);
        fs::copy(&file_path, &bak_path).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to back up keyring to {} before rotate: {} — aborting rotate",
                bak_path,
                e
            )
        })?;
    }

    // Atomic durable write: temp file (0600) → fsync → rename → dir fsync
    let json = serde_json::to_string_pretty(&kr)?;
    write_keyring_atomic(&file_path, &json).await?;

    Ok(RotateResult {
        new_active_id: new_id,
        previous_active_id: previous_active,
        total_keys: kr.keys.len(),
    })
}

/// Outcome of a `rotate` call. `previous_active_id` is `None` when rotating an
/// empty or freshly-bootstrapped keyring.
pub struct RotateResult {
    pub new_active_id: String,
    pub previous_active_id: Option<String>,
    pub total_keys: usize,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Durably and atomically write the keyring file.
///
/// Steps: create a per-process temp file next to `file_path` (mode 0600 from
/// the start on Unix — no world-readable window), write the JSON, fsync the
/// file, rename it over `file_path`, then fsync the parent directory so the
/// rename itself survives a crash. The directory fsync is Unix-only and skipped
/// gracefully elsewhere.
async fn write_keyring_atomic(file_path: &str, json: &str) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let tmp_path = format!("{}.tmp-{}", file_path, std::process::id());

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // Owner-only from the moment of creation (umask cannot widen this).
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    {
        warn!(
            path = %file_path,
            "SSE-S3 keyring written without owner-only file permissions on this platform — \
             restrict ACLs manually so only the maxio service account can read it"
        );
    }

    let write_result: anyhow::Result<()> = async {
        let mut f = opts.open(&tmp_path).await?;
        f.write_all(json.as_bytes()).await?;
        // Flush file contents + metadata to stable storage before the rename.
        f.sync_all().await?;
        drop(f);
        fs::rename(&tmp_path, file_path).await?;
        Ok(())
    }
    .await;

    if let Err(e) = write_result {
        // Best-effort cleanup of the temp file; the original is untouched.
        let _ = fs::remove_file(&tmp_path).await;
        return Err(e);
    }

    // Fsync the parent directory so the rename (directory entry) is durable.
    #[cfg(unix)]
    {
        if let Some(parent) = std::path::Path::new(file_path).parent() {
            let parent = parent.to_path_buf();
            tokio::task::spawn_blocking(move || {
                std::fs::File::open(&parent).and_then(|d| d.sync_all())
            })
            .await
            .map_err(|e| anyhow::anyhow!("directory fsync task failed: {}", e))??;
        }
    }

    Ok(())
}

/// Derive a stable 8-byte hex key-id from a master key via SHA-256.
fn key_id_from_bytes(key: &[u8; 32]) -> String {
    let hash = Sha256::digest(key);
    hex::encode(&hash[..8])
}

/// Decode a base64 string into exactly 32 bytes.
fn decode_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let raw = B64.decode(s).map_err(|_| anyhow::anyhow!("bad base64"))?;
    if raw.len() != 32 {
        anyhow::bail!("expected 32 bytes, got {}", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn rand_key_b64() -> (String, [u8; 32]) {
        let mut k = [0u8; 32];
        rand::rng().fill(&mut k[..]);
        (B64.encode(k), k)
    }

    #[tokio::test]
    async fn override_with_master_key_preserves_bootstrap_key() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();

        // Bootstrap (None) — generates a key, writes .maxio-keys.json.
        let bootstrap = Keyring::load(&dir, None).await.unwrap();
        let bootstrap_id = bootstrap.active_id().to_string();

        // Wrap a DEK under the bootstrap key.
        let dek = Keyring::generate_dek();
        let (wrapped, nonce) = bootstrap.wrap_dek(&bootstrap_id, &dek).unwrap();

        // Reload with explicit MAXIO_MASTER_KEY — operator takes over.
        let (new_b64, _) = rand_key_b64();
        let reloaded = Keyring::load(&dir, Some(&new_b64)).await.unwrap();

        // Active key is the new one.
        assert_ne!(reloaded.active_id(), bootstrap_id);

        // Old key still in ring → old DEK unwraps.
        let recovered = reloaded
            .unwrap_dek(&bootstrap_id, &wrapped, &nonce)
            .unwrap();
        assert_eq!(recovered, dek);
    }

    #[tokio::test]
    async fn override_with_no_keyring_file_succeeds() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();

        let (b64, raw) = rand_key_b64();
        let kr = Keyring::load(&dir, Some(&b64)).await.unwrap();

        assert_eq!(kr.active_id(), &key_id_from_bytes(&raw));

        // Round-trip wrap/unwrap proves the key is usable.
        let dek = Keyring::generate_dek();
        let (w, n) = kr.wrap_dek(kr.active_id(), &dek).unwrap();
        assert_eq!(kr.unwrap_dek(kr.active_id(), &w, &n).unwrap(), dek);
    }

    #[tokio::test]
    async fn override_with_invalid_base64_errors() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let err = Keyring::load(&dir, Some("not-base64!@#$"))
            .await
            .err()
            .expect("invalid base64 must fail");
        assert!(
            err.to_string().contains("base64-encoded 32 bytes"),
            "unexpected error: {}",
            err
        );
    }

    /// Bootstrap on a genuinely absent file must still work: creates the file
    /// with an active key that survives a reload.
    #[tokio::test]
    async fn bootstrap_creates_keyring_when_file_absent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = format!("{}/.maxio-keys.json", dir);
        assert!(!std::path::Path::new(&file_path).exists());

        let kr = Keyring::load(&dir, None).await.unwrap();
        let id = kr.active_id().to_string();
        assert!(std::path::Path::new(&file_path).exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "keyring file must be 0600");
        }

        // Reload sees the same active key (persisted, not regenerated).
        let reloaded = Keyring::load(&dir, None).await.unwrap();
        assert_eq!(reloaded.active_id(), id);
    }

    /// A read error that is NOT NotFound (here: path is a directory) must abort
    /// load instead of bootstrapping a fresh key over the existing path.
    #[tokio::test]
    async fn load_read_error_does_not_bootstrap() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = format!("{}/.maxio-keys.json", dir);

        // Keyring path is a directory containing a marker → read_to_string
        // fails with a non-NotFound error for any uid (even root).
        std::fs::create_dir(&file_path).unwrap();
        let marker = format!("{}/marker", file_path);
        std::fs::write(&marker, b"do-not-destroy").unwrap();

        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("read error must abort load");
        assert!(
            err.to_string().contains("Failed to read keyring file"),
            "expected read-failure error, got: {}",
            err
        );

        // Original path untouched, marker intact, no temp leftovers.
        assert_eq!(std::fs::read(&marker).unwrap(), b"do-not-destroy");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {:?}",
            leftovers
        );
    }

    /// chmod-000 variant of the above. Skips the core assertion when running
    /// privileged (root bypasses file permission checks via CAP_DAC_OVERRIDE).
    #[cfg(unix)]
    #[tokio::test]
    async fn load_unreadable_file_errors_and_preserves_content() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = format!("{}/.maxio-keys.json", dir);

        // Bootstrap a real keyring, capture its bytes.
        Keyring::load(&dir, None).await.unwrap();
        let original = std::fs::read(&file_path).unwrap();

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Privilege probe: root can read 0o000 files, making this test moot.
        let privileged = std::fs::read(&file_path).is_ok();

        if !privileged {
            let err = Keyring::load(&dir, None)
                .await
                .err()
                .expect("unreadable keyring must abort load, not regenerate");
            assert!(
                err.to_string().contains("Failed to read keyring file"),
                "expected read-failure error, got: {}",
                err
            );
        }

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            std::fs::read(&file_path).unwrap(),
            original,
            "keyring content must be untouched"
        );
    }

    /// Rotate with a non-NotFound read error must abort, leaving the original
    /// path untouched and writing nothing (no new-key-only keyring, no .bak).
    #[tokio::test]
    async fn rotate_read_error_aborts_without_writing() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = format!("{}/.maxio-keys.json", dir);

        std::fs::create_dir(&file_path).unwrap();
        let marker = format!("{}/marker", file_path);
        std::fs::write(&marker, b"do-not-destroy").unwrap();

        let err = rotate(&dir)
            .await
            .err()
            .expect("read error must abort rotate");
        assert!(
            err.to_string().contains("Failed to read keyring file"),
            "expected read-failure error, got: {}",
            err
        );

        assert_eq!(std::fs::read(&marker).unwrap(), b"do-not-destroy");
        assert!(!std::path::Path::new(&format!("{}.bak", file_path)).exists());
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {:?}",
            leftovers
        );
    }

    /// chmod-000 variant for rotate (skips when privileged).
    #[cfg(unix)]
    #[tokio::test]
    async fn rotate_unreadable_file_errors_and_preserves_content() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = format!("{}/.maxio-keys.json", dir);

        Keyring::load(&dir, None).await.unwrap();
        let original = std::fs::read(&file_path).unwrap();

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let privileged = std::fs::read(&file_path).is_ok();

        if !privileged {
            let err = rotate(&dir)
                .await
                .err()
                .expect("unreadable keyring must abort rotate");
            assert!(
                err.to_string().contains("Failed to read keyring file"),
                "expected read-failure error, got: {}",
                err
            );
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                std::fs::read(&file_path).unwrap(),
                original,
                "keyring content must be untouched"
            );
        } else {
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// Rotate must snapshot the pre-rotate keyring to `.maxio-keys.json.bak`.
    #[tokio::test]
    async fn rotate_writes_backup_of_previous_keyring() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = format!("{}/.maxio-keys.json", dir);
        let bak_path = format!("{}.bak", file_path);

        let kr = Keyring::load(&dir, None).await.unwrap();
        let bootstrap_id = kr.active_id().to_string();
        let pre_rotate = std::fs::read(&file_path).unwrap();

        let result = rotate(&dir).await.unwrap();
        assert_ne!(result.new_active_id, bootstrap_id);
        assert_eq!(
            result.previous_active_id.as_deref(),
            Some(bootstrap_id.as_str())
        );
        assert_eq!(result.total_keys, 2);

        // Backup matches the pre-rotate content exactly.
        assert_eq!(
            std::fs::read(&bak_path).unwrap(),
            pre_rotate,
            ".bak must match pre-rotate keyring"
        );

        // Second rotate overwrites the .bak with the (new) pre-rotate state.
        let pre_second = std::fs::read(&file_path).unwrap();
        rotate(&dir).await.unwrap();
        assert_eq!(std::fs::read(&bak_path).unwrap(), pre_second);

        // Rotated keyring still loads and retains the old key.
        let reloaded = Keyring::load(&dir, None).await.unwrap();
        assert_eq!(reloaded.keys.len(), 3);
        assert!(reloaded.keys.contains_key(&bootstrap_id));
    }

    #[tokio::test]
    async fn override_with_wrong_length_errors() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let short = B64.encode([0u8; 16]);
        let err = Keyring::load(&dir, Some(&short))
            .await
            .err()
            .expect("16-byte key must fail");
        assert!(
            err.to_string().contains("exactly 32 bytes"),
            "unexpected error: {}",
            err
        );
    }
}
