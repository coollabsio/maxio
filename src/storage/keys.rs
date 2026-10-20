//! Keyring management for SSE-S3 master keys.
//!
//! On startup the keyring is loaded from:
//! 1. `MAXIO_MASTER_KEY` or `MAXIO_MASTER_KEY_FILE` — a 32-byte key kept outside
//!    the data directory. It becomes the active key for new writes and is not
//!    copied into the data directory. Keys already stored in the keyring file
//!    are merged in so older objects still decrypt.
//! 2. `{data_dir}/.maxio-keys.json` — persisted keys. Created with a fresh
//!    random key only when the file is absent AND the data directory has no
//!    SSE-S3 objects. A missing or unreadable file never overwrites an existing
//!    keyring, and a missing file does not bootstrap when encrypted objects
//!    (or `{data_dir}/.maxio-key-check.json`) say a key is required.
//!
//! `.maxio-key-check.json` stores an HMAC of a fixed label under each master
//! key, plus whether that key lives in `.maxio-keys.json` (`on-disk`) or was
//! supplied from outside (`external`). It has no key material. It lives with
//! the data so a replaced key file fails at startup instead of serving
//! ciphertext as if it were plaintext. Files written before `source` existed
//! stay valid; `check` treats those as it did before the field.
//!
//! Losing every copy of the master key makes SSE-S3 objects unrecoverable.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use tokio::fs;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const KEYRING_FILE_NAME: &str = ".maxio-keys.json";
const KEY_CHECK_FILE_NAME: &str = ".maxio-key-check.json";
const KEY_CHECK_VERSION: u32 = 1;
const KEY_CHECK_CONTEXT: &[u8] = b"maxio-sse-s3-key-check-v1";

type HmacSha256 = Hmac<Sha256>;

/// How to load the SSE-S3 keyring.
pub struct LoadOptions<'a> {
    /// Base64-encoded 32-byte master key from `--master-key` or a key file.
    /// When set, this key is active for new writes and is not written into the
    /// data directory.
    pub master_key_b64: Option<&'a str>,
    /// Permit startup when SSE-S3 objects exist but their master key is absent.
    /// Does not overwrite an unreadable or corrupt keyring file. Pass it on
    /// every start until the original keys are restored.
    pub allow_missing_master_key: bool,
}

// ── Persisted key file format ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
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
    /// (if present and readable) is merged in for unwrapping older objects.
    /// The external key is not written into the data directory.
    /// If `master_key_b64` is `None`, the keyring file is loaded. A fresh key
    /// is created only when that file is absent and the data directory has no
    /// SSE-S3 objects.
    pub async fn load(data_dir: &str, master_key_b64: Option<&str>) -> anyhow::Result<Self> {
        Self::load_with(
            data_dir,
            LoadOptions {
                master_key_b64,
                allow_missing_master_key: false,
            },
        )
        .await
    }

    /// [`Keyring::load`] with an explicit missing-key override.
    pub async fn load_with(data_dir: &str, opts: LoadOptions<'_>) -> anyhow::Result<Self> {
        let file_path = keyring_path(data_dir);
        let mut keys: HashMap<String, [u8; 32]> = HashMap::new();
        // `external` only when no keyring file is involved. A file that is
        // merged in still holds keys, so losing it later must stay an error.
        let mut key_source = KeySource::OnDisk;

        let active_id = if let Some(mk) = opts.master_key_b64 {
            let key_bytes = decode_master_key(mk)?;
            let id = key_id_from_bytes(&key_bytes);
            keys.insert(id.clone(), key_bytes);
            match read_keyring_file(&file_path).await? {
                KeyringFileState::Missing => {
                    key_source = KeySource::External;
                }
                KeyringFileState::Parsed(kr) => {
                    warn_if_perms_open(Path::new(&file_path), "SSE-S3 keyring file").await;
                    ingest_keyring_entries(&mut keys, &kr)?;
                }
            }
            id
        } else {
            match read_keyring_file(&file_path).await? {
                KeyringFileState::Parsed(kr) => {
                    warn_if_perms_open(Path::new(&file_path), "SSE-S3 keyring file").await;
                    ingest_keyring_entries(&mut keys, &kr)?.ok_or_else(|| {
                        anyhow::anyhow!(
                            "Keyring file {file_path} has no active key. Refusing to generate a replacement."
                        )
                    })?
                }
                KeyringFileState::Missing => {
                    let required = collect_requirement(data_dir).await?;
                    if !required.is_empty() && !opts.allow_missing_master_key {
                        return Err(missing_master_key_error(data_dir, &file_path, &required));
                    }
                    let mut new_key = [0u8; 32];
                    rand::rng().fill(&mut new_key[..]);
                    let id = key_id_from_bytes(&new_key);
                    let kr = KeyringFile {
                        keys: vec![KeyEntryJson {
                            key_b64: B64.encode(new_key),
                            id: id.clone(),
                            created_at: now_iso(),
                            active: true,
                        }],
                    };
                    let json = serde_json::to_string_pretty(&kr)?;
                    write_private_file_atomic(&file_path, &json, "SSE-S3 keyring").await?;
                    keys.insert(id.clone(), new_key);
                    id
                }
            }
        };

        reconcile_key_check(data_dir, &keys, opts.allow_missing_master_key, key_source).await?;
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
            .map_err(|_| {
                anyhow::anyhow!(
                    "SSE-S3 master key mismatch for key id '{key_id}': DEK unwrapping failed: authentication error. \
                     The configured master key does not match the key that encrypted this object, or the encryption metadata was tampered with. \
                     Refusing to return object data."
                )
            })?;

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
            .ok_or_else(|| anyhow::anyhow!(
                "Key '{key_id}' not found in keyring; object may be unrecoverable — check your MAXIO_MASTER_KEY, MAXIO_MASTER_KEY_FILE, or keyring file. Refusing to return object data."
            ))
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
    let file_path = keyring_path(data_dir);

    // Load existing. Only a missing file with no SSE-S3 objects may start from
    // an empty keyring. Any other read error must abort, or rotate would write
    // a keyring containing only the new key and orphan every existing object.
    let (mut kr, original_exists) = match read_keyring_file(&file_path).await? {
        KeyringFileState::Parsed(kr) => {
            warn_if_perms_open(Path::new(&file_path), "SSE-S3 keyring file").await;
            let mut existing = HashMap::new();
            if ingest_keyring_entries(&mut existing, &kr)?.is_none() {
                anyhow::bail!("Keyring file {file_path} has no active key. Refusing to rotate.");
            }
            // Confirm the current keys match the data-directory check before
            // replacing the file. A failure here leaves the keyring untouched.
            reconcile_key_check(data_dir, &existing, false, KeySource::OnDisk).await?;
            (kr, true)
        }
        KeyringFileState::Missing => {
            let required = collect_requirement(data_dir).await?;
            if !required.is_empty() {
                return Err(missing_master_key_error(data_dir, &file_path, &required));
            }
            (KeyringFile { keys: Vec::new() }, false)
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

    // Atomic durable write: temp file (0600) → fsync → rename → dir fsync.
    // The check file is updated after this write. A crash in between is safe:
    // the new keyring already contains every previous key, and the next start
    // adds the new key id to the check file.
    let json = serde_json::to_string_pretty(&kr)?;
    write_private_file_atomic(&file_path, &json, "SSE-S3 keyring").await?;

    let mut updated = HashMap::new();
    ingest_keyring_entries(&mut updated, &kr)?;
    reconcile_key_check(data_dir, &updated, false, KeySource::OnDisk).await?;

    Ok(RotateResult {
        new_active_id: new_id,
        previous_active_id: previous_active,
        total_keys: kr.keys.len(),
    })
}

/// Outcome of [`merge_keyring`].
pub struct MergeResult {
    pub active_id: String,
    pub added_ids: Vec<String>,
    pub total_keys: usize,
}

/// Merge every key from `from_path` into the data directory keyring.
///
/// Keys already in the data directory are kept. The active key stays the one
/// already active there; if the data directory has no keyring yet, the imported
/// file's active key becomes active. Conflicting bytes for one id abort the
/// merge and leave the destination untouched.
///
/// Use this to put an original keyring back after `--allow-missing-master-key`
/// created a new key. Replacing `.maxio-keys.json` with the backup drops the
/// new key.
pub async fn merge_keyring(data_dir: &str, from_path: &Path) -> anyhow::Result<MergeResult> {
    let from_display = from_path.display().to_string();
    let imported = match read_keyring_file(&from_display).await? {
        KeyringFileState::Missing => {
            anyhow::bail!("keyring file {from_display} not found");
        }
        KeyringFileState::Parsed(kr) => kr,
    };
    let mut imported_keys = HashMap::new();
    ingest_keyring_entries(&mut imported_keys, &imported)?;
    if imported.keys.is_empty() {
        anyhow::bail!("keyring file {from_display} contains no keys");
    }

    let dest_path = keyring_path(data_dir);
    if Path::new(&dest_path) == from_path {
        anyhow::bail!("--from {from_display} is the data directory keyring; nothing to merge");
    }

    let (mut dest, dest_active) = match read_keyring_file(&dest_path).await? {
        KeyringFileState::Missing => (KeyringFile { keys: Vec::new() }, None),
        KeyringFileState::Parsed(kr) => {
            let mut existing = HashMap::new();
            let active = ingest_keyring_entries(&mut existing, &kr)?;
            (kr, active)
        }
    };

    let mut known: HashMap<String, [u8; 32]> = HashMap::new();
    ingest_keyring_entries(&mut known, &dest)?;

    let mut added_ids = Vec::new();
    let mut active_id = dest_active;
    for entry in &imported.keys {
        let bytes = imported_keys[&entry.id];
        if let Some(existing) = known.get(&entry.id) {
            if existing != &bytes {
                anyhow::bail!(
                    "key id {} in {from_display} does not match the key already stored in {dest_path}. Refusing to merge.",
                    entry.id
                );
            }
            continue;
        }
        let becomes_active = active_id.is_none() && entry.active;
        if becomes_active {
            active_id = Some(entry.id.clone());
        }
        dest.keys.push(KeyEntryJson {
            id: entry.id.clone(),
            key_b64: entry.key_b64.clone(),
            created_at: entry.created_at.clone(),
            active: becomes_active,
        });
        known.insert(entry.id.clone(), bytes);
        added_ids.push(entry.id.clone());
    }

    let active_id = match active_id {
        Some(id) => id,
        None => {
            let id = dest.keys[0].id.clone();
            dest.keys[0].active = true;
            id
        }
    };
    // Exactly one active flag. Imported entries that were active in the source
    // file are stored inactive unless they were chosen above.
    let mut seen_active = false;
    for entry in &mut dest.keys {
        if entry.id == active_id && !seen_active {
            entry.active = true;
            seen_active = true;
        } else {
            entry.active = false;
        }
    }

    let json = serde_json::to_string_pretty(&dest)?;
    write_private_file_atomic(&dest_path, &json, "SSE-S3 keyring").await?;

    if let Err(err) = reconcile_key_check(data_dir, &known, false, KeySource::OnDisk).await {
        return Err(anyhow::anyhow!(
            "{err}\n\nThe merged keyring was written to {dest_path} (added {}). Restart after the missing keys are merged in.",
            if added_ids.is_empty() {
                "nothing".to_string()
            } else {
                added_ids.join(", ")
            }
        ));
    }

    Ok(MergeResult {
        active_id,
        total_keys: dest.keys.len(),
        added_ids,
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

/// Durably and atomically write a secret or key-check file.
///
/// Steps: create a per-process temp file next to `file_path` (mode 0600 from
/// the start on Unix — no world-readable window), write the JSON, fsync the
/// file, rename it over `file_path`, then fsync the parent directory so the
/// rename itself survives a crash. The directory fsync is Unix-only and skipped
/// gracefully elsewhere.
async fn write_private_file_atomic(file_path: &str, json: &str, label: &str) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let tmp_path = format!("{}.tmp-{}", file_path, std::process::id());

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // Owner-only from the moment of creation (umask cannot widen this).
        let _ = label;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    {
        tracing::warn!(
            path = %file_path,
            "{} written without owner-only file permissions on this platform — \
             restrict ACLs manually so only the maxio service account can read it",
            label
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

fn keyring_path(data_dir: &str) -> String {
    format!("{data_dir}/{KEYRING_FILE_NAME}")
}

fn check_path(data_dir: &str) -> String {
    format!("{data_dir}/{KEY_CHECK_FILE_NAME}")
}

enum KeyringFileState {
    Missing,
    Parsed(KeyringFile),
}

async fn read_keyring_file(path: &str) -> anyhow::Result<KeyringFileState> {
    match fs::read_to_string(path).await {
        Ok(data) => {
            let kr = serde_json::from_str::<KeyringFile>(&data).map_err(|e| {
                anyhow::anyhow!("Failed to parse keyring file {path}: {e}. Refusing to replace it.")
            })?;
            Ok(KeyringFileState::Parsed(kr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeyringFileState::Missing),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to read keyring file {path}: {e} — refusing to bootstrap over it; \
             fix permissions or restore the file"
        )),
    }
}

/// Insert keyring entries. Returns the last entry marked active.
///
/// Every entry's id must be the id derived from its key bytes. A mismatch
/// means the file was edited: loading it would wrap new objects under an id
/// that does not identify the bytes, and unwrap would fail closed only later.
fn ingest_keyring_entries(
    keys: &mut HashMap<String, [u8; 32]>,
    kr: &KeyringFile,
) -> anyhow::Result<Option<String>> {
    let mut active = None;
    for entry in &kr.keys {
        let kb = decode_32(&entry.key_b64).map_err(|e| {
            anyhow::anyhow!(
                "Keyring entry '{}' has invalid key material ({e}). Refusing to start.",
                entry.id
            )
        })?;
        let computed = key_id_from_bytes(&kb);
        if computed != entry.id {
            anyhow::bail!(
                "Keyring entry id '{}' does not match its key material (expected id '{computed}'). \
                 The key file is corrupt or has been edited. Refusing to start.",
                entry.id
            );
        }
        if let Some(existing) = keys.get(&entry.id) {
            if existing != &kb {
                anyhow::bail!(
                    "Keyring has conflicting material for key id '{}'. Refusing to start.",
                    entry.id
                );
            }
        } else {
            keys.insert(entry.id.clone(), kb);
        }
        if entry.active {
            active = Some(entry.id.clone());
        }
    }
    Ok(active)
}

/// Decode a base64 master key, accepting standard and URL-safe alphabets.
fn decode_master_key(input: &str) -> anyhow::Result<[u8; 32]> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        anyhow::bail!("MAXIO_MASTER_KEY must be base64-encoded 32 bytes");
    }
    let raw = B64
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&compact))
        .map_err(|_| anyhow::anyhow!("MAXIO_MASTER_KEY must be base64-encoded 32 bytes"))?;
    if raw.len() != 32 {
        anyhow::bail!(
            "MAXIO_MASTER_KEY must be exactly 32 bytes when decoded (got {})",
            raw.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Resolve the external master key from a flag/env value or a file.
///
/// Inline text and a key file are mutually exclusive. The returned string is
/// canonical standard base64 with no whitespace. Nothing is written to disk.
pub async fn resolve_master_key(
    inline: Option<&str>,
    file: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    if let (Some(_), Some(path)) = (inline, file) {
        anyhow::bail!(
            "Set only one of --master-key (MAXIO_MASTER_KEY) and --master-key-file (MAXIO_MASTER_KEY_FILE). Both were provided (file: {}).",
            path.display()
        );
    }
    if let Some(path) = file {
        return Ok(Some(read_master_key_file(path).await?));
    }
    if let Some(value) = inline {
        if value.trim().is_empty() {
            anyhow::bail!("MAXIO_MASTER_KEY / --master-key is empty");
        }
        let key = decode_master_key(value)?;
        return Ok(Some(B64.encode(key)));
    }
    Ok(None)
}

/// Read-only view of whether this data directory's SSE-S3 master key is present.
///
/// Does not create a keyring or rewrite `.maxio-key-check.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterKeyAssessment {
    /// On-disk keyring and/or the supplied key satisfy `.maxio-key-check.json`.
    Satisfied,
    /// The check file records an external key, and this invocation did not receive one.
    ExternalKeyUnverified { ids: Vec<String> },
    /// The key is missing or does not match. `--repair` cannot fix this.
    Unrecoverable { detail: String },
}

pub async fn assess_master_key(
    data_dir: &str,
    supplied_b64: Option<&str>,
) -> anyhow::Result<MasterKeyAssessment> {
    let mut keys: HashMap<String, [u8; 32]> = HashMap::new();
    let keyring_present = match read_keyring_file(&keyring_path(data_dir)).await? {
        KeyringFileState::Missing => false,
        KeyringFileState::Parsed(kr) => {
            ingest_keyring_entries(&mut keys, &kr)?;
            true
        }
    };
    if let Some(b64) = supplied_b64 {
        let raw = decode_master_key(b64)?;
        keys.insert(key_id_from_bytes(&raw), raw);
    }

    let (check_entries, check_source) = match read_check_file(&check_path(data_dir)).await? {
        CheckRead::Missing => (Vec::new(), None),
        CheckRead::Parsed(file) => (file.keys, file.source),
    };
    let scan = scan_sse_s3(data_dir).await?;

    let mut required: BTreeSet<String> = BTreeSet::new();
    for entry in &check_entries {
        if !entry.id.is_empty() {
            required.insert(entry.id.clone());
        }
    }
    required.extend(scan.ids.iter().cloned());

    if required.is_empty() && scan.unresolved.is_empty() {
        return Ok(MasterKeyAssessment::Satisfied);
    }

    if keys.is_empty() {
        if check_source == Some(KeySource::OnDisk) && !keyring_present {
            return Ok(MasterKeyAssessment::Unrecoverable {
                detail: "the on-disk SSE-S3 keyring (.maxio-keys.json) is missing. .maxio-key-check.json records that this data directory stored its master key there. Plaintext cannot be recovered without that file or the original key.".into(),
            });
        }
        // No `source` field: files written before the field existed. Those stay
        // a note, which is what check did when any check file had no keyring.
        if !check_entries.is_empty() && !keyring_present && supplied_b64.is_none() {
            return Ok(MasterKeyAssessment::ExternalKeyUnverified {
                ids: required.into_iter().collect(),
            });
        }
        return Ok(MasterKeyAssessment::Unrecoverable {
            detail: "SSE-S3 objects are present but no master key is available (.maxio-keys.json is missing and no key was passed). Their plaintext cannot be recovered without the original key.".into(),
        });
    }

    let mut missing = Vec::new();
    for id in &required {
        let Some(key) = keys.get(id) else {
            missing.push(id.clone());
            continue;
        };
        if let Some(entry) = check_entries.iter().find(|entry| &entry.id == id) {
            if let Some(stored) = &entry.check {
                let stored_bytes = B64.decode(stored).unwrap_or_default();
                let actual = key_check_mac(key)?;
                if !ct_eq(&stored_bytes, &actual) {
                    return Ok(MasterKeyAssessment::Unrecoverable {
                        detail: format!(
                            "master key for id {id} does not match .maxio-key-check.json"
                        ),
                    });
                }
            }
        }
    }
    if missing.is_empty() {
        return Ok(MasterKeyAssessment::Satisfied);
    }
    if supplied_b64.is_none() && !keyring_present && !check_entries.is_empty() {
        if check_source == Some(KeySource::OnDisk) {
            return Ok(MasterKeyAssessment::Unrecoverable {
                detail: "the on-disk SSE-S3 keyring (.maxio-keys.json) is missing. .maxio-key-check.json records that this data directory stored its master key there. Plaintext cannot be recovered without that file or the original key.".into(),
            });
        }
        return Ok(MasterKeyAssessment::ExternalKeyUnverified { ids: missing });
    }
    let supplied_ids: Vec<&str> = keys.keys().map(String::as_str).collect();
    Ok(MasterKeyAssessment::Unrecoverable {
        detail: format!(
            "supplied master key does not match .maxio-key-check.json (required key ids: {}; available: {})",
            missing.join(", "),
            supplied_ids.join(", ")
        ),
    })
}

async fn read_master_key_file(path: &Path) -> anyhow::Result<String> {
    let raw = fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read master key file {}: {e}", path.display()))?;
    warn_if_perms_open(path, "SSE-S3 master key file").await;
    if let Ok(text) = std::str::from_utf8(&raw) {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.is_empty() {
            anyhow::bail!("Master key file {} is empty", path.display());
        }
        if let Ok(key) = decode_master_key(&compact) {
            return Ok(B64.encode(key));
        }
    }
    if raw.len() == 32 {
        return Ok(B64.encode(raw));
    }
    anyhow::bail!(
        "Master key file {} must contain a base64-encoded 32-byte key (a trailing newline is fine) or exactly 32 raw bytes. Got {} bytes.",
        path.display(),
        raw.len()
    )
}

/// Where the master key for this data directory is kept.
///
/// Recorded in `.maxio-key-check.json` so `check` can tell a deleted on-disk
/// keyring from an external key that was never stored there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum KeySource {
    #[serde(rename = "on-disk")]
    OnDisk,
    #[serde(rename = "external")]
    External,
}

#[derive(Serialize, Deserialize)]
struct KeyCheckFile {
    version: u32,
    /// Absent in files written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<KeySource>,
    keys: Vec<KeyCheckEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct KeyCheckEntry {
    id: String,
    /// Base64 HMAC-SHA256 of [`KEY_CHECK_CONTEXT`] under the master key.
    /// Absent when the id was observed but the key bytes were not available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    check: Option<String>,
}

enum CheckRead {
    Missing,
    Parsed(KeyCheckFile),
}

struct Requirement {
    /// Key ids named by `.maxio-key-check.json`. The file has no key material.
    check_ids: BTreeSet<String>,
    /// Key ids found in SSE-S3 object or multipart metadata.
    object_ids: BTreeSet<String>,
    unresolved: Vec<String>,
}

impl Requirement {
    fn is_empty(&self) -> bool {
        self.check_ids.is_empty() && self.object_ids.is_empty() && self.unresolved.is_empty()
    }

    fn has_encrypted_objects(&self) -> bool {
        !self.object_ids.is_empty() || !self.unresolved.is_empty()
    }
}

struct SseScan {
    ids: BTreeSet<String>,
    unresolved: Vec<String>,
}

async fn read_check_file(path: &str) -> anyhow::Result<CheckRead> {
    match fs::read_to_string(path).await {
        Ok(data) => {
            let parsed = serde_json::from_str::<KeyCheckFile>(&data).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to parse key check file {path}: {e}. This file records which master keys encrypted data in this directory and does not contain key material. Refusing to start. If .maxio-keys.json is intact, move this file aside and restart so it can be rebuilt from object metadata."
                )
            })?;
            if parsed.version != KEY_CHECK_VERSION {
                anyhow::bail!(
                    "Unsupported key check file version {} in {path} (this build understands version {KEY_CHECK_VERSION}). Refusing to start.",
                    parsed.version
                );
            }
            Ok(CheckRead::Parsed(parsed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CheckRead::Missing),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to read key check file {path}: {e}. Refusing to start, because this file is how MaxIO detects a missing or wrong SSE-S3 master key."
        )),
    }
}

async fn collect_requirement(data_dir: &str) -> anyhow::Result<Requirement> {
    let mut req = Requirement {
        check_ids: BTreeSet::new(),
        object_ids: BTreeSet::new(),
        unresolved: Vec::new(),
    };
    match read_check_file(&check_path(data_dir)).await? {
        CheckRead::Missing => {}
        CheckRead::Parsed(file) => {
            for entry in file.keys {
                if !entry.id.is_empty() {
                    req.check_ids.insert(entry.id);
                }
            }
        }
    }
    let scan = scan_sse_s3(data_dir).await?;
    req.object_ids = scan.ids;
    req.unresolved = scan.unresolved;
    Ok(req)
}

fn missing_master_key_error(
    data_dir: &str,
    keyring_path: &str,
    req: &Requirement,
) -> anyhow::Error {
    let check = check_path(data_dir);
    let lead = if req.has_encrypted_objects() {
        "SSE-S3 master key is missing and this data directory contains encrypted objects."
    } else {
        "SSE-S3 master key is missing. A key check file records key ids for this data directory; no encrypted object metadata was found."
    };
    anyhow::anyhow!(
        "{lead}\n\
         \n\
         keyring file: {keyring_path} (not found)\n\
         data directory: {data_dir}\n\
         key check file: {check}\n\
         still required: {}\n\
         \n\
         Refusing to generate a new master key. Restore the key, or pass --allow-missing-master-key\n\
         (MAXIO_ALLOW_MISSING_MASTER_KEY=true) on every server start until the original keys are restored.\n\
         Restore {keyring_path} from backup, or pass the original key with --master-key / --master-key-file\n\
         (MAXIO_MASTER_KEY / MAXIO_MASTER_KEY_FILE).\n\
         That flag does not overwrite an unreadable or corrupt keyring file. If it creates a new key, merge the original keyring back with `maxio keyring merge` instead of replacing this file.",
        requirement_details(req)
    )
}

fn keys_do_not_satisfy_error(data_dir: &str, missing: &[String]) -> anyhow::Error {
    anyhow::anyhow!(
        "SSE-S3 master key mismatch: data directory {data_dir} requires key ids [{}] but they are not in the loaded keyring. Refusing to start so existing objects are not orphaned. If --allow-missing-master-key created a new key, merge that keyring with the original instead of replacing the file: maxio keyring merge --data-dir {data_dir} --from <the-other-keyring.json> then restart. Otherwise restore the original .maxio-keys.json or pass --master-key / --master-key-file (MAXIO_MASTER_KEY / MAXIO_MASTER_KEY_FILE). To abandon the missing keys, pass --allow-missing-master-key on every start until they are restored.",
        missing.join(", ")
    )
}

fn requirement_details(req: &Requirement) -> String {
    let mut details = Vec::new();
    if !req.check_ids.is_empty() {
        let ids: Vec<&str> = req.check_ids.iter().map(String::as_str).collect();
        details.push(format!(
            "key check file records key ids: {}",
            ids.join(", ")
        ));
    }
    if !req.object_ids.is_empty() {
        let ids: Vec<&str> = req.object_ids.iter().map(String::as_str).collect();
        details.push(format!(
            "encrypted object metadata key ids: {}",
            ids.join(", ")
        ));
    }
    if !req.unresolved.is_empty() {
        let shown: Vec<&str> = req.unresolved.iter().take(5).map(String::as_str).collect();
        let extra = req.unresolved.len().saturating_sub(shown.len());
        let mut line = format!(
            "SSE-S3 metadata without a readable key id: {}",
            shown.join(", ")
        );
        if extra > 0 {
            line.push_str(&format!(" (+{extra} more)"));
        }
        details.push(line);
    }
    if details.is_empty() {
        "(none)".to_string()
    } else {
        details.join("; ")
    }
}

async fn reconcile_key_check(
    data_dir: &str,
    keys: &HashMap<String, [u8; 32]>,
    allow_missing: bool,
    source: KeySource,
) -> anyhow::Result<()> {
    let path = check_path(data_dir);
    let (mut entries, mut dirty, previous_source) = match read_check_file(&path).await? {
        CheckRead::Missing => {
            let scan = scan_sse_s3(data_dir).await?;
            if !scan.unresolved.is_empty() && !allow_missing {
                let shown = scan
                    .unresolved
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "SSE-S3 metadata is corrupt or has no key id ({shown}). Refusing to start, because the master key for those objects cannot be checked. Restore the metadata, or pass --allow-missing-master-key to abandon them."
                );
            }
            let entries = scan
                .ids
                .into_iter()
                .map(|id| KeyCheckEntry { id, check: None })
                .collect();
            (entries, true, None)
        }
        CheckRead::Parsed(file) => (file.keys, false, file.source),
    };
    if previous_source != Some(source) {
        dirty = true;
    }

    let mut missing = Vec::new();
    for entry in &entries {
        match keys.get(&entry.id) {
            None => missing.push(entry.id.clone()),
            Some(key) => {
                if let Some(stored) = &entry.check {
                    let actual = key_check_mac(key)?;
                    let stored_bytes = B64.decode(stored).unwrap_or_default();
                    if !ct_eq(&stored_bytes, &actual) {
                        anyhow::bail!(
                            "SSE-S3 master key mismatch for key id {}. The key loaded for this id does not match the check value stored in {path}. Refusing to start so encrypted objects are not opened with the wrong key. Restore the original .maxio-keys.json or pass the original --master-key / --master-key-file. --allow-missing-master-key does not bypass a key that is present but wrong.",
                            entry.id
                        );
                    }
                }
            }
        }
    }

    if !missing.is_empty() && !allow_missing {
        return Err(keys_do_not_satisfy_error(data_dir, &missing));
    }
    if !missing.is_empty() {
        tracing::error!(
            "SSE-S3 master keys [{}] are required by {} but are not loaded. --allow-missing-master-key is set, so startup continues and those objects stay unreadable until the original keys are restored. Pass the flag on every start until then.",
            missing.join(", "),
            path
        );
    }

    for entry in &mut entries {
        if entry.check.is_none() {
            if let Some(key) = keys.get(&entry.id) {
                entry.check = Some(B64.encode(key_check_mac(key)?));
                dirty = true;
            }
        }
    }

    let known: BTreeSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    let mut extra: Vec<&String> = keys
        .keys()
        .filter(|id| !known.contains(id.as_str()))
        .collect();
    extra.sort();
    for id in extra {
        let Some(key) = keys.get(id) else {
            continue;
        };
        entries.push(KeyCheckEntry {
            id: id.clone(),
            check: Some(B64.encode(key_check_mac(key)?)),
        });
        dirty = true;
    }

    if dirty {
        let file = KeyCheckFile {
            version: KEY_CHECK_VERSION,
            source: Some(source),
            keys: entries,
        };
        let json = serde_json::to_string_pretty(&file)?;
        write_private_file_atomic(&path, &json, "SSE-S3 key check file").await?;
    }
    Ok(())
}

fn key_check_mac(key: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("failed to init SSE-S3 key check HMAC"))?;
    mac.update(KEY_CHECK_CONTEXT);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn scan_sse_s3(data_dir: &str) -> anyhow::Result<SseScan> {
    let root = PathBuf::from(data_dir).join("buckets");
    tokio::task::spawn_blocking(move || scan_sse_s3_sync(&root))
        .await
        .map_err(|e| anyhow::anyhow!("SSE-S3 metadata scan task failed: {e}"))?
}

fn scan_sse_s3_sync(buckets: &Path) -> anyhow::Result<SseScan> {
    let mut scan = SseScan {
        ids: BTreeSet::new(),
        unresolved: Vec::new(),
    };
    if !buckets.exists() {
        return Ok(scan);
    }
    scan_dir_sync(buckets, &mut scan)?;
    Ok(scan)
}

fn scan_dir_sync(dir: &Path, scan: &mut SseScan) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to list {}: {e}. Refusing to continue, because encrypted objects in this directory would be missed.",
            dir.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            anyhow::anyhow!("Failed to read a directory entry in {}: {e}", dir.display())
        })?;
        let ft = entry
            .file_type()
            .map_err(|e| anyhow::anyhow!("Failed to stat {}: {e}", entry.path().display()))?;
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            scan_dir_sync(&path, scan)?;
        } else if ft.is_file() {
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".meta.json") {
                inspect_meta_file(&path, scan)?;
            }
        }
    }
    Ok(())
}

fn inspect_meta_file(path: &Path, scan: &mut SseScan) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read object metadata {}: {e}. Refusing to continue, because this file may record an SSE-S3 key id.",
            path.display()
        )
    })?;
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            if text.contains("sse_s3") {
                scan.unresolved.push(path.display().to_string());
            }
            return Ok(());
        }
    };
    if let Some(enc) = value.get("encryption").filter(|v| is_sse_s3(v)) {
        push_sse_id(enc, "key_id", path, scan);
    }
    if let Some(spec) = value.get("encryption_spec").filter(|v| is_sse_s3(v)) {
        push_sse_id(spec, "upload_dek_key_id", path, scan);
    }
    Ok(())
}

fn is_sse_s3(value: &serde_json::Value) -> bool {
    value.get("mode").and_then(|m| m.as_str()) == Some("sse_s3")
}

fn push_sse_id(obj: &serde_json::Value, field: &str, path: &Path, scan: &mut SseScan) {
    match obj.get(field).and_then(|v| v.as_str()) {
        Some(id) if !id.is_empty() => {
            scan.ids.insert(id.to_string());
        }
        _ => scan.unresolved.push(path.display().to_string()),
    }
}

async fn warn_if_perms_open(path: &Path, what: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(path).await {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        "{} {} has permissions {:o}; expected 0600. Group or other users can read it. Run: chmod 600 {}",
                        what,
                        path.display(),
                        mode,
                        path.display()
                    );
                }
            }
            Err(e) => {
                tracing::warn!("could not stat {} {}: {e}", what, path.display());
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, what);
    }
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

    #[tokio::test]
    async fn missing_key_with_only_check_file_does_not_claim_encrypted_objects() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let kr = Keyring::load(&dir, None).await.unwrap();
        let id = kr.active_id().to_string();
        std::fs::remove_file(keyring_path(&dir)).unwrap();

        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("check file alone must still refuse a new key");
        let msg = err.to_string();
        assert!(msg.contains("key check file"), "unexpected error: {msg}");
        assert!(msg.contains(&id), "unexpected error: {msg}");
        assert!(
            msg.contains("no encrypted object metadata was found"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("contains encrypted objects"),
            "empty data dir must not claim encrypted objects: {msg}"
        );
        assert!(!std::path::Path::new(&keyring_path(&dir)).exists());
    }

    #[tokio::test]
    async fn merge_restores_original_key_without_dropping_the_new_one() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let original = Keyring::load(&dir, None).await.unwrap();
        let old_id = original.active_id().to_string();
        let dek = Keyring::generate_dek();
        let (wrapped, nonce) = original.wrap_dek(&old_id, &dek).unwrap();
        let backup = tmp.path().join("original-keys.json");
        std::fs::copy(keyring_path(&dir), &backup).unwrap();

        std::fs::remove_file(keyring_path(&dir)).unwrap();
        let fresh = Keyring::load_with(
            &dir,
            LoadOptions {
                master_key_b64: None,
                allow_missing_master_key: true,
            },
        )
        .await
        .unwrap();
        let new_id = fresh.active_id().to_string();
        assert_ne!(new_id, old_id);
        let new_keyring = std::fs::read(keyring_path(&dir)).unwrap();

        // Copying the backup over the new file drops the new key.
        std::fs::copy(&backup, keyring_path(&dir)).unwrap();
        let replaced = Keyring::load(&dir, None)
            .await
            .err()
            .expect("restored original alone must not satisfy the new key id");
        let replaced_msg = replaced.to_string();
        assert!(
            replaced_msg.contains(&new_id),
            "unexpected error: {replaced_msg}"
        );
        assert!(
            replaced_msg.contains("keyring merge"),
            "unexpected error: {replaced_msg}"
        );

        std::fs::write(keyring_path(&dir), new_keyring).unwrap();
        let merged = merge_keyring(&dir, &backup).await.unwrap();
        assert_eq!(merged.active_id, new_id);
        assert_eq!(merged.added_ids, vec![old_id.clone()]);
        assert_eq!(merged.total_keys, 2);

        let loaded = Keyring::load(&dir, None).await.unwrap();
        assert_eq!(loaded.active_id(), new_id);
        assert_eq!(loaded.unwrap_dek(&old_id, &wrapped, &nonce).unwrap(), dek);
        let new_dek = Keyring::generate_dek();
        let (new_wrapped, new_nonce) = loaded.wrap_dek(&new_id, &new_dek).unwrap();
        assert_eq!(
            loaded
                .unwrap_dek(&new_id, &new_wrapped, &new_nonce)
                .unwrap(),
            new_dek
        );
    }

    fn write_sse_sidecar(dir: &str, rel: &str, body: &str) {
        let path = std::path::PathBuf::from(dir).join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn sse_object_meta(key_id: &str) -> String {
        format!(r#"{{"encryption":{{"algorithm":"AES256","mode":"sse_s3","key_id":"{key_id}"}}}}"#)
    }

    #[tokio::test]
    async fn missing_keyring_with_sse_object_does_not_bootstrap() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = keyring_path(&dir);
        write_sse_sidecar(
            &dir,
            "buckets/photos/vacation.jpg.meta.json",
            &sse_object_meta("aabbccddeeff0011"),
        );
        write_sse_sidecar(
            &dir,
            "buckets/photos/.versions/vacation.jpg/0001.meta.json",
            &sse_object_meta("0011223344556677"),
        );
        write_sse_sidecar(
            &dir,
            "buckets/photos/.uploads/upload-1/.meta.json",
            r#"{"encryption_spec":{"mode":"sse_s3","upload_dek_key_id":"ffeeddccbbaa9988"}}"#,
        );

        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("missing key must not bootstrap over encrypted objects");
        let msg = err.to_string();
        assert!(
            msg.contains("Refusing to generate a new master key"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("contains encrypted objects"),
            "object metadata must be described as encrypted objects: {msg}"
        );
        assert!(
            msg.contains("aabbccddeeff0011"),
            "error should name the key id: {msg}"
        );
        assert!(
            msg.contains("0011223344556677"),
            "error should name version key id: {msg}"
        );
        assert!(
            msg.contains("ffeeddccbbaa9988"),
            "error should name multipart key id: {msg}"
        );
        assert!(!std::path::Path::new(&file_path).exists());
        assert!(!std::path::Path::new(&check_path(&dir)).exists());
    }

    #[tokio::test]
    async fn allow_missing_bootstraps_but_keeps_required_ids() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        write_sse_sidecar(
            &dir,
            "buckets/b/obj.meta.json",
            &sse_object_meta("aabbccddeeff0011"),
        );

        let kr = Keyring::load_with(
            &dir,
            LoadOptions {
                master_key_b64: None,
                allow_missing_master_key: true,
            },
        )
        .await
        .unwrap();
        assert!(
            kr.unwrap_dek("aabbccddeeff0011", &[0u8; 32], &[0u8; 12])
                .unwrap_err()
                .to_string()
                .contains("not found in keyring")
        );

        let again = Keyring::load(&dir, None)
            .await
            .err()
            .expect("next start without the override must still refuse");
        assert!(
            again.to_string().contains("aabbccddeeff0011"),
            "required id must stick: {again}"
        );
    }

    #[tokio::test]
    async fn allow_missing_does_not_overwrite_unreadable_keyring() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let file_path = keyring_path(&dir);
        std::fs::create_dir(&file_path).unwrap();
        let marker = format!("{file_path}/marker");
        std::fs::write(&marker, b"do-not-destroy").unwrap();

        let err = Keyring::load_with(
            &dir,
            LoadOptions {
                master_key_b64: None,
                allow_missing_master_key: true,
            },
        )
        .await
        .err()
        .expect("unreadable keyring must still abort");
        assert!(
            err.to_string().contains("Failed to read keyring file"),
            "unexpected error: {err}"
        );
        assert_eq!(std::fs::read(&marker).unwrap(), b"do-not-destroy");
    }

    #[tokio::test]
    async fn external_key_is_not_copied_and_restart_requires_it() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let (b64, raw) = rand_key_b64();

        let kr = Keyring::load(&dir, Some(&b64)).await.unwrap();
        assert_eq!(kr.active_id(), key_id_from_bytes(&raw));
        assert!(!std::path::Path::new(&keyring_path(&dir)).exists());
        let check = std::fs::read_to_string(check_path(&dir)).unwrap();
        assert!(
            !check.contains(&b64),
            "check file must not contain key material"
        );
        assert!(check.contains(kr.active_id()));

        let missing = Keyring::load(&dir, None)
            .await
            .err()
            .expect("restart without the external key must fail");
        assert!(
            missing
                .to_string()
                .contains("Refusing to generate a new master key")
                || missing.to_string().contains("not in the loaded keyring"),
            "unexpected error: {missing}"
        );
        assert!(!std::path::Path::new(&keyring_path(&dir)).exists());

        let again = Keyring::load(&dir, Some(&b64)).await.unwrap();
        assert_eq!(again.active_id(), kr.active_id());
    }

    #[tokio::test]
    async fn wrong_external_key_fails_check_and_unwrap_is_not_plaintext() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let kr = Keyring::load(&dir, None).await.unwrap();
        let id = kr.active_id().to_string();
        let dek = Keyring::generate_dek();
        let (mut wrapped, nonce) = kr.wrap_dek(&id, &dek).unwrap();

        std::fs::remove_file(keyring_path(&dir)).unwrap();
        let (other, _) = rand_key_b64();
        let err = Keyring::load(&dir, Some(&other))
            .await
            .err()
            .expect("wrong external key must fail before serving data");
        assert!(
            err.to_string().contains("not in the loaded keyring")
                || err.to_string().contains("does not match the check value"),
            "unexpected error: {err}"
        );
        assert!(!std::path::Path::new(&keyring_path(&dir)).exists());

        wrapped[0] ^= 0xff;
        let tampered = kr.unwrap_dek(&id, &wrapped, &nonce).unwrap_err();
        let msg = tampered.to_string();
        assert!(
            msg.contains("authentication error"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("Refusing to return object data"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn replaced_keyring_fails_when_check_file_remains() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let original = Keyring::load(&dir, None).await.unwrap();
        let original_id = original.active_id().to_string();

        let other_dir = TempDir::new().unwrap();
        Keyring::load(other_dir.path().to_str().unwrap(), None)
            .await
            .unwrap();
        std::fs::copy(
            keyring_path(other_dir.path().to_str().unwrap()),
            keyring_path(&dir),
        )
        .unwrap();

        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("replaced keyring must not start");
        assert!(
            err.to_string().contains(&original_id),
            "error should name the original key id: {err}"
        );
    }

    #[tokio::test]
    async fn legacy_dir_without_check_file_rebuilds_it() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let kr = Keyring::load(&dir, None).await.unwrap();
        let id = kr.active_id().to_string();
        std::fs::remove_file(check_path(&dir)).unwrap();

        let reloaded = Keyring::load(&dir, None).await.unwrap();
        assert_eq!(reloaded.active_id(), id);
        let check = std::fs::read_to_string(check_path(&dir)).unwrap();
        assert!(check.contains(&id));
        assert!(!check.contains("key_b64"));
    }

    #[tokio::test]
    async fn legacy_replaced_keyring_is_caught_by_scanning_objects() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let kr = Keyring::load(&dir, None).await.unwrap();
        let id = kr.active_id().to_string();
        write_sse_sidecar(&dir, "buckets/b/obj.meta.json", &sse_object_meta(&id));
        std::fs::remove_file(check_path(&dir)).unwrap();

        let other_dir = TempDir::new().unwrap();
        Keyring::load(other_dir.path().to_str().unwrap(), None)
            .await
            .unwrap();
        std::fs::copy(
            keyring_path(other_dir.path().to_str().unwrap()),
            keyring_path(&dir),
        )
        .unwrap();

        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("scan must reject a keyring that cannot decrypt existing objects");
        assert!(err.to_string().contains(&id), "unexpected error: {err}");
        let on_disk = std::fs::read_to_string(keyring_path(&dir)).unwrap();
        assert!(
            !on_disk.contains(&id),
            "rejected load must not rewrite the replaced keyring"
        );
    }

    #[tokio::test]
    async fn keyring_entry_id_must_match_key_material() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        Keyring::load(&dir, None).await.unwrap();
        let path = keyring_path(&dir);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["keys"][0]["id"] = serde_json::Value::String("0011223344556677".to_string());
        let edited = serde_json::to_string_pretty(&value).unwrap();
        std::fs::write(&path, &edited).unwrap();

        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("id/material mismatch must fail");
        assert!(
            err.to_string().contains("does not match its key material"),
            "unexpected error: {err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    }

    #[tokio::test]
    async fn tampered_check_value_refuses_start_even_with_override() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        Keyring::load(&dir, None).await.unwrap();
        let path = check_path(&dir);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["keys"][0]["check"] = serde_json::Value::String(B64.encode([0u8; 32]));
        std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).unwrap();

        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("tampered check must fail");
        assert!(
            err.to_string().contains("does not match the check value"),
            "unexpected error: {err}"
        );

        let overridden = Keyring::load_with(
            &dir,
            LoadOptions {
                master_key_b64: None,
                allow_missing_master_key: true,
            },
        )
        .await
        .err()
        .expect("override must not accept a wrong key");
        assert!(
            overridden
                .to_string()
                .contains("does not match the check value"),
            "unexpected error: {overridden}"
        );
    }

    #[tokio::test]
    async fn rotate_refuses_when_keyring_missing_but_objects_exist() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        write_sse_sidecar(
            &dir,
            "buckets/b/obj.meta.json",
            &sse_object_meta("aabbccddeeff0011"),
        );
        let err = rotate(&dir)
            .await
            .err()
            .expect("rotate must not create a keyring over encrypted objects");
        assert!(
            err.to_string()
                .contains("Refusing to generate a new master key"),
            "unexpected error: {err}"
        );
        assert!(!std::path::Path::new(&keyring_path(&dir)).exists());
    }

    #[tokio::test]
    async fn corrupt_keyring_json_is_not_replaced() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let path = keyring_path(&dir);
        std::fs::write(&path, b"{ not json").unwrap();
        let err = Keyring::load(&dir, None)
            .await
            .err()
            .expect("corrupt keyring must fail");
        assert!(
            err.to_string().contains("Failed to parse keyring file"),
            "unexpected error: {err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn group_readable_keyring_still_loads_without_chmod() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let path = keyring_path(&dir);
        let kr = Keyring::load(&dir, None).await.unwrap();
        let id = kr.active_id().to_string();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let reloaded = Keyring::load(&dir, None).await.unwrap();
        assert_eq!(reloaded.active_id(), id);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "load warns about loose permissions and does not chmod"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_file_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        Keyring::load(&dir, None).await.unwrap();
        let mode = std::fs::metadata(check_path(&dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn resolve_master_key_validates_file_and_rejects_both_sources() {
        let tmp = TempDir::new().unwrap();
        let (b64, raw) = rand_key_b64();
        let text_path = tmp.path().join("master.key");
        std::fs::write(&text_path, format!("{b64}\n")).unwrap();
        let resolved = resolve_master_key(None, Some(&text_path))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved, b64);

        let raw_path = tmp.path().join("master.raw");
        std::fs::write(&raw_path, raw).unwrap();
        let from_raw = resolve_master_key(None, Some(&raw_path))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from_raw, b64);

        let err = resolve_master_key(Some(&b64), Some(&text_path))
            .await
            .expect_err("both sources must fail");
        assert!(
            err.to_string().contains("only one"),
            "unexpected error: {err}"
        );

        let short = tmp.path().join("short.key");
        std::fs::write(&short, B64.encode([0u8; 16])).unwrap();
        let err = resolve_master_key(None, Some(&short))
            .await
            .expect_err("short key file must fail");
        assert!(
            err.to_string().contains("exactly 32 bytes")
                || err.to_string().contains("32 raw bytes"),
            "unexpected error: {err}"
        );

        std::fs::write(tmp.path().join("empty.key"), b"\n").unwrap();
        let err = resolve_master_key(None, Some(&tmp.path().join("empty.key")))
            .await
            .expect_err("empty key file must fail");
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn external_key_with_restored_keyring_unwraps_old_dek() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let bootstrap = Keyring::load(&dir, None).await.unwrap();
        let old_id = bootstrap.active_id().to_string();
        let dek = Keyring::generate_dek();
        let (wrapped, nonce) = bootstrap.wrap_dek(&old_id, &dek).unwrap();
        let saved = std::fs::read(keyring_path(&dir)).unwrap();

        std::fs::remove_file(keyring_path(&dir)).unwrap();
        let (b64, _) = rand_key_b64();
        let err = Keyring::load(&dir, Some(&b64))
            .await
            .err()
            .expect("wrong external key must fail while the original key file is absent");
        assert!(err.to_string().contains(&old_id), "unexpected error: {err}");

        std::fs::write(keyring_path(&dir), saved).unwrap();
        let merged = Keyring::load(&dir, Some(&b64)).await.unwrap();
        assert_ne!(merged.active_id(), old_id);
        assert_eq!(merged.unwrap_dek(&old_id, &wrapped, &nonce).unwrap(), dek);
        let check = std::fs::read_to_string(check_path(&dir)).unwrap();
        assert!(
            !check.contains(&b64),
            "check file must not contain key material"
        );
    }
}
