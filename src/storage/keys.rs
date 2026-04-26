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
    aead::{Aead, KeyInit},
};
use base64::Engine;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::fs;

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
            let kr = if let Ok(data) = fs::read_to_string(&file_path).await {
                serde_json::from_str::<KeyringFile>(&data)
                    .map_err(|e| anyhow::anyhow!("Failed to parse keyring file: {}", e))?
            } else {
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
                fs::write(&file_path, &json).await?;
                // Restrict permissions to owner-only.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = fs::metadata(&file_path).await?.permissions();
                    perms.set_mode(0o600);
                    fs::set_permissions(&file_path, perms).await?;
                }
                kr
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
            found_active
                .ok_or_else(|| anyhow::anyhow!("Keyring file has no active key"))?
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

    /// Generate a fresh random 4-byte per-object nonce prefix.
    pub fn generate_nonce_prefix() -> [u8; 4] {
        let mut prefix = [0u8; 4];
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

        let wrapped = cipher
            .encrypt(nonce, dek.as_slice())
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

        let plaintext = cipher
            .decrypt(nonce, wrapped)
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
/// Writes the file atomically via `{data_dir}/.maxio-keys.json.tmp` + rename and
/// preserves 0600 permissions on Unix.
pub async fn rotate(data_dir: &str) -> anyhow::Result<RotateResult> {
    let file_path = format!("{}/.maxio-keys.json", data_dir);
    let tmp_path = format!("{}.tmp", file_path);

    // Load existing (or bootstrap an empty one)
    let mut kr = match fs::read_to_string(&file_path).await {
        Ok(data) => serde_json::from_str::<KeyringFile>(&data)
            .map_err(|e| anyhow::anyhow!("Failed to parse keyring file: {}", e))?,
        Err(_) => KeyringFile { keys: Vec::new() },
    };

    // Capture previously-active id (if any) for the return payload.
    let previous_active = kr
        .keys
        .iter()
        .find(|e| e.active)
        .map(|e| e.id.clone());

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

    // Atomic write: temp file → rename
    let json = serde_json::to_string_pretty(&kr)?;
    fs::write(&tmp_path, &json).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp_path).await?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp_path, perms).await?;
    }
    fs::rename(&tmp_path, &file_path).await?;

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
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
