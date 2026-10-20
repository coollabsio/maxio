//! Read sealed key ids out of `iam.json` without decrypting them.
//!
//! The SSE-S3 master-key check (including a missing keyring that must not be
//! replaced) has to see these ids. This module does not load the keyring, so
//! `storage::keys` can call it without a cycle.

use std::path::Path;

use anyhow::Context;

/// Master-key ids that sealed at least one IAM access-key secret.
///
/// An empty list means `iam.json` is absent or has no keys. A read or parse
/// failure is returned: startup must not ignore a file it cannot inspect.
pub async fn sealed_master_key_ids(data_dir: &str) -> anyhow::Result<Vec<String>> {
    let path = Path::new(data_dir).join("iam.json");
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            anyhow::bail!(
                "failed to read {}: {err}. Refusing to start, because IAM access-key secrets in this file are sealed with the SSE-S3 master key.",
                path.display()
            );
        }
    };
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON. Refusing to start.", path.display()))?;
    let mut ids = Vec::new();
    let Some(keys) = value.get("keys").and_then(|keys| keys.as_array()) else {
        return Ok(ids);
    };
    for key in keys {
        let Some(id) = key
            .pointer("/secret/keyId")
            .and_then(|id| id.as_str())
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        if !ids.contains(&id.to_string()) {
            ids.push(id.to_string());
        }
    }
    Ok(ids)
}

/// Refuse to mint a new master key when `iam.json` already holds sealed secrets
/// and neither the keyring file nor `MAXIO_MASTER_KEY` is available.
///
/// Call this before [`crate::storage::keys::Keyring::load`]. That load creates
/// a fresh keyring when the file is missing; doing so here would make every
/// existing access key permanently unverifiable.
pub async fn refuse_missing_keyring(
    data_dir: &str,
    master_key_provided: bool,
) -> anyhow::Result<()> {
    let ids = sealed_master_key_ids(data_dir).await?;
    if ids.is_empty() || master_key_provided {
        return Ok(());
    }
    let keyring_path = format!("{data_dir}/.maxio-keys.json");
    match tokio::fs::metadata(&keyring_path).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "IAM access-key secrets are sealed and the SSE-S3 master key is missing.\n\
                 \n\
                 keyring file: {keyring_path} (not found)\n\
                 data directory: {data_dir}\n\
                 iam.json requires master key ids: {}\n\
                 \n\
                 Refusing to generate a new master key. Those secrets cannot be recovered without the original key, so a new keyring would make the access keys permanently unverifiable.\n\
                 Restore {keyring_path} from the same backup as iam.json, or pass that key with --master-key (MAXIO_MASTER_KEY).\n\
                 Back up .maxio-keys.json and iam.json together.",
                ids.join(", ")
            )
        }
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_keyring_with_sealed_secrets_does_not_create_a_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let iam = r#"{"version":1,"users":[],"keys":[{"accessKeyId":"MXIAEXAMPLE000000001","userName":"alice","label":"alice","status":"Active","createdAt":"2026-01-01T00:00:00.000Z","secret":{"keyId":"aabbccddeeff0011","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAA"},"policy":null}],"policies":[]}"#;
        tokio::fs::write(dir.path().join("iam.json"), iam)
            .await
            .unwrap();
        let err = refuse_missing_keyring(path, false).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("iam.json"), "{message}");
        assert!(message.contains("master key"), "{message}");
        assert!(message.contains("aabbccddeeff0011"), "{message}");
        assert!(!dir.path().join(".maxio-keys.json").exists());
    }

    #[tokio::test]
    async fn absent_iam_file_does_not_block_startup() {
        let dir = tempfile::tempdir().unwrap();
        refuse_missing_keyring(dir.path().to_str().unwrap(), false)
            .await
            .unwrap();
    }
}
