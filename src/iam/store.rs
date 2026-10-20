//! Durable IAM state at `{data_dir}/iam.json`.
//!
//! Access-key secrets are encrypted with the SSE-S3 master key (AES-256-GCM,
//! AAD `maxio-iam-v1`) before they touch disk. SigV4 needs the raw secret to
//! check signatures, so a one-way hash is not enough. Losing the keyring makes
//! IAM keys unverifiable; the root access key keeps working because it lives
//! in the server config, not in this file.
//!
//! Writes are atomic: a 0600 temp file, fsync, rename, then a parent-directory
//! fsync. The in-memory copy is replaced only after the rename succeeds.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::storage::keys::Keyring;

use super::policy::{self, PolicyDocument, ScopeAccess};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const SECRET_AAD: &[u8] = b"maxio-iam-v1";
const MAX_USERS: usize = 1000;
const MAX_KEYS_PER_USER: usize = 10;
const MAX_SERVICE_KEYS: usize = 100;
const MAX_INLINE: usize = 10;
const MAX_ATTACHED: usize = 20;

const KEY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug)]
pub enum IamError {
    AlreadyExists(String),
    NotFound(String),
    Conflict(String),
    Invalid(String),
    Limit(String),
    Internal(String),
}

impl std::fmt::Display for IamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::Invalid(m)
            | Self::Limit(m)
            | Self::Internal(m) => write!(f, "{m}"),
        }
    }
}

impl IamError {
    pub fn status_code(&self) -> http::StatusCode {
        match self {
            Self::AlreadyExists(_) | Self::Conflict(_) => http::StatusCode::CONFLICT,
            Self::NotFound(_) => http::StatusCode::NOT_FOUND,
            Self::Limit(_) | Self::Invalid(_) => http::StatusCode::BAD_REQUEST,
            Self::Internal(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn iam_code(&self) -> &'static str {
        match self {
            Self::AlreadyExists(_) => "EntityAlreadyExists",
            Self::NotFound(_) => "NoSuchEntity",
            Self::Conflict(_) => "DeleteConflict",
            Self::Invalid(_) => "ValidationError",
            Self::Limit(_) => "LimitExceeded",
            Self::Internal(_) => "ServiceFailure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Inactive,
}

impl KeyStatus {
    pub fn parse(value: &str) -> Result<Self, IamError> {
        match value {
            "Active" => Ok(Self::Active),
            "Inactive" => Ok(Self::Inactive),
            _ => Err(IamError::Invalid(
                "status must be Active or Inactive".into(),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Inactive => "Inactive",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
    pub user_id: String,
    pub enabled: bool,
    pub created_at: String,
    pub key_count: usize,
    pub attached_policies: Vec<String>,
    pub inline_policies: Vec<InlineInfo>,
}

#[derive(Debug, Clone)]
pub struct InlineInfo {
    pub name: String,
    pub document: PolicyDocument,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub access_key_id: String,
    pub user_name: Option<String>,
    pub label: String,
    pub status: KeyStatus,
    pub created_at: String,
    pub has_policy: bool,
}

#[derive(Debug, Clone)]
pub struct CreatedKey {
    pub info: KeyInfo,
    pub secret: String,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicyInfo {
    pub name: String,
    pub description: String,
    pub builtin: bool,
    pub created_at: String,
    pub updated_at: String,
    pub document: PolicyDocument,
}

#[derive(Debug, Clone)]
pub struct KeyAuth {
    pub secret: String,
    pub status: KeyStatus,
    pub user_name: Option<String>,
    pub label: String,
    pub user_enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct UserRecord {
    name: String,
    #[serde(rename = "userId")]
    user_id: String,
    enabled: bool,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "attachedPolicies")]
    attached_policies: Vec<String>,
    #[serde(rename = "inlinePolicies")]
    inline_policies: Vec<InlineRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
struct InlineRecord {
    name: String,
    document: PolicyDocument,
}

#[derive(Clone, Serialize, Deserialize)]
struct SecretRecord {
    #[serde(rename = "keyId")]
    key_id: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct KeyRecord {
    #[serde(rename = "accessKeyId")]
    access_key_id: String,
    #[serde(rename = "userName")]
    user_name: Option<String>,
    label: String,
    status: KeyStatus,
    #[serde(rename = "createdAt")]
    created_at: String,
    secret: SecretRecord,
    policy: Option<PolicyDocument>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ManagedRecord {
    name: String,
    description: String,
    builtin: bool,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    document: PolicyDocument,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct DiskFile {
    version: u32,
    users: Vec<UserRecord>,
    keys: Vec<KeyRecord>,
    policies: Vec<ManagedRecord>,
}

#[derive(Clone)]
struct MemoryKey {
    access_key_id: String,
    user_name: Option<String>,
    label: String,
    status: KeyStatus,
    created_at: String,
    secret: String,
    policy: Option<PolicyDocument>,
}

#[derive(Clone)]
struct Memory {
    users: Vec<UserRecord>,
    keys: Vec<MemoryKey>,
    policies: Vec<ManagedRecord>,
}

pub struct IamStore {
    path: PathBuf,
    keyring: Arc<Keyring>,
    inner: Mutex<Memory>,
}

fn stores() -> &'static Mutex<HashMap<String, Arc<IamStore>>> {
    static STORES: OnceLock<Mutex<HashMap<String, Arc<IamStore>>>> = OnceLock::new();
    STORES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn store_for(config: &Config) -> Result<Arc<IamStore>, IamError> {
    IamStore::open(&config.data_dir, config.master_key.as_deref()).await
}

/// Decrypt every sealed secret with `keyring`, or explain why startup must stop.
///
/// A missing `iam.json` is success. A secret sealed by a key this ring does not
/// have, or a new ring that replaced the original, is a startup failure rather
/// than a 500 on the first signed request.
pub async fn ensure_secrets_readable(data_dir: &str, keyring: &Keyring) -> Result<(), String> {
    let path = Path::new(data_dir).join("iam.json");
    match load_memory(&path, keyring).await {
        Ok(_) => Ok(()),
        Err(err) => Err(format!(
            "Refusing to start: {err}. IAM access-key secrets in {} are sealed with the SSE-S3 master key in .maxio-keys.json. Restore that keyring from the same backup as iam.json, or pass the original key with --master-key (MAXIO_MASTER_KEY). A missing or new master key makes those access keys permanently unverifiable. Back up both files together.",
            path.display()
        )),
    }
}

impl IamStore {
    pub async fn open(data_dir: &str, master_key: Option<&str>) -> Result<Arc<Self>, IamError> {
        let cache_key = match master_key {
            Some(key) => format!("{data_dir}\n{key}"),
            None => data_dir.to_string(),
        };
        let mut map = stores().lock().await;
        if let Some(existing) = map.get(&cache_key) {
            return Ok(existing.clone());
        }
        let keyring = Arc::new(
            Keyring::load(data_dir, master_key)
                .await
                .map_err(|e| IamError::Internal(e.to_string()))?,
        );
        let path = Path::new(data_dir).join("iam.json");
        let memory = load_memory(&path, &keyring).await?;
        let store = Arc::new(Self {
            path,
            keyring,
            inner: Mutex::new(memory),
        });
        map.insert(cache_key, store.clone());
        Ok(store)
    }

    pub async fn list_users(&self) -> Vec<UserInfo> {
        let guard = self.inner.lock().await;
        guard
            .users
            .iter()
            .map(|user| user.name.clone())
            .collect::<Vec<_>>()
            .into_iter()
            .map(|name| snapshot_user(&guard, &name).expect("name came from users"))
            .collect()
    }

    pub async fn get_user(&self, name: &str) -> Result<UserInfo, IamError> {
        let guard = self.inner.lock().await;
        snapshot_user(&guard, name)
    }

    pub async fn create_user(&self, name: &str) -> Result<UserInfo, IamError> {
        validate_name(name, "user name")?;
        let info = self
            .mutate(|mem| {
                if mem.users.iter().any(|u| u.name == name) {
                    return Err(IamError::AlreadyExists(format!(
                        "user {name} already exists"
                    )));
                }
                if mem.users.len() >= MAX_USERS {
                    return Err(IamError::Limit(format!(
                        "at most {MAX_USERS} users are supported"
                    )));
                }
                mem.users.push(UserRecord {
                    name: name.to_string(),
                    user_id: random_id("MXIU"),
                    enabled: true,
                    created_at: now_iso(),
                    attached_policies: Vec::new(),
                    inline_policies: Vec::new(),
                });
                Ok(snapshot_user(mem, name).expect("user was just inserted"))
            })
            .await?;
        Ok(info)
    }

    pub async fn set_user_enabled(&self, name: &str, enabled: bool) -> Result<UserInfo, IamError> {
        self.mutate(|mem| {
            {
                let user = find_user_mut(mem, name)?;
                user.enabled = enabled;
            }
            snapshot_user(mem, name)
        })
        .await
    }

    /// `cascade` deletes the user's keys and policy attachments. Without it,
    /// keys or attached policies produce a conflict (AWS `DeleteUser`).
    pub async fn delete_user(&self, name: &str, cascade: bool) -> Result<(), IamError> {
        self.mutate(|mem| {
            let idx = mem
                .users
                .iter()
                .position(|u| u.name == name)
                .ok_or_else(|| IamError::NotFound(format!("user {name} does not exist")))?;
            let has_keys = mem
                .keys
                .iter()
                .any(|k| k.user_name.as_deref() == Some(name));
            let user = &mem.users[idx];
            if !cascade
                && (has_keys
                    || !user.attached_policies.is_empty()
                    || !user.inline_policies.is_empty())
            {
                return Err(IamError::Conflict(format!(
                    "cannot delete user {name} while access keys or policies are still attached"
                )));
            }
            mem.users.remove(idx);
            mem.keys.retain(|k| k.user_name.as_deref() != Some(name));
            Ok(())
        })
        .await
    }

    pub async fn create_access_key(
        &self,
        user_name: &str,
        policy: Option<PolicyDocument>,
        key_only: bool,
    ) -> Result<CreatedKey, IamError> {
        if let Some(doc) = &policy {
            policy::validate_policy(doc).map_err(IamError::Invalid)?;
        }
        self.mutate(|mem| {
            if find_user(mem, user_name).is_err() {
                return Err(IamError::NotFound(format!(
                    "user {user_name} does not exist"
                )));
            }
            let count = mem
                .keys
                .iter()
                .filter(|k| k.user_name.as_deref() == Some(user_name))
                .count();
            if count >= MAX_KEYS_PER_USER {
                return Err(IamError::Limit(format!(
                    "user {user_name} already has {MAX_KEYS_PER_USER} access keys"
                )));
            }
            let (info, secret) = push_key(
                mem,
                Some(user_name.to_string()),
                user_name,
                policy.clone(),
                key_only,
            )?;
            if let (Some(doc), false) = (policy, key_only) {
                let inline_name = format!("scope-{}", info.access_key_id);
                attach_inline(mem, user_name, &inline_name, doc)?;
            }
            Ok(CreatedKey { info, secret })
        })
        .await
    }

    pub async fn create_service_key(
        &self,
        label: &str,
        policy: PolicyDocument,
    ) -> Result<CreatedKey, IamError> {
        validate_name(label, "service key name")?;
        policy::validate_policy(&policy).map_err(IamError::Invalid)?;
        self.mutate(|mem| {
            if mem
                .keys
                .iter()
                .any(|k| k.user_name.is_none() && k.label == label)
            {
                return Err(IamError::AlreadyExists(format!(
                    "service key {label} already exists"
                )));
            }
            let count = mem.keys.iter().filter(|k| k.user_name.is_none()).count();
            if count >= MAX_SERVICE_KEYS {
                return Err(IamError::Limit(format!(
                    "at most {MAX_SERVICE_KEYS} service keys are supported"
                )));
            }
            let (info, secret) = push_key(mem, None, label, Some(policy), true)?;
            Ok(CreatedKey { info, secret })
        })
        .await
    }

    pub async fn list_access_keys(&self, user_name: &str) -> Result<Vec<KeyInfo>, IamError> {
        let guard = self.inner.lock().await;
        find_user(&guard, user_name)?;
        Ok(guard
            .keys
            .iter()
            .filter(|k| k.user_name.as_deref() == Some(user_name))
            .map(key_info)
            .collect())
    }

    pub async fn list_service_keys(&self) -> Vec<KeyInfo> {
        let guard = self.inner.lock().await;
        guard
            .keys
            .iter()
            .filter(|k| k.user_name.is_none())
            .map(key_info)
            .collect()
    }

    pub async fn update_access_key(
        &self,
        user_name: Option<&str>,
        access_key_id: &str,
        status: KeyStatus,
    ) -> Result<KeyInfo, IamError> {
        self.mutate(|mem| {
            {
                let key = find_key_mut(mem, user_name, access_key_id)?;
                key.status = status;
            }
            Ok(key_info(find_key(mem, user_name, access_key_id)?))
        })
        .await
    }

    pub async fn update_key_by_id(
        &self,
        access_key_id: &str,
        status: KeyStatus,
    ) -> Result<KeyInfo, IamError> {
        self.mutate(|mem| {
            let idx = mem
                .keys
                .iter()
                .position(|k| k.access_key_id == access_key_id)
                .ok_or_else(|| {
                    IamError::NotFound(format!("access key {access_key_id} does not exist"))
                })?;
            mem.keys[idx].status = status;
            Ok(key_info(&mem.keys[idx]))
        })
        .await
    }

    pub async fn delete_key_by_id(&self, access_key_id: &str) -> Result<(), IamError> {
        self.mutate(|mem| {
            let idx = mem
                .keys
                .iter()
                .position(|k| k.access_key_id == access_key_id)
                .ok_or_else(|| {
                    IamError::NotFound(format!("access key {access_key_id} does not exist"))
                })?;
            remove_key_at(mem, idx);
            Ok(())
        })
        .await
    }

    pub async fn delete_access_key(
        &self,
        user_name: Option<&str>,
        access_key_id: &str,
    ) -> Result<(), IamError> {
        self.mutate(|mem| {
            let idx = key_index(mem, user_name, access_key_id)?;
            remove_key_at(mem, idx);
            Ok(())
        })
        .await
    }

    pub async fn put_inline_policy(
        &self,
        user_name: &str,
        policy_name: &str,
        document: PolicyDocument,
    ) -> Result<(), IamError> {
        validate_name(policy_name, "policy name")?;
        policy::validate_policy(&document).map_err(IamError::Invalid)?;
        self.mutate(|mem| attach_inline(mem, user_name, policy_name, document))
            .await
    }

    pub async fn delete_inline_policy(
        &self,
        user_name: &str,
        policy_name: &str,
    ) -> Result<(), IamError> {
        self.mutate(|mem| {
            let user = find_user_mut(mem, user_name)?;
            let before = user.inline_policies.len();
            user.inline_policies.retain(|p| p.name != policy_name);
            if user.inline_policies.len() == before {
                return Err(IamError::NotFound(format!(
                    "inline policy {policy_name} does not exist on user {user_name}"
                )));
            }
            Ok(())
        })
        .await
    }

    pub async fn get_inline_policy(
        &self,
        user_name: &str,
        policy_name: &str,
    ) -> Result<PolicyDocument, IamError> {
        let guard = self.inner.lock().await;
        let user = find_user(&guard, user_name)?;
        user.inline_policies
            .iter()
            .find(|p| p.name == policy_name)
            .map(|p| p.document.clone())
            .ok_or_else(|| {
                IamError::NotFound(format!(
                    "inline policy {policy_name} does not exist on user {user_name}"
                ))
            })
    }

    pub async fn list_inline_names(&self, user_name: &str) -> Result<Vec<String>, IamError> {
        let guard = self.inner.lock().await;
        let user = find_user(&guard, user_name)?;
        Ok(user
            .inline_policies
            .iter()
            .map(|p| p.name.clone())
            .collect())
    }

    pub async fn attach_policy(&self, user_name: &str, policy_name: &str) -> Result<(), IamError> {
        self.mutate(|mem| {
            if !mem.policies.iter().any(|p| p.name == policy_name) {
                return Err(IamError::NotFound(format!(
                    "policy {policy_name} does not exist"
                )));
            }
            let user = find_user_mut(mem, user_name)?;
            if user.attached_policies.iter().any(|n| n == policy_name) {
                return Ok(());
            }
            if user.attached_policies.len() >= MAX_ATTACHED {
                return Err(IamError::Limit(format!(
                    "user {user_name} already has {MAX_ATTACHED} attached policies"
                )));
            }
            user.attached_policies.push(policy_name.to_string());
            Ok(())
        })
        .await
    }

    pub async fn detach_policy(&self, user_name: &str, policy_name: &str) -> Result<(), IamError> {
        self.mutate(|mem| {
            let user = find_user_mut(mem, user_name)?;
            let before = user.attached_policies.len();
            user.attached_policies.retain(|n| n != policy_name);
            if user.attached_policies.len() == before {
                return Err(IamError::NotFound(format!(
                    "policy {policy_name} is not attached to user {user_name}"
                )));
            }
            Ok(())
        })
        .await
    }

    pub async fn list_attached(&self, user_name: &str) -> Result<Vec<String>, IamError> {
        let guard = self.inner.lock().await;
        Ok(find_user(&guard, user_name)?.attached_policies.clone())
    }

    pub async fn list_policies(&self) -> Vec<ManagedPolicyInfo> {
        let guard = self.inner.lock().await;
        guard.policies.iter().map(policy_info).collect()
    }

    pub async fn get_policy(&self, name: &str) -> Result<ManagedPolicyInfo, IamError> {
        let guard = self.inner.lock().await;
        guard
            .policies
            .iter()
            .find(|p| p.name == name)
            .map(policy_info)
            .ok_or_else(|| IamError::NotFound(format!("policy {name} does not exist")))
    }

    pub async fn create_policy(
        &self,
        name: &str,
        description: &str,
        document: PolicyDocument,
    ) -> Result<ManagedPolicyInfo, IamError> {
        validate_name(name, "policy name")?;
        policy::validate_policy(&document).map_err(IamError::Invalid)?;
        self.mutate(|mem| {
            if mem.policies.iter().any(|p| p.name == name) {
                return Err(IamError::AlreadyExists(format!(
                    "policy {name} already exists"
                )));
            }
            let now = now_iso();
            mem.policies.push(ManagedRecord {
                name: name.to_string(),
                description: description.to_string(),
                builtin: false,
                created_at: now.clone(),
                updated_at: now,
                document,
            });
            Ok(policy_info(
                mem.policies.iter().find(|p| p.name == name).unwrap(),
            ))
        })
        .await
    }

    pub async fn update_policy(
        &self,
        name: &str,
        description: Option<&str>,
        document: PolicyDocument,
    ) -> Result<ManagedPolicyInfo, IamError> {
        policy::validate_policy(&document).map_err(IamError::Invalid)?;
        self.mutate(|mem| {
            {
                let policy = mem
                    .policies
                    .iter_mut()
                    .find(|p| p.name == name)
                    .ok_or_else(|| IamError::NotFound(format!("policy {name} does not exist")))?;
                if policy.builtin {
                    return Err(IamError::Invalid(format!(
                        "built-in policy {name} cannot be modified"
                    )));
                }
                if let Some(description) = description {
                    policy.description = description.to_string();
                }
                policy.document = document;
                policy.updated_at = now_iso();
            }
            Ok(policy_info(
                mem.policies.iter().find(|p| p.name == name).unwrap(),
            ))
        })
        .await
    }

    pub async fn delete_policy(&self, name: &str) -> Result<(), IamError> {
        self.mutate(|mem| {
            let policy = mem
                .policies
                .iter()
                .find(|p| p.name == name)
                .ok_or_else(|| IamError::NotFound(format!("policy {name} does not exist")))?;
            if policy.builtin {
                return Err(IamError::Invalid(format!(
                    "built-in policy {name} cannot be deleted"
                )));
            }
            if mem
                .users
                .iter()
                .any(|u| u.attached_policies.iter().any(|n| n == name))
            {
                return Err(IamError::Conflict(format!(
                    "cannot delete policy {name} while it is attached to a user"
                )));
            }
            mem.policies.retain(|p| p.name != name);
            Ok(())
        })
        .await
    }

    pub async fn lookup_key(&self, access_key_id: &str) -> Option<KeyAuth> {
        let guard = self.inner.lock().await;
        let key = guard
            .keys
            .iter()
            .find(|k| k.access_key_id == access_key_id)?;
        let user_enabled = match &key.user_name {
            Some(name) => guard
                .users
                .iter()
                .find(|u| &u.name == name)
                .is_some_and(|u| u.enabled),
            None => true,
        };
        Some(KeyAuth {
            secret: key.secret.clone(),
            status: key.status,
            user_name: key.user_name.clone(),
            label: key.label.clone(),
            user_enabled,
        })
    }

    /// Policies that apply to this access key. Service keys contribute only
    /// their own policy. A missing user or key is an empty set (implicit deny).
    pub async fn policies_for_key(
        &self,
        access_key_id: &str,
    ) -> Result<(Vec<PolicyDocument>, Option<PolicyDocument>, bool), IamError> {
        let guard = self.inner.lock().await;
        let Some(key) = guard.keys.iter().find(|k| k.access_key_id == access_key_id) else {
            return Ok((Vec::new(), None, false));
        };
        if key.user_name.is_none() {
            let docs = key.policy.clone().into_iter().collect();
            return Ok((docs, None, true));
        }
        let Some(name) = key.user_name.clone() else {
            return Ok((Vec::new(), None, false));
        };
        let Some(user) = guard.users.iter().find(|u| u.name == name) else {
            return Ok((Vec::new(), None, false));
        };
        let mut docs = Vec::new();
        for attached in &user.attached_policies {
            if let Some(policy) = guard.policies.iter().find(|p| &p.name == attached) {
                docs.push(policy.document.clone());
            }
        }
        for inline in &user.inline_policies {
            docs.push(inline.document.clone());
        }
        Ok((docs, key.policy.clone(), false))
    }

    pub async fn preview_scope(
        &self,
        buckets: &[String],
        prefix: &str,
        access: &str,
    ) -> Result<PolicyDocument, IamError> {
        for bucket in buckets {
            if !crate::storage::is_valid_bucket_name(bucket) {
                return Err(IamError::Invalid(format!("invalid bucket name: {bucket}")));
            }
        }
        if prefix.contains('\0') || prefix.contains("..") {
            return Err(IamError::Invalid("invalid prefix".into()));
        }
        let access = ScopeAccess::parse(access).map_err(IamError::Invalid)?;
        Ok(policy::policy_for_scope(buckets, prefix, access))
    }

    async fn mutate<T>(
        &self,
        f: impl FnOnce(&mut Memory) -> Result<T, IamError>,
    ) -> Result<T, IamError> {
        let mut guard = self.inner.lock().await;
        let mut next = guard.clone();
        let result = f(&mut next)?;
        persist(&self.path, &self.keyring, &next).await?;
        *guard = next;
        Ok(result)
    }
}

fn snapshot_user(mem: &Memory, name: &str) -> Result<UserInfo, IamError> {
    let key_count = mem
        .keys
        .iter()
        .filter(|k| k.user_name.as_deref() == Some(name))
        .count();
    let user = find_user(mem, name)?.clone();
    Ok(user_info(&user, key_count))
}

fn user_info(user: &UserRecord, key_count: usize) -> UserInfo {
    UserInfo {
        name: user.name.clone(),
        user_id: user.user_id.clone(),
        enabled: user.enabled,
        created_at: user.created_at.clone(),
        key_count,
        attached_policies: user.attached_policies.clone(),
        inline_policies: user
            .inline_policies
            .iter()
            .map(|p| InlineInfo {
                name: p.name.clone(),
                document: p.document.clone(),
            })
            .collect(),
    }
}

fn key_info(key: &MemoryKey) -> KeyInfo {
    KeyInfo {
        access_key_id: key.access_key_id.clone(),
        user_name: key.user_name.clone(),
        label: key.label.clone(),
        status: key.status,
        created_at: key.created_at.clone(),
        has_policy: key.policy.is_some(),
    }
}

fn policy_info(policy: &ManagedRecord) -> ManagedPolicyInfo {
    ManagedPolicyInfo {
        name: policy.name.clone(),
        description: policy.description.clone(),
        builtin: policy.builtin,
        created_at: policy.created_at.clone(),
        updated_at: policy.updated_at.clone(),
        document: policy.document.clone(),
    }
}

fn find_user<'a>(mem: &'a Memory, name: &str) -> Result<&'a UserRecord, IamError> {
    mem.users
        .iter()
        .find(|u| u.name == name)
        .ok_or_else(|| IamError::NotFound(format!("user {name} does not exist")))
}

fn find_user_mut<'a>(mem: &'a mut Memory, name: &str) -> Result<&'a mut UserRecord, IamError> {
    mem.users
        .iter_mut()
        .find(|u| u.name == name)
        .ok_or_else(|| IamError::NotFound(format!("user {name} does not exist")))
}

fn key_index(
    mem: &Memory,
    user_name: Option<&str>,
    access_key_id: &str,
) -> Result<usize, IamError> {
    mem.keys
        .iter()
        .position(|k| k.access_key_id == access_key_id && k.user_name.as_deref() == user_name)
        .ok_or_else(|| IamError::NotFound(format!("access key {access_key_id} does not exist")))
}

fn find_key<'a>(
    mem: &'a Memory,
    user_name: Option<&str>,
    access_key_id: &str,
) -> Result<&'a MemoryKey, IamError> {
    let idx = key_index(mem, user_name, access_key_id)?;
    Ok(&mem.keys[idx])
}

fn find_key_mut<'a>(
    mem: &'a mut Memory,
    user_name: Option<&str>,
    access_key_id: &str,
) -> Result<&'a mut MemoryKey, IamError> {
    let idx = key_index(mem, user_name, access_key_id)?;
    Ok(&mut mem.keys[idx])
}

fn remove_key_at(mem: &mut Memory, idx: usize) {
    let access_key_id = mem.keys[idx].access_key_id.clone();
    let inline_name = format!("scope-{access_key_id}");
    let owner = mem.keys[idx].user_name.clone();
    mem.keys.remove(idx);
    if let Some(owner) = owner {
        if let Some(user) = mem.users.iter_mut().find(|u| u.name == owner) {
            user.inline_policies.retain(|p| p.name != inline_name);
        }
    }
}

fn attach_inline(
    mem: &mut Memory,
    user_name: &str,
    policy_name: &str,
    document: PolicyDocument,
) -> Result<(), IamError> {
    let user = find_user_mut(mem, user_name)?;
    if let Some(existing) = user
        .inline_policies
        .iter_mut()
        .find(|p| p.name == policy_name)
    {
        existing.document = document;
        return Ok(());
    }
    if user.inline_policies.len() >= MAX_INLINE {
        return Err(IamError::Limit(format!(
            "user {user_name} already has {MAX_INLINE} inline policies"
        )));
    }
    user.inline_policies.push(InlineRecord {
        name: policy_name.to_string(),
        document,
    });
    Ok(())
}

fn push_key(
    mem: &mut Memory,
    user_name: Option<String>,
    label: &str,
    policy: Option<PolicyDocument>,
    keep_policy_on_key: bool,
) -> Result<(KeyInfo, String), IamError> {
    let secret = random_secret();
    let mut access_key_id = random_id("MXIA");
    while mem.keys.iter().any(|k| k.access_key_id == access_key_id) {
        access_key_id = random_id("MXIA");
    }
    let key_policy = if keep_policy_on_key { policy } else { None };
    let key = MemoryKey {
        access_key_id,
        user_name,
        label: label.to_string(),
        status: KeyStatus::Active,
        created_at: now_iso(),
        secret: secret.clone(),
        policy: key_policy,
    };
    let info = key_info(&key);
    mem.keys.push(key);
    Ok((info, secret))
}

fn validate_name(name: &str, what: &str) -> Result<(), IamError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | ',' | '.' | '@' | '_' | '-')
        });
    if ok {
        Ok(())
    } else {
        Err(IamError::Invalid(format!(
            "{what} must be 1-64 characters from A-Z a-z 0-9 +=,.@_- "
        )))
    }
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn random_id(prefix: &str) -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut id = String::with_capacity(prefix.len() + 16);
    id.push_str(prefix);
    let span = 256 / KEY_ALPHABET.len() * KEY_ALPHABET.len();
    while id.len() < prefix.len() + 16 {
        let mut byte = [0u8; 1];
        rng.fill(&mut byte);
        let value = byte[0] as usize;
        if value < span {
            id.push(KEY_ALPHABET[value % KEY_ALPHABET.len()] as char);
        }
    }
    id
}

fn random_secret() -> String {
    use rand::RngExt;
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    format!("mxsk_{}", hex::encode(buf))
}

fn seed_builtins(policies: &mut Vec<ManagedRecord>) {
    let now = now_iso();
    for (name, description, document) in policy::builtin_policies() {
        if let Some(existing) = policies.iter_mut().find(|p| p.name == name) {
            existing.description = description.to_string();
            existing.builtin = true;
            existing.document = document;
            existing.updated_at = now.clone();
        } else {
            policies.push(ManagedRecord {
                name: name.to_string(),
                description: description.to_string(),
                builtin: true,
                created_at: now.clone(),
                updated_at: now.clone(),
                document,
            });
        }
    }
}

async fn load_memory(path: &Path, keyring: &Keyring) -> Result<Memory, IamError> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut policies = Vec::new();
            seed_builtins(&mut policies);
            return Ok(Memory {
                users: Vec::new(),
                keys: Vec::new(),
                policies,
            });
        }
        Err(e) => {
            return Err(IamError::Internal(format!(
                "failed to read {}: {e}",
                path.display()
            )));
        }
    };
    let disk: DiskFile = serde_json::from_str(&text)
        .map_err(|e| IamError::Internal(format!("iam.json is not valid JSON: {e}")))?;
    let mut keys = Vec::with_capacity(disk.keys.len());
    for key in disk.keys {
        let nonce = B64
            .decode(&key.secret.nonce)
            .map_err(|_| IamError::Internal("iam secret nonce is corrupt".into()))?;
        if nonce.len() != 12 {
            return Err(IamError::Internal("iam secret nonce is corrupt".into()));
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce);
        let ciphertext = B64
            .decode(&key.secret.ciphertext)
            .map_err(|_| IamError::Internal("iam secret ciphertext is corrupt".into()))?;
        let plain = keyring
            .open(SECRET_AAD, &key.secret.key_id, &nonce_bytes, &ciphertext)
            .map_err(|_| {
                IamError::Internal(
                    "failed to decrypt an IAM access-key secret; the master keyring does not match iam.json"
                        .into(),
                )
            })?;
        let secret = String::from_utf8(plain)
            .map_err(|_| IamError::Internal("iam secret is not valid text".into()))?;
        keys.push(MemoryKey {
            access_key_id: key.access_key_id,
            user_name: key.user_name,
            label: key.label,
            status: key.status,
            created_at: key.created_at,
            secret,
            policy: key.policy,
        });
    }
    let mut policies = disk.policies;
    seed_builtins(&mut policies);
    Ok(Memory {
        users: disk.users,
        keys,
        policies,
    })
}

async fn persist(path: &Path, keyring: &Keyring, mem: &Memory) -> Result<(), IamError> {
    let keys = mem
        .keys
        .iter()
        .map(|key| {
            let (key_id, nonce, ciphertext) = keyring
                .seal(SECRET_AAD, key.secret.as_bytes())
                .map_err(|e| {
                    IamError::Internal(format!("failed to encrypt access-key secret: {e}"))
                })?;
            Ok(KeyRecord {
                access_key_id: key.access_key_id.clone(),
                user_name: key.user_name.clone(),
                label: key.label.clone(),
                status: key.status,
                created_at: key.created_at.clone(),
                secret: SecretRecord {
                    key_id,
                    nonce: B64.encode(nonce),
                    ciphertext: B64.encode(ciphertext),
                },
                policy: key.policy.clone(),
            })
        })
        .collect::<Result<Vec<_>, IamError>>()?;
    let disk = DiskFile {
        version: 1,
        users: mem.users.clone(),
        keys,
        policies: mem.policies.clone(),
    };
    let json =
        serde_json::to_string_pretty(&disk).map_err(|e| IamError::Internal(e.to_string()))?;
    write_atomic(path, &json).await
}

async fn write_atomic(path: &Path, json: &str) -> Result<(), IamError> {
    use tokio::io::AsyncWriteExt;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| IamError::Internal(e.to_string()))?;
    }
    let tmp_path = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let write_result: Result<(), IamError> = async {
        let mut file = opts
            .open(&tmp_path)
            .await
            .map_err(|e| IamError::Internal(e.to_string()))?;
        file.write_all(json.as_bytes())
            .await
            .map_err(|e| IamError::Internal(e.to_string()))?;
        file.sync_all()
            .await
            .map_err(|e| IamError::Internal(e.to_string()))?;
        drop(file);
        tokio::fs::rename(&tmp_path, path)
            .await
            .map_err(|e| IamError::Internal(e.to_string()))?;
        Ok(())
    }
    .await;
    if let Err(e) = write_result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent = parent.to_path_buf();
        tokio::task::spawn_blocking(move || {
            std::fs::File::open(&parent).and_then(|d| d.sync_all())
        })
        .await
        .map_err(|e| IamError::Internal(e.to_string()))?
        .map_err(|e| IamError::Internal(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh() -> (tempfile::TempDir, Arc<IamStore>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        // Unique cache key per call: master key is none, so use a private data dir.
        let store = IamStore::open(path, None).await.unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn secrets_are_encrypted_at_rest_and_round_trip() {
        let (dir, store) = fresh().await;
        store.create_user("alice").await.unwrap();
        let created = store.create_access_key("alice", None, false).await.unwrap();
        let raw = tokio::fs::read_to_string(dir.path().join("iam.json"))
            .await
            .unwrap();
        assert!(!raw.contains(&created.secret));
        assert!(!raw.contains("mxsk_"));
        assert!(raw.contains(&created.info.access_key_id));

        let meta = std::fs::metadata(dir.path().join("iam.json")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let reloaded = IamStore::open(dir.path().to_str().unwrap(), None)
            .await
            .unwrap();
        let auth = reloaded
            .lookup_key(&created.info.access_key_id)
            .await
            .unwrap();
        assert_eq!(auth.secret, created.secret);
        assert!(auth.user_enabled);
        assert_eq!(auth.status, KeyStatus::Active);
    }

    #[tokio::test]
    async fn disable_user_and_delete_conflict() {
        let (_dir, store) = fresh().await;
        store.create_user("alice").await.unwrap();
        store.create_access_key("alice", None, false).await.unwrap();
        let err = store.delete_user("alice", false).await.unwrap_err();
        assert!(matches!(err, IamError::Conflict(_)));
        store.set_user_enabled("alice", false).await.unwrap();
        let user = store.get_user("alice").await.unwrap();
        assert!(!user.enabled);
        store.delete_user("alice", true).await.unwrap();
        assert!(store.get_user("alice").await.is_err());
        assert!(store.list_access_keys("alice").await.is_err());
    }

    #[tokio::test]
    async fn builtin_policies_are_seeded_and_protected() {
        let (_dir, store) = fresh().await;
        let names: Vec<_> = store
            .list_policies()
            .await
            .into_iter()
            .map(|p| p.name)
            .collect();
        for required in ["readonly", "readwrite", "writeonly", "admin"] {
            assert!(names.iter().any(|n| n == required), "{required}");
        }
        let err = store.delete_policy("readonly").await.unwrap_err();
        assert!(matches!(err, IamError::Invalid(_)));
    }

    #[tokio::test]
    async fn wrong_master_key_fails_before_a_request_with_a_startup_error() {
        let (dir, store) = fresh().await;
        store.create_user("alice").await.unwrap();
        store.create_access_key("alice", None, true).await.unwrap();
        let other = tempfile::tempdir().unwrap();
        let other_keyring = Keyring::load(other.path().to_str().unwrap(), None)
            .await
            .unwrap();
        let err = ensure_secrets_readable(dir.path().to_str().unwrap(), &other_keyring)
            .await
            .unwrap_err();
        assert!(err.contains("Refusing to start"), "{err}");
        assert!(err.contains("iam.json"), "{err}");
        assert!(err.contains("master key"), "{err}");
    }

    #[tokio::test]
    async fn service_key_policy_is_not_an_intersection() {
        let (_dir, store) = fresh().await;
        let doc = policy::policy_for_scope(&["pics".into()], "", ScopeAccess::Read);
        let created = store.create_service_key("backup", doc).await.unwrap();
        let (docs, key, service) = store
            .policies_for_key(&created.info.access_key_id)
            .await
            .unwrap();
        assert!(service);
        assert!(key.is_none());
        assert_eq!(docs.len(), 1);
        store
            .update_access_key(None, &created.info.access_key_id, KeyStatus::Inactive)
            .await
            .unwrap();
        let auth = store.lookup_key(&created.info.access_key_id).await.unwrap();
        assert_eq!(auth.status, KeyStatus::Inactive);
    }
}
