//! Identity and access management.
//!
//! The configured root access key stays the superuser. Every other key is an
//! IAM user key or a standalone service key. Authorization runs after SigV4:
//! explicit deny wins, then identity allow, then an anonymous bucket-policy
//! allow for public read and list.

pub mod policy;
pub mod secrets;
pub mod session;
pub mod store;

use store::KeyStatus;

use crate::config::Config;
use crate::error::S3Error;

pub const ACCOUNT_ID: &str = "000000000000";

#[derive(Clone, Debug)]
pub enum Principal {
    Root,
    User {
        name: String,
        access_key_id: String,
    },
    Service {
        /// Label stored for the console. The session copies it separately.
        #[allow(dead_code)]
        label: String,
        access_key_id: String,
    },
    /// Set only for the anonymous public-bucket bypass.
    Anonymous,
}

impl Principal {
    pub fn is_root(&self) -> bool {
        matches!(self, Self::Root)
    }

    pub fn access_key_id<'a>(&'a self, root_access_key: &'a str) -> &'a str {
        match self {
            Self::Root => root_access_key,
            Self::User { access_key_id, .. } | Self::Service { access_key_id, .. } => access_key_id,
            Self::Anonymous => "",
        }
    }
}

/// Request extension inserted by authentication.
#[derive(Clone, Debug)]
pub struct Authenticated {
    pub principal: Principal,
}

pub struct SigningMaterial {
    pub secret: String,
    pub enabled: bool,
    pub authenticated: Authenticated,
}

#[derive(Clone, Debug)]
pub struct ConsoleIdentity {
    pub authenticated: Authenticated,
    pub iam_admin: bool,
    pub access_key_id: String,
    pub kind: &'static str,
    pub user_name: Option<String>,
    pub label: Option<String>,
}

pub fn policy_arn(name: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT_ID}:policy/{name}")
}

pub fn user_arn(name: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT_ID}:user/{name}")
}

pub fn parse_policy_name(arn_or_name: &str) -> Option<&str> {
    if let Some(name) = arn_or_name.strip_prefix(&format!("arn:aws:iam::{ACCOUNT_ID}:policy/")) {
        return (!name.is_empty()).then_some(name);
    }
    if arn_or_name.contains(':') {
        return None;
    }
    (!arn_or_name.is_empty()).then_some(arn_or_name)
}

pub async fn signing_material(
    config: &Config,
    access_key: &str,
) -> Result<SigningMaterial, S3Error> {
    if crate::auth::signature_v4::constant_time_eq(
        access_key.as_bytes(),
        config.access_key.as_bytes(),
    ) {
        return Ok(SigningMaterial {
            secret: config.secret_key.clone(),
            enabled: true,
            authenticated: Authenticated {
                principal: Principal::Root,
            },
        });
    }
    let store = store::store_for(config)
        .await
        .map_err(|e| S3Error::internal(e.to_string()))?;
    let Some(key) = store.lookup_key(access_key).await else {
        return Err(S3Error::invalid_access_key());
    };
    let principal = match &key.user_name {
        Some(name) => Principal::User {
            name: name.clone(),
            access_key_id: access_key.to_string(),
        },
        None => Principal::Service {
            label: key.label.clone(),
            access_key_id: access_key.to_string(),
        },
    };
    Ok(SigningMaterial {
        secret: key.secret,
        enabled: key.status == KeyStatus::Active && key.user_enabled,
        authenticated: Authenticated { principal },
    })
}

pub async fn authorize(
    config: &Config,
    principal: &Principal,
    action: &str,
    resource: &str,
    prefix: Option<&str>,
    public_read: bool,
    public_list: bool,
) -> Result<(), S3Error> {
    if principal.is_root() {
        return Ok(());
    }
    if matches!(principal, Principal::Anonymous) {
        return if policy::bucket_policy_allows(action, public_read, public_list) {
            Ok(())
        } else {
            Err(S3Error::access_denied("Access Denied"))
        };
    }
    let allowed = identity_allows(
        config,
        principal,
        action,
        resource,
        prefix,
        public_read,
        public_list,
    )
    .await
    .map_err(|e| S3Error::internal(e.to_string()))?;
    if allowed {
        Ok(())
    } else {
        Err(S3Error::access_denied("Access Denied"))
    }
}

pub async fn identity_allows(
    config: &Config,
    principal: &Principal,
    action: &str,
    resource: &str,
    prefix: Option<&str>,
    public_read: bool,
    public_list: bool,
) -> Result<bool, store::IamError> {
    if principal.is_root() {
        return Ok(true);
    }
    let Some(access_key_id) = principal_key(principal) else {
        return Ok(policy::bucket_policy_allows(
            action,
            public_read,
            public_list,
        ));
    };
    let store = store::store_for(config).await?;
    let (docs, key_policy, service) = store.policies_for_key(access_key_id).await?;
    let ctx = policy::EvalContext {
        action,
        resource,
        prefix,
    };
    let key = if service { None } else { key_policy.as_ref() };
    Ok(policy::is_allowed(
        &docs,
        key,
        &ctx,
        public_read,
        public_list,
    ))
}

pub async fn bucket_visible(
    config: &Config,
    principal: &Principal,
    bucket: &str,
) -> Result<bool, store::IamError> {
    if principal.is_root() {
        return Ok(true);
    }
    if identity_allows(
        config,
        principal,
        "s3:ListAllMyBuckets",
        "*",
        None,
        false,
        false,
    )
    .await?
    {
        return Ok(true);
    }
    let Some(access_key_id) = principal_key(principal) else {
        return Ok(false);
    };
    let store = store::store_for(config).await?;
    let (docs, key_policy, service) = store.policies_for_key(access_key_id).await?;
    let key = if service { None } else { key_policy.as_ref() };
    Ok(policy::bucket_visible(&docs, key, bucket))
}

/// What the web console should offer for this principal.
///
/// `bucket` and `prefix` scope object writes and deletes. `create_bucket` is
/// independent of the current bucket. Root can do all of them.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleCapabilities {
    pub create_bucket: bool,
    pub delete_bucket: bool,
    pub put_object: bool,
    pub delete_object: bool,
}

pub async fn console_capabilities(
    config: &Config,
    principal: &Principal,
    bucket: Option<&str>,
    prefix: Option<&str>,
) -> Result<ConsoleCapabilities, store::IamError> {
    if principal.is_root() {
        let in_bucket = bucket.is_some();
        return Ok(ConsoleCapabilities {
            create_bucket: true,
            delete_bucket: in_bucket,
            put_object: in_bucket,
            delete_object: in_bucket,
        });
    }
    let create_bucket = identity_allows(
        config,
        principal,
        "s3:CreateBucket",
        "*",
        None,
        false,
        false,
    )
    .await?
        || identity_allows(
            config,
            principal,
            "s3:CreateBucket",
            "arn:aws:s3:::new-bucket",
            None,
            false,
            false,
        )
        .await?;
    let Some(bucket) = bucket else {
        return Ok(ConsoleCapabilities {
            create_bucket,
            delete_bucket: false,
            put_object: false,
            delete_object: false,
        });
    };
    let prefix = prefix.unwrap_or("");
    let probe = if prefix.is_empty() {
        "object".to_string()
    } else if prefix.ends_with('/') {
        format!("{prefix}object")
    } else {
        format!("{prefix}/object")
    };
    let object = policy::object_arn(bucket, &probe);
    let bucket_arn = policy::bucket_arn(bucket);
    Ok(ConsoleCapabilities {
        create_bucket,
        delete_bucket: identity_allows(
            config,
            principal,
            "s3:DeleteBucket",
            &bucket_arn,
            None,
            false,
            false,
        )
        .await?,
        put_object: identity_allows(
            config,
            principal,
            "s3:PutObject",
            &object,
            None,
            false,
            false,
        )
        .await?,
        delete_object: identity_allows(
            config,
            principal,
            "s3:DeleteObject",
            &object,
            None,
            false,
            false,
        )
        .await?,
    })
}

pub async fn is_iam_admin(config: &Config, principal: &Principal) -> Result<bool, store::IamError> {
    if principal.is_root() {
        return Ok(true);
    }
    const ACTIONS: &[&str] = &[
        "iam:ListUsers",
        "iam:CreateUser",
        "iam:ListPolicies",
        "iam:CreatePolicy",
        "iam:CreateAccessKey",
        "iam:ListAccessKeys",
    ];
    for action in ACTIONS {
        if identity_allows(config, principal, action, "*", None, false, false).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn principal_key(principal: &Principal) -> Option<&str> {
    match principal {
        Principal::User { access_key_id, .. } | Principal::Service { access_key_id, .. } => {
            Some(access_key_id)
        }
        Principal::Root | Principal::Anonymous => None,
    }
}

pub async fn console_from_token(config: &Config, token: &str) -> Result<ConsoleIdentity, ()> {
    let parsed = session::parse_token(token).ok_or(())?;
    let now = chrono::Utc::now().timestamp();
    if !session::token_is_fresh(parsed.issued_at, now) {
        return Err(());
    }
    if parsed.legacy_root
        || parsed
            .access_key_id
            .as_deref()
            .is_some_and(|id| id == config.access_key)
    {
        if session::token_signature_ok(&parsed, &config.access_key, &config.secret_key) {
            return Ok(root_identity(&config.access_key));
        }
        return Err(());
    }
    let access_key_id = parsed.access_key_id.clone().ok_or(())?;
    let store = store::store_for(config).await.map_err(|_| ())?;
    let key = store.lookup_key(&access_key_id).await.ok_or(())?;
    if key.status != KeyStatus::Active || !key.user_enabled {
        return Err(());
    }
    if !session::token_signature_ok(&parsed, &access_key_id, &key.secret) {
        return Err(());
    }
    identity_from_key(config, &access_key_id, &key).await
}

#[derive(Debug)]
pub enum LoginError {
    Invalid,
    Disabled,
}

pub async fn issue_session_token(
    config: &Config,
    identity: &ConsoleIdentity,
) -> Result<String, ()> {
    let secret = if identity.authenticated.principal.is_root() {
        config.secret_key.clone()
    } else {
        let store = store::store_for(config).await.map_err(|_| ())?;
        store
            .lookup_key(&identity.access_key_id)
            .await
            .ok_or(())?
            .secret
    };
    let now = chrono::Utc::now().timestamp();
    Ok(session::issue_token(&identity.access_key_id, &secret, now))
}

pub async fn login(
    config: &Config,
    access_key: &str,
    secret: &str,
) -> Result<ConsoleIdentity, LoginError> {
    if crate::auth::signature_v4::constant_time_eq(
        access_key.as_bytes(),
        config.access_key.as_bytes(),
    ) {
        if crate::auth::signature_v4::constant_time_eq(
            secret.as_bytes(),
            config.secret_key.as_bytes(),
        ) {
            return Ok(root_identity(access_key));
        }
        return Err(LoginError::Invalid);
    }
    let store = store::store_for(config)
        .await
        .map_err(|_| LoginError::Invalid)?;
    let Some(key) = store.lookup_key(access_key).await else {
        return Err(LoginError::Invalid);
    };
    if !crate::auth::signature_v4::constant_time_eq(secret.as_bytes(), key.secret.as_bytes()) {
        return Err(LoginError::Invalid);
    }
    if key.status != KeyStatus::Active || !key.user_enabled {
        return Err(LoginError::Disabled);
    }
    identity_from_key(config, access_key, &key)
        .await
        .map_err(|_| LoginError::Invalid)
}

fn root_identity(access_key_id: &str) -> ConsoleIdentity {
    ConsoleIdentity {
        authenticated: Authenticated {
            principal: Principal::Root,
        },
        iam_admin: true,
        access_key_id: access_key_id.to_string(),
        kind: "root",
        user_name: None,
        label: None,
    }
}

async fn identity_from_key(
    config: &Config,
    access_key_id: &str,
    key: &store::KeyAuth,
) -> Result<ConsoleIdentity, ()> {
    let (principal, kind, user_name, label) = match &key.user_name {
        Some(name) => (
            Principal::User {
                name: name.clone(),
                access_key_id: access_key_id.to_string(),
            },
            "user",
            Some(name.clone()),
            None,
        ),
        None => (
            Principal::Service {
                label: key.label.clone(),
                access_key_id: access_key_id.to_string(),
            },
            "service",
            None,
            Some(key.label.clone()),
        ),
    };
    let iam_admin = is_iam_admin(config, &principal).await.unwrap_or(false);
    Ok(ConsoleIdentity {
        authenticated: Authenticated { principal },
        iam_admin,
        access_key_id: access_key_id.to_string(),
        kind,
        user_name,
        label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config(data_dir: &str) -> Config {
        Config {
            port: 0,
            address: "127.0.0.1".into(),
            data_dir: data_dir.into(),
            access_key: "root".into(),
            secret_key: "root".into(),
            region: "us-east-1".into(),
            master_key: None,
            allow_insecure_dev: true,
            secure_cookies: false,
            erasure_coding: false,
            chunk_size: 1024,
            parity_shards: 0,
            default_buckets: String::new(),
            max_console_body_bytes: 1024,
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn readonly_prefix_cannot_create_write_or_delete() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path().to_str().unwrap());
        let store = store::store_for(&config).await.unwrap();
        store.create_user("alice").await.unwrap();
        let document =
            policy::policy_for_scope(&["photos".into()], "uploads/", policy::ScopeAccess::Read);
        store
            .put_inline_policy("alice", "scope", document)
            .await
            .unwrap();
        let key = store.create_access_key("alice", None).await.unwrap();
        let principal = Principal::User {
            name: "alice".into(),
            access_key_id: key.info.access_key_id,
        };
        let caps = console_capabilities(&config, &principal, Some("photos"), Some("uploads/"))
            .await
            .unwrap();
        assert!(!caps.create_bucket);
        assert!(!caps.delete_bucket);
        assert!(!caps.put_object);
        assert!(!caps.delete_object);

        let document = policy::policy_for_scope(
            &["photos".into()],
            "uploads/",
            policy::ScopeAccess::ReadWrite,
        );
        store
            .put_inline_policy("alice", "scope", document)
            .await
            .unwrap();
        let caps = console_capabilities(&config, &principal, Some("photos"), Some("uploads/"))
            .await
            .unwrap();
        assert!(caps.put_object);
        assert!(caps.delete_object);
        assert!(!caps.create_bucket);
    }
}
