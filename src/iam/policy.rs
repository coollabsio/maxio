//! AWS IAM policy documents and evaluation.
//!
//! Explicit `Deny` wins over `Allow`. No matching statement is an implicit deny.
//! Action names are case-insensitive; resource ARNs are case-sensitive.
//! `*` and `?` wildcards follow IAM. A per-key policy, when present, is an
//! intersection: both the user policies and the key policy must allow, and a
//! deny in either one denies.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const POLICY_VERSION: &str = "2012-10-17";
/// AWS-compatible document size cap (bytes of canonical JSON).
pub const POLICY_MAX_BYTES: usize = 6144;
const MAX_STATEMENTS: usize = 32;
const MAX_PATTERN_CHARS: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectDecision {
    Allow,
    ExplicitDeny,
    ImplicitDeny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    pub fn values(&self) -> Vec<&str> {
        match self {
            Self::One(s) => vec![s.as_str()],
            Self::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.values().iter().all(|s| s.is_empty())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Condition {
    #[serde(
        rename = "StringEquals",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub string_equals: Option<BTreeMap<String, StringOrList>>,
    #[serde(
        rename = "StringLike",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub string_like: Option<BTreeMap<String, StringOrList>>,
    #[serde(
        rename = "StringNotEquals",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub string_not_equals: Option<BTreeMap<String, StringOrList>>,
    #[serde(
        rename = "StringNotLike",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub string_not_like: Option<BTreeMap<String, StringOrList>>,
    /// An operator this server does not evaluate. Allow statements with this set
    /// never match; Deny statements match on action and resource alone.
    #[serde(default, skip)]
    pub unsupported: bool,
}

impl Condition {
    fn is_empty(&self) -> bool {
        self.string_equals.is_none()
            && self.string_like.is_none()
            && self.string_not_equals.is_none()
            && self.string_not_like.is_none()
            && !self.unsupported
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "Sid", default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "Effect")]
    pub effect: Effect,
    #[serde(rename = "Action", default, skip_serializing_if = "Option::is_none")]
    pub action: Option<StringOrList>,
    #[serde(rename = "NotAction", default, skip_serializing_if = "Option::is_none")]
    pub not_action: Option<StringOrList>,
    #[serde(rename = "Resource", default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<StringOrList>,
    #[serde(
        rename = "NotResource",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub not_resource: Option<StringOrList>,
    #[serde(
        rename = "Condition",
        default,
        skip_serializing_if = "Condition::is_empty"
    )]
    pub condition: Condition,
    /// Identity policies ignore `Principal`. Accepted so copied documents still parse.
    #[serde(rename = "Principal", default, skip_serializing)]
    #[allow(dead_code)]
    pub principal: Option<Value>,
    #[serde(rename = "NotPrincipal", default, skip_serializing)]
    #[allow(dead_code)]
    pub not_principal: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Statements {
    One(Statement),
    Many(Vec<Statement>),
}

impl Statements {
    fn iter(&self) -> Vec<&Statement> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v.iter().collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    #[serde(rename = "Version", default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "Statement")]
    pub statement: Statements,
}

impl PolicyDocument {
    pub fn statements(&self) -> Vec<&Statement> {
        self.statement.iter()
    }

    pub fn to_canonical_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }
}

/// Request context for one authorization check.
pub struct EvalContext<'a> {
    pub action: &'a str,
    pub resource: &'a str,
    /// `Some` for list operations (`s3:prefix`). `None` when the request has no prefix.
    pub prefix: Option<&'a str>,
}

pub fn parse_policy(value: &Value) -> Result<PolicyDocument, String> {
    let doc = mark_unsupported(value)?;
    validate_policy(&doc)?;
    Ok(doc)
}

pub fn parse_policy_str(text: &str) -> Result<PolicyDocument, String> {
    if text.len() > POLICY_MAX_BYTES {
        return Err(format!("policy document exceeds {POLICY_MAX_BYTES} bytes"));
    }
    let value: Value = serde_json::from_str(text).map_err(|e| format!("malformed policy: {e}"))?;
    parse_policy(&value)
}

fn mark_unsupported(value: &Value) -> Result<PolicyDocument, String> {
    let mut doc: PolicyDocument =
        serde_json::from_value(value.clone()).map_err(|e| format!("malformed policy: {e}"))?;
    let statements = match value.get("Statement").or_else(|| value.get("statement")) {
        Some(Value::Array(items)) => items.clone(),
        Some(other @ Value::Object(_)) => vec![other.clone()],
        _ => {
            return Err("policy Statement must be an object or an array".into());
        }
    };
    let stmts: Vec<&mut Statement> = match &mut doc.statement {
        Statements::One(s) => vec![s],
        Statements::Many(v) => v.iter_mut().collect(),
    };
    if stmts.len() != statements.len() {
        return Err("policy Statement could not be parsed".into());
    }
    for (stmt, raw) in stmts.into_iter().zip(statements.iter()) {
        if let Some(cond) = raw.get("Condition").filter(|c| !c.is_null()) {
            let obj = cond
                .as_object()
                .ok_or_else(|| "Condition must be an object".to_string())?;
            for key in obj.keys() {
                if !matches!(
                    key.as_str(),
                    "StringEquals" | "StringLike" | "StringNotEquals" | "StringNotLike"
                ) {
                    stmt.condition.unsupported = true;
                }
            }
        }
    }
    Ok(doc)
}

pub fn validate_policy(doc: &PolicyDocument) -> Result<(), String> {
    let json = doc
        .to_canonical_json()
        .map_err(|e| format!("malformed policy: {e}"))?;
    if json.len() > POLICY_MAX_BYTES {
        return Err(format!("policy document exceeds {POLICY_MAX_BYTES} bytes"));
    }
    let stmts = doc.statements();
    if stmts.is_empty() {
        return Err("policy must contain at least one statement".into());
    }
    if stmts.len() > MAX_STATEMENTS {
        return Err(format!("policy exceeds {MAX_STATEMENTS} statements"));
    }
    for stmt in stmts {
        if stmt.action.is_some() && stmt.not_action.is_some() {
            return Err("a statement cannot set both Action and NotAction".into());
        }
        if stmt.action.is_none() && stmt.not_action.is_none() {
            return Err("a statement needs Action or NotAction".into());
        }
        if stmt.resource.is_some() && stmt.not_resource.is_some() {
            return Err("a statement cannot set both Resource and NotResource".into());
        }
        if stmt.resource.is_none() && stmt.not_resource.is_none() {
            return Err("a statement needs Resource or NotResource".into());
        }
        for list in [
            &stmt.action,
            &stmt.not_action,
            &stmt.resource,
            &stmt.not_resource,
        ]
        .into_iter()
        .flatten()
        {
            if list.is_empty() {
                return Err("action and resource lists cannot be empty".into());
            }
            for value in list.values() {
                if value.chars().count() > MAX_PATTERN_CHARS {
                    return Err("action or resource value is too long".into());
                }
            }
        }
    }
    Ok(())
}

pub fn evaluate(docs: &[PolicyDocument], ctx: &EvalContext<'_>) -> EffectDecision {
    let mut allow = false;
    for doc in docs {
        for stmt in doc.statements() {
            if !statement_matches(stmt, ctx) {
                continue;
            }
            if stmt.effect == Effect::Deny {
                return EffectDecision::ExplicitDeny;
            }
            allow = true;
        }
    }
    if allow {
        EffectDecision::Allow
    } else {
        EffectDecision::ImplicitDeny
    }
}

/// A key policy narrows the user policy. Neither side may deny, and both must allow.
#[allow(dead_code)]
pub fn intersect(user: EffectDecision, key: Option<EffectDecision>) -> EffectDecision {
    if user == EffectDecision::ExplicitDeny {
        return EffectDecision::ExplicitDeny;
    }
    let Some(key) = key else {
        return user;
    };
    if key == EffectDecision::ExplicitDeny {
        return EffectDecision::ExplicitDeny;
    }
    if user == EffectDecision::Allow && key == EffectDecision::Allow {
        EffectDecision::Allow
    } else {
        EffectDecision::ImplicitDeny
    }
}

fn statement_matches(stmt: &Statement, ctx: &EvalContext<'_>) -> bool {
    if stmt.condition.unsupported {
        if stmt.effect == Effect::Allow {
            return false;
        }
        return action_matches(stmt, ctx.action) && resource_matches(stmt, ctx.resource);
    }
    action_matches(stmt, ctx.action)
        && resource_matches(stmt, ctx.resource)
        && condition_matches(&stmt.condition, ctx)
}

fn action_matches(stmt: &Statement, action: &str) -> bool {
    if let Some(list) = &stmt.action {
        return list
            .values()
            .iter()
            .any(|pattern| wildcard_match(pattern, action, true));
    }
    if let Some(list) = &stmt.not_action {
        return list
            .values()
            .iter()
            .all(|pattern| !wildcard_match(pattern, action, true));
    }
    false
}

fn resource_matches(stmt: &Statement, resource: &str) -> bool {
    if let Some(list) = &stmt.resource {
        return list
            .values()
            .iter()
            .any(|pattern| wildcard_match(pattern, resource, false));
    }
    if let Some(list) = &stmt.not_resource {
        return list
            .values()
            .iter()
            .all(|pattern| !wildcard_match(pattern, resource, false));
    }
    false
}

fn condition_matches(cond: &Condition, ctx: &EvalContext<'_>) -> bool {
    if let Some(map) = &cond.string_equals {
        for (key, values) in map {
            let Some(actual) = context_value(key, ctx) else {
                return false;
            };
            if !values.values().contains(&actual) {
                return false;
            }
        }
    }
    if let Some(map) = &cond.string_like {
        for (key, values) in map {
            let Some(actual) = context_value(key, ctx) else {
                return false;
            };
            if !values
                .values()
                .iter()
                .any(|pattern| wildcard_match(pattern, actual, false))
            {
                return false;
            }
        }
    }
    if let Some(map) = &cond.string_not_equals {
        for (key, values) in map {
            let Some(actual) = context_value(key, ctx) else {
                return false;
            };
            if values.values().contains(&actual) {
                return false;
            }
        }
    }
    if let Some(map) = &cond.string_not_like {
        for (key, values) in map {
            let Some(actual) = context_value(key, ctx) else {
                return false;
            };
            if values
                .values()
                .iter()
                .any(|pattern| wildcard_match(pattern, actual, false))
            {
                return false;
            }
        }
    }
    true
}

fn context_value<'a>(key: &str, ctx: &'a EvalContext<'a>) -> Option<&'a str> {
    if key.eq_ignore_ascii_case("s3:prefix") {
        ctx.prefix
    } else {
        None
    }
}

pub fn wildcard_match(pattern: &str, value: &str, ignore_case: bool) -> bool {
    let pattern: Vec<char> = normalize(pattern, ignore_case);
    let value: Vec<char> = normalize(value, ignore_case);
    if pattern.len() > MAX_PATTERN_CHARS || value.len() > MAX_PATTERN_CHARS {
        return false;
    }
    let n = pattern.len();
    let m = value.len();
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[n][m] = true;
    for i in (0..n).rev() {
        if pattern[i] == '*' {
            dp[i][m] = dp[i + 1][m];
        }
    }
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            if pattern[i] == '*' {
                dp[i][j] = dp[i + 1][j] || dp[i][j + 1];
            } else if pattern[i] == '?' || pattern[i] == value[j] {
                dp[i][j] = dp[i + 1][j + 1];
            }
        }
    }
    dp[0][0]
}

fn normalize(text: &str, ignore_case: bool) -> Vec<char> {
    if ignore_case {
        text.chars().flat_map(|c| c.to_lowercase()).collect()
    } else {
        text.chars().collect()
    }
}

pub fn bucket_arn(bucket: &str) -> String {
    format!("arn:aws:s3:::{bucket}")
}

pub fn object_arn(bucket: &str, key: &str) -> String {
    format!("arn:aws:s3:::{bucket}/{key}")
}

/// `Allow` from an anonymous bucket policy (public read / list) fills an implicit deny.
/// An explicit identity deny still wins because the caller never reaches this on deny.
pub fn bucket_policy_allows(action: &str, public_read: bool, public_list: bool) -> bool {
    match action {
        "s3:GetObject" | "s3:GetObjectVersion" => public_read,
        "s3:ListBucket" => public_list,
        _ => false,
    }
}

fn policy_has_allow(doc: &PolicyDocument) -> bool {
    doc.statements()
        .iter()
        .any(|stmt| stmt.effect == Effect::Allow)
}

pub fn is_allowed(
    user_docs: &[PolicyDocument],
    key_policy: Option<&PolicyDocument>,
    ctx: &EvalContext<'_>,
    public_read: bool,
    public_list: bool,
) -> bool {
    let user = evaluate(user_docs, ctx);
    if user == EffectDecision::ExplicitDeny {
        return false;
    }
    if let Some(key) = key_policy {
        let key_decision = evaluate(std::slice::from_ref(key), ctx);
        if key_decision == EffectDecision::ExplicitDeny {
            return false;
        }
        // An allow in the key policy is a ceiling. A deny-only key policy only
        // subtracts; it does not require a second allow.
        if policy_has_allow(key) && key_decision != EffectDecision::Allow {
            return false;
        }
    }
    match user {
        EffectDecision::Allow => true,
        EffectDecision::ExplicitDeny => false,
        EffectDecision::ImplicitDeny => bucket_policy_allows(ctx.action, public_read, public_list),
    }
}

/// Whether the console should list this bucket for a non-root principal.
pub fn bucket_visible(
    user_docs: &[PolicyDocument],
    key_policy: Option<&PolicyDocument>,
    bucket: &str,
) -> bool {
    fn one(docs: &[PolicyDocument], bucket: &str) -> bool {
        let arn = bucket_arn(bucket);
        let prefixes = candidate_prefixes(docs, bucket);
        for prefix in &prefixes {
            if evaluate(
                docs,
                &EvalContext {
                    action: "s3:ListBucket",
                    resource: &arn,
                    prefix: Some(prefix),
                },
            ) == EffectDecision::Allow
            {
                return true;
            }
        }
        for key in probe_object_arns(bucket, &prefixes) {
            for action in ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:*"] {
                if evaluate(
                    docs,
                    &EvalContext {
                        action,
                        resource: &key,
                        prefix: None,
                    },
                ) == EffectDecision::Allow
                {
                    return true;
                }
            }
        }
        false
    }
    if !one(user_docs, bucket) {
        return false;
    }
    match key_policy {
        Some(policy) if policy_has_allow(policy) => one(std::slice::from_ref(policy), bucket),
        _ => true,
    }
}

fn candidate_prefixes(docs: &[PolicyDocument], bucket: &str) -> Vec<String> {
    let marker = format!("arn:aws:s3:::{bucket}/");
    let mut out = vec![String::new()];
    for doc in docs {
        for stmt in doc.statements() {
            if let Some(list) = &stmt.resource {
                for res in list.values() {
                    if let Some(rest) = res.strip_prefix(&marker) {
                        out.push(rest.trim_end_matches('*').trim_end_matches('/').to_string());
                    }
                }
            }
            for map in [&stmt.condition.string_like, &stmt.condition.string_equals]
                .into_iter()
                .flatten()
            {
                for (key, values) in map {
                    if key.eq_ignore_ascii_case("s3:prefix") {
                        for value in values.values() {
                            out.push(
                                value
                                    .trim_end_matches('*')
                                    .trim_end_matches('/')
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn probe_object_arns(bucket: &str, prefixes: &[String]) -> Vec<String> {
    let mut keys = vec![object_arn(bucket, "object")];
    for prefix in prefixes {
        if prefix.is_empty() {
            continue;
        }
        keys.push(object_arn(bucket, prefix));
        keys.push(object_arn(bucket, &format!("{prefix}/object")));
    }
    keys
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeAccess {
    Read,
    Write,
    ReadWrite,
    Admin,
}

impl ScopeAccess {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read" | "readonly" => Ok(Self::Read),
            "write" | "writeonly" => Ok(Self::Write),
            "readwrite" => Ok(Self::ReadWrite),
            "admin" => Ok(Self::Admin),
            _ => Err("access must be read, write, readwrite, or admin".into()),
        }
    }
}

const READ_BUCKET: &[&str] = &[
    "s3:ListBucket",
    "s3:ListBucketVersions",
    "s3:ListBucketMultipartUploads",
    "s3:GetBucketLocation",
];
const READ_OBJECT: &[&str] = &[
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:GetObjectAttributes",
    "s3:GetObjectTagging",
    "s3:GetObjectAcl",
    "s3:ListMultipartUploadParts",
];
const WRITE_OBJECT: &[&str] = &[
    "s3:PutObject",
    "s3:PutObjectTagging",
    "s3:PutObjectAcl",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:DeleteObjectTagging",
    "s3:AbortMultipartUpload",
];

/// Policy generated by the console scope picker.
///
/// An empty bucket list means every bucket. A prefix is a directory: `uploads`
/// and `uploads/` both become object ARN `arn:aws:s3:::bucket/uploads/*` and a
/// ListBucket `s3:prefix` condition of `uploads/` and `uploads/*`. The trailing
/// slash stays, so the scope does not also allow `uploads-private` or `uploadsX`.
pub fn policy_for_scope(buckets: &[String], prefix: &str, access: ScopeAccess) -> PolicyDocument {
    let prefix = normalize_scope_prefix(prefix);
    if buckets.is_empty() {
        return global_scope(access);
    }
    let mut statements = Vec::new();
    for bucket in buckets {
        let bucket_res = bucket_arn(bucket);
        let object_res = if prefix.is_empty() {
            format!("arn:aws:s3:::{bucket}/*")
        } else {
            format!("arn:aws:s3:::{bucket}/{prefix}*")
        };
        match access {
            ScopeAccess::Admin => {
                statements.push(stmt(
                    "Allow",
                    &["s3:*"],
                    &[bucket_res.as_str(), object_res.as_str()],
                    None,
                ));
            }
            ScopeAccess::Read | ScopeAccess::Write | ScopeAccess::ReadWrite => {
                let mut object_actions: Vec<&str> = Vec::new();
                let mut bucket_actions: Vec<&str> = Vec::new();
                if matches!(access, ScopeAccess::Read | ScopeAccess::ReadWrite) {
                    object_actions.extend_from_slice(READ_OBJECT);
                    bucket_actions.extend_from_slice(READ_BUCKET);
                }
                if matches!(access, ScopeAccess::Write | ScopeAccess::ReadWrite) {
                    object_actions.extend_from_slice(WRITE_OBJECT);
                    if !bucket_actions.contains(&"s3:ListBucket") {
                        bucket_actions
                            .extend_from_slice(&["s3:ListBucket", "s3:ListBucketMultipartUploads"]);
                    }
                }
                let condition = if prefix.is_empty() {
                    None
                } else {
                    Some(prefix_condition(&prefix))
                };
                statements.push(stmt(
                    "Allow",
                    &bucket_actions,
                    &[bucket_res.as_str()],
                    condition,
                ));
                statements.push(stmt("Allow", &object_actions, &[object_res.as_str()], None));
            }
        }
    }
    PolicyDocument {
        version: Some(POLICY_VERSION.into()),
        statement: Statements::Many(statements),
    }
}

fn global_scope(access: ScopeAccess) -> PolicyDocument {
    let actions: Vec<&str> = match access {
        ScopeAccess::Read => vec!["s3:Get*", "s3:List*"],
        ScopeAccess::Write => vec!["s3:PutObject*", "s3:DeleteObject*", "s3:Abort*"],
        ScopeAccess::ReadWrite => vec![
            "s3:Get*",
            "s3:List*",
            "s3:PutObject*",
            "s3:DeleteObject*",
            "s3:Abort*",
        ],
        ScopeAccess::Admin => vec!["s3:*", "iam:*"],
    };
    PolicyDocument {
        version: Some(POLICY_VERSION.into()),
        statement: Statements::One(stmt("Allow", &actions, &["*"], None)),
    }
}

/// `prefix` already ends with `/`. ListBucket is allowed for that directory and
/// for keys under it, and not for a sibling that merely shares the leading text.
fn prefix_condition(prefix: &str) -> Condition {
    let mut like = BTreeMap::new();
    like.insert(
        "s3:prefix".to_string(),
        StringOrList::Many(vec![prefix.to_string(), format!("{prefix}*")]),
    );
    Condition {
        string_like: Some(like),
        ..Condition::default()
    }
}

/// Directory prefix used in ARNs and `s3:prefix`. Empty means the whole bucket.
fn normalize_scope_prefix(prefix: &str) -> String {
    let mut prefix = prefix.trim().trim_start_matches('/').to_string();
    while prefix.ends_with('/') {
        prefix.pop();
    }
    if prefix.is_empty() {
        return String::new();
    }
    prefix.push('/');
    prefix
}

fn stmt(
    effect: &str,
    actions: &[&str],
    resources: &[&str],
    condition: Option<Condition>,
) -> Statement {
    let effect = if effect == "Deny" {
        Effect::Deny
    } else {
        Effect::Allow
    };
    let action = if actions.len() == 1 {
        StringOrList::One(actions[0].to_string())
    } else {
        StringOrList::Many(actions.iter().map(|s| (*s).to_string()).collect())
    };
    let resource = if resources.len() == 1 {
        StringOrList::One(resources[0].to_string())
    } else {
        StringOrList::Many(resources.iter().map(|s| (*s).to_string()).collect())
    };
    Statement {
        sid: None,
        effect,
        action: Some(action),
        not_action: None,
        resource: Some(resource),
        not_resource: None,
        condition: condition.unwrap_or_default(),
        principal: None,
        not_principal: None,
    }
}

/// One line for the console key table: the resources a key policy allows.
pub fn summarize_key_policy(doc: &PolicyDocument) -> String {
    let mut resources = Vec::new();
    for stmt in doc.statements() {
        if stmt.effect != Effect::Allow {
            continue;
        }
        let Some(list) = &stmt.resource else {
            continue;
        };
        for value in list.values() {
            if !resources.iter().any(|existing: &String| existing == value) {
                resources.push(value.to_string());
            }
        }
    }
    if resources.is_empty() {
        "Key policy (limits this key)".to_string()
    } else {
        format!("Key policy: {}", resources.join(", "))
    }
}

pub fn builtin_policies() -> Vec<(&'static str, &'static str, PolicyDocument)> {
    vec![
        (
            "readonly",
            "Read and list every bucket and object",
            global_scope(ScopeAccess::Read),
        ),
        (
            "readwrite",
            "Read and write objects without bucket administration",
            global_scope(ScopeAccess::ReadWrite),
        ),
        (
            "writeonly",
            "Upload and delete objects without read access",
            global_scope(ScopeAccess::Write),
        ),
        (
            "admin",
            "Full S3 and IAM administration",
            global_scope(ScopeAccess::Admin),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: &str) -> PolicyDocument {
        parse_policy_str(json).unwrap()
    }

    fn ctx<'a>(action: &'a str, resource: &'a str, prefix: Option<&'a str>) -> EvalContext<'a> {
        EvalContext {
            action,
            resource,
            prefix,
        }
    }

    #[test]
    fn allow_exact_action_and_resource() {
        let policy = doc(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::pics/a.txt"}}"#,
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:GetObject", "arn:aws:s3:::pics/a.txt", None)
            ),
            EffectDecision::Allow
        );
        assert_eq!(
            evaluate(
                &[policy],
                &ctx("s3:PutObject", "arn:aws:s3:::pics/a.txt", None)
            ),
            EffectDecision::ImplicitDeny
        );
    }

    #[test]
    fn explicit_deny_wins_over_allow() {
        let policy = doc(r#"{"Statement":[
                {"Effect":"Allow","Action":"s3:Get*","Resource":"*"},
                {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"}
            ]}"#);
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:GetObject", "arn:aws:s3:::pics/a", None)
            ),
            EffectDecision::Allow
        );
        assert_eq!(
            evaluate(
                &[policy],
                &ctx("s3:GetObject", "arn:aws:s3:::secret/a", None)
            ),
            EffectDecision::ExplicitDeny
        );
    }

    #[test]
    fn action_and_resource_wildcards() {
        let policy = doc(
            r#"{"Statement":{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":["arn:aws:s3:::pics","arn:aws:s3:::pics/albums*"]}}"#,
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:GetObject", "arn:aws:s3:::pics/albums/a.jpg", None)
            ),
            EffectDecision::Allow
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx(
                    "s3:GetObjectTagging",
                    "arn:aws:s3:::pics/albums/a.jpg",
                    None
                )
            ),
            EffectDecision::Allow
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:PutObject", "arn:aws:s3:::pics/albums/a.jpg", None)
            ),
            EffectDecision::ImplicitDeny
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:GetObject", "arn:aws:s3:::pics/other.jpg", None)
            ),
            EffectDecision::ImplicitDeny
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("S3:LISTBUCKET", "arn:aws:s3:::pics", Some("albums/"))
            ),
            EffectDecision::Allow
        );
    }

    #[test]
    fn prefix_condition_limits_list() {
        let policy = policy_for_scope(&["pics".into()], "albums", ScopeAccess::Read);
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx(
                    "s3:ListBucket",
                    "arn:aws:s3:::pics",
                    Some("albums/vacation")
                )
            ),
            EffectDecision::Allow
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:ListBucket", "arn:aws:s3:::pics", Some(""))
            ),
            EffectDecision::ImplicitDeny
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:ListBucket", "arn:aws:s3:::pics", Some("other"))
            ),
            EffectDecision::ImplicitDeny
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:GetObject", "arn:aws:s3:::pics/albums/a.jpg", None)
            ),
            EffectDecision::Allow
        );
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:GetObject", "arn:aws:s3:::pics/other.jpg", None)
            ),
            EffectDecision::ImplicitDeny
        );
    }

    #[test]
    fn key_policy_intersects_user_policy() {
        let user = doc(r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}"#);
        let key = policy_for_scope(&["pics".into()], "", ScopeAccess::Read);
        let allow = is_allowed(
            std::slice::from_ref(&user),
            Some(&key),
            &ctx("s3:GetObject", "arn:aws:s3:::pics/a", None),
            false,
            false,
        );
        let deny_write = is_allowed(
            std::slice::from_ref(&user),
            Some(&key),
            &ctx("s3:PutObject", "arn:aws:s3:::pics/a", None),
            false,
            false,
        );
        let deny_other = is_allowed(
            &[user],
            Some(&key),
            &ctx("s3:GetObject", "arn:aws:s3:::other/a", None),
            false,
            false,
        );
        assert!(allow);
        assert!(!deny_write);
        assert!(!deny_other);
    }

    #[test]
    fn deny_in_key_policy_blocks_user_allow() {
        let user = doc(r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}"#);
        let key =
            doc(r#"{"Statement":{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}}"#);
        assert!(!is_allowed(
            std::slice::from_ref(&user),
            Some(&key),
            &ctx("s3:DeleteObject", "arn:aws:s3:::pics/a", None),
            false,
            false,
        ));
        assert!(is_allowed(
            &[user],
            Some(&key),
            &ctx("s3:GetObject", "arn:aws:s3:::pics/a", None),
            false,
            false,
        ));
    }

    #[test]
    fn bucket_policy_allows_public_read_only_without_explicit_deny() {
        let empty: &[PolicyDocument] = &[];
        assert!(is_allowed(
            empty,
            None,
            &ctx("s3:GetObject", "arn:aws:s3:::pub/a", None),
            true,
            false,
        ));
        assert!(!is_allowed(
            empty,
            None,
            &ctx("s3:PutObject", "arn:aws:s3:::pub/a", None),
            true,
            true,
        ));
        let deny = doc(r#"{"Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}"#);
        assert!(!is_allowed(
            &[deny],
            None,
            &ctx("s3:GetObject", "arn:aws:s3:::pub/a", None),
            true,
            true,
        ));
    }

    #[test]
    fn unsupported_condition_fails_closed() {
        let policy = doc(
            r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"NumericLessThan":{"s3:max-keys":"10"}}}}"#,
        );
        assert!(policy.statements()[0].condition.unsupported);
        assert_eq!(
            evaluate(&[policy], &ctx("s3:GetObject", "arn:aws:s3:::b/k", None)),
            EffectDecision::ImplicitDeny
        );
    }

    #[test]
    fn not_action_excludes_listed_actions() {
        let policy =
            doc(r#"{"Statement":{"Effect":"Allow","NotAction":"s3:DeleteObject","Resource":"*"}}"#);
        assert_eq!(
            evaluate(
                std::slice::from_ref(&policy),
                &ctx("s3:GetObject", "*", None)
            ),
            EffectDecision::Allow
        );
        assert_eq!(
            evaluate(&[policy], &ctx("s3:DeleteObject", "*", None)),
            EffectDecision::ImplicitDeny
        );
    }

    #[test]
    fn scope_admin_all_buckets_includes_iam() {
        let policy = policy_for_scope(&[], "", ScopeAccess::Admin);
        assert_eq!(
            evaluate(&[policy], &ctx("iam:CreateUser", "*", None)),
            EffectDecision::Allow
        );
    }

    #[test]
    fn rejects_statement_without_resource() {
        let err = parse_policy_str(r#"{"Statement":{"Effect":"Allow","Action":"s3:*"}}"#);
        assert!(err.is_err());
    }

    #[test]
    fn wildcard_question_mark_and_star() {
        assert!(wildcard_match("s3:Get*", "s3:GetObject", true));
        assert!(wildcard_match("*", "anything", false));
        assert!(wildcard_match("a?c", "abc", false));
        assert!(!wildcard_match("a?c", "ac", false));
        assert!(wildcard_match(
            "arn:aws:s3:::b/pre*",
            "arn:aws:s3:::b/pre/a",
            false
        ));
        assert!(!wildcard_match(
            "arn:aws:s3:::b/pre*",
            "arn:aws:s3:::b/other",
            false
        ));
    }

    #[test]
    fn scope_prefix_keeps_the_directory_slash() {
        for raw in ["uploads/", "uploads", " uploads/ "] {
            let policy = policy_for_scope(&["photos".into()], raw, ScopeAccess::ReadWrite);
            let json = policy.to_canonical_json().unwrap();
            assert!(
                json.contains("arn:aws:s3:::photos/uploads/*"),
                "{raw} -> {json}"
            );
            assert!(
                !json.contains("arn:aws:s3:::photos/uploads*\""),
                "loose prefix in {json}"
            );
            let allow_inside = |action: &str, key: &str| {
                assert_eq!(
                    evaluate(
                        std::slice::from_ref(&policy),
                        &ctx(action, &object_arn("photos", key), None)
                    ),
                    EffectDecision::Allow,
                    "{action} {key} from {raw}"
                );
            };
            let deny = |action: &str, key: &str| {
                assert_eq!(
                    evaluate(
                        std::slice::from_ref(&policy),
                        &ctx(action, &object_arn("photos", key), None)
                    ),
                    EffectDecision::ImplicitDeny,
                    "{action} {key} from {raw}"
                );
            };
            allow_inside("s3:GetObject", "uploads/x.txt");
            allow_inside("s3:PutObject", "uploads/nested/x.txt");
            deny("s3:PutObject", "uploads-private/x.txt");
            deny("s3:PutObject", "uploadsX.txt");
            deny("s3:GetObject", "uploads-private/x.txt");
            deny("s3:GetObject", "uploadsX.txt");
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&policy),
                    &ctx("s3:ListBucket", "arn:aws:s3:::photos", Some("uploads/"))
                ),
                EffectDecision::Allow
            );
            assert_eq!(
                evaluate(
                    std::slice::from_ref(&policy),
                    &ctx(
                        "s3:ListBucket",
                        "arn:aws:s3:::photos",
                        Some("uploads/nested")
                    )
                ),
                EffectDecision::Allow
            );
            for blocked in ["", "uploads", "uploads-private/", "uploadsX"] {
                assert_eq!(
                    evaluate(
                        std::slice::from_ref(&policy),
                        &ctx("s3:ListBucket", "arn:aws:s3:::photos", Some(blocked))
                    ),
                    EffectDecision::ImplicitDeny,
                    "list {blocked:?} from {raw}"
                );
            }
        }
    }

    #[test]
    fn prefixed_bucket_is_visible_and_other_bucket_is_not() {
        let policy = policy_for_scope(&["pics".into()], "albums", ScopeAccess::Read);
        assert!(bucket_visible(std::slice::from_ref(&policy), None, "pics"));
        assert!(!bucket_visible(&[policy], None, "other"));
    }
}
