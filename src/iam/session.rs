//! Console session cookies.
//!
//! Legacy cookies are `{issued_hex}.{hmac}` keyed by the root secret (the
//! original console token). Current cookies are
//! `{base64url(access_key_id)}.{issued_hex}.{hmac}` so an IAM user's key can
//! be resolved and checked on every request.

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;

use signature_time::constant_time_eq;

type HmacSha256 = Hmac<Sha256>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub const TOKEN_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug)]
pub struct ParsedToken {
    pub access_key_id: Option<String>,
    pub issued_at: i64,
    /// Random per-login id. Absent on tokens issued before sessions were unique.
    pub nonce: Option<String>,
    signature: String,
    pub legacy_root: bool,
}

impl ParsedToken {
    /// Stable id stored when the session is revoked. Unique per login.
    pub fn revocation_id(&self) -> &str {
        self.nonce.as_deref().unwrap_or(self.signature.as_str())
    }
}

pub fn issue_token(access_key_id: &str, secret: &str, issued_at: i64) -> String {
    let mut raw = [0u8; 16];
    rand::rng().fill(&mut raw);
    let nonce = hex::encode(raw);
    let issued_hex = format!("{issued_at:x}");
    let sig = sign(secret, &format!("v2:{access_key_id}:{issued_hex}:{nonce}"));
    let id = B64.encode(access_key_id.as_bytes());
    format!("{id}.{issued_hex}.{nonce}.{sig}")
}

pub fn parse_token(token: &str) -> Option<ParsedToken> {
    let parts: Vec<&str> = token.split('.').collect();
    match parts.as_slice() {
        [issued_hex, signature] => {
            let issued_at = i64::from_str_radix(issued_hex, 16).ok()?;
            Some(ParsedToken {
                access_key_id: None,
                issued_at,
                nonce: None,
                signature: (*signature).to_string(),
                legacy_root: true,
            })
        }
        [id_b64, issued_hex, nonce, signature] => {
            let id = B64.decode(id_b64).ok()?;
            let access_key_id = String::from_utf8(id).ok()?;
            if access_key_id.is_empty() || nonce.is_empty() || nonce.contains('.') {
                return None;
            }
            let issued_at = i64::from_str_radix(issued_hex, 16).ok()?;
            Some(ParsedToken {
                access_key_id: Some(access_key_id),
                issued_at,
                nonce: Some((*nonce).to_string()),
                signature: (*signature).to_string(),
                legacy_root: false,
            })
        }
        [id_b64, issued_hex, signature] => {
            let id = B64.decode(id_b64).ok()?;
            let access_key_id = String::from_utf8(id).ok()?;
            if access_key_id.is_empty() {
                return None;
            }
            let issued_at = i64::from_str_radix(issued_hex, 16).ok()?;
            Some(ParsedToken {
                access_key_id: Some(access_key_id),
                issued_at,
                nonce: None,
                signature: (*signature).to_string(),
                legacy_root: false,
            })
        }
        _ => None,
    }
}

pub fn token_is_fresh(issued_at: i64, now: i64) -> bool {
    now - issued_at <= TOKEN_MAX_AGE_SECS && issued_at <= now + 60
}

pub fn token_signature_ok(token: &ParsedToken, access_key_id: &str, secret: &str) -> bool {
    let issued_hex = format!("{:x}", token.issued_at);
    let message = if token.legacy_root {
        format!("{access_key_id}:{issued_hex}")
    } else if let Some(nonce) = &token.nonce {
        format!("v2:{access_key_id}:{issued_hex}:{nonce}")
    } else {
        format!("v1:{access_key_id}:{issued_hex}")
    };
    let expected = sign(secret, &message);
    constant_time_eq(token.signature.as_bytes(), expected.as_bytes())
}

fn sign(secret: &str, message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Kept as a tiny local module so session tests do not depend on the HTTP stack.
pub mod signature_time {
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_iam_token() {
        let token = issue_token("MXIAEXAMPLEKEY0001", "mxsk_secret", 1_700_000_000);
        let parsed = parse_token(&token).unwrap();
        assert_eq!(parsed.access_key_id.as_deref(), Some("MXIAEXAMPLEKEY0001"));
        assert!(token_signature_ok(
            &parsed,
            "MXIAEXAMPLEKEY0001",
            "mxsk_secret"
        ));
        assert!(!token_signature_ok(&parsed, "MXIAEXAMPLEKEY0001", "other"));
        assert!(parsed.nonce.is_some());
    }

    #[test]
    fn two_tokens_in_the_same_second_are_different_sessions() {
        let a = issue_token("maxioadmin", "secret", 1_700_000_000);
        let b = issue_token("maxioadmin", "secret", 1_700_000_000);
        assert_ne!(a, b);
        let pa = parse_token(&a).unwrap();
        let pb = parse_token(&b).unwrap();
        assert_ne!(pa.revocation_id(), pb.revocation_id());
        assert!(token_signature_ok(&pa, "maxioadmin", "secret"));
        assert!(token_signature_ok(&pb, "maxioadmin", "secret"));
    }

    #[test]
    fn legacy_root_token_still_verifies() {
        let issued_at = 1_700_000_000_i64;
        let issued_hex = format!("{issued_at:x}");
        let signature = sign("root-secret", &format!("maxioadmin:{issued_hex}"));
        let token = format!("{issued_hex}.{signature}");
        let parsed = parse_token(&token).unwrap();
        assert!(parsed.legacy_root);
        assert!(token_signature_ok(&parsed, "maxioadmin", "root-secret"));
        assert!(token_is_fresh(issued_at, issued_at + 10));
        assert!(!token_is_fresh(
            issued_at,
            issued_at + TOKEN_MAX_AGE_SECS + 1
        ));
    }
}
