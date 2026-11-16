//! SPEC §9: service-account tokens (`ov_sa_…`) and refresh tokens (`ov_rt_…`), and the hashes the
//! server stores for them.
//!
//! Port of `packages/sdk/src/crypto/tokens.ts`.

use ov_error::{OvError, OvErrorCode};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::encoding::{b64u, from_b64u, to_hex};
use crate::envelope::{aad, unwrap, wrap, wrap_with_nonce};
use crate::primitives::{random_array, sha256, NONCE_BYTES};

/// The service-account token prefix.
pub const SA_TOKEN_PREFIX: &str = "ov_sa_";
/// The refresh token prefix.
pub const REFRESH_TOKEN_PREFIX: &str = "ov_rt_";

fn invalid(msg: impl Into<String>) -> OvError {
    OvError::new(OvErrorCode::InvalidToken, msg)
}

/// The token JSON, in the SPEC's key order so tokens are reproducible.
#[derive(Serialize)]
struct SaTokenPayload<'a> {
    v: u8,
    url: &'a str,
    sa_id: &'a str,
    secret: &'a str,
    kek: &'a str,
}

/// Builds `ov_sa_` + base64url(UTF-8 JSON `{"v":1,"url","sa_id","secret","kek"}`).
pub fn build_sa_token(url: &str, sa_id: &str, secret: &[u8; 32], kek: &[u8; 32]) -> Zeroizing<String> {
    let secret = Zeroizing::new(b64u(secret));
    let kek = Zeroizing::new(b64u(kek));
    let payload = SaTokenPayload { v: 1, url, sa_id, secret: &secret, kek: &kek };
    // Serializing a struct of strings can't fail.
    let json = Zeroizing::new(serde_json::to_vec(&payload).unwrap_or_default());
    let mut token = Zeroizing::new(String::with_capacity(SA_TOKEN_PREFIX.len() + json.len() * 4 / 3 + 4));
    token.push_str(SA_TOKEN_PREFIX);
    token.push_str(&Zeroizing::new(b64u(&json)));
    token
}

/// A parsed service-account token. The secrets wipe themselves on drop.
pub struct ParsedSaToken {
    /// The issuer URL.
    pub url: String,
    /// The service account's uuid.
    pub sa_id: String,
    /// The secret the server checks (`SHA-256(secret)` hex is stored).
    pub secret: Zeroizing<[u8; 32]>,
    /// The key that unwraps the SA master key.
    pub kek: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ParsedSaToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedSaToken")
            .field("url", &self.url)
            .field("sa_id", &self.sa_id)
            .field("secret", &"[redacted]")
            .field("kek", &"[redacted]")
            .finish()
    }
}

/// Parses a service-account token (surrounding whitespace is ignored).
///
/// Fails with [`OvErrorCode::InvalidToken`] for a missing prefix, malformed base64url or JSON, a
/// version other than 1, missing fields, or keys that aren't 32 bytes.
pub fn parse_sa_token(token: &str) -> Result<ParsedSaToken, OvError> {
    let t = token.trim();
    let body = t.strip_prefix(SA_TOKEN_PREFIX).ok_or_else(|| invalid("not a service account token (ov_sa_…)"))?;
    let json = Zeroizing::new(from_b64u(body).map_err(|_| invalid("malformed service account token"))?);
    let p: serde_json::Value = serde_json::from_slice(&json).map_err(|_| invalid("malformed service account token"))?;
    let obj = p.as_object().ok_or_else(|| invalid("malformed service account token"))?;
    let v = obj.get("v");
    if v.and_then(serde_json::Value::as_f64) != Some(1.0) {
        let shown = v.map_or_else(|| "undefined".to_owned(), ToString::to_string);
        return Err(invalid(format!("unsupported service account token version {shown}")));
    }
    let s = |k: &str| obj.get(k).and_then(serde_json::Value::as_str);
    let (Some(url), Some(sa_id), Some(secret), Some(kek)) = (s("url"), s("sa_id"), s("secret"), s("kek")) else {
        return Err(invalid("service account token is missing fields"));
    };
    let key = |b: &str| -> Result<Zeroizing<[u8; 32]>, OvError> {
        let v = Zeroizing::new(from_b64u(b).map_err(|_| invalid("malformed service account token"))?);
        let mut k = Zeroizing::new([0u8; 32]);
        if v.len() != 32 {
            return Err(invalid("service account token keys must be 32 bytes"));
        }
        k.copy_from_slice(&v);
        Ok(k)
    };
    let secret = key(secret)?;
    let kek = key(kek)?;
    Ok(ParsedSaToken { url: url.to_owned(), sa_id: sa_id.to_owned(), secret, kek })
}

/// What the server stores for an SA secret: hex SHA-256 of the 32 raw bytes.
pub fn sa_secret_hash(secret: &[u8; 32]) -> String {
    to_hex(&sha256(secret))
}

/// The first 8 characters of the base64url secret, shown in UIs to tell secrets apart.
pub fn sa_secret_prefix(secret: &[u8; 32]) -> String {
    let full = Zeroizing::new(b64u(secret));
    full[..8].to_owned()
}

/// `wrap(kek, master, "ov-sa-master-v1|<sa>")` as base64url (the per-secret `wrapped_master`).
pub fn wrap_sa_master(kek: &[u8; 32], sa_id: &str, master: &[u8; 32]) -> Result<String, OvError> {
    Ok(b64u(&wrap(kek, master, &aad::sa_master(sa_id))?))
}

/// [`wrap_sa_master`] with a fixed nonce (test vectors only).
pub fn wrap_sa_master_with_nonce(kek: &[u8; 32], sa_id: &str, master: &[u8; 32], nonce: &[u8; NONCE_BYTES]) -> String {
    b64u(&wrap_with_nonce(kek, master, &aad::sa_master(sa_id), nonce))
}

/// Unwraps the SA master key with the token's `kek`. Fails with `decryption_failed` for the wrong
/// key, SA id or data (or a plaintext that isn't 32 bytes), `unsupported_version` for an unknown
/// envelope version.
pub fn unwrap_sa_master(kek: &[u8; 32], sa_id: &str, wrapped: &str) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let blob = from_b64u(wrapped)
        .map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "wrapped master key is not valid base64url"))?;
    let plain = unwrap(kek, &blob, &aad::sa_master(sa_id))?;
    if plain.len() != 32 {
        return Err(OvError::new(OvErrorCode::DecryptionFailed, "an SA master key must be 32 bytes"));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&plain);
    Ok(k)
}

/// What the server stores for a refresh token: hex SHA-256 of the UTF-8 token.
pub fn refresh_token_hash(token: &str) -> String {
    to_hex(&sha256(token.as_bytes()))
}

/// A new refresh token: `ov_rt_` + base64url(32 random bytes).
pub fn new_refresh_token() -> Result<Zeroizing<String>, OvError> {
    let raw = random_array::<32>()?;
    let mut t = Zeroizing::new(String::from(REFRESH_TOKEN_PREFIX));
    t.push_str(&Zeroizing::new(b64u(raw.as_ref())));
    Ok(t)
}

/// The `NewSaSecret` request body of `openapi.yaml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NewSaSecretBody {
    /// The secret's id (client-chosen uuid).
    pub id: String,
    /// An optional display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// [`sa_secret_hash`] of the secret.
    pub secret_hash: String,
    /// [`sa_secret_prefix`] of the secret.
    pub prefix: String,
    /// [`wrap_sa_master`] under the token's `kek`.
    pub wrapped_master: String,
    /// RFC 3339 expiry, or `null` for none.
    pub expires_at: Option<String>,
}

/// A new SA secret: the token to show once, and the body for the server.
pub struct NewSaSecret {
    /// The `ov_sa_…` token. Show it once; it is the only copy of the secret and `kek`.
    pub token: Zeroizing<String>,
    /// The body for `POST /service-accounts/{sa}/secrets`.
    pub body: NewSaSecretBody,
}

impl std::fmt::Debug for NewSaSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSaSecret").field("token", &"[redacted]").field("body", &self.body).finish()
    }
}

/// Creates a new SA secret and `kek` for the SA master key `master` (unsealed by an owner/admin).
pub fn new_sa_secret(
    url: &str,
    sa_id: &str,
    master: &[u8; 32],
    secret_id: &str,
    name: Option<&str>,
    expires_at: Option<&str>,
) -> Result<NewSaSecret, OvError> {
    let secret = random_array::<32>()?;
    let kek = random_array::<32>()?;
    let token = build_sa_token(url, sa_id, &secret, &kek);
    let body = NewSaSecretBody {
        id: secret_id.to_owned(),
        name: name.map(str::to_owned),
        secret_hash: sa_secret_hash(&secret),
        prefix: sa_secret_prefix(&secret),
        wrapped_master: wrap_sa_master(&kek, sa_id, master)?,
        expires_at: expires_at.map(str::to_owned),
    };
    Ok(NewSaSecret { token, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_tokens() {
        assert!(parse_sa_token("ov_rt_abc").unwrap_err().is(OvErrorCode::InvalidToken));
        assert!(parse_sa_token("ov_sa_!!").unwrap_err().is(OvErrorCode::InvalidToken));
        let v2 = format!("ov_sa_{}", b64u(br#"{"v":2,"url":"u","sa_id":"s","secret":"","kek":""}"#));
        assert!(parse_sa_token(&v2).unwrap_err().message.contains("version 2"));
        let missing = format!("ov_sa_{}", b64u(br#"{"v":1,"url":"u"}"#));
        assert!(parse_sa_token(&missing).unwrap_err().message.contains("missing"));
        let short = format!("ov_sa_{}", b64u(br#"{"v":1,"url":"u","sa_id":"s","secret":"AQI","kek":"AQI"}"#));
        assert!(parse_sa_token(&short).unwrap_err().message.contains("32 bytes"));
    }

    #[test]
    fn new_sa_secret_unwraps_the_master_key() {
        let master = [8u8; 32];
        let s = new_sa_secret("https://x", "sa1", &master, "s1", None, None).unwrap();
        let p = parse_sa_token(&s.token).unwrap();
        assert_eq!(s.body.secret_hash, sa_secret_hash(&p.secret));
        assert_eq!(s.body.prefix.len(), 8);
        assert_eq!(*unwrap_sa_master(&p.kek, "sa1", &s.body.wrapped_master).unwrap(), master);
        let json = serde_json::to_string(&s.body).unwrap();
        assert!(json.contains(r#""expires_at":null"#) && !json.contains("name"));
        assert!(!format!("{s:?}").contains(s.token.as_str()));
    }

    #[test]
    fn refresh_tokens() {
        let t = new_refresh_token().unwrap();
        assert!(t.starts_with(REFRESH_TOKEN_PREFIX));
        assert_eq!(from_b64u(&t[REFRESH_TOKEN_PREFIX.len()..]).unwrap().len(), 32);
    }
}
