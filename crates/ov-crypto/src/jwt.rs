//! SPEC §9 access tokens (JWT). Clients only need [`decode_jwt`] (to read `exp` and `vlt`);
//! [`verify_jwt`] is the reference verifier (EdDSA only, `iss`/`aud`/`exp`/`nbf` with 60 s skew),
//! used by the test vectors and by `ov connect`-style servers.
//!
//! Port of `packages/sdk/src/crypto/jwt.ts`.

use std::collections::BTreeMap;

use ov_error::{OvError, OvErrorCode};
use serde::{Deserialize, Serialize};

use crate::curves::ed25519_verify;
use crate::encoding::from_b64u;

/// The clock skew verifiers allow on `exp` and `nbf` (seconds, SPEC §9).
pub const DEFAULT_SKEW_SECS: i64 = 60;

/// A vault grant in the `vlt` claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultClaim {
    /// Vault uuid.
    pub id: String,
    /// Role: `read`, `write` or `manage`.
    pub r: String,
    /// The vault's sync quota in bytes (SPEC §19), when the server sends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<u64>,
}

/// `aud` is an array in OpenVireo tokens, but JWT allows a single string too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// `"aud": "ov-sync"`.
    One(String),
    /// `"aud": ["ov-api", "ov-sync"]`.
    Many(Vec<String>),
}

impl Audience {
    /// Whether `aud` names `audience`.
    pub fn contains(&self, audience: &str) -> bool {
        match self {
            Audience::One(a) => a == audience,
            Audience::Many(v) => v.iter().any(|a| a == audience),
        }
    }
}

/// The access-token claims of SPEC §9. Unknown claims are kept in [`AccessClaims::extra`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Issuer URL.
    #[serde(default)]
    pub iss: String,
    /// Audience, `["ov-api","ov-sync"]`.
    pub aud: Option<Audience>,
    /// `user:<uuid>` or `sa:<uuid>`.
    #[serde(default)]
    pub sub: String,
    /// Device uuid (users only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    /// Owning org uuid (service accounts only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Every vault the principal can open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlt: Option<Vec<VaultClaim>>,
    /// RFC 3339 erase date on a pending-deletion account's token (SPEC §23).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub del: Option<String>,
    /// Issued at (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Not before (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Expiry (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Token id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Any other claims.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// A JWK from the issuer's JWKS (SPEC §9: `{"kty":"OKP","crv":"Ed25519","x","kid","use":"sig","alg":"EdDSA"}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type, `OKP`.
    pub kty: String,
    /// Curve, `Ed25519`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// base64url public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Key id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// `sig`.
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// `EdDSA`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// A JWK set (`/.well-known/jwks.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// The keys.
    pub keys: Vec<Jwk>,
}

/// A decoded (unverified) JWT.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedJwt {
    /// The JOSE header.
    pub header: serde_json::Map<String, serde_json::Value>,
    /// The claims.
    pub claims: AccessClaims,
}

impl DecodedJwt {
    /// The header's `kid`, if it is a string.
    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(serde_json::Value::as_str)
    }
}

/// Whether `token` has the three-part JWT shape (as opposed to an opaque token).
pub fn is_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

/// Decodes a JWT's header and claims **without verifying it**. Fails with
/// [`OvErrorCode::InvalidToken`] if it isn't a JWT or its parts aren't base64url JSON.
pub fn decode_jwt(token: &str) -> Result<DecodedJwt, OvError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(OvError::new(OvErrorCode::InvalidToken, "not a JWT"));
    }
    let malformed = || OvError::new(OvErrorCode::InvalidToken, "malformed JWT");
    let header = serde_json::from_slice(&from_b64u(parts[0]).map_err(|_| malformed())?).map_err(|_| malformed())?;
    let claims = serde_json::from_slice(&from_b64u(parts[1]).map_err(|_| malformed())?).map_err(|_| malformed())?;
    Ok(DecodedJwt { header, claims })
}

/// What [`verify_jwt`] checks the token against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyOptions {
    /// The expected `iss`.
    pub issuer: String,
    /// An audience `aud` must contain (the sync server needs `ov-sync`).
    pub audience: String,
    /// The current time (Unix seconds).
    pub now: i64,
    /// Allowed clock skew on `exp` and `nbf` ([`DEFAULT_SKEW_SECS`]).
    pub skew: i64,
}

fn unauthorized(msg: &str) -> OvError {
    OvError::new(OvErrorCode::Unauthorized, msg).with_status(401)
}

/// The JWKS key matching the token header's `kid` (OKP / Ed25519 / EdDSA only).
pub fn find_jwk<'a>(jwks: &'a Jwks, kid: Option<&str>) -> Option<&'a Jwk> {
    jwks.keys.iter().find(|k| {
        k.kid.as_deref() == kid
            && k.kty == "OKP"
            && k.crv.as_deref() == Some("Ed25519")
            && k.alg.as_deref().unwrap_or("EdDSA") == "EdDSA"
    })
}

/// Verifies an access token against a JWKS: `alg` must be `EdDSA`, the signature must verify with
/// the `kid`'s key, `iss` must equal the issuer, `aud` must contain the audience, and `exp` / `nbf`
/// must hold within the skew.
///
/// Every failure is [`OvErrorCode::Unauthorized`] with status 401, as a verifier answers.
pub fn verify_jwt(token: &str, jwks: &Jwks, opts: &VerifyOptions) -> Result<AccessClaims, OvError> {
    verify_jwt_refetching(token, jwks, opts, || Ok(None))
}

/// [`verify_jwt`] that calls `refetch` once when the `kid` is unknown (SPEC §9: refetch the JWKS at
/// most every 30 s; the caller rate-limits and may return `Ok(None)` to skip). A refetch error is
/// returned as is.
pub fn verify_jwt_refetching<F>(
    token: &str,
    jwks: &Jwks,
    opts: &VerifyOptions,
    refetch: F,
) -> Result<AccessClaims, OvError>
where
    F: FnOnce() -> Result<Option<Jwks>, OvError>,
{
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(unauthorized("not a JWT"));
    }
    let decoded = decode_jwt(token).map_err(|_| unauthorized("malformed JWT"))?;
    if decoded.header.get("alg").and_then(serde_json::Value::as_str) != Some("EdDSA") {
        return Err(unauthorized("only EdDSA is accepted"));
    }
    let kid = decoded.kid();
    let refetched;
    let jwk = match find_jwk(jwks, kid) {
        Some(k) => k,
        None => {
            refetched = refetch()?;
            refetched.as_ref().and_then(|set| find_jwk(set, kid)).ok_or_else(|| unauthorized("unknown kid"))?
        }
    };
    let x = jwk.x.as_deref().ok_or_else(|| unauthorized("unknown kid"))?;
    let pk = from_b64u(x).map_err(|_| unauthorized("unknown kid"))?;
    let sig = from_b64u(parts[2]).map_err(|_| unauthorized("bad signature"))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if !ed25519_verify(&sig, signing_input.as_bytes(), &pk) {
        return Err(unauthorized("bad signature"));
    }
    let claims = decoded.claims;
    if claims.iss != opts.issuer {
        return Err(unauthorized("wrong issuer"));
    }
    if !claims.aud.as_ref().is_some_and(|a| a.contains(&opts.audience)) {
        return Err(unauthorized("wrong audience"));
    }
    match claims.exp {
        Some(exp) if opts.now <= exp.saturating_add(opts.skew) => {}
        _ => return Err(unauthorized("expired")),
    }
    if let Some(nbf) = claims.nbf {
        if opts.now.saturating_add(opts.skew) < nbf {
            return Err(unauthorized("not yet valid"));
        }
    }
    Ok(claims)
}
