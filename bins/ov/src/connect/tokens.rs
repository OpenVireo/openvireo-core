//! `ov connect`'s own bearer tokens (port of `packages/connect/src/tokens.ts`). They are independent
//! of the SA token the server holds: each one is `ov_ct_` + base64url(32 random bytes), stored only
//! as its SHA-256 (lowercase hex), and scoped to some vaults with read or write access.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ov_error::{OvError, OvErrorCode};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::Value;
use zeroize::Zeroizing;

/// What every connect token starts with.
pub const CONNECT_TOKEN_PREFIX: &str = "ov_ct_";

/// Read or write access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// `GET` only.
    Read,
    /// `GET` and `PUT`.
    Write,
}

impl Access {
    /// `read` or `write`.
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
        }
    }
}

/// One configured token (the TS `ConnectToken`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectToken {
    /// Its name, in the request log and error messages.
    pub name: String,
    /// The hex SHA-256 of the UTF-8 token (64 lowercase hex digits).
    pub sha256: String,
    /// Vault ids or names this token may use; `*` for every vault the SA can open.
    pub vaults: Vec<String>,
    /// Read or write.
    pub access: Access,
}

impl Serialize for ConnectToken {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("ConnectToken", 4)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("sha256", &self.sha256)?;
        st.serialize_field("vaults", &self.vaults)?;
        st.serialize_field("access", self.access.as_str())?;
        st.end()
    }
}

fn invalid(message: String) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, message)
}

/// SHA-256. `ov` has no hash crate of its own (its direct dependencies are frozen by the
/// contract); rustls's ring provider, already linked for the optional TLS, has one: the hash of a
/// SHA-256 cipher suite.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let suite = tokio_rustls::rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let mut out = [0u8; 32];
    if let Some(s) = suite.tls13() {
        out.copy_from_slice(s.common.hash_provider.hash(data).as_ref());
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Compares in time that depends only on the length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// `hashConnectToken`: the lowercase hex SHA-256 of the UTF-8 token.
pub fn hash_token(token: &str) -> String {
    to_hex(&sha256(token.as_bytes()))
}

/// `newConnectToken`: a new token and its config entry (the plain token is shown once and not
/// stored). No vaults means every vault (`*`).
pub fn new_token(name: &str, vaults: &[String], access: Access) -> Result<(Zeroizing<String>, ConnectToken), OvError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut bytes[..]).map_err(|e| OvError::internal(format!("no randomness: {e}")))?;
    let token = Zeroizing::new(format!("{CONNECT_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(&bytes[..])));
    let entry = ConnectToken {
        name: name.to_string(),
        sha256: hash_token(&token),
        vaults: if vaults.is_empty() { vec!["*".to_string()] } else { vaults.to_vec() },
        access,
    };
    Ok((token, entry))
}

/// How JS prints a truthy `name` inside the error location (`#2 (eso)`).
fn shown_name(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) if n.as_f64() != Some(0.0) => Some(n.to_string()),
        Value::Bool(true) => Some("true".into()),
        Value::Object(_) => Some("[object Object]".into()),
        _ => None,
    }
}

/// `parseConnectTokens`: a JSON array of tokens, or `{"tokens": [...]}`, checked.
pub fn parse_tokens(text: &str) -> Result<Vec<ConnectToken>, OvError> {
    let raw: Value =
        serde_json::from_str(text).map_err(|e| invalid(format!("connect tokens config is not JSON: {e}")))?;
    let list = match &raw {
        Value::Array(a) => Some(a),
        Value::Object(o) => o.get("tokens").and_then(Value::as_array),
        _ => None,
    }
    .ok_or_else(|| invalid("connect tokens config must be an array or {\"tokens\": [...]}".into()))?;
    list.iter()
        .enumerate()
        .map(|(i, t)| {
            let o = t.as_object();
            let field = |k: &str| o.and_then(|o| o.get(k)).filter(|v| !v.is_null());
            let where_ = match shown_name(field("name")) {
                Some(n) => format!("connect token #{} ({n})", i + 1),
                None => format!("connect token #{}", i + 1),
            };
            let name = match field("name") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                _ => return Err(invalid(format!("{where_}: \"name\" is required"))),
            };
            let sha256 = match field("sha256") {
                Some(Value::String(s))
                    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
                {
                    s.clone()
                }
                _ => return Err(invalid(format!("{where_}: \"sha256\" must be 64 lowercase hex digits"))),
            };
            let vaults = match field("vaults") {
                None => vec!["*".to_string()],
                Some(Value::Array(a)) if a.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty())) => {
                    a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
                }
                Some(_) => return Err(invalid(format!("{where_}: \"vaults\" must be a list of vault ids or names"))),
            };
            let access = match field("access").map(|v| v.as_str()) {
                None | Some(Some("read")) => Access::Read,
                Some(Some("write")) => Access::Write,
                Some(_) => return Err(invalid(format!("{where_}: \"access\" must be \"read\" or \"write\""))),
            };
            Ok(ConnectToken { name, sha256, vaults, access })
        })
        .collect()
}

/// `authenticate`: the token presented in `Authorization: Bearer <token>` (the header's values
/// joined with `, `), compared in constant time against every configured token's hash.
pub fn authenticate<'a>(tokens: &'a [ConnectToken], header: Option<&str>) -> Option<&'a ConnectToken> {
    let h = header.unwrap_or("");
    // /^Bearer\s+(\S+)\s*$/i
    let scheme = h.get(..6).filter(|s| s.eq_ignore_ascii_case("bearer"))?;
    let rest = &h[scheme.len()..];
    let after_space = rest.trim_start_matches(crate::js::is_space);
    if after_space.len() == rest.len() {
        return None;
    }
    let presented = after_space.trim_end_matches(crate::js::is_space);
    if presented.is_empty() || presented.contains(crate::js::is_space) {
        return None;
    }
    let hash = sha256(presented.as_bytes());
    let mut found = None;
    for t in tokens {
        let stored = from_hex(&t.sha256).unwrap_or([0u8; 32]);
        if ct_eq(&hash, &stored) && found.is_none() {
            found = Some(t);
        }
    }
    found
}

/// `allowsVault`: the token names the vault by id or name, or has `*`.
pub fn allows_vault(t: &ConnectToken, id: &str, name: &str) -> bool {
    t.vaults.iter().any(|v| v == "*" || v == id || v == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_like_sha256() {
        assert_eq!(hash_token(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hash_token("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn new_tokens_have_the_ts_shape() {
        let (t, e) = new_token("eso", &[], Access::Read).unwrap();
        assert!(t.starts_with(CONNECT_TOKEN_PREFIX) && t.len() == 6 + 43, "{}", t.as_str());
        assert!(t[6..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(e.vaults, vec!["*"]);
        assert_eq!(e.sha256, hash_token(&t));
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            format!("{{\"name\":\"eso\",\"sha256\":\"{}\",\"vaults\":[\"*\"],\"access\":\"read\"}}", e.sha256)
        );
    }

    #[test]
    fn authenticates_bearer_headers() {
        let tokens = vec![
            ConnectToken {
                name: "a".into(),
                sha256: hash_token("one"),
                vaults: vec!["*".into()],
                access: Access::Read,
            },
            ConnectToken {
                name: "b".into(),
                sha256: hash_token("two"),
                vaults: vec!["*".into()],
                access: Access::Write,
            },
        ];
        assert_eq!(authenticate(&tokens, Some("Bearer two")).map(|t| t.name.as_str()), Some("b"));
        assert_eq!(authenticate(&tokens, Some("bearer   one  ")).map(|t| t.name.as_str()), Some("a"));
        for h in [
            None,
            Some(""),
            Some("Bearer"),
            Some("Bearer "),
            Some("Bearerone"),
            Some("Bearer one two"),
            Some("Basic one"),
        ] {
            assert!(authenticate(&tokens, h).is_none(), "{h:?}");
        }
        assert!(authenticate(&tokens, Some("Bearer three")).is_none());
    }

    #[test]
    fn parses_token_configs() {
        let a = "a".repeat(64);
        let one = parse_tokens(&format!(
            "{{\"tokens\":[{{\"name\":\"x\",\"sha256\":\"{a}\",\"vaults\":[\"V\"],\"access\":\"write\"}}]}}"
        ))
        .unwrap();
        assert_eq!(one[0].vaults, vec!["V"]);
        assert_eq!(one[0].access, Access::Write);
        let err = |t: &str| parse_tokens(t).unwrap_err().message;
        assert!(err("{}").contains("must be an array"));
        assert_eq!(err("[{}]"), "connect token #1: \"name\" is required");
        assert_eq!(err("[{\"name\":\"n\"}]"), "connect token #1 (n): \"sha256\" must be 64 lowercase hex digits");
        assert_eq!(
            err(&format!("[{{\"name\":\"n\",\"sha256\":\"{a}\",\"vaults\":[\"\"]}}]")),
            "connect token #1 (n): \"vaults\" must be a list of vault ids or names"
        );
    }
}
