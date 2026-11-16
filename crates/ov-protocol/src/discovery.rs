//! Discovery (SPEC §10): `GET {issuer}/.well-known/openvireo-configuration`, and the JWKS it
//! points to. Ported from `discover` and `fetchJwks` in `auth/client.ts`.

use ov_error::{OvError, OvErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::parse_json;
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::url::{json_request, require_secure_url};

/// The discovery document (SPEC §10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVireoConfiguration {
    /// The issuer (`iss` of access tokens).
    pub issuer: String,
    /// `{api}`: the auth server's API base.
    pub api: String,
    /// `{sync}`: the sync server's API base (ends in `/api/v1`).
    pub sync: String,
    /// Where the access-token signing keys are.
    pub jwks_uri: String,
    /// The OPAQUE configuration (SPEC §8).
    pub opaque: OpaqueConfig,
    /// The server's KDF minimums.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_min: Option<KdfMin>,
    /// The web app (SPEC §16); clients without it hide "Manage account".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<String>,
    /// The public share page (SPEC §22); `<web>/s` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<String>,
}

impl OpenVireoConfiguration {
    /// The share page base: `share`, else `<web>/s`, else `None`.
    pub fn share_base(&self) -> Option<String> {
        self.share.clone().or_else(|| self.web.as_ref().map(|w| format!("{}/s", w.trim_end_matches('/'))))
    }
}

/// `opaque` in the discovery document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueConfig {
    /// Server library name.
    #[serde(default)]
    pub lib: String,
    /// Server library version.
    #[serde(default)]
    pub version: String,
    /// OPAQUE context string (`ov-opaque-v1`).
    #[serde(default)]
    pub context: String,
    /// The server identity (`idS`).
    pub ids: String,
}

/// `kdf_min` in the discovery document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfMin {
    /// Minimum memory, KiB.
    pub m: u32,
    /// Minimum iterations.
    pub t: u32,
}

/// The `GET` for an issuer's discovery document. Fails with `insecure_url` for a plain-http
/// issuer that isn't loopback.
pub fn build_discovery(issuer: &str) -> Result<HttpRequest, OvError> {
    let base = issuer.trim().trim_end_matches('/');
    require_secure_url(base, "issuer")?;
    Ok(json_request(Method::Get, format!("{base}/.well-known/openvireo-configuration"), None, None))
}

/// Parses and checks the discovery document: `issuer`, `api`, `sync` and `jwks_uri` must be
/// strings and secure URLs, `web` and `share` secure when present, and `opaque.ids` set.
pub fn parse_discovery(res: &HttpResponse) -> Result<OpenVireoConfiguration, OvError> {
    let v: Value = parse_json(res)?;
    let invalid = |m: String| OvError::new(OvErrorCode::InvalidRequest, m);
    for k in ["issuer", "api", "sync", "jwks_uri"] {
        let Some(url) = v.get(k).and_then(Value::as_str) else {
            return Err(invalid(format!("openvireo-configuration is missing \"{k}\"")));
        };
        require_secure_url(url, k)?;
    }
    for k in ["web", "share"] {
        if let Some(url) = v.get(k).and_then(Value::as_str) {
            require_secure_url(url, k)?;
        }
    }
    let ids = v.get("opaque").and_then(|o| o.get("ids"));
    if !ids.and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
        return Err(invalid("openvireo-configuration is missing opaque.ids".into()));
    }
    serde_json::from_value(v).map_err(|_| invalid("openvireo-configuration doesn't match SPEC §10".into()))
}

/// A JSON Web Key (Ed25519 `OKP` for access tokens).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (`OKP`).
    pub kty: String,
    /// Curve (`Ed25519`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// Public key, base64url.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Key id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// `sig`.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// `EdDSA`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// A JWK set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// Keys.
    pub keys: Vec<Jwk>,
}

/// The `GET` for `jwks_uri`.
pub fn build_jwks(jwks_uri: &str) -> Result<HttpRequest, OvError> {
    require_secure_url(jwks_uri, "server")?;
    Ok(json_request(Method::Get, jwks_uri.to_string(), None, None))
}

/// Parses a JWK set.
pub fn parse_jwks(res: &HttpResponse) -> Result<Jwks, OvError> {
    parse_json(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{request_header, response};

    /// The example document in SPEC §10.
    const SPEC_10: &str = r#"{"issuer":"https://accounts.openvireo.com","api":"https://accounts.openvireo.com/api/v1",
 "sync":"https://sync.openvireo.com/api/v1","jwks_uri":"https://accounts.openvireo.com/.well-known/jwks.json",
 "opaque":{"lib":"libopaque","version":"1.0.1-6e9ac92","context":"ov-opaque-v1","ids":"accounts.openvireo.com"},
 "kdf_min":{"m":19456,"t":2},"web":"https://app.openvireo.com"}"#;

    #[test]
    fn spec_example_parses() {
        let r = build_discovery("https://accounts.openvireo.com/").unwrap();
        assert_eq!(r.url, "https://accounts.openvireo.com/.well-known/openvireo-configuration");
        assert_eq!((r.method, request_header(&r, "accept")), (Method::Get, Some("application/json")));
        let c = parse_discovery(&response(200, &[], SPEC_10)).unwrap();
        assert_eq!(c.sync, "https://sync.openvireo.com/api/v1");
        assert_eq!(c.opaque.ids, "accounts.openvireo.com");
        assert_eq!(c.kdf_min, Some(KdfMin { m: 19456, t: 2 }));
        assert_eq!(c.share_base().as_deref(), Some("https://app.openvireo.com/s"));
        let back: Value = serde_json::to_value(&c).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(SPEC_10).unwrap());
    }

    #[test]
    fn checks_like_the_sdk() {
        assert_eq!(build_discovery("http://accounts.example").unwrap_err().code, OvErrorCode::InsecureUrl);
        assert!(build_discovery("http://localhost:8000").is_ok());
        let doc = |f: &dyn Fn(&mut Value)| {
            let mut v: Value = serde_json::from_str(SPEC_10).unwrap();
            f(&mut v);
            parse_discovery(&response(200, &[], v.to_string()))
        };
        let e = doc(&|v| {
            v.as_object_mut().unwrap().remove("sync");
        })
        .unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            (OvErrorCode::InvalidRequest, "openvireo-configuration is missing \"sync\"")
        );
        let e = doc(&|v| v["api"] = "http://accounts.example/api/v1".into()).unwrap_err();
        assert_eq!(e.code, OvErrorCode::InsecureUrl);
        assert!(e.message.starts_with("the api URL"));
        let e = doc(&|v| v["share"] = "http://share.example".into()).unwrap_err();
        assert_eq!(e.code, OvErrorCode::InsecureUrl);
        let e = doc(&|v| v["opaque"]["ids"] = "".into()).unwrap_err();
        assert_eq!(e.message, "openvireo-configuration is missing opaque.ids");
        assert_eq!(
            doc(&|v| v["share"] = "https://share.openvireo.com".into()).unwrap().share_base().as_deref(),
            Some("https://share.openvireo.com")
        );
        assert_eq!(parse_discovery(&response(404, &[], "")).unwrap_err().code, OvErrorCode::NotFound);
    }

    #[test]
    fn jwks() {
        let r = build_jwks("https://accounts.openvireo.com/.well-known/jwks.json").unwrap();
        assert_eq!(r.method, Method::Get);
        let body = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1","use":"sig","alg":"EdDSA"}]}"#;
        let k = parse_jwks(&response(200, &[], body)).unwrap();
        assert_eq!((k.keys[0].kid.as_deref(), k.keys[0].use_.as_deref()), (Some("k1"), Some("sig")));
        assert_eq!(build_jwks("http://evil.example/jwks").unwrap_err().code, OvErrorCode::InsecureUrl);
    }
}
