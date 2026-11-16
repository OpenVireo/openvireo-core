//! URL checks and building (`http/request.ts`): SPEC §1 "Transport", path segments, queries.

use ov_error::{OvError, OvErrorCode};

use crate::http::{HttpRequest, Method};

/// `localhost`, `*.localhost`, `127.0.0.0/8` and `::1`: the only hosts plain `http://` is allowed
/// for (SPEC §1).
pub fn is_loopback_host(hostname: &str) -> bool {
    let h = hostname.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    if h == "localhost" || h.ends_with(".localhost") || h == "[::1]" || h == "::1" {
        return true;
    }
    // /^127(\.\d{1,3}){3}$/
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4
        && parts[0] == "127"
        && parts[1..].iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The parts of an absolute URL that the transport rule needs.
struct Origin {
    scheme: String,
    host: String,
    /// `scheme://host[:port]`, lowercased.
    origin: String,
}

fn parse_origin(url: &str) -> Option<Origin> {
    let (scheme, rest) = url.trim().split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a).to_ascii_lowercase();
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        authority[..=end].to_string()
    } else {
        authority.split(':').next().unwrap_or("").to_string()
    };
    if host.is_empty() {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    Some(Origin { origin: format!("{scheme}://{authority}"), scheme, host })
}

/// `insecure_url` unless the URL is `https://`, or `http://` to this computer (SPEC §1);
/// `invalid_request` if it isn't a URL. `what` names it in the message (`"server"`, `"issuer"`,
/// `"api"`, ...), as `requireSecureUrl` does.
pub fn require_secure_url(url: &str, what: &str) -> Result<(), OvError> {
    let Some(o) = parse_origin(url) else {
        return Err(OvError::new(OvErrorCode::InvalidRequest, format!("the {what} URL is not valid: {url}")));
    };
    if o.scheme == "https" || (o.scheme == "http" && is_loopback_host(&o.host)) {
        return Ok(());
    }
    Err(OvError::new(
        OvErrorCode::InsecureUrl,
        format!("the {what} URL must use https:// (plain http:// is only allowed for localhost): {}", o.origin),
    ))
}

/// `base` and `path` with exactly one `/` between them.
pub fn join_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
}

/// `encodeURIComponent`: everything but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` is percent-encoded as UTF-8.
pub fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// One path segment, encoded; keeps `:` readable for principals (`user:<uuid>`), like the SDK's `seg`.
pub fn seg(s: &str) -> String {
    encode_component(s).replace("%3A", ":")
}

/// `?k=v&...` for the pairs whose value is `Some`, or `""` when there are none.
pub fn query(pairs: &[(&str, Option<String>)]) -> String {
    let q: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| format!("{}={}", encode_component(k), encode_component(v))))
        .collect();
    if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    }
}

/// A checked base URL (`{api}`, `{sync}`, or an issuer) that request paths are joined to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Base(String);

impl Base {
    pub(crate) fn new(url: &str, what: &str) -> Result<Self, OvError> {
        let url = url.trim().trim_end_matches('/');
        require_secure_url(url, what)?;
        Ok(Base(url.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn url(&self, path: &str) -> String {
        join_url(&self.0, path)
    }
}

/// Serialises a wire type. The types in this crate only have string map keys and derived impls,
/// so this can't fail.
pub(crate) fn to_json<T: serde::Serialize + ?Sized>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("wire types always serialise")
}

/// The request `sendJson` makes: `Accept: application/json`, a JSON body with its
/// `Content-Type`, and `Authorization: Bearer` when there is a token.
pub(crate) fn json_request(method: Method, url: String, token: Option<&str>, body: Option<Vec<u8>>) -> HttpRequest {
    let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
    if body.is_some() {
        headers.push(("Content-Type".into(), "application/json".into()));
    }
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        headers.push(("Authorization".into(), format!("Bearer {t}")));
    }
    HttpRequest { method, url, headers, body, keepalive: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        for h in ["localhost", "LOCALHOST.", "a.localhost", "127.0.0.1", "127.1.22.255", "[::1]", "::1"] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in ["example.com", "127.0.0", "127.0.0.1.nip.io", "128.0.0.1", "localhost.example", "127.0.0.1234"] {
            assert!(!is_loopback_host(h), "{h}");
        }
    }

    #[test]
    fn secure_urls() {
        assert!(require_secure_url("https://accounts.openvireo.com/api/v1", "api").is_ok());
        assert!(require_secure_url("http://localhost:8000", "api").is_ok());
        assert!(require_secure_url("http://user:pw@127.0.0.1:8000/x", "api").is_ok());
        assert!(require_secure_url("http://[::1]:8787/api/v1", "sync").is_ok());
        let e = require_secure_url("http://sync.example.org:8787/api/v1", "sync").unwrap_err();
        assert_eq!(e.code, OvErrorCode::InsecureUrl);
        assert_eq!(
            e.message,
            "the sync URL must use https:// (plain http:// is only allowed for localhost): http://sync.example.org:8787"
        );
        let e = require_secure_url("http://localhost@evil.example/", "server").unwrap_err();
        assert_eq!(e.code, OvErrorCode::InsecureUrl);
        let e = require_secure_url("not a url", "issuer").unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            (OvErrorCode::InvalidRequest, "the issuer URL is not valid: not a url")
        );
        assert_eq!(require_secure_url("ftp://x", "server").unwrap_err().code, OvErrorCode::InsecureUrl);
    }

    #[test]
    fn segments_and_queries() {
        assert_eq!(seg("user:0000-1"), "user:0000-1");
        assert_eq!(seg("a/b c?é"), "a%2Fb%20c%3F%C3%A9");
        assert_eq!(join_url("https://x/api/v1//", "/me"), "https://x/api/v1/me");
        assert_eq!(query(&[("email", Some("a+b@x.y".into())), ("org", None)]), "?email=a%2Bb%40x.y");
        assert_eq!(query(&[("before", None)]), "");
    }
}
