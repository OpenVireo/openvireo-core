//! The small HTTP toolkit the two servers share: parsed requests, route matching, JSON and error
//! responses, an insertion-ordered table, and time formatting. Ported from `mock-fetch.ts`.

use ov_host::{HttpRequest, HttpResponse, Method};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

/// A handler's result: `Err` carries an error response, so handlers can use `?`.
pub(crate) type Res = Result<HttpResponse, HttpResponse>;

/// A request as the servers see it.
pub(crate) struct Req {
    pub method: Method,
    /// The path below the server's API base (`/me`, `/vaults/x`), or the full path for routes outside it.
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn from_http(req: &HttpRequest, path: String, query: &str) -> Self {
        Req {
            method: req.method,
            path,
            query: parse_query(query),
            headers: req.headers.clone(),
            body: req.body.clone().unwrap_or_default(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The bearer token, or `""`.
    pub fn bearer(&self) -> &str {
        self.header("authorization").and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("")
    }

    pub fn query(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The JSON body as `T`; 400 `invalid_request` when it is missing or doesn't match.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, HttpResponse> {
        serde_json::from_slice(&self.body)
            .map_err(|e| error(400, "invalid_request", &format!("the request body doesn't match the contract: {e}")))
    }

    /// The JSON body as a value, `Null` when absent or not JSON.
    pub fn value(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// The parameters a route pattern captured.
pub(crate) struct Params(Vec<(&'static str, String)>);

impl Params {
    pub fn get(&self, name: &str) -> &str {
        self.0.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

/// Matches `pattern` (`/vaults/{vault}/keys/{version}/activate`) against the request. A GET route
/// also answers HEAD, as in `mock-fetch.ts`.
pub(crate) fn matches(req: &Req, method: Method, pattern: &'static str) -> Option<Params> {
    if req.method != method && !(method == Method::Get && req.method == Method::Head) {
        return None;
    }
    let want: Vec<&'static str> = pattern.split('/').collect();
    let got: Vec<&str> = req.path.split('/').collect();
    if want.len() != got.len() {
        return None;
    }
    let mut params = Vec::new();
    for (w, g) in want.iter().zip(&got) {
        if let Some(name) = w.strip_prefix('{').and_then(|w| w.strip_suffix('}')) {
            if g.is_empty() {
                return None;
            }
            params.push((name, percent_decode(g)));
        } else if w != g {
            return None;
        }
    }
    Some(Params(params))
}

/// Splits a URL into `(host, path, query)`. `None` when it isn't an absolute http(s) URL.
pub(crate) fn split_url(url: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or("");
    let (authority, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (path, query) = path_query.split_once('?').unwrap_or((path_query, ""));
    Some((authority.to_ascii_lowercase(), path.to_string(), query.to_string()))
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(&k.replace('+', " ")), percent_decode(&v.replace('+', " ")))
        })
        .collect()
}

/// `decodeURIComponent`, keeping bad sequences as they are.
pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16)) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ------------------------------------------------------------------------------------ responses

/// A JSON response.
pub(crate) fn json_response(status: u16, body: &Value, extra: &[(&str, String)]) -> HttpResponse {
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    headers.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
    HttpResponse { status, headers, body: serde_json::to_vec(body).expect("JSON values serialise") }
}

/// `Ok` with a typed body.
pub(crate) fn ok<T: Serialize>(status: u16, body: &T) -> Res {
    Ok(json_response(status, &serde_json::to_value(body).expect("wire types serialise"), &[]))
}

/// A response without a body.
pub(crate) fn empty(status: u16) -> HttpResponse {
    HttpResponse { status, headers: vec![], body: vec![] }
}

/// The `{error, code}` body of every error.
pub(crate) fn error(status: u16, code: &str, message: &str) -> HttpResponse {
    error_with(status, code, message, json!({}))
}

/// An error with extra body fields (`scheduled_for`, `attempts_left`, `max`, ...).
pub(crate) fn error_with(status: u16, code: &str, message: &str, extra: Value) -> HttpResponse {
    let mut body = json!({ "error": message, "code": code });
    if let (Some(b), Value::Object(e)) = (body.as_object_mut(), extra) {
        b.extend(e);
    }
    let headers: Vec<(&str, String)> =
        if status == 401 { vec![("WWW-Authenticate", "Bearer".to_string())] } else { vec![] };
    json_response(status, &body, &headers)
}

/// The usual code for a status, for injected faults.
pub(crate) fn code_for_status(status: u16) -> &'static str {
    match status {
        400 => "invalid_request",
        401 => "unauthorized",
        402 => "plan_limit",
        403 => "forbidden",
        404 => "not_found",
        409 => "conflict",
        410 => "gone",
        412 => "precondition_failed",
        413 => "quota_exceeded",
        428 => "precondition_required",
        429 => "rate_limited",
        _ => "server_error",
    }
}

// ------------------------------------------------------------------------------------ table

/// A map that keeps insertion order, like a JS `Map` (lists come out in creation order).
pub(crate) struct Table<T>(Vec<(String, T)>);

impl<T> Default for Table<T> {
    fn default() -> Self {
        Table(Vec::new())
    }
}

impl<T> Table<T> {
    pub fn get(&self, k: &str) -> Option<&T> {
        self.0.iter().find(|(key, _)| key == k).map(|(_, v)| v)
    }
    pub fn get_mut(&mut self, k: &str) -> Option<&mut T> {
        self.0.iter_mut().find(|(key, _)| key == k).map(|(_, v)| v)
    }
    pub fn contains(&self, k: &str) -> bool {
        self.get(k).is_some()
    }
    /// Inserts or replaces (keeping the old position).
    pub fn insert(&mut self, k: impl Into<String>, v: T) {
        let k = k.into();
        match self.get_mut(&k) {
            Some(old) => *old = v,
            None => self.0.push((k, v)),
        }
    }
    pub fn remove(&mut self, k: &str) -> Option<T> {
        let i = self.0.iter().position(|(key, _)| key == k)?;
        Some(self.0.remove(i).1)
    }
    pub fn retain(&mut self, mut f: impl FnMut(&str, &mut T) -> bool) {
        self.0.retain_mut(|(k, v)| f(k, v));
    }
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&str, &T)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut T)> {
        self.0.iter_mut().map(|(k, v)| (k.as_str(), v))
    }
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.iter().map(|(_, v)| v)
    }
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut().map(|(_, v)| v)
    }
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

// ------------------------------------------------------------------------------------ time

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's `civil_from_days`.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// (year, month, day) → days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 in UTC with seconds: `2026-11-15T12:00:00Z`.
pub(crate) fn iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z", t / 3600, t % 3600 / 60, t % 60)
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff](Z|+00:00)` into Unix ms. `None` for anything else.
pub(crate) fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b' ') || b[13] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, sec) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    let mut rest = &s[19..];
    let mut ms = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
        rest = &frac[digits.len()..];
        ms = format!("{:0<3}", &digits[..digits.len().min(3)]).parse().ok()?;
    }
    if !matches!(rest, "Z" | "+00:00" | "z") {
        return None;
    }
    Some(((days_from_civil(y, mo, d) * 86_400) + h * 3600 + mi * 60 + sec) * 1000 + ms)
}

/// An IMF-fixdate for `Date` and `Last-Modified`: `Sun, 15 Nov 2026 12:00:00 GMT`.
pub(crate) fn http_date(ms: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let (y, mo, d) = civil(days);
    let t = secs.rem_euclid(86_400);
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(mo - 1) as usize],
        t / 3600,
        t % 3600 / 60,
        t % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(iso(1_794_744_000_000), "2026-11-15T12:00:00Z");
        assert_eq!(parse_iso("2026-11-15T12:00:00Z"), Some(1_794_744_000_000));
        assert_eq!(parse_iso("2026-11-15T12:00:00.250Z"), Some(1_794_744_000_250));
        assert_eq!(parse_iso("2026-11-15T12:00:00+00:00"), Some(1_794_744_000_000));
        assert_eq!(parse_iso("yesterday"), None);
        assert_eq!(http_date(784_111_777_000), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(ov_protocol::sync::parse_http_date(&http_date(1_794_744_000_000)), Some(1_794_744_000_000));
    }

    #[test]
    fn routes_and_urls() {
        let req = |m, p: &str| Req { method: m, path: p.into(), query: vec![], headers: vec![], body: vec![] };
        let p = matches(
            &req(Method::Get, "/principals/user%3Aab/public-key"),
            Method::Get,
            "/principals/{principal}/public-key",
        )
        .unwrap();
        assert_eq!(p.get("principal"), "user:ab");
        assert!(matches(&req(Method::Head, "/vaults/v"), Method::Get, "/vaults/{vault}").is_some());
        assert!(matches(&req(Method::Put, "/vaults/v"), Method::Get, "/vaults/{vault}").is_none());
        assert!(matches(&req(Method::Get, "/vaults/"), Method::Get, "/vaults/{vault}").is_none());
        assert_eq!(
            split_url("https://Auth.Test/api/v1/users/lookup?email=a%2Bb%40x.y"),
            Some(("auth.test".into(), "/api/v1/users/lookup".into(), "email=a%2Bb%40x.y".into()))
        );
        assert_eq!(
            parse_query("email=a%2Bb%40x.y&x"),
            vec![("email".into(), "a+b@x.y".into()), ("x".into(), "".into())]
        );
        assert_eq!(percent_decode("100%"), "100%");
    }
}
