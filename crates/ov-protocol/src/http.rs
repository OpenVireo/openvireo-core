//! The plain HTTP request and response the builders make and the parsers read: the frozen
//! `ov-http` types, which `ov_core::host` re-exports too, plus a few helpers.

pub use ov_http::{HttpRequest, HttpResponse, Method};

/// A response with a status, headers and body (for tests and fake servers).
pub fn response(status: u16, headers: &[(&str, &str)], body: impl Into<Vec<u8>>) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        body: body.into(),
    }
}

/// The first request header named `name`, compared case-insensitively.
pub fn request_header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Whether the status is 2xx (`Response.ok`).
pub(crate) fn is_ok(res: &HttpResponse) -> bool {
    (200..300).contains(&res.status)
}
