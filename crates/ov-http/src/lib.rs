//! Plain HTTP request and response types.
//!
//! **Frozen contract** (rust-core-tasks.md §2.2, tag `contract-v1.2`). These lived in
//! `ov_core::host` until contract-v1.2 and are re-exported there unchanged. They sit in their own
//! crate so `ov-protocol` (pure request builders and parsers) can use them without depending on
//! `ov-core`, which depends on `ov-protocol`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET.
    Get,
    /// HEAD (sync `localChanged: false` checks).
    Head,
    /// POST.
    Post,
    /// PUT (vault uploads).
    Put,
    /// PATCH.
    Patch,
    /// DELETE.
    Delete,
}

impl Method {
    /// The method name, e.g. `"GET"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// A request for the platform to send.
///
/// The core has already checked the URL against SPEC §1 "Transport" (https, or loopback http).
/// Transports must **not follow redirects** (the SDK uses `redirect: "error"`), must not add
/// cookies or credentials, and must send exactly these headers (plus what the platform always adds,
/// such as `User-Agent`). Headers may carry bearer tokens: never log them.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Method.
    pub method: Method,
    /// Absolute URL.
    pub url: String,
    /// Header names and values, in order.
    pub headers: Vec<(String, String)>,
    /// Body bytes (`None` for no body).
    pub body: Option<Vec<u8>>,
    /// Keep the request alive past page unload (`fetch` `keepalive`). Only the web honours it,
    /// for `ov_core::api::Account::sign_out_on_unload`.
    pub keepalive: bool,
}

impl std::fmt::Debug for HttpRequest {
    /// Shows header names only, since values may be bearer tokens.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &names)
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .field("keepalive", &self.keepalive)
            .finish()
    }
}

/// A response the platform received. Any status is a response (4xx/5xx are not transport errors).
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Header names (any case) and values, in order.
    pub headers: Vec<(String, String)>,
    /// Body bytes (empty for none).
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl HttpResponse {
    /// The first header named `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}
