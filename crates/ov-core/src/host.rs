//! The Host: everything the core asks the platform to do (rust-core.md §5).
//!
//! **Frozen contract** (rust-core-tasks.md §2.2, tag `contract-v1`). The core never opens a socket
//! or a file, reads the clock or touches the Keychain itself. Each platform implements these traits
//! once (URLSession + Keychain on iOS, QNetworkAccessManager + DPAPI/libsecret on desktop, `fetch` +
//! IndexedDB on the web, reqwest + files in the `ov` CLI) and passes a [`Host`] to
//! [`OvClient::new`](crate::api::OvClient::new).
//!
//! Randomness is not part of the Host: the core reads the platform CSPRNG through `getrandom`
//! (`crypto.getRandomValues` on wasm32).
//!
//! Async traits use `async_trait`. On wasm32 the futures and trait objects are not `Send`
//! (`async_trait(?Send)`, and [`MaybeSend`]/[`MaybeSync`] are empty), because JS values can't
//! cross threads; everywhere else they are `Send + Sync`.

use std::sync::Arc;

use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

/// `Send` on native targets; nothing on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}
/// `Send` on native targets; nothing on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// `Sync` on native targets; nothing on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}
/// `Sync` on native targets; nothing on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

// ------------------------------------------------------------------------------------------ HTTP

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
    /// for [`Account::sign_out_on_unload`](crate::api::Account::sign_out_on_unload).
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

/// Why a request didn't produce a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// No network, DNS failure or connection refused.
    Offline,
    /// The request timed out.
    Timeout,
    /// TLS failed (certificate, handshake); the text is for logs.
    Tls(String),
    /// The platform cancelled the request.
    Cancelled,
    /// Anything else; the text is for logs.
    Other(String),
}

impl From<TransportError> for OvError {
    /// `Cancelled` becomes `aborted`; everything else is `network_error`, which offline fallbacks
    /// (SPEC §20) treat as "the server can't be reached".
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Cancelled => OvError::new(OvErrorCode::Aborted, "the request was cancelled"),
            TransportError::Offline => OvError::new(OvErrorCode::NetworkError, "the server can't be reached"),
            TransportError::Timeout => OvError::new(OvErrorCode::NetworkError, "the request timed out"),
            TransportError::Tls(m) => OvError::new(OvErrorCode::NetworkError, format!("TLS failed: {m}")),
            TransportError::Other(m) => OvError::new(OvErrorCode::NetworkError, m),
        }
    }
}

/// HTTP for the core: URLSession, QNetworkAccessManager, `fetch` or reqwest.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HttpTransport: MaybeSend + MaybeSync {
    /// Sends one request and returns the whole response.
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError>;

    /// Opens a server-sent events stream (SPEC §11): `GET {sync}/events` with `Accept:
    /// text/event-stream`. The transport checks the status (an error status may be returned as
    /// `Ok` with a stream that yields the body); the core parses the SSE framing. Browsers must
    /// use `fetch` with `cache: "no-store"`, not `EventSource`.
    async fn open_stream(&self, req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError>;
}

/// The body of an open stream, read chunk by chunk.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ByteStream: MaybeSend + MaybeSync {
    /// The response status the stream was opened with.
    fn status(&self) -> u16;
    /// The next chunk of bytes (any size), or `None` when the server closed the stream.
    async fn next_chunk(&self) -> Result<Option<Vec<u8>>, TransportError>;
    /// Closes the stream; later `next_chunk` calls return `None`.
    fn close(&self);
}

// ------------------------------------------------------------------------------------ storage

/// Small secrets that must survive restarts: sessions (refresh tokens), trusted Secret Keys,
/// device ids, the remembered-accounts list (SPEC §2, §21). Keychain, DPAPI/libsecret, or
/// IndexedDB values wrapped with a non-extractable WebCrypto key.
///
/// Keys are short ASCII strings chosen by the core (`secret_key:<idS>:<idU>`, `device:…`,
/// `session`, `parked_session:…`; the same names the TS SDK and iOS app use, so existing data
/// carries over). Values are opaque bytes. Implementations must be safe to call concurrently.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SecureStore: MaybeSend + MaybeSync {
    /// The value for `key`, or `None`. A store that can't be read (e.g. a locked Keychain before
    /// first unlock) returns an error, which is not the same as `None`.
    async fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, OvError>;
    /// Stores `value` under `key`, replacing any old value.
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), OvError>;
    /// Removes `key`; removing a missing key is not an error.
    async fn delete(&self, key: &str) -> Result<(), OvError>;
}

/// What the offline cache keeps for one vault of one user (SPEC §20). Everything in it is already
/// encrypted (vault bytes under the vault key) or not secret, so it can live in ordinary app
/// storage (files, IndexedDB).
#[derive(Clone, PartialEq, Eq)]
pub struct CachedVault {
    /// The core's sync state for the vault, serialized by the core (opaque to the host). It holds
    /// the ETag, revision, sync generation, entry snapshot and last-sync time.
    pub state: Vec<u8>,
    /// The server's encrypted `.kdbx` at the last sync: the merge base and the offline copy.
    pub base: Option<Vec<u8>>,
    /// Local edits not yet uploaded: a `.kdbx` encrypted with the vault key.
    pub pending: Option<Vec<u8>>,
    /// Edits made by an AutoFill extension, waiting for the app to merge them (iOS), encrypted
    /// like `pending`.
    pub autofill: Option<Vec<u8>>,
}

impl std::fmt::Debug for CachedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedVault")
            .field("state_len", &self.state.len())
            .field("base_len", &self.base.as_ref().map(Vec::len))
            .field("pending_len", &self.pending.as_ref().map(Vec::len))
            .field("autofill_len", &self.autofill.as_ref().map(Vec::len))
            .finish()
    }
}

/// The offline cache (SPEC §20): per user, per vault, plus a few per-user and per-server records.
///
/// Records are keyed by `user_id` because two accounts on one device can share a vault (SPEC §21).
/// The `meta_*` records hold what offline unlock and listing need: the discovery document (`user_id`
/// is then `""` and `name` is `config:<issuer>`), and per user the wrapped keyset + KDF (`profile`)
/// and the vault list as the server returned it (`vaults`). All of it is ciphertext or public.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait BlobCache: MaybeSend + MaybeSync {
    /// The cached vault, or `None`.
    async fn load(&self, user_id: &str, vault_id: &str) -> Result<Option<CachedVault>, OvError>;
    /// Stores the cached vault, replacing the old record.
    async fn save(&self, user_id: &str, vault_id: &str, v: &CachedVault) -> Result<(), OvError>;
    /// Removes one vault's record.
    async fn remove(&self, user_id: &str, vault_id: &str) -> Result<(), OvError>;
    /// The ids of every vault cached for `user_id`.
    async fn list(&self, user_id: &str) -> Result<Vec<String>, OvError>;
    /// A per-user (or, with `user_id == ""`, per-device) record such as `profile` or `vaults`.
    async fn load_meta(&self, user_id: &str, name: &str) -> Result<Option<Vec<u8>>, OvError>;
    /// Stores a per-user record.
    async fn save_meta(&self, user_id: &str, name: &str, value: &[u8]) -> Result<(), OvError>;
    /// Removes everything cached for `user_id`: its vaults and its records (sign-out, SPEC §20).
    async fn clear_user(&self, user_id: &str) -> Result<(), OvError>;
}

// --------------------------------------------------------------------------------- clock, logs

/// Wall-clock time. Tests pass a fixed clock (`ov-testkit`).
pub trait Clock: MaybeSend + MaybeSync {
    /// Milliseconds since the Unix epoch.
    fn now_unix_ms(&self) -> i64;
}

/// Log severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Something failed.
    Error,
    /// Something unexpected that the core recovered from.
    Warn,
    /// Notable steps (sync outcomes, offline fallbacks).
    Info,
    /// Detail for debugging.
    Debug,
    /// Very detailed tracing.
    Trace,
}

/// Where the core's log lines go (os_log, qDebug, `console`, stderr). The core never logs secrets.
pub trait LogSink: MaybeSend + MaybeSync {
    /// One log line. `target` names the module, e.g. `"ov_sync"`.
    fn log(&self, level: Level, target: &str, msg: &str);
}

/// The platform services the core runs on. Cheap to clone; every [`OvClient`](crate::api::OvClient)
/// and handle made from it shares these.
#[derive(Clone)]
pub struct Host {
    /// HTTP.
    pub http: Arc<dyn HttpTransport>,
    /// Secrets that persist.
    pub store: Arc<dyn SecureStore>,
    /// The offline cache.
    pub cache: Arc<dyn BlobCache>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// Logs.
    pub log: Arc<dyn LogSink>,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Host { .. }")
    }
}
