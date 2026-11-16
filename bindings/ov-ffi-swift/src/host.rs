//! The Host traits as UniFFI foreign traits: Swift implements them (URLSession, Keychain, files,
//! os_log) and passes them to [`Host::new`]. Small adapters turn each into the matching
//! `ov_core::host` trait. The FFI shapes differ from the core's only where UniFFI needs it:
//! owned `String` arguments, header pairs as [`HttpHeader`] records, `Arc` instead of `Box` for
//! the returned stream, and plain `Vec<u8>` for secrets (wrapped in `Zeroizing` on the way in).

use std::sync::Arc;

use ov_core::host as core_host;
use zeroize::Zeroizing;

use crate::error::{OvError, TransportError};
use crate::types_ext::{HttpRequest, HttpResponse};

/// HTTP: URLSession on Apple platforms. Must not follow redirects or add cookies; see
/// `ov_core::host::HttpTransport`.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait HttpTransport: Send + Sync {
    /// Sends one request and returns the whole response (any status is a response).
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError>;
    /// Opens a server-sent events stream (SPEC §11); the core parses the framing.
    async fn open_stream(&self, req: HttpRequest) -> Result<OpenedStream, TransportError>;
}

/// The stream `HttpTransport.openStream` returns. A record rather than the bare trait object:
/// UniFFI 0.32 can't return `Arc<dyn Trait>` directly from an async foreign method.
#[derive(Clone, uniffi::Record)]
pub struct OpenedStream {
    /// The open stream.
    pub stream: Arc<dyn ByteStream>,
}

/// The body of an open stream, read chunk by chunk.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait ByteStream: Send + Sync {
    /// The response status the stream was opened with.
    fn status(&self) -> u16;
    /// The next chunk, or `nil` when the server closed the stream.
    async fn next_chunk(&self) -> Result<Option<Vec<u8>>, TransportError>;
    /// Closes the stream; later `next_chunk` calls return `nil`.
    fn close(&self);
}

/// Secrets that persist (the Keychain). Keys are chosen by the core; see
/// `ov_core::host::SecureStore`.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait SecureStore: Send + Sync {
    /// The value for `key`, or `nil`. An unreadable store throws (not the same as `nil`).
    async fn get(&self, key: String) -> Result<Option<Vec<u8>>, OvError>;
    /// Stores `value` under `key`, replacing any old value. The host wipes `value` after use.
    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), OvError>;
    /// Removes `key`; a missing key is not an error.
    async fn delete(&self, key: String) -> Result<(), OvError>;
}

/// The offline cache (SPEC §20), per user and vault; see `ov_core::host::BlobCache`.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BlobCache: Send + Sync {
    /// The cached vault, or `nil`.
    async fn load(&self, user_id: String, vault_id: String) -> Result<Option<core_host::CachedVault>, OvError>;
    /// Stores the cached vault, replacing the old record.
    async fn save(&self, user_id: String, vault_id: String, v: core_host::CachedVault) -> Result<(), OvError>;
    /// Removes one vault's record.
    async fn remove(&self, user_id: String, vault_id: String) -> Result<(), OvError>;
    /// The ids of every vault cached for `user_id`.
    async fn list(&self, user_id: String) -> Result<Vec<String>, OvError>;
    /// A per-user (or, with `user_id == ""`, per-device) record.
    async fn load_meta(&self, user_id: String, name: String) -> Result<Option<Vec<u8>>, OvError>;
    /// Stores a per-user record.
    async fn save_meta(&self, user_id: String, name: String, value: Vec<u8>) -> Result<(), OvError>;
    /// Removes everything cached for `user_id`.
    async fn clear_user(&self, user_id: String) -> Result<(), OvError>;
}

/// Wall-clock time.
#[uniffi::export(with_foreign)]
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_unix_ms(&self) -> i64;
}

/// Where the core's log lines go (os_log). The core never logs secrets.
#[uniffi::export(with_foreign)]
pub trait LogSink: Send + Sync {
    /// One log line; `target` names the module, e.g. `"ov_sync"`.
    fn log(&self, level: core_host::Level, target: String, msg: String);
}

/// The platform services the core runs on (`ov_core::host::Host`).
#[derive(uniffi::Object)]
pub struct Host(pub(crate) core_host::Host);

#[uniffi::export]
impl Host {
    /// Bundles the five host implementations.
    #[uniffi::constructor]
    pub fn new(
        http: Arc<dyn HttpTransport>,
        store: Arc<dyn SecureStore>,
        cache: Arc<dyn BlobCache>,
        clock: Arc<dyn Clock>,
        log: Arc<dyn LogSink>,
    ) -> Arc<Self> {
        Arc::new(Host(core_host::Host {
            http: Arc::new(HttpAdapter(http)),
            store: Arc::new(StoreAdapter(store)),
            cache: Arc::new(CacheAdapter(cache)),
            clock: Arc::new(ClockAdapter(clock)),
            log: Arc::new(LogAdapter(log)),
        }))
    }
}

// ------------------------------------------------------------------------------ adapters

struct HttpAdapter(Arc<dyn HttpTransport>);

#[async_trait::async_trait]
impl core_host::HttpTransport for HttpAdapter {
    async fn send(&self, req: core_host::HttpRequest) -> Result<core_host::HttpResponse, core_host::TransportError> {
        Ok(self.0.send(req.into()).await?.into())
    }

    async fn open_stream(
        &self,
        req: core_host::HttpRequest,
    ) -> Result<Box<dyn core_host::ByteStream>, core_host::TransportError> {
        Ok(Box::new(StreamAdapter(self.0.open_stream(req.into()).await?.stream)))
    }
}

struct StreamAdapter(Arc<dyn ByteStream>);

#[async_trait::async_trait]
impl core_host::ByteStream for StreamAdapter {
    fn status(&self) -> u16 {
        self.0.status()
    }

    async fn next_chunk(&self) -> Result<Option<Vec<u8>>, core_host::TransportError> {
        Ok(self.0.next_chunk().await?)
    }

    fn close(&self) {
        self.0.close()
    }
}

struct StoreAdapter(Arc<dyn SecureStore>);

#[async_trait::async_trait]
impl core_host::SecureStore for StoreAdapter {
    async fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ov_error::OvError> {
        Ok(self.0.get(key.to_string()).await?.map(Zeroizing::new))
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), ov_error::OvError> {
        Ok(self.0.set(key.to_string(), value.to_vec()).await?)
    }

    async fn delete(&self, key: &str) -> Result<(), ov_error::OvError> {
        Ok(self.0.delete(key.to_string()).await?)
    }
}

struct CacheAdapter(Arc<dyn BlobCache>);

#[async_trait::async_trait]
impl core_host::BlobCache for CacheAdapter {
    async fn load(&self, user_id: &str, vault_id: &str) -> Result<Option<core_host::CachedVault>, ov_error::OvError> {
        Ok(self.0.load(user_id.into(), vault_id.into()).await?)
    }

    async fn save(&self, user_id: &str, vault_id: &str, v: &core_host::CachedVault) -> Result<(), ov_error::OvError> {
        Ok(self.0.save(user_id.into(), vault_id.into(), v.clone()).await?)
    }

    async fn remove(&self, user_id: &str, vault_id: &str) -> Result<(), ov_error::OvError> {
        Ok(self.0.remove(user_id.into(), vault_id.into()).await?)
    }

    async fn list(&self, user_id: &str) -> Result<Vec<String>, ov_error::OvError> {
        Ok(self.0.list(user_id.into()).await?)
    }

    async fn load_meta(&self, user_id: &str, name: &str) -> Result<Option<Vec<u8>>, ov_error::OvError> {
        Ok(self.0.load_meta(user_id.into(), name.into()).await?)
    }

    async fn save_meta(&self, user_id: &str, name: &str, value: &[u8]) -> Result<(), ov_error::OvError> {
        Ok(self.0.save_meta(user_id.into(), name.into(), value.to_vec()).await?)
    }

    async fn clear_user(&self, user_id: &str) -> Result<(), ov_error::OvError> {
        Ok(self.0.clear_user(user_id.into()).await?)
    }
}

struct ClockAdapter(Arc<dyn Clock>);

impl core_host::Clock for ClockAdapter {
    fn now_unix_ms(&self) -> i64 {
        self.0.now_unix_ms()
    }
}

struct LogAdapter(Arc<dyn LogSink>);

impl core_host::LogSink for LogAdapter {
    fn log(&self, level: core_host::Level, target: &str, msg: &str) {
        self.0.log(level, target.to_string(), msg.to_string())
    }
}
