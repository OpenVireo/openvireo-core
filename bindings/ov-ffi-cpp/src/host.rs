//! Adapters from the C++ Host classes (`include/host.h`) to the core's Host traits.
//!
//! The C++ methods are synchronous; each async trait method calls straight through and is ready
//! on its first poll. C++ exceptions become `OvError`s (`host_exception`); transport failures come
//! back through `TransportFailure`.

use std::sync::Arc;

use cxx::UniquePtr;
use ov_core::host as h;
use ov_error::OvError;
use zeroize::Zeroizing;

use crate::convert;
use crate::edge::host_exception;
use crate::ffi;

// SAFETY: include/host.h requires every implementation to be safe to call from any thread and
// concurrently (the Rust traits are `Send + Sync`), and all methods are `const`. The bridge only
// ever calls them through `&self`.
unsafe impl Send for ffi::HttpTransport {}
unsafe impl Sync for ffi::HttpTransport {}
unsafe impl Send for ffi::ByteStream {}
unsafe impl Sync for ffi::ByteStream {}
unsafe impl Send for ffi::SecureStore {}
unsafe impl Sync for ffi::SecureStore {}
unsafe impl Send for ffi::BlobCache {}
unsafe impl Sync for ffi::BlobCache {}
unsafe impl Send for ffi::Clock {}
unsafe impl Sync for ffi::Clock {}
unsafe impl Send for ffi::LogSink {}
unsafe impl Sync for ffi::LogSink {}

fn non_null<T: cxx::memory::UniquePtrTarget>(p: UniquePtr<T>, what: &str) -> Result<UniquePtr<T>, OvError> {
    if p.is_null() {
        Err(OvError::new(ov_error::OvErrorCode::InvalidRequest, format!("{what} is null")))
    } else {
        Ok(p)
    }
}

/// Builds a core [`h::Host`] from the five C++ objects. Fails with `invalid_request` on a null one.
pub fn host_from_cpp(
    http: UniquePtr<ffi::HttpTransport>,
    store: UniquePtr<ffi::SecureStore>,
    cache: UniquePtr<ffi::BlobCache>,
    clock: UniquePtr<ffi::Clock>,
    log: UniquePtr<ffi::LogSink>,
) -> Result<h::Host, OvError> {
    Ok(h::Host {
        http: Arc::new(CppHttp(non_null(http, "http")?)),
        store: Arc::new(CppStore(non_null(store, "store")?)),
        cache: Arc::new(CppCache(non_null(cache, "cache")?)),
        clock: Arc::new(CppClock(non_null(clock, "clock")?)),
        log: Arc::new(CppLog(non_null(log, "log")?)),
    })
}

fn transport_exception(e: cxx::Exception) -> h::TransportError {
    h::TransportError::Other(format!("host: {}", e.what()))
}

struct CppHttp(UniquePtr<ffi::HttpTransport>);

#[async_trait::async_trait]
impl h::HttpTransport for CppHttp {
    async fn send(&self, req: h::HttpRequest) -> Result<h::HttpResponse, h::TransportError> {
        let req = convert::http_request(req);
        let mut failure = convert::no_failure();
        let resp = self.0.send(&req, &mut failure).map_err(transport_exception)?;
        match convert::transport_error(failure) {
            Some(e) => Err(e),
            None => Ok(convert::http_response(resp)),
        }
    }

    async fn open_stream(&self, req: h::HttpRequest) -> Result<Box<dyn h::ByteStream>, h::TransportError> {
        let req = convert::http_request(req);
        let mut failure = convert::no_failure();
        let stream = self.0.open_stream(&req, &mut failure).map_err(transport_exception)?;
        if let Some(e) = convert::transport_error(failure) {
            return Err(e);
        }
        if stream.is_null() {
            return Err(h::TransportError::Other("host: open_stream returned null without a failure".into()));
        }
        Ok(Box::new(CppStream(stream)))
    }
}

struct CppStream(UniquePtr<ffi::ByteStream>);

#[async_trait::async_trait]
impl h::ByteStream for CppStream {
    fn status(&self) -> u16 {
        // A throwing status() has no error channel in the trait; 0 makes the core treat it as failed.
        self.0.status().unwrap_or(0)
    }

    async fn next_chunk(&self) -> Result<Option<Vec<u8>>, h::TransportError> {
        let mut chunk = Vec::new();
        let mut failure = convert::no_failure();
        let more = self.0.next_chunk(&mut chunk, &mut failure).map_err(transport_exception)?;
        match convert::transport_error(failure) {
            Some(e) => Err(e),
            None => Ok(more.then_some(chunk)),
        }
    }

    fn close(&self) {
        // Nothing useful to do with a failure to close.
        let _ = self.0.close();
    }
}

struct CppStore(UniquePtr<ffi::SecureStore>);

#[async_trait::async_trait]
impl h::SecureStore for CppStore {
    async fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, OvError> {
        let mut value = Zeroizing::new(Vec::new());
        let found = self.0.get(key, &mut value).map_err(host_exception)?;
        Ok(found.then_some(value))
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), OvError> {
        self.0.set(key, value).map_err(host_exception)
    }

    async fn delete(&self, key: &str) -> Result<(), OvError> {
        self.0.remove(key).map_err(host_exception)
    }
}

struct CppCache(UniquePtr<ffi::BlobCache>);

#[async_trait::async_trait]
impl h::BlobCache for CppCache {
    async fn load(&self, user_id: &str, vault_id: &str) -> Result<Option<h::CachedVault>, OvError> {
        let mut out = ffi::CachedVault::default();
        let found = self.0.load(user_id, vault_id, &mut out).map_err(host_exception)?;
        Ok(found.then(|| convert::cached_vault_from_ffi(out)))
    }

    async fn save(&self, user_id: &str, vault_id: &str, v: &h::CachedVault) -> Result<(), OvError> {
        self.0.save(user_id, vault_id, &convert::cached_vault_to_ffi(v)).map_err(host_exception)
    }

    async fn remove(&self, user_id: &str, vault_id: &str) -> Result<(), OvError> {
        self.0.remove(user_id, vault_id).map_err(host_exception)
    }

    async fn list(&self, user_id: &str) -> Result<Vec<String>, OvError> {
        self.0.list(user_id).map_err(host_exception)
    }

    async fn load_meta(&self, user_id: &str, name: &str) -> Result<Option<Vec<u8>>, OvError> {
        let mut value = Vec::new();
        let found = self.0.load_meta(user_id, name, &mut value).map_err(host_exception)?;
        Ok(found.then_some(value))
    }

    async fn save_meta(&self, user_id: &str, name: &str, value: &[u8]) -> Result<(), OvError> {
        self.0.save_meta(user_id, name, value).map_err(host_exception)
    }

    async fn clear_user(&self, user_id: &str) -> Result<(), OvError> {
        self.0.clear_user(user_id).map_err(host_exception)
    }
}

struct CppClock(UniquePtr<ffi::Clock>);

impl h::Clock for CppClock {
    fn now_unix_ms(&self) -> i64 {
        // `Clock::now_unix_ms` has no error channel, so a throwing C++
        // clock falls back to the system clock rather than panicking inside the core.
        self.0.now_unix_ms().unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        })
    }
}

struct CppLog(UniquePtr<ffi::LogSink>);

impl h::LogSink for CppLog {
    fn log(&self, level: h::Level, target: &str, msg: &str) {
        // A log line that can't be written is dropped.
        let _ = self.0.log(convert::level(level), target, msg);
    }
}
