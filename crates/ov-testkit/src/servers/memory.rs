//! In-memory Host parts: a [`SecureStore`], a [`BlobCache`], a silent [`LogSink`], and the
//! event-stream body ([`ByteStream`]) the sync server hands out.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Poll, Waker};

use ov_error::OvError;
use ov_host::{BlobCache, ByteStream, CachedVault, Level, LogSink, SecureStore, TransportError};
use zeroize::Zeroizing;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A [`SecureStore`] in memory (one per simulated device). Values are wiped when dropped.
#[derive(Default)]
pub struct MemoryStore {
    map: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The keys stored now, sorted (to check what a client persisted, without reading values).
    pub fn keys(&self) -> Vec<String> {
        lock(&self.map).keys().cloned().collect()
    }
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStore").field("keys", &self.keys()).finish()
    }
}

#[async_trait::async_trait]
impl SecureStore for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, OvError> {
        Ok(lock(&self.map).get(key).cloned())
    }
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), OvError> {
        lock(&self.map).insert(key.to_string(), Zeroizing::new(value.to_vec()));
        Ok(())
    }
    async fn delete(&self, key: &str) -> Result<(), OvError> {
        lock(&self.map).remove(key);
        Ok(())
    }
}

/// A [`BlobCache`] in memory (one per simulated device).
#[derive(Default)]
pub struct MemoryCache {
    vaults: Mutex<BTreeMap<(String, String), CachedVault>>,
    meta: Mutex<BTreeMap<(String, String), Vec<u8>>>,
}

impl MemoryCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The `(user_id, vault_id)` pairs cached now.
    pub fn vault_keys(&self) -> Vec<(String, String)> {
        lock(&self.vaults).keys().cloned().collect()
    }

    /// The `(user_id, name)` meta records cached now.
    pub fn meta_keys(&self) -> Vec<(String, String)> {
        lock(&self.meta).keys().cloned().collect()
    }
}

impl std::fmt::Debug for MemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCache").field("vaults", &self.vault_keys()).field("meta", &self.meta_keys()).finish()
    }
}

#[async_trait::async_trait]
impl BlobCache for MemoryCache {
    async fn load(&self, user_id: &str, vault_id: &str) -> Result<Option<CachedVault>, OvError> {
        Ok(lock(&self.vaults).get(&(user_id.into(), vault_id.into())).cloned())
    }
    async fn save(&self, user_id: &str, vault_id: &str, v: &CachedVault) -> Result<(), OvError> {
        lock(&self.vaults).insert((user_id.into(), vault_id.into()), v.clone());
        Ok(())
    }
    async fn remove(&self, user_id: &str, vault_id: &str) -> Result<(), OvError> {
        lock(&self.vaults).remove(&(user_id.into(), vault_id.into()));
        Ok(())
    }
    async fn list(&self, user_id: &str) -> Result<Vec<String>, OvError> {
        Ok(lock(&self.vaults).keys().filter(|(u, _)| u == user_id).map(|(_, v)| v.clone()).collect())
    }
    async fn load_meta(&self, user_id: &str, name: &str) -> Result<Option<Vec<u8>>, OvError> {
        Ok(lock(&self.meta).get(&(user_id.into(), name.into())).cloned())
    }
    async fn save_meta(&self, user_id: &str, name: &str, value: &[u8]) -> Result<(), OvError> {
        lock(&self.meta).insert((user_id.into(), name.into()), value.to_vec());
        Ok(())
    }
    async fn clear_user(&self, user_id: &str) -> Result<(), OvError> {
        lock(&self.vaults).retain(|(u, _), _| u != user_id);
        lock(&self.meta).retain(|(u, _), _| u != user_id);
        Ok(())
    }
}

/// A [`LogSink`] that drops every line.
#[derive(Debug, Default, Clone, Copy)]
pub struct SilentLog;

impl LogSink for SilentLog {
    fn log(&self, _level: Level, _target: &str, _msg: &str) {}
}

// ------------------------------------------------------------------------------------ streams

#[derive(Default)]
struct StreamInner {
    queue: VecDeque<Vec<u8>>,
    closed: bool,
    waker: Option<Waker>,
}

/// The server side of an open event stream: the server pushes chunks, the client reads them.
#[derive(Default)]
pub(crate) struct StreamPipe {
    inner: Mutex<StreamInner>,
}

impl StreamPipe {
    pub fn push(&self, chunk: Vec<u8>) {
        let mut s = lock(&self.inner);
        if s.closed {
            return;
        }
        s.queue.push_back(chunk);
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }

    /// Ends the stream after the queued chunks.
    pub fn close(&self) {
        let mut s = lock(&self.inner);
        s.closed = true;
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }

    pub fn is_closed(&self) -> bool {
        lock(&self.inner).closed
    }
}

/// The client side: a [`ByteStream`] over a [`StreamPipe`].
pub(crate) struct PipeStream {
    pub status: u16,
    pub pipe: Arc<StreamPipe>,
}

#[async_trait::async_trait]
impl ByteStream for PipeStream {
    fn status(&self) -> u16 {
        self.status
    }

    async fn next_chunk(&self) -> Result<Option<Vec<u8>>, TransportError> {
        std::future::poll_fn(|cx| {
            let mut s = lock(&self.pipe.inner);
            if let Some(chunk) = s.queue.pop_front() {
                return Poll::Ready(Ok(Some(chunk)));
            }
            if s.closed {
                return Poll::Ready(Ok(None));
            }
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    fn close(&self) {
        let mut s = lock(&self.pipe.inner);
        s.closed = true;
        s.queue.clear();
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
}
