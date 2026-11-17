//! A small in-memory Host for the ungated tests: a scripted HTTP transport, a memory SecureStore and
//! BlobCache and a manual clock. The full in-memory servers are W2-E's `ov_testkit::servers`; the
//! gated tests (`cfg(ov_test_servers)`) use those.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ov_core::api::{ClientConfig, DeviceInfo, OpaqueConfig, Platform, ServerConfig};
use ov_core::host::{
    BlobCache, ByteStream, CachedVault, Host, HttpRequest, HttpResponse, HttpTransport, Level, LogSink, SecureStore,
    TransportError,
};
use ov_core::OvError;
use ov_testkit::ManualClock;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct MemStore(pub Mutex<HashMap<String, Vec<u8>>>);

#[async_trait::async_trait]
impl SecureStore for MemStore {
    async fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, OvError> {
        Ok(self.0.lock().unwrap().get(key).cloned().map(Zeroizing::new))
    }
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), OvError> {
        self.0.lock().unwrap().insert(key.into(), value.to_vec());
        Ok(())
    }
    async fn delete(&self, key: &str) -> Result<(), OvError> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemCache {
    vaults: Mutex<HashMap<(String, String), CachedVault>>,
    meta: Mutex<HashMap<(String, String), Vec<u8>>>,
}

#[async_trait::async_trait]
impl BlobCache for MemCache {
    async fn load(&self, u: &str, v: &str) -> Result<Option<CachedVault>, OvError> {
        Ok(self.vaults.lock().unwrap().get(&(u.into(), v.into())).cloned())
    }
    async fn save(&self, u: &str, v: &str, c: &CachedVault) -> Result<(), OvError> {
        self.vaults.lock().unwrap().insert((u.into(), v.into()), c.clone());
        Ok(())
    }
    async fn remove(&self, u: &str, v: &str) -> Result<(), OvError> {
        self.vaults.lock().unwrap().remove(&(u.into(), v.into()));
        Ok(())
    }
    async fn list(&self, u: &str) -> Result<Vec<String>, OvError> {
        Ok(self.vaults.lock().unwrap().keys().filter(|k| k.0 == u).map(|k| k.1.clone()).collect())
    }
    async fn load_meta(&self, u: &str, n: &str) -> Result<Option<Vec<u8>>, OvError> {
        Ok(self.meta.lock().unwrap().get(&(u.into(), n.into())).cloned())
    }
    async fn save_meta(&self, u: &str, n: &str, v: &[u8]) -> Result<(), OvError> {
        self.meta.lock().unwrap().insert((u.into(), n.into()), v.to_vec());
        Ok(())
    }
    async fn clear_user(&self, u: &str) -> Result<(), OvError> {
        self.vaults.lock().unwrap().retain(|k, _| k.0 != u);
        self.meta.lock().unwrap().retain(|k, _| k.0 != u);
        Ok(())
    }
}

pub struct Quiet;
impl LogSink for Quiet {
    fn log(&self, _: Level, _: &str, _: &str) {}
}

pub type Handler = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

/// Answers with a handler and records every request (`METHOD path`).
pub struct Scripted {
    pub handler: Mutex<Handler>,
    pub calls: Mutex<Vec<String>>,
}

impl Scripted {
    pub fn new(h: Handler) -> Arc<Self> {
        Arc::new(Scripted { handler: Mutex::new(h), calls: Mutex::new(vec![]) })
    }
    pub fn set(&self, h: Handler) {
        *self.handler.lock().unwrap() = h;
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl HttpTransport for Scripted {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let path = req.url.split_once("://").map_or(req.url.as_str(), |(_, r)| r);
        let path = &path[path.find('/').unwrap_or(path.len())..];
        self.calls.lock().unwrap().push(format!("{} {path}", req.method.as_str()));
        (self.handler.lock().unwrap())(&req)
    }
    async fn open_stream(&self, _req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
        Err(TransportError::Other("no streams here".into()))
    }
}

pub fn json(status: u16, body: serde_json::Value) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.to_string().into_bytes(),
    })
}

pub fn server_config() -> ServerConfig {
    ServerConfig {
        issuer: "https://auth.example".into(),
        api: "https://auth.example/api/v1".into(),
        sync: "https://sync.example/api/v1".into(),
        jwks_uri: "https://auth.example/.well-known/jwks.json".into(),
        opaque: OpaqueConfig {
            lib: "opaque-ke".into(),
            version: "4.0.1".into(),
            context: "ov-opaque-v1".into(),
            ids: "auth.example".into(),
        },
        kdf_min: None,
        web: Some("https://app.example".into()),
        share: None,
    }
}

pub fn client_config(offline: bool, server: Option<ServerConfig>) -> ClientConfig {
    ClientConfig { device: DeviceInfo { id: None, name: "test".into(), platform: Platform::Cli }, offline, server }
}

pub struct TestDevice {
    pub host: Host,
    pub http: Arc<Scripted>,
    pub store: Arc<MemStore>,
    pub cache: Arc<MemCache>,
    pub clock: Arc<ManualClock>,
}

pub fn device(handler: Handler) -> TestDevice {
    let http = Scripted::new(handler);
    let store = Arc::new(MemStore::default());
    let cache = Arc::new(MemCache::default());
    let clock = Arc::new(ManualClock::new(1_763_200_000_000));
    let host = Host {
        http: http.clone(),
        store: store.clone(),
        cache: cache.clone(),
        clock: clock.clone(),
        log: Arc::new(Quiet),
    };
    TestDevice { host, http, store, cache, clock }
}

/// An unsigned JWT-shaped token with `exp` (the core only decodes it).
pub fn jwt(claims: serde_json::Value) -> String {
    use base64::Engine as _;
    let b = |v: &serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    format!("{}.{}.sig", b(&serde_json::json!({"alg": "EdDSA"})), b(&claims))
}
