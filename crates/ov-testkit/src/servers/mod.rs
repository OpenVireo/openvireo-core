//! In-memory auth and sync servers behind one [`ov_host::HttpTransport`], for tests of ov-sync,
//! ov-core and the bindings. Ported from the TS SDK's `src/testing/{auth-server,sync-server,mock-fetch}.ts`
//! (`@openvireo/sdk/testing`), following `openapi.yaml` and `sync-openapi.yaml`.
//!
//! ```no_run
//! use std::sync::Arc;
//! use ov_testkit::{servers::TestServers, ManualClock};
//!
//! let servers = TestServers::new(Arc::new(ManualClock::new(1_794_744_000_000)));
//! let host = servers.host();               // a new device: fresh SecureStore and BlobCache
//! let issuer = servers.issuer();           // "https://auth.test": discovery points at sync_url()
//! let sync = servers.sync_url();           // "https://sync.test/api/v1"
//! # let _ = (host, issuer, sync);
//! ```
//!
//! What they do, briefly:
//!
//! - **Auth server** (`https://auth.test`): every client route of `openapi.yaml`, OPAQUE through
//!   opaque-ke's server side (one `ServerSetup` per user, as libopaque's per-user keypair; unknown
//!   emails get a fake record), real EdDSA access tokens (SPEC §9 claims incl. `vlt`, `del`) with a
//!   JWKS, rotating refresh tokens with reuse detection and the 60-second grace, TOTP, orgs,
//!   invitations, vault access and rotation, service accounts, share links, recovery and restore,
//!   account deletion, audit and Apple billing.
//! - **Sync server** (`https://sync.test/api/v1`): the JWT `vaults/*` routes with `ETag`, revisions,
//!   412/428, history and quota (`q` in `vlt`); the legacy device-token `databases/*`, pairing and
//!   health routes; `GET /events` (SSE) with `vault`, `access` and `database` events; the internal
//!   routes.
//! - **Time** comes from the [`ManualClock`] (plus an optional server skew), so
//!   token expiry, refresh-token lifetime, share expiry and recovery delays follow the test.
//! - **Faults**: offline, injected statuses, rate limits, transport errors ([`FaultRule`]); a
//!   rolled-back or lost sync database; another device's upload between a GET and a PUT
//!   ([`TestServers::set_after_get`]); clock skew.
//!
//! The servers are deterministic: ids, keys and nonces come from a seeded RNG
//! ([`TestServers::with_seed`]).

use std::sync::{Arc, Mutex, MutexGuard};

use ov_host::{ByteStream, Host, HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::Value;

use crate::ManualClock;

mod auth;
mod helpers;
mod http;
mod memory;
mod sync;
#[cfg(test)]
mod tests;

pub use memory::{MemoryCache, MemoryStore, SilentLog};

use http::{code_for_status, error, http_date, Req};

/// The auth server's host.
pub const AUTH_HOST: &str = "auth.test";
/// The sync server's host.
pub const SYNC_HOST: &str = "sync.test";
/// The device token the sync server's legacy `databases/*` routes accept from the start.
pub const DEVICE_TOKEN: &str = "dev-token";
/// A pairing code the sync server accepts once (it pairs a device as `alice`, token `dev-token-2`).
pub const PAIRING_CODE: &str = "ABCD-EFGH";
/// The bearer token of the sync server's `/internal/*` routes (`SYNC_INTERNAL_TOKEN`).
pub const INTERNAL_TOKEN: &str = "internal-token";
/// The OPAQUE context (SPEC §8).
pub const OPAQUE_CONTEXT: &str = "ov-opaque-v1";

/// Which server a request reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Server {
    /// `https://auth.test`.
    Auth,
    /// `https://sync.test`.
    Sync,
}

impl Server {
    fn name(self) -> &'static str {
        match self {
            Server::Auth => "auth",
            Server::Sync => "sync",
        }
    }
}

/// What an injected fault does instead of reaching the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// `Err(TransportError::Offline)`.
    Offline,
    /// Any transport error.
    Transport(TransportError),
    /// That status, with the usual `{error, code}` body (500 → `server_error`, 412 →
    /// `precondition_failed`, ...).
    Status(u16),
    /// 429 `rate_limited` with `Retry-After: <seconds>`.
    RateLimited {
        /// Seconds.
        retry_after: u32,
    },
    /// Exactly this response.
    Response(HttpResponse),
}

/// When a [`Fault`] applies: every condition left unset matches anything. It applies to the next
/// `times` matching requests (default 1), then it is gone.
#[derive(Clone, Debug)]
pub struct FaultRule {
    fault: Fault,
    server: Option<Server>,
    method: Option<Method>,
    path: Option<String>,
    times: usize,
}

impl FaultRule {
    /// The fault for the next request of any kind.
    pub fn new(fault: Fault) -> Self {
        FaultRule { fault, server: None, method: None, path: None, times: 1 }
    }
    /// Only requests to this server.
    pub fn server(mut self, server: Server) -> Self {
        self.server = Some(server);
        self
    }
    /// Only requests with this method.
    pub fn method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }
    /// Only requests whose URL path contains this text (e.g. `"/vaults/"`, `"/auth/refresh"`).
    pub fn path(mut self, contains: &str) -> Self {
        self.path = Some(contains.to_string());
        self
    }
    /// For the next `n` matching requests.
    pub fn times(mut self, n: usize) -> Self {
        self.times = n;
        self
    }

    fn matches(&self, server: Server, method: Method, path: &str) -> bool {
        self.times > 0
            && self.server.is_none_or(|s| s == server)
            && self.method.is_none_or(|m| m == method)
            && self.path.as_deref().is_none_or(|p| path.contains(p))
    }
}

/// One request the servers saw (never its headers or body, which may hold secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// Which server.
    pub server: Server,
    /// Method.
    pub method: Method,
    /// The URL path, e.g. `/api/v1/vaults/x`.
    pub path: String,
    /// The route that answered, as `"<server> <METHOD> <pattern>"` with the contract's names, e.g.
    /// `"sync PUT /vaults/{vault}"`; `None` for a fault or an unknown route.
    pub route: Option<String>,
    /// The response status; `None` when a transport fault answered.
    pub status: Option<u16>,
}

/// A vault or database blob as the sync server holds it now.
#[derive(Clone, PartialEq, Eq)]
pub struct BlobData {
    /// The bytes.
    pub data: Vec<u8>,
    /// Quoted hex SHA-256.
    pub etag: String,
    /// Revision, from 1.
    pub revision: i64,
}

impl std::fmt::Debug for BlobData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobData")
            .field("len", &self.data.len())
            .field("etag", &self.etag)
            .field("revision", &self.revision)
            .finish()
    }
}

/// A hook run after the sync server answers a vault or database GET with 200, before the client
/// can PUT ([`TestServers::set_after_get`]). It gets the servers and the vault or database id.
pub type AfterGet = Arc<dyn Fn(&TestServers, &str) + Send + Sync>;

/// Everything both servers keep, behind one lock.
pub(crate) struct World {
    pub clock: Arc<ManualClock>,
    pub skew_ms: i64,
    pub rng: ChaCha20Rng,
    pub offline: bool,
    pub faults: Vec<FaultRule>,
    pub requests: Vec<Recorded>,
    /// The sync server checks the auth server's live access instead of the token's `vlt`.
    pub live_access: bool,
    pub auth: auth::AuthState,
    pub sync: sync::SyncState,
}

impl World {
    /// The servers' clock: the test clock plus the skew.
    pub fn now_ms(&self) -> i64 {
        self.clock.now_unix_ms() + self.skew_ms
    }
    pub fn now_s(&self) -> i64 {
        self.now_ms().div_euclid(1000)
    }
    pub fn random_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut b = vec![0; n];
        self.rng.fill_bytes(&mut b);
        b
    }
    /// A random (v4) UUID.
    pub fn uuid(&mut self) -> String {
        let mut b = self.random_bytes(16);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h = hex::encode(b);
        format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
    }
}

struct Shared {
    world: Mutex<World>,
    after_get: Mutex<Option<AfterGet>>,
}

/// The in-memory auth server and sync server. Cheap to clone; clones share the servers.
#[derive(Clone)]
pub struct TestServers {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for TestServers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestServers { .. }")
    }
}

/// The default RNG seed of [`TestServers::new`].
pub const DEFAULT_SEED: [u8; 32] = *b"openvireo-core test servers seed";

impl TestServers {
    /// Both servers on `clock`, with the [`DEFAULT_SEED`].
    pub fn new(clock: Arc<ManualClock>) -> Self {
        Self::with_seed(clock, DEFAULT_SEED)
    }

    /// Both servers on `clock`, with their ids and keys drawn from `seed`.
    pub fn with_seed(clock: Arc<ManualClock>, seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let auth = auth::AuthState::new(&mut rng);
        let world = World {
            clock,
            skew_ms: 0,
            rng,
            offline: false,
            faults: vec![],
            requests: vec![],
            live_access: false,
            auth,
            sync: sync::SyncState::new(),
        };
        TestServers { shared: Arc::new(Shared { world: Mutex::new(world), after_get: Mutex::new(None) }) }
    }

    pub(crate) fn world(&self) -> MutexGuard<'_, World> {
        self.shared.world.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // -------------------------------------------------------------------------------- the Host

    /// The transport: `https://auth.test/…` reaches the auth server, `https://sync.test/…` the sync
    /// server, and any other host fails with [`TransportError::Offline`] (as a DNS failure would).
    pub fn http(&self) -> Arc<dyn HttpTransport> {
        Arc::new(self.clone())
    }

    /// A Host for a new device: [`http`](Self::http), a fresh [`MemoryStore`] and [`MemoryCache`],
    /// the servers' [`ManualClock`] (without the server skew) and a [`SilentLog`]. Call it again for
    /// a second device on the same servers.
    pub fn host(&self) -> Host {
        self.host_with(Arc::new(MemoryStore::new()), Arc::new(MemoryCache::new()))
    }

    /// A Host with the given store and cache (to keep a device's storage across "restarts").
    pub fn host_with(&self, store: Arc<MemoryStore>, cache: Arc<MemoryCache>) -> Host {
        Host { http: self.http(), store, cache, clock: self.clock(), log: Arc::new(SilentLog) }
    }

    /// The test clock.
    pub fn clock(&self) -> Arc<ManualClock> {
        self.world().clock.clone()
    }

    /// The issuer: `https://auth.test`. Its discovery document (SPEC §10) names [`api_url`](Self::api_url)
    /// and [`sync_url`](Self::sync_url).
    pub fn issuer(&self) -> String {
        format!("https://{AUTH_HOST}")
    }

    /// `{api}`: `https://auth.test/api/v1`.
    pub fn api_url(&self) -> String {
        format!("https://{AUTH_HOST}/api/v1")
    }

    /// `{sync}`, the discovery document's `sync`: `https://sync.test/api/v1`. It already ends in
    /// `/api/v1`, so `SyncApi::new(&sync_url())` works (and so does `SyncApi::self_hosted("https://sync.test")`).
    pub fn sync_url(&self) -> String {
        format!("https://{SYNC_HOST}/api/v1")
    }

    /// The discovery document the auth server serves.
    pub fn discovery(&self) -> ov_protocol::discovery::OpenVireoConfiguration {
        auth::configuration()
    }

    // -------------------------------------------------------------------------------- faults

    /// While `true`, every request fails with [`TransportError::Offline`].
    pub fn set_offline(&self, offline: bool) {
        self.world().offline = offline;
    }

    /// Answers matching requests with a fault instead of the server (see [`FaultRule`]). Rules
    /// apply in the order they were added.
    pub fn fail_next(&self, rule: FaultRule) {
        self.world().faults.push(rule);
    }

    /// Drops every pending fault rule.
    pub fn clear_faults(&self) {
        self.world().faults.clear();
    }

    /// Moves the servers' clock by `ms` from the test clock (`Date` headers, token times, expiry
    /// checks), to test clock-skew warnings.
    pub fn set_server_clock_skew_ms(&self, ms: i64) {
        self.world().skew_ms = ms;
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<Recorded> {
        self.world().requests.clone()
    }

    /// Forgets the recorded requests.
    pub fn clear_requests(&self) {
        self.world().requests.clear();
    }

    /// `false` (default): the sync server checks vault roles in the token's `vlt` claim, as the real
    /// server does, so a client must refresh its token after an access change. `true`: it checks
    /// the auth server's current access instead (like the TS `world.ts`).
    pub fn set_live_access(&self, live: bool) {
        self.world().live_access = live;
    }

    /// Runs `hook` after every 200 GET of a vault blob or legacy database (not HEAD), before the
    /// client can PUT: the way to simulate another device uploading in between (TS `afterGet`).
    /// The hook gets the vault or database id. `None` removes it.
    pub fn set_after_get(&self, hook: Option<AfterGet>) {
        *self.shared.after_get.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    // -------------------------------------------------------------------------------- transport

    fn dispatch(&self, req: &HttpRequest) -> Result<(HttpResponse, Option<Arc<memory::StreamPipe>>), TransportError> {
        let Some((host, path, query)) = http::split_url(&req.url) else {
            return Err(TransportError::Other(format!("not an absolute URL: {}", req.url)));
        };
        let server = match host.as_str() {
            AUTH_HOST => Server::Auth,
            SYNC_HOST => Server::Sync,
            _ => return Err(TransportError::Offline),
        };
        let mut w = self.world();
        if w.offline {
            w.requests.push(Recorded { server, method: req.method, path, route: None, status: None });
            return Err(TransportError::Offline);
        }
        if let Some(i) = w.faults.iter().position(|f| f.matches(server, req.method, &path)) {
            w.faults[i].times -= 1;
            let fault = w.faults[i].fault.clone();
            if w.faults[i].times == 0 {
                w.faults.remove(i);
            }
            let res = match fault {
                Fault::Offline => Err(TransportError::Offline),
                Fault::Transport(e) => Err(e),
                Fault::Status(s) => Ok(error(s, code_for_status(s), &format!("injected HTTP {s}"))),
                Fault::RateLimited { retry_after } => {
                    let mut r = error(429, "rate_limited", "Too many requests");
                    r.headers.push(("Retry-After".into(), retry_after.to_string()));
                    Ok(r)
                }
                Fault::Response(r) => Ok(r),
            };
            let status = res.as_ref().ok().map(|r| r.status);
            w.requests.push(Recorded { server, method: req.method, path, route: None, status });
            return res.map(|r| (self.finish(&w, req.method, r), None));
        }
        let api_path = path.strip_prefix("/api/v1").filter(|p| p.is_empty() || p.starts_with('/'));
        let r = Req::from_http(req, api_path.map_or_else(|| path.clone(), str::to_string), &query);
        let (route, res, pipe) = match (server, api_path) {
            (Server::Auth, Some(_)) => {
                let (route, res) = auth::handle(&mut w, &r);
                (route, res, None)
            }
            (Server::Auth, None) => {
                let (route, res) = auth::handle_root(&mut w, &r);
                (route, res, None)
            }
            (Server::Sync, Some(_)) => sync::handle(&mut w, &r),
            (Server::Sync, None) => (None, None, None),
        };
        let route = route.map(|r| format!("{} {} {r}", server.name(), req.method.as_str()));
        let res =
            res.unwrap_or_else(|| error(404, "not_found", &format!("no route for {} {}", req.method.as_str(), r.path)));
        let after_get = server == Server::Sync
            && req.method == Method::Get
            && res.status == 200
            && matches!(route.as_deref(), Some("sync GET /vaults/{vault}" | "sync GET /databases/{id}"));
        w.requests.push(Recorded { server, method: req.method, path: path.clone(), route, status: Some(res.status) });
        let res = self.finish(&w, req.method, res);
        drop(w);
        if after_get {
            let hook = self.shared.after_get.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            if let Some(hook) = hook {
                let rest = path.trim_start_matches("/api/v1/");
                let id = http::percent_decode(rest.split_once('/').map_or(rest, |(_, id)| id));
                hook(self, &id);
            }
        }
        Ok((res, pipe))
    }

    /// Adds `Date` and strips HEAD bodies.
    fn finish(&self, w: &World, method: Method, mut res: HttpResponse) -> HttpResponse {
        if !res.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("date")) {
            res.headers.push(("Date".into(), http_date(w.now_ms())));
        }
        if method == Method::Head {
            res.body.clear();
        }
        res
    }
}

#[async_trait::async_trait]
impl HttpTransport for TestServers {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let (res, pipe) = self.dispatch(&req)?;
        if let Some(p) = pipe {
            // A stream route reached through send(): nothing will read it.
            p.close();
        }
        Ok(res)
    }

    async fn open_stream(&self, req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
        let (res, pipe) = self.dispatch(&req)?;
        let pipe = pipe.unwrap_or_else(|| {
            // Not an event stream (an error status, or another route): a stream of the body.
            let p = Arc::new(memory::StreamPipe::default());
            if !res.body.is_empty() {
                p.push(res.body.clone());
            }
            p.close();
            p
        });
        Ok(Box::new(memory::PipeStream { status: res.status, pipe }))
    }
}

/// Runs a future to completion on the current thread (no runtime needed: the servers answer at
/// once, and only event streams wait, for another thread or a later push).
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

/// `Value` helpers shared by the servers.
pub(crate) fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}
