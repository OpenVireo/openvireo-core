//! The sync server client over the Host's HTTP (TS `SyncClient` / `BlobHandle`): ov-protocol builds
//! the requests and reads the responses; this sends them, adds the bearer token, retries once with
//! a fresh token after a 401 (refreshable sources only) and measures the clock offset from `Date`.

use std::sync::{Arc, Mutex};

use ov_error::OvError;
use ov_host::{Clock, HttpRequest, HttpResponse, HttpTransport, MaybeSend, MaybeSync};
use ov_protocol::sync::{self as proto, BlobPath, GetResult, HeadResult, PutCondition, PutResult, Revision, SyncApi};
use ov_protocol::types::{BlobMeta, PairingClaim, PairingCode};

/// Where access tokens come from: a fixed device token, or the account's token manager.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait TokenSource: MaybeSend + MaybeSync {
    /// The bearer token to send (`None`: no `Authorization` header). `force_refresh` asks for a new
    /// one after the server rejected the last (TS `getAccessToken({ force })`).
    async fn access_token(&self, force_refresh: bool) -> Result<Option<String>, OvError>;

    /// Whether [`access_token`](Self::access_token) can return a fresh token, so a 401 is worth
    /// one retry. A fixed device token can't.
    fn refreshable(&self) -> bool {
        true
    }
}

/// A fixed token (a legacy device token), or none.
#[derive(Clone, Default)]
pub struct StaticToken(pub Option<String>);

impl std::fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StaticToken").field(&self.0.as_ref().map(|_| "<redacted>")).finish()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TokenSource for StaticToken {
    async fn access_token(&self, _force_refresh: bool) -> Result<Option<String>, OvError> {
        Ok(self.0.clone())
    }
    fn refreshable(&self) -> bool {
        false
    }
}

/// A sync server client. Cheap to clone; clones share the measured clock offset.
#[derive(Clone)]
pub struct SyncClient {
    http: Arc<dyn HttpTransport>,
    clock: Arc<dyn Clock>,
    api: SyncApi,
    token: Arc<dyn TokenSource>,
    offset: Arc<Mutex<Option<i64>>>,
}

impl std::fmt::Debug for SyncClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncClient").field("base_url", &self.api.base_url()).finish_non_exhaustive()
    }
}

impl SyncClient {
    /// A client for `api` (`SyncApi::new(sync)` or `SyncApi::self_hosted(url)`).
    pub fn new(http: Arc<dyn HttpTransport>, clock: Arc<dyn Clock>, api: SyncApi, token: Arc<dyn TokenSource>) -> Self {
        SyncClient { http, clock, api, token, offset: Arc::new(Mutex::new(None)) }
    }

    /// The request builders.
    pub fn api(&self) -> &SyncApi {
        &self.api
    }

    /// The transport.
    pub fn http(&self) -> &Arc<dyn HttpTransport> {
        &self.http
    }

    /// The clock.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The token source.
    pub fn token_source(&self) -> &Arc<dyn TokenSource> {
        &self.token
    }

    /// How far this device's clock is ahead of the server's in milliseconds (negative: behind), from
    /// the `Date` header of the last response that had a readable one; `None` until then.
    pub fn clock_offset_ms(&self) -> Option<i64> {
        *self.offset.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn go(&self, req: HttpRequest) -> Result<HttpResponse, OvError> {
        let res = self.http.send(req).await.map_err(OvError::from)?;
        if let Some(server) = proto::server_time_ms(&res) {
            *self.offset.lock().unwrap_or_else(|p| p.into_inner()) = Some(self.clock.now_unix_ms() - server);
        }
        Ok(res)
    }

    /// Sends the request `build` makes with the current token; after a 401 from a refreshable
    /// source, once more with a fresh token (TS `SyncClient.request`).
    pub async fn send<F>(&self, build: F) -> Result<HttpResponse, OvError>
    where
        F: Fn(Option<&str>) -> HttpRequest + MaybeSend + MaybeSync,
    {
        let token = self.token.access_token(false).await?;
        let res = self.go(build(token.as_deref())).await?;
        if res.status == 401 && self.token.refreshable() {
            let token = self.token.access_token(true).await?;
            return self.go(build(token.as_deref())).await;
        }
        Ok(res)
    }

    /// `vaults/<id>` (JWT routes).
    pub fn vault(&self, id: &str) -> Blob {
        Blob { client: self.clone(), path: BlobPath::vault(id) }
    }

    /// `databases/<id>` (legacy device-token routes).
    pub fn database(&self, id: &str) -> Blob {
        Blob { client: self.clone(), path: BlobPath::database(id) }
    }

    /// `GET vaults`.
    pub async fn list_vaults(&self) -> Result<Vec<BlobMeta>, OvError> {
        let res = self.send(|t| self.api.build_list_vaults(t.unwrap_or_default())).await?;
        proto::parse_list_vaults(&res)
    }

    /// `GET databases`.
    pub async fn list_databases(&self) -> Result<Vec<BlobMeta>, OvError> {
        let res = self.send(|t| self.api.build_list_databases(t.unwrap_or_default())).await?;
        proto::parse_list_databases(&res)
    }

    /// `GET health`.
    pub async fn health(&self) -> Result<serde_json::Value, OvError> {
        proto::parse_health(&self.go(self.api.build_health()).await?)
    }

    /// `POST devices/pairing`: a code another device of the same user can claim.
    pub async fn create_pairing_code(&self) -> Result<PairingCode, OvError> {
        let res = self.send(|t| self.api.build_create_pairing_code(t.unwrap_or_default())).await?;
        proto::parse_pairing_code(&res)
    }

    /// `POST devices/pairing/claim` (no token; the code is the credential).
    pub async fn claim_pairing_code(&self, code: &str, device_name: &str) -> Result<PairingClaim, OvError> {
        proto::parse_pairing_claim(&self.go(self.api.build_claim_pairing_code(code, device_name)).await?)
    }
}

/// One blob: `vaults/<id>` or `databases/<id>` (TS `BlobHandle`).
#[derive(Clone, Debug)]
pub struct Blob {
    client: SyncClient,
    path: BlobPath,
}

impl Blob {
    /// The client.
    pub fn client(&self) -> &SyncClient {
        &self.client
    }

    /// The path.
    pub fn path(&self) -> &BlobPath {
        &self.path
    }

    /// The client's clock offset (see [`SyncClient::clock_offset_ms`]).
    pub fn clock_offset_ms(&self) -> Option<i64> {
        self.client.clock_offset_ms()
    }

    /// `HEAD`, optionally `If-None-Match`.
    pub async fn head(&self, if_none_match: Option<&str>) -> Result<HeadResult, OvError> {
        let api = &self.client.api;
        let res = self.client.send(|t| api.build_blob_head(&self.path, t, if_none_match)).await?;
        proto::parse_blob_head(&res)
    }

    /// `GET`, optionally `If-None-Match`.
    pub async fn get(&self, if_none_match: Option<&str>) -> Result<GetResult, OvError> {
        let api = &self.client.api;
        let res = self.client.send(|t| api.build_blob_get(&self.path, t, if_none_match)).await?;
        proto::parse_blob_get(&res)
    }

    /// Conditional `PUT`; a mismatch is `precondition_failed` (412).
    pub async fn put(&self, data: &[u8], cond: &PutCondition) -> Result<PutResult, OvError> {
        let api = &self.client.api;
        let res = self.client.send(|t| api.build_blob_put(&self.path, t, data.to_vec(), cond)).await?;
        proto::parse_blob_put(&res)
    }

    /// `DELETE`, optionally `If-Match`.
    pub async fn delete(&self, if_match: Option<&str>) -> Result<(), OvError> {
        let api = &self.client.api;
        let res = self.client.send(|t| api.build_blob_delete(&self.path, t, if_match)).await?;
        proto::parse_blob_delete(&res)
    }

    /// `GET <blob>/history`, newest first.
    pub async fn history(&self) -> Result<Vec<BlobMeta>, OvError> {
        let api = &self.client.api;
        let res = self.client.send(|t| api.build_history(&self.path, t)).await?;
        proto::parse_history(&res)
    }

    /// `GET <blob>/history/<revision>`.
    pub async fn revision(&self, revision: i64) -> Result<Revision, OvError> {
        let api = &self.client.api;
        let res = self.client.send(|t| api.build_revision(&self.path, t, revision)).await?;
        proto::parse_revision(&res)
    }
}
