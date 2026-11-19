//! [`SelfHosted`] (SPEC §13 `standalone` mode), a port of the SDK's `self-hosted.ts`: a device token
//! from a pairing code, kept in the SecureStore under `selfhosted:<url>`, and the legacy routes.
//! Whole-database sync and the `event: database` stream go through `ov-sync`.

use std::sync::Arc;

use ov_error::OvError;
use ov_protocol::sync::{parse_health, parse_list_databases, parse_pairing_claim, parse_pairing_code, SyncApi};
use zeroize::Zeroizing;

use super::convert::blob_meta;
use super::net::send;
use super::util::lock;
use crate::api::{BlobMeta, CancelToken, KdbxCredentials, OvClient, PairingCode, SelfHosted, Vault, VaultVersion};
use crate::state::{SelfHostedState, VaultSource};

/// The SecureStore key of a paired server (TS `SelfHostedSync.tokenKey`).
pub(crate) fn token_key(url: &str) -> String {
    format!("selfhosted:{}", url.trim().trim_end_matches('/'))
}

impl SelfHosted {
    pub(crate) fn new_impl(
        client: OvClient,
        server_url: String,
        token: Zeroizing<String>,
    ) -> Result<SelfHosted, OvError> {
        let sync = SyncApi::self_hosted(&server_url)?;
        Ok(SelfHosted { inner: Arc::new(SelfHostedState { client: client.inner, server_url, sync, token }) })
    }

    pub(crate) async fn pair_impl(
        client: OvClient,
        server_url: String,
        code: &str,
        device_name: &str,
        cancel: &CancelToken,
    ) -> Result<SelfHosted, OvError> {
        let sync = SyncApi::self_hosted(&server_url)?;
        let host = client.inner.host.clone();
        let claim = parse_pairing_claim(&send(&host, sync.build_claim_pairing_code(code, device_name), cancel).await?)?;
        let stored = Zeroizing::new(super::util::to_json(&claim));
        host.store.set(&token_key(&server_url), &stored).await?;
        SelfHosted::new_impl(client, server_url, Zeroizing::new(claim.token))
    }

    pub(crate) async fn restore_impl(client: OvClient, server_url: String) -> Result<Option<SelfHosted>, OvError> {
        let Some(raw) = client.inner.host.store.get(&token_key(&server_url)).await? else { return Ok(None) };
        let token = serde_json::from_slice::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("token").and_then(|t| t.as_str()).map(|t| Zeroizing::new(t.to_owned())));
        match token {
            Some(t) => SelfHosted::new_impl(client, server_url, t).map(Some),
            None => Ok(None),
        }
    }

    pub(crate) async fn health_impl(&self, cancel: &CancelToken) -> Result<String, OvError> {
        Ok(parse_health(&send(&self.inner.client.host, self.inner.sync.build_health(), cancel).await?)?.to_string())
    }

    pub(crate) async fn list_impl(&self, cancel: &CancelToken) -> Result<Vec<BlobMeta>, OvError> {
        let req = self.inner.sync.build_list_databases(&self.inner.token);
        Ok(parse_list_databases(&send(&self.inner.client.host, req, cancel).await?)?.iter().map(blob_meta).collect())
    }

    fn sync_client(&self) -> ov_sync::SyncClient {
        let h = &self.inner.client.host;
        ov_sync::SyncClient::new(
            h.http.clone(),
            h.clock.clone(),
            self.inner.sync.clone(),
            Arc::new(ov_sync::StaticToken(Some(self.inner.token.to_string()))),
        )
    }

    pub(crate) async fn history_impl(
        &self,
        database_id: &str,
        cancel: &CancelToken,
    ) -> Result<Vec<VaultVersion>, OvError> {
        cancel.check()?;
        let list = self.sync_client().database(database_id).history().await?;
        Ok(super::vaults::versions(list))
    }

    pub(crate) async fn open_version_impl(
        &self,
        database_id: &str,
        revision: u64,
        credentials: KdbxCredentials,
        cancel: &CancelToken,
    ) -> Result<Vault, OvError> {
        let rev = i64::try_from(revision)
            .map_err(|_| OvError::new(ov_error::OvErrorCode::InvalidRequest, "revision out of range"))?;
        let key = super::vaults::local_key(&credentials)?;
        cancel.check()?;
        let r = self.sync_client().database(database_id).revision(rev).await?;
        cancel.check()?;
        let db = ov_kdbx::read(&r.data, &key)?;
        let host = self.inner.client.host.clone();
        let v = super::vaults::new_vault(VaultSource::Version { info: None }, Some(host), db, false, None);
        *lock(&v.inner.etag) = Some(r.version.etag);
        Ok(v)
    }

    pub(crate) async fn pairing_code_impl(&self, cancel: &CancelToken) -> Result<PairingCode, OvError> {
        let req = self.inner.sync.build_create_pairing_code(&self.inner.token);
        let c = parse_pairing_code(&send(&self.inner.client.host, req, cancel).await?)?;
        Ok(PairingCode { code: c.code, expires_at: c.expires_at })
    }
}
