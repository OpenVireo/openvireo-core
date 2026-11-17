//! [`ServiceAccount`] (SPEC §9, §15), a port of the SDK's `service-account.ts`: token → KEK →
//! master key → keyset, the JWT re-exchanged before it expires (SAs have no refresh token), the
//! granted vaults and downloading them. `ov://` reads and writes are `ov-vault`'s (W2-V) and the
//! upload `ov-sync`'s (W2-Y).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ov_crypto::encoding::b64u;
use ov_crypto::keyset::unwrap_keyset;
use ov_crypto::tokens::{parse_sa_token, unwrap_sa_master};
use ov_error::{OvError, OvErrorCode};
use ov_kdbx::vault::open_with_key_versions;
use ov_protocol::auth::{parse_service_account_exchange, parse_vaults, AuthApi};
use ov_protocol::sync::{parse_blob_get, parse_blob_head, BlobPath, GetResult, HeadResult, SyncApi};
use ov_protocol::types::ServiceAccountExchangeRequest;
use zeroize::Zeroizing;

use super::client::discover_raw;
use super::convert::{crypto_wrapped, server_config, wire_config};
use super::net::send;
use super::util::{lock, secret_text, signed_out};
use super::vault_glue::{ingest, VaultEntry};
use super::vaults::new_vault;
use crate::api::{CancelToken, OvClient, SaVault, SecretBytes, ServiceAccount, Vault};
use crate::host::{HttpRequest, HttpResponse};
use crate::state::{SaInner, ServiceAccountState, VaultSource};

const MARGIN_MS: i64 = 60_000;

fn sa_vault(e: &VaultEntry) -> SaVault {
    SaVault { id: e.info.id.clone(), name: e.info.name.clone(), role: e.info.role }
}

impl ServiceAccount {
    pub(crate) async fn from_token_impl(
        client: OvClient,
        token: SecretBytes,
        cancel: &CancelToken,
    ) -> Result<ServiceAccount, OvError> {
        let token = secret_text(token, "service account token")?;
        let t = parse_sa_token(&token)?;
        let config = match &client.inner.config.server {
            Some(c) => c.clone(),
            None => server_config(&discover_raw(&client, &t.url, cancel).await?.0),
        };
        let wire = wire_config(&config);
        let auth = AuthApi::new(&wire.api)?;
        let sync = SyncApi::new(&wire.sync)?;
        let host = &client.inner.host;
        let body = ServiceAccountExchangeRequest { sa_id: t.sa_id.clone(), secret: b64u(&t.secret[..]) };
        let ex =
            parse_service_account_exchange(&send(host, auth.build_service_account_exchange(&body), cancel).await?)?;
        // W2-V: SA master unwrapping (ov_vault) — token KEK → master → keyset.
        let master = unwrap_sa_master(&t.kek, &t.sa_id, &ex.wrapped_master)?;
        let keyset = unwrap_keyset(&master, &crypto_wrapped(&ex.keyset))?;
        let expires = host.clock.now_unix_ms() + ex.expires_in.saturating_mul(1000);
        let state = ServiceAccountState {
            client: client.inner.clone(),
            config,
            auth,
            sync,
            sa_id: t.sa_id.clone(),
            inner: Mutex::new(SaInner {
                keyset: Some(keyset),
                secret: Zeroizing::new(*t.secret),
                access: Some((Zeroizing::new(ex.access_token), expires)),
                vaults: None,
                opened: HashMap::new(),
            }),
            refresh_lock: futures::lock::Mutex::new(()),
        };
        Ok(ServiceAccount { inner: Arc::new(state) })
    }

    fn now(&self) -> i64 {
        self.inner.client.host.clock.now_unix_ms()
    }

    /// The JWT, exchanged again when it is about to expire (or `force`).
    async fn access_token(&self, force: bool, cancel: &CancelToken) -> Result<Zeroizing<String>, OvError> {
        let valid = |g: &SaInner, now: i64| -> Result<Option<Zeroizing<String>>, OvError> {
            if g.keyset.is_none() {
                return Err(signed_out("service account closed"));
            }
            Ok(g.access.as_ref().filter(|(_, at)| at - MARGIN_MS > now).map(|(t, _)| t.clone()))
        };
        if !force {
            if let Some(t) = valid(&lock(&self.inner.inner), self.now())? {
                return Ok(t);
            }
        }
        let seen = lock(&self.inner.inner).access.as_ref().map(|(t, _)| t.clone());
        let _guard = self.inner.refresh_lock.lock().await;
        {
            let g = lock(&self.inner.inner);
            if let (Some((t, _)), Some(old)) = (&g.access, &seen) {
                if t != old {
                    return Ok(t.clone());
                }
            }
        }
        let secret = lock(&self.inner.inner).secret.clone();
        let body = ServiceAccountExchangeRequest { sa_id: self.inner.sa_id.clone(), secret: b64u(&secret[..]) };
        let host = &self.inner.client.host;
        let ex = parse_service_account_exchange(
            &send(host, self.inner.auth.build_service_account_exchange(&body), cancel).await?,
        )?;
        let t = Zeroizing::new(ex.access_token);
        let mut g = lock(&self.inner.inner);
        if g.keyset.is_none() {
            return Err(signed_out("service account closed"));
        }
        g.access = Some((t.clone(), self.now() + ex.expires_in.saturating_mul(1000)));
        Ok(t)
    }

    async fn authed(&self, cancel: &CancelToken, build: impl Fn(&str) -> HttpRequest) -> Result<HttpResponse, OvError> {
        let t = self.access_token(false, cancel).await?;
        let mut res = send(&self.inner.client.host, build(&t), cancel).await?;
        if res.status == 401 {
            let t = self.access_token(true, cancel).await?;
            res = send(&self.inner.client.host, build(&t), cancel).await?;
        }
        Ok(res)
    }

    pub(crate) async fn entries(&self, refresh: bool, cancel: &CancelToken) -> Result<Vec<VaultEntry>, OvError> {
        if !refresh {
            if let Some(v) = &lock(&self.inner.inner).vaults {
                return Ok(v.clone());
            }
        }
        let res = self.authed(cancel, |t| self.inner.auth.build_list_vaults(t)).await?;
        let list = parse_vaults(&res)?;
        let mut g = lock(&self.inner.inner);
        let ks = g.keyset.as_ref().ok_or_else(|| signed_out("service account closed"))?;
        let entries: Vec<VaultEntry> = list.vaults.iter().map(|v| ingest(ks, v)).collect();
        g.vaults = Some(entries.clone());
        Ok(entries)
    }

    pub(crate) async fn entry(&self, id_or_name: &str, cancel: &CancelToken) -> Result<VaultEntry, OvError> {
        let all = self.entries(false, cancel).await?;
        if let Some(e) = all.iter().find(|e| e.info.id == id_or_name) {
            return Ok(e.clone());
        }
        let named: Vec<&VaultEntry> = all.iter().filter(|e| e.info.name == id_or_name).collect();
        if named.len() == 1 {
            return Ok(named[0].clone());
        }
        let msg = if named.is_empty() {
            format!("vault \"{id_or_name}\" not found or not shared with this service account")
        } else {
            format!("{} vaults are named \"{id_or_name}\"", named.len())
        };
        Err(OvError::new(OvErrorCode::NotFound, msg).with_status(404))
    }

    pub(crate) async fn vaults_impl(&self, refresh: bool, cancel: &CancelToken) -> Result<Vec<SaVault>, OvError> {
        Ok(self.entries(refresh, cancel).await?.iter().map(sa_vault).collect())
    }

    pub(crate) async fn vault_impl(&self, id_or_name: &str, cancel: &CancelToken) -> Result<SaVault, OvError> {
        Ok(sa_vault(&self.entry(id_or_name, cancel).await?))
    }

    /// Downloads a vault; the downloaded copy becomes the cached one.
    async fn download(&self, e: &VaultEntry, cancel: &CancelToken) -> Result<Vault, OvError> {
        let blob = BlobPath::vault(&e.info.id);
        let res = self.authed(cancel, |t| self.inner.sync.build_blob_get(&blob, Some(t), None)).await?;
        let GetResult::Ok { data, version } = parse_blob_get(&res)? else {
            return Err(OvError::new(
                OvErrorCode::NotFound,
                format!("vault {} has no data on the sync server", e.info.id),
            )
            .with_status(404));
        };
        let (db, _) = open_with_key_versions(&data, &e.keys)?;
        let v = new_vault(
            VaultSource::ServiceAccount { info: e.info.clone() },
            Some(self.inner.client.host.clone()),
            db,
            false,
        );
        *lock(&v.inner.etag) = Some(version.etag);
        *lock(&v.inner.base) = Some(data);
        lock(&self.inner.inner).opened.insert(e.info.id.clone(), v.clone());
        Ok(v)
    }

    pub(crate) async fn open_impl(
        &self,
        id_or_name: &str,
        refresh: bool,
        cancel: &CancelToken,
    ) -> Result<Vault, OvError> {
        let e = self.entry(id_or_name, cancel).await?;
        if !refresh {
            if let Some(v) = lock(&self.inner.inner).opened.get(&e.info.id) {
                return Ok(v.clone());
            }
        }
        self.download(&e, cancel).await
    }

    /// A HEAD with the last ETag; a download only when the server has a newer version.
    pub(crate) async fn pull_impl(&self, id_or_name: &str, cancel: &CancelToken) -> Result<Vault, OvError> {
        let e = self.entry(id_or_name, cancel).await?;
        let cached = lock(&self.inner.inner).opened.get(&e.info.id).cloned();
        let Some(v) = cached else { return self.download(&e, cancel).await };
        let Some(etag) = v.etag() else { return self.download(&e, cancel).await };
        let blob = BlobPath::vault(&e.info.id);
        let res = self.authed(cancel, |t| self.inner.sync.build_blob_head(&blob, Some(t), Some(&etag))).await?;
        match parse_blob_head(&res)? {
            HeadResult::NotModified(_) => Ok(v),
            _ => self.download(&e, cancel).await,
        }
    }

    pub(crate) fn close_impl(&self) {
        let mut g = lock(&self.inner.inner);
        g.keyset = None;
        g.vaults = None;
        g.opened.clear();
        g.access = None;
        g.secret = Zeroizing::new([0u8; 32]);
    }
}
