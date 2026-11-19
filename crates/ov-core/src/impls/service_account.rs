//! [`ServiceAccount`] (SPEC §9, §15), a port of the SDK's `service-account.ts`: token → KEK →
//! master key → keyset, the JWT re-exchanged before it expires (SAs have no refresh token), the
//! granted vaults, downloading them, and reading and writing `ov://` references (`ov-vault`), with
//! uploads through `ov-sync`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ov_crypto::tokens::parse_sa_token;
use ov_error::OvError;
use ov_protocol::auth::{parse_service_account_exchange, parse_vaults, AuthApi};
use ov_protocol::sync::{HeadResult, SyncApi};
use zeroize::Zeroizing;

use super::client::discover_raw;
use super::convert::{server_config, wire_config};
use super::keyring::VaultEntry;
use super::net::send;
use super::util::{lock, secret_text, signed_out};
use crate::api::{CancelToken, Injected, OvClient, SaVault, SecretBytes, ServiceAccount, SyncOptions, Vault};
use crate::host::{HttpRequest, HttpResponse};
use crate::state::{SaInner, ServiceAccountState};

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
        let body = ov_vault::exchange_request(&t);
        let ex =
            parse_service_account_exchange(&send(host, auth.build_service_account_exchange(&body), cancel).await?)?;
        let keyset = ov_vault::unlock_service_account(&t, &ex)?;
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
    pub(crate) async fn access_token(&self, force: bool, cancel: &CancelToken) -> Result<Zeroizing<String>, OvError> {
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
        let body = ov_protocol::types::ServiceAccountExchangeRequest {
            sa_id: self.inner.sa_id.clone(),
            secret: ov_crypto::encoding::b64u(&secret[..]),
        };
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
        let entries: Vec<VaultEntry> =
            list.vaults.iter().map(|v| VaultEntry::of(&ov_vault::VaultKeys::from_vault(v, ks))).collect();
        g.vaults = Some(entries.clone());
        Ok(entries)
    }

    pub(crate) async fn entry(&self, id_or_name: &str, cancel: &CancelToken) -> Result<VaultEntry, OvError> {
        let all = self.entries(false, cancel).await?;
        let found = ov_vault::find_vault(all.iter().map(|e| &e.vk), id_or_name)?;
        Ok(VaultEntry::of(found))
    }

    pub(crate) async fn vaults_impl(&self, refresh: bool, cancel: &CancelToken) -> Result<Vec<SaVault>, OvError> {
        Ok(self.entries(refresh, cancel).await?.iter().map(sa_vault).collect())
    }

    pub(crate) async fn vault_impl(&self, id_or_name: &str, cancel: &CancelToken) -> Result<SaVault, OvError> {
        Ok(sa_vault(&self.entry(id_or_name, cancel).await?))
    }

    /// Downloads a vault; the downloaded copy becomes the cached one.
    async fn download(&self, e: &VaultEntry, cancel: &CancelToken) -> Result<Vault, OvError> {
        let v = super::syncing::open_sa_session(self, e, cancel).await?;
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
        cancel.check()?;
        match self.sync_client().vault(&e.info.id).head(Some(&etag)).await? {
            HeadResult::NotModified(_) => Ok(v),
            _ => self.download(&e, cancel).await,
        }
    }

    /// The value of a secret reference.
    pub(crate) async fn read_impl(&self, reference: &str, cancel: &CancelToken) -> Result<Zeroizing<String>, OvError> {
        let r = ov_vault::parse_reference(reference)?;
        let v = self.open_impl(&r.vault, false, cancel).await?;
        let out = ov_vault::read_field(&v.db(), &r);
        out
    }

    /// Replaces every reference in a template; each distinct reference is read once.
    pub(crate) async fn inject_impl(&self, template: &str, cancel: &CancelToken) -> Result<Injected, OvError> {
        let mut values: HashMap<String, Zeroizing<String>> = HashMap::new();
        for r in ov_vault::find_references(template) {
            let s = &template[r];
            if !values.contains_key(s) {
                values.insert(s.to_owned(), self.read_impl(s, cancel).await?);
            }
        }
        let out = ov_vault::inject(template, |s| {
            values.get(s).cloned().ok_or_else(|| OvError::internal("reference not resolved"))
        })?;
        Ok(Injected {
            text: out.text.as_bytes().to_vec(),
            secrets: out.secrets.iter().map(|v| v.as_bytes().to_vec()).collect(),
        })
    }

    /// Sets the field a reference names and uploads (needs `write`). A failed upload drops the
    /// cached copy, so a failed edit is never read back.
    pub(crate) async fn write_impl(
        &self,
        reference: &str,
        value: &str,
        create: bool,
        cancel: &CancelToken,
    ) -> Result<(), OvError> {
        let r = ov_vault::parse_reference(reference)?;
        let e = self.entry(&r.vault, cancel).await?;
        ov_vault::check_writable(&e.vk)?;
        let v = self.open_impl(&e.info.id, false, cancel).await?;
        let now = v.now();
        let result = async {
            ov_vault::write_field(&mut v.db(), &r, value, create, None, now)?;
            super::syncing::sync_vault(&v, SyncOptions::default(), None, cancel).await
        }
        .await;
        if result.is_err() {
            lock(&self.inner.inner).opened.remove(&e.info.id);
        }
        result.map(|_| ())
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
