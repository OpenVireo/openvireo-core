//! The account machinery behind [`Account`]: authenticated calls with the 401 → refresh → retry
//! rule, the SecureStore keys (Secret Key, device id, sessions), the offline cache records (SPEC
//! §20), unlocking, and the vault list. A port of the private half of the SDK's `account.ts`.

use ov_crypto::auk::{derive_auk, DeriveAukOptions, KdfParams};
use ov_crypto::keyset::{unwrap_keyset, Keyset};
use ov_crypto::secret_key::{format_secret_key, parse_secret_key, SECRET_KEY_BYTES};
use ov_error::{OvError, OvErrorCode};
use ov_opaque::{opaque_ids, OpaqueIds};
use ov_protocol::auth::{retries_on_401, AuthApi};
use ov_protocol::types as w;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::convert::{crypto_kdf, crypto_wrapped, from_stored, kdf_min, wire_platform};
use super::keyring::VaultEntry;
use super::net::send;
use super::tokens::StoredSession;
use super::util::{lock, signed_out, to_json};
use crate::api::{Account, CancelToken, ClientConfig, VaultInfo};
use crate::host::{Host, HttpRequest, HttpResponse};

/// Cache record names (`BlobCache::*_meta`).
pub(crate) const META_PROFILE: &str = "profile";
pub(crate) const META_VAULTS: &str = "vaults";

/// The discovery document's cache record (user `""`).
pub(crate) fn config_meta_name(issuer: &str) -> String {
    format!("config:{}", issuer.trim().trim_end_matches('/'))
}

/// What unlocking needs from the account record (cached for offline unlock).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CachedProfile {
    pub kdf: w::Kdf,
    pub keyset: w::WrappedKeyset,
}

/// The device as the server sees it, with the id from an earlier sign-in.
pub(crate) fn device_info(config: &ClientConfig, id: Option<String>) -> w::DeviceInfo {
    let name: String = config.device.name.chars().take(64).collect();
    w::DeviceInfo { id: id.or_else(|| config.device.id.clone()), name, platform: wire_platform(config.device.platform) }
}

/// The `del` claim of an access token: the erase date of a pending account (SPEC §23).
pub(crate) fn pending_until(access_token: &str) -> Option<String> {
    ov_crypto::jwt::decode_jwt(access_token).ok().and_then(|d| d.claims.del)
}

/// The secret key text as 16 bytes.
pub(crate) fn parse_sk(text: &str) -> Result<Zeroizing<[u8; SECRET_KEY_BYTES]>, OvError> {
    parse_secret_key(text)
}

/// `details` of an `unauthorized` sign-in or unlock whose keyset didn't unwrap: the password was
/// accepted (OPAQUE succeeded, or offline nothing checked it), so the Secret Key (or, offline, the
/// password) is wrong.
pub(crate) const KEYSET_UNWRAP_FAILED: &str = r#"{"reason":"keyset_unwrap_failed"}"#;
/// `details` of an `unauthorized` sign-in the OPAQUE exchange refused: wrong email or password.
pub(crate) const OPAQUE_REFUSED: &str = r#"{"reason":"opaque_refused"}"#;

/// `decryption_failed` while unwrapping a keyset means a wrong password or Secret Key
/// ([`KEYSET_UNWRAP_FAILED`]).
pub(crate) fn unauthorized_on_decrypt(e: OvError, msg: &str) -> OvError {
    if e.is(OvErrorCode::DecryptionFailed) {
        OvError::new(OvErrorCode::Unauthorized, msg).with_status(401).with_details(KEYSET_UNWRAP_FAILED)
    } else {
        e
    }
}

impl Account {
    pub(crate) fn host(&self) -> &Host {
        &self.inner.client.host
    }

    pub(crate) fn auth(&self) -> &AuthApi {
        &self.inner.auth
    }

    pub(crate) fn keeps_offline_data(&self) -> bool {
        self.inner.client.config.offline
    }

    pub(crate) fn now_ms(&self) -> i64 {
        self.host().clock.now_unix_ms()
    }

    pub(crate) fn opaque_context(&self) -> String {
        let c = &self.inner.config.opaque.context;
        if c.is_empty() {
            ov_opaque::CONTEXT.to_owned()
        } else {
            c.clone()
        }
    }

    pub(crate) fn kdf_opts(&self) -> DeriveAukOptions {
        DeriveAukOptions { allow_weak: false, kdf_min: kdf_min(&self.inner.config) }
    }

    pub(crate) fn ids(&self, email: &str) -> OpaqueIds {
        opaque_ids(email, &self.inner.config.opaque.ids)
    }

    // ------------------------------------------------------------------ SecureStore keys

    pub(crate) fn sk_key(&self, email: &str) -> String {
        let i = self.ids(email);
        format!("secret_key:{}:{}", i.id_s, i.id_u)
    }
    pub(crate) fn dev_key(&self, email: &str) -> String {
        let i = self.ids(email);
        format!("device:{}:{}", i.id_s, i.id_u)
    }
    pub(crate) fn older_sk_key(&self, email: &str) -> String {
        format!("secret_key:{}", self.ids(email).id_u)
    }
    pub(crate) fn older_dev_key(&self, email: &str) -> String {
        format!("device:{}", self.ids(email).id_u)
    }

    /// `ov:parked_session:<idS>:<user>` (TS `Account.parkedKey` in the `ov:` namespace).
    pub(crate) fn parked_key(issuer: &str, user_id: &str) -> String {
        format!("ov:parked_session:{}:{user_id}", opaque_ids("", issuer).id_s)
    }

    async fn get_text(&self, key: &str) -> Result<Option<Zeroizing<String>>, OvError> {
        Ok(self
            .host()
            .store
            .get(key)
            .await?
            .and_then(|v| std::str::from_utf8(&v).ok().map(|s| Zeroizing::new(s.to_owned()))))
    }

    pub(crate) async fn stored_sk(&self, email: &str) -> Result<Option<Zeroizing<String>>, OvError> {
        match self.get_text(&self.sk_key(email)).await? {
            Some(v) => Ok(Some(v)),
            None => self.get_text(&self.older_sk_key(email)).await,
        }
    }

    pub(crate) async fn stored_device(&self, email: &str) -> Result<Option<String>, OvError> {
        match self.get_text(&self.dev_key(email)).await? {
            Some(v) => Ok(Some(v.to_string())),
            None => Ok(self.get_text(&self.older_dev_key(email)).await?.map(|v| v.to_string())),
        }
    }

    /// `text` opened this account: kept under the key naming this server; an older copy goes.
    pub(crate) async fn keep_sk(&self, text: &str, email: &str) -> Result<(), OvError> {
        let store = &self.host().store;
        store.set(&self.sk_key(email), text.as_bytes()).await?;
        if self.get_text(&self.older_sk_key(email)).await?.as_deref().map(String::as_str) != Some(text) {
            return Ok(());
        }
        if let Some(device) = self.get_text(&self.older_dev_key(email)).await? {
            if self.get_text(&self.dev_key(email)).await?.is_none() {
                store.set(&self.dev_key(email), device.as_bytes()).await?;
            }
        }
        store.delete(&self.older_sk_key(email)).await?;
        store.delete(&self.older_dev_key(email)).await
    }

    /// The session and the Secret Key this device keeps for it.
    pub(crate) async fn session_and_sk(&self) -> Result<(StoredSession, Zeroizing<[u8; 16]>), OvError> {
        let session = self.inner.tokens.load().await?.ok_or_else(|| signed_out("not signed in"))?;
        let text = self
            .stored_sk(&session.email)
            .await?
            .ok_or_else(|| OvError::new(OvErrorCode::InvalidSecretKey, "this device needs the account's Secret Key"))?;
        Ok((session, parse_sk(&text)?))
    }

    // --------------------------------------------------------------------- requests

    /// An access token; when a refresh is refused the session ends here (lock, offline data).
    pub(crate) async fn bearer_token(&self, force: bool, cancel: &CancelToken) -> Result<Zeroizing<String>, OvError> {
        match self.inner.tokens.access_token(force, cancel).await {
            Ok(t) => Ok(t),
            Err(e) => {
                if e.is(OvErrorCode::SignedOut) && e.status.is_some() {
                    self.session_ended().await;
                }
                Err(e)
            }
        }
    }

    /// Forces a refresh (new `vlt` claims, or a token issued in the last five minutes).
    pub(crate) async fn refresh_token(&self, cancel: &CancelToken) -> Result<(), OvError> {
        self.bearer_token(true, cancel).await.map(|_| ())
    }

    /// An authenticated auth-server call, retried once with a fresh token after a 401 (except the
    /// restore steps, `retries_on_401`).
    pub(crate) async fn call<T>(
        &self,
        cancel: &CancelToken,
        build: impl Fn(&AuthApi, &str) -> HttpRequest,
        parse: impl Fn(&HttpResponse) -> Result<T, OvError>,
    ) -> Result<T, OvError> {
        let token = self.bearer_token(false, cancel).await?;
        let req = build(self.auth(), &token);
        let retry = retries_on_401(&req);
        let mut res = send(self.host(), req, cancel).await?;
        if res.status == 401 && retry {
            let token = self.bearer_token(true, cancel).await?;
            res = send(self.host(), build(self.auth(), &token), cancel).await?;
        }
        parse(&res)
    }

    /// An unauthenticated auth-server call.
    pub(crate) async fn call_public<T>(
        &self,
        cancel: &CancelToken,
        req: HttpRequest,
        parse: impl Fn(&HttpResponse) -> Result<T, OvError>,
    ) -> Result<T, OvError> {
        let res = send(self.host(), req, cancel).await?;
        parse(&res)
    }

    /// The server ended the session: lock and drop the user's offline data (SPEC §20).
    pub(crate) async fn session_ended(&self) {
        let user = lock(&self.inner.inner).cache_user.take();
        self.lock_keys();
        if let Some(u) = user {
            let _ = self.clear_offline_data(&u).await;
        }
    }

    /// Wipes the keyset and vault keys.
    pub(crate) fn lock_keys(&self) {
        let mut g = lock(&self.inner.inner);
        g.keyset = None;
        g.vaults.clear();
    }

    pub(crate) fn with_keyset<T>(&self, f: impl FnOnce(&Keyset) -> T) -> Result<T, OvError> {
        let g = lock(&self.inner.inner);
        g.keyset.as_ref().map(f).ok_or_else(|| signed_out("the account is locked"))
    }

    pub(crate) fn set_offline(&self, v: bool) {
        lock(&self.inner.inner).offline = v;
    }

    pub(crate) fn principal_str(&self) -> Result<String, OvError> {
        let s = self.inner.tokens.current().ok_or_else(|| signed_out("not signed in"))?;
        Ok(format!("user:{}", s.user_id))
    }

    pub(crate) fn current_user(&self) -> Option<String> {
        self.inner.tokens.current().map(|s| s.user_id).or_else(|| lock(&self.inner.inner).cache_user.clone())
    }

    // -------------------------------------------------------------------- sign-in

    /// Keeps the new session, the Secret Key (when trusted) and the device id.
    pub(crate) async fn begin(&self, email: &str, s: &w::Session, sk: &[u8; 16], trust: bool) -> Result<(), OvError> {
        let stored = StoredSession {
            issuer: self.inner.config.issuer.clone(),
            user_id: s.user.id.clone(),
            email: if s.user.email.is_empty() { email.to_owned() } else { s.user.email.clone() },
            device_id: s.device_id.clone(),
            refresh_token: Zeroizing::new(s.refresh_token.clone()),
        };
        self.inner.tokens.start(stored, &s.access_token, s.expires_in).await?;
        lock(&self.inner.inner).cache_user = Some(s.user.id.clone());
        if trust {
            self.keep_sk(&format_secret_key(sk), email).await?;
        }
        self.host().store.set(&self.dev_key(email), s.device_id.as_bytes()).await
    }

    /// Derives the AUK and unwraps the keyset into memory; returns the AUK.
    pub(crate) fn unlock_with(
        &self,
        password: &str,
        kdf: &w::Kdf,
        wrapped: &w::WrappedKeyset,
        sk: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, OvError> {
        let params: KdfParams = crypto_kdf(kdf);
        ov_crypto::auk::check_kdf_params(&params, kdf_min(&self.inner.config))?;
        let auk = derive_auk(password, &params, sk, self.kdf_opts())?;
        self.unlock_with_auk_key(&auk, wrapped)?;
        Ok(auk)
    }

    /// Unwraps the keyset with an AUK into memory.
    pub(crate) fn unlock_with_auk_key(&self, auk: &[u8; 32], wrapped: &w::WrappedKeyset) -> Result<(), OvError> {
        let ks = unwrap_keyset(auk, &crypto_wrapped(wrapped))
            .map_err(|e| unauthorized_on_decrypt(e, "wrong password or Secret Key"))?;
        self.lock_keys();
        lock(&self.inner.inner).keyset = Some(ks);
        Ok(())
    }

    /// Unwraps the keyset from `/me` with this password, which proves it is the master password.
    pub(crate) async fn check_password(
        &self,
        password: &str,
        sk: &[u8; 16],
        cancel: &CancelToken,
    ) -> Result<Keyset, OvError> {
        let me = self.call(cancel, |a, t| a.build_me(t), ov_protocol::auth::parse_me).await?;
        let params = crypto_kdf(&me.kdf);
        ov_crypto::auk::check_kdf_params(&params, kdf_min(&self.inner.config))?;
        let auk = derive_auk(password, &params, sk, self.kdf_opts())?;
        unwrap_keyset(&auk, &crypto_wrapped(&me.keyset))
            .map_err(|e| unauthorized_on_decrypt(e, "the master password is wrong"))
    }

    /// The account record for unlocking: `/me`, or offline the cached profile. Returns it and whether
    /// it came from the cache.
    pub(crate) async fn unlock_profile(
        &self,
        user_id: &str,
        cancel: &CancelToken,
    ) -> Result<(CachedProfile, bool), OvError> {
        match self.call(cancel, |a, t| a.build_me(t), ov_protocol::auth::parse_me).await {
            Ok(me) => {
                lock(&self.inner.inner).deletion = me.deletion_scheduled_for.clone();
                self.follow_email(&me.email).await?;
                Ok((CachedProfile { kdf: me.kdf, keyset: me.keyset }, false))
            }
            Err(e) => {
                if e.is_unreachable() {
                    if let Some(p) = self.cached_profile(user_id).await? {
                        return Ok((p, true));
                    }
                }
                Err(e)
            }
        }
    }

    /// Moves what this device keeps under the email to the account's current email (SPEC §16).
    pub(crate) async fn follow_email(&self, email: &str) -> Result<(), OvError> {
        let Some(session) = self.inner.tokens.load().await? else { return Ok(()) };
        if email.is_empty() || self.ids(&session.email).id_u == self.ids(email).id_u {
            return Ok(());
        }
        let sk = self.stored_sk(&session.email).await?;
        let device = self.stored_device(&session.email).await?;
        let store = &self.host().store;
        if let Some(sk) = sk {
            store.set(&self.sk_key(email), sk.as_bytes()).await?;
        }
        if let Some(d) = device {
            store.set(&self.dev_key(email), d.as_bytes()).await?;
        }
        for key in [
            self.sk_key(&session.email),
            self.dev_key(&session.email),
            self.older_sk_key(&session.email),
            self.older_dev_key(&session.email),
        ] {
            store.delete(&key).await?;
        }
        self.inner.tokens.update_email(email).await
    }

    // -------------------------------------------------------------- offline cache

    pub(crate) async fn cache_profile(&self, user_id: &str, p: &CachedProfile) -> Result<(), OvError> {
        if self.keeps_offline_data() {
            self.host().cache.save_meta(user_id, META_PROFILE, &to_json(p)).await?;
        }
        Ok(())
    }

    pub(crate) async fn cached_profile(&self, user_id: &str) -> Result<Option<CachedProfile>, OvError> {
        if !self.keeps_offline_data() {
            return Ok(None);
        }
        match self.host().cache.load_meta(user_id, META_PROFILE).await? {
            Some(raw) => Ok(Some(from_stored(&raw, "profile")?)),
            None => Ok(None),
        }
    }

    pub(crate) async fn cached_wire_vaults(&self) -> Result<Option<Vec<w::Vault>>, OvError> {
        let Some(user) = self.inner.tokens.current().map(|s| s.user_id) else { return Ok(None) };
        if !self.keeps_offline_data() {
            return Ok(None);
        }
        match self.host().cache.load_meta(&user, META_VAULTS).await? {
            Some(raw) => Ok(Some(from_stored(&raw, "vault list")?)),
            None => Ok(None),
        }
    }

    /// Adds or replaces one vault in the cached vault list.
    pub(crate) async fn cache_vault(&self, v: &w::Vault) -> Result<(), OvError> {
        let Some(user) = self.inner.tokens.current().map(|s| s.user_id) else { return Ok(()) };
        if !self.keeps_offline_data() {
            return Ok(());
        }
        let mut list: Vec<w::Vault> = self.cached_wire_vaults().await?.unwrap_or_default();
        list.retain(|x| x.id != v.id);
        list.push(v.clone());
        self.host().cache.save_meta(&user, META_VAULTS, &to_json(&list)).await
    }

    /// Drops everything the offline cache holds for a user.
    pub(crate) async fn clear_offline_data(&self, user_id: &str) -> Result<(), OvError> {
        if !self.keeps_offline_data() {
            return Ok(());
        }
        self.host().cache.clear_user(user_id).await
    }

    // ---------------------------------------------------------------- vault list

    /// Ingests a listed vault into the keyring.
    pub(crate) fn ingest(&self, v: &w::Vault) -> Result<VaultEntry, OvError> {
        let mut g = lock(&self.inner.inner);
        let crate::state::AccountInner { keyset, vaults, .. } = &mut *g;
        let ks = keyset.as_ref().ok_or_else(|| signed_out("the account is locked"))?;
        Ok(VaultEntry::of(vaults.ingest(v, ks)))
    }

    /// `GET /vaults` (offline: the cached list). Returns the list and the vaults no longer listed.
    pub(crate) async fn load_vault_list(&self, cancel: &CancelToken) -> Result<(Vec<VaultInfo>, Vec<String>), OvError> {
        self.with_keyset(|_| ())?;
        let vaults = match self.call(cancel, |a, t| a.build_list_vaults(t), ov_protocol::auth::parse_vaults).await {
            Ok(l) => l.vaults,
            Err(e) => {
                if e.is_unreachable() {
                    if let Some(cached) = self.cached_wire_vaults().await? {
                        self.set_offline(true);
                        let infos = cached.iter().map(|v| self.ingest(v).map(|e| e.info)).collect::<Result<_, _>>()?;
                        return Ok((infos, vec![]));
                    }
                }
                return Err(e);
            }
        };
        self.set_offline(false);
        let seen: std::collections::HashSet<&str> = vaults.iter().map(|v| v.id.as_str()).collect();
        let mut known: Vec<String> = lock(&self.inner.inner).vaults.iter().map(|k| k.id().to_owned()).collect();
        for v in self.cached_wire_vaults().await?.unwrap_or_default() {
            if !known.contains(&v.id) {
                known.push(v.id);
            }
        }
        let dropped: Vec<String> = known.into_iter().filter(|id| !seen.contains(id.as_str())).collect();
        {
            let mut g = lock(&self.inner.inner);
            for id in &dropped {
                g.vaults.remove(id);
            }
        }
        if self.keeps_offline_data() {
            if let Some(user) = self.inner.tokens.current().map(|s| s.user_id) {
                for id in &dropped {
                    self.host().cache.remove(&user, id).await?;
                }
                self.host().cache.save_meta(&user, META_VAULTS, &to_json(&vaults)).await?;
            }
        }
        let infos = vaults.iter().map(|v| self.ingest(v).map(|e| e.info)).collect::<Result<_, _>>()?;
        Ok((infos, dropped))
    }

    /// The keyring entry of a vault: known, `GET /vaults/{id}`, or offline the cached list.
    pub(crate) async fn entry(&self, vault_id: &str, cancel: &CancelToken) -> Result<VaultEntry, OvError> {
        if let Some(e) = lock(&self.inner.inner).vaults.get(vault_id) {
            return Ok(VaultEntry::of(e));
        }
        self.with_keyset(|_| ())?;
        match self.call(cancel, |a, t| a.build_get_vault(t, vault_id), ov_protocol::auth::parse_vault).await {
            Ok(v) => {
                self.cache_vault(&v).await?;
                self.ingest(&v)
            }
            Err(e) => {
                if e.is_unreachable() {
                    if let Some(v) =
                        self.cached_wire_vaults().await?.unwrap_or_default().into_iter().find(|v| v.id == vault_id)
                    {
                        self.set_offline(true);
                        return self.ingest(&v);
                    }
                }
                Err(e)
            }
        }
    }

    /// The keyring entry from memory or the cached list, without the network.
    pub(crate) async fn entry_offline(&self, vault_id: &str) -> Result<VaultEntry, OvError> {
        if let Some(e) = lock(&self.inner.inner).vaults.get(vault_id) {
            return Ok(VaultEntry::of(e));
        }
        let cached = self.cached_wire_vaults().await?.unwrap_or_default();
        let v = cached.into_iter().find(|v| v.id == vault_id).ok_or_else(|| {
            OvError::new(OvErrorCode::NotAvailableOffline, format!("vault {vault_id} isn't known on this device"))
        })?;
        self.ingest(&v)
    }
}
