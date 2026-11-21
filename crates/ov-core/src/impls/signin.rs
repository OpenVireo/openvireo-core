//! Sign-up, sign-in with TOTP, unlock (online and offline, SPEC §8, §9, §20), sign-out and several
//! sessions on one device (SPEC §21). A port of the matching parts of the SDK's `account.ts` and
//! the iOS `Account+Switching.swift`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ov_crypto::auk::{check_kdf_params, derive_auk, new_kdf_params_with, KDF_DEFAULTS};
use ov_crypto::encoding::{b64u, from_b64u};
use ov_crypto::keyset::{generate_keyset, wrap_keyset};
use ov_crypto::secret_key::{format_secret_key, generate_secret_key};
use ov_error::{OvError, OvErrorCode};
use ov_protocol::auth::{parse_login_finish, parse_login_start, parse_register_start, parse_session};
use ov_protocol::parse_empty;
use ov_protocol::types::{self as w, LoginFinishResponse, LoginMfaRequest};
use zeroize::Zeroizing;

use super::account::{device_info, parse_sk, pending_until, CachedProfile};
use super::convert::{api_kdf, kdf_min, wire_kdf, wire_wrapped};
use super::net::send;
use super::tokens::TokenManager;
use super::util::{lock, rng, secret_text, signed_out};
use crate::api::{
    Account, CancelToken, EmergencyKit, KdfOverrides, LoginInput, LoginStep, NewAccount, ParkedCheck, RegisterInput,
    SecretBytes, TotpChallenge, Unlocked,
};
use crate::state::TotpState;

/// New KDF parameters with overrides, checked against the floor.
pub(crate) fn new_kdf(acct: &Account, o: Option<KdfOverrides>) -> Result<ov_crypto::auk::KdfParams, OvError> {
    let (m, t, p) = KDF_DEFAULTS;
    let o = o.unwrap_or_default();
    let kdf = new_kdf_params_with(o.m.unwrap_or(m), o.t.unwrap_or(t), o.p.unwrap_or(p))?;
    check_kdf_params(&kdf, kdf_min(&acct.inner.config))?;
    Ok(kdf)
}

/// What a fresh keyset registration (sign-up and reset) produced.
pub(crate) struct Fresh {
    pub sk: Zeroizing<[u8; 16]>,
    pub kdf: ov_crypto::auk::KdfParams,
    pub record: Vec<u8>,
    pub auk: Zeroizing<[u8; 32]>,
    pub keyset: ov_crypto::keyset::Keyset,
    pub wrapped: ov_crypto::keyset::WrappedKeysetJson,
}

/// OPAQUE registration around `start` (which posts the request and returns `(session_id, response)`),
/// plus a new Secret Key, KDF salt and keyset (SPEC §2, §3, §5).
pub(crate) fn fresh_keys(
    acct: &Account,
    password: &str,
    email: &str,
    kdf: ov_crypto::auk::KdfParams,
    state: ov_opaque::ClientRegistrationState,
    response: &[u8],
) -> Result<Fresh, OvError> {
    let reg = ov_opaque::finish_registration(&mut rng(), state, response, &acct.ids(email))?;
    let sk = generate_secret_key()?;
    let auk = derive_auk(password, &kdf, &sk, acct.kdf_opts())?;
    let keyset = generate_keyset()?;
    let wrapped = wrap_keyset(&auk, &keyset)?;
    Ok(Fresh { sk, kdf, record: reg.record, auk, keyset, wrapped })
}

impl Account {
    pub(crate) async fn register_impl(
        &self,
        input: RegisterInput,
        cancel: &CancelToken,
    ) -> Result<NewAccount, OvError> {
        let RegisterInput { email, password, kdf, trust_device } = input;
        let email = email.trim().to_owned();
        let password = secret_text(password, "password")?;
        let kdf = new_kdf(self, kdf)?;
        let reg = ov_opaque::start_registration(&mut rng(), &password)?;
        let req = w::RegisterStartRequest { email: email.clone(), request: b64u(&reg.request) };
        let started = self.call_public(cancel, self.auth().build_register_start(&req), parse_register_start).await?;
        let response =
            from_b64u(&started.response).map_err(|_| OvError::new(OvErrorCode::OpaqueFailed, "bad response"))?;
        let f = fresh_keys(self, &password, &email, kdf, reg.state, &response)?;
        let finish = w::RegisterFinishRequest {
            session_id: started.session_id,
            record: b64u(&f.record),
            kdf: wire_kdf(&f.kdf),
            keyset: wire_wrapped(&f.wrapped),
            device: device_info(&self.inner.client.config, None),
        };
        let session = self.call_public(cancel, self.auth().build_register_finish(&finish), parse_session).await?;
        self.begin(&email, &session, &f.sk, trust_device).await?;
        self.cache_profile(&session.user.id, &CachedProfile { kdf: finish.kdf, keyset: finish.keyset }).await?;
        {
            let mut g = lock(&self.inner.inner);
            g.keyset = Some(f.keyset);
            g.offline = false;
            g.deletion = None;
        }
        Ok(NewAccount {
            user_id: session.user.id,
            secret_key: format_secret_key(&f.sk).as_bytes().to_vec(),
            emergency_kit: EmergencyKit {
                email,
                issuer: self.inner.config.issuer.clone(),
                web: self.inner.config.web.clone(),
            },
            auk: f.auk.to_vec(),
        })
    }

    pub(crate) async fn login_impl(&self, input: LoginInput, cancel: &CancelToken) -> Result<LoginStep, OvError> {
        let LoginInput { email, password, secret_key, totp, trust_device } = input;
        let password = secret_text(password, "password")?;
        let sk_text = match secret_key {
            Some(s) => Some(secret_text(s, "Secret Key")?),
            None => self.stored_sk(&email).await?,
        };
        let sk_text = sk_text
            .ok_or_else(|| OvError::new(OvErrorCode::InvalidSecretKey, "this device needs the account's Secret Key"))?;
        let sk = parse_sk(&sk_text)?;
        let device_id = self.stored_device(&email).await?;
        let login = ov_opaque::start_login(&mut rng(), &password)?;
        let req = w::LoginStartRequest { email: email.trim().to_owned(), ke1: b64u(&login.ke1) };
        let started = self.call_public(cancel, self.auth().build_login_start(&req), parse_login_start).await?;
        let ke2 = from_b64u(&started.ke2).map_err(|_| opaque_refused())?;
        let fin = ov_opaque::finish_login(&mut rng(), login.state, &ke2, &self.ids(&email), &self.opaque_context())
            .map_err(|_| opaque_refused())?;
        let req = w::LoginFinishRequest {
            session_id: started.session_id,
            auth_u: b64u(&fin.auth_u),
            device: device_info(&self.inner.client.config, device_id),
        };
        let res =
            self.call_public(cancel, self.auth().build_login_finish(&req), parse_login_finish).await.map_err(|e| {
                // The server refused the OPAQUE proof
                if e.is(OvErrorCode::Unauthorized) && e.details.is_none() {
                    e.with_details(super::account::OPAQUE_REFUSED)
                } else {
                    e
                }
            })?;
        match res {
            LoginFinishResponse::Session(s) => {
                self.finish_signin(&email, &password, &sk, &s, trust_device).await.map(LoginStep::Unlocked)
            }
            LoginFinishResponse::Mfa(m) => {
                let challenge = TotpChallenge {
                    inner: Arc::new(TotpState {
                        email,
                        mfa_token: Zeroizing::new(m.mfa_token),
                        password,
                        secret_key: sk,
                        trust_device,
                        attempt: AtomicU32::new(1),
                        last_error: Mutex::new(None),
                        used: AtomicBool::new(false),
                    }),
                };
                match totp {
                    None => Ok(LoginStep::NeedsTotp(challenge)),
                    Some(code) => self.submit_totp_impl(challenge, code, cancel).await,
                }
            }
        }
    }

    pub(crate) async fn submit_totp_impl(
        &self,
        ch: TotpChallenge,
        code: String,
        cancel: &CancelToken,
    ) -> Result<LoginStep, OvError> {
        let st = &ch.inner;
        if st.used.load(Ordering::SeqCst) {
            return Err(OvError::new(OvErrorCode::MfaExpired, "this sign-in is finished; sign in again"));
        }
        let req = LoginMfaRequest { mfa_token: st.mfa_token.to_string(), totp: code.trim().to_owned() };
        match self.call_public(cancel, self.auth().build_login_mfa(&req), parse_session).await {
            Ok(s) => {
                st.used.store(true, Ordering::SeqCst);
                let out = self.finish_signin(&st.email, &st.password, &st.secret_key, &s, st.trust_device).await?;
                Ok(LoginStep::Unlocked(out))
            }
            Err(e) if e.is(OvErrorCode::InvalidMfa) => {
                st.attempt.fetch_add(1, Ordering::SeqCst);
                *lock(&st.last_error) = Some(e.clone());
                Err(e)
            }
            Err(e) if matches!(e.status, Some(401 | 410)) => {
                st.used.store(true, Ordering::SeqCst);
                let mut out = OvError::new(
                    OvErrorCode::MfaExpired,
                    "the sign-in expired or the code was wrong too often; sign in again",
                );
                out.status = e.status;
                Err(out)
            }
            Err(e) => Err(e),
        }
    }

    /// Unlocks with the session's keyset, keeps the session and caches the profile.
    async fn finish_signin(
        &self,
        email: &str,
        password: &str,
        sk: &[u8; 16],
        s: &w::Session,
        trust: bool,
    ) -> Result<Unlocked, OvError> {
        let auk = match self.unlock_with(password, &s.kdf, &s.keyset, sk) {
            Ok(auk) => auk,
            Err(e) => {
                // The server opened a session for a password it accepted, but the keyset doesn't
                // unwrap (wrong Secret Key): end that session rather than leave it behind
                let _ = send(self.host(), self.auth().build_logout(&s.access_token, false), &CancelToken::new()).await;
                return Err(e);
            }
        };
        self.begin(email, s, sk, trust).await?;
        self.cache_profile(&s.user.id, &CachedProfile { kdf: s.kdf.clone(), keyset: s.keyset.clone() }).await?;
        let deletion = pending_until(&s.access_token);
        {
            let mut g = lock(&self.inner.inner);
            g.offline = false;
            g.deletion = deletion.clone();
        }
        Ok(Unlocked { auk: auk.to_vec(), offline: false, deletion_scheduled_for: deletion })
    }

    pub(crate) async fn unlock_impl(
        &self,
        password: SecretBytes,
        secret_key: Option<SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<Unlocked, OvError> {
        let password = secret_text(password, "password")?;
        let session = self.inner.tokens.load().await?.ok_or_else(|| signed_out("not signed in"))?;
        lock(&self.inner.inner).cache_user = Some(session.user_id.clone());
        let sk_text = match secret_key {
            Some(s) => Some(secret_text(s, "Secret Key")?),
            None => self.stored_sk(&session.email).await?,
        };
        let sk_text = sk_text
            .ok_or_else(|| OvError::new(OvErrorCode::InvalidSecretKey, "this device needs the account's Secret Key"))?;
        let sk = parse_sk(&sk_text)?;
        let (profile, offline) = self.unlock_profile(&session.user_id, cancel).await?;
        let auk = self.unlock_with(&password, &profile.kdf, &profile.keyset, &sk)?;
        if !offline {
            self.cache_profile(&session.user_id, &profile).await?;
        }
        let deletion = {
            let mut g = lock(&self.inner.inner);
            g.offline = offline;
            g.deletion.clone()
        };
        Ok(Unlocked { auk: auk.to_vec(), offline, deletion_scheduled_for: deletion })
    }

    pub(crate) async fn unlock_with_auk_impl(&self, auk: SecretBytes, cancel: &CancelToken) -> Result<(), OvError> {
        let auk = Zeroizing::new(auk);
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            auk.as_slice().try_into().map_err(|_| OvError::new(OvErrorCode::InvalidRequest, "an AUK is 32 bytes"))?,
        );
        let session = self.inner.tokens.load().await?.ok_or_else(|| signed_out("not signed in"))?;
        lock(&self.inner.inner).cache_user = Some(session.user_id.clone());
        let (profile, offline) = self.unlock_profile(&session.user_id, cancel).await?;
        self.unlock_with_auk_key(&key, &profile.keyset)?;
        if !offline {
            self.cache_profile(&session.user_id, &profile).await?;
        }
        self.set_offline(offline);
        Ok(())
    }

    pub(crate) async fn resume_unlocked_impl(&self, secret: SecretBytes, cancel: &CancelToken) -> Result<(), OvError> {
        let secret = Zeroizing::new(secret);
        let session = self.inner.tokens.load().await?.ok_or_else(|| signed_out("not signed in"))?;
        let (profile, offline) = self.unlock_profile(&session.user_id, cancel).await?;
        let ks = ov_vault::resume_keyset(&secret, &ov_vault::keys::public_of_wrapped(&profile.keyset))?;
        if !offline {
            self.cache_profile(&session.user_id, &profile).await?;
        }
        self.lock_keys();
        let mut g = lock(&self.inner.inner);
        g.keyset = Some(ks);
        g.cache_user = Some(session.user_id);
        g.offline = offline;
        Ok(())
    }

    pub(crate) async fn sign_out_impl(&self, forget_device: bool, cancel: &CancelToken) -> Result<(), OvError> {
        let current = self.inner.tokens.current();
        if current.is_some() {
            // Best effort: the session ends here either way.
            let _ = self.call(cancel, |a, t| a.build_logout(t, false), parse_empty).await;
        }
        self.lock_keys();
        lock(&self.inner.inner).cache_user = None;
        if let Some(s) = &current {
            self.clear_offline_data(&s.user_id).await?;
        }
        {
            let mut g = lock(&self.inner.inner);
            g.offline = false;
            g.deletion = None;
        }
        self.inner.tokens.clear(crate::api::SignedOutReason::Logout).await?;
        if let (true, Some(s)) = (forget_device, current) {
            self.forget_device_impl(&s.email).await?;
        }
        Ok(())
    }

    pub(crate) async fn forget_device_impl(&self, email: &str) -> Result<(), OvError> {
        if let Some(s) = self.inner.tokens.load().await? {
            if self.ids(&s.email).id_u == self.ids(email).id_u {
                return Err(OvError::new(OvErrorCode::ServerError, "sign out of this account first"));
            }
        }
        for key in [self.sk_key(email), self.dev_key(email), self.older_sk_key(email), self.older_dev_key(email)] {
            self.host().store.delete(&key).await?;
        }
        Ok(())
    }

    /// Ends the session here after the account was deleted (here or elsewhere, SPEC §23).
    pub(crate) async fn end_session(&self, user_id: &str, reason: crate::api::SignedOutReason) -> Result<(), OvError> {
        let email = self.inner.tokens.current().map(|s| s.email);
        self.lock_keys();
        lock(&self.inner.inner).cache_user = None;
        self.clear_offline_data(user_id).await?;
        {
            let mut g = lock(&self.inner.inner);
            g.offline = false;
            g.deletion = None;
        }
        self.inner.tokens.clear(reason).await?;
        if let (crate::api::SignedOutReason::AccountDeleted, Some(e)) = (reason, email) {
            self.forget_device_impl(&e).await?;
        }
        Ok(())
    }

    // --------------------------------------------------------------------- §21

    fn parked_tokens(&self, user_id: &str) -> TokenManager {
        TokenManager::new(
            self.host().clone(),
            self.auth().clone(),
            Account::parked_key(&self.inner.config.issuer, user_id),
            Arc::new(super::tokens::SignedOutSignal::default()),
        )
    }

    pub(crate) async fn park_impl(&self) -> Result<bool, OvError> {
        let Some(session) = self.inner.tokens.load().await? else { return Ok(false) };
        self.lock_keys();
        {
            let mut g = lock(&self.inner.inner);
            g.cache_user = None;
            g.offline = false;
            g.deletion = None;
        }
        self.inner.tokens.set_aside(&Account::parked_key(&self.inner.config.issuer, &session.user_id)).await
    }

    pub(crate) async fn resume_impl(&self, user_id: &str) -> Result<bool, OvError> {
        if let Some(active) = self.inner.tokens.load().await? {
            if active.user_id == user_id {
                return Ok(true);
            }
            return Err(OvError::new(OvErrorCode::ServerError, "another account is open"));
        }
        if !self.inner.tokens.resume(&Account::parked_key(&self.inner.config.issuer, user_id)).await? {
            return Ok(false);
        }
        lock(&self.inner.inner).cache_user = Some(user_id.to_owned());
        Ok(true)
    }

    pub(crate) async fn check_parked_impl(&self, user_id: &str, cancel: &CancelToken) -> Result<ParkedCheck, OvError> {
        let tokens = self.parked_tokens(user_id);
        if tokens.load().await?.is_none() {
            return Ok(ParkedCheck::Ended);
        }
        match tokens.refresh_now(cancel).await {
            Ok(_) => Ok(ParkedCheck::Valid),
            Err(e) if e.is(OvErrorCode::Aborted) => Err(e),
            Err(e) if e.is(OvErrorCode::SignedOut) && e.status.is_some() => {
                self.drop_offline_data(user_id, &e).await?;
                Ok(ParkedCheck::Ended)
            }
            Err(_) => Ok(ParkedCheck::NoAnswer),
        }
    }

    pub(crate) async fn sign_out_parked_impl(&self, user_id: &str, cancel: &CancelToken) -> Result<(), OvError> {
        let tokens = self.parked_tokens(user_id);
        if tokens.load().await?.is_some() {
            if let Ok(t) = tokens.access_token(false, cancel).await {
                let _ = send(self.host(), self.auth().build_logout(&t, false), cancel).await;
            }
            tokens.clear(crate::api::SignedOutReason::Logout).await?;
        }
        self.clear_offline_data(user_id).await
    }

    pub(crate) async fn cached_kdf_impl(&self) -> Result<Option<crate::api::KdfParams>, OvError> {
        let Some(user) = self.current_user() else { return Ok(None) };
        Ok(self.cached_profile(&user).await?.map(|p| api_kdf(&p.kdf)))
    }
}

/// `unauthorized` for a sign-in the OPAQUE exchange refused (wrong email or password), with
/// `details` [`OPAQUE_REFUSED`](super::account::OPAQUE_REFUSED).
fn opaque_refused() -> OvError {
    OvError::new(OvErrorCode::Unauthorized, "wrong email or password")
        .with_status(401)
        .with_details(super::account::OPAQUE_REFUSED)
}
