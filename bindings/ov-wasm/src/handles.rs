//! The facade's handles as wasm-bindgen classes, one export per facade method.
//!
//! Conventions (rust-core-tasks.md §2.3):
//! - Methods are camelCase. Records are plain objects (see `records.rs`); secrets are `Uint8Array`
//!   and the caller wipes what it receives.
//! - Every call that takes a [`ov_core::api::CancelToken`] in Rust takes an optional
//!   `AbortSignal` last; aborting it cancels the call, which then rejects with `aborted`.
//! - Async calls return a `Promise`; errors are `OvError`s (thrown, or the promise rejects).
//! - `u64`/`i64` arguments are JS numbers (integers up to 2^53).

use std::future::Future;

use js_sys::{Function, Promise};
use ov_core::api::{
    self, Account, CancelToken, EventStream, OvClient, SelfHosted, ServiceAccount, TotpChallenge, Vault,
};
use ov_error::OvError;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::convert::{arg, int, ToJs, MAX_SAFE};
use crate::error::{self, arg_err};

// ------------------------------------------------------------------------------ cancellation

#[wasm_bindgen]
extern "C" {
    /// The standard `AbortSignal` (any object with `aborted` and `add/removeEventListener`).
    pub type AbortSignal;
    #[wasm_bindgen(method, getter, structural)]
    fn aborted(this: &AbortSignal) -> bool;
    #[wasm_bindgen(method, structural, js_name = addEventListener)]
    fn add_event_listener(this: &AbortSignal, ty: &str, f: &Function);
    #[wasm_bindgen(method, structural, js_name = removeEventListener)]
    fn remove_event_listener(this: &AbortSignal, ty: &str, f: &Function);
}

/// Keeps the `abort` listener registered while a call runs; removes it when dropped.
struct AbortGuard {
    signal: AbortSignal,
    listener: Closure<dyn FnMut()>,
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.signal.remove_event_listener("abort", self.listener.as_ref().unchecked_ref());
    }
}

/// A [`CancelToken`] that follows `signal`.
fn token(signal: Option<AbortSignal>) -> (CancelToken, Option<AbortGuard>) {
    let token = CancelToken::new();
    let Some(signal) = signal.filter(|s| !s.is_undefined() && !s.is_null()) else { return (token, None) };
    if signal.aborted() {
        token.cancel();
        return (token, None);
    }
    let t = token.clone();
    let listener = Closure::<dyn FnMut()>::new(move || t.cancel());
    signal.add_event_listener("abort", listener.as_ref().unchecked_ref());
    (token, Some(AbortGuard { signal, listener }))
}

/// Runs an async facade call as a `Promise`: resolves with the converted value, rejects with an
/// `OvError`.
fn call<T, Fut>(signal: Option<AbortSignal>, f: impl FnOnce(CancelToken) -> Fut) -> Promise
where
    T: ToJs,
    Fut: Future<Output = Result<T, OvError>> + 'static,
{
    let (token, guard) = token(signal);
    let fut = f(token);
    future_to_promise(async move {
        let r = fut.await;
        drop(guard);
        error::js(r)
    })
}

/// [`call`] for the few async calls without a `CancelToken`.
fn call0<T, Fut>(fut: Fut) -> Promise
where
    T: ToJs,
    Fut: Future<Output = Result<T, OvError>> + 'static,
{
    future_to_promise(async move { error::js(fut.await) })
}

/// A JS number argument as `u64`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn u64_arg(n: f64, name: &str) -> Result<u64, OvError> {
    int(&JsValue::from_f64(n), name, 0.0, MAX_SAFE).map(|n| n as u64)
}

/// A JS number argument as `i64`.
#[allow(clippy::cast_possible_truncation)]
fn i64_arg(n: f64, name: &str) -> Result<i64, OvError> {
    int(&JsValue::from_f64(n), name, -MAX_SAFE, MAX_SAFE).map(|n| n as i64)
}

macro_rules! handle_to_js {
    ($($rust:ty => $js:ident),*) => {$(
        impl ToJs for $rust {
            fn to_js(&self) -> JsValue {
                $js(self.clone()).into()
            }
        }
    )*};
}

handle_to_js! {
    OvClient => OvClientJs, Account => AccountJs, Vault => VaultJs, ServiceAccount => ServiceAccountJs,
    SelfHosted => SelfHostedJs, EventStream => EventStreamJs, TotpChallenge => TotpChallengeJs
}

// ---------------------------------------------------------------------------------- OvClient

/// The entry point: one per app (or per test). `new OvClient(config, host)`.
#[wasm_bindgen(js_name = OvClient)]
pub struct OvClientJs(pub(crate) OvClient);

#[wasm_bindgen(js_class = OvClient)]
impl OvClientJs {
    /// A client over `host` (see `host/` in the package for ready-made adapters). Does no I/O.
    #[wasm_bindgen(constructor)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "ClientConfig")] config: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Host")] host: JsValue,
    ) -> Result<OvClientJs, JsValue> {
        let config = arg(&config, "config").map_err(arg_err)?;
        let host = crate::host::from_js(&host).map_err(arg_err)?;
        Ok(OvClientJs(OvClient::new(config, host)))
    }

    /// The settings this client was made with.
    #[wasm_bindgen(unchecked_return_type = "ClientConfig")]
    pub fn config(&self) -> JsValue {
        self.0.config().to_js()
    }

    /// Fetches and checks the discovery document (SPEC §10).
    #[wasm_bindgen(unchecked_return_type = "Promise<ServerConfig>")]
    pub fn discover(&self, issuer: String, signal: Option<AbortSignal>) -> Promise {
        let c = self.0.clone();
        call(signal, move |t| async move { c.discover(issuer, t).await })
    }

    /// Discovers the server and loads a stored session (signed in but locked).
    #[wasm_bindgen(unchecked_return_type = "Promise<Account>")]
    pub fn connect(&self, issuer: String, signal: Option<AbortSignal>) -> Promise {
        let c = self.0.clone();
        call(signal, move |t| async move { c.connect(issuer, t).await })
    }

    /// Remembered accounts, most recently used first (SPEC §21).
    #[wasm_bindgen(js_name = rememberedAccounts, unchecked_return_type = "Promise<RememberedAccount[]>")]
    pub fn remembered_accounts(&self) -> Promise {
        let c = self.0.clone();
        call0(async move { c.remembered_accounts().await })
    }

    /// Adds or refreshes a remembered account.
    #[wasm_bindgen(js_name = rememberAccount, unchecked_return_type = "Promise<void>")]
    pub fn remember_account(&self, email: String, issuer: String, user_id: String) -> Promise {
        let c = self.0.clone();
        call0(async move { c.remember_account(email, issuer, user_id).await })
    }

    /// Records (or clears) a remembered account's erase date (SPEC §23).
    #[wasm_bindgen(js_name = setRememberedDeletion, unchecked_return_type = "Promise<void>")]
    pub fn set_remembered_deletion(&self, issuer: String, user_id: String, at: Option<String>) -> Promise {
        let c = self.0.clone();
        call0(async move { c.set_remembered_deletion(issuer, user_id, at).await })
    }

    /// Records that the server confirmed the account's parked session now.
    #[wasm_bindgen(js_name = markRememberedChecked, unchecked_return_type = "Promise<void>")]
    pub fn mark_remembered_checked(&self, issuer: String, user_id: String) -> Promise {
        let c = self.0.clone();
        call0(async move { c.mark_remembered_checked(issuer, user_id).await })
    }

    /// Removes an account from the remembered list.
    #[wasm_bindgen(js_name = forgetRemembered, unchecked_return_type = "Promise<void>")]
    pub fn forget_remembered(&self, issuer: String, user_id: String) -> Promise {
        let c = self.0.clone();
        call0(async move { c.forget_remembered(issuer, user_id).await })
    }

    /// Active, parked or no session for a user on this device (no network).
    #[wasm_bindgen(js_name = sessionState, unchecked_return_type = "Promise<SessionState>")]
    pub fn session_state(&self, issuer: String, user_id: String) -> Promise {
        let c = self.0.clone();
        call0(async move { c.session_state(issuer, user_id).await })
    }

    /// Whether a user's offline cache holds edits not yet uploaded.
    #[wasm_bindgen(js_name = hasPendingEdits, unchecked_return_type = "Promise<boolean>")]
    pub fn has_pending_edits(&self, user_id: String) -> Promise {
        let c = self.0.clone();
        call0(async move { c.has_pending_edits(user_id).await })
    }

    /// What the public share page knows before opening a share (SPEC §22).
    #[wasm_bindgen(js_name = shareInfo, unchecked_return_type = "Promise<ShareInfo>")]
    pub fn share_info(&self, api: String, share_id: String, signal: Option<AbortSignal>) -> Promise {
        let c = self.0.clone();
        call(signal, move |t| async move { c.share_info(api, share_id, t).await })
    }

    /// Opens a share link (SPEC §22).
    #[wasm_bindgen(js_name = openShare, unchecked_return_type = "Promise<OpenedShare>")]
    pub fn open_share(
        &self,
        api: String,
        link: Vec<u8>,
        passcode: Option<Vec<u8>>,
        #[wasm_bindgen(unchecked_param_type = "ShareInfo | undefined")] info: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let c = self.0.clone();
        call(signal, move |t| async move { c.open_share(api, link, passcode, arg(&info, "info")?, t).await })
    }
}

// ------------------------------------------------------------------------------ TotpChallenge

/// A sign-in waiting for a TOTP code. Pass it to `Account.submitTotp`.
#[wasm_bindgen(js_name = TotpChallenge)]
pub struct TotpChallengeJs(pub(crate) TotpChallenge);

#[wasm_bindgen(js_class = TotpChallenge)]
impl TotpChallengeJs {
    /// Which try this is, from 1.
    pub fn attempt(&self) -> u32 {
        self.0.attempt()
    }

    /// The previous wrong code's error (`invalid_mfa`), if any.
    #[wasm_bindgen(js_name = lastError, unchecked_return_type = "OvError | undefined")]
    pub fn last_error(&self) -> JsValue {
        self.0.last_error().to_js()
    }
}

// ----------------------------------------------------------------------------------- Account

/// An account on one server: signed out, signed in but locked, or unlocked.
#[wasm_bindgen(js_name = Account)]
pub struct AccountJs(pub(crate) Account);

/// Async `Account` methods: `name(args) [cancel] -> "TS result" => |account, args..., token| body`.
macro_rules! account_async {
    ($( $(#[$doc:meta])* $js:ident = $rust:ident ( $($p:ident : $pt:ty),* ) -> $ts:literal; )*) => {
        #[wasm_bindgen(js_class = Account)]
        impl AccountJs {$(
            $(#[$doc])*
            #[wasm_bindgen(js_name = $js, unchecked_return_type = $ts)]
            pub fn $rust(&self, $($p: $pt,)* signal: Option<AbortSignal>) -> Promise {
                let a = self.0.clone();
                call(signal, move |t| async move { a.$rust($($p,)* t).await })
            }
        )*}
    };
}

/// Async `Account` methods without a cancel token.
macro_rules! account_async0 {
    ($( $(#[$doc:meta])* $js:ident = $rust:ident ( $($p:ident : $pt:ty),* ) -> $ts:literal; )*) => {
        #[wasm_bindgen(js_class = Account)]
        impl AccountJs {$(
            $(#[$doc])*
            #[wasm_bindgen(js_name = $js, unchecked_return_type = $ts)]
            pub fn $rust(&self, $($p: $pt),*) -> Promise {
                let a = self.0.clone();
                call0(async move { a.$rust($($p),*).await })
            }
        )*}
    };
}

#[wasm_bindgen(js_class = Account)]
impl AccountJs {
    // ---- state

    /// The server's discovery document.
    #[wasm_bindgen(js_name = serverConfig, unchecked_return_type = "ServerConfig")]
    pub fn server_config(&self) -> JsValue {
        self.0.server_config().to_js()
    }

    /// Working from the offline cache (SPEC §20).
    #[wasm_bindgen(js_name = isOffline)]
    pub fn is_offline(&self) -> bool {
        self.0.is_offline()
    }

    /// A session is loaded (it may be locked).
    #[wasm_bindgen(js_name = isSignedIn)]
    pub fn is_signed_in(&self) -> bool {
        self.0.is_signed_in()
    }

    /// The keyset is in memory.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.0.is_unlocked()
    }

    /// The erase date while the account is pending deletion (SPEC §23).
    #[wasm_bindgen(js_name = deletionScheduledFor)]
    pub fn deletion_scheduled_for(&self) -> Option<String> {
        self.0.deletion_scheduled_for()
    }

    /// The signed-in user's id.
    #[wasm_bindgen(js_name = userId)]
    pub fn user_id(&self) -> Option<String> {
        self.0.user_id()
    }

    /// The signed-in email.
    pub fn email(&self) -> Option<String> {
        self.0.email()
    }

    /// `user:<id>`; `signed_out` without a session.
    #[wasm_bindgen(unchecked_return_type = "Principal")]
    pub fn principal(&self) -> Result<JsValue, JsValue> {
        error::js(self.0.principal())
    }

    /// This account's public-key fingerprint (SPEC §5).
    #[wasm_bindgen(unchecked_return_type = "string")]
    pub fn fingerprint(&self) -> Result<JsValue, JsValue> {
        error::js(self.0.fingerprint())
    }

    /// How far this device's clock is ahead of the sync server's (ms).
    #[wasm_bindgen(js_name = clockOffsetMs, unchecked_return_type = "number | undefined")]
    pub fn clock_offset_ms(&self) -> JsValue {
        self.0.clock_offset_ms().to_js()
    }

    /// Sends a TOTP code for a waiting sign-in.
    #[wasm_bindgen(js_name = submitTotp, unchecked_return_type = "Promise<LoginStep>")]
    pub fn submit_totp(&self, challenge: &TotpChallengeJs, code: String, signal: Option<AbortSignal>) -> Promise {
        let a = self.0.clone();
        let ch = challenge.0.clone();
        call(signal, move |t| async move { a.submit_totp(ch, code, t).await })
    }

    /// Creates an account (SPEC §2, §3, §5, §8). Show the returned Secret Key once.
    #[wasm_bindgen(unchecked_return_type = "Promise<NewAccount>")]
    pub fn register(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RegisterInput")] input: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.register(arg(&input, "input")?, t).await })
    }

    /// OPAQUE sign-in (SPEC §8), then unlock.
    #[wasm_bindgen(unchecked_return_type = "Promise<LoginStep>")]
    pub fn login(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LoginInput")] input: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.login(arg(&input, "input")?, t).await })
    }

    /// The unlocked keyset's private halves (64 bytes), for the web's `sealUnlocked`.
    #[wasm_bindgen(js_name = unlockedKeysetSecret, unchecked_return_type = "Uint8Array")]
    pub fn unlocked_keyset_secret(&self) -> Result<JsValue, JsValue> {
        error::js(self.0.unlocked_keyset_secret())
    }

    /// Clears the keyset and vault keys from memory. The session stays.
    pub fn lock(&self) {
        self.0.lock();
    }

    /// For a page closing on a shared session: locks and returns the logout request to fire.
    #[wasm_bindgen(js_name = signOutOnUnload, unchecked_return_type = "HttpRequest | undefined")]
    pub fn sign_out_on_unload(&self) -> JsValue {
        self.0.sign_out_on_unload().to_js()
    }

    /// Imports a `.kdbx` into the account (new vault, merge or copies).
    #[wasm_bindgen(js_name = importKdbx, unchecked_return_type = "Promise<ImportOutcome>")]
    pub fn import_kdbx(
        &self,
        kdbx: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "KdbxCredentials")] credentials: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ImportMode")] mode: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move {
            a.import_kdbx(kdbx, arg(&credentials, "credentials")?, arg(&mode, "mode")?, t).await
        })
    }

    /// Imports an already open vault.
    #[wasm_bindgen(js_name = importVault, unchecked_return_type = "Promise<ImportOutcome>")]
    pub fn import_vault(
        &self,
        source: &VaultJs,
        #[wasm_bindgen(unchecked_param_type = "ImportMode")] mode: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        let source = source.0.clone();
        call(signal, move |t| async move { a.import_vault(source, arg(&mode, "mode")?, t).await })
    }

    /// Opens one saved version, read-only. `revision` is an integer.
    #[wasm_bindgen(js_name = openVaultVersion, unchecked_return_type = "Promise<Vault>")]
    pub fn open_vault_version(&self, vault_id: String, revision: f64, signal: Option<AbortSignal>) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.open_vault_version(vault_id, u64_arg(revision, "revision")?, t).await })
    }

    /// Keeps an entry the AutoFill extension saved, for the app to merge later.
    #[wasm_bindgen(js_name = keepAutofillEdit, unchecked_return_type = "Promise<void>")]
    pub fn keep_autofill_edit(
        &self,
        vault_id: String,
        #[wasm_bindgen(unchecked_param_type = "EntryRecord")] entry: JsValue,
        group_path: String,
    ) -> Promise {
        let a = self.0.clone();
        call0(async move { a.keep_autofill_edit(vault_id, arg(&entry, "entry")?, group_path).await })
    }

    /// Removes AutoFill edits once taken.
    #[wasm_bindgen(js_name = clearAutofillEdits, unchecked_return_type = "Promise<void>")]
    pub fn clear_autofill_edits(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AutoFillEdits")] edits: JsValue,
    ) -> Promise {
        let a = self.0.clone();
        call0(async move { a.clear_autofill_edits(arg(&edits, "edits")?).await })
    }

    // ---- settings with record arguments

    /// Changes the master password; returns the new AUK.
    #[wasm_bindgen(js_name = changePassword, unchecked_return_type = "Promise<Uint8Array>")]
    pub fn change_password(
        &self,
        current: Vec<u8>,
        next: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "KdfOverrides | undefined")] kdf: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.change_password(current, next, arg(&kdf, "kdf")?, t).await })
    }

    /// Resets the account from a recovery link (SPEC §18).
    #[wasm_bindgen(unchecked_return_type = "Promise<NewAccount>")]
    pub fn recover(
        &self,
        token: Vec<u8>,
        password: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "KdfOverrides | undefined")] kdf: JsValue,
        trust_device: bool,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.recover(token, password, arg(&kdf, "kdf")?, trust_device, t).await })
    }

    // ---- plans

    /// The upgrade page for a `plan_limit` / `quota_exceeded` error.
    #[wasm_bindgen(js_name = upgradeUrl)]
    pub fn upgrade_url(
        &self,
        #[wasm_bindgen(unchecked_param_type = "OvError")] error: JsValue,
    ) -> Result<Option<String>, JsValue> {
        let e = arg(&error, "error").map_err(arg_err)?;
        Ok(self.0.upgrade_url(e))
    }

    // ---- sharing with record arguments

    /// Shares a vault with a user (SPEC §7).
    #[wasm_bindgen(js_name = shareVault, unchecked_return_type = "Promise<GrantResult>")]
    pub fn share_vault(
        &self,
        vault_id: String,
        #[wasm_bindgen(unchecked_param_type = "Grantee")] grantee: JsValue,
        #[wasm_bindgen(unchecked_param_type = "VaultRole")] role: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move {
            a.share_vault(vault_id, arg(&grantee, "grantee")?, arg(&role, "role")?, t).await
        })
    }

    /// Changes a member's role on a vault.
    #[wasm_bindgen(js_name = changeRole, unchecked_return_type = "Promise<void>")]
    pub fn change_role(
        &self,
        vault_id: String,
        principal: String,
        #[wasm_bindgen(unchecked_param_type = "VaultRole")] role: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.change_role(vault_id, principal, arg(&role, "role")?, t).await })
    }

    /// Sets an org's item share-link policy.
    #[wasm_bindgen(js_name = setOrgShareLinks, unchecked_return_type = "Promise<Org>")]
    pub fn set_org_share_links(
        &self,
        org_id: String,
        #[wasm_bindgen(unchecked_param_type = "ShareLinkPolicy")] policy: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.set_org_share_links(org_id, arg(&policy, "policy")?, t).await })
    }

    /// Invites an email to an org.
    #[wasm_bindgen(unchecked_return_type = "Promise<Invitation>")]
    pub fn invite(
        &self,
        org_id: String,
        email: String,
        #[wasm_bindgen(unchecked_param_type = "OrgRole")] role: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.invite(org_id, email, arg(&role, "role")?, t).await })
    }

    /// Confirms an accepted member and grants vaults.
    #[wasm_bindgen(js_name = confirmMember, unchecked_return_type = "Promise<Member>")]
    pub fn confirm_member(
        &self,
        org_id: String,
        #[wasm_bindgen(unchecked_param_type = "Member")] member: JsValue,
        #[wasm_bindgen(unchecked_param_type = "VaultGrantRequest[]")] vaults: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move {
            a.confirm_member(org_id, arg(&member, "member")?, arg(&vaults, "vaults")?, t).await
        })
    }

    /// Promotes or demotes a member.
    #[wasm_bindgen(js_name = setMemberRole, unchecked_return_type = "Promise<Member>")]
    pub fn set_member_role(
        &self,
        org_id: String,
        #[wasm_bindgen(unchecked_param_type = "Member")] member: JsValue,
        #[wasm_bindgen(unchecked_param_type = "OrgRole")] role: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move {
            a.set_member_role(org_id, arg(&member, "member")?, arg(&role, "role")?, t).await
        })
    }

    /// Creates a service account (SPEC §9).
    #[wasm_bindgen(js_name = createServiceAccount, unchecked_return_type = "Promise<CreatedServiceAccount>")]
    pub fn create_service_account(
        &self,
        org_id: String,
        #[wasm_bindgen(unchecked_param_type = "NewServiceAccount")] input: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.create_service_account(org_id, arg(&input, "input")?, t).await })
    }

    /// Changes a service-account secret's expiry.
    #[wasm_bindgen(js_name = setSecretExpiry, unchecked_return_type = "Promise<SaSecretInfo>")]
    pub fn set_secret_expiry(
        &self,
        sa_id: String,
        secret_id: String,
        #[wasm_bindgen(unchecked_param_type = "ExpiryChange")] expires_at: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(
            signal,
            move |t| async move { a.set_secret_expiry(sa_id, secret_id, arg(&expires_at, "expiresAt")?, t).await },
        )
    }

    /// Updates a service account.
    #[wasm_bindgen(js_name = updateServiceAccount, unchecked_return_type = "Promise<ServiceAccountInfo>")]
    pub fn update_service_account(
        &self,
        sa_id: String,
        #[wasm_bindgen(unchecked_param_type = "ServiceAccountUpdate")] update: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(signal, move |t| async move { a.update_service_account(sa_id, arg(&update, "update")?, t).await })
    }

    // ---- share links with record arguments

    /// The share page's base URL, if the server has one.
    #[wasm_bindgen(js_name = shareBase)]
    pub fn share_base(&self) -> Option<String> {
        self.0.share_base()
    }

    /// Creates a share link (SPEC §22).
    #[wasm_bindgen(js_name = createShare, unchecked_return_type = "Promise<CreatedShare>")]
    pub fn create_share(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SharePayload")] payload: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ShareOptions")] options: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let a = self.0.clone();
        call(
            signal,
            move |t| async move { a.create_share(arg(&payload, "payload")?, arg(&options, "options")?, t).await },
        )
    }
}

account_async! {
    /// Asks the server whether this device's session still stands.
    verifySession = verify_session() -> "Promise<void>";
    /// Completes the next time the server ends this session. Await it in a loop.
    signedOut = signed_out() -> "Promise<SignedOutReason>";
    /// Unlocks a signed-in session with the master password (offline: from the cache).
    unlock = unlock(password: Vec<u8>, secret_key: Option<Vec<u8>>) -> "Promise<Unlocked>";
    /// Unlocks with an AUK kept behind biometrics.
    unlockWithAuk = unlock_with_auk(auk: Vec<u8>) -> "Promise<void>";
    /// Unlocks from keyset secrets saved by `unlockedKeysetSecret`.
    resumeUnlocked = resume_unlocked(keyset_secret: Vec<u8>) -> "Promise<void>";
    /// Signs this device out (and with `forgetDevice` drops the kept Secret Key).
    signOut = sign_out(forget_device: bool) -> "Promise<void>";
    /// Goes back online after working offline.
    reconnect = reconnect() -> "Promise<ReconnectResult>";
    /// Asks the server about a parked session.
    checkParkedSession = check_parked_session(user_id: String) -> "Promise<ParkedCheck>";
    /// Signs a parked session out.
    signOutParked = sign_out_parked(user_id: String) -> "Promise<void>";
    /// Every vault this account can open (SPEC §7).
    vaults = vaults() -> "Promise<VaultInfo[]>";
    /// Downloads and opens a vault.
    openVault = open_vault(vault_id: String) -> "Promise<Vault>";
    /// Creates a vault (SPEC §7, §13).
    createVault = create_vault(name: String, org_id: Option<String>) -> "Promise<Vault>";
    /// Renames a vault (needs `manage`).
    renameVault = rename_vault(vault_id: String, name: String) -> "Promise<VaultInfo>";
    /// Deletes a vault for everyone (needs `manage`).
    deleteVault = delete_vault(vault_id: String) -> "Promise<void>";
    /// The saved versions of a vault, newest first.
    vaultHistory = vault_history(vault_id: String) -> "Promise<VaultVersion[]>";
    /// Live updates (SPEC §11).
    subscribe = subscribe() -> "Promise<EventStream>";
    /// `GET /me` (SPEC §16).
    me = me() -> "Promise<Profile>";
    /// Sends a code to a new email address.
    requestEmailChange = request_email_change(email: String) -> "Promise<void>";
    /// Changes the email with the code that was sent.
    changeEmail = change_email(email: String, code: String, password: Vec<u8>) -> "Promise<void>";
    /// A one-time URL that signs the web app in.
    webSessionUrl = web_session_url(next: Option<String>) -> "Promise<Uint8Array>";
    /// Starts two-step sign-in setup (SPEC §8).
    startTwoStep = start_two_step() -> "Promise<TotpSetup>";
    /// Confirms two-step setup with a code.
    confirmTwoStep = confirm_two_step(code: String) -> "Promise<void>";
    /// Turns two-step sign-in off.
    disableTwoStep = disable_two_step(code: String) -> "Promise<void>";
    /// Signed-in devices.
    devices = devices() -> "Promise<Device[]>";
    /// Signs a device out.
    revokeDevice = revoke_device(device_id: String) -> "Promise<void>";
    /// What a recovery link resets (SPEC §18).
    recoverInfo = recover_info(token: Vec<u8>) -> "Promise<RecoveryReset>";
    /// Whether an archive from a reset can be restored.
    recoveryStatus = recovery_status() -> "Promise<RecoveryStatus>";
    /// Restores vaults from the archive with the old credentials.
    restoreFromArchive = restore_from_archive(old_password: Vec<u8>, old_secret_key: Vec<u8>) -> "Promise<number>";
    /// What deleting the account would do (SPEC §23).
    deletionPreview = deletion_preview() -> "Promise<DeletionPreview>";
    /// Schedules the account's deletion; returns the erase date.
    deleteAccount = delete_account(password: Vec<u8>, confirm: String) -> "Promise<Rfc3339>";
    /// Cancels a scheduled deletion.
    restoreAccount = restore_account(password: Vec<u8>) -> "Promise<void>";
    /// Hands a vault to another member before deletion.
    transferVault = transfer_vault(vault_id: String, to: String) -> "Promise<void>";
    /// The account's plan (SPEC §19).
    plan = plan() -> "Promise<Plan | undefined>";
    /// Whether In-App Purchase is possible.
    appleEligibility = apple_eligibility(org_id: Option<String>) -> "Promise<AppleEligibility>";
    /// Reports an App Store transaction.
    reportAppleTransaction = report_apple_transaction(jws: String) -> "Promise<AppleTransactionResult>";
    /// A vault's members.
    members = members(vault_id: String) -> "Promise<VaultMember[]>";
    /// A principal's public keys, verified.
    verifiedPublicKeys = verified_public_keys(principal: String) -> "Promise<PublicKeys>";
    /// Looks a user up by email for sharing.
    lookUp = look_up(email: String) -> "Promise<ShareRecipient>";
    /// A known principal as a share recipient.
    recipient = recipient(principal: String, display: Option<String>) -> "Promise<ShareRecipient>";
    /// Revokes members from a vault (rotating its key).
    revoke = revoke(vault_id: String, principals: Vec<String>) -> "Promise<SyncReport>";
    /// Rotates a vault's key, optionally removing principals.
    rotateVaultKey = rotate_vault_key(vault_id: String, remove: Vec<String>) -> "Promise<SyncReport>";
    /// The orgs this account belongs to (SPEC §12).
    orgs = orgs() -> "Promise<OrgMembership[]>";
    /// Creates an org.
    createOrg = create_org(name: String) -> "Promise<Org>";
    /// One org.
    org = org(org_id: String) -> "Promise<Org>";
    /// Renames an org.
    renameOrg = rename_org(org_id: String, name: String) -> "Promise<Org>";
    /// Deletes an org.
    deleteOrg = delete_org(org_id: String) -> "Promise<void>";
    /// An org's members.
    orgMembers = org_members(org_id: String) -> "Promise<Member[]>";
    /// An org's open invitations.
    invitations = invitations(org_id: String) -> "Promise<Invitation[]>";
    /// Cancels an invitation.
    cancelInvitation = cancel_invitation(org_id: String, invitation_id: String) -> "Promise<void>";
    /// Accepts an invitation.
    acceptInvitation = accept_invitation(token: Vec<u8>) -> "Promise<Member>";
    /// Removes a member (rotating the vaults they could open).
    removeMember = remove_member(org_id: String, user_id: String) -> "Promise<RotationReport>";
    /// Rotates every vault flagged for rotation.
    rotateFlagged = rotate_flagged(org_id: String) -> "Promise<RotationReport>";
    /// The org's vaults an admin manages.
    managedOrgVaults = managed_org_vaults(org_id: String) -> "Promise<VaultInfo[]>";
    /// One page of an org's audit log.
    auditLog = audit_log(org_id: String, before: Option<String>, limit: Option<u32>) -> "Promise<AuditPage>";
    /// An org's service accounts.
    serviceAccounts = service_accounts(org_id: String) -> "Promise<ServiceAccountInfo[]>";
    /// Issues a new secret for a service account.
    issueServiceAccountSecret = issue_service_account_secret(sa_id: String, name: Option<String>, expires_at: Option<String>) -> "Promise<IssuedSecret>";
    /// A service account's secrets.
    serviceAccountSecrets = service_account_secrets(sa_id: String) -> "Promise<SaSecretInfo[]>";
    /// Revokes a service-account secret.
    revokeSecret = revoke_secret(sa_id: String, secret_id: String) -> "Promise<void>";
    /// Deletes a service account.
    deleteServiceAccount = delete_service_account(sa_id: String) -> "Promise<void>";
    /// Your share links.
    listShares = list_shares() -> "Promise<ShareListing[]>";
    /// Ends a share link.
    revokeShare = revoke_share(share_id: String) -> "Promise<void>";
}

account_async0! {
    /// The stored session (without tokens).
    storedSession = stored_session() -> "Promise<StoredSession | undefined>";
    /// Whether this device keeps the Secret Key for `email`.
    hasSecretKey = has_secret_key(email: String) -> "Promise<boolean>";
    /// The Secret Key this device keeps for `email`.
    storedSecretKey = stored_secret_key(email: String) -> "Promise<Uint8Array | undefined>";
    /// Removes the kept Secret Key and device id for `email`.
    forgetDevice = forget_device(email: String) -> "Promise<void>";
    /// The KDF parameters cached at the last sign-in or unlock.
    cachedKdf = cached_kdf() -> "Promise<KdfParams | undefined>";
    /// Locks and sets this session aside (SPEC §21).
    parkSession = park_session() -> "Promise<boolean>";
    /// Makes a parked session the active one.
    resumeSession = resume_session(user_id: String) -> "Promise<boolean>";
    /// The vault list from the last successful call, without the network.
    cachedVaults = cached_vaults() -> "Promise<VaultInfo[] | undefined>";
    /// Opens a vault from this device's copies only, plus AutoFill's edits.
    openOffline = open_offline(vault_id: String) -> "Promise<Vault>";
    /// Opens this device's copy of a vault, without AutoFill's edits.
    openCopy = open_copy(vault_id: String) -> "Promise<Vault>";
    /// Whether any vault has edits waiting on this device.
    hasAnyPendingEdits = has_any_pending_edits() -> "Promise<boolean>";
    /// Whether a vault has edits waiting on this device.
    hasPendingEdits = has_pending_edits(vault_id: String) -> "Promise<boolean>";
    /// What AutoFill saved for a vault and the app hasn't taken yet.
    autofillEdits = autofill_edits(vault_id: String) -> "Promise<AutoFillEdits | undefined>";
    /// The Secret Key, to show again in settings.
    secretKey = secret_key() -> "Promise<Uint8Array | undefined>";
    /// A vault's storage quota in bytes.
    vaultQuota = vault_quota(vault_id: String) -> "Promise<number | undefined>";
    /// Why share links are blocked for an org (or personal vaults), if they are.
    shareBlockedReason = share_blocked_reason(org_id: Option<String>) -> "Promise<string | undefined>";
}

// ------------------------------------------------------------------------------------- Vault

/// One open vault: an account vault, a local file, or a read-only saved version.
#[wasm_bindgen(js_name = Vault)]
pub struct VaultJs(pub(crate) Vault);

/// Synchronous `Vault` methods that return `Result<T, OvError>`.
macro_rules! vault_sync {
    ($( $(#[$doc:meta])* $js:ident = $rust:ident ( $($p:ident : $pt:ty),* ) -> $ts:literal; )*) => {
        #[wasm_bindgen(js_class = Vault)]
        impl VaultJs {$(
            $(#[$doc])*
            #[wasm_bindgen(js_name = $js, unchecked_return_type = $ts)]
            pub fn $rust(&self, $($p: $pt),*) -> Result<JsValue, JsValue> {
                error::js(self.0.$rust($($p),*))
            }
        )*}
    };
}

#[wasm_bindgen(js_class = Vault)]
impl VaultJs {
    /// Opens a local `.kdbx`.
    #[wasm_bindgen(js_name = openLocal, unchecked_return_type = "Promise<Vault>")]
    pub fn open_local(
        kdbx: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "KdbxCredentials")] credentials: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        call(signal, move |t| async move { Vault::open_local(kdbx, arg(&credentials, "credentials")?, t).await })
    }

    /// Creates a new local database.
    #[wasm_bindgen(js_name = createLocal, unchecked_return_type = "Promise<Vault>")]
    pub fn create_local(
        name: String,
        #[wasm_bindgen(unchecked_param_type = "KdbxCredentials")] credentials: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        call(signal, move |t| async move { Vault::create_local(name, arg(&credentials, "credentials")?, t).await })
    }

    /// Encrypts a local database for saving.
    #[wasm_bindgen(js_name = saveLocal, unchecked_return_type = "Promise<Uint8Array>")]
    pub fn save_local(&self, signal: Option<AbortSignal>) -> Promise {
        let v = self.0.clone();
        call(signal, move |t| async move { v.save_local(t).await })
    }

    /// The vault id (or the local database's id).
    pub fn id(&self) -> String {
        self.0.id()
    }

    /// The vault's name.
    pub fn name(&self) -> String {
        self.0.name()
    }

    /// The account vault's info (`undefined` for a local file).
    #[wasm_bindgen(unchecked_return_type = "VaultInfo | undefined")]
    pub fn info(&self) -> JsValue {
        self.0.info().to_js()
    }

    /// The ETag of the last sync.
    pub fn etag(&self) -> Option<String> {
        self.0.etag()
    }

    /// Opened from this device's copy because the server couldn't be reached.
    #[wasm_bindgen(js_name = isOffline)]
    pub fn is_offline(&self) -> bool {
        self.0.is_offline()
    }

    /// A saved version, or a vault this account can only read.
    #[wasm_bindgen(js_name = isReadOnly)]
    pub fn is_read_only(&self) -> bool {
        self.0.is_read_only()
    }

    /// Conflicts from the last sync.
    #[wasm_bindgen(unchecked_return_type = "SyncConflict[]")]
    pub fn conflicts(&self) -> JsValue {
        self.0.conflicts().to_js()
    }

    /// The root group's id.
    #[wasm_bindgen(js_name = rootGroupId)]
    pub fn root_group_id(&self) -> String {
        self.0.root_group_id()
    }

    /// Every entry (optionally including the Recycle Bin).
    #[wasm_bindgen(unchecked_return_type = "EntrySummary[]")]
    pub fn entries(&self, include_recycle_bin: bool) -> JsValue {
        self.0.entries(include_recycle_bin).to_js()
    }

    /// Every group.
    #[wasm_bindgen(unchecked_return_type = "GroupInfo[]")]
    pub fn groups(&self) -> JsValue {
        self.0.groups().to_js()
    }

    /// The group at a `/`-separated path.
    #[wasm_bindgen(js_name = groupIdAt)]
    pub fn group_id_at(&self, path: String) -> Option<String> {
        self.0.group_id_at(path)
    }

    /// Whether an entry or group is in the Recycle Bin.
    #[wasm_bindgen(js_name = isInRecycleBin)]
    pub fn is_in_recycle_bin(&self, id: String) -> bool {
        self.0.is_in_recycle_bin(id)
    }

    /// Writes one field and syncs (TS `AccountVault.write`).
    #[wasm_bindgen(js_name = writeField, unchecked_return_type = "Promise<SyncReport>")]
    pub fn write_field(&self, reference: String, value: Vec<u8>, create: bool, signal: Option<AbortSignal>) -> Promise {
        let v = self.0.clone();
        call(signal, move |t| async move { v.write_field(reference, value, create, t).await })
    }

    /// Sets several fields of an entry found by reference.
    #[wasm_bindgen(js_name = setFields, unchecked_return_type = "SetFieldsResult")]
    pub fn set_fields(
        &self,
        reference: String,
        #[wasm_bindgen(unchecked_param_type = "FieldInput[]")] fields: JsValue,
        #[wasm_bindgen(unchecked_param_type = "CreateMode")] create: JsValue,
    ) -> Result<JsValue, JsValue> {
        let fields = arg(&fields, "fields").map_err(arg_err)?;
        let create = arg(&create, "create").map_err(arg_err)?;
        error::js(self.0.set_fields(reference, fields, create))
    }

    /// Adds an entry; returns its id.
    #[wasm_bindgen(js_name = addEntry, unchecked_return_type = "string")]
    pub fn add_entry(
        &self,
        group_id: String,
        #[wasm_bindgen(unchecked_param_type = "EntryInput")] input: JsValue,
    ) -> Result<JsValue, JsValue> {
        let input = arg(&input, "input").map_err(arg_err)?;
        error::js(self.0.add_entry(group_id, input))
    }

    /// Edits an entry (keeping a history copy).
    #[wasm_bindgen(js_name = editEntry, unchecked_return_type = "undefined")]
    pub fn edit_entry(
        &self,
        entry_id: String,
        #[wasm_bindgen(unchecked_param_type = "EntryInput")] input: JsValue,
    ) -> Result<JsValue, JsValue> {
        let input = arg(&input, "input").map_err(arg_err)?;
        error::js(self.0.edit_entry(entry_id, input))
    }

    /// How an entry differs between this vault and a saved version.
    #[wasm_bindgen(js_name = versionDifference, unchecked_return_type = "VersionDifference")]
    pub fn version_difference(&self, version: &VaultJs, entry_id: String) -> Result<JsValue, JsValue> {
        error::js(self.0.version_difference(version.0.clone(), entry_id))
    }

    /// Restores an entry from a saved version.
    #[wasm_bindgen(js_name = restoreEntry, unchecked_return_type = "undefined")]
    pub fn restore_entry(&self, version: &VaultJs, entry_id: String, group_path: String) -> Result<JsValue, JsValue> {
        error::js(self.0.restore_entry(version.0.clone(), entry_id, group_path))
    }

    /// Merges AutoFill's edits into this vault.
    #[wasm_bindgen(js_name = applyAutofillEdits, unchecked_return_type = "boolean")]
    pub fn apply_autofill_edits(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AutoFillEdits")] edits: JsValue,
    ) -> Result<JsValue, JsValue> {
        let edits = arg(&edits, "edits").map_err(arg_err)?;
        error::js(self.0.apply_autofill_edits(edits))
    }

    /// Syncs with the server (SPEC §11).
    #[wasm_bindgen(unchecked_return_type = "Promise<SyncReport>")]
    pub fn sync(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SyncOptions | undefined")] options: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let v = self.0.clone();
        call(signal, move |t| async move {
            let options: Option<api::SyncOptions> = arg(&options, "options")?;
            v.sync(options.unwrap_or_default(), t).await
        })
    }

    /// Keeps local edits in the offline cache without syncing.
    #[wasm_bindgen(js_name = keepEdits, unchecked_return_type = "Promise<void>")]
    pub fn keep_edits(&self) -> Promise {
        let v = self.0.clone();
        call0(async move { v.keep_edits().await })
    }

    /// Whether this vault has edits waiting for its next upload.
    #[wasm_bindgen(js_name = hasPendingEdits, unchecked_return_type = "Promise<boolean>")]
    pub fn has_pending_edits(&self) -> Promise {
        let v = self.0.clone();
        call0(async move { v.has_pending_edits().await })
    }

    /// Exports as a `.kdbx` under new credentials (optionally only some groups).
    #[wasm_bindgen(js_name = exportKdbx, unchecked_return_type = "Promise<Uint8Array>")]
    pub fn export_kdbx(
        &self,
        #[wasm_bindgen(unchecked_param_type = "KdbxCredentials")] credentials: JsValue,
        group_ids: Option<Vec<String>>,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let v = self.0.clone();
        call(signal, move |t| async move { v.export_kdbx(arg(&credentials, "credentials")?, group_ids, t).await })
    }

    /// Exports in the clear (CSV or JSON).
    #[wasm_bindgen(js_name = exportPlain, unchecked_return_type = "Uint8Array")]
    pub fn export_plain(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ExportFormat")] format: JsValue,
        group_ids: Option<Vec<String>>,
    ) -> Result<JsValue, JsValue> {
        let format = arg(&format, "format").map_err(arg_err)?;
        error::js(self.0.export_plain(format, group_ids))
    }
}

vault_sync! {
    /// One entry by id.
    entry = entry(entry_id: String) -> "EntryRecord";
    /// One entry by reference (`ov://vault/item/field`, id or title).
    find = find(reference: String) -> "EntryRecord";
    /// One field's value by reference.
    readField = read_field(reference: String) -> "Uint8Array";
    /// An entry's history, oldest first.
    history = history(entry_id: String) -> "EntryRecord[]";
    /// An attachment's bytes.
    attachment = attachment(entry_id: String, name: String) -> "Uint8Array";
    /// A custom icon's PNG bytes.
    customIcon = custom_icon(icon_id: String) -> "Uint8Array";
    /// Moves an entry to another group.
    moveEntry = move_entry(entry_id: String, group_id: String) -> "undefined";
    /// Deletes an entry (to the Recycle Bin when enabled).
    deleteEntry = delete_entry(entry_id: String) -> "undefined";
    /// Restores an entry or group from the Recycle Bin.
    restoreFromRecycleBin = restore_from_recycle_bin(id: String) -> "undefined";
    /// Empties the Recycle Bin.
    emptyRecycleBin = empty_recycle_bin() -> "undefined";
    /// Adds or replaces an attachment.
    setAttachment = set_attachment(entry_id: String, name: String, data: Vec<u8>) -> "undefined";
    /// Removes an attachment.
    removeAttachment = remove_attachment(entry_id: String, name: String) -> "undefined";
    /// Adds a custom icon; returns its id.
    addCustomIcon = add_custom_icon(png: Vec<u8>) -> "string";
    /// Adds a group; returns its id.
    addGroup = add_group(parent_id: Option<String>, name: String) -> "string";
    /// The group at a path, creating missing groups; returns its id.
    ensureGroup = ensure_group(path: String) -> "string";
    /// Renames a group.
    renameGroup = rename_group(group_id: String, name: String) -> "undefined";
    /// Sets a group's icon.
    setGroupIcon = set_group_icon(group_id: String, icon_id: u32) -> "undefined";
    /// Moves a group.
    moveGroup = move_group(group_id: String, parent_id: String) -> "undefined";
    /// Deletes a group.
    deleteGroup = delete_group(group_id: String) -> "undefined";
}

// ---------------------------------------------------------------------------- ServiceAccount

/// A service account signed in with its token (SPEC §9, §15).
#[wasm_bindgen(js_name = ServiceAccount)]
pub struct ServiceAccountJs(pub(crate) ServiceAccount);

#[wasm_bindgen(js_class = ServiceAccount)]
impl ServiceAccountJs {
    /// Signs in with a service-account token.
    #[wasm_bindgen(js_name = fromToken, unchecked_return_type = "Promise<ServiceAccount>")]
    pub fn from_token(client: &OvClientJs, token: Vec<u8>, signal: Option<AbortSignal>) -> Promise {
        let c = client.0.clone();
        call(signal, move |t| async move { ServiceAccount::from_token(c, token, t).await })
    }

    /// The service account's id.
    #[wasm_bindgen(js_name = saId)]
    pub fn sa_id(&self) -> String {
        self.0.sa_id()
    }

    /// `sa:<id>`.
    pub fn principal(&self) -> String {
        self.0.principal()
    }

    /// The vaults it can open.
    #[wasm_bindgen(unchecked_return_type = "Promise<SaVault[]>")]
    pub fn vaults(&self, refresh: bool, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.vaults(refresh, t).await })
    }

    /// One vault by id or name.
    #[wasm_bindgen(unchecked_return_type = "Promise<SaVault>")]
    pub fn vault(&self, id_or_name: String, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.vault(id_or_name, t).await })
    }

    /// Opens a vault by id or name.
    #[wasm_bindgen(js_name = openVault, unchecked_return_type = "Promise<Vault>")]
    pub fn open_vault(&self, id_or_name: String, refresh: bool, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.open_vault(id_or_name, refresh, t).await })
    }

    /// Opens a vault, always downloading it.
    #[wasm_bindgen(unchecked_return_type = "Promise<Vault>")]
    pub fn pull(&self, id_or_name: String, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.pull(id_or_name, t).await })
    }

    /// Reads a secret by reference.
    #[wasm_bindgen(unchecked_return_type = "Promise<Uint8Array>")]
    pub fn read(&self, reference: String, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.read(reference, t).await })
    }

    /// Replaces `ov://` references in a template.
    #[wasm_bindgen(unchecked_return_type = "Promise<Injected>")]
    pub fn inject(&self, template: Vec<u8>, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.inject(template, t).await })
    }

    /// Writes a secret by reference.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn write(&self, reference: String, value: Vec<u8>, create: bool, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.write(reference, value, create, t).await })
    }

    /// Drops the keys from memory.
    pub fn close(&self) {
        self.0.close();
    }
}

// -------------------------------------------------------------------------------- SelfHosted

/// A self-hosted sync server (SPEC §13).
#[wasm_bindgen(js_name = SelfHosted)]
pub struct SelfHostedJs(pub(crate) SelfHosted);

#[wasm_bindgen(js_class = SelfHosted)]
impl SelfHostedJs {
    /// Connects with a device token.
    pub fn connect(client: &OvClientJs, server_url: String, device_token: Vec<u8>) -> Result<SelfHostedJs, JsValue> {
        SelfHosted::connect(client.0.clone(), server_url, device_token).map(SelfHostedJs).map_err(|e| error::to_js(&e))
    }

    /// Pairs this device with a pairing code.
    #[wasm_bindgen(unchecked_return_type = "Promise<SelfHosted>")]
    pub fn pair(
        client: &OvClientJs,
        server_url: String,
        code: String,
        device_name: String,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let c = client.0.clone();
        call(signal, move |t| async move { SelfHosted::pair(c, server_url, code, device_name, t).await })
    }

    /// Reconnects with the device token kept in the secure store.
    #[wasm_bindgen(unchecked_return_type = "Promise<SelfHosted | undefined>")]
    pub fn restore(client: &OvClientJs, server_url: String) -> Promise {
        let c = client.0.clone();
        call0(async move { SelfHosted::restore(c, server_url).await })
    }

    /// The server URL.
    #[wasm_bindgen(js_name = serverUrl)]
    pub fn server_url(&self) -> String {
        self.0.server_url()
    }

    /// The server's health text.
    #[wasm_bindgen(unchecked_return_type = "Promise<string>")]
    pub fn health(&self, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.health(t).await })
    }

    /// The databases on the server.
    #[wasm_bindgen(js_name = listDatabases, unchecked_return_type = "Promise<BlobMeta[]>")]
    pub fn list_databases(&self, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.list_databases(t).await })
    }

    /// A code to pair another device.
    #[wasm_bindgen(js_name = createPairingCode, unchecked_return_type = "Promise<PairingCode>")]
    pub fn create_pairing_code(&self, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.create_pairing_code(t).await })
    }

    /// Syncs a local `.kdbx` with the server's copy.
    #[wasm_bindgen(js_name = syncDatabase, unchecked_return_type = "Promise<SelfHostedSyncResult>")]
    pub fn sync_database(
        &self,
        database_id: String,
        kdbx: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "KdbxCredentials")] credentials: JsValue,
        signal: Option<AbortSignal>,
    ) -> Promise {
        let s = self.0.clone();
        call(
            signal,
            move |t| async move { s.sync_database(database_id, kdbx, arg(&credentials, "credentials")?, t).await },
        )
    }

    /// Live updates from the server.
    #[wasm_bindgen(unchecked_return_type = "Promise<EventStream>")]
    pub fn events(&self, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.events(t).await })
    }
}

// ------------------------------------------------------------------------------- EventStream

/// Live updates: `await next()` in a loop until it resolves `undefined`.
#[wasm_bindgen(js_name = EventStream)]
pub struct EventStreamJs(pub(crate) EventStream);

#[wasm_bindgen(js_class = EventStream)]
impl EventStreamJs {
    /// The next event, or `undefined` once closed.
    #[wasm_bindgen(unchecked_return_type = "Promise<AccountEvent | undefined>")]
    pub fn next(&self, signal: Option<AbortSignal>) -> Promise {
        let s = self.0.clone();
        call(signal, move |t| async move { s.next(t).await })
    }

    /// Reconnects now (e.g. after the page comes back online).
    pub fn reconnect(&self) {
        self.0.reconnect();
    }

    /// Closes the stream.
    pub fn close(&self) {
        self.0.close();
    }
}

// ------------------------------------------------------------------------------ free functions

/// Whether a remembered account's erase date is more than a day past.
#[wasm_bindgen(js_name = deletionExpired)]
pub fn deletion_expired(scheduled_for: Option<String>, now_ms: f64) -> Result<bool, JsValue> {
    let now = i64_arg(now_ms, "nowMs").map_err(arg_err)?;
    Ok(api::deletion_expired(scheduled_for, now))
}

/// The fields an item share includes by default.
#[wasm_bindgen(js_name = defaultShareFields)]
pub fn default_share_fields() -> Vec<String> {
    api::default_share_fields()
}

/// The fields of an entry that can be shared.
#[wasm_bindgen(js_name = shareableFields, unchecked_return_type = "ShareableField[]")]
pub fn shareable_fields(
    #[wasm_bindgen(unchecked_param_type = "EntryRecord")] entry: JsValue,
) -> Result<JsValue, JsValue> {
    let entry = arg(&entry, "entry").map_err(arg_err)?;
    Ok(api::shareable_fields(entry).to_js())
}

/// The payload of an item share.
#[wasm_bindgen(js_name = itemSharePayload, unchecked_return_type = "SharePayload")]
pub fn item_share_payload(
    #[wasm_bindgen(unchecked_param_type = "EntryRecord")] entry: JsValue,
    names: Vec<String>,
    shared_by: Option<String>,
) -> Result<JsValue, JsValue> {
    let entry = arg(&entry, "entry").map_err(arg_err)?;
    Ok(api::item_share_payload(entry, names, shared_by).to_js())
}

/// The payload of a text share.
#[wasm_bindgen(js_name = textSharePayload, unchecked_return_type = "SharePayload")]
pub fn text_share_payload(text: Vec<u8>, title: Option<String>, shared_by: Option<String>) -> JsValue {
    api::text_share_payload(text, title, shared_by).to_js()
}

/// Parses an `otpauth://` URI.
#[wasm_bindgen(js_name = parseTotpUri, unchecked_return_type = "TotpParams")]
pub fn parse_totp_uri(uri: Vec<u8>) -> Result<JsValue, JsValue> {
    error::js(api::parse_totp_uri(uri))
}

/// The TOTP code at `nowMs`.
#[wasm_bindgen(js_name = totpCode, unchecked_return_type = "TotpCode")]
pub fn totp_code(
    #[wasm_bindgen(unchecked_param_type = "TotpParams")] params: JsValue,
    now_ms: f64,
) -> Result<JsValue, JsValue> {
    let params = arg(&params, "params").map_err(arg_err)?;
    let now = i64_arg(now_ms, "nowMs").map_err(arg_err)?;
    Ok(api::totp_code(params, now).to_js())
}

/// An entry's TOTP URI, from its fields (KeePassXC and KeePass conventions).
#[wasm_bindgen(js_name = entryTotpUri, unchecked_return_type = "Uint8Array | undefined")]
pub fn entry_totp_uri(
    #[wasm_bindgen(unchecked_param_type = "FieldRecord[]")] fields: JsValue,
    label: String,
) -> Result<JsValue, JsValue> {
    let fields = arg(&fields, "fields").map_err(arg_err)?;
    Ok(api::entry_totp_uri(fields, label).to_js())
}
