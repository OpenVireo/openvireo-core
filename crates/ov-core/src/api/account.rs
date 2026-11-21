//! [`Account`]: one account on one server. Signed out, signed in but locked, or unlocked.
//!
//! Sign-up and sign-in (SPEC §3, §8, §9), unlock and lock, offline unlock (§20), sessions on a
//! shared device (§21), the vault list and opening vaults (§7), history (§11), AutoFill edits and
//! live events. Settings, recovery and deletion are in `settings.rs`; sharing and orgs in
//! `sharing.rs`; share links in `share_links.rs`; plans in `plan.rs`.

use std::sync::Arc;

use ov_error::OvError;

use super::{
    AutoFillEdits, CancelToken, EntryRecord, EventStream, ImportMode, ImportOutcome, KdbxCredentials, KdfOverrides,
    KdfParams, NewAccount, ParkedCheck, Principal, ReconnectResult, Rfc3339, SecretBytes, ServerConfig,
    SignedOutReason, StoredSession, SyncOptions, Vault, VaultInfo, VaultKdbxSyncResult, VaultVersion,
};
use crate::host::HttpRequest;
use crate::state::{AccountState, TotpState};

/// An account on one server. Cheap to clone; clones share state.
///
/// Port of the TS SDK's `Account` and the iOS `Account` actor. Made by
/// [`OvClient::connect`](crate::api::OvClient::connect).
#[derive(Clone)]
pub struct Account {
    pub(crate) inner: Arc<AccountState>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Account { .. }")
    }
}

/// Input of [`Account::register`].
#[derive(Clone, PartialEq, Eq)]
pub struct RegisterInput {
    /// The email (trimmed by the core).
    pub email: String,
    /// The master password, UTF-8 (NFKC-normalised by the core, not trimmed; SPEC §3).
    pub password: SecretBytes,
    /// KDF overrides (default `m=65536, t=3, p=1`).
    pub kdf: Option<KdfOverrides>,
    /// Keep the Secret Key on this device for later sign-ins (default in the SDK: true).
    pub trust_device: bool,
}

impl std::fmt::Debug for RegisterInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterInput").field("email", &self.email).field("trust_device", &self.trust_device).finish()
    }
}

/// Input of [`Account::login`].
#[derive(Clone, PartialEq, Eq)]
pub struct LoginInput {
    /// The email.
    pub email: String,
    /// The master password, UTF-8.
    pub password: SecretBytes,
    /// The Secret Key (`K1-…`); `None` uses the one this device keeps (`invalid_secret_key` if none).
    pub secret_key: Option<SecretBytes>,
    /// A TOTP code to use if the account asks for one (CLI `--totp`); without it a
    /// [`LoginStep::NeedsTotp`] is returned instead.
    pub totp: Option<String>,
    /// Keep the Secret Key on this device (default in the SDK: true).
    pub trust_device: bool,
}

impl std::fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginInput").field("email", &self.email).field("trust_device", &self.trust_device).finish()
    }
}

/// Where a sign-in is.
#[derive(Clone, Debug)]
pub enum LoginStep {
    /// The account has two-step sign-in: ask for a code and pass it to [`Account::submit_totp`].
    NeedsTotp(TotpChallenge),
    /// Signed in and unlocked.
    Unlocked(Unlocked),
}

/// The result of a sign-in or unlock.
#[derive(Clone, PartialEq, Eq)]
pub struct Unlocked {
    /// The AUK, for a biometric unlock later ([`Account::unlock_with_auk`]). Wipe it if unused.
    pub auk: SecretBytes,
    /// Unlocked from the offline cache because the server couldn't be reached (SPEC §20).
    pub offline: bool,
    /// The erase date if the account is pending deletion (SPEC §23); such a session opens no vaults.
    pub deletion_scheduled_for: Option<Rfc3339>,
}

impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked")
            .field("offline", &self.offline)
            .field("deletion_scheduled_for", &self.deletion_scheduled_for)
            .finish()
    }
}

/// A sign-in waiting for a TOTP code (SPEC §8). Holds the MFA token and what finishing the sign-in
/// needs, in memory only, wiped when the last clone is dropped.
#[derive(Clone)]
pub struct TotpChallenge {
    pub(crate) inner: Arc<TotpState>,
}

impl std::fmt::Debug for TotpChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpChallenge { .. }")
    }
}

impl TotpChallenge {
    /// Which try this is, from 1.
    pub fn attempt(&self) -> u32 {
        self.inner.attempt.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The previous wrong code's error (`invalid_mfa`), if any.
    pub fn last_error(&self) -> Option<OvError> {
        crate::impls::util::lock(&self.inner.last_error).clone()
    }
}

impl Account {
    // ------------------------------------------------------------------------------ state

    /// The server's discovery document.
    pub fn server_config(&self) -> ServerConfig {
        self.inner.config.clone()
    }

    /// Working from the offline cache because the server can't be reached (SPEC §20). Edits are
    /// kept and upload once a sync succeeds; [`reconnect`](Self::reconnect) goes back online.
    pub fn is_offline(&self) -> bool {
        crate::impls::util::lock(&self.inner.inner).offline
    }

    /// A session is loaded (it may be locked).
    pub fn is_signed_in(&self) -> bool {
        self.inner.tokens.current().is_some()
    }

    /// The keyset is in memory.
    pub fn is_unlocked(&self) -> bool {
        crate::impls::util::lock(&self.inner.inner).keyset.is_some()
    }

    /// The erase date while the account is pending deletion (SPEC §23), else `None`. Such a session
    /// opens no vaults: offer [`restore_account`](Self::restore_account) or sign out.
    pub fn deletion_scheduled_for(&self) -> Option<Rfc3339> {
        crate::impls::util::lock(&self.inner.inner).deletion.clone()
    }

    /// The signed-in user's id.
    pub fn user_id(&self) -> Option<String> {
        self.inner.tokens.current().map(|s| s.user_id)
    }

    /// The signed-in email.
    pub fn email(&self) -> Option<String> {
        self.inner.tokens.current().map(|s| s.email)
    }

    /// `user:<id>`; `signed_out` without a session.
    pub fn principal(&self) -> Result<Principal, OvError> {
        self.principal_str()
    }

    /// This account's public-key fingerprint, to compare out of band (SPEC §5); `signed_out` while locked.
    pub fn fingerprint(&self) -> Result<String, OvError> {
        self.with_keyset(|ks| ks.public.fingerprint())
    }

    /// How far this device's clock is ahead of the sync server's, from the last sync (ms).
    pub fn clock_offset_ms(&self) -> Option<i64> {
        crate::impls::util::lock(&self.inner.inner).clock_offset_ms
    }

    /// The stored session (without tokens). An error means the secure store couldn't be read, which
    /// is not the same as being signed out (`None`).
    pub async fn stored_session(&self) -> Result<Option<StoredSession>, OvError> {
        Ok(self.inner.tokens.load().await?.map(|s| StoredSession {
            issuer: s.issuer.clone(),
            user_id: s.user_id.clone(),
            email: s.email.clone(),
            device_id: s.device_id.clone(),
        }))
    }

    /// Asks the server whether this device's session still stands (a token refresh), so a device
    /// signed out elsewhere finds out now. Does nothing offline.
    pub async fn verify_session(&self, cancel: CancelToken) -> Result<(), OvError> {
        if self.is_offline() || self.inner.tokens.load().await?.is_none() {
            return Ok(());
        }
        match self.refresh_token(&cancel).await {
            Err(e) if e.is_unreachable() => Ok(()),
            r => r,
        }
    }

    /// Completes the next time the server ends this session (signed out elsewhere, password changed,
    /// refresh token reused or expired, account deleted), after the account has locked and dropped
    /// that user's offline data (SPEC §20). Not for this device's own sign-out. Await it in a loop.
    /// What is dropped depends on the [`SignedOutReason`]: after an accident
    /// ([`TokenReused`](SignedOutReason::TokenReused),
    /// [`SessionExpired`](SignedOutReason::SessionExpired)) the vaults' unsynced and AutoFill edits
    /// stay for the same user's next sign-in (contract-v1.8).
    pub async fn signed_out(&self, cancel: CancelToken) -> Result<SignedOutReason, OvError> {
        let signal = self.inner.signal.clone();
        let seen = signal.count();
        let wait = signal.wait(seen);
        let cancelled = cancel.cancelled();
        futures::pin_mut!(wait, cancelled);
        match futures::future::select(wait, cancelled).await {
            futures::future::Either::Left((reason, _)) => Ok(reason),
            futures::future::Either::Right(_) => Err(OvError::new(ov_error::OvErrorCode::Aborted, "cancelled")),
        }
    }

    /// Whether this device keeps the Secret Key for `email` (so sign-in needs only the password).
    pub async fn has_secret_key(&self, email: String) -> Result<bool, OvError> {
        Ok(self.stored_sk(&email).await?.is_some())
    }

    /// The Secret Key this device keeps for `email`, without unlocking (Swift `storedSecretKey`).
    pub async fn stored_secret_key(&self, email: String) -> Result<Option<SecretBytes>, OvError> {
        Ok(self.stored_sk(&email).await?.map(|s| s.as_bytes().to_vec()))
    }

    // ------------------------------------------------------------------- sign-up, sign-in

    /// Creates an account (SPEC §2, §3, §5, §8): a new Secret Key, KDF salt and keyset, OPAQUE
    /// registration, then signed in and unlocked. Show the returned Secret Key once (Emergency Kit).
    pub async fn register(&self, input: RegisterInput, cancel: CancelToken) -> Result<NewAccount, OvError> {
        self.register_impl(input, &cancel).await
    }

    /// OPAQUE sign-in (SPEC §8), then unlock. Returns [`LoginStep::NeedsTotp`] when the account has
    /// two-step sign-in and `input.totp` is `None`. A wrong password or unknown email is
    /// `unauthorized` (401) either way.
    pub async fn login(&self, input: LoginInput, cancel: CancelToken) -> Result<LoginStep, OvError> {
        self.login_impl(input, &cancel).await
    }

    /// Sends a TOTP code for a waiting sign-in. A wrong code is `invalid_mfa` and the challenge stays
    /// usable (its [`attempt`](TotpChallenge::attempt) goes up); once the server drops the MFA token
    /// (5th wrong code, or it expired) it is `mfa_expired` and the sign-in starts over.
    pub async fn submit_totp(
        &self,
        challenge: TotpChallenge,
        code: String,
        cancel: CancelToken,
    ) -> Result<LoginStep, OvError> {
        self.submit_totp_impl(challenge, code, &cancel).await
    }

    /// Unlocks a signed-in session with the master password, without an OPAQUE round trip. With
    /// the offline cache, an unreachable server falls back to the wrapped keyset cached at the last
    /// sign-in or unlock (SPEC §20), so password and Secret Key still have to be right; a refusal
    /// online retries once with a fresher profile (password changed elsewhere).
    pub async fn unlock(
        &self,
        password: SecretBytes,
        secret_key: Option<SecretBytes>,
        cancel: CancelToken,
    ) -> Result<Unlocked, OvError> {
        self.unlock_impl(password, secret_key, &cancel).await
    }

    /// Unlocks with an AUK kept behind biometrics (Swift `unlock(auk:)`). Offline it uses the cached
    /// profile.
    pub async fn unlock_with_auk(&self, auk: SecretBytes, cancel: CancelToken) -> Result<(), OvError> {
        self.unlock_with_auk_impl(auk, &cancel).await
    }

    /// The unlocked keyset's private halves (`enc_sk ‖ sign_seed`, 64 bytes), for the web wrapper's
    /// `sealUnlocked`, which seals them with a non-extractable WebCrypto key so a page reload can
    /// resume. `signed_out` while locked.
    pub fn unlocked_keyset_secret(&self) -> Result<SecretBytes, OvError> {
        self.with_keyset(|ks| ov_vault::keyset_secret(ks).to_vec())
    }

    /// Unlocks from keyset secrets saved by [`unlocked_keyset_secret`](Self::unlocked_keyset_secret)
    /// (TS `resumeUnlocked`). The keys must match the account's public keys (from `/me`, or offline
    /// the cached profile): `invalid_public_keys` otherwise; `signed_out` without a session.
    pub async fn resume_unlocked(&self, keyset_secret: SecretBytes, cancel: CancelToken) -> Result<(), OvError> {
        self.resume_unlocked_impl(keyset_secret, &cancel).await
    }

    /// Clears the keyset and vault keys from memory. The session stays.
    pub fn lock(&self) {
        self.lock_keys()
    }

    /// Signs this device out: revokes the session on the server (best effort), deletes the offline
    /// cache (the [BlobCache](crate::host::BlobCache)'s `clear_user`), unsynced and AutoFill edits
    /// included, and with `forget_device` also the kept Secret Key and device id (SPEC §21). The
    /// same for [`sign_out_parked`](Self::sign_out_parked),
    /// [`delete_account`](Self::delete_account) and a session the server revoked; only an accidental
    /// end keeps the edits ([`SignedOutReason`], contract-v1.8).
    pub async fn sign_out(&self, forget_device: bool, cancel: CancelToken) -> Result<(), OvError> {
        self.sign_out_impl(forget_device, &cancel).await
    }

    /// For a page closing on a shared session (SPEC §21): locks, stops using the session, and returns
    /// the `POST /auth/logout` request (with `keepalive`) for the platform to fire and forget. `None`
    /// when no access token is in hand (a closing page can't refresh one).
    pub fn sign_out_on_unload(&self) -> Option<HttpRequest> {
        let token = self.inner.tokens.access_token_now();
        self.lock_keys();
        token.map(|t| self.inner.auth.build_logout(&t, true))
    }

    /// Removes what signing in again would reuse (Secret Key, device id), so the next sign-in needs
    /// the Emergency Kit. Works signed out; the account must not be the open one.
    pub async fn forget_device(&self, email: String) -> Result<(), OvError> {
        self.forget_device_impl(&email).await
    }

    /// Goes back online after working offline: re-reads the account and the vault list. Vaults no
    /// longer listed are forgotten with their local copies. Fails while still unreachable.
    pub async fn reconnect(&self, cancel: CancelToken) -> Result<ReconnectResult, OvError> {
        let session = self.inner.tokens.load().await?.ok_or_else(|| crate::impls::util::signed_out("not signed in"))?;
        let me = self.call(&cancel, |a, t| a.build_me(t), ov_protocol::auth::parse_me).await?;
        self.follow_email(&me.email).await?;
        crate::impls::util::lock(&self.inner.inner).deletion = me.deletion_scheduled_for.clone();
        self.cache_profile(&session.user_id, &crate::impls::account::CachedProfile { kdf: me.kdf, keyset: me.keyset })
            .await?;
        let (vaults, dropped) = self.load_vault_list(&cancel).await?;
        Ok(ReconnectResult { vaults, dropped })
    }

    /// The KDF parameters cached at the last sign-in or unlock, so AutoFill can check what a
    /// password unlock costs before running it.
    pub async fn cached_kdf(&self) -> Result<Option<KdfParams>, OvError> {
        self.cached_kdf_impl().await
    }

    // ------------------------------------------------------------ several accounts (§21)

    /// Locks and sets this session aside for its user to come back to. The server isn't told and the
    /// offline cache stays. `false` when no session is open.
    pub async fn park_session(&self) -> Result<bool, OvError> {
        self.park_impl().await
    }

    /// Makes a parked session the active one. `false` when it ended (sign in again); an error when
    /// another account is open.
    pub async fn resume_session(&self, user_id: String) -> Result<bool, OvError> {
        self.resume_impl(&user_id).await
    }

    /// Asks the server about a parked session (a refresh), keeping it within its 30 days. A refusal
    /// ends it like any other (SPEC §9, §20), keeping unsynced edits only after an accident
    /// ([`SignedOutReason`]).
    pub async fn check_parked_session(&self, user_id: String, cancel: CancelToken) -> Result<ParkedCheck, OvError> {
        self.check_parked_impl(&user_id, &cancel).await
    }

    /// Signs a parked session out, as [`sign_out`](Self::sign_out) does for the open one.
    pub async fn sign_out_parked(&self, user_id: String, cancel: CancelToken) -> Result<(), OvError> {
        self.sign_out_parked_impl(&user_id, &cancel).await
    }

    // ----------------------------------------------------------------------------- vaults

    /// `GET /vaults`: every vault this account can open, names decrypted (SPEC §7). Offline, the
    /// list from the last successful call.
    pub async fn vaults(&self, cancel: CancelToken) -> Result<Vec<VaultInfo>, OvError> {
        Ok(self.load_vault_list(&cancel).await?.0)
    }

    /// The vault list from the last successful call, without the network; `None` if none is cached.
    pub async fn cached_vaults(&self) -> Result<Option<Vec<VaultInfo>>, OvError> {
        let Some(list) = self.cached_wire_vaults().await? else { return Ok(None) };
        Ok(Some(list.iter().map(|v| self.ingest(v).map(|e| e.info)).collect::<Result<_, _>>()?))
    }

    /// Downloads and opens a vault (newest key first), merging edits this device kept from an
    /// earlier session. Offline, opens this device's copy ([`Vault::is_offline`]); a vault never
    /// synced here is `not_available_offline`. With nothing kept on this device it is one `GET`
    /// (contract-v1.8; before, the download was followed by a sync that downloaded again).
    pub async fn open_vault(&self, vault_id: String, cancel: CancelToken) -> Result<Vault, OvError> {
        self.open_vault_impl(&vault_id, &cancel).await
    }

    /// Opens a vault from this device's copies only (edits not uploaded, else the server's bytes at
    /// the last sync), plus what AutoFill saved since. For the AutoFill extension; never syncs.
    pub async fn open_offline(&self, vault_id: String) -> Result<Vault, OvError> {
        self.open_offline_impl(&vault_id, true).await
    }

    /// Opens this device's copy of a vault without the network and without AutoFill's edits.
    pub async fn open_copy(&self, vault_id: String) -> Result<Vault, OvError> {
        self.open_offline_impl(&vault_id, false).await
    }

    /// Creates a vault: a new vault key sealed to this account (and in an org to every confirmed
    /// owner and admin, after checking their keys), then an empty KDBX uploaded with
    /// `If-None-Match: *` (SPEC §7, §13). An owner or admin whose keys don't verify is
    /// `invalid_public_keys` with `details` `{"principal": "user:<id>", "email": "<email>"}` naming
    /// them, before anything is created (contract-v1.8).
    pub async fn create_vault(
        &self,
        name: String,
        org_id: Option<String>,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        self.create_vault_impl(&name, org_id.as_deref(), &cancel).await
    }

    /// Imports a `.kdbx` (opened with `credentials`) into the account: as a new vault ("Move to
    /// account", re-keyed to a fresh vault key, the original untouched), merged into a vault, or as
    /// copies. If the vault was created but the upload failed, [`ImportOutcome::uploaded`] is false.
    /// A wrong password or key file is `vault_key_mismatch` (TS 0.11; contract-v1.7, was `kdbx_error`).
    /// A file whose key derivation is over this build's limits ([`ov_kdbx::check_kdf_limits`]: Argon2
    /// over 1 GiB or 16 GiB of work, AES-KDF over 10⁹ rounds) is `too_large`, before it runs. An org owner or admin with keys that don't verify is `invalid_public_keys` naming them, as for
    /// [`create_vault`](Self::create_vault). The database custom data (`Meta/CustomData`, where
    /// KeePassXC keeps its remote settings) comes along: whole into a new vault, minus the
    /// sync-server and account-vault remotes; on a merge, the items the vault doesn't have yet
    /// (never its remote settings or sync generation). Contract-v1.8; before, a merge left it out.
    pub async fn import_kdbx(
        &self,
        kdbx: Vec<u8>,
        credentials: KdbxCredentials,
        mode: ImportMode,
        cancel: CancelToken,
    ) -> Result<ImportOutcome, OvError> {
        let key = crate::impls::vaults::local_key(&credentials)?;
        let source = ov_kdbx::read(&kdbx, &key)?;
        self.import_db(source, mode, &cancel).await
    }

    /// Imports an already open vault (a local database, or one synced with a self-hosted server),
    /// as [`import_kdbx`](Self::import_kdbx) does for bytes. TS `importVault(kdbx)`, Swift
    /// `importVault(_ database:)`.
    pub async fn import_vault(
        &self,
        source: Vault,
        mode: ImportMode,
        cancel: CancelToken,
    ) -> Result<ImportOutcome, OvError> {
        let db = crate::impls::util::lock(&source.inner.db).clone();
        self.import_db(db, mode, &cancel).await
    }

    /// Renames a vault (needs `manage`): the encrypted name on the auth server, which every client
    /// shows (SPEC §7, §17).
    pub async fn rename_vault(
        &self,
        vault_id: String,
        name: String,
        cancel: CancelToken,
    ) -> Result<VaultInfo, OvError> {
        self.rename_vault_impl(&vault_id, &name, &cancel).await
    }

    /// Deletes a vault for everyone (needs `manage`): the blob on the sync server, then the vault.
    pub async fn delete_vault(&self, vault_id: String, cancel: CancelToken) -> Result<(), OvError> {
        self.delete_vault_impl(&vault_id, &cancel).await
    }

    /// Whether any vault has edits waiting on this device.
    pub async fn has_any_pending_edits(&self) -> Result<bool, OvError> {
        self.pending_for(None).await
    }

    /// Whether a vault has edits waiting on this device for its next upload.
    pub async fn has_pending_edits(&self, vault_id: String) -> Result<bool, OvError> {
        self.pending_for(Some(&vault_id)).await
    }

    // ------------------------------------------------- vault files and the session token

    /// The credentials an account vault's `.kdbx` is under: its newest vault key as a raw key file
    /// (no password). A secret: wipe it. For a client that keeps the vault as a file (the desktop)
    /// and syncs it with [`sync_vault_kdbx`](Self::sync_vault_kdbx). Contract-v1.6.
    pub async fn vault_kdbx_credentials(
        &self,
        vault_id: String,
        cancel: CancelToken,
    ) -> Result<KdbxCredentials, OvError> {
        crate::impls::vault_files::credentials(self, &vault_id, &cancel).await
    }

    /// Syncs an account vault held as `.kdbx` bytes, as
    /// [`SelfHosted::sync_database`](crate::api::SelfHosted::sync_database) does for a self-hosted
    /// database: download, three-way merge, conditional upload with retries on 412 (SPEC §11, §20),
    /// on `ov-sync`'s state machine.
    /// `kdbx` may be under any of the vault's key versions. The merge base is `base` (the server's
    /// bytes from this device's last sync) or else the one in the cached sync state, which is kept
    /// in the [BlobCache](crate::host::BlobCache) record `kdbx-file:<vault id>` when the account keeps
    /// offline data (apart from [`Vault::sync`]'s: the file is its own working copy).
    /// `server_rolled_back` / `server_lost_database` are errors; sync again with
    /// [`SyncOptions::accept_server_state`] to continue anyway. A vault shared after the token was
    /// issued refreshes the token once. Contract-v1.6.
    pub async fn sync_vault_kdbx(
        &self,
        vault_id: String,
        kdbx: Vec<u8>,
        base: Option<Vec<u8>>,
        options: SyncOptions,
        cancel: CancelToken,
    ) -> Result<VaultKdbxSyncResult, OvError> {
        crate::impls::vault_files::sync(self, &vault_id, kdbx, base, options, &cancel).await
    }

    /// The session's access token (the JWT for the auth and sync servers; SPEC §9 has one audience),
    /// refreshed first when it is about to expire, or when `force_refresh` (after a 403 for a vault
    /// shared since it was issued). For code that still makes its own calls with the core's session;
    /// it never starts a second session. A refused refresh ends the session (`signed_out`). A secret:
    /// don't log it. Contract-v1.6.
    pub async fn access_token(&self, force_refresh: bool, cancel: CancelToken) -> Result<SecretBytes, OvError> {
        Ok(self.bearer_token(force_refresh, &cancel).await?.as_bytes().to_vec())
    }

    // ---------------------------------------------------------------------------- history

    /// The saved versions of a vault on the sync server (SPEC §11 history), newest first.
    pub async fn vault_history(&self, vault_id: String, cancel: CancelToken) -> Result<Vec<VaultVersion>, OvError> {
        self.history_impl(&vault_id, &cancel).await
    }

    /// Opens one saved version, read-only ([`Vault::is_read_only`]).
    pub async fn open_vault_version(
        &self,
        vault_id: String,
        revision: u64,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        self.open_version_impl(&vault_id, revision, &cancel).await
    }

    // ------------------------------------------------------------------- AutoFill (iOS)

    /// Keeps an entry the AutoFill extension saved, for the app to merge later (with earlier ones
    /// not taken yet), encrypted with the vault key.
    pub async fn keep_autofill_edit(
        &self,
        vault_id: String,
        entry: EntryRecord,
        group_path: String,
    ) -> Result<(), OvError> {
        self.keep_autofill_impl(&vault_id, entry, &group_path).await
    }

    /// What AutoFill saved for a vault and the app hasn't taken yet.
    pub async fn autofill_edits(&self, vault_id: String) -> Result<Option<AutoFillEdits>, OvError> {
        self.autofill_edits_impl(&vault_id).await
    }

    /// Removes AutoFill edits once taken, unless newer ones were written meanwhile.
    pub async fn clear_autofill_edits(&self, edits: AutoFillEdits) -> Result<(), OvError> {
        self.clear_autofill_impl(&edits).await
    }

    // ----------------------------------------------------------------------------- events

    /// Live updates (SPEC §11). `vault` events come through as
    /// [`AccountEvent::VaultChanged`](super::AccountEvent::VaultChanged); on `access` events the
    /// account refreshes its token (new `vlt` claims), reloads the vault list
    /// ([`AccountEvent::VaultsChanged`](super::AccountEvent::VaultsChanged)) and reconnects;
    /// `deletion_scheduled` / `account_deleted` end the session
    /// ([`AccountEvent::SessionEnded`](super::AccountEvent::SessionEnded)).
    pub async fn subscribe(&self, cancel: CancelToken) -> Result<EventStream, OvError> {
        cancel.check()?;
        Ok(crate::impls::syncing::stream(self.sync_client(), Some(self.clone())))
    }
}
