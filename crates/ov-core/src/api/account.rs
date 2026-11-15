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
    SignedOutReason, StoredSession, Vault, VaultInfo, VaultVersion,
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
        todo!()
    }

    /// The previous wrong code's error (`invalid_mfa`), if any.
    pub fn last_error(&self) -> Option<OvError> {
        todo!()
    }
}

impl Account {
    // ------------------------------------------------------------------------------ state

    /// The server's discovery document.
    pub fn server_config(&self) -> ServerConfig {
        todo!()
    }

    /// Working from the offline cache because the server can't be reached (SPEC §20). Edits are
    /// kept and upload once a sync succeeds; [`reconnect`](Self::reconnect) goes back online.
    pub fn is_offline(&self) -> bool {
        todo!()
    }

    /// A session is loaded (it may be locked).
    pub fn is_signed_in(&self) -> bool {
        todo!()
    }

    /// The keyset is in memory.
    pub fn is_unlocked(&self) -> bool {
        todo!()
    }

    /// The erase date while the account is pending deletion (SPEC §23), else `None`. Such a session
    /// opens no vaults: offer [`restore_account`](Self::restore_account) or sign out.
    pub fn deletion_scheduled_for(&self) -> Option<Rfc3339> {
        todo!()
    }

    /// The signed-in user's id.
    pub fn user_id(&self) -> Option<String> {
        todo!()
    }

    /// The signed-in email.
    pub fn email(&self) -> Option<String> {
        todo!()
    }

    /// `user:<id>`; `signed_out` without a session.
    pub fn principal(&self) -> Result<Principal, OvError> {
        todo!()
    }

    /// This account's public-key fingerprint, to compare out of band (SPEC §5); `signed_out` while locked.
    pub fn fingerprint(&self) -> Result<String, OvError> {
        todo!()
    }

    /// How far this device's clock is ahead of the sync server's, from the last sync (ms).
    pub fn clock_offset_ms(&self) -> Option<i64> {
        todo!()
    }

    /// The stored session (without tokens). An error means the secure store couldn't be read, which
    /// is not the same as being signed out (`None`).
    pub async fn stored_session(&self) -> Result<Option<StoredSession>, OvError> {
        todo!()
    }

    /// Asks the server whether this device's session still stands (a token refresh), so a device
    /// signed out elsewhere finds out now. Does nothing offline.
    pub async fn verify_session(&self, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// Completes the next time the server ends this session (signed out elsewhere, password changed,
    /// refresh token reused or expired, account deleted), after the account has locked and dropped
    /// that user's offline data (SPEC §20). Not for this device's own sign-out. Await it in a loop.
    pub async fn signed_out(&self, cancel: CancelToken) -> Result<SignedOutReason, OvError> {
        todo!()
    }

    /// Whether this device keeps the Secret Key for `email` (so sign-in needs only the password).
    pub async fn has_secret_key(&self, email: String) -> Result<bool, OvError> {
        todo!()
    }

    /// The Secret Key this device keeps for `email`, without unlocking (Swift `storedSecretKey`).
    pub async fn stored_secret_key(&self, email: String) -> Result<Option<SecretBytes>, OvError> {
        todo!()
    }

    // ------------------------------------------------------------------- sign-up, sign-in

    /// Creates an account (SPEC §2, §3, §5, §8): a new Secret Key, KDF salt and keyset, OPAQUE
    /// registration, then signed in and unlocked. Show the returned Secret Key once (Emergency Kit).
    pub async fn register(&self, input: RegisterInput, cancel: CancelToken) -> Result<NewAccount, OvError> {
        todo!()
    }

    /// OPAQUE sign-in (SPEC §8), then unlock. Returns [`LoginStep::NeedsTotp`] when the account has
    /// two-step sign-in and `input.totp` is `None`. A wrong password or unknown email is
    /// `unauthorized` (401) either way.
    pub async fn login(&self, input: LoginInput, cancel: CancelToken) -> Result<LoginStep, OvError> {
        todo!()
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
        todo!()
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
        todo!()
    }

    /// Unlocks with an AUK kept behind biometrics (Swift `unlock(auk:)`). Offline it uses the cached
    /// profile.
    pub async fn unlock_with_auk(&self, auk: SecretBytes, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// The unlocked keyset's private halves (`enc_sk ‖ sign_seed`, 64 bytes), for the web wrapper's
    /// `sealUnlocked`, which seals them with a non-extractable WebCrypto key so a page reload can
    /// resume. `signed_out` while locked.
    pub fn unlocked_keyset_secret(&self) -> Result<SecretBytes, OvError> {
        todo!()
    }

    /// Unlocks from keyset secrets saved by [`unlocked_keyset_secret`](Self::unlocked_keyset_secret)
    /// (TS `resumeUnlocked`). The keys must match the account's public keys (from `/me`, or offline
    /// the cached profile): `invalid_public_keys` otherwise; `signed_out` without a session.
    pub async fn resume_unlocked(&self, keyset_secret: SecretBytes, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// Clears the keyset and vault keys from memory. The session stays.
    pub fn lock(&self) {
        todo!()
    }

    /// Signs this device out: revokes the session on the server (best effort), deletes the offline
    /// cache, and with `forget_device` also the kept Secret Key and device id (SPEC §21).
    pub async fn sign_out(&self, forget_device: bool, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// For a page closing on a shared session (SPEC §21): locks, stops using the session, and returns
    /// the `POST /auth/logout` request (with `keepalive`) for the platform to fire and forget. `None`
    /// when no access token is in hand (a closing page can't refresh one).
    pub fn sign_out_on_unload(&self) -> Option<HttpRequest> {
        todo!()
    }

    /// Removes what signing in again would reuse (Secret Key, device id), so the next sign-in needs
    /// the Emergency Kit. Works signed out; the account must not be the open one.
    pub async fn forget_device(&self, email: String) -> Result<(), OvError> {
        todo!()
    }

    /// Goes back online after working offline: re-reads the account and the vault list. Vaults no
    /// longer listed are forgotten with their local copies. Fails while still unreachable.
    pub async fn reconnect(&self, cancel: CancelToken) -> Result<ReconnectResult, OvError> {
        todo!()
    }

    /// The KDF parameters cached at the last sign-in or unlock, so AutoFill can check what a
    /// password unlock costs before running it.
    pub async fn cached_kdf(&self) -> Result<Option<KdfParams>, OvError> {
        todo!()
    }

    // ------------------------------------------------------------ several accounts (§21)

    /// Locks and sets this session aside for its user to come back to. The server isn't told and the
    /// offline cache stays. `false` when no session is open.
    pub async fn park_session(&self) -> Result<bool, OvError> {
        todo!()
    }

    /// Makes a parked session the active one. `false` when it ended (sign in again); an error when
    /// another account is open.
    pub async fn resume_session(&self, user_id: String) -> Result<bool, OvError> {
        todo!()
    }

    /// Asks the server about a parked session (a refresh), keeping it within its 30 days. A refusal
    /// ends it like any other (SPEC §9, §20).
    pub async fn check_parked_session(&self, user_id: String, cancel: CancelToken) -> Result<ParkedCheck, OvError> {
        todo!()
    }

    /// Signs a parked session out, as [`sign_out`](Self::sign_out) does for the open one.
    pub async fn sign_out_parked(&self, user_id: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    // ----------------------------------------------------------------------------- vaults

    /// `GET /vaults`: every vault this account can open, names decrypted (SPEC §7). Offline, the
    /// list from the last successful call.
    pub async fn vaults(&self, cancel: CancelToken) -> Result<Vec<VaultInfo>, OvError> {
        todo!()
    }

    /// The vault list from the last successful call, without the network; `None` if none is cached.
    pub async fn cached_vaults(&self) -> Result<Option<Vec<VaultInfo>>, OvError> {
        todo!()
    }

    /// Downloads and opens a vault (newest key first), merging edits this device kept from an
    /// earlier session. Offline, opens this device's copy ([`Vault::is_offline`]); a vault never
    /// synced here is `not_available_offline`.
    pub async fn open_vault(&self, vault_id: String, cancel: CancelToken) -> Result<Vault, OvError> {
        todo!()
    }

    /// Opens a vault from this device's copies only (edits not uploaded, else the server's bytes at
    /// the last sync), plus what AutoFill saved since. For the AutoFill extension; never syncs.
    pub async fn open_offline(&self, vault_id: String) -> Result<Vault, OvError> {
        todo!()
    }

    /// Opens this device's copy of a vault without the network and without AutoFill's edits.
    pub async fn open_copy(&self, vault_id: String) -> Result<Vault, OvError> {
        todo!()
    }

    /// Creates a vault: a new vault key sealed to this account (and in an org to every confirmed
    /// owner and admin, after checking their keys), then an empty KDBX uploaded with
    /// `If-None-Match: *` (SPEC §7, §13).
    pub async fn create_vault(
        &self,
        name: String,
        org_id: Option<String>,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        todo!()
    }

    /// Imports a `.kdbx` (opened with `credentials`) into the account: as a new vault ("Move to
    /// account", re-keyed to a fresh vault key, the original untouched), merged into a vault, or as
    /// copies. If the vault was created but the upload failed, [`ImportOutcome::uploaded`] is false.
    pub async fn import_kdbx(
        &self,
        kdbx: Vec<u8>,
        credentials: KdbxCredentials,
        mode: ImportMode,
        cancel: CancelToken,
    ) -> Result<ImportOutcome, OvError> {
        todo!()
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
        todo!()
    }

    /// Renames a vault (needs `manage`): the encrypted name on the auth server, which every client
    /// shows (SPEC §7, §17).
    pub async fn rename_vault(
        &self,
        vault_id: String,
        name: String,
        cancel: CancelToken,
    ) -> Result<VaultInfo, OvError> {
        todo!()
    }

    /// Deletes a vault for everyone (needs `manage`): the blob on the sync server, then the vault.
    pub async fn delete_vault(&self, vault_id: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// Whether any vault has edits waiting on this device.
    pub async fn has_any_pending_edits(&self) -> Result<bool, OvError> {
        todo!()
    }

    /// Whether a vault has edits waiting on this device for its next upload.
    pub async fn has_pending_edits(&self, vault_id: String) -> Result<bool, OvError> {
        todo!()
    }

    // ---------------------------------------------------------------------------- history

    /// The saved versions of a vault on the sync server (SPEC §11 history), newest first.
    pub async fn vault_history(&self, vault_id: String, cancel: CancelToken) -> Result<Vec<VaultVersion>, OvError> {
        todo!()
    }

    /// Opens one saved version, read-only ([`Vault::is_read_only`]).
    pub async fn open_vault_version(
        &self,
        vault_id: String,
        revision: u64,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        todo!()
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
        todo!()
    }

    /// What AutoFill saved for a vault and the app hasn't taken yet.
    pub async fn autofill_edits(&self, vault_id: String) -> Result<Option<AutoFillEdits>, OvError> {
        todo!()
    }

    /// Removes AutoFill edits once taken, unless newer ones were written meanwhile.
    pub async fn clear_autofill_edits(&self, edits: AutoFillEdits) -> Result<(), OvError> {
        todo!()
    }

    // ----------------------------------------------------------------------------- events

    /// Live updates (SPEC §11). `vault` events come through as
    /// [`AccountEvent::VaultChanged`](super::AccountEvent::VaultChanged); on `access` events the
    /// account refreshes its token (new `vlt` claims), reloads the vault list
    /// ([`AccountEvent::VaultsChanged`](super::AccountEvent::VaultsChanged)) and reconnects;
    /// `deletion_scheduled` / `account_deleted` end the session
    /// ([`AccountEvent::SessionEnded`](super::AccountEvent::SessionEnded)).
    pub async fn subscribe(&self, cancel: CancelToken) -> Result<EventStream, OvError> {
        todo!()
    }
}
