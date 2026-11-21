//! The facade's handles as UniFFI objects. Each wraps the `ov_core` handle and forwards every
//! method through `guard`, one Swift method per core method (rust-core-tasks.md
//! §2.3). Sharing, settings, plans and share links are `Account` methods in the core; they are
//! in [`crate::account_ext`].

use std::sync::Arc;

use ov_core::api as core;

use crate::error::OvError;
use crate::guard::{guard, guard_async, guard_ok};
use crate::host::Host;
use crate::types_ext::{HttpRequest, ImportOutcome, LoginStep};

type R<T> = Result<T, OvError>;

/// Cancels a running call: pass it to the call and `cancel()` it from anywhere; the call returns
/// `aborted`. A token stays cancelled; use a fresh one per call.
#[derive(uniffi::Object, Default)]
pub struct CancelToken(pub(crate) core::CancelToken);

#[uniffi::export]
impl CancelToken {
    /// A token that isn't cancelled.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Cancels every call holding this token.
    pub fn cancel(&self) {
        self.0.cancel()
    }

    /// Whether `cancel()` was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

fn tok(c: &CancelToken) -> core::CancelToken {
    c.0.clone()
}

// ---------------------------------------------------------------------------- OvClient

/// The entry point: a configuration plus the Host (`ov_core::api::OvClient`).
#[derive(uniffi::Object)]
pub struct OvClient(pub(crate) core::OvClient);

#[uniffi::export]
impl OvClient {
    /// A client for `config` running on `host`.
    #[uniffi::constructor]
    pub fn new(config: core::ClientConfig, host: Arc<Host>) -> Arc<Self> {
        Arc::new(OvClient(core::OvClient::new(config, host.0.clone())))
    }

    /// The configuration.
    pub fn config(&self) -> R<core::ClientConfig> {
        guard_ok(|| self.0.config())
    }

    /// Fetches the server's discovery document (SPEC §1).
    pub async fn discover(&self, issuer: String, cancel: Arc<CancelToken>) -> R<core::ServerConfig> {
        guard_async(self.0.discover(issuer, tok(&cancel))).await
    }

    /// An `Account` for `issuer`, restoring a stored session if there is one.
    pub async fn connect(&self, issuer: String, cancel: Arc<CancelToken>) -> R<Arc<Account>> {
        guard_async(self.0.connect(issuer, tok(&cancel))).await.map(Account::wrap)
    }

    /// Opens a local `.kdbx` on this client's Host clock (contract-v1.6).
    pub async fn open_local(
        &self,
        kdbx: Vec<u8>,
        credentials: core::KdbxCredentials,
        cancel: Arc<CancelToken>,
    ) -> R<Arc<Vault>> {
        guard_async(self.0.open_local(kdbx, credentials, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Creates a new local database on this client's Host clock (contract-v1.6).
    pub async fn create_local(
        &self,
        name: String,
        credentials: core::KdbxCredentials,
        cancel: Arc<CancelToken>,
    ) -> R<Arc<Vault>> {
        guard_async(self.0.create_local(name, credentials, tok(&cancel))).await.map(Vault::wrap)
    }

    /// The remembered accounts (SPEC §21).
    pub async fn remembered_accounts(&self) -> R<Vec<core::RememberedAccount>> {
        guard_async(self.0.remembered_accounts()).await
    }

    /// Remembers an account.
    pub async fn remember_account(&self, email: String, issuer: String, user_id: String) -> R<()> {
        guard_async(self.0.remember_account(email, issuer, user_id)).await
    }

    /// Records a scheduled deletion on a remembered account.
    pub async fn set_remembered_deletion(&self, issuer: String, user_id: String, at: Option<String>) -> R<()> {
        guard_async(self.0.set_remembered_deletion(issuer, user_id, at)).await
    }

    /// Marks a remembered account as checked now.
    pub async fn mark_remembered_checked(&self, issuer: String, user_id: String) -> R<()> {
        guard_async(self.0.mark_remembered_checked(issuer, user_id)).await
    }

    /// Forgets a remembered account.
    pub async fn forget_remembered(&self, issuer: String, user_id: String) -> R<()> {
        guard_async(self.0.forget_remembered(issuer, user_id)).await
    }

    /// The session state of a remembered account.
    pub async fn session_state(&self, issuer: String, user_id: String) -> R<core::SessionState> {
        guard_async(self.0.session_state(issuer, user_id)).await
    }

    /// Whether any vault of `user_id` has edits not yet uploaded.
    pub async fn has_pending_edits(&self, user_id: String) -> R<bool> {
        guard_async(self.0.has_pending_edits(user_id)).await
    }

    /// Public facts about a share link (SPEC §22).
    pub async fn share_info(&self, api: String, share_id: String, cancel: Arc<CancelToken>) -> R<core::ShareInfo> {
        guard_async(self.0.share_info(api, share_id, tok(&cancel))).await
    }

    /// Opens a share link (SPEC §22).
    pub async fn open_share(
        &self,
        api: String,
        link: Vec<u8>,
        passcode: Option<Vec<u8>>,
        info: Option<core::ShareInfo>,
        cancel: Arc<CancelToken>,
    ) -> R<core::OpenedShare> {
        guard_async(self.0.open_share(api, link, passcode, info, tok(&cancel))).await
    }
}

// ------------------------------------------------------------------------ TotpChallenge

/// A sign-in waiting for a two-step code (`ov_core::api::TotpChallenge`).
#[derive(uniffi::Object)]
pub struct TotpChallenge(pub(crate) core::TotpChallenge);

#[uniffi::export]
impl TotpChallenge {
    /// How many codes were tried.
    pub fn attempt(&self) -> R<u32> {
        guard_ok(|| self.0.attempt())
    }

    /// Why the last code was refused.
    pub fn last_error(&self) -> R<Option<OvError>> {
        guard_ok(|| self.0.last_error().map(Into::into))
    }
}

// ----------------------------------------------------------------------------- Account

/// An account session (`ov_core::api::Account`).
#[derive(uniffi::Object)]
pub struct Account(pub(crate) core::Account);

impl Account {
    pub(crate) fn wrap(a: core::Account) -> Arc<Self> {
        Arc::new(Account(a))
    }
}

#[uniffi::export]
impl Account {
    // ------------------------------------------------------------------------- state

    /// The server's discovery document.
    pub fn server_config(&self) -> R<core::ServerConfig> {
        guard_ok(|| self.0.server_config())
    }

    /// Whether the account is working from the offline cache.
    pub fn is_offline(&self) -> R<bool> {
        guard_ok(|| self.0.is_offline())
    }

    /// Whether there is a session.
    pub fn is_signed_in(&self) -> R<bool> {
        guard_ok(|| self.0.is_signed_in())
    }

    /// Whether the keyset is unlocked.
    pub fn is_unlocked(&self) -> R<bool> {
        guard_ok(|| self.0.is_unlocked())
    }

    /// When deletion is scheduled for, if it is (SPEC §23).
    pub fn deletion_scheduled_for(&self) -> R<Option<String>> {
        guard_ok(|| self.0.deletion_scheduled_for())
    }

    /// The user id.
    pub fn user_id(&self) -> R<Option<String>> {
        guard_ok(|| self.0.user_id())
    }

    /// The email.
    pub fn email(&self) -> R<Option<String>> {
        guard_ok(|| self.0.email())
    }

    /// The account's principal.
    pub fn principal(&self) -> R<String> {
        guard(|| self.0.principal())
    }

    /// The account's public-key fingerprint.
    pub fn fingerprint(&self) -> R<String> {
        guard(|| self.0.fingerprint())
    }

    /// The measured server clock offset.
    pub fn clock_offset_ms(&self) -> R<Option<i64>> {
        guard_ok(|| self.0.clock_offset_ms())
    }

    /// The stored session, if any.
    pub async fn stored_session(&self) -> R<Option<core::StoredSession>> {
        guard_async(self.0.stored_session()).await
    }

    /// Checks the session with the server.
    pub async fn verify_session(&self, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.verify_session(tok(&cancel))).await
    }

    /// Completes when the session ends; await it in a loop.
    pub async fn signed_out(&self, cancel: Arc<CancelToken>) -> R<core::SignedOutReason> {
        guard_async(self.0.signed_out(tok(&cancel))).await
    }

    /// Whether a Secret Key is stored for `email`.
    pub async fn has_secret_key(&self, email: String) -> R<bool> {
        guard_async(self.0.has_secret_key(email)).await
    }

    /// The Secret Key stored for `email`.
    pub async fn stored_secret_key(&self, email: String) -> R<Option<Vec<u8>>> {
        guard_async(self.0.stored_secret_key(email)).await
    }

    // ---------------------------------------------------------------- sign-up, sign-in

    /// Creates an account (SPEC §3).
    pub async fn register(&self, input: core::RegisterInput, cancel: Arc<CancelToken>) -> R<core::NewAccount> {
        guard_async(self.0.register(input, tok(&cancel))).await
    }

    /// Signs in (SPEC §3, §8).
    pub async fn login(&self, input: core::LoginInput, cancel: Arc<CancelToken>) -> R<LoginStep> {
        guard_async(self.0.login(input, tok(&cancel))).await.map(Into::into)
    }

    /// Finishes a sign-in with a two-step code.
    pub async fn submit_totp(
        &self,
        challenge: Arc<TotpChallenge>,
        code: String,
        cancel: Arc<CancelToken>,
    ) -> R<LoginStep> {
        guard_async(self.0.submit_totp(challenge.0.clone(), code, tok(&cancel))).await.map(Into::into)
    }

    /// Unlocks with the password (online or offline).
    pub async fn unlock(
        &self,
        password: Vec<u8>,
        secret_key: Option<Vec<u8>>,
        cancel: Arc<CancelToken>,
    ) -> R<core::Unlocked> {
        guard_async(self.0.unlock(password, secret_key, tok(&cancel))).await
    }

    /// Unlocks with a saved AUK (biometric unlock).
    pub async fn unlock_with_auk(&self, auk: Vec<u8>, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.unlock_with_auk(auk, tok(&cancel))).await
    }

    /// The unlocked keyset, for the caller to seal.
    pub fn unlocked_keyset_secret(&self) -> R<Vec<u8>> {
        guard(|| self.0.unlocked_keyset_secret())
    }

    /// Resumes from a keyset secret.
    pub async fn resume_unlocked(&self, keyset_secret: Vec<u8>, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.resume_unlocked(keyset_secret, tok(&cancel))).await
    }

    /// Locks (wipes keys, keeps the session).
    pub fn lock(&self) -> R<()> {
        guard_ok(|| self.0.lock())
    }

    /// Signs out.
    pub async fn sign_out(&self, forget_device: bool, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.sign_out(forget_device, tok(&cancel))).await
    }

    /// The request to send on page unload (web only).
    pub fn sign_out_on_unload(&self) -> R<Option<HttpRequest>> {
        guard_ok(|| self.0.sign_out_on_unload().map(Into::into))
    }

    /// Forgets this device's trust for `email`.
    pub async fn forget_device(&self, email: String) -> R<()> {
        guard_async(self.0.forget_device(email)).await
    }

    /// Reconnects after being offline.
    pub async fn reconnect(&self, cancel: Arc<CancelToken>) -> R<core::ReconnectResult> {
        guard_async(self.0.reconnect(tok(&cancel))).await
    }

    /// The cached KDF parameters.
    pub async fn cached_kdf(&self) -> R<Option<core::KdfParams>> {
        guard_async(self.0.cached_kdf()).await
    }

    // ---------------------------------------------------------- several accounts (§21)

    /// Parks the session.
    pub async fn park_session(&self) -> R<bool> {
        guard_async(self.0.park_session()).await
    }

    /// Resumes a parked session.
    pub async fn resume_session(&self, user_id: String) -> R<bool> {
        guard_async(self.0.resume_session(user_id)).await
    }

    /// Checks a parked session with the server.
    pub async fn check_parked_session(&self, user_id: String, cancel: Arc<CancelToken>) -> R<core::ParkedCheck> {
        guard_async(self.0.check_parked_session(user_id, tok(&cancel))).await
    }

    /// Signs out a parked session.
    pub async fn sign_out_parked(&self, user_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.sign_out_parked(user_id, tok(&cancel))).await
    }

    // ------------------------------------------------------------------------- vaults

    /// The vaults this account can open.
    pub async fn vaults(&self, cancel: Arc<CancelToken>) -> R<Vec<core::VaultInfo>> {
        guard_async(self.0.vaults(tok(&cancel))).await
    }

    /// The vault list from the offline cache.
    pub async fn cached_vaults(&self) -> R<Option<Vec<core::VaultInfo>>> {
        guard_async(self.0.cached_vaults()).await
    }

    /// Opens a vault (syncing it).
    pub async fn open_vault(&self, vault_id: String, cancel: Arc<CancelToken>) -> R<Arc<Vault>> {
        guard_async(self.0.open_vault(vault_id, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Opens a vault from the offline cache.
    pub async fn open_offline(&self, vault_id: String) -> R<Arc<Vault>> {
        guard_async(self.0.open_offline(vault_id)).await.map(Vault::wrap)
    }

    /// Opens a read-only copy.
    pub async fn open_copy(&self, vault_id: String) -> R<Arc<Vault>> {
        guard_async(self.0.open_copy(vault_id)).await.map(Vault::wrap)
    }

    /// Creates a vault.
    pub async fn create_vault(&self, name: String, org_id: Option<String>, cancel: Arc<CancelToken>) -> R<Arc<Vault>> {
        guard_async(self.0.create_vault(name, org_id, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Imports a `.kdbx` file.
    pub async fn import_kdbx(
        &self,
        kdbx: Vec<u8>,
        credentials: core::KdbxCredentials,
        mode: core::ImportMode,
        cancel: Arc<CancelToken>,
    ) -> R<ImportOutcome> {
        guard_async(self.0.import_kdbx(kdbx, credentials, mode, tok(&cancel))).await.map(Into::into)
    }

    /// Imports an open vault.
    pub async fn import_vault(
        &self,
        source: Arc<Vault>,
        mode: core::ImportMode,
        cancel: Arc<CancelToken>,
    ) -> R<ImportOutcome> {
        guard_async(self.0.import_vault(source.0.clone(), mode, tok(&cancel))).await.map(Into::into)
    }

    /// Renames a vault.
    pub async fn rename_vault(&self, vault_id: String, name: String, cancel: Arc<CancelToken>) -> R<core::VaultInfo> {
        guard_async(self.0.rename_vault(vault_id, name, tok(&cancel))).await
    }

    /// Deletes a vault.
    pub async fn delete_vault(&self, vault_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.delete_vault(vault_id, tok(&cancel))).await
    }

    /// Whether any vault has edits not yet uploaded.
    pub async fn has_any_pending_edits(&self) -> R<bool> {
        guard_async(self.0.has_any_pending_edits()).await
    }

    /// Whether `vault_id` has edits not yet uploaded.
    pub async fn has_pending_edits(&self, vault_id: String) -> R<bool> {
        guard_async(self.0.has_pending_edits(vault_id)).await
    }

    // ------------------------------------------- vault files and the session token (v1.6)

    /// The credentials an account vault's `.kdbx` is under (contract-v1.6). Wipe them.
    pub async fn vault_kdbx_credentials(&self, vault_id: String, cancel: Arc<CancelToken>) -> R<core::KdbxCredentials> {
        guard_async(self.0.vault_kdbx_credentials(vault_id, tok(&cancel))).await
    }

    /// Syncs an account vault held as `.kdbx` bytes (contract-v1.6).
    pub async fn sync_vault_kdbx(
        &self,
        vault_id: String,
        kdbx: Vec<u8>,
        base: Option<Vec<u8>>,
        options: core::SyncOptions,
        cancel: Arc<CancelToken>,
    ) -> R<core::VaultKdbxSyncResult> {
        guard_async(self.0.sync_vault_kdbx(vault_id, kdbx, base, options, tok(&cancel))).await
    }

    /// The session's access token, refreshed when needed (contract-v1.6). Don't log it.
    pub async fn access_token(&self, force_refresh: bool, cancel: Arc<CancelToken>) -> R<Vec<u8>> {
        guard_async(self.0.access_token(force_refresh, tok(&cancel))).await
    }

    // ------------------------------------------------------------------------ history

    /// The saved versions of a vault.
    pub async fn vault_history(&self, vault_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::VaultVersion>> {
        guard_async(self.0.vault_history(vault_id, tok(&cancel))).await
    }

    /// Opens one saved version (read-only).
    pub async fn open_vault_version(&self, vault_id: String, revision: u64, cancel: Arc<CancelToken>) -> R<Arc<Vault>> {
        guard_async(self.0.open_vault_version(vault_id, revision, tok(&cancel))).await.map(Vault::wrap)
    }

    // --------------------------------------------------------------- AutoFill (iOS)

    /// Keeps an AutoFill extension's edit for the app to merge.
    pub async fn keep_autofill_edit(&self, vault_id: String, entry: core::EntryRecord, group_path: String) -> R<()> {
        guard_async(self.0.keep_autofill_edit(vault_id, entry, group_path)).await
    }

    /// The AutoFill edits waiting for `vault_id`.
    pub async fn autofill_edits(&self, vault_id: String) -> R<Option<core::AutoFillEdits>> {
        guard_async(self.0.autofill_edits(vault_id)).await
    }

    /// Clears merged AutoFill edits.
    pub async fn clear_autofill_edits(&self, edits: core::AutoFillEdits) -> R<()> {
        guard_async(self.0.clear_autofill_edits(edits)).await
    }

    // ------------------------------------------------------------------------- events

    /// Subscribes to server events (SPEC §11).
    pub async fn subscribe(&self, cancel: Arc<CancelToken>) -> R<Arc<EventStream>> {
        guard_async(self.0.subscribe(tok(&cancel))).await.map(|s| Arc::new(EventStream(s)))
    }
}

// --------------------------------------------------------------------------- EventStream

/// Server events, pulled one at a time (`ov_core::api::EventStream`).
#[derive(uniffi::Object)]
pub struct EventStream(pub(crate) core::EventStream);

#[uniffi::export]
impl EventStream {
    /// The next event, or `nil` once closed.
    pub async fn next(&self, cancel: Arc<CancelToken>) -> R<Option<core::AccountEvent>> {
        guard_async(self.0.next(tok(&cancel))).await
    }

    /// Reconnects now (e.g. when the app comes to the foreground).
    pub fn reconnect(&self) -> R<()> {
        guard_ok(|| self.0.reconnect())
    }

    /// Closes the stream.
    pub fn close(&self) -> R<()> {
        guard_ok(|| self.0.close())
    }
}

// --------------------------------------------------------------------------------- Vault

/// One open vault: an account vault, a local file or a read-only version (`ov_core::api::Vault`).
#[derive(uniffi::Object)]
pub struct Vault(pub(crate) core::Vault);

impl Vault {
    pub(crate) fn wrap(v: core::Vault) -> Arc<Self> {
        Arc::new(Vault(v))
    }
}

#[uniffi::export]
impl Vault {
    // ------------------------------------------------------------------- local files

    /// Opens a local `.kdbx` file.
    #[uniffi::constructor]
    pub async fn open_local(
        kdbx: Vec<u8>,
        credentials: core::KdbxCredentials,
        cancel: Arc<CancelToken>,
    ) -> R<Arc<Self>> {
        guard_async(core::Vault::open_local(kdbx, credentials, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Creates a new local database.
    #[uniffi::constructor]
    pub async fn create_local(
        name: String,
        credentials: core::KdbxCredentials,
        cancel: Arc<CancelToken>,
    ) -> R<Arc<Self>> {
        guard_async(core::Vault::create_local(name, credentials, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Serializes a local database.
    pub async fn save_local(&self, cancel: Arc<CancelToken>) -> R<Vec<u8>> {
        guard_async(self.0.save_local(tok(&cancel))).await
    }

    /// Renames a local database (contract-v1.6).
    pub fn set_name(&self, name: String) -> R<()> {
        guard(|| self.0.set_name(name))
    }

    /// Sets a local database's key derivation (contract-v1.6).
    pub fn set_kdf(&self, kdf: core::KdbxKdf) -> R<()> {
        guard(|| self.0.set_kdf(kdf))
    }

    /// A local copy without sync-server remotes (contract-v1.6).
    pub fn copy_without_remotes(&self, credentials: Option<core::KdbxCredentials>) -> R<Arc<Vault>> {
        guard(|| self.0.copy_without_remotes(credentials)).map(Vault::wrap)
    }

    /// A database custom data value (contract-v1.6).
    pub fn meta_custom_data(&self, key: String) -> R<Option<String>> {
        guard_ok(|| self.0.meta_custom_data(key))
    }

    /// Sets or removes a database custom data item (contract-v1.6).
    pub fn set_meta_custom_data(&self, key: String, value: Option<String>) -> R<()> {
        guard(|| self.0.set_meta_custom_data(key, value))
    }

    // ------------------------------------------------------------------------- state

    /// The vault id.
    pub fn id(&self) -> R<String> {
        guard_ok(|| self.0.id())
    }

    /// The display name.
    pub fn name(&self) -> R<String> {
        guard_ok(|| self.0.name())
    }

    /// The server's record (account vaults).
    pub fn info(&self) -> R<Option<core::VaultInfo>> {
        guard_ok(|| self.0.info())
    }

    /// The ETag of the last sync.
    pub fn etag(&self) -> R<Option<String>> {
        guard_ok(|| self.0.etag())
    }

    /// Whether the vault came from the offline cache.
    pub fn is_offline(&self) -> R<bool> {
        guard_ok(|| self.0.is_offline())
    }

    /// Whether edits are refused.
    pub fn is_read_only(&self) -> R<bool> {
        guard_ok(|| self.0.is_read_only())
    }

    /// Conflicts from the last sync.
    pub fn conflicts(&self) -> R<Vec<core::SyncConflict>> {
        guard_ok(|| self.0.conflicts())
    }

    /// The root group id.
    pub fn root_group_id(&self) -> R<String> {
        guard_ok(|| self.0.root_group_id())
    }

    // ----------------------------------------------------------------------- reading

    /// Every entry.
    pub fn entries(&self, include_recycle_bin: bool) -> R<Vec<core::EntrySummary>> {
        guard_ok(|| self.0.entries(include_recycle_bin))
    }

    /// Every group.
    pub fn groups(&self) -> R<Vec<core::GroupInfo>> {
        guard_ok(|| self.0.groups())
    }

    /// Every entry with its values in one call (contract-v1.6).
    pub fn entry_records(&self, include_recycle_bin: bool) -> R<Vec<core::EntryRecord>> {
        guard_ok(|| self.0.entry_records(include_recycle_bin))
    }

    /// One entry with its fields.
    pub fn entry(&self, entry_id: String) -> R<core::EntryRecord> {
        guard(|| self.0.entry(entry_id))
    }

    /// The entry a reference names.
    pub fn find(&self, reference: String) -> R<core::EntryRecord> {
        guard(|| self.0.find(reference))
    }

    /// The field a reference names.
    pub fn read_field(&self, reference: String) -> R<Vec<u8>> {
        guard(|| self.0.read_field(reference))
    }

    /// An entry's history.
    pub fn history(&self, entry_id: String) -> R<Vec<core::EntryRecord>> {
        guard(|| self.0.history(entry_id))
    }

    /// An attachment's bytes.
    pub fn attachment(&self, entry_id: String, name: String) -> R<Vec<u8>> {
        guard(|| self.0.attachment(entry_id, name))
    }

    /// A custom icon's bytes.
    pub fn custom_icon(&self, icon_id: String) -> R<Vec<u8>> {
        guard(|| self.0.custom_icon(icon_id))
    }

    /// The group at a `/`-separated path.
    pub fn group_id_at(&self, path: String) -> R<Option<String>> {
        guard_ok(|| self.0.group_id_at(path))
    }

    /// Whether an entry or group is in the Recycle Bin.
    pub fn is_in_recycle_bin(&self, id: String) -> R<bool> {
        guard_ok(|| self.0.is_in_recycle_bin(id))
    }

    // ----------------------------------------------------------------------- editing

    /// Writes one field and syncs.
    pub async fn write_field(
        &self,
        reference: String,
        value: Vec<u8>,
        create: bool,
        cancel: Arc<CancelToken>,
    ) -> R<core::SyncReport> {
        guard_async(self.0.write_field(reference, value, create, tok(&cancel))).await
    }

    /// Sets several fields of one entry.
    pub fn set_fields(
        &self,
        reference: String,
        fields: Vec<core::FieldInput>,
        create: core::CreateMode,
    ) -> R<core::SetFieldsResult> {
        guard(|| self.0.set_fields(reference, fields, create))
    }

    /// Adds an entry; returns its id.
    pub fn add_entry(&self, group_id: String, input: core::EntryInput) -> R<String> {
        guard(|| self.0.add_entry(group_id, input))
    }

    /// Adds an entry with a chosen id (contract-v1.6).
    pub fn add_entry_with_id(&self, entry_id: String, group_id: String, input: core::EntryInput) -> R<String> {
        guard(|| self.0.add_entry_with_id(entry_id, group_id, input))
    }

    /// Edits an entry.
    pub fn edit_entry(&self, entry_id: String, input: core::EntryInput) -> R<()> {
        guard(|| self.0.edit_entry(entry_id, input))
    }

    /// Moves an entry.
    pub fn move_entry(&self, entry_id: String, group_id: String) -> R<()> {
        guard(|| self.0.move_entry(entry_id, group_id))
    }

    /// Deletes an entry (to the Recycle Bin when enabled).
    pub fn delete_entry(&self, entry_id: String) -> R<()> {
        guard(|| self.0.delete_entry(entry_id))
    }

    /// Restores an entry or group from the Recycle Bin.
    pub fn restore_from_recycle_bin(&self, id: String) -> R<()> {
        guard(|| self.0.restore_from_recycle_bin(id))
    }

    /// Empties the Recycle Bin.
    pub fn empty_recycle_bin(&self) -> R<()> {
        guard(|| self.0.empty_recycle_bin())
    }

    /// Adds or replaces an attachment.
    pub fn set_attachment(&self, entry_id: String, name: String, data: Vec<u8>) -> R<()> {
        guard(|| self.0.set_attachment(entry_id, name, data))
    }

    /// Adds or replaces an attachment with its protected flag (`nil` keeps the replaced one's;
    /// contract-v1.6).
    pub fn set_attachment_with(&self, entry_id: String, name: String, data: Vec<u8>, protected: Option<bool>) -> R<()> {
        guard(|| self.0.set_attachment_with(entry_id, name, data, protected))
    }

    /// Removes an attachment.
    pub fn remove_attachment(&self, entry_id: String, name: String) -> R<()> {
        guard(|| self.0.remove_attachment(entry_id, name))
    }

    /// Adds a custom icon; returns its id.
    pub fn add_custom_icon(&self, png: Vec<u8>) -> R<String> {
        guard(|| self.0.add_custom_icon(png))
    }

    /// Adds a group; returns its id.
    pub fn add_group(&self, parent_id: Option<String>, name: String) -> R<String> {
        guard(|| self.0.add_group(parent_id, name))
    }

    /// The group at a path, creating missing groups.
    pub fn ensure_group(&self, path: String) -> R<String> {
        guard(|| self.0.ensure_group(path))
    }

    /// Renames a group.
    pub fn rename_group(&self, group_id: String, name: String) -> R<()> {
        guard(|| self.0.rename_group(group_id, name))
    }

    /// Sets a group's icon.
    pub fn set_group_icon(&self, group_id: String, icon_id: u32) -> R<()> {
        guard(|| self.0.set_group_icon(group_id, icon_id))
    }

    /// Moves a group.
    pub fn move_group(&self, group_id: String, parent_id: String) -> R<()> {
        guard(|| self.0.move_group(group_id, parent_id))
    }

    /// Deletes a group.
    pub fn delete_group(&self, group_id: String) -> R<()> {
        guard(|| self.0.delete_group(group_id))
    }

    /// How an entry differs in an older version.
    pub fn version_difference(&self, version: Arc<Vault>, entry_id: String) -> R<core::VersionDifference> {
        guard(|| self.0.version_difference(version.0.clone(), entry_id))
    }

    /// Restores an entry from an older version.
    pub fn restore_entry(&self, version: Arc<Vault>, entry_id: String, group_path: String) -> R<()> {
        guard(|| self.0.restore_entry(version.0.clone(), entry_id, group_path))
    }

    /// Merges AutoFill edits; returns whether anything changed.
    pub fn apply_autofill_edits(&self, edits: core::AutoFillEdits) -> R<bool> {
        guard(|| self.0.apply_autofill_edits(edits))
    }

    // ------------------------------------------------------------------------ import

    /// Imports another open vault into this one (contract-v1.6).
    pub fn import_from(&self, source: Arc<Vault>, mode: core::LocalImportMode) -> R<core::ImportSummary> {
        guard(|| self.0.import_from(source.0.clone(), mode))
    }

    /// What importing this vault would bring in (contract-v1.6).
    pub fn import_preview(&self) -> R<core::ImportPreview> {
        guard_ok(|| self.0.import_preview())
    }

    /// The groups an import can go into (contract-v1.6).
    pub fn import_targets(&self) -> R<Vec<core::ImportTarget>> {
        guard_ok(|| self.0.import_targets())
    }

    // -------------------------------------------------------------------------- sync

    /// Syncs with the server (SPEC §10).
    pub async fn sync(&self, options: core::SyncOptions, cancel: Arc<CancelToken>) -> R<core::SyncReport> {
        guard_async(self.0.sync(options, tok(&cancel))).await
    }

    /// Saves local edits to the offline cache.
    pub async fn keep_edits(&self) -> R<()> {
        guard_async(self.0.keep_edits()).await
    }

    /// Whether there are edits not yet uploaded.
    pub async fn has_pending_edits(&self) -> R<bool> {
        guard_async(self.0.has_pending_edits()).await
    }

    // ------------------------------------------------------------------------ export

    /// Exports as a `.kdbx` file.
    pub async fn export_kdbx(
        &self,
        credentials: core::KdbxCredentials,
        group_ids: Option<Vec<String>>,
        cancel: Arc<CancelToken>,
    ) -> R<Vec<u8>> {
        guard_async(self.0.export_kdbx(credentials, group_ids, tok(&cancel))).await
    }

    /// Exports as a `.kdbx` file with a chosen key derivation (contract-v1.6).
    pub async fn export_kdbx_with(
        &self,
        credentials: core::KdbxCredentials,
        group_ids: Option<Vec<String>>,
        kdf: core::KdbxKdf,
        cancel: Arc<CancelToken>,
    ) -> R<Vec<u8>> {
        guard_async(self.0.export_kdbx_with(credentials, group_ids, kdf, tok(&cancel))).await
    }

    /// Exports as plain CSV or JSON (secret: the caller wipes it).
    pub fn export_plain(&self, format: core::ExportFormat, group_ids: Option<Vec<String>>) -> R<Vec<u8>> {
        guard(|| self.0.export_plain(format, group_ids))
    }
}

// ------------------------------------------------------------------------ ServiceAccount

/// A service-account session (SPEC §9, `ov_core::api::ServiceAccount`).
#[derive(uniffi::Object)]
pub struct ServiceAccount(pub(crate) core::ServiceAccount);

#[uniffi::export]
impl ServiceAccount {
    /// Signs in with a service-account token.
    #[uniffi::constructor]
    pub async fn from_token(client: Arc<OvClient>, token: Vec<u8>, cancel: Arc<CancelToken>) -> R<Arc<Self>> {
        guard_async(core::ServiceAccount::from_token(client.0.clone(), token, tok(&cancel)))
            .await
            .map(|s| Arc::new(ServiceAccount(s)))
    }

    /// The server this service account signed in to (contract-v1.6).
    pub fn server_config(&self) -> R<core::ServerConfig> {
        guard_ok(|| self.0.server_config())
    }

    /// The server's issuer (contract-v1.6).
    pub fn issuer(&self) -> R<String> {
        guard_ok(|| self.0.issuer())
    }

    /// The service account's id.
    pub fn sa_id(&self) -> R<String> {
        guard_ok(|| self.0.sa_id())
    }

    /// The service account's principal.
    pub fn principal(&self) -> R<String> {
        guard_ok(|| self.0.principal())
    }

    /// The vaults it can read.
    pub async fn vaults(&self, refresh: bool, cancel: Arc<CancelToken>) -> R<Vec<core::SaVault>> {
        guard_async(self.0.vaults(refresh, tok(&cancel))).await
    }

    /// One vault by id or name.
    pub async fn vault(&self, id_or_name: String, cancel: Arc<CancelToken>) -> R<core::SaVault> {
        guard_async(self.0.vault(id_or_name, tok(&cancel))).await
    }

    /// Opens a vault.
    pub async fn open_vault(&self, id_or_name: String, refresh: bool, cancel: Arc<CancelToken>) -> R<Arc<Vault>> {
        guard_async(self.0.open_vault(id_or_name, refresh, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Pulls a vault's latest version.
    pub async fn pull(&self, id_or_name: String, cancel: Arc<CancelToken>) -> R<Arc<Vault>> {
        guard_async(self.0.pull(id_or_name, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Reads one field by reference.
    pub async fn read(&self, reference: String, cancel: Arc<CancelToken>) -> R<Vec<u8>> {
        guard_async(self.0.read(reference, tok(&cancel))).await
    }

    /// Fills a template's references.
    pub async fn inject(&self, template: Vec<u8>, cancel: Arc<CancelToken>) -> R<core::Injected> {
        guard_async(self.0.inject(template, tok(&cancel))).await
    }

    /// Writes one field by reference.
    pub async fn write(&self, reference: String, value: Vec<u8>, create: bool, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.write(reference, value, create, tok(&cancel))).await
    }

    /// The credentials a granted vault's `.kdbx` is under (contract-v1.8). Wipe them.
    pub async fn vault_kdbx_credentials(&self, vault_id: String, cancel: Arc<CancelToken>) -> R<core::KdbxCredentials> {
        guard_async(self.0.vault_kdbx_credentials(vault_id, tok(&cancel))).await
    }

    /// Syncs a granted vault held as `.kdbx` bytes (contract-v1.8).
    pub async fn sync_vault_kdbx(
        &self,
        vault_id: String,
        kdbx: Vec<u8>,
        base: Option<Vec<u8>>,
        options: core::SyncOptions,
        cancel: Arc<CancelToken>,
    ) -> R<core::VaultKdbxSyncResult> {
        guard_async(self.0.sync_vault_kdbx(vault_id, kdbx, base, options, tok(&cancel))).await
    }

    /// Ends the session.
    pub fn close(&self) -> R<()> {
        guard_ok(|| self.0.close())
    }
}

// ---------------------------------------------------------------------------- SelfHosted

/// A self-hosted sync server (SPEC §13, `ov_core::api::SelfHosted`).
#[derive(uniffi::Object)]
pub struct SelfHosted(pub(crate) core::SelfHosted);

fn self_hosted(s: core::SelfHosted) -> Arc<SelfHosted> {
    Arc::new(SelfHosted(s))
}

#[uniffi::export]
impl SelfHosted {
    /// Connects with a stored device token.
    #[uniffi::constructor]
    pub fn connect(client: Arc<OvClient>, server_url: String, device_token: Vec<u8>) -> R<Arc<Self>> {
        guard(|| core::SelfHosted::connect(client.0.clone(), server_url, device_token)).map(self_hosted)
    }

    /// Pairs this device with a pairing code.
    #[uniffi::constructor]
    pub async fn pair(
        client: Arc<OvClient>,
        server_url: String,
        code: String,
        device_name: String,
        cancel: Arc<CancelToken>,
    ) -> R<Arc<Self>> {
        guard_async(core::SelfHosted::pair(client.0.clone(), server_url, code, device_name, tok(&cancel)))
            .await
            .map(self_hosted)
    }

    /// The server URL.
    pub fn server_url(&self) -> R<String> {
        guard_ok(|| self.0.server_url())
    }

    /// The server's health text.
    pub async fn health(&self, cancel: Arc<CancelToken>) -> R<String> {
        guard_async(self.0.health(tok(&cancel))).await
    }

    /// The databases on the server.
    pub async fn list_databases(&self, cancel: Arc<CancelToken>) -> R<Vec<core::BlobMeta>> {
        guard_async(self.0.list_databases(tok(&cancel))).await
    }

    /// A code for pairing another device.
    pub async fn create_pairing_code(&self, cancel: Arc<CancelToken>) -> R<core::PairingCode> {
        guard_async(self.0.create_pairing_code(tok(&cancel))).await
    }

    /// Syncs a local database with the server's copy.
    pub async fn sync_database(
        &self,
        database_id: String,
        kdbx: Vec<u8>,
        credentials: core::KdbxCredentials,
        cancel: Arc<CancelToken>,
    ) -> R<core::SelfHostedSyncResult> {
        guard_async(self.0.sync_database(database_id, kdbx, credentials, tok(&cancel))).await
    }

    /// [`sync_database`](Self::sync_database) with options: `local_changed: false` checks with a
    /// HEAD first and, when the server is unchanged, returns `kdbx` as it is (contract-v1.7).
    pub async fn sync_database_with(
        &self,
        database_id: String,
        kdbx: Vec<u8>,
        credentials: core::KdbxCredentials,
        options: core::SyncOptions,
        cancel: Arc<CancelToken>,
    ) -> R<core::SelfHostedSyncResult> {
        guard_async(self.0.sync_database_with(database_id, kdbx, credentials, options, tok(&cancel))).await
    }

    /// Downloads a database as the server has it, without its key; `None` when there is none
    /// (contract-v1.8).
    pub async fn download(&self, database_id: String, cancel: Arc<CancelToken>) -> R<Option<Vec<u8>>> {
        guard_async(self.0.download(database_id, tok(&cancel))).await
    }

    /// The versions the server keeps of a database (contract-v1.6).
    pub async fn history(&self, database_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::VaultVersion>> {
        guard_async(self.0.history(database_id, tok(&cancel))).await
    }

    /// Opens one kept version of a database, read-only (contract-v1.6).
    pub async fn open_version(
        &self,
        database_id: String,
        revision: u64,
        credentials: core::KdbxCredentials,
        cancel: Arc<CancelToken>,
    ) -> R<Arc<Vault>> {
        guard_async(self.0.open_version(database_id, revision, credentials, tok(&cancel))).await.map(Vault::wrap)
    }

    /// Subscribes to the server's events.
    pub async fn events(&self, cancel: Arc<CancelToken>) -> R<Arc<EventStream>> {
        guard_async(self.0.events(tok(&cancel))).await.map(|s| Arc::new(EventStream(s)))
    }
}

/// `SelfHosted::restore`: the pairing stored for `server_url`, if there is one. A free function
/// because a UniFFI constructor can't return an optional object.
#[uniffi::export]
pub async fn restore_self_hosted(client: Arc<OvClient>, server_url: String) -> R<Option<Arc<SelfHosted>>> {
    guard_async(core::SelfHosted::restore(client.0.clone(), server_url)).await.map(|s| s.map(self_hosted))
}
