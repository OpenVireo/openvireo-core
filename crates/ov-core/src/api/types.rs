//! Records and enums shared across the facade. All are plain data, safe to copy across FFI.

use ov_error::OvError;

/// Secret bytes crossing the API: passwords, Secret Keys, field values, tokens, AUKs, share URLs
/// (whose fragment holds the key). Text is UTF-8. The core wipes inputs after use; the caller
/// wipes outputs (`Data`, `QByteArray`, `Uint8Array`) when done.
pub type SecretBytes = Vec<u8>;

/// An RFC 3339 timestamp as the server sends it (e.g. `2026-11-15T10:00:00Z`).
pub type Rfc3339 = String;

/// `user:<uuid>` or `sa:<uuid>` (SPEC §1).
pub type Principal = String;

// ---------------------------------------------------------------------------------- config

/// The discovery document, `GET /.well-known/openvireo-configuration` (SPEC §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// The issuer, e.g. `https://accounts.openvireo.com`.
    pub issuer: String,
    /// `{issuer}/api/v1`.
    pub api: String,
    /// The sync server's `/api/v1`.
    pub sync: String,
    /// JWKS for access-token verification (SPEC §9).
    pub jwks_uri: String,
    /// OPAQUE settings (SPEC §8).
    pub opaque: OpaqueConfig,
    /// The server's KDF floor (SPEC §3); clients use the stricter of this and `m=19456, t=2`.
    pub kdf_min: Option<KdfMin>,
    /// The web app (SPEC §16); without it clients hide "Manage account".
    pub web: Option<String>,
    /// The public share page (SPEC §22); without it `<web>/s`.
    pub share: Option<String>,
}

/// `opaque` in the discovery document (SPEC §8, §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueConfig {
    /// Server library name (informational).
    pub lib: String,
    /// Server library version (informational).
    pub version: String,
    /// The OPAQUE context string, `ov-opaque-v1`.
    pub context: String,
    /// The server identity used for `idS` (a host name).
    pub ids: String,
}

/// `kdf_min` in the discovery document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfMin {
    /// Minimum memory in KiB.
    pub m: u32,
    /// Minimum iterations.
    pub t: u32,
}

/// Which app this device is (the server's `Platform`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Desktop on Linux.
    QtLinux,
    /// Desktop on macOS.
    QtMacos,
    /// Desktop on Windows.
    QtWindows,
    /// The web app or the browser extension.
    Web,
    /// The `ov` CLI.
    Cli,
    /// `openvireo-connect` / the GitHub Action.
    Connect,
    /// The iOS app.
    Ios,
}

impl Platform {
    /// The wire string, e.g. `"qt-macos"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::QtLinux => "qt-linux",
            Platform::QtMacos => "qt-macos",
            Platform::QtWindows => "qt-windows",
            Platform::Web => "web",
            Platform::Cli => "cli",
            Platform::Connect => "connect",
            Platform::Ios => "ios",
        }
    }
}

/// This device as the server sees it (`DeviceInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The device id from an earlier sign-in; the core fills it from the [SecureStore](crate::host::SecureStore).
    pub id: Option<String>,
    /// A display name, at most 64 characters (longer names are cut).
    pub name: String,
    /// The app.
    pub platform: Platform,
}

/// How an [`OvClient`](crate::api::OvClient) behaves. Plain settings, no secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    /// This device.
    pub device: DeviceInfo,
    /// Keep the offline cache (SPEC §20): unlock, list and open vaults without the network, and
    /// keep edits until they upload. The TS SDK's `offline` option; always on for iOS and desktop.
    pub offline: bool,
    /// Use this discovery document instead of fetching it (tests, or a cached copy the app keeps).
    pub server: Option<ServerConfig>,
}

// ------------------------------------------------------------------------------------ crypto

/// The account's KDF parameters, the `Kdf` schema of openapi.yaml (SPEC §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Always `"argon2id"`.
    pub alg: String,
    /// 16 bytes, base64url.
    pub salt: String,
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

/// Overrides for new KDF parameters (default `m=65536, t=3, p=1`). Values under the minimum fail
/// with `weak_kdf`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KdfOverrides {
    /// Memory in KiB.
    pub m: Option<u32>,
    /// Iterations.
    pub t: Option<u32>,
    /// Parallelism.
    pub p: Option<u32>,
}

/// A principal's public keys, verified against their signature (SPEC §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeys {
    /// X25519 encryption public key (32 bytes).
    pub enc_pk: Vec<u8>,
    /// Ed25519 signing public key (32 bytes).
    pub sign_pk: Vec<u8>,
    /// Signature over `enc_pk` by `sign_pk` (64 bytes).
    pub sig: Vec<u8>,
    /// The fingerprint to compare out of band (SPEC §5).
    pub fingerprint: String,
}

// -------------------------------------------------------------------------------- sessions

/// A signed-in session as stored on this device, without its tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSession {
    /// The issuer.
    pub issuer: String,
    /// The user's id.
    pub user_id: String,
    /// The account email.
    pub email: String,
    /// This device's id on the server.
    pub device_id: String,
}

/// Why a session ended (the SDK's `SignedOutReason`).
///
/// What this device keeps of the user's offline cache (SPEC §20; contract-v1.8): after an accident
/// ([`TokenReused`](Self::TokenReused), [`SessionExpired`](Self::SessionExpired)) each vault's
/// unsynced edits and AutoFill edits stay, still encrypted with the vault key, and merge in after
/// the same user next signs in; the vault list, keyset, sync states and server copies go. For every
/// other reason, and for this device's own sign-out, everything goes (the
/// [BlobCache](crate::host::BlobCache)'s `clear_user`). Before contract-v1.8 everything went every
/// time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignedOutReason {
    /// A refresh token was used twice (SPEC §9). Unsynced edits are kept.
    TokenReused,
    /// The refresh token expired. Unsynced edits are kept.
    SessionExpired,
    /// The server refused the session (revoked elsewhere, password changed).
    Unauthorized,
    /// This device signed out.
    Logout,
    /// The account was scheduled for deletion (SPEC §23).
    DeletionScheduled,
    /// The account was deleted (SPEC §23).
    AccountDeleted,
}

/// Where a user's session is on this device, read without the network (SPEC §21).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// The open session.
    Active,
    /// Set aside by a switch; resumable.
    Parked,
    /// No session.
    SignedOut,
}

/// The server's answer about a parked session (SPEC §21).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParkedCheck {
    /// Still valid (and now refreshed).
    Valid,
    /// Ended; the user signs in again. Its offline data is gone.
    Ended,
    /// The server couldn't be reached.
    NoAnswer,
}

/// An account this device remembers for switching (SPEC §21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RememberedAccount {
    /// The email.
    pub email: String,
    /// The issuer.
    pub issuer: String,
    /// The user's id.
    pub user_id: String,
    /// Last used.
    pub last_used_at: Rfc3339,
    /// Last time the server confirmed a parked session.
    pub checked_at: Option<Rfc3339>,
    /// The erase date if the account is pending deletion (SPEC §23).
    pub deletion_scheduled_for: Option<Rfc3339>,
}

/// What [`Account::register`](crate::api::Account::register) and
/// [`Account::recover`](crate::api::Account::recover) return.
#[derive(Clone, PartialEq, Eq)]
pub struct NewAccount {
    /// The user's id.
    pub user_id: String,
    /// The Secret Key in display form (`K1-…`), to show once.
    pub secret_key: SecretBytes,
    /// What the Emergency Kit prints next to the Secret Key.
    pub emergency_kit: EmergencyKit,
    /// The AUK, for a biometric unlock later ([`Account::unlock_with_auk`](crate::api::Account::unlock_with_auk)).
    pub auk: SecretBytes,
}

impl std::fmt::Debug for NewAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewAccount")
            .field("user_id", &self.user_id)
            .field("emergency_kit", &self.emergency_kit)
            .finish()
    }
}

/// The non-secret half of an Emergency Kit (SPEC §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyKit {
    /// The account email.
    pub email: String,
    /// The sign-in address (the issuer).
    pub issuer: String,
    /// The web app, if the server has one.
    pub web: Option<String>,
}

/// The signed-in user (`GET /me`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The user's id.
    pub id: String,
    /// The email.
    pub email: String,
    /// The display name.
    pub name: Option<String>,
    /// Two-step sign-in (TOTP) is on.
    pub totp_enabled: bool,
    /// The personal plan (SPEC §19).
    pub plan: Option<Plan>,
    /// Org memberships.
    pub orgs: Vec<OrgMembership>,
    /// Set while the account is pending deletion (SPEC §23).
    pub deletion_scheduled_for: Option<Rfc3339>,
    /// The KDF parameters the keyset is wrapped with (what the offline cache keeps; SPEC §3, §20).
    /// Contract-v1.8.
    pub kdf: KdfParams,
    /// The keyset's public keys, signature checked, with the fingerprint (SPEC §5). Different from
    /// the ones this device knew means the keyset was replaced (account recovery, SPEC §18).
    /// Contract-v1.8.
    pub public_keys: PublicKeys,
}

/// One device signed in to the account (`GET /me/devices`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// The device id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its platform wire string (open set).
    pub platform: String,
    /// First sign-in.
    pub created_at: Rfc3339,
    /// Last seen.
    pub last_seen_at: Rfc3339,
    /// This device.
    pub current: bool,
}

/// TOTP enrolment (`POST /me/totp`, SPEC §8). Both values reveal the TOTP secret.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSetup {
    /// The base32 secret.
    pub secret: SecretBytes,
    /// The `otpauth://` URI for a QR code.
    pub uri: SecretBytes,
}

impl std::fmt::Debug for TotpSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSetup { .. }")
    }
}

/// The result of [`Account::reconnect`](crate::api::Account::reconnect).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectResult {
    /// The vault list now.
    pub vaults: Vec<VaultInfo>,
    /// Vaults no longer listed (access revoked or deleted meanwhile); their local copies are gone.
    pub dropped: Vec<String>,
}

// ------------------------------------------------------------------------- recovery (§18)

/// What an approved reset will do (`GET /auth/recover/{token}`, SPEC §18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReset {
    /// The account email.
    pub email: String,
    /// The link works from then on.
    pub not_before: Rfc3339,
    /// The link stops working then.
    pub expires_at: Rfc3339,
    /// How long the old keys and vaults are kept for a restore (30).
    pub archive_days: u32,
    /// Personal vaults that will be archived.
    pub personal_vaults: u32,
    /// Grants on vaults the user doesn't own that will be archived.
    pub shared_grants: u32,
    /// Orgs whose only confirmed owner/admin is this user.
    pub sole_admin_orgs: Vec<String>,
}

/// Whether a recovery archive exists (`GET /me/recovery`, SPEC §18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryStatus {
    /// An archive exists.
    pub archived: bool,
    /// The email before the reset.
    pub email: Option<String>,
    /// When the archive is erased.
    pub expires_at: Option<Rfc3339>,
    /// Archived personal vaults plus archived grants.
    pub vaults: Option<u32>,
    /// Too many failed restore attempts.
    pub locked: bool,
}

/// The result of [`Account::recover`](crate::api::Account::recover): what
/// [`Account::register`](crate::api::Account::register) returns.
pub type RecoverResult = NewAccount;

// ------------------------------------------------------------------------- deletion (§23)

/// What deleting the account will do (SPEC §23), vault names decrypted where this device can.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionPreview {
    /// Set when the account is already pending.
    pub scheduled_for: Option<Rfc3339>,
    /// When the account would be (or will be) erased.
    pub erase_on: Rfc3339,
    /// Personal vaults and who else is in them.
    pub vaults: Vec<DeletionVault>,
    /// Org memberships and what happens to each.
    pub orgs: Vec<DeletionOrg>,
    /// The paid plan, if any.
    pub subscription: Option<DeletionSubscription>,
    /// Active share links that will end.
    pub share_links: u32,
    /// Deletion is blocked until orgs are handed over.
    pub blocked: bool,
}

/// A personal vault in a [`DeletionPreview`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionVault {
    /// The vault id.
    pub id: String,
    /// Its name, when this device can decrypt it.
    pub name: Option<String>,
    /// Others with access.
    pub shared_with: Vec<DeletionShare>,
}

/// Someone else with access to a vault in a [`DeletionPreview`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionShare {
    /// The principal.
    pub principal: Principal,
    /// Email or name, when known.
    pub display: Option<String>,
    /// Their role.
    pub role: VaultRole,
}

/// What happens to an org membership on deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeletionOutcome {
    /// The user leaves the org.
    Leave,
    /// The org is deleted with the account (no one else is in it).
    Delete,
    /// The user is the only confirmed owner and others are in it.
    Blocked,
}

/// An org in a [`DeletionPreview`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionOrg {
    /// The org id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// The user's role.
    pub role: OrgRole,
    /// What happens.
    pub outcome: DeletionOutcome,
    /// Candidates for owner, admins first.
    pub members: Vec<DeletionCandidate>,
}

/// A candidate owner in a [`DeletionOrg`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionCandidate {
    /// The user id.
    pub id: String,
    /// Their email.
    pub email: String,
    /// Their role.
    pub role: OrgRole,
}

/// The paid plan in a [`DeletionPreview`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionSubscription {
    /// The plan id.
    pub plan: String,
    /// When the paid period ends.
    pub period_end: Option<Rfc3339>,
    /// `stripe` or `apple` (open set).
    pub source: String,
    /// `website` or `app_store` (open set): `app_store` must be cancelled by the user first.
    pub manage: String,
}

// ----------------------------------------------------------------------------- plans (§19)

/// A plan and its limits (SPEC §19). On a server without billing `id` and every limit are `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// `free`, `premium`, `org_free`, `families`, `teams`, `business`, …
    pub id: Option<String>,
    /// Limits by name (see [`plan_limits`]); `None` is unlimited.
    pub limits: Vec<PlanLimit>,
    /// How a paid plan is billed.
    pub billing: Option<Billing>,
}

impl Plan {
    /// The limit `name`, or `None` when unlimited or not part of this plan (Swift `Plan.limit`).
    pub fn limit(&self, name: &str) -> Option<i64> {
        self.limits.iter().find(|l| l.name == name).and_then(|l| l.value)
    }

    /// Whether the plan has the limit at all; a personal plan has no `members` (Swift `Plan.has`).
    pub fn has(&self, name: &str) -> bool {
        self.limits.iter().any(|l| l.name == name)
    }

    /// False on a server without billing: no plan id, and nothing is limited (Swift `hasBilling`).
    pub fn has_billing(&self) -> bool {
        self.id.is_some()
    }
}

/// One limit of a [`Plan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanLimit {
    /// The limit name (see [`plan_limits`]).
    pub name: String,
    /// The limit; `None` is unlimited.
    pub value: Option<i64>,
}

/// Limit names (SPEC §19).
pub mod plan_limits {
    /// Personal vaults a user may own.
    pub const PERSONAL_VAULTS: &str = "personal_vaults";
    /// People a personal vault can be shared with.
    pub const SHARE_RECIPIENTS: &str = "share_recipients";
    /// Org members.
    pub const MEMBERS: &str = "members";
    /// Org vaults.
    pub const ORG_VAULTS: &str = "org_vaults";
    /// Org service accounts.
    pub const SERVICE_ACCOUNTS: &str = "service_accounts";
    /// Days of org audit log.
    pub const AUDIT_DAYS: &str = "audit_days";
    /// Bytes per vault.
    pub const VAULT_BYTES: &str = "vault_bytes";
    /// Longest share-link lifetime in days (SPEC §22).
    pub const SHARE_LINK_DAYS: &str = "share_link_days";
}

/// How a paid plan is billed (SPEC §19). String fields are open sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Billing {
    /// `stripe` or `apple`.
    pub source: String,
    /// `month` or `year`.
    pub interval: String,
    /// `active`, `trialing` or `past_due`.
    pub status: String,
    /// When it renews, or `None` when set not to.
    pub renews_at: Option<Rfc3339>,
    /// When it ends because it won't renew.
    pub ends_at: Option<Rfc3339>,
    /// `website` or `app_store`: where the plan is changed. Follow this, not `source`.
    pub manage: String,
}

/// Whether the App Store may sell this account (or org) a plan (SPEC §19).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppleEligibility {
    /// It may.
    pub eligible: bool,
    /// Why not: `billed_by_stripe`, `billed_by_apple`, `not_owner`, `per_seat_plan`, `billing_off`.
    pub reason: Option<String>,
}

/// The result of reporting an App Store transaction (SPEC §19).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppleTransactionResult {
    /// `user:<uuid>` or `org:<uuid>`.
    pub subject: String,
    /// The plan now.
    pub plan: Plan,
}

// ------------------------------------------------------------------------- vaults & roles

/// A role on a vault (SPEC §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VaultRole {
    /// Read.
    Read,
    /// Read and write.
    Write,
    /// Write, share, rotate, rename, delete.
    Manage,
}

/// A role in an org (SPEC §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OrgRole {
    /// Owner.
    Owner,
    /// Admin.
    Admin,
    /// Member.
    Member,
}

/// Where an org member is in joining (SPEC §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberStatus {
    /// Invited, not accepted.
    Invited,
    /// Accepted, waiting for an admin to confirm (and seal keys).
    Accepted,
    /// Confirmed.
    Confirmed,
}

/// Who may make share links from an org's vaults (SPEC §22).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShareLinkPolicy {
    /// Everyone with access.
    On,
    /// Owners and admins only.
    Managers,
    /// Nobody.
    Off,
}

/// A vault this account can open, name decrypted (the SDK's `VaultInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    /// The vault id.
    pub id: String,
    /// The decrypted name (`""` if no held key opens it).
    pub name: String,
    /// This account's role.
    pub role: VaultRole,
    /// The org, for an org vault.
    pub org_id: Option<String>,
    /// The current key version (SPEC §7).
    pub current_key_version: u32,
    /// A rotation in progress.
    pub pending_key_version: Option<u32>,
    /// A member was removed and the vault needs a rotation.
    pub rotation_required: bool,
}

/// A saved version of a vault on the sync server (SPEC §11 history).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultVersion {
    /// The revision number.
    pub revision: u64,
    /// Its ETag.
    pub etag: String,
    /// Size in bytes.
    pub size: Option<u64>,
    /// When it was saved.
    pub saved_at: Option<Rfc3339>,
    /// The current version.
    pub is_current: bool,
}

/// A blob on the sync server (`BlobMeta`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    /// The vault or database id.
    pub id: String,
    /// Its ETag.
    pub etag: String,
    /// Its revision.
    pub revision: u64,
    /// Size in bytes.
    pub size: u64,
    /// Last update.
    pub updated_at: Rfc3339,
}

/// How [`Account::import_kdbx`](crate::api::Account::import_kdbx) brings a `.kdbx` in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportMode {
    /// "Move to account": a new vault (personal, or in `org_id`), named `name` or after the root
    /// group, with the file's sync remotes dropped.
    NewVault {
        /// The vault name.
        name: Option<String>,
        /// The org, for an org vault.
        org_id: Option<String>,
    },
    /// Merge into an existing vault (entries matched by UUID, newer wins, as Database > Merge).
    Merge {
        /// The target vault.
        vault_id: String,
    },
    /// Add every entry to an existing vault as a new copy, under a group named after the file.
    Copies {
        /// The target vault.
        vault_id: String,
    },
}

/// What [`Account::import_kdbx`](crate::api::Account::import_kdbx) did.
#[derive(Clone, Debug)]
pub struct ImportOutcome {
    /// The vault the entries are in (new or existing).
    pub vault: crate::api::Vault,
    /// The upload succeeded. When `false`, the vault exists and holds the import locally;
    /// [`Vault::sync`](crate::api::Vault::sync) retries the upload (the TS `VaultUploadError`).
    pub uploaded: bool,
    /// Why the upload failed (`vault_upload_failed` with the cause's message).
    pub upload_error: Option<OvError>,
    /// The sync result when it uploaded.
    pub report: Option<SyncReport>,
}

/// Options for [`Vault::sync`](crate::api::Vault::sync),
/// [`Account::sync_vault_kdbx`](crate::api::Account::sync_vault_kdbx) and
/// [`SelfHosted::sync_database_with`](crate::api::SelfHosted::sync_database_with).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncOptions {
    /// `false`: nothing changed here, so ask the server with a HEAD first and stop if it didn't
    /// change either.
    pub local_changed: bool,
    /// "Continue anyway" after `server_rolled_back` or `server_lost_database`: forget what this
    /// device knew of the server (revision, sync generation, base) and take the server's state as it
    /// is, merging the local copy into it, or uploading it as the first version (contract-v1.6).
    pub accept_server_state: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions { local_changed: true, accept_server_state: false }
    }
}

/// The result of [`Account::sync_vault_kdbx`](crate::api::Account::sync_vault_kdbx)
/// (contract-v1.6).
#[derive(Clone, PartialEq, Eq)]
pub struct VaultKdbxSyncResult {
    /// The merged vault, encrypted under `credentials`: keep it as the local copy.
    pub kdbx: Vec<u8>,
    /// The credentials `kdbx` is under (the vault key the server copy uses, as a raw key file).
    /// A secret: wipe it.
    pub credentials: crate::api::KdbxCredentials,
    /// What the sync did: outcome, conflicts, changes, attempts, the new ETag and the clock offset.
    pub report: SyncReport,
}

impl std::fmt::Debug for VaultKdbxSyncResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKdbxSyncResult").field("report", &self.report).finish_non_exhaustive()
    }
}

/// What a sync did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyncOutcome {
    /// Nothing to do.
    Unchanged,
    /// Downloaded and merged; nothing to upload.
    Pulled,
    /// Uploaded local changes.
    Uploaded,
    /// Created the blob on the server.
    Created,
}

/// The kind of a sync conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    /// Edited on both sides.
    EditedOnBoth,
    /// Deleted here, edited on the server.
    DeletedHereEditedThere,
    /// Edited here, deleted on the server.
    EditedHereDeletedThere,
}

/// A conflict the merge resolved (the newer side won; the other is in history).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConflict {
    /// The entry UUID (32 lowercase hex digits).
    pub uuid: String,
    /// What happened.
    pub kind: ConflictKind,
    /// The entry title.
    pub title: String,
    /// For edits on both sides with a base: the fields both changed differently.
    pub fields: Vec<String>,
}

/// The kind of a merge change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChangeType {
    /// Added.
    Added,
    /// Modified.
    Modified,
    /// Moved to another group.
    Moved,
    /// Deleted.
    Deleted,
    /// Database metadata changed.
    Metadata,
}

/// One change the merge applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeChange {
    /// What changed.
    pub change: ChangeType,
    /// The entry or group UUID.
    pub uuid: Option<String>,
    /// Its title.
    pub title: Option<String>,
    /// Its group.
    pub group: Option<String>,
    /// A description.
    pub details: String,
}

/// The result of a sync (the SDK's `SyncResult` without the database itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    /// What happened.
    pub outcome: SyncOutcome,
    /// Conflicts resolved.
    pub conflicts: Vec<SyncConflict>,
    /// Changes merged in.
    pub changes: Vec<MergeChange>,
    /// Upload attempts (more than 1 after 412 retries).
    pub attempts: u32,
    /// The server's ETag now.
    pub etag: Option<String>,
    /// How far this device's clock is ahead of the sync server's (ms; negative: behind), when the
    /// server sent a readable `Date`.
    pub clock_offset_ms: Option<i64>,
    /// `clock_offset_ms` is beyond 5 minutes: warn the user (SPEC §20).
    pub clock_skewed: bool,
}

/// AutoFill edits waiting for the app (iOS): entries an extension saved while the app was closed,
/// kept encrypted with the vault key in [`CachedVault::autofill`](crate::host::CachedVault::autofill).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoFillEdits {
    /// The vault.
    pub vault_id: String,
    /// The saved entries with their group paths.
    pub entries: Vec<AutoFillEdit>,
    /// Identifies this set of edits (a hash of the stored bytes), so
    /// [`Account::clear_autofill_edits`](crate::api::Account::clear_autofill_edits) leaves newer ones alone.
    pub version: String,
}

/// One entry in [`AutoFillEdits`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoFillEdit {
    /// The entry as AutoFill saved it.
    pub entry: crate::api::EntryRecord,
    /// The group path, `/`-separated.
    pub group_path: String,
}

// --------------------------------------------------------------------------- sharing (§7, §12)

/// Someone with access to a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultMember {
    /// The principal.
    pub principal: Principal,
    /// Their role.
    pub role: VaultRole,
    /// Email, name or service-account name.
    pub display: String,
    /// The key version they hold.
    pub key_version: u32,
    /// This account.
    pub is_you: bool,
}

/// A person (or SA) a vault can be shared with, keys verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRecipient {
    /// The principal.
    pub principal: Principal,
    /// Their email.
    pub email: Option<String>,
    /// Their name.
    pub name: Option<String>,
    /// Their verified public keys.
    pub public_keys: PublicKeys,
}

/// Who [`Account::share_vault`](crate::api::Account::share_vault) grants access to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grantee {
    /// Look the user up by email.
    Email(String),
    /// A known principal.
    Principal(Principal),
}

/// The result of sharing a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantResult {
    /// Who got access.
    pub principal: Principal,
    /// Their fingerprint, to compare out of band.
    pub fingerprint: String,
}

/// A vault and role, for SA creation and member confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultGrantRequest {
    /// The vault.
    pub vault_id: String,
    /// The role.
    pub role: VaultRole,
}

/// An org (`GET /orgs/{org}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Org {
    /// The org id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// This user's role.
    pub role: OrgRole,
    /// The org's plan.
    pub plan: Option<Plan>,
    /// Who may make share links from its vaults.
    pub item_share_links: Option<ShareLinkPolicy>,
    /// Created.
    pub created_at: Rfc3339,
}

/// An org this user belongs to, as `/me` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgMembership {
    /// The org id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// This user's role.
    pub role: OrgRole,
    /// This user's status.
    pub status: MemberStatus,
    /// The org's plan.
    pub plan: Option<Plan>,
    /// Who may make share links from its vaults.
    pub item_share_links: Option<ShareLinkPolicy>,
}

/// An org member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The user id.
    pub user_id: String,
    /// Their email.
    pub email: String,
    /// Their name.
    pub name: Option<String>,
    /// Their role.
    pub role: OrgRole,
    /// Their status.
    pub status: MemberStatus,
    /// Their public keys (signature not yet checked), once they have accepted.
    pub public_keys: Option<PublicKeys>,
}

/// An org invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    /// The invitation id.
    pub id: String,
    /// Invited email.
    pub email: String,
    /// The role on joining.
    pub role: OrgRole,
    /// Expiry.
    pub expires_at: Rfc3339,
    /// Who invited.
    pub invited_by: Principal,
}

/// The result of rotating several vaults (member removal, flagged vaults).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationReport {
    /// Vaults rotated.
    pub rotated: Vec<String>,
    /// Vaults whose rotation failed.
    pub failed: Vec<RotationFailure>,
}

/// A vault whose rotation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationFailure {
    /// The vault.
    pub vault_id: String,
    /// Why.
    pub error: OvError,
}

// --------------------------------------------------------------------- service accounts (§9)

/// A service account as its org's admins see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceAccountInfo {
    /// The SA id.
    pub id: String,
    /// Its org.
    pub org_id: String,
    /// Its name.
    pub name: String,
    /// Its public keys.
    pub public_keys: Option<PublicKeys>,
    /// Who created it.
    pub created_by: Option<Principal>,
    /// Created.
    pub created_at: Option<Rfc3339>,
    /// Expiry.
    pub expires_at: Option<Rfc3339>,
    /// Disabled.
    pub disabled: bool,
}

/// A new service account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewServiceAccount {
    /// Its name.
    pub name: String,
    /// Vaults to grant it.
    pub vaults: Vec<VaultGrantRequest>,
    /// Expiry of the SA and its first secret.
    pub expires_at: Option<Rfc3339>,
    /// A name for the first secret.
    pub secret_name: Option<String>,
}

/// A created service account and its first token (show once).
#[derive(Clone, PartialEq, Eq)]
pub struct CreatedServiceAccount {
    /// The SA.
    pub service_account: ServiceAccountInfo,
    /// The `ov_sa_…` token.
    pub token: SecretBytes,
}

impl std::fmt::Debug for CreatedServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedServiceAccount").field("service_account", &self.service_account).finish()
    }
}

/// A newly issued SA secret (show the token once).
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedSecret {
    /// The `ov_sa_…` token.
    pub token: SecretBytes,
    /// The secret id.
    pub id: String,
    /// The token prefix shown in lists.
    pub prefix: String,
}

impl std::fmt::Debug for IssuedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedSecret").field("id", &self.id).field("prefix", &self.prefix).finish()
    }
}

/// An SA secret in a list (never the token).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaSecretInfo {
    /// The secret id.
    pub id: String,
    /// The token prefix.
    pub prefix: String,
    /// Its name.
    pub name: Option<String>,
    /// Created.
    pub created_at: Rfc3339,
    /// Last used.
    pub last_used_at: Option<Rfc3339>,
    /// Expiry.
    pub expires_at: Option<Rfc3339>,
}

/// A change to an expiry date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpiryChange {
    /// Leave it.
    Keep,
    /// Never expires.
    Never,
    /// Expires then.
    At(Rfc3339),
}

/// Changes to a service account (`PATCH /service-accounts/{sa}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceAccountUpdate {
    /// A new name.
    pub name: Option<String>,
    /// A new expiry.
    pub expires_at: ExpiryChange,
    /// Disable or enable.
    pub disabled: Option<bool>,
}

/// One org audit-log event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// The event id.
    pub id: String,
    /// When.
    pub at: Rfc3339,
    /// Who.
    pub actor: Principal,
    /// What, e.g. `vault.share`.
    pub action: String,
    /// The object.
    pub target: Option<String>,
    /// The client IP.
    pub ip: Option<String>,
    /// Extra data, as a JSON object.
    pub details: Option<String>,
}

/// A page of the audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPage {
    /// Events, newest first.
    pub events: Vec<AuditEvent>,
    /// Pass as `before` for the next page.
    pub next: Option<String>,
}
