//! The facade's plain records and enums, exposed as they are with `#[uniffi::remote]`: each
//! declaration below restates an `ov_core` type field for field (the compiler checks they match),
//! so no conversion code runs and Swift sees the same names. Records that hold a handle or an
//! `OvError` can't be remote; they have local mirrors in `wrapped`.
//!
//! `SecretBytes` fields are `[u8]` here and `Data` in Swift; the caller wipes what it receives.

use ov_core::api::ReconnectResult;
use ov_core::api::{
    AccountEvent, AppleEligibility, AppleTransactionResult, AttachmentInfo, AuditEvent, AuditPage, AutoFillEdit,
    AutoFillEdits, Billing, BlobMeta, ChangeType, ClientConfig, ConflictKind, CreateMode, CreatedServiceAccount,
    CreatedShare, DeletionCandidate, DeletionOrg, DeletionOutcome, DeletionPreview, DeletionShare,
    DeletionSubscription, DeletionVault, Device, DeviceInfo, EmergencyKit, EntryExpiry, EntryInput, EntryRecord,
    EntrySummary, ExpiryChange, ExportFormat, FieldInput, FieldRecord, GrantResult, Grantee, GroupInfo, ImportMode,
    ImportPreview, ImportSummary, ImportTarget, Injected, Invitation, IssuedSecret, KdbxCredentials, KdbxKdf, KdfMin,
    KdfOverrides, KdfParams, LocalImportMode, LoginInput, Member, MemberStatus, MergeChange, NewAccount,
    NewServiceAccount, OpaqueConfig, OpenedShare, Org, OrgMembership, OrgRole, PairingCode, ParkedCheck, Plan,
    PlanLimit, Platform, Profile, PublicKeys, RecoveryReset, RecoveryStatus, RegisterInput, RememberedAccount,
    SaSecretInfo, SaVault, SelfHostedSyncResult, ServerConfig, ServiceAccountInfo, ServiceAccountUpdate, SessionState,
    SetFieldsResult, ShareField, ShareInfo, ShareLinkPolicy, ShareListing, ShareOptions, SharePayload, ShareRecipient,
    ShareRef, ShareableField, SignedOutReason, StoredSession, SyncConflict, SyncOptions, SyncOutcome, SyncReport,
    TotpAlgorithm, TotpCode, TotpParams, TotpSetup, Unlocked, VaultGrantRequest, VaultInfo, VaultKdbxSyncResult,
    VaultMember, VaultRole, VaultVersion, VersionDifference,
};
use ov_core::host::{CachedVault, Level, Method};

// ------------------------------------------------------------------------------- config

#[uniffi::remote(Record)]
pub struct ServerConfig {
    pub issuer: String,
    pub api: String,
    pub sync: String,
    pub jwks_uri: String,
    pub opaque: OpaqueConfig,
    pub kdf_min: Option<KdfMin>,
    pub web: Option<String>,
    pub share: Option<String>,
}

#[uniffi::remote(Record)]
pub struct OpaqueConfig {
    pub lib: String,
    pub version: String,
    pub context: String,
    pub ids: String,
}

#[uniffi::remote(Record)]
pub struct KdfMin {
    pub m: u32,
    pub t: u32,
}

#[uniffi::remote(Enum)]
pub enum Platform {
    QtLinux,
    QtMacos,
    QtWindows,
    Web,
    Cli,
    Connect,
    Ios,
}

#[uniffi::remote(Record)]
pub struct DeviceInfo {
    pub id: Option<String>,
    pub name: String,
    pub platform: Platform,
}

#[uniffi::remote(Record)]
pub struct ClientConfig {
    pub device: DeviceInfo,
    pub offline: bool,
    pub server: Option<ServerConfig>,
}

// ------------------------------------------------------------------------------- crypto

#[uniffi::remote(Record)]
pub struct KdfParams {
    pub alg: String,
    pub salt: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

#[uniffi::remote(Record)]
pub struct KdfOverrides {
    pub m: Option<u32>,
    pub t: Option<u32>,
    pub p: Option<u32>,
}

#[uniffi::remote(Record)]
pub struct PublicKeys {
    pub enc_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub fingerprint: String,
}

// ----------------------------------------------------------------------------- sessions

#[uniffi::remote(Record)]
pub struct StoredSession {
    pub issuer: String,
    pub user_id: String,
    pub email: String,
    pub device_id: String,
}

#[uniffi::remote(Enum)]
pub enum SignedOutReason {
    TokenReused,
    SessionExpired,
    Unauthorized,
    Logout,
    DeletionScheduled,
    AccountDeleted,
}

#[uniffi::remote(Enum)]
pub enum SessionState {
    Active,
    Parked,
    SignedOut,
}

#[uniffi::remote(Enum)]
pub enum ParkedCheck {
    Valid,
    Ended,
    NoAnswer,
}

#[uniffi::remote(Record)]
pub struct RememberedAccount {
    pub email: String,
    pub issuer: String,
    pub user_id: String,
    pub last_used_at: String,
    pub checked_at: Option<String>,
    pub deletion_scheduled_for: Option<String>,
}

#[uniffi::remote(Record)]
pub struct NewAccount {
    pub user_id: String,
    pub secret_key: Vec<u8>,
    pub emergency_kit: EmergencyKit,
    pub auk: Vec<u8>,
}

#[uniffi::remote(Record)]
pub struct EmergencyKit {
    pub email: String,
    pub issuer: String,
    pub web: Option<String>,
}

#[uniffi::remote(Record)]
pub struct RegisterInput {
    pub email: String,
    pub password: Vec<u8>,
    pub kdf: Option<KdfOverrides>,
    pub trust_device: bool,
}

#[uniffi::remote(Record)]
pub struct LoginInput {
    pub email: String,
    pub password: Vec<u8>,
    pub secret_key: Option<Vec<u8>>,
    pub totp: Option<String>,
    pub trust_device: bool,
}

#[uniffi::remote(Record)]
pub struct Unlocked {
    pub auk: Vec<u8>,
    pub offline: bool,
    pub deletion_scheduled_for: Option<String>,
}

#[uniffi::remote(Record)]
pub struct Profile {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub totp_enabled: bool,
    pub plan: Option<Plan>,
    pub orgs: Vec<OrgMembership>,
    pub deletion_scheduled_for: Option<String>,
}

#[uniffi::remote(Record)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub current: bool,
}

#[uniffi::remote(Record)]
pub struct TotpSetup {
    pub secret: Vec<u8>,
    pub uri: Vec<u8>,
}

#[uniffi::remote(Record)]
pub struct ReconnectResult {
    pub vaults: Vec<VaultInfo>,
    pub dropped: Vec<String>,
}

// ----------------------------------------------------------------------- recovery (§18)

#[uniffi::remote(Record)]
pub struct RecoveryReset {
    pub email: String,
    pub not_before: String,
    pub expires_at: String,
    pub archive_days: u32,
    pub personal_vaults: u32,
    pub shared_grants: u32,
    pub sole_admin_orgs: Vec<String>,
}

#[uniffi::remote(Record)]
pub struct RecoveryStatus {
    pub archived: bool,
    pub email: Option<String>,
    pub expires_at: Option<String>,
    pub vaults: Option<u32>,
    pub locked: bool,
}

// ----------------------------------------------------------------------- deletion (§23)

#[uniffi::remote(Record)]
pub struct DeletionPreview {
    pub scheduled_for: Option<String>,
    pub erase_on: String,
    pub vaults: Vec<DeletionVault>,
    pub orgs: Vec<DeletionOrg>,
    pub subscription: Option<DeletionSubscription>,
    pub share_links: u32,
    pub blocked: bool,
}

#[uniffi::remote(Record)]
pub struct DeletionVault {
    pub id: String,
    pub name: Option<String>,
    pub shared_with: Vec<DeletionShare>,
}

#[uniffi::remote(Record)]
pub struct DeletionShare {
    pub principal: String,
    pub display: Option<String>,
    pub role: VaultRole,
}

#[uniffi::remote(Enum)]
pub enum DeletionOutcome {
    Leave,
    Delete,
    Blocked,
}

#[uniffi::remote(Record)]
pub struct DeletionOrg {
    pub id: String,
    pub name: String,
    pub role: OrgRole,
    pub outcome: DeletionOutcome,
    pub members: Vec<DeletionCandidate>,
}

#[uniffi::remote(Record)]
pub struct DeletionCandidate {
    pub id: String,
    pub email: String,
    pub role: OrgRole,
}

#[uniffi::remote(Record)]
pub struct DeletionSubscription {
    pub plan: String,
    pub period_end: Option<String>,
    pub source: String,
    pub manage: String,
}

// --------------------------------------------------------------------------- plans (§19)

#[uniffi::remote(Record)]
pub struct Plan {
    pub id: Option<String>,
    pub limits: Vec<PlanLimit>,
    pub billing: Option<Billing>,
}

#[uniffi::remote(Record)]
pub struct PlanLimit {
    pub name: String,
    pub value: Option<i64>,
}

#[uniffi::remote(Record)]
pub struct Billing {
    pub source: String,
    pub interval: String,
    pub status: String,
    pub renews_at: Option<String>,
    pub ends_at: Option<String>,
    pub manage: String,
}

#[uniffi::remote(Record)]
pub struct AppleEligibility {
    pub eligible: bool,
    pub reason: Option<String>,
}

#[uniffi::remote(Record)]
pub struct AppleTransactionResult {
    pub subject: String,
    pub plan: Plan,
}

// ----------------------------------------------------------------------- vaults & roles

#[uniffi::remote(Enum)]
pub enum VaultRole {
    Read,
    Write,
    Manage,
}

#[uniffi::remote(Enum)]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

#[uniffi::remote(Enum)]
pub enum MemberStatus {
    Invited,
    Accepted,
    Confirmed,
}

#[uniffi::remote(Enum)]
pub enum ShareLinkPolicy {
    On,
    Managers,
    Off,
}

#[uniffi::remote(Record)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub role: VaultRole,
    pub org_id: Option<String>,
    pub current_key_version: u32,
    pub pending_key_version: Option<u32>,
    pub rotation_required: bool,
}

#[uniffi::remote(Record)]
pub struct VaultVersion {
    pub revision: u64,
    pub etag: String,
    pub size: Option<u64>,
    pub saved_at: Option<String>,
    pub is_current: bool,
}

#[uniffi::remote(Record)]
pub struct BlobMeta {
    pub id: String,
    pub etag: String,
    pub revision: u64,
    pub size: u64,
    pub updated_at: String,
}

#[uniffi::remote(Enum)]
pub enum ImportMode {
    NewVault { name: Option<String>, org_id: Option<String> },
    Merge { vault_id: String },
    Copies { vault_id: String },
}

#[uniffi::remote(Record)]
pub struct SyncOptions {
    pub local_changed: bool,
    #[uniffi(default = false)]
    pub accept_server_state: bool,
}

#[uniffi::remote(Enum)]
pub enum SyncOutcome {
    Unchanged,
    Pulled,
    Uploaded,
    Created,
}

#[uniffi::remote(Enum)]
pub enum ConflictKind {
    EditedOnBoth,
    DeletedHereEditedThere,
    EditedHereDeletedThere,
}

#[uniffi::remote(Record)]
pub struct SyncConflict {
    pub uuid: String,
    pub kind: ConflictKind,
    pub title: String,
    pub fields: Vec<String>,
}

#[uniffi::remote(Enum)]
pub enum ChangeType {
    Added,
    Modified,
    Moved,
    Deleted,
    Metadata,
}

#[uniffi::remote(Record)]
pub struct MergeChange {
    pub change: ChangeType,
    pub uuid: Option<String>,
    pub title: Option<String>,
    pub group: Option<String>,
    pub details: String,
}

#[uniffi::remote(Record)]
pub struct SyncReport {
    pub outcome: SyncOutcome,
    pub conflicts: Vec<SyncConflict>,
    pub changes: Vec<MergeChange>,
    pub attempts: u32,
    pub etag: Option<String>,
    pub clock_offset_ms: Option<i64>,
    pub clock_skewed: bool,
}

#[uniffi::remote(Record)]
pub struct AutoFillEdits {
    pub vault_id: String,
    pub entries: Vec<AutoFillEdit>,
    pub version: String,
}

#[uniffi::remote(Record)]
pub struct AutoFillEdit {
    pub entry: EntryRecord,
    pub group_path: String,
}

// ----------------------------------------------------------------------- sharing (§7, §12)

#[uniffi::remote(Record)]
pub struct VaultMember {
    pub principal: String,
    pub role: VaultRole,
    pub display: String,
    pub key_version: u32,
    pub is_you: bool,
}

#[uniffi::remote(Record)]
pub struct ShareRecipient {
    pub principal: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub public_keys: PublicKeys,
}

#[uniffi::remote(Enum)]
pub enum Grantee {
    Email(String),
    Principal(String),
}

#[uniffi::remote(Record)]
pub struct GrantResult {
    pub principal: String,
    pub fingerprint: String,
}

#[uniffi::remote(Record)]
pub struct VaultGrantRequest {
    pub vault_id: String,
    pub role: VaultRole,
}

#[uniffi::remote(Record)]
pub struct Org {
    pub id: String,
    pub name: String,
    pub role: OrgRole,
    pub plan: Option<Plan>,
    pub item_share_links: Option<ShareLinkPolicy>,
    pub created_at: String,
}

#[uniffi::remote(Record)]
pub struct OrgMembership {
    pub id: String,
    pub name: String,
    pub role: OrgRole,
    pub status: MemberStatus,
    pub plan: Option<Plan>,
    pub item_share_links: Option<ShareLinkPolicy>,
}

#[uniffi::remote(Record)]
pub struct Member {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub role: OrgRole,
    pub status: MemberStatus,
    pub public_keys: Option<PublicKeys>,
}

#[uniffi::remote(Record)]
pub struct Invitation {
    pub id: String,
    pub email: String,
    pub role: OrgRole,
    pub expires_at: String,
    pub invited_by: String,
}

// ------------------------------------------------------------------- service accounts (§9)

#[uniffi::remote(Record)]
pub struct ServiceAccountInfo {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub public_keys: Option<PublicKeys>,
    pub created_by: Option<String>,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
    pub disabled: bool,
}

#[uniffi::remote(Record)]
pub struct NewServiceAccount {
    pub name: String,
    pub vaults: Vec<VaultGrantRequest>,
    pub expires_at: Option<String>,
    pub secret_name: Option<String>,
}

#[uniffi::remote(Record)]
pub struct CreatedServiceAccount {
    pub service_account: ServiceAccountInfo,
    pub token: Vec<u8>,
}

#[uniffi::remote(Record)]
pub struct IssuedSecret {
    pub token: Vec<u8>,
    pub id: String,
    pub prefix: String,
}

#[uniffi::remote(Record)]
pub struct SaSecretInfo {
    pub id: String,
    pub prefix: String,
    pub name: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
}

#[uniffi::remote(Enum)]
pub enum ExpiryChange {
    Keep,
    Never,
    At(String),
}

#[uniffi::remote(Record)]
pub struct ServiceAccountUpdate {
    pub name: Option<String>,
    pub expires_at: ExpiryChange,
    pub disabled: Option<bool>,
}

#[uniffi::remote(Record)]
pub struct AuditEvent {
    pub id: String,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub ip: Option<String>,
    pub details: Option<String>,
}

#[uniffi::remote(Record)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next: Option<String>,
}

#[uniffi::remote(Record)]
pub struct SaVault {
    pub id: String,
    pub name: String,
    pub role: VaultRole,
}

#[uniffi::remote(Record)]
pub struct Injected {
    pub text: Vec<u8>,
    pub secrets: Vec<Vec<u8>>,
}

// ------------------------------------------------------------------------- self-hosted

#[uniffi::remote(Record)]
pub struct PairingCode {
    pub code: String,
    pub expires_at: String,
}

#[uniffi::remote(Record)]
pub struct SelfHostedSyncResult {
    pub kdbx: Vec<u8>,
    pub report: SyncReport,
}

#[uniffi::remote(Record)]
pub struct VaultKdbxSyncResult {
    pub kdbx: Vec<u8>,
    pub credentials: KdbxCredentials,
    pub report: SyncReport,
}

// ------------------------------------------------------------------------- share links (§22)

#[uniffi::remote(Record)]
pub struct ShareOptions {
    pub expires_in: u32,
    pub max_opens: Option<u32>,
    pub passcode: Option<Vec<u8>>,
    pub vault_id: Option<String>,
    pub entry_id: Option<String>,
}

#[uniffi::remote(Record)]
pub struct CreatedShare {
    pub id: String,
    pub url: Vec<u8>,
    pub expires_at: String,
}

#[uniffi::remote(Record)]
pub struct ShareRef {
    pub vault: Option<String>,
    pub entry: Option<String>,
    pub title: String,
}

#[uniffi::remote(Record)]
pub struct ShareListing {
    pub id: String,
    pub vault_id: Option<String>,
    pub reference: Option<ShareRef>,
    pub passcode: bool,
    pub max_opens: Option<u32>,
    pub opens: u32,
    pub opened_at: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    pub status: String,
    pub ended_at: Option<String>,
    pub end_reason: Option<String>,
}

#[uniffi::remote(Record)]
pub struct SharePayload {
    pub v: u32,
    pub kind: String,
    pub title: Option<String>,
    pub shared_by: Option<String>,
    pub fields: Vec<ShareField>,
}

#[uniffi::remote(Record)]
pub struct ShareField {
    pub k: String,
    pub label: String,
    pub value: Vec<u8>,
    pub protected: bool,
}

#[uniffi::remote(Record)]
pub struct ShareableField {
    pub name: String,
    pub kind: String,
    pub label: String,
    pub value: Vec<u8>,
    pub protected: bool,
}

#[uniffi::remote(Record)]
pub struct ShareInfo {
    pub expires_at: String,
    pub opens_left: Option<u32>,
    pub kdf: Option<KdfParams>,
}

#[uniffi::remote(Record)]
pub struct OpenedShare {
    pub payload: SharePayload,
    pub opens_left: Option<u32>,
}

// -------------------------------------------------------------------------------- TOTP

#[uniffi::remote(Enum)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[uniffi::remote(Record)]
pub struct TotpParams {
    pub secret: Vec<u8>,
    pub digits: u32,
    pub period: u32,
    pub algorithm: TotpAlgorithm,
    pub encoder: Option<String>,
}

#[uniffi::remote(Record)]
pub struct TotpCode {
    pub code: Vec<u8>,
    pub remaining: u32,
}

// ------------------------------------------------------------------------------- vault

#[uniffi::remote(Record)]
pub struct KdbxCredentials {
    pub password: Option<Vec<u8>>,
    pub key_file: Option<Vec<u8>>,
}

#[uniffi::remote(Record)]
pub struct EntrySummary {
    pub id: String,
    pub group_id: String,
    pub group_path: Vec<String>,
    pub title: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    pub protected_fields: Vec<String>,
    pub icon_id: u32,
    pub custom_icon: Option<String>,
    pub modified_at: i64,
    pub expires_at: Option<i64>,
    pub in_recycle_bin: bool,
    #[uniffi(default = None)]
    pub last_access_at: Option<i64>,
    #[uniffi(default = 0)]
    pub usage_count: u32,
}

#[uniffi::remote(Record)]
pub struct FieldRecord {
    pub name: String,
    pub value: Vec<u8>,
    pub protected: bool,
}

#[uniffi::remote(Record)]
pub struct AttachmentInfo {
    pub name: String,
    pub size: u64,
    #[uniffi(default = true)]
    pub protected: bool,
}

#[uniffi::remote(Record)]
pub struct EntryRecord {
    pub id: String,
    pub group_id: String,
    pub group_path: Vec<String>,
    pub fields: Vec<FieldRecord>,
    pub tags: Vec<String>,
    pub icon_id: u32,
    pub custom_icon: Option<String>,
    pub foreground_color: String,
    pub background_color: String,
    pub override_url: String,
    pub created_at: i64,
    pub modified_at: i64,
    pub expires_at: Option<i64>,
    pub attachments: Vec<AttachmentInfo>,
    pub history_count: u32,
    pub quality_check: bool,
    #[uniffi(default = None)]
    pub last_access_at: Option<i64>,
    #[uniffi(default = 0)]
    pub usage_count: u32,
}

#[uniffi::remote(Record)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub path: Vec<String>,
    pub icon_id: u32,
    pub notes: String,
    pub is_recycle_bin: bool,
    pub entry_count: u32,
}

#[uniffi::remote(Record)]
pub struct FieldInput {
    pub name: String,
    pub value: Vec<u8>,
    pub protected: Option<bool>,
}

#[uniffi::remote(Enum)]
pub enum EntryExpiry {
    Keep,
    Never,
    At(i64),
}

#[uniffi::remote(Record)]
pub struct EntryInput {
    pub fields: Vec<FieldInput>,
    pub remove_fields: Vec<String>,
    pub tags: Option<Vec<String>>,
    pub icon_id: Option<u32>,
    pub expiry: EntryExpiry,
    #[uniffi(default = None)]
    pub foreground_color: Option<String>,
    #[uniffi(default = None)]
    pub background_color: Option<String>,
    #[uniffi(default = None)]
    pub custom_icon: Option<Option<String>>,
    #[uniffi(default = None)]
    pub field_order: Option<Vec<String>>,
}

#[uniffi::remote(Enum)]
pub enum CreateMode {
    MustExist,
    CreateIfMissing,
    CreateOnly,
}

#[uniffi::remote(Record)]
pub struct SetFieldsResult {
    pub entry: EntryRecord,
    pub created: bool,
}

#[uniffi::remote(Enum)]
pub enum VersionDifference {
    Same,
    Changed,
    Deleted,
}

#[uniffi::remote(Enum)]
pub enum ExportFormat {
    Csv,
    Json,
}

#[uniffi::remote(Enum)]
pub enum LocalImportMode {
    Merge,
    Copies { parent_group_id: Option<String> },
}

#[uniffi::remote(Record)]
pub struct ImportSummary {
    pub added: u32,
    pub updated: u32,
    pub unchanged: u32,
    pub groups_added: u32,
    pub changes: Vec<MergeChange>,
}

#[uniffi::remote(Record)]
pub struct ImportPreview {
    pub entries: u32,
    pub groups: u32,
}

#[uniffi::remote(Record)]
pub struct ImportTarget {
    pub group_id: String,
    pub path: String,
}

#[uniffi::remote(Enum)]
pub enum KdbxKdf {
    DatabaseDefault,
    Argon2d { memory: u64, iterations: u64, parallelism: u32 },
    Argon2id { memory: u64, iterations: u64, parallelism: u32 },
    AesKdf { rounds: u64 },
}

// ------------------------------------------------------------------------------ events

#[uniffi::remote(Enum)]
pub enum AccountEvent {
    VaultChanged { vault_id: String, etag: Option<String>, revision: Option<u64>, deleted: bool },
    VaultsChanged { vaults: Vec<VaultInfo> },
    SessionEnded { reason: SignedOutReason, at: Option<String> },
    DatabaseChanged { database_id: String, etag: Option<String>, revision: Option<u64>, deleted: bool },
}

// -------------------------------------------------------------------------------- host

#[uniffi::remote(Enum)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

#[uniffi::remote(Enum)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[uniffi::remote(Record)]
pub struct CachedVault {
    pub state: Vec<u8>,
    pub base: Option<Vec<u8>>,
    pub pending: Option<Vec<u8>>,
    pub autofill: Option<Vec<u8>>,
}
