//! cxx C++ binding of the ov-core facade, for the desktop (C++17 / Qt).
//!
//! - [`ffi`] is the cxx bridge. Records cross as plain shared structs and enums; handles
//!   ([`Client`], [`Account`], [`Vault`], [`EventStream`], [`TotpChallenge`], [`LoginStep`],
//!   [`CancelToken`]) are opaque Rust types C++ owns through `rust::Box`.
//! - The Host traits are C++ pure-virtual classes (`include/host.h`), adapted to the Rust traits in
//!   [`host`].
//! - Async calls block the calling thread (see `README.md`): every one takes a [`CancelToken`].
//! - Every call catches panics at the edge and fails with `OvError { code: internal }`. A failed
//!   call throws `rust::Error` in C++; `ov::call()` (in `include/ovcore.h`) turns it into an
//!   `ov::Error` carrying the whole OvError, read from `ffi::take_last_error`.
//!
//! Every public method and free function of `ov_core::api` is bridged (`tests/coverage.rs` checks
//! it); `README.md` lists the one deliberate exclusion.

#![warn(missing_docs)]

mod account_ext;
mod convert;
mod crypto;
mod edge;
mod handles;
pub mod host;
mod merge;
mod more;
mod opaque;
mod primitives;
mod records;
mod test_servers;
mod v16;

pub use edge::FfiError;
pub use handles::{
    new_cancel_token, new_client, vault_create_local, vault_open_local, Account, CancelToken, Client, EventStream,
    LoginStep, TotpChallenge, Vault,
};

pub use more::{
    default_share_fields, deletion_expired, entry_totp_uri, item_share_payload, parse_totp_uri, plan_has,
    plan_has_billing, plan_limit, platform_as_str, self_hosted_connect, self_hosted_pair, self_hosted_restore,
    service_account_from_token, shareable_fields, text_share_payload, totp_code, RestoredSelfHosted, SelfHosted,
    ServiceAccount,
};

use crypto::{
    build_service_account_token, ed25519_public_key, ed25519_sign, ed25519_verify, fingerprint, format_secret_key,
    generate_secret_key, keyset_from_secrets, nfkc_utf8, parse_secret_key, parse_service_account_token,
    refresh_token_hash, seal, seal_derived_key, service_account_secret_hash, service_account_secret_prefix, unseal,
    unwrap, vault_name_key, verify_public_keys, wrap, x25519_public_key, x25519_shared,
};
use edge::take_last_error;
pub use merge::merge_kdbx;
use opaque::{
    opaque_finish_login, opaque_finish_login_seeded, opaque_finish_registration, opaque_finish_registration_seeded,
    opaque_server_credential_response, opaque_server_credential_response_seeded, opaque_server_registration_response,
    opaque_server_registration_response_seeded, opaque_server_store_record, opaque_server_user_auth,
    opaque_start_login, opaque_start_login_seeded, opaque_start_registration, opaque_start_registration_seeded,
    test_server_enabled,
};
use primitives::{aead_decrypt, aead_encrypt, argon2id, hkdf_sha256, random_bytes, sha256};
pub use test_servers::{test_servers_start, TestServers, TestStream};

/// The core's version, as C++ sees it (`ov::version()`).
pub fn version() -> String {
    ov_core::version().to_string()
}

/// The cxx bridge. Everything here is visible to C++ in namespace `ov`.
#[cxx::bridge(namespace = "ov")]
#[allow(missing_docs)]
pub mod ffi {
    // ------------------------------------------------------------------------------- errors

    /// An `OvError` (rust-core-tasks.md §2.4). Empty strings and 0 mean "none".
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ErrorInfo {
        /// The stable wire code, e.g. `plan_limit`.
        code: String,
        message: String,
        /// HTTP status; 0 for none.
        status: u16,
        has_retry_after: bool,
        retry_after: u32,
        /// A JSON object string, or empty.
        details: String,
        /// The server's code when it isn't one of the wire codes, or empty.
        server_code: String,
    }

    // ------------------------------------------------------------------------- host records

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Method {
        Get,
        Head,
        Post,
        Put,
        Patch,
        Delete,
    }

    #[derive(Clone, PartialEq, Eq)]
    struct Header {
        name: String,
        value: String,
    }

    #[derive(Clone)]
    struct HttpRequest {
        method: Method,
        url: String,
        headers: Vec<Header>,
        has_body: bool,
        body: Vec<u8>,
        keepalive: bool,
    }

    #[derive(Clone, Default)]
    struct HttpResponse {
        status: u16,
        headers: Vec<Header>,
        body: Vec<u8>,
    }

    /// Rust `TransportError`; `None` means no failure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    enum TransportErrorKind {
        None,
        Offline,
        Timeout,
        Tls,
        Cancelled,
        Other,
    }

    /// Set by HttpTransport/ByteStream implementations when a request fails.
    #[derive(Clone, Debug)]
    struct TransportFailure {
        kind: TransportErrorKind,
        message: String,
    }

    /// Rust `CachedVault`; the `has_*` flags say whether the optional copies are present.
    #[derive(Clone, Default)]
    struct CachedVault {
        state: Vec<u8>,
        has_base: bool,
        base: Vec<u8>,
        has_pending: bool,
        pending: Vec<u8>,
        has_autofill: bool,
        autofill: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    enum LogLevel {
        Error,
        Warn,
        Info,
        Debug,
        Trace,
    }

    // ----------------------------------------------------------------------- facade records

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Platform {
        QtLinux,
        QtMacos,
        QtWindows,
        Web,
        Cli,
        Connect,
        Ios,
    }

    /// The discovery document (SPEC §10). Empty strings mean "none".
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ServerConfig {
        issuer: String,
        api: String,
        sync: String,
        jwks_uri: String,
        opaque_lib: String,
        opaque_version: String,
        opaque_context: String,
        opaque_ids: String,
        has_kdf_min: bool,
        kdf_min_m: u32,
        kdf_min_t: u32,
        web: String,
        share: String,
    }

    /// Rust `ClientConfig` (with `DeviceInfo` flattened). Empty `device_id` means none.
    #[derive(Clone, Debug)]
    struct ClientConfig {
        device_id: String,
        device_name: String,
        platform: Platform,
        offline: bool,
        has_server: bool,
        server: ServerConfig,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SessionState {
        Active,
        Parked,
        SignedOut,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RememberedAccount {
        email: String,
        issuer: String,
        user_id: String,
        last_used_at: String,
        checked_at: String,
        deletion_scheduled_for: String,
    }

    /// Rust `LoginInput`. Secrets are moved into the core, which wipes them.
    struct LoginInput {
        email: String,
        password: Vec<u8>,
        has_secret_key: bool,
        secret_key: Vec<u8>,
        /// A TOTP code, or empty.
        totp: String,
        trust_device: bool,
    }

    /// Rust `Unlocked`. Wipe `auk` (ov::wipe) when done with it.
    struct Unlocked {
        auk: Vec<u8>,
        offline: bool,
        deletion_scheduled_for: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum VaultRole {
        Read,
        Write,
        Manage,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct VaultInfo {
        id: String,
        name: String,
        role: VaultRole,
        org_id: String,
        current_key_version: u32,
        has_pending_key_version: bool,
        pending_key_version: u32,
        rotation_required: bool,
    }

    /// Rust `KdbxCredentials`.
    struct KdbxCredentials {
        has_password: bool,
        password: Vec<u8>,
        has_key_file: bool,
        key_file: Vec<u8>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct EntrySummary {
        id: String,
        group_id: String,
        group_path: Vec<String>,
        title: String,
        username: String,
        url: String,
        tags: Vec<String>,
        protected_fields: Vec<String>,
        icon_id: u32,
        custom_icon: String,
        modified_at: i64,
        has_expires_at: bool,
        expires_at: i64,
        in_recycle_bin: bool,
        /// contract-v1.6: `LastAccessTime` when `usage_count > 0`.
        has_last_access_at: bool,
        last_access_at: i64,
        usage_count: u32,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct GroupInfo {
        id: String,
        name: String,
        /// Empty for the root.
        parent_id: String,
        path: Vec<String>,
        icon_id: u32,
        notes: String,
        is_recycle_bin: bool,
        entry_count: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SyncOutcome {
        Unchanged,
        Pulled,
        Uploaded,
        Created,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ConflictKind {
        EditedOnBoth,
        DeletedHereEditedThere,
        EditedHereDeletedThere,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SyncConflict {
        uuid: String,
        kind: ConflictKind,
        title: String,
        fields: Vec<String>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ChangeType {
        Added,
        Modified,
        Moved,
        Deleted,
        Metadata,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MergeChange {
        change: ChangeType,
        uuid: String,
        title: String,
        group: String,
        details: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SyncReport {
        outcome: SyncOutcome,
        conflicts: Vec<SyncConflict>,
        changes: Vec<MergeChange>,
        attempts: u32,
        etag: String,
        has_clock_offset: bool,
        clock_offset_ms: i64,
        clock_skewed: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SignedOutReason {
        TokenReused,
        SessionExpired,
        Unauthorized,
        Logout,
        DeletionScheduled,
        AccountDeleted,
    }

    /// Which `AccountEvent` variant; `Closed` means the stream ended (Rust `None`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AccountEventKind {
        Closed,
        VaultChanged,
        VaultsChanged,
        SessionEnded,
        DatabaseChanged,
    }

    /// Rust `Option<AccountEvent>`, flattened. `id` is the vault or database id.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AccountEvent {
        kind: AccountEventKind,
        id: String,
        etag: String,
        has_revision: bool,
        revision: u64,
        deleted: bool,
        vaults: Vec<VaultInfo>,
        reason: SignedOutReason,
        at: String,
    }

    // ------------------------------------------------------------------ optional results
    //
    // cxx can't return `Option<T>`; these carry a `has` flag instead. `Option<String>` results are
    // an empty string.

    /// An optional byte string (a secret when the call says so: wipe it with ov::wipe).
    #[derive(Clone, Default)]
    struct OptionalBytes {
        has: bool,
        value: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct OptionalU64 {
        has: bool,
        value: u64,
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct OptionalI64 {
        has: bool,
        value: i64,
    }

    /// An optional OvError (`TotpChallenge::last_error`).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct OptionalError {
        has: bool,
        error: ErrorInfo,
    }

    /// One byte string in a list (cxx has no `Vec<Vec<u8>>`).
    #[derive(Clone, Default)]
    struct Bytes {
        value: Vec<u8>,
    }

    // ------------------------------------------------------------------ crypto, sessions

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct KdfParams {
        alg: String,
        salt: String,
        m: u32,
        t: u32,
        p: u32,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct OptionalKdfParams {
        has: bool,
        value: KdfParams,
    }

    /// Rust `KdfOverrides`; all `has_*` false means the defaults (Rust `None`).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct KdfOverrides {
        has_m: bool,
        m: u32,
        has_t: bool,
        t: u32,
        has_p: bool,
        p: u32,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct PublicKeys {
        enc_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        sig: Vec<u8>,
        fingerprint: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct StoredSession {
        issuer: String,
        user_id: String,
        email: String,
        device_id: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct OptionalStoredSession {
        has: bool,
        value: StoredSession,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ParkedCheck {
        Valid,
        Ended,
        NoAnswer,
    }

    /// Rust `RegisterInput`. The password moves into the core, which wipes it.
    struct RegisterInput {
        email: String,
        password: Vec<u8>,
        kdf: KdfOverrides,
        trust_device: bool,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct EmergencyKit {
        email: String,
        issuer: String,
        web: String,
    }

    /// Rust `NewAccount` (also the result of `recover`). Wipe `secret_key` and `auk` when done.
    struct NewAccount {
        user_id: String,
        secret_key: Vec<u8>,
        emergency_kit: EmergencyKit,
        auk: Vec<u8>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReconnectResult {
        vaults: Vec<VaultInfo>,
        dropped: Vec<String>,
    }

    /// Rust `Option<Vec<VaultInfo>>` (`Account::cached_vaults`).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct OptionalVaultList {
        has: bool,
        vaults: Vec<VaultInfo>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct OptionalVaultInfo {
        has: bool,
        value: VaultInfo,
    }

    /// Rust `Option<HttpRequest>` (`Account::sign_out_on_unload`).
    #[derive(Clone)]
    struct OptionalHttpRequest {
        has: bool,
        value: HttpRequest,
    }

    // ---------------------------------------------------------------- settings (§16, §8)

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct PlanLimit {
        name: String,
        has_value: bool,
        /// `-1` or no value means unlimited, as in Rust.
        value: i64,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Billing {
        source: String,
        interval: String,
        status: String,
        renews_at: String,
        ends_at: String,
        manage: String,
    }

    /// Rust `Plan`. Its helpers are the free functions `plan_limit`, `plan_has`, `plan_has_billing`.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Plan {
        /// Empty on a server without billing.
        id: String,
        limits: Vec<PlanLimit>,
        has_billing: bool,
        billing: Billing,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct OptionalPlan {
        has: bool,
        value: Plan,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum OrgRole {
        Owner,
        Admin,
        Member,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum MemberStatus {
        Invited,
        Accepted,
        Confirmed,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ShareLinkPolicy {
        On,
        Managers,
        Off,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct OrgMembership {
        id: String,
        name: String,
        role: OrgRole,
        status: MemberStatus,
        has_plan: bool,
        plan: Plan,
        has_item_share_links: bool,
        item_share_links: ShareLinkPolicy,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Profile {
        id: String,
        email: String,
        name: String,
        totp_enabled: bool,
        has_plan: bool,
        plan: Plan,
        orgs: Vec<OrgMembership>,
        deletion_scheduled_for: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Device {
        id: String,
        name: String,
        platform: String,
        created_at: String,
        last_seen_at: String,
        current: bool,
    }

    /// Rust `TotpSetup`. Wipe both when done.
    #[derive(Clone)]
    struct TotpSetup {
        secret: Vec<u8>,
        uri: Vec<u8>,
    }

    // ----------------------------------------------------------- recovery (§18), deletion (§23)

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct RecoveryReset {
        email: String,
        not_before: String,
        expires_at: String,
        archive_days: u32,
        personal_vaults: u32,
        shared_grants: u32,
        sole_admin_orgs: Vec<String>,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct RecoveryStatus {
        archived: bool,
        email: String,
        expires_at: String,
        has_vaults: bool,
        vaults: u32,
        locked: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DeletionShare {
        principal: String,
        display: String,
        role: VaultRole,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DeletionVault {
        id: String,
        name: String,
        shared_with: Vec<DeletionShare>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DeletionOutcome {
        Leave,
        Delete,
        Blocked,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DeletionCandidate {
        id: String,
        email: String,
        role: OrgRole,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DeletionOrg {
        id: String,
        name: String,
        role: OrgRole,
        outcome: DeletionOutcome,
        members: Vec<DeletionCandidate>,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct DeletionSubscription {
        plan: String,
        period_end: String,
        source: String,
        manage: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DeletionPreview {
        scheduled_for: String,
        erase_on: String,
        vaults: Vec<DeletionVault>,
        orgs: Vec<DeletionOrg>,
        has_subscription: bool,
        subscription: DeletionSubscription,
        share_links: u32,
        blocked: bool,
    }

    // -------------------------------------------------------------------------- plans (§19)

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct AppleEligibility {
        eligible: bool,
        reason: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct AppleTransactionResult {
        subject: String,
        plan: Plan,
    }

    // ------------------------------------------------------------------ vaults, history

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct VaultVersion {
        revision: u64,
        etag: String,
        has_size: bool,
        size: u64,
        saved_at: String,
        is_current: bool,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct BlobMeta {
        id: String,
        etag: String,
        revision: u64,
        size: u64,
        updated_at: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ImportModeKind {
        NewVault,
        Merge,
        Copies,
    }

    /// Rust `ImportMode`: `NewVault` uses `name` and `org_id` (empty = none); `Merge` and `Copies`
    /// use `vault_id`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ImportMode {
        kind: ImportModeKind,
        name: String,
        org_id: String,
        vault_id: String,
    }

    /// Rust `ImportOutcome`.
    struct ImportOutcome {
        vault: Box<Vault>,
        uploaded: bool,
        has_upload_error: bool,
        upload_error: ErrorInfo,
        has_report: bool,
        report: SyncReport,
    }

    /// One string field of an entry. Wipe `value` when done.
    #[derive(Clone)]
    struct FieldRecord {
        name: String,
        value: Vec<u8>,
        /// Rust `protected` (a C++ keyword).
        is_protected: bool,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct AttachmentInfo {
        name: String,
        size: u64,
        /// contract-v1.6; Rust `protected` (a C++ keyword).
        is_protected: bool,
    }

    /// Rust `EntryRecord`.
    #[derive(Clone)]
    struct EntryRecord {
        id: String,
        group_id: String,
        group_path: Vec<String>,
        fields: Vec<FieldRecord>,
        tags: Vec<String>,
        icon_id: u32,
        custom_icon: String,
        foreground_color: String,
        background_color: String,
        override_url: String,
        created_at: i64,
        modified_at: i64,
        has_expires_at: bool,
        expires_at: i64,
        attachments: Vec<AttachmentInfo>,
        history_count: u32,
        quality_check: bool,
        /// contract-v1.6: `LastAccessTime` when `usage_count > 0`.
        has_last_access_at: bool,
        last_access_at: i64,
        usage_count: u32,
    }

    #[derive(Clone)]
    struct AutoFillEdit {
        entry: EntryRecord,
        group_path: String,
    }

    #[derive(Clone, Default)]
    struct AutoFillEdits {
        vault_id: String,
        entries: Vec<AutoFillEdit>,
        version: String,
    }

    #[derive(Clone, Default)]
    struct OptionalAutoFillEdits {
        has: bool,
        value: AutoFillEdits,
    }

    /// Rust `FieldInput`. `has_protected == false` uses the default for the field.
    struct FieldInput {
        name: String,
        value: Vec<u8>,
        has_protected: bool,
        is_protected: bool,
    }

    /// `Keep`, `Never` or `At` (for `EntryExpiry` and `ExpiryChange`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ExpiryKind {
        Keep,
        Never,
        At,
    }

    /// Rust `EntryExpiry`; `at` (Unix seconds) is read for `At`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct EntryExpiry {
        kind: ExpiryKind,
        at: i64,
    }

    /// What [`EntryInput`] does to the custom icon (contract-v1.6).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CustomIconChange {
        Keep,
        Clear,
        /// Set to `EntryInput::custom_icon`.
        Set,
    }

    /// Rust `EntryInput`. The fields after `expiry` are contract-v1.6; left value-initialized they
    /// change nothing.
    struct EntryInput {
        fields: Vec<FieldInput>,
        remove_fields: Vec<String>,
        has_tags: bool,
        tags: Vec<String>,
        has_icon_id: bool,
        icon_id: u32,
        expiry: EntryExpiry,
        /// `#RRGGBB`, or empty to clear.
        has_foreground_color: bool,
        foreground_color: String,
        has_background_color: bool,
        background_color: String,
        custom_icon_change: CustomIconChange,
        custom_icon: String,
        /// Custom fields in this order after the standard ones.
        has_field_order: bool,
        field_order: Vec<String>,
    }

    /// Rust `LocalImportMode` kind (contract-v1.6).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LocalImportKind {
        Merge,
        Copies,
    }

    /// Rust `LocalImportMode`: `Copies` goes under `parent_group_id` (empty = the root).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LocalImportMode {
        kind: LocalImportKind,
        parent_group_id: String,
    }

    /// Rust `ImportSummary` (contract-v1.6).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ImportSummary {
        added: u32,
        updated: u32,
        unchanged: u32,
        groups_added: u32,
        changes: Vec<MergeChange>,
    }

    /// Rust `ImportPreview` (contract-v1.6).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct ImportPreview {
        entries: u32,
        groups: u32,
    }

    /// Rust `ImportTarget` (contract-v1.6).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ImportTarget {
        group_id: String,
        path: String,
    }

    /// Rust `KdbxKdf` variant (contract-v1.6).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum KdbxKdfKind {
        /// Argon2d, 64 MiB, 10 iterations, 2 lanes.
        DatabaseDefault,
        Argon2d,
        Argon2id,
        AesKdf,
    }

    /// Rust `KdbxKdf`: Argon2 reads `memory` (bytes), `iterations`, `parallelism`; AES-KDF reads
    /// `rounds`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct KdbxKdf {
        kind: KdbxKdfKind,
        memory: u64,
        iterations: u64,
        parallelism: u32,
        rounds: u64,
    }

    /// What [`TestStream::poll_chunk`] found (feature `test-server`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestStreamPollKind {
        Data,
        /// Nothing yet: poll again later.
        Pending,
        /// The stream ended.
        End,
    }

    /// One poll of a test event stream.
    struct TestStreamPoll {
        kind: TestStreamPollKind,
        data: Vec<u8>,
    }

    /// An optional string (contract-v1.6 `Vault::meta_custom_data`).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct OptionalString {
        has: bool,
        value: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CreateMode {
        MustExist,
        CreateIfMissing,
        CreateOnly,
    }

    #[derive(Clone)]
    struct SetFieldsResult {
        entry: EntryRecord,
        created: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum VersionDifference {
        Same,
        Changed,
        Deleted,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ExportFormat {
        Csv,
        Json,
    }

    // ------------------------------------------------------------- sharing, orgs (§7, §12)

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct VaultMember {
        principal: String,
        role: VaultRole,
        display: String,
        key_version: u32,
        is_you: bool,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ShareRecipient {
        principal: String,
        email: String,
        name: String,
        public_keys: PublicKeys,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum GranteeKind {
        Email,
        Principal,
    }

    /// Rust `Grantee`: an email or a principal (`user:<id>`, `sa:<id>`) in `value`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Grantee {
        kind: GranteeKind,
        value: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct GrantResult {
        principal: String,
        fingerprint: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct VaultGrantRequest {
        vault_id: String,
        role: VaultRole,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Org {
        id: String,
        name: String,
        role: OrgRole,
        has_plan: bool,
        plan: Plan,
        has_item_share_links: bool,
        item_share_links: ShareLinkPolicy,
        created_at: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Member {
        user_id: String,
        email: String,
        name: String,
        role: OrgRole,
        status: MemberStatus,
        has_public_keys: bool,
        public_keys: PublicKeys,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Invitation {
        id: String,
        email: String,
        role: OrgRole,
        expires_at: String,
        invited_by: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RotationFailure {
        vault_id: String,
        error: ErrorInfo,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct RotationReport {
        rotated: Vec<String>,
        failed: Vec<RotationFailure>,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct AuditEvent {
        id: String,
        at: String,
        actor: String,
        action: String,
        target: String,
        ip: String,
        /// A JSON object string, or empty.
        details: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct AuditPage {
        events: Vec<AuditEvent>,
        /// The cursor for the next page, or empty.
        next: String,
    }

    // --------------------------------------------------------- service accounts (§9, §15)

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ServiceAccountInfo {
        id: String,
        org_id: String,
        name: String,
        has_public_keys: bool,
        public_keys: PublicKeys,
        created_by: String,
        created_at: String,
        expires_at: String,
        disabled: bool,
    }

    /// Rust `NewServiceAccount`; empty strings are `None`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct NewServiceAccount {
        name: String,
        vaults: Vec<VaultGrantRequest>,
        expires_at: String,
        secret_name: String,
    }

    /// Rust `CreatedServiceAccount`. Show `token` once, then wipe it.
    struct CreatedServiceAccount {
        service_account: ServiceAccountInfo,
        token: Vec<u8>,
    }

    /// Rust `IssuedSecret`. Show `token` once, then wipe it.
    struct IssuedSecret {
        token: Vec<u8>,
        id: String,
        prefix: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct SaSecretInfo {
        id: String,
        prefix: String,
        name: String,
        created_at: String,
        last_used_at: String,
        expires_at: String,
    }

    /// Rust `ExpiryChange`; `at` (RFC 3339) is read for `At`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ExpiryChange {
        kind: ExpiryKind,
        at: String,
    }

    /// Rust `ServiceAccountUpdate`; an empty `name` keeps it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ServiceAccountUpdate {
        name: String,
        expires_at: ExpiryChange,
        has_disabled: bool,
        disabled: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SaVault {
        id: String,
        name: String,
        role: VaultRole,
    }

    /// Rust `Injected`. Wipe `text` and every secret when done.
    struct Injected {
        text: Vec<u8>,
        secrets: Vec<Bytes>,
    }

    // ------------------------------------------------------------------ self-hosted (§13)

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct PairingCode {
        code: String,
        expires_at: String,
    }

    /// Rust `SelfHostedSyncResult`: save `kdbx` as the local file.
    struct SelfHostedSyncResult {
        kdbx: Vec<u8>,
        report: SyncReport,
    }

    /// Rust `SyncOptions` (contract-v1.6 `accept_server_state`: "continue anyway").
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SyncOptions {
        local_changed: bool,
        accept_server_state: bool,
    }

    /// Rust `VaultKdbxSyncResult` (contract-v1.6): keep `kdbx` as the local copy, under
    /// `credentials` (the vault key as a raw key file; wipe it).
    struct VaultKdbxSyncResult {
        kdbx: Vec<u8>,
        credentials: KdbxCredentials,
        report: SyncReport,
    }

    // ------------------------------------------------------------------ share links (§22)

    /// Rust `ShareOptions`; empty `vault_id` / `entry_id` are `None` (text shares).
    struct ShareOptions {
        expires_in: u32,
        has_max_opens: bool,
        max_opens: u32,
        has_passcode: bool,
        passcode: Vec<u8>,
        vault_id: String,
        entry_id: String,
    }

    /// Rust `CreatedShare`. `url` holds the key in its fragment: treat it as a secret.
    struct CreatedShare {
        id: String,
        url: Vec<u8>,
        expires_at: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ShareRef {
        vault: String,
        entry: String,
        title: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ShareListing {
        id: String,
        vault_id: String,
        has_reference: bool,
        reference: ShareRef,
        passcode: bool,
        has_max_opens: bool,
        max_opens: u32,
        opens: u32,
        opened_at: Vec<String>,
        created_at: String,
        expires_at: String,
        status: String,
        ended_at: String,
        end_reason: String,
    }

    #[derive(Clone)]
    struct ShareField {
        k: String,
        label: String,
        value: Vec<u8>,
        is_protected: bool,
    }

    /// Rust `SharePayload`; empty `title` / `shared_by` are `None`.
    #[derive(Clone)]
    struct SharePayload {
        v: u32,
        kind: String,
        title: String,
        shared_by: String,
        fields: Vec<ShareField>,
    }

    #[derive(Clone)]
    struct ShareableField {
        name: String,
        kind: String,
        label: String,
        value: Vec<u8>,
        is_protected: bool,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ShareInfo {
        expires_at: String,
        has_opens_left: bool,
        opens_left: u32,
        has_kdf: bool,
        kdf: KdfParams,
    }

    /// The link and optional parts of `OvClient::open_share`. `passcode` is read when `has_passcode`,
    /// `info` (from `share_info`, saves a request) when `has_info`. Both secrets move into the core.
    struct OpenShareInput {
        link: Vec<u8>,
        has_passcode: bool,
        passcode: Vec<u8>,
        has_info: bool,
        info: ShareInfo,
    }

    #[derive(Clone)]
    struct OpenedShare {
        payload: SharePayload,
        has_opens_left: bool,
        opens_left: u32,
    }

    // ------------------------------------------------------------------------------ TOTP

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TotpAlgorithm {
        Sha1,
        Sha256,
        Sha512,
    }

    /// Rust `TotpParams`; an empty `encoder` is `None`. Wipe `secret` when done.
    #[derive(Clone)]
    struct TotpParams {
        secret: Vec<u8>,
        digits: u32,
        period: u32,
        algorithm: TotpAlgorithm,
        encoder: String,
    }

    /// Rust `TotpCode`. Wipe `code` when done.
    #[derive(Clone)]
    struct TotpCode {
        code: Vec<u8>,
        remaining: u32,
    }

    // ------------------------------------------------ below the facade (crypto, OPAQUE, merge)
    //
    // The pieces of the core the desktop's account code calls directly (README.md, "Desktop swap").

    /// The two outputs of an OPAQUE client start: what goes to the server, and the state the next
    /// step needs.
    #[derive(Clone, Default)]
    struct OpaqueStart {
        /// The registration request, or KE1.
        message: Vec<u8>,
        /// Secret: wipe it.
        state: Vec<u8>,
    }

    /// A finished OPAQUE login. All three are secret except `auth_u` (sent to the server).
    #[derive(Clone, Default)]
    struct OpaqueLogin {
        auth_u: Vec<u8>,
        session_key: Vec<u8>,
        export_key: Vec<u8>,
    }

    /// The server half of an OPAQUE step (test-server only): the message to the client and the
    /// server's (secret) state.
    #[derive(Clone, Default)]
    struct OpaqueServerStep {
        message: Vec<u8>,
        state: Vec<u8>,
    }

    /// A parsed `ov_sa_…` token (SPEC §15). `secret` and `kek` are secret.
    #[derive(Clone, Default)]
    struct ServiceAccountToken {
        url: String,
        sa_id: String,
        secret: Vec<u8>,
        kek: Vec<u8>,
    }

    /// What a [`KdbxMergeChange`] is about.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ChangeSubject {
        Entry,
        Group,
        Database,
    }

    /// One change `merge_kdbx` made (ov-merge `MergeChange`).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct KdbxMergeChange {
        change: ChangeType,
        subject: ChangeSubject,
        /// 16 bytes (RFC 4122 order), or empty for the database.
        uuid: Vec<u8>,
        /// The entry's title, or empty.
        title: String,
        /// The entry's group name, or the group's own name, or empty.
        group: String,
        details: String,
    }

    /// An entry both copies edited with fields changed differently (the newer value was kept).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct KdbxMergeConflict {
        /// Hyphenated, lowercase.
        uuid: String,
        title: String,
        fields: Vec<String>,
    }

    /// The result of `merge_kdbx`. A copy's bytes are empty unless the merge changed it.
    #[derive(Clone, Default)]
    struct KdbxMergeResult {
        local: Vec<u8>,
        remote: Vec<u8>,
        local_changed: bool,
        remote_changed: bool,
        changes: Vec<KdbxMergeChange>,
        conflicts: Vec<KdbxMergeConflict>,
    }

    // ------------------------------------------------------------------- the Host, in C++

    unsafe extern "C++" {
        include!("ov-ffi-cpp/include/host.h");

        type HttpTransport;
        fn send(self: &HttpTransport, req: &HttpRequest, failure: &mut TransportFailure) -> Result<HttpResponse>;
        fn open_stream(
            self: &HttpTransport,
            req: &HttpRequest,
            failure: &mut TransportFailure,
        ) -> Result<UniquePtr<ByteStream>>;

        type ByteStream;
        fn status(self: &ByteStream) -> Result<u16>;
        fn next_chunk(self: &ByteStream, chunk: &mut Vec<u8>, failure: &mut TransportFailure) -> Result<bool>;
        fn close(self: &ByteStream) -> Result<()>;

        type SecureStore;
        fn get(self: &SecureStore, key: &str, value: &mut Vec<u8>) -> Result<bool>;
        fn set(self: &SecureStore, key: &str, value: &[u8]) -> Result<()>;
        fn remove(self: &SecureStore, key: &str) -> Result<()>;

        type BlobCache;
        fn load(self: &BlobCache, user_id: &str, vault_id: &str, out: &mut CachedVault) -> Result<bool>;
        fn save(self: &BlobCache, user_id: &str, vault_id: &str, v: &CachedVault) -> Result<()>;
        fn remove(self: &BlobCache, user_id: &str, vault_id: &str) -> Result<()>;
        fn list(self: &BlobCache, user_id: &str) -> Result<Vec<String>>;
        fn load_meta(self: &BlobCache, user_id: &str, name: &str, value: &mut Vec<u8>) -> Result<bool>;
        fn save_meta(self: &BlobCache, user_id: &str, name: &str, value: &[u8]) -> Result<()>;
        fn clear_user(self: &BlobCache, user_id: &str) -> Result<()>;

        type Clock;
        fn now_unix_ms(self: &Clock) -> Result<i64>;

        type LogSink;
        fn log(self: &LogSink, level: LogLevel, target: &str, msg: &str) -> Result<()>;
    }

    // ------------------------------------------------------------------ the core, for C++

    extern "Rust" {
        // ---- free functions
        fn version() -> String;
        /// The OvError of the last call that failed on this thread (then cleared).
        fn take_last_error() -> ErrorInfo;

        fn sha256(data: &[u8]) -> Vec<u8>;
        fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>>;
        fn aead_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
        fn aead_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
        fn argon2id(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Vec<u8>>;
        fn random_bytes(n: usize) -> Result<Vec<u8>>;

        // ---- cancellation
        type CancelToken;
        fn new_cancel_token() -> Box<CancelToken>;
        /// Another handle to the same token (keep one on the GUI thread to cancel with).
        fn clone(self: &CancelToken) -> Box<CancelToken>;
        fn cancel(self: &CancelToken);
        fn is_cancelled(self: &CancelToken) -> bool;

        // ---- OvClient
        type Client;
        fn new_client(
            config: &ClientConfig,
            http: UniquePtr<HttpTransport>,
            store: UniquePtr<SecureStore>,
            cache: UniquePtr<BlobCache>,
            clock: UniquePtr<Clock>,
            log: UniquePtr<LogSink>,
        ) -> Result<Box<Client>>;
        fn discover(self: &Client, issuer: &str, cancel: &CancelToken) -> Result<ServerConfig>;
        fn connect(self: &Client, issuer: &str, cancel: &CancelToken) -> Result<Box<Account>>;
        fn remembered_accounts(self: &Client) -> Result<Vec<RememberedAccount>>;
        fn forget_remembered(self: &Client, issuer: &str, user_id: &str) -> Result<()>;
        fn session_state(self: &Client, issuer: &str, user_id: &str) -> Result<SessionState>;
        fn has_pending_edits(self: &Client, user_id: &str) -> Result<bool>;

        // ---- Account
        type Account;
        fn server_config(self: &Account) -> Result<ServerConfig>;
        fn is_offline(self: &Account) -> Result<bool>;
        fn is_signed_in(self: &Account) -> Result<bool>;
        fn is_unlocked(self: &Account) -> Result<bool>;
        /// Empty when signed out.
        fn user_id(self: &Account) -> Result<String>;
        /// Empty when signed out.
        fn email(self: &Account) -> Result<String>;
        fn login(self: &Account, input: LoginInput, cancel: &CancelToken) -> Result<Box<LoginStep>>;
        fn submit_totp(
            self: &Account,
            challenge: &TotpChallenge,
            code: &str,
            cancel: &CancelToken,
        ) -> Result<Box<LoginStep>>;
        /// An empty `secret_key` uses the one this device keeps.
        fn unlock(self: &Account, password: Vec<u8>, secret_key: Vec<u8>, cancel: &CancelToken) -> Result<Unlocked>;
        fn lock(self: &Account) -> Result<()>;
        fn sign_out(self: &Account, forget_device: bool, cancel: &CancelToken) -> Result<()>;
        fn vaults(self: &Account, cancel: &CancelToken) -> Result<Vec<VaultInfo>>;
        fn open_vault(self: &Account, vault_id: &str, cancel: &CancelToken) -> Result<Box<Vault>>;
        fn subscribe(self: &Account, cancel: &CancelToken) -> Result<Box<EventStream>>;

        // ---- LoginStep / TotpChallenge
        type LoginStep;
        fn needs_totp(self: &LoginStep) -> bool;
        /// The challenge, when `needs_totp()`; else `invalid_request`.
        fn challenge(self: &LoginStep) -> Result<Box<TotpChallenge>>;
        /// The result, when signed in; else `invalid_request`. Moves the AUK out (call once).
        fn take_unlocked(self: &mut LoginStep) -> Result<Unlocked>;

        type TotpChallenge;
        fn attempt(self: &TotpChallenge) -> Result<u32>;

        // ---- Vault
        type Vault;
        fn vault_open_local(kdbx: Vec<u8>, credentials: KdbxCredentials, cancel: &CancelToken) -> Result<Box<Vault>>;
        fn vault_create_local(name: &str, credentials: KdbxCredentials, cancel: &CancelToken) -> Result<Box<Vault>>;
        fn save_local(self: &Vault, cancel: &CancelToken) -> Result<Vec<u8>>;
        fn id(self: &Vault) -> Result<String>;
        fn name(self: &Vault) -> Result<String>;
        /// Empty when none.
        fn etag(self: &Vault) -> Result<String>;
        fn is_offline(self: &Vault) -> Result<bool>;
        fn is_read_only(self: &Vault) -> Result<bool>;
        fn entries(self: &Vault, include_recycle_bin: bool) -> Result<Vec<EntrySummary>>;
        fn groups(self: &Vault) -> Result<Vec<GroupInfo>>;
        fn read_field(self: &Vault, reference: &str) -> Result<Vec<u8>>;
        fn write_field(
            self: &Vault,
            reference: &str,
            value: Vec<u8>,
            create: bool,
            cancel: &CancelToken,
        ) -> Result<SyncReport>;
        fn sync(self: &Vault, local_changed: bool, cancel: &CancelToken) -> Result<SyncReport>;
        /// An empty `group_ids` exports every group.
        fn export_kdbx(
            self: &Vault,
            credentials: KdbxCredentials,
            group_ids: Vec<String>,
            cancel: &CancelToken,
        ) -> Result<Vec<u8>>;

        // ---- EventStream
        type EventStream;
        fn next(self: &EventStream, cancel: &CancelToken) -> Result<AccountEvent>;
        fn reconnect(self: &EventStream) -> Result<()>;
        fn close(self: &EventStream) -> Result<()>;

        // ---- facade free functions and record helpers
        /// `Platform::as_str`: the wire name, e.g. `qt-macos`.
        fn platform_as_str(platform: Platform) -> Result<String>;
        /// `Plan::limit`: the limit's value; `has == false` when absent or unlimited.
        fn plan_limit(plan: &Plan, name: &str) -> Result<OptionalI64>;
        /// `Plan::has`.
        fn plan_has(plan: &Plan, name: &str) -> Result<bool>;
        /// `Plan::has_billing`.
        fn plan_has_billing(plan: &Plan) -> Result<bool>;
        /// An empty `scheduled_for` is none.
        fn deletion_expired(scheduled_for: &str, now_ms: i64) -> Result<bool>;
        fn default_share_fields() -> Result<Vec<String>>;
        fn shareable_fields(entry: &EntryRecord) -> Result<Vec<ShareableField>>;
        fn item_share_payload(entry: &EntryRecord, names: Vec<String>, shared_by: &str) -> Result<SharePayload>;
        fn text_share_payload(text: Vec<u8>, title: &str, shared_by: &str) -> Result<SharePayload>;
        fn parse_totp_uri(uri: Vec<u8>) -> Result<TotpParams>;
        fn totp_code(params: TotpParams, now_ms: i64) -> Result<TotpCode>;
        fn entry_totp_uri(fields: Vec<FieldRecord>, label: &str) -> Result<OptionalBytes>;

        // ---- CancelToken (more)
        /// `aborted` once cancelled.
        fn check(self: &CancelToken) -> Result<()>;

        // ---- OvClient (more)
        fn config(self: &Client) -> Result<ClientConfig>;
        fn remember_account(self: &Client, email: &str, issuer: &str, user_id: &str) -> Result<()>;
        /// An empty `at` clears it.
        fn set_remembered_deletion(self: &Client, issuer: &str, user_id: &str, at: &str) -> Result<()>;
        fn mark_remembered_checked(self: &Client, issuer: &str, user_id: &str) -> Result<()>;
        fn share_info(self: &Client, api: &str, share_id: &str, cancel: &CancelToken) -> Result<ShareInfo>;
        fn open_share(self: &Client, api: &str, input: OpenShareInput, cancel: &CancelToken) -> Result<OpenedShare>;

        // ---- TotpChallenge (more)
        fn last_error(self: &TotpChallenge) -> Result<OptionalError>;

        // ---- Account: state and sessions
        /// Empty when not pending deletion.
        fn deletion_scheduled_for(self: &Account) -> Result<String>;
        fn principal(self: &Account) -> Result<String>;
        fn fingerprint(self: &Account) -> Result<String>;
        fn clock_offset_ms(self: &Account) -> Result<OptionalI64>;
        fn stored_session(self: &Account) -> Result<OptionalStoredSession>;
        fn verify_session(self: &Account, cancel: &CancelToken) -> Result<()>;
        /// Blocks until the server ends this session; loop on it from a worker.
        fn signed_out(self: &Account, cancel: &CancelToken) -> Result<SignedOutReason>;
        fn has_secret_key(self: &Account, email: &str) -> Result<bool>;
        fn stored_secret_key(self: &Account, email: &str) -> Result<OptionalBytes>;
        /// Rust `Account::register` (`register` is a C++ keyword).
        fn register_account(self: &Account, input: RegisterInput, cancel: &CancelToken) -> Result<NewAccount>;
        fn unlock_with_auk(self: &Account, auk: Vec<u8>, cancel: &CancelToken) -> Result<()>;
        fn unlocked_keyset_secret(self: &Account) -> Result<Vec<u8>>;
        fn resume_unlocked(self: &Account, keyset_secret: Vec<u8>, cancel: &CancelToken) -> Result<()>;
        fn sign_out_on_unload(self: &Account) -> Result<OptionalHttpRequest>;
        fn forget_device(self: &Account, email: &str) -> Result<()>;
        fn reconnect(self: &Account, cancel: &CancelToken) -> Result<ReconnectResult>;
        fn cached_kdf(self: &Account) -> Result<OptionalKdfParams>;
        fn park_session(self: &Account) -> Result<bool>;
        fn resume_session(self: &Account, user_id: &str) -> Result<bool>;
        fn check_parked_session(self: &Account, user_id: &str, cancel: &CancelToken) -> Result<ParkedCheck>;
        fn sign_out_parked(self: &Account, user_id: &str, cancel: &CancelToken) -> Result<()>;

        // ---- Account: vaults, history, AutoFill
        fn cached_vaults(self: &Account) -> Result<OptionalVaultList>;
        fn open_offline(self: &Account, vault_id: &str) -> Result<Box<Vault>>;
        fn open_copy(self: &Account, vault_id: &str) -> Result<Box<Vault>>;
        /// An empty `org_id` makes a personal vault.
        fn create_vault(self: &Account, name: &str, org_id: &str, cancel: &CancelToken) -> Result<Box<Vault>>;
        fn import_kdbx(
            self: &Account,
            kdbx: Vec<u8>,
            credentials: KdbxCredentials,
            mode: &ImportMode,
            cancel: &CancelToken,
        ) -> Result<ImportOutcome>;
        fn import_vault(
            self: &Account,
            source: &Vault,
            mode: &ImportMode,
            cancel: &CancelToken,
        ) -> Result<ImportOutcome>;
        fn rename_vault(self: &Account, vault_id: &str, name: &str, cancel: &CancelToken) -> Result<VaultInfo>;
        fn delete_vault(self: &Account, vault_id: &str, cancel: &CancelToken) -> Result<()>;
        fn has_any_pending_edits(self: &Account) -> Result<bool>;
        fn has_pending_edits(self: &Account, vault_id: &str) -> Result<bool>;
        fn vault_history(self: &Account, vault_id: &str, cancel: &CancelToken) -> Result<Vec<VaultVersion>>;
        fn open_vault_version(
            self: &Account,
            vault_id: &str,
            revision: u64,
            cancel: &CancelToken,
        ) -> Result<Box<Vault>>;
        fn keep_autofill_edit(self: &Account, vault_id: &str, entry: &EntryRecord, group_path: &str) -> Result<()>;
        fn autofill_edits(self: &Account, vault_id: &str) -> Result<OptionalAutoFillEdits>;
        fn clear_autofill_edits(self: &Account, edits: &AutoFillEdits) -> Result<()>;

        // ---- Account: settings, two-step, devices (§16, §8)
        fn me(self: &Account, cancel: &CancelToken) -> Result<Profile>;
        /// Returns the new AUK (wipe it).
        fn change_password(
            self: &Account,
            current: Vec<u8>,
            next: Vec<u8>,
            kdf: KdfOverrides,
            cancel: &CancelToken,
        ) -> Result<Vec<u8>>;
        fn request_email_change(self: &Account, email: &str, cancel: &CancelToken) -> Result<()>;
        fn change_email(self: &Account, email: &str, code: &str, password: Vec<u8>, cancel: &CancelToken)
            -> Result<()>;
        fn secret_key(self: &Account) -> Result<OptionalBytes>;
        /// An empty `next` opens the site's home. The link is a secret (wipe it).
        fn web_session_url(self: &Account, next: &str, cancel: &CancelToken) -> Result<Vec<u8>>;
        fn start_two_step(self: &Account, cancel: &CancelToken) -> Result<TotpSetup>;
        fn confirm_two_step(self: &Account, code: &str, cancel: &CancelToken) -> Result<()>;
        fn disable_two_step(self: &Account, code: &str, cancel: &CancelToken) -> Result<()>;
        fn devices(self: &Account, cancel: &CancelToken) -> Result<Vec<Device>>;
        fn revoke_device(self: &Account, device_id: &str, cancel: &CancelToken) -> Result<()>;

        // ---- Account: recovery (§18), deletion (§23)
        fn recover_info(self: &Account, token: Vec<u8>, cancel: &CancelToken) -> Result<RecoveryReset>;
        fn recover(
            self: &Account,
            token: Vec<u8>,
            password: Vec<u8>,
            kdf: KdfOverrides,
            trust_device: bool,
            cancel: &CancelToken,
        ) -> Result<NewAccount>;
        fn recovery_status(self: &Account, cancel: &CancelToken) -> Result<RecoveryStatus>;
        fn restore_from_archive(
            self: &Account,
            old_password: Vec<u8>,
            old_secret_key: Vec<u8>,
            cancel: &CancelToken,
        ) -> Result<u32>;
        fn deletion_preview(self: &Account, cancel: &CancelToken) -> Result<DeletionPreview>;
        /// Returns the erase date.
        fn delete_account(self: &Account, password: Vec<u8>, confirm: &str, cancel: &CancelToken) -> Result<String>;
        fn restore_account(self: &Account, password: Vec<u8>, cancel: &CancelToken) -> Result<()>;
        fn transfer_vault(self: &Account, vault_id: &str, to: &str, cancel: &CancelToken) -> Result<()>;

        // ---- Account: plans (§19)
        fn plan(self: &Account, cancel: &CancelToken) -> Result<OptionalPlan>;
        fn vault_quota(self: &Account, vault_id: &str) -> Result<OptionalU64>;
        /// Empty when there is nowhere to go.
        fn upgrade_url(self: &Account, error: &ErrorInfo) -> Result<String>;
        /// An empty `org_id` asks for this user.
        fn apple_eligibility(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<AppleEligibility>;
        fn report_apple_transaction(self: &Account, jws: &str, cancel: &CancelToken) -> Result<AppleTransactionResult>;

        // ---- Account: vault sharing (§7)
        fn members(self: &Account, vault_id: &str, cancel: &CancelToken) -> Result<Vec<VaultMember>>;
        fn verified_public_keys(self: &Account, principal: &str, cancel: &CancelToken) -> Result<PublicKeys>;
        fn look_up(self: &Account, email: &str, cancel: &CancelToken) -> Result<ShareRecipient>;
        /// An empty `display` is none.
        fn recipient(self: &Account, principal: &str, display: &str, cancel: &CancelToken) -> Result<ShareRecipient>;
        fn share_vault(
            self: &Account,
            vault_id: &str,
            grantee: &Grantee,
            role: VaultRole,
            cancel: &CancelToken,
        ) -> Result<GrantResult>;
        fn change_role(
            self: &Account,
            vault_id: &str,
            principal: &str,
            role: VaultRole,
            cancel: &CancelToken,
        ) -> Result<()>;
        fn revoke(self: &Account, vault_id: &str, principals: Vec<String>, cancel: &CancelToken) -> Result<SyncReport>;
        fn rotate_vault_key(
            self: &Account,
            vault_id: &str,
            remove: Vec<String>,
            cancel: &CancelToken,
        ) -> Result<SyncReport>;

        // ---- Account: orgs (§12)
        fn orgs(self: &Account, cancel: &CancelToken) -> Result<Vec<OrgMembership>>;
        fn create_org(self: &Account, name: &str, cancel: &CancelToken) -> Result<Org>;
        fn org(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<Org>;
        fn rename_org(self: &Account, org_id: &str, name: &str, cancel: &CancelToken) -> Result<Org>;
        fn set_org_share_links(
            self: &Account,
            org_id: &str,
            policy: ShareLinkPolicy,
            cancel: &CancelToken,
        ) -> Result<Org>;
        fn delete_org(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<()>;
        fn org_members(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<Vec<Member>>;
        fn invitations(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<Vec<Invitation>>;
        fn invite(self: &Account, org_id: &str, email: &str, role: OrgRole, cancel: &CancelToken)
            -> Result<Invitation>;
        fn cancel_invitation(self: &Account, org_id: &str, invitation_id: &str, cancel: &CancelToken) -> Result<()>;
        fn accept_invitation(self: &Account, token: Vec<u8>, cancel: &CancelToken) -> Result<Member>;
        fn confirm_member(
            self: &Account,
            org_id: &str,
            member: &Member,
            vaults: Vec<VaultGrantRequest>,
            cancel: &CancelToken,
        ) -> Result<Member>;
        fn set_member_role(
            self: &Account,
            org_id: &str,
            member: &Member,
            role: OrgRole,
            cancel: &CancelToken,
        ) -> Result<Member>;
        fn remove_member(self: &Account, org_id: &str, user_id: &str, cancel: &CancelToken) -> Result<RotationReport>;
        fn rotate_flagged(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<RotationReport>;
        fn managed_org_vaults(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<Vec<VaultInfo>>;
        /// An empty `before` starts at the newest; `limit` is read when `has_limit`.
        fn audit_log(
            self: &Account,
            org_id: &str,
            before: &str,
            has_limit: bool,
            limit: u32,
            cancel: &CancelToken,
        ) -> Result<AuditPage>;

        // ---- Account: service-account admin (§9)
        fn service_accounts(self: &Account, org_id: &str, cancel: &CancelToken) -> Result<Vec<ServiceAccountInfo>>;
        fn create_service_account(
            self: &Account,
            org_id: &str,
            input: &NewServiceAccount,
            cancel: &CancelToken,
        ) -> Result<CreatedServiceAccount>;
        /// Empty `name` / `expires_at` are none.
        fn issue_service_account_secret(
            self: &Account,
            sa_id: &str,
            name: &str,
            expires_at: &str,
            cancel: &CancelToken,
        ) -> Result<IssuedSecret>;
        fn service_account_secrets(self: &Account, sa_id: &str, cancel: &CancelToken) -> Result<Vec<SaSecretInfo>>;
        fn set_secret_expiry(
            self: &Account,
            sa_id: &str,
            secret_id: &str,
            expires_at: &ExpiryChange,
            cancel: &CancelToken,
        ) -> Result<SaSecretInfo>;
        fn revoke_secret(self: &Account, sa_id: &str, secret_id: &str, cancel: &CancelToken) -> Result<()>;
        fn update_service_account(
            self: &Account,
            sa_id: &str,
            update: &ServiceAccountUpdate,
            cancel: &CancelToken,
        ) -> Result<ServiceAccountInfo>;
        fn delete_service_account(self: &Account, sa_id: &str, cancel: &CancelToken) -> Result<()>;

        // ---- Account: share links (§22)
        /// Empty when unknown.
        fn share_base(self: &Account) -> Result<String>;
        /// Empty when allowed; an empty `org_id` is a personal vault.
        fn share_blocked_reason(self: &Account, org_id: &str) -> Result<String>;
        fn create_share(
            self: &Account,
            payload: SharePayload,
            options: ShareOptions,
            cancel: &CancelToken,
        ) -> Result<CreatedShare>;
        fn list_shares(self: &Account, cancel: &CancelToken) -> Result<Vec<ShareListing>>;
        fn revoke_share(self: &Account, share_id: &str, cancel: &CancelToken) -> Result<()>;

        // ---- Vault (more)
        fn info(self: &Vault) -> Result<OptionalVaultInfo>;
        fn conflicts(self: &Vault) -> Result<Vec<SyncConflict>>;
        fn root_group_id(self: &Vault) -> Result<String>;
        fn entry(self: &Vault, entry_id: &str) -> Result<EntryRecord>;
        fn find(self: &Vault, reference: &str) -> Result<EntryRecord>;
        fn history(self: &Vault, entry_id: &str) -> Result<Vec<EntryRecord>>;
        fn attachment(self: &Vault, entry_id: &str, name: &str) -> Result<Vec<u8>>;
        fn custom_icon(self: &Vault, icon_id: &str) -> Result<Vec<u8>>;
        /// Empty when there is no such group.
        fn group_id_at(self: &Vault, path: &str) -> Result<String>;
        fn is_in_recycle_bin(self: &Vault, id: &str) -> Result<bool>;
        fn set_fields(
            self: &Vault,
            reference: &str,
            fields: Vec<FieldInput>,
            create: CreateMode,
        ) -> Result<SetFieldsResult>;
        fn add_entry(self: &Vault, group_id: &str, input: EntryInput) -> Result<String>;
        fn edit_entry(self: &Vault, entry_id: &str, input: EntryInput) -> Result<()>;
        fn move_entry(self: &Vault, entry_id: &str, group_id: &str) -> Result<()>;
        fn delete_entry(self: &Vault, entry_id: &str) -> Result<()>;
        fn restore_from_recycle_bin(self: &Vault, id: &str) -> Result<()>;
        fn empty_recycle_bin(self: &Vault) -> Result<()>;
        fn set_attachment(self: &Vault, entry_id: &str, name: &str, data: Vec<u8>) -> Result<()>;
        fn remove_attachment(self: &Vault, entry_id: &str, name: &str) -> Result<()>;
        fn add_custom_icon(self: &Vault, png: Vec<u8>) -> Result<String>;
        /// An empty `parent_id` is the root.
        fn add_group(self: &Vault, parent_id: &str, name: &str) -> Result<String>;
        fn ensure_group(self: &Vault, path: &str) -> Result<String>;
        fn rename_group(self: &Vault, group_id: &str, name: &str) -> Result<()>;
        fn set_group_icon(self: &Vault, group_id: &str, icon_id: u32) -> Result<()>;
        fn move_group(self: &Vault, group_id: &str, parent_id: &str) -> Result<()>;
        fn delete_group(self: &Vault, group_id: &str) -> Result<()>;
        fn version_difference(self: &Vault, version: &Vault, entry_id: &str) -> Result<VersionDifference>;
        fn restore_entry(self: &Vault, version: &Vault, entry_id: &str, group_path: &str) -> Result<()>;
        fn apply_autofill_edits(self: &Vault, edits: &AutoFillEdits) -> Result<bool>;
        fn keep_edits(self: &Vault) -> Result<()>;
        fn has_pending_edits(self: &Vault) -> Result<bool>;
        /// An empty `group_ids` exports every group. The result is unencrypted: wipe it.
        fn export_plain(self: &Vault, format: ExportFormat, group_ids: Vec<String>) -> Result<Vec<u8>>;

        // ---- ServiceAccount (§9, §15)
        type ServiceAccount;
        fn service_account_from_token(
            client: &Client,
            token: Vec<u8>,
            cancel: &CancelToken,
        ) -> Result<Box<ServiceAccount>>;
        fn sa_id(self: &ServiceAccount) -> Result<String>;
        fn principal(self: &ServiceAccount) -> Result<String>;
        fn vaults(self: &ServiceAccount, refresh: bool, cancel: &CancelToken) -> Result<Vec<SaVault>>;
        fn vault(self: &ServiceAccount, id_or_name: &str, cancel: &CancelToken) -> Result<SaVault>;
        fn open_vault(
            self: &ServiceAccount,
            id_or_name: &str,
            refresh: bool,
            cancel: &CancelToken,
        ) -> Result<Box<Vault>>;
        fn pull(self: &ServiceAccount, id_or_name: &str, cancel: &CancelToken) -> Result<Box<Vault>>;
        fn read(self: &ServiceAccount, reference: &str, cancel: &CancelToken) -> Result<Vec<u8>>;
        fn inject(self: &ServiceAccount, tmpl: Vec<u8>, cancel: &CancelToken) -> Result<Injected>;
        fn write(
            self: &ServiceAccount,
            reference: &str,
            value: Vec<u8>,
            create: bool,
            cancel: &CancelToken,
        ) -> Result<()>;
        fn close(self: &ServiceAccount) -> Result<()>;

        // ---- SelfHosted (§13)
        type SelfHosted;
        fn self_hosted_connect(client: &Client, server_url: &str, device_token: Vec<u8>) -> Result<Box<SelfHosted>>;
        fn self_hosted_pair(
            client: &Client,
            server_url: &str,
            code: &str,
            device_name: &str,
            cancel: &CancelToken,
        ) -> Result<Box<SelfHosted>>;
        /// Rust `Option<SelfHosted>`: check `is_paired()`, then `take()`.
        fn self_hosted_restore(client: &Client, server_url: &str) -> Result<Box<RestoredSelfHosted>>;
        fn server_url(self: &SelfHosted) -> Result<String>;
        fn health(self: &SelfHosted, cancel: &CancelToken) -> Result<String>;
        fn list_databases(self: &SelfHosted, cancel: &CancelToken) -> Result<Vec<BlobMeta>>;
        fn create_pairing_code(self: &SelfHosted, cancel: &CancelToken) -> Result<PairingCode>;
        fn sync_database(
            self: &SelfHosted,
            database_id: &str,
            kdbx: Vec<u8>,
            credentials: KdbxCredentials,
            cancel: &CancelToken,
        ) -> Result<SelfHostedSyncResult>;
        fn events(self: &SelfHosted, cancel: &CancelToken) -> Result<Box<EventStream>>;

        type RestoredSelfHosted;
        fn is_paired(self: &RestoredSelfHosted) -> bool;
        /// The server, when paired (call once); else `invalid_request`.
        fn take(self: &mut RestoredSelfHosted) -> Result<Box<SelfHosted>>;

        // ---- contract-v1.6 (docs/adr/0001-contract.md)
        /// A local `.kdbx` on this client's Host clock.
        fn open_local(
            self: &Client,
            kdbx: Vec<u8>,
            credentials: KdbxCredentials,
            cancel: &CancelToken,
        ) -> Result<Box<Vault>>;
        fn create_local(
            self: &Client,
            name: &str,
            credentials: KdbxCredentials,
            cancel: &CancelToken,
        ) -> Result<Box<Vault>>;
        fn set_name(self: &Vault, name: &str) -> Result<()>;
        fn set_kdf(self: &Vault, kdf: KdbxKdf) -> Result<()>;
        /// Empty `credentials` (no password, no key file) keep a local file's own.
        fn copy_without_remotes(self: &Vault, credentials: KdbxCredentials) -> Result<Box<Vault>>;
        fn meta_custom_data(self: &Vault, key: &str) -> Result<OptionalString>;
        /// `has_value == false` removes the item.
        fn set_meta_custom_data(self: &Vault, key: &str, has_value: bool, value: &str) -> Result<()>;
        fn entry_records(self: &Vault, include_recycle_bin: bool) -> Result<Vec<EntryRecord>>;
        fn add_entry_with_id(self: &Vault, entry_id: &str, group_id: &str, input: EntryInput) -> Result<String>;
        /// `has_protected == false` keeps the replaced attachment's flag (protected for a new one).
        fn set_attachment_with(
            self: &Vault,
            entry_id: &str,
            name: &str,
            data: Vec<u8>,
            has_protected: bool,
            is_protected: bool,
        ) -> Result<()>;
        fn import_from(self: &Vault, source: &Vault, mode: &LocalImportMode) -> Result<ImportSummary>;
        fn import_preview(self: &Vault) -> Result<ImportPreview>;
        fn import_targets(self: &Vault) -> Result<Vec<ImportTarget>>;
        /// An empty `group_ids` exports every group.
        fn export_kdbx_with(
            self: &Vault,
            credentials: KdbxCredentials,
            group_ids: Vec<String>,
            kdf: KdbxKdf,
            cancel: &CancelToken,
        ) -> Result<Vec<u8>>;
        fn history(self: &SelfHosted, database_id: &str, cancel: &CancelToken) -> Result<Vec<VaultVersion>>;
        fn open_version(
            self: &SelfHosted,
            database_id: &str,
            revision: u64,
            credentials: KdbxCredentials,
            cancel: &CancelToken,
        ) -> Result<Box<Vault>>;
        fn server_config(self: &ServiceAccount) -> Result<ServerConfig>;
        fn issuer(self: &ServiceAccount) -> Result<String>;
        /// The newest vault key as `.kdbx` credentials (a raw key file). Wipe them.
        fn vault_kdbx_credentials(self: &Account, vault_id: &str, cancel: &CancelToken) -> Result<KdbxCredentials>;
        /// Syncs an account vault held as `.kdbx` bytes; `has_base == false` uses the cached base.
        fn sync_vault_kdbx(
            self: &Account,
            vault_id: &str,
            kdbx: Vec<u8>,
            has_base: bool,
            base: Vec<u8>,
            options: SyncOptions,
            cancel: &CancelToken,
        ) -> Result<VaultKdbxSyncResult>;
        /// The session's access token (UTF-8), refreshed when needed. Never log it.
        fn access_token(self: &Account, force_refresh: bool, cancel: &CancelToken) -> Result<Vec<u8>>;
        /// [`Vault::sync`] with every option (`accept_server_state`).
        fn sync_with_options(self: &Vault, options: SyncOptions, cancel: &CancelToken) -> Result<SyncReport>;

        // ---- in-process test servers (feature `test-server`; README.md "Test servers")
        type TestServers;
        type TestStream;
        /// Fresh auth + sync servers, the clock at `now_ms` (0: the testkit default). Fails with
        /// `internal` without the feature.
        fn test_servers_start(now_ms: i64) -> Result<Box<TestServers>>;
        fn issuer(self: &TestServers) -> Result<String>;
        fn api_url(self: &TestServers) -> Result<String>;
        fn sync_url(self: &TestServers) -> Result<String>;
        fn now_ms(self: &TestServers) -> Result<i64>;
        fn set_now_ms(self: &TestServers, ms: i64) -> Result<()>;
        fn advance_ms(self: &TestServers, delta_ms: i64) -> Result<i64>;
        /// For a C++ `HttpTransport::send`: answers in process; failures go to `failure`.
        fn handle(self: &TestServers, req: &HttpRequest, failure: &mut TransportFailure) -> Result<HttpResponse>;
        /// For a C++ `HttpTransport::open_stream`.
        fn open_stream(
            self: &TestServers,
            req: &HttpRequest,
            failure: &mut TransportFailure,
        ) -> Result<Box<TestStream>>;
        /// A Client on the servers' own Host (memory store and cache, the test clock).
        fn client(self: &TestServers, config: &ClientConfig) -> Result<Box<Client>>;
        fn set_offline(self: &TestServers, offline: bool) -> Result<()>;
        /// `status == 0` is a transport failure; empty `server` / `method` / `path_contains` match any.
        fn fail_next(
            self: &TestServers,
            server: &str,
            method: &str,
            path_contains: &str,
            status: u16,
            times: usize,
        ) -> Result<()>;
        fn clear_faults(self: &TestServers) -> Result<()>;
        fn set_server_clock_skew_ms(self: &TestServers, ms: i64) -> Result<()>;
        fn requests(self: &TestServers) -> Result<Vec<String>>;
        fn clear_requests(self: &TestServers) -> Result<()>;
        fn set_live_access(self: &TestServers, live: bool) -> Result<()>;
        fn vault_blob(self: &TestServers, vault_id: &str) -> Result<OptionalBytes>;
        fn vault_revision(self: &TestServers, vault_id: &str) -> Result<i64>;
        fn put_vault_blob(self: &TestServers, vault_id: &str, data: &[u8]) -> Result<()>;
        fn rollback_vault(self: &TestServers, vault_id: &str, to_revision: i64) -> Result<()>;
        fn lose_vault(self: &TestServers, vault_id: &str) -> Result<()>;
        fn add_device_token(self: &TestServers, token: &str, user: &str) -> Result<()>;
        fn close_streams(self: &TestServers) -> Result<()>;
        fn user_id(self: &TestServers, email: &str) -> Result<String>;
        fn set_totp_code(self: &TestServers, email: &str, code: &str) -> Result<bool>;
        fn totp_now(self: &TestServers, email: &str) -> Result<String>;
        fn email_code(self: &TestServers, user_id: &str) -> Result<String>;
        fn approve_reset(self: &TestServers, email: &str, delay_secs: i64) -> Result<String>;
        fn invitation_token(self: &TestServers, org_id: &str, email: &str) -> Result<String>;
        fn add_member(self: &TestServers, org_id: &str, email: &str, role: &str) -> Result<bool>;
        fn revoke_sessions(self: &TestServers, principal: &str) -> Result<()>;
        fn access_events(self: &TestServers) -> Result<String>;
        fn set_deletion_days(self: &TestServers, days: i64) -> Result<()>;
        fn set_access_token_ttl_secs(self: &TestServers, secs: i64) -> Result<()>;
        fn set_recent_token_ms(self: &TestServers, ms: i64) -> Result<()>;
        fn status(self: &TestStream) -> Result<u16>;
        fn poll_chunk(self: &TestStream) -> Result<TestStreamPoll>;
        fn close(self: &TestStream) -> Result<()>;
    }

    // ------------------------------------------- below the facade, for C++ (README.md, "Desktop swap")
    //
    // Synchronous and CPU-only (the OPAQUE steps run Argon2id: keep them off the GUI thread). Byte
    // inputs are borrowed: the caller wipes its secrets. Text given as bytes must be UTF-8. Fixed
    // nonces, ephemeral keys and seeds are for the test vectors only: pass them empty to get fresh
    // random ones.
    extern "Rust" {
        // ---- ov v1 crypto (ov-crypto, SPEC §1-§9)
        fn nfkc_utf8(text: &[u8]) -> Result<Vec<u8>>;
        fn generate_secret_key() -> Result<Vec<u8>>;
        fn format_secret_key(raw: &[u8]) -> Result<String>;
        fn parse_secret_key(text: &str) -> Result<Vec<u8>>;
        fn wrap(key: &[u8], plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
        fn unwrap(key: &[u8], wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
        fn seal(
            recipient_pk: &[u8],
            plaintext: &[u8],
            aad: &[u8],
            ephemeral_sk: &[u8],
            nonce: &[u8],
        ) -> Result<Vec<u8>>;
        fn unseal(recipient_sk: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
        fn seal_derived_key(recipient_sk: &[u8], sealed: &[u8]) -> Result<Vec<u8>>;
        fn x25519_public_key(secret_key: &[u8]) -> Result<Vec<u8>>;
        fn x25519_shared(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>>;
        fn ed25519_public_key(seed: &[u8]) -> Result<Vec<u8>>;
        fn ed25519_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>>;
        fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
        /// The public half (with fingerprint) of a keyset's two secret halves (SPEC §5).
        fn keyset_from_secrets(enc_sk: &[u8], sign_seed: &[u8]) -> Result<PublicKeys>;
        fn verify_public_keys(enc_pk: &[u8], sign_pk: &[u8], sig: &[u8]) -> bool;
        fn fingerprint(enc_pk: &[u8], sign_pk: &[u8]) -> String;
        fn vault_name_key(vault_key: &[u8]) -> Result<Vec<u8>>;
        fn refresh_token_hash(token: &str) -> String;
        fn build_service_account_token(url: &str, sa_id: &str, secret: &[u8], kek: &[u8]) -> Result<String>;
        fn parse_service_account_token(text: &str) -> Result<ServiceAccountToken>;
        fn service_account_secret_hash(secret: &[u8]) -> Result<String>;
        fn service_account_secret_prefix(secret: &[u8]) -> Result<String>;

        // ---- OPAQUE client (ov-opaque, SPEC §8). `password` is UTF-8, NFKC-normalised here.
        fn opaque_start_registration(password: &[u8]) -> Result<OpaqueStart>;
        fn opaque_finish_registration(state: &[u8], response: &[u8], id_u: &[u8], id_s: &[u8]) -> Result<Vec<u8>>;
        fn opaque_start_login(password: &[u8]) -> Result<OpaqueStart>;
        fn opaque_finish_login(
            state: &[u8],
            ke2: &[u8],
            id_u: &[u8],
            id_s: &[u8],
            context: &[u8],
        ) -> Result<OpaqueLogin>;

        // ---- tests only: built with the `test-server` cargo feature, else they fail with `internal`
        /// Whether this library was built with the `test-server` feature.
        fn test_server_enabled() -> bool;
        fn opaque_start_registration_seeded(password: &[u8], seed: &[u8]) -> Result<OpaqueStart>;
        fn opaque_finish_registration_seeded(
            state: &[u8],
            response: &[u8],
            id_u: &[u8],
            id_s: &[u8],
            seed: &[u8],
        ) -> Result<Vec<u8>>;
        fn opaque_start_login_seeded(password: &[u8], seed: &[u8]) -> Result<OpaqueStart>;
        fn opaque_finish_login_seeded(
            state: &[u8],
            ke2: &[u8],
            id_u: &[u8],
            id_s: &[u8],
            context: &[u8],
            seed: &[u8],
        ) -> Result<OpaqueLogin>;
        fn opaque_server_registration_response(request: &[u8]) -> Result<OpaqueServerStep>;
        fn opaque_server_registration_response_seeded(request: &[u8], seed: &[u8]) -> Result<OpaqueServerStep>;
        fn opaque_server_store_record(setup: &[u8], record: &[u8]) -> Result<Vec<u8>>;
        fn opaque_server_credential_response(
            ke1: &[u8],
            stored_record: &[u8],
            id_u: &[u8],
            id_s: &[u8],
            context: &[u8],
        ) -> Result<OpaqueServerStep>;
        fn opaque_server_credential_response_seeded(
            ke1: &[u8],
            stored_record: &[u8],
            id_u: &[u8],
            id_s: &[u8],
            context: &[u8],
            seed: &[u8],
        ) -> Result<OpaqueServerStep>;
        fn opaque_server_user_auth(state: &[u8], auth_u: &[u8]) -> Result<Vec<u8>>;

        // ---- the sync merge (ov-merge on ov-kdbx), bytes in, bytes out
        /// Each copy is a KDBX file with its composite key as one or two raw 32-byte components
        /// (password and/or key file, in order). An empty `base` means no common base. Serialise
        /// with a throwaway key: the user's vault key need not cross.
        fn merge_kdbx(
            local: &[u8],
            local_key: &[u8],
            remote: &[u8],
            remote_key: &[u8],
            base: &[u8],
            base_key: &[u8],
            now: i64,
        ) -> Result<KdbxMergeResult>;
    }
}
