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
//! `README.md` lists which facade methods are bridged so far.

#![warn(missing_docs)]

mod convert;
mod edge;
mod handles;
pub mod host;
mod primitives;

pub use edge::FfiError;
pub use handles::{
    new_cancel_token, new_client, vault_create_local, vault_open_local, Account, CancelToken, Client, EventStream,
    LoginStep, TotpChallenge, Vault,
};

use edge::take_last_error;
use primitives::{aead_decrypt, aead_encrypt, argon2id, hkdf_sha256, random_bytes, sha256};

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
        /// Every group.
        fn export_kdbx(self: &Vault, credentials: KdbxCredentials, cancel: &CancelToken) -> Result<Vec<u8>>;

        // ---- EventStream
        type EventStream;
        fn next(self: &EventStream, cancel: &CancelToken) -> Result<AccountEvent>;
        fn reconnect(self: &EventStream) -> Result<()>;
        fn close(self: &EventStream) -> Result<()>;
    }
}
