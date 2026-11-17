//! Private state behind the facade handles. **Not frozen**: W2-A owns this file and adds whatever
//! fields the implementation needs, without touching the handles' public API in `api/`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, Mutex};

use ov_crypto::keyset::Keyset;
use ov_error::OvError;
use ov_kdbx::model::Database;
use ov_protocol::auth::AuthApi;
use ov_protocol::sync::SyncApi;
use zeroize::Zeroizing;

use crate::api::{ClientConfig, KdbxCredentials, ServerConfig, SyncConflict, VaultInfo};
use crate::host::Host;
use crate::impls::keyring::VaultEntry;
use crate::impls::tokens::{SignedOutSignal, TokenManager};

/// Behind [`OvClient`](crate::api::OvClient).
pub(crate) struct ClientState {
    pub(crate) host: Host,
    pub(crate) config: ClientConfig,
}

/// Behind [`Account`](crate::api::Account).
pub(crate) struct AccountState {
    pub(crate) client: Arc<ClientState>,
    pub(crate) config: ServerConfig,
    pub(crate) auth: AuthApi,
    pub(crate) sync: SyncApi,
    pub(crate) tokens: TokenManager,
    pub(crate) signal: Arc<SignedOutSignal>,
    pub(crate) inner: Mutex<AccountInner>,
}

/// The mutable part of an account.
#[derive(Default)]
pub(crate) struct AccountInner {
    /// The unlocked keyset.
    pub(crate) keyset: Option<Keyset>,
    /// Listed vaults with the keys this account holds.
    pub(crate) vaults: ov_vault::Keyring,
    /// Working from the offline cache.
    pub(crate) offline: bool,
    /// Whose offline cache to drop when the session ends (the session is gone by then).
    pub(crate) cache_user: Option<String>,
    /// The erase date of a pending account (SPEC §23).
    pub(crate) deletion: Option<String>,
    /// From the last sync.
    pub(crate) clock_offset_ms: Option<i64>,
}

/// Behind [`TotpChallenge`](crate::api::TotpChallenge): the MFA token and what finishing the
/// sign-in needs (wiped on drop).
pub(crate) struct TotpState {
    pub(crate) email: String,
    pub(crate) mfa_token: Zeroizing<String>,
    pub(crate) password: Zeroizing<String>,
    pub(crate) secret_key: Zeroizing<[u8; 16]>,
    pub(crate) trust_device: bool,
    pub(crate) attempt: AtomicU32,
    pub(crate) last_error: Mutex<Option<OvError>>,
    pub(crate) used: AtomicBool,
}

/// Where a [`Vault`](crate::api::Vault) came from.
pub(crate) enum VaultSource {
    /// A local `.kdbx` with its credentials.
    Local(KdbxCredentials),
    /// An account vault.
    Account { account: crate::api::Account, info: Mutex<VaultInfo> },
    /// An old version from history (read-only).
    Version { info: VaultInfo },
    /// A vault opened by a service account (weak: the SA keeps its opened vaults).
    ServiceAccount { sa: std::sync::Weak<ServiceAccountState>, info: VaultInfo },
}

/// Behind [`Vault`](crate::api::Vault).
pub(crate) struct VaultState {
    pub(crate) source: VaultSource,
    /// The Host, for the clock and the offline cache; `None` for a local file opened without one.
    pub(crate) host: Option<Host>,
    pub(crate) db: Mutex<Database>,
    pub(crate) offline: AtomicBool,
    pub(crate) etag: Mutex<Option<String>>,
    pub(crate) conflicts: Mutex<Vec<SyncConflict>>,
    /// The sync session (state, pending edits, offline flag) of an account or SA vault.
    pub(crate) session: futures::lock::Mutex<ov_sync::VaultSession>,
}

/// Behind [`ServiceAccount`](crate::api::ServiceAccount).
pub(crate) struct ServiceAccountState {
    pub(crate) client: Arc<ClientState>,
    pub(crate) auth: AuthApi,
    pub(crate) sync: SyncApi,
    pub(crate) sa_id: String,
    pub(crate) inner: Mutex<SaInner>,
    pub(crate) refresh_lock: futures::lock::Mutex<()>,
}

/// The mutable part of a service account.
pub(crate) struct SaInner {
    pub(crate) keyset: Option<Keyset>,
    pub(crate) secret: Zeroizing<[u8; 32]>,
    pub(crate) access: Option<(Zeroizing<String>, i64)>,
    pub(crate) vaults: Option<Vec<VaultEntry>>,
    pub(crate) opened: HashMap<String, crate::api::Vault>,
}

/// Behind [`SelfHosted`](crate::api::SelfHosted).
pub(crate) struct SelfHostedState {
    pub(crate) client: Arc<ClientState>,
    pub(crate) server_url: String,
    pub(crate) sync: SyncApi,
    pub(crate) token: Zeroizing<String>,
}

/// Behind [`EventStream`](crate::api::EventStream).
pub(crate) struct EventStreamState {
    pub(crate) stream: ov_sync::EventStream,
    /// The account that acts on `access` events (`None` for a self-hosted stream).
    pub(crate) account: Option<crate::api::Account>,
}
