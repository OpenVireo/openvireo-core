//! [`OvClient`]: the entry point. Holds the [`Host`] and settings; makes [`Account`]s, opens share
//! links, and keeps the remembered-accounts list (SPEC §21).

use std::sync::Arc;

use ov_error::OvError;

use super::share_links::{OpenedShare, ShareInfo};
use super::{Account, CancelToken, ClientConfig, RememberedAccount, Rfc3339, SecretBytes, ServerConfig, SessionState};
use crate::host::Host;
use crate::state::ClientState;

/// The entry point of the core: one per app process (or per test).
#[derive(Clone)]
pub struct OvClient {
    pub(crate) inner: Arc<ClientState>,
}

impl std::fmt::Debug for OvClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OvClient").field("config", &self.inner.config).finish()
    }
}

impl OvClient {
    /// A client over the platform's [`Host`]. Does no I/O.
    pub fn new(config: ClientConfig, host: Host) -> Self {
        OvClient { inner: Arc::new(ClientState { host, config }) }
    }

    /// The settings this client was made with.
    pub fn config(&self) -> ClientConfig {
        self.inner.config.clone()
    }

    /// Fetches the discovery document `GET {issuer}/.well-known/openvireo-configuration` (SPEC §10)
    /// and checks every URL in it against SPEC §1 "Transport" (`insecure_url`). With
    /// [`ClientConfig::offline`], an unreachable server falls back to the copy from the last
    /// successful call (kept in the [BlobCache](crate::host::BlobCache)).
    pub async fn discover(&self, issuer: String, cancel: CancelToken) -> Result<ServerConfig, OvError> {
        crate::impls::client::discover(self, &issuer, &cancel).await
    }

    /// Discovers the server (or uses [`ClientConfig::server`]) and loads a stored session if any:
    /// the account is then signed in but locked. TS `Account.connect`, Swift `Account.connect`.
    /// [`Account::is_offline`] is true when discovery fell back to the cached document.
    pub async fn connect(&self, issuer: String, cancel: CancelToken) -> Result<Account, OvError> {
        crate::impls::client::connect(self, issuer, cancel).await
    }

    /// Accounts this device remembers for switching, most recently used first (SPEC §21).
    pub async fn remembered_accounts(&self) -> Result<Vec<RememberedAccount>, OvError> {
        crate::impls::remembered::all(&self.inner.host).await
    }

    /// Adds or refreshes a remembered account (last used: now).
    pub async fn remember_account(&self, email: String, issuer: String, user_id: String) -> Result<(), OvError> {
        let host = &self.inner.host;
        let mut list = crate::impls::remembered::all(host).await?;
        let previous = list.iter().position(|a| a.issuer == issuer && a.user_id == user_id).map(|i| list.remove(i));
        list.push(RememberedAccount {
            email,
            issuer,
            user_id,
            last_used_at: crate::impls::util::rfc3339(host.clock.now_unix_ms()),
            checked_at: previous.as_ref().and_then(|p| p.checked_at.clone()),
            deletion_scheduled_for: previous.and_then(|p| p.deletion_scheduled_for),
        });
        crate::impls::remembered::save(host, &list).await
    }

    /// Records (or clears) a remembered account's erase date (SPEC §23).
    pub async fn set_remembered_deletion(
        &self,
        issuer: String,
        user_id: String,
        at: Option<Rfc3339>,
    ) -> Result<(), OvError> {
        crate::impls::remembered::update(&self.inner.host, &issuer, &user_id, |a| a.deletion_scheduled_for = at).await
    }

    /// Records that the server confirmed the account's parked session now.
    pub async fn mark_remembered_checked(&self, issuer: String, user_id: String) -> Result<(), OvError> {
        let now = crate::impls::util::rfc3339(self.inner.host.clock.now_unix_ms());
        crate::impls::remembered::update(&self.inner.host, &issuer, &user_id, |a| a.checked_at = Some(now)).await
    }

    /// Removes an account from the remembered list. Doesn't sign it out or delete its Secret Key
    /// (that is [`Account::forget_device`]).
    pub async fn forget_remembered(&self, issuer: String, user_id: String) -> Result<(), OvError> {
        let host = &self.inner.host;
        let mut list = crate::impls::remembered::all(host).await?;
        list.retain(|a| !(a.issuer == issuer && a.user_id == user_id));
        crate::impls::remembered::save(host, &list).await
    }

    /// Whether a user has an active, parked or no session on this device, with no network
    /// (SPEC §21). If a crash left the session under both keys, the active one wins and the
    /// parked copy is removed. TS static `Account.sessionState`, Swift `Account.sessionState(of:)`.
    pub async fn session_state(&self, issuer: String, user_id: String) -> Result<SessionState, OvError> {
        crate::impls::client::session_state(&self.inner.host, &issuer, &user_id).await
    }

    /// Whether a user's offline cache holds edits not yet uploaded (reads no secrets). TS static
    /// `Account.hasPendingEdits`, Swift `Account.hasUnsyncedEdits`.
    pub async fn has_pending_edits(&self, user_id: String) -> Result<bool, OvError> {
        let cache = &self.inner.host.cache;
        for id in cache.list(&user_id).await? {
            if cache.load(&user_id, &id).await?.is_some_and(|v| v.pending.is_some()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What the public share page knows before opening a share (`GET {api}/public/shares/{id}`,
    /// SPEC §22): expiry, opens left, and the passcode KDF if it needs one. A share that ended or
    /// never existed is `not_found`. Works without an account.
    pub async fn share_info(&self, api: String, share_id: String, cancel: CancelToken) -> Result<ShareInfo, OvError> {
        crate::impls::client::share_info(self, &api, &share_id, &cancel).await
    }

    /// Opens a share link (SPEC §22): counts one open on the server and decrypts the payload with
    /// the key in the link's fragment. `passcode_required` when it needs a passcode and none was
    /// given; the server's `invalid_passcode` (with `details.attemptsLeft`) for a wrong one. `info`
    /// saves a request when the page already called [`share_info`](Self::share_info).
    pub async fn open_share(
        &self,
        api: String,
        link: SecretBytes,
        passcode: Option<SecretBytes>,
        info: Option<ShareInfo>,
        cancel: CancelToken,
    ) -> Result<OpenedShare, OvError> {
        crate::impls::client::open_share(self, &api, link, passcode, info, &cancel).await
    }
}

/// Whether a remembered account's stored erase date (SPEC §23) is more than a day past, so the app
/// removes it and its Secret Key. `now_ms` is Unix milliseconds. TS `deletionExpired`, Swift
/// `Account.deletionExpired`.
pub fn deletion_expired(scheduled_for: Option<Rfc3339>, now_ms: i64) -> bool {
    let Some(at) = scheduled_for.as_deref().and_then(crate::impls::util::parse_rfc3339) else { return false };
    now_ms > at + 24 * 3600_000
}
