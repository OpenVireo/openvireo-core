//! Sync on the facade, over `ov-sync`: the token sources, account and service-account vault sync
//! through `VaultSession`, self-hosted database sync, and the event streams.
//!
//! The Host has no timer, so the core never sleeps. When `ov_sync::EventStream` says
//! `Waiting { retry_in_ms }`, [`EventStream::next`] returns `Err(network_error)` with
//! `retry_after` (seconds, rounded up) and `details: {"retryInMs": n}`; the platform waits that long
//! and calls `next` again (the contract's "connection errors while reconnecting are returned as
//! `Err` and the stream keeps going").

use std::sync::Arc;

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::vault::{vault_credentials, KeyVersion};
use ov_sync::{SessionSyncOptions, StreamItem, SyncClient, SyncEvent, TokenSource, VaultCache};
use zeroize::Zeroizing;

use super::convert::{merge_change, sync_conflict};
use super::util::lock;
use crate::api::{
    Account, AccountEvent, CancelToken, EventStream, KdbxCredentials, SelfHosted, SelfHostedSyncResult, ServiceAccount,
    SignedOutReason, SyncOptions, SyncOutcome, SyncReport, Vault,
};
use crate::state::VaultSource;

/// The account's tokens for `ov-sync` (refreshing; a refused refresh ends the session here).
pub(crate) struct AccountTokens(pub(crate) Account);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TokenSource for AccountTokens {
    async fn access_token(&self, force_refresh: bool) -> Result<Option<String>, OvError> {
        Ok(Some(self.0.bearer_token(force_refresh, &CancelToken::new()).await?.to_string()))
    }
}

/// The token manager itself is a token source too (parked sessions, tests).
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TokenSource for super::tokens::TokenManager {
    async fn access_token(&self, force_refresh: bool) -> Result<Option<String>, OvError> {
        Ok(Some(super::tokens::TokenManager::access_token(self, force_refresh, &CancelToken::new()).await?.to_string()))
    }
}

/// A service account's JWT for `ov-sync` (re-exchanged before it expires).
pub(crate) struct SaTokens(pub(crate) ServiceAccount);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TokenSource for SaTokens {
    async fn access_token(&self, force_refresh: bool) -> Result<Option<String>, OvError> {
        Ok(Some(self.0.access_token(force_refresh, &CancelToken::new()).await?.to_string()))
    }
}

/// Wraps the facade's `CancelToken` for `ov-sync`.
pub(crate) struct CancelWrap(pub(crate) CancelToken);

impl ov_sync::Cancel for CancelWrap {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

impl Account {
    /// A sync client on the account's token.
    pub(crate) fn sync_client(&self) -> SyncClient {
        let h = self.host();
        SyncClient::new(h.http.clone(), h.clock.clone(), self.inner.sync.clone(), Arc::new(AccountTokens(self.clone())))
    }

    /// The offline-cache record of a vault, when the cache is on.
    pub(crate) fn vault_cache(&self, vault_id: &str) -> Option<VaultCache> {
        let user = self.current_user()?;
        self.keeps_offline_data().then(|| VaultCache::new(self.host().cache.clone(), user, vault_id))
    }

    pub(crate) fn note_clock(&self, offset: Option<i64>) {
        if offset.is_some() {
            lock(&self.inner.inner).clock_offset_ms = offset;
        }
    }
}

impl ServiceAccount {
    pub(crate) fn sync_client(&self) -> SyncClient {
        let h = &self.inner.client.host;
        SyncClient::new(h.http.clone(), h.clock.clone(), self.inner.sync.clone(), Arc::new(SaTokens(self.clone())))
    }
}

pub(crate) fn report(r: &ov_sync::SyncResult) -> SyncReport {
    let conflicts: Vec<_> = r.conflicts.iter().map(sync_conflict).collect();
    SyncReport {
        outcome: match r.outcome {
            ov_sync::SyncOutcome::Unchanged => SyncOutcome::Unchanged,
            ov_sync::SyncOutcome::Pulled => SyncOutcome::Pulled,
            ov_sync::SyncOutcome::Uploaded => SyncOutcome::Uploaded,
            ov_sync::SyncOutcome::Created => SyncOutcome::Created,
        },
        conflicts,
        changes: r.changes.iter().map(merge_change).collect(),
        attempts: r.attempts,
        etag: Some(r.state.etag.clone()).filter(|e| !e.is_empty()),
        clock_offset_ms: r.clock_offset_ms,
        clock_skewed: r.clock_skewed(),
    }
}

/// The keys of the vault behind an account or SA vault handle, newest first.
async fn vault_keys(v: &Vault) -> Result<(String, Vec<KeyVersion>), OvError> {
    match &v.inner.source {
        VaultSource::Account { account, info } => {
            let id = lock(info).id.clone();
            let e = account.entry_offline(&id).await?;
            Ok((id, e.keys().to_vec()))
        }
        VaultSource::ServiceAccount { sa, info } => {
            let sa = sa.upgrade().ok_or_else(|| super::util::signed_out("service account closed"))?;
            let sa = ServiceAccount { inner: sa };
            let e = sa.entry(&info.id, &CancelToken::new()).await?;
            Ok((info.id.clone(), e.keys().to_vec()))
        }
        _ => Err(OvError::new(OvErrorCode::InvalidRequest, "this vault has no server")),
    }
}

/// The keys of the vault behind a handle fetched again from the server, after its copy didn't open
/// with the keys held: another device rotated the vault key since they were fetched. The account's
/// keyring (or the service account's list) and the handle's record follow.
async fn refetch_keys(v: &Vault, cancel: &CancelToken) -> Result<Vec<KeyVersion>, OvError> {
    match &v.inner.source {
        VaultSource::Account { account, info } => {
            let id = lock(info).id.clone();
            let e = account.refetch_entry(&id, cancel).await?;
            *lock(info) = e.info.clone();
            Ok(e.keys().to_vec())
        }
        VaultSource::ServiceAccount { sa, info } => {
            let sa = sa.upgrade().ok_or_else(|| super::util::signed_out("service account closed"))?;
            let sa = ServiceAccount { inner: sa };
            sa.entries(true, cancel).await?;
            Ok(sa.entry(&info.id, cancel).await?.keys().to_vec())
        }
        _ => Err(OvError::new(OvErrorCode::InvalidRequest, "this vault has no server")),
    }
}

/// Syncs an account or SA vault (conditional PUT, merge and retry on 412), re-keying to `rekey_to`
/// before the upload (rotation). The working copy, etag, conflicts and the account's clock offset
/// follow the result. Offline, the working copy goes to the cache's pending edits.
pub(crate) async fn sync_vault(
    v: &Vault,
    options: SyncOptions,
    rekey_to: Option<&[u8; 32]>,
    cancel: &CancelToken,
) -> Result<SyncReport, OvError> {
    sync_vault_with(v, options, rekey_to, false, cancel).await
}

/// [`sync_vault`], where `remote_is_base`: the vault was just downloaded, so the first attempt
/// uploads against that copy instead of downloading it again (a 412 downloads).
///
/// Edits made to the handle while a round runs are merged into its result three ways (the copy the
/// round started from is the base) and uploaded by up to two more rounds, each against the copy the
/// round before left on the server (contract-v1.8). A later round that fails leaves them as
/// unsynced edits and the call returns what the earlier rounds did.
pub(crate) async fn sync_vault_with(
    v: &Vault,
    options: SyncOptions,
    rekey_to: Option<&[u8; 32]>,
    remote_is_base: bool,
    cancel: &CancelToken,
) -> Result<SyncReport, OvError> {
    const ROUNDS: usize = 3;
    cancel.check()?;
    let (id, mut keys) = vault_keys(v).await?;
    let client = match &v.inner.source {
        VaultSource::Account { account, .. } => account.sync_client(),
        VaultSource::ServiceAccount { sa, .. } => {
            let sa = sa.upgrade().ok_or_else(|| super::util::signed_out("service account closed"))?;
            ServiceAccount { inner: sa }.sync_client()
        }
        _ => return Err(OvError::new(OvErrorCode::InvalidRequest, "this vault has no server")),
    };
    let blob = client.vault(&id);
    let mut session = v.inner.session.lock().await;
    if session.key.is_none() {
        let newest = keys
            .iter()
            .max_by_key(|k| k.version)
            .ok_or_else(|| OvError::new(OvErrorCode::NoVaultKey, "no vault key available"))?;
        session.key = Some(vault_credentials(&newest.key)?);
    }
    let cw = CancelWrap(cancel.clone());
    let rekey = rekey_to.map(|k| Zeroizing::new(k.to_vec()));
    let mut total: Option<SyncReport> = None;
    for round in 0..ROUNDS {
        let first = round == 0;
        let start = v.db().clone();
        session.db = Some(start.clone());
        let opts = SessionSyncOptions {
            local_changed: Some(!first || options.local_changed),
            accept_server_state: first && options.accept_server_state,
            rekey_to: rekey.as_deref().map(|k| &k[..]).filter(|_| first),
            remote_is_base: !first || remote_is_base,
            cancel: Some(&cw),
        };
        let mut result = session.sync(&blob, &keys, opts).await;
        if first && matches!(&result, Err(e) if e.is(OvErrorCode::VaultKeyMismatch)) {
            // Another device rotated the vault key since this device fetched its keys: once more
            // with the keys the server holds for this principal now
            keys = refetch_keys(v, cancel).await?;
            result = session.sync(&blob, &keys, opts).await;
        }
        v.inner.offline.store(session.offline, std::sync::atomic::Ordering::SeqCst);
        if let VaultSource::Account { account, .. } = &v.inner.source {
            account.note_clock(blob.clock_offset_ms());
            if let Err(e) = &result {
                if e.is(OvErrorCode::SignedOut) && e.status.is_some() {
                    account.session_ended(e).await;
                }
                if e.is_unreachable() {
                    account.set_offline(true);
                }
            } else {
                account.set_offline(false);
            }
        }
        let r = match result {
            Ok(r) => r,
            Err(e) if first => return Err(e),
            Err(_) => {
                // The edits made during the first rounds stay in the working copy, kept on the device
                session.db = Some(v.db().clone());
                let _ = session.keep_edits().await;
                break;
            }
        };
        *lock(&v.inner.etag) = Some(r.state.etag.clone());
        total = Some(combine_reports(total, report(&r)));
        let synced = session.db.clone().unwrap_or_else(|| r.db.clone());
        let now = v.now();
        let more = {
            let mut db = v.db();
            if *db == start {
                *db = synced;
                false
            } else {
                // Edited while the round ran: those edits on top of its result
                let (mut merged, m) = ov_merge::merge(Some(&start), &db, &synced, now);
                merged.header = synced.header.clone();
                *db = merged.clone();
                session.db = Some(merged);
                m.remote_changed
            }
        };
        if !more {
            break;
        }
        if round + 1 == ROUNDS {
            let _ = session.keep_edits().await;
        }
    }
    let rep = total.expect("the first round succeeded");
    *lock(&v.inner.conflicts) = rep.conflicts.clone();
    Ok(rep)
}

fn outcome_rank(o: SyncOutcome) -> u8 {
    match o {
        SyncOutcome::Unchanged => 0,
        SyncOutcome::Pulled => 1,
        SyncOutcome::Uploaded => 2,
        SyncOutcome::Created => 3,
    }
}

/// The report of several rounds of one sync: the most a round did, every round's conflicts, changes
/// and attempts, the last round's ETag and clock.
fn combine_reports(so_far: Option<SyncReport>, next: SyncReport) -> SyncReport {
    let Some(mut a) = so_far else { return next };
    if outcome_rank(next.outcome) > outcome_rank(a.outcome) {
        a.outcome = next.outcome;
    }
    for c in next.conflicts {
        if !a.conflicts.contains(&c) {
            a.conflicts.push(c);
        }
    }
    a.changes.extend(next.changes);
    a.attempts += next.attempts;
    a.etag = next.etag.or(a.etag);
    a.clock_offset_ms = next.clock_offset_ms.or(a.clock_offset_ms);
    a.clock_skewed = next.clock_skewed;
    a
}

/// Downloads (or, offline, opens this device's copy of) an account vault through a new session.
pub(crate) async fn open_session(
    account: &Account,
    e: &super::keyring::VaultEntry,
    cancel: &CancelToken,
) -> Result<Vault, OvError> {
    let v = super::vaults::new_vault(
        VaultSource::Account { account: account.clone(), info: std::sync::Mutex::new(e.info.clone()) },
        Some(account.host().clone()),
        ov_kdbx::vault::create_kdbx("", 0)?,
        false,
        account.vault_cache(&e.info.id),
    );
    let client = account.sync_client();
    let blob = client.vault(&e.info.id);
    let cw = CancelWrap(cancel.clone());
    let mut session = v.inner.session.lock().await;
    let opts = SessionSyncOptions { cancel: Some(&cw), ..Default::default() };
    let mut keys = e.keys().to_vec();
    let mut first = session.sync(&blob, &keys, opts).await;
    if matches!(&first, Err(err) if err.is(OvErrorCode::Forbidden)) {
        // A vault shared since the token was issued isn't in its `vlt` claim yet: refresh once.
        account.refresh_token(cancel).await?;
        first = session.sync(&blob, &keys, opts).await;
    }
    if matches!(&first, Err(err) if err.is(OvErrorCode::VaultKeyMismatch)) {
        // Another device rotated the vault key since this device fetched its keys: fetch them again
        keys = refetch_keys(&v, cancel).await?;
        first = session.sync(&blob, &keys, opts).await;
    }
    match first {
        Ok(r) => {
            account.note_clock(blob.clock_offset_ms());
            account.set_offline(false);
            *lock(&v.inner.etag) = Some(r.state.etag.clone());
            *lock(&v.inner.conflicts) = report(&r).conflicts;
        }
        Err(err) => {
            if err.is(OvErrorCode::SignedOut) && err.status.is_some() {
                account.session_ended(&err).await;
            }
            if !(account.keeps_offline_data() && err.is_unreachable()) {
                return Err(err);
            }
            session.open_local_copy(&keys, &e.info.name, &err).await?;
            account.set_offline(true);
        }
    }
    v.inner.offline.store(session.offline, std::sync::atomic::Ordering::SeqCst);
    if let Some(db) = &session.db {
        *v.db() = db.clone();
    }
    drop(session);
    Ok(v)
}

/// Downloads a vault for a service account (no offline cache): one GET.
pub(crate) async fn open_sa_session(
    sa: &ServiceAccount,
    e: &super::keyring::VaultEntry,
    cancel: &CancelToken,
) -> Result<Vault, OvError> {
    let v = super::vaults::new_vault(
        VaultSource::ServiceAccount { sa: Arc::downgrade(&sa.inner), info: e.info.clone() },
        Some(sa.inner.client.host.clone()),
        ov_kdbx::vault::create_kdbx("", 0)?,
        false,
        None,
    );
    let client = sa.sync_client();
    let blob = client.vault(&e.info.id);
    let cw = CancelWrap(cancel.clone());
    let mut session = v.inner.session.lock().await;
    // One GET: the downloaded copy is the working copy and the base (TS `ServiceAccount.download`)
    let r = match session.download(&blob, e.keys(), Some(&cw)).await {
        Err(err) if err.is(OvErrorCode::VaultKeyMismatch) => {
            // The vault key was rotated since the list was fetched: fetch it again, once
            let keys = refetch_keys(&v, cancel).await?;
            session.download(&blob, &keys, Some(&cw)).await?
        }
        r => r?,
    };
    *lock(&v.inner.etag) = Some(r.state.etag.clone());
    if let Some(db) = &session.db {
        *v.db() = db.clone();
    }
    drop(session);
    Ok(v)
}

/// One sync of a vault from its pending edits or the server's copy, re-keyed to `new_key` before
/// the upload (rotation). `e` must already hold the new key.
pub(crate) async fn rekey_sync(
    account: &Account,
    e: &super::keyring::VaultEntry,
    new_key: &[u8],
    cancel: &CancelToken,
) -> Result<SyncReport, OvError> {
    let client = account.sync_client();
    let blob = client.vault(&e.info.id);
    let cw = CancelWrap(cancel.clone());
    let mut session = ov_sync::VaultSession::new(account.vault_cache(&e.info.id));
    let opts = SessionSyncOptions {
        local_changed: Some(true),
        accept_server_state: false,
        rekey_to: Some(new_key),
        remote_is_base: false,
        cancel: Some(&cw),
    };
    let r = session.sync(&blob, e.keys(), opts).await;
    account.note_clock(blob.clock_offset_ms());
    Ok(report(&r?))
}

/// Keeps the working copy as pending edits (Swift `keepEdits`).
pub(crate) async fn keep_edits(v: &Vault) -> Result<(), OvError> {
    if !matches!(v.inner.source, VaultSource::Account { .. }) {
        return Ok(());
    }
    let (_, keys) = vault_keys(v).await?;
    let mut session = v.inner.session.lock().await;
    session.db = Some(v.db().clone());
    if session.key.is_none() {
        if let Some(k) = keys.iter().max_by_key(|k| k.version) {
            session.key = Some(vault_credentials(&k.key)?);
        }
    }
    session.keep_edits().await
}

/// Self-hosted whole-database sync (SPEC §13), the state kept in the BlobCache under the user
/// `selfhosted:<url>`. With `local_changed: false` and a stored state, a HEAD first: unchanged on the
/// server means nothing is decrypted, merged or downloaded, and `kdbx` comes back as it is.
pub(crate) async fn sync_database(
    sh: &SelfHosted,
    database_id: &str,
    kdbx: &[u8],
    credentials: &KdbxCredentials,
    options: SyncOptions,
    cancel: &CancelToken,
) -> Result<SelfHostedSyncResult, OvError> {
    cancel.check()?;
    let host = &sh.inner.client.host;
    let key = super::vaults::local_key(credentials)?;
    let client = SyncClient::new(
        host.http.clone(),
        host.clock.clone(),
        sh.inner.sync.clone(),
        Arc::new(ov_sync::StaticToken(Some(sh.inner.token.to_string()))),
    );
    let blob = client.database(database_id);
    let cache = VaultCache::new(host.cache.clone(), super::self_hosted::token_key(&sh.inner.server_url), database_id);
    let state = if options.accept_server_state { None } else { cache.load_state().await? };
    let mut head_changed = false;
    if let (Some(prev), false) = (&state, options.local_changed) {
        // Before the file is decrypted (a KDF run): most checks find nothing new
        if let ov_protocol::sync::HeadResult::NotModified(v) = blob.head(Some(&prev.etag)).await? {
            if let Some(r) = v.revision.filter(|r| *r >= 0 && *r < prev.revision) {
                return Err(OvError::new(
                    OvErrorCode::ServerRolledBack,
                    format!(
                        "the sync server returned revision {r}, older than revision {} this device already synced",
                        prev.revision
                    ),
                ));
            }
            let mut checked = prev.clone();
            checked.last_sync = ov_sync::state::iso_time(host.clock.now_unix_ms());
            cache.save_state(&checked).await?;
            let offset = blob.clock_offset_ms();
            let report = SyncReport {
                outcome: SyncOutcome::Unchanged,
                conflicts: Vec::new(),
                changes: Vec::new(),
                attempts: 0,
                etag: Some(prev.etag.clone()).filter(|e| !e.is_empty()),
                clock_offset_ms: offset,
                clock_skewed: ov_sync::is_clock_skewed(offset),
            };
            return Ok(SelfHostedSyncResult { kdbx: kdbx.to_vec(), report });
        }
        head_changed = true;
    }
    cancel.check()?;
    let mut db = ov_kdbx::read(kdbx, &key)?;
    let creds = [key.clone()];
    let cw = CancelWrap(cancel.clone());
    // After a HEAD that found a new version, don't ask again: download and merge
    let mut opts = ov_sync::SyncOptions::new(&key, &creds)
        .state(state.as_ref())
        .local_changed(options.local_changed || head_changed)
        .accept_server_state(options.accept_server_state);
    opts.cancel = Some(&cw);
    let r = ov_sync::sync_kdbx(&blob, &mut db, &opts).await?;
    cache.save_state(&r.state).await?;
    let out = ov_kdbx::write(&r.db, &r.key)?;
    Ok(SelfHostedSyncResult { kdbx: out, report: report(&r) })
}

/// A new stream on a sync client.
pub(crate) fn stream(client: SyncClient, account: Option<Account>) -> EventStream {
    EventStream {
        inner: Arc::new(crate::state::EventStreamState {
            stream: ov_sync::EventStream::new(client, ov_sync::EventStreamOptions::default()),
            account,
        }),
    }
}

fn rev(r: Option<i64>) -> Option<u64> {
    r.and_then(|r| u64::try_from(r).ok())
}

/// The next event, after the account acted on it (`access`: refresh, reload the vault list,
/// reconnect; deletion: end the session and close).
pub(crate) async fn next_event(s: &EventStream, cancel: &CancelToken) -> Result<Option<AccountEvent>, OvError> {
    loop {
        cancel.check()?;
        let item = {
            let fut = s.inner.stream.next();
            let c = cancel.cancelled();
            futures::pin_mut!(fut, c);
            match futures::future::select(fut, c).await {
                futures::future::Either::Left((i, _)) => i,
                futures::future::Either::Right(_) => return Err(OvError::new(OvErrorCode::Aborted, "cancelled")),
            }
        };
        match item {
            StreamItem::Connecting | StreamItem::Open => continue,
            StreamItem::Closed { .. } => return Ok(None),
            StreamItem::Waiting { retry_in_ms, error } => {
                let base = error.unwrap_or_else(|| OvError::new(OvErrorCode::NetworkError, "the event stream ended"));
                let mut e = OvError::new(OvErrorCode::NetworkError, base.message.clone());
                e.status = base.status;
                let secs = retry_in_ms.div_ceil(1000).min(u64::from(u32::MAX)) as u32;
                return Err(e.with_retry_after(secs).with_details(format!("{{\"retryInMs\":{retry_in_ms}}}")));
            }
            StreamItem::Event(ev) => match ev {
                SyncEvent::Vault { id, etag, revision, deleted } => {
                    return Ok(Some(AccountEvent::VaultChanged {
                        vault_id: id,
                        etag,
                        revision: rev(revision),
                        deleted,
                    }))
                }
                SyncEvent::Database { id, etag, revision, deleted } => {
                    return Ok(Some(AccountEvent::DatabaseChanged {
                        database_id: id,
                        etag,
                        revision: rev(revision),
                        deleted,
                    }))
                }
                SyncEvent::Access { change, at, .. } => {
                    let Some(account) = &s.inner.account else { continue };
                    let reason = match change.as_str() {
                        "deletion_scheduled" => Some(SignedOutReason::DeletionScheduled),
                        "account_deleted" => Some(SignedOutReason::AccountDeleted),
                        _ => None,
                    };
                    if let Some(reason) = reason {
                        s.inner.stream.close();
                        if let Some(user) = account.user_id() {
                            account.end_session(&user, reason).await?;
                        }
                        return Ok(Some(AccountEvent::SessionEnded { reason, at }));
                    }
                    account.refresh_token(cancel).await?;
                    let vaults = account.load_vault_list(cancel).await?.0;
                    s.inner.stream.reconnect();
                    return Ok(Some(AccountEvent::VaultsChanged { vaults }));
                }
                SyncEvent::Unknown { .. } => continue,
            },
        }
    }
}
