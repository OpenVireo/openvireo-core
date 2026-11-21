//! The sync loop (TS `syncKdbx`, from the desktop `SyncEngine` without the Qt parts): HEAD/GET with
//! the ETag → open → three-way merge with the base copy → conditional PUT → on 412 download, merge
//! and retry. The base copy is the server's bytes from the last successful sync; a [`BaseCache`]
//! keeps it opened between syncs.

use std::borrow::Cow;
use std::sync::Mutex;

use ov_error::{OvError, OvErrorCode};
use ov_host::{MaybeSend, MaybeSync};
use ov_kdbx::entries::find_entry;
use ov_kdbx::model::Database;
use ov_kdbx::vault::{set_sync_generation, sync_generation};
use ov_kdbx::CompositeKey;
use ov_merge::{
    conflicting_fields, copies_differ, edited_on_both, find_conflicts, merge_in_place, snapshot_of, ConflictKind,
    MergeChange, SyncConflict,
};
use ov_protocol::sync::{BlobVersion, GetResult, HeadResult, PutCondition};

use crate::client::Blob;
use crate::state::{iso_time, SyncState};

/// How far a clock may be off before apps warn (5 minutes), as the desktop and iOS apps do.
pub const CLOCK_SKEW_WARNING_MS: i64 = 5 * 60 * 1000;

/// Whether this device's clock is far enough off the server's to warn the user (TS
/// `isClockSkewed`). Sync doesn't depend on the clock (deletions and edits are decided against the
/// base copy), but a wrong clock gives entries wrong modification times, which decide between two
/// copies when there is no base, and it breaks TOTP codes.
pub fn is_clock_skewed(clock_offset_ms: Option<i64>) -> bool {
    clock_offset_ms.is_some_and(|o| o.unsigned_abs() > CLOCK_SKEW_WARNING_MS as u64)
}

/// What a sync did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyncOutcome {
    /// Nothing changed on either side.
    Unchanged,
    /// Downloaded and merged; nothing to upload.
    Pulled,
    /// Uploaded the merged copy.
    Uploaded,
    /// The server had nothing; uploaded the local copy as the first version.
    Created,
}

/// A step of a sync, for progress UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyncStep {
    /// The HEAD check (nothing changed locally).
    Checking,
    /// Downloading the server copy.
    Downloading,
    /// Merging.
    Merging,
    /// Uploading.
    Uploading,
}

/// Lets a caller stop a sync between steps (the facade wraps its `CancelToken`). A cancelled sync
/// fails with `aborted`.
pub trait Cancel: MaybeSend + MaybeSync {
    /// Whether to stop.
    fn is_cancelled(&self) -> bool;
}

impl<F: Fn() -> bool + MaybeSend + MaybeSync> Cancel for F {
    fn is_cancelled(&self) -> bool {
        self()
    }
}

/// Runs on the copy about to be uploaded (key rotation re-keys here) and forces an upload. Returns
/// the key to save with when it changed it.
pub trait BeforeUpload: MaybeSend + MaybeSync {
    /// Changes `db` before it is saved and uploaded.
    fn before_upload(&self, db: &mut Database) -> Result<Option<CompositeKey>, OvError>;
}

impl<F> BeforeUpload for F
where
    F: Fn(&mut Database) -> Result<Option<CompositeKey>, OvError> + MaybeSend + MaybeSync,
{
    fn before_upload(&self, db: &mut Database) -> Result<Option<CompositeKey>, OvError> {
        self(db)
    }
}

/// The base copy kept opened between syncs, so a sync doesn't decrypt and parse it again (about
/// 90 ms of a 5k-entry sync before, W4-F), nor the server copy when that is still the base (no
/// upload since this device's last sync). A session keeps one per database and passes it with
/// [`SyncOptions::base_cache`]; each sync uses what it holds when those bytes come up, opened with
/// one of the credentials, and leaves it holding the new base.
///
/// Entries are checked, not trusted: the cache holds the SHA-256 of the bytes it was opened from
/// and the key that opened them, and anything else is a miss (the base is opened as before). A
/// sync that fails keeps what the cache held; one whose future is dropped leaves it empty.
#[derive(Default)]
pub struct BaseCache(Mutex<Option<OpenedBase>>);

impl std::fmt::Debug for BaseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaseCache").field("held", &self.lock().is_some()).finish()
    }
}

impl BaseCache {
    /// An empty cache.
    pub fn new() -> Self {
        BaseCache::default()
    }

    /// Drops what it holds (the vault was locked or closed).
    pub fn clear(&self) {
        *self.lock() = None;
    }

    /// Keeps `db`, opened with `key` from `data` (the state's new base), for the next sync.
    pub fn keep(&self, data: &[u8], key: &CompositeKey, db: Database) {
        *self.lock() = Some(OpenedBase::new(data, key, db));
    }

    /// A copy of what it holds when that is `data` opened (with any key), else `None`.
    pub fn get(&self, data: &[u8]) -> Option<Database> {
        let digest = ov_crypto::primitives::sha256(data);
        self.lock().as_ref().filter(|b| b.digest == digest).map(|b| b.db.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<OpenedBase>> {
        // A panic while held leaves nothing half-written: the value is replaced whole
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A base copy opened: the database, the SHA-256 of the bytes and the key it was opened from.
struct OpenedBase {
    digest: [u8; 32],
    key: CompositeKey,
    db: Database,
}

impl OpenedBase {
    fn new(data: &[u8], key: &CompositeKey, db: Database) -> Self {
        OpenedBase { digest: ov_crypto::primitives::sha256(data), key: key.clone(), db }
    }

    /// `db` as reading `data` (`ov_kdbx::write(db)`) gives it back: the same, with the version the
    /// write chose (a 4.0 file holding 4.1 elements is written as 4.1).
    fn written(data: &[u8], key: &CompositeKey, db: &Database) -> Self {
        let mut db = db.clone();
        db.header.version = ov_kdbx::write_version(&db);
        OpenedBase::new(data, key, db)
    }
}

/// The base copy opened: from `keep` when it holds these bytes opened with one of `creds`, else
/// opened now and kept there (a 412 retry merges against the same base). `None` when no
/// credentials open it: a base under another key is no use, and the merge goes without one.
fn open_base<'k>(data: &[u8], creds: &[CompositeKey], keep: &'k mut Option<OpenedBase>) -> Option<&'k Database> {
    let digest = ov_crypto::primitives::sha256(data);
    let hit = keep.as_ref().is_some_and(|k| k.digest == digest && creds.iter().any(|c| c.opens_same_as(&k.key)));
    if !hit {
        let (db, i) = open_with(data, creds).ok()?;
        *keep = Some(OpenedBase { digest, key: creds[i].clone(), db });
    }
    keep.as_ref().map(|k| &k.db)
}

/// The server copy opened: a copy of the cached base when the server still has the bytes it was
/// opened from (nothing was uploaded since), else read from `data` (as [`open_with`]). The index is
/// the first credentials that open it either way: only a key with the same KDF input does.
fn open_remote(data: &[u8], creds: &[CompositeKey], keep: &Option<OpenedBase>) -> Result<(Database, usize), OvError> {
    if let Some(k) = keep.as_ref().filter(|k| k.digest == ov_crypto::primitives::sha256(data)) {
        if let Some(i) = creds.iter().position(|c| c.opens_same_as(&k.key)) {
            return Ok((k.db.clone(), i));
        }
    }
    open_with(data, creds)
}

/// Progress callback.
pub trait Progress: MaybeSend + MaybeSync {
    /// A step started.
    fn step(&self, step: SyncStep);
}

impl<F: Fn(SyncStep) + MaybeSend + MaybeSync> Progress for F {
    fn step(&self, step: SyncStep) {
        self(step)
    }
}

/// The inputs of [`sync_kdbx`] besides the blob and the working copy (TS `SyncOptions`).
#[derive(Clone, Copy)]
pub struct SyncOptions<'a> {
    /// The working copy's own key: it saves the local copy when the server has none.
    pub local_key: &'a CompositeKey,
    /// Opens the server copy and the base, tried in order (newest key first).
    pub credentials: &'a [CompositeKey],
    /// The state from the last sync, if any.
    pub state: Option<&'a SyncState>,
    /// Whether the local copy changed since the last sync (default `true`). `false` → a cheap HEAD
    /// check first.
    pub local_changed: bool,
    /// Start over from what the server has (after the user confirmed a rollback or loss).
    pub accept_server_state: bool,
    /// The state's base is the server's current copy (it was just downloaded, e.g. by
    /// [`VaultSession::download`](crate::VaultSession::download)): the first attempt merges against
    /// it and uploads with its ETag instead of downloading it again. If the server changed meanwhile
    /// the PUT gets 412 and the next attempt downloads as usual. Ignored without a base.
    pub remote_is_base: bool,
    /// Attempts on 412 (default 5, like the desktop's `MaxAttempts`).
    pub max_attempts: u32,
    /// Runs on the copy about to be uploaded; forces an upload.
    pub before_upload: Option<&'a dyn BeforeUpload>,
    /// Checked between steps.
    pub cancel: Option<&'a dyn Cancel>,
    /// Told about each step.
    pub progress: Option<&'a dyn Progress>,
    /// Keeps the base opened between syncs (see [`BaseCache`]).
    pub base_cache: Option<&'a BaseCache>,
}

impl<'a> SyncOptions<'a> {
    /// The defaults: no state, `local_changed`, 5 attempts.
    pub fn new(local_key: &'a CompositeKey, credentials: &'a [CompositeKey]) -> Self {
        SyncOptions {
            local_key,
            credentials,
            state: None,
            local_changed: true,
            accept_server_state: false,
            remote_is_base: false,
            max_attempts: 5,
            before_upload: None,
            cancel: None,
            progress: None,
            base_cache: None,
        }
    }

    /// With the last sync's state.
    pub fn state(mut self, state: Option<&'a SyncState>) -> Self {
        self.state = state;
        self
    }

    /// With `local_changed`.
    pub fn local_changed(mut self, changed: bool) -> Self {
        self.local_changed = changed;
        self
    }

    /// With `accept_server_state`.
    pub fn accept_server_state(mut self, accept: bool) -> Self {
        self.accept_server_state = accept;
        self
    }

    /// With `remote_is_base`.
    pub fn remote_is_base(mut self, yes: bool) -> Self {
        self.remote_is_base = yes;
        self
    }

    /// With `max_attempts`.
    pub fn max_attempts(mut self, n: u32) -> Self {
        self.max_attempts = n;
        self
    }

    /// With a `before_upload` hook.
    pub fn before_upload(mut self, hook: &'a dyn BeforeUpload) -> Self {
        self.before_upload = Some(hook);
        self
    }

    /// With a cancel check.
    pub fn cancel(mut self, cancel: &'a dyn Cancel) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// With a progress callback.
    pub fn progress(mut self, progress: &'a dyn Progress) -> Self {
        self.progress = Some(progress);
        self
    }

    /// With a cache of the opened base.
    pub fn base_cache(mut self, cache: &'a BaseCache) -> Self {
        self.base_cache = Some(cache);
        self
    }
}

/// What [`sync_kdbx`] did (TS `SyncResult`).
#[derive(Clone)]
pub struct SyncResult {
    /// What happened.
    pub outcome: SyncOutcome,
    /// The merged database with the server's header: use it as the working copy from now on, with
    /// [`key`](Self::key). (The working copy passed in was merged too, but keeps its own header.)
    pub db: Database,
    /// The key `db` is saved with.
    pub key: CompositeKey,
    /// Index into `credentials` that opened the server copy (`None` when nothing was downloaded).
    pub credentials_index: Option<usize>,
    /// The server's bytes now.
    pub data: Option<Vec<u8>>,
    /// The new state to keep.
    pub state: SyncState,
    /// Conflicts found (edits on both sides keep the newer value; the other is in history).
    pub conflicts: Vec<SyncConflict>,
    /// The changes the merge applied.
    pub changes: Vec<MergeChange>,
    /// Download attempts (more than 1 after 412 retries; 0 after a HEAD check).
    pub attempts: u32,
    /// How far this device's clock is ahead of the sync server's, in ms (negative: behind);
    /// `None` when the server sent no readable `Date`. See [`is_clock_skewed`].
    pub clock_offset_ms: Option<i64>,
}

impl SyncResult {
    /// `is_clock_skewed(self.clock_offset_ms)`.
    pub fn clock_skewed(&self) -> bool {
        is_clock_skewed(self.clock_offset_ms)
    }
}

impl std::fmt::Debug for SyncResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncResult")
            .field("outcome", &self.outcome)
            .field("credentials_index", &self.credentials_index)
            .field("data_len", &self.data.as_ref().map(Vec::len))
            .field("state", &self.state)
            .field("conflicts", &self.conflicts)
            .field("changes", &self.changes.len())
            .field("attempts", &self.attempts)
            .field("clock_offset_ms", &self.clock_offset_ms)
            .finish_non_exhaustive()
    }
}

/// Opens `data` with the first credentials that fit; only `vault_key_mismatch` moves on.
pub fn open_with(data: &[u8], creds: &[CompositeKey]) -> Result<(Database, usize), OvError> {
    let mut last = None;
    for (i, key) in creds.iter().enumerate() {
        match ov_kdbx::read(data, key) {
            Ok(db) => return Ok((db, i)),
            Err(e) if e.is(OvErrorCode::VaultKeyMismatch) => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    // The desktop asks the user to unlock the server copy here; callers get an error they can act on
    Err(last.unwrap_or_else(|| OvError::new(OvErrorCode::VaultKeyMismatch, "no credentials to open the server copy")))
}

struct Finish<'a> {
    prev: Option<&'a SyncState>,
    now_ms: i64,
    clock_offset_ms: Option<i64>,
}

impl Finish<'_> {
    #[allow(clippy::too_many_arguments)]
    fn result(
        &self,
        outcome: SyncOutcome,
        local: &Database,
        db: Database,
        key: CompositeKey,
        etag: String,
        revision: i64,
        data: Option<Vec<u8>>,
        index: Option<usize>,
        attempts: u32,
        remote_generation: u64,
        conflicts: Vec<SyncConflict>,
        changes: Vec<MergeChange>,
    ) -> SyncResult {
        let prev = self.prev;
        let state = SyncState {
            etag,
            revision: prev.map_or(0, |p| p.revision).max(revision),
            generation: prev
                .map_or(0, |p| p.generation)
                .max(remote_generation)
                .max(sync_generation(&db))
                .max(sync_generation(local)),
            snapshot: snapshot_of(local),
            base: data.clone().or_else(|| prev.and_then(|p| p.base.clone())),
            last_sync: iso_time(self.now_ms),
        };
        SyncResult {
            outcome,
            db,
            key,
            credentials_index: index,
            data,
            state,
            conflicts,
            changes,
            attempts,
            clock_offset_ms: self.clock_offset_ms,
        }
    }
}

/// Syncs `local` (the working copy, merged in place) with `blob` (TS `syncKdbx`).
///
/// Errors besides the transport's (`network_error` when offline: the working copy is untouched or
/// merged, never lost):
/// - `server_rolled_back`: the server's revision or sync generation is older than what this device
///   synced (a restore from backup). Confirm with the user, then sync with `accept_server_state`.
/// - `server_lost_database`: the server has no copy although this device synced one.
/// - `too_many_conflicts` (412): the server copy kept changing for `max_attempts` attempts.
/// - `vault_key_mismatch`: no credentials open the server copy.
/// - `aborted`: [`SyncOptions::cancel`] said stop.
pub async fn sync_kdbx(blob: &Blob, local: &mut Database, opts: &SyncOptions<'_>) -> Result<SyncResult, OvError> {
    let mut keep = opts.base_cache.and_then(|c| c.lock().take());
    let result = run(blob, local, opts, &mut keep).await;
    if let Some(c) = opts.base_cache {
        *c.lock() = keep;
    }
    result
}

/// [`sync_kdbx`], with the opened base in `keep`: read when it is the state's base, replaced by the
/// new base when a sync succeeds with a [`BaseCache`].
async fn run(
    blob: &Blob,
    local: &mut Database,
    opts: &SyncOptions<'_>,
    keep: &mut Option<OpenedBase>,
) -> Result<SyncResult, OvError> {
    let caching = opts.base_cache.is_some();
    let clock = blob.client().clock().clone();
    let prev = if opts.accept_server_state { None } else { opts.state };
    let progress = |s: SyncStep| {
        if let Some(p) = opts.progress {
            p.step(s)
        }
    };
    let finish = |blob: &Blob| Finish { prev, now_ms: clock.now_unix_ms(), clock_offset_ms: blob.clock_offset_ms() };
    let check_revision = |revision: Option<i64>| -> Result<(), OvError> {
        match (prev, revision) {
            (Some(p), Some(r)) if r >= 0 && r < p.revision => Err(OvError::new(
                OvErrorCode::ServerRolledBack,
                format!(
                    "the sync server returned revision {r}, older than revision {} this device already synced",
                    p.revision
                ),
            )),
            _ => Ok(()),
        }
    };
    let check_cancel = || match opts.cancel {
        Some(c) if c.is_cancelled() => Err(OvError::new(OvErrorCode::Aborted, "the sync was cancelled")),
        _ => Ok(()),
    };

    // Nothing changed here since the last sync: only download when the server has a new version
    if let (Some(p), false, None) = (prev, opts.local_changed, opts.before_upload) {
        check_cancel()?;
        progress(SyncStep::Checking);
        if let HeadResult::NotModified(v) = blob.head(Some(&p.etag)).await? {
            check_revision(v.revision)?;
            return Ok(finish(blob).result(
                SyncOutcome::Unchanged,
                local,
                local.clone(),
                opts.local_key.clone(),
                p.etag.clone(),
                v.revision.unwrap_or(-1),
                p.base.clone(),
                None,
                0,
                0,
                Vec::new(),
                Vec::new(),
            ));
        }
    }

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        check_cancel()?;
        // The base was just downloaded: it is the server copy for the first attempt
        let known = match prev {
            Some(p) if attempt == 1 && opts.remote_is_base && !p.etag.is_empty() => p
                .base
                .clone()
                .map(|b| (b, BlobVersion { etag: p.etag.clone(), revision: Some(p.revision), last_modified: None })),
            _ => None,
        };
        let from_base = known.is_some();
        if !from_base {
            progress(SyncStep::Downloading);
        }
        let got = match known {
            Some((data, version)) => GetResult::Ok { data, version },
            None => blob.get(None).await?,
        };
        let (data, version) = match got {
            GetResult::NotFound => {
                if prev.is_some_and(|p| p.revision > 0) {
                    return Err(OvError::new(
                        OvErrorCode::ServerLostDatabase,
                        "the sync server no longer has this database, although this device synced it before",
                    ));
                }
                // Nothing on the server yet: publish the local database as the first version
                let mut key = opts.local_key.clone();
                if let Some(hook) = opts.before_upload {
                    if let Some(k) = hook.before_upload(local)? {
                        key = k;
                    }
                }
                let data = ov_kdbx::write(local, &key)?;
                check_cancel()?;
                progress(SyncStep::Uploading);
                match blob.put(&data, &PutCondition::Create).await {
                    Ok(put) => {
                        if caching {
                            *keep = Some(OpenedBase::written(&data, &key, local));
                        }
                        return Ok(finish(blob).result(
                            SyncOutcome::Created,
                            local,
                            local.clone(),
                            key,
                            put.version.etag,
                            put.version.revision.unwrap_or(-1),
                            Some(data),
                            None,
                            attempt,
                            0,
                            Vec::new(),
                            Vec::new(),
                        ));
                    }
                    Err(e) if e.is(OvErrorCode::PreconditionFailed) && attempt < opts.max_attempts => continue,
                    Err(e) => return Err(e),
                }
            }
            GetResult::NotModified(_) => {
                return Err(OvError::new(OvErrorCode::ServerError, "unexpected status 304").with_status(304))
            }
            GetResult::Ok { data, version } => (data, version),
        };
        check_revision(version.revision)?;

        check_cancel()?;
        progress(SyncStep::Merging);
        let (mut remote, index) = open_remote(&data, opts.credentials, keep)?;
        // The server copy as opened: the next sync's base when nothing is uploaded (the merge
        // changes `remote`, if only its attachment pool)
        let opened = caching.then(|| remote.clone());
        let remote_generation = sync_generation(&remote);
        if let Some(p) = prev.filter(|p| remote_generation < p.generation) {
            return Err(OvError::new(
                OvErrorCode::ServerRolledBack,
                format!(
                    "the server copy has sync generation {remote_generation}, older than {} already synced here",
                    p.generation
                ),
            ));
        }

        // The copy both sides last synced from tells which fields each side changed. It is opened
        // whenever the copies differ, not only when the snapshot says so: the snapshot compares
        // whole-second times, so an edit made in the second of the last sync (or of a 412 retry's
        // first merge) looks unchanged to it, and the newer copy would win whole.
        let empty = Vec::new();
        let snapshot = prev.map_or(&empty, |p| &p.snapshot);
        let mut conflicts = find_conflicts(local, &remote, snapshot);
        let base: Option<Cow<'_, Database>> = match prev.and_then(|p| p.base.as_deref()) {
            Some(_) if from_base => Some(opened.as_ref().map_or_else(|| Cow::Owned(remote.clone()), Cow::Borrowed)),
            Some(b) if copies_differ(local, &remote) => open_base(b, opts.credentials, keep).map(Cow::Borrowed),
            _ => None,
        };
        if let Some(base) = &base {
            conflicts.retain_mut(|c| {
                if c.kind != ConflictKind::EditedOnBoth {
                    return true;
                }
                let Some(b) = find_entry(&base.root, c.uuid) else { return true };
                c.fields = conflicting_fields(
                    find_entry(&local.root, c.uuid).map(|e| (e, &*local)),
                    find_entry(&remote.root, c.uuid).map(|e| (e, &remote)),
                    Some((b, base)),
                );
                // Different fields changed: both changes are kept
                !c.fields.is_empty()
            });
            // Edits on both sides the snapshot missed (same-second times), found by content
            for c in edited_on_both(local, &remote, base) {
                if !conflicts.iter().any(|k| k.uuid == c.uuid) {
                    conflicts.push(c);
                }
            }
        }

        let now_s = clock.now_unix_ms().div_euclid(1000);
        let merged = merge_in_place(local, &mut remote, base.as_deref(), now_s);
        drop(base);
        let changes = merged.changes.clone();

        if !merged.remote_changed && opts.before_upload.is_none() {
            // The merge didn't change the server copy: nothing to upload. The merge bumped the
            // generation for an upload that won't happen, so both copies keep the server's;
            // otherwise the next sync would take the server for a rollback.
            if !merged.changes.is_empty() {
                set_sync_generation(local, remote_generation, now_s);
                set_sync_generation(&mut remote, remote_generation, now_s);
            }
            let outcome =
                if !opts.local_changed && !merged.local_changed { SyncOutcome::Unchanged } else { SyncOutcome::Pulled };
            if let Some(db) = opened {
                *keep = Some(OpenedBase::new(&data, &opts.credentials[index], db));
            }
            return Ok(finish(blob).result(
                outcome,
                local,
                remote,
                opts.credentials[index].clone(),
                version.etag,
                version.revision.unwrap_or(-1),
                Some(data),
                Some(index),
                attempt,
                remote_generation,
                conflicts,
                changes,
            ));
        }

        let mut key = opts.credentials[index].clone();
        if let Some(hook) = opts.before_upload {
            if let Some(k) = hook.before_upload(&mut remote)? {
                key = k;
            }
        }
        let upload = ov_kdbx::write(&remote, &key)?;
        check_cancel()?;
        progress(SyncStep::Uploading);
        match blob.put(&upload, &PutCondition::IfMatch(version.etag.clone())).await {
            Ok(put) => {
                if caching {
                    *keep = Some(OpenedBase::written(&upload, &key, &remote));
                }
                return Ok(finish(blob).result(
                    SyncOutcome::Uploaded,
                    local,
                    remote,
                    key,
                    put.version.etag,
                    put.version.revision.unwrap_or(-1),
                    Some(upload),
                    Some(index),
                    attempt,
                    remote_generation,
                    conflicts,
                    changes,
                ));
            }
            // Another device uploaded since our download: merge its version too and try again
            Err(e) if e.is(OvErrorCode::PreconditionFailed) => {
                if attempt < opts.max_attempts {
                    continue;
                }
                return Err(OvError::new(
                    OvErrorCode::TooManyConflicts,
                    "the database on the sync server kept changing during the sync; local changes are kept, sync again",
                )
                .with_status(412));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_skew() {
        assert!(!is_clock_skewed(None));
        assert!(!is_clock_skewed(Some(CLOCK_SKEW_WARNING_MS)));
        assert!(is_clock_skewed(Some(CLOCK_SKEW_WARNING_MS + 1)));
        assert!(is_clock_skewed(Some(-2 * CLOCK_SKEW_WARNING_MS)));
        assert!(is_clock_skewed(Some(i64::MIN)));
    }
}
