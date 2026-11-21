//! An account vault kept in sync with `vaults/<id>` and cached for offline use (SPEC §20; TS
//! `AccountVault.sync` / `openLocalCopy` and the `Account` offline-cache helpers).
//!
//! The cache record ([`CachedVault`]) holds the sync state, the server's bytes at the last sync
//! (`base`: the merge base and the offline copy) and local edits not yet uploaded (`pending`,
//! encrypted with the vault key). When a sync can't reach the server the working copy goes to
//! `pending`, so edits survive a restart; the next successful sync merges and uploads them and
//! clears it.

use std::sync::Arc;

use ov_error::{OvError, OvErrorCode};
use ov_host::{BlobCache, CachedVault};
use ov_kdbx::model::Database;
use ov_kdbx::vault::{open_with_key_versions, vault_credentials, KeyVersion};
use ov_kdbx::CompositeKey;
use ov_protocol::sync::GetResult;

use crate::client::Blob;
use crate::engine::{sync_kdbx, BeforeUpload, Cancel, SyncOptions, SyncOutcome, SyncResult};
use crate::state::{from_cached, iso_time, to_cached, SyncState};

/// One vault's record in the offline cache, keyed by user (two accounts on one device can share a
/// vault, SPEC §21).
#[derive(Clone)]
pub struct VaultCache {
    cache: Arc<dyn BlobCache>,
    user_id: String,
    vault_id: String,
}

impl std::fmt::Debug for VaultCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultCache").field("user_id", &self.user_id).field("vault_id", &self.vault_id).finish()
    }
}

impl VaultCache {
    /// The record of `vault_id` for `user_id`.
    pub fn new(cache: Arc<dyn BlobCache>, user_id: impl Into<String>, vault_id: impl Into<String>) -> Self {
        VaultCache { cache, user_id: user_id.into(), vault_id: vault_id.into() }
    }

    async fn record(&self) -> Result<Option<CachedVault>, OvError> {
        self.cache.load(&self.user_id, &self.vault_id).await
    }

    async fn update(&self, f: impl FnOnce(&mut CachedVault)) -> Result<(), OvError> {
        let mut rec = self.record().await?.unwrap_or(CachedVault {
            state: Vec::new(),
            base: None,
            pending: None,
            autofill: None,
        });
        f(&mut rec);
        if rec.state.is_empty() && rec.base.is_none() && rec.pending.is_none() && rec.autofill.is_none() {
            return self.cache.remove(&self.user_id, &self.vault_id).await;
        }
        self.cache.save(&self.user_id, &self.vault_id, &rec).await
    }

    /// The sync state (with its base), if any.
    pub async fn load_state(&self) -> Result<Option<SyncState>, OvError> {
        match self.record().await? {
            Some(rec) => from_cached(&rec),
            None => Ok(None),
        }
    }

    /// Stores the state and base, keeping `pending` and `autofill`.
    pub async fn save_state(&self, state: &SyncState) -> Result<(), OvError> {
        let c = to_cached(state);
        self.update(|rec| {
            rec.state = c.state;
            rec.base = c.base;
        })
        .await
    }

    /// Local edits not yet uploaded (an encrypted `.kdbx`).
    pub async fn load_pending(&self) -> Result<Option<Vec<u8>>, OvError> {
        Ok(self.record().await?.and_then(|r| r.pending))
    }

    /// Stores local edits not yet uploaded.
    pub async fn save_pending(&self, data: Vec<u8>) -> Result<(), OvError> {
        self.update(|rec| rec.pending = Some(data)).await
    }

    /// Drops the pending edits (after an upload).
    pub async fn clear_pending(&self) -> Result<(), OvError> {
        self.update(|rec| rec.pending = None).await
    }

    /// Removes the whole record.
    pub async fn forget(&self) -> Result<(), OvError> {
        self.cache.remove(&self.user_id, &self.vault_id).await
    }
}

/// Inputs of [`VaultSession::sync`] besides the blob and keys.
#[derive(Clone, Copy, Default)]
pub struct SessionSyncOptions<'a> {
    /// `Some(false)`: nothing changed here, so a HEAD check first. Default: changed.
    pub local_changed: Option<bool>,
    /// Start over from the server copy (after the user confirmed a rollback or loss).
    pub accept_server_state: bool,
    /// Re-key to this vault key before uploading (rotation).
    pub rekey_to: Option<&'a [u8]>,
    /// The last sync's base is the server's current copy (just [downloaded](VaultSession::download)):
    /// upload against it without downloading again ([`SyncOptions::remote_is_base`]).
    pub remote_is_base: bool,
    /// Checked between steps.
    pub cancel: Option<&'a dyn Cancel>,
}

/// An opened account vault: the working copy, its key, the sync state and the offline flags (TS
/// `AccountVault`).
pub struct VaultSession {
    cache: Option<VaultCache>,
    /// The working copy, once opened or synced.
    pub db: Option<Database>,
    /// The key `db` is saved with.
    pub key: Option<CompositeKey>,
    state: Option<Option<SyncState>>,
    /// The last sync couldn't reach the server, or the vault was opened from the offline cache.
    pub offline: bool,
    has_pending: bool,
}

impl std::fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSession")
            .field("cache", &self.cache)
            .field("opened", &self.db.is_some())
            .field("offline", &self.offline)
            .field("has_pending", &self.has_pending)
            .finish_non_exhaustive()
    }
}

fn credentials(keys: &[KeyVersion]) -> Result<(Vec<KeyVersion>, Vec<CompositeKey>), OvError> {
    let mut sorted = keys.to_vec();
    sorted.sort_by_key(|k| std::cmp::Reverse(k.version));
    let creds = sorted.iter().map(|k| vault_credentials(&k.key)).collect::<Result<Vec<_>, _>>()?;
    Ok((sorted, creds))
}

impl VaultSession {
    /// A session. With `cache` the state, base and pending edits persist (SPEC §20); without it
    /// (offline cache off) the state lives only in this session.
    pub fn new(cache: Option<VaultCache>) -> Self {
        VaultSession { cache, db: None, key: None, state: None, offline: false, has_pending: false }
    }

    /// The server ETag at the last sync (compare with a `vault` event's etag).
    pub fn etag(&self) -> Option<&str> {
        self.state.as_ref().and_then(|s| s.as_ref()).map(|s| s.etag.as_str())
    }

    /// The state from the last sync, if loaded.
    pub fn state(&self) -> Option<&SyncState> {
        self.state.as_ref().and_then(|s| s.as_ref())
    }

    /// Edits wait on this device for the next upload.
    pub fn has_pending(&self) -> bool {
        self.has_pending
    }

    async fn ensure_state(&mut self) -> Result<(), OvError> {
        if self.state.is_none() {
            self.state = Some(match &self.cache {
                Some(c) => c.load_state().await?,
                None => None,
            });
        }
        Ok(())
    }

    /// Local edits kept from an earlier session that couldn't upload them; they merge in on the
    /// next sync. `None` when there are none or no key opens them (rotated twice meanwhile).
    async fn open_pending(&mut self, keys: &[KeyVersion]) -> Result<Option<(Database, CompositeKey)>, OvError> {
        let Some(cache) = &self.cache else { return Ok(None) };
        let Some(pending) = cache.load_pending().await? else { return Ok(None) };
        self.has_pending = true;
        Ok(open_with_key_versions(&pending, keys).ok().and_then(|(db, version)| {
            let k = keys.iter().find(|k| k.version == version)?;
            Some((db, vault_credentials(&k.key).ok()?))
        }))
    }

    /// Downloads, merges local edits and uploads them (TS `AccountVault.sync`). When the server
    /// can't be reached the working copy is kept in the cache as `pending` (when there is
    /// something to keep), [`offline`](Self::offline) is set and the `network_error` is returned.
    pub async fn sync(
        &mut self,
        blob: &Blob,
        keys: &[KeyVersion],
        opts: SessionSyncOptions<'_>,
    ) -> Result<SyncResult, OvError> {
        self.ensure_state().await?;
        let (sorted, creds) = credentials(keys)?;
        if self.db.is_none() {
            if let Some((db, key)) = self.open_pending(&sorted).await? {
                self.db = Some(db);
                self.key = Some(key);
            }
        }
        let mut fresh: Option<SyncState> = None;
        if self.db.is_none() {
            // Nothing local yet: the server copy becomes the working copy
            let got = match blob.get(None).await {
                Ok(g) => g,
                Err(e) => {
                    if e.is_unreachable() {
                        self.offline = true;
                    }
                    return Err(e);
                }
            };
            let GetResult::Ok { data, version } = got else {
                return Err(
                    OvError::new(OvErrorCode::NotFound, "this vault has no data on the sync server").with_status(404)
                );
            };
            let (db, kv) = open_with_key_versions(&data, &sorted)?;
            let k = sorted.iter().find(|k| k.version == kv).expect("the version that opened it");
            let key = vault_credentials(&k.key)?;
            let state = SyncState {
                etag: version.etag.clone(),
                revision: version.revision.unwrap_or(-1),
                generation: ov_kdbx::vault::sync_generation(&db),
                snapshot: ov_merge::snapshot_of(&db),
                base: Some(data.clone()),
                last_sync: iso_time(blob.client().clock().now_unix_ms()),
            };
            // What this device synced before still tells a rolled-back server
            if let (Some(prev), false) = (self.state.clone().flatten(), opts.accept_server_state) {
                if state.revision >= 0 && state.revision < prev.revision {
                    return Err(OvError::new(
                        OvErrorCode::ServerRolledBack,
                        format!(
                            "the sync server returned revision {}, older than revision {} this device already synced",
                            state.revision, prev.revision
                        ),
                    ));
                }
                if state.generation < prev.generation {
                    return Err(OvError::new(
                        OvErrorCode::ServerRolledBack,
                        format!(
                            "the server copy has sync generation {}, older than {} already synced here",
                            state.generation, prev.generation
                        ),
                    ));
                }
            }
            if opts.rekey_to.is_none() {
                // Just downloaded and nothing to change: no second request (contract-v1.8)
                if let Some(cache) = &self.cache {
                    cache.save_state(&state).await?;
                }
                self.offline = false;
                self.db = Some(db.clone());
                self.key = Some(key.clone());
                self.state = Some(Some(state.clone()));
                let index = sorted.iter().position(|k| k.version == kv);
                return Ok(SyncResult {
                    outcome: SyncOutcome::Pulled,
                    db,
                    key,
                    credentials_index: index,
                    data: Some(data),
                    state,
                    conflicts: Vec::new(),
                    changes: Vec::new(),
                    attempts: 1,
                    clock_offset_ms: blob.clock_offset_ms(),
                });
            }
            self.key = Some(key);
            self.db = Some(db);
            fresh = Some(state);
        }
        let rekey = opts.rekey_to.map(|to| {
            move |db: &mut Database| -> Result<Option<CompositeKey>, OvError> {
                Ok(Some(ov_kdbx::vault::rekey_to_vault_key(db, to)?))
            }
        });
        let local_key = self.key.clone().expect("a key with the working copy");
        // A copy just downloaded for a re-keyed upload is its own base: upload against it
        let from_download = fresh.is_some();
        let state = fresh.or_else(|| self.state.clone().flatten());
        let mut o = SyncOptions::new(&local_key, &creds)
            .state(state.as_ref())
            .local_changed(opts.local_changed.unwrap_or(true))
            .accept_server_state(opts.accept_server_state && !from_download)
            .remote_is_base(opts.remote_is_base || from_download);
        if let Some(r) = &rekey {
            o = o.before_upload(r as &dyn BeforeUpload);
        }
        o.cancel = opts.cancel;
        let db = self.db.as_mut().expect("the working copy is open");
        let result = match sync_kdbx(blob, db, &o).await {
            Ok(r) => r,
            Err(e) => {
                if e.is_unreachable() {
                    self.offline = true;
                    // Keep local edits on this device (encrypted with the vault key) until an upload succeeds
                    if let Some(cache) = &self.cache {
                        if opts.local_changed != Some(false) || self.has_pending {
                            cache.save_pending(ov_kdbx::write(db, &local_key)?).await?;
                            self.has_pending = true;
                        }
                    }
                }
                return Err(e);
            }
        };
        self.offline = false;
        self.db = Some(result.db.clone());
        self.key = Some(result.key.clone());
        self.state = Some(Some(result.state.clone()));
        if let Some(cache) = &self.cache {
            cache.save_state(&result.state).await?;
            if self.has_pending {
                cache.clear_pending().await?;
            }
        }
        self.has_pending = false;
        Ok(result)
    }

    /// Downloads the server copy as the working copy, with a sync state whose base is that copy (TS
    /// `ServiceAccount.download`): one GET, no merge. For a session without local edits to keep (a
    /// service account's); the working copy, its key and the state are replaced. `not_found` when the
    /// server has no copy.
    pub async fn download(
        &mut self,
        blob: &Blob,
        keys: &[KeyVersion],
        cancel: Option<&dyn Cancel>,
    ) -> Result<SyncResult, OvError> {
        if cancel.is_some_and(|c| c.is_cancelled()) {
            return Err(OvError::new(OvErrorCode::Aborted, "the sync was cancelled"));
        }
        let (sorted, _) = credentials(keys)?;
        let got = match blob.get(None).await {
            Ok(g) => g,
            Err(e) => {
                if e.is_unreachable() {
                    self.offline = true;
                }
                return Err(e);
            }
        };
        let GetResult::Ok { data, version } = got else {
            return Err(
                OvError::new(OvErrorCode::NotFound, "this vault has no data on the sync server").with_status(404)
            );
        };
        let (db, kv) = open_with_key_versions(&data, &sorted)?;
        let k = sorted.iter().find(|k| k.version == kv).expect("the version that opened it");
        let key = vault_credentials(&k.key)?;
        let index = sorted.iter().position(|k| k.version == kv);
        let state = SyncState {
            etag: version.etag.clone(),
            revision: version.revision.unwrap_or(-1),
            generation: ov_kdbx::vault::sync_generation(&db),
            snapshot: ov_merge::snapshot_of(&db),
            base: Some(data.clone()),
            last_sync: iso_time(blob.client().clock().now_unix_ms()),
        };
        if let Some(cache) = &self.cache {
            cache.save_state(&state).await?;
        }
        self.offline = false;
        self.db = Some(db.clone());
        self.key = Some(key.clone());
        self.state = Some(Some(state.clone()));
        Ok(SyncResult {
            outcome: SyncOutcome::Pulled,
            db,
            key,
            credentials_index: index,
            data: Some(data),
            state,
            conflicts: Vec::new(),
            changes: Vec::new(),
            attempts: 1,
            clock_offset_ms: blob.clock_offset_ms(),
        })
    }

    /// Makes the working copy durable before anything is sent (Swift `keepEdits`): it goes to the
    /// cache as `pending` until a sync uploads it. Does nothing without a cache or a working copy.
    pub async fn keep_edits(&mut self) -> Result<(), OvError> {
        let (Some(cache), Some(db), Some(key)) = (&self.cache, &self.db, &self.key) else { return Ok(()) };
        cache.save_pending(ov_kdbx::write(db, key)?).await?;
        self.has_pending = true;
        Ok(())
    }

    /// Offline open (TS `openLocalCopy`): local edits not yet uploaded, else the server's bytes at
    /// the last sync. `cause` is the network error to report when there is neither
    /// (`not_available_offline`).
    pub async fn open_local_copy(
        &mut self,
        keys: &[KeyVersion],
        vault_name: &str,
        cause: &OvError,
    ) -> Result<(), OvError> {
        self.offline = true;
        if self.db.is_some() {
            return Ok(());
        }
        self.ensure_state().await?;
        let (sorted, _) = credentials(keys)?;
        if let Some((db, key)) = self.open_pending(&sorted).await? {
            self.db = Some(db);
            self.key = Some(key);
            return Ok(());
        }
        let Some(base) = self.state().and_then(|s| s.base.clone()) else {
            return Err(OvError::new(
                OvErrorCode::NotAvailableOffline,
                format!("vault \"{vault_name}\" was never synced on this device, so it can't be opened offline"),
            )
            .with_details(serde_json::json!({ "cause": cause.wire_code() }).to_string()));
        };
        let (db, version) = open_with_key_versions(&base, &sorted)?;
        let k = sorted.iter().find(|k| k.version == version).expect("the version that opened it");
        self.key = Some(vault_credentials(&k.key)?);
        self.db = Some(db);
        Ok(())
    }
}
