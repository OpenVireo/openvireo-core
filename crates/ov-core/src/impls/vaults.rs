//! Account vaults on the facade: opening (online, offline, from history), creating, importing,
//! renaming and deleting, pending edits and AutoFill edits (SPEC §7, §11, §20). Syncing is
//! `ov-sync`'s (through [`syncing`](super::syncing)); new vaults and grants are `ov-vault`'s.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use ov_crypto::encoding::to_hex;
use ov_error::{OvError, OvErrorCode};
use ov_kdbx::model::{Database, Uuid};
use ov_kdbx::vault::{open_with_key_versions, vault_credentials, KeyVersion};

use super::kdbx_ops;
use super::keyring::VaultEntry;
use super::util::{lock, signed_out};
use crate::api::{
    Account, AutoFillEdit, AutoFillEdits, CancelToken, EntryRecord, ImportMode, ImportOutcome, KdbxCredentials,
    SyncOptions, Vault, VaultInfo, VaultVersion,
};
use crate::host::{CachedVault, Host};
use crate::state::{VaultSource, VaultState};

/// A vault handle over a working copy.
pub(crate) fn new_vault(
    source: VaultSource,
    host: Option<Host>,
    db: Database,
    offline: bool,
    cache: Option<ov_sync::VaultCache>,
) -> Vault {
    Vault {
        inner: Arc::new(VaultState {
            source,
            host,
            db: Mutex::new(db),
            offline: AtomicBool::new(offline),
            etag: Mutex::new(None),
            conflicts: Mutex::new(Vec::new()),
            session: futures::lock::Mutex::new(ov_sync::VaultSession::new(cache)),
        }),
    }
}

/// Opens local `.kdbx` credentials.
pub(crate) fn local_key(c: &KdbxCredentials) -> Result<ov_kdbx::CompositeKey, OvError> {
    let password = c
        .password
        .as_ref()
        .map(|p| String::from_utf8(p.clone()))
        .transpose()
        .map_err(|_| OvError::new(OvErrorCode::InvalidRequest, "the database password is not UTF-8"))?;
    let password = password.map(zeroize::Zeroizing::new);
    Ok(ov_kdbx::vault::password_credentials(password.as_deref().map(String::as_str), c.key_file.as_deref()))
}

/// The newest key's credentials.
pub(crate) fn newest_key(keys: &[KeyVersion]) -> Result<&KeyVersion, OvError> {
    keys.iter().max_by_key(|k| k.version).ok_or_else(|| OvError::new(OvErrorCode::NoVaultKey, "no vault key available"))
}

impl Account {
    fn account_vault(&self, info: VaultInfo, db: Database, offline: bool) -> Vault {
        let cache = self.vault_cache(&info.id);
        new_vault(
            VaultSource::Account { account: self.clone(), info: Mutex::new(info) },
            Some(self.host().clone()),
            db,
            offline,
            cache,
        )
    }

    /// This device's copy: pending edits, else the server's bytes at the last sync.
    async fn local_copy(&self, e: &VaultEntry, with_autofill: bool) -> Result<Database, OvError> {
        let user = self.current_user().ok_or_else(|| signed_out("not signed in"))?;
        let cached = self.host().cache.load(&user, &e.info.id).await?;
        let not_offline = || {
            let name = if e.info.name.is_empty() { e.info.id.clone() } else { e.info.name.clone() };
            OvError::new(
                OvErrorCode::NotAvailableOffline,
                format!("vault \"{name}\" was never synced on this device, so it can't be opened offline"),
            )
        };
        let cached = cached.ok_or_else(not_offline)?;
        let mut db = match (&cached.pending, &cached.base) {
            (Some(p), _) => match open_with_key_versions(p, e.keys()) {
                Ok((db, _)) => db,
                Err(_) => open_with_key_versions(cached.base.as_ref().ok_or_else(not_offline)?, e.keys())?.0,
            },
            (None, Some(b)) => open_with_key_versions(b, e.keys())?.0,
            (None, None) => return Err(not_offline()),
        };
        if with_autofill {
            if let Some(edits) = self.autofill_from(&e.info.id, &cached, e.keys())? {
                let now = self.now_ms() / 1000;
                for ed in &edits.entries {
                    kdbx_ops::upsert_record(&mut db, &ed.entry, &ed.group_path, now)?;
                }
            }
        }
        Ok(db)
    }

    pub(crate) async fn open_vault_impl(&self, vault_id: &str, cancel: &CancelToken) -> Result<Vault, OvError> {
        let e = self.entry(vault_id, cancel).await?;
        super::syncing::open_session(self, &e, cancel).await
    }

    pub(crate) async fn open_offline_impl(&self, vault_id: &str, with_autofill: bool) -> Result<Vault, OvError> {
        let e = self.entry_offline(vault_id).await?;
        let db = self.local_copy(&e, with_autofill).await?;
        Ok(self.account_vault(e.info, db, true))
    }

    /// `POST /vaults` with key version 1 sealed to this account (and an org's confirmed owners and
    /// admins); no blob yet. Returns the entry and the new key.
    pub(crate) async fn register_vault(
        &self,
        name: &str,
        org_id: Option<&str>,
        cancel: &CancelToken,
    ) -> Result<(VaultEntry, zeroize::Zeroizing<[u8; 32]>), OvError> {
        let me = self.principal_str()?;
        let members = match org_id {
            Some(org) => Some(
                self.call(cancel, |a, t| a.build_list_members(t, org), ov_protocol::auth::parse_members).await?.members,
            ),
            None => None,
        };
        let nv = {
            let g = lock(&self.inner.inner);
            let ks = g.keyset.as_ref().ok_or_else(|| signed_out("the account is locked"))?;
            let org = org_id.zip(members.as_deref());
            ov_vault::new_vault(name, &me, ks, org)?
        };
        let created =
            self.call(cancel, |a, t| a.build_create_vault(t, &nv.request), ov_protocol::auth::parse_vault).await?;
        let listed = nv.listing(created);
        self.cache_vault(&listed).await?;
        let entry = self.ingest(&listed)?;
        // The new vault is only in the next token's vlt claim.
        self.refresh_token(cancel).await?;
        Ok((entry, zeroize::Zeroizing::new(*nv.key)))
    }

    pub(crate) async fn create_vault_impl(
        &self,
        name: &str,
        org_id: Option<&str>,
        cancel: &CancelToken,
    ) -> Result<Vault, OvError> {
        let (entry, key) = self.register_vault(name, org_id, cancel).await?;
        let (db, _) = ov_kdbx::vault::create_vault_kdbx(name, &key[..], self.now_ms() / 1000)?;
        let v = self.account_vault(entry.info, db, false);
        v.sync(SyncOptions::default(), cancel.clone()).await?;
        Ok(v)
    }

    pub(crate) async fn import_db(
        &self,
        source: Database,
        mode: ImportMode,
        cancel: &CancelToken,
    ) -> Result<ImportOutcome, OvError> {
        self.with_keyset(|_| ())?;
        let now = self.now_ms() / 1000;
        let vault = match mode {
            ImportMode::NewVault { name, org_id } => {
                let mut copy = ov_kdbx::vault::copy_kdbx(&source);
                let name = name
                    .map(|n| n.trim().to_owned())
                    .filter(|n| !n.is_empty())
                    .or_else(|| Some(copy.root.name.trim().to_owned()).filter(|n| !n.is_empty()))
                    .unwrap_or_else(|| "Imported".to_owned());
                ov_kdbx::vault::drop_server_remotes(&mut copy);
                let (entry, key) = self.register_vault(&name, org_id.as_deref(), cancel).await?;
                ov_kdbx::vault::rekey_to_vault_key(&mut copy, &key[..])?;
                copy.root.name = name;
                copy.root.times.last_modification = now;
                self.account_vault(entry.info, copy, false)
            }
            ImportMode::Merge { vault_id } => {
                let v = self.open_vault_impl(&vault_id, cancel).await?;
                ov_merge::import_into(&source, &mut lock(&v.inner.db));
                v
            }
            ImportMode::Copies { vault_id } => {
                let v = self.open_vault_impl(&vault_id, cancel).await?;
                let mut ids = fresh_uuids(&source)?;
                {
                    let mut db = lock(&v.inner.db);
                    let root = db.root.uuid;
                    ov_merge::import_as_copies(&source, &mut db, root, now, &mut || {
                        ids.pop().unwrap_or_else(Uuid::nil)
                    })?;
                }
                v
            }
        };
        match vault.sync(SyncOptions::default(), cancel.clone()).await {
            Ok(report) => Ok(ImportOutcome { vault, uploaded: true, upload_error: None, report: Some(report) }),
            Err(e) => {
                // The import stays on this device until a sync uploads it.
                let _ = vault.keep_edits().await;
                let mut err = OvError::new(
                    OvErrorCode::VaultUploadFailed,
                    format!("the vault was created, but its first upload failed: {}", e.message),
                );
                err.status = e.status;
                Ok(ImportOutcome { vault, uploaded: false, upload_error: Some(err), report: None })
            }
        }
    }

    pub(crate) async fn rename_vault_impl(
        &self,
        vault_id: &str,
        name: &str,
        cancel: &CancelToken,
    ) -> Result<VaultInfo, OvError> {
        let e = self.entry(vault_id, cancel).await?;
        let enc = ov_crypto::vault_name::encrypt_vault_name(&*e.current_key_bytes()?, vault_id, name)?;
        let v =
            self.call(cancel, |a, t| a.build_rename_vault(t, vault_id, &enc), ov_protocol::auth::parse_vault).await?;
        self.cache_vault(&v).await?;
        Ok(self.ingest(&v)?.info)
    }

    pub(crate) async fn delete_vault_impl(&self, vault_id: &str, cancel: &CancelToken) -> Result<(), OvError> {
        cancel.check()?;
        match self.sync_client().vault(vault_id).delete(None).await {
            Ok(()) => {}
            Err(e) if e.is(OvErrorCode::NotFound) => {}
            Err(e) => return Err(e),
        }
        self.call(cancel, |a, t| a.build_delete_vault(t, vault_id), ov_protocol::parse_empty).await?;
        lock(&self.inner.inner).vaults.remove(vault_id);
        if let Some(user) = self.current_user() {
            if self.keeps_offline_data() {
                self.host().cache.remove(&user, vault_id).await?;
                if let Some(mut list) = self.cached_wire_vaults().await? {
                    list.retain(|v| v.id != vault_id);
                    self.host()
                        .cache
                        .save_meta(&user, super::account::META_VAULTS, &super::util::to_json(&list))
                        .await?;
                }
            }
        }
        self.refresh_token(cancel).await
    }

    pub(crate) async fn pending_for(&self, vault_id: Option<&str>) -> Result<bool, OvError> {
        let Some(user) = self.current_user() else { return Ok(false) };
        let ids = match vault_id {
            Some(id) => vec![id.to_owned()],
            None => self.host().cache.list(&user).await?,
        };
        for id in ids {
            if self.host().cache.load(&user, &id).await?.is_some_and(|c| c.pending.is_some()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) async fn history_impl(
        &self,
        vault_id: &str,
        cancel: &CancelToken,
    ) -> Result<Vec<VaultVersion>, OvError> {
        cancel.check()?;
        let list = self.sync_client().vault(vault_id).history().await?;
        let newest = list.iter().map(|b| b.revision).max();
        Ok(list
            .into_iter()
            .map(|b| VaultVersion {
                is_current: Some(b.revision) == newest,
                revision: b.revision.max(0) as u64,
                etag: b.etag,
                size: Some(b.size),
                saved_at: Some(b.updated_at),
            })
            .collect())
    }

    pub(crate) async fn open_version_impl(
        &self,
        vault_id: &str,
        revision: u64,
        cancel: &CancelToken,
    ) -> Result<Vault, OvError> {
        let e = self.entry(vault_id, cancel).await?;
        let rev =
            i64::try_from(revision).map_err(|_| OvError::new(OvErrorCode::InvalidRequest, "revision out of range"))?;
        cancel.check()?;
        let r = self.sync_client().vault(vault_id).revision(rev).await?;
        let (db, _) = open_with_key_versions(&r.data, e.keys())?;
        let v = new_vault(VaultSource::Version { info: e.info }, Some(self.host().clone()), db, false, None);
        *lock(&v.inner.etag) = Some(r.version.etag);
        Ok(v)
    }

    // ------------------------------------------------------------------ AutoFill

    fn autofill_from(
        &self,
        vault_id: &str,
        cached: &CachedVault,
        keys: &[KeyVersion],
    ) -> Result<Option<AutoFillEdits>, OvError> {
        let Some(bytes) = &cached.autofill else { return Ok(None) };
        let (db, _) = open_with_key_versions(bytes, keys)?;
        let entries = kdbx_ops::entries(&db, true)
            .into_iter()
            .map(|s| {
                let rec = kdbx_ops::entry(&db, &s.id)?;
                Ok(AutoFillEdit { group_path: s.group_path.join("/"), entry: rec })
            })
            .collect::<Result<Vec<_>, OvError>>()?;
        Ok(Some(AutoFillEdits {
            vault_id: vault_id.to_owned(),
            entries,
            version: to_hex(&ov_crypto::primitives::sha256(bytes)),
        }))
    }

    pub(crate) async fn keep_autofill_impl(
        &self,
        vault_id: &str,
        entry: EntryRecord,
        group_path: &str,
    ) -> Result<(), OvError> {
        let e = self.entry_offline(vault_id).await?;
        let user = self.current_user().ok_or_else(|| signed_out("not signed in"))?;
        let key = newest_key(e.keys())?;
        let now = self.now_ms() / 1000;
        let mut cached = self.host().cache.load(&user, vault_id).await?.unwrap_or(CachedVault {
            state: Vec::new(),
            base: None,
            pending: None,
            autofill: None,
        });
        let mut db = match &cached.autofill {
            Some(b) => open_with_key_versions(b, e.keys())?.0,
            None => ov_kdbx::vault::create_vault_kdbx("AutoFill", &key.key, now)?.0,
        };
        kdbx_ops::upsert_record(&mut db, &entry, group_path, now)?;
        cached.autofill = Some(ov_kdbx::write(&db, &vault_credentials(&key.key)?)?);
        self.host().cache.save(&user, vault_id, &cached).await
    }

    pub(crate) async fn autofill_edits_impl(&self, vault_id: &str) -> Result<Option<AutoFillEdits>, OvError> {
        let e = self.entry_offline(vault_id).await?;
        let user = self.current_user().ok_or_else(|| signed_out("not signed in"))?;
        match self.host().cache.load(&user, vault_id).await? {
            Some(c) => self.autofill_from(vault_id, &c, e.keys()),
            None => Ok(None),
        }
    }

    pub(crate) async fn clear_autofill_impl(&self, edits: &AutoFillEdits) -> Result<(), OvError> {
        let user = self.current_user().ok_or_else(|| signed_out("not signed in"))?;
        let Some(mut c) = self.host().cache.load(&user, &edits.vault_id).await? else { return Ok(()) };
        let same = c.autofill.as_ref().is_some_and(|b| to_hex(&ov_crypto::primitives::sha256(b)) == edits.version);
        if same {
            c.autofill = None;
            self.host().cache.save(&user, &edits.vault_id, &c).await?;
        }
        Ok(())
    }
}

/// Enough fresh UUIDs for every entry (with history) and group of `source`, drawn up front.
fn fresh_uuids(source: &Database) -> Result<Vec<Uuid>, OvError> {
    fn count(g: &ov_kdbx::model::Group) -> usize {
        1 + g.entries.iter().map(|e| 1 + e.history.len()).sum::<usize>() + g.groups.iter().map(count).sum::<usize>()
    }
    (0..count(&source.root) + 1).map(|_| ov_kdbx::vault::new_uuid()).collect()
}
