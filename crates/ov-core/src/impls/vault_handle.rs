//! Helpers behind [`Vault`]: the clock, the source checks and the working copy lock.

use std::sync::MutexGuard;

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::model::{Database, Timestamp};

use super::util::lock;
use crate::api::{Vault, VaultInfo};
use crate::state::VaultSource;

impl Vault {
    pub(crate) fn db(&self) -> MutexGuard<'_, Database> {
        lock(&self.inner.db)
    }

    /// KDBX time (Unix seconds) from the Host clock; for a local file opened without a Host, the
    /// system clock (native) or one second after the newest time in the file (wasm32, which has no
    /// clock of its own).
    pub(crate) fn now(&self) -> Timestamp {
        if let Some(h) = &self.inner.host {
            return h.clock.now_unix_ms().div_euclid(1000);
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db();
            db.root.times.last_modification.max(db.meta.settings_changed.unwrap_or(0)) + 1
        }
    }

    /// `invalid_request` for an old version from history.
    pub(crate) fn writable(&self) -> Result<(), OvError> {
        if matches!(self.inner.source, VaultSource::Version { .. }) {
            return Err(OvError::new(OvErrorCode::InvalidRequest, "an old version is read-only"));
        }
        Ok(())
    }

    /// Edits the working copy (refused for read-only versions).
    pub(crate) fn edit<T>(&self, f: impl FnOnce(&mut Database, Timestamp) -> Result<T, OvError>) -> Result<T, OvError> {
        self.writable()?;
        let now = self.now();
        f(&mut self.db(), now)
    }

    pub(crate) fn vault_info(&self) -> Option<VaultInfo> {
        match &self.inner.source {
            VaultSource::Local(_) => None,
            VaultSource::Account { info, .. } => Some(lock(info).clone()),
            VaultSource::Version { info } | VaultSource::ServiceAccount { info } => Some(info.clone()),
        }
    }
}

impl Vault {
    /// Keeps the working copy on this device, encrypted with the vault's newest key, as the pending
    /// edits of the offline cache (SPEC §20). Local files and versions keep nothing.
    pub(crate) async fn keep_edits_impl(&self) -> Result<(), OvError> {
        let VaultSource::Account { account, info } = &self.inner.source else { return Ok(()) };
        if !account.keeps_offline_data() {
            return Ok(());
        }
        let vault_id = lock(info).id.clone();
        let user = account.current_user().ok_or_else(|| super::util::signed_out("not signed in"))?;
        let e = account.entry_offline(&vault_id).await?;
        let key = super::vaults::newest_key(&e.keys)?;
        let db = self.db().clone();
        let bytes = ov_kdbx::write(&db, &ov_kdbx::vault::vault_credentials(&key.key)?)?;
        let host = account.host();
        let mut cached = host.cache.load(&user, &vault_id).await?.unwrap_or(crate::host::CachedVault {
            state: Vec::new(),
            base: lock(&self.inner.base).clone(),
            pending: None,
            autofill: None,
        });
        cached.pending = Some(bytes);
        host.cache.save(&user, &vault_id, &cached).await
    }
}
