//! Account vaults held as `.kdbx` bytes by the platform (the desktop keeps its KeePassXC `Database`
//! and serializes it), contract-v1.6: the vault key as file credentials, and a whole-file sync on
//! `ov_sync::sync_kdbx`, as [`sync_database`](super::syncing::sync_database) does for self-hosted
//! databases. The sync state lives in the BlobCache record `kdbx-file:<vault id>` when the account
//! keeps offline data.

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::vault::{open_with_key_versions, vault_credentials, KeyVersion};
use ov_sync::SyncState;

use super::keyring::VaultEntry;
use super::syncing::{report, CancelWrap};
use super::vaults::newest_key;
use crate::api::{Account, CancelToken, KdbxCredentials, ServiceAccount, SyncOptions, VaultKdbxSyncResult};

/// Whose vault file: an account's (offline cache, session end) or a service account's (contract-v1.8).
enum Owner<'a> {
    Account(&'a Account),
    Sa(&'a ServiceAccount),
}

impl Owner<'_> {
    async fn entry(&self, vault_id: &str, cancel: &CancelToken) -> Result<VaultEntry, OvError> {
        match self {
            Owner::Account(a) => a.entry(vault_id, cancel).await,
            Owner::Sa(sa) => sa.entry(vault_id, cancel).await,
        }
    }

    fn client(&self) -> ov_sync::SyncClient {
        match self {
            Owner::Account(a) => a.sync_client(),
            Owner::Sa(sa) => sa.sync_client(),
        }
    }

    async fn refresh(&self, cancel: &CancelToken) -> Result<(), OvError> {
        match self {
            Owner::Account(a) => a.refresh_token(cancel).await,
            Owner::Sa(sa) => sa.access_token(true, cancel).await.map(|_| ()),
        }
    }
}

fn file_credentials(k: &KeyVersion) -> KdbxCredentials {
    KdbxCredentials { password: None, key_file: Some(k.key.to_vec()), password_hash: None }
}

pub(crate) async fn credentials(a: &Account, vault_id: &str, cancel: &CancelToken) -> Result<KdbxCredentials, OvError> {
    owner_credentials(Owner::Account(a), vault_id, cancel).await
}

pub(crate) async fn sa_credentials(
    sa: &ServiceAccount,
    vault_id: &str,
    cancel: &CancelToken,
) -> Result<KdbxCredentials, OvError> {
    owner_credentials(Owner::Sa(sa), vault_id, cancel).await
}

async fn owner_credentials(o: Owner<'_>, vault_id: &str, cancel: &CancelToken) -> Result<KdbxCredentials, OvError> {
    cancel.check()?;
    let e = o.entry(vault_id, cancel).await?;
    Ok(file_credentials(newest_key(e.keys())?))
}

pub(crate) async fn sync(
    a: &Account,
    vault_id: &str,
    kdbx: Vec<u8>,
    base: Option<Vec<u8>>,
    options: SyncOptions,
    cancel: &CancelToken,
) -> Result<VaultKdbxSyncResult, OvError> {
    owner_sync(Owner::Account(a), vault_id, kdbx, base, options, cancel).await
}

pub(crate) async fn sa_sync(
    sa: &ServiceAccount,
    vault_id: &str,
    kdbx: Vec<u8>,
    base: Option<Vec<u8>>,
    options: SyncOptions,
    cancel: &CancelToken,
) -> Result<VaultKdbxSyncResult, OvError> {
    owner_sync(Owner::Sa(sa), vault_id, kdbx, base, options, cancel).await
}

async fn owner_sync(
    o: Owner<'_>,
    vault_id: &str,
    kdbx: Vec<u8>,
    base: Option<Vec<u8>>,
    options: SyncOptions,
    cancel: &CancelToken,
) -> Result<VaultKdbxSyncResult, OvError> {
    cancel.check()?;
    let e = o.entry(vault_id, cancel).await?;
    let keys = e.keys().to_vec();
    let (db, _) = open_with_key_versions(&kdbx, &keys)?;
    drop(kdbx);
    let mut newest: Vec<&KeyVersion> = keys.iter().collect();
    newest.sort_by_key(|k| std::cmp::Reverse(k.version));
    let creds = newest.iter().map(|k| vault_credentials(&k.key)).collect::<Result<Vec<_>, _>>()?;
    let local_key = creds.first().ok_or_else(|| OvError::new(OvErrorCode::NoVaultKey, "no vault key available"))?;

    // Its own record: the file and a `Vault` handle of the same vault are separate working copies.
    let cache = match &o {
        Owner::Account(a) => a.vault_cache(&format!("kdbx-file:{vault_id}")),
        Owner::Sa(_) => None,
    };
    let mut state = match &cache {
        Some(c) => c.load_state().await?,
        None => None,
    };
    if let Some(b) = base {
        match &mut state {
            Some(s) => s.base = Some(b),
            None => {
                state = Some(SyncState {
                    etag: String::new(),
                    revision: -1,
                    generation: 0,
                    snapshot: Default::default(),
                    base: Some(b),
                    last_sync: String::new(),
                })
            }
        }
    }

    let mut attempt = 0;
    let r = loop {
        let client = o.client();
        let blob = client.vault(vault_id);
        let cw = CancelWrap(cancel.clone());
        let mut opts = ov_sync::SyncOptions::new(local_key, &creds)
            .state(state.as_ref())
            .local_changed(options.local_changed)
            .accept_server_state(options.accept_server_state);
        opts.cancel = Some(&cw);
        let mut work = db.clone();
        let result = ov_sync::sync_kdbx(&blob, &mut work, &opts).await;
        if let Owner::Account(a) = &o {
            a.note_clock(blob.clock_offset_ms());
        }
        match result {
            Err(err) if err.is(OvErrorCode::Forbidden) && attempt == 0 => {
                // A vault shared since the token was issued isn't in its `vlt` claim yet: refresh once.
                attempt += 1;
                o.refresh(cancel).await?;
            }
            Err(err) => {
                if let Owner::Account(a) = &o {
                    if err.is(OvErrorCode::SignedOut) && err.status.is_some() {
                        a.session_ended(&err).await;
                    }
                    if err.is_unreachable() {
                        a.set_offline(true);
                    }
                }
                return Err(err);
            }
            Ok(r) => {
                if let Owner::Account(a) = &o {
                    a.set_offline(false);
                }
                break r;
            }
        }
    };
    if let Some(c) = &cache {
        c.save_state(&r.state).await?;
    }
    let used = r.credentials_index.and_then(|i| newest.get(i).copied()).unwrap_or(newest[0]);
    let out = ov_kdbx::write(&r.db, &r.key)?;
    Ok(VaultKdbxSyncResult { kdbx: out, credentials: file_credentials(used), report: report(&r) })
}
