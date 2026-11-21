//! contract-v1.8 for C++ (docs/adr/0001-contract.md § contract-v1.8): sharing to confirmed keys,
//! self-hosted download, and a service account's vault files. The behaviour changes need no new
//! bridge functions; `Profile` grew `kdf` and `public_keys`.

use crate::convert;
use crate::edge::{run, FfiError};
use crate::ffi;
use crate::handles::{Account, CancelToken};
use crate::more::{SelfHosted, ServiceAccount};
use crate::records as rec;
use crate::v16::{kdbx_credentials_out, sync_options_in};

type R<T> = Result<T, FfiError>;

impl Account {
    /// [`ov_core::api::Account::share_vault_with_keys`].
    pub fn share_vault_with_keys(
        &self,
        vault_id: &str,
        grantee: &ffi::Grantee,
        role: ffi::VaultRole,
        keys: &ffi::PublicKeys,
        cancel: &CancelToken,
    ) -> R<ffi::GrantResult> {
        run(cancel, |c| async move {
            let grantee = rec::grantee_in(grantee)?;
            let role = rec::vault_role_in(role)?;
            let keys = rec::public_keys_in(keys);
            self.0.share_vault_with_keys(vault_id.into(), grantee, role, keys, c).await.map(rec::grant_result)
        })
    }
}

impl SelfHosted {
    /// [`ov_core::api::SelfHosted::download`].
    pub fn download(&self, database_id: &str, cancel: &CancelToken) -> R<ffi::OptionalBytes> {
        run(cancel, |c| async move { self.0.download(database_id.into(), c).await.map(rec::opt_bytes) })
    }
}

impl ServiceAccount {
    /// [`ov_core::api::ServiceAccount::vault_kdbx_credentials`].
    pub fn vault_kdbx_credentials(&self, vault_id: &str, cancel: &CancelToken) -> R<ffi::KdbxCredentials> {
        run(
            cancel,
            |c| async move { self.0.vault_kdbx_credentials(vault_id.into(), c).await.map(kdbx_credentials_out) },
        )
    }

    /// [`ov_core::api::ServiceAccount::sync_vault_kdbx`]; `has_base == false` is no base.
    pub fn sync_vault_kdbx(
        &self,
        vault_id: &str,
        kdbx: Vec<u8>,
        has_base: bool,
        base: Vec<u8>,
        options: ffi::SyncOptions,
        cancel: &CancelToken,
    ) -> R<ffi::VaultKdbxSyncResult> {
        run(cancel, |c| async move {
            let base = has_base.then_some(base);
            let r = self.0.sync_vault_kdbx(vault_id.into(), kdbx, base, sync_options_in(options), c).await?;
            Ok(ffi::VaultKdbxSyncResult {
                kdbx: r.kdbx,
                credentials: kdbx_credentials_out(r.credentials),
                report: convert::sync_report(r.report),
            })
        })
    }
}
