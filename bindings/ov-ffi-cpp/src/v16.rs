//! contract-v1.6 for C++ (docs/adr/0001-contract.md § contract-v1.6): local files on the Host clock,
//! file metadata and KDFs, copies without remotes, entries with chosen ids, attachment flags, every
//! record in one call, imports between open vaults, self-hosted history and the SA's server.

use ov_core::api as core;
use ov_error::OvError;

use crate::convert::{self, kdbx_credentials, merge_change};
use crate::edge::{edge, run, FfiError};
use crate::ffi;
use crate::handles::{CancelToken, Client, Vault};
use crate::more::{SelfHosted, ServiceAccount};
use crate::records::{self as rec, bad_enum, some};

type R<T> = Result<T, FfiError>;

fn boxed(v: core::Vault) -> Box<Vault> {
    Box::new(Vault(v))
}

pub(crate) fn kdbx_kdf_in(k: ffi::KdbxKdf) -> Result<core::KdbxKdf, OvError> {
    Ok(match k.kind {
        ffi::KdbxKdfKind::DatabaseDefault => core::KdbxKdf::DatabaseDefault,
        ffi::KdbxKdfKind::Argon2d => {
            core::KdbxKdf::Argon2d { memory: k.memory, iterations: k.iterations, parallelism: k.parallelism }
        }
        ffi::KdbxKdfKind::Argon2id => {
            core::KdbxKdf::Argon2id { memory: k.memory, iterations: k.iterations, parallelism: k.parallelism }
        }
        ffi::KdbxKdfKind::AesKdf => core::KdbxKdf::AesKdf { rounds: k.rounds },
        other => return Err(bad_enum("KdbxKdfKind", other.repr)),
    })
}

pub(crate) fn local_import_mode_in(m: &ffi::LocalImportMode) -> Result<core::LocalImportMode, OvError> {
    Ok(match m.kind {
        ffi::LocalImportKind::Merge => core::LocalImportMode::Merge,
        ffi::LocalImportKind::Copies => core::LocalImportMode::Copies { parent_group_id: some(&m.parent_group_id) },
        other => return Err(bad_enum("LocalImportKind", other.repr)),
    })
}

pub(crate) fn import_summary(s: core::ImportSummary) -> ffi::ImportSummary {
    ffi::ImportSummary {
        added: s.added,
        updated: s.updated,
        unchanged: s.unchanged,
        groups_added: s.groups_added,
        changes: s.changes.into_iter().map(merge_change).collect(),
    }
}

impl Client {
    /// [`core::OvClient::open_local`].
    pub fn open_local(&self, kdbx: Vec<u8>, credentials: ffi::KdbxCredentials, cancel: &CancelToken) -> R<Box<Vault>> {
        run(cancel, |c| async move { self.0.open_local(kdbx, kdbx_credentials(credentials), c).await.map(boxed) })
    }

    /// [`core::OvClient::create_local`].
    pub fn create_local(&self, name: &str, credentials: ffi::KdbxCredentials, cancel: &CancelToken) -> R<Box<Vault>> {
        run(cancel, |c| async move {
            self.0.create_local(name.to_string(), kdbx_credentials(credentials), c).await.map(boxed)
        })
    }
}

impl Vault {
    /// [`core::Vault::set_name`].
    pub fn set_name(&self, name: &str) -> R<()> {
        edge(|| self.0.set_name(name.into()))
    }

    /// [`core::Vault::set_kdf`].
    pub fn set_kdf(&self, kdf: ffi::KdbxKdf) -> R<()> {
        edge(|| self.0.set_kdf(kdbx_kdf_in(kdf)?))
    }

    /// [`core::Vault::copy_without_remotes`]; empty credentials keep a local file's own.
    pub fn copy_without_remotes(&self, credentials: ffi::KdbxCredentials) -> R<Box<Vault>> {
        edge(|| {
            let creds = (credentials.has_password || credentials.has_key_file).then(|| kdbx_credentials(credentials));
            self.0.copy_without_remotes(creds).map(boxed)
        })
    }

    /// [`core::Vault::meta_custom_data`].
    pub fn meta_custom_data(&self, key: &str) -> R<ffi::OptionalString> {
        edge(|| {
            let v = self.0.meta_custom_data(key.into());
            Ok(ffi::OptionalString { has: v.is_some(), value: v.unwrap_or_default() })
        })
    }

    /// [`core::Vault::set_meta_custom_data`].
    pub fn set_meta_custom_data(&self, key: &str, has_value: bool, value: &str) -> R<()> {
        edge(|| self.0.set_meta_custom_data(key.into(), has_value.then(|| value.to_string())))
    }

    /// [`core::Vault::entry_records`].
    pub fn entry_records(&self, include_recycle_bin: bool) -> R<Vec<ffi::EntryRecord>> {
        edge(|| Ok(self.0.entry_records(include_recycle_bin).into_iter().map(rec::entry_record).collect()))
    }

    /// [`core::Vault::add_entry_with_id`].
    pub fn add_entry_with_id(&self, entry_id: &str, group_id: &str, input: ffi::EntryInput) -> R<String> {
        edge(|| self.0.add_entry_with_id(entry_id.into(), group_id.into(), rec::entry_input(input)?))
    }

    /// [`core::Vault::set_attachment_with`].
    pub fn set_attachment_with(
        &self,
        entry_id: &str,
        name: &str,
        data: Vec<u8>,
        has_protected: bool,
        is_protected: bool,
    ) -> R<()> {
        edge(|| self.0.set_attachment_with(entry_id.into(), name.into(), data, has_protected.then_some(is_protected)))
    }

    /// [`core::Vault::import_from`].
    pub fn import_from(&self, source: &Vault, mode: &ffi::LocalImportMode) -> R<ffi::ImportSummary> {
        edge(|| self.0.import_from(source.0.clone(), local_import_mode_in(mode)?).map(import_summary))
    }

    /// [`core::Vault::import_preview`].
    pub fn import_preview(&self) -> R<ffi::ImportPreview> {
        edge(|| {
            let p = self.0.import_preview();
            Ok(ffi::ImportPreview { entries: p.entries, groups: p.groups })
        })
    }

    /// [`core::Vault::import_targets`].
    pub fn import_targets(&self) -> R<Vec<ffi::ImportTarget>> {
        edge(|| {
            Ok(self
                .0
                .import_targets()
                .into_iter()
                .map(|t| ffi::ImportTarget { group_id: t.group_id, path: t.path })
                .collect())
        })
    }

    /// [`core::Vault::export_kdbx_with`]; an empty `group_ids` exports every group.
    pub fn export_kdbx_with(
        &self,
        credentials: ffi::KdbxCredentials,
        group_ids: Vec<String>,
        kdf: ffi::KdbxKdf,
        cancel: &CancelToken,
    ) -> R<Vec<u8>> {
        run(cancel, |c| async move {
            let kdf = kdbx_kdf_in(kdf)?;
            self.0.export_kdbx_with(kdbx_credentials(credentials), rec::group_ids(group_ids), kdf, c).await
        })
    }
}

impl SelfHosted {
    /// [`core::SelfHosted::history`].
    pub fn history(&self, database_id: &str, cancel: &CancelToken) -> R<Vec<ffi::VaultVersion>> {
        run(cancel, |c| async move {
            Ok(self.0.history(database_id.into(), c).await?.into_iter().map(rec::vault_version).collect())
        })
    }

    /// [`core::SelfHosted::open_version`].
    pub fn open_version(
        &self,
        database_id: &str,
        revision: u64,
        credentials: ffi::KdbxCredentials,
        cancel: &CancelToken,
    ) -> R<Box<Vault>> {
        run(cancel, |c| async move {
            self.0.open_version(database_id.into(), revision, kdbx_credentials(credentials), c).await.map(boxed)
        })
    }
}

impl ServiceAccount {
    /// [`core::ServiceAccount::server_config`].
    pub fn server_config(&self) -> R<ffi::ServerConfig> {
        edge(|| Ok(convert::server_config_to_ffi(self.0.server_config())))
    }

    /// [`core::ServiceAccount::issuer`].
    pub fn issuer(&self) -> R<String> {
        edge(|| Ok(self.0.issuer()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ov_error::OvErrorCode;

    #[test]
    fn flattened_v16_inputs_map() {
        let k = ffi::KdbxKdf {
            kind: ffi::KdbxKdfKind::Argon2id,
            memory: 1 << 20,
            iterations: 3,
            parallelism: 2,
            rounds: 9,
        };
        assert_eq!(kdbx_kdf_in(k).unwrap(), core::KdbxKdf::Argon2id { memory: 1 << 20, iterations: 3, parallelism: 2 });
        let aes = ffi::KdbxKdf { kind: ffi::KdbxKdfKind::AesKdf, ..k };
        assert_eq!(kdbx_kdf_in(aes).unwrap(), core::KdbxKdf::AesKdf { rounds: 9 });
        let bad = ffi::KdbxKdf { kind: ffi::KdbxKdfKind { repr: 9 }, ..k };
        assert_eq!(kdbx_kdf_in(bad).unwrap_err().code, OvErrorCode::InvalidRequest);
        let m = ffi::LocalImportMode { kind: ffi::LocalImportKind::Copies, parent_group_id: String::new() };
        assert_eq!(local_import_mode_in(&m).unwrap(), core::LocalImportMode::Copies { parent_group_id: None });
        let m = ffi::LocalImportMode { kind: ffi::LocalImportKind::Merge, parent_group_id: "x".into() };
        assert_eq!(local_import_mode_in(&m).unwrap(), core::LocalImportMode::Merge);
    }
}
