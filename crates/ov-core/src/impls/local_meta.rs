//! Local-file operations behind [`Vault`] and [`OvClient`](crate::api::OvClient) added in
//! contract-v1.6: opening and creating local files (optionally on the Host clock), the database name,
//! KDF and custom data, copies without sync remotes, and importing one open vault into another. The
//! KDBX work is `ov_kdbx::vault`'s and the import `ov_merge`'s; this module only orchestrates.

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::model::{Argon2Type, Database, KdbxVersion, Uuid};

use super::convert::{merge_change, uuid_hex};
use super::kdbx_ops::parse_id;
use super::vaults::{fresh_uuids, local_key, new_vault};
use crate::api::{
    CancelToken, ImportPreview, ImportSummary, ImportTarget, KdbxCredentials, KdbxKdf, LocalImportMode, Vault,
};
use crate::host::Host;
use crate::state::VaultSource;

fn local_only(v: &Vault, what: &str) -> Result<(), OvError> {
    v.writable()?;
    match v.inner.source {
        VaultSource::Local(_) => Ok(()),
        _ => Err(OvError::new(OvErrorCode::InvalidRequest, format!("{what} is only for a local file"))),
    }
}

/// `Vault::open_local` / `OvClient::open_local`.
pub(crate) fn open_local(
    host: Option<Host>,
    kdbx: Vec<u8>,
    credentials: KdbxCredentials,
    cancel: &CancelToken,
) -> Result<Vault, OvError> {
    cancel.check()?;
    let key = local_key(&credentials)?;
    let db = ov_kdbx::read(&kdbx, &key).map_err(|e| {
        if e.is(OvErrorCode::VaultKeyMismatch) {
            OvError::new(OvErrorCode::KdbxError, "the password or key file is wrong")
        } else {
            e
        }
    })?;
    Ok(new_vault(VaultSource::Local(credentials), host, db, false, None))
}

/// `Vault::create_local` / `OvClient::create_local`: KDBX 4, ChaCha20, Argon2id.
pub(crate) fn create_local(
    host: Option<Host>,
    name: String,
    credentials: KdbxCredentials,
    cancel: &CancelToken,
) -> Result<Vault, OvError> {
    cancel.check()?;
    local_key(&credentials)?;
    let v = new_vault(VaultSource::Local(credentials), host, ov_kdbx::vault::create_kdbx(&name, 0)?, false, None);
    let now = v.now();
    let mut db = ov_kdbx::vault::create_kdbx(&name, now)?;
    db.header.cipher = ov_kdbx::model::Cipher::ChaCha20;
    if let ov_kdbx::model::Kdf::Argon2 { kind, .. } = &mut db.header.kdf {
        *kind = Argon2Type::Id;
    }
    *v.db() = db;
    Ok(v)
}

/// The model KDF for a [`KdbxKdf`] choice, with a fresh salt.
fn kdf_of(kdf: KdbxKdf) -> Result<ov_kdbx::model::Kdf, OvError> {
    match kdf {
        KdbxKdf::DatabaseDefault => ov_kdbx::vault::database_default_kdf(),
        KdbxKdf::Argon2d { memory, iterations, parallelism } => {
            ov_kdbx::vault::argon2_kdf(Argon2Type::D, memory, iterations, parallelism)
        }
        KdbxKdf::Argon2id { memory, iterations, parallelism } => {
            ov_kdbx::vault::argon2_kdf(Argon2Type::Id, memory, iterations, parallelism)
        }
        KdbxKdf::AesKdf { rounds } => ov_kdbx::vault::aes_kdf(rounds),
    }
}

/// Sets a database's KDF from a [`KdbxKdf`] choice.
pub(crate) fn apply_kdf(db: &mut Database, kdf: KdbxKdf) -> Result<(), OvError> {
    ov_kdbx::vault::set_kdf(db, kdf_of(kdf)?);
    Ok(())
}

pub(crate) fn set_kdf(v: &Vault, kdf: KdbxKdf) -> Result<(), OvError> {
    local_only(v, "changing the key derivation")?;
    let k = kdf_of(kdf)?;
    ov_kdbx::vault::set_kdf(&mut v.db(), k);
    Ok(())
}

fn is_v41(db: &Database) -> bool {
    db.header.version >= KdbxVersion { major: 4, minor: 1 }
}

pub(crate) fn set_name(v: &Vault, name: String) -> Result<(), OvError> {
    local_only(v, "renaming the database")?;
    v.edit(|db, now| {
        if db.meta.database_name != name {
            db.meta.database_name = name;
            db.meta.database_name_changed = Some(now);
        }
        Ok(())
    })
}

pub(crate) fn set_meta_custom_data(v: &Vault, key: String, value: Option<String>) -> Result<(), OvError> {
    if key.is_empty() {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "a custom data key can't be empty"));
    }
    v.edit(|db, now| {
        let stamp = is_v41(db).then_some(now);
        match value {
            Some(value) => ov_kdbx::vault::set_custom_data(&mut db.meta.custom_data, &key, &value, stamp),
            None => db.meta.custom_data.retain(|i| i.key != key),
        }
        Ok(())
    })
}

pub(crate) fn copy_without_remotes(v: &Vault, credentials: Option<KdbxCredentials>) -> Result<Vault, OvError> {
    let own = match &v.inner.source {
        VaultSource::Local(c) => Some(c.clone()),
        _ => None,
    };
    let is_local = own.is_some();
    let credentials = credentials.or(own).ok_or_else(|| {
        OvError::new(OvErrorCode::InvalidRequest, "a copy of an account vault needs a password or key file")
    })?;
    local_key(&credentials)?;
    let mut db = ov_kdbx::vault::copy_kdbx(&v.db());
    ov_kdbx::vault::drop_server_remotes(&mut db);
    if !is_local {
        // The vault KDF is light because a vault key is random; a password needs the real thing.
        apply_kdf(&mut db, KdbxKdf::DatabaseDefault)?;
    }
    Ok(new_vault(VaultSource::Local(credentials), v.inner.host.clone(), db, false, None))
}

pub(crate) fn import_preview(db: &Database) -> ImportPreview {
    let (entries, groups) = ov_merge::import_preview(db);
    ImportPreview {
        entries: u32::try_from(entries).unwrap_or(u32::MAX),
        groups: u32::try_from(groups).unwrap_or(u32::MAX),
    }
}

pub(crate) fn import_targets(db: &Database) -> Vec<ImportTarget> {
    ov_merge::import_targets(db).into_iter().map(|(id, path)| ImportTarget { group_id: uuid_hex(&id), path }).collect()
}

pub(crate) fn import_from(v: &Vault, source: Vault, mode: LocalImportMode) -> Result<ImportSummary, OvError> {
    v.writable()?;
    // Copy the source first: it may be this very vault (same lock).
    let source = source.db().clone();
    let summary = match mode {
        LocalImportMode::Merge => ov_merge::import_into(&source, &mut v.db()),
        LocalImportMode::Copies { parent_group_id } => {
            let mut ids = fresh_uuids(&source)?;
            v.edit(|db, now| {
                let parent = match parent_group_id.as_deref() {
                    Some(p) => parse_id(p)?,
                    None => db.root.uuid,
                };
                ov_merge::import_as_copies(&source, db, parent, now, &mut || ids.pop().unwrap_or_else(Uuid::nil))
            })?
        }
    };
    Ok(ImportSummary {
        added: summary.added,
        updated: summary.updated,
        unchanged: summary.unchanged,
        groups_added: summary.groups_added,
        changes: summary.changes.iter().map(merge_change).collect(),
    })
}
