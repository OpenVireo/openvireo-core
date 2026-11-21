//! [`Vault`]: one open KDBX database, either an account vault kept in sync with
//! `{sync}/vaults/{id}` (SPEC §7, §11, §20) or a local file.
//!
//! Edits are local until [`Vault::sync`] (except [`Vault::write_field`], which syncs, as the TS
//! `AccountVault.write` does). Entry and group ids are KDBX UUIDs as 32 lowercase hex digits; times
//! are KDBX Unix seconds. Field values cross as [`SecretBytes`].

use std::sync::Arc;

use ov_error::OvError;

use super::{AutoFillEdits, CancelToken, MergeChange, SecretBytes, SyncConflict, SyncOptions, SyncReport, VaultInfo};
use crate::state::VaultState;

/// An open vault. Cheap to clone; clones share the same working copy.
///
/// Port of the TS `AccountVault` (plus the kdbxweb operations the web app runs on its `db`) and the
/// Swift `OpenedVault` with the `Database` editing extensions.
#[derive(Clone)]
pub struct Vault {
    pub(crate) inner: Arc<VaultState>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vault { .. }")
    }
}

/// Credentials for a local or imported `.kdbx` (password and/or key file).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KdbxCredentials {
    /// The database password, UTF-8.
    pub password: Option<SecretBytes>,
    /// The key file's bytes (any KeePass key-file format).
    pub key_file: Option<SecretBytes>,
    /// Instead of `password`: its SHA-256, 32 bytes (the password component of the composite key,
    /// TS `passwordHash`). An app that keeps a database openable across reloads keeps this rather
    /// than the password. Setting both `password` and `password_hash`, or a hash that isn't 32 bytes,
    /// is `invalid_request`. Contract-v1.7.
    pub password_hash: Option<SecretBytes>,
}

impl std::fmt::Debug for KdbxCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdbxCredentials")
            .field("password", &self.password.is_some())
            .field("key_file", &self.key_file.is_some())
            .field("password_hash", &self.password_hash.is_some())
            .finish()
    }
}

/// An entry without field values, for lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrySummary {
    /// Entry UUID.
    pub id: String,
    /// The group it is in.
    pub group_id: String,
    /// Group names from below the root down to the entry's group.
    pub group_path: Vec<String>,
    /// `Title`.
    pub title: String,
    /// `UserName`.
    pub username: String,
    /// `URL`.
    pub url: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Names of protected fields.
    pub protected_fields: Vec<String>,
    /// Standard icon.
    pub icon_id: u32,
    /// Custom icon UUID.
    pub custom_icon: Option<String>,
    /// Last modification.
    pub modified_at: i64,
    /// Expiry, when it expires.
    pub expires_at: Option<i64>,
    /// In the Recycle Bin.
    pub in_recycle_bin: bool,
    /// `LastAccessTime`, when the entry was ever used (`UsageCount` > 0); `None` otherwise
    /// (contract-v1.6).
    pub last_access_at: Option<i64>,
    /// `UsageCount` (saturated to `u32`; contract-v1.6).
    pub usage_count: u32,
}

/// One string field of an entry. `Debug` hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldRecord {
    /// The field name (`Title`, `UserName`, `Password`, `URL`, `Notes`, or custom).
    pub name: String,
    /// The value.
    pub value: SecretBytes,
    /// Protected.
    pub protected: bool,
}

impl std::fmt::Debug for FieldRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldRecord").field("name", &self.name).field("protected", &self.protected).finish()
    }
}

/// An attachment's name and size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInfo {
    /// File name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Kept protected in memory (the KDBX 4 inner-header flag; contract-v1.6).
    pub protected: bool,
}

/// A whole entry with its field values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryRecord {
    /// Entry UUID.
    pub id: String,
    /// The group it is in.
    pub group_id: String,
    /// Group names from below the root down to the entry's group.
    pub group_path: Vec<String>,
    /// String fields in file order.
    pub fields: Vec<FieldRecord>,
    /// Tags.
    pub tags: Vec<String>,
    /// Standard icon.
    pub icon_id: u32,
    /// Custom icon UUID.
    pub custom_icon: Option<String>,
    /// Foreground colour (`#RRGGBB` or empty).
    pub foreground_color: String,
    /// Background colour.
    pub background_color: String,
    /// Override URL.
    pub override_url: String,
    /// Creation time.
    pub created_at: i64,
    /// Last modification.
    pub modified_at: i64,
    /// Expiry, when it expires.
    pub expires_at: Option<i64>,
    /// Attachments.
    pub attachments: Vec<AttachmentInfo>,
    /// Older versions kept.
    pub history_count: u32,
    /// Included in password health reports (KDBX 4.1 `QualityCheck`).
    pub quality_check: bool,
    /// `LastAccessTime`, when the entry was ever used (`UsageCount` > 0); `None` otherwise
    /// (contract-v1.6).
    pub last_access_at: Option<i64>,
    /// `UsageCount` (saturated to `u32`; contract-v1.6).
    pub usage_count: u32,
}

/// A group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    /// Group UUID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Parent group; `None` for the root.
    pub parent_id: Option<String>,
    /// Names from below the root down to this group.
    pub path: Vec<String>,
    /// Standard icon.
    pub icon_id: u32,
    /// Notes.
    pub notes: String,
    /// The Recycle Bin.
    pub is_recycle_bin: bool,
    /// Entries directly in it.
    pub entry_count: u32,
}

/// A field to set.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldInput {
    /// Field name; `username`, `password`, `url`, `notes`, `title` (any case) map to the standard
    /// fields.
    pub name: String,
    /// The value.
    pub value: SecretBytes,
    /// Store it protected; `None`: `Password` and custom fields are, the other standard ones aren't.
    pub protected: Option<bool>,
}

impl std::fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInput").field("name", &self.name).field("protected", &self.protected).finish()
    }
}

/// An entry's expiry in an edit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EntryExpiry {
    /// Leave it (a new entry doesn't expire).
    #[default]
    Keep,
    /// Doesn't expire.
    Never,
    /// Expires at this Unix time (seconds).
    At(i64),
}

/// Changes to an entry (or a new entry's contents). Editing pushes the old version to history first,
/// as KeePassXC does, and applies the history limits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryInput {
    /// Fields to set.
    pub fields: Vec<FieldInput>,
    /// Custom fields to remove.
    pub remove_fields: Vec<String>,
    /// New tags.
    pub tags: Option<Vec<String>>,
    /// New standard icon.
    pub icon_id: Option<u32>,
    /// New expiry.
    pub expiry: EntryExpiry,
    /// New foreground colour: `#RRGGBB`, or empty to clear (contract-v1.6). `invalid_request` for
    /// anything else.
    pub foreground_color: Option<String>,
    /// New background colour, as [`foreground_color`](Self::foreground_color) (contract-v1.6).
    pub background_color: Option<String>,
    /// Custom icon: `None` leaves it, `Some(None)` clears it, `Some(Some(id))` sets it to a custom
    /// icon of this database (from [`Vault::add_custom_icon`]; `not_found` otherwise). Contract-v1.6.
    pub custom_icon: Option<Option<String>>,
    /// The custom fields in this order, after the standard ones (`Title`, `UserName`, `Password`,
    /// `URL`, `Notes` keep their places). Custom fields not named here follow in their current order;
    /// names the entry doesn't have are ignored (contract-v1.6).
    pub field_order: Option<Vec<String>>,
}

/// Whether [`Vault::set_fields`] may create the entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CreateMode {
    /// The entry must exist (`entry_not_found`).
    #[default]
    MustExist,
    /// Create it (by title, under its group path) when missing.
    CreateIfMissing,
    /// Create it; `conflict` if it exists.
    CreateOnly,
}

/// What [`Vault::set_fields`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetFieldsResult {
    /// The entry now.
    pub entry: EntryRecord,
    /// It was created.
    pub created: bool,
}

/// How an entry in an old version compares with the vault now ([`Vault::version_difference`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersionDifference {
    /// The same as now.
    Same,
    /// Changed since (restoring it is an edit).
    Changed,
    /// In the Recycle Bin, or deleted for good, since.
    Deleted,
}

/// Unencrypted export formats, byte for byte as the web app's ExportDialog writes them
/// (contract-v1.8; before, the CSV header was quoted, the CSV ended with a newline, the JSON keys
/// were sorted and `folder` was the group path).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    /// The header `Folder,Title,Username,Password,URL,Notes` unquoted, then one line per entry with
    /// every value in double quotes (`"` doubled), lines joined by `\n` with no newline at the end.
    /// Values may hold newlines of their own.
    Csv,
    /// `JSON.stringify(rows, null, 2)`: an array of objects with the keys `folder`, `title`,
    /// `username`, `passwordValue`, `url`, `notes` in that order (`[]` when there are none).
    Json,
}

/// How [`Vault::import_from`] brings another database's entries in (contract-v1.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalImportMode {
    /// Merge by UUID: the newer version of each entry wins (the older goes to its history), nothing
    /// is deleted, so importing twice changes nothing (Database > Merge).
    Merge,
    /// Every entry and group as a new copy with a fresh UUID, in one new group named after the
    /// source's root group, under `parent_group_id` (the root when `None`).
    Copies {
        /// The group to put the copy under.
        parent_group_id: Option<String>,
    },
}

/// What [`Vault::import_from`] did (contract-v1.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSummary {
    /// Entries new to this vault.
    pub added: u32,
    /// Entries this vault had that the import changed.
    pub updated: u32,
    /// Entries this vault already had as they are.
    pub unchanged: u32,
    /// Groups new to this vault.
    pub groups_added: u32,
    /// Every change, in order.
    pub changes: Vec<MergeChange>,
}

/// What importing a vault would bring in ([`Vault::import_preview`], contract-v1.6): its
/// Recycle Bin is never imported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ImportPreview {
    /// Entries outside the Recycle Bin.
    pub entries: u32,
    /// Groups below the root, outside the Recycle Bin.
    pub groups: u32,
}

/// A group an import can go into ([`Vault::import_targets`], contract-v1.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportTarget {
    /// Group UUID.
    pub group_id: String,
    /// `Root / Sub / Leaf` (the root's path is its name).
    pub path: String,
}

/// The key derivation a password-protected `.kdbx` is saved with (contract-v1.6). Every choice
/// gets a fresh salt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum KdbxKdf {
    /// KeePassXC's default for new databases: Argon2d, 64 MiB, 10 iterations, 2 lanes (about a
    /// second of work).
    #[default]
    DatabaseDefault,
    /// Argon2d with these settings.
    Argon2d {
        /// Memory in bytes (at least 8 KiB per lane).
        memory: u64,
        /// Iterations (at least 1).
        iterations: u64,
        /// Lanes (1 to 255).
        parallelism: u32,
    },
    /// Argon2id with these settings.
    Argon2id {
        /// Memory in bytes (at least 8 KiB per lane).
        memory: u64,
        /// Iterations (at least 1).
        iterations: u64,
        /// Lanes (1 to 255).
        parallelism: u32,
    },
    /// AES-KDF (KDBX 3.1 compatible) with this many rounds (at least 1).
    AesKdf {
        /// Transform rounds.
        rounds: u64,
    },
}

impl Vault {
    // ---------------------------------------------------------------------- local files

    /// Opens a local `.kdbx` (not an account vault). TS `decryptKdbx`. `vault_key_mismatch` for a
    /// wrong password or key file (as TS 0.11 and [`ov_kdbx::read`] report it; contract-v1.7, was
    /// `kdbx_error`), `kdbx_error` for a damaged file, `too_large` for a key derivation over this build's
    /// limits ([`ov_kdbx::check_kdf_limits`]), refused before it runs. Edits are stamped with the system clock (on wasm32, one second after the
    /// newest time in the file); [`OvClient::open_local`](crate::api::OvClient::open_local) uses the
    /// Host clock instead.
    pub async fn open_local(
        kdbx: Vec<u8>,
        credentials: KdbxCredentials,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        crate::impls::local_meta::open_local(None, kdbx, credentials, &cancel)
    }

    /// A new empty local database named `name` (KDBX 4, ChaCha20, Argon2id). TS `createNewKdbx`.
    /// [`OvClient::create_local`](crate::api::OvClient::create_local) does the same on the Host clock.
    /// It is saved as KDBX 4.0 until it holds something only KDBX 4.1 stores (an item's previous
    /// group after a move or delete, tags on a group, ...), then as 4.1, as KeePassXC 2.7 does
    /// (contract-v1.8).
    pub async fn create_local(
        name: String,
        credentials: KdbxCredentials,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        crate::impls::local_meta::create_local(None, name, credentials, &cancel)
    }

    /// Saves a local database with its credentials. `invalid_request` for an account vault (use
    /// [`sync`](Self::sync)). A KDBX 4.0 database that now holds something only KDBX 4.1 stores is
    /// written as 4.1 (contract-v1.8; KeePassXC 2.7 and later, and KeePass 2.48 and later, read every
    /// 4.1 element; older KDBX 4 readers open the file and drop them).
    pub async fn save_local(&self, cancel: CancelToken) -> Result<Vec<u8>, OvError> {
        cancel.check()?;
        let crate::state::VaultSource::Local(creds) = &self.inner.source else {
            return Err(OvError::new(ov_error::OvErrorCode::InvalidRequest, "an account vault is saved with sync"));
        };
        let key = crate::impls::vaults::local_key(creds)?;
        let db = self.db().clone();
        ov_kdbx::write(&db, &key)
    }

    /// Renames a local database (`Meta/DatabaseName`; the root group keeps its name). Account vaults
    /// are renamed with [`Account::rename_vault`](crate::api::Account::rename_vault):
    /// `invalid_request` here. Contract-v1.6.
    pub fn set_name(&self, name: String) -> Result<(), OvError> {
        crate::impls::local_meta::set_name(self, name)
    }

    /// Sets the key derivation a local database is saved with by [`save_local`](Self::save_local)
    /// (a KDBX 3.1 file is upgraded to KDBX 4 for Argon2). `invalid_request` for an account vault,
    /// whose KDF belongs to its raw vault key; `too_large` over the limits a file is opened with
    /// ([`ov_kdbx::check_kdf_limits`]). Contract-v1.6.
    pub fn set_kdf(&self, kdf: KdbxKdf) -> Result<(), OvError> {
        crate::impls::local_meta::set_kdf(self, kdf)
    }

    /// A separate local copy of this vault with its unsaved changes, without the sync-server and
    /// account-vault remotes in KeePassXC's `KPXC_REMOTE_SYNC_SETTINGS` (command remotes stay):
    /// "Save a copy", or "Export" of a whole database. It is saved with `credentials`, or a local
    /// file's own credentials when `None` (`invalid_request` for an account vault or a version without
    /// credentials). A copy of an account vault (or of a version or SA vault) gets the
    /// [`KdbxKdf::DatabaseDefault`] KDF, since its vault KDF is only light because its key is random;
    /// change it with [`set_kdf`](Self::set_kdf). Contract-v1.6.
    pub fn copy_without_remotes(&self, credentials: Option<KdbxCredentials>) -> Result<Vault, OvError> {
        crate::impls::local_meta::copy_without_remotes(self, credentials)
    }

    /// The database custom data value for `key` (`Meta/CustomData`, e.g.
    /// `KPXC_REMOTE_SYNC_SETTINGS`). Contract-v1.6.
    pub fn meta_custom_data(&self, key: String) -> Option<String> {
        self.db().meta.custom_data.iter().find(|i| i.key == key).map(|i| i.value.clone())
    }

    /// Sets (`Some`) or removes (`None`) a database custom data item. Edits are local until saved or
    /// synced, as every edit. Contract-v1.6.
    pub fn set_meta_custom_data(&self, key: String, value: Option<String>) -> Result<(), OvError> {
        crate::impls::local_meta::set_meta_custom_data(self, key, value)
    }

    // ------------------------------------------------------------------------------ state

    /// The vault id (for a local file, its root group UUID).
    pub fn id(&self) -> String {
        match self.vault_info() {
            Some(i) => i.id,
            None => crate::impls::convert::uuid_hex(&self.db().root.uuid),
        }
    }

    /// The vault name (account vaults: the decrypted name from the auth server).
    pub fn name(&self) -> String {
        match self.vault_info() {
            Some(i) => i.name,
            None => {
                let db = self.db();
                if db.meta.database_name.is_empty() {
                    db.root.name.clone()
                } else {
                    db.meta.database_name.clone()
                }
            }
        }
    }

    /// The account's view of the vault; `None` for a local file.
    pub fn info(&self) -> Option<VaultInfo> {
        self.vault_info()
    }

    /// The server ETag at the last sync (compare with a `vault` event's etag).
    pub fn etag(&self) -> Option<String> {
        crate::impls::util::lock(&self.inner.etag).clone()
    }

    /// The last sync couldn't reach the server, or the vault was opened from the offline cache.
    pub fn is_offline(&self) -> bool {
        self.inner.offline.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// An old version from history: edits and sync are refused.
    pub fn is_read_only(&self) -> bool {
        matches!(self.inner.source, crate::state::VaultSource::Version { .. })
    }

    /// Conflicts the last sync resolved (Swift `OpenedVault.conflicts`).
    pub fn conflicts(&self) -> Vec<SyncConflict> {
        crate::impls::util::lock(&self.inner.conflicts).clone()
    }

    /// The root group's id.
    pub fn root_group_id(&self) -> String {
        crate::impls::convert::uuid_hex(&self.db().root.uuid)
    }

    // ----------------------------------------------------------------------------- reading

    /// Every entry, without values (TS `listItems`, `collectAllDbData`; Swift `entries`). The
    /// Recycle Bin is left out unless `include_recycle_bin`.
    pub fn entries(&self, include_recycle_bin: bool) -> Vec<EntrySummary> {
        crate::impls::kdbx_ops::entries(&self.db(), include_recycle_bin)
    }

    /// Every group in tree order, the root first.
    pub fn groups(&self) -> Vec<GroupInfo> {
        crate::impls::kdbx_ops::groups(&self.db())
    }

    /// Every entry with its values in one call (as [`entry`](Self::entry) for each of
    /// [`entries`](Self::entries)), in the same order. Contract-v1.6.
    pub fn entry_records(&self, include_recycle_bin: bool) -> Vec<EntryRecord> {
        crate::impls::kdbx_ops::entry_records(&self.db(), include_recycle_bin)
    }

    /// One entry with its values; `entry_not_found` if missing.
    pub fn entry(&self, entry_id: String) -> Result<EntryRecord, OvError> {
        crate::impls::kdbx_ops::entry(&self.db(), &entry_id)
    }

    /// The entry an item reference names (`ov://<vault>/[<group>/…]<entry>`, SPEC §14; the vault
    /// segment is not checked here). `<entry>` is a UUID (hex, dashed or base64) or a unique title.
    pub fn find(&self, reference: String) -> Result<EntryRecord, OvError> {
        let r = ov_vault::parse_item_reference(&reference)?;
        let db = self.db();
        let (e, _) = ov_vault::find_entry(&db, &r.group_path, &r.entry)?;
        crate::impls::kdbx_ops::entry(&db, &crate::impls::convert::uuid_hex(&e.uuid))
    }

    /// The value a secret reference names (`ov://<vault>/[<group>/…]<entry>/<field>`, SPEC §14).
    /// TS `AccountVault.read`.
    pub fn read_field(&self, reference: String) -> Result<SecretBytes, OvError> {
        let r = ov_vault::parse_reference(&reference)?;
        Ok(ov_vault::read_field(&self.db(), &r)?.as_bytes().to_vec())
    }

    /// Older versions of an entry, oldest first.
    pub fn history(&self, entry_id: String) -> Result<Vec<EntryRecord>, OvError> {
        crate::impls::kdbx_ops::history(&self.db(), &entry_id)
    }

    /// An attachment's content.
    pub fn attachment(&self, entry_id: String, name: String) -> Result<SecretBytes, OvError> {
        crate::impls::kdbx_ops::attachment(&self.db(), &entry_id, &name)
    }

    /// A custom icon's PNG bytes.
    pub fn custom_icon(&self, icon_id: String) -> Result<Vec<u8>, OvError> {
        crate::impls::kdbx_ops::custom_icon(&self.db(), &icon_id)
    }

    /// The group at a `/`-separated path of names below the root, if it exists.
    pub fn group_id_at(&self, path: String) -> Option<String> {
        crate::impls::kdbx_ops::group_id_at(&self.db(), &path).map(|u| crate::impls::convert::uuid_hex(&u))
    }

    /// Whether an entry or group is in the Recycle Bin.
    pub fn is_in_recycle_bin(&self, id: String) -> bool {
        ov_kdbx::entries::parse_uuid_string(&id).is_some_and(|u| crate::impls::kdbx_ops::in_recycle_bin(&self.db(), u))
    }

    // ----------------------------------------------------------------------------- editing

    /// Sets a field by secret reference and syncs it up (TS `AccountVault.write`). With `create`,
    /// a missing entry is created by title under its group path.
    pub async fn write_field(
        &self,
        reference: String,
        value: SecretBytes,
        create: bool,
        cancel: CancelToken,
    ) -> Result<SyncReport, OvError> {
        let r = ov_vault::parse_reference(&reference)?;
        let value = crate::impls::util::secret_text(value, "field value")?;
        self.edit(|db, now| ov_vault::write_field(db, &r, &value, create, None, now).map(|_| ()))?;
        self.sync(SyncOptions::default(), cancel).await
    }

    /// Sets several fields of the entry an item reference names, keeping history (TS
    /// `setItemFields`). Returns the entry and whether it was created.
    pub fn set_fields(
        &self,
        reference: String,
        fields: Vec<FieldInput>,
        create: CreateMode,
    ) -> Result<SetFieldsResult, OvError> {
        let r = ov_vault::parse_item_reference(&reference)?;
        let updates = fields
            .into_iter()
            .map(|f| {
                Ok(ov_vault::FieldUpdate {
                    name: f.name,
                    value: crate::impls::util::secret_text(f.value, "field value")?,
                    protected: f.protected,
                })
            })
            .collect::<Result<Vec<_>, OvError>>()?;
        let mode = match create {
            CreateMode::MustExist => ov_vault::CreateMode::MustExist,
            CreateMode::CreateIfMissing => ov_vault::CreateMode::CreateIfMissing,
            CreateMode::CreateOnly => ov_vault::CreateMode::CreateOnly,
        };
        let out = self.edit(|db, now| ov_vault::set_item_fields(db, &r, &updates, mode, now))?;
        let entry = self.entry(crate::impls::convert::uuid_hex(&out.entry_id))?;
        Ok(SetFieldsResult { entry, created: out.created })
    }

    /// Adds an entry to a group; returns its id.
    pub fn add_entry(&self, group_id: String, input: EntryInput) -> Result<String, OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::add_entry(db, &group_id, input, now))
    }

    /// Adds an entry with an id the caller chose (32 hex digits, a dashed UUID or base64); returns it
    /// as 32 lowercase hex digits. `conflict` if an entry with that id exists, `invalid_request` for
    /// a malformed or nil id. A deletion record for that id is dropped, so the entry syncs as new.
    /// Contract-v1.6.
    pub fn add_entry_with_id(&self, entry_id: String, group_id: String, input: EntryInput) -> Result<String, OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::add_entry_with_id(db, &entry_id, &group_id, input, now))
    }

    /// Edits an entry (history first).
    pub fn edit_entry(&self, entry_id: String, input: EntryInput) -> Result<(), OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::edit_entry(db, &entry_id, input, now))
    }

    /// Moves an entry to another group (updates `LocationChanged`, and records the group it left as
    /// `PreviousParentGroup`, whatever the file's KDBX version; contract-v1.8).
    pub fn move_entry(&self, entry_id: String, group_id: String) -> Result<(), OvError> {
        self.edit(|db, now| {
            let id =
                ov_kdbx::entries::parse_uuid_string(&entry_id).ok_or_else(crate::impls::kdbx_ops::entry_not_found)?;
            crate::impls::kdbx_ops::move_entry_to(db, id, crate::impls::kdbx_ops::parse_id(&group_id)?, now)
        })
    }

    /// Deletes an entry: into the Recycle Bin when it is enabled (remembering the group it was in, for
    /// [`restore_from_recycle_bin`](Self::restore_from_recycle_bin); contract-v1.8), else (or when
    /// already there) for good, with a `DeletedObject` so the deletion syncs.
    pub fn delete_entry(&self, entry_id: String) -> Result<(), OvError> {
        self.edit(|db, now| {
            let id =
                ov_kdbx::entries::parse_uuid_string(&entry_id).ok_or_else(crate::impls::kdbx_ops::entry_not_found)?;
            ov_kdbx::entries::delete_entry(db, id, now)
        })
    }

    /// Moves an entry or group out of the Recycle Bin, to its previous parent when that still exists
    /// outside the bin, else to the root. Since contract-v1.8 the previous parent is recorded on every
    /// move and delete (before, only in KDBX 4.1 files, so items from new vaults came back in the root).
    pub fn restore_from_recycle_bin(&self, id: String) -> Result<(), OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::restore_from_recycle_bin(db, &id, now))
    }

    /// Empties the Recycle Bin (each item gets a `DeletedObject`).
    pub fn empty_recycle_bin(&self) -> Result<(), OvError> {
        self.edit(ov_kdbx::entries::empty_recycle_bin)
    }

    /// Sets or replaces an attachment, kept protected in memory (as
    /// [`set_attachment_with`](Self::set_attachment_with) with `Some(true)`).
    pub fn set_attachment(&self, entry_id: String, name: String, data: SecretBytes) -> Result<(), OvError> {
        self.set_attachment_with(entry_id, name, data, Some(true))
    }

    /// Sets or replaces an attachment with its protected flag; `None` keeps the flag of the
    /// attachment it replaces (protected for a new one). Contract-v1.6.
    pub fn set_attachment_with(
        &self,
        entry_id: String,
        name: String,
        data: SecretBytes,
        protected: Option<bool>,
    ) -> Result<(), OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::set_attachment(db, &entry_id, &name, data, protected, now))
    }

    /// Removes an attachment.
    pub fn remove_attachment(&self, entry_id: String, name: String) -> Result<(), OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::remove_attachment(db, &entry_id, &name, now))
    }

    /// Adds a custom icon (or finds the identical one); returns its id.
    pub fn add_custom_icon(&self, png: Vec<u8>) -> Result<String, OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::add_custom_icon(db, png, now))
    }

    /// Adds a group under `parent_id` (the root when `None`); returns its id.
    pub fn add_group(&self, parent_id: Option<String>, name: String) -> Result<String, OvError> {
        self.edit(|db, now| {
            let parent = crate::impls::kdbx_ops::parent_group(db, parent_id.as_deref())?;
            ov_kdbx::entries::create_group(db, parent, &name, now).map(|u| crate::impls::convert::uuid_hex(&u))
        })
    }

    /// The group at a `/`-separated path, creating missing groups.
    pub fn ensure_group(&self, path: String) -> Result<String, OvError> {
        self.edit(|db, now| {
            crate::impls::kdbx_ops::ensure_group(db, &path, now).map(|u| crate::impls::convert::uuid_hex(&u))
        })
    }

    /// Renames a group.
    pub fn rename_group(&self, group_id: String, name: String) -> Result<(), OvError> {
        self.edit(|db, now| {
            ov_kdbx::entries::rename_group(db, crate::impls::kdbx_ops::parse_id(&group_id)?, &name, now)
        })
    }

    /// Sets a group's standard icon.
    pub fn set_group_icon(&self, group_id: String, icon_id: u32) -> Result<(), OvError> {
        self.edit(|db, now| {
            ov_kdbx::entries::set_group_icon(db, crate::impls::kdbx_ops::parse_id(&group_id)?, icon_id, now)
        })
    }

    /// Moves a group under another; `invalid_request` for a move into itself or its subtree. Records
    /// the group it left as `PreviousParentGroup` (contract-v1.8).
    pub fn move_group(&self, group_id: String, parent_id: String) -> Result<(), OvError> {
        self.edit(|db, now| {
            crate::impls::kdbx_ops::move_group_to(
                db,
                crate::impls::kdbx_ops::parse_id(&group_id)?,
                crate::impls::kdbx_ops::parse_id(&parent_id)?,
                now,
            )
        })
    }

    /// Deletes a group with everything in it (Recycle Bin rules as [`delete_entry`](Self::delete_entry)).
    pub fn delete_group(&self, group_id: String) -> Result<(), OvError> {
        self.edit(|db, now| ov_kdbx::entries::delete_group(db, crate::impls::kdbx_ops::parse_id(&group_id)?, now))
    }

    /// How entry `entry_id` of `version` (from
    /// [`Account::open_vault_version`](crate::api::Account::open_vault_version)) compares with this
    /// vault (Swift `Database.difference(from:)`).
    pub fn version_difference(&self, version: Vault, entry_id: String) -> Result<VersionDifference, OvError> {
        let old = version.db().clone();
        crate::impls::kdbx_ops::version_difference(&self.db(), &old, &entry_id)
    }

    /// Brings entry `entry_id` back from an old `version`: its content becomes the current version
    /// (the current one goes to history), or it is re-added at `group_path` if it was deleted for
    /// good (Swift `Database.restoreEntry`). Sync afterwards.
    ///
    /// An entry in the Recycle Bin is edited the same way, keeping its history, and moved out of the
    /// bin: to its previous group when that still exists outside the bin, else to `group_path`
    /// (created when missing). Contract-v1.8; before, the binned copy was replaced by the version's,
    /// dropping its history.
    pub fn restore_entry(&self, version: Vault, entry_id: String, group_path: String) -> Result<(), OvError> {
        let old = version.db().clone();
        self.edit(|db, now| crate::impls::kdbx_ops::restore_entry(db, &old, &entry_id, &group_path, now))
    }

    /// Merges AutoFill's saved entries into the working copy (Swift `AutoFillEdits.apply`); `true`
    /// if anything changed.
    pub fn apply_autofill_edits(&self, edits: AutoFillEdits) -> Result<bool, OvError> {
        self.edit(|db, now| {
            let mut changed = false;
            for e in &edits.entries {
                changed |= crate::impls::kdbx_ops::upsert_record(db, &e.entry, &e.group_path, now)?;
            }
            Ok(changed)
        })
    }

    // ------------------------------------------------------------------------------ import

    /// Imports `source` (another open vault: a local file, an account vault, a version) into this
    /// one, without changing `source`. Its Recycle Bin stays behind. Database custom data
    /// (`Meta/CustomData`): with [`LocalImportMode::Merge`] the source's items this vault doesn't
    /// have are added (KeePassXC-Browser keys, for example), except its remote settings and the
    /// generated items (sync generation, `_LAST_MODIFIED`, `KPXC_RANDOM_SLUG`), and this vault's own
    /// items are never changed (contract-v1.8; before, none came along); with
    /// [`LocalImportMode::Copies`] none come along, and references between the copied entries
    /// follow them. An account vault uploads the result on its next [`sync`](Self::sync); a local
    /// file on [`save_local`](Self::save_local). Contract-v1.6.
    pub fn import_from(&self, source: Vault, mode: LocalImportMode) -> Result<ImportSummary, OvError> {
        crate::impls::local_meta::import_from(self, source, mode)
    }

    /// What importing this vault elsewhere would bring in (entries and groups outside its Recycle
    /// Bin), to show before [`import_from`](Self::import_from). Contract-v1.6.
    pub fn import_preview(&self) -> ImportPreview {
        crate::impls::local_meta::import_preview(&self.db())
    }

    /// The groups of this vault an import can go into (not the Recycle Bin or anything in it), the
    /// root first. Contract-v1.6.
    pub fn import_targets(&self) -> Vec<ImportTarget> {
        crate::impls::local_meta::import_targets(&self.db())
    }

    // -------------------------------------------------------------------------------- sync

    /// Downloads, merges local edits and uploads them (conditional PUT; merge and retry on 412),
    /// SPEC §11, §13, §20. Offline, the working copy is kept on the device (encrypted) and uploads
    /// on a later sync; the error is `network_error`.
    ///
    /// Edits made to this handle (or a clone) while the sync runs are kept (contract-v1.8; before,
    /// the sync's result replaced them): the result is merged with them three ways, the copy the sync
    /// started from being the base, and they are uploaded in up to two more rounds of the same call
    /// (the first against the copy just uploaded, without downloading it again). Edits still landing
    /// after that, or when a later round can't reach the server, stay in the working copy as
    /// unsynced edits (kept on the device like [`keep_edits`](Self::keep_edits);
    /// [`has_pending_edits`](Self::has_pending_edits)) for the next sync, and the call still returns
    /// what the rounds that succeeded did: the report's outcome is the most a round did (`Created`,
    /// then `Uploaded`, then `Pulled`), its conflicts, changes and attempts those of every round.
    /// Service-account vaults ([`write_field`](Self::write_field)) work the same way.
    ///
    /// The database custom data (`Meta/CustomData`) merges three ways too (contract-v1.8): an item
    /// added, changed or removed on one side since the last sync is taken, one changed on both
    /// keeps the newer copy's value; before, an item another device added could be dropped.
    pub async fn sync(&self, options: SyncOptions, cancel: CancelToken) -> Result<SyncReport, OvError> {
        self.writable()?;
        match &self.inner.source {
            crate::state::VaultSource::Local(_) => {
                Err(OvError::new(ov_error::OvErrorCode::InvalidRequest, "a local file has no server; save it instead"))
            }
            _ => crate::impls::syncing::sync_vault(self, options, None, &cancel).await,
        }
    }

    /// Makes the working copy durable before anything is sent: it survives the app being killed, and
    /// AutoFill sees it. The copy goes once a sync uploads it (Swift `keepEdits`).
    pub async fn keep_edits(&self) -> Result<(), OvError> {
        self.keep_edits_impl().await
    }

    /// Edits wait on this device for the next upload.
    pub async fn has_pending_edits(&self) -> Result<bool, OvError> {
        match &self.inner.source {
            crate::state::VaultSource::Account { account, .. } => account.pending_for(Some(&self.id())).await,
            _ => Ok(false),
        }
    }

    // ------------------------------------------------------------------------------ export

    /// The groups `group_ids` (every group when `None`) as a new `.kdbx` with `credentials`. TS
    /// `exportSelectedGroupsToKdbx`. The KDF is kdbxweb's `Kdbx.create` one (Argon2d, 1 MiB, 2
    /// iterations, 1 lane), as the TS SDK writes it; choose another with
    /// [`export_kdbx_with`](Self::export_kdbx_with).
    pub async fn export_kdbx(
        &self,
        credentials: KdbxCredentials,
        group_ids: Option<Vec<String>>,
        cancel: CancelToken,
    ) -> Result<Vec<u8>, OvError> {
        cancel.check()?;
        let key = crate::impls::vaults::local_key(&credentials)?;
        let now = self.now();
        let out = crate::impls::kdbx_ops::export_db(&self.db(), group_ids, now)?;
        ov_kdbx::write(&out, &key)
    }

    /// As [`export_kdbx`](Self::export_kdbx), saved with the key derivation `kdf`. Contract-v1.6.
    pub async fn export_kdbx_with(
        &self,
        credentials: KdbxCredentials,
        group_ids: Option<Vec<String>>,
        kdf: KdbxKdf,
        cancel: CancelToken,
    ) -> Result<Vec<u8>, OvError> {
        cancel.check()?;
        let key = crate::impls::vaults::local_key(&credentials)?;
        let now = self.now();
        let mut out = crate::impls::kdbx_ops::export_db(&self.db(), group_ids, now)?;
        crate::impls::local_meta::apply_kdf(&mut out, kdf)?;
        cancel.check()?;
        ov_kdbx::write(&out, &key)
    }

    /// The entries directly in `group_ids` (every group when `None`), unencrypted, as CSV or JSON in
    /// the web app's exact format ([`ExportFormat`]), in tree order. `folder` is the name of the
    /// entry's own group (`Root` for an unnamed root) and an empty title is `(Untitled Entry)`, as
    /// the web app lists them (contract-v1.8). The Recycle Bin is never exported (Swift `Export`).
    pub fn export_plain(&self, format: ExportFormat, group_ids: Option<Vec<String>>) -> Result<SecretBytes, OvError> {
        crate::impls::kdbx_ops::export_plain(&self.db(), format, group_ids)
    }
}
