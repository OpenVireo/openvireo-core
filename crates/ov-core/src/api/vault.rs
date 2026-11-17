//! [`Vault`]: one open KDBX database, either an account vault kept in sync with
//! `{sync}/vaults/{id}` (SPEC §7, §11, §20) or a local file.
//!
//! Edits are local until [`Vault::sync`] (except [`Vault::write_field`], which syncs, as the TS
//! `AccountVault.write` does). Entry and group ids are KDBX UUIDs as 32 lowercase hex digits; times
//! are KDBX Unix seconds. Field values cross as [`SecretBytes`].

use std::sync::Arc;

use ov_error::OvError;

use super::{AutoFillEdits, CancelToken, SecretBytes, SyncConflict, SyncOptions, SyncReport, VaultInfo};
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
}

impl std::fmt::Debug for KdbxCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdbxCredentials")
            .field("password", &self.password.is_some())
            .field("key_file", &self.key_file.is_some())
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

/// Unencrypted export formats (the web app's ExportDialog).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    /// `Folder,Title,Username,Password,URL,Notes`, every value quoted.
    Csv,
    /// Pretty-printed objects with `folder`, `title`, `username`, `passwordValue`, `url`, `notes`.
    Json,
}

impl Vault {
    // ---------------------------------------------------------------------- local files

    /// Opens a local `.kdbx` (not an account vault). TS `decryptKdbx`. `kdbx_error` for a wrong key
    /// or a damaged file.
    pub async fn open_local(
        kdbx: Vec<u8>,
        credentials: KdbxCredentials,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        cancel.check()?;
        let key = crate::impls::vaults::local_key(&credentials)?;
        let db = ov_kdbx::read(&kdbx, &key).map_err(|e| {
            if e.is(ov_error::OvErrorCode::VaultKeyMismatch) {
                OvError::new(ov_error::OvErrorCode::KdbxError, "the password or key file is wrong")
            } else {
                e
            }
        })?;
        Ok(crate::impls::vaults::new_vault(crate::state::VaultSource::Local(credentials), None, db, false, None))
    }

    /// A new empty local database named `name` (KDBX 4, ChaCha20, Argon2id). TS `createNewKdbx`.
    pub async fn create_local(
        name: String,
        credentials: KdbxCredentials,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        cancel.check()?;
        crate::impls::vaults::local_key(&credentials)?;
        let v = crate::impls::vaults::new_vault(
            crate::state::VaultSource::Local(credentials),
            None,
            ov_kdbx::vault::create_kdbx(&name, 0)?,
            false,
            None,
        );
        let now = v.now();
        let mut db = ov_kdbx::vault::create_kdbx(&name, now)?;
        db.header.cipher = ov_kdbx::model::Cipher::ChaCha20;
        if let ov_kdbx::model::Kdf::Argon2 { kind, .. } = &mut db.header.kdf {
            *kind = ov_kdbx::model::Argon2Type::Id;
        }
        *v.db() = db;
        Ok(v)
    }

    /// Saves a local database with its credentials. `invalid_request` for an account vault (use
    /// [`sync`](Self::sync)).
    pub async fn save_local(&self, cancel: CancelToken) -> Result<Vec<u8>, OvError> {
        cancel.check()?;
        let crate::state::VaultSource::Local(creds) = &self.inner.source else {
            return Err(OvError::new(ov_error::OvErrorCode::InvalidRequest, "an account vault is saved with sync"));
        };
        let key = crate::impls::vaults::local_key(creds)?;
        let db = self.db().clone();
        ov_kdbx::write(&db, &key)
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

    /// Edits an entry (history first).
    pub fn edit_entry(&self, entry_id: String, input: EntryInput) -> Result<(), OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::edit_entry(db, &entry_id, input, now))
    }

    /// Moves an entry to another group (updates `LocationChanged`).
    pub fn move_entry(&self, entry_id: String, group_id: String) -> Result<(), OvError> {
        self.edit(|db, now| {
            let id =
                ov_kdbx::entries::parse_uuid_string(&entry_id).ok_or_else(crate::impls::kdbx_ops::entry_not_found)?;
            crate::impls::kdbx_ops::move_entry_to(db, id, crate::impls::kdbx_ops::parse_id(&group_id)?, now)
        })
    }

    /// Deletes an entry: into the Recycle Bin when it is enabled, else (or when already there) for
    /// good, with a `DeletedObject` so the deletion syncs.
    pub fn delete_entry(&self, entry_id: String) -> Result<(), OvError> {
        self.edit(|db, now| {
            let id =
                ov_kdbx::entries::parse_uuid_string(&entry_id).ok_or_else(crate::impls::kdbx_ops::entry_not_found)?;
            ov_kdbx::entries::delete_entry(db, id, now)
        })
    }

    /// Moves an entry or group out of the Recycle Bin, to its previous parent when that still exists.
    pub fn restore_from_recycle_bin(&self, id: String) -> Result<(), OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::restore_from_recycle_bin(db, &id, now))
    }

    /// Empties the Recycle Bin (each item gets a `DeletedObject`).
    pub fn empty_recycle_bin(&self) -> Result<(), OvError> {
        self.edit(ov_kdbx::entries::empty_recycle_bin)
    }

    /// Sets or replaces an attachment.
    pub fn set_attachment(&self, entry_id: String, name: String, data: SecretBytes) -> Result<(), OvError> {
        self.edit(|db, now| crate::impls::kdbx_ops::set_attachment(db, &entry_id, &name, data, now))
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

    /// Moves a group under another; `invalid_request` for a move into itself or its subtree.
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
    /// (the current one goes to history), or it is re-added at `group_path` if it was deleted
    /// (Swift `Database.restoreEntry`). Sync afterwards.
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

    // -------------------------------------------------------------------------------- sync

    /// Downloads, merges local edits and uploads them (conditional PUT; merge and retry on 412),
    /// SPEC §11, §13, §20. Offline, the working copy is kept on the device (encrypted) and uploads
    /// on a later sync; the error is `network_error`.
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
    /// `exportSelectedGroupsToKdbx`.
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

    /// The entries directly in `group_ids` (every group when `None`), unencrypted, as CSV or JSON.
    /// The Recycle Bin is never exported (Swift `Export`).
    pub fn export_plain(&self, format: ExportFormat, group_ids: Option<Vec<String>>) -> Result<SecretBytes, OvError> {
        crate::impls::kdbx_ops::export_plain(&self.db(), format, group_ids)
    }
}
