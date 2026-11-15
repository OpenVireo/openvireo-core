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
        todo!()
    }

    /// A new empty local database named `name` (KDBX 4, ChaCha20, Argon2id). TS `createNewKdbx`.
    pub async fn create_local(
        name: String,
        credentials: KdbxCredentials,
        cancel: CancelToken,
    ) -> Result<Vault, OvError> {
        todo!()
    }

    /// Saves a local database with its credentials. `invalid_request` for an account vault (use
    /// [`sync`](Self::sync)).
    pub async fn save_local(&self, cancel: CancelToken) -> Result<Vec<u8>, OvError> {
        todo!()
    }

    // ------------------------------------------------------------------------------ state

    /// The vault id (for a local file, its root group UUID).
    pub fn id(&self) -> String {
        todo!()
    }

    /// The vault name (account vaults: the decrypted name from the auth server).
    pub fn name(&self) -> String {
        todo!()
    }

    /// The account's view of the vault; `None` for a local file.
    pub fn info(&self) -> Option<VaultInfo> {
        todo!()
    }

    /// The server ETag at the last sync (compare with a `vault` event's etag).
    pub fn etag(&self) -> Option<String> {
        todo!()
    }

    /// The last sync couldn't reach the server, or the vault was opened from the offline cache.
    pub fn is_offline(&self) -> bool {
        todo!()
    }

    /// An old version from history: edits and sync are refused.
    pub fn is_read_only(&self) -> bool {
        todo!()
    }

    /// Conflicts the last sync resolved (Swift `OpenedVault.conflicts`).
    pub fn conflicts(&self) -> Vec<SyncConflict> {
        todo!()
    }

    /// The root group's id.
    pub fn root_group_id(&self) -> String {
        todo!()
    }

    // ----------------------------------------------------------------------------- reading

    /// Every entry, without values (TS `listItems`, `collectAllDbData`; Swift `entries`). The
    /// Recycle Bin is left out unless `include_recycle_bin`.
    pub fn entries(&self, include_recycle_bin: bool) -> Vec<EntrySummary> {
        todo!()
    }

    /// Every group in tree order, the root first.
    pub fn groups(&self) -> Vec<GroupInfo> {
        todo!()
    }

    /// One entry with its values; `entry_not_found` if missing.
    pub fn entry(&self, entry_id: String) -> Result<EntryRecord, OvError> {
        todo!()
    }

    /// The entry an item reference names (`ov://<vault>/[<group>/…]<entry>`, SPEC §14; the vault
    /// segment is not checked here). `<entry>` is a UUID (hex, dashed or base64) or a unique title.
    pub fn find(&self, reference: String) -> Result<EntryRecord, OvError> {
        todo!()
    }

    /// The value a secret reference names (`ov://<vault>/[<group>/…]<entry>/<field>`, SPEC §14).
    /// TS `AccountVault.read`.
    pub fn read_field(&self, reference: String) -> Result<SecretBytes, OvError> {
        todo!()
    }

    /// Older versions of an entry, oldest first.
    pub fn history(&self, entry_id: String) -> Result<Vec<EntryRecord>, OvError> {
        todo!()
    }

    /// An attachment's content.
    pub fn attachment(&self, entry_id: String, name: String) -> Result<SecretBytes, OvError> {
        todo!()
    }

    /// A custom icon's PNG bytes.
    pub fn custom_icon(&self, icon_id: String) -> Result<Vec<u8>, OvError> {
        todo!()
    }

    /// The group at a `/`-separated path of names below the root, if it exists.
    pub fn group_id_at(&self, path: String) -> Option<String> {
        todo!()
    }

    /// Whether an entry or group is in the Recycle Bin.
    pub fn is_in_recycle_bin(&self, id: String) -> bool {
        todo!()
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
        todo!()
    }

    /// Sets several fields of the entry an item reference names, keeping history (TS
    /// `setItemFields`). Returns the entry and whether it was created.
    pub fn set_fields(
        &self,
        reference: String,
        fields: Vec<FieldInput>,
        create: CreateMode,
    ) -> Result<SetFieldsResult, OvError> {
        todo!()
    }

    /// Adds an entry to a group; returns its id.
    pub fn add_entry(&self, group_id: String, input: EntryInput) -> Result<String, OvError> {
        todo!()
    }

    /// Edits an entry (history first).
    pub fn edit_entry(&self, entry_id: String, input: EntryInput) -> Result<(), OvError> {
        todo!()
    }

    /// Moves an entry to another group (updates `LocationChanged`).
    pub fn move_entry(&self, entry_id: String, group_id: String) -> Result<(), OvError> {
        todo!()
    }

    /// Deletes an entry: into the Recycle Bin when it is enabled, else (or when already there) for
    /// good, with a `DeletedObject` so the deletion syncs.
    pub fn delete_entry(&self, entry_id: String) -> Result<(), OvError> {
        todo!()
    }

    /// Moves an entry or group out of the Recycle Bin, to its previous parent when that still exists.
    pub fn restore_from_recycle_bin(&self, id: String) -> Result<(), OvError> {
        todo!()
    }

    /// Empties the Recycle Bin (each item gets a `DeletedObject`).
    pub fn empty_recycle_bin(&self) -> Result<(), OvError> {
        todo!()
    }

    /// Sets or replaces an attachment.
    pub fn set_attachment(&self, entry_id: String, name: String, data: SecretBytes) -> Result<(), OvError> {
        todo!()
    }

    /// Removes an attachment.
    pub fn remove_attachment(&self, entry_id: String, name: String) -> Result<(), OvError> {
        todo!()
    }

    /// Adds a custom icon (or finds the identical one); returns its id.
    pub fn add_custom_icon(&self, png: Vec<u8>) -> Result<String, OvError> {
        todo!()
    }

    /// Adds a group under `parent_id` (the root when `None`); returns its id.
    pub fn add_group(&self, parent_id: Option<String>, name: String) -> Result<String, OvError> {
        todo!()
    }

    /// The group at a `/`-separated path, creating missing groups.
    pub fn ensure_group(&self, path: String) -> Result<String, OvError> {
        todo!()
    }

    /// Renames a group.
    pub fn rename_group(&self, group_id: String, name: String) -> Result<(), OvError> {
        todo!()
    }

    /// Sets a group's standard icon.
    pub fn set_group_icon(&self, group_id: String, icon_id: u32) -> Result<(), OvError> {
        todo!()
    }

    /// Moves a group under another; `invalid_request` for a move into itself or its subtree.
    pub fn move_group(&self, group_id: String, parent_id: String) -> Result<(), OvError> {
        todo!()
    }

    /// Deletes a group with everything in it (Recycle Bin rules as [`delete_entry`](Self::delete_entry)).
    pub fn delete_group(&self, group_id: String) -> Result<(), OvError> {
        todo!()
    }

    /// Merges AutoFill's saved entries into the working copy (Swift `AutoFillEdits.apply`); `true`
    /// if anything changed.
    pub fn apply_autofill_edits(&self, edits: AutoFillEdits) -> Result<bool, OvError> {
        todo!()
    }

    // -------------------------------------------------------------------------------- sync

    /// Downloads, merges local edits and uploads them (conditional PUT; merge and retry on 412),
    /// SPEC §11, §13, §20. Offline, the working copy is kept on the device (encrypted) and uploads
    /// on a later sync; the error is `network_error`.
    pub async fn sync(&self, options: SyncOptions, cancel: CancelToken) -> Result<SyncReport, OvError> {
        todo!()
    }

    /// Makes the working copy durable before anything is sent: it survives the app being killed, and
    /// AutoFill sees it. The copy goes once a sync uploads it (Swift `keepEdits`).
    pub async fn keep_edits(&self) -> Result<(), OvError> {
        todo!()
    }

    /// Edits wait on this device for the next upload.
    pub async fn has_pending_edits(&self) -> Result<bool, OvError> {
        todo!()
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
        todo!()
    }

    /// The entries directly in `group_ids` (every group when `None`), unencrypted, as CSV or JSON.
    /// The Recycle Bin is never exported (Swift `Export`).
    pub fn export_plain(&self, format: ExportFormat, group_ids: Option<Vec<String>>) -> Result<SecretBytes, OvError> {
        todo!()
    }
}
