//! KDBX read/write/merge over `ov-kdbx` and `ov-merge`, bytes in and bytes out. Full module only.
//!
//! The SDK exposes kdbxweb objects in its public API, which can't cross the boundary; what the core
//! offers instead is a `Kdbx` handle (one decrypted database, so the Argon2 work happens once per
//! read and write) plus `kdbxMerge`, the whole sync merge on file bytes. Entry and group ids are
//! kdbxweb's (base64 of the 16 UUID bytes); hex and hyphenated UUIDs are accepted too. Times are
//! Unix seconds. Editing entries is the facade's `Vault` (`Vault.openLocal`/`createLocal`).

use js_sys::{Array, Uint8Array};
use ov_error::{OvError, OvErrorCode};
use ov_kdbx::entries::{collect_all_db_data, parse_uuid_string, uuid_string, KeePassEntry, KeePassGroup};
use ov_kdbx::model::{Cipher, Compression, Database, Header, Kdf, Timestamp, Uuid};
use ov_kdbx::vault::{self, KdfSettings, KeyVersion};
use ov_kdbx::CompositeKey;
use ov_merge::{
    ChangeSubject, ChangeType, ConflictKind, EntryConflict, ImportSummary, MergeChange, MergeIntoOptions, MergeMode,
    MergeReport, SyncConflict,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use zeroize::Zeroizing;

use crate::convert::{arg, bad, field, int, obj, out, set, unit_enum, Elem, FromJs, SecretText, ToJs, MAX_SAFE};
use crate::error::{arg_err, to_js};

// ----------------------------------------------------------------------------------- records

#[wasm_bindgen(typescript_custom_section)]
const KDBX_TS: &str = "\
/** A KDBX key: any of a password (text), a password's SHA-256 (`kdbxPasswordHash`), a key file's bytes, or a 32-byte vault key (SPEC §7, the key-file component). */
export interface KdbxKey { password?: string | Uint8Array; passwordHash?: Uint8Array; keyFile?: Uint8Array; vaultKey?: Uint8Array }
export interface KdbxKeyVersion { version: number; key: Uint8Array }
/** Outer-header settings, readable without the key. */
export interface KdbxHeaderInfo { version: string; cipher: string; compression: \"none\" | \"gzip\"; kdf: KdbxKdfSettings }
/** `kdf`: `argon2id`, `argon2d`, `aes` or `other`; Argon2 `m` in bytes (as KDBX stores it), AES `t` = rounds. */
export interface KdbxKdfSettings { kdf: string; m?: number; t?: number; p?: number }
/** The SDK's `KeePassEntry` (times in Unix seconds, the password as UTF-8). */
export interface KdbxEntryInfo { uuid: string; title: string; username: string; passwordValue: Uint8Array; url: string; notes: string; groupName: string; groupUuid: string; tags: string[]; expiryTime?: number; lastModified?: number }
export interface KdbxGroupInfo { uuid: string; name: string; parentUuid?: string; icon: number; isRecycleBin: boolean }
export type ChangeSubject = \"entry\" | \"group\" | \"database\";
export interface KdbxMergeChange { change: ChangeType; subject: ChangeSubject; uuid?: string; title?: string; group?: string; details: string }
export interface KdbxEntryConflict { uuid: string; title: string; fields: string[] }
/** What the sync merge did (`added`/`updated`/`deleted`: entry ids, seen from the local side). */
export interface KdbxMergeReport { conflicts: KdbxEntryConflict[]; added: string[]; updated: string[]; deleted: string[]; changes: KdbxMergeChange[]; localChanged: boolean; remoteChanged: boolean }
export interface KdbxSyncConflict { uuid: string; kind: ConflictKind; title: string; fields: string[] }
export interface KdbxImportSummary { added: number; updated: number; unchanged: number; groupsAdded: number; changes: KdbxMergeChange[] }
export type MergeMode = \"keep-newer\" | \"synchronize\";
export interface MergeIntoOptions { skipDatabaseCustomData?: boolean; skipGroups?: string[] }
/** Entry id → last modification in Unix milliseconds: the SDK's `Snapshot` (`Record<string, number>`). */
export type KdbxSnapshot = Record<string, number>;
";

unit_enum!(@no_ts ChangeType => ChangeType { Added => "added", Modified => "modified", Moved => "moved", Deleted => "deleted", Metadata => "metadata" });
unit_enum!(@no_ts ChangeSubject => ChangeSubject { Entry => "entry", Group => "group", Database => "database" });
unit_enum!(@no_ts ConflictKind => ConflictKind {
    EditedOnBoth => "edited-on-both", DeletedHereEditedThere => "deleted-here-edited-there", EditedHereDeletedThere => "edited-here-deleted-there",
});
unit_enum!(@no_ts MergeMode => MergeMode { KeepNewer => "keep-newer", Synchronize => "synchronize" });

/// A UUID as the kdbxweb id string.
struct Id(Uuid);

impl ToJs for Id {
    fn to_js(&self) -> JsValue {
        uuid_string(&self.0).to_js()
    }
}
impl FromJs for Id {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let s: String = String::from_js(v, path)?;
        parse_uuid_string(&s).map(Id).ok_or_else(|| bad(path, "an entry or group id"))
    }
}
impl Elem for Id {}

fn ids(v: &[Uuid]) -> JsValue {
    v.iter().map(|u| Id(*u).to_js()).collect::<Array>().into()
}

impl ToJs for MergeChange {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "change", self.change.to_js());
        set(&o, "subject", self.subject.to_js());
        set(&o, "uuid", self.uuid.map(Id).to_js());
        set(&o, "title", self.title.to_js());
        set(&o, "group", self.group.to_js());
        set(&o, "details", self.details.to_js());
        o.into()
    }
}
impl FromJs for MergeChange {
    fn from_js(_: &JsValue, path: &str) -> Result<Self, OvError> {
        Err(bad(path, "no KdbxMergeChange input"))
    }
}
impl Elem for MergeChange {}

impl ToJs for EntryConflict {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "uuid", Id(self.uuid).to_js());
        set(&o, "title", self.title.to_js());
        set(&o, "fields", self.fields.to_js());
        o.into()
    }
}
impl FromJs for EntryConflict {
    fn from_js(_: &JsValue, path: &str) -> Result<Self, OvError> {
        Err(bad(path, "no KdbxEntryConflict input"))
    }
}
impl Elem for EntryConflict {}

impl ToJs for MergeReport {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "conflicts", self.conflicts.to_js());
        set(&o, "added", ids(&self.added));
        set(&o, "updated", ids(&self.updated));
        set(&o, "deleted", ids(&self.deleted));
        set(&o, "changes", self.changes.to_js());
        set(&o, "localChanged", self.local_changed.to_js());
        set(&o, "remoteChanged", self.remote_changed.to_js());
        o.into()
    }
}

impl ToJs for SyncConflict {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "uuid", Id(self.uuid).to_js());
        set(&o, "kind", self.kind.to_js());
        set(&o, "title", self.title.to_js());
        set(&o, "fields", self.fields.to_js());
        o.into()
    }
}
impl FromJs for SyncConflict {
    fn from_js(_: &JsValue, path: &str) -> Result<Self, OvError> {
        Err(bad(path, "no KdbxSyncConflict input"))
    }
}
impl Elem for SyncConflict {}

impl ToJs for ImportSummary {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "added", self.added.to_js());
        set(&o, "updated", self.updated.to_js());
        set(&o, "unchanged", self.unchanged.to_js());
        set(&o, "groupsAdded", self.groups_added.to_js());
        set(&o, "changes", self.changes.to_js());
        o.into()
    }
}

impl ToJs for KeePassEntry {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "uuid", self.uuid.to_js());
        set(&o, "title", self.title.to_js());
        set(&o, "username", self.username.to_js());
        set(&o, "passwordValue", self.password_value.to_js());
        set(&o, "url", self.url.to_js());
        set(&o, "notes", self.notes.to_js());
        set(&o, "groupName", self.group_name.to_js());
        set(&o, "groupUuid", self.group_uuid.to_js());
        set(&o, "tags", self.tags.to_js());
        set(&o, "expiryTime", self.expiry_time.to_js());
        set(&o, "lastModified", self.last_modified.to_js());
        o.into()
    }
}
impl FromJs for KeePassEntry {
    fn from_js(_: &JsValue, path: &str) -> Result<Self, OvError> {
        Err(bad(path, "no KdbxEntryInfo input"))
    }
}
impl Elem for KeePassEntry {}

impl ToJs for KeePassGroup {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "uuid", self.uuid.to_js());
        set(&o, "name", self.name.to_js());
        set(&o, "parentUuid", self.parent_uuid.to_js());
        set(&o, "icon", self.icon.to_js());
        set(&o, "isRecycleBin", self.is_recycle_bin.to_js());
        o.into()
    }
}
impl FromJs for KeePassGroup {
    fn from_js(_: &JsValue, path: &str) -> Result<Self, OvError> {
        Err(bad(path, "no KdbxGroupInfo input"))
    }
}
impl Elem for KeePassGroup {}

impl ToJs for KdfSettings {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "kdf", self.kdf.to_js());
        set(&o, "m", self.m.to_js());
        set(&o, "t", self.t.to_js());
        set(&o, "p", self.p.to_js());
        o.into()
    }
}

/// The header's settings, as `kdfSettings` reports them for a database.
fn header_info(h: &Header) -> JsValue {
    let o = obj();
    set(&o, "version", format!("{}.{}", h.version.major, h.version.minor).to_js());
    let cipher = match &h.cipher {
        Cipher::Aes256Cbc => "aes256".to_string(),
        Cipher::ChaCha20 => "chacha20".to_string(),
        Cipher::Twofish => "twofish".to_string(),
        Cipher::Other(u) => u.hyphenated().to_string(),
    };
    set(&o, "cipher", cipher.to_js());
    let compression = match h.compression {
        Compression::None => "none",
        Compression::Gzip => "gzip",
    };
    set(&o, "compression", compression.to_string().to_js());
    let kdf = match &h.kdf {
        Kdf::Argon2 { kind, memory, iterations, parallelism, .. } => KdfSettings {
            kdf: match kind {
                ov_kdbx::model::Argon2Type::Id => "argon2id",
                ov_kdbx::model::Argon2Type::D => "argon2d",
            }
            .into(),
            m: Some(*memory),
            t: Some(*iterations),
            p: Some(*parallelism),
        },
        Kdf::AesKdf { rounds, .. } => KdfSettings { kdf: "aes".into(), m: None, t: Some(*rounds), p: None },
        Kdf::Other(_) => KdfSettings { kdf: "other".into(), m: None, t: None, p: None },
    };
    set(&o, "kdf", kdf.to_js());
    o.into()
}

/// `KdbxKey` → the composite key.
struct Key(CompositeKey);

impl FromJs for Key {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        if !v.is_object() {
            return Err(bad(path, "a KdbxKey object"));
        }
        let vault_key: Option<Zeroizing<Vec<u8>>> = field(v, "vaultKey", path)?;
        let password: Option<SecretText> = field(v, "password", path)?;
        let hash: Option<Zeroizing<[u8; 32]>> = field(v, "passwordHash", path)?;
        let key_file: Option<Zeroizing<Vec<u8>>> = field(v, "keyFile", path)?;
        if let Some(vk) = vault_key {
            if password.is_some() || hash.is_some() || key_file.is_some() {
                return Err(bad(path, "either vaultKey or password/passwordHash/keyFile"));
            }
            return vault::vault_credentials(&vk).map(Key);
        }
        let mut k = CompositeKey::new();
        if let Some(p) = &password {
            k = k.with_password(p);
        }
        if let Some(h) = &hash {
            k = k.with_password_hash(h);
        }
        if let Some(f) = &key_file {
            k = k.with_key_file(f);
        }
        if k.is_empty() {
            return Err(bad(path, "a KdbxKey with a password, passwordHash, keyFile or vaultKey"));
        }
        Ok(Key(k))
    }
}

impl FromJs for KeyVersion {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        Ok(KeyVersion { version: field(v, "version", path)?, key: field(v, "key", path)? })
    }
}
impl ToJs for KeyVersion {
    fn to_js(&self) -> JsValue {
        JsValue::UNDEFINED
    }
}
impl Elem for KeyVersion {}

/// Seconds now, or the given `nowSecs`.
#[allow(clippy::cast_possible_truncation)]
fn now(now_secs: Option<f64>) -> Result<Timestamp, JsValue> {
    match now_secs {
        Some(n) => int(&JsValue::from_f64(n), "nowSecs", -MAX_SAFE, MAX_SAFE).map(|n| n as i64).map_err(arg_err),
        None => Ok((js_sys::Date::now() / 1000.0).floor() as i64),
    }
}

fn snapshot_from(v: &JsValue) -> Result<Vec<(Uuid, i64)>, JsValue> {
    if !v.is_object() || Array::is_array(v) {
        return Err(arg_err(bad("snapshot", "a Record<id, ms> object")));
    }
    js_sys::Object::entries(v.unchecked_ref())
        .iter()
        .map(|pair| {
            let pair: Array = pair.unchecked_into();
            let p = format!("snapshot[{}]", pair.get(0).as_string().unwrap_or_default());
            let id = Id::from_js(&pair.get(0), &p).map_err(arg_err)?;
            let ms = i64::from_js(&pair.get(1), &p).map_err(arg_err)?;
            Ok((id.0, ms))
        })
        .collect()
}

fn err(e: OvError) -> JsValue {
    to_js(&e)
}

// -------------------------------------------------------------------------------------- Kdbx

/// One decrypted KDBX database. `Kdbx.read(bytes, key)` → inspect, merge, import → `write()`.
/// `free()` drops it (the decrypted model lives in the module's memory until then).
#[wasm_bindgen(js_name = Kdbx)]
pub struct KdbxJs {
    db: Database,
    key: Option<CompositeKey>,
}

#[wasm_bindgen(js_class = Kdbx)]
impl KdbxJs {
    /// Opens a KDBX 3.1 or 4.x file. `vault_key_mismatch` for a wrong key, `kdbx_error` for a file
    /// that isn't KDBX or is corrupt or unsupported. The key is kept for `write()`.
    pub fn read(
        bytes: &[u8],
        #[wasm_bindgen(unchecked_param_type = "KdbxKey")] key: JsValue,
    ) -> Result<KdbxJs, JsValue> {
        let Key(key) = arg(&key, "key").map_err(arg_err)?;
        let db = ov_kdbx::read(bytes, &key).map_err(err)?;
        Ok(KdbxJs { db, key: Some(key) })
    }

    /// Opens a vault with the newest of its key versions that fits (SPEC §7): `{ db, keyVersion }`.
    #[wasm_bindgen(js_name = openWithKeyVersions, unchecked_return_type = "{ db: Kdbx; keyVersion: number }")]
    pub fn open_with_key_versions(
        bytes: &[u8],
        #[wasm_bindgen(unchecked_param_type = "KdbxKeyVersion[]")] keys: JsValue,
    ) -> Result<JsValue, JsValue> {
        let keys: Vec<KeyVersion> = arg(&keys, "keys").map_err(arg_err)?;
        let (db, version) = vault::open_with_key_versions(bytes, &keys).map_err(err)?;
        let used = keys
            .iter()
            .find(|k| k.version == version)
            .map(|k| vault::vault_credentials(&k.key))
            .transpose()
            .map_err(err)?;
        let o = obj();
        set(&o, "db", KdbxJs { db, key: used }.into());
        set(&o, "keyVersion", version.to_js());
        Ok(o.into())
    }

    /// A new, empty database named `name` (KDBX 4, AES, Argon2d). Set a key with `setKey` before `write()`.
    pub fn create(name: &str, now_secs: Option<f64>) -> Result<KdbxJs, JsValue> {
        Ok(KdbxJs { db: vault::create_kdbx(name, now(now_secs)?).map_err(err)?, key: None })
    }

    /// A new vault database keyed with a 32-byte vault key (ChaCha20, the vault KDF).
    #[wasm_bindgen(js_name = createVault)]
    pub fn create_vault(name: &str, vault_key: Vec<u8>, now_secs: Option<f64>) -> Result<KdbxJs, JsValue> {
        let vk = Zeroizing::new(vault_key);
        let (db, key) = vault::create_vault_kdbx(name, &vk, now(now_secs)?).map_err(err)?;
        Ok(KdbxJs { db, key: Some(key) })
    }

    /// The outer header's settings, without the key.
    #[wasm_bindgen(js_name = peekHeader, unchecked_return_type = "KdbxHeaderInfo")]
    pub fn peek_header(bytes: &[u8]) -> Result<JsValue, JsValue> {
        ov_kdbx::peek_header(bytes).map(|h| header_info(&h)).map_err(err)
    }

    /// Saves as KDBX 4 with `key`, or the key it was read or created with.
    #[wasm_bindgen(unchecked_return_type = "Uint8Array")]
    pub fn write(
        &self,
        #[wasm_bindgen(unchecked_optional_param_type = "KdbxKey")] key: Option<JsValue>,
    ) -> Result<Uint8Array, JsValue> {
        let key = key.unwrap_or(JsValue::UNDEFINED);
        let given: Option<Key> = arg(&key, "key").map_err(arg_err)?;
        let key = match (&given, &self.key) {
            (Some(Key(k)), _) | (None, Some(k)) => k,
            (None, None) => {
                return Err(err(OvError::new(
                    OvErrorCode::InvalidRequest,
                    "this database has no key: pass one or call setKey",
                )))
            }
        };
        ov_kdbx::write(&self.db, key).map(|b| out(&Zeroizing::new(b))).map_err(err)
    }

    /// Replaces the key `write()` uses.
    #[wasm_bindgen(js_name = setKey)]
    pub fn set_key(&mut self, #[wasm_bindgen(unchecked_param_type = "KdbxKey")] key: JsValue) -> Result<(), JsValue> {
        let Key(k) = arg(&key, "key").map_err(arg_err)?;
        self.key = Some(k);
        Ok(())
    }

    /// Re-keys to a vault key: the vault KDF, and the vault key as the key from now on.
    #[wasm_bindgen(js_name = rekeyToVaultKey)]
    pub fn rekey_to_vault_key(&mut self, vault_key: Vec<u8>) -> Result<(), JsValue> {
        let vk = Zeroizing::new(vault_key);
        self.key = Some(vault::rekey_to_vault_key(&mut self.db, &vk).map_err(err)?);
        Ok(())
    }

    /// Switches to the vault KDF (Argon2id, 1 GiB… as `VAULT_KDF`).
    #[wasm_bindgen(js_name = applyVaultKdf)]
    pub fn apply_vault_kdf(&mut self) -> Result<(), JsValue> {
        vault::apply_vault_kdf(&mut self.db).map_err(err)
    }

    /// The KDF settings the database is saved with.
    #[wasm_bindgen(js_name = kdfSettings, unchecked_return_type = "KdbxKdfSettings")]
    pub fn kdf_settings(&self) -> JsValue {
        vault::kdf_settings(&self.db).to_js()
    }

    /// The outer-header settings it is saved with.
    #[wasm_bindgen(unchecked_return_type = "KdbxHeaderInfo")]
    pub fn header(&self) -> JsValue {
        header_info(&self.db.header)
    }

    /// Removes the desktop's sync-server remotes from the database settings (an imported file).
    #[wasm_bindgen(js_name = dropServerRemotes)]
    pub fn drop_server_remotes(&mut self) {
        vault::drop_server_remotes(&mut self.db);
    }

    /// The sync generation in the custom data (0 when absent).
    #[wasm_bindgen(js_name = syncGeneration)]
    pub fn sync_generation(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let g = vault::sync_generation(&self.db) as f64;
        g
    }

    /// Sets the sync generation.
    #[wasm_bindgen(js_name = setSyncGeneration)]
    pub fn set_sync_generation(&mut self, generation: f64, now_secs: Option<f64>) -> Result<(), JsValue> {
        let g = u64::from_js(&JsValue::from_f64(generation), "generation").map_err(arg_err)?;
        vault::set_sync_generation(&mut self.db, g, now(now_secs)?);
        Ok(())
    }

    /// A deep copy (with the same key).
    #[wasm_bindgen(js_name = clone)]
    pub fn clone_db(&self) -> KdbxJs {
        KdbxJs { db: vault::copy_kdbx(&self.db), key: self.key.clone() }
    }

    /// The database name (Meta).
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.db.meta.database_name.clone()
    }

    /// The root group's id.
    #[wasm_bindgen(getter, js_name = rootGroupId)]
    pub fn root_group_id(&self) -> String {
        uuid_string(&self.db.root.uuid)
    }

    /// Every entry (Recycle Bin included), depth first, as the SDK's `collectAllDbData`.
    #[wasm_bindgen(unchecked_return_type = "KdbxEntryInfo[]")]
    pub fn entries(&self) -> JsValue {
        collect_all_db_data(&self.db).0.to_js()
    }

    /// Every group, depth first.
    #[wasm_bindgen(unchecked_return_type = "KdbxGroupInfo[]")]
    pub fn groups(&self) -> JsValue {
        collect_all_db_data(&self.db).1.to_js()
    }

    /// The sync merge (SDK `mergeDatabases`) without a base: both copies end up with the same entries.
    #[wasm_bindgen(unchecked_return_type = "KdbxMergeReport")]
    pub fn merge(&mut self, remote: &mut KdbxJs, now_secs: Option<f64>) -> Result<JsValue, JsValue> {
        Ok(ov_merge::merge_in_place(&mut self.db, &mut remote.db, None, now(now_secs)?).to_js())
    }

    /// The sync merge against `base`, the copy both last synced from.
    #[wasm_bindgen(js_name = mergeWithBase, unchecked_return_type = "KdbxMergeReport")]
    pub fn merge_with_base(
        &mut self,
        remote: &mut KdbxJs,
        base: &KdbxJs,
        now_secs: Option<f64>,
    ) -> Result<JsValue, JsValue> {
        Ok(ov_merge::merge_in_place(&mut self.db, &mut remote.db, Some(&base.db), now(now_secs)?).to_js())
    }

    /// The one-way structure merge of `source` into this database (SDK `mergeInto`).
    #[wasm_bindgen(js_name = mergeFrom, unchecked_return_type = "KdbxMergeChange[]")]
    pub fn merge_from(
        &mut self,
        source: &KdbxJs,
        #[wasm_bindgen(unchecked_optional_param_type = "MergeMode")] mode: Option<JsValue>,
        #[wasm_bindgen(unchecked_optional_param_type = "MergeIntoOptions")] opts: Option<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let mode = mode.unwrap_or(JsValue::UNDEFINED);
        let opts = opts.unwrap_or(JsValue::UNDEFINED);
        let mode: Option<MergeMode> = arg(&mode, "mode").map_err(arg_err)?;
        let opts = if opts.is_undefined() || opts.is_null() {
            MergeIntoOptions::default()
        } else {
            let skip: Option<Vec<Id>> = field(&opts, "skipGroups", "opts").map_err(arg_err)?;
            MergeIntoOptions {
                skip_database_custom_data: field::<Option<bool>>(&opts, "skipDatabaseCustomData", "opts")
                    .map_err(arg_err)?
                    .unwrap_or(false),
                skip_groups: skip.unwrap_or_default().into_iter().map(|i| i.0).collect(),
            }
        };
        Ok(ov_merge::merge_into(&source.db, &mut self.db, mode.unwrap_or_default(), &opts).to_js())
    }

    /// Imports `source` by UUID, keeping newer versions and deleting nothing (SDK `importInto`).
    #[wasm_bindgen(js_name = importFrom, unchecked_return_type = "KdbxImportSummary")]
    pub fn import_from(&mut self, source: &KdbxJs) -> JsValue {
        ov_merge::import_into(&source.db, &mut self.db).to_js()
    }

    /// Imports `source`'s entries as new copies under the group `parentId` (SDK `importAsCopies`).
    #[wasm_bindgen(js_name = importAsCopies, unchecked_return_type = "KdbxImportSummary")]
    pub fn import_as_copies(
        &mut self,
        source: &KdbxJs,
        parent_id: &str,
        now_secs: Option<f64>,
    ) -> Result<JsValue, JsValue> {
        let parent = Id::from_js(&JsValue::from_str(parent_id), "parentId").map_err(arg_err)?;
        let mut failed: Option<OvError> = None;
        let mut new_uuid = || match vault::new_uuid() {
            Ok(u) => u,
            Err(e) => {
                failed.get_or_insert(e);
                Uuid::nil()
            }
        };
        let r = ov_merge::import_as_copies(&source.db, &mut self.db, parent.0, now(now_secs)?, &mut new_uuid);
        if let Some(e) = failed {
            return Err(err(e));
        }
        r.map(|s| s.to_js()).map_err(err)
    }

    /// Where entries can be imported to: `{ uuid, path }` for every group outside the Recycle Bin.
    #[wasm_bindgen(js_name = importTargets, unchecked_return_type = "{ uuid: string; path: string }[]")]
    pub fn import_targets(&self) -> JsValue {
        ov_merge::import_targets(&self.db)
            .into_iter()
            .map(|(u, path)| {
                let o = obj();
                set(&o, "uuid", Id(u).to_js());
                set(&o, "path", path.to_js());
                JsValue::from(o)
            })
            .collect::<Array>()
            .into()
    }

    /// The snapshot to keep after a sync (SDK `snapshotOf`).
    #[wasm_bindgen(unchecked_return_type = "KdbxSnapshot")]
    pub fn snapshot(&self) -> JsValue {
        let o = obj();
        for (u, ms) in ov_merge::snapshot_of(&self.db) {
            set(&o, &uuid_string(&u), ms.to_js());
        }
        o.into()
    }

    /// Conflicts between this (local) copy and `remote` since `snapshot` (SDK `findConflicts`).
    #[wasm_bindgen(js_name = findConflicts, unchecked_return_type = "KdbxSyncConflict[]")]
    pub fn find_conflicts(
        &self,
        remote: &KdbxJs,
        #[wasm_bindgen(unchecked_param_type = "KdbxSnapshot")] snapshot: JsValue,
    ) -> Result<JsValue, JsValue> {
        Ok(ov_merge::find_conflicts(&self.db, &remote.db, &snapshot_from(&snapshot)?).to_js())
    }

    /// Whether the merge needs the common base (SDK `needsCommonBase`).
    #[wasm_bindgen(js_name = needsCommonBase)]
    pub fn needs_common_base(
        &self,
        remote: &KdbxJs,
        #[wasm_bindgen(unchecked_param_type = "KdbxSnapshot")] snapshot: JsValue,
    ) -> Result<bool, JsValue> {
        Ok(ov_merge::needs_common_base(&self.db, &remote.db, &snapshot_from(&snapshot)?))
    }

    /// Whether either side has deletions the other hasn't seen (SDK `hasPendingDeletions`).
    #[wasm_bindgen(js_name = hasPendingDeletions)]
    pub fn has_pending_deletions(&self, remote: &KdbxJs) -> bool {
        ov_merge::has_pending_deletions(&self.db, &remote.db)
    }
}

/// SHA-256 of a password as KDBX uses it (the SDK's `passwordHash`).
#[wasm_bindgen(js_name = kdbxPasswordHash)]
pub fn kdbx_password_hash(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] password: JsValue,
) -> Result<Uint8Array, JsValue> {
    let pw: SecretText = arg(&password, "password").map_err(arg_err)?;
    Ok(out(&vault::password_hash(&pw)[..]))
}

/// The sync merge on file bytes: reads `local`, `remote` and `base` (when given) with `key`, merges,
/// and writes both copies back with the same key. `{ local, remote, report }`; upload `remote` when
/// `report.remoteChanged`.
#[wasm_bindgen(js_name = kdbxMerge, unchecked_return_type = "{ local: Uint8Array; remote: Uint8Array; report: KdbxMergeReport }")]
pub fn kdbx_merge(
    local: &[u8],
    remote: &[u8],
    base: Option<Vec<u8>>,
    #[wasm_bindgen(unchecked_param_type = "KdbxKey")] key: JsValue,
    now_secs: Option<f64>,
) -> Result<JsValue, JsValue> {
    let Key(key) = arg(&key, "key").map_err(arg_err)?;
    let now = now(now_secs)?;
    let mut l = ov_kdbx::read(local, &key).map_err(err)?;
    let mut r = ov_kdbx::read(remote, &key).map_err(err)?;
    let b = base.map(|b| ov_kdbx::read(&Zeroizing::new(b), &key)).transpose().map_err(err)?;
    let report = ov_merge::merge_in_place(&mut l, &mut r, b.as_ref(), now);
    let o = obj();
    set(&o, "local", out(&Zeroizing::new(ov_kdbx::write(&l, &key).map_err(err)?)).into());
    set(&o, "remote", out(&Zeroizing::new(ov_kdbx::write(&r, &key).map_err(err)?)).into());
    set(&o, "report", report.to_js());
    Ok(o.into())
}
