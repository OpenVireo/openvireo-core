//! Whole entries ("items") for `ov item`, `ov connect` and `ServiceAccount.edit`: listing, reading
//! and setting several fields of one entry by reference (SPEC §14).
//!
//! Port of the SDK's `vault/items.ts`.

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::entries::{apply_history_rules, create_group, find_entry_mut, set_field};
use ov_kdbx::model::{Database, Entry, Group, Timestamp, Uuid, STANDARD_FIELDS};
use ov_kdbx::vault::new_uuid;
use zeroize::Zeroizing;

use crate::reference::{find_entry, locate, resolve_field_name, ItemReference};

/// One field of an [`Item`].
#[derive(Clone, PartialEq, Eq)]
pub struct ItemField {
    /// The field name.
    pub name: String,
    /// Its value. Wiped on drop.
    pub value: Zeroizing<String>,
}

impl std::fmt::Debug for ItemField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemField").field("name", &self.name).finish_non_exhaustive()
    }
}

/// An entry as JSON-friendly data (TS `Item`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The entry UUID, 32 lowercase hex digits (as OpenVireo shows it).
    pub id: String,
    /// `Title`.
    pub title: String,
    /// Group names from below the root down to the entry's group.
    pub group: Vec<String>,
    /// Field values in file order; which ones depends on [`ItemValues`].
    pub fields: Vec<ItemField>,
    /// Names of the protected fields (always listed).
    pub protected: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Last modification, ISO 8601 with milliseconds (`2024-01-02T03:04:05.000Z`).
    pub updated_at: String,
}

impl Item {
    /// The value of a field, if it is in [`Item::fields`].
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|f| f.name == name).map(|f| f.value.as_str())
    }
}

/// Which values [`item_of`] includes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ItemValues {
    /// No values (names of protected fields are still listed). What [`list_items`] gives.
    None,
    /// Unprotected values only (TS default).
    #[default]
    Unprotected,
    /// Every value (`reveal`).
    All,
}

/// The entry UUID as 32 lowercase hex digits.
pub fn entry_id(entry: &Entry) -> String {
    entry.uuid.simple().to_string()
}

/// Unix seconds as ISO 8601 UTC with milliseconds, as JavaScript's `Date.toISOString`.
pub fn iso8601(ts: Timestamp) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // civil_from_days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// An entry as an [`Item`]; `group` is its group path (from [`find_entry`] or [`list_items`]).
pub fn item_of(entry: &Entry, group: &[String], values: ItemValues) -> Item {
    let mut fields = Vec::new();
    let mut protected = Vec::new();
    for f in &entry.strings {
        if f.protected {
            protected.push(f.key.clone());
        }
        let include = match values {
            ItemValues::None => false,
            ItemValues::Unprotected => !f.protected,
            ItemValues::All => true,
        };
        if include {
            fields.push(ItemField { name: f.key.clone(), value: f.value.clone() });
        }
    }
    Item {
        id: entry_id(entry),
        title: entry.title().to_owned(),
        group: group.to_vec(),
        fields,
        protected,
        tags: entry.tags.clone(),
        updated_at: iso8601(entry.times.last_modification),
    }
}

/// The item a reference names (its vault part is the caller's business). Errors as [`find_entry`].
pub fn find_item(db: &Database, r: &ItemReference, values: ItemValues) -> Result<Item, OvError> {
    let (entry, path) = find_entry(db, &r.group_path, &r.entry)?;
    Ok(item_of(entry, &path, values))
}

/// Every entry outside the Recycle Bin, without field values, entries before subgroups.
pub fn list_items(db: &Database) -> Vec<Item> {
    fn walk(g: &Group, path: &mut Vec<String>, rb: Option<Uuid>, out: &mut Vec<Item>) {
        if Some(g.uuid) == rb {
            return;
        }
        for e in &g.entries {
            out.push(item_of(e, path, ItemValues::None));
        }
        for c in &g.groups {
            path.push(c.name.clone());
            walk(c, path, rb, out);
            path.pop();
        }
    }
    let mut out = Vec::new();
    walk(&db.root, &mut Vec::new(), db.meta.recycle_bin_uuid, &mut out);
    out
}

/// `Password` and custom fields are stored protected; `Title`, `UserName`, `URL` and `Notes` aren't.
pub fn is_protected_by_default(field: &str) -> bool {
    field == "Password" || !STANDARD_FIELDS.contains(&field)
}

/// Whether [`set_item_fields`] may create the entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CreateMode {
    /// The entry must exist (`entry_not_found`).
    #[default]
    MustExist,
    /// Create it (by title, under its group path) when missing.
    CreateIfMissing,
    /// Create it; `conflict` (409) if it exists.
    CreateOnly,
}

/// A field to set.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldUpdate {
    /// Field name or alias (resolved as [`resolve_field_name`]).
    pub name: String,
    /// The value. Wiped on drop.
    pub value: Zeroizing<String>,
    /// Store it protected; `None`: [`is_protected_by_default`] of the resolved name.
    pub protected: Option<bool>,
}

impl std::fmt::Debug for FieldUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldUpdate").field("name", &self.name).field("protected", &self.protected).finish()
    }
}

/// What [`set_item_fields`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetFieldsOutcome {
    /// The entry changed or created.
    pub entry_id: Uuid,
    /// It was created.
    pub created: bool,
}

/// A new entry as kdbxweb's `createEntry` makes it: the standard fields empty, protected as the
/// database's memory protection says.
fn new_entry(db: &Database, now: Timestamp) -> Result<Entry, OvError> {
    let mut e = Entry::new(new_uuid()?, now);
    let mp = db.meta.memory_protection;
    for (key, protect) in STANDARD_FIELDS.iter().zip([mp.title, mp.user_name, mp.password, mp.url, mp.notes]) {
        set_field(&mut e, key, "", protect);
    }
    Ok(e)
}

/// Sets several fields of the entry `r` names, keeping history: an existing entry's current state is
/// pushed to its history first (as KeePassXC does), the modification time becomes `now`, and the
/// database's history limits are applied. With [`CreateMode::CreateIfMissing`] or
/// [`CreateMode::CreateOnly`] a missing entry is created by title under its group path, making
/// missing groups.
///
/// Errors: `entry_not_found` (missing with [`CreateMode::MustExist`], or several entries with the
/// title, whatever the mode); `conflict` (409) when it exists with [`CreateMode::CreateOnly`].
pub fn set_item_fields(
    db: &mut Database,
    r: &ItemReference,
    fields: &[FieldUpdate],
    create: CreateMode,
    now: Timestamp,
) -> Result<SetFieldsOutcome, OvError> {
    let found = match locate(db, &r.group_path, &r.entry) {
        Ok((_, id)) => Some(id),
        Err(l) if l.ambiguous || create == CreateMode::MustExist => return Err(l.error),
        Err(_) => None,
    };
    let (id, created) = match found {
        Some(id) => {
            if create == CreateMode::CreateOnly {
                return Err(OvError::new(OvErrorCode::Conflict, format!("entry \"{}\" already exists", r.entry))
                    .with_status(409));
            }
            let e = find_entry_mut(&mut db.root, id)
                .ok_or_else(|| OvError::new(OvErrorCode::EntryNotFound, "entry not found"))?;
            let mut snapshot = e.clone();
            snapshot.history.clear();
            e.history.push(snapshot);
            (id, false)
        }
        None => {
            let mut group = db.root.uuid;
            for name in &r.group_path {
                let parent =
                    ov_kdbx::entries::find_group(&db.root, group).ok_or_else(|| OvError::internal("group vanished"))?;
                group = match parent.groups.iter().find(|g| &g.name == name) {
                    Some(g) => g.uuid,
                    None => create_group(db, group, name, now)?,
                };
            }
            let mut e = new_entry(db, now)?;
            set_field(&mut e, "Title", &r.entry, false);
            let id = e.uuid;
            ov_kdbx::entries::find_group_mut(&mut db.root, group)
                .ok_or_else(|| OvError::internal("group vanished"))?
                .entries
                .push(e);
            (id, true)
        }
    };
    let e = find_entry_mut(&mut db.root, id).ok_or_else(|| OvError::internal("entry vanished"))?;
    for f in fields {
        let name = resolve_field_name(e, &f.name);
        let protect = f.protected.unwrap_or_else(|| is_protected_by_default(&name));
        set_field(e, &name, &f.value, protect);
    }
    e.times.last_modification = now;
    e.times.last_access = now;
    apply_history_rules(db);
    Ok(SetFieldsOutcome { entry_id: id, created })
}
