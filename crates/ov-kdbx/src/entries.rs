//! Entry and group operations, ported from the SDK's `vault/entries.ts` (kdbxweb semantics).
//!
//! Items are addressed by [`Uuid`]; [`uuid_string`] gives the id string the web app uses
//! (kdbxweb's `KdbxUuid.toString()`, base64). Times come in as `now` (Unix seconds) because the core
//! takes time from the host's clock.
//!
//! Differences from the TS code, all deliberate:
//! - Deleting a group for good records a `DeletedObject` for every entry and subgroup inside it, as
//!   KeePassXC does (kdbxweb records only the group), so sync can't bring them back.
//! - `PreviousParentGroup` is set on a move only for KDBX 4.1 databases (4.0 has no such element).

use base64::Engine as _;
use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::model::{Database, DeletedObject, Entry, Group, KdbxVersion, StringField, Timestamp, Uuid, STANDARD_FIELDS};
use crate::vault::new_uuid;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The KeePass "trash bin" icon kdbxweb gives a new Recycle Bin.
pub const RECYCLE_BIN_ICON: u32 = 43;

/// An entry as the web app lists it (TS `KeePassEntry`). Times are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeePassEntry {
    /// [`uuid_string`] of the entry.
    pub uuid: String,
    /// `Title`, or `"(Untitled Entry)"`.
    pub title: String,
    /// `UserName`.
    pub username: String,
    /// `Password` (wiped on drop).
    pub password_value: Zeroizing<String>,
    /// `URL`.
    pub url: String,
    /// `Notes`.
    pub notes: String,
    /// The group's name (`"Root"` when empty).
    pub group_name: String,
    /// [`uuid_string`] of the group.
    pub group_uuid: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Expiry, when the entry expires.
    pub expiry_time: Option<Timestamp>,
    /// Last modification.
    pub last_modified: Option<Timestamp>,
}

/// A group as the web app lists it (TS `KeePassGroup`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeePassGroup {
    /// [`uuid_string`] of the group.
    pub uuid: String,
    /// Name (`"Root"` when empty).
    pub name: String,
    /// The parent's [`uuid_string`]; `None` for the root.
    pub parent_uuid: Option<String>,
    /// Icon id.
    pub icon: u32,
    /// Whether this is the Recycle Bin.
    pub is_recycle_bin: bool,
}

/// New entry content (TS `EntryData`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryData {
    /// `Title`.
    pub title: String,
    /// `UserName`.
    pub username: String,
    /// `Password` (stored protected).
    pub password_value: Zeroizing<String>,
    /// `URL`.
    pub url: String,
    /// `Notes`.
    pub notes: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Expiry; `None` = doesn't expire.
    pub expiry_time: Option<Timestamp>,
}

/// A custom field value for [`EntryEdit::fields`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldValue {
    /// The value.
    pub value: Zeroizing<String>,
    /// Store it protected.
    pub protected: bool,
}

/// Changes to an entry (TS `editEntryInDb`'s `data`): `None` leaves a field as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryEdit {
    /// `Title`.
    pub title: Option<String>,
    /// `UserName`.
    pub username: Option<String>,
    /// `Password` (stored protected).
    pub password_value: Option<Zeroizing<String>>,
    /// `URL`.
    pub url: Option<String>,
    /// `Notes`.
    pub notes: Option<String>,
    /// Tags.
    pub tags: Option<Vec<String>>,
    /// `Some(None)` clears the expiry; `Some(Some(t))` sets it.
    pub expiry_time: Option<Option<Timestamp>>,
    /// Other fields to set, in order.
    pub fields: Vec<(String, FieldValue)>,
}

/// The id string the web app uses: kdbxweb's `KdbxUuid.toString()`, the base64 of the 16 bytes.
pub fn uuid_string(uuid: &Uuid) -> String {
    B64.encode(uuid.as_bytes())
}

/// Parses an id from [`uuid_string`] (base64), 32 hex digits or a hyphenated UUID.
pub fn parse_uuid_string(s: &str) -> Option<Uuid> {
    if let Ok(b) = B64.decode(s.trim()) {
        if let Ok(u) = Uuid::from_slice(&b) {
            return Some(u);
        }
    }
    Uuid::try_parse(s.trim()).ok()
}

fn not_found_entry() -> OvError {
    OvError::new(OvErrorCode::EntryNotFound, "Entry not found")
}

fn not_found_group(what: &str) -> OvError {
    OvError::new(OvErrorCode::NotFound, format!("{what} not found"))
}

// ---------------------------------------------------------------------------------------------
// Listing and finding

/// Every entry and group, depth first from the root (TS `collectAllDbData`). History items and
/// entries in the Recycle Bin are listed as the TS code lists them (bin entries included).
pub fn collect_all_db_data(db: &Database) -> (Vec<KeePassEntry>, Vec<KeePassGroup>) {
    fn walk(
        g: &Group,
        parent: Option<&str>,
        rb: Option<Uuid>,
        entries: &mut Vec<KeePassEntry>,
        groups: &mut Vec<KeePassGroup>,
    ) {
        let id = uuid_string(&g.uuid);
        let name = if g.name.is_empty() { "Root".to_owned() } else { g.name.clone() };
        groups.push(KeePassGroup {
            uuid: id.clone(),
            name: name.clone(),
            parent_uuid: parent.map(str::to_owned),
            icon: g.icon_id,
            is_recycle_bin: rb == Some(g.uuid),
        });
        for e in &g.entries {
            let title = e.title();
            entries.push(KeePassEntry {
                uuid: uuid_string(&e.uuid),
                title: if title.is_empty() { "(Untitled Entry)".into() } else { title.to_owned() },
                username: e.field_text("UserName").to_owned(),
                password_value: Zeroizing::new(e.field_text("Password").to_owned()),
                url: e.field_text("URL").to_owned(),
                notes: e.field_text("Notes").to_owned(),
                group_name: name.clone(),
                group_uuid: id.clone(),
                tags: e.tags.clone(),
                expiry_time: e.times.expires.then_some(e.times.expiry),
                last_modified: Some(e.times.last_modification),
            });
        }
        for sub in &g.groups {
            walk(sub, Some(&id), rb, entries, groups);
        }
    }
    let mut entries = Vec::new();
    let mut groups = Vec::new();
    walk(&db.root, None, db.meta.recycle_bin_uuid, &mut entries, &mut groups);
    (entries, groups)
}

/// The group `id` in the tree under `group` (itself included).
pub fn find_group(group: &Group, id: Uuid) -> Option<&Group> {
    if group.uuid == id {
        return Some(group);
    }
    group.groups.iter().find_map(|g| find_group(g, id))
}

/// Mutable [`find_group`].
pub fn find_group_mut(group: &mut Group, id: Uuid) -> Option<&mut Group> {
    if group.uuid == id {
        return Some(group);
    }
    group.groups.iter_mut().find_map(|g| find_group_mut(g, id))
}

/// The entry `id` in the tree under `group` (history items aren't searched).
pub fn find_entry(group: &Group, id: Uuid) -> Option<&Entry> {
    group.entries.iter().find(|e| e.uuid == id).or_else(|| group.groups.iter().find_map(|g| find_entry(g, id)))
}

/// Mutable [`find_entry`].
pub fn find_entry_mut(group: &mut Group, id: Uuid) -> Option<&mut Entry> {
    if let Some(i) = group.entries.iter().position(|e| e.uuid == id) {
        return Some(&mut group.entries[i]);
    }
    group.groups.iter_mut().find_map(|g| find_entry_mut(g, id))
}

/// The uuid of the group directly holding entry `id`.
fn entry_parent(group: &Group, id: Uuid) -> Option<Uuid> {
    if group.entries.iter().any(|e| e.uuid == id) {
        return Some(group.uuid);
    }
    group.groups.iter().find_map(|g| entry_parent(g, id))
}

/// The uuid of the group directly holding group `id`.
fn group_parent(group: &Group, id: Uuid) -> Option<Uuid> {
    if group.groups.iter().any(|g| g.uuid == id) {
        return Some(group.uuid);
    }
    group.groups.iter().find_map(|g| group_parent(g, id))
}

/// Whether group `id` is the Recycle Bin or inside it.
fn in_recycle_bin(db: &Database, id: Uuid) -> bool {
    let Some(rb) = db.meta.recycle_bin_uuid else { return false };
    find_group(&db.root, rb).is_some_and(|bin| find_group(bin, id).is_some())
}

fn is_v41(db: &Database) -> bool {
    db.header.version >= KdbxVersion { major: 4, minor: 1 }
}

// ---------------------------------------------------------------------------------------------
// Moving and deleting

fn detach_entry(group: &mut Group, id: Uuid) -> Option<Entry> {
    if let Some(i) = group.entries.iter().position(|e| e.uuid == id) {
        return Some(group.entries.remove(i));
    }
    group.groups.iter_mut().find_map(|g| detach_entry(g, id))
}

fn detach_group(group: &mut Group, id: Uuid) -> Option<Group> {
    if let Some(i) = group.groups.iter().position(|g| g.uuid == id) {
        return Some(group.groups.remove(i));
    }
    group.groups.iter_mut().find_map(|g| detach_group(g, id))
}

/// The Recycle Bin, made under the root when enabled but missing (kdbxweb `createRecycleBin`).
fn recycle_bin(db: &mut Database, now: Timestamp) -> Result<Option<Uuid>, OvError> {
    if !db.meta.recycle_bin_enabled {
        return Ok(None);
    }
    if let Some(rb) = db.meta.recycle_bin_uuid {
        if find_group(&db.root, rb).is_some() {
            return Ok(Some(rb));
        }
    }
    let mut bin = Group::new(new_uuid()?, "Recycle Bin", now);
    bin.icon_id = RECYCLE_BIN_ICON;
    bin.enable_auto_type = Some(false);
    bin.enable_searching = Some(false);
    let id = bin.uuid;
    db.root.groups.push(bin);
    db.meta.recycle_bin_uuid = Some(id);
    db.meta.recycle_bin_changed = Some(now);
    Ok(Some(id))
}

enum Item {
    Entry(Entry),
    Group(Group),
}

/// Moves a detached item into group `to` (kdbxweb `move`): `LocationChanged` = now, and on 4.1
/// `PreviousParentGroup` = the old parent.
fn attach(db: &mut Database, item: Item, from: Uuid, to: Uuid, now: Timestamp) -> Result<(), OvError> {
    let v41 = is_v41(db);
    let dest = find_group_mut(&mut db.root, to).ok_or_else(|| not_found_group("Target group"))?;
    match item {
        Item::Entry(mut e) => {
            e.times.location_changed = now;
            if v41 {
                e.previous_parent_group = Some(from);
            }
            dest.entries.push(e);
        }
        Item::Group(mut g) => {
            g.times.location_changed = now;
            if v41 {
                g.previous_parent_group = Some(from);
            }
            dest.groups.push(g);
        }
    }
    Ok(())
}

/// Records tombstones for a group deleted for good and everything inside it.
fn tombstone_group(db: &mut Database, g: &Group, now: Timestamp) {
    for e in &g.entries {
        db.deleted_objects.push(DeletedObject { uuid: e.uuid, deletion_time: now });
    }
    for sub in &g.groups {
        tombstone_group(db, sub, now);
    }
    db.deleted_objects.push(DeletedObject { uuid: g.uuid, deletion_time: now });
}

/// Deletes an entry (TS `deleteEntryFromDb`): into the Recycle Bin, or for good (with a
/// `DeletedObject`) when it is already there or the bin is disabled.
pub fn delete_entry(db: &mut Database, id: Uuid, now: Timestamp) -> Result<(), OvError> {
    let parent = entry_parent(&db.root, id).ok_or_else(not_found_entry)?;
    let bin = if in_recycle_bin(db, parent) { None } else { recycle_bin(db, now)? };
    let entry = detach_entry(&mut db.root, id).ok_or_else(not_found_entry)?;
    match bin {
        Some(bin) => attach(db, Item::Entry(entry), parent, bin, now),
        None => {
            db.deleted_objects.push(DeletedObject { uuid: entry.uuid, deletion_time: now });
            Ok(())
        }
    }
}

/// Deletes a group (TS `deleteGroupFromDb`): into the Recycle Bin, or for good when it is the bin,
/// is inside it, or the bin is disabled. The root can't be deleted (`invalid_request`).
pub fn delete_group(db: &mut Database, id: Uuid, now: Timestamp) -> Result<(), OvError> {
    if db.root.uuid == id {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "Cannot delete root group"));
    }
    let parent = group_parent(&db.root, id).ok_or_else(|| not_found_group("Group"))?;
    let bin = if in_recycle_bin(db, id) { None } else { recycle_bin(db, now)? };
    let group = detach_group(&mut db.root, id).ok_or_else(|| not_found_group("Group"))?;
    match bin {
        Some(bin) => attach(db, Item::Group(group), parent, bin, now),
        None => {
            tombstone_group(db, &group, now);
            Ok(())
        }
    }
}

/// Deletes everything in the Recycle Bin for good (TS `emptyRecycleBinInDb`). `invalid_request`
/// when there is no bin.
pub fn empty_recycle_bin(db: &mut Database, now: Timestamp) -> Result<(), OvError> {
    let rb = db
        .meta
        .recycle_bin_uuid
        .ok_or_else(|| OvError::new(OvErrorCode::InvalidRequest, "No Recycle Bin configured in this database."))?;
    let bin = find_group_mut(&mut db.root, rb).ok_or_else(|| not_found_group("Recycle Bin group"))?;
    let entries = std::mem::take(&mut bin.entries);
    let groups = std::mem::take(&mut bin.groups);
    for e in &entries {
        db.deleted_objects.push(DeletedObject { uuid: e.uuid, deletion_time: now });
    }
    for g in &groups {
        tombstone_group(db, g, now);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Entries

/// Sets a string field: replaced in place when present, else appended.
pub fn set_field(entry: &mut Entry, key: &str, value: &str, protected: bool) {
    match entry.strings.iter_mut().find(|f| f.key == key) {
        Some(f) => {
            f.value = Zeroizing::new(value.to_owned());
            f.protected = protected;
        }
        None => entry.strings.push(StringField::new(key, value, protected)),
    }
}

/// Adds an entry to group `group` (TS `addEntryToDb`): the standard fields (Password protected),
/// tags and expiry. Returns its uuid.
pub fn add_entry(db: &mut Database, group: Uuid, data: &EntryData, now: Timestamp) -> Result<Uuid, OvError> {
    let mut e = Entry::new(new_uuid()?, now);
    let id = e.uuid;
    for (key, value) in
        STANDARD_FIELDS.iter().zip([&data.title, &data.username, &*data.password_value, &data.url, &data.notes])
    {
        set_field(&mut e, key, value, *key == "Password");
    }
    e.tags = data.tags.clone();
    e.times.expires = data.expiry_time.is_some();
    if let Some(t) = data.expiry_time {
        e.times.expiry = t;
    }
    let g = find_group_mut(&mut db.root, group).ok_or_else(|| not_found_group("Target group"))?;
    g.entries.push(e);
    Ok(id)
}

/// Edits an entry (TS `editEntryInDb`): pushes its current state to history first (as KeePassXC
/// does), applies `edit`, sets the modification and access times to `now`, then applies the
/// history limits to the database.
pub fn edit_entry(db: &mut Database, id: Uuid, edit: &EntryEdit, now: Timestamp) -> Result<(), OvError> {
    let e = find_entry_mut(&mut db.root, id).ok_or_else(not_found_entry)?;
    let mut snapshot = e.clone();
    snapshot.history.clear();
    e.history.push(snapshot);
    let plain = [("Title", &edit.title), ("UserName", &edit.username), ("URL", &edit.url), ("Notes", &edit.notes)];
    for (key, value) in plain {
        if let Some(v) = value {
            set_field(e, key, v, false);
        }
    }
    if let Some(p) = &edit.password_value {
        set_field(e, "Password", p, true);
    }
    for (key, v) in &edit.fields {
        set_field(e, key, &v.value, v.protected);
    }
    if let Some(tags) = &edit.tags {
        e.tags = tags.clone();
    }
    if let Some(expiry) = edit.expiry_time {
        e.times.expires = expiry.is_some();
        if let Some(t) = expiry {
            e.times.expiry = t;
        }
    }
    e.times.last_modification = now;
    e.times.last_access = now;
    apply_history_rules(db);
    Ok(())
}

/// Trims every entry's history to `HistoryMaxItems` and `HistoryMaxSize`, oldest first (kdbxweb
/// `cleanup({historyRules: true})`). Negative limits mean unlimited.
pub fn apply_history_rules(db: &mut Database) {
    fn walk(g: &mut Group, max_items: i32, sizes: &dyn Fn(&Entry) -> i64, max_size: i64) {
        for e in &mut g.entries {
            if max_items >= 0 {
                let excess = e.history.len().saturating_sub(max_items as usize);
                e.history.drain(..excess);
            }
            if max_size >= 0 {
                let mut total: i64 = e.history.iter().map(sizes).sum();
                while total > max_size && !e.history.is_empty() {
                    total -= sizes(&e.history.remove(0));
                }
            }
        }
        for sub in &mut g.groups {
            walk(sub, max_items, sizes, max_size);
        }
    }
    let (max_items, max_size) = (db.meta.history_max_items, db.meta.history_max_size);
    let pool: Vec<usize> = db.binaries.iter().map(|b| b.data.len()).collect();
    let sizes = |e: &Entry| history_item_size_with(&pool, e);
    walk(&mut db.root, max_items, &sizes, max_size);
}

/// The size a history item counts for against `HistoryMaxSize`: its string keys and values, tags,
/// colours and override URL, and the attachments it refers to (`pool` holds attachment sizes).
fn history_item_size_with(pool: &[usize], e: &Entry) -> i64 {
    let strings: usize = e.strings.iter().map(|f| f.key.len() + f.value.len()).sum();
    let binaries: usize = e.binaries.iter().filter_map(|b| pool.get(b.index as usize)).sum();
    let other = e.tags.iter().map(String::len).sum::<usize>()
        + e.foreground_color.len()
        + e.background_color.len()
        + e.override_url.len();
    (strings + binaries + other) as i64
}

// ---------------------------------------------------------------------------------------------
// Groups

/// Creates a group under `parent` (TS `createGroupInDb`). Returns its uuid.
pub fn create_group(db: &mut Database, parent: Uuid, name: &str, now: Timestamp) -> Result<Uuid, OvError> {
    let g = Group::new(new_uuid()?, name, now);
    let id = g.uuid;
    find_group_mut(&mut db.root, parent).ok_or_else(|| not_found_group("Parent group"))?.groups.push(g);
    Ok(id)
}

/// Renames a group (TS `renameGroupInDb`).
pub fn rename_group(db: &mut Database, id: Uuid, name: &str, now: Timestamp) -> Result<(), OvError> {
    let g = find_group_mut(&mut db.root, id).ok_or_else(|| not_found_group("Group"))?;
    g.name = name.to_owned();
    g.times.last_modification = now;
    g.times.last_access = now;
    Ok(())
}

/// Sets a group's icon (TS `setGroupIconInDb`).
pub fn set_group_icon(db: &mut Database, id: Uuid, icon: u32, now: Timestamp) -> Result<(), OvError> {
    let g = find_group_mut(&mut db.root, id).ok_or_else(|| not_found_group("Group"))?;
    g.icon_id = icon;
    g.times.last_modification = now;
    g.times.last_access = now;
    Ok(())
}

/// A new database holding the selected groups' entries and the folders leading to them (TS
/// `exportSelectedGroupsToKdbx`). Entries get new uuids and copy their fields, tags and expiry, as
/// the TS code does. Save it with [`crate::write()`] and the export password.
pub fn export_selected_groups(original: &Database, selected: &[Uuid], now: Timestamp) -> Result<Database, OvError> {
    fn has_selected(g: &Group, selected: &[Uuid]) -> bool {
        selected.contains(&g.uuid) || g.groups.iter().any(|s| has_selected(s, selected))
    }
    fn copy(src: &Group, dst: &mut Group, selected: &[Uuid], now: Timestamp) -> Result<(), OvError> {
        if selected.contains(&src.uuid) {
            for e in &src.entries {
                let mut d = Entry::new(new_uuid()?, now);
                for f in &e.strings {
                    set_field(&mut d, &f.key, &f.value, f.protected);
                }
                d.tags = e.tags.clone();
                d.times.expires = e.times.expires;
                d.times.expiry = e.times.expiry;
                dst.entries.push(d);
            }
        }
        for sub in &src.groups {
            if has_selected(sub, selected) {
                let name = if sub.name.is_empty() { "Folder" } else { sub.name.as_str() };
                let mut d = Group::new(new_uuid()?, name, now);
                d.icon_id = sub.icon_id;
                copy(sub, &mut d, selected, now)?;
                dst.groups.push(d);
            }
        }
        Ok(())
    }
    let name = if original.root.name.is_empty() { "Exported DB" } else { original.root.name.as_str() };
    let mut out = crate::vault::create_kdbx(name, now)?;
    copy(&original.root, &mut out.root, selected, now)?;
    Ok(out)
}
