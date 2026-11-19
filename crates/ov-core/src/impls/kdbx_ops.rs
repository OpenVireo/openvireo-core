//! What [`Vault`](crate::api::Vault) does to its working copy: reading entries and groups as facade
//! records and editing them, on the `ov_kdbx` model. The entry and group primitives come from
//! `ov_kdbx::entries`; this module adds the record conversions and the few edits the facade has that
//! `vault/entries.ts` doesn't (field removal, icons, moves, attachments, restore).

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::entries::{find_entry, find_entry_mut, find_group, find_group_mut, parse_uuid_string, set_field};
use ov_kdbx::model::{Binary, BinaryRef, CustomIcon, Database, Entry, Group, KdbxVersion, Timestamp, Uuid};
use zeroize::Zeroizing;

use super::convert::uuid_hex;
use super::util::secret_text;
use crate::api::{
    AttachmentInfo, EntryExpiry, EntryInput, EntryRecord, EntrySummary, ExportFormat, FieldInput, FieldRecord,
    GroupInfo, SecretBytes, VersionDifference,
};

pub(crate) fn entry_not_found() -> OvError {
    OvError::new(OvErrorCode::EntryNotFound, "Entry not found")
}

fn group_not_found() -> OvError {
    OvError::new(OvErrorCode::NotFound, "Group not found")
}

/// Parses an id: 32 hex digits, a hyphenated UUID or kdbxweb's base64.
pub(crate) fn parse_id(s: &str) -> Result<Uuid, OvError> {
    parse_uuid_string(s).ok_or_else(|| OvError::new(OvErrorCode::InvalidRequest, format!("not an id: {s}")))
}

/// `(entry, group, path below the root)` for every entry, depth first.
fn walk_entries<'a>(g: &'a Group, path: &mut Vec<String>, out: &mut Vec<(&'a Entry, &'a Group, Vec<String>)>) {
    for e in &g.entries {
        out.push((e, g, path.clone()));
    }
    for sub in &g.groups {
        path.push(sub.name.clone());
        walk_entries(sub, path, out);
        path.pop();
    }
}

fn all_entries(db: &Database) -> Vec<(&Entry, &Group, Vec<String>)> {
    let mut out = Vec::new();
    walk_entries(&db.root, &mut Vec::new(), &mut out);
    out
}

fn entry_parent(g: &Group, id: Uuid) -> Option<Uuid> {
    if g.entries.iter().any(|e| e.uuid == id) {
        return Some(g.uuid);
    }
    g.groups.iter().find_map(|s| entry_parent(s, id))
}

fn group_parent(g: &Group, id: Uuid) -> Option<Uuid> {
    if g.groups.iter().any(|s| s.uuid == id) {
        return Some(g.uuid);
    }
    g.groups.iter().find_map(|s| group_parent(s, id))
}

/// Whether `id` (entry or group) is the Recycle Bin or inside it.
pub(crate) fn in_recycle_bin(db: &Database, id: Uuid) -> bool {
    let Some(rb) = db.meta.recycle_bin_uuid else { return false };
    let Some(bin) = find_group(&db.root, rb) else { return false };
    find_group(bin, id).is_some() || find_entry(bin, id).is_some()
}

fn attachments(db: &Database, e: &Entry) -> Vec<AttachmentInfo> {
    e.binaries
        .iter()
        .map(|b| AttachmentInfo {
            name: b.name.clone(),
            size: db.binaries.get(b.index as usize).map_or(0, |x| x.data.len() as u64),
            protected: db.binaries.get(b.index as usize).is_some_and(|x| x.protected),
        })
        .collect()
}

pub(crate) fn record(db: &Database, e: &Entry, g: &Group, path: Vec<String>) -> EntryRecord {
    EntryRecord {
        id: uuid_hex(&e.uuid),
        group_id: uuid_hex(&g.uuid),
        group_path: path,
        fields: e
            .strings
            .iter()
            .map(|f| FieldRecord { name: f.key.clone(), value: f.value.as_bytes().to_vec(), protected: f.protected })
            .collect(),
        tags: e.tags.clone(),
        icon_id: e.icon_id,
        custom_icon: e.custom_icon.as_ref().map(uuid_hex),
        foreground_color: e.foreground_color.clone(),
        background_color: e.background_color.clone(),
        override_url: e.override_url.clone(),
        created_at: e.times.creation,
        modified_at: e.times.last_modification,
        expires_at: e.times.expires.then_some(e.times.expiry),
        attachments: attachments(db, e),
        history_count: e.history.len() as u32,
        quality_check: e.quality_check.unwrap_or(true),
        last_access_at: last_access(e),
        usage_count: usage_count(e),
    }
}

/// `LastAccessTime` when the entry was ever used.
fn last_access(e: &Entry) -> Option<i64> {
    (e.times.usage_count > 0).then_some(e.times.last_access)
}

fn usage_count(e: &Entry) -> u32 {
    u32::try_from(e.times.usage_count).unwrap_or(u32::MAX)
}

fn summary(db: &Database, e: &Entry, g: &Group, path: Vec<String>) -> EntrySummary {
    EntrySummary {
        id: uuid_hex(&e.uuid),
        group_id: uuid_hex(&g.uuid),
        group_path: path,
        title: e.title().to_owned(),
        username: e.field_text("UserName").to_owned(),
        url: e.field_text("URL").to_owned(),
        tags: e.tags.clone(),
        protected_fields: e.strings.iter().filter(|f| f.protected).map(|f| f.key.clone()).collect(),
        icon_id: e.icon_id,
        custom_icon: e.custom_icon.as_ref().map(uuid_hex),
        modified_at: e.times.last_modification,
        expires_at: e.times.expires.then_some(e.times.expiry),
        in_recycle_bin: in_recycle_bin(db, g.uuid),
        last_access_at: last_access(e),
        usage_count: usage_count(e),
    }
}

pub(crate) fn entries(db: &Database, include_recycle_bin: bool) -> Vec<EntrySummary> {
    all_entries(db)
        .into_iter()
        .filter(|(_, g, _)| include_recycle_bin || !in_recycle_bin(db, g.uuid))
        .map(|(e, g, p)| summary(db, e, g, p))
        .collect()
}

pub(crate) fn entry_records(db: &Database, include_recycle_bin: bool) -> Vec<EntryRecord> {
    all_entries(db)
        .into_iter()
        .filter(|(_, g, _)| include_recycle_bin || !in_recycle_bin(db, g.uuid))
        .map(|(e, g, p)| record(db, e, g, p))
        .collect()
}

pub(crate) fn groups(db: &Database) -> Vec<GroupInfo> {
    fn go(db: &Database, g: &Group, parent: Option<Uuid>, path: &mut Vec<String>, out: &mut Vec<GroupInfo>) {
        out.push(GroupInfo {
            id: uuid_hex(&g.uuid),
            name: g.name.clone(),
            parent_id: parent.as_ref().map(uuid_hex),
            path: path.clone(),
            icon_id: g.icon_id,
            notes: g.notes.clone(),
            is_recycle_bin: db.meta.recycle_bin_uuid == Some(g.uuid),
            entry_count: g.entries.len() as u32,
        });
        for sub in &g.groups {
            path.push(sub.name.clone());
            go(db, sub, Some(g.uuid), path, out);
            path.pop();
        }
    }
    let mut out = Vec::new();
    go(db, &db.root, None, &mut Vec::new(), &mut out);
    out
}

pub(crate) fn entry(db: &Database, id: &str) -> Result<EntryRecord, OvError> {
    let id = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    all_entries(db)
        .into_iter()
        .find(|(e, _, _)| e.uuid == id)
        .map(|(e, g, p)| record(db, e, g, p))
        .ok_or_else(entry_not_found)
}

pub(crate) fn history(db: &Database, id: &str) -> Result<Vec<EntryRecord>, OvError> {
    let uid = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    let (e, g, p) = all_entries(db).into_iter().find(|(e, _, _)| e.uuid == uid).ok_or_else(entry_not_found)?;
    Ok(e.history.iter().map(|h| record(db, h, g, p.clone())).collect())
}

pub(crate) fn attachment(db: &Database, id: &str, name: &str) -> Result<SecretBytes, OvError> {
    let uid = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    let e = find_entry(&db.root, uid).ok_or_else(entry_not_found)?;
    let r = e
        .binaries
        .iter()
        .find(|b| b.name == name)
        .ok_or_else(|| OvError::new(OvErrorCode::NotFound, format!("no attachment named {name}")))?;
    db.binaries
        .get(r.index as usize)
        .map(|b| b.data.to_vec())
        .ok_or_else(|| OvError::new(OvErrorCode::KdbxError, "the attachment is missing from the file"))
}

pub(crate) fn custom_icon(db: &Database, id: &str) -> Result<Vec<u8>, OvError> {
    let uid = parse_id(id)?;
    db.meta
        .custom_icons
        .iter()
        .find(|i| i.uuid == uid)
        .map(|i| i.data.clone())
        .ok_or_else(|| OvError::new(OvErrorCode::NotFound, "no such custom icon"))
}

fn split_path(path: &str) -> Vec<&str> {
    path.split('/').map(str::trim).filter(|s| !s.is_empty()).collect()
}

pub(crate) fn group_id_at(db: &Database, path: &str) -> Option<Uuid> {
    let mut g = &db.root;
    for name in split_path(path) {
        g = g.groups.iter().find(|s| s.name == name)?;
    }
    Some(g.uuid)
}

pub(crate) fn ensure_group(db: &mut Database, path: &str, now: Timestamp) -> Result<Uuid, OvError> {
    let mut current = db.root.uuid;
    for name in split_path(path) {
        let g = find_group(&db.root, current).ok_or_else(group_not_found)?;
        current = match g.groups.iter().find(|s| s.name == name) {
            Some(s) => s.uuid,
            None => ov_kdbx::entries::create_group(db, current, name, now)?,
        };
    }
    Ok(current)
}

// ------------------------------------------------------------------------------- editing

/// A field name as stored: the five standard fields by any case, else as given.
fn field_key(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "title" => "Title".into(),
        "username" => "UserName".into(),
        "password" => "Password".into(),
        "url" => "URL".into(),
        "notes" => "Notes".into(),
        _ => name.to_owned(),
    }
}

fn default_protected(key: &str) -> bool {
    !matches!(key, "Title" | "UserName" | "URL" | "Notes")
}

/// `#RRGGBB` or empty.
fn check_color(c: &str) -> Result<(), OvError> {
    let ok = c.is_empty() || (c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(())
    } else {
        Err(OvError::new(OvErrorCode::InvalidRequest, format!("not a colour (#RRGGBB or empty): {c}")))
    }
}

/// Checks the parts of an input that depend on the database (colours, the custom icon) before
/// anything changes; returns the custom icon change as a UUID.
fn check_input(db: &Database, input: &EntryInput) -> Result<Option<Option<Uuid>>, OvError> {
    for c in [&input.foreground_color, &input.background_color].into_iter().flatten() {
        check_color(c)?;
    }
    match &input.custom_icon {
        None => Ok(None),
        Some(None) => Ok(Some(None)),
        Some(Some(id)) => {
            let uid = parse_id(id)?;
            if !db.meta.custom_icons.iter().any(|i| i.uuid == uid) {
                return Err(OvError::new(OvErrorCode::NotFound, "no such custom icon"));
            }
            Ok(Some(Some(uid)))
        }
    }
}

/// Puts the custom fields in `order` after the standard fields; the rest follow as they were.
fn reorder_fields(e: &mut Entry, order: &[String]) {
    let order: Vec<String> = order.iter().map(|n| field_key(n)).collect();
    let rank = |key: &str| -> (u8, usize) {
        if ov_kdbx::model::STANDARD_FIELDS.contains(&key) {
            (0, 0)
        } else {
            match order.iter().position(|o| o == key) {
                Some(i) => (1, i),
                None => (2, 0),
            }
        }
    };
    // A stable sort keeps the standard fields and the unnamed custom fields in their order.
    e.strings.sort_by_key(|f| rank(&f.key));
}

/// Applies an input to an entry (no history, no times). `icon` is [`check_input`]'s result.
fn apply_input(e: &mut Entry, input: EntryInput, icon: Option<Option<Uuid>>) -> Result<(), OvError> {
    for f in input.fields {
        let FieldInput { name, value, protected } = f;
        let key = field_key(&name);
        let text = secret_text(value, "field value")?;
        set_field(e, &key, &text, protected.unwrap_or_else(|| default_protected(&key)));
    }
    for name in input.remove_fields {
        let key = field_key(&name);
        if !ov_kdbx::model::STANDARD_FIELDS.contains(&key.as_str()) {
            e.strings.retain(|f| f.key != key);
        }
    }
    if let Some(tags) = input.tags {
        e.tags = tags;
    }
    if let Some(icon) = input.icon_id {
        e.icon_id = icon;
    }
    match input.expiry {
        EntryExpiry::Keep => {}
        EntryExpiry::Never => e.times.expires = false,
        EntryExpiry::At(t) => {
            e.times.expires = true;
            e.times.expiry = t;
        }
    }
    if let Some(c) = input.foreground_color {
        e.foreground_color = c;
    }
    if let Some(c) = input.background_color {
        e.background_color = c;
    }
    if let Some(icon) = icon {
        e.custom_icon = icon;
    }
    if let Some(order) = input.field_order {
        reorder_fields(e, &order);
    }
    Ok(())
}

pub(crate) fn add_entry(db: &mut Database, group: &str, input: EntryInput, now: Timestamp) -> Result<String, OvError> {
    add_new_entry(db, ov_kdbx::vault::new_uuid()?, group, input, now)
}

fn add_new_entry(
    db: &mut Database,
    id: Uuid,
    group: &str,
    input: EntryInput,
    now: Timestamp,
) -> Result<String, OvError> {
    let gid = parse_id(group)?;
    find_group(&db.root, gid).ok_or_else(group_not_found)?;
    let icon = check_input(db, &input)?;
    let mut e = Entry::new(id, now);
    apply_input(&mut e, input, icon)?;
    find_group_mut(&mut db.root, gid).ok_or_else(group_not_found)?.entries.push(e);
    Ok(uuid_hex(&id))
}

pub(crate) fn add_entry_with_id(
    db: &mut Database,
    id: &str,
    group: &str,
    input: EntryInput,
    now: Timestamp,
) -> Result<String, OvError> {
    let uid = parse_id(id)?;
    if uid.is_nil() {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "an entry id can't be the nil UUID"));
    }
    if find_entry(&db.root, uid).is_some() {
        return Err(OvError::new(OvErrorCode::Conflict, format!("an entry with id {} exists", uuid_hex(&uid))));
    }
    let out = add_new_entry(db, uid, group, input, now)?;
    db.deleted_objects.retain(|d| d.uuid != uid);
    Ok(out)
}

/// Pushes the entry's current state to its history and applies the history limits afterwards.
pub(crate) fn edit_with_history(
    db: &mut Database,
    id: Uuid,
    now: Timestamp,
    f: impl FnOnce(&mut Entry) -> Result<(), OvError>,
) -> Result<(), OvError> {
    let e = find_entry_mut(&mut db.root, id).ok_or_else(entry_not_found)?;
    let mut snapshot = e.clone();
    snapshot.history.clear();
    let before = e.clone();
    f(e)?;
    if *e != before {
        e.history.push(snapshot);
        e.times.last_modification = now;
        e.times.last_access = now;
    }
    ov_kdbx::entries::apply_history_rules(db);
    Ok(())
}

pub(crate) fn edit_entry(db: &mut Database, id: &str, input: EntryInput, now: Timestamp) -> Result<(), OvError> {
    let uid = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    find_entry(&db.root, uid).ok_or_else(entry_not_found)?;
    let icon = check_input(db, &input)?;
    edit_with_history(db, uid, now, |e| apply_input(e, input, icon))
}

fn detach_entry(g: &mut Group, id: Uuid) -> Option<Entry> {
    if let Some(i) = g.entries.iter().position(|e| e.uuid == id) {
        return Some(g.entries.remove(i));
    }
    g.groups.iter_mut().find_map(|s| detach_entry(s, id))
}

fn detach_group(g: &mut Group, id: Uuid) -> Option<Group> {
    if let Some(i) = g.groups.iter().position(|s| s.uuid == id) {
        return Some(g.groups.remove(i));
    }
    g.groups.iter_mut().find_map(|s| detach_group(s, id))
}

fn is_v41(db: &Database) -> bool {
    db.header.version >= KdbxVersion { major: 4, minor: 1 }
}

pub(crate) fn move_entry_to(db: &mut Database, id: Uuid, to: Uuid, now: Timestamp) -> Result<(), OvError> {
    find_group(&db.root, to).ok_or_else(group_not_found)?;
    let from = entry_parent(&db.root, id).ok_or_else(entry_not_found)?;
    if from == to {
        return Ok(());
    }
    let v41 = is_v41(db);
    let mut e = detach_entry(&mut db.root, id).ok_or_else(entry_not_found)?;
    e.times.location_changed = now;
    if v41 {
        e.previous_parent_group = Some(from);
    }
    find_group_mut(&mut db.root, to).ok_or_else(group_not_found)?.entries.push(e);
    Ok(())
}

pub(crate) fn move_group_to(db: &mut Database, id: Uuid, to: Uuid, now: Timestamp) -> Result<(), OvError> {
    if id == db.root.uuid {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "the root group can't be moved"));
    }
    let g = find_group(&db.root, id).ok_or_else(group_not_found)?;
    if find_group(g, to).is_some() {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "a group can't move into itself"));
    }
    find_group(&db.root, to).ok_or_else(group_not_found)?;
    let from = group_parent(&db.root, id).ok_or_else(group_not_found)?;
    if from == to {
        return Ok(());
    }
    let v41 = is_v41(db);
    let mut g = detach_group(&mut db.root, id).ok_or_else(group_not_found)?;
    g.times.location_changed = now;
    if v41 {
        g.previous_parent_group = Some(from);
    }
    find_group_mut(&mut db.root, to).ok_or_else(group_not_found)?.groups.push(g);
    Ok(())
}

pub(crate) fn restore_from_recycle_bin(db: &mut Database, id: &str, now: Timestamp) -> Result<(), OvError> {
    let uid = parse_id(id)?;
    if !in_recycle_bin(db, uid) || Some(uid) == db.meta.recycle_bin_uuid {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "this isn't in the Recycle Bin"));
    }
    let previous = find_entry(&db.root, uid)
        .map(|e| e.previous_parent_group)
        .or_else(|| find_group(&db.root, uid).map(|g| g.previous_parent_group))
        .flatten();
    let to = previous.filter(|p| find_group(&db.root, *p).is_some() && !in_recycle_bin(db, *p)).unwrap_or(db.root.uuid);
    if find_entry(&db.root, uid).is_some() {
        move_entry_to(db, uid, to, now)
    } else {
        move_group_to(db, uid, to, now)
    }
}

pub(crate) fn set_attachment(
    db: &mut Database,
    id: &str,
    name: &str,
    data: SecretBytes,
    protected: Option<bool>,
    now: Timestamp,
) -> Result<(), OvError> {
    let uid = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    let e = find_entry(&db.root, uid).ok_or_else(entry_not_found)?;
    let protected = protected.unwrap_or_else(|| {
        e.binaries
            .iter()
            .find(|b| b.name == name)
            .and_then(|b| db.binaries.get(b.index as usize))
            .is_none_or(|b| b.protected)
    });
    let index = db.binaries.len() as u32;
    db.binaries.push(Binary { data: Zeroizing::new(data), protected });
    let r = edit_with_history(db, uid, now, |e| {
        e.binaries.retain(|b| b.name != name);
        e.binaries.push(BinaryRef { name: name.to_owned(), index });
        Ok(())
    });
    ov_merge::compact_binaries(db);
    r
}

pub(crate) fn remove_attachment(db: &mut Database, id: &str, name: &str, now: Timestamp) -> Result<(), OvError> {
    let uid = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    let e = find_entry(&db.root, uid).ok_or_else(entry_not_found)?;
    if !e.binaries.iter().any(|b| b.name == name) {
        return Err(OvError::new(OvErrorCode::NotFound, format!("no attachment named {name}")));
    }
    let r = edit_with_history(db, uid, now, |e| {
        e.binaries.retain(|b| b.name != name);
        Ok(())
    });
    ov_merge::compact_binaries(db);
    r
}

pub(crate) fn add_custom_icon(db: &mut Database, png: Vec<u8>, now: Timestamp) -> Result<String, OvError> {
    if let Some(i) = db.meta.custom_icons.iter().find(|i| i.data == png) {
        return Ok(uuid_hex(&i.uuid));
    }
    let uuid = ov_kdbx::vault::new_uuid()?;
    let v41 = is_v41(db);
    db.meta.custom_icons.push(CustomIcon { uuid, data: png, name: None, last_modification: v41.then_some(now) });
    Ok(uuid_hex(&uuid))
}

pub(crate) fn parent_group(db: &Database, parent: Option<&str>) -> Result<Uuid, OvError> {
    match parent {
        Some(p) => {
            let id = parse_id(p)?;
            find_group(&db.root, id).ok_or_else(group_not_found)?;
            Ok(id)
        }
        None => Ok(db.root.uuid),
    }
}

// ------------------------------------------------------------------------- versions

pub(crate) fn version_difference(
    current: &Database,
    version: &Database,
    id: &str,
) -> Result<VersionDifference, OvError> {
    let uid = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    let old = find_entry(&version.root, uid).ok_or_else(entry_not_found)?;
    match find_entry(&current.root, uid) {
        None => Ok(VersionDifference::Deleted),
        Some(_) if in_recycle_bin(current, uid) => Ok(VersionDifference::Deleted),
        Some(now) => {
            let same = now.strings == old.strings
                && now.tags == old.tags
                && now.icon_id == old.icon_id
                && now.times.expires == old.times.expires
                && (!now.times.expires || now.times.expiry == old.times.expiry)
                && now.binaries.len() == old.binaries.len();
            Ok(if same { VersionDifference::Same } else { VersionDifference::Changed })
        }
    }
}

/// Copies an entry from another database's attachment pool into `db`'s.
fn reintern(db: &mut Database, from: &Database, e: &mut Entry) {
    for b in &mut e.binaries {
        let data = from.binaries.get(b.index as usize).cloned();
        if let Some(bin) = data {
            b.index = db.binaries.len() as u32;
            db.binaries.push(bin);
        }
    }
}

pub(crate) fn restore_entry(
    db: &mut Database,
    version: &Database,
    id: &str,
    group_path: &str,
    now: Timestamp,
) -> Result<(), OvError> {
    let uid = parse_uuid_string(id).ok_or_else(entry_not_found)?;
    let mut old = find_entry(&version.root, uid).ok_or_else(entry_not_found)?.clone();
    old.history.clear();
    reintern(db, version, &mut old);
    if find_entry(&db.root, uid).is_some() && !in_recycle_bin(db, uid) {
        edit_with_history(db, uid, now, |e| {
            e.strings = old.strings.clone();
            e.binaries = old.binaries.clone();
            e.tags = old.tags.clone();
            e.icon_id = old.icon_id;
            e.custom_icon = old.custom_icon;
            e.times.expires = old.times.expires;
            e.times.expiry = old.times.expiry;
            Ok(())
        })?;
    } else {
        // Deleted since: drop any copy in the Recycle Bin and re-add it under its path.
        detach_entry(&mut db.root, uid);
        db.deleted_objects.retain(|d| d.uuid != uid);
        let gid = ensure_group(db, group_path, now)?;
        old.times.last_modification = now;
        old.times.location_changed = now;
        find_group_mut(&mut db.root, gid).ok_or_else(group_not_found)?.entries.push(old);
    }
    ov_merge::compact_binaries(db);
    Ok(())
}

/// Puts `record` into `db` at `group_path`: an edit (with history) when the entry exists, else a new
/// entry with that id. Returns whether anything changed.
pub(crate) fn upsert_record(
    db: &mut Database,
    rec: &EntryRecord,
    group_path: &str,
    now: Timestamp,
) -> Result<bool, OvError> {
    let uid = parse_id(&rec.id)?;
    let apply = |e: &mut Entry| -> Result<(), OvError> {
        e.strings = rec
            .fields
            .iter()
            .map(|f| {
                let text = std::str::from_utf8(&f.value).unwrap_or_default();
                ov_kdbx::model::StringField::new(f.name.clone(), text, f.protected)
            })
            .collect();
        e.tags = rec.tags.clone();
        e.icon_id = rec.icon_id;
        e.times.expires = rec.expires_at.is_some();
        if let Some(t) = rec.expires_at {
            e.times.expiry = t;
        }
        Ok(())
    };
    if find_entry(&db.root, uid).is_some() {
        let before = find_entry(&db.root, uid).cloned();
        edit_with_history(db, uid, now, apply)?;
        return Ok(find_entry(&db.root, uid).cloned() != before);
    }
    let mut e = Entry::new(uid, now);
    apply(&mut e)?;
    if rec.created_at > 0 {
        e.times.creation = rec.created_at;
    }
    let gid = ensure_group(db, group_path, now)?;
    find_group_mut(&mut db.root, gid).ok_or_else(group_not_found)?.entries.push(e);
    Ok(true)
}

// ---------------------------------------------------------------------------- export

fn selected(db: &Database, group_ids: Option<Vec<String>>) -> Result<Vec<Uuid>, OvError> {
    match group_ids {
        Some(ids) => ids.iter().map(|s| parse_id(s)).collect(),
        None => Ok(groups(db).iter().filter_map(|g| parse_uuid_string(&g.id)).collect()),
    }
}

pub(crate) fn export_db(db: &Database, group_ids: Option<Vec<String>>, now: Timestamp) -> Result<Database, OvError> {
    let mut sel = selected(db, group_ids)?;
    if let Some(rb) = db.meta.recycle_bin_uuid {
        sel.retain(|g| *g != rb && !in_recycle_bin(db, *g));
    }
    ov_kdbx::entries::export_selected_groups(db, &sel, now)
}

fn csv_cell(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub(crate) fn export_plain(
    db: &Database,
    format: ExportFormat,
    group_ids: Option<Vec<String>>,
) -> Result<SecretBytes, OvError> {
    let sel = selected(db, group_ids)?;
    let rows: Vec<(String, &Entry)> = all_entries(db)
        .into_iter()
        .filter(|(_, g, _)| sel.contains(&g.uuid) && !in_recycle_bin(db, g.uuid))
        .map(|(e, g, p)| (if p.is_empty() { g.name.clone() } else { p.join("/") }, e))
        .collect();
    let out = match format {
        ExportFormat::Csv => {
            let mut s = String::from("\"Folder\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n");
            for (folder, e) in &rows {
                let cells = [
                    folder.as_str(),
                    e.title(),
                    e.field_text("UserName"),
                    e.field_text("Password"),
                    e.field_text("URL"),
                    e.field_text("Notes"),
                ];
                s.push_str(&cells.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
                s.push('\n');
            }
            s
        }
        ExportFormat::Json => {
            let items: Vec<serde_json::Value> = rows
                .iter()
                .map(|(folder, e)| {
                    serde_json::json!({
                        "folder": folder,
                        "title": e.title(),
                        "username": e.field_text("UserName"),
                        "passwordValue": e.field_text("Password"),
                        "url": e.field_text("URL"),
                        "notes": e.field_text("Notes"),
                    })
                })
                .collect();
            serde_json::to_string_pretty(&items).unwrap_or_default()
        }
    };
    Ok(out.into_bytes())
}
