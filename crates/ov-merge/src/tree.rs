//! The structure merge (the SDK's `merge/tree.ts`, written from its `docs/merge-behaviour.md`; the
//! section numbers below refer to it): brings one database's entries, groups, history, deletions and
//! metadata into another. Also the tree helpers the rest of the crate uses.

use std::collections::BTreeMap;

use ov_kdbx::model::{CustomDataItem, Database, DeletedObject, Entry, Group, Timestamp, Uuid};

use crate::fields::{fields_of, FieldKey};
use crate::{pool, time, ChangeSubject, ChangeType, MergeChange};

// ------------------------------------------------------------------------------------ tree helpers

/// Every entry under `g` (not history items), in the TS `entriesUnder` order (pre-order).
pub(crate) fn entries_under(g: &Group) -> Vec<&Entry> {
    let mut out = Vec::new();
    fn walk<'a>(g: &'a Group, out: &mut Vec<&'a Entry>) {
        out.extend(g.entries.iter());
        for c in &g.groups {
            walk(c, out);
        }
    }
    walk(g, &mut out);
    out
}

/// Every group below `g` (not `g` itself), pre-order.
pub(crate) fn groups_under(g: &Group) -> Vec<&Group> {
    let mut out = Vec::new();
    fn walk<'a>(g: &'a Group, out: &mut Vec<&'a Group>) {
        for c in &g.groups {
            out.push(c);
            walk(c, out);
        }
    }
    walk(g, &mut out);
    out
}

/// Calls `f` on every entry under `g` (not history items), pre-order.
pub(crate) fn for_each_entry_mut(g: &mut Group, f: &mut dyn FnMut(&mut Entry)) {
    for e in &mut g.entries {
        f(e);
    }
    for c in &mut g.groups {
        for_each_entry_mut(c, f);
    }
}

/// The entry `id` under `root` and the group it is directly in.
pub(crate) fn find_entry(root: &Group, id: Uuid) -> Option<(&Entry, &Group)> {
    if let Some(e) = root.entries.iter().find(|e| e.uuid == id) {
        return Some((e, root));
    }
    root.groups.iter().find_map(|c| find_entry(c, id))
}

pub(crate) fn find_entry_mut(root: &mut Group, id: Uuid) -> Option<&mut Entry> {
    if let Some(i) = root.entries.iter().position(|e| e.uuid == id) {
        return root.entries.get_mut(i);
    }
    root.groups.iter_mut().find_map(|c| find_entry_mut(c, id))
}

/// The group `id`: `root` itself or a group below it.
pub(crate) fn find_group(root: &Group, id: Uuid) -> Option<&Group> {
    if root.uuid == id {
        return Some(root);
    }
    root.groups.iter().find_map(|c| find_group(c, id))
}

pub(crate) fn find_group_mut(root: &mut Group, id: Uuid) -> Option<&mut Group> {
    if root.uuid == id {
        return Some(root);
    }
    root.groups.iter_mut().find_map(|c| find_group_mut(c, id))
}

/// The group that directly holds group `id`.
pub(crate) fn group_parent(root: &Group, id: Uuid) -> Option<&Group> {
    if root.groups.iter().any(|c| c.uuid == id) {
        return Some(root);
    }
    root.groups.iter().find_map(|c| group_parent(c, id))
}

/// How many groups are above group `id` (0 for the root).
pub(crate) fn depth(root: &Group, id: Uuid) -> usize {
    fn walk(g: &Group, id: Uuid, d: usize) -> Option<usize> {
        if g.uuid == id {
            return Some(d);
        }
        g.groups.iter().find_map(|c| walk(c, id, d + 1))
    }
    walk(root, id, 0).unwrap_or(0)
}

/// Removes entry `id` from its group and returns it.
pub(crate) fn take_entry(root: &mut Group, id: Uuid) -> Option<Entry> {
    if let Some(i) = root.entries.iter().position(|e| e.uuid == id) {
        return Some(root.entries.remove(i));
    }
    root.groups.iter_mut().find_map(|c| take_entry(c, id))
}

/// Removes group `id` (never `root` itself) from its parent and returns it.
pub(crate) fn take_group(root: &mut Group, id: Uuid) -> Option<Group> {
    if let Some(i) = root.groups.iter().position(|g| g.uuid == id) {
        return Some(root.groups.remove(i));
    }
    root.groups.iter_mut().find_map(|c| take_group(c, id))
}

/// Appends `entry` to group `group`. Returns `false` (dropping it) when that group doesn't exist;
/// callers check the group first.
pub(crate) fn push_entry(root: &mut Group, group: Uuid, entry: Entry) -> bool {
    match find_group_mut(root, group) {
        Some(g) => {
            g.entries.push(entry);
            true
        }
        None => false,
    }
}

/// Appends `child` to group `group`, as [`push_entry`].
pub(crate) fn push_group(root: &mut Group, group: Uuid, child: Group) -> bool {
    match find_group_mut(root, group) {
        Some(g) => {
            g.groups.push(child);
            true
        }
        None => false,
    }
}

/// Makes entry `id` the last entry of group `to` (TS `appendEntry`). Nothing else changes.
pub(crate) fn append_entry(root: &mut Group, id: Uuid, to: Uuid) {
    if find_group(root, to).is_none() {
        return;
    }
    if let Some(e) = take_entry(root, id) {
        let _ = push_entry(root, to, e);
    }
}

/// Makes group `id` the last child of group `to`, unless that would put it inside itself.
pub(crate) fn append_group(root: &mut Group, id: Uuid, to: Uuid) -> bool {
    match find_group(root, id) {
        Some(g) if find_group(g, to).is_none() && find_group(root, to).is_some() => {}
        _ => return false,
    }
    match take_group(root, id) {
        Some(g) => push_group(root, to, g),
        None => false,
    }
}

/// `group` without its entries and subgroups.
pub(crate) fn shallow_group(g: &Group) -> Group {
    Group {
        uuid: g.uuid,
        name: g.name.clone(),
        notes: g.notes.clone(),
        icon_id: g.icon_id,
        custom_icon: g.custom_icon,
        times: g.times,
        is_expanded: g.is_expanded,
        default_auto_type_sequence: g.default_auto_type_sequence.clone(),
        enable_auto_type: g.enable_auto_type,
        enable_searching: g.enable_searching,
        last_top_visible_entry: g.last_top_visible_entry,
        tags: g.tags.clone(),
        previous_parent_group: g.previous_parent_group,
        custom_data: g.custom_data.clone(),
        entries: Vec::new(),
        groups: Vec::new(),
        unknown: g.unknown.clone(),
    }
}

// ------------------------------------------------------------------------------------- records

pub(crate) fn entry_record(
    change: ChangeType,
    e: &Entry,
    group: Option<&str>,
    details: impl Into<String>,
) -> MergeChange {
    MergeChange {
        change,
        subject: ChangeSubject::Entry,
        uuid: Some(e.uuid),
        title: Some(e.title().to_owned()),
        group: group.map(str::to_owned),
        details: details.into(),
    }
}

pub(crate) fn group_record(change: ChangeType, g: &Group, details: impl Into<String>) -> MergeChange {
    MergeChange {
        change,
        subject: ChangeSubject::Group,
        uuid: Some(g.uuid),
        title: None,
        group: Some(g.name.clone()),
        details: details.into(),
    }
}

pub(crate) fn db_record(change: ChangeType, details: impl Into<String>) -> MergeChange {
    MergeChange {
        change,
        subject: ChangeSubject::Database,
        uuid: None,
        title: None,
        group: None,
        details: details.into(),
    }
}

// ------------------------------------------------------------------------------------------ copies

/// A detached copy of `src` for `into`: `full` keeps (copies of) its history, otherwise none. With
/// `from` (the database `src` lives in, when it isn't `into`), its attachments are re-interned into
/// `into`'s pool and its custom icons brought over.
pub(crate) fn copy_entry(src: &Entry, from: Option<&Database>, into: &mut Database, full: bool) -> Entry {
    let mut out = src.clone();
    if !full {
        out.history.clear();
    }
    for h in &mut out.history {
        h.history.clear();
    }
    if let Some(from) = from {
        pool::rehome(&mut out, from, into);
    }
    out
}

/// Trims `entry`'s history to `limit` items, keeping the newest (no limit when negative).
pub(crate) fn trim_history(entry: &mut Entry, limit: i32) {
    if limit < 0 {
        return;
    }
    let extra = entry.history.len().saturating_sub(limit as usize);
    if extra > 0 {
        entry.history.drain(..extra);
    }
}

// ---------------------------------------------------------------------------------- equality (§3)

pub(crate) fn custom_data_key(items: &[CustomDataItem]) -> Vec<(&str, &str)> {
    let mut v: Vec<(&str, &str)> = items.iter().map(|i| (i.key.as_str(), i.value.as_str())).collect();
    v.sort();
    v
}

/// §3: two entries of `db` are equal (history included, item by item).
pub(crate) fn entries_equal(a: &Entry, b: &Entry, db: &Database) -> bool {
    digest_equal(a, b, db)
        && a.history.len() == b.history.len()
        && a.history.iter().zip(&b.history).all(|(x, y)| entries_equal(x, y, db))
}

fn digest_equal(a: &Entry, b: &Entry, db: &Database) -> bool {
    if a.uuid != b.uuid {
        return false;
    }
    let (ta, tb) = (&a.times, &b.times);
    if (ta.last_modification, ta.creation, ta.last_access, ta.location_changed, ta.usage_count)
        != (tb.last_modification, tb.creation, tb.last_access, tb.location_changed, tb.usage_count)
    {
        return false;
    }
    if a.override_url != b.override_url
        || a.auto_type != b.auto_type
        || custom_data_key(&a.custom_data) != custom_data_key(&b.custom_data)
        || a.previous_parent_group != b.previous_parent_group
    {
        return false;
    }
    let raw = |e: &Entry, k: &FieldKey| match k {
        FieldKey::Attribute(key) => e.field(key).is_some_and(|f| f.protected),
        _ => false,
    };
    let (fa, fb) = (fields_of(a, db), fields_of(b, db));
    fa.len() == fb.len() && fa.0.iter().all(|(k, v)| fb.get(k).is_some_and(|w| v.same(w)) && raw(a, k) == raw(b, k))
}

// --------------------------------------------------------------------------------- history (§2)

/// §2: merges the history of `other` into `kept`, a detached entry in `kept_db`'s terms. `other`
/// lives in `other_db`, or in `kept_db` when that is `None`. Returns whether `kept` changed.
pub(crate) fn merge_history_into(
    kept: &mut Entry,
    kept_db: &mut Database,
    other: &Entry,
    other_db: Option<&Database>,
) -> bool {
    let kept_at = kept.times.last_modification;
    let other_at = other.times.last_modification;
    // Items keyed by modification time, as KeePassXC's `Merger::mergeHistory` does. KDBX keeps whole
    // seconds, so one entry can hold several items of the same second (edits within a second): each
    // time keeps all its items, in order, rather than the last one only, which would drop items and
    // make merging an entry with itself look like a change.
    let mut by_time: BTreeMap<Timestamp, Vec<Entry>> = BTreeMap::new();
    for h in &kept.history {
        by_time.entry(h.times.last_modification).or_default().push(copy_entry(h, None, kept_db, false));
    }
    let mut theirs: BTreeMap<Timestamp, Vec<Entry>> = BTreeMap::new();
    for h in &other.history {
        theirs.entry(h.times.last_modification).or_default().push(copy_entry(h, other_db, kept_db, false));
    }
    for (at, items) in theirs {
        if !by_time.contains_key(&at) || other_at > kept_at {
            by_time.insert(at, items);
        }
    }
    if kept_at < other_at && !by_time.contains_key(&kept_at) {
        by_time.insert(kept_at, vec![copy_entry(kept, None, kept_db, false)]);
    }
    if kept_at > other_at && !by_time.contains_key(&other_at) {
        by_time.insert(other_at, vec![copy_entry(other, other_db, kept_db, false)]);
    }
    let next: Vec<Entry> = by_time.into_values().flatten().collect();

    let window = kept_db.meta.history_max_items.saturating_sub(1);
    let old = &kept.history;
    let mut changed = false;
    let mut back = 1i64;
    while back <= i64::from(window) && !changed {
        let a = old.len().checked_sub(back as usize).map(|i| &old[i]);
        let b = next.len().checked_sub(back as usize).map(|i| &next[i]);
        changed = match (a, b) {
            (Some(a), Some(b)) => !entries_equal(a, b, kept_db),
            (None, None) => false,
            _ => true,
        };
        back += 1;
    }
    if !changed {
        return false;
    }
    kept.history = next;
    trim_history(kept, kept_db.meta.history_max_items);
    true
}

// ------------------------------------------------------------------------------------------ passes

/// How [`merge_into`](crate::merge_into) treats deletion records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MergeMode {
    /// The sync default: the target's deletion records stay as they are (sync decides deletions
    /// against the base instead).
    #[default]
    KeepNewer,
    /// Also apply deletion records by time (§4).
    Synchronize,
}

/// Options for [`merge_into`](crate::merge_into).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeIntoOptions {
    /// Leave the target's database custom data alone (desktop `Merger::setSkipDatabaseCustomData`).
    pub skip_database_custom_data: bool,
    /// Source groups to leave out, with everything under them.
    pub skip_groups: Vec<Uuid>,
}

struct Pass<'a> {
    from: &'a Database,
    into: &'a mut Database,
    opts: &'a MergeIntoOptions,
    changes: Vec<MergeChange>,
}

impl Pass<'_> {
    /// §1: walks `src` (a group of `from`) into group `dst` of `into`.
    fn walk(&mut self, src: &Group, dst: Uuid) {
        for entry in &src.entries {
            self.entry(entry, src, dst);
        }
        for child in &src.groups {
            if !self.opts.skip_groups.contains(&child.uuid) {
                let target = self.group(child, dst);
                self.walk(child, target);
            }
        }
    }

    /// §1.1
    fn entry(&mut self, src: &Entry, src_group: &Group, dst: Uuid) {
        let id = src.uuid;
        let Some((existing, parent)) = find_entry(&self.into.root, id) else {
            self.changes.push(entry_record(ChangeType::Added, src, Some(&src_group.name), ""));
            let copy = copy_entry(src, Some(self.from), self.into, true);
            let _ = push_entry(&mut self.into.root, dst, copy);
            return;
        };
        let mut existing = existing.clone();
        let (mut home, mut home_name) = (parent.uuid, parent.name.clone());
        if existing.times.location_changed < src.times.location_changed && home != dst {
            if let Some(g) = find_group(&self.into.root, dst) {
                let name = g.name.clone();
                self.changes.push(entry_record(
                    ChangeType::Moved,
                    src,
                    Some(&src_group.name),
                    format!("Previous location: {home_name}"),
                ));
                append_entry(&mut self.into.root, id, dst);
                (home, home_name) = (dst, name);
            }
        }
        if existing.times.last_modification < src.times.last_modification {
            let mut replacement = copy_entry(src, Some(self.from), self.into, true);
            merge_history_into(&mut replacement, self.into, &existing, None);
            self.changes.push(entry_record(
                ChangeType::Modified,
                &existing,
                Some(&home_name),
                "Add local modifications to new entry",
            ));
            take_entry(&mut self.into.root, id);
            let _ = push_entry(&mut self.into.root, home, replacement);
        } else if merge_history_into(&mut existing, self.into, src, Some(self.from)) {
            self.changes.push(entry_record(
                ChangeType::Modified,
                &existing,
                Some(&home_name),
                "Add new modifications to existing entry",
            ));
            if let Some(slot) = find_entry_mut(&mut self.into.root, id) {
                *slot = existing;
            }
        }
    }

    /// §1.2: returns the target group to walk `src`'s contents into.
    fn group(&mut self, src: &Group, dst: Uuid) -> Uuid {
        let id = src.uuid;
        let Some(existing) = find_group(&self.into.root, id) else {
            self.changes.push(group_record(
                ChangeType::Added,
                src,
                format!("Number of entries in group: {}", src.entries.len()),
            ));
            let _ = push_group(&mut self.into.root, dst, shallow_group(src));
            pool::bring_icon(src.custom_icon, self.from, self.into);
            return id;
        };
        let (location, name, modified) =
            (existing.times.location_changed, existing.name.clone(), existing.times.last_modification);
        let parent = group_parent(&self.into.root, id).map(|p| p.uuid);
        if location < src.times.location_changed && parent != Some(dst) && append_group(&mut self.into.root, id, dst) {
            self.changes.push(group_record(ChangeType::Moved, src, format!("Previous location: {name}")));
            if let Some(g) = find_group_mut(&mut self.into.root, id) {
                g.times.location_changed = src.times.location_changed;
                // Where it was before the move goes with it, so the Recycle Bin restores it there
                g.previous_parent_group = src.previous_parent_group;
            }
        }
        if modified < src.times.last_modification {
            self.update_group(src);
        }
        id
    }

    fn update_group(&mut self, src: &Group) {
        let Some(dst) = find_group_mut(&mut self.into.root, src.uuid) else { return };
        let mut what: Vec<&str> = Vec::new();
        if dst.name != src.name {
            what.push("Group name");
            dst.name = src.name.clone();
        }
        if dst.notes != src.notes {
            what.push("Notes");
            dst.notes = src.notes.clone();
        }
        let mut bring = None;
        match src.custom_icon.filter(|id| !id.is_nil()) {
            Some(custom) => {
                if dst.custom_icon != Some(custom) {
                    what.push("Icon (UUID)");
                    dst.custom_icon = Some(custom);
                    bring = Some(custom);
                }
            }
            None => {
                if dst.icon_id != src.icon_id || dst.custom_icon.is_some() {
                    what.push("Icon (Number)");
                    dst.icon_id = src.icon_id;
                    dst.custom_icon = None;
                }
            }
        }
        if dst.times.expiry != src.times.expiry {
            what.push("Expiry time");
            dst.times.expiry = src.times.expiry;
        }
        what.push("Modification time");
        dst.times.last_modification = src.times.last_modification;
        pool::bring_icon(bring, self.from, self.into);
        self.changes.push(group_record(ChangeType::Modified, src, what.join(", ")));
    }

    /// §4 (synchronize mode only).
    fn deletions(&mut self) {
        let root = self.into.root.uuid;
        let mut earliest: BTreeMap<Uuid, DeletedObject> = BTreeMap::new();
        let mut kept: Vec<DeletedObject> = Vec::new();
        let mut entries: Vec<Uuid> = Vec::new();
        let mut groups: Vec<Uuid> = Vec::new();
        for rec in self.into.deleted_objects.iter().chain(&self.from.deleted_objects) {
            if let Some(seen) = earliest.get_mut(&rec.uuid) {
                if seen.deletion_time > rec.deletion_time {
                    *seen = *rec;
                }
                continue;
            }
            earliest.insert(rec.uuid, *rec);
            if find_entry(&self.into.root, rec.uuid).is_some() {
                entries.push(rec.uuid);
            } else if rec.uuid != root && find_group(&self.into.root, rec.uuid).is_some() {
                groups.push(rec.uuid);
            } else {
                kept.push(*rec);
            }
        }
        for id in entries {
            let rec = earliest[&id];
            let Some((entry, parent)) = find_entry(&self.into.root, id) else { continue };
            if entry.times.last_modification > rec.deletion_time {
                continue;
            }
            kept.push(rec);
            self.changes.push(entry_record(ChangeType::Deleted, entry, Some(&parent.name), "Explicit deletion"));
            take_entry(&mut self.into.root, id);
        }
        let mut waiting = std::collections::VecDeque::from(groups);
        while let Some(id) = waiting.pop_front() {
            let Some(group) = find_group(&self.into.root, id) else { continue };
            if group.groups.iter().any(|c| waiting.contains(&c.uuid)) {
                waiting.push_back(id);
                continue;
            }
            let rec = earliest[&id];
            if group.times.last_modification > rec.deletion_time
                || !group.entries.is_empty()
                || !group.groups.is_empty()
            {
                continue;
            }
            kept.push(rec);
            self.changes.push(group_record(ChangeType::Deleted, group, "Explicit deletion"));
            take_group(&mut self.into.root, id);
        }
        if kept != self.into.deleted_objects {
            self.changes.push(db_record(ChangeType::Metadata, "Changed deleted objects"));
            self.into.deleted_objects = kept;
        }
    }

    /// §5
    fn metadata(&mut self) {
        for icon in &self.from.meta.custom_icons {
            if self.into.meta.custom_icons.iter().any(|i| i.uuid == icon.uuid) {
                continue;
            }
            self.changes.push(db_record(ChangeType::Metadata, format!("Adding new icon {}", icon.uuid)));
            self.into.meta.custom_icons.push(icon.clone());
        }
        if self.opts.skip_database_custom_data {
            return;
        }
        let src = &self.from.meta.custom_data;
        let dst = &mut self.into.meta.custom_data;
        let dst_time = time::custom_data_time(dst);
        let src_time = time::custom_data_time(src);
        let has_stamp = dst.iter().any(|i| i.key == LAST_MODIFIED);
        let apply = !has_stamp || matches!((dst_time, src_time), (Some(d), Some(s)) if d < s);
        if !apply {
            return;
        }
        let mut i = 0;
        while i < dst.len() {
            let key = &dst[i].key;
            if src.iter().any(|s| s.key == *key)
                || PROTECTED_KEYS.contains(&key.as_str())
                || key.starts_with("KPXC_BROWSER_")
            {
                i += 1;
                continue;
            }
            let item = dst.remove(i);
            self.changes
                .push(db_record(ChangeType::Metadata, format!("Removed custom data {} [{}]", item.key, item.value)));
        }
        for item in src {
            if GENERATED_KEYS.contains(&item.key.as_str()) {
                continue;
            }
            match dst.iter_mut().find(|d| d.key == item.key) {
                Some(d) if d.value == item.value => continue,
                Some(d) => *d = item.clone(),
                None => dst.push(item.clone()),
            }
            self.changes
                .push(db_record(ChangeType::Metadata, format!("Adding custom data {} [{}]", item.key, item.value)));
        }
    }
}

const LAST_MODIFIED: &str = "_LAST_MODIFIED";
const PROTECTED_KEYS: [&str; 4] =
    ["_CREATED_", "FDO_SECRETS_EXPOSED_GROUP", "KPXC_REMOTE_SYNC_SETTINGS", "KPXC_SYNC_GENERATION"];
const GENERATED_KEYS: [&str; 3] = ["_LAST_MODIFIED", "KPXC_RANDOM_SLUG", "KPXC_SYNC_GENERATION"];

/// Brings `from`'s changes into `into` without rebuilding the attachment pool.
pub(crate) fn merge_into_raw(
    from: &Database,
    into: &mut Database,
    mode: MergeMode,
    opts: &MergeIntoOptions,
) -> Vec<MergeChange> {
    let mut pass = Pass { from, into, opts, changes: Vec::new() };
    let root = pass.into.root.uuid;
    pass.walk(&from.root, root);
    if mode == MergeMode::Synchronize {
        pass.deletions();
    }
    pass.metadata();
    pass.changes
}

/// Sets custom data item `key` (in place when it exists), as kdbxweb's `customData.set`.
pub(crate) fn set_custom_data(items: &mut Vec<CustomDataItem>, key: &str, value: String) {
    match items.iter_mut().find(|i| i.key == key) {
        Some(i) => {
            i.value = value;
            i.last_modification = None;
        }
        None => items.push(CustomDataItem { key: key.to_owned(), value, last_modification: None }),
    }
}
