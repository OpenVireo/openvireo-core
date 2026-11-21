//! The sync merge of the desktop `SyncEngine` (`gui/remote/SyncEngine.cpp`), ported from the SDK's
//! `merge/merger.ts`: the three-way field merge of entries edited on both sides against the common
//! base (`combineEntries`), the structure merge both ways, each entry put where it was moved last,
//! deletions decided against the base, the Recycle Bin, the sync generation bump; plus the conflict
//! checks against the last-sync snapshot.

use ov_kdbx::model::{CustomDataItem, Database, DeletedObject, Entry, Group, Timestamp, Uuid};

use crate::fields::{fields_of, resolve_fields, same_fields, same_value, union_keys, FieldKey, Fields};
use crate::index::Finder;
use crate::tree::{self, entries_under, find_entry, find_group, groups_under, MergeIntoOptions, MergeMode};
use crate::{pool, ChangeSubject, ChangeType, EntryConflict, MergeChange, MergeReport};

/// The sync generation kept in the database's custom data.
pub const SYNC_GENERATION_KEY: &str = "KPXC_SYNC_GENERATION";

/// The database's sync generation (0 when unset or unreadable).
pub fn sync_generation(db: &Database) -> u64 {
    db.meta.custom_data_value(SYNC_GENERATION_KEY).and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

/// `combineEntries()`: gives both copies of entry `id` the combined fields and the same modification
/// time, so the structure merge sees one version. Each keeps its previous state in its history.
/// Returns the display names of the fields both sides changed differently.
fn combine_entries(
    (local, fl): (&mut Database, &Finder),
    (remote, fr): (&mut Database, &Finder),
    (base, fb): (&Database, &Finder),
    id: Uuid,
    now: Timestamp,
) -> Vec<String> {
    let (Some((l, _)), Some((r, _)), Some((b, _))) =
        (fl.entry(&local.root, id), fr.entry(&remote.root, id), fb.entry(&base.root, id))
    else {
        return Vec::new();
    };
    let local_is_newer = l.times.last_modification >= r.times.last_modification;
    let (merged, conflicts) = resolve_fields((l, local), (r, remote), (b, base), local_is_newer);
    let when = now.max(l.times.last_modification).max(r.times.last_modification);
    let ((older_db, fo), (newer_db, fnew)) =
        if local_is_newer { ((remote, fr), (local, fl)) } else { ((local, fl), (remote, fr)) };
    let newer = fnew.entry(&newer_db.root, id).map(|(e, _)| e.clone()).unwrap_or_else(|| unreachable_entry(id));
    let older = fo.entry(&older_db.root, id).map(|(e, _)| e.clone()).unwrap_or_else(|| unreachable_entry(id));

    let older = update_side(older, older_db, Some((&newer, &*newer_db)), &merged, when);
    put_back(older_db, fo, older);
    let newer = update_side(newer, newer_db, None, &merged, when);
    put_back(newer_db, fnew, newer);
    conflicts
}

fn unreachable_entry(id: Uuid) -> Entry {
    Entry::new(id, 0)
}

fn put_back(db: &mut Database, find: &Finder, entry: Entry) {
    if let Some(slot) = find.entry_mut(&mut db.root, entry.uuid) {
        *slot = entry;
    }
}

/// One side of `combineEntries`: `beginUpdate()`, the newer side's data (for the older side), the
/// merged fields, the new time, and `endUpdate()` (history when anything emitted a modification).
fn update_side(
    mut entry: Entry,
    db: &mut Database,
    newer: Option<(&Entry, &Database)>,
    merged: &Fields,
    when: Timestamp,
) -> Entry {
    let before = tree::copy_entry(&entry, None, db, false);
    let mut modified = false;
    if let Some((newer, newer_db)) = newer {
        // copyDataFrom() emits for attributes, attachments, custom data and auto-type
        modified = emitting_data_differs(&entry, db, newer, newer_db);
        // Everything not merged field by field comes from the newer entry
        let history = std::mem::take(&mut entry.history);
        entry = tree::copy_entry(newer, Some(newer_db), db, false);
        entry.history = history;
    }
    let current = fields_of(&entry, db);
    for key in union_keys(&[&current, merged]) {
        if !same_value(current.get(key), merged.get(key)) {
            crate::fields::apply_field(&mut entry, db, key, merged.get(key));
            modified = true;
        }
    }
    entry.times.last_modification = when;
    if modified {
        entry.history.push(before);
        tree::trim_history(&mut entry, db.meta.history_max_items);
    }
    entry
}

/// Whether `Entry::copyDataFrom(b)` on `a` would emit a modification (attributes, attachments,
/// custom data, auto-type).
fn emitting_data_differs(a: &Entry, a_db: &Database, b: &Entry, b_db: &Database) -> bool {
    let pick = |e: &Entry, f: &Fields| {
        let mut parts: Vec<(FieldKey, bool)> =
            f.0.iter()
                .filter(|(k, _)| matches!(k, FieldKey::Attribute(_) | FieldKey::Attachment(_)))
                .map(|(k, _)| {
                    let prot = match k {
                        FieldKey::Attribute(key) => e.field(key).is_some_and(|s| s.protected),
                        _ => false,
                    };
                    (k.clone(), prot)
                })
                .collect();
        parts.sort();
        parts
    };
    let (fa, fb) = (fields_of(a, a_db), fields_of(b, b_db));
    let (pa, pb) = (pick(a, &fa), pick(b, &fb));
    if pa != pb || pa.iter().any(|(k, _)| !same_value(fa.get(k), fb.get(k))) {
        return true;
    }
    tree::custom_data_key(&a.custom_data) != tree::custom_data_key(&b.custom_data) || a.auto_type != b.auto_type
}

/// `SyncEngine::mergeDatabases()` on both copies: merges `remote` into `local` and `local` into
/// `remote`, using `base` (the copy both last synced from) to combine entries edited on both sides
/// field by field and to decide deletions. Afterwards both have the same entries and groups, and
/// each entry both had sits, on both, in the group of the copy with the newer `LocationChanged`
/// (local wins a tie), with that time.
///
/// `now` (Unix seconds) is the combined entries' modification time when it is the latest, and the
/// time of the moves and deletion records the Recycle Bin merge makes. Both attachment pools are
/// rebuilt ([`compact_binaries`](crate::compact_binaries)).
pub fn merge_in_place(
    local: &mut Database,
    remote: &mut Database,
    base: Option<&Database>,
    now: Timestamp,
) -> MergeReport {
    let mut changes: Vec<MergeChange> = Vec::new();
    let mut conflicts: Vec<EntryConflict> = Vec::new();
    let mut combined: Vec<Uuid> = Vec::new();
    // Entries only one side changed, copied whole onto the other copy: (into local, into remote)
    let (mut taken_local, mut taken_remote): (Vec<Uuid>, Vec<Uuid>) = (Vec::new(), Vec::new());
    // Before combine_entries and the structure merge copy one entry's location over the other's
    let locations = locations_of(local, remote);
    // Database custom data merges three ways against the base, after the structure merge (which
    // then leaves it alone): its one-way rule would drop an item the other side added
    let custom_data =
        base.map(|b| merge_custom_data(&local.meta.custom_data, &remote.meta.custom_data, &b.meta.custom_data));
    if let Some(base) = base {
        let ids: Vec<Uuid> = entries_under(&local.root).iter().map(|e| e.uuid).collect();
        // Entries are only edited in place below, so the indexes stay right until the structure merge
        let (fl, fr, fb) = (Finder::new(&local.root), Finder::new(&remote.root), Finder::new(&base.root));
        for id in ids {
            let (Some((l, _)), Some((r, _)), Some((b, _))) =
                (fl.entry(&local.root, id), fr.entry(&remote.root, id), fb.entry(&base.root, id))
            else {
                continue;
            };
            if same_fields(l, local, r, remote) {
                continue;
            }
            // Compared by content with the base, so neither clocks nor same-second edits can mislead
            let local_changed = !same_fields(l, local, b, base);
            let remote_changed = !same_fields(r, remote, b, base);
            let (lt, rt) = (l.times.last_modification, r.times.last_modification);
            // The structure merge keeps the newer entry: right when only one side changed and it is strictly newer
            let needed =
                (local_changed && remote_changed) || (local_changed && lt <= rt) || (remote_changed && rt <= lt);
            if needed && local_changed != remote_changed && lt == rt {
                // Only one side changed it (by content, against the base), in the same second as the
                // other copy's time (an edit in the second of the last sync): that side's entry wins
                // whole and the other copy becomes it. Combining would stamp both with `now` and push
                // history on the unchanged side, so a pull with nothing changed here would upload. A
                // changed side whose clock is behind (strictly older) is still combined, as the
                // desktop's SyncEngine does (merge fixture 03).
                let (from, f_from, into, f_into, taken) = if remote_changed {
                    (&*remote, &fr, &mut *local, &fl, &mut taken_local)
                } else {
                    (&*local, &fl, &mut *remote, &fr, &mut taken_remote)
                };
                let (src, parent) = f_from.entry(&from.root, id).expect("the entry is on both sides");
                changes.push(tree::entry_record(
                    ChangeType::Modified,
                    src,
                    Some(&parent.name),
                    "Took the version changed on the other device",
                ));
                let copy = tree::copy_entry(src, Some(from), into, true);
                put_back(into, f_into, copy);
                taken.push(id);
                continue;
            }
            if needed {
                let c = combine_entries((local, &fl), (remote, &fr), (base, &fb), id, now);
                let (entry, parent) = fl.entry(&local.root, id).expect("combined entry is in local");
                if !c.is_empty() {
                    conflicts.push(EntryConflict { uuid: id, title: entry.title().to_owned(), fields: c });
                }
                combined.push(id);
                changes.push(tree::entry_record(
                    ChangeType::Modified,
                    entry,
                    Some(&parent.name),
                    "Combined the changes made on both devices",
                ));
            }
        }
    }
    // Found before the structure merge brings the deleted items back from the other side
    let pending = match base {
        Some(_) => {
            let mut p = pending_deletions(local, remote);
            for (id, rec) in pending_deletions(remote, local) {
                match p.iter_mut().find(|(i, _)| *i == id) {
                    Some(slot) => slot.1 = rec,
                    None => p.push((id, rec)),
                }
            }
            p
        }
        None => Vec::new(),
    };
    let opts = MergeIntoOptions { skip_database_custom_data: custom_data.is_some(), ..Default::default() };
    let mut to_remote = tree::merge_into_raw(local, remote, MergeMode::KeepNewer, &opts);
    let mut to_local = tree::merge_into_raw(remote, local, MergeMode::KeepNewer, &opts);
    if let Some(merged) = &custom_data {
        to_local.extend(apply_custom_data(&mut local.meta.custom_data, merged));
        to_remote.extend(apply_custom_data(&mut remote.meta.custom_data, merged));
    }
    let placed = apply_locations(local, remote, &locations);
    let mut after = match base {
        Some(base) if !pending.is_empty() => apply_deletions(local, remote, base, &pending),
        _ => Vec::new(),
    };
    after.extend(merge_recycle_bins(local, remote, now));

    let added = entry_ids(&to_local, |c| c == ChangeType::Added, &[]);
    let mut updated = combined.clone();
    updated.extend(taken_local.iter().copied());
    let moved_here = entry_ids(&to_local, |c| matches!(c, ChangeType::Modified | ChangeType::Moved), &added);
    for id in moved_here.into_iter().chain(placed.moved_here.iter().copied()) {
        if !updated.contains(&id) && !added.contains(&id) {
            updated.push(id);
        }
    }
    let deleted = entry_ids(&after, |c| c == ChangeType::Deleted, &[]);
    let remote_changed =
        !combined.is_empty() || !taken_remote.is_empty() || !after.is_empty() || !to_remote.is_empty() || placed.remote;
    let local_changed =
        !combined.is_empty() || !taken_local.is_empty() || !after.is_empty() || !to_local.is_empty() || placed.local;
    changes.extend(to_remote);
    changes.extend(to_local);
    changes.extend(placed.changes);
    changes.extend(after);
    if !changes.is_empty() {
        let generation = sync_generation(local).max(sync_generation(remote)) + 1;
        for db in [&mut *local, &mut *remote] {
            tree::set_custom_data(&mut db.meta.custom_data, SYNC_GENERATION_KEY, generation.to_string());
        }
    }
    pool::compact_binaries(local);
    pool::compact_binaries(remote);
    MergeReport { conflicts, added, updated, deleted, changes, local_changed, remote_changed }
}

/// The three-way merge of database custom data (contract-v1.8): per key, the value both sides
/// agree on; else the side that changed it since `base` (a removal included); changed on both, the
/// item with the newer `LastModificationTime` (local on a tie). The sync generation is left out:
/// the merge sets it. Local's order first, then the items only remote has.
fn merge_custom_data(
    local: &[CustomDataItem],
    remote: &[CustomDataItem],
    base: &[CustomDataItem],
) -> Vec<CustomDataItem> {
    let get = |items: &[CustomDataItem], k: &str| items.iter().find(|i| i.key == k).cloned();
    let mut keys: Vec<&str> = Vec::new();
    for i in local.iter().chain(remote) {
        if i.key != SYNC_GENERATION_KEY && !keys.contains(&i.key.as_str()) {
            keys.push(&i.key);
        }
    }
    let value = |i: &Option<CustomDataItem>| i.as_ref().map(|i| i.value.clone());
    let mut out = Vec::new();
    for k in keys {
        let (l, r, b) = (get(local, k), get(remote, k), get(base, k));
        let pick = if value(&l) == value(&r) {
            l
        } else if value(&l) == value(&b) {
            r
        } else if value(&r) == value(&b) {
            l
        } else {
            match (&l, &r) {
                (Some(li), Some(ri)) if ri.last_modification > li.last_modification => r,
                (None, _) => r,
                _ => l,
            }
        };
        out.extend(pick);
    }
    out
}

/// Makes `items` hold `merged` (keeping its own sync generation item); returns a change per item
/// added, changed or removed.
fn apply_custom_data(items: &mut Vec<CustomDataItem>, merged: &[CustomDataItem]) -> Vec<MergeChange> {
    let mut changes = Vec::new();
    for i in items.iter() {
        if i.key != SYNC_GENERATION_KEY && !merged.iter().any(|m| m.key == i.key) {
            changes.push(tree::db_record(ChangeType::Metadata, format!("Removed custom data {} [{}]", i.key, i.value)));
        }
    }
    for m in merged {
        if !items.iter().any(|i| i.key == m.key && i.value == m.value) {
            changes.push(tree::db_record(ChangeType::Metadata, format!("Adding custom data {} [{}]", m.key, m.value)));
        }
    }
    if changes.is_empty() {
        return changes;
    }
    let generation = items.iter().find(|i| i.key == SYNC_GENERATION_KEY).cloned();
    *items = merged.to_vec();
    items.extend(generation);
    changes
}

/// The entry UUIDs of `changes` whose type passes `pick`, each once, leaving out `except`.
fn entry_ids(changes: &[MergeChange], pick: impl Fn(ChangeType) -> bool, except: &[Uuid]) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = Vec::new();
    for c in changes {
        if c.subject != ChangeSubject::Entry || !pick(c.change) {
            continue;
        }
        if let Some(id) = c.uuid {
            if !out.contains(&id) && !except.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

// ------------------------------------------------------------------- locations (SyncEngine)

/// Where an entry both sides have ends up: in the group of the copy moved last (newer
/// `LocationChanged`, whole seconds; local wins a tie), whichever copy wins on its fields. The
/// structure merge replaces the older-modified copy with the newer one, location time and all, so a
/// move made on one device and an edit made on the other would leave the copies in different groups
/// with the same `LocationChanged`, and no later sync would bring them together. Found before
/// anything is merged ([`locations_of`]), applied to both copies after the structure merge
/// ([`apply_locations`]). Desktop `SyncEngine.cpp` `locationsOf`/`applyLocations`.
struct Location {
    entry: Uuid,
    /// `None` for the root group, which counts as the same group whatever its UUID.
    group: Option<Uuid>,
    changed: Timestamp,
    /// The moved-last copy's `PreviousParentGroup` (where the Recycle Bin restores it).
    previous: Option<Uuid>,
}

fn locations_of(local: &Database, remote: &Database) -> Vec<Location> {
    let (fl, fr) = (Finder::new(&local.root), Finder::new(&remote.root));
    entries_under(&local.root)
        .into_iter()
        .filter_map(|l| {
            let (l, lp) = fl.entry(&local.root, l.uuid)?;
            let (r, rp) = fr.entry(&remote.root, l.uuid)?;
            let (winner, parent, db) =
                if l.times.location_changed >= r.times.location_changed { (l, lp, local) } else { (r, rp, remote) };
            Some(Location {
                entry: l.uuid,
                group: (parent.uuid != db.root.uuid).then_some(parent.uuid),
                changed: winner.times.location_changed,
                previous: winner.previous_parent_group,
            })
        })
        .collect()
}

/// What [`apply_locations`] did.
struct Placed {
    /// One `Moved` record per entry that changed group on either side.
    changes: Vec<MergeChange>,
    /// A local copy changed (group or `LocationChanged`).
    local: bool,
    /// Entries whose local copy changed group.
    moved_here: Vec<Uuid>,
    /// A remote copy changed.
    remote: bool,
}

/// Puts each copy where `locations` says, with that `LocationChanged` and the moved-last copy's
/// `PreviousParentGroup` (so a deletion synced from another device restores to where it was),
/// without touching any modification times.
fn apply_locations(local: &mut Database, remote: &mut Database, locations: &[Location]) -> Placed {
    let mut placed = Placed { changes: Vec::new(), local: false, remote: false, moved_here: Vec::new() };
    let (mut fl, mut fr) = (Finder::new(&local.root), Finder::new(&remote.root));
    for loc in locations {
        let mut moved = false;
        for (is_local, db, find) in [(true, &mut *local, &mut fl), (false, &mut *remote, &mut fr)] {
            let group = loc.group.unwrap_or(db.root.uuid);
            let Some((entry, parent)) = find.entry(&db.root, loc.entry) else { continue };
            if find.group(&db.root, group).is_none() {
                continue;
            }
            let previous = parent.uuid;
            if previous == group
                && entry.times.location_changed == loc.changed
                && entry.previous_parent_group == loc.previous
            {
                continue;
            }
            if previous != group {
                find.append_entry(&mut db.root, loc.entry, group);
                moved = true;
                if is_local {
                    placed.moved_here.push(loc.entry);
                }
            }
            if let Some(e) = find.entry_mut(&mut db.root, loc.entry) {
                e.times.location_changed = loc.changed;
                e.previous_parent_group = loc.previous;
            }
            if is_local {
                placed.local = true;
            } else {
                placed.remote = true;
            }
        }
        if moved {
            if let Some((e, p)) = fl.entry(&local.root, loc.entry) {
                placed.changes.push(tree::entry_record(
                    ChangeType::Moved,
                    e,
                    Some(&p.name),
                    "Moved to where it was moved last",
                ));
            }
        }
    }
    placed
}

// ------------------------------------------------------------------- deletions (SyncEngine)

/// UUIDs of the entries and of the groups below the root.
fn ids_of(db: &Database) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = entries_under(&db.root).iter().map(|e| e.uuid).collect();
    ids.extend(groups_under(&db.root).iter().map(|g| g.uuid));
    ids
}

/// The deletions `from` made that `into` hasn't applied: recorded in `from`, gone there, still in
/// `into` (the first record per UUID). The root group is never deleted.
fn pending_deletions(from: &Database, into: &Database) -> Vec<(Uuid, DeletedObject)> {
    let mut mine = ids_of(from);
    mine.push(from.root.uuid);
    let theirs = ids_of(into);
    let mut pending: Vec<(Uuid, DeletedObject)> = Vec::new();
    for rec in &from.deleted_objects {
        let id = rec.uuid;
        if !mine.contains(&id) && theirs.contains(&id) && !pending.iter().any(|(i, _)| *i == id) {
            pending.push((id, *rec));
        }
    }
    pending
}

/// Whether a sync has deletions to apply, which needs the common base.
pub fn has_pending_deletions(local: &Database, remote: &Database) -> bool {
    !pending_deletions(local, remote).is_empty() || !pending_deletions(remote, local).is_empty()
}

fn entry_parent(db: &Database, id: Uuid) -> Option<Uuid> {
    find_entry(&db.root, id).map(|(_, p)| p.uuid)
}

fn same_group(db: &Database, a: &Group, base: &Database, b: &Group) -> bool {
    a.name == b.name
        && a.notes == b.notes
        && a.icon_id == b.icon_id
        && a.custom_icon == b.custom_icon
        && tree::group_parent(&db.root, a.uuid).map(|p| p.uuid)
            == tree::group_parent(&base.root, b.uuid).map(|p| p.uuid)
}

/// Replaces `db`'s deletion records for `id` with `rec`, or drops them.
fn set_deletion(db: &mut Database, id: Uuid, rec: Option<DeletedObject>) {
    db.deleted_objects.retain(|r| r.uuid != id);
    if let Some(rec) = rec {
        db.deleted_objects.push(rec);
    }
}

/// Applies the deletions either side made since the last sync (`pending`, found before the
/// structure merge brought the items back) to both, decided by the base rather than by times: an
/// item goes only when both copies still match the base (same fields, or for a group the same name,
/// notes and icon; in the same parent group) and, for a group, nothing is left in it. A deletion
/// held back is dropped, so the item stays on both.
fn apply_deletions(
    local: &mut Database,
    remote: &mut Database,
    base: &Database,
    pending: &[(Uuid, DeletedObject)],
) -> Vec<MergeChange> {
    let mut changes = Vec::new();
    for &(id, rec) in pending {
        let copies: Vec<&Database> =
            [&*local, &*remote].into_iter().filter(|db| find_entry(&db.root, id).is_some()).collect();
        let Some(first) = copies.first() else { continue };
        let unchanged = find_entry(&base.root, id).is_some_and(|(b, bp)| {
            copies.iter().all(|db| {
                let (e, _) = find_entry(&db.root, id).expect("copy has the entry");
                entry_parent(db, id) == Some(bp.uuid) && same_fields(e, db, b, base)
            })
        });
        if unchanged {
            let (e, p) = find_entry(&first.root, id).expect("copy has the entry");
            changes.push(tree::entry_record(ChangeType::Deleted, e, Some(&p.name), "Deleted on another device"));
            tree::take_entry(&mut local.root, id);
            tree::take_entry(&mut remote.root, id);
        }
        set_deletion(local, id, unchanged.then_some(rec));
        set_deletion(remote, id, unchanged.then_some(rec));
    }

    // Deepest first, so a group's deleted subgroups are gone before it is looked at
    let mut groups: Vec<Uuid> = pending
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| *id != local.root.uuid && find_group(&local.root, *id).is_some())
        .collect();
    groups.sort_by_key(|id| std::cmp::Reverse(tree::depth(&local.root, *id)));
    for id in groups {
        let rec = pending.iter().find(|(i, _)| *i == id).map(|(_, r)| *r);
        let unchanged = match find_group(&base.root, id) {
            Some(b) if b.uuid != base.root.uuid => {
                [&*local, &*remote].into_iter().all(|db| match find_group(&db.root, id) {
                    Some(g) => g.entries.is_empty() && g.groups.is_empty() && same_group(db, g, base, b),
                    None => true,
                })
            }
            _ => false,
        };
        if unchanged {
            if let Some(g) = find_group(&local.root, id) {
                changes.push(tree::group_record(ChangeType::Deleted, g, "Deleted on another device"));
            }
            tree::take_group(&mut local.root, id);
            tree::take_group(&mut remote.root, id);
        }
        set_deletion(local, id, if unchanged { rec } else { None });
        set_deletion(remote, id, if unchanged { rec } else { None });
    }
    changes
}

/// The structure merge doesn't carry the Recycle Bin, so a bin made on one device was a plain group
/// on the others. As in KeePass, the bin changed last wins on both sides; another bin is emptied into
/// it and deleted.
fn merge_recycle_bins(local: &mut Database, remote: &mut Database, now: Timestamp) -> Vec<MergeChange> {
    let bin_of = |db: &Database| db.meta.recycle_bin_uuid.filter(|id| find_group(&db.root, *id).is_some());
    let (local_bin, remote_bin) = (bin_of(local), bin_of(remote));
    let (bin, bin_changed) = match (local_bin, remote_bin) {
        (None, None) => return Vec::new(),
        (Some(l), Some(r)) if l == r => return Vec::new(),
        (Some(l), None) => (l, local.meta.recycle_bin_changed),
        (None, Some(r)) => (r, remote.meta.recycle_bin_changed),
        (Some(l), Some(r)) => {
            // Whole seconds, as the files keep them; the UUIDs' bytes break a tie
            let lt = local.meta.recycle_bin_changed.unwrap_or(0);
            let rt = remote.meta.recycle_bin_changed.unwrap_or(0);
            let local_wins = if lt != rt { lt > rt } else { l.as_bytes() < r.as_bytes() };
            if local_wins {
                (l, local.meta.recycle_bin_changed)
            } else {
                (r, remote.meta.recycle_bin_changed)
            }
        }
    };
    let others: Vec<Uuid> = [local_bin, remote_bin].into_iter().flatten().filter(|id| *id != bin).collect();
    for db in [&mut *local, &mut *remote] {
        if find_group(&db.root, bin).is_none() {
            continue;
        }
        for &other in &others {
            let Some(o) = find_group(&db.root, other) else { continue };
            // A bin inside the other one stays where it is
            if o.uuid == bin || find_group(o, bin).is_some() {
                continue;
            }
            let entries: Vec<Uuid> = o.entries.iter().map(|e| e.uuid).collect();
            let groups: Vec<Uuid> = o.groups.iter().map(|g| g.uuid).collect();
            for id in entries {
                if let Some(mut e) = tree::take_entry(&mut db.root, id) {
                    e.previous_parent_group = Some(other);
                    e.times.location_changed = now;
                    let _ = tree::push_entry(&mut db.root, bin, e);
                }
            }
            for id in groups {
                if let Some(mut g) = tree::take_group(&mut db.root, id) {
                    g.previous_parent_group = Some(other);
                    g.times.location_changed = now;
                    let _ = tree::push_group(&mut db.root, bin, g);
                }
            }
            // Recorded, so the devices that sync next delete it too
            if let Some(g) = tree::take_group(&mut db.root, other) {
                let mut ids = vec![g.uuid];
                ids.extend(groups_under(&g).iter().map(|c| c.uuid));
                ids.extend(entries_under(&g).iter().map(|e| e.uuid));
                for id in ids {
                    db.deleted_objects.push(DeletedObject { uuid: id, deletion_time: now });
                }
            }
        }
        if db.meta.recycle_bin_uuid != Some(bin) {
            db.meta.recycle_bin_uuid = Some(bin);
            db.meta.recycle_bin_changed = bin_changed;
        }
    }
    vec![tree::db_record(ChangeType::Metadata, "Recycle Bin set from another device")]
}

// --------------------------------------------------------------------- conflict detection (SyncEngine)

/// Entry UUID → last modification time in **milliseconds**, taken after each sync (the SDK's stored
/// snapshot format; KDBX keeps whole seconds, so only `ms / 1000` is compared).
pub type Snapshot = Vec<(Uuid, i64)>;

/// The snapshot of `db` after a sync.
pub fn snapshot_of(db: &Database) -> Snapshot {
    entries_under(&db.root).iter().map(|e| (e.uuid, e.times.last_modification * 1000)).collect()
}

struct Changed {
    local: bool,
    remote: bool,
}

fn changes_since(l: &Entry, l_db: &Database, r: &Entry, r_db: &Database, snapshot_ms: i64) -> Changed {
    let snap = snapshot_ms.div_euclid(1000);
    let local = l.times.last_modification != snap;
    let remote = r.times.last_modification != snap || (!local && !same_fields(l, l_db, r, r_db));
    Changed { local, remote }
}

/// Whether merging needs the common base (`SyncEngine::needsCommonBase`): to combine entries, or to
/// apply deletions.
pub fn needs_common_base(local: &Database, remote: &Database, snapshot: &[(Uuid, i64)]) -> bool {
    if has_pending_deletions(local, remote) {
        return true;
    }
    let (fl, fr) = (Finder::new(&local.root), Finder::new(&remote.root));
    snapshot.iter().any(|&(id, ms)| {
        let (Some((l, _)), Some((r, _))) = (fl.entry(&local.root, id), fr.entry(&remote.root, id)) else {
            return false;
        };
        if same_fields(l, local, r, remote) {
            return false;
        }
        let c = changes_since(l, local, r, remote, ms);
        let (lt, rt) = (l.times.last_modification, r.times.last_modification);
        (c.local && c.remote) || (c.local && lt <= rt) || (c.remote && rt <= lt)
    })
}

/// Whether a merge of these copies can use the common base at all: there are deletions to apply, or
/// an entry both have differs. A sync opens the base whenever this holds, because the snapshot check
/// ([`needs_common_base`]) compares whole-second modification times: an edit made in the same second
/// as the last sync looks unchanged to it, and the newer copy would then win whole (its other
/// side's edit going to history) where the base keeps both, field by field.
///
/// Different database custom data (sync generation aside) counts too: it merges against the base.
pub fn copies_differ(local: &Database, remote: &Database) -> bool {
    fn custom(db: &Database) -> Vec<(&str, &str)> {
        let mut v: Vec<(&str, &str)> = db
            .meta
            .custom_data
            .iter()
            .filter(|i| i.key != SYNC_GENERATION_KEY)
            .map(|i| (i.key.as_str(), i.value.as_str()))
            .collect();
        v.sort_unstable();
        v
    }
    if custom(local) != custom(remote) || has_pending_deletions(local, remote) {
        return true;
    }
    let fr = Finder::new(&remote.root);
    entries_under(&local.root)
        .iter()
        .any(|l| fr.entry(&remote.root, l.uuid).is_some_and(|(r, _)| !same_fields(l, local, r, remote)))
}

/// The entries both sides changed against `base`, by content (not by time), with the fields they
/// changed differently: [`ConflictKind::EditedOnBoth`] conflicts with their fields filled in. An entry
/// whose two sides changed different fields isn't one (both changes are kept).
pub fn edited_on_both(local: &Database, remote: &Database, base: &Database) -> Vec<SyncConflict> {
    let mut out = Vec::new();
    let (fr, fb) = (Finder::new(&remote.root), Finder::new(&base.root));
    for l in entries_under(&local.root) {
        let (Some((r, _)), Some((b, _))) = (fr.entry(&remote.root, l.uuid), fb.entry(&base.root, l.uuid)) else {
            continue;
        };
        if same_fields(l, local, r, remote) {
            continue;
        }
        let fields = conflicting_fields(Some((l, local)), Some((r, remote)), Some((b, base)));
        if !fields.is_empty() {
            out.push(SyncConflict {
                uuid: l.uuid,
                kind: ConflictKind::EditedOnBoth,
                title: l.title().to_owned(),
                fields,
            });
        }
    }
    out
}

/// The kind of a [`SyncConflict`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    /// Edited on both sides.
    EditedOnBoth,
    /// Deleted here, edited on the other side.
    DeletedHereEditedThere,
    /// Edited here, deleted on the other side.
    EditedHereDeletedThere,
}

/// A conflict [`find_conflicts`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConflict {
    /// The entry.
    pub uuid: Uuid,
    /// What happened.
    pub kind: ConflictKind,
    /// The entry's title.
    pub title: String,
    /// Always empty here; the merge fills field names in [`MergeReport::conflicts`].
    pub fields: Vec<String>,
}

/// `SyncEngine::findConflicts`: the entries changed on both sides since the snapshot, or deleted on
/// one and changed on the other.
pub fn find_conflicts(local: &Database, remote: &Database, snapshot: &[(Uuid, i64)]) -> Vec<SyncConflict> {
    let deleted_in = |db: &Database, id: Uuid| db.deleted_objects.iter().any(|o| o.uuid == id);
    let changed_since = |e: &Entry, ms: i64| e.times.last_modification != ms.div_euclid(1000);
    let mut out = Vec::new();
    let (fl, fr) = (Finder::new(&local.root), Finder::new(&remote.root));
    for &(id, ms) in snapshot {
        let l = fl.entry(&local.root, id).map(|(e, _)| e);
        let r = fr.entry(&remote.root, id).map(|(e, _)| e);
        let (kind, e) = match (l, r) {
            (Some(l), Some(r)) => {
                let c = changes_since(l, local, r, remote, ms);
                if !c.local || !c.remote || same_fields(l, local, r, remote) {
                    continue;
                }
                (ConflictKind::EditedOnBoth, l)
            }
            (None, Some(r)) if deleted_in(local, id) && changed_since(r, ms) => {
                (ConflictKind::DeletedHereEditedThere, r)
            }
            (Some(l), None) if deleted_in(remote, id) && changed_since(l, ms) => {
                (ConflictKind::EditedHereDeletedThere, l)
            }
            _ => continue,
        };
        out.push(SyncConflict { uuid: id, kind, title: e.title().to_owned(), fields: Vec::new() });
    }
    out
}

/// The fields both sides changed differently (`SyncEngine::conflictingFields`), each entry read in
/// its own database. Empty without all three copies.
pub fn conflicting_fields(
    local: Option<(&Entry, &Database)>,
    remote: Option<(&Entry, &Database)>,
    base: Option<(&Entry, &Database)>,
) -> Vec<String> {
    match (local, remote, base) {
        (Some(l), Some(r), Some(b)) => resolve_fields(l, r, b, true).1,
        _ => Vec::new(),
    }
}
