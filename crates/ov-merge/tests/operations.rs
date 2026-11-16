//! Cases the fixtures don't cover: attachment re-interning across pools, import (merge and copies),
//! the Recycle Bin, group deletions, snapshot conflicts, custom data metadata.

mod common;

use common::{empty_db, set_field};
use ov_kdbx::model::{Binary, BinaryRef, CustomDataItem, Database, DeletedObject, Entry, Group, Timestamp, Uuid};
use ov_merge::{
    find_conflicts, import_as_copies, import_into, import_targets, merge, merge_in_place, needs_common_base,
    snapshot_of, sync_generation, ConflictKind,
};
use zeroize::Zeroizing;

const T0: Timestamp = 1_772_000_000;
const ROOT: Uuid = Uuid::from_u128(1);

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0xa1000000_0000_4000_8000_000000000000 + n)
}

fn entry(n: u128, title: &str, t: Timestamp) -> Entry {
    let mut e = Entry::new(id(n), T0);
    set_field(&mut e, "Title", title, false);
    e.times.last_modification = t;
    e
}

fn bin(data: &[u8]) -> Binary {
    Binary { data: Zeroizing::new(data.to_vec()), protected: false }
}

fn attachment<'a>(db: &'a Database, e: &Entry, name: &str) -> &'a [u8] {
    let r = e.binaries.iter().find(|b| b.name == name).expect("attachment");
    &db.binaries[r.index as usize].data
}

fn find(db: &Database, n: u128) -> Option<&Entry> {
    fn walk(g: &Group, u: Uuid) -> Option<&Entry> {
        g.entries.iter().find(|e| e.uuid == u).or_else(|| g.groups.iter().find_map(|c| walk(c, u)))
    }
    walk(&db.root, id(n))
}

#[test]
fn attachments_are_reinterned_across_pools() {
    // local: pool [x, y]; remote: pool [z, y'] with the entries pointing at different indexes
    let mut local = empty_db(ROOT, T0);
    local.binaries = vec![bin(b"unused"), bin(b"local file")];
    let mut a = entry(1, "A", T0 + 10);
    a.binaries.push(BinaryRef { name: "a.txt".into(), index: 1 });
    local.root.entries.push(a);

    let mut remote = empty_db(ROOT, T0);
    remote.binaries = vec![bin(b"remote file"), bin(b"history file")];
    let mut b = entry(2, "B", T0 + 20);
    b.binaries.push(BinaryRef { name: "b.txt".into(), index: 0 });
    let mut old = entry(2, "B", T0 + 5);
    old.binaries.push(BinaryRef { name: "b.txt".into(), index: 1 });
    b.history.push(old);
    remote.root.entries.push(b);

    let (merged, report) = merge(None, &local, &remote, T0 + 100);
    assert_eq!(report.added, vec![id(2)]);
    // the pool holds exactly what is used, in tree order
    assert_eq!(merged.binaries.len(), 3);
    let a = find(&merged, 1).unwrap();
    let b = find(&merged, 2).unwrap();
    assert_eq!(attachment(&merged, a, "a.txt"), b"local file");
    assert_eq!(attachment(&merged, b, "b.txt"), b"remote file");
    assert_eq!(attachment(&merged, &b.history[0], "b.txt"), b"history file");
}

#[test]
fn identical_attachments_share_one_pool_item() {
    let mut local = empty_db(ROOT, T0);
    local.binaries = vec![bin(b"same")];
    let mut a = entry(1, "A", T0);
    a.binaries.push(BinaryRef { name: "f".into(), index: 0 });
    local.root.entries.push(a);
    let mut remote = empty_db(ROOT, T0);
    remote.binaries = vec![bin(b"same")];
    let mut b = entry(2, "B", T0);
    b.binaries.push(BinaryRef { name: "g".into(), index: 0 });
    remote.root.entries.push(b);
    let (merged, _) = merge(None, &local, &remote, T0 + 100);
    assert_eq!(merged.binaries.len(), 1);
}

#[test]
fn import_into_merges_by_uuid_and_twice_changes_nothing() {
    let mut target = empty_db(ROOT, T0);
    target.root.name = "My vault".into();
    target.root.entries.push(entry(1, "Old title", T0 + 10));
    target.meta.custom_data.push(CustomDataItem {
        key: "KPXC_REMOTE_SYNC_SETTINGS".into(),
        value: "x".into(),
        last_modification: None,
    });

    let mut source = empty_db(Uuid::from_u128(99), T0);
    source.root.name = "File".into();
    source.root.entries.push(entry(1, "New title", T0 + 20));
    source.root.entries.push(entry(2, "Added", T0 + 20));
    let bin_id = Uuid::from_u128(77);
    let mut recycle = Group::new(bin_id, "Recycle Bin", T0);
    recycle.entries.push(entry(3, "Trashed", T0));
    source.root.groups.push(recycle);
    source.meta.recycle_bin_uuid = Some(bin_id);
    source.meta.custom_data.push(CustomDataItem { key: "Other".into(), value: "y".into(), last_modification: None });

    let s = import_into(&source, &mut target);
    assert_eq!((s.added, s.updated, s.unchanged, s.groups_added), (1, 1, 0, 0));
    assert_eq!(target.root.name, "My vault");
    assert_eq!(find(&target, 1).unwrap().title(), "New title");
    assert_eq!(find(&target, 1).unwrap().history.len(), 1);
    assert!(find(&target, 3).is_none(), "the source's Recycle Bin stays behind");
    assert_eq!(target.meta.custom_data.len(), 1, "database custom data stays behind");

    let again = target.clone();
    let s = import_into(&source, &mut target);
    assert_eq!((s.added, s.updated, s.unchanged), (0, 0, 2));
    assert_eq!(target, again);
}

#[test]
fn import_as_copies_gives_fresh_uuids_and_follows_references() {
    let mut target = empty_db(ROOT, T0);
    let sub = Uuid::from_u128(5);
    target.root.groups.push(Group::new(sub, "Imports", T0));

    let mut source = empty_db(Uuid::from_u128(99), T0);
    source.root.name = "Work".into();
    source.binaries = vec![bin(b"doc")];
    let mut a = entry(1, "A", T0);
    a.binaries.push(BinaryRef { name: "d".into(), index: 0 });
    a.history.push(entry(1, "A old", T0 - 5));
    let mut b = entry(2, "B", T0);
    let a_hex: String = id(1).simple().to_string().to_uppercase();
    set_field(&mut b, "Password", &format!("{{REF:P@I:{a_hex}}}"), true);
    set_field(&mut b, "Notes", &format!("{{REF:U@I:{}}} {{REF:bad", a_hex.to_lowercase()), false);
    source.root.entries.extend([a, b]);
    let mut nested = Group::new(Uuid::from_u128(98), "Nested", T0);
    nested.entries.push(entry(3, "C", T0));
    source.root.groups.push(nested);

    let mut next = 0x1000u128;
    let mut fresh = || {
        next += 1;
        Uuid::from_u128(next)
    };
    let s = import_as_copies(&source, &mut target, sub, T0 + 50, &mut fresh).unwrap();
    assert_eq!((s.added, s.groups_added), (3, 2));
    let top = &target.root.groups[0].groups[0];
    assert_eq!(top.name, "Work");
    assert_eq!(top.times.location_changed, T0 + 50);
    let (ca, cb) = (&top.entries[0], &top.entries[1]);
    assert_ne!(ca.uuid, id(1));
    assert_eq!(ca.history[0].uuid, ca.uuid);
    assert_eq!(attachment(&target, ca, "d"), b"doc");
    let ca_hex = ca.uuid.simple().to_string().to_uppercase();
    assert_eq!(cb.field_text("Password"), format!("{{REF:P@I:{ca_hex}}}"));
    assert!(cb.field("Password").unwrap().protected);
    assert_eq!(cb.field_text("Notes"), format!("{{REF:U@I:{ca_hex}}} {{REF:bad"));
    assert_eq!(top.groups[0].entries[0].title(), "C");

    let err = import_as_copies(&source, &mut target, Uuid::from_u128(404), T0, &mut fresh).unwrap_err();
    assert_eq!(err.wire_code(), "not_found");
    let paths: Vec<String> = import_targets(&target).into_iter().map(|(_, p)| p).collect();
    assert_eq!(paths, ["Root", "Root / Imports", "Root / Imports / Work", "Root / Imports / Work / Nested"]);
}

#[test]
fn recycle_bins_converge_on_the_later_one() {
    let base = empty_db(ROOT, T0);
    let (lb, rb) = (Uuid::from_u128(10), Uuid::from_u128(11));
    let mut local = base.clone();
    let mut g = Group::new(lb, "Recycle Bin", T0);
    g.entries.push(entry(1, "trashed here", T0));
    local.root.groups.push(g);
    local.meta.recycle_bin_uuid = Some(lb);
    local.meta.recycle_bin_changed = Some(T0 + 10);
    let mut remote = base.clone();
    let mut g = Group::new(rb, "Recycle Bin", T0);
    g.entries.push(entry(2, "trashed there", T0));
    remote.root.groups.push(g);
    remote.meta.recycle_bin_uuid = Some(rb);
    remote.meta.recycle_bin_changed = Some(T0 + 20);

    merge_in_place(&mut local, &mut remote, Some(&base), T0 + 100);
    for db in [&local, &remote] {
        assert_eq!(db.meta.recycle_bin_uuid, Some(rb));
        assert_eq!(db.meta.recycle_bin_changed, Some(T0 + 20));
        assert_eq!(db.root.groups.len(), 1);
        let bin = &db.root.groups[0];
        assert_eq!(bin.uuid, rb);
        assert_eq!(bin.entries.len(), 2);
        assert!(db.deleted_objects.iter().any(|d| d.uuid == lb && d.deletion_time == T0 + 100));
        assert_eq!(sync_generation(db), 1);
    }
}

#[test]
fn empty_group_deleted_on_one_side_goes_from_both() {
    let g = Uuid::from_u128(20);
    let mut base = empty_db(ROOT, T0);
    base.root.groups.push(Group::new(g, "Old", T0));
    let mut local = base.clone();
    local.root.groups.clear();
    local.deleted_objects.push(DeletedObject { uuid: g, deletion_time: T0 + 5 });
    let mut remote = base.clone();
    let report = merge_in_place(&mut local, &mut remote, Some(&base), T0 + 100);
    assert!(local.root.groups.is_empty() && remote.root.groups.is_empty());
    assert!(remote.deleted_objects.iter().any(|d| d.uuid == g));
    assert!(report.remote_changed);

    // renamed on the other side since the base: it stays and the record is dropped
    let mut local = base.clone();
    local.root.groups.clear();
    local.deleted_objects.push(DeletedObject { uuid: g, deletion_time: T0 + 5 });
    let mut remote = base.clone();
    remote.root.groups[0].name = "Renamed".into();
    remote.root.groups[0].times.last_modification = T0 + 3;
    merge_in_place(&mut local, &mut remote, Some(&base), T0 + 100);
    assert_eq!(local.root.groups[0].name, "Renamed");
    assert!(local.deleted_objects.is_empty() && remote.deleted_objects.is_empty());
}

#[test]
fn snapshot_conflicts() {
    let mut base = empty_db(ROOT, T0);
    base.root.entries.extend([entry(1, "A", T0), entry(2, "B", T0), entry(3, "C", T0)]);
    let snap = snapshot_of(&base);
    let mut local = base.clone();
    let mut remote = base.clone();
    set_field(&mut local.root.entries[0], "Password", "l", true);
    local.root.entries[0].times.last_modification = T0 + 1;
    set_field(&mut remote.root.entries[0], "Password", "r", true);
    remote.root.entries[0].times.last_modification = T0 + 2;
    // B deleted here, edited there
    local.root.entries.remove(1);
    local.deleted_objects.push(DeletedObject { uuid: id(2), deletion_time: T0 + 1 });
    remote.root.entries[1].times.last_modification = T0 + 3;
    let c = find_conflicts(&local, &remote, &snap);
    let kinds: Vec<(Uuid, ConflictKind)> = c.iter().map(|c| (c.uuid, c.kind)).collect();
    assert_eq!(kinds, [(id(1), ConflictKind::EditedOnBoth), (id(2), ConflictKind::DeletedHereEditedThere)]);
    assert!(needs_common_base(&local, &remote, &snap));
    assert!(!needs_common_base(&base, &base, &snap));
}

#[test]
fn newer_database_custom_data_is_applied() {
    let mut local = empty_db(ROOT, T0);
    local.meta.custom_data = vec![
        CustomDataItem {
            key: "_LAST_MODIFIED".into(),
            value: "Tue Mar 3 10:00:00 2026 GMT".into(),
            last_modification: None,
        },
        CustomDataItem { key: "Gone".into(), value: "1".into(), last_modification: None },
        CustomDataItem { key: "KPXC_BROWSER_x".into(), value: "kept".into(), last_modification: None },
    ];
    let mut remote = empty_db(ROOT, T0);
    remote.meta.custom_data = vec![
        CustomDataItem { key: "_LAST_MODIFIED".into(), value: "2026-03-04T10:00:00Z".into(), last_modification: None },
        CustomDataItem { key: "New".into(), value: "2".into(), last_modification: None },
    ];
    let (merged, _) = merge(None, &local, &remote, T0);
    let keys: Vec<&str> = merged.meta.custom_data.iter().map(|i| i.key.as_str()).collect();
    assert_eq!(keys, ["_LAST_MODIFIED", "KPXC_BROWSER_x", "New", "KPXC_SYNC_GENERATION"]);
}
