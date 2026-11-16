//! Properties of the sync merge:
//!
//! - idempotence: `merge(x, x, x) == x` (exact model equality, and without a base too);
//! - symmetry: swapping local and remote gives an equal result, where "equal" is [`canonical`]
//!   equality (see its doc for what it leaves out and why), on inputs where the two sides never stamp
//!   different content with the same second (local edits at odd seconds, remote at even) and an entry
//!   isn't moved on one side while edited on the other (see `case()`);
//! - both copies agree after `merge_in_place`.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{empty_db, intern, set_field};
use ov_kdbx::model::{BinaryRef, Database, DeletedObject, Entry, Group, Timestamp, Uuid};
use ov_merge::{merge, merge_in_place};
use proptest::prelude::*;

const T0: Timestamp = 1_772_000_000;
const ROOT: Uuid = Uuid::from_u128(0x6e3a9f40_1c2b_4d5e_8f70_9a1b2c3d4e5f);
const SUB: Uuid = Uuid::from_u128(0x5b000000_0000_4000_8000_000000000001);
const POOL: usize = 6;

fn entry_id(i: usize) -> Uuid {
    Uuid::from_u128(0xa1000000_0000_4000_8000_000000000000 + i as u128)
}

/// One entry's content, small enough that collisions happen often.
#[derive(Clone, Debug)]
struct Content {
    password: u8,
    url: Option<u8>,
    custom: Option<u8>,
    attachment: Option<u8>,
    tags: u8,
}

fn content() -> impl Strategy<Value = Content> {
    (0u8..4, proptest::option::of(0u8..3), proptest::option::of(0u8..3), proptest::option::of(0u8..2), 0u8..3)
        .prop_map(|(password, url, custom, attachment, tags)| Content { password, url, custom, attachment, tags })
}

fn make_entry(db: &mut Database, i: usize, c: &Content, modified: Timestamp) -> Entry {
    let mut e = Entry::new(entry_id(i), T0);
    set_field(&mut e, "Title", &format!("E{i}"), false);
    set_field(&mut e, "Password", &format!("p{}", c.password), true);
    if let Some(u) = c.url {
        set_field(&mut e, "URL", &format!("https://{u}.example"), false);
    }
    if let Some(v) = c.custom {
        set_field(&mut e, "API key", &format!("k{v}"), true);
    }
    if let Some(a) = c.attachment {
        let index = intern(db, format!("attachment {a}").as_bytes());
        e.binaries.push(BinaryRef { name: "file.txt".into(), index });
    }
    e.tags = match c.tags {
        0 => vec![],
        1 => vec!["a".into()],
        _ => vec!["a".into(), "b".into()],
    };
    e.times.last_modification = modified;
    e.times.last_access = modified;
    e
}

#[derive(Clone, Debug)]
struct BaseEntry {
    content: Content,
    in_sub: bool,
    /// A history item (older content).
    history: Option<Content>,
}

#[derive(Clone, Debug)]
enum Action {
    Keep,
    /// New content, at this many steps from the base time (may be behind it: a slow clock).
    Edit(Content, i64),
    Delete(i64),
    /// Move to the other group.
    Move(i64),
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        3 => Just(Action::Keep),
        3 => (content(), -2i64..6).prop_map(|(c, t)| Action::Edit(c, t)),
        1 => (0i64..6).prop_map(Action::Delete),
        1 => (0i64..6).prop_map(Action::Move),
    ]
}

#[derive(Clone, Debug)]
struct Side {
    actions: Vec<Action>,
    /// New entries (pool index beyond the base ones; the same index on both sides is the same UUID).
    added: Vec<(usize, Content, i64)>,
}

fn side() -> impl Strategy<Value = Side> {
    (proptest::collection::vec(action(), POOL), proptest::collection::vec((0usize..3, content(), 0i64..6), 0..3))
        .prop_map(|(actions, added)| Side { actions, added })
}

#[derive(Clone, Debug)]
struct Case {
    base: Vec<Option<BaseEntry>>,
    with_sub: bool,
    local: Side,
    remote: Side,
}

fn case() -> impl Strategy<Value = Case> {
    let base_entry = (content(), any::<bool>(), proptest::option::of(content()))
        .prop_map(|(content, in_sub, history)| BaseEntry { content, in_sub, history });
    (proptest::collection::vec(proptest::option::of(base_entry), POOL), any::<bool>(), side(), side()).prop_map(
        |(base, with_sub, mut local, mut remote)| {
            // A move on one side and an edit on the other is left out: the side whose entry is older
            // takes a copy of the newer one *with its location time*, so the move is lost on one
            // copy only and the copies end up in different groups. That is the desktop `Merger`'s
            // and the SDK's behaviour (merge-behaviour.md §1.1), kept as is; see the W1-M report.
            for (l, r) in local.actions.iter_mut().zip(remote.actions.iter_mut()) {
                match (&*l, &*r) {
                    (Action::Move(_), Action::Edit(..)) => *l = Action::Keep,
                    (Action::Edit(..), Action::Move(_)) => *r = Action::Keep,
                    _ => {}
                }
            }
            Case { base, with_sub, local, remote }
        },
    )
}

fn base_time(i: usize) -> Timestamp {
    T0 + 100 + 4 * i as i64
}

fn build_base(c: &Case) -> Database {
    let mut db = empty_db(ROOT, T0);
    if c.with_sub {
        db.root.groups.push(Group::new(SUB, "Sub", T0));
    }
    for (i, b) in c.base.iter().enumerate() {
        let Some(b) = b else { continue };
        let mut e = make_entry(&mut db, i, &b.content, base_time(i));
        if let Some(h) = &b.history {
            let item = make_entry(&mut db, i, h, base_time(i) - 50);
            e.history.push(item);
        }
        let group = if b.in_sub && c.with_sub { &mut db.root.groups[0] } else { &mut db.root };
        group.entries.push(e);
    }
    ov_merge::compact_binaries(&mut db);
    db
}

/// A side's copy: the base with its actions applied. Local stamps odd seconds, remote even ones.
fn build_side(base: &Database, c: &Case, s: &Side, parity: i64) -> Database {
    let mut db = base.clone();
    let stamp = |step: i64| T0 + 1000 + 2 * step + parity;
    for (i, a) in s.actions.iter().enumerate() {
        let id = entry_id(i);
        let Some(current) = find(&db.root, id).cloned() else { continue };
        match a {
            Action::Keep => {}
            Action::Edit(content, step) => {
                // slow clocks: steps below 0 land before the base time
                let t = if *step < 0 { base_time(i) - 10 + 2 * step + parity } else { stamp(*step) };
                let mut e = make_entry(&mut db, i, content, t);
                e.times.location_changed = current.times.location_changed;
                let mut before = current.clone();
                before.history.clear();
                e.history = current.history.clone();
                e.history.push(before);
                replace(&mut db.root, e);
            }
            Action::Delete(step) => {
                take(&mut db.root, id);
                db.deleted_objects.push(DeletedObject { uuid: id, deletion_time: stamp(*step) });
            }
            Action::Move(step) => {
                if !c.with_sub {
                    continue;
                }
                let mut e = take(&mut db.root, id).expect("present");
                let in_root = base.root.entries.iter().any(|x| x.uuid == id);
                e.times.location_changed = stamp(*step);
                if in_root {
                    db.root.groups[0].entries.push(e);
                } else {
                    db.root.entries.push(e);
                }
            }
        }
    }
    for (k, content, step) in &s.added {
        let i = POOL + k;
        if find(&db.root, entry_id(i)).is_some() {
            continue;
        }
        let mut e = make_entry(&mut db, i, content, stamp(*step));
        e.times.creation = stamp(*step);
        db.root.entries.push(e);
    }
    ov_merge::compact_binaries(&mut db);
    db
}

fn find(g: &Group, id: Uuid) -> Option<&Entry> {
    g.entries.iter().find(|e| e.uuid == id).or_else(|| g.groups.iter().find_map(|c| find(c, id)))
}

fn take(g: &mut Group, id: Uuid) -> Option<Entry> {
    if let Some(i) = g.entries.iter().position(|e| e.uuid == id) {
        return Some(g.entries.remove(i));
    }
    g.groups.iter_mut().find_map(|c| take(c, id))
}

fn replace(g: &mut Group, e: Entry) {
    if let Some(slot) = g.entries.iter_mut().find(|x| x.uuid == e.uuid) {
        *slot = e;
        return;
    }
    for c in &mut g.groups {
        replace(c, e.clone());
    }
}

/// A database with the parts the merge leaves order- or side-dependent normalised away:
///
/// - sibling order is ignored (each side appends what it brings in at the end of a group);
/// - entries and history items are compared with attachments resolved to their content (pool
///   indexes depend on tree order);
/// - deletion records are compared as a set of UUIDs, and only with a base: a record for an item
///   both sides deleted keeps each side's own deletion time, and without a base the sync leaves each
///   side's records as they are (TS `mergeDatabases`; the structure merge in keep-newer mode never
///   copies deletion records), so the local copy's list is local's.
///
/// - an entry's `LocationChanged` is left out: when the structure merge moves an entry to follow
///   the other side, the counterpart keeps its own location time (merge-behaviour.md §1.1, TS
///   `Pass.entry`), so the two copies hold different values for it. Its group is compared.
///
/// Everything else in the database (meta, custom data with the sync generation, groups and their
/// properties and parents, every entry field, times, history) must match exactly.
fn canonical(db: &Database, with_deleted: bool) -> String {
    let mut groups = BTreeMap::new();
    let mut entries = BTreeMap::new();
    fn walk(
        db: &Database,
        g: &Group,
        parent: Option<Uuid>,
        groups: &mut BTreeMap<Uuid, String>,
        entries: &mut BTreeMap<Uuid, String>,
    ) {
        let mut shallow = g.clone();
        shallow.entries.clear();
        shallow.groups.clear();
        groups.insert(g.uuid, format!("{parent:?} {shallow:?}"));
        for e in &g.entries {
            entries.insert(e.uuid, format!("in {} {}", g.uuid, entry_text(db, e)));
        }
        for c in &g.groups {
            walk(db, c, Some(g.uuid), groups, entries);
        }
    }
    walk(db, &db.root, None, &mut groups, &mut entries);
    let deleted: BTreeSet<Uuid> =
        if with_deleted { db.deleted_objects.iter().map(|d| d.uuid).collect() } else { BTreeSet::new() };
    let mut meta = db.meta.clone();
    meta.custom_data.sort_by(|a, b| a.key.cmp(&b.key));
    format!("{:?}\n{meta:?}\n{groups:#?}\n{entries:#?}\ndeleted {deleted:?}", db.header)
}

fn entry_text(db: &Database, e: &Entry) -> String {
    let mut plain = e.clone();
    plain.history.clear();
    plain.times.location_changed = 0;
    let atts: Vec<(String, Vec<u8>, bool)> = e
        .binaries
        .iter()
        .map(|b| {
            let bin = &db.binaries[b.index as usize];
            (b.name.clone(), bin.data.to_vec(), bin.protected)
        })
        .collect();
    plain.binaries.clear();
    let strings: Vec<(String, String, bool)> =
        e.strings.iter().map(|s| (s.key.clone(), s.value.to_string(), s.protected)).collect();
    plain.strings.clear();
    let history: Vec<String> = e.history.iter().map(|h| entry_text(db, h)).collect();
    format!("{plain:?} {strings:?} {atts:?} history {history:?}")
}

fn assert_pool_consistent(db: &Database) {
    let mut used = vec![false; db.binaries.len()];
    let mut check = |e: &Entry| {
        for b in &e.binaries {
            assert!((b.index as usize) < db.binaries.len(), "dangling BinaryRef {}", b.index);
            used[b.index as usize] = true;
        }
    };
    fn each(g: &Group, f: &mut dyn FnMut(&Entry)) {
        for e in &g.entries {
            f(e);
            e.history.iter().for_each(&mut *f);
        }
        g.groups.iter().for_each(|c| each(c, f));
    }
    each(&db.root, &mut check);
    assert!(used.iter().all(|u| *u), "unreferenced binaries in the pool");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn merging_a_database_with_itself_changes_nothing(c in case(), side_pick in 0u8..3) {
        let base = build_base(&c);
        let x = match side_pick {
            0 => base,
            1 => build_side(&base, &c, &c.local, 1),
            _ => build_side(&base, &c, &c.remote, 0),
        };
        let (merged, report) = merge(Some(&x), &x, &x, T0 + 5000);
        prop_assert_eq!(&merged, &x);
        prop_assert!(report.changes.is_empty() && !report.local_changed && !report.remote_changed);
        let (merged, _) = merge(None, &x, &x, T0 + 5000);
        prop_assert_eq!(&merged, &x);
    }

    #[test]
    fn merging_is_symmetric(c in case(), with_base in any::<bool>()) {
        let base = build_base(&c);
        let local = build_side(&base, &c, &c.local, 1);
        let remote = build_side(&base, &c, &c.remote, 0);
        let b = with_base.then_some(&base);
        let now = T0 + 5000;
        let (lr, report_lr) = merge(b, &local, &remote, now);
        let (rl, report_rl) = merge(b, &remote, &local, now);
        assert_pool_consistent(&lr);
        prop_assert_eq!(canonical(&lr, with_base), canonical(&rl, with_base));
        let conflicts = |r: &ov_merge::MergeReport| {
            // Field names come in the local entry's field order (the TS Map order), so compare sets
            r.conflicts.iter().map(|c| (c.uuid, c.fields.iter().cloned().collect::<BTreeSet<_>>())).collect::<BTreeMap<_, _>>()
        };
        prop_assert_eq!(conflicts(&report_lr), conflicts(&report_rl));
        prop_assert_eq!(report_lr.local_changed || report_lr.remote_changed, report_rl.local_changed || report_rl.remote_changed);
    }

    #[test]
    fn both_copies_agree_after_merging(c in case(), with_base in any::<bool>()) {
        let base = build_base(&c);
        let mut local = build_side(&base, &c, &c.local, 1);
        let mut remote = build_side(&base, &c, &c.remote, 0);
        merge_in_place(&mut local, &mut remote, with_base.then_some(&base), T0 + 5000);
        assert_pool_consistent(&local);
        assert_pool_consistent(&remote);
        prop_assert_eq!(canonical(&local, false), canonical(&remote, false));
    }
}
