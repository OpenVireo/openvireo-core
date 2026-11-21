//! Fixtures for the benchmarks: account vaults of any size (the 5k vault is the layout of
//! ov-kdbx's `five_thousand_entries_round_trip` test, as a vault with the vault KDF), and the
//! local / remote edits a sync merges.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ov_kdbx::entries::{delete_entry, find_entry_mut, find_group_mut, set_field};
use ov_kdbx::model::{Binary, BinaryRef, Database, Entry, Group, StringField, Timestamp, Uuid};
use ov_kdbx::vault::create_vault_kdbx;
use ov_kdbx::CompositeKey;

/// The vault key of every fixture.
pub const VAULT_KEY: [u8; 32] = [7; 32];
/// When the fixture vault was last synced: 2025-11-15T12:00:00Z.
pub const T0: Timestamp = 1_763_208_000;
/// When the local edits were made.
pub const T_LOCAL: Timestamp = T0 + 3600;
/// When the other device's edits were made.
pub const T_REMOTE: Timestamp = T0 + 7200;
/// When the merge runs.
pub const T_MERGE: Timestamp = T0 + 10_800;

/// The id of entry `n`.
pub fn entry_id(n: u32) -> Uuid {
    Uuid::from_u128(0x5200_0000 + u128::from(n))
}

/// The id of group `g`.
pub fn group_id(g: u32) -> Uuid {
    Uuid::from_u128(0x5100_0000 + u128::from(g))
}

/// An account vault (vault KDF: Argon2id 1 MiB, t = 2) with `groups` × `per_group` entries. Every
/// 10th entry has a history item, every 7th a tag and every 100th an attachment.
pub fn vault(groups: u32, per_group: u32) -> (Database, CompositeKey) {
    let (mut db, key) = create_vault_kdbx("Vault", &VAULT_KEY, T0).expect("new vault");
    let attachment = u32::try_from(db.binaries.len()).expect("pool index");
    db.binaries.push(Binary { data: b"5k attachment".to_vec().into(), protected: false });
    for g in 0..groups {
        let mut group = Group::new(group_id(g), format!("Group {g}"), T0);
        for e in 0..per_group {
            let n = g * per_group + e;
            let mut entry = Entry::new(entry_id(n), T0 - 86_400 + i64::from(n));
            entry.strings = vec![
                StringField::new("Title", format!("Entry {n}"), false),
                StringField::new("UserName", format!("user{n}"), false),
                StringField::new("Password", format!("pw-{n}-✓"), true),
                StringField::new("URL", format!("https://site{n}.example"), false),
                StringField::new(
                    "Notes",
                    if n.is_multiple_of(10) { format!("notes {n}") } else { String::new() },
                    false,
                ),
            ];
            if n.is_multiple_of(7) {
                entry.tags = vec!["seven".into()];
            }
            if n.is_multiple_of(10) {
                let mut old = entry.clone();
                old.strings[2] = StringField::new("Password", format!("old-{n}"), true);
                old.times.last_modification -= 60;
                entry.history.push(old);
            }
            if n.is_multiple_of(100) {
                entry.binaries.push(BinaryRef { name: format!("file{n}.txt"), index: attachment });
            }
            group.entries.push(entry);
        }
        db.root.groups.push(group);
    }
    (db, key)
}

/// The 5,000-entry vault (50 groups of 100).
pub fn vault_5k() -> (Database, CompositeKey) {
    vault(50, 100)
}

/// Edits an entry as a client does: the old version into history, a new password, the time.
fn edit(db: &mut Database, n: u32, tag: &str, now: Timestamp) {
    let e = find_entry_mut(&mut db.root, entry_id(n)).expect("entry");
    let mut old = e.clone();
    old.history.clear();
    e.history.push(old);
    set_field(e, "Password", &format!("{tag}-{n}"), true);
    e.times.last_modification = now;
}

fn add(db: &mut Database, g: u32, id: u128, title: &str, now: Timestamp) {
    let mut e = Entry::new(Uuid::from_u128(id), now);
    e.strings = vec![StringField::new("Title", title, false), StringField::new("Password", "new", true)];
    find_group_mut(&mut db.root, group_id(g)).expect("group").entries.push(e);
}

/// The three copies of a sync merge, from a vault of `total` entries (`total / 100` groups of 100,
/// so at least 100): `base` as last synced; `local` with 1% of the entries edited and 10 added;
/// `remote` (another device) with another 1% edited, 10% of the local edits edited again (conflicts
/// on one field), 5 deleted (to the Recycle Bin), 10 added and a group renamed.
pub fn three_way(total: u32) -> (Database, Database, Database, CompositeKey) {
    let groups = (total / 100).max(1);
    let (base, key) = vault(groups, 100);
    let total = groups * 100;
    let mut local = base.clone();
    let mut remote = base.clone();
    for n in (1..total).step_by(100) {
        edit(&mut local, n, "local", T_LOCAL);
    }
    for i in 0..10 {
        add(&mut local, i % groups, 0x6100_0000 + u128::from(i), &format!("Local new {i}"), T_LOCAL);
    }
    for n in (2..total).step_by(100) {
        edit(&mut remote, n, "remote", T_REMOTE);
    }
    for n in (1..total).step_by(1000) {
        edit(&mut remote, n, "remote", T_REMOTE);
    }
    for n in (3..total).step_by((total / 5) as usize) {
        delete_entry(&mut remote, entry_id(n), T_REMOTE).expect("delete");
    }
    for i in 0..10 {
        add(&mut remote, i % groups, 0x6200_0000 + u128::from(i), &format!("Remote new {i}"), T_REMOTE);
    }
    let g = find_group_mut(&mut remote.root, group_id(0)).expect("group");
    g.name = "Renamed".into();
    g.times.last_modification = T_REMOTE;
    (base, local, remote, key)
}

/// Counts the entries in `db` (not history).
pub fn count_entries(db: &Database) -> usize {
    fn walk(g: &Group) -> usize {
        g.entries.len() + g.groups.iter().map(walk).sum::<usize>()
    }
    walk(&db.root)
}
