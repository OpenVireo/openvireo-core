//! The attachment pool: entries refer to [`Database::binaries`] by index ([`BinaryRef::index`]), so
//! anything that moves an entry (or a history item) from one database to another has to re-intern
//! its attachments, and a merged database gets its pool rebuilt so it holds exactly what its entries
//! use.

use ov_kdbx::model::{Binary, BinaryRef, CustomIcon, Database, Entry, Uuid};
use zeroize::Zeroizing;

/// The content and protection flag `r` points at in `db`. A dangling reference reads as an empty,
/// unprotected attachment (as kdbxweb reads a missing binary).
pub(crate) fn resolve<'a>(db: &'a Database, r: &BinaryRef) -> (&'a [u8], bool) {
    match db.binaries.get(r.index as usize) {
        Some(b) => (b.data.as_slice(), b.protected),
        None => (&[], false),
    }
}

/// The index of an item with this content and flag in `db`'s pool, adding one when there is none.
pub(crate) fn intern(db: &mut Database, data: &[u8], protected: bool) -> u32 {
    if let Some(i) = db.binaries.iter().position(|b| b.protected == protected && b.data.as_slice() == data) {
        return i as u32;
    }
    db.binaries.push(Binary { data: Zeroizing::new(data.to_vec()), protected });
    (db.binaries.len() - 1) as u32
}

/// Rewrites the references of `entry` and its history, which point into `from`, to point into
/// `into` (adding the attachments there when missing), and brings the custom icons they use.
pub(crate) fn rehome(entry: &mut Entry, from: &Database, into: &mut Database) {
    rehome_one(entry, from, into);
    for h in &mut entry.history {
        rehome_one(h, from, into);
    }
}

fn rehome_one(entry: &mut Entry, from: &Database, into: &mut Database) {
    for r in &mut entry.binaries {
        let (data, protected) = resolve(from, r);
        r.index = intern(into, data, protected);
    }
    bring_icon(entry.custom_icon, from, into);
}

/// Adds custom icon `id` from `from` to `into` when `into` lacks it.
pub(crate) fn bring_icon(id: Option<Uuid>, from: &Database, into: &mut Database) {
    let Some(id) = id else { return };
    if id.is_nil() || into.meta.custom_icons.iter().any(|i| i.uuid == id) {
        return;
    }
    if let Some(icon) = from.meta.custom_icons.iter().find(|i| i.uuid == id) {
        into.meta.custom_icons.push(icon.clone());
    }
}

/// Adds `icon` to `into` when it has no icon with that UUID.
pub(crate) fn add_icon(into: &mut Database, icon: &CustomIcon) {
    if !into.meta.custom_icons.iter().any(|i| i.uuid == icon.uuid) {
        into.meta.custom_icons.push(icon.clone());
    }
}

/// Rebuilds `db`'s attachment pool from what its entries (and their history items) refer to, in tree
/// order: one item per distinct content and protection flag, nothing unreferenced. Every
/// [`BinaryRef::index`] is renumbered to match. Running it again changes nothing.
pub fn compact_binaries(db: &mut Database) {
    let old = std::mem::take(&mut db.binaries);
    let mut pool: Vec<Binary> = Vec::new();
    let mut visit = |e: &mut Entry| {
        for r in &mut e.binaries {
            let (data, protected) = match old.get(r.index as usize) {
                Some(b) => (b.data.as_slice(), b.protected),
                None => (&[][..], false),
            };
            r.index = match pool.iter().position(|b| b.protected == protected && b.data.as_slice() == data) {
                Some(i) => i as u32,
                None => {
                    pool.push(Binary { data: Zeroizing::new(data.to_vec()), protected });
                    (pool.len() - 1) as u32
                }
            };
        }
    };
    crate::tree::for_each_entry_mut(&mut db.root, &mut |e| {
        visit(e);
        for h in &mut e.history {
            visit(h);
        }
    });
    db.binaries = pool;
}
