//! Importing a `.kdbx` into an open database (the SDK's `merge/import.ts`): a UUID merge, or copies
//! with fresh UUIDs under a chosen group. The source is never changed. Either way the source's
//! Recycle Bin and its database custom data (sync remotes, browser keys…) stay behind.

use std::collections::BTreeMap;

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::model::{Database, Entry, Group, StringField, Timestamp, Uuid};
use zeroize::Zeroizing;

use crate::tree::{self, MergeIntoOptions, MergeMode};
use crate::{pool, ChangeSubject, ChangeType, MergeChange};

/// What an import did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// Entries new to the target.
    pub added: u32,
    /// Entries the target had that the import changed (newer version, history or location).
    pub updated: u32,
    /// Entries the target already had as they are.
    pub unchanged: u32,
    /// Groups new to the target.
    pub groups_added: u32,
    /// Every change, in order.
    pub changes: Vec<MergeChange>,
}

fn recycle_bin_of(db: &Database) -> Option<Uuid> {
    db.meta.recycle_bin_uuid.filter(|id| !id.is_nil())
}

/// How many of the source's entries are outside its Recycle Bin.
fn importable_entries(source: &Database) -> usize {
    let bin = recycle_bin_of(source);
    fn walk(g: &Group, bin: Option<Uuid>) -> usize {
        if Some(g.uuid) == bin {
            return 0;
        }
        g.entries.len() + g.groups.iter().map(|c| walk(c, bin)).sum::<usize>()
    }
    walk(&source.root, bin)
}

/// What importing `source` would bring in: `(entries, groups)` outside its Recycle Bin, the root
/// group not counted (Swift `Importer.importableEntries(_:).count`, `importableGroupCount`).
pub fn import_preview(source: &Database) -> (usize, usize) {
    let bin = recycle_bin_of(source);
    fn groups(g: &Group, bin: Option<Uuid>) -> usize {
        g.groups.iter().filter(|c| Some(c.uuid) != bin).map(|c| 1 + groups(c, bin)).sum()
    }
    (importable_entries(source), groups(&source.root, bin))
}

/// Merges `source` into `target` by UUID, keeping the newer version of each entry (the older one goes
/// into its history) and deleting nothing, so importing the same file twice changes nothing. The
/// target's root group (an account vault's name) and database custom data are left as they are.
/// The target's attachment pool is rebuilt.
pub fn import_into(source: &Database, target: &mut Database) -> ImportSummary {
    let opts =
        MergeIntoOptions { skip_database_custom_data: true, skip_groups: recycle_bin_of(source).into_iter().collect() };
    let changes = tree::merge_into_raw(source, target, MergeMode::KeepNewer, &opts);
    pool::compact_binaries(target);
    let is_entry = |c: &MergeChange| c.subject == ChangeSubject::Entry;
    let mut added: Vec<Uuid> = Vec::new();
    for c in changes.iter().filter(|c| c.change == ChangeType::Added && is_entry(c)) {
        if let Some(id) = c.uuid.filter(|id| !added.contains(id)) {
            added.push(id);
        }
    }
    let mut updated: Vec<Uuid> = Vec::new();
    for c in changes.iter().filter(|c| matches!(c.change, ChangeType::Modified | ChangeType::Moved) && is_entry(c)) {
        if let Some(id) = c.uuid.filter(|id| !added.contains(id) && !updated.contains(id)) {
            updated.push(id);
        }
    }
    let total = importable_entries(source);
    ImportSummary {
        added: added.len() as u32,
        updated: updated.len() as u32,
        unchanged: total.saturating_sub(added.len() + updated.len()) as u32,
        groups_added: changes
            .iter()
            .filter(|c| c.change == ChangeType::Added && c.subject == ChangeSubject::Group)
            .count() as u32,
        changes,
    }
}

/// 32 uppercase hex digits, as KeePass field references write a UUID.
fn ref_hex(id: Uuid) -> String {
    hex_upper(id.as_bytes())
}

fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    bytes.iter().flat_map(|b| [DIGITS[(b >> 4) as usize] as char, DIGITS[(b & 15) as usize] as char]).collect()
}

/// Rewrites `{REF:<T|U|P|A|N>@I:<32 hex>}` references whose UUID is in `ids`.
fn remap_refs(text: &str, ids: &BTreeMap<String, String>) -> Option<String> {
    if !text.contains("{REF:") {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(i) = rest.find("{REF:") {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        // {REF:X@I: + 32 hex + }
        let b = tail.as_bytes();
        let ok = b.len() >= 42
            && matches!(b[5], b'T' | b'U' | b'P' | b'A' | b'N')
            && &b[6..9] == b"@I:"
            && b[9..41].iter().all(u8::is_ascii_hexdigit)
            && b[41] == b'}';
        if ok {
            let hex = tail[9..41].to_ascii_uppercase();
            match ids.get(&hex) {
                Some(to) => {
                    out.push_str(&tail[..9]);
                    out.push_str(to);
                    out.push('}');
                    changed = true;
                }
                None => out.push_str(&tail[..42]),
            }
            rest = &tail[42..];
        } else {
            out.push_str("{REF:");
            rest = &tail[5..];
        }
    }
    out.push_str(rest);
    changed.then_some(out)
}

fn remap_entry(e: &mut Entry, ids: &BTreeMap<String, String>) {
    for s in &mut e.strings {
        if let Some(next) = remap_refs(&s.value, ids) {
            *s = StringField { key: std::mem::take(&mut s.key), value: Zeroizing::new(next), protected: s.protected };
        }
    }
}

/// Copies `source`'s tree into `target` as one new group under group `parent`, named after the
/// source's root group. Every entry (with its history) and group gets a fresh UUID from `new_uuid`,
/// and field references between the copied entries (`{REF:…@I:<uuid>}`) follow them. Nothing is
/// matched against the target, so importing twice gives two copies. The new top group's location
/// time is `now`. The target's attachment pool is rebuilt.
///
/// `not_found` when `parent` isn't a group of `target`.
pub fn import_as_copies(
    source: &Database,
    target: &mut Database,
    parent: Uuid,
    now: Timestamp,
    new_uuid: &mut dyn FnMut() -> Uuid,
) -> Result<ImportSummary, OvError> {
    if tree::find_group(&target.root, parent).is_none() {
        return Err(OvError::new(OvErrorCode::NotFound, "the group to import into no longer exists"));
    }
    let bin = recycle_bin_of(source);
    let mut cx = Copier {
        source,
        target,
        new_uuid,
        bin,
        changes: Vec::new(),
        ids: BTreeMap::new(),
        copies: Vec::new(),
        groups_added: 0,
    };
    let mut top = cx.copy_group(&source.root);
    top.times.location_changed = now;
    // References by UUID between the copied entries now point at the copies
    let ids = std::mem::take(&mut cx.ids);
    remap_group(&mut top, &ids);
    let (changes, added, groups_added) = (cx.changes, cx.copies.len() as u32, cx.groups_added);
    let _ = tree::push_group(&mut target.root, parent, top);
    pool::compact_binaries(target);
    Ok(ImportSummary { added, updated: 0, unchanged: 0, groups_added, changes })
}

fn remap_group(g: &mut Group, ids: &BTreeMap<String, String>) {
    for e in &mut g.entries {
        remap_entry(e, ids);
        for h in &mut e.history {
            remap_entry(h, ids);
        }
    }
    for c in &mut g.groups {
        remap_group(c, ids);
    }
}

struct Copier<'a> {
    source: &'a Database,
    target: &'a mut Database,
    new_uuid: &'a mut dyn FnMut() -> Uuid,
    bin: Option<Uuid>,
    changes: Vec<MergeChange>,
    ids: BTreeMap<String, String>,
    copies: Vec<Uuid>,
    groups_added: u32,
}

impl Copier<'_> {
    fn copy_group(&mut self, src: &Group) -> Group {
        let mut made = tree::shallow_group(src);
        made.uuid = (self.new_uuid)();
        pool::bring_icon(src.custom_icon, self.source, self.target);
        self.groups_added += 1;
        self.changes.push(tree::group_record(
            ChangeType::Added,
            &made,
            format!("Number of entries in group: {}", src.entries.len()),
        ));
        for entry in &src.entries {
            let mut out = tree::copy_entry(entry, Some(self.source), self.target, true);
            out.uuid = (self.new_uuid)();
            for h in &mut out.history {
                h.uuid = out.uuid;
            }
            self.ids.insert(ref_hex(entry.uuid), ref_hex(out.uuid));
            self.copies.push(out.uuid);
            self.changes.push(tree::entry_record(ChangeType::Added, &out, Some(&made.name), ""));
            made.entries.push(out);
        }
        for child in &src.groups {
            if Some(child.uuid) != self.bin {
                let c = self.copy_group(child);
                made.groups.push(c);
            }
        }
        made
    }
}

/// Every group of `db` an import can go into (not the Recycle Bin or anything in it), root first,
/// with its path (`"Root / Sub / Leaf"`; the root's path is its name).
pub fn import_targets(db: &Database) -> Vec<(Uuid, String)> {
    let bin = recycle_bin_of(db);
    let mut out = Vec::new();
    fn walk_all(g: &Group, path: &str, bin: Option<Uuid>, out: &mut Vec<(Uuid, String)>) {
        if Some(g.uuid) == bin {
            return;
        }
        out.push((g.uuid, path.to_owned()));
        for c in &g.groups {
            let p = if path.is_empty() { c.name.clone() } else { format!("{path} / {}", c.name) };
            walk_all(c, &p, bin, out);
        }
    }
    walk_all(&db.root, &db.root.name, bin, &mut out);
    out
}
