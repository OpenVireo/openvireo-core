//! UUID lookups over a group tree without walking it each time. [`tree::find_entry`] walks the whole
//! tree, and the merge looks every entry up on each side, so a 5k-entry merge was quadratic (W4-F
//! profile: about 80% of the time). A [`Finder`] indexes the tree once and keeps the index right
//! through its own structural edits (append, take, move); anything else that adds, removes or moves
//! entries or groups must go through it, or build a new one.
//!
//! The index holds positions, not references, so the entries themselves can be edited in place
//! while it is alive. A tree with a repeated entry or group UUID isn't indexed: the finder falls
//! back to the tree walks, which return the first match in tree order. Both give the same answers.

use std::collections::HashMap;

use ov_kdbx::model::{Entry, Group, Uuid};

use crate::tree;

/// Every group's path (child indices from the root) and every entry's group and index in it.
struct TreeIndex {
    groups: HashMap<Uuid, Vec<usize>>,
    entries: HashMap<Uuid, (Uuid, usize)>,
}

impl TreeIndex {
    /// `None` when an entry or group UUID repeats.
    fn of(root: &Group) -> Option<TreeIndex> {
        let mut idx = TreeIndex { groups: HashMap::new(), entries: HashMap::new() };
        idx.add(root, Vec::new()).then_some(idx)
    }

    /// Indexes `g` (at `path`) and everything under it. `false` on a repeated UUID.
    fn add(&mut self, g: &Group, path: Vec<usize>) -> bool {
        for (i, e) in g.entries.iter().enumerate() {
            if self.entries.insert(e.uuid, (g.uuid, i)).is_some() {
                return false;
            }
        }
        for (i, c) in g.groups.iter().enumerate() {
            let mut p = path.clone();
            p.push(i);
            if !self.add(c, p) {
                return false;
            }
        }
        self.groups.insert(g.uuid, path).is_none()
    }

    fn resolve<'a>(root: &'a Group, path: &[usize]) -> &'a Group {
        path.iter().fold(root, |g, &i| &g.groups[i])
    }

    fn resolve_mut<'a>(root: &'a mut Group, path: &[usize]) -> &'a mut Group {
        path.iter().fold(root, |g, &i| &mut g.groups[i])
    }

    fn group<'a>(&self, root: &'a Group, id: Uuid) -> Option<&'a Group> {
        self.groups.get(&id).map(|p| Self::resolve(root, p))
    }

    fn entry<'a>(&self, root: &'a Group, id: Uuid) -> Option<(&'a Entry, &'a Group)> {
        let (g, i) = self.entries.get(&id)?;
        let group = self.group(root, *g)?;
        let e = &group.entries[*i];
        debug_assert_eq!(e.uuid, id, "stale merge index");
        Some((e, group))
    }
}

/// Entry and group lookups on one tree: indexed when its UUIDs are unique, else the tree walks.
pub(crate) struct Finder {
    idx: Option<TreeIndex>,
}

impl Finder {
    pub(crate) fn new(root: &Group) -> Finder {
        Finder { idx: TreeIndex::of(root) }
    }

    /// Indexes the tree again, after a structural edit made without the finder.
    pub(crate) fn rebuild(&mut self, root: &Group) {
        self.idx = TreeIndex::of(root);
    }

    /// [`tree::find_entry`].
    pub(crate) fn entry<'a>(&self, root: &'a Group, id: Uuid) -> Option<(&'a Entry, &'a Group)> {
        match &self.idx {
            Some(i) => i.entry(root, id),
            None => tree::find_entry(root, id),
        }
    }

    /// [`tree::find_entry_mut`].
    pub(crate) fn entry_mut<'a>(&self, root: &'a mut Group, id: Uuid) -> Option<&'a mut Entry> {
        let Some(i) = &self.idx else { return tree::find_entry_mut(root, id) };
        let (g, pos) = *i.entries.get(&id)?;
        let path = i.groups.get(&g)?;
        let e = &mut TreeIndex::resolve_mut(root, path).entries[pos];
        debug_assert_eq!(e.uuid, id, "stale merge index");
        Some(e)
    }

    /// [`tree::find_group`].
    pub(crate) fn group<'a>(&self, root: &'a Group, id: Uuid) -> Option<&'a Group> {
        match &self.idx {
            Some(i) => i.group(root, id),
            None => tree::find_group(root, id),
        }
    }

    /// [`tree::find_group_mut`].
    pub(crate) fn group_mut<'a>(&self, root: &'a mut Group, id: Uuid) -> Option<&'a mut Group> {
        match &self.idx {
            Some(i) => i.groups.get(&id).map(|p| TreeIndex::resolve_mut(root, p)),
            None => tree::find_group_mut(root, id),
        }
    }

    /// [`tree::group_parent`].
    pub(crate) fn group_parent<'a>(&self, root: &'a Group, id: Uuid) -> Option<&'a Group> {
        match &self.idx {
            Some(i) => {
                let path = i.groups.get(&id)?;
                let (_, up) = path.split_last()?;
                Some(TreeIndex::resolve(root, up))
            }
            None => tree::group_parent(root, id),
        }
    }

    /// [`tree::push_entry`].
    pub(crate) fn push_entry(&mut self, root: &mut Group, group: Uuid, entry: Entry) -> bool {
        let Some(i) = &mut self.idx else { return tree::push_entry(root, group, entry) };
        let Some(path) = i.groups.get(&group) else { return false };
        let g = TreeIndex::resolve_mut(root, path);
        let id = entry.uuid;
        g.entries.push(entry);
        if i.entries.insert(id, (group, g.entries.len() - 1)).is_some() {
            // Now repeated: the tree walks keep the first in tree order
            self.idx = None;
        }
        true
    }

    /// [`tree::take_entry`].
    pub(crate) fn take_entry(&mut self, root: &mut Group, id: Uuid) -> Option<Entry> {
        let Some(i) = &mut self.idx else { return tree::take_entry(root, id) };
        let (group, pos) = i.entries.remove(&id)?;
        let g = TreeIndex::resolve_mut(root, i.groups.get(&group)?);
        let e = g.entries.remove(pos);
        debug_assert_eq!(e.uuid, id, "stale merge index");
        for (k, later) in g.entries.iter().enumerate().skip(pos) {
            i.entries.insert(later.uuid, (group, k));
        }
        Some(e)
    }

    /// Makes entry `id` the last entry of group `to` (TS `appendEntry`). Nothing else changes.
    pub(crate) fn append_entry(&mut self, root: &mut Group, id: Uuid, to: Uuid) {
        if self.group(root, to).is_none() {
            return;
        }
        if let Some(e) = self.take_entry(root, id) {
            let _ = self.push_entry(root, to, e);
        }
    }

    /// [`tree::push_group`].
    pub(crate) fn push_group(&mut self, root: &mut Group, group: Uuid, child: Group) -> bool {
        let Some(i) = &mut self.idx else { return tree::push_group(root, group, child) };
        let Some(path) = i.groups.get(&group).cloned() else { return false };
        let g = TreeIndex::resolve_mut(root, &path);
        g.groups.push(child);
        let mut child_path = path;
        child_path.push(g.groups.len() - 1);
        let added = &g.groups[g.groups.len() - 1];
        if !i.add(added, child_path) {
            self.idx = None;
        }
        true
    }

    /// [`tree::append_group`]; a move re-indexes the tree.
    pub(crate) fn append_group(&mut self, root: &mut Group, id: Uuid, to: Uuid) -> bool {
        let moved = tree::append_group(root, id, to);
        if moved && self.idx.is_some() {
            self.rebuild(root);
        }
        moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u128) -> Entry {
        Entry::new(Uuid::from_u128(n), 0)
    }

    fn group(n: u128, entries: Vec<Entry>, groups: Vec<Group>) -> Group {
        let mut g = Group::new(Uuid::from_u128(n), format!("g{n}"), 0);
        g.entries = entries;
        g.groups = groups;
        g
    }

    /// root(e1, e2; a(e3, e4; c(e5)); b())
    fn tree() -> Group {
        let c = group(30, vec![entry(5)], vec![]);
        let a = group(10, vec![entry(3), entry(4)], vec![c]);
        let b = group(20, vec![], vec![]);
        group(1, vec![entry(1), entry(2)], vec![a, b])
    }

    fn same_as_walks(f: &Finder, root: &Group) {
        for n in 0..40u128 {
            let id = Uuid::from_u128(n);
            let got = f.entry(root, id).map(|(e, g)| (e.uuid, g.uuid));
            let want = tree::find_entry(root, id).map(|(e, g)| (e.uuid, g.uuid));
            assert_eq!(got, want, "entry {n}");
            assert_eq!(f.group(root, id).map(|g| g.uuid), tree::find_group(root, id).map(|g| g.uuid), "group {n}");
            assert_eq!(
                f.group_parent(root, id).map(|g| g.uuid),
                tree::group_parent(root, id).map(|g| g.uuid),
                "parent {n}"
            );
        }
    }

    #[test]
    fn answers_like_the_tree_walks_through_edits() {
        let mut root = tree();
        let mut f = Finder::new(&root);
        assert!(f.idx.is_some());
        same_as_walks(&f, &root);

        f.append_entry(&mut root, Uuid::from_u128(3), Uuid::from_u128(30));
        same_as_walks(&f, &root);
        f.append_entry(&mut root, Uuid::from_u128(1), Uuid::from_u128(1));
        same_as_walks(&f, &root);
        let e = f.take_entry(&mut root, Uuid::from_u128(4)).unwrap();
        same_as_walks(&f, &root);
        assert!(f.push_entry(&mut root, Uuid::from_u128(20), e));
        assert!(f.push_group(&mut root, Uuid::from_u128(20), group(40, vec![entry(6)], vec![])));
        same_as_walks(&f, &root);
        assert!(f.append_group(&mut root, Uuid::from_u128(30), Uuid::from_u128(40)));
        same_as_walks(&f, &root);
        f.entry_mut(&mut root, Uuid::from_u128(5)).unwrap().times.last_modification = 7;
        assert_eq!(tree::find_entry(&root, Uuid::from_u128(5)).unwrap().0.times.last_modification, 7);
        assert!(!f.push_entry(&mut root, Uuid::from_u128(99), entry(8)));
        same_as_walks(&f, &root);
        assert!(f.idx.is_some());
    }

    #[test]
    fn falls_back_to_the_walks_on_repeated_uuids() {
        let mut root = tree();
        root.groups[1].entries.push(entry(3));
        let f = Finder::new(&root);
        assert!(f.idx.is_none());
        same_as_walks(&f, &root);

        let mut root = tree();
        let mut f = Finder::new(&root);
        assert!(f.push_entry(&mut root, Uuid::from_u128(20), entry(5)));
        assert!(f.idx.is_none());
        same_as_walks(&f, &root);
    }
}
