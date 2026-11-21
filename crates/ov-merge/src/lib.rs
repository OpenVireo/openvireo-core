//! Three-way KDBX merge on the `ov_kdbx::model` types, with the same rules as the SDK's `merge/`
//! (TS `merger.ts`, `tree.ts`, `fields.ts`, `import.ts`; specified in the SDK's
//! `docs/merge-behaviour.md`) and the desktop `SyncEngine::mergeDatabases()`, checked against the
//! recorded `vectors/merge-fixtures/`.
//!
//! - [`merge`] / [`merge_in_place`]: the sync merge (field-by-field combine against the base,
//!   structure merge both ways, each entry put where it was moved last, deletions decided against
//!   the base, Recycle Bin, sync generation).
//! - [`find_conflicts`], [`needs_common_base`], [`snapshot_of`], [`conflicting_fields`]: the checks
//!   the sync runs around it.
//! - [`import_into`] / [`import_as_copies`] / [`import_targets`]: importing a `.kdbx`.
//! - [`merge_into`]: the one-way structure merge (desktop `Merger`).
//!
//! Attachments are a pool referenced by index ([`ov_kdbx::model::BinaryRef`]): entries brought from
//! another database have their attachments re-interned, and every operation that changes a database
//! ends by rebuilding its pool ([`compact_binaries`]).
//!
//! The crate does no I/O and draws no randomness: times come in as `now` (Unix seconds), fresh UUIDs
//! from a caller-supplied function.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod fields;
mod import;
mod index;
mod merger;
mod pool;
mod time;
mod tree;

use ov_kdbx::model::{Database, Timestamp, Uuid};

pub use import::{import_as_copies, import_into, import_preview, import_targets, ImportSummary};
pub use merger::{
    conflicting_fields, copies_differ, edited_on_both, find_conflicts, has_pending_deletions, merge_in_place,
    needs_common_base, snapshot_of, sync_generation, ConflictKind, Snapshot, SyncConflict, SYNC_GENERATION_KEY,
};
pub use pool::compact_binaries;
pub use tree::{MergeIntoOptions, MergeMode};

/// The kind of a [`MergeChange`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChangeType {
    /// Added.
    Added,
    /// Modified.
    Modified,
    /// Moved to another group.
    Moved,
    /// Deleted.
    Deleted,
    /// Database metadata changed.
    Metadata,
}

/// What a [`MergeChange`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChangeSubject {
    /// An entry (`uuid`, `title` and its parent group's name in `group`).
    Entry,
    /// A group (`uuid`, and its own name in `group`).
    Group,
    /// The database (no `uuid`, `title` or `group`).
    Database,
}

/// One change the merge applied (the SDK's `MergeChange` record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeChange {
    /// What changed.
    pub change: ChangeType,
    /// What it is about.
    pub subject: ChangeSubject,
    /// The entry or group.
    pub uuid: Option<Uuid>,
    /// The entry's title.
    pub title: Option<String>,
    /// The entry's group name, or the group's own name.
    pub group: Option<String>,
    /// A description (the desktop `Merger`'s wording).
    pub details: String,
}

/// An entry both sides edited, with the fields both changed differently (the newer side's value was
/// kept; the other is in the history).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryConflict {
    /// The entry.
    pub uuid: Uuid,
    /// Its title after the merge.
    pub title: String,
    /// Display names (`Title`, `Username`, `Password`, `URL`, `Notes`, a custom key,
    /// `attachment <name>`, `Tags`, `Expiry`, `Icon`, `Colors`).
    pub fields: Vec<String>,
}

/// What [`merge`] did. `added`, `updated` and `deleted` are entry UUIDs, seen from the local side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Entries edited on both sides with fields changed differently, in local tree order.
    pub conflicts: Vec<EntryConflict>,
    /// Entries the remote side brought in.
    pub added: Vec<Uuid>,
    /// Entries combined field by field, or replaced, re-historied or moved from the remote side.
    pub updated: Vec<Uuid>,
    /// Entries deleted from both sides (a deletion on one side the other hadn't changed).
    pub deleted: Vec<Uuid>,
    /// Every change, in order: combines, structure merge into remote, into local, entries put where
    /// they were moved last, deletions and Recycle Bin.
    pub changes: Vec<MergeChange>,
    /// The local copy changed.
    pub local_changed: bool,
    /// The remote copy changed (it needs uploading).
    pub remote_changed: bool,
}

/// The sync merge: `local` and `remote` merged against `base` (the copy both last synced from;
/// `None` when there is none), at time `now` (Unix seconds). Returns the merged database (the local
/// copy after [`merge_in_place`]; the remote copy ends up with the same entries and groups) and the
/// report.
pub fn merge(base: Option<&Database>, local: &Database, remote: &Database, now: Timestamp) -> (Database, MergeReport) {
    let mut l = local.clone();
    let mut r = remote.clone();
    let report = merge_in_place(&mut l, &mut r, base, now);
    (l, report)
}

/// The one-way structure merge (desktop `Merger`, SDK `mergeInto`): brings `source`'s entries,
/// groups, history, metadata and (in [`MergeMode::Synchronize`]) deletions into `target`. Returns what
/// changed in `target`. The target's attachment pool is rebuilt.
pub fn merge_into(
    source: &Database,
    target: &mut Database,
    mode: MergeMode,
    opts: &MergeIntoOptions,
) -> Vec<MergeChange> {
    let changes = tree::merge_into_raw(source, target, mode, opts);
    compact_binaries(target);
    changes
}
