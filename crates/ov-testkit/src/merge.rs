//! Typed `vectors/merge-fixtures/*.json`: three-way merge cases recorded from the desktop merge
//! (`SyncEngine::mergeDatabases()`). `vectors/merge-fixtures/README.md` defines the format and the rules a
//! port follows. This module only types the JSON; turning a [`Database`] into a KDBX model is ov-merge's job.
//!
//! Times are `YYYY-MM-DDTHH:MM:SSZ` strings; [`crate::utc_seconds`] converts them to Unix seconds.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The root group every fixture database shares.
pub const ROOT_GROUP_UUID: &str = "6e3a9f40-1c2b-4d5e-8f70-9a1b2c3d4e5f";
/// Root group times, and every entry's creation and location-changed time.
pub const FIXED_TIME: &str = "2026-01-01T00:00:00Z";

/// One merge case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeFixture {
    pub description: String,
    /// The clock during the merge.
    pub now: String,
    /// The copy both sides last synced from; `None` means no base.
    pub base: Option<Database>,
    pub local: Database,
    pub remote: Database,
    pub expected: Expected,
}

/// An input database: entries directly in the root group, plus deleted objects.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub entries: Vec<Entry>,
    pub deleted: Vec<DeletedObject>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub uuid: String,
    /// Last modification time (whole seconds, UTC); the last access time equals it.
    pub modified: String,
    /// Standard (`Title`, `UserName`, `Password`, `URL`, `Notes`) and custom fields.
    pub attributes: BTreeMap<String, String>,
    /// Protected custom attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// Attachment name → base64 (standard alphabet, padded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedObject {
    pub uuid: String,
    pub time: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    /// Entry UUID → display names of the fields both sides changed differently (before merging).
    pub conflicts: BTreeMap<String, Vec<String>>,
    pub result: Projection,
}

/// The merged database (local and remote end up equal).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    /// Sorted by UUID.
    pub entries: Vec<ProjectedEntry>,
    /// Sorted deleted-object UUIDs.
    pub deleted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedEntry {
    pub uuid: String,
    pub modified: String,
    /// Empty standard fields are left out.
    pub attributes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<BTreeMap<String, String>>,
    /// From KeePassXC's `Merger`; informative, a port may compare it loosely.
    pub history_count: u32,
}

/// Every fixture as `(file name, fixture)`, sorted by file name. Panics if there are none.
pub fn merge_fixtures() -> Vec<(String, MergeFixture)> {
    let dir = crate::vectors_dir().join("merge-fixtures");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("read_dir entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no merge fixtures in {}", dir.display());
    names.into_iter().map(|n| (n.clone(), crate::load_json(&format!("merge-fixtures/{n}")))).collect()
}
