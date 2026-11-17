//! Test helpers: the merge-fixture JSON → `ov_kdbx::model` adapter, the fixtures' projection, and a
//! canonical form of a whole database for equality checks.

#![allow(dead_code)]

use std::collections::BTreeMap;

use base64::Engine as _;
use ov_kdbx::model::{
    Argon2Type, Binary, BinaryRef, Cipher, Compression, Database, DeletedObject, Entry, Group, Header, KdbxVersion,
    Kdf, Meta, StringField, Timestamp, Uuid, STANDARD_FIELDS,
};
use ov_testkit::merge::{self as fx, ProjectedEntry, ProjectedGroup, Projection};
use ov_testkit::utc_seconds;
use zeroize::Zeroizing;

pub fn uuid(s: &str) -> Uuid {
    Uuid::parse_str(s).unwrap_or_else(|e| panic!("bad uuid {s:?}: {e}"))
}

pub fn iso(t: Timestamp) -> String {
    // inverse of utc_seconds (civil_from_days)
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
}

/// An empty database shaped like the fixtures' (root group, no Recycle Bin).
pub fn empty_db(root: Uuid, t0: Timestamp) -> Database {
    let meta = Meta { recycle_bin_enabled: false, recycle_bin_uuid: None, ..Meta::default() };
    Database {
        header: Header {
            version: KdbxVersion { major: 4, minor: 0 },
            cipher: Cipher::ChaCha20,
            compression: Compression::Gzip,
            kdf: Kdf::Argon2 {
                kind: Argon2Type::Id,
                salt: vec![0; 32],
                memory: 64 << 20,
                iterations: 2,
                parallelism: 2,
                version: 0x13,
                secret: None,
                associated_data: None,
            },
            public_custom_data: None,
            unknown_fields: Vec::new(),
        },
        meta,
        root: Group::new(root, "Root", t0),
        deleted_objects: Vec::new(),
        binaries: Vec::new(),
        unknown_file: Vec::new(),
        unknown_root: Vec::new(),
    }
}

pub fn set_field(e: &mut Entry, key: &str, value: &str, protected: bool) {
    let f = StringField::new(key, value, protected);
    match e.strings.iter_mut().find(|s| s.key == key) {
        Some(s) => *s = f,
        None => e.strings.push(f),
    }
}

pub fn intern(db: &mut Database, data: &[u8]) -> u32 {
    if let Some(i) = db.binaries.iter().position(|b| !b.protected && b.data.as_slice() == data) {
        return i as u32;
    }
    db.binaries.push(Binary { data: Zeroizing::new(data.to_vec()), protected: false });
    (db.binaries.len() - 1) as u32
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_else(|e| panic!("bad base64 {s:?}: {e}"))
}

fn group_mut(g: &mut Group, id: Uuid) -> Option<&mut Group> {
    if g.uuid == id {
        return Some(g);
    }
    g.groups.iter_mut().find_map(|c| group_mut(c, id))
}

fn time_or_default(t: Option<&String>) -> Timestamp {
    utc_seconds(t.map_or(fx::FIXED_TIME, String::as_str))
}

/// The fixture database as a model (as the SDK's `merge-fixtures.test.ts` builds it with kdbxweb).
pub fn build(spec: &fx::Database) -> Database {
    let t0 = utc_seconds(fx::FIXED_TIME);
    let root = uuid(fx::ROOT_GROUP_UUID);
    let mut db = empty_db(root, t0);
    // Groups come in any order: place each once its parent is there
    let mut waiting: Vec<&fx::Group> = spec.groups.iter().flatten().collect();
    while !waiting.is_empty() {
        let before = waiting.len();
        waiting.retain(|s| {
            let parent = s.parent.as_deref().map_or(root, uuid);
            let Some(p) = group_mut(&mut db.root, parent) else { return true };
            let mut g = Group::new(uuid(&s.uuid), s.name.clone(), t0);
            g.times.last_modification = time_or_default(s.modified.as_ref());
            g.times.location_changed = time_or_default(s.location_changed.as_ref());
            p.groups.push(g);
            false
        });
        assert!(waiting.len() < before, "groups with missing parents: {waiting:?}");
    }
    for s in &spec.entries {
        let modified = utc_seconds(&s.modified);
        let mut e = Entry::new(uuid(&s.uuid), t0);
        let protected = s.protected.clone().unwrap_or_default();
        for (k, v) in &s.attributes {
            set_field(&mut e, k, v, k == "Password" || protected.contains(k));
        }
        e.tags = s.tags.as_deref().map(split_tags).unwrap_or_default();
        for (name, data) in s.attachments.iter().flatten() {
            let index = intern(&mut db, &b64(data));
            e.binaries.push(BinaryRef { name: name.clone(), index });
        }
        e.times.last_modification = modified;
        e.times.last_access = modified;
        e.times.location_changed = time_or_default(s.location_changed.as_ref());
        let group = s.group.as_deref().map_or(root, uuid);
        group_mut(&mut db.root, group).unwrap_or_else(|| panic!("no group {group}")).entries.push(e);
    }
    for d in &spec.deleted {
        db.deleted_objects.push(DeletedObject { uuid: uuid(&d.uuid), deletion_time: utc_seconds(&d.time) });
    }
    db
}

pub fn split_tags(s: &str) -> Vec<String> {
    s.split([',', ';']).filter(|t| !t.is_empty()).map(str::to_owned).collect()
}

/// The fixtures' projection of every entry and group (tags and protected names sorted, so they
/// compare with [`normalize`]).
pub fn project(db: &Database) -> Projection {
    let t0 = utc_seconds(fx::FIXED_TIME);
    let not_default = |t: Timestamp| (t != t0).then(|| iso(t));
    let mut placed: Vec<(&Entry, &Group)> = Vec::new();
    let mut groups: Vec<ProjectedGroup> = Vec::new();
    fn walk<'a>(g: &'a Group, placed: &mut Vec<(&'a Entry, &'a Group)>, groups: &mut Vec<(&'a Group, &'a Group)>) {
        placed.extend(g.entries.iter().map(|e| (e, g)));
        for c in &g.groups {
            groups.push((c, g));
            walk(c, placed, groups);
        }
    }
    let mut raw_groups = Vec::new();
    walk(&db.root, &mut placed, &mut raw_groups);
    for (g, parent) in raw_groups {
        groups.push(ProjectedGroup {
            uuid: g.uuid.hyphenated().to_string(),
            name: g.name.clone(),
            parent: parent.uuid.hyphenated().to_string(),
            modified: not_default(g.times.last_modification),
            location_changed: not_default(g.times.location_changed),
        });
    }
    groups.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    let mut entries: Vec<ProjectedEntry> = placed
        .into_iter()
        .map(|(e, g)| {
            let mut attributes = BTreeMap::new();
            let mut protected = Vec::new();
            for s in &e.strings {
                let standard = STANDARD_FIELDS.contains(&s.key.as_str());
                if standard && s.value.is_empty() {
                    continue;
                }
                attributes.insert(s.key.clone(), s.value.to_string());
                if !standard && s.protected {
                    protected.push(s.key.clone());
                }
            }
            protected.sort();
            let attachments: BTreeMap<String, String> = e
                .binaries
                .iter()
                .map(|b| {
                    let data = db.binaries.get(b.index as usize).map(|x| x.data.to_vec()).unwrap_or_default();
                    (b.name.clone(), base64::engine::general_purpose::STANDARD.encode(data))
                })
                .collect();
            let mut tags = e.tags.clone();
            tags.sort();
            ProjectedEntry {
                uuid: e.uuid.hyphenated().to_string(),
                modified: iso(e.times.last_modification),
                attributes,
                protected: (!protected.is_empty()).then_some(protected),
                tags: (!tags.is_empty()).then(|| tags.join(";")),
                attachments: (!attachments.is_empty()).then_some(attachments),
                group: (g.uuid != db.root.uuid).then(|| g.uuid.hyphenated().to_string()),
                location_changed: not_default(e.times.location_changed),
                history_count: e.history.len() as u32,
            }
        })
        .collect();
    entries.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    let mut deleted: Vec<String> = db.deleted_objects.iter().map(|d| d.uuid.hyphenated().to_string()).collect();
    deleted.sort();
    Projection { entries, deleted, groups: (!groups.is_empty()).then_some(groups) }
}

/// The expected projection with tags and protected names sorted and attachments re-encoded.
pub fn normalize(p: &Projection) -> Projection {
    let mut p = p.clone();
    for e in &mut p.entries {
        if let Some(t) = &e.tags {
            let mut tags = split_tags(t);
            tags.sort();
            e.tags = Some(tags.join(";"));
        }
        if let Some(pr) = &mut e.protected {
            pr.sort();
        }
        if let Some(a) = &mut e.attachments {
            for v in a.values_mut() {
                *v = base64::engine::general_purpose::STANDARD.encode(b64(v));
            }
        }
    }
    p.entries.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    p.deleted.sort();
    if let Some(g) = &mut p.groups {
        g.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    }
    p
}
