//! Test helpers: the merge-fixture JSON → `ov_kdbx::model` adapter, the fixtures' projection, and a
//! canonical form of a whole database for equality checks.

#![allow(dead_code)]

use std::collections::BTreeMap;

use base64::Engine as _;
use ov_kdbx::model::{
    Argon2Type, Binary, BinaryRef, Cipher, Compression, Database, DeletedObject, Entry, Group, Header, KdbxVersion,
    Kdf, Meta, StringField, Timestamp, Uuid, STANDARD_FIELDS,
};
use ov_testkit::merge::{self as fx, ProjectedEntry, Projection};
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

/// The fixture database as a model (as the SDK's `merge-fixtures.test.ts` builds it with kdbxweb).
pub fn build(spec: &fx::Database) -> Database {
    let t0 = utc_seconds(fx::FIXED_TIME);
    let mut db = empty_db(uuid(fx::ROOT_GROUP_UUID), t0);
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
        db.root.entries.push(e);
    }
    for d in &spec.deleted {
        db.deleted_objects.push(DeletedObject { uuid: uuid(&d.uuid), deletion_time: utc_seconds(&d.time) });
    }
    db
}

pub fn split_tags(s: &str) -> Vec<String> {
    s.split([',', ';']).filter(|t| !t.is_empty()).map(str::to_owned).collect()
}

/// The fixtures' projection of the root group's entries (tags and protected names sorted, so they
/// compare with [`normalize`]).
pub fn project(db: &Database) -> Projection {
    let mut entries: Vec<ProjectedEntry> = db
        .root
        .entries
        .iter()
        .map(|e| {
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
                history_count: e.history.len() as u32,
            }
        })
        .collect();
    entries.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    let mut deleted: Vec<String> = db.deleted_objects.iter().map(|d| d.uuid.hyphenated().to_string()).collect();
    deleted.sort();
    Projection { entries, deleted }
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
    p
}
