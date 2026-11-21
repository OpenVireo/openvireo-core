//! [`model`](crate::model) → KDBX 4 XML, in KeePassXC's element order (`KdbxXmlWriter.cpp`).
//!
//! Elements the model holds as `Option` or empty lists are written only when present, so nothing is
//! invented (`QualityCheck` stays absent when it was absent). Unknown elements go back at the end of
//! their parent, which is where other apps' writers put them and where they were read from in the
//! corpus files.

use base64::Engine as _;
use ov_error::OvError;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::read::EPOCH_OFFSET;
use super::tree::XmlOut;
use crate::crypto::InnerStream;
use crate::model::*;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The XML of `db` with protected values encrypted by `stream`, in document order.
#[cfg(test)]
pub(crate) fn document(db: &Database, stream: InnerStream) -> Result<Zeroizing<Vec<u8>>, OvError> {
    document_into(db, stream, Zeroizing::new(Vec::new()))
}

/// About how long the XML of `db` is, a little over for most vaults, to size the buffer once
/// (each time it grows, the old copy has to be wiped).
pub(crate) fn estimated_len(db: &Database) -> usize {
    fn entry(e: &Entry) -> usize {
        let strings: usize = e.strings.iter().map(|s| s.key.len() + s.value.len() * 4 / 3).sum();
        let tags: usize = e.tags.iter().map(|t| t.len() + 1).sum();
        1200 + strings + tags + e.history.iter().map(entry).sum::<usize>()
    }
    fn group(g: &Group) -> usize {
        800 + g.name.len()
            + g.notes.len()
            + g.entries.iter().map(entry).sum::<usize>()
            + g.groups.iter().map(group).sum::<usize>()
    }
    4096 + group(&db.root)
        + db.deleted_objects.len() * 160
        + db.meta.custom_icons.iter().map(|i| i.data.len() * 4 / 3 + 200).sum::<usize>()
}

/// [`document`], appended to `out` (the inner header is already there).
pub(crate) fn document_into(
    db: &Database,
    stream: InnerStream,
    out: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let mut w = Writer { out: XmlOut::with_buffer(stream, out)? };
    w.out.open("KeePassFile")?;
    w.meta(&db.meta)?;
    w.out.open("Root")?;
    w.group(&db.root)?;
    w.out.open("DeletedObjects")?;
    for d in &db.deleted_objects {
        w.out.open("DeletedObject")?;
        w.uuid("UUID", d.uuid)?;
        w.time("DeletionTime", d.deletion_time)?;
        w.out.close("DeletedObject")?;
    }
    w.out.close("DeletedObjects")?;
    w.unknown(&db.unknown_root)?;
    w.out.close("Root")?;
    w.unknown(&db.unknown_file)?;
    w.out.close("KeePassFile")?;
    Ok(w.out.finish())
}

/// `bytes` as base64 in `buf`, without allocating (times and UUIDs: most of the values).
fn b64_in<'b>(bytes: &[u8], buf: &'b mut [u8; 32]) -> &'b str {
    let n = B64.encode_slice(bytes, buf).expect("32 bytes hold the base64 of 16");
    std::str::from_utf8(&buf[..n]).expect("base64 is ASCII")
}

struct Writer {
    out: XmlOut,
}

fn bool_text(b: bool) -> &'static str {
    if b {
        "True"
    } else {
        "False"
    }
}

impl Writer {
    fn s(&mut self, name: &str, text: &str) -> Result<(), OvError> {
        self.out.leaf(name, text)
    }

    fn bool(&mut self, name: &str, b: bool) -> Result<(), OvError> {
        self.out.leaf(name, bool_text(b))
    }

    fn num(&mut self, name: &str, n: impl std::fmt::Display) -> Result<(), OvError> {
        use std::io::Write as _;
        let mut buf = [0u8; 40];
        let mut c = std::io::Cursor::new(&mut buf[..]);
        match write!(c, "{n}") {
            Ok(()) => {
                let len = c.position() as usize;
                self.out.leaf(name, std::str::from_utf8(&buf[..len]).expect("a number is ASCII"))
            }
            Err(_) => self.out.leaf(name, &n.to_string()),
        }
    }

    fn time(&mut self, name: &str, t: Timestamp) -> Result<(), OvError> {
        let mut buf = [0u8; 32];
        self.out.leaf(name, b64_in(&t.saturating_add(EPOCH_OFFSET).to_le_bytes(), &mut buf))
    }

    fn opt_time(&mut self, name: &str, t: Option<Timestamp>) -> Result<(), OvError> {
        match t {
            Some(t) => self.time(name, t),
            None => Ok(()),
        }
    }

    fn uuid(&mut self, name: &str, u: Uuid) -> Result<(), OvError> {
        let mut buf = [0u8; 32];
        self.out.leaf(name, b64_in(u.as_bytes(), &mut buf))
    }

    /// An optional reference written as the all-zero UUID when absent (as KeePassXC does).
    fn uuid_or_nil(&mut self, name: &str, u: Option<Uuid>) -> Result<(), OvError> {
        self.uuid(name, u.unwrap_or_default())
    }

    fn unknown(&mut self, list: &[XmlElement]) -> Result<(), OvError> {
        list.iter().try_for_each(|e| self.out.element(e))
    }

    fn custom_data(&mut self, items: &[CustomDataItem]) -> Result<(), OvError> {
        if items.is_empty() {
            return Ok(());
        }
        self.out.open("CustomData")?;
        for i in items {
            self.out.open("Item")?;
            self.s("Key", &i.key)?;
            self.s("Value", &i.value)?;
            self.opt_time("LastModificationTime", i.last_modification)?;
            self.out.close("Item")?;
        }
        self.out.close("CustomData")
    }

    fn meta(&mut self, m: &Meta) -> Result<(), OvError> {
        self.out.open("Meta")?;
        self.s("Generator", &m.generator)?;
        self.s("DatabaseName", &m.database_name)?;
        self.opt_time("DatabaseNameChanged", m.database_name_changed)?;
        self.s("DatabaseDescription", &m.database_description)?;
        self.opt_time("DatabaseDescriptionChanged", m.database_description_changed)?;
        self.s("DefaultUserName", &m.default_user_name)?;
        self.opt_time("DefaultUserNameChanged", m.default_user_name_changed)?;
        self.num("MaintenanceHistoryDays", m.maintenance_history_days)?;
        self.s("Color", &m.color)?;
        self.opt_time("MasterKeyChanged", m.master_key_changed)?;
        self.num("MasterKeyChangeRec", m.master_key_change_rec)?;
        self.num("MasterKeyChangeForce", m.master_key_change_force)?;
        self.out.open("MemoryProtection")?;
        let p = m.memory_protection;
        self.bool("ProtectTitle", p.title)?;
        self.bool("ProtectUserName", p.user_name)?;
        self.bool("ProtectPassword", p.password)?;
        self.bool("ProtectURL", p.url)?;
        self.bool("ProtectNotes", p.notes)?;
        self.out.close("MemoryProtection")?;
        if !m.custom_icons.is_empty() {
            self.out.open("CustomIcons")?;
            for icon in &m.custom_icons {
                self.out.open("Icon")?;
                self.uuid("UUID", icon.uuid)?;
                if let Some(name) = &icon.name {
                    self.s("Name", name)?;
                }
                self.opt_time("LastModificationTime", icon.last_modification)?;
                self.s("Data", &B64.encode(&icon.data))?;
                self.out.close("Icon")?;
            }
            self.out.close("CustomIcons")?;
        }
        self.bool("RecycleBinEnabled", m.recycle_bin_enabled)?;
        self.uuid_or_nil("RecycleBinUUID", m.recycle_bin_uuid)?;
        self.opt_time("RecycleBinChanged", m.recycle_bin_changed)?;
        self.uuid_or_nil("EntryTemplatesGroup", m.entry_templates_group)?;
        self.opt_time("EntryTemplatesGroupChanged", m.entry_templates_group_changed)?;
        self.uuid_or_nil("LastSelectedGroup", m.last_selected_group)?;
        self.uuid_or_nil("LastTopVisibleGroup", m.last_top_visible_group)?;
        self.num("HistoryMaxItems", m.history_max_items)?;
        self.num("HistoryMaxSize", m.history_max_size)?;
        self.opt_time("SettingsChanged", m.settings_changed)?;
        self.custom_data(&m.custom_data)?;
        self.unknown(&m.unknown)?;
        self.out.close("Meta")
    }

    fn times(&mut self, t: &Times) -> Result<(), OvError> {
        self.out.open("Times")?;
        self.time("LastModificationTime", t.last_modification)?;
        self.time("CreationTime", t.creation)?;
        self.time("LastAccessTime", t.last_access)?;
        self.time("ExpiryTime", t.expiry)?;
        self.bool("Expires", t.expires)?;
        self.num("UsageCount", t.usage_count)?;
        self.time("LocationChanged", t.location_changed)?;
        self.out.close("Times")
    }

    fn group(&mut self, g: &Group) -> Result<(), OvError> {
        self.out.open("Group")?;
        self.uuid("UUID", g.uuid)?;
        self.s("Name", &g.name)?;
        self.s("Notes", &g.notes)?;
        if !g.tags.is_empty() {
            self.s("Tags", &g.tags.join(";"))?;
        }
        self.num("IconID", g.icon_id)?;
        if let Some(u) = g.custom_icon {
            self.uuid("CustomIconUUID", u)?;
        }
        self.times(&g.times)?;
        self.bool("IsExpanded", g.is_expanded)?;
        self.s("DefaultAutoTypeSequence", &g.default_auto_type_sequence)?;
        let tri = |v: Option<bool>| match v {
            None => "null",
            Some(true) => "true",
            Some(false) => "false",
        };
        self.s("EnableAutoType", tri(g.enable_auto_type))?;
        self.s("EnableSearching", tri(g.enable_searching))?;
        self.uuid_or_nil("LastTopVisibleEntry", g.last_top_visible_entry)?;
        self.custom_data(&g.custom_data)?;
        if let Some(u) = g.previous_parent_group {
            self.uuid("PreviousParentGroup", u)?;
        }
        for e in &g.entries {
            self.entry(e, false)?;
        }
        for sub in &g.groups {
            self.group(sub)?;
        }
        self.unknown(&g.unknown)?;
        self.out.close("Group")
    }

    fn entry(&mut self, e: &Entry, is_history: bool) -> Result<(), OvError> {
        self.out.open("Entry")?;
        self.uuid("UUID", e.uuid)?;
        self.num("IconID", e.icon_id)?;
        if let Some(u) = e.custom_icon {
            self.uuid("CustomIconUUID", u)?;
        }
        self.s("ForegroundColor", &e.foreground_color)?;
        self.s("BackgroundColor", &e.background_color)?;
        self.s("OverrideURL", &e.override_url)?;
        self.s("Tags", &e.tags.join(";"))?;
        self.times(&e.times)?;
        if let Some(q) = e.quality_check {
            self.bool("QualityCheck", q)?;
        }
        if let Some(u) = e.previous_parent_group {
            self.uuid("PreviousParentGroup", u)?;
        }
        for f in &e.strings {
            self.out.open("String")?;
            self.s("Key", &f.key)?;
            let attrs: &[(&str, &str)] = if f.protected { &[("Protected", "True")] } else { &[] };
            self.out.leaf_with("Value", attrs, &f.value)?;
            self.out.close("String")?;
        }
        for b in &e.binaries {
            self.out.open("Binary")?;
            self.s("Key", &b.name)?;
            self.out.leaf_with("Value", &[("Ref", &b.index.to_string())], "")?;
            self.out.close("Binary")?;
        }
        if let Some(a) = &e.auto_type {
            self.out.open("AutoType")?;
            self.bool("Enabled", a.enabled)?;
            self.num("DataTransferObfuscation", a.data_transfer_obfuscation)?;
            self.s("DefaultSequence", &a.default_sequence)?;
            for assoc in &a.associations {
                self.out.open("Association")?;
                self.s("Window", &assoc.window)?;
                self.s("KeystrokeSequence", &assoc.keystroke_sequence)?;
                self.out.close("Association")?;
            }
            self.unknown(&a.unknown)?;
            self.out.close("AutoType")?;
        }
        self.custom_data(&e.custom_data)?;
        if !is_history || !e.history.is_empty() {
            self.out.open("History")?;
            for h in &e.history {
                self.entry(h, true)?;
            }
            self.out.close("History")?;
        }
        self.unknown(&e.unknown)?;
        self.out.close("Entry")
    }
}

#[cfg(test)]
mod tests {
    use super::super::tree::{parse, Node};
    use super::*;

    fn last_child_name<'a>(n: &Node<'a>) -> &'a str {
        n.children.last().map_or("", |c| c.name)
    }

    /// `XmlOut::finish` asserts the same bytes as quick-xml's writer under `cfg(test)`.
    #[test]
    fn corpus_files_write_like_quick_xml() {
        for f in super::super::corpus::files() {
            let db = crate::read(&f.bytes, &f.key).unwrap_or_else(|e| panic!("{}: {e}", f.name));
            document(&db, InnerStream::new(3, &[9; 64]).unwrap().unwrap()).unwrap();
        }
    }

    #[test]
    fn odd_text_writes_like_quick_xml() {
        let odd = [
            "",
            "plain",
            "<&>\"'",
            "a\r\nb\rc\nd\te",
            "ctl \u{0}\u{1}\u{8}\u{b}\u{c}\u{1f}\u{7f} end",
            "\u{fffe}\u{ffff}\u{fffd}\u{e000}\u{d7ff}\u{10000}\u{10ffff}",
            "é ✓ 𝄞 \u{ef}\u{bf}",
            "  lead and trail  ",
        ];
        let mut w = XmlOut::new(InnerStream::new(3, &[9; 64]).unwrap().unwrap()).unwrap();
        w.open("Root").unwrap();
        for t in odd {
            w.leaf("Leaf", t).unwrap();
            w.leaf_with("Attr", &[("a", t), ("b", "x")], t).unwrap();
            w.leaf_with("P", &[("Protected", "True")], t).unwrap();
            w.element(&XmlElement {
                name: "Mixed".into(),
                attributes: vec![("k".into(), t.into())],
                text: t.into(),
                children: vec![
                    XmlElement { name: "In".into(), text: t.into(), ..XmlElement::default() },
                    XmlElement {
                        name: "Deep".into(),
                        children: vec![XmlElement { name: "E".into(), ..XmlElement::default() }],
                        ..XmlElement::default()
                    },
                ],
            })
            .unwrap();
        }
        w.close("Root").unwrap();
        w.finish();
    }

    #[test]
    fn a_big_vault_writes_like_quick_xml() {
        let (mut db, _) = crate::vault::create_vault_kdbx("Big", &[3; 32], 1_700_000_000).unwrap();
        for g in 0..20u128 {
            let mut group = Group::new(Uuid::from_u128(1000 + g), format!("G{g}"), 1_700_000_000);
            for e in 0..100u128 {
                let mut entry = Entry::new(Uuid::from_u128(g * 1000 + e + 1), 1_700_000_000);
                entry.strings = vec![
                    StringField::new("Title", format!("E {e} <&>"), false),
                    StringField::new("Password", format!("pw{e}\r\n"), true),
                ];
                entry.tags = vec!["t".into()];
                entry.history.push(entry.clone());
                group.entries.push(entry);
            }
            db.root.groups.push(group);
        }
        document(&db, InnerStream::new(3, &[9; 64]).unwrap().unwrap()).unwrap();
    }

    #[test]
    fn the_estimate_is_close() {
        let mut ratios = Vec::new();
        for f in super::super::corpus::files() {
            let db = crate::read(&f.bytes, &f.key).unwrap();
            let xml = document(&db, InnerStream::new(3, &[9; 64]).unwrap().unwrap()).unwrap();
            ratios.push((f.name, estimated_len(&db) as f64 / xml.len() as f64));
        }
        // A little over is the aim; small files are mostly the fixed 4 KB
        assert!(ratios.iter().all(|(_, r)| (0.8..2.5).contains(r)), "{ratios:?}");
    }

    #[test]
    fn unknown_elements_are_written_last_in_their_parent() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../corpus/kdbx/kdbxweb/kdbxweb-unknown.kdbx");
        let db =
            crate::read(&std::fs::read(path).unwrap(), &crate::CompositeKey::new().with_password("spike pw")).unwrap();
        let xml = document(&db, InnerStream::new(3, &[9; 64]).unwrap().unwrap()).unwrap();
        let mut s = InnerStream::new(3, &[9; 64]).unwrap().unwrap();
        let file = parse(std::str::from_utf8(&xml).unwrap(), Some(&mut s)).unwrap();
        assert_eq!(last_child_name(&file), "ZzUnknownFile");
        let meta = file.child("Meta").unwrap();
        assert_eq!(last_child_name(meta), "ZzUnknownMeta");
        let root = file.child("Root").unwrap();
        assert_eq!(last_child_name(root), "ZzUnknownRoot");
        let group = root.child("Group").unwrap();
        assert_eq!(last_child_name(group), "ZzUnknownGroup");
        let work = group
            .children
            .iter()
            .find(|g| g.name == "Group" && g.child("Name").unwrap().text.as_str() == "Work")
            .unwrap();
        let entry = work.child("Entry").unwrap();
        assert_eq!(last_child_name(entry), "ZzUnknownEntry");
        assert_eq!(last_child_name(entry.child("AutoType").unwrap()), "ZzUnknownAutoType");
        assert!(entry.child("QualityCheck").is_none(), "nothing invented");
    }
}
