//! The decrypted XML tree → [`model`](crate::model).
//!
//! Every element KeePassXC's `KdbxXmlReader` knows maps to a field; any other child of
//! `<KeePassFile>`, `<Root>`, `<Meta>`, `<Group>`, `<Entry>` or `<AutoType>` is kept in that
//! parent's `unknown` list. Reference: KeePassXC `src/format/KdbxXmlReader.cpp`.

use base64::Engine as _;
use ov_error::OvError;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::tree::Node;
use crate::bytes::err;
use crate::model::*;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Seconds from 0001-01-01 to 1970-01-01 (KDBX 4 times count from year 1).
pub(crate) const EPOCH_OFFSET: i64 = 62_135_596_800;

/// What the XML holds besides the model's own fields.
pub(crate) struct XmlDocument {
    pub(crate) meta: Meta,
    pub(crate) root: Group,
    pub(crate) deleted_objects: Vec<DeletedObject>,
    pub(crate) unknown_file: Vec<XmlElement>,
    pub(crate) unknown_root: Vec<XmlElement>,
    /// KDBX 3.1 `<Meta><HeaderHash>`, if present.
    pub(crate) header_hash: Option<Vec<u8>>,
}

/// Maps the tree. `binaries` is the pool: the KDBX 4 inner header's, to which KDBX 3.1
/// `<Meta><Binaries>` and inline entry attachments are added.
pub(crate) fn document(root: Node<'_>, binaries: &mut Vec<Binary>) -> Result<XmlDocument, OvError> {
    if root.name != "KeePassFile" {
        return Err(err("the XML is not a KeePass document"));
    }
    let mut doc = XmlDocument {
        meta: Meta { generator: String::new(), ..Meta::default() },
        root: Group::new(Uuid::nil(), "", 0),
        deleted_objects: Vec::new(),
        unknown_file: Vec::new(),
        unknown_root: Vec::new(),
        header_hash: None,
    };
    let mut have_meta = false;
    let mut have_root = false;
    // Meta first: KDBX 3.1 attachments live in Meta/Binaries and entries refer to them by ID.
    let (metas, rest): (Vec<Node<'_>>, Vec<Node<'_>>) = root.children.into_iter().partition(|c| c.name == "Meta");
    let mut metas = metas.into_iter();
    if let Some(m) = metas.next() {
        have_meta = true;
        read_meta(m, &mut doc, binaries)?;
    }
    for c in metas {
        doc.unknown_file.push(c.into_element());
    }
    for c in rest {
        match c.name {
            "Root" if !have_root => {
                have_root = true;
                read_root(c, &mut doc, binaries)?;
            }
            _ => doc.unknown_file.push(c.into_element()),
        }
    }
    if !have_meta || !have_root {
        return Err(err("the XML has no Meta or Root"));
    }
    Ok(doc)
}

// ---------------------------------------------------------------------------------------------
// Values

fn text<'n>(n: &'n Node<'_>) -> &'n str {
    n.text.as_str()
}

pub(crate) fn parse_bool(s: &str) -> bool {
    let s = s.trim();
    s.eq_ignore_ascii_case("true") || s == "1"
}

fn parse_tristate(s: &str) -> Option<bool> {
    match s.trim() {
        t if t.eq_ignore_ascii_case("true") => Some(true),
        t if t.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn parse_num<T: std::str::FromStr>(n: &Node<'_>, default: T) -> T {
    text(n).trim().parse().unwrap_or(default)
}

/// `s` as base64 of exactly `N` bytes, decoded without allocating (UUIDs and times: most values).
fn b64_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    // Room for any input that could decode to N bytes; a longer one fails as too small
    let mut buf = [0u8; 64];
    let n = B64.decode_slice(s, &mut buf).ok()?;
    buf[..n].try_into().ok()
}

pub(crate) fn parse_uuid(s: &str) -> Option<Uuid> {
    b64_exact::<16>(s.trim()).map(Uuid::from_bytes)
}

fn parse_opt_uuid(n: &Node<'_>) -> Option<Uuid> {
    parse_uuid(text(n)).filter(|u| !u.is_nil())
}

/// A KDBX time: base64 of i64 LE seconds since year 1 (KDBX 4), or ISO 8601 text (KDBX 3.1).
pub(crate) fn parse_time(s: &str) -> Option<Timestamp> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains('-') || s.contains(':') {
        return parse_iso8601(s);
    }
    let secs = i64::from_le_bytes(b64_exact::<8>(s)?);
    Some(secs - EPOCH_OFFSET)
}

/// `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]`; sub-seconds dropped, no zone means UTC (as KeePassXC).
fn parse_iso8601(s: &str) -> Option<Timestamp> {
    let (date, time) = s.split_once(['T', ' '])?;
    let mut d = date.splitn(3, '-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;
    let (clock, offset) = if let Some(t) = time.strip_suffix('Z') {
        (t, 0)
    } else if let Some(i) = time.rfind(['+', '-']) {
        let (t, z) = time.split_at(i);
        let sign = if z.starts_with('-') { -1 } else { 1 };
        let (h, m) = z[1..].split_once(':').unwrap_or((&z[1..], "0"));
        (t, sign * (h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60))
    } else {
        (time, 0)
    };
    let mut c = clock.splitn(3, ':');
    let h: i64 = c.next()?.parse().ok()?;
    let m: i64 = c.next()?.parse().ok()?;
    let sec: i64 = c.next().unwrap_or("0").split('.').next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // In i128: any i64 fields fit, and a time that doesn't fit an i64 is no time (fuzzing found the
    // overflow)
    let t = days_from_civil(i128::from(year), month, day) * 86_400
        + i128::from(h) * 3600
        + i128::from(m) * 60
        + i128::from(sec)
        - i128::from(offset);
    i64::try_from(t).ok()
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i128, m: u32, d: u32) -> i128 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i128::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i128::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(crate) fn split_tags(s: &str) -> Vec<String> {
    s.split([';', ',']).map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned).collect()
}

fn decode_b64(n: &Node<'_>) -> Result<Vec<u8>, OvError> {
    let cleaned: String = text(n).chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(cleaned).map_err(|_| err(format!("<{}> is not base64", n.name)))
}

/// The bytes of a binary element: its decrypted bytes if protected, else base64; gunzipped when
/// `Compressed="True"`.
fn binary_bytes(n: &Node<'_>) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let raw = match &n.raw {
        Some(r) => r.clone(),
        None => Zeroizing::new(decode_b64(n)?),
    };
    if n.attr("Compressed").is_some_and(parse_bool) {
        crate::crypto::gunzip(&raw)
    } else {
        Ok(raw)
    }
}

// ---------------------------------------------------------------------------------------------
// Meta

fn read_meta(meta: Node<'_>, doc: &mut XmlDocument, binaries: &mut Vec<Binary>) -> Result<(), OvError> {
    let m = &mut doc.meta;
    for c in meta.children {
        match c.name {
            "Generator" => m.generator = text(&c).to_owned(),
            "HeaderHash" => doc.header_hash = Some(decode_b64(&c)?),
            "DatabaseName" => m.database_name = text(&c).to_owned(),
            "DatabaseNameChanged" => m.database_name_changed = parse_time(text(&c)),
            "DatabaseDescription" => m.database_description = text(&c).to_owned(),
            "DatabaseDescriptionChanged" => m.database_description_changed = parse_time(text(&c)),
            "DefaultUserName" => m.default_user_name = text(&c).to_owned(),
            "DefaultUserNameChanged" => m.default_user_name_changed = parse_time(text(&c)),
            "MaintenanceHistoryDays" => m.maintenance_history_days = parse_num(&c, 365),
            "Color" => m.color = text(&c).to_owned(),
            "MasterKeyChanged" => m.master_key_changed = parse_time(text(&c)),
            "MasterKeyChangeRec" => m.master_key_change_rec = parse_num(&c, -1),
            "MasterKeyChangeForce" => m.master_key_change_force = parse_num(&c, -1),
            "MemoryProtection" => {
                for p in &c.children {
                    let v = parse_bool(text(p));
                    match p.name {
                        "ProtectTitle" => m.memory_protection.title = v,
                        "ProtectUserName" => m.memory_protection.user_name = v,
                        "ProtectPassword" => m.memory_protection.password = v,
                        "ProtectURL" => m.memory_protection.url = v,
                        "ProtectNotes" => m.memory_protection.notes = v,
                        _ => {}
                    }
                }
            }
            "CustomIcons" => {
                for icon in c.children.iter().filter(|i| i.name == "Icon") {
                    let mut ci =
                        CustomIcon { uuid: Uuid::nil(), data: Vec::new(), name: None, last_modification: None };
                    for f in &icon.children {
                        match f.name {
                            "UUID" => ci.uuid = parse_uuid(text(f)).unwrap_or_default(),
                            "Data" => ci.data = decode_b64(f)?,
                            "Name" => ci.name = Some(text(f).to_owned()),
                            "LastModificationTime" => ci.last_modification = parse_time(text(f)),
                            _ => {}
                        }
                    }
                    m.custom_icons.push(ci);
                }
            }
            "RecycleBinEnabled" => m.recycle_bin_enabled = parse_bool(text(&c)),
            "RecycleBinUUID" => m.recycle_bin_uuid = parse_opt_uuid(&c),
            "RecycleBinChanged" => m.recycle_bin_changed = parse_time(text(&c)),
            "EntryTemplatesGroup" => m.entry_templates_group = parse_opt_uuid(&c),
            "EntryTemplatesGroupChanged" => m.entry_templates_group_changed = parse_time(text(&c)),
            "HistoryMaxItems" => m.history_max_items = parse_num(&c, -1),
            "HistoryMaxSize" => m.history_max_size = parse_num(&c, -1),
            "LastSelectedGroup" => m.last_selected_group = parse_opt_uuid(&c),
            "LastTopVisibleGroup" => m.last_top_visible_group = parse_opt_uuid(&c),
            "Binaries" => read_meta_binaries(&c, binaries)?,
            "CustomData" => m.custom_data = read_custom_data(&c),
            "SettingsChanged" => m.settings_changed = parse_time(text(&c)),
            _ => m.unknown.push(c.into_element()),
        }
    }
    Ok(())
}

/// KDBX 3.1 `<Meta><Binaries>`: the pool, by ID.
fn read_meta_binaries(node: &Node<'_>, binaries: &mut Vec<Binary>) -> Result<(), OvError> {
    for b in node.children.iter().filter(|b| b.name == "Binary") {
        let id: usize = b.attr("ID").and_then(|v| v.trim().parse().ok()).ok_or_else(|| err("a binary has no ID"))?;
        if id > 1_000_000 {
            return Err(err("a binary ID is out of range"));
        }
        let data = binary_bytes(b)?;
        while binaries.len() <= id {
            binaries.push(Binary { data: Zeroizing::new(Vec::new()), protected: false });
        }
        binaries[id] = Binary { data, protected: b.is_protected() };
    }
    Ok(())
}

fn read_custom_data(node: &Node<'_>) -> Vec<CustomDataItem> {
    node.children
        .iter()
        .filter(|i| i.name == "Item")
        .map(|i| {
            let mut item = CustomDataItem { key: String::new(), value: String::new(), last_modification: None };
            for f in &i.children {
                match f.name {
                    "Key" => item.key = text(f).to_owned(),
                    "Value" => item.value = text(f).to_owned(),
                    "LastModificationTime" => item.last_modification = parse_time(text(f)),
                    _ => {}
                }
            }
            item
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Root, groups, entries

fn read_root(node: Node<'_>, doc: &mut XmlDocument, binaries: &mut Vec<Binary>) -> Result<(), OvError> {
    let mut have_group = false;
    for c in node.children {
        match c.name {
            "Group" if !have_group => {
                have_group = true;
                doc.root = read_group(c, binaries)?;
            }
            "DeletedObjects" => {
                for d in c.children.iter().filter(|d| d.name == "DeletedObject") {
                    let mut o = DeletedObject { uuid: Uuid::nil(), deletion_time: 0 };
                    for f in &d.children {
                        match f.name {
                            "UUID" => o.uuid = parse_uuid(text(f)).unwrap_or_default(),
                            "DeletionTime" => o.deletion_time = parse_time(text(f)).unwrap_or(0),
                            _ => {}
                        }
                    }
                    doc.deleted_objects.push(o);
                }
            }
            _ => doc.unknown_root.push(c.into_element()),
        }
    }
    if !have_group {
        return Err(err("the XML has no root group"));
    }
    Ok(())
}

fn read_times(node: &Node<'_>) -> Times {
    let mut t = Times::at(0);
    for f in &node.children {
        match f.name {
            "CreationTime" => t.creation = parse_time(text(f)).unwrap_or(0),
            "LastModificationTime" => t.last_modification = parse_time(text(f)).unwrap_or(0),
            "LastAccessTime" => t.last_access = parse_time(text(f)).unwrap_or(0),
            "ExpiryTime" => t.expiry = parse_time(text(f)).unwrap_or(0),
            "Expires" => t.expires = parse_bool(text(f)),
            "UsageCount" => t.usage_count = parse_num(f, 0),
            "LocationChanged" => t.location_changed = parse_time(text(f)).unwrap_or(0),
            _ => {}
        }
    }
    t
}

fn read_group(node: Node<'_>, binaries: &mut Vec<Binary>) -> Result<Group, OvError> {
    let mut g = Group::new(Uuid::nil(), "", 0);
    for c in node.children {
        match c.name {
            "UUID" => g.uuid = parse_uuid(text(&c)).unwrap_or_default(),
            "Name" => g.name = text(&c).to_owned(),
            "Notes" => g.notes = text(&c).to_owned(),
            "IconID" => g.icon_id = parse_num(&c, 48),
            "CustomIconUUID" => g.custom_icon = parse_opt_uuid(&c),
            "Times" => g.times = read_times(&c),
            "IsExpanded" => g.is_expanded = parse_bool(text(&c)),
            "DefaultAutoTypeSequence" => g.default_auto_type_sequence = text(&c).to_owned(),
            "EnableAutoType" => g.enable_auto_type = parse_tristate(text(&c)),
            "EnableSearching" => g.enable_searching = parse_tristate(text(&c)),
            "LastTopVisibleEntry" => g.last_top_visible_entry = parse_opt_uuid(&c),
            "Tags" => g.tags = split_tags(text(&c)),
            "PreviousParentGroup" => g.previous_parent_group = parse_opt_uuid(&c),
            "CustomData" => g.custom_data = read_custom_data(&c),
            "Entry" => g.entries.push(read_entry(c, binaries)?),
            "Group" => g.groups.push(read_group(c, binaries)?),
            _ => g.unknown.push(c.into_element()),
        }
    }
    Ok(g)
}

fn read_entry(node: Node<'_>, binaries: &mut Vec<Binary>) -> Result<Entry, OvError> {
    let mut e = Entry::new(Uuid::nil(), 0);
    e.strings.clear();
    e.auto_type = None;
    for c in node.children {
        match c.name {
            "UUID" => e.uuid = parse_uuid(text(&c)).unwrap_or_default(),
            "IconID" => e.icon_id = parse_num(&c, 0),
            "CustomIconUUID" => e.custom_icon = parse_opt_uuid(&c),
            "ForegroundColor" => e.foreground_color = text(&c).to_owned(),
            "BackgroundColor" => e.background_color = text(&c).to_owned(),
            "OverrideURL" => e.override_url = text(&c).to_owned(),
            "Tags" => e.tags = split_tags(text(&c)),
            "Times" => e.times = read_times(&c),
            "QualityCheck" => e.quality_check = Some(parse_bool(text(&c))),
            "PreviousParentGroup" => e.previous_parent_group = parse_opt_uuid(&c),
            "String" => {
                let mut key = String::new();
                let mut value = Zeroizing::new(String::new());
                let mut protected = false;
                for f in c.children {
                    match f.name {
                        "Key" => key = text(&f).to_owned(),
                        "Value" => {
                            protected = f.is_protected() || f.attr("ProtectInMemory").is_some_and(parse_bool);
                            value = f.text.into_zeroizing();
                        }
                        _ => {}
                    }
                }
                e.strings.push(StringField { key, value, protected });
            }
            "Binary" => {
                let mut name = String::new();
                let mut index = None;
                for f in &c.children {
                    match f.name {
                        "Key" => name = text(f).to_owned(),
                        "Value" => {
                            index = match f.attr("Ref") {
                                Some(r) => {
                                    Some(r.trim().parse::<u32>().map_err(|_| err("a binary Ref is not a number"))?)
                                }
                                None => {
                                    // An inline attachment (old KDBX 3.1 writers): add it to the pool.
                                    binaries.push(Binary { data: binary_bytes(f)?, protected: f.is_protected() });
                                    Some((binaries.len() - 1) as u32)
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(index) = index {
                    e.binaries.push(BinaryRef { name, index });
                }
            }
            "AutoType" => e.auto_type = Some(read_auto_type(c)),
            "History" => {
                for h in c.children {
                    if h.name == "Entry" {
                        e.history.push(read_entry(h, binaries)?);
                    }
                }
            }
            "CustomData" => e.custom_data = read_custom_data(&c),
            _ => e.unknown.push(c.into_element()),
        }
    }
    Ok(e)
}

fn read_auto_type(node: Node<'_>) -> AutoType {
    let mut a = AutoType::default();
    for c in node.children {
        match c.name {
            "Enabled" => a.enabled = parse_bool(text(&c)),
            "DataTransferObfuscation" => a.data_transfer_obfuscation = parse_num(&c, 0),
            "DefaultSequence" => a.default_sequence = text(&c).to_owned(),
            "Association" => {
                let mut assoc = AutoTypeAssociation { window: String::new(), keystroke_sequence: String::new() };
                for f in &c.children {
                    match f.name {
                        "Window" => assoc.window = text(f).to_owned(),
                        "KeystrokeSequence" => assoc.keystroke_sequence = text(f).to_owned(),
                        _ => {}
                    }
                }
                a.associations.push(assoc);
            }
            _ => a.unknown.push(c.into_element()),
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_times() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2026-10-30T12:34:56Z"), Some(1_793_363_696));
        assert_eq!(parse_time("2026-10-30T12:34:56.789Z"), Some(1_793_363_696));
        assert_eq!(parse_time("2026-10-30T14:34:56+02:00"), Some(1_793_363_696));
        assert_eq!(parse_time("0001-01-01T00:00:00Z"), Some(-EPOCH_OFFSET));
        // Out of range: no time, no overflow
        assert_eq!(parse_time("2026-10-30T9223372036854775807:00:00Z"), None);
        assert_eq!(parse_time("9223372036854775807-12-31T00:00:00Z"), None);
        assert_eq!(parse_time("-9223372036854775808-01-01T00:00:00+99:99"), None);
    }

    #[test]
    fn binary_times() {
        let b = B64.encode((EPOCH_OFFSET + 1_700_000_000).to_le_bytes());
        assert_eq!(parse_time(&b), Some(1_700_000_000));
    }

    #[test]
    fn exact_base64_lengths() {
        let id = Uuid::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        assert_eq!(parse_uuid(&format!(" {} ", B64.encode(id.as_bytes()))), Some(id));
        assert_eq!(parse_uuid(&B64.encode([1u8; 15])), None);
        assert_eq!(parse_uuid(&B64.encode([1u8; 17])), None);
        assert_eq!(parse_uuid(&B64.encode([1u8; 100])), None);
        assert_eq!(parse_uuid("not base64!"), None);
        assert_eq!(parse_time(&B64.encode([0u8; 9])), None);
    }

    #[test]
    fn tags_split_on_both_separators() {
        assert_eq!(split_tags("a; b,c;;"), vec!["a", "b", "c"]);
    }
}
