//! The field model of the desktop `SyncEngine` (`fieldsOf`, `applyField`, `resolveFields`), ported
//! from the SDK's `merge/fields.ts`: an entry split into parts that merge one by one, by name.

use ov_kdbx::model::{CustomIcon, Database, Entry, StringField, Timestamp, Uuid, STANDARD_FIELDS};
use zeroize::Zeroizing;

use crate::pool;

pub(crate) fn is_standard(key: &str) -> bool {
    STANDARD_FIELDS.contains(&key)
}

/// The name of one mergeable part of an entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FieldKey {
    /// A string field (`attribute/<key>`).
    Attribute(String),
    /// An attachment (`attachment/<name>`).
    Attachment(String),
    Tags,
    Expiry,
    Icon,
    Colors,
}

/// One part's value. Self-contained (attachment bytes, custom icon image), so it can be applied to an
/// entry of another database.
#[derive(Clone)]
pub(crate) enum FieldValue {
    Attribute {
        text: Zeroizing<String>,
        protect: bool,
    },
    Attachment {
        data: Zeroizing<Vec<u8>>,
        protected: bool,
    },
    Tags(Vec<String>),
    /// `None`: never expires.
    Expiry(Option<Timestamp>),
    Icon {
        number: u32,
        custom: Option<(Uuid, Option<CustomIcon>)>,
    },
    Colors {
        fg: String,
        bg: String,
    },
}

impl FieldValue {
    /// The TS `cmp` equality: text and protection, attachment content, tags joined with `;`, expiry,
    /// custom icon UUID or standard number, colours.
    pub(crate) fn same(&self, other: &FieldValue) -> bool {
        use FieldValue::*;
        match (self, other) {
            (Attribute { text: a, protect: pa }, Attribute { text: b, protect: pb }) => a == b && pa == pb,
            (Attachment { data: a, .. }, Attachment { data: b, .. }) => a == b,
            (Tags(a), Tags(b)) => a.join(";") == b.join(";"),
            (Expiry(a), Expiry(b)) => a == b,
            (Icon { number: na, custom: ca }, Icon { number: nb, custom: cb }) => match (ca, cb) {
                (Some((a, _)), Some((b, _))) => a == b,
                (None, None) => na == nb,
                _ => false,
            },
            (Colors { fg: fa, bg: ba }, Colors { fg: fb, bg: bb }) => fa == fb && ba == bb,
            _ => false,
        }
    }
}

pub(crate) fn same_value(a: Option<&FieldValue>, b: Option<&FieldValue>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.same(b),
        _ => false,
    }
}

/// An insertion-ordered map of an entry's parts (the TS `Map`; order decides conflict order).
#[derive(Clone, Default)]
pub(crate) struct Fields(pub(crate) Vec<(FieldKey, FieldValue)>);

impl Fields {
    pub(crate) fn get(&self, key: &FieldKey) -> Option<&FieldValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn set(&mut self, key: FieldKey, value: FieldValue) {
        match self.0.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key, value)),
        }
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &FieldKey> {
        self.0.iter().map(|(k, _)| k)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

/// The keys of `lists`, each once, in first-seen order.
pub(crate) fn union_keys<'a>(lists: &[&'a Fields]) -> Vec<&'a FieldKey> {
    let mut out: Vec<&FieldKey> = Vec::new();
    for f in lists {
        for k in f.keys() {
            if !out.contains(&k) {
                out.push(k);
            }
        }
    }
    out
}

/// `fieldsOf()`: the parts of `entry`, which lives in `db` (its attachment pool and custom icons).
pub(crate) fn fields_of(entry: &Entry, db: &Database) -> Fields {
    let mut f = Fields::default();
    for s in &entry.strings {
        // The file marks the standard fields protected by the database's settings, whatever the entry says
        let protect = !is_standard(&s.key) && s.protected;
        f.set(FieldKey::Attribute(s.key.clone()), FieldValue::Attribute { text: s.value.clone(), protect });
    }
    // KeePassXC entries always have the standard attributes (an absent one reads as "")
    for key in STANDARD_FIELDS {
        let k = FieldKey::Attribute(key.to_owned());
        if f.get(&k).is_none() {
            f.set(k, FieldValue::Attribute { text: Zeroizing::new(String::new()), protect: false });
        }
    }
    for r in &entry.binaries {
        let (data, protected) = pool::resolve(db, r);
        f.set(
            FieldKey::Attachment(r.name.clone()),
            FieldValue::Attachment { data: Zeroizing::new(data.to_vec()), protected },
        );
    }
    f.set(FieldKey::Tags, FieldValue::Tags(entry.tags.clone()));
    f.set(FieldKey::Expiry, FieldValue::Expiry(entry.times.expires.then_some(entry.times.expiry)));
    let custom = entry.custom_icon.filter(|id| !id.is_nil());
    let custom = custom.map(|id| (id, db.meta.custom_icons.iter().find(|i| i.uuid == id).cloned()));
    f.set(FieldKey::Icon, FieldValue::Icon { number: entry.icon_id, custom });
    f.set(
        FieldKey::Colors,
        FieldValue::Colors { fg: entry.foreground_color.clone(), bg: entry.background_color.clone() },
    );
    f
}

/// `sameFields()`: equal parts, each entry read in its own database.
pub(crate) fn same_fields(a: &Entry, a_db: &Database, b: &Entry, b_db: &Database) -> bool {
    let fa = fields_of(a, a_db);
    let fb = fields_of(b, b_db);
    fa.len() == fb.len() && fa.0.iter().all(|(k, v)| same_value(Some(v), fb.get(k)))
}

/// `SyncEngine::fieldName()`: the display name of a part (English).
pub(crate) fn field_name(key: &FieldKey) -> String {
    match key {
        FieldKey::Attribute(k) => match k.as_str() {
            "UserName" => "Username".to_owned(),
            other => other.to_owned(),
        },
        FieldKey::Attachment(n) => format!("attachment {n}"),
        FieldKey::Tags => "Tags".to_owned(),
        FieldKey::Expiry => "Expiry".to_owned(),
        FieldKey::Icon => "Icon".to_owned(),
        FieldKey::Colors => "Colors".to_owned(),
    }
}

/// `applyField()`: sets one part of `entry` (in `db`); `None` removes it.
pub(crate) fn apply_field(entry: &mut Entry, db: &mut Database, key: &FieldKey, value: Option<&FieldValue>) {
    match key {
        FieldKey::Attribute(k) => {
            let pos = entry.strings.iter().position(|s| s.key == *k);
            let current_protected = pos.is_some_and(|i| entry.strings[i].protected);
            let Some(FieldValue::Attribute { text, protect }) = value else {
                // The standard fields always exist
                if is_standard(k) {
                    set_string(entry, pos, StringField::new(k.clone(), "", current_protected));
                } else if let Some(i) = pos {
                    entry.strings.remove(i);
                }
                return;
            };
            let protect = if is_standard(k) { current_protected } else { *protect };
            let field = StringField { key: k.clone(), value: text.clone(), protected: protect };
            set_string(entry, pos, field);
        }
        FieldKey::Attachment(name) => {
            let pos = entry.binaries.iter().position(|b| b.name == *name);
            let Some(FieldValue::Attachment { data, protected }) = value else {
                if let Some(i) = pos {
                    entry.binaries.remove(i);
                }
                return;
            };
            let index = pool::intern(db, data, *protected);
            match pos {
                Some(i) => entry.binaries[i].index = index,
                None => entry.binaries.push(ov_kdbx::model::BinaryRef { name: name.clone(), index }),
            }
        }
        FieldKey::Tags => {
            entry.tags = match value {
                Some(FieldValue::Tags(t)) => t.clone(),
                _ => Vec::new(),
            };
        }
        FieldKey::Expiry => {
            let at = match value {
                Some(FieldValue::Expiry(at)) => *at,
                _ => None,
            };
            entry.times.expires = at.is_some();
            if let Some(at) = at {
                entry.times.expiry = at;
            }
        }
        FieldKey::Icon => {
            let Some(FieldValue::Icon { number, custom }) = value else { return };
            match custom {
                Some((id, icon)) => {
                    if let Some(icon) = icon {
                        pool::add_icon(db, icon);
                    }
                    entry.custom_icon = Some(*id);
                }
                None => {
                    entry.custom_icon = None;
                    entry.icon_id = *number;
                }
            }
        }
        FieldKey::Colors => {
            let (fg, bg) = match value {
                Some(FieldValue::Colors { fg, bg }) => (fg.clone(), bg.clone()),
                _ => (String::new(), String::new()),
            };
            entry.foreground_color = fg;
            entry.background_color = bg;
        }
    }
}

fn set_string(entry: &mut Entry, pos: Option<usize>, field: StringField) {
    match pos {
        Some(i) => entry.strings[i] = field,
        None => entry.strings.push(field),
    }
}

/// `resolveFields()`: the three-way merge of the parts. A part one side changed takes that change; one
/// both changed differently takes the newer side's value and is a conflict (its display name).
pub(crate) fn resolve_fields(
    local: (&Entry, &Database),
    remote: (&Entry, &Database),
    base: (&Entry, &Database),
    local_is_newer: bool,
) -> (Fields, Vec<String>) {
    let lf = fields_of(local.0, local.1);
    let rf = fields_of(remote.0, remote.1);
    let bf = fields_of(base.0, base.1);
    let mut merged = Fields::default();
    let mut conflicts = Vec::new();
    for key in union_keys(&[&lf, &rf, &bf]) {
        let (l, r, b) = (lf.get(key), rf.get(key), bf.get(key));
        let v = if same_value(l, r) || same_value(r, b) {
            l
        } else if same_value(l, b) {
            r
        } else {
            conflicts.push(field_name(key));
            if local_is_newer {
                l
            } else {
                r
            }
        };
        if let Some(v) = v {
            merged.0.push((key.clone(), v.clone()));
        }
    }
    (merged, conflicts)
}
