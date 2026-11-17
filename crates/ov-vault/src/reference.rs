//! Secret references (SPEC §14): `ov://<vault>/[<group>/…]<entry>/<field>`, and without the field
//! an *item* reference to a whole entry.
//!
//! Port of the SDK's `vault/reference.ts` and the reference half of `vault/items.ts`.
//!
//! - Segments are split on `/` and then percent-decoded (UTF-8), so a `/` inside a name is `%2F`.
//!   An empty segment is `invalid_reference`.
//! - Group segments match by exact name, one level at a time from the root group.
//! - `<entry>` is an entry UUID (32 hex digits, with or without dashes, or KDBX base64), or else a
//!   title that exactly one entry under that group has, recursively, outside the Recycle Bin.
//! - `<field>` matches exactly first, then the aliases `title`, `username`/`user`, `password`,
//!   `url`, `notes` (any case), then case-insensitively.
//! - In templates a bare reference runs up to whitespace, a quote, a backtick or `}`
//!   ([`find_references`], [`inject`]).

use ov_error::{OvError, OvErrorCode};
use ov_kdbx::entries::uuid_string;
use ov_kdbx::model::{Database, Entry, Group, Timestamp, Uuid};
use zeroize::Zeroizing;

use crate::items::{set_item_fields, CreateMode, FieldUpdate};

/// The scheme every reference starts with.
pub const SCHEME: &str = "ov://";

/// A parsed `ov://<vault>/[<group>/…]<entry>/<field>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretReference {
    /// Vault id or name.
    pub vault: String,
    /// Group names below the root group.
    pub group_path: Vec<String>,
    /// Entry UUID or title.
    pub entry: String,
    /// Field name or alias.
    pub field: String,
}

/// A parsed `ov://<vault>/[<group>/…]<entry>` (a whole entry, for `ov item` and `ov connect`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ItemReference {
    /// Vault id or name.
    pub vault: String,
    /// Group names below the root group.
    pub group_path: Vec<String>,
    /// Entry UUID or title.
    pub entry: String,
}

impl SecretReference {
    /// The reference without its field.
    pub fn item(&self) -> ItemReference {
        ItemReference { vault: self.vault.clone(), group_path: self.group_path.clone(), entry: self.entry.clone() }
    }
}

fn invalid(msg: String) -> OvError {
    OvError::new(OvErrorCode::InvalidReference, msg)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// JavaScript's `decodeURIComponent`: `%XX` escapes decoded as UTF-8; `None` for a malformed escape
/// or bytes that aren't UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = b.get(i + 1).copied().and_then(hex_val)?;
            let lo = b.get(i + 2).copied().and_then(hex_val)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// JavaScript's `encodeURIComponent`: everything but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` percent-encoded
/// as UTF-8 with uppercase hex.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Splits and decodes the segments after the scheme; `min` is the fewest allowed.
fn segments(r: &str, min: usize, expected: &str) -> Result<Vec<String>, OvError> {
    let rest = r.strip_prefix(SCHEME).ok_or_else(|| invalid(format!("not a ov:// reference: {r}")))?;
    let parts = rest
        .split('/')
        .map(|p| percent_decode(p).ok_or_else(|| invalid(format!("bad percent-encoding in {r}"))))
        .collect::<Result<Vec<_>, _>>()?;
    if parts.len() < min || parts.iter().any(String::is_empty) {
        return Err(invalid(format!("expected {expected}: {r}")));
    }
    Ok(parts)
}

/// Parses `ov://<vault>/[<group>/…]<entry>/<field>`. `invalid_reference` for another scheme, bad
/// percent-encoding, fewer than three segments or an empty one.
pub fn parse_reference(r: &str) -> Result<SecretReference, OvError> {
    let mut parts = segments(r, 3, "ov://<vault>/<entry>/<field>")?;
    let field = parts.pop().unwrap_or_default();
    let entry = parts.pop().unwrap_or_default();
    let vault = parts.remove(0);
    Ok(SecretReference { vault, group_path: parts, entry, field })
}

/// Parses `ov://<vault>/[<group>/…]<entry>`. `invalid_reference` as [`parse_reference`], with at
/// least two segments.
pub fn parse_item_reference(r: &str) -> Result<ItemReference, OvError> {
    let mut parts = segments(r, 2, "ov://<vault>/<entry>")?;
    let entry = parts.pop().unwrap_or_default();
    let vault = parts.remove(0);
    Ok(ItemReference { vault, group_path: parts, entry })
}

/// Formats a reference, percent-encoding each segment.
pub fn format_reference(r: &SecretReference) -> String {
    let segs = std::iter::once(&r.vault).chain(&r.group_path).chain([&r.entry, &r.field]);
    SCHEME.to_owned() + &segs.map(|s| percent_encode(s)).collect::<Vec<_>>().join("/")
}

/// Formats an item reference, percent-encoding each segment.
pub fn format_item_reference(r: &ItemReference) -> String {
    let segs = std::iter::once(&r.vault).chain(&r.group_path).chain([&r.entry]);
    SCHEME.to_owned() + &segs.map(|s| percent_encode(s)).collect::<Vec<_>>().join("/")
}

// ------------------------------------------------------------------------------------- lookup

/// An entry found under a group path, with the names of the groups leading to it (from below the
/// root down to the entry's group).
#[derive(Clone, Copy, Debug)]
pub struct FoundEntry<'a> {
    /// The entry.
    pub entry: &'a Entry,
    /// The groups from below the root down to the entry's group.
    pub group_path: &'a [String],
}

/// A failed lookup: whether it failed because several entries share the title (then creating one
/// would make it worse, so writes refuse to).
pub(crate) struct Lookup {
    pub(crate) error: OvError,
    pub(crate) ambiguous: bool,
}

fn not_found(msg: String) -> Lookup {
    Lookup { error: OvError::new(OvErrorCode::EntryNotFound, msg), ambiguous: false }
}

/// Whether `id` names `entry`: 32 hex digits (dashes ignored) compare the bytes, anything else is
/// compared with the KDBX base64 form.
fn uuid_matches(entry: &Entry, id: &str) -> bool {
    let hex: String = id.chars().filter(|c| *c != '-').collect::<String>().to_ascii_lowercase();
    if hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return entry.uuid.simple().to_string() == hex;
    }
    uuid_string(&entry.uuid) == id
}

/// Every entry under `group` outside the Recycle Bin, with its group path, entries before
/// subgroups (kdbxweb order).
fn entries_under<'a>(
    group: &'a Group,
    path: &mut Vec<String>,
    rb: Option<Uuid>,
    out: &mut Vec<(Vec<String>, &'a Entry)>,
) {
    if Some(group.uuid) == rb {
        return;
    }
    for e in &group.entries {
        out.push((path.clone(), e));
    }
    for g in &group.groups {
        path.push(g.name.clone());
        entries_under(g, path, rb, out);
        path.pop();
    }
}

/// The entry a reference names, with its group path (see [`find_entry`]).
pub(crate) fn locate(db: &Database, group_path: &[String], entry: &str) -> Result<(Vec<String>, Uuid), Lookup> {
    let mut group = &db.root;
    for name in group_path {
        group = group
            .groups
            .iter()
            .find(|g| &g.name == name)
            .ok_or_else(|| not_found(format!("group \"{}\" not found", group_path.join("/"))))?;
    }
    let mut all = Vec::new();
    entries_under(group, &mut group_path.to_vec(), db.meta.recycle_bin_uuid, &mut all);
    if let Some((path, e)) = all.iter().find(|(_, e)| uuid_matches(e, entry)) {
        return Ok((path.clone(), e.uuid));
    }
    let by_title: Vec<&(Vec<String>, &Entry)> = all.iter().filter(|(_, e)| e.title() == entry).collect();
    match by_title.as_slice() {
        [(path, e)] => Ok((path.clone(), e.uuid)),
        [] => Err(not_found(format!("entry \"{entry}\" not found"))),
        many => Err(Lookup {
            error: OvError::new(
                OvErrorCode::EntryNotFound,
                format!("{} entries are titled \"{entry}\"; use the entry UUID", many.len()),
            ),
            ambiguous: true,
        }),
    }
}

/// Finds the entry `entry` (UUID or unique title) under `group_path`, outside the Recycle Bin.
/// Returns it and its full group path. `entry_not_found` for a missing group, no match, or several
/// entries with that title.
pub fn find_entry<'a>(
    db: &'a Database,
    group_path: &[String],
    entry: &str,
) -> Result<(&'a Entry, Vec<String>), OvError> {
    let (path, id) = locate(db, group_path, entry).map_err(|l| l.error)?;
    let e = ov_kdbx::entries::find_entry(&db.root, id)
        .ok_or_else(|| OvError::new(OvErrorCode::EntryNotFound, format!("entry \"{entry}\" not found")))?;
    Ok((e, path))
}

/// The standard field an alias stands for (`title`, `username`, `user`, `password`, `url`,
/// `notes`, any case).
pub fn standard_alias(field: &str) -> Option<&'static str> {
    match field.to_lowercase().as_str() {
        "title" => Some("Title"),
        "username" | "user" => Some("UserName"),
        "password" => Some("Password"),
        "url" => Some("URL"),
        "notes" => Some("Notes"),
        _ => None,
    }
}

/// The name a field reference resolves to on `entry`: an exact match, else the standard field of an
/// alias, else a case-insensitive match, else `field` as given.
pub fn resolve_field_name(entry: &Entry, field: &str) -> String {
    if entry.field(field).is_some() {
        return field.to_owned();
    }
    if let Some(std) = standard_alias(field) {
        return std.to_owned();
    }
    let lower = field.to_lowercase();
    entry.strings.iter().find(|f| f.key.to_lowercase() == lower).map_or_else(|| field.to_owned(), |f| f.key.clone())
}

/// Reads the field a reference names (the reference's vault part is the caller's business).
/// `entry_not_found` when the entry or field doesn't exist.
pub fn read_field(db: &Database, r: &SecretReference) -> Result<Zeroizing<String>, OvError> {
    let (entry, _) = find_entry(db, &r.group_path, &r.entry)?;
    let name = resolve_field_name(entry, &r.field);
    let f = entry
        .field(&name)
        .ok_or_else(|| OvError::new(OvErrorCode::EntryNotFound, format!("field \"{}\" not found", r.field)))?;
    Ok(f.value.clone())
}

/// Sets the field a reference names, keeping history (the old version is pushed first). With
/// `create`, a missing entry is created by title under its group path (groups too). `protect`
/// overrides whether the value is stored protected (default: `Password` and custom fields are).
/// Returns the entry's UUID. Errors as [`find_entry`]; several entries with the title always fail.
pub fn write_field(
    db: &mut Database,
    r: &SecretReference,
    value: &str,
    create: bool,
    protect: Option<bool>,
    now: Timestamp,
) -> Result<Uuid, OvError> {
    let mode = if create { CreateMode::CreateIfMissing } else { CreateMode::MustExist };
    let update = FieldUpdate { name: r.field.clone(), value: Zeroizing::new(value.to_owned()), protected: protect };
    Ok(set_item_fields(db, &r.item(), &[update], mode, now)?.entry_id)
}

// ------------------------------------------------------------------------------------ templates

/// JavaScript's `\s`.
fn js_whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}')
        || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

fn ends_reference(c: char) -> bool {
    js_whitespace(c) || matches!(c, '"' | '\'' | '`' | '}')
}

/// Every reference in a template, in order, as byte ranges: `ov://` and what follows up to
/// whitespace, a quote, a backtick or `}` (the SDK's `REFERENCE_PATTERN`).
pub fn find_references(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(i) = text[pos..].find(SCHEME) {
        let start = pos + i;
        let body = start + SCHEME.len();
        let len = text[body..].find(ends_reference).unwrap_or(text.len() - body);
        if len == 0 {
            pos = start + 1;
        } else {
            out.push(start..body + len);
            pos = body + len;
        }
    }
    out
}

/// A template with its references replaced.
#[derive(Clone, PartialEq, Eq)]
pub struct Injected {
    /// The text with every reference replaced. Wiped on drop.
    pub text: Zeroizing<String>,
    /// The distinct values substituted, in order of first use (for masking output).
    pub secrets: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for Injected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injected").field("secrets", &self.secrets.len()).finish_non_exhaustive()
    }
}

/// Replaces every reference in `template` (`ov inject`, `ov run --env-file`). `resolve` reads one
/// reference; each distinct reference is resolved once, in order of first appearance, and the first
/// error stops it.
pub fn inject(
    template: &str,
    mut resolve: impl FnMut(&str) -> Result<Zeroizing<String>, OvError>,
) -> Result<Injected, OvError> {
    let ranges = find_references(template);
    let mut refs: Vec<&str> = Vec::new();
    let mut values: Vec<Zeroizing<String>> = Vec::new();
    for r in &ranges {
        let s = &template[r.clone()];
        if !refs.contains(&s) {
            values.push(resolve(s)?);
            refs.push(s);
        }
    }
    let mut text = Zeroizing::new(String::with_capacity(template.len()));
    let mut last = 0;
    for r in &ranges {
        text.push_str(&template[last..r.start]);
        let i = refs.iter().position(|x| *x == &template[r.clone()]).unwrap_or_default();
        text.push_str(&values[i]);
        last = r.end;
    }
    text.push_str(&template[last..]);
    Ok(Injected { text, secrets: values })
}
