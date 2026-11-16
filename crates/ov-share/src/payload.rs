//! What a share link holds (SPEC §22), the owner's reference to it, and how an entry becomes a
//! payload. Ported from the TS SDK's `crypto/share.ts` types and `share/index.ts` builders.
//!
//! The JSON is byte-for-byte what the TS SDK's `JSON.stringify` writes (keys in this order, absent
//! optional keys left out), so a payload encrypts to the SPEC vectors.

use ov_error::{OvError, OvErrorCode};
use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::totp::entry_totp_uri;

/// What a share link holds. Pages render every value as plain text.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SharePayload {
    /// Format version, 1.
    pub v: u32,
    /// `entry` or `text`.
    pub kind: String,
    /// The title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Chosen by the sender and shown as such.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_by: Option<String>,
    /// The fields.
    pub fields: Vec<ShareField>,
}

impl std::fmt::Debug for SharePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharePayload")
            .field("v", &self.v)
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("shared_by", &self.shared_by)
            .field("fields", &self.fields)
            .finish()
    }
}

/// One field of a [`SharePayload`]. The value is wiped on drop; `Debug` hides it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareField {
    /// `username`, `password`, `url`, `notes`, `totp`, `custom` or `text` (open set).
    #[serde(default)]
    pub k: String,
    /// The label to show.
    #[serde(default)]
    pub label: String,
    /// The value.
    #[serde(default)]
    pub value: String,
    /// Hidden until shown.
    #[serde(default, skip_serializing_if = "is_false")]
    pub protected: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Drop for ShareField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for ShareField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareField")
            .field("k", &self.k)
            .field("label", &self.label)
            .field("protected", &self.protected)
            .finish_non_exhaustive()
    }
}

/// Which item a share came from, readable only by its owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRef {
    /// The vault id, or `null`.
    pub vault: Option<String>,
    /// KDBX UUID, 32 lowercase hex characters, or `null`.
    pub entry: Option<String>,
    /// The title when shared.
    #[serde(default)]
    pub title: String,
}

/// A decrypted payload, read leniently as the TS SDK does: it checks `v == 1` and that `fields` is a
/// list, and nothing more.
#[derive(Deserialize)]
pub(crate) struct IncomingPayload {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    shared_by: Option<String>,
    fields: Vec<ShareField>,
}

/// The parts of a payload that decide whether this client can read it.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    v: Option<serde_json::Value>,
    #[serde(default)]
    fields: IsList,
}

/// Whether a JSON value is a list, without keeping its contents.
#[derive(Default)]
struct IsList(bool);

impl<'de> Deserialize<'de> for IsList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = IsList;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<IsList, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(IsList(true))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<IsList, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(IsList(false))
            }
            fn visit_bool<E>(self, _: bool) -> Result<IsList, E> {
                Ok(IsList(false))
            }
            fn visit_i64<E>(self, _: i64) -> Result<IsList, E> {
                Ok(IsList(false))
            }
            fn visit_u64<E>(self, _: u64) -> Result<IsList, E> {
                Ok(IsList(false))
            }
            fn visit_f64<E>(self, _: f64) -> Result<IsList, E> {
                Ok(IsList(false))
            }
            fn visit_str<E>(self, _: &str) -> Result<IsList, E> {
                Ok(IsList(false))
            }
            fn visit_unit<E>(self) -> Result<IsList, E> {
                Ok(IsList(false))
            }
        }
        d.deserialize_any(V)
    }
}

impl IncomingPayload {
    /// Parses decrypted, unpadded payload JSON. `unsupported_version` when it isn't a version 1
    /// payload with a `fields` list (or its fields aren't text); `decryption_failed` when it isn't
    /// JSON at all.
    pub(crate) fn parse(json: &[u8]) -> Result<SharePayload, OvError> {
        let unsupported = || OvError::new(OvErrorCode::UnsupportedVersion, "unsupported share payload");
        let probe: Probe = serde_json::from_slice(json).map_err(|e| match e.classify() {
            serde_json::error::Category::Data => unsupported(),
            _ => OvError::new(OvErrorCode::DecryptionFailed, "the share payload isn't JSON"),
        })?;
        if probe.v.as_ref().and_then(serde_json::Value::as_f64) != Some(1.0) || !probe.fields.0 {
            return Err(unsupported());
        }
        let p: IncomingPayload = serde_json::from_slice(json).map_err(|_| unsupported())?;
        Ok(SharePayload { v: 1, kind: p.kind, title: p.title, shared_by: p.shared_by, fields: p.fields })
    }
}

/// A string field of an entry, as the vault reads it (protected values revealed). The value is wiped
/// on drop; `Debug` hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct EntryField {
    /// The KeePass field name (`Title`, `UserName`, `Password`, `URL`, `Notes`, `otp`, or custom).
    pub name: String,
    /// The value.
    pub value: String,
    /// Protected in the entry.
    pub protected: bool,
}

impl EntryField {
    /// A field.
    pub fn new(name: impl Into<String>, value: impl Into<String>, protected: bool) -> Self {
        EntryField { name: name.into(), value: value.into(), protected }
    }
}

impl Drop for EntryField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for EntryField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryField")
            .field("name", &self.name)
            .field("protected", &self.protected)
            .finish_non_exhaustive()
    }
}

/// A field an entry can share: `name` is the KeePass field name (`otp` stands for the entry's TOTP
/// however it is stored) and `field` what it becomes in a payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareableField {
    /// The KeePass field name.
    pub name: String,
    /// The payload field.
    pub field: ShareField,
}

/// Fields an item shares by default; the rest are opt-in.
pub const DEFAULT_SHARE_FIELDS: [&str; 3] = ["UserName", "Password", "URL"];

/// [`DEFAULT_SHARE_FIELDS`] as owned strings.
pub fn default_share_fields() -> Vec<String> {
    DEFAULT_SHARE_FIELDS.iter().map(|s| s.to_string()).collect()
}

/// The standard fields in display order, with their share kind and label.
const STANDARD: [(&str, &str, &str); 4] = [
    ("UserName", "username", "Username"),
    ("Password", "password", "Password"),
    ("URL", "url", "Website"),
    ("Notes", "notes", "Notes"),
];

/// KeePass fields that hold TOTP settings, shared together as one `totp` field named `otp`.
const TOTP_FIELDS: [&str; 3] = ["otp", "TOTP Seed", "TOTP Settings"];

fn field<'a>(fields: &'a [EntryField], name: &str) -> Option<&'a EntryField> {
    fields.iter().find(|f| f.name == name)
}

/// The fields of an entry a user can choose to share, in display order: the standard ones, the TOTP
/// (as an `otpauth://` URI), then custom fields. Empty fields are left out. Needs revealed values.
pub fn shareable_fields(fields: &[EntryField]) -> Vec<ShareableField> {
    let mut out = Vec::new();
    for (name, k, label) in STANDARD {
        if let Some(f) = field(fields, name).filter(|f| !f.value.is_empty()) {
            let protected = f.protected || name == "Password";
            out.push(ShareableField {
                name: name.to_string(),
                field: ShareField { k: k.into(), label: label.into(), value: f.value.clone(), protected },
            });
        }
    }
    let title = field(fields, "Title").map(|f| f.value.as_str()).filter(|t| !t.is_empty()).unwrap_or("OpenVireo");
    if let Some(uri) = entry_totp_uri(fields, title) {
        out.push(ShareableField {
            name: "otp".into(),
            field: ShareField {
                k: "totp".into(),
                label: "One-time code".into(),
                value: uri.to_string(),
                protected: true,
            },
        });
    }
    for f in fields {
        let name = f.name.as_str();
        if name == "Title"
            || STANDARD.iter().any(|(n, _, _)| *n == name)
            || TOTP_FIELDS.contains(&name)
            || f.value.is_empty()
        {
            continue;
        }
        out.push(ShareableField {
            name: name.to_string(),
            field: ShareField {
                k: "custom".into(),
                label: name.into(),
                value: f.value.clone(),
                protected: f.protected,
            },
        });
    }
    out
}

/// A payload for the chosen fields of an entry (names as in [`shareable_fields`]), in display order.
pub fn item_share_payload(fields: &[EntryField], names: &[String], shared_by: Option<&str>) -> SharePayload {
    let chosen = shareable_fields(fields).into_iter().filter(|f| names.contains(&f.name)).map(|f| f.field.clone());
    SharePayload {
        v: 1,
        kind: "entry".into(),
        title: Some(field(fields, "Title").map(|f| f.value.clone()).unwrap_or_default()),
        shared_by: shared_by.filter(|s| !s.is_empty()).map(str::to_string),
        fields: chosen.collect(),
    }
}

/// A payload for some text. An empty title or sender is left out.
pub fn text_share_payload(text: &str, title: Option<&str>, shared_by: Option<&str>) -> SharePayload {
    SharePayload {
        v: 1,
        kind: "text".into(),
        title: title.filter(|s| !s.is_empty()).map(str::to_string),
        shared_by: shared_by.filter(|s| !s.is_empty()).map(str::to_string),
        fields: vec![ShareField { k: "text".into(), label: "Text".into(), value: text.to_string(), protected: false }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> Vec<EntryField> {
        vec![
            EntryField::new("Title", "Office Wi-Fi", false),
            EntryField::new("UserName", "guest", false),
            EntryField::new("Password", "pw", true),
            EntryField::new("URL", "https://x", false),
            EntryField::new("Notes", "", false),
            EntryField::new("PIN", "1234", true),
            EntryField::new("otp", "otpauth://totp/a?secret=JBSWY3DP", true),
        ]
    }

    #[test]
    fn lists_what_can_be_shared_in_order() {
        let got: Vec<_> = shareable_fields(&item())
            .into_iter()
            .map(|f| (f.name.clone(), f.field.k.clone(), f.field.protected))
            .collect();
        let want = [
            ("UserName", "username", false),
            ("Password", "password", true),
            ("URL", "url", false),
            ("otp", "totp", true),
            ("PIN", "custom", true),
        ];
        assert_eq!(got, want.map(|(a, b, c)| (a.to_string(), b.to_string(), c)));
    }

    #[test]
    fn builds_payloads() {
        let p = item_share_payload(&item(), &["Password".into(), "PIN".into()], Some("Sam"));
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"v":1,"kind":"entry","title":"Office Wi-Fi","shared_by":"Sam","fields":[{"k":"password","label":"Password","value":"pw","protected":true},{"k":"custom","label":"PIN","value":"1234","protected":true}]}"#
        );
        let t = text_share_payload("hi", None, Some(""));
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            r#"{"v":1,"kind":"text","fields":[{"k":"text","label":"Text","value":"hi"}]}"#
        );
        assert_eq!(default_share_fields(), ["UserName", "Password", "URL"]);
        assert!(!format!("{p:?}").contains("1234"));
    }

    #[test]
    fn parses_leniently_but_checks_the_version() {
        let ok = IncomingPayload::parse(
            br#"{"v":1.0,"kind":"text","fields":[{"k":"text","value":"x","extra":1}],"more":{}}"#,
        )
        .unwrap();
        assert_eq!((ok.v, ok.fields[0].label.as_str(), ok.fields[0].value.as_str()), (1, "", "x"));
        for (json, code) in [
            (&br#"{"v":2,"fields":[]}"#[..], OvErrorCode::UnsupportedVersion),
            (br#"{"v":1,"fields":{}}"#, OvErrorCode::UnsupportedVersion),
            (br#"{"v":"1","fields":[]}"#, OvErrorCode::UnsupportedVersion),
            (br#"{"fields":[]}"#, OvErrorCode::UnsupportedVersion),
            (br#"{"v":1,"fields":[{"value":5}]}"#, OvErrorCode::UnsupportedVersion),
            (br#"[1]"#, OvErrorCode::UnsupportedVersion),
            (br#"null"#, OvErrorCode::UnsupportedVersion),
            (b"not json", OvErrorCode::DecryptionFailed),
        ] {
            assert_eq!(IncomingPayload::parse(json).unwrap_err().code, code, "{}", String::from_utf8_lossy(json));
        }
    }
}
