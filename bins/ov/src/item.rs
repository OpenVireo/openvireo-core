//! Whole entries ("items") as the TS CLI prints them: `itemOf` and `listItems` from
//! `packages/sdk/src/vault/items.ts`, and `JSON.stringify(x, null, 2)` with the TS key order.

use ov_core::api::{EntryRecord, EntrySummary, ShareListing};
use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Serialize, Serializer};

use crate::plan::iso_from_unix_s;
use crate::source::VaultSummary;

/// The TS `Item`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Entry UUID, 32 lowercase hex digits.
    pub id: String,
    /// `Title`.
    pub title: String,
    /// Group names from below the root down to the entry's group.
    pub group: Vec<String>,
    /// Field values in entry order; protected ones only with `reveal`.
    pub fields: Vec<(String, String)>,
    /// Names of protected fields.
    pub protected: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Last modification, ISO 8601.
    pub updated_at: String,
}

impl Item {
    /// `group/…/title`.
    pub fn path(&self) -> String {
        let mut parts = self.group.clone();
        parts.push(self.title.clone());
        parts.join("/")
    }
}

/// `itemOf(entry, { reveal })`.
pub fn item_of(e: &EntryRecord, reveal: bool) -> Item {
    let mut fields = Vec::new();
    let mut protected = Vec::new();
    let mut title = String::new();
    for f in &e.fields {
        let value = String::from_utf8_lossy(&f.value).into_owned();
        if f.name == "Title" {
            title = value.clone();
        }
        if f.protected {
            protected.push(f.name.clone());
        }
        if !f.protected || reveal {
            fields.push((f.name.clone(), value));
        }
    }
    Item {
        id: e.id.clone(),
        title,
        group: e.group_path.clone(),
        fields,
        protected,
        tags: e.tags.clone(),
        updated_at: iso_from_unix_s(e.modified_at),
    }
}

/// `itemOf(entry, { values: false })` for `listItems`.
pub fn item_of_summary(e: &EntrySummary) -> Item {
    Item {
        id: e.id.clone(),
        title: e.title.clone(),
        group: e.group_path.clone(),
        fields: Vec::new(),
        protected: e.protected_fields.clone(),
        tags: e.tags.clone(),
        updated_at: iso_from_unix_s(e.modified_at),
    }
}

struct Fields<'a>(&'a [(String, String)]);

impl Serialize for Fields<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl Serialize for Item {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Item", 7)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("title", &self.title)?;
        st.serialize_field("group", &self.group)?;
        st.serialize_field("fields", &Fields(&self.fields))?;
        st.serialize_field("protected", &self.protected)?;
        st.serialize_field("tags", &self.tags)?;
        st.serialize_field("updatedAt", &self.updated_at)?;
        st.end()
    }
}

impl Serialize for VaultSummary {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("VaultSummary", 3)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("role", &self.role)?;
        st.end()
    }
}

/// A share link as the TS `ShareListing` JSON.
pub struct ShareJson<'a>(pub &'a ShareListing);

impl Serialize for ShareJson<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Ref<'a> {
            vault: &'a Option<String>,
            entry: &'a Option<String>,
            title: &'a str,
        }
        let l = self.0;
        let mut st = s.serialize_struct("ShareListing", 12)?;
        st.serialize_field("id", &l.id)?;
        st.serialize_field("vaultId", &l.vault_id)?;
        st.serialize_field(
            "ref",
            &l.reference.as_ref().map(|r| Ref { vault: &r.vault, entry: &r.entry, title: &r.title }),
        )?;
        st.serialize_field("passcode", &l.passcode)?;
        st.serialize_field("maxOpens", &l.max_opens)?;
        st.serialize_field("opens", &l.opens)?;
        st.serialize_field("openedAt", &l.opened_at)?;
        st.serialize_field("createdAt", &l.created_at)?;
        st.serialize_field("expiresAt", &l.expires_at)?;
        st.serialize_field("status", &l.status)?;
        st.serialize_field("endedAt", &l.ended_at)?;
        st.serialize_field("endReason", &l.end_reason)?;
        st.end()
    }
}

/// `JSON.stringify(value, null, 2) + "\n"`.
pub fn json<T: Serialize + ?Sized>(value: &T) -> String {
    let mut s = serde_json::to_string_pretty(value).unwrap_or_default();
    s.push('\n');
    s
}

/// `ov item get` without `--json`: the path and id, then every field (protected ones as
/// `<concealed>` unless revealed).
pub fn describe(item: &Item) -> String {
    let mut out = format!("{}  ({})\n", item.path(), item.id);
    let mut names: Vec<&str> = item.fields.iter().map(|(k, _)| k.as_str()).collect();
    for p in &item.protected {
        if !names.contains(&p.as_str()) {
            names.push(p);
        }
    }
    for name in names {
        let value = item.fields.iter().find(|(k, _)| k == name).map_or("<concealed>", |(_, v)| v.as_str());
        out.push_str(&format!("  {name}: {value}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> Item {
        Item {
            id: "ab".into(),
            title: "GitHub".into(),
            group: vec!["Deploy".into()],
            fields: vec![("Title".into(), "GitHub".into()), ("UserName".into(), "ci".into())],
            protected: vec!["Password".into()],
            tags: vec![],
            updated_at: iso_from_unix_s(1_794_700_800),
        }
    }

    #[test]
    fn prints_like_json_stringify() {
        assert_eq!(
            json(&item()),
            "{\n  \"id\": \"ab\",\n  \"title\": \"GitHub\",\n  \"group\": [\n    \"Deploy\"\n  ],\n  \"fields\": {\n    \"Title\": \"GitHub\",\n    \"UserName\": \"ci\"\n  },\n  \"protected\": [\n    \"Password\"\n  ],\n  \"tags\": [],\n  \"updatedAt\": \"2026-11-15T00:00:00.000Z\"\n}\n"
        );
        assert_eq!(json::<[Item]>(&[]), "[]\n");
    }

    #[test]
    fn describes_an_item() {
        assert_eq!(
            describe(&item()),
            "Deploy/GitHub  (ab)\n  Title: GitHub\n  UserName: ci\n  Password: <concealed>\n"
        );
    }
}
