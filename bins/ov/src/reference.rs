//! `ov://` references, ported from `packages/sdk/src/vault/reference.ts` and `items.ts`.
//!
//! A secret reference is `ov://<vault>/[<group>/…]<entry>/<field>`; an item reference drops the
//! field. Segments are percent-decoded.
// TODO(W3-L3): use ov-core's reference parser instead, if the facade exposes one.

use ov_error::{OvError, OvErrorCode};

use crate::js;

const SCHEME: &str = "ov://";

/// `ov://<vault>/[<group>/…]<entry>/<field>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretReference {
    /// Vault id or name.
    pub vault: String,
    /// Groups below the root group.
    pub group_path: Vec<String>,
    /// Entry UUID or unique title.
    pub entry: String,
    /// Field name.
    pub field: String,
}

/// `ov://<vault>/[<group>/…]<entry>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemReference {
    /// Vault id or name.
    pub vault: String,
    /// Groups below the root group.
    pub group_path: Vec<String>,
    /// Entry UUID or unique title.
    pub entry: String,
}

fn segments(r: &str) -> Result<Vec<String>, OvError> {
    let Some(rest) = r.strip_prefix(SCHEME) else {
        return Err(OvError::new(OvErrorCode::InvalidReference, format!("not a ov:// reference: {r}")));
    };
    rest.split('/')
        .map(|p| {
            js::decode_uri_component(p)
                .ok_or_else(|| OvError::new(OvErrorCode::InvalidReference, format!("bad percent-encoding in {r}")))
        })
        .collect()
}

/// `parseReference`.
pub fn parse_reference(r: &str) -> Result<SecretReference, OvError> {
    let mut parts = segments(r)?;
    if parts.len() < 3 || parts.iter().any(String::is_empty) {
        return Err(OvError::new(OvErrorCode::InvalidReference, format!("expected ov://<vault>/<entry>/<field>: {r}")));
    }
    let field = parts.pop().unwrap_or_default();
    let entry = parts.pop().unwrap_or_default();
    let vault = parts.remove(0);
    Ok(SecretReference { vault, group_path: parts, entry, field })
}

/// `parseItemReference`.
pub fn parse_item_reference(r: &str) -> Result<ItemReference, OvError> {
    let mut parts = segments(r)?;
    if parts.len() < 2 || parts.iter().any(String::is_empty) {
        return Err(OvError::new(OvErrorCode::InvalidReference, format!("expected ov://<vault>/<entry>: {r}")));
    }
    let entry = parts.pop().unwrap_or_default();
    let vault = parts.remove(0);
    Ok(ItemReference { vault, group_path: parts, entry })
}

/// `formatReference`.
pub fn format_reference(r: &SecretReference) -> String {
    let all = std::iter::once(&r.vault).chain(&r.group_path).chain([&r.entry, &r.field]);
    let encoded: Vec<String> = all.map(|s| js::encode_uri_component(s)).collect();
    format!("{SCHEME}{}", encoded.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // units.test.ts: "parses ov:// references"
    #[test]
    fn parses_ov_references() {
        assert_eq!(
            parse_reference("ov://Team%20Infra/Deploy/Database/password").unwrap(),
            SecretReference {
                vault: "Team Infra".into(),
                group_path: vec!["Deploy".into()],
                entry: "Database".into(),
                field: "password".into()
            }
        );
        for bad in ["ov://v/e", "ov:/v/e/f", "ov://v//f", "ov://v/e/%E0%A4%A"] {
            assert!(parse_reference(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn item_references_and_formatting() {
        let r = parse_item_reference("ov://v/g/h/e").unwrap();
        assert_eq!(r.group_path, vec!["g", "h"]);
        assert_eq!(r.entry, "e");
        assert_eq!(parse_item_reference("bad").unwrap_err().message, "not a ov:// reference: bad");
        let s = parse_reference("ov://Team%20Infra/a%2Fb/e/f").unwrap();
        assert_eq!(s.group_path, vec!["a/b"]);
        assert_eq!(format_reference(&s), "ov://Team%20Infra/a%2Fb/e/f");
    }
}
