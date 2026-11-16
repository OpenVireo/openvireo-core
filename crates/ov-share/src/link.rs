//! The link format, `<base>/<id>#<K>` (SPEC §22): a 22-character base64url id and the 32-byte link key
//! as 43 base64url characters in the fragment, which browsers never send to a server.
//!
//! [`parse_share_link`] takes untrusted text (pasted links, QR codes) and returns an error for
//! anything it can't use; it never panics.

use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::b64::{b64u, decode};
use crate::crypto::SHARE_KEY_BYTES;

/// Length of a share id (16 bytes as base64url).
pub const SHARE_ID_CHARS: usize = 22;
/// Length of the link key in a link (32 bytes as base64url).
pub const SHARE_KEY_CHARS: usize = 43;

/// A parsed share link. `Debug` hides the key.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareLinkParts {
    /// Everything before `/<id>`, e.g. `https://share.openvireo.com`.
    pub base: String,
    /// The share id.
    pub id: String,
    /// The link key `K`.
    pub key: Zeroizing<[u8; SHARE_KEY_BYTES]>,
}

impl std::fmt::Debug for ShareLinkParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareLinkParts").field("base", &self.base).field("id", &self.id).finish_non_exhaustive()
    }
}

/// `<base>/<id>#<K>`, with any trailing slashes of `base` removed. The result holds the key.
pub fn share_link(base: &str, share_id: &str, key: &[u8; SHARE_KEY_BYTES]) -> Zeroizing<String> {
    let key = Zeroizing::new(b64u(key));
    Zeroizing::new(format!("{}/{share_id}#{}", base.trim_end_matches('/'), key.as_str()))
}

fn is_b64u_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// What JavaScript's `String.prototype.trim` removes: Unicode white space, line terminators and the
/// byte order mark.
fn js_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// `.` in a JavaScript regex doesn't match line terminators.
fn has_line_terminator(text: &str) -> bool {
    text.contains(['\n', '\r', '\u{2028}', '\u{2029}'])
}

fn incomplete() -> OvError {
    OvError::new(OvErrorCode::InvalidLink, "this isn't a complete share link")
}

fn key_from_text(text: &str) -> Result<Zeroizing<[u8; SHARE_KEY_BYTES]>, OvError> {
    let bytes = decode(text, OvErrorCode::InvalidLink, "the link key")?;
    let mut key = Zeroizing::new([0u8; SHARE_KEY_BYTES]);
    if bytes.len() != SHARE_KEY_BYTES {
        return Err(incomplete());
    }
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Splits a share link into its base, id and key. Matches the TS regex
/// `^(.*)\/([A-Za-z0-9_-]{22})\/?#([A-Za-z0-9_-]{43})$` on the trimmed text; `invalid_link` otherwise.
pub fn parse_share_link(link: &str) -> Result<ShareLinkParts, OvError> {
    let link = js_trim(link);
    let (before, key_text) = link.rsplit_once('#').ok_or_else(incomplete)?;
    if key_text.len() != SHARE_KEY_CHARS || !key_text.bytes().all(is_b64u_char) {
        return Err(incomplete());
    }
    let path = before.strip_suffix('/').unwrap_or(before).as_bytes();
    // `/` then 22 id characters at the end of `path`; all ASCII, so the slices below fall on
    // character boundaries.
    let id_start = path.len().checked_sub(SHARE_ID_CHARS).ok_or_else(incomplete)?;
    let slash = id_start.checked_sub(1).ok_or_else(incomplete)?;
    if path[slash] != b'/' || !path[id_start..].iter().all(|&b| is_b64u_char(b)) {
        return Err(incomplete());
    }
    let base = &before[..slash];
    if has_line_terminator(base) {
        return Err(incomplete());
    }
    let id = &before[id_start..id_start + SHARE_ID_CHARS];
    Ok(ShareLinkParts { base: base.to_string(), id: id.to_string(), key: key_from_text(key_text)? })
}

/// The key from a page's `location.hash` (`#<K>`); `invalid_link` when it is incomplete.
pub fn share_key_from_hash(hash: &str) -> Result<Zeroizing<[u8; SHARE_KEY_BYTES]>, OvError> {
    let text = hash.strip_prefix('#').unwrap_or(hash);
    if text.len() != SHARE_KEY_CHARS || !text.bytes().all(is_b64u_char) {
        return Err(OvError::new(OvErrorCode::InvalidLink, "the link is incomplete"));
    }
    key_from_text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "NV00OunMUMpHjQ03oooedw";

    #[test]
    fn formats_and_parses() {
        let key = [7u8; 32];
        let link = share_link("https://share.example//", ID, &key);
        assert_eq!(link.as_str(), format!("https://share.example/{ID}#{}", b64u(&key)));
        let parts = parse_share_link(&format!("  {}\n", link.as_str())).unwrap();
        assert_eq!((parts.base.as_str(), parts.id.as_str(), *parts.key), ("https://share.example", ID, key));
        // a slash before the fragment is allowed
        let slashed = format!("https://share.example/{ID}/#{}", b64u(&key));
        assert_eq!(parse_share_link(&slashed).unwrap().id, ID);
        // an empty base is allowed, as in the regex
        assert_eq!(parse_share_link(&format!("/{ID}#{}", b64u(&key))).unwrap().base, "");
        assert!(!format!("{parts:?}").contains(&b64u(&key)));
    }

    #[test]
    fn refuses_incomplete_links() {
        let k = "A".repeat(43);
        for bad in [
            format!("https://share.example/{ID}"),
            format!("https://share.example/{ID}#short"),
            format!("https://share.example/{ID}#{k}A"),
            format!("https://share.example/{}#{k}", &ID[1..]),
            format!("https://share.example{ID}#{k}"),
            format!("{ID}#{k}"),
            format!("https://share.example/{ID}//#{k}"),
            format!("https://share.ex\nample/{ID}#{k}"),
            format!("https://share.example/{ID}#{}=", &k[..42]),
            format!("https://share.example/é{}#{k}", &ID[2..]),
            String::new(),
            "#".into(),
        ] {
            assert_eq!(parse_share_link(&bad).unwrap_err().code, OvErrorCode::InvalidLink, "{bad:?}");
        }
    }

    #[test]
    fn key_from_hash() {
        assert_eq!(share_key_from_hash("#").unwrap_err().code, OvErrorCode::InvalidLink);
        assert_eq!(share_key_from_hash(&format!("#{}", "A".repeat(43))).unwrap().len(), 32);
        assert_eq!(share_key_from_hash(&"A".repeat(43)).unwrap().len(), 32);
        assert!(share_key_from_hash(&format!("#{}+", "A".repeat(42))).is_err());
    }
}
