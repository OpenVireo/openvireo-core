//! Opening a share link without an account (SPEC §22), the TS `openShare` minus HTTP.
//!
//! The facade fetches `GET {api}/public/shares/{id}` (the KDF, if the share has a passcode), builds a
//! [`ShareOpen`], sends [`ShareOpen::request_body`] to `POST {api}/public/shares/{id}/open`, and hands
//! the returned `ct` to [`ShareOpen::decrypt_b64u`].

use ov_crypto::primitives::KEY_BYTES;
use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::b64::{b64u, decode};
use crate::crypto::{check_kdf_params, decrypt_share_payload, share_auth, share_passcode_key, KdfParams, KDF_MIN};
use crate::link::{parse_share_link, ShareLinkParts};
use crate::payload::SharePayload;

/// A share link ready to open: its key, and the passcode key and `auth` value when it has a
/// passcode. `Debug` hides the keys.
pub struct ShareOpen {
    link: ShareLinkParts,
    passcode_key: Option<Zeroizing<[u8; KEY_BYTES]>>,
    auth: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ShareOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareOpen").field("link", &self.link).field("passcode", &self.auth.is_some()).finish()
    }
}

impl ShareOpen {
    /// Prepares to open `link`. `kdf` is the `kdf` of the share's public info (`None` when it has no
    /// passcode). With a KDF: `passcode_required` when `passcode` is missing or empty, `weak_kdf`
    /// below the SPEC §3 minimum. The Argon2id work happens here.
    pub fn new(link: ShareLinkParts, kdf: Option<&KdfParams>, passcode: Option<&str>) -> Result<Self, OvError> {
        let Some(kdf) = kdf else { return Ok(ShareOpen { link, passcode_key: None, auth: None }) };
        let passcode = passcode
            .filter(|p| !p.is_empty())
            .ok_or_else(|| OvError::new(OvErrorCode::PasscodeRequired, "this link needs a passcode"))?;
        check_kdf_params(kdf, KDF_MIN)?;
        let passcode_key = share_passcode_key(passcode, kdf, false)?;
        let auth = Zeroizing::new(b64u(&share_auth(&passcode_key)[..]));
        Ok(ShareOpen { link, passcode_key: Some(passcode_key), auth: Some(auth) })
    }

    /// [`new`](Self::new) from the link text.
    pub fn from_link(link: &str, kdf: Option<&KdfParams>, passcode: Option<&str>) -> Result<Self, OvError> {
        Self::new(parse_share_link(link)?, kdf, passcode)
    }

    /// The share id.
    pub fn id(&self) -> &str {
        &self.link.id
    }

    /// The parsed link.
    pub fn link(&self) -> &ShareLinkParts {
        &self.link
    }

    /// `auth` (base64url) when the share has a passcode.
    pub fn auth(&self) -> Option<&str> {
        self.auth.as_deref().map(String::as_str)
    }

    /// The JSON body of `POST …/open`: `{"auth":"…"}` with a passcode, else `{}`.
    pub fn request_body(&self) -> Zeroizing<String> {
        Zeroizing::new(match self.auth() {
            Some(a) => format!("{{\"auth\":\"{a}\"}}"),
            None => "{}".to_string(),
        })
    }

    /// Decrypts the share's `ct` bytes.
    pub fn decrypt(&self, ct: &[u8]) -> Result<SharePayload, OvError> {
        decrypt_share_payload(&self.link.key, &self.link.id, ct, self.passcode_key.as_deref())
    }

    /// Decrypts the share's `ct` as the server sends it (base64url).
    pub fn decrypt_b64u(&self, ct: &str) -> Result<SharePayload, OvError> {
        self.decrypt(&decode(ct, OvErrorCode::DecryptionFailed, "the share content")?)
    }
}

/// Opens a share in one step from its link, the public info's `kdf`, the passcode and the fetched
/// `ct` (base64url). For callers that already have the blob; the facade uses [`ShareOpen`] so it can
/// send `auth` first.
pub fn open_share(
    link: &str,
    kdf: Option<&KdfParams>,
    passcode: Option<&str>,
    ct_b64u: &str,
) -> Result<SharePayload, OvError> {
    ShareOpen::from_link(link, kdf, passcode)?.decrypt_b64u(ct_b64u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_share_payload, new_share_key};
    use crate::link::share_link;
    use crate::payload::text_share_payload;

    #[test]
    fn opens_without_a_passcode() {
        let key = new_share_key().unwrap();
        let id = "AAAAAAAAAAAAAAAAAAAAAA";
        let ct = encrypt_share_payload(&key, id, &text_share_payload("hi", None, None), None).unwrap();
        let link = share_link("https://s.example", id, &key);
        let open = ShareOpen::from_link(&link, None, None).unwrap();
        assert_eq!(open.request_body().as_str(), "{}");
        assert_eq!(open.decrypt(&ct).unwrap().fields[0].value, "hi");
        assert!(!format!("{open:?}").contains(&b64u(&key[..])));
    }

    #[test]
    fn needs_a_passcode_and_a_strong_kdf() {
        let link = share_link("https://s.example", "AAAAAAAAAAAAAAAAAAAAAA", &[1u8; 32]);
        let kdf = KdfParams { alg: "argon2id".into(), salt: "AAAAAAAAAAAAAAAAAAAAAA".into(), m: 1024, t: 2, p: 1 };
        for pc in [None, Some("")] {
            assert_eq!(ShareOpen::from_link(&link, Some(&kdf), pc).unwrap_err().code, OvErrorCode::PasscodeRequired);
        }
        assert_eq!(ShareOpen::from_link(&link, Some(&kdf), Some("pw")).unwrap_err().code, OvErrorCode::WeakKdf);
        assert_eq!(ShareOpen::from_link("nope", None, None).unwrap_err().code, OvErrorCode::InvalidLink);
    }
}
