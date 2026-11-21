//! Share-link crypto (SPEC §22) for the platform bindings: the key schedule, padding, payload and owner-reference
//! envelopes on raw bytes, and the link format (task W3-BS2). The facade's `Account.create_share` /
//! `open_share` run the whole flow; these are the pieces the iOS `ShareLink` enum wraps.
//!
//! The payload and reference functions take and return the JSON **bytes**, so a caller keeps
//! its own encoder and the vectors replay byte for byte.

use ov_crypto::envelope;
use ov_crypto::primitives::{random_nonce, NONCE_BYTES};
use ov_error::OvErrorCode;
use ov_share as share;
use zeroize::Zeroizing;

use crate::crypto::{array, secret};
use crate::error::OvError;
use crate::guard::{guard, guard_ok};

type R<T> = Result<T, OvError>;
type CoreResult<T> = Result<T, ov_error::OvError>;

fn link_key(key: &[u8]) -> CoreResult<Zeroizing<[u8; share::SHARE_KEY_BYTES]>> {
    secret::<{ share::SHARE_KEY_BYTES }>(key, "link key")
}

fn passcode(p: Option<Vec<u8>>) -> CoreResult<Option<Zeroizing<[u8; 32]>>> {
    p.map(|p| secret::<32>(&p, "passcode key")).transpose()
}

fn nonce(n: Option<Vec<u8>>) -> CoreResult<[u8; NONCE_BYTES]> {
    match n {
        Some(n) => array::<NONCE_BYTES>(&n, "nonce"),
        None => random_nonce(),
    }
}

fn content_key(key: &[u8], passcode_key: Option<Vec<u8>>) -> CoreResult<Zeroizing<[u8; 32]>> {
    let k = link_key(key)?;
    let p = passcode(passcode_key)?;
    Ok(share::share_content_key(&k, p.as_deref()))
}

/// The padding block (512 bytes).
#[uniffi::export]
pub fn share_pad_block() -> u32 {
    share::SHARE_PAD as u32
}

/// The largest `ct` a share may have (64 KiB).
#[uniffi::export]
pub fn share_max_ciphertext() -> u32 {
    share::SHARE_MAX_CT_BYTES as u32
}

/// A fresh random link key `K` (32 bytes).
#[uniffi::export]
pub fn new_share_key() -> R<Vec<u8>> {
    guard(|| share::new_share_key().map(|k| k.to_vec()))
}

/// `0x80` then zeros up to the next multiple of 512.
#[uniffi::export]
pub fn share_pad(data: Vec<u8>) -> R<Vec<u8>> {
    guard_ok(|| share::pad_share(&data).to_vec())
}

/// Strips [`share_pad`] padding; `decryption_failed` when it isn't there.
#[uniffi::export]
pub fn share_unpad(padded: Vec<u8>) -> R<Vec<u8>> {
    guard(|| share::unpad_share(&padded).map(<[u8]>::to_vec))
}

/// `P = Argon2id(NFKC(passcode), kdf)` (32 bytes). `allow_weak` skips the SPEC floor (vectors only).
#[uniffi::export]
pub fn share_passcode_key(passcode: String, kdf: ov_core::api::KdfParams, allow_weak: bool) -> R<Vec<u8>> {
    guard(|| {
        let kdf = share::KdfParams { alg: kdf.alg, salt: kdf.salt, m: kdf.m, t: kdf.t, p: kdf.p };
        share::share_passcode_key(&passcode, &kdf, allow_weak).map(|k| k.to_vec())
    })
}

/// `content = HKDF(ikm = K, salt = P or empty, "ov-share-v1")`.
#[uniffi::export]
pub fn share_content_key(link_key: Vec<u8>, passcode_key: Option<Vec<u8>>) -> R<Vec<u8>> {
    guard(|| content_key(&link_key, passcode_key).map(|k| k.to_vec()))
}

/// `auth = HKDF(ikm = P, "ov-share-auth-v1")`, sent to open a passcode share.
#[uniffi::export]
pub fn share_auth(passcode_key: Vec<u8>) -> R<Vec<u8>> {
    guard(|| Ok(share::share_auth(&*secret::<32>(&passcode_key, "passcode key")?).to_vec()))
}

/// `SHA-256(auth)`, what the server stores.
#[uniffi::export]
pub fn share_auth_hash(auth: Vec<u8>) -> R<Vec<u8>> {
    guard_ok(|| share::share_auth_hash(&auth).to_vec())
}

/// `ref_key = HKDF(ikm = enc_sk, "ov-share-ref-v1")`.
#[uniffi::export]
pub fn share_ref_key(enc_sk: Vec<u8>) -> R<Vec<u8>> {
    guard_ok(|| share::share_ref_key(&enc_sk).to_vec())
}

/// Encrypts a payload's JSON bytes for share `share_id`: `wrap(content, pad(json),
/// "ov-share-v1|<id>")`. A random nonce unless `nonce` (vectors only). `too_large` over 64 KiB.
#[uniffi::export]
pub fn share_encrypt(
    payload_json: Vec<u8>,
    link_key: Vec<u8>,
    share_id: String,
    passcode_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> R<Vec<u8>> {
    guard(|| {
        let content = content_key(&link_key, passcode_key)?;
        let padded = share::pad_share(&payload_json);
        let ct = envelope::wrap_with_nonce(&content, &padded, &share::share_aad(&share_id), &self::nonce(nonce)?);
        if ct.len() > share::SHARE_MAX_CT_BYTES {
            return Err(ov_error::OvError::new(OvErrorCode::TooLarge, "this is too much to share in one link"));
        }
        Ok(ct)
    })
}

/// Decrypts a share's `ct` to the payload's JSON bytes; `decryption_failed` for a wrong key,
/// passcode or id.
#[uniffi::export]
pub fn share_decrypt(ct: Vec<u8>, link_key: Vec<u8>, share_id: String, passcode_key: Option<Vec<u8>>) -> R<Vec<u8>> {
    guard(|| {
        let content = content_key(&link_key, passcode_key)?;
        let padded = envelope::unwrap(&content, &ct, &share::share_aad(&share_id))?;
        share::unpad_share(&padded).map(<[u8]>::to_vec)
    })
}

/// Encrypts the owner's reference JSON bytes (base64url), AAD `ov-share-ref|<id>`.
#[uniffi::export]
pub fn share_encrypt_ref(
    reference_json: Vec<u8>,
    enc_sk: Vec<u8>,
    share_id: String,
    nonce: Option<Vec<u8>>,
) -> R<String> {
    guard(|| {
        let k = share::share_ref_key(&enc_sk);
        let blob =
            envelope::wrap_with_nonce(&k, &reference_json, &share::share_ref_aad(&share_id), &self::nonce(nonce)?);
        Ok(share::b64u(&blob))
    })
}

/// Decrypts the owner's reference to its JSON bytes; `decryption_failed` if unreadable.
#[uniffi::export]
pub fn share_decrypt_ref(reference: String, enc_sk: Vec<u8>, share_id: String) -> R<Vec<u8>> {
    guard(|| {
        let k = share::share_ref_key(&enc_sk);
        let blob = share::from_b64u(&reference).map_err(|_| {
            ov_error::OvError::new(OvErrorCode::DecryptionFailed, "the share reference isn't base64url")
        })?;
        envelope::unwrap(&k, &blob, &share::share_ref_aad(&share_id)).map(|p| p.to_vec())
    })
}

/// A parsed share link. `key` is the secret link key: wipe it.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareLinkParts {
    /// Everything before `/<id>`.
    pub base: String,
    /// The share id (22 characters).
    pub id: String,
    /// The link key `K`.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for ShareLinkParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareLinkParts").field("base", &self.base).field("id", &self.id).finish_non_exhaustive()
    }
}

/// `<base>/<id>#<K>` (trailing slashes of `base` removed). Holds the key.
#[uniffi::export]
pub fn share_link(base: String, share_id: String, link_key: Vec<u8>) -> R<String> {
    guard(|| Ok(share::share_link(&base, &share_id, &*self::link_key(&link_key)?).to_string()))
}

/// Splits a share link; `invalid_link` when it isn't complete.
#[uniffi::export]
pub fn parse_share_link(link: String) -> R<ShareLinkParts> {
    guard(|| {
        let p = share::parse_share_link(&link)?;
        Ok(ShareLinkParts { base: p.base.clone(), id: p.id.clone(), key: p.key.to_vec() })
    })
}

/// The key from a page's `#<K>`; `invalid_link` when incomplete.
#[uniffi::export]
pub fn share_key_from_hash(hash: String) -> R<Vec<u8>> {
    guard(|| share::share_key_from_hash(&hash).map(|k| k.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ov_testkit::{b64u, hex_bytes};

    #[test]
    fn share_vectors() {
        let v: serde_json::Value = ov_testkit::load_json("test-vectors.json");
        for c in v["share"]["cases"].as_array().unwrap() {
            let key = b64u(c["key"].as_str().unwrap());
            let id = c["id"].as_str().unwrap().to_string();
            let p = c.get("passcode_key_hex").map(|h| hex_bytes(h.as_str().unwrap()));
            let payload = c["payload"].as_str().unwrap().as_bytes().to_vec();
            let ct = share_encrypt(
                payload.clone(),
                key.clone(),
                id.clone(),
                p.clone(),
                Some(hex_bytes(c["nonce_hex"].as_str().unwrap())),
            )
            .unwrap();
            assert_eq!(ov_crypto::encoding::b64u(&ct), c["ct"].as_str().unwrap());
            assert_eq!(share_decrypt(ct, key, id, p).unwrap(), payload);
        }
        let r = &v["share"]["ref"];
        let sk = hex_bytes(r["owner_enc_sk_hex"].as_str().unwrap());
        let id = r["share_id"].as_str().unwrap().to_string();
        let enc = share_encrypt_ref(
            r["plaintext"].as_str().unwrap().as_bytes().to_vec(),
            sk.clone(),
            id.clone(),
            Some(hex_bytes(r["nonce_hex"].as_str().unwrap())),
        )
        .unwrap();
        assert_eq!(enc, r["ref"].as_str().unwrap());
        assert_eq!(share_decrypt_ref(enc, sk, id).unwrap(), r["plaintext"].as_str().unwrap().as_bytes());
    }
}
