//! The SPEC §22 key schedule and envelopes, ported from the TS SDK's `crypto/share.ts`.
//!
//! - link key `K`: 32 random bytes, only ever in the link's fragment
//! - passcode key `P = Argon2id(NFKC(passcode), kdf)` (SPEC §3 parameters)
//! - `content = HKDF(ikm=K, salt=P or empty, info="ov-share-v1")`
//! - `auth = HKDF(ikm=P, salt=empty, info="ov-share-auth-v1")`; the server keeps `SHA-256(auth)`
//! - `ct = wrap(content, pad(JSON(payload)), "ov-share-v1|<id>")`
//! - `ref = b64u(wrap(HKDF(ikm=enc_sk, salt=empty, info="ov-share-ref-v1"), JSON(ref), "ov-share-ref|<id>"))`

use ov_crypto::primitives::{
    aead_decrypt, aead_encrypt, argon2id_32, hkdf_sha256_32, random_key, random_nonce, sha256, KEY_BYTES, NONCE_BYTES,
    SHA256_BYTES, TAG_BYTES,
};
use ov_error::{OvError, OvErrorCode};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::b64::{b64u, decode};
use crate::payload::{IncomingPayload, SharePayload, ShareRef};

/// Length of the link key `K` (bytes).
pub const SHARE_KEY_BYTES: usize = 32;
/// Payloads are padded to a multiple of this many bytes.
pub const SHARE_PAD: usize = 512;
/// The largest `ct` the server takes (bytes).
pub const SHARE_MAX_CT_BYTES: usize = 64 * 1024;
/// SPEC §3: the smallest Argon2id memory (KiB) a client accepts.
pub const KDF_MIN_M: u32 = 19456;
/// SPEC §3: the fewest Argon2id iterations a client accepts.
pub const KDF_MIN_T: u32 = 2;

const WRAP_VERSION: u8 = 0x01;

/// Argon2id parameters, the `Kdf` schema of `openapi.yaml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Always `"argon2id"`.
    pub alg: String,
    /// 16 bytes, base64url.
    pub salt: String,
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

// The same check as the TS `checkKdfParams`; ov-crypto's AUK module (W1-C1) will have one too, and
// the facade can use either once that lands (follow-up).
/// Refuses parameters below the SPEC §3 minimum (`m >= 19456`, `t >= 2`, `p >= 1`) or a stricter
/// server floor (`min = (m, t)`): `weak_kdf`.
pub fn check_kdf_params(kdf: &KdfParams, min: Option<(u32, u32)>) -> Result<(), OvError> {
    let (min_m, min_t) = min.unwrap_or((KDF_MIN_M, KDF_MIN_T));
    if kdf.alg != "argon2id" {
        return Err(OvError::new(OvErrorCode::WeakKdf, format!("unsupported KDF {}", kdf.alg)));
    }
    if kdf.m < min_m || kdf.t < min_t || kdf.p < 1 {
        return Err(OvError::new(
            OvErrorCode::WeakKdf,
            format!("KDF parameters below the minimum (m >= {min_m}, t >= {min_t})"),
        ));
    }
    Ok(())
}

/// The bytes a passcode is stretched from: UTF-8 of its NFKC form, not trimmed (SPEC §3, §22).
pub fn passcode_bytes(passcode: &str) -> Zeroizing<Vec<u8>> {
    let mut normalized: String = passcode.nfkc().collect();
    let out = Zeroizing::new(normalized.as_bytes().to_vec());
    normalized.zeroize();
    out
}

/// `P = Argon2id(NFKC(passcode), kdf)`, 32 bytes. Checks `kdf` against the SPEC §3 minimum unless
/// `allow_weak` (test vectors use `m = 1024`; never set it for server-provided parameters).
pub fn share_passcode_key(
    passcode: &str,
    kdf: &KdfParams,
    allow_weak: bool,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, OvError> {
    if !allow_weak {
        check_kdf_params(kdf, None)?;
    }
    let salt = decode(&kdf.salt, OvErrorCode::WeakKdf, "the KDF salt")?;
    let pw = passcode_bytes(passcode);
    let out = argon2id_32(&pw, &salt, kdf.m, kdf.t, kdf.p)?;
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    key.copy_from_slice(&out);
    Ok(key)
}

/// `content = HKDF(ikm=K, salt=P or empty, info="ov-share-v1")`.
pub fn share_content_key(key: &[u8; SHARE_KEY_BYTES], passcode_key: Option<&[u8; KEY_BYTES]>) -> Zeroizing<[u8; 32]> {
    hkdf_sha256_32(key, passcode_key.map_or(&[][..], |p| &p[..]), b"ov-share-v1")
}

/// `auth = HKDF(ikm=P, salt=empty, info="ov-share-auth-v1")`, sent (base64url) to open a share with a
/// passcode.
pub fn share_auth(passcode_key: &[u8; KEY_BYTES]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256_32(passcode_key, &[], b"ov-share-auth-v1")
}

/// `SHA-256(auth)`, what the server stores.
pub fn share_auth_hash(auth: &[u8]) -> [u8; SHA256_BYTES] {
    sha256(auth)
}

/// `ref_key = HKDF(ikm=enc_sk, salt=empty, info="ov-share-ref-v1")`.
pub fn share_ref_key(enc_sk: &[u8]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256_32(enc_sk, &[], b"ov-share-ref-v1")
}

/// The payload AAD, `ov-share-v1|<id>` (SPEC §22).
pub fn share_aad(share_id: &str) -> String {
    format!("ov-share-v1|{share_id}")
}

/// The owner reference AAD, `ov-share-ref|<id>` (SPEC §22).
pub fn share_ref_aad(share_id: &str) -> String {
    format!("ov-share-ref|{share_id}")
}

/// A fresh random link key `K`.
pub fn new_share_key() -> Result<Zeroizing<[u8; SHARE_KEY_BYTES]>, OvError> {
    random_key()
}

/// `0x80`, then zero bytes up to the next multiple of [`SHARE_PAD`] (always at least one byte added).
pub fn pad_share(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let len = (data.len() + 1).div_ceil(SHARE_PAD) * SHARE_PAD;
    let mut out = Zeroizing::new(vec![0u8; len]);
    out[..data.len()].copy_from_slice(data);
    out[data.len()] = 0x80;
    out
}

/// Strips [`pad_share`] padding; `decryption_failed` when it isn't there.
pub fn unpad_share(padded: &[u8]) -> Result<&[u8], OvError> {
    let end = padded.iter().rposition(|&b| b != 0).ok_or_else(bad_padding)?;
    if padded[end] != 0x80 {
        return Err(bad_padding());
    }
    Ok(&padded[..end])
}

fn bad_padding() -> OvError {
    OvError::new(OvErrorCode::DecryptionFailed, "bad share padding")
}

// The SPEC §4 envelope, implemented here on the frozen primitives so this crate doesn't wait for
// ov-crypto's envelope module (W1-C1). Follow-up: call `ov_crypto` wrap/unwrap once merged.
/// `0x01 ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce, plaintext, aad)`.
fn wrap(key: &[u8; KEY_BYTES], plaintext: &[u8], aad: &str, nonce: &[u8; NONCE_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + NONCE_BYTES + plaintext.len() + TAG_BYTES);
    out.push(WRAP_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&aead_encrypt(key, nonce, plaintext, aad.as_bytes()));
    out
}

fn unwrap(key: &[u8; KEY_BYTES], blob: &[u8], aad: &str) -> Result<Zeroizing<Vec<u8>>, OvError> {
    match blob.first() {
        Some(&WRAP_VERSION) => {}
        Some(v) => {
            return Err(OvError::new(OvErrorCode::UnsupportedVersion, format!("unsupported envelope version {v}")))
        }
        None => return Err(OvError::new(OvErrorCode::UnsupportedVersion, "unsupported envelope version (empty)")),
    }
    if blob.len() < 1 + NONCE_BYTES + TAG_BYTES {
        return Err(OvError::new(OvErrorCode::DecryptionFailed, "envelope too short"));
    }
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&blob[1..1 + NONCE_BYTES]);
    aead_decrypt(key, &nonce, &blob[1 + NONCE_BYTES..], aad.as_bytes()).map_err(|_| {
        OvError::new(OvErrorCode::DecryptionFailed, "decryption failed (wrong key, wrong AAD or corrupted data)")
    })
}

fn to_json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, OvError> {
    serde_json::to_vec(value).map(Zeroizing::new).map_err(|e| OvError::internal(format!("JSON encoding failed: {e}")))
}

/// Encrypts a payload for share `share_id` with a random nonce: `wrap(content, pad(JSON), aad)`.
/// `too_large` when the result is over [`SHARE_MAX_CT_BYTES`].
pub fn encrypt_share_payload(
    key: &[u8; SHARE_KEY_BYTES],
    share_id: &str,
    payload: &SharePayload,
    passcode_key: Option<&[u8; KEY_BYTES]>,
) -> Result<Vec<u8>, OvError> {
    encrypt_share_payload_with_nonce(key, share_id, payload, passcode_key, &random_nonce()?)
}

/// [`encrypt_share_payload`] with a fixed nonce, for test vectors. Never reuse a nonce under one key.
pub fn encrypt_share_payload_with_nonce(
    key: &[u8; SHARE_KEY_BYTES],
    share_id: &str,
    payload: &SharePayload,
    passcode_key: Option<&[u8; KEY_BYTES]>,
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>, OvError> {
    let content = share_content_key(key, passcode_key);
    let padded = pad_share(&to_json(payload)?);
    let ct = wrap(&content, &padded, &share_aad(share_id), nonce);
    if ct.len() > SHARE_MAX_CT_BYTES {
        return Err(OvError::new(OvErrorCode::TooLarge, "this is too much to share in one link"));
    }
    Ok(ct)
}

/// Decrypts a share's `ct`. `decryption_failed` for a wrong key, passcode or id, or broken data;
/// `unsupported_version` when the payload isn't version 1 with a `fields` list.
pub fn decrypt_share_payload(
    key: &[u8; SHARE_KEY_BYTES],
    share_id: &str,
    ct: &[u8],
    passcode_key: Option<&[u8; KEY_BYTES]>,
) -> Result<SharePayload, OvError> {
    let content = share_content_key(key, passcode_key);
    let padded = unwrap(&content, ct, &share_aad(share_id))?;
    IncomingPayload::parse(unpad_share(&padded)?)
}

/// Encrypts the owner's reference to a share (base64url), with a random nonce.
pub fn encrypt_share_ref(enc_sk: &[u8], share_id: &str, reference: &ShareRef) -> Result<String, OvError> {
    encrypt_share_ref_with_nonce(enc_sk, share_id, reference, &random_nonce()?)
}

/// [`encrypt_share_ref`] with a fixed nonce, for test vectors.
pub fn encrypt_share_ref_with_nonce(
    enc_sk: &[u8],
    share_id: &str,
    reference: &ShareRef,
    nonce: &[u8; NONCE_BYTES],
) -> Result<String, OvError> {
    let k = share_ref_key(enc_sk);
    Ok(b64u(&wrap(&k, &to_json(reference)?, &share_ref_aad(share_id), nonce)))
}

/// Decrypts the owner's reference to a share; `decryption_failed` if it can't be read.
pub fn decrypt_share_ref(enc_sk: &[u8], share_id: &str, reference: &str) -> Result<ShareRef, OvError> {
    let k = share_ref_key(enc_sk);
    let blob = decode(reference, OvErrorCode::DecryptionFailed, "the share reference")?;
    let mut plain = unwrap(&k, &blob, &share_ref_aad(share_id))?;
    let parsed = serde_json::from_slice::<ShareRef>(&plain)
        .map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "the share reference isn't readable"));
    plain.zeroize();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_sizes_and_errors() {
        for n in [0usize, 1, 510, 511, 512, 1000] {
            let data = vec![7u8; n];
            let padded = pad_share(&data);
            assert_eq!(padded.len() % SHARE_PAD, 0);
            assert!(padded.len() > n);
            assert_eq!(unpad_share(&padded).unwrap(), &data[..]);
        }
        assert_eq!(unpad_share(&[0u8; 512]).unwrap_err().code, OvErrorCode::DecryptionFailed);
        assert_eq!(unpad_share(&[1, 2, 0]).unwrap_err().code, OvErrorCode::DecryptionFailed);
        assert_eq!(unpad_share(&[]).unwrap_err().code, OvErrorCode::DecryptionFailed);
    }

    #[test]
    fn passcodes_are_nfkc() {
        // "ﬁ" (U+FB01) is "fi" in NFKC; "e" + U+0301 composes to "é"
        assert_eq!(passcode_bytes("\u{fb01}x e\u{301}").as_slice(), "fix \u{e9}".as_bytes());
        assert_eq!(passcode_bytes(" tiger lily 42 ").as_slice(), b" tiger lily 42 ");
    }

    #[test]
    fn kdf_check() {
        let mut kdf = KdfParams { alg: "argon2id".into(), salt: "AAAAAAAAAAAAAAAAAAAAAA".into(), m: 19456, t: 2, p: 1 };
        assert!(check_kdf_params(&kdf, None).is_ok());
        assert_eq!(check_kdf_params(&kdf, Some((65536, 3))).unwrap_err().code, OvErrorCode::WeakKdf);
        kdf.m = 1024;
        assert_eq!(check_kdf_params(&kdf, None).unwrap_err().code, OvErrorCode::WeakKdf);
        assert_eq!(share_passcode_key("pw", &kdf, false).unwrap_err().code, OvErrorCode::WeakKdf);
        kdf.m = 19456;
        kdf.alg = "scrypt".into();
        assert_eq!(check_kdf_params(&kdf, None).unwrap_err().code, OvErrorCode::WeakKdf);
    }

    #[test]
    fn envelope_errors() {
        let key = [1u8; 32];
        let blob = wrap(&key, b"x", "a", &[2u8; 24]);
        assert_eq!(unwrap(&key, &blob, "a").unwrap().as_slice(), b"x");
        assert_eq!(unwrap(&key, &blob, "b").unwrap_err().code, OvErrorCode::DecryptionFailed);
        assert_eq!(unwrap(&key, &[], "a").unwrap_err().code, OvErrorCode::UnsupportedVersion);
        assert_eq!(unwrap(&key, &[2, 0, 0], "a").unwrap_err().code, OvErrorCode::UnsupportedVersion);
        assert_eq!(unwrap(&key, &blob[..20], "a").unwrap_err().code, OvErrorCode::DecryptionFailed);
    }
}
