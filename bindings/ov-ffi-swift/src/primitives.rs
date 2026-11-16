//! `ov-crypto` primitives for Swift (`ov_crypto::primitives`). Byte arrays of the wrong length
//! are `invalid_request`; derived secrets come back as `Data` that the caller wipes.

use ov_crypto::primitives as p;
use ov_error::OvErrorCode;

use crate::error::OvError;
use crate::guard::{guard, guard_ok};

fn array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], ov_error::OvError> {
    bytes
        .try_into()
        .map_err(|_| ov_error::OvError::new(OvErrorCode::InvalidRequest, format!("{what} must be {N} bytes")))
}

/// SHA-256 of `data`.
#[uniffi::export]
pub fn sha256(data: Vec<u8>) -> Result<Vec<u8>, OvError> {
    guard_ok(|| p::sha256(&data).to_vec())
}

/// HKDF-SHA256 (RFC 5869) producing `length` bytes.
#[uniffi::export]
pub fn hkdf_sha256(ikm: Vec<u8>, salt: Vec<u8>, info: Vec<u8>, length: u32) -> Result<Vec<u8>, OvError> {
    guard(|| p::hkdf_sha256(&ikm, &salt, &info, length as usize).map(|k| k.to_vec()))
}

/// XChaCha20-Poly1305 encryption (32-byte key, 24-byte nonce); returns ciphertext + tag.
#[uniffi::export]
pub fn aead_encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, OvError> {
    guard(|| {
        let key = zeroize::Zeroizing::new(array::<{ p::KEY_BYTES }>(&key, "key")?);
        let nonce = array::<{ p::NONCE_BYTES }>(&nonce, "nonce")?;
        Ok(p::aead_encrypt(&key, &nonce, &plaintext, &aad))
    })
}

/// XChaCha20-Poly1305 decryption; `decryption_failed` when the tag doesn't verify.
#[uniffi::export]
pub fn aead_decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, OvError> {
    guard(|| {
        let key = zeroize::Zeroizing::new(array::<{ p::KEY_BYTES }>(&key, "key")?);
        let nonce = array::<{ p::NONCE_BYTES }>(&nonce, "nonce")?;
        p::aead_decrypt(&key, &nonce, &ciphertext, &aad).map(|pt| pt.to_vec())
    })
}

/// Argon2id (v1.3) with a 32-byte output.
#[uniffi::export]
pub fn argon2id32(password: Vec<u8>, salt: Vec<u8>, m_kib: u32, t: u32, p_lanes: u32) -> Result<Vec<u8>, OvError> {
    guard(|| p::argon2id_32(&password, &salt, m_kib, t, p_lanes).map(|k| k.to_vec()))
}

/// `n` bytes from the platform CSPRNG.
#[uniffi::export]
pub fn random_bytes(n: u32) -> Result<Vec<u8>, OvError> {
    guard(|| p::random_bytes(n as usize).map(|b| b.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        let d = sha256(b"abc".to_vec()).unwrap();
        assert_eq!(d[..4], [0xba, 0x78, 0x16, 0xbf]);
    }

    #[test]
    fn aead_round_trip_and_bad_lengths() {
        let ct = aead_encrypt(vec![7; 32], vec![9; 24], b"hi".to_vec(), vec![]).unwrap();
        assert_eq!(aead_decrypt(vec![7; 32], vec![9; 24], ct.clone(), vec![]).unwrap(), b"hi");
        let OvError::Failure { code, .. } = aead_decrypt(vec![8; 32], vec![9; 24], ct, vec![]).unwrap_err();
        assert_eq!(code, crate::OvErrorCode::DecryptionFailed);
        let OvError::Failure { code, .. } = aead_encrypt(vec![7; 31], vec![9; 24], vec![], vec![]).unwrap_err();
        assert_eq!(code, crate::OvErrorCode::InvalidRequest);
    }
}
