//! The crypto primitives (`ov-crypto::primitives`) for C++. Secret outputs move out of their
//! `Zeroizing` wrapper into the returned `rust::Vec`, which the caller wipes (`ov::wipe`).

use ov_crypto::primitives as prim;
use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::edge::{edge, FfiError};

fn take(mut z: Zeroizing<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *z)
}

fn array<const N: usize>(what: &str, bytes: &[u8]) -> Result<Zeroizing<[u8; N]>, OvError> {
    let arr: [u8; N] = bytes.try_into().map_err(|_| {
        OvError::new(OvErrorCode::InvalidRequest, format!("{what} must be {N} bytes, got {}", bytes.len()))
    })?;
    Ok(Zeroizing::new(arr))
}

/// SHA-256 (`ov::sha256`).
pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    prim::sha256(data).to_vec()
}

/// HKDF-SHA256 (`ov::hkdf_sha256`).
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, FfiError> {
    edge(|| prim::hkdf_sha256(ikm, salt, info, length).map(take))
}

/// XChaCha20-Poly1305 encryption (`ov::aead_encrypt`): 32-byte key, 24-byte nonce.
pub(crate) fn aead_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FfiError> {
    edge(|| {
        let key = array::<{ prim::KEY_BYTES }>("key", key)?;
        let nonce = array::<{ prim::NONCE_BYTES }>("nonce", nonce)?;
        Ok(prim::aead_encrypt(&key, &nonce, plaintext, aad))
    })
}

/// XChaCha20-Poly1305 decryption (`ov::aead_decrypt`); `decryption_failed` on a bad tag.
pub(crate) fn aead_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FfiError> {
    edge(|| {
        let key = array::<{ prim::KEY_BYTES }>("key", key)?;
        let nonce = array::<{ prim::NONCE_BYTES }>("nonce", nonce)?;
        prim::aead_decrypt(&key, &nonce, ciphertext, aad).map(take)
    })
}

/// Argon2id with a 32-byte output (`ov::argon2id`). CPU-bound: call it off the GUI thread.
pub(crate) fn argon2id(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Vec<u8>, FfiError> {
    edge(|| prim::argon2id_32(password, salt, m_kib, t, p).map(take))
}

/// `n` bytes from the platform CSPRNG (`ov::random_bytes`).
pub(crate) fn random_bytes(n: usize) -> Result<Vec<u8>, FfiError> {
    edge(|| prim::random_bytes(n).map(take))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn aead_round_trips_and_checks_lengths() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let ct = aead_encrypt(&key, &nonce, b"hi", b"ad").unwrap();
        assert_eq!(aead_decrypt(&key, &nonce, &ct, b"ad").unwrap(), b"hi");
        assert_eq!(aead_decrypt(&key, &nonce, &ct, b"xx").unwrap_err().0.code, OvErrorCode::DecryptionFailed);
        assert_eq!(aead_encrypt(&key[..31], &nonce, b"", b"").unwrap_err().0.code, OvErrorCode::InvalidRequest);
        let _ = crate::edge::take_last_error();
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
