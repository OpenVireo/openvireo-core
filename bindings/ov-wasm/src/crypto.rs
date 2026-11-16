//! The frozen `ov-crypto` primitives, for the bindings' smoke tests and for JS code that needs
//! the exact same primitives as the core (test servers, vectors).

use ov_crypto::primitives;
use wasm_bindgen::prelude::*;

use crate::error::to_js;

fn array<const N: usize>(b: &[u8], name: &str) -> Result<[u8; N], JsValue> {
    b.try_into().map_err(|_| {
        to_js(&ov_error::OvError::new(
            ov_error::OvErrorCode::InvalidRequest,
            format!("{name}: expected {N} bytes, got {}", b.len()),
        ))
    })
}

/// SHA-256.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    primitives::sha256(data).to_vec()
}

/// HKDF-SHA256 (RFC 5869) with `length` output bytes.
#[wasm_bindgen(js_name = hkdfSha256)]
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, JsValue> {
    primitives::hkdf_sha256(ikm, salt, info, length).map(|k| k.to_vec()).map_err(|e| to_js(&e))
}

/// XChaCha20-Poly1305 encryption: 32-byte key, 24-byte nonce; returns ciphertext ‖ tag.
#[wasm_bindgen(js_name = aeadEncrypt)]
pub fn aead_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key = zeroize::Zeroizing::new(array::<32>(key, "key")?);
    Ok(primitives::aead_encrypt(&key, &array::<24>(nonce, "nonce")?, plaintext, aad))
}

/// XChaCha20-Poly1305 decryption; `decryption_failed` on a wrong key or tampered input.
#[wasm_bindgen(js_name = aeadDecrypt)]
pub fn aead_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key = zeroize::Zeroizing::new(array::<32>(key, "key")?);
    primitives::aead_decrypt(&key, &array::<24>(nonce, "nonce")?, ciphertext, aad)
        .map(|p| p.to_vec())
        .map_err(|e| to_js(&e))
}

/// Argon2id (v0x13), 32-byte output. `m` in KiB.
#[wasm_bindgen]
pub fn argon2id(password: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<Vec<u8>, JsValue> {
    primitives::argon2id_32(password, salt, m, t, p).map(|k| k.to_vec()).map_err(|e| to_js(&e))
}

/// `n` bytes from the platform CSPRNG (`crypto.getRandomValues`).
#[wasm_bindgen(js_name = randomBytes)]
pub fn random_bytes(n: usize) -> Result<Vec<u8>, JsValue> {
    primitives::random_bytes(n).map(|b| b.to_vec()).map_err(|e| to_js(&e))
}
