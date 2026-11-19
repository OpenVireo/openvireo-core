//! The `ov-crypto` primitives (SPEC §1): SHA-256, HKDF, the AEAD, Argon2 and the CSPRNG. In both
//! modules (shared with `bindings/ov-wasm-lite`). X25519/Ed25519 are in `curves.rs` (full module only:
//! the share page doesn't need them, and they are ~15% of the lite module).
//!
//! Secret arguments are owned and wiped after use; outputs are fresh `Uint8Array`s (see
//! `convert`, "Secrets in linear memory").

use js_sys::Uint8Array;
use ov_crypto::primitives;
use ov_error::OvError;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::convert::{arg, array, field, fixed, out, FromJs};
use crate::error::{arg_err, to_js};

/// `Result<Uint8Array, OvError>` → the export's result.
pub(crate) fn bytes_out(r: Result<impl AsRef<[u8]>, OvError>) -> Result<Uint8Array, JsValue> {
    r.map(|b| out(b.as_ref())).map_err(|e| to_js(&e))
}

/// SHA-256.
#[wasm_bindgen]
pub fn sha256(data: Vec<u8>) -> Uint8Array {
    let data = Zeroizing::new(data);
    out(&primitives::sha256(&data))
}

/// HKDF-SHA256 (RFC 5869) with `length` output bytes (at most 8160).
#[wasm_bindgen(js_name = hkdfSha256)]
pub fn hkdf_sha256(ikm: Vec<u8>, salt: &[u8], info: &[u8], length: usize) -> Result<Uint8Array, JsValue> {
    let ikm = Zeroizing::new(ikm);
    bytes_out(primitives::hkdf_sha256(&ikm, salt, info, length))
}

/// XChaCha20-Poly1305 encryption: 32-byte key, 24-byte nonce; returns ciphertext ‖ tag.
#[wasm_bindgen(js_name = aeadEncrypt)]
pub fn aead_encrypt(key: Vec<u8>, nonce: &[u8], plaintext: Vec<u8>, aad: &[u8]) -> Result<Uint8Array, JsValue> {
    let (key, plaintext) = (Zeroizing::new(key), Zeroizing::new(plaintext));
    let key = fixed::<32>(&key, "key").map_err(arg_err)?;
    let nonce = array::<24>(nonce, "nonce").map_err(arg_err)?;
    Ok(out(&primitives::aead_encrypt(&key, &nonce, &plaintext, aad)))
}

/// XChaCha20-Poly1305 decryption; `decryption_failed` on a wrong key or tampered input.
#[wasm_bindgen(js_name = aeadDecrypt)]
pub fn aead_decrypt(key: Vec<u8>, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Uint8Array, JsValue> {
    let key = Zeroizing::new(key);
    let key = fixed::<32>(&key, "key").map_err(arg_err)?;
    let nonce = array::<24>(nonce, "nonce").map_err(arg_err)?;
    bytes_out(primitives::aead_decrypt(&key, &nonce, ciphertext, aad))
}

/// Argon2id (v0x13), 32-byte output. `m` in KiB.
#[wasm_bindgen]
pub fn argon2id(password: Vec<u8>, salt: &[u8], m: u32, t: u32, p: u32) -> Result<Uint8Array, JsValue> {
    let password = Zeroizing::new(password);
    bytes_out(primitives::argon2id_32(&password, salt, m, t, p))
}

/// The SDK's `Argon2Params`.
struct Argon2Input {
    variant: primitives::Argon2Variant,
    password: Zeroizing<Vec<u8>>,
    salt: Vec<u8>,
    params: primitives::Argon2Params,
}

impl FromJs for Argon2Input {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let ty: String = field(v, "type", path)?;
        let variant = match ty.as_str() {
            "argon2d" => primitives::Argon2Variant::Argon2d,
            "argon2i" => primitives::Argon2Variant::Argon2i,
            "argon2id" => primitives::Argon2Variant::Argon2id,
            _ => return Err(crate::convert::bad(&format!("{path}.type"), "\"argon2d\" | \"argon2i\" | \"argon2id\"")),
        };
        let dk_len: u32 = field(v, "dkLen", path)?;
        Ok(Argon2Input {
            variant,
            password: field(v, "password", path)?,
            salt: field(v, "salt", path)?,
            params: primitives::Argon2Params {
                m_kib: field(v, "m", path)?,
                t: field(v, "t", path)?,
                p: field(v, "p", path)?,
                out_len: dk_len as usize,
            },
        })
    }
}

#[wasm_bindgen(typescript_custom_section)]
const ARGON2_TS: &str = "\
export type Argon2Type = \"argon2d\" | \"argon2i\" | \"argon2id\";
/** The SDK's `Argon2Params`: memory `m` in KiB, output length `dkLen` in bytes. Argon2 version 0x13. */
export interface Argon2Params { type: Argon2Type; password: Uint8Array; salt: Uint8Array; m: number; t: number; p: number; dkLen: number }
";

/// Argon2d, Argon2i or Argon2id (version 0x13) with any output length (KDBX files, the SDK's
/// `argon2()`). `weak_kdf` for parameters Argon2 refuses. No minimum-cost check: see `checkKdfParams`.
#[wasm_bindgen]
pub fn argon2(#[wasm_bindgen(unchecked_param_type = "Argon2Params")] params: JsValue) -> Result<Uint8Array, JsValue> {
    let i: Argon2Input = arg(&params, "params").map_err(arg_err)?;
    bytes_out(primitives::argon2(i.variant, &i.password, &i.salt, i.params))
}

/// `n` bytes from the platform CSPRNG (`crypto.getRandomValues`).
#[wasm_bindgen(js_name = randomBytes)]
pub fn random_bytes(n: usize) -> Result<Uint8Array, JsValue> {
    bytes_out(primitives::random_bytes(n))
}
