//! X25519 and Ed25519 (SPEC §1) over `ov-crypto::curves`. Full module only.

use js_sys::Uint8Array;
use ov_crypto::curves;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::convert::{fixed, out};
use crate::error::arg_err;
use crate::primitives::bytes_out;

/// A random X25519 secret key (clamped).
#[wasm_bindgen(js_name = x25519RandomSecret)]
pub fn x25519_random_secret() -> Result<Uint8Array, JsValue> {
    bytes_out(curves::x25519_random_secret())
}

/// The X25519 public key of a 32-byte secret key.
#[wasm_bindgen(js_name = x25519PublicKey)]
pub fn x25519_public_key(sk: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let sk = Zeroizing::new(sk);
    let sk = fixed::<32>(&sk, "sk").map_err(arg_err)?;
    Ok(out(&curves::x25519_public_key(&sk)))
}

/// X25519(sk, pk); `low_order_point` when the result is all zeroes.
#[wasm_bindgen(js_name = x25519Shared)]
pub fn x25519_shared(sk: Vec<u8>, pk: &[u8]) -> Result<Uint8Array, JsValue> {
    let sk = Zeroizing::new(sk);
    let sk = fixed::<32>(&sk, "sk").map_err(arg_err)?;
    bytes_out(curves::x25519_shared(&sk, pk))
}

/// The Ed25519 public key of a 32-byte seed.
#[wasm_bindgen(js_name = ed25519PublicKey)]
pub fn ed25519_public_key(seed: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let seed = Zeroizing::new(seed);
    let seed = fixed::<32>(&seed, "seed").map_err(arg_err)?;
    Ok(out(&curves::ed25519_public_key(&seed)))
}

/// An Ed25519 signature (64 bytes) of `message` with a 32-byte seed.
#[wasm_bindgen(js_name = ed25519Sign)]
pub fn ed25519_sign(message: &[u8], seed: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let seed = Zeroizing::new(seed);
    let seed = fixed::<32>(&seed, "seed").map_err(arg_err)?;
    Ok(out(&curves::ed25519_sign(message, &seed)))
}

/// Whether `sig` is a valid (strict) Ed25519 signature of `message` by `pk`. Never throws.
#[wasm_bindgen(js_name = ed25519Verify)]
pub fn ed25519_verify(sig: &[u8], message: &[u8], pk: &[u8]) -> bool {
    curves::ed25519_verify(sig, message, pk)
}
