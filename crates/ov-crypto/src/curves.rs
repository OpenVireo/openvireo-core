//! X25519 (RFC 7748) and Ed25519 (RFC 8032), the SPEC §5 keypairs, named after the SPEC as
//! `primitives.ts` names them. The envelope, keyset and restore modules build on these.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ov_error::{OvError, OvErrorCode};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::primitives::random_array;

/// X25519 and Ed25519 key length (bytes).
pub const CURVE_KEY_BYTES: usize = 32;
/// Ed25519 signature length (bytes).
pub const SIGNATURE_BYTES: usize = 64;

/// A random X25519 secret key (clamped when used, as RFC 7748 says).
pub fn x25519_random_secret() -> Result<Zeroizing<[u8; 32]>, OvError> {
    random_array::<32>()
}

/// The X25519 public key of `sk`.
pub fn x25519_public_key(sk: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*sk);
    PublicKey::from(&secret).to_bytes()
}

/// X25519(`sk`, `pk`), rejecting a low-order `pk` as SPEC §6 says: an all-zero shared secret
/// (checked in constant time) fails with [`OvErrorCode::LowOrderPoint`], and so does a `pk` that
/// isn't 32 bytes.
pub fn x25519_shared(sk: &[u8; 32], pk: &[u8]) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let pk: [u8; 32] =
        pk.try_into().map_err(|_| OvError::new(OvErrorCode::LowOrderPoint, "invalid X25519 public key"))?;
    let secret = StaticSecret::from(*sk);
    let shared = secret.diffie_hellman(&PublicKey::from(pk));
    if !shared.was_contributory() {
        return Err(OvError::new(OvErrorCode::LowOrderPoint, "X25519 result is all zero"));
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// The Ed25519 public key of a 32-byte seed.
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Ed25519 signature of `message` with a 32-byte seed (deterministic, RFC 8032).
pub fn ed25519_sign(message: &[u8], seed: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Verifies an Ed25519 signature. Returns `false` (never an error) for a signature or key of the
/// wrong length, a key that isn't a curve point, or a bad signature.
///
/// Verification is strict (`verify_strict`: canonical `S`, no small-order `R` or public key), which
/// every honestly made signature passes.
pub fn ed25519_verify(sig: &[u8], message: &[u8], pk: &[u8]) -> bool {
    let (Ok(sig), Ok(pk)) = (<[u8; 64]>::try_from(sig), <[u8; 32]>::try_from(pk)) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(&sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7748 §6.1
    #[test]
    fn rfc7748_x25519() {
        let a: [u8; 32] = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap()
            .try_into()
            .unwrap();
        let b: [u8; 32] = hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(x25519_public_key(&a)),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        let k = x25519_shared(&a, &x25519_public_key(&b)).unwrap();
        assert_eq!(hex::encode(*k), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }

    #[test]
    fn rejects_low_order_points() {
        let sk = [7u8; 32];
        // u = 0 and u = 1 are low-order points; X25519 with them gives all zeros.
        assert!(x25519_shared(&sk, &[0u8; 32]).unwrap_err().is(OvErrorCode::LowOrderPoint));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(x25519_shared(&sk, &one).unwrap_err().is(OvErrorCode::LowOrderPoint));
        assert!(x25519_shared(&sk, &[9u8; 31]).unwrap_err().is(OvErrorCode::LowOrderPoint));
    }

    #[test]
    fn ed25519_roundtrip_and_bad_inputs() {
        let seed = [3u8; 32];
        let pk = ed25519_public_key(&seed);
        let sig = ed25519_sign(b"msg", &seed);
        assert!(ed25519_verify(&sig, b"msg", &pk));
        assert!(!ed25519_verify(&sig, b"msh", &pk));
        assert!(!ed25519_verify(&sig[..63], b"msg", &pk));
        assert!(!ed25519_verify(&sig, b"msg", &pk[..31]));
    }
}
