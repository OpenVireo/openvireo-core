//! The SPEC §1 primitives, named after the SPEC rather than a library: HKDF-SHA256 (RFC 5869),
//! XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha, libsodium's `crypto_aead_xchacha20poly1305_ietf`),
//! Argon2 (RFC 9106) and random bytes from the platform CSPRNG.
//!
//! Port of `packages/sdk/src/crypto/primitives.ts` and `argon2.ts`. Everything else in the core
//! builds on these functions. Keys and derived secrets come back in [`Zeroizing`] buffers, which
//! wipe themselves when dropped.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use ov_error::{OvError, OvErrorCode};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 key length (bytes).
pub const KEY_BYTES: usize = 32;
/// XChaCha20-Poly1305 nonce length (bytes).
pub const NONCE_BYTES: usize = 24;
/// Poly1305 tag length (bytes), appended to every ciphertext.
pub const TAG_BYTES: usize = 16;
/// SHA-256 output length (bytes).
pub const SHA256_BYTES: usize = 32;
/// The largest output HKDF-SHA256 can produce (255 × 32 bytes, RFC 5869 §2.3).
pub const HKDF_MAX_BYTES: usize = 255 * SHA256_BYTES;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; SHA256_BYTES] {
    Sha256::digest(data).into()
}

/// HKDF-SHA256 (RFC 5869): extract with `salt`, expand with `info` to `length` bytes.
///
/// An empty salt means 32 zero bytes (SPEC §1), which RFC 5869 and HMAC treat the same as no salt.
/// `info` is taken byte for byte; the SPEC's info strings are ASCII (`b"ov-auk-v1"`).
///
/// Fails with [`OvErrorCode::Internal`] only if `length` is over [`HKDF_MAX_BYTES`].
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let mut out = Zeroizing::new(vec![0u8; length]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .map_err(|_| OvError::internal(format!("HKDF-SHA256 can't produce {length} bytes")))?;
    Ok(out)
}

/// HKDF-SHA256 to a 32-byte key, the length every SPEC derivation uses.
pub fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is always within HKDF's output limit.
    let _ = Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, out.as_mut());
    out
}

/// XChaCha20-Poly1305 encryption: returns `ciphertext ‖ tag` (plaintext length + 16).
///
/// Nonces must never repeat under one key; callers pass [`random_nonce`] unless a test vector
/// fixes the nonce. The SPEC envelopes (wrap §4, seal §6) add their own version byte and nonce
/// framing on top of this.
pub fn aead_encrypt(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    // Encryption only fails for inputs over ~256 GiB, which no caller can hold in memory.
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer")
}

/// XChaCha20-Poly1305 decryption of `ciphertext ‖ tag`.
///
/// Fails with [`OvErrorCode::DecryptionFailed`] when the tag doesn't verify (wrong key, nonce or
/// AAD, or changed data) or the input is shorter than a tag. No plaintext is released on failure.
pub fn aead_decrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "decryption failed"))
}

/// The Argon2 variant. The account KDF (SPEC §3) and OPAQUE use Argon2id; KDBX files may use
/// Argon2d or Argon2id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Argon2Variant {
    /// Argon2d (data-dependent; KeePass's default for KDBX 4).
    Argon2d,
    /// Argon2i.
    Argon2i,
    /// Argon2id (SPEC §3).
    Argon2id,
}

/// Argon2 cost parameters, named as the SPEC's `kdf` object names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Argon2Params {
    /// Memory in KiB (`m`).
    pub m_kib: u32,
    /// Iterations (`t`).
    pub t: u32,
    /// Parallelism (`p`).
    pub p: u32,
    /// Output length in bytes.
    pub out_len: usize,
}

/// Argon2 version 0x13 (1.3) over `password` and `salt`. This wrapper doesn't enforce the SPEC's
/// minimum cost (`m >= 19456`, `t >= 2`): `checkKdfParams` in the AUK module does that for
/// server-provided parameters, and KDBX files carry their own.
///
/// Fails with [`OvErrorCode::WeakKdf`] for parameters Argon2 itself refuses (memory below 8 × p KiB,
/// `t = 0`, `p = 0`, a salt shorter than 8 bytes, an output shorter than 4 bytes).
///
/// The work is synchronous and CPU-bound (≈64 MiB and a fraction of a second at the production
/// defaults); async callers run it where blocking is acceptable.
pub fn argon2(
    variant: Argon2Variant,
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let algorithm = match variant {
        Argon2Variant::Argon2d => argon2::Algorithm::Argon2d,
        Argon2Variant::Argon2i => argon2::Algorithm::Argon2i,
        Argon2Variant::Argon2id => argon2::Algorithm::Argon2id,
    };
    let weak = |e: argon2::Error| OvError::new(OvErrorCode::WeakKdf, format!("Argon2 refused the parameters: {e}"));
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(params.out_len)).map_err(weak)?;
    let mut out = Zeroizing::new(vec![0u8; params.out_len]);
    // The work area holds password-derived blocks: keep it in wiped-on-drop memory (argon2's own
    // `hash_password_into` frees it without wiping).
    // Allocated fallibly: a failed allocation would abort the app (huge parameters, a small device)
    let mut blocks = Zeroizing::new(Vec::new());
    blocks.try_reserve_exact(p.block_count()).map_err(|_| {
        OvError::new(
            OvErrorCode::TooLarge,
            format!("not enough memory for Argon2 ({} MiB)", u64::from(params.m_kib) / 1024),
        )
    })?;
    blocks.resize(p.block_count(), argon2::Block::default());
    argon2::Argon2::new(algorithm, argon2::Version::V0x13, p)
        .hash_password_into_with_memory(password, salt, &mut out[..], blocks.as_mut_slice())
        .map_err(weak)?;
    Ok(out)
}

/// Argon2id with a 32-byte output, the SPEC §3 stretch.
pub fn argon2id_32(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Zeroizing<Vec<u8>>, OvError> {
    argon2(Argon2Variant::Argon2id, password, salt, Argon2Params { m_kib, t, p, out_len: 32 })
}

/// Fills `buf` from the platform CSPRNG (`getrandom`: the OS generator natively,
/// `crypto.getRandomValues` on wasm32).
///
/// Fails with [`OvErrorCode::Internal`] only if the platform generator is unavailable.
pub fn fill_random(buf: &mut [u8]) -> Result<(), OvError> {
    getrandom::getrandom(buf).map_err(|e| OvError::internal(format!("the platform random generator failed: {e}")))
}

/// `n` random bytes.
pub fn random_bytes(n: usize) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let mut out = Zeroizing::new(vec![0u8; n]);
    fill_random(&mut out)?;
    Ok(out)
}

/// A random array of `N` bytes (keys, salts, ids).
pub fn random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>, OvError> {
    let mut out = Zeroizing::new([0u8; N]);
    fill_random(out.as_mut())?;
    Ok(out)
}

/// A random 32-byte key (vault keys, share keys, SA master keys).
pub fn random_key() -> Result<Zeroizing<[u8; KEY_BYTES]>, OvError> {
    random_array::<KEY_BYTES>()
}

/// A random 24-byte XChaCha20-Poly1305 nonce.
pub fn random_nonce() -> Result<[u8; NONCE_BYTES], OvError> {
    let mut n = [0u8; NONCE_BYTES];
    fill_random(&mut n)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, SecretSlice};

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '\n'], "")).unwrap()
    }

    fn range(from: u8, to_inclusive: u8) -> Vec<u8> {
        (from..=to_inclusive).collect()
    }

    // ---- RFC 5869 Appendix A, SHA-256 cases (A.1-A.3)

    #[test]
    fn rfc5869_test_case_1_basic() {
        let okm = hkdf_sha256(&[0x0b; 22], &range(0x00, 0x0c), &range(0xf0, 0xf9), 42).unwrap();
        assert_eq!(
            okm.as_slice(),
            h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    #[test]
    fn rfc5869_test_case_2_long_inputs() {
        let okm = hkdf_sha256(&range(0x00, 0x4f), &range(0x60, 0xaf), &range(0xb0, 0xff), 82).unwrap();
        assert_eq!(
            okm.as_slice(),
            h("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
               59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
               cc30c58179ec3e87c14c01d5c1f3434f1d87")
        );
    }

    #[test]
    fn rfc5869_test_case_3_empty_salt_and_info() {
        let okm = hkdf_sha256(&[0x0b; 22], &[], &[], 42).unwrap();
        let expected = h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
        assert_eq!(okm.as_slice(), expected);
        // SPEC §1: an empty salt means 32 zero bytes.
        assert_eq!(hkdf_sha256(&[0x0b; 22], &[0u8; 32], &[], 42).unwrap().as_slice(), expected);
    }

    #[test]
    fn hkdf_32_matches_and_length_limit() {
        let a = hkdf_sha256(b"ikm", b"salt", b"ov-auk-v1", 32).unwrap();
        assert_eq!(a.as_slice(), hkdf_sha256_32(b"ikm", b"salt", b"ov-auk-v1").as_slice());
        assert_eq!(hkdf_sha256(b"k", b"", b"", HKDF_MAX_BYTES).unwrap().len(), HKDF_MAX_BYTES);
        assert_eq!(hkdf_sha256(b"k", b"", b"", HKDF_MAX_BYTES + 1).unwrap_err().code, OvErrorCode::Internal);
    }

    // ---- draft-irtf-cfrg-xchacha-03 §A.3.1 (AEAD_XChaCha20_Poly1305)

    const XCHACHA_PLAINTEXT: &[u8] =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for \
the future, sunscreen would be it.";

    fn xchacha_key() -> [u8; 32] {
        range(0x80, 0x9f).try_into().unwrap()
    }

    fn xchacha_nonce() -> [u8; 24] {
        range(0x40, 0x57).try_into().unwrap()
    }

    fn xchacha_expected() -> Vec<u8> {
        let mut ct = h("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
                        731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
                        2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
                        21f9664c97637da9768812f615c68b13b52e");
        ct.extend(h("c0875924c1c7987947deafd8780acf49"));
        ct
    }

    #[test]
    fn draft_irtf_cfrg_xchacha_a_3_1_encrypt() {
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let ct = aead_encrypt(&xchacha_key(), &xchacha_nonce(), XCHACHA_PLAINTEXT, &aad);
        assert_eq!(ct.len(), XCHACHA_PLAINTEXT.len() + TAG_BYTES);
        assert_eq!(ct, xchacha_expected());
    }

    #[test]
    fn draft_irtf_cfrg_xchacha_a_3_1_decrypt() {
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let pt = aead_decrypt(&xchacha_key(), &xchacha_nonce(), &xchacha_expected(), &aad).unwrap();
        assert_eq!(pt.as_slice(), XCHACHA_PLAINTEXT);
    }

    #[test]
    fn draft_irtf_cfrg_xchacha_a_3_1_tampering_fails() {
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let good = xchacha_expected();
        let fail = |key: &[u8; 32], nonce: &[u8; 24], ct: &[u8], aad: &[u8]| {
            assert_eq!(aead_decrypt(key, nonce, ct, aad).unwrap_err().code, OvErrorCode::DecryptionFailed);
        };
        let mut flipped = good.clone();
        flipped[0] ^= 1;
        fail(&xchacha_key(), &xchacha_nonce(), &flipped, &aad);
        let mut tag_flipped = good.clone();
        *tag_flipped.last_mut().unwrap() ^= 1;
        fail(&xchacha_key(), &xchacha_nonce(), &tag_flipped, &aad);
        fail(&xchacha_key(), &xchacha_nonce(), &good, b"other aad");
        fail(&[0u8; 32], &xchacha_nonce(), &good, &aad);
        fail(&xchacha_key(), &[0u8; 24], &good, &aad);
        fail(&xchacha_key(), &xchacha_nonce(), &good[..TAG_BYTES - 1], &aad);
    }

    #[test]
    fn aead_round_trip_with_random_nonce() {
        let key = random_key().unwrap();
        let nonce = random_nonce().unwrap();
        let ct = aead_encrypt(&key, &nonce, b"", b"ov-vault-name|id");
        assert_eq!(ct.len(), TAG_BYTES);
        assert!(aead_decrypt(&key, &nonce, &ct, b"ov-vault-name|id").unwrap().is_empty());
    }

    // ---- Argon2id against the SPEC's test-vectors.json `auk` cases (m=1024, t=2, p=1)

    const AUK_SALT_HEX: &str = "18b6d0d9fd8fd0b90b052d829b44713b"; // "GLbQ2f2P0LkLBS2Cm0RxOw"
    const AUK_SECRET_KEY_HEX: &str = "e7382233c33d2700596787c9384ca315";

    fn auk_case(password_nfkc_hex: &str, argon2id_hex: &str, auk_hex: &str) {
        let password = SecretSlice::from(h(password_nfkc_hex));
        let stretched = argon2id_32(password.expose_secret(), &h(AUK_SALT_HEX), 1024, 2, 1).unwrap();
        assert_eq!(stretched.as_slice(), h(argon2id_hex));
        // SPEC §3: AUK = HKDF(ikm=stretched, salt=SecretKey, info="ov-auk-v1", L=32)
        let auk = hkdf_sha256_32(&stretched, &h(AUK_SECRET_KEY_HEX), b"ov-auk-v1");
        assert_eq!(auk.as_slice(), h(auk_hex));
    }

    #[test]
    fn spec_auk_vector_ascii_password() {
        auk_case(
            "636f727265637420686f727365206261747465727920737461706c65",
            "f2c8c8a7f94b8dc5202fc56cca177df5bb25443d3190be618e081f06926d2c45",
            "43a097ad11187208cba53de88206322761e16b53a17cd3a9c74f30b32e4fee84",
        );
    }

    #[test]
    fn spec_auk_vector_nfkc_password() {
        auk_case(
            "c39c6ec3af63c3b664c3a92070c3a4737377c3b67264206669",
            "7bda82fb191da5cec8ad43a2695cf1be21c5e77cba4a35a90382d67f15f2bc57",
            "b738f5bc5b08779d83bda4fa1e60b4278d152fb12dcedc4dfa7e23a1ea235528",
        );
    }

    #[test]
    fn argon2_variants_differ_and_bad_params_are_weak_kdf() {
        let params = Argon2Params { m_kib: 64, t: 1, p: 1, out_len: 32 };
        let d = argon2(Argon2Variant::Argon2d, b"pw", b"saltsalt", params).unwrap();
        let i = argon2(Argon2Variant::Argon2i, b"pw", b"saltsalt", params).unwrap();
        let id = argon2(Argon2Variant::Argon2id, b"pw", b"saltsalt", params).unwrap();
        assert!(d != i && i != id && d != id);
        let bad = Argon2Params { t: 0, ..params };
        assert_eq!(argon2(Argon2Variant::Argon2id, b"pw", b"saltsalt", bad).unwrap_err().code, OvErrorCode::WeakKdf);
        assert_eq!(argon2(Argon2Variant::Argon2id, b"pw", b"short", params).unwrap_err().code, OvErrorCode::WeakKdf);
    }

    // ---- SHA-256 (FIPS 180-2 "abc") and randomness

    #[test]
    fn sha256_abc() {
        assert_eq!(sha256(b"abc").to_vec(), h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    #[test]
    fn random_bytes_are_random_and_sized() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a.as_slice(), b.as_slice());
        assert!(random_bytes(0).unwrap().is_empty());
        assert_ne!(random_array::<16>().unwrap().as_slice(), &[0u8; 16]);
    }
}
