//! SPEC §3: the Account Unlock Key.
//!
//! ```text
//! pw        = UTF-8(NFKC(master password))          # not trimmed
//! stretched = Argon2id(pw, kdf.salt, m, t, p, version 0x13, len 32)
//! AUK       = HKDF(ikm=stretched, salt=SecretKey, info="ov-auk-v1", L=32)
//! ```
//!
//! Port of `packages/sdk/src/crypto/auk.ts`.

use ov_error::{OvError, OvErrorCode};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{b64u, from_b64u};
use crate::primitives::{argon2id_32, hkdf_sha256_32, random_array};
use crate::secret_key::SECRET_KEY_BYTES;

/// The only KDF algorithm the SPEC allows.
pub const KDF_ALG: &str = "argon2id";
/// The KDF salt length a new account uses (bytes).
pub const KDF_SALT_BYTES: usize = 16;

/// The `Kdf` schema of `openapi.yaml`: Argon2id parameters with a base64url salt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Always `"argon2id"`.
    pub alg: String,
    /// base64url, 16 bytes.
    pub salt: String,
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

/// A minimum KDF cost: the SPEC's floor ([`KDF_MIN`]) or the server's stricter `kdf_min`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfMin {
    /// Minimum memory in KiB.
    pub m: u32,
    /// Minimum iterations.
    pub t: u32,
}

/// The production defaults for a new account: m = 64 MiB, t = 3, p = 1.
pub const KDF_DEFAULTS: (u32, u32, u32) = (65536, 3, 1);
/// Clients refuse `m < 19456` or `t < 2` (SPEC §3).
pub const KDF_MIN: KdfMin = KdfMin { m: 19456, t: 2 };

/// KDF parameters for a new account: [`KDF_DEFAULTS`] and a random 16-byte salt.
pub fn new_kdf_params() -> Result<KdfParams, OvError> {
    let (m, t, p) = KDF_DEFAULTS;
    new_kdf_params_with(m, t, p)
}

/// KDF parameters with a random 16-byte salt and the given cost.
pub fn new_kdf_params_with(m: u32, t: u32, p: u32) -> Result<KdfParams, OvError> {
    let salt = random_array::<KDF_SALT_BYTES>()?;
    Ok(KdfParams { alg: KDF_ALG.to_owned(), salt: b64u(salt.as_ref()), m, t, p })
}

/// Refuses KDF parameters below `min` (pass [`KDF_MIN`] unless the server sent a stricter
/// `kdf_min`), with `p = 0`, or of an algorithm other than Argon2id. Fails with
/// [`OvErrorCode::WeakKdf`]. Run it on every server-provided `kdf` before deriving.
pub fn check_kdf_params(kdf: &KdfParams, min: KdfMin) -> Result<(), OvError> {
    if kdf.alg != KDF_ALG {
        return Err(OvError::new(OvErrorCode::WeakKdf, format!("unsupported KDF {}", kdf.alg)));
    }
    if kdf.m < min.m || kdf.t < min.t || kdf.p < 1 {
        return Err(OvError::new(
            OvErrorCode::WeakKdf,
            format!("KDF parameters below the minimum (m >= {}, t >= {})", min.m, min.t),
        ));
    }
    Ok(())
}

/// Options for [`derive_auk`] and [`stretch_password`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeriveAukOptions {
    /// Skip the minimum-cost check (the test vectors use m = 1024). Never set this for
    /// server-provided parameters.
    pub allow_weak: bool,
    /// The floor to enforce, [`KDF_MIN`] by default.
    pub kdf_min: KdfMin,
}

impl Default for DeriveAukOptions {
    fn default() -> Self {
        Self { allow_weak: false, kdf_min: KDF_MIN }
    }
}

/// UTF-8 of the NFKC-normalized password, not trimmed (SPEC §3). It is also the OPAQUE password
/// input (SPEC §8).
pub fn password_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(password.len()));
    let mut buf = [0u8; 4];
    for c in password.nfkc() {
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    buf.zeroize();
    out
}

/// Argon2id of the normalized password (the `stretched` value of SPEC §3).
pub fn stretch_password(
    password: &str,
    kdf: &KdfParams,
    opts: DeriveAukOptions,
) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let pw = password_bytes(password);
    stretch_password_bytes(&pw, kdf, opts)
}

/// [`stretch_password`] over already-normalized password bytes.
pub fn stretch_password_bytes(
    password: &[u8],
    kdf: &KdfParams,
    opts: DeriveAukOptions,
) -> Result<Zeroizing<[u8; 32]>, OvError> {
    if !opts.allow_weak {
        check_kdf_params(kdf, opts.kdf_min)?;
    }
    if kdf.alg != KDF_ALG {
        return Err(OvError::new(OvErrorCode::WeakKdf, format!("unsupported KDF {}", kdf.alg)));
    }
    let salt = from_b64u(&kdf.salt).map_err(|_| OvError::new(OvErrorCode::WeakKdf, "KDF salt is not base64url"))?;
    let out = argon2id_32(password, &salt, kdf.m, kdf.t, kdf.p)?;
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// The AUK from the master password, the account's `kdf` and its Secret Key (SPEC §3).
///
/// Fails with [`OvErrorCode::WeakKdf`] for parameters under the floor (unless
/// [`DeriveAukOptions::allow_weak`]).
pub fn derive_auk(
    password: &str,
    kdf: &KdfParams,
    secret_key: &[u8; SECRET_KEY_BYTES],
    opts: DeriveAukOptions,
) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let stretched = stretch_password(password, kdf, opts)?;
    Ok(auk_from_stretched(&stretched, secret_key))
}

/// [`derive_auk`] over already-normalized password bytes.
pub fn derive_auk_from_bytes(
    password: &[u8],
    kdf: &KdfParams,
    secret_key: &[u8; SECRET_KEY_BYTES],
    opts: DeriveAukOptions,
) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let stretched = stretch_password_bytes(password, kdf, opts)?;
    Ok(auk_from_stretched(&stretched, secret_key))
}

/// HKDF(ikm = stretched, salt = Secret Key, info = `"ov-auk-v1"`).
pub fn auk_from_stretched(stretched: &[u8; 32], secret_key: &[u8; SECRET_KEY_BYTES]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256_32(stretched, secret_key, b"ov-auk-v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf(m: u32, t: u32) -> KdfParams {
        KdfParams { alg: KDF_ALG.into(), salt: "GLbQ2f2P0LkLBS2Cm0RxOw".into(), m, t, p: 1 }
    }

    #[test]
    fn weak_kdf_floor() {
        assert!(check_kdf_params(&kdf(19456, 1), KDF_MIN).unwrap_err().is(OvErrorCode::WeakKdf));
        assert!(check_kdf_params(&kdf(19455, 2), KDF_MIN).unwrap_err().is(OvErrorCode::WeakKdf));
        assert!(check_kdf_params(&kdf(19456, 2), KDF_MIN).is_ok());
        let mut p0 = kdf(19456, 2);
        p0.p = 0;
        assert!(check_kdf_params(&p0, KDF_MIN).is_err());
        let mut alg = kdf(65536, 3);
        alg.alg = "scrypt".into();
        assert!(check_kdf_params(&alg, KDF_MIN).unwrap_err().is(OvErrorCode::WeakKdf));
        // A stricter server minimum.
        assert!(check_kdf_params(&kdf(19456, 2), KdfMin { m: 65536, t: 3 }).is_err());
        // derive refuses before running Argon2.
        let e = derive_auk("pw", &kdf(1024, 2), &[0; 16], DeriveAukOptions::default()).unwrap_err();
        assert!(e.is(OvErrorCode::WeakKdf) && e.message.contains("minimum"));
    }

    #[test]
    fn new_params() {
        let k = new_kdf_params().unwrap();
        assert_eq!((k.alg.as_str(), k.m, k.t, k.p), ("argon2id", 65536, 3, 1));
        assert_eq!(from_b64u(&k.salt).unwrap().len(), 16);
        assert_ne!(k.salt, new_kdf_params().unwrap().salt);
        assert!(check_kdf_params(&k, KDF_MIN).is_ok());
    }

    #[test]
    fn password_bytes_is_untrimmed() {
        assert_eq!(&**password_bytes(" pw "), b" pw ");
        // NFKC folds the "fi" ligature and composes combining marks.
        assert_eq!(&**password_bytes("\u{fb01}e\u{301}"), "fi\u{e9}".as_bytes());
    }
}
