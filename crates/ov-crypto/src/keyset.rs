//! SPEC §5: keysets (an X25519 encryption keypair and an Ed25519 signing keypair), signed public
//! keys and fingerprints, and keysets wrapped under the AUK or an SA master key (SPEC §4).
//!
//! Port of `packages/sdk/src/crypto/keyset.ts`.

use ov_error::{OvError, OvErrorCode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::curves::{ed25519_public_key, ed25519_sign, ed25519_verify, x25519_public_key, x25519_random_secret};
use crate::encoding::{b64u, ct_eq, from_b64u, to_hex};
use crate::envelope::{aad, unwrap, wrap, wrap_with_nonce};
use crate::primitives::{random_array, sha256, NONCE_BYTES};

/// The `PublicKeys` schema of `openapi.yaml` (base64url fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeysJson {
    /// X25519 public key.
    pub enc_pk: String,
    /// Ed25519 public key.
    pub sign_pk: String,
    /// Ed25519 signature over `"ov-pubkeys-v1" ‖ enc_pk ‖ sign_pk`.
    pub sig: String,
}

/// The `WrappedKeyset` schema of `openapi.yaml`: the public keys plus the wrapped secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKeysetJson {
    /// X25519 public key.
    pub enc_pk: String,
    /// Ed25519 public key.
    pub sign_pk: String,
    /// Signature over the public keys.
    pub sig: String,
    /// base64url `wrap(key, enc_sk ‖ sign_seed, "ov-keyset-v1")`.
    pub wrapped: String,
}

impl WrappedKeysetJson {
    /// The public half.
    pub fn public(&self) -> PublicKeysJson {
        PublicKeysJson { enc_pk: self.enc_pk.clone(), sign_pk: self.sign_pk.clone(), sig: self.sig.clone() }
    }
}

/// A principal's public keys. Lengths are fixed, so a parsed value is well formed; whether `sig`
/// verifies is checked by [`verify_public_keys`] / [`trusted_public_keys`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKeys {
    /// X25519 public key.
    pub enc_pk: [u8; 32],
    /// Ed25519 public key.
    pub sign_pk: [u8; 32],
    /// Ed25519 signature over `"ov-pubkeys-v1" ‖ enc_pk ‖ sign_pk`.
    pub sig: [u8; 64],
}

impl PublicKeys {
    /// The JSON form.
    pub fn to_json(&self) -> PublicKeysJson {
        PublicKeysJson { enc_pk: b64u(&self.enc_pk), sign_pk: b64u(&self.sign_pk), sig: b64u(&self.sig) }
    }

    /// Parses the JSON form without checking `sig`. Fails with
    /// [`OvErrorCode::InvalidPublicKeys`] for bad base64url or wrong lengths. Use
    /// [`trusted_public_keys`] for keys you will seal to.
    pub fn from_json(j: &PublicKeysJson) -> Result<Self, OvError> {
        fn field<const N: usize>(s: &str, what: &str) -> Result<[u8; N], OvError> {
            crate::encoding::from_b64u_array::<N>(s, OvErrorCode::InvalidPublicKeys, what)
        }
        Ok(Self {
            enc_pk: field(&j.enc_pk, "enc_pk")?,
            sign_pk: field(&j.sign_pk, "sign_pk")?,
            sig: field(&j.sig, "sig")?,
        })
    }

    /// The SPEC §5 fingerprint, see [`fingerprint`].
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.enc_pk, &self.sign_pk)
    }
}

/// A decrypted keyset. Keep it in memory only while unlocked; the secrets wipe themselves on drop.
#[derive(Clone)]
pub struct Keyset {
    /// X25519 secret key.
    pub enc_sk: Zeroizing<[u8; 32]>,
    /// Ed25519 seed.
    pub sign_seed: Zeroizing<[u8; 32]>,
    /// The public half, with its signature.
    pub public: PublicKeys,
}

impl std::fmt::Debug for Keyset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyset")
            .field("enc_sk", &"[redacted]")
            .field("sign_seed", &"[redacted]")
            .field("public", &self.public)
            .finish()
    }
}

fn pubkeys_message(enc_pk: &[u8], sign_pk: &[u8]) -> Vec<u8> {
    [b"ov-pubkeys-v1".as_slice(), enc_pk, sign_pk].concat()
}

/// Builds a keyset from its two secrets, computing the public keys and signing them.
pub fn keyset_from_secrets(enc_sk: &[u8; 32], sign_seed: &[u8; 32]) -> Keyset {
    let enc_pk = x25519_public_key(enc_sk);
    let sign_pk = ed25519_public_key(sign_seed);
    let sig = ed25519_sign(&pubkeys_message(&enc_pk, &sign_pk), sign_seed);
    Keyset {
        enc_sk: Zeroizing::new(*enc_sk),
        sign_seed: Zeroizing::new(*sign_seed),
        public: PublicKeys { enc_pk, sign_pk, sig },
    }
}

/// A fresh random keyset.
pub fn generate_keyset() -> Result<Keyset, OvError> {
    let enc_sk = x25519_random_secret()?;
    let sign_seed = random_array::<32>()?;
    Ok(keyset_from_secrets(&enc_sk, &sign_seed))
}

/// Checks `sig` over the public keys. Every client does this before sealing anything to them.
pub fn verify_public_keys(pub_keys: &PublicKeys) -> bool {
    ed25519_verify(&pub_keys.sig, &pubkeys_message(&pub_keys.enc_pk, &pub_keys.sign_pk), &pub_keys.sign_pk)
}

/// Parses and verifies public keys from the server. Fails with
/// [`OvErrorCode::InvalidPublicKeys`] if they are malformed or `sig` is wrong.
pub fn trusted_public_keys(j: &PublicKeysJson) -> Result<PublicKeys, OvError> {
    let pk = PublicKeys::from_json(j)?;
    if !verify_public_keys(&pk) {
        return Err(OvError::new(OvErrorCode::InvalidPublicKeys, "public key signature is invalid"));
    }
    Ok(pk)
}

/// The first 20 bytes of `SHA-256("ov-fp-v1" ‖ enc_pk ‖ sign_pk)`, lowercase hex in groups of 4
/// separated by spaces (SPEC §5).
pub fn fingerprint(enc_pk: &[u8], sign_pk: &[u8]) -> String {
    let h = to_hex(&sha256(&[b"ov-fp-v1".as_slice(), enc_pk, sign_pk].concat())[..20]);
    h.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect::<Vec<_>>().join(" ")
}

fn keyset_plain(ks: &Keyset) -> Zeroizing<[u8; 64]> {
    let mut plain = Zeroizing::new([0u8; 64]);
    plain[..32].copy_from_slice(ks.enc_sk.as_ref());
    plain[32..].copy_from_slice(ks.sign_seed.as_ref());
    plain
}

fn wrapped_json(ks: &Keyset, blob: &[u8]) -> WrappedKeysetJson {
    let p = ks.public.to_json();
    WrappedKeysetJson { enc_pk: p.enc_pk, sign_pk: p.sign_pk, sig: p.sig, wrapped: b64u(blob) }
}

/// Wraps `enc_sk ‖ sign_seed` with the AUK or an SA master key (AAD `"ov-keyset-v1"`).
pub fn wrap_keyset(key: &[u8; 32], ks: &Keyset) -> Result<WrappedKeysetJson, OvError> {
    let plain = keyset_plain(ks);
    Ok(wrapped_json(ks, &wrap(key, plain.as_ref(), aad::KEYSET)?))
}

/// [`wrap_keyset`] with a fixed nonce (test vectors only).
pub fn wrap_keyset_with_nonce(key: &[u8; 32], ks: &Keyset, nonce: &[u8; NONCE_BYTES]) -> WrappedKeysetJson {
    let plain = keyset_plain(ks);
    wrapped_json(ks, &wrap_with_nonce(key, plain.as_ref(), aad::KEYSET, nonce))
}

/// Unwraps a keyset and checks that the private keys match the stored public keys and that the
/// stored signature verifies, so a server can't pair someone's wrapped secrets with other public
/// keys.
///
/// Fails with `unsupported_version` / `decryption_failed` from [`unwrap`] (a wrong AUK is
/// `decryption_failed`), and [`OvErrorCode::InvalidPublicKeys`] for a plaintext that isn't 64 bytes
/// or public keys that don't match.
pub fn unwrap_keyset(key: &[u8; 32], w: &WrappedKeysetJson) -> Result<Keyset, OvError> {
    let blob = from_b64u(&w.wrapped)
        .map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "wrapped keyset is not valid base64url"))?;
    let plain = unwrap(key, &blob, aad::KEYSET)?;
    if plain.len() != 64 {
        return Err(OvError::new(OvErrorCode::InvalidPublicKeys, "wrapped keyset has the wrong length"));
    }
    let mut enc_sk = Zeroizing::new([0u8; 32]);
    let mut sign_seed = Zeroizing::new([0u8; 32]);
    enc_sk.copy_from_slice(&plain[..32]);
    sign_seed.copy_from_slice(&plain[32..]);
    drop(plain);
    let mut ks = keyset_from_secrets(&enc_sk, &sign_seed);
    let mismatch = || OvError::new(OvErrorCode::InvalidPublicKeys, "keyset public keys don't match its private keys");
    let stored = PublicKeys::from_json(&w.public()).map_err(|_| mismatch())?;
    if !ct_eq(&ks.public.enc_pk, &stored.enc_pk)
        || !ct_eq(&ks.public.sign_pk, &stored.sign_pk)
        || !verify_public_keys(&stored)
    {
        return Err(mismatch());
    }
    ks.public.sig = stored.sig;
    Ok(ks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keysets_verify_and_roundtrip() {
        let ks = generate_keyset().unwrap();
        assert!(verify_public_keys(&ks.public));
        let key = [4u8; 32];
        let w = wrap_keyset(&key, &ks).unwrap();
        let back = unwrap_keyset(&key, &w).unwrap();
        assert_eq!(*back.enc_sk, *ks.enc_sk);
        assert_eq!(back.public, ks.public);
        assert!(!format!("{back:?}").contains(&to_hex(back.enc_sk.as_ref())));
    }

    #[test]
    fn rejects_malformed_json() {
        let j = PublicKeysJson { enc_pk: "AQI".into(), sign_pk: "AQI".into(), sig: "AQI".into() };
        assert!(trusted_public_keys(&j).unwrap_err().is(OvErrorCode::InvalidPublicKeys));
    }
}
