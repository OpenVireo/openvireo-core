//! SPEC §4 (wrap, the symmetric envelope) and §6 (seal, the public-key envelope `"ov-seal-v1"`),
//! plus the [`aad`] strings every envelope is bound to.
//!
//! ```text
//! wrap(key, pt, aad) = 0x01 ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce, pt, aad)
//! sealed             = 0x01 ‖ epk(32) ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce, pt, aad)
//!   where key = HKDF(ikm = X25519(esk, recipient_pk), salt = epk ‖ recipient_pk, info = "ov-seal-v1")
//! ```
//!
//! Port of `packages/sdk/src/crypto/envelope.ts`.

use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::curves::{x25519_public_key, x25519_random_secret, x25519_shared};
use crate::primitives::{aead_decrypt, aead_encrypt, hkdf_sha256_32, random_nonce, KEY_BYTES, NONCE_BYTES, TAG_BYTES};

/// The envelope version byte (SPEC §4, §6). Anything else is `unsupported_version`.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// The shortest valid wrap: version, nonce and tag.
pub const WRAP_MIN_BYTES: usize = 1 + NONCE_BYTES + TAG_BYTES;
/// The shortest valid seal: version, ephemeral key, nonce and tag.
pub const SEAL_MIN_BYTES: usize = 1 + 32 + NONCE_BYTES + TAG_BYTES;

/// The AAD strings of SPEC §4, §6 and §22, used byte for byte.
pub mod aad {
    /// A wrapped user or SA keyset.
    pub const KEYSET: &str = "ov-keyset-v1";

    /// A vault key sealed to a member: `ov-vault-key|<vault uuid>`.
    pub fn vault_key(vault_id: &str) -> String {
        format!("ov-vault-key|{vault_id}")
    }
    /// An encrypted vault name: `ov-vault-name|<vault uuid>`.
    pub fn vault_name(vault_id: &str) -> String {
        format!("ov-vault-name|{vault_id}")
    }
    /// An SA master key (wrapped per secret, or sealed to an admin): `ov-sa-master-v1|<sa uuid>`.
    pub fn sa_master(sa_id: &str) -> String {
        format!("ov-sa-master-v1|{sa_id}")
    }
    /// A share link's content: `ov-share-v1|<share id>`.
    pub fn share(share_id: &str) -> String {
        format!("ov-share-v1|{share_id}")
    }
    /// The owner's encrypted reference to a share: `ov-share-ref|<share id>`.
    pub fn share_ref(share_id: &str) -> String {
        format!("ov-share-ref|{share_id}")
    }
}

fn check_version(blob: &[u8], min_len: usize) -> Result<(), OvError> {
    match blob.first() {
        Some(&ENVELOPE_VERSION) => {}
        Some(v) => {
            return Err(OvError::new(OvErrorCode::UnsupportedVersion, format!("unsupported envelope version {v}")))
        }
        None => return Err(OvError::new(OvErrorCode::UnsupportedVersion, "unsupported envelope version (empty)")),
    }
    if blob.len() < min_len {
        return Err(OvError::new(OvErrorCode::DecryptionFailed, "envelope too short"));
    }
    Ok(())
}

fn decrypt(key: &[u8; KEY_BYTES], nonce: &[u8], ct: &[u8], aad: &str) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let nonce: &[u8; NONCE_BYTES] = nonce.try_into().map_err(|_| decryption_failed())?;
    aead_decrypt(key, nonce, ct, aad.as_bytes()).map_err(|_| decryption_failed())
}

fn decryption_failed() -> OvError {
    OvError::new(OvErrorCode::DecryptionFailed, "decryption failed (wrong key, wrong AAD or corrupted data)")
}

/// `wrap(key, plaintext, aad)` with a fresh random nonce (SPEC §4).
pub fn wrap(key: &[u8; KEY_BYTES], plaintext: &[u8], aad: &str) -> Result<Vec<u8>, OvError> {
    Ok(wrap_with_nonce(key, plaintext, aad, &random_nonce()?))
}

/// `wrap` with a caller-chosen nonce. Only for test vectors: a nonce must never repeat under a key.
pub fn wrap_with_nonce(key: &[u8; KEY_BYTES], plaintext: &[u8], aad: &str, nonce: &[u8; NONCE_BYTES]) -> Vec<u8> {
    let ct = aead_encrypt(key, nonce, plaintext, aad.as_bytes());
    let mut out = Vec::with_capacity(1 + NONCE_BYTES + ct.len());
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

/// Opens a [`wrap`] envelope.
///
/// Fails with [`OvErrorCode::UnsupportedVersion`] if the first byte isn't `0x01` (or the blob is
/// empty), and [`OvErrorCode::DecryptionFailed`] for a wrong key, a wrong AAD, changed data or a
/// blob too short to hold a nonce and tag.
pub fn unwrap(key: &[u8; KEY_BYTES], blob: &[u8], aad: &str) -> Result<Zeroizing<Vec<u8>>, OvError> {
    check_version(blob, WRAP_MIN_BYTES)?;
    decrypt(key, &blob[1..1 + NONCE_BYTES], &blob[1 + NONCE_BYTES..], aad)
}

/// Fixed randomness for [`seal_with`]. Only for test vectors.
#[derive(Default)]
pub struct SealOptions {
    /// A fixed ephemeral X25519 secret key.
    pub ephemeral_secret_key: Option<Zeroizing<[u8; 32]>>,
    /// A fixed nonce.
    pub nonce: Option<[u8; NONCE_BYTES]>,
}

impl std::fmt::Debug for SealOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealOptions")
            .field("ephemeral_secret_key", &self.ephemeral_secret_key.as_ref().map(|_| "[redacted]"))
            .field("nonce", &self.nonce.is_some())
            .finish()
    }
}

/// HKDF(shared, salt = epk ‖ recipient_pk, "ov-seal-v1"). X25519 has already refused an all-zero
/// shared secret.
fn seal_key(shared: &[u8; 32], epk: &[u8; 32], recipient_pk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(recipient_pk);
    hkdf_sha256_32(shared, &salt, b"ov-seal-v1")
}

/// Seals `plaintext` to a recipient's X25519 public key (SPEC §6) with a fresh ephemeral key and
/// nonce. Check the recipient's signed public keys first ([`crate::keyset::trusted_public_keys`]).
///
/// Fails with [`OvErrorCode::LowOrderPoint`] for a low-order (or wrong-length) recipient key.
pub fn seal(recipient_enc_pk: &[u8], plaintext: &[u8], aad: &str) -> Result<Vec<u8>, OvError> {
    seal_with(recipient_enc_pk, plaintext, aad, &SealOptions::default())
}

/// [`seal`] with fixed randomness from `opts` (test vectors only).
pub fn seal_with(recipient_enc_pk: &[u8], plaintext: &[u8], aad: &str, opts: &SealOptions) -> Result<Vec<u8>, OvError> {
    let esk = match &opts.ephemeral_secret_key {
        Some(k) => k.clone(),
        None => x25519_random_secret()?,
    };
    let epk = x25519_public_key(&esk);
    let shared = x25519_shared(&esk, recipient_enc_pk)?;
    // x25519_shared checked the length.
    let recipient: [u8; 32] = recipient_enc_pk.try_into().map_err(|_| OvError::internal("recipient key length"))?;
    let key = seal_key(&shared, &epk, &recipient);
    let nonce = match opts.nonce {
        Some(n) => n,
        None => random_nonce()?,
    };
    let ct = aead_encrypt(&key, &nonce, plaintext, aad.as_bytes());
    let mut out = Vec::with_capacity(1 + 32 + NONCE_BYTES + ct.len());
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&epk);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The AEAD key a sealed box was made with, as the recipient derives it. Exposed for the test
/// vectors (`derived_key_hex`); [`unseal`] is what callers want.
pub fn seal_derived_key(recipient_enc_sk: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>, OvError> {
    check_version(sealed, SEAL_MIN_BYTES)?;
    let epk: [u8; 32] = sealed[1..33].try_into().map_err(|_| decryption_failed())?;
    let shared = x25519_shared(recipient_enc_sk, &epk)?;
    Ok(seal_key(&shared, &epk, &x25519_public_key(recipient_enc_sk)))
}

/// Opens a sealed box with the recipient's X25519 secret key.
///
/// Fails with [`OvErrorCode::UnsupportedVersion`] for an unknown version byte,
/// [`OvErrorCode::LowOrderPoint`] for a low-order ephemeral key and
/// [`OvErrorCode::DecryptionFailed`] for a wrong recipient, wrong AAD or changed data.
pub fn unseal(recipient_enc_sk: &[u8; 32], sealed: &[u8], aad: &str) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let key = seal_derived_key(recipient_enc_sk, sealed)?;
    decrypt(&key, &sealed[33..33 + NONCE_BYTES], &sealed[33 + NONCE_BYTES..], aad)
}

fn key32(v: Zeroizing<Vec<u8>>, what: &str) -> Result<Zeroizing<[u8; 32]>, OvError> {
    if v.len() != 32 {
        return Err(OvError::new(OvErrorCode::DecryptionFailed, format!("{what} must be 32 bytes")));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&v);
    Ok(k)
}

/// Seals a vault key to a member (AAD `ov-vault-key|<vault>`).
pub fn seal_vault_key(recipient_enc_pk: &[u8], vault_id: &str, vault_key: &[u8; 32]) -> Result<Vec<u8>, OvError> {
    seal(recipient_enc_pk, vault_key, &aad::vault_key(vault_id))
}

/// [`seal_vault_key`] with fixed randomness (test vectors only).
pub fn seal_vault_key_with(
    recipient_enc_pk: &[u8],
    vault_id: &str,
    vault_key: &[u8; 32],
    opts: &SealOptions,
) -> Result<Vec<u8>, OvError> {
    seal_with(recipient_enc_pk, vault_key, &aad::vault_key(vault_id), opts)
}

/// Unseals a member's vault key. Fails with `decryption_failed` if the plaintext isn't 32 bytes.
pub fn unseal_vault_key(enc_sk: &[u8; 32], vault_id: &str, sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>, OvError> {
    key32(unseal(enc_sk, sealed, &aad::vault_key(vault_id))?, "a vault key")
}

/// Seals an SA master key to an org owner or admin (AAD `ov-sa-master-v1|<sa>`).
pub fn seal_sa_master(recipient_enc_pk: &[u8], sa_id: &str, master: &[u8; 32]) -> Result<Vec<u8>, OvError> {
    seal(recipient_enc_pk, master, &aad::sa_master(sa_id))
}

/// [`seal_sa_master`] with fixed randomness (test vectors only).
pub fn seal_sa_master_with(
    recipient_enc_pk: &[u8],
    sa_id: &str,
    master: &[u8; 32],
    opts: &SealOptions,
) -> Result<Vec<u8>, OvError> {
    seal_with(recipient_enc_pk, master, &aad::sa_master(sa_id), opts)
}

/// Unseals an SA master key. Fails with `decryption_failed` if the plaintext isn't 32 bytes.
pub fn unseal_sa_master(enc_sk: &[u8; 32], sa_id: &str, sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>, OvError> {
    key32(unseal(enc_sk, sealed, &aad::sa_master(sa_id))?, "an SA master key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrip_and_errors() {
        let key = [5u8; 32];
        let blob = wrap(&key, b"hello", "a").unwrap();
        assert_eq!(blob.len(), WRAP_MIN_BYTES + 5);
        assert_eq!(&**unwrap(&key, &blob, "a").unwrap(), b"hello");
        assert!(unwrap(&key, &blob, "b").unwrap_err().is(OvErrorCode::DecryptionFailed));
        assert!(unwrap(&[6u8; 32], &blob, "a").unwrap_err().is(OvErrorCode::DecryptionFailed));
        let mut v2 = blob.clone();
        v2[0] = 2;
        assert!(unwrap(&key, &v2, "a").unwrap_err().is(OvErrorCode::UnsupportedVersion));
        assert!(unwrap(&key, &[], "a").unwrap_err().is(OvErrorCode::UnsupportedVersion));
        assert!(unwrap(&key, &blob[..WRAP_MIN_BYTES - 1], "a").unwrap_err().is(OvErrorCode::DecryptionFailed));
    }

    #[test]
    fn seal_rejects_all_zero_shared_secret() {
        let e = seal(&[0u8; 32], &[0u8; 32], "x").unwrap_err();
        assert!(e.is(OvErrorCode::LowOrderPoint));
        assert!(seal(&[1u8; 31], b"x", "x").unwrap_err().is(OvErrorCode::LowOrderPoint));
    }

    #[test]
    fn unseal_rejects_low_order_ephemeral_key() {
        let sk = [9u8; 32];
        let mut sealed = seal(&x25519_public_key(&sk), b"x", "a").unwrap();
        sealed[1..33].fill(0);
        assert!(unseal(&sk, &sealed, "a").unwrap_err().is(OvErrorCode::LowOrderPoint));
    }

    #[test]
    fn seal_roundtrip() {
        let sk = [9u8; 32];
        let pk = x25519_public_key(&sk);
        let sealed = seal_vault_key(&pk, "v", &[1u8; 32]).unwrap();
        assert_eq!(*unseal_vault_key(&sk, "v", &sealed).unwrap(), [1u8; 32]);
        assert!(unseal_vault_key(&sk, "w", &sealed).unwrap_err().is(OvErrorCode::DecryptionFailed));
    }
}
