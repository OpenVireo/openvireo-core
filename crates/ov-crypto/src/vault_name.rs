//! SPEC §4 and §7: vault names encrypted under a key derived from the vault key, so the auth server
//! never learns them.
//!
//! Port of `packages/sdk/src/crypto/vault-name.ts`.

use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::encoding::{b64u, from_b64u};
use crate::envelope::{aad, unwrap, wrap, wrap_with_nonce};
use crate::primitives::{hkdf_sha256_32, NONCE_BYTES};

/// `HKDF(vault_key, salt = "", info = "ov-vault-name-v1")`.
pub fn vault_name_key(vault_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256_32(vault_key, &[], b"ov-vault-name-v1")
}

/// Encrypts a vault name: base64url `wrap(name_key, utf8(name), "ov-vault-name|<vault>")`.
pub fn encrypt_vault_name(vault_key: &[u8; 32], vault_id: &str, name: &str) -> Result<String, OvError> {
    let k = vault_name_key(vault_key);
    Ok(b64u(&wrap(&k, name.as_bytes(), &aad::vault_name(vault_id))?))
}

/// [`encrypt_vault_name`] with a fixed nonce (test vectors only).
pub fn encrypt_vault_name_with_nonce(
    vault_key: &[u8; 32],
    vault_id: &str,
    name: &str,
    nonce: &[u8; NONCE_BYTES],
) -> String {
    let k = vault_name_key(vault_key);
    b64u(&wrap_with_nonce(&k, name.as_bytes(), &aad::vault_name(vault_id), nonce))
}

/// Decrypts a vault name. Fails with [`OvErrorCode::DecryptionFailed`] for the wrong key or vault
/// id, changed data, bad base64url or a name that isn't UTF-8, and `unsupported_version` for an
/// unknown envelope version.
pub fn decrypt_vault_name(vault_key: &[u8; 32], vault_id: &str, encrypted_name: &str) -> Result<String, OvError> {
    let k = vault_name_key(vault_key);
    let blob = from_b64u(encrypted_name)
        .map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "encrypted vault name is not valid base64url"))?;
    let plain = unwrap(&k, &blob, &aad::vault_name(vault_id))?;
    String::from_utf8(plain.to_vec())
        .map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "vault name is not UTF-8"))
}
