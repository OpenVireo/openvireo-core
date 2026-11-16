//! SPEC §18: restoring archived vault keys after an account reset, the proof that the restorer
//! holds the old keyset, and the reseal of each archived vault key to the current keyset.
//!
//! Port of `packages/sdk/src/crypto/restore.ts`.

use ov_error::{OvError, OvErrorCode};

use crate::curves::{ed25519_sign, ed25519_verify};
use crate::envelope::{seal_vault_key_with, unseal_vault_key, SealOptions};

/// `"ov-restore-v1" ‖ utf8(user id) ‖ current enc_pk ‖ current sign_pk`. The user id is the
/// 36-character uuid string; "current" is the account's public keys after the reset.
pub fn restore_proof_message(user_id: &str, current_enc_pk: &[u8; 32], current_sign_pk: &[u8; 32]) -> Vec<u8> {
    [b"ov-restore-v1".as_slice(), user_id.as_bytes(), current_enc_pk, current_sign_pk].concat()
}

/// `proof = Ed25519.sign(old sign_seed, restore_proof_message(…))`: shows the restorer holds the
/// archived keyset (and so the old Secret Key).
pub fn restore_proof(
    old_sign_seed: &[u8; 32],
    user_id: &str,
    current_enc_pk: &[u8; 32],
    current_sign_pk: &[u8; 32],
) -> [u8; 64] {
    ed25519_sign(&restore_proof_message(user_id, current_enc_pk, current_sign_pk), old_sign_seed)
}

/// What the server checks: `proof` against the archived `sign_pk`. `false` for a proof that isn't
/// 64 bytes or doesn't verify.
pub fn verify_restore_proof(
    proof: &[u8],
    user_id: &str,
    current_enc_pk: &[u8; 32],
    current_sign_pk: &[u8; 32],
    old_sign_pk: &[u8],
) -> bool {
    proof.len() == 64
        && ed25519_verify(proof, &restore_proof_message(user_id, current_enc_pk, current_sign_pk), old_sign_pk)
}

/// [`verify_restore_proof`] as a `Result`: fails with [`OvErrorCode::InvalidProof`] (the server's
/// 400 `invalid_proof`).
pub fn check_restore_proof(
    proof: &[u8],
    user_id: &str,
    current_enc_pk: &[u8; 32],
    current_sign_pk: &[u8; 32],
    old_sign_pk: &[u8],
) -> Result<(), OvError> {
    if verify_restore_proof(proof, user_id, current_enc_pk, current_sign_pk, old_sign_pk) {
        Ok(())
    } else {
        Err(OvError::new(OvErrorCode::InvalidProof, "the restore proof doesn't verify against the archived keys"))
    }
}

/// Unseals an archived vault key with the old `enc_sk` (AAD `ov-vault-key|<vault>`) and seals it to
/// the current `enc_pk`.
pub fn reseal_vault_key(
    old_enc_sk: &[u8; 32],
    current_enc_pk: &[u8; 32],
    vault_id: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, OvError> {
    reseal_vault_key_with(old_enc_sk, current_enc_pk, vault_id, sealed, &SealOptions::default())
}

/// [`reseal_vault_key`] with fixed randomness (test vectors only).
pub fn reseal_vault_key_with(
    old_enc_sk: &[u8; 32],
    current_enc_pk: &[u8; 32],
    vault_id: &str,
    sealed: &[u8],
    opts: &SealOptions,
) -> Result<Vec<u8>, OvError> {
    let key = unseal_vault_key(old_enc_sk, vault_id, sealed)?;
    seal_vault_key_with(current_enc_pk, vault_id, &key, opts)
}
