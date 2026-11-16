//! Unlocking from a sealed keyset (the web's `sealUnlocked` / `resumeUnlocked`, SPEC §20).
//!
//! The web app seals the unlocked keyset under a non-extractable WebCrypto AES-GCM key, so a page
//! reload doesn't ask for the master password. That seal (format `s1.<iv>.<data>`) stays in the TS
//! wrapper; the core gives it the 64 secret bytes ([`keyset_secret`]) and the AAD
//! ([`unlock_seal_aad`]), and checks what comes back ([`resume_keyset`]) against the account's public
//! keys, so a seal never unlocks another account or a reset one.

use ov_crypto::encoding::ct_eq;
use ov_crypto::keyset::{keyset_from_secrets, Keyset};
use ov_error::{OvError, OvErrorCode};
use ov_protocol::types::PublicKeys;
use zeroize::Zeroizing;

use crate::keys::trusted;

/// The version prefix of a sealed keyset string (`s1.<b64u iv>.<b64u AES-GCM(enc_sk ‖ sign_seed)>`).
pub const UNLOCK_SEAL_VERSION: &str = "s1";

/// The AES-GCM additional data that binds a sealed keyset to the issuer and the user:
/// `ov-unlock-seal-v1|<issuer without trailing slashes>|<user id>`.
pub fn unlock_seal_aad(issuer: &str, user_id: &str) -> String {
    format!("ov-unlock-seal-v1|{}|{user_id}", issuer.trim_end_matches('/'))
}

/// `enc_sk ‖ sign_seed`, the 64 bytes the seal encrypts. Wiped on drop.
pub fn keyset_secret(ks: &Keyset) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    out.extend_from_slice(ks.enc_sk.as_ref());
    out.extend_from_slice(ks.sign_seed.as_ref());
    out
}

/// Rebuilds the keyset from the 64 unsealed bytes and checks it is the account's: its public keys
/// must equal `account` (from `GET /me`, or offline the cached profile), whose signature must verify.
///
/// Errors: `decryption_failed` unless `plain` is 64 bytes; `invalid_public_keys` when `account`
/// doesn't verify or the keys differ (another account, or keys reset since the seal).
pub fn resume_keyset(plain: &[u8], account: &PublicKeys) -> Result<Keyset, OvError> {
    if plain.len() != 64 {
        return Err(OvError::new(OvErrorCode::DecryptionFailed, "the sealed keyset has the wrong length"));
    }
    let mut enc_sk = Zeroizing::new([0u8; 32]);
    let mut sign_seed = Zeroizing::new([0u8; 32]);
    enc_sk.copy_from_slice(&plain[..32]);
    sign_seed.copy_from_slice(&plain[32..]);
    let mut ks = keyset_from_secrets(&enc_sk, &sign_seed);
    let public = trusted(account)?;
    if !ct_eq(&ks.public.enc_pk, &public.enc_pk) || !ct_eq(&ks.public.sign_pk, &public.sign_pk) {
        return Err(OvError::new(OvErrorCode::InvalidPublicKeys, "the sealed keyset isn't this account's"));
    }
    ks.public.sig = public.sig;
    Ok(ks)
}
