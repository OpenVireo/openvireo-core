//! Glue to W2-V's `ov-vault` (keyring, sealing, rotation, member confirmation, SA master keys,
//! `ov://` references). `ov-vault` isn't merged yet, so this module is the only place the facade
//! touches that logic:
//!
//! - the keyring helpers below ([`ingest`], [`seal_vault_key_to`], [`verified_keys`]) are thin
//!   compositions of `ov-crypto` calls the facade needs today; each is marked `// W2-V:` and switches
//!   to `ov_vault`'s functions when it merges;
//! - everything else that would duplicate `ov-vault` returns [`needs_vault`] (`internal`,
//!   "needs ov-vault") until then.

use ov_crypto::encoding::{b64u, from_b64u};
use ov_crypto::keyset::{Keyset, PublicKeys};
use ov_error::OvError;
use ov_kdbx::vault::KeyVersion;
use ov_protocol::types as w;
use zeroize::Zeroizing;

use super::convert::{crypto_public_json, vault_role};
use crate::api::VaultInfo;

/// Whether `ov-vault` is wired in. Callers check it before a server-side step whose follow-up would
/// need it (so nothing is half-done).
pub(crate) const AVAILABLE: bool = false;

/// The fallback for operations `ov-vault` owns.
pub(crate) fn needs_vault() -> OvError {
    OvError::internal("needs ov-vault")
}

/// A listed vault and the keys this principal holds for it (newest first).
#[derive(Clone)]
pub(crate) struct VaultEntry {
    pub(crate) info: VaultInfo,
    pub(crate) keys: Vec<KeyVersion>,
}

impl VaultEntry {
    /// The key of the vault's current version, if held.
    pub(crate) fn current_key(&self) -> Option<&KeyVersion> {
        self.keys.iter().find(|k| k.version == self.info.current_key_version)
    }
}

/// A key version as a 32-byte array.
pub(crate) fn key_array(k: &KeyVersion) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let mut out = Zeroizing::new([0u8; 32]);
    if k.key.len() != 32 {
        return Err(OvError::new(ov_error::OvErrorCode::NoVaultKey, "a vault key is 32 bytes"));
    }
    out.copy_from_slice(&k.key);
    Ok(out)
}

/// Unseals the vault keys this keyset can open and decrypts the name (TS `Account.ingest`).
// W2-V: ov_vault keyring ingest.
pub(crate) fn ingest(ks: &Keyset, v: &w::Vault) -> VaultEntry {
    let mut keys: Vec<KeyVersion> = Vec::new();
    for k in &v.keys {
        let Ok(sealed) = from_b64u(&k.sealed_key) else { continue };
        // A key sealed to an old keyset is skipped; another version may open.
        if let Ok(key) = ov_crypto::envelope::unseal_vault_key(&ks.enc_sk, &v.id, &sealed) {
            keys.push(KeyVersion { version: k.key_version.clamp(0, u32::MAX as i64) as u32, key: Zeroizing::new(key.to_vec()) });
        }
    }
    keys.sort_by_key(|k| std::cmp::Reverse(k.version));
    let mut name = String::new();
    for k in &keys {
        if let Ok(arr) = key_array(k) {
            if let Ok(n) = ov_crypto::vault_name::decrypt_vault_name(&arr, &v.id, &v.encrypted_name) {
                name = n;
                break;
            }
        }
    }
    VaultEntry {
        info: VaultInfo {
            id: v.id.clone(),
            name,
            role: vault_role(&v.role),
            org_id: v.org_id.clone(),
            current_key_version: v.current_key_version.clamp(0, u32::MAX as i64) as u32,
            pending_key_version: v.pending_key_version.map(|p| p.clamp(0, u32::MAX as i64) as u32),
            rotation_required: v.rotation_required.unwrap_or(false),
        },
        keys,
    }
}

/// Seals a vault key to a recipient's (verified) X25519 key, base64url.
// W2-V: ov_vault member sealing.
pub(crate) fn seal_vault_key_to(enc_pk: &[u8], vault_id: &str, key: &[u8; 32]) -> Result<String, OvError> {
    Ok(b64u(&ov_crypto::envelope::seal_vault_key(enc_pk, vault_id, key)?))
}

/// A principal's keys after checking their signature (SPEC §5).
// W2-V: ov_vault verified recipient keys.
pub(crate) fn verified_keys(p: &w::PublicKeys) -> Result<PublicKeys, OvError> {
    ov_crypto::keyset::trusted_public_keys(&crypto_public_json(p))
}
