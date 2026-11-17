//! The account's keyring on the facade: `ov_vault::Keyring` entries as facade records.

use ov_error::OvError;
use ov_kdbx::vault::KeyVersion;
use ov_vault::VaultKeys;

use super::convert::vault_role;
use crate::api::VaultInfo;

/// A listed vault with the keys this principal holds for it (`ov_vault::VaultKeys`) and its facade
/// record.
#[derive(Clone)]
pub(crate) struct VaultEntry {
    pub(crate) info: VaultInfo,
    pub(crate) vk: VaultKeys,
}

impl VaultEntry {
    pub(crate) fn of(vk: &VaultKeys) -> VaultEntry {
        let i = &vk.info;
        VaultEntry {
            info: VaultInfo {
                id: i.id.clone(),
                name: i.name.clone(),
                role: vault_role(&i.role),
                org_id: i.org_id.clone(),
                current_key_version: i.current_key_version,
                pending_key_version: i.pending_key_version,
                rotation_required: i.rotation_required,
            },
            vk: vk.clone(),
        }
    }

    /// Every key held, newest first.
    pub(crate) fn keys(&self) -> &[KeyVersion] {
        self.vk.keys()
    }

    /// The current key's bytes (`no_vault_key` when not held).
    pub(crate) fn current_key_bytes(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, OvError> {
        self.vk.current_key_bytes()
    }
}
