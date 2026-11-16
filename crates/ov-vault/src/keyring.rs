//! The keyring (SPEC §5, §7): every vault this principal can open, with the vault keys it holds for
//! each key version, unsealed with its keyset, and the vault names decrypted.
//!
//! Port of `Account.ingest` / `ServiceAccount.listVaults` in the TS SDK. A sealed key that doesn't
//! open (sealed to an older keyset) is skipped, so the other version may still work; the name is
//! decrypted with the newest key that opens it.

use std::collections::BTreeMap;

use ov_crypto::envelope::unseal_vault_key;
use ov_crypto::keyset::Keyset;
use ov_crypto::vault_name::decrypt_vault_name;
use ov_error::{OvError, OvErrorCode};
use ov_kdbx::vault::KeyVersion;
use ov_protocol::types::{Vault, VaultRole};
use zeroize::Zeroizing;

use crate::keys::{role_rank, sealed_bytes};

/// A vault this principal can open, name decrypted (the SDK's `VaultInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    /// The vault id.
    pub id: String,
    /// The decrypted name (`""` if no held key opens it).
    pub name: String,
    /// This principal's role.
    pub role: VaultRole,
    /// The org, for an org vault.
    pub org_id: Option<String>,
    /// The current key version (SPEC §7).
    pub current_key_version: u32,
    /// A rotation in progress.
    pub pending_key_version: Option<u32>,
    /// A member was removed and the vault needs a rotation.
    pub rotation_required: bool,
}

/// One vault and the keys this principal holds for it, newest version first. The keys wipe
/// themselves on drop.
#[derive(Clone, Debug)]
pub struct VaultKeys {
    /// What the vault list says about it.
    pub info: VaultInfo,
    keys: Vec<KeyVersion>,
}

/// A key version from the wire: negative or too large values aren't versions.
fn version(v: i64) -> Option<u32> {
    u32::try_from(v).ok()
}

impl VaultKeys {
    /// Unseals the keys of a listed vault (`GET /vaults`, `GET /vaults/{id}`) with this principal's
    /// keyset and decrypts its name. Never fails: keys that don't open are left out (then
    /// [`VaultKeys::current_key`] is `no_vault_key`), and a name no key opens is `""`.
    pub fn from_vault(v: &Vault, keyset: &Keyset) -> VaultKeys {
        let mut keys: Vec<KeyVersion> = Vec::new();
        for k in &v.keys {
            let Some(ver) = version(k.key_version) else { continue };
            let Ok(sealed) = sealed_bytes(&k.sealed_key) else { continue };
            if let Ok(key) = unseal_vault_key(&keyset.enc_sk, &v.id, &sealed) {
                keys.retain(|x| x.version != ver);
                keys.push(KeyVersion { version: ver, key: Zeroizing::new(key.to_vec()) });
            }
        }
        keys.sort_by_key(|k| std::cmp::Reverse(k.version));
        let mut name = String::new();
        for k in &keys {
            if let Ok(n) = decrypt_vault_name(&key_array(&k.key), &v.id, &v.encrypted_name) {
                name = n;
                break;
            }
        }
        VaultKeys {
            info: VaultInfo {
                id: v.id.clone(),
                name,
                role: v.role.clone(),
                org_id: v.org_id.clone(),
                current_key_version: version(v.current_key_version).unwrap_or(0),
                pending_key_version: v.pending_key_version.and_then(version),
                rotation_required: v.rotation_required.unwrap_or(false),
            },
            keys,
        }
    }

    /// The vault id.
    pub fn id(&self) -> &str {
        &self.info.id
    }

    /// Every key held, newest version first: what `ov_kdbx::vault::open_with_key_versions` takes.
    pub fn keys(&self) -> &[KeyVersion] {
        &self.keys
    }

    /// The key of one version.
    pub fn key(&self, version: u32) -> Option<&KeyVersion> {
        self.keys.iter().find(|k| k.version == version)
    }

    /// The key of the current version, the one new grants are sealed with. `no_vault_key` if this
    /// principal doesn't hold it.
    pub fn current_key(&self) -> Result<&KeyVersion, OvError> {
        self.key(self.info.current_key_version)
            .ok_or_else(|| OvError::new(OvErrorCode::NoVaultKey, format!("no current key for vault {}", self.info.id)))
    }

    /// The current key as 32 bytes (see [`VaultKeys::current_key`]).
    pub fn current_key_bytes(&self) -> Result<Zeroizing<[u8; 32]>, OvError> {
        Ok(key_array(&self.current_key()?.key))
    }

    /// Whether this principal has `manage` (needed to share, rotate and rename).
    pub fn can_manage(&self) -> bool {
        role_rank(&self.info.role) >= role_rank(&VaultRole::Manage)
    }

    /// Whether this principal may change the vault (`write` or `manage`).
    pub fn can_write(&self) -> bool {
        role_rank(&self.info.role) >= role_rank(&VaultRole::Write)
    }

    /// Adds (or replaces) a key version, keeping newest first. A rotation adds its new key before the
    /// re-keyed upload, so both versions open the vault until it is activated.
    pub fn add_key(&mut self, key: KeyVersion) {
        self.keys.retain(|k| k.version != key.version);
        self.keys.push(key);
        self.keys.sort_by_key(|k| std::cmp::Reverse(k.version));
    }

    /// Records an activated rotation: `version` becomes current, nothing is pending and the vault no
    /// longer needs a rotation. Older keys stay until the next vault list drops them.
    pub fn activate(&mut self, version: u32) {
        self.info.current_key_version = version;
        self.info.pending_key_version = None;
        self.info.rotation_required = false;
    }
}

/// A 32-byte key from a [`KeyVersion`] (whose length `ov-kdbx` checks when it builds credentials);
/// a key of another length gives all zeroes, which opens nothing.
pub(crate) fn key_array(key: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    if key.len() == 32 {
        out.copy_from_slice(key);
    }
    out
}

/// The result of [`Keyring::ingest_list`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ingested {
    /// Every listed vault, in the server's order.
    pub vaults: Vec<VaultInfo>,
    /// Vaults the keyring held that the list no longer has (access removed or vault deleted). Their
    /// keys are already wiped; the caller drops anything else it kept for them (SPEC §20).
    pub dropped: Vec<String>,
}

/// The vaults one principal can open, by id.
#[derive(Clone, Debug, Default)]
pub struct Keyring {
    vaults: BTreeMap<String, VaultKeys>,
}

impl Keyring {
    /// An empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or refreshes one vault (`GET /vaults/{id}`, a created vault).
    pub fn ingest(&mut self, v: &Vault, keyset: &Keyset) -> &VaultKeys {
        self.vaults.insert(v.id.clone(), VaultKeys::from_vault(v, keyset));
        &self.vaults[&v.id]
    }

    /// Replaces the keyring with a full vault list (`GET /vaults`).
    pub fn ingest_list(&mut self, list: &[Vault], keyset: &Keyset) -> Ingested {
        let dropped: Vec<String> =
            self.vaults.keys().filter(|id| !list.iter().any(|v| &v.id == *id)).cloned().collect();
        for id in &dropped {
            self.vaults.remove(id);
        }
        let vaults = list.iter().map(|v| self.ingest(v, keyset).info.clone()).collect();
        Ingested { vaults, dropped }
    }

    /// One vault.
    pub fn get(&self, vault_id: &str) -> Option<&VaultKeys> {
        self.vaults.get(vault_id)
    }

    /// One vault, mutable (to add a rotation's key or record its activation).
    pub fn get_mut(&mut self, vault_id: &str) -> Option<&mut VaultKeys> {
        self.vaults.get_mut(vault_id)
    }

    /// One vault, or `not_found` naming it.
    pub fn require(&self, vault_id: &str) -> Result<&VaultKeys, OvError> {
        self.get(vault_id)
            .ok_or_else(|| OvError::new(OvErrorCode::NotFound, format!("vault {vault_id} not found")).with_status(404))
    }

    /// Removes a vault (deleted, or access lost) and wipes its keys.
    pub fn remove(&mut self, vault_id: &str) -> Option<VaultKeys> {
        self.vaults.remove(vault_id)
    }

    /// Every vault, by id.
    pub fn iter(&self) -> impl Iterator<Item = &VaultKeys> {
        self.vaults.values()
    }

    /// Every vault's info, by id.
    pub fn infos(&self) -> Vec<VaultInfo> {
        self.iter().map(|v| v.info.clone()).collect()
    }

    /// The number of vaults.
    pub fn len(&self) -> usize {
        self.vaults.len()
    }

    /// Whether it holds no vault.
    pub fn is_empty(&self) -> bool {
        self.vaults.is_empty()
    }

    /// Drops every vault and wipes the keys (lock, sign-out).
    pub fn clear(&mut self) {
        self.vaults.clear();
    }

    /// The org's vaults this principal manages: what a confirmed or promoted owner/admin gets
    /// (SPEC §12).
    pub fn managed_org_vaults(&self, org_id: &str) -> Vec<&VaultKeys> {
        self.iter().filter(|v| v.info.org_id.as_deref() == Some(org_id) && v.can_manage()).collect()
    }

    /// The org's vaults the server flagged (`rotation_required`, after a member was removed) that
    /// this principal manages and so rotates (SPEC §12, §7).
    pub fn flagged_for_rotation(&self, org_id: &str) -> Vec<&VaultKeys> {
        self.managed_org_vaults(org_id).into_iter().filter(|v| v.info.rotation_required).collect()
    }
}
