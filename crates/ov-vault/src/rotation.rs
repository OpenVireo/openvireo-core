//! Key rotation (SPEC §7 "Key versions and rotation").
//!
//! 1. [`plan_rotation`]: a new key for `current + 1` and who keeps access (everyone in
//!    `GET /vaults/{id}/access` except the removed principals, plus the caller).
//! 2. The facade fetches each remaining member's public keys, then
//!    [`RotationPlan::start_request`] seals the new key to all of them: the
//!    `POST /vaults/{id}/keys` body (the server removes `remove` at once and stores the grants as
//!    pending).
//! 3. The facade adds [`RotationPlan::new_key`] to the vault's keys, downloads the blob, re-keys it
//!    (`ov_kdbx::vault::rekey_to_vault_key`) and uploads it with the conditional PUT.
//! 4. `POST /vaults/{id}/keys/{version}/activate`, then [`RotationPlan::rename_request`] re-encrypts
//!    the name under the new key and [`VaultKeys::activate`] records it.
//!
//! Port of `Account.rotate` in the TS SDK.

use ov_crypto::envelope::seal_vault_key;
use ov_crypto::keyset::PublicKeys as CryptoPublicKeys;
use ov_crypto::vault_name::encrypt_vault_name;
use ov_error::{OvError, OvErrorCode};
use ov_kdbx::vault::KeyVersion;
use ov_protocol::types::{
    Grant, Principal, PublicPrincipal, RenameVaultRequest, StartRotationRequest, VaultAccess, VaultRole,
};
use zeroize::Zeroizing;

use crate::keyring::VaultKeys;
use crate::keys::{b64u, public_of_principal, random_key, trusted};

/// A member who keeps access after a rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationMember {
    /// The principal.
    pub principal: Principal,
    /// Their role, unchanged.
    pub role: VaultRole,
}

/// A rotation in progress: the new key and who gets it. The key wipes itself on drop.
pub struct RotationPlan {
    vault_id: String,
    me: Principal,
    key_version: u32,
    key: Zeroizing<[u8; 32]>,
    members: Vec<RotationMember>,
    remove: Vec<Principal>,
}

impl std::fmt::Debug for RotationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationPlan")
            .field("vault_id", &self.vault_id)
            .field("key_version", &self.key_version)
            .field("key", &"[redacted]")
            .field("members", &self.members)
            .field("remove", &self.remove)
            .finish()
    }
}

/// Starts a rotation of `vault` by `me` (who must have `manage`: `forbidden` otherwise). `access` is
/// `GET /vaults/{id}/access`; `remove` the principals to take out (a revoke, a removed org member;
/// empty for a voluntary rotation).
///
/// Everyone in `access` not in `remove` keeps their role; `me` is always kept with its own role.
pub fn plan_rotation(
    vault: &VaultKeys,
    me: &str,
    access: &[VaultAccess],
    remove: &[Principal],
) -> Result<RotationPlan, OvError> {
    if !vault.can_manage() {
        return Err(OvError::new(OvErrorCode::Forbidden, "rotating a vault key needs the manage role").with_status(403));
    }
    let key_version = vault
        .info
        .current_key_version
        .checked_add(1)
        .ok_or_else(|| OvError::new(OvErrorCode::InvalidRequest, "the key version can't go higher"))?;
    let mut removed: Vec<Principal> = Vec::new();
    for p in remove {
        if !removed.contains(p) {
            removed.push(p.clone());
        }
    }
    let mut members: Vec<RotationMember> = Vec::new();
    let mut keep = |principal: &str, role: &VaultRole| match members.iter_mut().find(|m| m.principal == principal) {
        Some(m) => m.role = role.clone(),
        None => members.push(RotationMember { principal: principal.to_owned(), role: role.clone() }),
    };
    for a in access {
        if !removed.contains(&a.principal) {
            keep(&a.principal, &a.role);
        }
    }
    keep(me, &vault.info.role);
    Ok(RotationPlan {
        vault_id: vault.id().to_owned(),
        me: me.to_owned(),
        key_version,
        key: random_key()?,
        members,
        remove: removed,
    })
}

impl RotationPlan {
    /// The vault.
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// The new key version (`current + 1`).
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Who keeps access, with their roles (the caller included).
    pub fn members(&self) -> &[RotationMember] {
        &self.members
    }

    /// The principals removed at once by `POST keys`.
    pub fn removed(&self) -> &[Principal] {
        &self.remove
    }

    /// The members whose public keys the facade must fetch (everyone but the caller).
    pub fn principals_needing_keys(&self) -> Vec<Principal> {
        self.members.iter().filter(|m| m.principal != self.me).map(|m| m.principal.clone()).collect()
    }

    /// The `POST /vaults/{id}/keys` body: the new key sealed to every member. `my_public` is the
    /// caller's own keyset's public keys; `others` the fetched public keys of
    /// [`RotationPlan::principals_needing_keys`] (each signature is checked).
    ///
    /// Errors: `invalid_public_keys` when a member's keys are missing from `others` or don't verify.
    pub fn start_request(
        &self,
        my_public: &CryptoPublicKeys,
        others: &[PublicPrincipal],
    ) -> Result<StartRotationRequest, OvError> {
        let mut grants = Vec::with_capacity(self.members.len());
        for m in &self.members {
            let pk = if m.principal == self.me {
                *my_public
            } else {
                let found = others.iter().find(|p| p.principal == m.principal).ok_or_else(|| {
                    OvError::new(OvErrorCode::InvalidPublicKeys, format!("no public keys for {}", m.principal))
                })?;
                trusted(&public_of_principal(found))?
            };
            grants.push(Grant {
                principal: m.principal.clone(),
                role: m.role.clone(),
                key_version: i64::from(self.key_version),
                sealed_key: b64u(&seal_vault_key(&pk.enc_pk, &self.vault_id, &self.key)?),
            });
        }
        Ok(StartRotationRequest { key_version: i64::from(self.key_version), grants, remove: Some(self.remove.clone()) })
    }

    /// The new key, for re-keying the blob and for [`VaultKeys::add_key`].
    pub fn new_key(&self) -> KeyVersion {
        KeyVersion { version: self.key_version, key: Zeroizing::new(self.key.to_vec()) }
    }

    /// The `PATCH /vaults/{id}` body that re-encrypts the name under the new key (after activation).
    pub fn rename_request(&self, name: &str) -> Result<RenameVaultRequest, OvError> {
        Ok(RenameVaultRequest { encrypted_name: encrypt_vault_name(&self.key, &self.vault_id, name)? })
    }
}

/// `PATCH /vaults/{id}` body for a rename: the name encrypted under the vault's current key.
/// `no_vault_key` if this principal doesn't hold it.
pub fn rename_request(vault: &VaultKeys, name: &str) -> Result<RenameVaultRequest, OvError> {
    let key = vault.current_key_bytes()?;
    Ok(RenameVaultRequest { encrypted_name: encrypt_vault_name(&key, vault.id(), name)? })
}
