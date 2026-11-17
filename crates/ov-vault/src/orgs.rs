//! Org members (SPEC §12 "Confirming members"): confirming an accepted member, promoting one to
//! owner/admin, and which vaults to rotate after a removal.
//!
//! Port of `Account.confirmMember`, `setMemberRole` and `removeMember` in the TS SDK.
//!
//! - An **owner or admin** gets every org vault the confirming principal manages, with `manage`,
//!   plus the org's SA master keys it holds ([`crate::service_account::seal_sa_master_keys`]).
//! - A **member** gets only the vaults picked for them, with the role picked for each, and no SA
//!   master keys. An empty pick is valid.

use ov_crypto::keyset::PublicKeys as CryptoPublicKeys;
use ov_error::{OvError, OvErrorCode};
use ov_protocol::types::{
    ConfirmMemberRequest, Member, MemberStatus, OrgRole, Principal, SaMasterGrant, SetMemberRoleRequest, VaultGrant,
    VaultRole,
};

use crate::keyring::Keyring;
use crate::keys::{is_manager, trusted, user_principal};
use crate::sharing::seal_grant;

/// A vault picked for a member, with the role they get on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultChoice {
    /// The vault id.
    pub vault_id: String,
    /// The role.
    pub role: VaultRole,
}

/// An org member whose keys were checked, ready to have keys sealed to them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberKeys {
    /// `user:<id>`.
    pub principal: Principal,
    /// Their verified public keys.
    pub public: CryptoPublicKeys,
    /// Whether their org role is owner or admin.
    pub manager: bool,
}

/// Checks a member before confirming them. `invalid_request` (400) when they have no public keys
/// yet; `invalid_public_keys` when the signature doesn't verify.
pub fn member_keys(member: &Member) -> Result<MemberKeys, OvError> {
    let Some(public) = &member.public else {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "this member has no public keys yet").with_status(400));
    };
    Ok(MemberKeys {
        principal: user_principal(&member.user_id),
        public: trusted(public)?,
        manager: is_manager(&member.role),
    })
}

/// The vaults a confirmation grants: for an owner/admin every org vault `keyring` manages (with
/// `manage`, `picked` is ignored), for a member `picked`.
pub fn confirm_choices(
    org_id: &str,
    target: &MemberKeys,
    keyring: &Keyring,
    picked: &[VaultChoice],
) -> Vec<VaultChoice> {
    if target.manager {
        keyring
            .managed_org_vaults(org_id)
            .into_iter()
            .map(|v| VaultChoice { vault_id: v.id().to_owned(), role: VaultRole::Manage })
            .collect()
    } else {
        picked.to_vec()
    }
}

/// The picked vaults `keyring` doesn't hold yet: the facade loads each (`GET /vaults/{id}`) into
/// the keyring before [`confirm_member_request`].
pub fn missing_vaults(keyring: &Keyring, picked: &[VaultChoice]) -> Vec<String> {
    picked.iter().filter(|c| keyring.get(&c.vault_id).is_none()).map(|c| c.vault_id.clone()).collect()
}

/// The `POST /orgs/{org}/members/{user}/confirm` body: each vault of [`confirm_choices`] sealed to
/// the member at its current key version, and, for an owner/admin only, `sa_master_keys` (an empty
/// list when the org has none or `None` is passed).
///
/// Errors: `invalid_request` (400) for a vault that isn't the org's; `no_vault_key` when the
/// current key isn't held; `not_found` for a vault not in `keyring` (see [`missing_vaults`]).
pub fn confirm_member_request(
    org_id: &str,
    target: &MemberKeys,
    keyring: &Keyring,
    picked: &[VaultChoice],
    sa_master_keys: Option<Vec<SaMasterGrant>>,
) -> Result<ConfirmMemberRequest, OvError> {
    let mut grants = Vec::new();
    for c in confirm_choices(org_id, target, keyring, picked) {
        let vault = keyring.require(&c.vault_id)?;
        if vault.info.org_id.as_deref() != Some(org_id) {
            return Err(OvError::new(
                OvErrorCode::InvalidRequest,
                format!("vault {} is not a vault of this org", c.vault_id),
            )
            .with_status(400));
        }
        let g = seal_grant(vault, &target.principal, &target.public, c.role)?.grant;
        grants.push(VaultGrant {
            principal: g.principal,
            role: g.role,
            key_version: g.key_version,
            sealed_key: g.sealed_key,
            vault_id: c.vault_id,
        });
    }
    Ok(ConfirmMemberRequest {
        grants: Some(grants),
        sa_master_keys: target.manager.then(|| sa_master_keys.unwrap_or_default()),
    })
}

/// Whether changing `member`'s role to `role` is a promotion that hands over keys: a confirmed
/// member with public keys becoming owner/admin. Then the facade seals the SA master keys to them
/// ([`set_member_role_request`]) and, after the role change, grants `manage` on every vault of
/// [`Keyring::managed_org_vaults`]. `invalid_public_keys` if their signature doesn't verify.
pub fn promotion(member: &Member, role: &OrgRole) -> Result<Option<MemberKeys>, OvError> {
    if !is_manager(role) || member.status != MemberStatus::Confirmed || member.public.is_none() {
        return Ok(None);
    }
    let mut keys = member_keys(member)?;
    keys.manager = true;
    Ok(Some(keys))
}

/// The `PATCH /orgs/{org}/members/{user}` body. Pass `sa_master_keys` on a promotion
/// ([`promotion`]), `None` otherwise (the server drops them on a demotion).
pub fn set_member_role_request(role: OrgRole, sa_master_keys: Option<Vec<SaMasterGrant>>) -> SetMemberRoleRequest {
    SetMemberRoleRequest { role, sa_master_keys }
}
