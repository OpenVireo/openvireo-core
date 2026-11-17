//! Vault sharing (SPEC §7), orgs (§12) and service-account administration (§9) on the facade.
//! Sealing the current vault key to one verified recipient uses the keyring glue; rotation, member
//! confirmation with the org grant rule and SA master keys are `ov-vault`'s (W2-V) and return
//! [`needs_vault`] until it merges.

use ov_error::{OvError, OvErrorCode};
use ov_protocol::auth as api;
use ov_protocol::parse_empty;
use ov_protocol::types as w;

use super::convert::{api_public_keys, wire_org_role, wire_vault_role};
use super::vault_glue::{key_array, needs_vault, seal_vault_key_to, verified_keys};
use crate::api::{
    Account, CancelToken, GrantResult, Grantee, Member, OrgRole, Principal, RotationFailure, RotationReport,
    ShareRecipient, SyncReport, VaultRole,
};

fn recipient(pp: &w::PublicPrincipal) -> Result<ShareRecipient, OvError> {
    let keys =
        verified_keys(&w::PublicKeys { enc_pk: pp.enc_pk.clone(), sign_pk: pp.sign_pk.clone(), sig: pp.sig.clone() })?;
    Ok(ShareRecipient {
        principal: pp.principal.clone(),
        email: pp.email.clone(),
        name: pp.name.clone(),
        public_keys: api_public_keys(&keys),
    })
}

impl Account {
    pub(crate) async fn public_principal(
        &self,
        who: &Grantee,
        cancel: &CancelToken,
    ) -> Result<w::PublicPrincipal, OvError> {
        match who {
            Grantee::Principal(p) => {
                self.call(cancel, |a, t| a.build_public_key(t, p), api::parse_public_principal).await
            }
            Grantee::Email(e) => {
                self.call(cancel, |a, t| a.build_lookup_user(t, e.trim()), api::parse_public_principal).await
            }
        }
    }

    pub(crate) async fn recipient_impl(
        &self,
        who: Grantee,
        display: Option<String>,
        cancel: &CancelToken,
    ) -> Result<ShareRecipient, OvError> {
        let pp = self.public_principal(&who, cancel).await?;
        let mut r = recipient(&pp)?;
        if display.is_some() {
            r.name = display;
        }
        Ok(r)
    }

    /// Seals the vault's current key to the grantee after checking their keys (SPEC §6, §7).
    pub(crate) async fn share_vault_impl(
        &self,
        vault_id: &str,
        who: Grantee,
        role: VaultRole,
        cancel: &CancelToken,
    ) -> Result<GrantResult, OvError> {
        let e = self.entry(vault_id, cancel).await?;
        let current = e
            .current_key()
            .ok_or_else(|| OvError::new(OvErrorCode::NoVaultKey, "this account doesn't hold the current vault key"))?;
        let pp = self.public_principal(&who, cancel).await?;
        let r = recipient(&pp)?;
        let sealed = seal_vault_key_to(&r.public_keys.enc_pk, vault_id, &*key_array(current)?)?;
        let grant = w::Grant {
            principal: pp.principal.clone(),
            role: wire_vault_role(role),
            key_version: i64::from(current.version),
            sealed_key: sealed,
        };
        self.call(cancel, |a, t| a.build_grant_access(t, vault_id, std::slice::from_ref(&grant)), parse_empty).await?;
        Ok(GrantResult { principal: pp.principal, fingerprint: r.public_keys.fingerprint })
    }

    /// Key rotation (SPEC §7).
    // W2-V + W2-Y: ov_vault builds the rotation (new key sealed to every remaining member, POST keys),
    // ov_sync re-keys and uploads, then activate and re-encrypt the name.
    pub(crate) async fn rotate_impl(
        &self,
        vault_id: &str,
        remove: Vec<Principal>,
        cancel: &CancelToken,
    ) -> Result<SyncReport, OvError> {
        let e = self.entry(vault_id, cancel).await?;
        if e.info.role < VaultRole::Manage {
            return Err(
                OvError::new(OvErrorCode::Forbidden, "rotating a vault key needs the manage role").with_status(403)
            );
        }
        let _ = remove;
        Err(needs_vault())
    }

    /// Rotates every flagged org vault this account manages; failures are reported.
    pub(crate) async fn rotate_flagged_impl(
        &self,
        org_id: &str,
        cancel: &CancelToken,
    ) -> Result<RotationReport, OvError> {
        let mut report = RotationReport { rotated: vec![], failed: vec![] };
        for v in self.load_vault_list(cancel).await?.0 {
            if v.org_id.as_deref() != Some(org_id) || !v.rotation_required || v.role != VaultRole::Manage {
                continue;
            }
            match self.rotate_impl(&v.id, vec![], cancel).await {
                Ok(_) => report.rotated.push(v.id),
                Err(error) => report.failed.push(RotationFailure { vault_id: v.id, error }),
            }
        }
        Ok(report)
    }

    /// Confirms an accepted member (SPEC §12). A member confirmed with no vaults needs no sealing;
    /// anything else (vault grants, an owner/admin's SA master keys) is `ov-vault`'s.
    // W2-V: ov_vault member confirmation with the org grant rule and SA master keys.
    pub(crate) async fn confirm_member_impl(
        &self,
        org_id: &str,
        member: Member,
        vaults: Vec<crate::api::VaultGrantRequest>,
        cancel: &CancelToken,
    ) -> Result<Member, OvError> {
        let public = member.public_keys.as_ref().ok_or_else(|| {
            OvError::new(OvErrorCode::InvalidRequest, "this member has no public keys yet").with_status(400)
        })?;
        verified_keys(&super::convert::wire_public_from_api(public))?;
        let manager = matches!(member.role, OrgRole::Owner | OrgRole::Admin);
        if manager || !vaults.is_empty() {
            return Err(needs_vault());
        }
        let body = w::ConfirmMemberRequest { grants: Some(vec![]), sa_master_keys: None };
        let m = self
            .call(cancel, |a, t| a.build_confirm_member(t, org_id, &member.user_id, &body), api::parse_member)
            .await?;
        Ok(super::convert::member(&m))
    }

    /// Changes a member's role. A promotion of a confirmed member hands over SA master keys and
    /// vault access, which is `ov-vault`'s; other changes are plain.
    // W2-V: ov_vault promotion (SA master keys + manage on managed org vaults).
    pub(crate) async fn set_member_role_impl(
        &self,
        org_id: &str,
        member: Member,
        role: OrgRole,
        cancel: &CancelToken,
    ) -> Result<Member, OvError> {
        let promote = matches!(role, OrgRole::Owner | OrgRole::Admin)
            && member.status == crate::api::MemberStatus::Confirmed
            && member.public_keys.is_some();
        if promote {
            return Err(needs_vault());
        }
        let body = w::SetMemberRoleRequest { role: wire_org_role(role), sa_master_keys: None };
        let m = self
            .call(cancel, |a, t| a.build_set_member_role(t, org_id, &member.user_id, &body), api::parse_member)
            .await?;
        Ok(super::convert::member(&m))
    }
}
