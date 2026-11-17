//! Vault sharing and key rotation (SPEC §7), orgs and members (§12), service-account
//! administration (§9, §15) and the org audit log.

use ov_error::OvError;

use super::{
    Account, AuditPage, CancelToken, CreatedServiceAccount, ExpiryChange, GrantResult, Grantee, Invitation,
    IssuedSecret, Member, NewServiceAccount, Org, OrgMembership, OrgRole, Principal, PublicKeys, Rfc3339,
    RotationReport, SaSecretInfo, SecretBytes, ServiceAccountInfo, ServiceAccountUpdate, ShareLinkPolicy,
    ShareRecipient, SyncReport, VaultGrantRequest, VaultInfo, VaultMember, VaultRole,
};

impl Account {
    // --------------------------------------------------------------------- vault sharing (§7)

    /// Who has access to a vault, with display names (`GET /vaults/{id}/access`).
    pub async fn members(&self, vault_id: String, cancel: CancelToken) -> Result<Vec<VaultMember>, OvError> {
        let me = self.principal_str()?;
        let l = self.call(&cancel, |a, t| a.build_list_access(t, &vault_id), ov_protocol::auth::parse_access).await?;
        Ok(l.access
            .into_iter()
            .map(|a| VaultMember {
                is_you: a.principal == me,
                display: a.display.unwrap_or_else(|| a.principal.clone()),
                role: crate::impls::convert::vault_role(&a.role),
                key_version: a.key_version.clamp(0, u32::MAX as i64) as u32,
                principal: a.principal,
            })
            .collect())
    }

    /// A principal's public keys, verified (signature, SPEC §5) before anything is sealed to them.
    pub async fn verified_public_keys(&self, principal: Principal, cancel: CancelToken) -> Result<PublicKeys, OvError> {
        Ok(self.recipient_impl(Grantee::Principal(principal), None, &cancel).await?.public_keys)
    }

    /// Looks a user up by email, keys verified, to show their fingerprint before sharing.
    pub async fn look_up(&self, email: String, cancel: CancelToken) -> Result<ShareRecipient, OvError> {
        self.recipient_impl(Grantee::Email(email), None, &cancel).await
    }

    /// A recipient for a known principal (keys verified), with an optional display name.
    pub async fn recipient(
        &self,
        principal: Principal,
        display: Option<String>,
        cancel: CancelToken,
    ) -> Result<ShareRecipient, OvError> {
        self.recipient_impl(Grantee::Principal(principal), display, &cancel).await
    }

    /// Grants (or changes) access: seals the current vault key to the grantee after checking their
    /// keys (SPEC §6, §7). `no_vault_key` if this account doesn't hold the current key.
    pub async fn share_vault(
        &self,
        vault_id: String,
        grantee: Grantee,
        role: VaultRole,
        cancel: CancelToken,
    ) -> Result<GrantResult, OvError> {
        self.share_vault_impl(&vault_id, grantee, role, &cancel).await
    }

    /// Changes a member's role on a vault (re-grants at the current key version).
    pub async fn change_role(
        &self,
        vault_id: String,
        principal: Principal,
        role: VaultRole,
        cancel: CancelToken,
    ) -> Result<(), OvError> {
        self.share_vault_impl(&vault_id, Grantee::Principal(principal), role, &cancel).await.map(|_| ())
    }

    /// Removes members and rotates the vault key in one step (SPEC §7).
    pub async fn revoke(
        &self,
        vault_id: String,
        principals: Vec<Principal>,
        cancel: CancelToken,
    ) -> Result<SyncReport, OvError> {
        self.rotate_impl(&vault_id, principals, &cancel).await
    }

    /// Key rotation (SPEC §7 "Key versions and rotation"): a new key sealed to every remaining
    /// member, `POST keys` (removing `remove` at once), download, re-key, conditional PUT (merge and
    /// retry on 412), activate, and re-encrypt the name. Needs `manage` (`forbidden` otherwise).
    pub async fn rotate_vault_key(
        &self,
        vault_id: String,
        remove: Vec<Principal>,
        cancel: CancelToken,
    ) -> Result<SyncReport, OvError> {
        self.rotate_impl(&vault_id, remove, &cancel).await
    }

    // ----------------------------------------------------------------------------- orgs (§12)

    /// The orgs this user belongs to (from `GET /me`).
    pub async fn orgs(&self, cancel: CancelToken) -> Result<Vec<OrgMembership>, OvError> {
        let me = self.call(&cancel, |a, t| a.build_me(t), ov_protocol::auth::parse_me).await?;
        Ok(me.orgs.unwrap_or_default().iter().map(crate::impls::convert::org_membership).collect())
    }

    /// Creates an org; this user is its owner.
    pub async fn create_org(&self, name: String, cancel: CancelToken) -> Result<Org, OvError> {
        let o = self.call(&cancel, |a, t| a.build_create_org(t, name.trim()), ov_protocol::auth::parse_org).await?;
        // New org claims and limits come with the next token.
        self.refresh_token(&cancel).await?;
        Ok(crate::impls::convert::org(&o))
    }

    /// One org.
    pub async fn org(&self, org_id: String, cancel: CancelToken) -> Result<Org, OvError> {
        let o = self.call(&cancel, |a, t| a.build_get_org(t, &org_id), ov_protocol::auth::parse_org).await?;
        Ok(crate::impls::convert::org(&o))
    }

    /// Renames an org (owner/admin).
    pub async fn rename_org(&self, org_id: String, name: String, cancel: CancelToken) -> Result<Org, OvError> {
        let body = ov_protocol::types::UpdateOrgRequest { name: Some(name.trim().to_owned()), item_share_links: None };
        let o = self.call(&cancel, |a, t| a.build_update_org(t, &org_id, &body), ov_protocol::auth::parse_org).await?;
        Ok(crate::impls::convert::org(&o))
    }

    /// Sets who may make share links from the org's vaults (owner/admin, SPEC §22).
    pub async fn set_org_share_links(
        &self,
        org_id: String,
        policy: ShareLinkPolicy,
        cancel: CancelToken,
    ) -> Result<Org, OvError> {
        let body = ov_protocol::types::UpdateOrgRequest {
            name: None,
            item_share_links: Some(crate::impls::convert::wire_share_policy(policy)),
        };
        let o = self.call(&cancel, |a, t| a.build_update_org(t, &org_id, &body), ov_protocol::auth::parse_org).await?;
        Ok(crate::impls::convert::org(&o))
    }

    /// Deletes an org (owner).
    pub async fn delete_org(&self, org_id: String, cancel: CancelToken) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_delete_org(t, &org_id), ov_protocol::parse_empty).await
    }

    /// The org's members.
    pub async fn org_members(&self, org_id: String, cancel: CancelToken) -> Result<Vec<Member>, OvError> {
        let l = self.call(&cancel, |a, t| a.build_list_members(t, &org_id), ov_protocol::auth::parse_members).await?;
        Ok(l.members.iter().map(crate::impls::convert::member).collect())
    }

    /// The org's open invitations.
    pub async fn invitations(&self, org_id: String, cancel: CancelToken) -> Result<Vec<Invitation>, OvError> {
        let l = self
            .call(&cancel, |a, t| a.build_list_invitations(t, &org_id), ov_protocol::auth::parse_invitations)
            .await?;
        Ok(l.invitations.iter().map(crate::impls::convert::invitation).collect())
    }

    /// Invites an email to the org (SPEC §12); the server mails the `ov_inv_` link.
    pub async fn invite(
        &self,
        org_id: String,
        email: String,
        role: OrgRole,
        cancel: CancelToken,
    ) -> Result<Invitation, OvError> {
        let body = ov_protocol::types::InviteRequest {
            email: email.trim().to_owned(),
            role: crate::impls::convert::wire_org_role(role),
        };
        let i =
            self.call(&cancel, |a, t| a.build_invite(t, &org_id, &body), ov_protocol::auth::parse_invitation).await?;
        Ok(crate::impls::convert::invitation(&i))
    }

    /// Cancels an invitation.
    pub async fn cancel_invitation(
        &self,
        org_id: String,
        invitation_id: String,
        cancel: CancelToken,
    ) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_cancel_invitation(t, &org_id, &invitation_id), ov_protocol::parse_empty).await
    }

    /// Accepts an invitation with the `ov_inv_` token from the link's fragment (SPEC §12).
    pub async fn accept_invitation(&self, token: SecretBytes, cancel: CancelToken) -> Result<Member, OvError> {
        let token = crate::impls::util::secret_text(token, "invitation token")?;
        let m = self
            .call(&cancel, |a, t| a.build_accept_invitation(t, token.trim()), ov_protocol::auth::parse_member)
            .await?;
        Ok(crate::impls::convert::member(&m))
    }

    /// Confirms an accepted member after checking their key signature (SPEC §12 "Confirming
    /// members"). Owners and admins get every org vault this account manages, with `manage`, and the
    /// org's SA master keys; a member gets only `vaults`.
    pub async fn confirm_member(
        &self,
        org_id: String,
        member: Member,
        vaults: Vec<VaultGrantRequest>,
        cancel: CancelToken,
    ) -> Result<Member, OvError> {
        self.confirm_member_impl(&org_id, member, vaults, &cancel).await
    }

    /// Changes a member's org role. Promoting a confirmed member to owner/admin also hands over the
    /// SA master keys and `manage` on every org vault this account manages; the server drops their
    /// master keys on a demotion.
    pub async fn set_member_role(
        &self,
        org_id: String,
        member: Member,
        role: OrgRole,
        cancel: CancelToken,
    ) -> Result<Member, OvError> {
        self.set_member_role_impl(&org_id, member, role, &cancel).await
    }

    /// Removes a member, then rotates every org vault the server flagged (`rotation_required`) that
    /// this account manages. Failed rotations are reported, not returned as an error.
    pub async fn remove_member(
        &self,
        org_id: String,
        user_id: String,
        cancel: CancelToken,
    ) -> Result<RotationReport, OvError> {
        self.call(&cancel, |a, t| a.build_remove_member(t, &org_id, &user_id), ov_protocol::parse_empty).await?;
        self.rotate_flagged_impl(&org_id, &cancel).await
    }

    /// Rotates every flagged org vault this account manages (after removals elsewhere).
    pub async fn rotate_flagged(&self, org_id: String, cancel: CancelToken) -> Result<RotationReport, OvError> {
        self.rotate_flagged_impl(&org_id, &cancel).await
    }

    /// The org's vaults this account manages.
    pub async fn managed_org_vaults(&self, org_id: String, cancel: CancelToken) -> Result<Vec<VaultInfo>, OvError> {
        Ok(self
            .load_vault_list(&cancel)
            .await?
            .0
            .into_iter()
            .filter(|v| v.org_id.as_deref() == Some(org_id.as_str()) && v.role == VaultRole::Manage)
            .collect())
    }

    /// The org audit log, newest first, `limit` events before `before` (owner/admin).
    pub async fn audit_log(
        &self,
        org_id: String,
        before: Option<String>,
        limit: Option<u32>,
        cancel: CancelToken,
    ) -> Result<AuditPage, OvError> {
        let p = self
            .call(&cancel, |a, t| a.build_audit(t, &org_id, before.as_deref(), limit), ov_protocol::auth::parse_audit)
            .await?;
        Ok(crate::impls::convert::audit_page(&p))
    }

    // ---------------------------------------------------------------- service accounts (§9)

    /// The org's service accounts (owner/admin).
    pub async fn service_accounts(
        &self,
        org_id: String,
        cancel: CancelToken,
    ) -> Result<Vec<ServiceAccountInfo>, OvError> {
        let l = self
            .call(&cancel, |a, t| a.build_list_service_accounts(t, &org_id), ov_protocol::auth::parse_service_accounts)
            .await?;
        Ok(l.service_accounts.iter().map(crate::impls::convert::service_account).collect())
    }

    /// Creates a service account (owner/admin): its keyset and master key are made here, the master
    /// key is sealed to every owner and admin, the vaults are granted, and the first token is
    /// returned to show once (SPEC §9).
    pub async fn create_service_account(
        &self,
        org_id: String,
        input: NewServiceAccount,
        cancel: CancelToken,
    ) -> Result<CreatedServiceAccount, OvError> {
        // W2-V: ov_vault makes the SA keyset and master key and seals it to every owner and admin.
        let _ = (org_id, input);
        cancel.check()?;
        Err(crate::impls::vault_glue::needs_vault())
    }

    /// Issues another secret for an SA (owner/admin): unseals the master key and builds a token to
    /// show once. `forbidden` if this account holds no master key for it.
    pub async fn issue_service_account_secret(
        &self,
        sa_id: String,
        name: Option<String>,
        expires_at: Option<Rfc3339>,
        cancel: CancelToken,
    ) -> Result<IssuedSecret, OvError> {
        // W2-V: ov_vault unseals the SA master key and wraps it for the new secret.
        let _ = (sa_id, name, expires_at);
        cancel.check()?;
        Err(crate::impls::vault_glue::needs_vault())
    }

    /// An SA's secrets (never the tokens).
    pub async fn service_account_secrets(
        &self,
        sa_id: String,
        cancel: CancelToken,
    ) -> Result<Vec<SaSecretInfo>, OvError> {
        let l =
            self.call(&cancel, |a, t| a.build_list_sa_secrets(t, &sa_id), ov_protocol::auth::parse_sa_secrets).await?;
        Ok(l.secrets.iter().map(crate::impls::convert::sa_secret).collect())
    }

    /// Changes when a secret expires; the token stays the same (SPEC §9).
    pub async fn set_secret_expiry(
        &self,
        sa_id: String,
        secret_id: String,
        expires_at: ExpiryChange,
        cancel: CancelToken,
    ) -> Result<SaSecretInfo, OvError> {
        let at = match expires_at {
            ExpiryChange::Keep => {
                let all = self.service_account_secrets(sa_id.clone(), cancel.clone()).await?;
                return all
                    .into_iter()
                    .find(|s| s.id == secret_id)
                    .ok_or_else(|| OvError::new(ov_error::OvErrorCode::NotFound, "no such secret").with_status(404));
            }
            ExpiryChange::Never => None,
            ExpiryChange::At(t) => Some(t),
        };
        let s = self
            .call(
                &cancel,
                |a, t| a.build_update_sa_secret(t, &sa_id, &secret_id, at.as_deref()),
                ov_protocol::auth::parse_sa_secret,
            )
            .await?;
        Ok(crate::impls::convert::sa_secret(&s))
    }

    /// Revokes one SA secret.
    pub async fn revoke_secret(&self, sa_id: String, secret_id: String, cancel: CancelToken) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_revoke_sa_secret(t, &sa_id, &secret_id), ov_protocol::parse_empty).await
    }

    /// Renames, re-dates, disables or enables an SA.
    pub async fn update_service_account(
        &self,
        sa_id: String,
        update: ServiceAccountUpdate,
        cancel: CancelToken,
    ) -> Result<ServiceAccountInfo, OvError> {
        let body = ov_protocol::types::UpdateServiceAccountRequest {
            name: update.name,
            expires_at: match update.expires_at {
                ExpiryChange::Keep => None,
                ExpiryChange::Never => Some(None),
                ExpiryChange::At(t) => Some(Some(t)),
            },
            disabled: update.disabled,
        };
        let s = self
            .call(
                &cancel,
                |a, t| a.build_update_service_account(t, &sa_id, &body),
                ov_protocol::auth::parse_service_account,
            )
            .await?;
        Ok(crate::impls::convert::service_account(&s))
    }

    /// Deletes an SA.
    pub async fn delete_service_account(&self, sa_id: String, cancel: CancelToken) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_delete_service_account(t, &sa_id), ov_protocol::parse_empty).await
    }
}
