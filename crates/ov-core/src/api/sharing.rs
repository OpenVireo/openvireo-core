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
        todo!()
    }

    /// A principal's public keys, verified (signature, SPEC §5) before anything is sealed to them.
    pub async fn verified_public_keys(&self, principal: Principal, cancel: CancelToken) -> Result<PublicKeys, OvError> {
        todo!()
    }

    /// Looks a user up by email, keys verified, to show their fingerprint before sharing.
    pub async fn look_up(&self, email: String, cancel: CancelToken) -> Result<ShareRecipient, OvError> {
        todo!()
    }

    /// A recipient for a known principal (keys verified), with an optional display name.
    pub async fn recipient(
        &self,
        principal: Principal,
        display: Option<String>,
        cancel: CancelToken,
    ) -> Result<ShareRecipient, OvError> {
        todo!()
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
        todo!()
    }

    /// Changes a member's role on a vault (re-grants at the current key version).
    pub async fn change_role(
        &self,
        vault_id: String,
        principal: Principal,
        role: VaultRole,
        cancel: CancelToken,
    ) -> Result<(), OvError> {
        todo!()
    }

    /// Removes members and rotates the vault key in one step (SPEC §7).
    pub async fn revoke(
        &self,
        vault_id: String,
        principals: Vec<Principal>,
        cancel: CancelToken,
    ) -> Result<SyncReport, OvError> {
        todo!()
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
        todo!()
    }

    // ----------------------------------------------------------------------------- orgs (§12)

    /// The orgs this user belongs to (from `GET /me`).
    pub async fn orgs(&self, cancel: CancelToken) -> Result<Vec<OrgMembership>, OvError> {
        todo!()
    }

    /// Creates an org; this user is its owner.
    pub async fn create_org(&self, name: String, cancel: CancelToken) -> Result<Org, OvError> {
        todo!()
    }

    /// One org.
    pub async fn org(&self, org_id: String, cancel: CancelToken) -> Result<Org, OvError> {
        todo!()
    }

    /// Renames an org (owner/admin).
    pub async fn rename_org(&self, org_id: String, name: String, cancel: CancelToken) -> Result<Org, OvError> {
        todo!()
    }

    /// Sets who may make share links from the org's vaults (owner/admin, SPEC §22).
    pub async fn set_org_share_links(
        &self,
        org_id: String,
        policy: ShareLinkPolicy,
        cancel: CancelToken,
    ) -> Result<Org, OvError> {
        todo!()
    }

    /// Deletes an org (owner).
    pub async fn delete_org(&self, org_id: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// The org's members.
    pub async fn org_members(&self, org_id: String, cancel: CancelToken) -> Result<Vec<Member>, OvError> {
        todo!()
    }

    /// The org's open invitations.
    pub async fn invitations(&self, org_id: String, cancel: CancelToken) -> Result<Vec<Invitation>, OvError> {
        todo!()
    }

    /// Invites an email to the org (SPEC §12); the server mails the `ov_inv_` link.
    pub async fn invite(
        &self,
        org_id: String,
        email: String,
        role: OrgRole,
        cancel: CancelToken,
    ) -> Result<Invitation, OvError> {
        todo!()
    }

    /// Cancels an invitation.
    pub async fn cancel_invitation(
        &self,
        org_id: String,
        invitation_id: String,
        cancel: CancelToken,
    ) -> Result<(), OvError> {
        todo!()
    }

    /// Accepts an invitation with the `ov_inv_` token from the link's fragment (SPEC §12).
    pub async fn accept_invitation(&self, token: SecretBytes, cancel: CancelToken) -> Result<Member, OvError> {
        todo!()
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
        todo!()
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
        todo!()
    }

    /// Removes a member, then rotates every org vault the server flagged (`rotation_required`) that
    /// this account manages. Failed rotations are reported, not returned as an error.
    pub async fn remove_member(
        &self,
        org_id: String,
        user_id: String,
        cancel: CancelToken,
    ) -> Result<RotationReport, OvError> {
        todo!()
    }

    /// Rotates every flagged org vault this account manages (after removals elsewhere).
    pub async fn rotate_flagged(&self, org_id: String, cancel: CancelToken) -> Result<RotationReport, OvError> {
        todo!()
    }

    /// The org's vaults this account manages.
    pub async fn managed_org_vaults(&self, org_id: String, cancel: CancelToken) -> Result<Vec<VaultInfo>, OvError> {
        todo!()
    }

    /// The org audit log, newest first, `limit` events before `before` (owner/admin).
    pub async fn audit_log(
        &self,
        org_id: String,
        before: Option<String>,
        limit: Option<u32>,
        cancel: CancelToken,
    ) -> Result<AuditPage, OvError> {
        todo!()
    }

    // ---------------------------------------------------------------- service accounts (§9)

    /// The org's service accounts (owner/admin).
    pub async fn service_accounts(
        &self,
        org_id: String,
        cancel: CancelToken,
    ) -> Result<Vec<ServiceAccountInfo>, OvError> {
        todo!()
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
        todo!()
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
        todo!()
    }

    /// An SA's secrets (never the tokens).
    pub async fn service_account_secrets(
        &self,
        sa_id: String,
        cancel: CancelToken,
    ) -> Result<Vec<SaSecretInfo>, OvError> {
        todo!()
    }

    /// Changes when a secret expires; the token stays the same (SPEC §9).
    pub async fn set_secret_expiry(
        &self,
        sa_id: String,
        secret_id: String,
        expires_at: ExpiryChange,
        cancel: CancelToken,
    ) -> Result<SaSecretInfo, OvError> {
        todo!()
    }

    /// Revokes one SA secret.
    pub async fn revoke_secret(&self, sa_id: String, secret_id: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// Renames, re-dates, disables or enables an SA.
    pub async fn update_service_account(
        &self,
        sa_id: String,
        update: ServiceAccountUpdate,
        cancel: CancelToken,
    ) -> Result<ServiceAccountInfo, OvError> {
        todo!()
    }

    /// Deletes an SA.
    pub async fn delete_service_account(&self, sa_id: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }
}
