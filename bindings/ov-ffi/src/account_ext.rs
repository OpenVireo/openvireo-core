//! The `Account` methods the core defines outside `account.rs` (sharing, organizations, service
//! accounts, settings, recovery, deletion, plans, share links), plus the facade's free functions.

use std::sync::Arc;

use ov_core::api as core;

use crate::error::OvError;
use crate::guard::{guard, guard_async, guard_ok};
use crate::handles::{Account, CancelToken};
use crate::types_ext::RotationReport;

type R<T> = Result<T, OvError>;

fn tok(c: &CancelToken) -> core::CancelToken {
    c.0.clone()
}

#[uniffi::export]
impl Account {
    // ------------------------------------------------------------------ vault sharing (§7)

    /// The members of a vault.
    pub async fn members(&self, vault_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::VaultMember>> {
        guard_async(self.0.members(vault_id, tok(&cancel))).await
    }

    /// A principal's public keys, verified.
    pub async fn verified_public_keys(&self, principal: String, cancel: Arc<CancelToken>) -> R<core::PublicKeys> {
        guard_async(self.0.verified_public_keys(principal, tok(&cancel))).await
    }

    /// Looks a user up by email.
    pub async fn look_up(&self, email: String, cancel: Arc<CancelToken>) -> R<core::ShareRecipient> {
        guard_async(self.0.look_up(email, tok(&cancel))).await
    }

    /// A share recipient by principal.
    pub async fn recipient(
        &self,
        principal: String,
        display: Option<String>,
        cancel: Arc<CancelToken>,
    ) -> R<core::ShareRecipient> {
        guard_async(self.0.recipient(principal, display, tok(&cancel))).await
    }

    /// Shares a vault.
    pub async fn share_vault(
        &self,
        vault_id: String,
        grantee: core::Grantee,
        role: core::VaultRole,
        cancel: Arc<CancelToken>,
    ) -> R<core::GrantResult> {
        guard_async(self.0.share_vault(vault_id, grantee, role, tok(&cancel))).await
    }

    /// Shares a vault to the keys the user confirmed; `invalid_public_keys` if they changed
    /// (contract-v1.8).
    pub async fn share_vault_with_keys(
        &self,
        vault_id: String,
        grantee: core::Grantee,
        role: core::VaultRole,
        keys: core::PublicKeys,
        cancel: Arc<CancelToken>,
    ) -> R<core::GrantResult> {
        guard_async(self.0.share_vault_with_keys(vault_id, grantee, role, keys, tok(&cancel))).await
    }

    /// Changes a member's role.
    pub async fn change_role(
        &self,
        vault_id: String,
        principal: String,
        role: core::VaultRole,
        cancel: Arc<CancelToken>,
    ) -> R<()> {
        guard_async(self.0.change_role(vault_id, principal, role, tok(&cancel))).await
    }

    /// Revokes members (rotating the key).
    pub async fn revoke(
        &self,
        vault_id: String,
        principals: Vec<String>,
        cancel: Arc<CancelToken>,
    ) -> R<core::SyncReport> {
        guard_async(self.0.revoke(vault_id, principals, tok(&cancel))).await
    }

    /// Rotates a vault key.
    pub async fn rotate_vault_key(
        &self,
        vault_id: String,
        remove: Vec<String>,
        cancel: Arc<CancelToken>,
    ) -> R<core::SyncReport> {
        guard_async(self.0.rotate_vault_key(vault_id, remove, tok(&cancel))).await
    }

    // ------------------------------------------------------------------------- orgs (§12)

    /// The organizations this account belongs to.
    pub async fn orgs(&self, cancel: Arc<CancelToken>) -> R<Vec<core::OrgMembership>> {
        guard_async(self.0.orgs(tok(&cancel))).await
    }

    /// Creates an organization.
    pub async fn create_org(&self, name: String, cancel: Arc<CancelToken>) -> R<core::Org> {
        guard_async(self.0.create_org(name, tok(&cancel))).await
    }

    /// One organization.
    pub async fn org(&self, org_id: String, cancel: Arc<CancelToken>) -> R<core::Org> {
        guard_async(self.0.org(org_id, tok(&cancel))).await
    }

    /// Renames an organization.
    pub async fn rename_org(&self, org_id: String, name: String, cancel: Arc<CancelToken>) -> R<core::Org> {
        guard_async(self.0.rename_org(org_id, name, tok(&cancel))).await
    }

    /// Sets an organization's share-link policy.
    pub async fn set_org_share_links(
        &self,
        org_id: String,
        policy: core::ShareLinkPolicy,
        cancel: Arc<CancelToken>,
    ) -> R<core::Org> {
        guard_async(self.0.set_org_share_links(org_id, policy, tok(&cancel))).await
    }

    /// Deletes an organization.
    pub async fn delete_org(&self, org_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.delete_org(org_id, tok(&cancel))).await
    }

    /// An organization's members.
    pub async fn org_members(&self, org_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::Member>> {
        guard_async(self.0.org_members(org_id, tok(&cancel))).await
    }

    /// An organization's open invitations.
    pub async fn invitations(&self, org_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::Invitation>> {
        guard_async(self.0.invitations(org_id, tok(&cancel))).await
    }

    /// Invites someone.
    pub async fn invite(
        &self,
        org_id: String,
        email: String,
        role: core::OrgRole,
        cancel: Arc<CancelToken>,
    ) -> R<core::Invitation> {
        guard_async(self.0.invite(org_id, email, role, tok(&cancel))).await
    }

    /// Cancels an invitation.
    pub async fn cancel_invitation(&self, org_id: String, invitation_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.cancel_invitation(org_id, invitation_id, tok(&cancel))).await
    }

    /// Accepts an invitation.
    pub async fn accept_invitation(&self, token: Vec<u8>, cancel: Arc<CancelToken>) -> R<core::Member> {
        guard_async(self.0.accept_invitation(token, tok(&cancel))).await
    }

    /// Confirms a member (granting vaults).
    pub async fn confirm_member(
        &self,
        org_id: String,
        member: core::Member,
        vaults: Vec<core::VaultGrantRequest>,
        cancel: Arc<CancelToken>,
    ) -> R<core::Member> {
        guard_async(self.0.confirm_member(org_id, member, vaults, tok(&cancel))).await
    }

    /// Changes a member's organization role.
    pub async fn set_member_role(
        &self,
        org_id: String,
        member: core::Member,
        role: core::OrgRole,
        cancel: Arc<CancelToken>,
    ) -> R<core::Member> {
        guard_async(self.0.set_member_role(org_id, member, role, tok(&cancel))).await
    }

    /// Removes a member (rotating the keys of their vaults).
    pub async fn remove_member(&self, org_id: String, user_id: String, cancel: Arc<CancelToken>) -> R<RotationReport> {
        guard_async(self.0.remove_member(org_id, user_id, tok(&cancel))).await.map(Into::into)
    }

    /// Rotates every vault flagged for rotation.
    pub async fn rotate_flagged(&self, org_id: String, cancel: Arc<CancelToken>) -> R<RotationReport> {
        guard_async(self.0.rotate_flagged(org_id, tok(&cancel))).await.map(Into::into)
    }

    /// The organization vaults this account manages.
    pub async fn managed_org_vaults(&self, org_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::VaultInfo>> {
        guard_async(self.0.managed_org_vaults(org_id, tok(&cancel))).await
    }

    /// A page of the audit log.
    pub async fn audit_log(
        &self,
        org_id: String,
        before: Option<String>,
        limit: Option<u32>,
        cancel: Arc<CancelToken>,
    ) -> R<core::AuditPage> {
        guard_async(self.0.audit_log(org_id, before, limit, tok(&cancel))).await
    }

    // -------------------------------------------------------------- service accounts (§9)

    /// An organization's service accounts.
    pub async fn service_accounts(&self, org_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::ServiceAccountInfo>> {
        guard_async(self.0.service_accounts(org_id, tok(&cancel))).await
    }

    /// Creates a service account.
    pub async fn create_service_account(
        &self,
        org_id: String,
        input: core::NewServiceAccount,
        cancel: Arc<CancelToken>,
    ) -> R<core::CreatedServiceAccount> {
        guard_async(self.0.create_service_account(org_id, input, tok(&cancel))).await
    }

    /// Issues a new secret for a service account.
    pub async fn issue_service_account_secret(
        &self,
        sa_id: String,
        name: Option<String>,
        expires_at: Option<String>,
        cancel: Arc<CancelToken>,
    ) -> R<core::IssuedSecret> {
        guard_async(self.0.issue_service_account_secret(sa_id, name, expires_at, tok(&cancel))).await
    }

    /// A service account's secrets.
    pub async fn service_account_secrets(&self, sa_id: String, cancel: Arc<CancelToken>) -> R<Vec<core::SaSecretInfo>> {
        guard_async(self.0.service_account_secrets(sa_id, tok(&cancel))).await
    }

    /// Changes a secret's expiry.
    pub async fn set_secret_expiry(
        &self,
        sa_id: String,
        secret_id: String,
        expires_at: core::ExpiryChange,
        cancel: Arc<CancelToken>,
    ) -> R<core::SaSecretInfo> {
        guard_async(self.0.set_secret_expiry(sa_id, secret_id, expires_at, tok(&cancel))).await
    }

    /// Revokes a secret.
    pub async fn revoke_secret(&self, sa_id: String, secret_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.revoke_secret(sa_id, secret_id, tok(&cancel))).await
    }

    /// Updates a service account.
    pub async fn update_service_account(
        &self,
        sa_id: String,
        update: core::ServiceAccountUpdate,
        cancel: Arc<CancelToken>,
    ) -> R<core::ServiceAccountInfo> {
        guard_async(self.0.update_service_account(sa_id, update, tok(&cancel))).await
    }

    /// Deletes a service account.
    pub async fn delete_service_account(&self, sa_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.delete_service_account(sa_id, tok(&cancel))).await
    }

    // ---------------------------------------------------------------------- profile (§16)

    /// The profile.
    pub async fn me(&self, cancel: Arc<CancelToken>) -> R<core::Profile> {
        guard_async(self.0.me(tok(&cancel))).await
    }

    /// Changes the password; returns the new AUK.
    pub async fn change_password(
        &self,
        current: Vec<u8>,
        next: Vec<u8>,
        kdf: Option<core::KdfOverrides>,
        cancel: Arc<CancelToken>,
    ) -> R<Vec<u8>> {
        guard_async(self.0.change_password(current, next, kdf, tok(&cancel))).await
    }

    /// Sends a code to a new email address.
    pub async fn request_email_change(&self, email: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.request_email_change(email, tok(&cancel))).await
    }

    /// Changes the email with the code.
    pub async fn change_email(
        &self,
        email: String,
        code: String,
        password: Vec<u8>,
        cancel: Arc<CancelToken>,
    ) -> R<()> {
        guard_async(self.0.change_email(email, code, password, tok(&cancel))).await
    }

    /// The Secret Key, for showing again in settings.
    pub async fn secret_key(&self) -> R<Option<Vec<u8>>> {
        guard_async(self.0.secret_key()).await
    }

    /// A one-time URL that signs the web vault in.
    pub async fn web_session_url(&self, next: Option<String>, cancel: Arc<CancelToken>) -> R<Vec<u8>> {
        guard_async(self.0.web_session_url(next, tok(&cancel))).await
    }

    // ----------------------------------------------------------------- two-step (§8)

    /// Starts enabling two-step verification.
    pub async fn start_two_step(&self, cancel: Arc<CancelToken>) -> R<core::TotpSetup> {
        guard_async(self.0.start_two_step(tok(&cancel))).await
    }

    /// Confirms two-step verification with a code.
    pub async fn confirm_two_step(&self, code: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.confirm_two_step(code, tok(&cancel))).await
    }

    /// Disables two-step verification.
    pub async fn disable_two_step(&self, code: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.disable_two_step(code, tok(&cancel))).await
    }

    // -------------------------------------------------------------------------- devices

    /// The signed-in devices.
    pub async fn devices(&self, cancel: Arc<CancelToken>) -> R<Vec<core::Device>> {
        guard_async(self.0.devices(tok(&cancel))).await
    }

    /// Signs a device out.
    pub async fn revoke_device(&self, device_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.revoke_device(device_id, tok(&cancel))).await
    }

    // ------------------------------------------------------------------- recovery (§18)

    /// What a recovery reset link will do.
    pub async fn recover_info(&self, token: Vec<u8>, cancel: Arc<CancelToken>) -> R<core::RecoveryReset> {
        guard_async(self.0.recover_info(token, tok(&cancel))).await
    }

    /// Resets the account with a recovery link.
    pub async fn recover(
        &self,
        token: Vec<u8>,
        password: Vec<u8>,
        kdf: Option<core::KdfOverrides>,
        trust_device: bool,
        cancel: Arc<CancelToken>,
    ) -> R<core::NewAccount> {
        guard_async(self.0.recover(token, password, kdf, trust_device, tok(&cancel))).await
    }

    /// The recovery archive's status.
    pub async fn recovery_status(&self, cancel: Arc<CancelToken>) -> R<core::RecoveryStatus> {
        guard_async(self.0.recovery_status(tok(&cancel))).await
    }

    /// Restores vaults from the archive with the old credentials; returns how many.
    pub async fn restore_from_archive(
        &self,
        old_password: Vec<u8>,
        old_secret_key: Vec<u8>,
        cancel: Arc<CancelToken>,
    ) -> R<u32> {
        guard_async(self.0.restore_from_archive(old_password, old_secret_key, tok(&cancel))).await
    }

    // ------------------------------------------------------------------- deletion (§23)

    /// What deleting the account would do.
    pub async fn deletion_preview(&self, cancel: Arc<CancelToken>) -> R<core::DeletionPreview> {
        guard_async(self.0.deletion_preview(tok(&cancel))).await
    }

    /// Schedules deletion; returns when it happens.
    pub async fn delete_account(&self, password: Vec<u8>, confirm: String, cancel: Arc<CancelToken>) -> R<String> {
        guard_async(self.0.delete_account(password, confirm, tok(&cancel))).await
    }

    /// Cancels a scheduled deletion.
    pub async fn restore_account(&self, password: Vec<u8>, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.restore_account(password, tok(&cancel))).await
    }

    /// Transfers a vault to another principal.
    pub async fn transfer_vault(&self, vault_id: String, to: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.transfer_vault(vault_id, to, tok(&cancel))).await
    }

    // ---------------------------------------------------------------------- plans (§19)

    /// The account's plan.
    pub async fn plan(&self, cancel: Arc<CancelToken>) -> R<Option<core::Plan>> {
        guard_async(self.0.plan(tok(&cancel))).await
    }

    /// A vault's byte quota.
    pub async fn vault_quota(&self, vault_id: String) -> R<Option<u64>> {
        guard_async(self.0.vault_quota(vault_id)).await
    }

    /// Where to upgrade for a `plan_limit` error.
    pub fn upgrade_url(&self, error: OvError) -> R<Option<String>> {
        guard_ok(|| self.0.upgrade_url(error.into()))
    }

    /// Whether In-App Purchase is available.
    pub async fn apple_eligibility(
        &self,
        org_id: Option<String>,
        cancel: Arc<CancelToken>,
    ) -> R<core::AppleEligibility> {
        guard_async(self.0.apple_eligibility(org_id, tok(&cancel))).await
    }

    /// Reports a StoreKit transaction.
    pub async fn report_apple_transaction(
        &self,
        jws: String,
        cancel: Arc<CancelToken>,
    ) -> R<core::AppleTransactionResult> {
        guard_async(self.0.report_apple_transaction(jws, tok(&cancel))).await
    }

    // ---------------------------------------------------------------- share links (§22)

    /// The share-link base URL.
    pub fn share_base(&self) -> R<Option<String>> {
        guard_ok(|| self.0.share_base())
    }

    /// Why share links are blocked, if they are.
    pub async fn share_blocked_reason(&self, org_id: Option<String>) -> R<Option<String>> {
        guard_async(self.0.share_blocked_reason(org_id)).await
    }

    /// Creates a share link.
    pub async fn create_share(
        &self,
        payload: core::SharePayload,
        options: core::ShareOptions,
        cancel: Arc<CancelToken>,
    ) -> R<core::CreatedShare> {
        guard_async(self.0.create_share(payload, options, tok(&cancel))).await
    }

    /// The account's share links.
    pub async fn list_shares(&self, cancel: Arc<CancelToken>) -> R<Vec<core::ShareListing>> {
        guard_async(self.0.list_shares(tok(&cancel))).await
    }

    /// Revokes a share link.
    pub async fn revoke_share(&self, share_id: String, cancel: Arc<CancelToken>) -> R<()> {
        guard_async(self.0.revoke_share(share_id, tok(&cancel))).await
    }
}

// --------------------------------------------------------------------------- free functions

/// Whether a scheduled deletion has passed.
#[uniffi::export]
pub fn deletion_expired(scheduled_for: Option<String>, now_ms: i64) -> R<bool> {
    guard_ok(|| core::deletion_expired(scheduled_for, now_ms))
}

/// The fields shared by default.
#[uniffi::export]
pub fn default_share_fields() -> R<Vec<String>> {
    guard_ok(core::default_share_fields)
}

/// The fields of an entry that can be shared.
#[uniffi::export]
pub fn shareable_fields(entry: core::EntryRecord) -> R<Vec<core::ShareableField>> {
    guard_ok(|| core::shareable_fields(entry))
}

/// A share payload for some fields of an entry.
#[uniffi::export]
pub fn item_share_payload(
    entry: core::EntryRecord,
    names: Vec<String>,
    shared_by: Option<String>,
) -> R<core::SharePayload> {
    guard_ok(|| core::item_share_payload(entry, names, shared_by))
}

/// A share payload for a piece of text.
#[uniffi::export]
pub fn text_share_payload(text: Vec<u8>, title: Option<String>, shared_by: Option<String>) -> R<core::SharePayload> {
    guard_ok(|| core::text_share_payload(text, title, shared_by))
}

/// Parses an `otpauth://` URI.
#[uniffi::export]
pub fn parse_totp_uri(uri: Vec<u8>) -> R<core::TotpParams> {
    guard(|| core::parse_totp_uri(uri))
}

/// The TOTP code at `now_ms`.
#[uniffi::export]
pub fn totp_code(params: core::TotpParams, now_ms: i64) -> R<core::TotpCode> {
    guard_ok(|| core::totp_code(params, now_ms))
}

/// An entry's TOTP URI, from its fields.
#[uniffi::export]
pub fn entry_totp_uri(fields: Vec<core::FieldRecord>, label: String) -> R<Option<Vec<u8>>> {
    guard_ok(|| core::entry_totp_uri(fields, label))
}
