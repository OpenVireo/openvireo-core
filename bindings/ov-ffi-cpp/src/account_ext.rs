//! The rest of `ov::Account`: sessions, vault management, history, AutoFill, settings, recovery,
//! deletion, plans, sharing and orgs, service-account administration and share links. Same edge
//! pattern as `handles.rs`: async calls block with the caller's token, panics become `internal`.

use ov_core::api as core;

use crate::convert::{self, sync_report, vault_info};
use crate::edge::{block, edge, run, FfiError};
use crate::ffi;
use crate::handles::{Account, CancelToken, Vault};
use crate::records::{self as rec, some};

type R<T> = Result<T, FfiError>;

fn vault(v: core::Vault) -> Box<Vault> {
    Box::new(Vault(v))
}

impl Account {
    // ------------------------------------------------------------------ state, sessions

    /// [`core::Account::deletion_scheduled_for`]; empty when none.
    pub fn deletion_scheduled_for(&self) -> R<String> {
        edge(|| Ok(rec::opt(self.0.deletion_scheduled_for())))
    }

    /// [`core::Account::principal`].
    pub fn principal(&self) -> R<String> {
        edge(|| self.0.principal())
    }

    /// [`core::Account::fingerprint`].
    pub fn fingerprint(&self) -> R<String> {
        edge(|| self.0.fingerprint())
    }

    /// [`core::Account::clock_offset_ms`].
    pub fn clock_offset_ms(&self) -> R<ffi::OptionalI64> {
        edge(|| Ok(rec::opt_i64(self.0.clock_offset_ms())))
    }

    /// [`core::Account::stored_session`].
    pub fn stored_session(&self) -> R<ffi::OptionalStoredSession> {
        block(|| async { self.0.stored_session().await.map(rec::stored_session) })
    }

    /// [`core::Account::verify_session`].
    pub fn verify_session(&self, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.verify_session(c))
    }

    /// [`core::Account::signed_out`].
    pub fn signed_out(&self, cancel: &CancelToken) -> R<ffi::SignedOutReason> {
        run(cancel, |c| async move { self.0.signed_out(c).await.map(rec::signed_out_reason) })
    }

    /// [`core::Account::has_secret_key`].
    pub fn has_secret_key(&self, email: &str) -> R<bool> {
        block(|| self.0.has_secret_key(email.into()))
    }

    /// [`core::Account::stored_secret_key`]. Wipe the value.
    pub fn stored_secret_key(&self, email: &str) -> R<ffi::OptionalBytes> {
        block(|| async { self.0.stored_secret_key(email.into()).await.map(rec::opt_bytes) })
    }

    /// [`core::Account::register`].
    pub fn register_account(&self, input: ffi::RegisterInput, cancel: &CancelToken) -> R<ffi::NewAccount> {
        run(cancel, |c| async move { self.0.register(rec::register_input(input), c).await.map(rec::new_account) })
    }

    /// [`core::Account::unlock_with_auk`].
    pub fn unlock_with_auk(&self, auk: Vec<u8>, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.unlock_with_auk(auk, c))
    }

    /// [`core::Account::unlocked_keyset_secret`]. Wipe the result.
    pub fn unlocked_keyset_secret(&self) -> R<Vec<u8>> {
        edge(|| self.0.unlocked_keyset_secret())
    }

    /// [`core::Account::resume_unlocked`].
    pub fn resume_unlocked(&self, keyset_secret: Vec<u8>, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.resume_unlocked(keyset_secret, c))
    }

    /// [`core::Account::sign_out_on_unload`].
    pub fn sign_out_on_unload(&self) -> R<ffi::OptionalHttpRequest> {
        edge(|| Ok(rec::opt_http_request(self.0.sign_out_on_unload())))
    }

    /// [`core::Account::forget_device`].
    pub fn forget_device(&self, email: &str) -> R<()> {
        block(|| self.0.forget_device(email.into()))
    }

    /// [`core::Account::reconnect`].
    pub fn reconnect(&self, cancel: &CancelToken) -> R<ffi::ReconnectResult> {
        run(cancel, |c| async move { self.0.reconnect(c).await.map(rec::reconnect_result) })
    }

    /// [`core::Account::cached_kdf`].
    pub fn cached_kdf(&self) -> R<ffi::OptionalKdfParams> {
        block(|| async {
            let k = self.0.cached_kdf().await?;
            Ok(ffi::OptionalKdfParams { has: k.is_some(), value: k.map(rec::kdf_params).unwrap_or_default() })
        })
    }

    /// [`core::Account::park_session`].
    pub fn park_session(&self) -> R<bool> {
        block(|| self.0.park_session())
    }

    /// [`core::Account::resume_session`].
    pub fn resume_session(&self, user_id: &str) -> R<bool> {
        block(|| self.0.resume_session(user_id.into()))
    }

    /// [`core::Account::check_parked_session`].
    pub fn check_parked_session(&self, user_id: &str, cancel: &CancelToken) -> R<ffi::ParkedCheck> {
        run(cancel, |c| async move { self.0.check_parked_session(user_id.into(), c).await.map(rec::parked_check) })
    }

    /// [`core::Account::sign_out_parked`].
    pub fn sign_out_parked(&self, user_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.sign_out_parked(user_id.into(), c))
    }

    // ------------------------------------------------------------ vaults, history, AutoFill

    /// [`core::Account::cached_vaults`].
    pub fn cached_vaults(&self) -> R<ffi::OptionalVaultList> {
        block(|| async { self.0.cached_vaults().await.map(rec::opt_vault_list) })
    }

    /// [`core::Account::open_offline`].
    pub fn open_offline(&self, vault_id: &str) -> R<Box<Vault>> {
        block(|| async { self.0.open_offline(vault_id.into()).await.map(vault) })
    }

    /// [`core::Account::open_copy`].
    pub fn open_copy(&self, vault_id: &str) -> R<Box<Vault>> {
        block(|| async { self.0.open_copy(vault_id.into()).await.map(vault) })
    }

    /// [`core::Account::create_vault`]; an empty `org_id` is a personal vault.
    pub fn create_vault(&self, name: &str, org_id: &str, cancel: &CancelToken) -> R<Box<Vault>> {
        run(cancel, |c| async move { self.0.create_vault(name.into(), some(org_id), c).await.map(vault) })
    }

    /// [`core::Account::import_kdbx`].
    pub fn import_kdbx(
        &self,
        kdbx: Vec<u8>,
        credentials: ffi::KdbxCredentials,
        mode: &ffi::ImportMode,
        cancel: &CancelToken,
    ) -> R<ffi::ImportOutcome> {
        run(cancel, |c| async move {
            let mode = rec::import_mode_in(mode)?;
            self.0.import_kdbx(kdbx, convert::kdbx_credentials(credentials), mode, c).await.map(rec::import_outcome)
        })
    }

    /// [`core::Account::import_vault`].
    pub fn import_vault(&self, source: &Vault, mode: &ffi::ImportMode, cancel: &CancelToken) -> R<ffi::ImportOutcome> {
        run(cancel, |c| async move {
            let mode = rec::import_mode_in(mode)?;
            self.0.import_vault(source.0.clone(), mode, c).await.map(rec::import_outcome)
        })
    }

    /// [`core::Account::rename_vault`].
    pub fn rename_vault(&self, vault_id: &str, name: &str, cancel: &CancelToken) -> R<ffi::VaultInfo> {
        run(cancel, |c| async move { self.0.rename_vault(vault_id.into(), name.into(), c).await.map(vault_info) })
    }

    /// [`core::Account::delete_vault`].
    pub fn delete_vault(&self, vault_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.delete_vault(vault_id.into(), c))
    }

    /// [`core::Account::has_any_pending_edits`].
    pub fn has_any_pending_edits(&self) -> R<bool> {
        block(|| self.0.has_any_pending_edits())
    }

    /// [`core::Account::has_pending_edits`].
    pub fn has_pending_edits(&self, vault_id: &str) -> R<bool> {
        block(|| self.0.has_pending_edits(vault_id.into()))
    }

    /// [`core::Account::vault_history`].
    pub fn vault_history(&self, vault_id: &str, cancel: &CancelToken) -> R<Vec<ffi::VaultVersion>> {
        run(cancel, |c| async move {
            Ok(self.0.vault_history(vault_id.into(), c).await?.into_iter().map(rec::vault_version).collect())
        })
    }

    /// [`core::Account::open_vault_version`].
    pub fn open_vault_version(&self, vault_id: &str, revision: u64, cancel: &CancelToken) -> R<Box<Vault>> {
        run(cancel, |c| async move { self.0.open_vault_version(vault_id.into(), revision, c).await.map(vault) })
    }

    /// [`core::Account::keep_autofill_edit`].
    pub fn keep_autofill_edit(&self, vault_id: &str, entry: &ffi::EntryRecord, group_path: &str) -> R<()> {
        block(|| self.0.keep_autofill_edit(vault_id.into(), rec::entry_record_in(entry), group_path.into()))
    }

    /// [`core::Account::autofill_edits`].
    pub fn autofill_edits(&self, vault_id: &str) -> R<ffi::OptionalAutoFillEdits> {
        block(|| async { self.0.autofill_edits(vault_id.into()).await.map(rec::opt_autofill_edits) })
    }

    /// [`core::Account::clear_autofill_edits`].
    pub fn clear_autofill_edits(&self, edits: &ffi::AutoFillEdits) -> R<()> {
        block(|| self.0.clear_autofill_edits(rec::autofill_edits_in(edits)))
    }

    // ------------------------------------------------------------------- settings (§16, §8)

    /// [`core::Account::me`].
    pub fn me(&self, cancel: &CancelToken) -> R<ffi::Profile> {
        run(cancel, |c| async move { self.0.me(c).await.map(rec::profile) })
    }

    /// [`core::Account::change_password`]. Returns the new AUK (wipe it).
    pub fn change_password(
        &self,
        current: Vec<u8>,
        next: Vec<u8>,
        kdf: ffi::KdfOverrides,
        cancel: &CancelToken,
    ) -> R<Vec<u8>> {
        run(cancel, |c| self.0.change_password(current, next, rec::kdf_overrides_in(kdf), c))
    }

    /// [`core::Account::request_email_change`].
    pub fn request_email_change(&self, email: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.request_email_change(email.into(), c))
    }

    /// [`core::Account::change_email`].
    pub fn change_email(&self, email: &str, code: &str, password: Vec<u8>, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.change_email(email.into(), code.into(), password, c))
    }

    /// [`core::Account::secret_key`]. Wipe the value.
    pub fn secret_key(&self) -> R<ffi::OptionalBytes> {
        block(|| async { self.0.secret_key().await.map(rec::opt_bytes) })
    }

    /// [`core::Account::web_session_url`]; an empty `next` is none.
    pub fn web_session_url(&self, next: &str, cancel: &CancelToken) -> R<Vec<u8>> {
        run(cancel, |c| self.0.web_session_url(some(next), c))
    }

    /// [`core::Account::start_two_step`].
    pub fn start_two_step(&self, cancel: &CancelToken) -> R<ffi::TotpSetup> {
        run(cancel, |c| async move { self.0.start_two_step(c).await.map(rec::totp_setup) })
    }

    /// [`core::Account::confirm_two_step`].
    pub fn confirm_two_step(&self, code: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.confirm_two_step(code.into(), c))
    }

    /// [`core::Account::disable_two_step`].
    pub fn disable_two_step(&self, code: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.disable_two_step(code.into(), c))
    }

    /// [`core::Account::devices`].
    pub fn devices(&self, cancel: &CancelToken) -> R<Vec<ffi::Device>> {
        run(cancel, |c| async move { Ok(self.0.devices(c).await?.into_iter().map(rec::device).collect()) })
    }

    /// [`core::Account::revoke_device`].
    pub fn revoke_device(&self, device_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.revoke_device(device_id.into(), c))
    }

    // -------------------------------------------------------- recovery (§18), deletion (§23)

    /// [`core::Account::recover_info`].
    pub fn recover_info(&self, token: Vec<u8>, cancel: &CancelToken) -> R<ffi::RecoveryReset> {
        run(cancel, |c| async move { self.0.recover_info(token, c).await.map(rec::recovery_reset) })
    }

    /// [`core::Account::recover`].
    pub fn recover(
        &self,
        token: Vec<u8>,
        password: Vec<u8>,
        kdf: ffi::KdfOverrides,
        trust_device: bool,
        cancel: &CancelToken,
    ) -> R<ffi::NewAccount> {
        run(cancel, |c| async move {
            self.0.recover(token, password, rec::kdf_overrides_in(kdf), trust_device, c).await.map(rec::new_account)
        })
    }

    /// [`core::Account::recovery_status`].
    pub fn recovery_status(&self, cancel: &CancelToken) -> R<ffi::RecoveryStatus> {
        run(cancel, |c| async move { self.0.recovery_status(c).await.map(rec::recovery_status) })
    }

    /// [`core::Account::restore_from_archive`].
    pub fn restore_from_archive(&self, old_password: Vec<u8>, old_secret_key: Vec<u8>, cancel: &CancelToken) -> R<u32> {
        run(cancel, |c| self.0.restore_from_archive(old_password, old_secret_key, c))
    }

    /// [`core::Account::deletion_preview`].
    pub fn deletion_preview(&self, cancel: &CancelToken) -> R<ffi::DeletionPreview> {
        run(cancel, |c| async move { self.0.deletion_preview(c).await.map(rec::deletion_preview) })
    }

    /// [`core::Account::delete_account`]; returns the erase date.
    pub fn delete_account(&self, password: Vec<u8>, confirm: &str, cancel: &CancelToken) -> R<String> {
        run(cancel, |c| self.0.delete_account(password, confirm.into(), c))
    }

    /// [`core::Account::restore_account`].
    pub fn restore_account(&self, password: Vec<u8>, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.restore_account(password, c))
    }

    /// [`core::Account::transfer_vault`].
    pub fn transfer_vault(&self, vault_id: &str, to: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.transfer_vault(vault_id.into(), to.into(), c))
    }

    // ------------------------------------------------------------------------ plans (§19)

    /// [`core::Account::plan`].
    pub fn plan(&self, cancel: &CancelToken) -> R<ffi::OptionalPlan> {
        run(cancel, |c| async move { self.0.plan(c).await.map(rec::opt_plan) })
    }

    /// [`core::Account::vault_quota`].
    pub fn vault_quota(&self, vault_id: &str) -> R<ffi::OptionalU64> {
        block(|| async { self.0.vault_quota(vault_id.into()).await.map(rec::opt_u64) })
    }

    /// [`core::Account::upgrade_url`]; empty when none.
    pub fn upgrade_url(&self, error: &ffi::ErrorInfo) -> R<String> {
        edge(|| Ok(rec::opt(self.0.upgrade_url(rec::error_from_info(error)))))
    }

    /// [`core::Account::apple_eligibility`]; an empty `org_id` is this user.
    pub fn apple_eligibility(&self, org_id: &str, cancel: &CancelToken) -> R<ffi::AppleEligibility> {
        run(cancel, |c| async move { self.0.apple_eligibility(some(org_id), c).await.map(rec::apple_eligibility) })
    }

    /// [`core::Account::report_apple_transaction`].
    pub fn report_apple_transaction(&self, jws: &str, cancel: &CancelToken) -> R<ffi::AppleTransactionResult> {
        run(cancel, |c| async move { self.0.report_apple_transaction(jws.into(), c).await.map(rec::apple_transaction) })
    }

    // ---------------------------------------------------------------- vault sharing (§7)

    /// [`core::Account::members`].
    pub fn members(&self, vault_id: &str, cancel: &CancelToken) -> R<Vec<ffi::VaultMember>> {
        run(cancel, |c| async move {
            Ok(self.0.members(vault_id.into(), c).await?.into_iter().map(rec::vault_member).collect())
        })
    }

    /// [`core::Account::verified_public_keys`].
    pub fn verified_public_keys(&self, principal: &str, cancel: &CancelToken) -> R<ffi::PublicKeys> {
        run(cancel, |c| async move { self.0.verified_public_keys(principal.into(), c).await.map(rec::public_keys) })
    }

    /// [`core::Account::look_up`].
    pub fn look_up(&self, email: &str, cancel: &CancelToken) -> R<ffi::ShareRecipient> {
        run(cancel, |c| async move { self.0.look_up(email.into(), c).await.map(rec::share_recipient) })
    }

    /// [`core::Account::recipient`]; an empty `display` is none.
    pub fn recipient(&self, principal: &str, display: &str, cancel: &CancelToken) -> R<ffi::ShareRecipient> {
        run(
            cancel,
            |c| async move { self.0.recipient(principal.into(), some(display), c).await.map(rec::share_recipient) },
        )
    }

    /// [`core::Account::share_vault`].
    pub fn share_vault(
        &self,
        vault_id: &str,
        grantee: &ffi::Grantee,
        role: ffi::VaultRole,
        cancel: &CancelToken,
    ) -> R<ffi::GrantResult> {
        run(cancel, |c| async move {
            let grantee = rec::grantee_in(grantee)?;
            let role = rec::vault_role_in(role)?;
            self.0.share_vault(vault_id.into(), grantee, role, c).await.map(rec::grant_result)
        })
    }

    /// [`core::Account::change_role`].
    pub fn change_role(&self, vault_id: &str, principal: &str, role: ffi::VaultRole, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| async move {
            let role = rec::vault_role_in(role)?;
            self.0.change_role(vault_id.into(), principal.into(), role, c).await
        })
    }

    /// [`core::Account::revoke`].
    pub fn revoke(&self, vault_id: &str, principals: Vec<String>, cancel: &CancelToken) -> R<ffi::SyncReport> {
        run(cancel, |c| async move { self.0.revoke(vault_id.into(), principals, c).await.map(sync_report) })
    }

    /// [`core::Account::rotate_vault_key`].
    pub fn rotate_vault_key(&self, vault_id: &str, remove: Vec<String>, cancel: &CancelToken) -> R<ffi::SyncReport> {
        run(cancel, |c| async move { self.0.rotate_vault_key(vault_id.into(), remove, c).await.map(sync_report) })
    }

    // ------------------------------------------------------------------------- orgs (§12)

    /// [`core::Account::orgs`].
    pub fn orgs(&self, cancel: &CancelToken) -> R<Vec<ffi::OrgMembership>> {
        run(cancel, |c| async move { Ok(self.0.orgs(c).await?.into_iter().map(rec::org_membership).collect()) })
    }

    /// [`core::Account::create_org`].
    pub fn create_org(&self, name: &str, cancel: &CancelToken) -> R<ffi::Org> {
        run(cancel, |c| async move { self.0.create_org(name.into(), c).await.map(rec::org) })
    }

    /// [`core::Account::org`].
    pub fn org(&self, org_id: &str, cancel: &CancelToken) -> R<ffi::Org> {
        run(cancel, |c| async move { self.0.org(org_id.into(), c).await.map(rec::org) })
    }

    /// [`core::Account::rename_org`].
    pub fn rename_org(&self, org_id: &str, name: &str, cancel: &CancelToken) -> R<ffi::Org> {
        run(cancel, |c| async move { self.0.rename_org(org_id.into(), name.into(), c).await.map(rec::org) })
    }

    /// [`core::Account::set_org_share_links`].
    pub fn set_org_share_links(&self, org_id: &str, policy: ffi::ShareLinkPolicy, cancel: &CancelToken) -> R<ffi::Org> {
        run(cancel, |c| async move {
            let policy = rec::share_link_policy_in(policy)?;
            self.0.set_org_share_links(org_id.into(), policy, c).await.map(rec::org)
        })
    }

    /// [`core::Account::delete_org`].
    pub fn delete_org(&self, org_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.delete_org(org_id.into(), c))
    }

    /// [`core::Account::org_members`].
    pub fn org_members(&self, org_id: &str, cancel: &CancelToken) -> R<Vec<ffi::Member>> {
        run(cancel, |c| async move {
            Ok(self.0.org_members(org_id.into(), c).await?.into_iter().map(rec::member).collect())
        })
    }

    /// [`core::Account::invitations`].
    pub fn invitations(&self, org_id: &str, cancel: &CancelToken) -> R<Vec<ffi::Invitation>> {
        run(cancel, |c| async move {
            Ok(self.0.invitations(org_id.into(), c).await?.into_iter().map(rec::invitation).collect())
        })
    }

    /// [`core::Account::invite`].
    pub fn invite(&self, org_id: &str, email: &str, role: ffi::OrgRole, cancel: &CancelToken) -> R<ffi::Invitation> {
        run(cancel, |c| async move {
            let role = rec::org_role_in(role)?;
            self.0.invite(org_id.into(), email.into(), role, c).await.map(rec::invitation)
        })
    }

    /// [`core::Account::cancel_invitation`].
    pub fn cancel_invitation(&self, org_id: &str, invitation_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.cancel_invitation(org_id.into(), invitation_id.into(), c))
    }

    /// [`core::Account::accept_invitation`].
    pub fn accept_invitation(&self, token: Vec<u8>, cancel: &CancelToken) -> R<ffi::Member> {
        run(cancel, |c| async move { self.0.accept_invitation(token, c).await.map(rec::member) })
    }

    /// [`core::Account::confirm_member`].
    pub fn confirm_member(
        &self,
        org_id: &str,
        member: &ffi::Member,
        vaults: Vec<ffi::VaultGrantRequest>,
        cancel: &CancelToken,
    ) -> R<ffi::Member> {
        run(cancel, |c| async move {
            let member = rec::member_in(member)?;
            let vaults = rec::grant_requests_in(vaults)?;
            self.0.confirm_member(org_id.into(), member, vaults, c).await.map(rec::member)
        })
    }

    /// [`core::Account::set_member_role`].
    pub fn set_member_role(
        &self,
        org_id: &str,
        member: &ffi::Member,
        role: ffi::OrgRole,
        cancel: &CancelToken,
    ) -> R<ffi::Member> {
        run(cancel, |c| async move {
            let member = rec::member_in(member)?;
            let role = rec::org_role_in(role)?;
            self.0.set_member_role(org_id.into(), member, role, c).await.map(rec::member)
        })
    }

    /// [`core::Account::remove_member`].
    pub fn remove_member(&self, org_id: &str, user_id: &str, cancel: &CancelToken) -> R<ffi::RotationReport> {
        run(cancel, |c| async move {
            self.0.remove_member(org_id.into(), user_id.into(), c).await.map(rec::rotation_report)
        })
    }

    /// [`core::Account::rotate_flagged`].
    pub fn rotate_flagged(&self, org_id: &str, cancel: &CancelToken) -> R<ffi::RotationReport> {
        run(cancel, |c| async move { self.0.rotate_flagged(org_id.into(), c).await.map(rec::rotation_report) })
    }

    /// [`core::Account::managed_org_vaults`].
    pub fn managed_org_vaults(&self, org_id: &str, cancel: &CancelToken) -> R<Vec<ffi::VaultInfo>> {
        run(cancel, |c| async move {
            Ok(self.0.managed_org_vaults(org_id.into(), c).await?.into_iter().map(vault_info).collect())
        })
    }

    /// [`core::Account::audit_log`].
    pub fn audit_log(
        &self,
        org_id: &str,
        before: &str,
        has_limit: bool,
        limit: u32,
        cancel: &CancelToken,
    ) -> R<ffi::AuditPage> {
        run(cancel, |c| async move {
            self.0.audit_log(org_id.into(), some(before), has_limit.then_some(limit), c).await.map(rec::audit_page)
        })
    }

    // ------------------------------------------------------------ service accounts (§9)

    /// [`core::Account::service_accounts`].
    pub fn service_accounts(&self, org_id: &str, cancel: &CancelToken) -> R<Vec<ffi::ServiceAccountInfo>> {
        run(cancel, |c| async move {
            Ok(self.0.service_accounts(org_id.into(), c).await?.into_iter().map(rec::service_account_info).collect())
        })
    }

    /// [`core::Account::create_service_account`].
    pub fn create_service_account(
        &self,
        org_id: &str,
        input: &ffi::NewServiceAccount,
        cancel: &CancelToken,
    ) -> R<ffi::CreatedServiceAccount> {
        run(cancel, |c| async move {
            let input = rec::new_service_account_in(input)?;
            self.0.create_service_account(org_id.into(), input, c).await.map(rec::created_service_account)
        })
    }

    /// [`core::Account::issue_service_account_secret`]; empty strings are none.
    pub fn issue_service_account_secret(
        &self,
        sa_id: &str,
        name: &str,
        expires_at: &str,
        cancel: &CancelToken,
    ) -> R<ffi::IssuedSecret> {
        run(cancel, |c| async move {
            self.0
                .issue_service_account_secret(sa_id.into(), some(name), some(expires_at), c)
                .await
                .map(rec::issued_secret)
        })
    }

    /// [`core::Account::service_account_secrets`].
    pub fn service_account_secrets(&self, sa_id: &str, cancel: &CancelToken) -> R<Vec<ffi::SaSecretInfo>> {
        run(cancel, |c| async move {
            Ok(self.0.service_account_secrets(sa_id.into(), c).await?.into_iter().map(rec::sa_secret_info).collect())
        })
    }

    /// [`core::Account::set_secret_expiry`].
    pub fn set_secret_expiry(
        &self,
        sa_id: &str,
        secret_id: &str,
        expires_at: &ffi::ExpiryChange,
        cancel: &CancelToken,
    ) -> R<ffi::SaSecretInfo> {
        run(cancel, |c| async move {
            let expires_at = rec::expiry_change_in(expires_at)?;
            self.0.set_secret_expiry(sa_id.into(), secret_id.into(), expires_at, c).await.map(rec::sa_secret_info)
        })
    }

    /// [`core::Account::revoke_secret`].
    pub fn revoke_secret(&self, sa_id: &str, secret_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.revoke_secret(sa_id.into(), secret_id.into(), c))
    }

    /// [`core::Account::update_service_account`].
    pub fn update_service_account(
        &self,
        sa_id: &str,
        update: &ffi::ServiceAccountUpdate,
        cancel: &CancelToken,
    ) -> R<ffi::ServiceAccountInfo> {
        run(cancel, |c| async move {
            let update = rec::service_account_update_in(update)?;
            self.0.update_service_account(sa_id.into(), update, c).await.map(rec::service_account_info)
        })
    }

    /// [`core::Account::delete_service_account`].
    pub fn delete_service_account(&self, sa_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.delete_service_account(sa_id.into(), c))
    }

    // ------------------------------------------------------------------ share links (§22)

    /// [`core::Account::share_base`]; empty when unknown.
    pub fn share_base(&self) -> R<String> {
        edge(|| Ok(rec::opt(self.0.share_base())))
    }

    /// [`core::Account::share_blocked_reason`]; empty when allowed.
    pub fn share_blocked_reason(&self, org_id: &str) -> R<String> {
        block(|| async { self.0.share_blocked_reason(some(org_id)).await.map(rec::opt) })
    }

    /// [`core::Account::create_share`].
    pub fn create_share(
        &self,
        payload: ffi::SharePayload,
        options: ffi::ShareOptions,
        cancel: &CancelToken,
    ) -> R<ffi::CreatedShare> {
        run(cancel, |c| async move {
            self.0
                .create_share(rec::share_payload_in(payload), rec::share_options_in(options), c)
                .await
                .map(rec::created_share)
        })
    }

    /// [`core::Account::list_shares`].
    pub fn list_shares(&self, cancel: &CancelToken) -> R<Vec<ffi::ShareListing>> {
        run(cancel, |c| async move { Ok(self.0.list_shares(c).await?.into_iter().map(rec::share_listing).collect()) })
    }

    /// [`core::Account::revoke_share`].
    pub fn revoke_share(&self, share_id: &str, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.revoke_share(share_id.into(), c))
    }
}
