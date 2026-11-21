//! Vault sharing and key rotation (SPEC §7), org members (§12) and service-account administration
//! (§9) on the facade. The sealing, the rotation plan, the org grant rule and the SA master keys are
//! `ov-vault`'s; this module fetches what they need and sends what they build.

use ov_error::{OvError, OvErrorCode};
use ov_protocol::auth as api;
use ov_protocol::parse_empty;
use ov_protocol::types as w;

use super::convert::{api_public_keys, wire_org_role, wire_vault_role};
use super::util::{lock, signed_out};
use crate::api::{
    Account, CancelToken, CreatedServiceAccount, GrantResult, Grantee, IssuedSecret, Member, NewServiceAccount,
    OrgRole, Principal, Rfc3339, RotationFailure, RotationReport, ShareRecipient, SyncReport, VaultGrantRequest,
    VaultRole,
};

fn recipient(pp: &w::PublicPrincipal) -> Result<ShareRecipient, OvError> {
    let keys = ov_vault::keys::trusted(&ov_vault::keys::public_of_principal(pp))?;
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
        self.share_vault_checked(vault_id, who, role, None, cancel).await
    }

    /// [`share_vault_impl`](Self::share_vault_impl) to the keys the user confirmed: refused with
    /// `invalid_public_keys` before anything is sealed when the grantee's keys are no longer those
    /// (contract-v1.8).
    pub(crate) async fn share_vault_confirmed_impl(
        &self,
        vault_id: &str,
        who: Grantee,
        role: VaultRole,
        keys: crate::api::PublicKeys,
        cancel: &CancelToken,
    ) -> Result<GrantResult, OvError> {
        self.share_vault_checked(vault_id, who, role, Some(keys), cancel).await
    }

    async fn share_vault_checked(
        &self,
        vault_id: &str,
        who: Grantee,
        role: VaultRole,
        confirmed: Option<crate::api::PublicKeys>,
        cancel: &CancelToken,
    ) -> Result<GrantResult, OvError> {
        let e = self.entry(vault_id, cancel).await?;
        let pp = self.public_principal(&who, cancel).await?;
        if let Some(keys) = confirmed {
            let now = recipient(&pp)?.public_keys;
            if (now.enc_pk.as_slice(), now.sign_pk.as_slice(), now.sig.as_slice())
                != (keys.enc_pk.as_slice(), keys.sign_pk.as_slice(), keys.sig.as_slice())
            {
                return Err(OvError::new(
                    OvErrorCode::InvalidPublicKeys,
                    "the recipient's keys changed since they were shown; check their fingerprint again",
                ));
            }
        }
        let sealed = ov_vault::grant(&e.vk, &pp, wire_vault_role(role))?;
        self.call(cancel, |a, t| a.build_grant_access(t, vault_id, std::slice::from_ref(&sealed.grant)), parse_empty)
            .await?;
        Ok(GrantResult { principal: pp.principal, fingerprint: sealed.fingerprint })
    }

    /// Key rotation (SPEC §7): POST keys (removing `remove` at once) → add the new key → re-key and
    /// conditional PUT (merge and retry on 412) → activate → re-encrypt the name.
    pub(crate) async fn rotate_impl(
        &self,
        vault_id: &str,
        remove: Vec<Principal>,
        cancel: &CancelToken,
    ) -> Result<SyncReport, OvError> {
        // The server's current view: a rotation may be pending (SPEC §7, contract-v1.8)
        let listed = self.call(cancel, |a, t| a.build_get_vault(t, vault_id), api::parse_vault).await?;
        self.cache_vault(&listed).await?;
        let mut e = self.ingest(&listed)?;
        if let Some(pending) = e.info.pending_key_version {
            if let Some(key) = e.vk.key(pending).map(|k| k.key.clone()) {
                // This account holds its key (a device stopped before activating): finish it first
                self.finish_rotation(&e, pending, &key, cancel).await?;
                e = self.entry(vault_id, cancel).await?;
            }
        }
        let foreign_pending = e.info.pending_key_version.is_some();
        let me = self.principal_str()?;
        let access = self.call(cancel, |a, t| a.build_list_access(t, vault_id), api::parse_access).await?.access;
        let plan = ov_vault::plan_rotation(&e.vk, &me, &access, &remove)?;
        let mut others = Vec::new();
        for p in plan.principals_needing_keys() {
            others.push(self.call(cancel, |a, t| a.build_public_key(t, &p), api::parse_public_principal).await?);
        }
        let my_public = self.with_keyset(|ks| ks.public)?;
        let req = plan.start_request(&my_public, &others)?;
        match self.call(cancel, |a, t| a.build_start_rotation(t, vault_id, &req), parse_empty).await {
            Err(err) if foreign_pending && err.is(OvErrorCode::Conflict) => {
                // Another member's rotation, less than 24 hours old (an older one the server replaces)
                let mut out = OvError::new(
                    OvErrorCode::Conflict,
                    "another member is rotating this vault's key; try again once they're done, or after 24 hours",
                )
                .with_status(409);
                out.server_code = Some("rotation_pending".to_owned());
                return Err(out);
            }
            r => r?,
        }
        if let Some(vk) = lock(&self.inner.inner).vaults.get_mut(vault_id) {
            vk.add_key(plan.new_key());
        }
        // One sync from the pending edits or the server's copy, re-keyed before the upload.
        let e = self.entry(vault_id, cancel).await?;
        let report = super::syncing::rekey_sync(self, &e, &plan.new_key().key, cancel).await?;
        let version = i64::from(plan.key_version());
        self.call(cancel, |a, t| a.build_activate_key(t, vault_id, version), parse_empty).await?;
        let rename = plan.rename_request(&e.info.name)?;
        self.call(cancel, |a, t| a.build_rename_vault(t, vault_id, &rename.encrypted_name), api::parse_vault).await?;
        if let Some(vk) = lock(&self.inner.inner).vaults.get_mut(vault_id) {
            vk.activate(plan.key_version());
        }
        // The cached list must hold the new sealed key, or the re-keyed copy won't open offline.
        if self.keeps_offline_data() {
            if let Ok(v) = self.call(cancel, |a, t| a.build_get_vault(t, vault_id), api::parse_vault).await {
                self.cache_vault(&v).await?;
                self.ingest(&v)?;
            }
        }
        Ok(report)
    }

    /// Finishes a rotation left pending at `version` whose key this account holds: one sync re-keyed
    /// to it, activate, and the name under the new key (SPEC §7 steps 2 and 3).
    async fn finish_rotation(
        &self,
        e: &super::keyring::VaultEntry,
        version: u32,
        key: &[u8],
        cancel: &CancelToken,
    ) -> Result<(), OvError> {
        super::syncing::rekey_sync(self, e, key, cancel).await?;
        let v = i64::from(version);
        self.call(cancel, |a, t| a.build_activate_key(t, &e.info.id, v), parse_empty).await?;
        if let Some(vk) = lock(&self.inner.inner).vaults.get_mut(&e.info.id) {
            vk.activate(version);
        }
        let mut k = zeroize::Zeroizing::new([0u8; 32]);
        if key.len() == 32 {
            k.copy_from_slice(key);
        }
        let enc = ov_crypto::vault_name::encrypt_vault_name(&k, &e.info.id, &e.info.name)?;
        let listed = self.call(cancel, |a, t| a.build_rename_vault(t, &e.info.id, &enc), api::parse_vault).await?;
        self.cache_vault(&listed).await?;
        self.ingest(&listed)?;
        Ok(())
    }

    /// Rotates every flagged org vault this account manages; failures are reported.
    pub(crate) async fn rotate_flagged_impl(
        &self,
        org_id: &str,
        cancel: &CancelToken,
    ) -> Result<RotationReport, OvError> {
        let mut report = RotationReport { rotated: vec![], failed: vec![] };
        self.load_vault_list(cancel).await?;
        let flagged: Vec<String> =
            lock(&self.inner.inner).vaults.flagged_for_rotation(org_id).iter().map(|v| v.id().to_owned()).collect();
        for id in flagged {
            match self.rotate_impl(&id, vec![], cancel).await {
                Ok(_) => report.rotated.push(id),
                Err(error) => report.failed.push(RotationFailure { vault_id: id, error }),
            }
        }
        Ok(report)
    }

    /// The member as the server lists it (with the public keys the facade record doesn't keep raw).
    async fn wire_member(&self, org_id: &str, user_id: &str, cancel: &CancelToken) -> Result<w::Member, OvError> {
        let members = self.call(cancel, |a, t| a.build_list_members(t, org_id), api::parse_members).await?.members;
        members
            .into_iter()
            .find(|m| m.user_id == user_id)
            .ok_or_else(|| OvError::new(OvErrorCode::NotFound, "no such member").with_status(404))
    }

    /// The org's SA master keys this account holds, sealed to another owner/admin.
    async fn sealed_sa_master_keys(
        &self,
        org_id: &str,
        principal: &str,
        enc_pk: &[u8; 32],
        cancel: &CancelToken,
    ) -> Result<Vec<w::SaMasterGrant>, OvError> {
        let listed =
            self.call(cancel, |a, t| a.build_list_service_accounts(t, org_id), api::parse_service_accounts).await?;
        let mut sas = Vec::new();
        for sa in listed.service_accounts {
            if sa.master_key.is_some() {
                sas.push(sa);
            } else {
                sas.push(
                    self.call(cancel, |a, t| a.build_get_service_account(t, &sa.id), api::parse_service_account)
                        .await?,
                );
            }
        }
        let g = lock(&self.inner.inner);
        let ks = g.keyset.as_ref().ok_or_else(|| signed_out("the account is locked"))?;
        ov_vault::seal_sa_master_keys(ks, &sas, principal, enc_pk)
    }

    /// Confirms an accepted member (SPEC §12): owners and admins get every org vault this account
    /// manages (`manage`) and the org's SA master keys; a member gets `vaults`.
    pub(crate) async fn confirm_member_impl(
        &self,
        org_id: &str,
        member: Member,
        vaults: Vec<VaultGrantRequest>,
        cancel: &CancelToken,
    ) -> Result<Member, OvError> {
        let wm = self.wire_member(org_id, &member.user_id, cancel).await?;
        if wm.public.is_none() {
            return Err(
                OvError::new(OvErrorCode::InvalidRequest, "this member has no public keys yet").with_status(400)
            );
        }
        let target = ov_vault::member_keys(&wm)?;
        let picked: Vec<ov_vault::VaultChoice> = vaults
            .iter()
            .map(|v| ov_vault::VaultChoice { vault_id: v.vault_id.clone(), role: wire_vault_role(v.role) })
            .collect();
        self.load_vault_list(cancel).await?;
        let missing = ov_vault::missing_vaults(&lock(&self.inner.inner).vaults, &picked);
        for id in missing {
            self.entry(&id, cancel).await?;
        }
        let sa_keys = if target.manager {
            Some(self.sealed_sa_master_keys(org_id, &target.principal, &target.public.enc_pk, cancel).await?)
        } else {
            None
        };
        let body = {
            let g = lock(&self.inner.inner);
            ov_vault::confirm_member_request(org_id, &target, &g.vaults, &picked, sa_keys)?
        };
        let m = self
            .call(cancel, |a, t| a.build_confirm_member(t, org_id, &member.user_id, &body), api::parse_member)
            .await?;
        Ok(super::convert::member(&m))
    }

    /// Changes a member's role; a promotion hands over the SA master keys, then `manage` on every org
    /// vault this account manages.
    pub(crate) async fn set_member_role_impl(
        &self,
        org_id: &str,
        member: Member,
        role: OrgRole,
        cancel: &CancelToken,
    ) -> Result<Member, OvError> {
        let wm = self.wire_member(org_id, &member.user_id, cancel).await?;
        let wrole = wire_org_role(role);
        let promoted = ov_vault::promotion(&wm, &wrole)?;
        let sa_keys = match &promoted {
            Some(k) => Some(self.sealed_sa_master_keys(org_id, &k.principal, &k.public.enc_pk, cancel).await?),
            None => None,
        };
        let body = ov_vault::set_member_role_request(wrole, sa_keys);
        let m = self
            .call(cancel, |a, t| a.build_set_member_role(t, org_id, &member.user_id, &body), api::parse_member)
            .await?;
        if let Some(k) = promoted {
            self.load_vault_list(cancel).await?;
            let managed: Vec<String> =
                lock(&self.inner.inner).vaults.managed_org_vaults(org_id).iter().map(|v| v.id().to_owned()).collect();
            for id in managed {
                self.share_vault_impl(&id, Grantee::Principal(k.principal.clone()), VaultRole::Manage, cancel).await?;
            }
        }
        Ok(super::convert::member(&m))
    }

    /// Creates a service account (SPEC §9): keyset and master key made here, the master key sealed
    /// to every owner and admin, the vaults granted, the first token returned.
    pub(crate) async fn create_service_account_impl(
        &self,
        org_id: &str,
        input: NewServiceAccount,
        cancel: &CancelToken,
    ) -> Result<CreatedServiceAccount, OvError> {
        let me = self.principal_str()?;
        let members = self.call(cancel, |a, t| a.build_list_members(t, org_id), api::parse_members).await?.members;
        let spec = ov_vault::ServiceAccountSpec {
            name: input.name.clone(),
            expires_at: input.expires_at.clone(),
            secret_name: input.secret_name.clone(),
        };
        let nsa = {
            let g = lock(&self.inner.inner);
            let ks = g.keyset.as_ref().ok_or_else(|| signed_out("the account is locked"))?;
            ov_vault::new_service_account(&self.inner.config.issuer, &me, ks, &members, &spec)?
        };
        let sa = self
            .call(cancel, |a, t| a.build_create_service_account(t, org_id, &nsa.request), api::parse_service_account)
            .await?;
        for g in &input.vaults {
            let e = self.entry(&g.vault_id, cancel).await?;
            let grant = nsa.vault_grant(&e.vk, wire_vault_role(g.role))?;
            self.call(cancel, |a, t| a.build_grant_access(t, &g.vault_id, std::slice::from_ref(&grant)), parse_empty)
                .await?;
        }
        Ok(CreatedServiceAccount {
            service_account: super::convert::service_account(&sa),
            token: nsa.token.as_bytes().to_vec(),
        })
    }

    /// Another secret for an SA (owner/admin): the master key unsealed here and wrapped for it.
    pub(crate) async fn issue_secret_impl(
        &self,
        sa_id: &str,
        name: Option<String>,
        expires_at: Option<Rfc3339>,
        cancel: &CancelToken,
    ) -> Result<IssuedSecret, OvError> {
        let sa = self.call(cancel, |a, t| a.build_get_service_account(t, sa_id), api::parse_service_account).await?;
        let issued = {
            let g = lock(&self.inner.inner);
            let ks = g.keyset.as_ref().ok_or_else(|| signed_out("the account is locked"))?;
            ov_vault::issue_sa_secret(&self.inner.config.issuer, ks, &sa, name.as_deref(), expires_at.as_deref())?
        };
        self.call(cancel, |a, t| a.build_issue_sa_secret(t, sa_id, &issued.body), parse_empty).await?;
        Ok(IssuedSecret {
            token: issued.token.as_bytes().to_vec(),
            id: issued.body.id.clone(),
            prefix: issued.body.prefix.clone(),
        })
    }
}
