//! Settings (SPEC §16), recovery (§18) and deletion (§23) on the facade, ported from `account.ts`.

use ov_crypto::encoding::{b64u, from_b64u};
use ov_crypto::keyset::{unwrap_keyset, wrap_keyset};
use ov_crypto::secret_key::format_secret_key;
use ov_error::{OvError, OvErrorCode};
use ov_protocol::auth as api;
use ov_protocol::types as w;
use zeroize::Zeroizing;

use super::account::{device_info, parse_sk, CachedProfile};
use super::convert::{
    crypto_kdf, crypto_wrapped, deletion_outcome, org_role, profile, vault_role, wire_kdf, wire_wrapped,
};
use super::signin::{fresh_keys, new_kdf};
use super::util::{lock, rng, secret_text, signed_out};
use crate::api::{
    Account, CancelToken, DeletionCandidate, DeletionOrg, DeletionPreview, DeletionShare, DeletionSubscription,
    DeletionVault, EmergencyKit, KdfOverrides, NewAccount, Profile, RecoveryReset, SecretBytes, SignedOutReason,
};

fn opaque_response(b64: &str) -> Result<Vec<u8>, OvError> {
    from_b64u(b64).map_err(|_| OvError::new(OvErrorCode::OpaqueFailed, "the server's OPAQUE response is malformed"))
}

impl Account {
    pub(crate) async fn me_impl(&self, cancel: &CancelToken) -> Result<Profile, OvError> {
        let me = self.call(cancel, |a, t| a.build_me(t), api::parse_me).await?;
        self.follow_email(&me.email).await?;
        lock(&self.inner.inner).deletion = me.deletion_scheduled_for.clone();
        self.cache_profile(&me.id, &CachedProfile { kdf: me.kdf.clone(), keyset: me.keyset.clone() }).await?;
        profile(&me)
    }

    pub(crate) async fn change_password_impl(
        &self,
        current: SecretBytes,
        next: SecretBytes,
        kdf: Option<KdfOverrides>,
        cancel: &CancelToken,
    ) -> Result<SecretBytes, OvError> {
        let current = secret_text(current, "password")?;
        let next = secret_text(next, "password")?;
        let (session, sk) = self.session_and_sk().await?;
        let keyset = self.check_password(&current, &sk, cancel).await?;
        let kdf = new_kdf(self, kdf)?;
        let auk = ov_crypto::auk::derive_auk(&next, &kdf, &sk, self.kdf_opts())?;
        let wrapped = wrap_keyset(&auk, &keyset)?;
        // password/start needs an access token issued in the last five minutes
        self.refresh_token(cancel).await?;
        let reg = ov_opaque::start_registration(&mut rng(), &next)?;
        let body = w::PasswordStartRequest { request: b64u(&reg.request) };
        let started =
            self.call(cancel, |a, t| a.build_password_start(t, &body), api::parse_opaque_registration).await?;
        let fin = ov_opaque::finish_registration(
            &mut rng(),
            reg.state,
            &opaque_response(&started.response)?,
            &self.ids(&session.email),
        )?;
        let body = w::PasswordFinishRequest {
            session_id: started.session_id,
            record: b64u(&fin.record),
            kdf: wire_kdf(&kdf),
            keyset: wire_wrapped(&wrapped),
        };
        self.call(cancel, |a, t| a.build_password_finish(t, &body), ov_protocol::parse_empty).await?;
        self.cache_profile(&session.user_id, &CachedProfile { kdf: body.kdf.clone(), keyset: body.keyset.clone() })
            .await?;
        Ok(auk.to_vec())
    }

    pub(crate) async fn request_email_change_impl(&self, email: &str, cancel: &CancelToken) -> Result<(), OvError> {
        self.refresh_token(cancel).await?;
        let email = email.trim();
        self.call(cancel, |a, t| a.build_email_request(t, email), api::parse_email_request).await.map(|_| ())
    }

    pub(crate) async fn change_email_impl(
        &self,
        email: &str,
        code: &str,
        password: SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), OvError> {
        let password = secret_text(password, "password")?;
        let (_, sk) = self.session_and_sk().await?;
        let email = email.trim().to_owned();
        drop(self.check_password(&password, &sk, cancel).await?);
        self.refresh_token(cancel).await?;
        let reg = ov_opaque::start_registration(&mut rng(), &password)?;
        let body =
            w::EmailStartRequest { email: email.clone(), code: code.trim().to_owned(), request: b64u(&reg.request) };
        let started = self.call(cancel, |a, t| a.build_email_start(t, &body), api::parse_opaque_registration).await?;
        let fin = ov_opaque::finish_registration(
            &mut rng(),
            reg.state,
            &opaque_response(&started.response)?,
            &self.ids(&email),
        )?;
        let body = w::EmailFinishRequest { session_id: started.session_id, record: b64u(&fin.record) };
        self.call(cancel, |a, t| a.build_email_finish(t, &body), ov_protocol::parse_empty).await?;
        self.follow_email(&email).await
    }

    pub(crate) async fn web_session_impl(
        &self,
        next: Option<String>,
        cancel: &CancelToken,
    ) -> Result<SecretBytes, OvError> {
        let ws = self.call(cancel, |a, t| a.build_web_session(t), api::parse_web_session).await?;
        let base = format!("{}/session/claim", self.inner.config.issuer.trim_end_matches('/'));
        let q = ov_protocol::url::query(&[("code", Some(ws.code)), ("next", next)]);
        Ok(format!("{base}{q}").into_bytes())
    }

    // --------------------------------------------------------------------- §18

    pub(crate) async fn recover_info_impl(&self, token: &str, cancel: &CancelToken) -> Result<RecoveryReset, OvError> {
        let r = self.call_public(cancel, self.auth().build_recover_info(token), api::parse_recover_info).await?;
        Ok(super::convert::recovery_reset(&r))
    }

    pub(crate) async fn recover_impl(
        &self,
        token: SecretBytes,
        password: SecretBytes,
        kdf: Option<KdfOverrides>,
        trust: bool,
        cancel: &CancelToken,
    ) -> Result<NewAccount, OvError> {
        let token = secret_text(token, "reset token")?;
        let password = secret_text(password, "password")?;
        // The email (idU) comes from the reset; this also fails early before not_before or after a cancel.
        let info = self.recover_info_impl(&token, cancel).await?;
        let email = info.email;
        let kdf = new_kdf(self, kdf)?;
        let reg = ov_opaque::start_registration(&mut rng(), &password)?;
        let body = w::RecoverStartRequest { token: token.to_string(), request: b64u(&reg.request) };
        let started =
            self.call_public(cancel, self.auth().build_recover_start(&body), api::parse_opaque_registration).await?;
        let f = fresh_keys(self, &password, &email, kdf, reg.state, &opaque_response(&started.response)?)?;
        let finish = w::RecoverFinishRequest {
            session_id: started.session_id,
            record: b64u(&f.record),
            kdf: wire_kdf(&f.kdf),
            keyset: wire_wrapped(&f.wrapped),
            device: device_info(&self.inner.client.config, None),
        };
        let session = self.call_public(cancel, self.auth().build_recover_finish(&finish), api::parse_session).await?;
        // Whatever this device held for the account belongs to the old keys.
        self.lock_keys();
        self.clear_offline_data(&session.user.id).await?;
        self.host().store.delete(&self.older_sk_key(&email)).await?;
        self.begin(&email, &session, &f.sk, trust).await?;
        self.cache_profile(&session.user.id, &CachedProfile { kdf: finish.kdf, keyset: finish.keyset }).await?;
        {
            let mut g = lock(&self.inner.inner);
            g.keyset = Some(f.keyset);
            g.offline = false;
            g.deletion = None;
        }
        Ok(NewAccount {
            user_id: session.user.id,
            secret_key: format_secret_key(&f.sk).as_bytes().to_vec(),
            emergency_kit: EmergencyKit {
                email,
                issuer: self.inner.config.issuer.clone(),
                web: self.inner.config.web.clone(),
            },
            auk: f.auk.to_vec(),
        })
    }

    pub(crate) async fn restore_from_archive_impl(
        &self,
        old_password: SecretBytes,
        old_secret_key: SecretBytes,
        cancel: &CancelToken,
    ) -> Result<u32, OvError> {
        let old_password = secret_text(old_password, "password")?;
        let old_sk = parse_sk(&secret_text(old_secret_key, "Secret Key")?)?;
        let (cur_enc_pk, cur_sign_pk) = self.with_keyset(|ks| (ks.public.enc_pk, ks.public.sign_pk))?;
        let session = self.inner.tokens.load().await?.ok_or_else(|| signed_out("not signed in"))?;
        let principal = format!("user:{}", session.user_id);
        // The restore routes need an access token issued in the last five minutes.
        self.refresh_token(cancel).await?;
        let login = ov_opaque::start_login(&mut rng(), &old_password)?;
        let body = w::RestoreStartRequest { ke1: b64u(&login.ke1) };
        let started = self.call(cancel, |a, t| a.build_restore_start(t, &body), api::parse_restore_start).await?;
        let email = started.email.clone().unwrap_or_else(|| session.email.clone());
        let wrong = || OvError::new(OvErrorCode::Unauthorized, "the old master password is wrong").with_status(401);
        let ke2 = from_b64u(&started.ke2).map_err(|_| wrong())?;
        let fin = ov_opaque::finish_login(&mut rng(), login.state, &ke2, &self.ids(&email), &self.opaque_context())
            .map_err(|_| wrong())?;
        let body = w::RestoreVerifyRequest { session_id: started.session_id, auth_u: b64u(&fin.auth_u) };
        let verified = self.call(cancel, |a, t| a.build_restore_verify(t, &body), api::parse_restore_verify).await?;
        let params = crypto_kdf(&verified.kdf);
        ov_crypto::auk::check_kdf_params(&params, super::convert::kdf_min(&self.inner.config))?;
        let auk = ov_crypto::auk::derive_auk(&old_password, &params, &old_sk, self.kdf_opts())?;
        // The password was right (OPAQUE), so a failure here means the wrong Secret Key.
        let old = unwrap_keyset(&auk, &crypto_wrapped(&verified.keyset)).map_err(|e| {
            if e.is(OvErrorCode::DecryptionFailed) {
                OvError::new(OvErrorCode::InvalidSecretKey, "the old Secret Key doesn't open the archived keys")
            } else {
                e
            }
        })?;
        let mut grants = Vec::with_capacity(verified.grants.len());
        for g in &verified.grants {
            let sealed =
                from_b64u(&g.sealed_key).map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "bad sealed key"))?;
            let resealed = ov_crypto::restore::reseal_vault_key(&old.enc_sk, &cur_enc_pk, &g.vault_id, &sealed)?;
            grants.push(w::VaultGrant {
                vault_id: g.vault_id.clone(),
                principal: principal.clone(),
                role: g.role.clone(),
                key_version: g.key_version,
                sealed_key: b64u(&resealed),
            });
        }
        let proof = ov_crypto::restore::restore_proof(&old.sign_seed, &session.user_id, &cur_enc_pk, &cur_sign_pk);
        drop(old);
        let restored = grants.len() as u32;
        let body = w::RestoreFinishRequest { session_id: verified.session_id, grants, proof: b64u(&proof) };
        self.call(cancel, |a, t| a.build_restore_finish(t, &body), ov_protocol::parse_empty).await?;
        // As on an `access` event: new vlt claims, then the vault list.
        self.refresh_token(cancel).await?;
        self.load_vault_list(cancel).await?;
        Ok(restored)
    }

    // --------------------------------------------------------------------- §23

    pub(crate) async fn deletion_preview_impl(&self, cancel: &CancelToken) -> Result<DeletionPreview, OvError> {
        let p = self.call(cancel, |a, t| a.build_deletion_preview(t), api::parse_deletion_preview).await?;
        let mut names = std::collections::HashMap::new();
        if p.scheduled_for.is_none() && self.is_unlocked() {
            for v in self.load_vault_list(cancel).await?.0 {
                names.insert(v.id, v.name);
            }
        }
        Ok(DeletionPreview {
            scheduled_for: p.scheduled_for,
            erase_on: p.would_erase_on,
            vaults: p
                .vaults
                .iter()
                .map(|v| DeletionVault {
                    id: v.id.clone(),
                    name: names.get(&v.id).cloned(),
                    shared_with: v
                        .shared_with
                        .iter()
                        .map(|s| DeletionShare {
                            principal: s.principal.clone(),
                            display: s.display.clone(),
                            role: vault_role(&s.role),
                        })
                        .collect(),
                })
                .collect(),
            orgs: p
                .orgs
                .iter()
                .map(|o| DeletionOrg {
                    id: o.id.clone(),
                    name: o.name.clone(),
                    role: org_role(&o.role),
                    outcome: deletion_outcome(&o.outcome),
                    members: o
                        .members
                        .iter()
                        .map(|m| DeletionCandidate {
                            id: m.id.clone(),
                            email: m.email.clone(),
                            role: org_role(&m.role),
                        })
                        .collect(),
                })
                .collect(),
            subscription: p.subscription.as_ref().map(|s| DeletionSubscription {
                plan: s.plan.clone(),
                period_end: s.period_end.clone(),
                source: s.source.clone().unwrap_or_else(|| "stripe".into()),
                manage: s.manage.clone().unwrap_or_else(|| "website".into()),
            }),
            share_links: p.share_links.clamp(0, u32::MAX as i64) as u32,
            blocked: p.blocked,
        })
    }

    pub(crate) async fn delete_account_impl(
        &self,
        password: SecretBytes,
        confirm: &str,
        cancel: &CancelToken,
    ) -> Result<String, OvError> {
        let password = secret_text(password, "password")?;
        let (session, sk) = self.session_and_sk().await?;
        drop(self.check_password(&password, &sk, cancel).await?);
        // DELETE /me needs an access token issued in the last five minutes.
        self.refresh_token(cancel).await?;
        let confirm = confirm.trim();
        let r = self.call(cancel, |a, t| a.build_schedule_deletion(t, confirm), api::parse_schedule_deletion).await?;
        self.end_session(&session.user_id, SignedOutReason::DeletionScheduled).await?;
        Ok(r.scheduled_for)
    }

    pub(crate) async fn restore_account_impl(
        &self,
        password: SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), OvError> {
        let password = secret_text(password, "password")?;
        let (_, sk) = self.session_and_sk().await?;
        drop(self.check_password(&password, &sk, cancel).await?);
        self.refresh_token(cancel).await?;
        self.call(cancel, |a, t| a.build_cancel_deletion(t), ov_protocol::parse_empty).await?;
        // A token without `del`, which opens vaults again.
        self.refresh_token(cancel).await?;
        lock(&self.inner.inner).deletion = None;
        Ok(())
    }

    pub(crate) async fn secret_key_impl(&self) -> Result<Option<SecretBytes>, OvError> {
        self.with_keyset(|_| ())?;
        let Some(s) = self.inner.tokens.load().await? else { return Ok(None) };
        Ok(self.stored_sk(&s.email).await?.map(|t: Zeroizing<String>| t.as_bytes().to_vec()))
    }
}
