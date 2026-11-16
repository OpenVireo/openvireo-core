//! Share links (SPEC §22) on the facade: record conversions to and from `ov-share`, and the
//! account's create / list / revoke.

use ov_crypto::auk::new_kdf_params;
use ov_crypto::encoding::b64u;
use ov_error::{OvError, OvErrorCode};
use ov_protocol::auth::{parse_share, parse_shares};
use ov_protocol::parse_empty;
use ov_protocol::types::{CreateShareRequest, UploadShareRequest};
use zeroize::Zeroizing;

use super::convert::wire_kdf;
use super::util::{lock, secret_text, signed_out};
use crate::api::{
    Account, CancelToken, CreatedShare, EntryRecord, FieldRecord, ShareField, ShareListing, ShareOptions, SharePayload,
    ShareRef, ShareableField,
};

pub(crate) fn api_payload(p: &ov_share::SharePayload) -> SharePayload {
    SharePayload {
        v: p.v,
        kind: p.kind.clone(),
        title: p.title.clone(),
        shared_by: p.shared_by.clone(),
        fields: p
            .fields
            .iter()
            .map(|f| ShareField { k: f.k.clone(), label: f.label.clone(), value: f.value.as_bytes().to_vec(), protected: f.protected })
            .collect(),
    }
}

pub(crate) fn share_payload(p: SharePayload) -> Result<ov_share::SharePayload, OvError> {
    let fields = p
        .fields
        .into_iter()
        .map(|f| {
            Ok(ov_share::ShareField {
                k: f.k,
                label: f.label,
                value: secret_text(f.value, "share field")?.to_string(),
                protected: f.protected,
            })
        })
        .collect::<Result<Vec<_>, OvError>>()?;
    Ok(ov_share::SharePayload { v: p.v, kind: p.kind, title: p.title, shared_by: p.shared_by, fields })
}

pub(crate) fn entry_fields(fields: &[FieldRecord]) -> Vec<ov_share::EntryField> {
    fields
        .iter()
        .map(|f| ov_share::EntryField::new(f.name.clone(), String::from_utf8_lossy(&f.value).into_owned(), f.protected))
        .collect()
}

pub(crate) fn shareable(entry: &EntryRecord) -> Vec<ShareableField> {
    ov_share::shareable_fields(&entry_fields(&entry.fields))
        .into_iter()
        .map(|s| ShareableField {
            name: s.name.clone(),
            kind: s.field.k.clone(),
            label: s.field.label.clone(),
            value: s.field.value.as_bytes().to_vec(),
            protected: s.field.protected,
        })
        .collect()
}

impl Account {
    pub(crate) async fn share_blocked(&self, org_id: Option<String>) -> Result<Option<String>, OvError> {
        let Some(org_id) = org_id else { return Ok(None) };
        let me = self.call(&CancelToken::new(), |a, t| a.build_me(t), ov_protocol::auth::parse_me).await?;
        let Some(org) = me.orgs.unwrap_or_default().into_iter().find(|o| o.id == org_id) else { return Ok(None) };
        use ov_protocol::types::{MemberStatus, OrgRole, ShareLinkPolicy};
        Ok(match org.item_share_links.unwrap_or(ShareLinkPolicy::On) {
            ShareLinkPolicy::Off => Some("Your organization has turned share links off.".into()),
            ShareLinkPolicy::Managers
                if !(org.status == MemberStatus::Confirmed && matches!(org.role, OrgRole::Owner | OrgRole::Admin)) =>
            {
                Some("In your organization only owners and admins can make share links.".into())
            }
            _ => None,
        })
    }

    pub(crate) async fn create_share_impl(
        &self,
        payload: SharePayload,
        options: ShareOptions,
        cancel: &CancelToken,
    ) -> Result<CreatedShare, OvError> {
        let enc_sk = self.with_keyset(|ks| Zeroizing::new(*ks.enc_sk))?;
        let base = self.share_base_url().ok_or_else(|| OvError::new(OvErrorCode::Unsupported, "this server has no share page"))?;
        let payload = share_payload(payload)?;
        let ShareOptions { expires_in, max_opens, passcode, vault_id, entry_id } = options;
        let passcode = passcode.map(|p| secret_text(p, "passcode")).transpose()?.filter(|p| !p.is_empty());
        let (kdf, passcode_key, auth) = match &passcode {
            Some(pc) => {
                let kdf = new_kdf_params()?;
                let key = ov_share::share_passcode_key(pc, &kdf, false)?;
                let auth = ov_share::share_auth(&key);
                (Some(kdf), Some(key), Some(b64u(&auth[..])))
            }
            None => (None, None, None),
        };
        let key = ov_share::new_share_key()?;
        let req = CreateShareRequest {
            vault_id: vault_id.clone(),
            expires_in: i64::from(expires_in),
            max_opens: max_opens.map(i64::from),
            kdf: kdf.as_ref().map(wire_kdf),
            auth,
        };
        let share = self.call(cancel, |a, t| a.build_create_share(t, &req), parse_share).await?;
        let ct = ov_share::encrypt_share_payload(&key, &share.id, &payload, passcode_key.as_deref())?;
        let reference = ov_share::ShareRef { vault: vault_id, entry: entry_id, title: payload.title.clone().unwrap_or_default() };
        let r = ov_share::encrypt_share_ref(&enc_sk[..], &share.id, &reference)?;
        let body = UploadShareRequest { ct: b64u(&ct), reference: r };
        self.call(cancel, |a, t| a.build_upload_share(t, &share.id, &body), parse_share).await?;
        let url = ov_share::share_link(&base, &share.id, &key);
        Ok(CreatedShare { id: share.id, url: url.as_bytes().to_vec(), expires_at: share.expires_at })
    }

    pub(crate) async fn list_shares_impl(&self, cancel: &CancelToken) -> Result<Vec<ShareListing>, OvError> {
        let enc_sk = self.with_keyset(|ks| Zeroizing::new(*ks.enc_sk))?;
        let list = self.call(cancel, |a, t| a.build_list_shares(t), parse_shares).await?;
        Ok(list
            .shares
            .into_iter()
            .map(|s| {
                let reference = s
                    .reference
                    .as_deref()
                    .and_then(|r| ov_share::decrypt_share_ref(&enc_sk[..], &s.id, r).ok())
                    .map(|r| ShareRef { vault: r.vault.clone(), entry: r.entry.clone(), title: r.title.clone() });
                ShareListing {
                    id: s.id,
                    vault_id: s.vault_id,
                    reference,
                    passcode: s.passcode,
                    max_opens: s.max_opens.map(|n| n.clamp(0, u32::MAX as i64) as u32),
                    opens: s.opens.clamp(0, u32::MAX as i64) as u32,
                    opened_at: s.opened_at,
                    created_at: s.created_at,
                    expires_at: s.expires_at,
                    status: s.status.as_str().to_owned(),
                    ended_at: s.ended_at,
                    end_reason: s.end_reason.map(|r| r.as_str().to_owned()),
                }
            })
            .collect())
    }

    pub(crate) async fn revoke_share_impl(&self, id: &str, cancel: &CancelToken) -> Result<(), OvError> {
        self.call(cancel, |a, t| a.build_revoke_share(t, id), parse_empty).await
    }

    pub(crate) fn share_base_url(&self) -> Option<String> {
        let c = &self.inner.config;
        c.share.clone().or_else(|| c.web.as_ref().map(|w| format!("{}/s", w.trim_end_matches('/'))))
    }

    /// Unused helper kept for symmetry with the lock check.
    pub(crate) fn require_unlocked(&self) -> Result<(), OvError> {
        if lock(&self.inner.inner).keyset.is_some() {
            Ok(())
        } else {
            Err(signed_out("the account is locked"))
        }
    }
}
