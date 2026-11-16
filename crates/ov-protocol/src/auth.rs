//! Request builders and response parsers for every client route of `openapi.yaml` (the auth
//! server, under `{api}`), ported from `auth/client.ts`.
//!
//! Each route has a `build_*` method on [`AuthApi`] that makes the [`HttpRequest`] and a `parse_*`
//! function that reads the [`HttpResponse`]. Authenticated routes take the access token; the caller
//! retries once with a refreshed token on a 401, except for [`AuthApi::build_restore_verify`] and
//! [`AuthApi::build_restore_finish`] (see [`retries_on_401`]). Routes with nothing to read on success
//! (204s, DELETEs, logout, ...) use [`parse_empty`](crate::parse_empty).

use ov_error::OvError;
use serde::Serialize;

#[cfg(test)]
use crate::error::parse_empty;
use crate::error::parse_json;
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::types::*;
use crate::url::{json_request, query, seg, to_json, Base};

/// Builds requests for the auth server's `{api}` base URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthApi {
    base: Base,
}

/// Whether a failed request should be retried once with a forced token refresh on 401. False for
/// the restore steps, whose 401 means a wrong old password and counts towards the lockout.
pub fn retries_on_401(req: &HttpRequest) -> bool {
    !(req.url.ends_with("/me/recovery/restore/verify") || req.url.ends_with("/me/recovery/restore/finish"))
}

impl AuthApi {
    /// `api` is `{api}` from discovery, e.g. `https://accounts.openvireo.com/api/v1`. Fails with
    /// `insecure_url` unless it is https (or loopback http, SPEC §1).
    pub fn new(api: &str) -> Result<Self, OvError> {
        Ok(AuthApi { base: Base::new(api, "api")? })
    }

    /// The base URL, without a trailing slash.
    pub fn api(&self) -> &str {
        self.base.as_str()
    }

    fn bare(&self, method: Method, path: &str, token: Option<&str>) -> HttpRequest {
        json_request(method, self.base.url(path), token, None)
    }

    fn with_body<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> HttpRequest {
        json_request(method, self.base.url(path), token, Some(to_json(body)))
    }

    // ---------------------------------------------------------------- authentication

    /// `POST /auth/register/start` → [`parse_register_start`].
    pub fn build_register_start(&self, body: &RegisterStartRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/register/start", None, body)
    }
    /// `POST /auth/register/finish` → [`parse_session`].
    pub fn build_register_finish(&self, body: &RegisterFinishRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/register/finish", None, body)
    }
    /// `POST /auth/login/start` → [`parse_login_start`].
    pub fn build_login_start(&self, body: &LoginStartRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/login/start", None, body)
    }
    /// `POST /auth/login/finish` → [`parse_login_finish`].
    pub fn build_login_finish(&self, body: &LoginFinishRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/login/finish", None, body)
    }
    /// `POST /auth/login/mfa` → [`parse_session`].
    pub fn build_login_mfa(&self, body: &LoginMfaRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/login/mfa", None, body)
    }
    /// `POST /auth/refresh` → [`parse_refresh`].
    pub fn build_refresh(&self, refresh_token: &str) -> HttpRequest {
        self.with_body(Method::Post, "auth/refresh", None, &RefreshRequest { refresh_token: refresh_token.into() })
    }
    /// `POST /auth/logout` → [`parse_empty`](crate::parse_empty). `keepalive` lets the web send it during page unload.
    pub fn build_logout(&self, token: &str, keepalive: bool) -> HttpRequest {
        HttpRequest { keepalive, ..self.bare(Method::Post, "auth/logout", Some(token)) }
    }
    /// `POST /auth/service-account` → [`parse_service_account_exchange`].
    pub fn build_service_account_exchange(&self, body: &ServiceAccountExchangeRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/service-account", None, body)
    }

    // ---------------------------------------------------------------- account recovery (SPEC §18)

    /// `GET /auth/recover/{token}` → [`parse_recover_info`]. 409 `recovery_not_ready` (details
    /// `notBefore`), 410 `recovery_cancelled` / `session_expired`.
    pub fn build_recover_info(&self, reset_token: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("auth/recover/{}", seg(reset_token)), None)
    }
    /// `POST /auth/recover/start` → [`parse_opaque_registration`].
    pub fn build_recover_start(&self, body: &RecoverStartRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/recover/start", None, body)
    }
    /// `POST /auth/recover/finish` → [`parse_session`].
    pub fn build_recover_finish(&self, body: &RecoverFinishRequest) -> HttpRequest {
        self.with_body(Method::Post, "auth/recover/finish", None, body)
    }

    // ---------------------------------------------------------------- me, keys, devices

    /// `GET /me` → [`parse_me`].
    pub fn build_me(&self, token: &str) -> HttpRequest {
        self.bare(Method::Get, "me", Some(token))
    }
    /// `POST /me/password/start` → [`parse_opaque_registration`]. Needs a recent token.
    pub fn build_password_start(&self, token: &str, body: &PasswordStartRequest) -> HttpRequest {
        self.with_body(Method::Post, "me/password/start", Some(token), body)
    }
    /// `POST /me/password/finish` → [`parse_empty`](crate::parse_empty).
    pub fn build_password_finish(&self, token: &str, body: &PasswordFinishRequest) -> HttpRequest {
        self.with_body(Method::Post, "me/password/finish", Some(token), body)
    }
    /// `GET /me/deletion` → [`parse_deletion_preview`] (SPEC §23).
    pub fn build_deletion_preview(&self, token: &str) -> HttpRequest {
        self.bare(Method::Get, "me/deletion", Some(token))
    }
    /// `DELETE /me` → [`parse_schedule_deletion`]. 409 `deletion_blocked` lists `orgs`.
    pub fn build_schedule_deletion(&self, token: &str, confirm_email: &str) -> HttpRequest {
        self.with_body(Method::Delete, "me", Some(token), &DeleteAccountRequest { confirm: confirm_email.into() })
    }
    /// `POST /me/deletion/cancel` → [`parse_empty`](crate::parse_empty).
    pub fn build_cancel_deletion(&self, token: &str) -> HttpRequest {
        self.bare(Method::Post, "me/deletion/cancel", Some(token))
    }
    /// `POST /me/email` → [`parse_email_request`].
    pub fn build_email_request(&self, token: &str, email: &str) -> HttpRequest {
        self.with_body(Method::Post, "me/email", Some(token), &EmailChangeRequest { email: email.into() })
    }
    /// `POST /me/email/start` → [`parse_opaque_registration`].
    pub fn build_email_start(&self, token: &str, body: &EmailStartRequest) -> HttpRequest {
        self.with_body(Method::Post, "me/email/start", Some(token), body)
    }
    /// `POST /me/email/finish` → [`parse_empty`](crate::parse_empty).
    pub fn build_email_finish(&self, token: &str, body: &EmailFinishRequest) -> HttpRequest {
        self.with_body(Method::Post, "me/email/finish", Some(token), body)
    }
    /// `GET /me/recovery` → [`parse_recovery_status`].
    pub fn build_recovery_status(&self, token: &str) -> HttpRequest {
        self.bare(Method::Get, "me/recovery", Some(token))
    }
    /// `POST /me/recovery/restore/start` → [`parse_restore_start`]. Needs a recent token.
    pub fn build_restore_start(&self, token: &str, body: &RestoreStartRequest) -> HttpRequest {
        self.with_body(Method::Post, "me/recovery/restore/start", Some(token), body)
    }
    /// `POST /me/recovery/restore/verify` → [`parse_restore_verify`]. Not retried on 401.
    pub fn build_restore_verify(&self, token: &str, body: &RestoreVerifyRequest) -> HttpRequest {
        self.with_body(Method::Post, "me/recovery/restore/verify", Some(token), body)
    }
    /// `POST /me/recovery/restore/finish` → [`parse_empty`](crate::parse_empty). Not retried on 401.
    pub fn build_restore_finish(&self, token: &str, body: &RestoreFinishRequest) -> HttpRequest {
        self.with_body(Method::Post, "me/recovery/restore/finish", Some(token), body)
    }
    /// `POST /me/web-session` → [`parse_web_session`] (SPEC §16).
    pub fn build_web_session(&self, token: &str) -> HttpRequest {
        self.bare(Method::Post, "me/web-session", Some(token))
    }
    /// `POST /me/totp` → [`parse_totp_start`].
    pub fn build_totp_start(&self, token: &str) -> HttpRequest {
        self.bare(Method::Post, "me/totp", Some(token))
    }
    /// `PUT /me/totp` → [`parse_empty`](crate::parse_empty).
    pub fn build_totp_confirm(&self, token: &str, totp: &str) -> HttpRequest {
        self.with_body(Method::Put, "me/totp", Some(token), &TotpCodeRequest { totp: totp.into() })
    }
    /// `DELETE /me/totp` → [`parse_empty`](crate::parse_empty).
    pub fn build_totp_disable(&self, token: &str, totp: &str) -> HttpRequest {
        self.with_body(Method::Delete, "me/totp", Some(token), &TotpCodeRequest { totp: totp.into() })
    }
    /// `GET /users/lookup?email=` → [`parse_public_principal`].
    pub fn build_lookup_user(&self, token: &str, email: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("users/lookup{}", query(&[("email", Some(email.into()))])), Some(token))
    }
    /// `GET /principals/{principal}/public-key` → [`parse_public_principal`].
    pub fn build_public_key(&self, token: &str, principal: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("principals/{}/public-key", seg(principal)), Some(token))
    }
    /// `GET /devices` → [`parse_devices`].
    pub fn build_list_devices(&self, token: &str) -> HttpRequest {
        self.bare(Method::Get, "devices", Some(token))
    }
    /// `DELETE /devices/{id}` → [`parse_empty`](crate::parse_empty).
    pub fn build_revoke_device(&self, token: &str, device_id: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("devices/{}", seg(device_id)), Some(token))
    }

    // ---------------------------------------------------------------- orgs

    /// `POST /orgs` → [`parse_org`].
    pub fn build_create_org(&self, token: &str, name: &str) -> HttpRequest {
        self.with_body(Method::Post, "orgs", Some(token), &CreateOrgRequest { name: name.into() })
    }
    /// `GET /orgs/{org}` → [`parse_org`].
    pub fn build_get_org(&self, token: &str, org: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("orgs/{}", seg(org)), Some(token))
    }
    /// `PATCH /orgs/{org}` (rename or share-link policy) → [`parse_org`].
    pub fn build_update_org(&self, token: &str, org: &str, body: &UpdateOrgRequest) -> HttpRequest {
        self.with_body(Method::Patch, &format!("orgs/{}", seg(org)), Some(token), body)
    }
    /// `DELETE /orgs/{org}` → [`parse_empty`](crate::parse_empty).
    pub fn build_delete_org(&self, token: &str, org: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("orgs/{}", seg(org)), Some(token))
    }
    /// `GET /orgs/{org}/members` → [`parse_members`].
    pub fn build_list_members(&self, token: &str, org: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("orgs/{}/members", seg(org)), Some(token))
    }
    /// `PATCH /orgs/{org}/members/{user}` → [`parse_member`].
    pub fn build_set_member_role(
        &self,
        token: &str,
        org: &str,
        user: &str,
        body: &SetMemberRoleRequest,
    ) -> HttpRequest {
        self.with_body(Method::Patch, &format!("orgs/{}/members/{}", seg(org), seg(user)), Some(token), body)
    }
    /// `DELETE /orgs/{org}/members/{user}` → [`parse_empty`](crate::parse_empty).
    pub fn build_remove_member(&self, token: &str, org: &str, user: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("orgs/{}/members/{}", seg(org), seg(user)), Some(token))
    }
    /// `POST /orgs/{org}/members/{user}/confirm` → [`parse_member`]. 402 `plan_limit`.
    pub fn build_confirm_member(&self, token: &str, org: &str, user: &str, body: &ConfirmMemberRequest) -> HttpRequest {
        self.with_body(Method::Post, &format!("orgs/{}/members/{}/confirm", seg(org), seg(user)), Some(token), body)
    }
    /// `GET /orgs/{org}/invitations` → [`parse_invitations`].
    pub fn build_list_invitations(&self, token: &str, org: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("orgs/{}/invitations", seg(org)), Some(token))
    }
    /// `POST /orgs/{org}/invitations` → [`parse_invitation`]. 402 `plan_limit`.
    pub fn build_invite(&self, token: &str, org: &str, body: &InviteRequest) -> HttpRequest {
        self.with_body(Method::Post, &format!("orgs/{}/invitations", seg(org)), Some(token), body)
    }
    /// `DELETE /orgs/{org}/invitations/{id}` → [`parse_empty`](crate::parse_empty).
    pub fn build_cancel_invitation(&self, token: &str, org: &str, id: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("orgs/{}/invitations/{}", seg(org), seg(id)), Some(token))
    }
    /// `POST /invitations/accept` → [`parse_member`].
    pub fn build_accept_invitation(&self, token: &str, invitation_token: &str) -> HttpRequest {
        let body = AcceptInvitationRequest { token: invitation_token.into() };
        self.with_body(Method::Post, "invitations/accept", Some(token), &body)
    }

    // ---------------------------------------------------------------- vaults

    /// `GET /vaults` → [`parse_vaults`].
    pub fn build_list_vaults(&self, token: &str) -> HttpRequest {
        self.bare(Method::Get, "vaults", Some(token))
    }
    /// `POST /vaults` → [`parse_vault`]. 402 `plan_limit`, 409 id taken.
    pub fn build_create_vault(&self, token: &str, body: &CreateVaultRequest) -> HttpRequest {
        self.with_body(Method::Post, "vaults", Some(token), body)
    }
    /// `GET /vaults/{vault}` → [`parse_vault`].
    pub fn build_get_vault(&self, token: &str, vault: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("vaults/{}", seg(vault)), Some(token))
    }
    /// `PATCH /vaults/{vault}` → [`parse_vault`].
    pub fn build_rename_vault(&self, token: &str, vault: &str, encrypted_name: &str) -> HttpRequest {
        let body = RenameVaultRequest { encrypted_name: encrypted_name.into() };
        self.with_body(Method::Patch, &format!("vaults/{}", seg(vault)), Some(token), &body)
    }
    /// `DELETE /vaults/{vault}` → [`parse_empty`](crate::parse_empty). Delete the sync blob first.
    pub fn build_delete_vault(&self, token: &str, vault: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("vaults/{}", seg(vault)), Some(token))
    }
    /// `POST /vaults/{vault}/owner` → [`parse_vault`] (SPEC §23).
    pub fn build_transfer_vault(&self, token: &str, vault: &str, principal: &str) -> HttpRequest {
        let body = TransferVaultRequest { principal: principal.into() };
        self.with_body(Method::Post, &format!("vaults/{}/owner", seg(vault)), Some(token), &body)
    }
    /// `GET /vaults/{vault}/access` → [`parse_access`].
    pub fn build_list_access(&self, token: &str, vault: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("vaults/{}/access", seg(vault)), Some(token))
    }
    /// `POST /vaults/{vault}/access` → [`parse_empty`](crate::parse_empty). 402 `plan_limit`, 409 stale key version.
    pub fn build_grant_access(&self, token: &str, vault: &str, grants: &[Grant]) -> HttpRequest {
        let body = GrantAccessRequest { grants: grants.to_vec() };
        self.with_body(Method::Post, &format!("vaults/{}/access", seg(vault)), Some(token), &body)
    }
    /// `POST /vaults/{vault}/keys` (start a rotation, SPEC §7) → [`parse_empty`](crate::parse_empty).
    pub fn build_start_rotation(&self, token: &str, vault: &str, body: &StartRotationRequest) -> HttpRequest {
        self.with_body(Method::Post, &format!("vaults/{}/keys", seg(vault)), Some(token), body)
    }
    /// `POST /vaults/{vault}/keys/{version}/activate` → [`parse_empty`](crate::parse_empty).
    pub fn build_activate_key(&self, token: &str, vault: &str, version: i64) -> HttpRequest {
        self.bare(Method::Post, &format!("vaults/{}/keys/{version}/activate", seg(vault)), Some(token))
    }

    // ---------------------------------------------------------------- service accounts

    /// `GET /orgs/{org}/service-accounts` → [`parse_service_accounts`].
    pub fn build_list_service_accounts(&self, token: &str, org: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("orgs/{}/service-accounts", seg(org)), Some(token))
    }
    /// `POST /orgs/{org}/service-accounts` → [`parse_service_account`]. 402 `plan_limit`.
    pub fn build_create_service_account(
        &self,
        token: &str,
        org: &str,
        body: &CreateServiceAccountRequest,
    ) -> HttpRequest {
        self.with_body(Method::Post, &format!("orgs/{}/service-accounts", seg(org)), Some(token), body)
    }
    /// `GET /service-accounts/{sa}` → [`parse_service_account`].
    pub fn build_get_service_account(&self, token: &str, sa: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("service-accounts/{}", seg(sa)), Some(token))
    }
    /// `PATCH /service-accounts/{sa}` → [`parse_service_account`].
    pub fn build_update_service_account(
        &self,
        token: &str,
        sa: &str,
        body: &UpdateServiceAccountRequest,
    ) -> HttpRequest {
        self.with_body(Method::Patch, &format!("service-accounts/{}", seg(sa)), Some(token), body)
    }
    /// `DELETE /service-accounts/{sa}` → [`parse_empty`](crate::parse_empty).
    pub fn build_delete_service_account(&self, token: &str, sa: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("service-accounts/{}", seg(sa)), Some(token))
    }
    /// `GET /service-accounts/{sa}/secrets` → [`parse_sa_secrets`].
    pub fn build_list_sa_secrets(&self, token: &str, sa: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("service-accounts/{}/secrets", seg(sa)), Some(token))
    }
    /// `POST /service-accounts/{sa}/secrets` → [`parse_empty`](crate::parse_empty) (201, no body to read).
    pub fn build_issue_sa_secret(&self, token: &str, sa: &str, body: &NewSaSecret) -> HttpRequest {
        self.with_body(Method::Post, &format!("service-accounts/{}/secrets", seg(sa)), Some(token), body)
    }
    /// `PATCH /service-accounts/{sa}/secrets/{id}` → [`parse_sa_secret`].
    pub fn build_update_sa_secret(&self, token: &str, sa: &str, id: &str, expires_at: Option<&str>) -> HttpRequest {
        let body = UpdateSaSecretRequest { expires_at: expires_at.map(str::to_string) };
        self.with_body(Method::Patch, &format!("service-accounts/{}/secrets/{}", seg(sa), seg(id)), Some(token), &body)
    }
    /// `DELETE /service-accounts/{sa}/secrets/{id}` → [`parse_empty`](crate::parse_empty).
    pub fn build_revoke_sa_secret(&self, token: &str, sa: &str, id: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("service-accounts/{}/secrets/{}", seg(sa), seg(id)), Some(token))
    }

    // ---------------------------------------------------------------- share links (SPEC §22)

    /// `POST /shares` (reserve an id) → [`parse_share`]. 402 `plan_limit`, 403 policy.
    pub fn build_create_share(&self, token: &str, body: &CreateShareRequest) -> HttpRequest {
        self.with_body(Method::Post, "shares", Some(token), body)
    }
    /// `PUT /shares/{id}` (upload the ciphertext) → [`parse_share`].
    pub fn build_upload_share(&self, token: &str, id: &str, body: &UploadShareRequest) -> HttpRequest {
        self.with_body(Method::Put, &format!("shares/{}", seg(id)), Some(token), body)
    }
    /// `GET /shares` → [`parse_shares`].
    pub fn build_list_shares(&self, token: &str) -> HttpRequest {
        self.bare(Method::Get, "shares", Some(token))
    }
    /// `DELETE /shares/{id}` → [`parse_empty`](crate::parse_empty).
    pub fn build_revoke_share(&self, token: &str, id: &str) -> HttpRequest {
        self.bare(Method::Delete, &format!("shares/{}", seg(id)), Some(token))
    }
    /// `GET /public/shares/{id}` (no auth) → [`parse_public_share`].
    pub fn build_public_share(&self, id: &str) -> HttpRequest {
        self.bare(Method::Get, &format!("public/shares/{}", seg(id)), None)
    }
    /// `POST /public/shares/{id}/open` (no auth) → [`parse_open_share`]. 403 `invalid_passcode`
    /// (details `attemptsLeft`).
    pub fn build_open_share(&self, id: &str, body: &OpenShareRequest) -> HttpRequest {
        self.with_body(Method::Post, &format!("public/shares/{}/open", seg(id)), None, body)
    }

    // ---------------------------------------------------------------- audit, billing

    /// `GET /orgs/{org}/audit?before=&limit=` → [`parse_audit`].
    pub fn build_audit(&self, token: &str, org: &str, before: Option<&str>, limit: Option<u32>) -> HttpRequest {
        let q = query(&[("before", before.map(str::to_string)), ("limit", limit.map(|l| l.to_string()))]);
        self.bare(Method::Get, &format!("orgs/{}/audit{q}", seg(org)), Some(token))
    }
    /// `GET /billing/apple/eligibility?org=` → [`parse_apple_eligibility`] (SPEC §19).
    pub fn build_apple_eligibility(&self, token: &str, org: Option<&str>) -> HttpRequest {
        let q = query(&[("org", org.map(str::to_string))]);
        self.bare(Method::Get, &format!("billing/apple/eligibility{q}"), Some(token))
    }
    /// `POST /billing/apple/transactions` → [`parse_apple_transaction`] (SPEC §19).
    pub fn build_report_apple_transaction(&self, token: &str, signed_transaction: &str) -> HttpRequest {
        let body = AppleTransactionRequest { signed_transaction: signed_transaction.into() };
        self.with_body(Method::Post, "billing/apple/transactions", Some(token), &body)
    }
}

macro_rules! parsers {
    ($( $(#[$m:meta])* $name:ident -> $t:ty; )+) => {
        $(
            $(#[$m])*
            pub fn $name(res: &HttpResponse) -> Result<$t, OvError> {
                parse_json(res)
            }
        )+
    };
}

parsers! {
    /// `POST /auth/register/start`.
    parse_register_start -> RegisterStartResponse;
    /// `POST /auth/register/finish`, `/auth/login/mfa`, `/auth/recover/finish`.
    parse_session -> Session;
    /// `POST /auth/login/start`.
    parse_login_start -> LoginStartResponse;
    /// `POST /auth/login/finish`: a session or an MFA challenge.
    parse_login_finish -> LoginFinishResponse;
    /// `POST /auth/refresh`.
    parse_refresh -> TokenPair;
    /// `POST /auth/service-account`.
    parse_service_account_exchange -> ServiceAccountExchange;
    /// `GET /auth/recover/{token}`.
    parse_recover_info -> RecoveryReset;
    /// `POST /auth/recover/start`, `/me/password/start`, `/me/email/start`.
    parse_opaque_registration -> OpaqueRegistrationResponse;
    /// `GET /me`.
    parse_me -> Me;
    /// `GET /me/deletion`.
    parse_deletion_preview -> DeletionPreview;
    /// `DELETE /me` (202).
    parse_schedule_deletion -> DeletionScheduled;
    /// `GET /me/recovery`.
    parse_recovery_status -> RecoveryArchive;
    /// `POST /me/recovery/restore/start`.
    parse_restore_start -> RestoreStartResponse;
    /// `POST /me/recovery/restore/verify`.
    parse_restore_verify -> RestoreVerified;
    /// `POST /me/web-session`.
    parse_web_session -> WebSession;
    /// `POST /me/totp`.
    parse_totp_start -> TotpEnrolment;
    /// `GET /users/lookup`, `GET /principals/{principal}/public-key`.
    parse_public_principal -> PublicPrincipal;
    /// `GET /devices`.
    parse_devices -> DeviceList;
    /// `POST /orgs`, `GET`/`PATCH /orgs/{org}`.
    parse_org -> Org;
    /// `GET /orgs/{org}/members`.
    parse_members -> MemberList;
    /// `PATCH /orgs/{org}/members/{user}`, `.../confirm`, `POST /invitations/accept`.
    parse_member -> Member;
    /// `GET /orgs/{org}/invitations`.
    parse_invitations -> InvitationList;
    /// `POST /orgs/{org}/invitations`.
    parse_invitation -> Invitation;
    /// `GET /vaults`.
    parse_vaults -> VaultList;
    /// `POST /vaults`, `GET`/`PATCH /vaults/{vault}`, `POST /vaults/{vault}/owner`.
    parse_vault -> Vault;
    /// `GET /vaults/{vault}/access`.
    parse_access -> VaultAccessList;
    /// `GET /orgs/{org}/service-accounts`.
    parse_service_accounts -> ServiceAccountList;
    /// `POST /orgs/{org}/service-accounts`, `GET`/`PATCH /service-accounts/{sa}`.
    parse_service_account -> ServiceAccount;
    /// `GET /service-accounts/{sa}/secrets`.
    parse_sa_secrets -> SaSecretList;
    /// `PATCH /service-accounts/{sa}/secrets/{id}`.
    parse_sa_secret -> SaSecret;
    /// `POST /shares`, `PUT /shares/{id}`.
    parse_share -> Share;
    /// `GET /shares`.
    parse_shares -> ShareList;
    /// `GET /public/shares/{id}`.
    parse_public_share -> PublicShareInfo;
    /// `POST /public/shares/{id}/open`.
    parse_open_share -> OpenedShare;
    /// `GET /orgs/{org}/audit`.
    parse_audit -> AuditPage;
    /// `GET /billing/apple/eligibility`.
    parse_apple_eligibility -> AppleEligibility;
    /// `POST /billing/apple/transactions`.
    parse_apple_transaction -> AppleTransactionRecorded;
}

/// `POST /me/email` (202): the body is optional.
pub fn parse_email_request(res: &HttpResponse) -> Result<EmailCodeSent, OvError> {
    Ok(parse_json::<Option<EmailCodeSent>>(res)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{request_header, response};
    use ov_error::OvErrorCode;
    use serde_json::{json, Value};

    fn api() -> AuthApi {
        AuthApi::new("https://accounts.example/api/v1/").unwrap()
    }

    fn body(req: &HttpRequest) -> Value {
        serde_json::from_slice(req.body.as_deref().unwrap()).unwrap()
    }

    #[test]
    fn base_url_must_be_secure() {
        assert_eq!(AuthApi::new("http://accounts.example/api/v1").unwrap_err().code, OvErrorCode::InsecureUrl);
        assert_eq!(AuthApi::new("http://localhost:8000/api/v1").unwrap().api(), "http://localhost:8000/api/v1");
        assert_eq!(api().api(), "https://accounts.example/api/v1");
    }

    #[test]
    fn public_json_request() {
        let r = api().build_login_start(&LoginStartRequest { email: "a@b.c".into(), ke1: "AA".into() });
        assert_eq!((r.method, r.url.as_str()), (Method::Post, "https://accounts.example/api/v1/auth/login/start"));
        assert_eq!(request_header(&r, "accept"), Some("application/json"));
        assert_eq!(request_header(&r, "content-type"), Some("application/json"));
        assert_eq!(request_header(&r, "authorization"), None);
        assert_eq!(body(&r), json!({"email": "a@b.c", "ke1": "AA"}));
        assert!(!r.keepalive);
    }

    #[test]
    fn authenticated_requests() {
        let r = api().build_me("jwt");
        assert_eq!((r.method, r.url.as_str()), (Method::Get, "https://accounts.example/api/v1/me"));
        assert_eq!(request_header(&r, "Authorization"), Some("Bearer jwt"));
        assert_eq!(request_header(&r, "content-type"), None);
        assert_eq!(r.body, None);
        // Debug never shows the token.
        assert!(!format!("{r:?}").contains("jwt"));

        let r = api().build_logout("jwt", true);
        assert!(r.keepalive);
        let r = api().build_public_key("jwt", "user:0000-1");
        assert_eq!(r.url, "https://accounts.example/api/v1/principals/user:0000-1/public-key");
        let r = api().build_lookup_user("jwt", "a+b@x.y");
        assert_eq!(r.url, "https://accounts.example/api/v1/users/lookup?email=a%2Bb%40x.y");
        let r = api().build_audit("jwt", "org/1", None, Some(50));
        assert_eq!(r.url, "https://accounts.example/api/v1/orgs/org%2F1/audit?limit=50");
        let r = api().build_apple_eligibility("jwt", None);
        assert_eq!(r.url, "https://accounts.example/api/v1/billing/apple/eligibility");
        let r = api().build_activate_key("jwt", "v1", 3);
        assert_eq!(
            (r.method, r.url.as_str()),
            (Method::Post, "https://accounts.example/api/v1/vaults/v1/keys/3/activate")
        );
        let r = api().build_schedule_deletion("jwt", "a@b.c");
        assert_eq!((r.method, body(&r)), (Method::Delete, json!({"confirm": "a@b.c"})));
        let r = api().build_update_sa_secret("jwt", "sa", "s1", None);
        assert_eq!(body(&r), json!({"expires_at": null}));
        let r = api().build_update_org(
            "jwt",
            "o",
            &UpdateOrgRequest { item_share_links: Some(ShareLinkPolicy::Off), ..Default::default() },
        );
        assert_eq!(body(&r), json!({"item_share_links": "off"}));
        let r = api().build_public_share("AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(request_header(&r, "authorization"), None);
    }

    #[test]
    fn restore_steps_are_not_retried_on_401() {
        let a = api();
        let v = a.build_restore_verify("t", &RestoreVerifyRequest { session_id: "s".into(), auth_u: "A".into() });
        let f = a.build_restore_finish(
            "t",
            &RestoreFinishRequest { session_id: "s".into(), grants: vec![], proof: "p".into() },
        );
        assert!(!retries_on_401(&v) && !retries_on_401(&f));
        assert!(retries_on_401(&a.build_me("t")));
    }

    #[test]
    fn parsers() {
        let r = response(200, &[], r#"{"access_token":"a","refresh_token":"r","expires_in":600}"#);
        assert_eq!(parse_refresh(&r).unwrap().expires_in, 600);
        let e = parse_refresh(&response(401, &[], r#"{"error":"gone","code":"token_reused"}"#)).unwrap_err();
        assert_eq!((e.code, e.status), (OvErrorCode::TokenReused, Some(401)));
        assert_eq!(parse_email_request(&response(202, &[], "")).unwrap(), EmailCodeSent::default());
        assert_eq!(parse_email_request(&response(202, &[], r#"{"expires_in":900}"#)).unwrap().expires_in, Some(900));
        assert_eq!(parse_empty(&response(204, &[], "")), Ok(()));
        assert_eq!(parse_empty(&response(201, &[], "{}")), Ok(()));
    }
}
