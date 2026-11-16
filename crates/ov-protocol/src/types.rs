//! Serde types for the JSON bodies of `openapi.yaml` (auth server) that clients use, ported from
//! `auth/types.ts`. Field names are the wire names.
//!
//! Conventions:
//! - A field the server always sends is a plain type. A field that may be absent is an `Option`
//!   that is left out when `None`. A field the schema marks nullable is an `Option` that
//!   serialises `None` as `null` (and reads a missing key as `None`).
//! - Binary fields stay base64url strings (`B64`), as in the SDK; ov-crypto decodes them.
//! - Enums keep values this build doesn't know in an `Other` variant, so a newer server never
//!   breaks parsing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// An enum on the wire as a string, with an `Other` variant for values this build doesn't know.
macro_rules! wire_enum {
    ($(#[$m:meta])* $name:ident { $( $(#[$vm:meta])* $variant:ident => $wire:literal, )+ }) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vm])* #[doc = concat!("`", $wire, "` on the wire.")] $variant, )+
            /// A value this build doesn't know, kept as sent.
            Other(String),
        }

        impl $name {
            /// The wire string.
            pub fn as_str(&self) -> &str {
                match self {
                    $( $name::$variant => $wire, )+
                    $name::Other(s) => s,
                }
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                match s {
                    $( $wire => $name::$variant, )+
                    other => $name::Other(other.to_string()),
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok($name::from(<String as serde::Deserialize>::deserialize(d)?.as_str()))
            }
        }
    };
}
pub(crate) use wire_enum;

/// `Option<Option<T>>` for PATCH fields where a missing key means "leave it" and `null` means
/// "clear it": `None` is left out, `Some(None)` is `null`, `Some(Some(v))` is `v`. Use with
/// `#[serde(default, skip_serializing_if = "Option::is_none", with = "double_option")]`.
pub mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialises the inner option (`Some(None)` → `null`).
    pub fn serialize<T: Serialize, S: Serializer>(v: &Option<Option<T>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(inner) => inner.serialize(s),
            None => s.serialize_none(),
        }
    }

    /// A present key, `null` or not, is `Some`.
    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}

// ------------------------------------------------------------------------------------ shared

/// `"user:<uuid>"` or `"sa:<uuid>"`.
pub type Principal = String;
/// base64url without padding.
pub type B64 = String;

wire_enum! {
    /// Role in an org.
    OrgRole { Owner => "owner", Admin => "admin", Member => "member", }
}
wire_enum! {
    /// Org membership status (SPEC §12).
    MemberStatus { Invited => "invited", Accepted => "accepted", Confirmed => "confirmed", }
}
wire_enum! {
    /// Role on a vault (SPEC §7).
    VaultRole { Read => "read", Write => "write", Manage => "manage", }
}
wire_enum! {
    /// Client platform of a device.
    Platform {
        /// Desktop on Linux.
        QtLinux => "qt-linux",
        /// Desktop on macOS.
        QtMacos => "qt-macos",
        /// Desktop on Windows.
        QtWindows => "qt-windows",
        /// Web app.
        Web => "web",
        /// `ov` CLI.
        Cli => "cli",
        /// `openvireo-connect`.
        Connect => "connect",
        /// iOS app.
        Ios => "ios",
    }
}
wire_enum! {
    /// Who may make share links from an org's vaults (SPEC §22).
    ShareLinkPolicy { On => "on", Managers => "managers", Off => "off", }
}

/// Argon2id parameters (`Kdf`, SPEC §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    /// `"argon2id"`.
    pub alg: String,
    /// base64url, 16 bytes.
    pub salt: B64,
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

/// `PublicKeys` (SPEC §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeys {
    /// X25519 public key.
    pub enc_pk: B64,
    /// Ed25519 public key.
    pub sign_pk: B64,
    /// Signature over the two keys.
    pub sig: B64,
}

/// `WrappedKeyset`: public keys plus the wrapped secret keys (SPEC §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKeyset {
    /// X25519 public key.
    pub enc_pk: B64,
    /// Ed25519 public key.
    pub sign_pk: B64,
    /// Signature over the two keys.
    pub sig: B64,
    /// `wrap(AUK or SA master, enc_sk ‖ sign_seed, "ov-keyset-v1")`.
    pub wrapped: B64,
}

/// `PublicPrincipal`: a principal's public keys, for sharing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPrincipal {
    /// X25519 public key.
    pub enc_pk: B64,
    /// Ed25519 public key.
    pub sign_pk: B64,
    /// Signature over the two keys.
    pub sig: B64,
    /// `user:<id>` or `sa:<id>`.
    pub principal: Principal,
    /// The user's email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The user's or SA's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `DeviceInfo`, sent at sign-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Absent on a device's first login; the server assigns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Up to 64 characters.
    pub name: String,
    /// Platform.
    pub platform: Platform,
}

/// `Session`: what a sign-in returns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// JWT, sent as `Authorization: Bearer`.
    pub access_token: String,
    /// Refresh token (SPEC §9).
    pub refresh_token: String,
    /// Seconds until the access token expires.
    pub expires_in: i64,
    /// This device's id.
    pub device_id: String,
    /// The user.
    pub user: SessionUser,
    /// The account's KDF parameters.
    pub kdf: Kdf,
    /// The account's keyset, wrapped with the AUK.
    pub keyset: WrappedKeyset,
}

/// `Session.user`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionUser {
    /// User id.
    pub id: String,
    /// Email.
    pub email: String,
}

/// A vault key sealed to a principal (`Grant`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Grantee.
    pub principal: Principal,
    /// Role.
    pub role: VaultRole,
    /// Key version the sealed key is for.
    pub key_version: i64,
    /// `seal(enc_pk, vault key, "ov-vault-key|<vault>")`.
    pub sealed_key: B64,
}

/// `VaultGrant`: a [`Grant`] that names its vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrant {
    /// Grantee.
    pub principal: Principal,
    /// Role.
    pub role: VaultRole,
    /// Key version the sealed key is for.
    pub key_version: i64,
    /// `seal(enc_pk, vault key, "ov-vault-key|<vault>")`.
    pub sealed_key: B64,
    /// Vault id.
    pub vault_id: String,
}

/// `SaMasterGrant`: an SA master key sealed to an owner or admin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaMasterGrant {
    /// Service account id.
    pub sa_id: String,
    /// Owner or admin it is sealed to.
    pub principal: Principal,
    /// `seal(enc_pk, SA master key, "ov-sa-master-v1|<sa>")`.
    pub sealed_key: B64,
}

/// The `{error, code}` body of every error response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Human-readable message.
    pub error: String,
    /// Machine-readable code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// `PlanLimit`: the 402 body (SPEC §19). [`crate::error_from_response`] puts these fields in
/// `OvError::details`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanLimitBody {
    /// Human-readable message.
    pub error: String,
    /// `"plan_limit"`.
    pub code: String,
    /// Which limit, e.g. `personal_vaults`.
    pub limit: String,
    /// The limit's value.
    pub max: i64,
    /// Current usage.
    pub current: i64,
    /// Plan id.
    pub plan: String,
    /// Where to change plan.
    pub upgrade_url: String,
}

// ------------------------------------------------------------------------------------ plans

/// A plan and its limits (SPEC §19). Without billing, `id` and every limit are `None`; a `None`
/// limit is unlimited.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// `free`, `premium`, `org_free`, `families`, `teams`, `business` (open set), or `None`.
    #[serde(default)]
    pub id: Option<String>,
    /// Limits by name (`personal_vaults`, `vault_bytes`, `members`, ...).
    pub limits: BTreeMap<String, Option<i64>>,
    /// Who bills a paid plan; `None` on a free plan, with billing off, or from older servers.
    #[serde(default)]
    pub billing: Option<Billing>,
}

/// How a paid plan is billed (SPEC §19). Clients follow `manage`, not `source`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Billing {
    /// `stripe` or `apple` (open set).
    pub source: String,
    /// `month` or `year` (open set).
    pub interval: String,
    /// `active`, `trialing` or `past_due` (open set).
    pub status: String,
    /// When it renews, or `None` when it won't.
    #[serde(default)]
    pub renews_at: Option<String>,
    /// When it ends because it won't renew.
    #[serde(default)]
    pub ends_at: Option<String>,
    /// `website` or `app_store` (open set).
    pub manage: String,
}

// ------------------------------------------------------------------------------------ authentication

/// `POST /auth/register/start` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    /// Email.
    pub email: String,
    /// OPAQUE registration request.
    pub request: B64,
}

/// `POST /auth/register/start` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// Server session (5 minutes).
    pub session_id: String,
    /// OPAQUE registration response.
    pub response: B64,
    /// The id the new user will have.
    pub user_id: String,
}

/// `POST /auth/register/finish` and `POST /auth/recover/finish` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFinishRequest {
    /// From the start step.
    pub session_id: String,
    /// OPAQUE registration record.
    pub record: B64,
    /// KDF parameters.
    pub kdf: Kdf,
    /// Keyset wrapped with the AUK.
    pub keyset: WrappedKeyset,
    /// This device.
    pub device: DeviceInfo,
}

/// `POST /auth/recover/finish` body (same shape as registration).
pub type RecoverFinishRequest = RegisterFinishRequest;

/// `POST /auth/login/start` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartRequest {
    /// Email.
    pub email: String,
    /// OPAQUE KE1.
    pub ke1: B64,
}

/// `POST /auth/login/start` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Server session.
    pub session_id: String,
    /// OPAQUE KE2.
    pub ke2: B64,
}

/// `POST /auth/login/finish` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    /// From the start step.
    pub session_id: String,
    /// OPAQUE authU.
    pub auth_u: B64,
    /// This device.
    pub device: DeviceInfo,
}

/// The MFA challenge `POST /auth/login/finish` answers with when TOTP is on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaChallenge {
    /// Always `true`.
    pub mfa_required: bool,
    /// Single use; 5 minutes.
    pub mfa_token: String,
    /// `["totp"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
}

/// `POST /auth/login/finish` response: a session, or an MFA challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LoginFinishResponse {
    /// TOTP is on: call `POST /auth/login/mfa`.
    Mfa(MfaChallenge),
    /// Signed in.
    Session(Box<Session>),
}

/// `POST /auth/login/mfa` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginMfaRequest {
    /// From the challenge.
    pub mfa_token: String,
    /// Six digits.
    pub totp: String,
}

/// `POST /auth/refresh` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// The current refresh token.
    pub refresh_token: String,
}

/// `POST /auth/refresh` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPair {
    /// New access token.
    pub access_token: String,
    /// New refresh token (the old one is now rotated).
    pub refresh_token: String,
    /// Seconds until the access token expires.
    pub expires_in: i64,
}

/// `POST /auth/service-account` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountExchangeRequest {
    /// Service account id.
    pub sa_id: String,
    /// The 32 secret bytes, base64url.
    pub secret: B64,
}

/// `POST /auth/service-account` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountExchange {
    /// Access token.
    pub access_token: String,
    /// Seconds until it expires.
    pub expires_in: i64,
    /// `wrap(kek, master, "ov-sa-master-v1|<sa>")`.
    pub wrapped_master: B64,
    /// The SA keyset, wrapped with the SA master key.
    pub keyset: WrappedKeyset,
}

// ------------------------------------------------------------------------------------ recovery (SPEC §18)

/// The `{session_id, response}` answer of an OPAQUE registration start (`/auth/recover/start`,
/// `/me/password/start`, `/me/email/start`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRegistrationResponse {
    /// Server session (5 minutes).
    pub session_id: String,
    /// OPAQUE registration response.
    pub response: B64,
}

/// `GET /auth/recover/{token}` response: what an approved reset will do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReset {
    /// Account email.
    pub email: String,
    /// The link works from this time.
    pub not_before: String,
    /// The link stops working at this time.
    pub expires_at: String,
    /// Days the archive is kept (30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_days: Option<i64>,
    /// What gets archived.
    pub archives: RecoveryArchives,
}

/// `RecoveryReset.archives`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArchives {
    /// Personal vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_vaults: Option<i64>,
    /// Grants on vaults the user doesn't own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_grants: Option<i64>,
    /// Orgs whose only confirmed owner/admin is this user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sole_admin_orgs: Option<Vec<String>>,
}

/// `POST /auth/recover/start` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverStartRequest {
    /// `ov_rc_…` reset token.
    pub token: String,
    /// OPAQUE registration request.
    pub request: B64,
}

/// `GET /me/recovery` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArchive {
    /// Whether an archive exists.
    pub archived: bool,
    /// The archived email (idU for the restore login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// When the archive is deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Archived personal vaults plus grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vaults: Option<i64>,
    /// Too many failed attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
}

/// `POST /me/recovery/restore/start` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreStartRequest {
    /// OPAQUE KE1.
    pub ke1: B64,
}

/// `POST /me/recovery/restore/start` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreStartResponse {
    /// Server session.
    pub session_id: String,
    /// OPAQUE KE2.
    pub ke2: B64,
    /// The archived email; finish OPAQUE with it as idU. Absent from older servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// `POST /me/recovery/restore/verify` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreVerifyRequest {
    /// From the start step.
    pub session_id: String,
    /// OPAQUE authU.
    pub auth_u: B64,
}

/// `POST /me/recovery/restore/verify` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreVerified {
    /// The same session, now valid for finish.
    pub session_id: String,
    /// The archived KDF.
    pub kdf: Kdf,
    /// The archived keyset, wrapped with the old AUK.
    pub keyset: WrappedKeyset,
    /// Archived grants whose vault still exists at that key version.
    pub grants: Vec<VaultGrant>,
}

/// `POST /me/recovery/restore/finish` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreFinishRequest {
    /// From verify.
    pub session_id: String,
    /// The vault keys re-sealed to the current keyset.
    pub grants: Vec<VaultGrant>,
    /// Ed25519 restore proof (SPEC §18).
    pub proof: B64,
}

// ------------------------------------------------------------------------------------ me

/// `GET /me` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Me {
    /// User id.
    pub id: String,
    /// Email.
    pub email: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// KDF parameters.
    pub kdf: Kdf,
    /// Keyset wrapped with the AUK.
    pub keyset: WrappedKeyset,
    /// Second factors.
    pub mfa: MeMfa,
    /// The personal plan (SPEC §19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Plan>,
    /// Orgs the user belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orgs: Option<Vec<MeOrg>>,
    /// Set while the account is scheduled for deletion (SPEC §23).
    #[serde(default)]
    pub deletion_scheduled_for: Option<String>,
}

/// `Me.mfa`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeMfa {
    /// TOTP is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
}

/// One of `Me.orgs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeOrg {
    /// Org id.
    pub id: String,
    /// Name.
    pub name: String,
    /// The user's role.
    pub role: OrgRole,
    /// The user's membership status.
    pub status: MemberStatus,
    /// The org's plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Plan>,
    /// The org's share-link policy (sent by servers with SPEC §22; not in openapi.yaml's `/me`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_share_links: Option<ShareLinkPolicy>,
}

/// `DELETE /me` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    /// The account email.
    pub confirm: String,
}

/// `DELETE /me` response (202).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionScheduled {
    /// When the account will be erased.
    pub scheduled_for: String,
}

/// `POST /me/password/start` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordStartRequest {
    /// OPAQUE registration request.
    pub request: B64,
}

/// `POST /me/password/finish` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordFinishRequest {
    /// From the start step.
    pub session_id: String,
    /// OPAQUE registration record.
    pub record: B64,
    /// New KDF parameters.
    pub kdf: Kdf,
    /// Keyset re-wrapped with the new AUK.
    pub keyset: WrappedKeyset,
}

/// `POST /me/web-session` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSession {
    /// `ov_ws_…`, single use.
    pub code: String,
    /// Seconds it is valid.
    pub expires_in: i64,
}

/// `POST /me/email` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailChangeRequest {
    /// New email.
    pub email: String,
}

/// `POST /me/email` response (202).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailCodeSent {
    /// Seconds the code is valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
}

/// `POST /me/email/start` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailStartRequest {
    /// New email.
    pub email: String,
    /// The 8-digit code.
    pub code: String,
    /// OPAQUE registration request under the new email.
    pub request: B64,
}

/// `POST /me/email/finish` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailFinishRequest {
    /// From the start step.
    pub session_id: String,
    /// OPAQUE registration record.
    pub record: B64,
}

/// `POST /me/totp` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpEnrolment {
    /// Base32 secret.
    pub secret: String,
    /// `otpauth://` URI.
    pub otpauth_uri: String,
}

/// `PUT /me/totp` and `DELETE /me/totp` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpCodeRequest {
    /// Six digits.
    pub totp: String,
}

/// `GET /me/deletion` response (SPEC §23).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionPreview {
    /// Set when the deletion is already scheduled.
    #[serde(default)]
    pub scheduled_for: Option<String>,
    /// When it would be erased if scheduled now.
    pub would_erase_on: String,
    /// Personal vaults.
    pub vaults: Vec<DeletionVault>,
    /// Orgs and what happens to them.
    pub orgs: Vec<DeletionOrg>,
    /// The paid subscription, if any.
    #[serde(default)]
    pub subscription: Option<DeletionSubscription>,
    /// Number of share links.
    pub share_links: i64,
    /// Whether an org blocks the deletion.
    pub blocked: bool,
}

/// One of `DeletionPreview.vaults`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionVault {
    /// Vault id.
    pub id: String,
    /// Encrypted name (SPEC §7).
    pub encrypted_name: B64,
    /// Others with access.
    pub shared_with: Vec<DeletionShare>,
}

/// One of `DeletionVault.shared_with`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionShare {
    /// Principal.
    pub principal: Principal,
    /// Email or SA name.
    #[serde(default)]
    pub display: Option<String>,
    /// Role.
    pub role: VaultRole,
}

wire_enum! {
    /// What happens to an org when its member deletes their account.
    DeletionOutcome { Leave => "leave", Delete => "delete", Blocked => "blocked", }
}

/// One of `DeletionPreview.orgs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionOrg {
    /// Org id.
    pub id: String,
    /// Name.
    pub name: String,
    /// The user's role.
    pub role: OrgRole,
    /// What happens to it.
    pub outcome: DeletionOutcome,
    /// Confirmed members, only for a blocked org.
    pub members: Vec<DeletionMember>,
}

/// One of `DeletionOrg.members`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionMember {
    /// User id.
    pub id: String,
    /// Email.
    pub email: String,
    /// Role.
    pub role: OrgRole,
}

/// `DeletionPreview.subscription`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionSubscription {
    /// Plan id.
    pub plan: String,
    /// End of the paid period.
    #[serde(default)]
    pub period_end: Option<String>,
    /// `stripe` or `apple`; absent from servers before In-App Purchase (read as stripe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// `website` or `app_store`; absent from older servers (read as website).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manage: Option<String>,
}

/// `GET /devices` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceList {
    /// Devices.
    pub devices: Vec<Device>,
}

/// One signed-in device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Device id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: Platform,
    /// First sign-in.
    pub created_at: String,
    /// Last use.
    pub last_seen_at: String,
    /// Whether it is the calling device.
    pub current: bool,
}

// ------------------------------------------------------------------------------------ orgs

/// `Org`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    /// Org id.
    pub id: String,
    /// Name.
    pub name: String,
    /// The caller's role.
    pub role: OrgRole,
    /// The org's plan (SPEC §19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Plan>,
    /// Share-link policy (SPEC §22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_share_links: Option<ShareLinkPolicy>,
    /// Created.
    pub created_at: String,
}

/// `POST /orgs` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    /// Up to 128 characters.
    pub name: String,
}

/// `PATCH /orgs/{org}` body: rename, or set the share-link policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateOrgRequest {
    /// New name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New share-link policy (owner/admin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_share_links: Option<ShareLinkPolicy>,
}

/// `Member`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// User id.
    pub user_id: String,
    /// Email.
    pub email: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Role.
    pub role: OrgRole,
    /// Status.
    pub status: MemberStatus,
    /// Public keys (for confirming).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<PublicKeys>,
}

/// `GET /orgs/{org}/members` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberList {
    /// Members.
    pub members: Vec<Member>,
}

/// `PATCH /orgs/{org}/members/{user}` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMemberRoleRequest {
    /// New role.
    pub role: OrgRole,
    /// SA master keys sealed to the member, on promotion to admin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sa_master_keys: Option<Vec<SaMasterGrant>>,
}

/// `POST /orgs/{org}/members/{user}/confirm` body.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmMemberRequest {
    /// Org vaults the member gets, each at its current key version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<VaultGrant>>,
    /// SA master keys, for admins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sa_master_keys: Option<Vec<SaMasterGrant>>,
}

/// `Invitation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    /// Invitation id.
    pub id: String,
    /// Invitee email.
    pub email: String,
    /// Role on acceptance.
    pub role: OrgRole,
    /// Expiry.
    pub expires_at: String,
    /// Who invited.
    pub invited_by: Principal,
}

/// `GET /orgs/{org}/invitations` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationList {
    /// Invitations.
    pub invitations: Vec<Invitation>,
}

/// `POST /orgs/{org}/invitations` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRequest {
    /// Invitee email.
    pub email: String,
    /// Role.
    pub role: OrgRole,
}

/// `POST /invitations/accept` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInvitationRequest {
    /// The token from the email.
    pub token: String,
}

// ------------------------------------------------------------------------------------ vaults

/// `Vault`: a vault the caller can open, with the caller's sealed keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    /// Vault id.
    pub id: String,
    /// Org, for an org vault.
    #[serde(default)]
    pub org_id: Option<String>,
    /// Owner, for a personal vault.
    #[serde(default)]
    pub owner_id: Option<String>,
    /// Encrypted name (SPEC §7).
    pub encrypted_name: B64,
    /// The caller's role.
    pub role: VaultRole,
    /// Current key version.
    pub current_key_version: i64,
    /// Pending key version during a rotation.
    #[serde(default)]
    pub pending_key_version: Option<i64>,
    /// A member was removed without a rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_required: Option<bool>,
    /// The caller's sealed keys for the current and pending versions, newest first.
    pub keys: Vec<VaultKey>,
    /// Created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// One of `Vault.keys`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKey {
    /// Key version.
    pub key_version: i64,
    /// The vault key sealed to the caller.
    pub sealed_key: B64,
}

/// `GET /vaults` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultList {
    /// Vaults.
    pub vaults: Vec<Vault>,
}

/// `POST /vaults` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    /// Client-generated UUIDv4.
    pub id: String,
    /// Org, or `None` for a personal vault.
    #[serde(default)]
    pub org_id: Option<String>,
    /// Encrypted name.
    pub encrypted_name: B64,
    /// At least the caller's own grant.
    pub grants: Vec<Grant>,
}

/// `PATCH /vaults/{vault}` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameVaultRequest {
    /// New encrypted name.
    pub encrypted_name: B64,
}

/// `POST /vaults/{vault}/owner` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferVaultRequest {
    /// The new owner.
    pub principal: Principal,
}

/// One of `GET /vaults/{vault}/access`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAccess {
    /// Principal.
    pub principal: Principal,
    /// Role.
    pub role: VaultRole,
    /// Key version they hold.
    pub key_version: i64,
    /// Email or SA name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// Who granted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<Principal>,
    /// When.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<String>,
}

/// `GET /vaults/{vault}/access` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAccessList {
    /// Access rows.
    pub access: Vec<VaultAccess>,
}

/// `POST /vaults/{vault}/access` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAccessRequest {
    /// Grants at the current key version.
    pub grants: Vec<Grant>,
}

/// `POST /vaults/{vault}/keys` body: start a rotation (SPEC §7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartRotationRequest {
    /// `current_key_version + 1`.
    pub key_version: i64,
    /// Every remaining member, including the caller.
    pub grants: Vec<Grant>,
    /// Principals to remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<Vec<Principal>>,
}

// ------------------------------------------------------------------------------------ service accounts

/// `ServiceAccount`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccount {
    /// SA id.
    pub id: String,
    /// Org.
    pub org_id: String,
    /// Name.
    pub name: String,
    /// Public keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<PublicKeys>,
    /// Keyset (owners/admins only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset: Option<WrappedKeyset>,
    /// The caller's sealed master key (owners/admins only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_key: Option<B64>,
    /// Creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Principal>,
    /// Created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Expiry.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

/// `GET /orgs/{org}/service-accounts` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountList {
    /// Service accounts.
    pub service_accounts: Vec<ServiceAccount>,
}

/// `NewSaSecret`: a new SA secret (the token is built client-side and shown once).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewSaSecret {
    /// Secret id.
    pub id: String,
    /// Name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Hex SHA-256 of the 32 raw secret bytes.
    pub secret_hash: String,
    /// 8-character prefix.
    pub prefix: String,
    /// The SA master key wrapped with the secret's KEK.
    pub wrapped_master: B64,
    /// Expiry, or `None` for never.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// `POST /orgs/{org}/service-accounts` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateServiceAccountRequest {
    /// Client-generated id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Expiry, or `None` for never.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// SA keyset wrapped with the SA master key.
    pub keyset: WrappedKeyset,
    /// The master key sealed to every owner and admin.
    pub master_keys: Vec<SaMasterGrant>,
    /// The first secret.
    pub secret: NewSaSecret,
}

/// `PATCH /service-accounts/{sa}` body. `expires_at`: `None` leaves it, `Some(None)` clears it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateServiceAccountRequest {
    /// New name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New expiry (`Some(None)`: never).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "double_option")]
    pub expires_at: Option<Option<String>>,
    /// Disable or enable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

/// `SaSecret`: an SA secret as listed (never the secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaSecret {
    /// Secret id.
    pub id: String,
    /// 8-character prefix.
    pub prefix: String,
    /// Name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Created.
    pub created_at: String,
    /// Last used.
    #[serde(default)]
    pub last_used_at: Option<String>,
    /// Expiry.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// `GET /service-accounts/{sa}/secrets` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaSecretList {
    /// Secrets.
    pub secrets: Vec<SaSecret>,
}

/// `PATCH /service-accounts/{sa}/secrets/{id}` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateSaSecretRequest {
    /// New expiry; `None` is never (sent as `null`).
    pub expires_at: Option<String>,
}

// ------------------------------------------------------------------------------------ audit, billing

/// One org audit event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event id.
    pub id: String,
    /// When.
    pub at: String,
    /// Who.
    pub actor: Principal,
    /// What, e.g. `vault.access.grant`.
    pub action: String,
    /// On what.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// From where.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Extra data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Map<String, serde_json::Value>>,
}

/// `GET /orgs/{org}/audit` response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditPage {
    /// Events, newest first.
    pub events: Vec<AuditEvent>,
    /// Cursor for `before`, or `None` at the end.
    #[serde(default)]
    pub next: Option<String>,
}

/// `GET /billing/apple/eligibility` response (SPEC §19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleEligibility {
    /// Whether the app may sell a plan.
    pub eligible: bool,
    /// Why not: `billed_by_stripe`, `billed_by_apple`, `not_owner`, `per_seat_plan`,
    /// `billing_off` (open set).
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /billing/apple/transactions` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleTransactionRequest {
    /// StoreKit 2 JWS.
    pub signed_transaction: String,
}

/// `POST /billing/apple/transactions` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleTransactionRecorded {
    /// `user:<uuid>` or `org:<uuid>`.
    pub subject: String,
    /// The subject's plan now.
    pub plan: Plan,
}

// ------------------------------------------------------------------------------------ share links (SPEC §22)

wire_enum! {
    /// State of a share link.
    ShareStatus { Pending => "pending", Active => "active", Ended => "ended", }
}
wire_enum! {
    /// Why a share link ended.
    ShareEndReason {
        Expired => "expired",
        Opened => "opened",
        Revoked => "revoked",
        Passcode => "passcode",
        AccessLost => "access_lost",
        Policy => "policy",
    }
}

/// `Share`: a share link as its owner sees it (never the ciphertext).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// Share id (22 base64url characters).
    pub id: String,
    /// Vault, or `None` for a text share.
    #[serde(default)]
    pub vault_id: Option<String>,
    /// Encrypted owner reference.
    #[serde(rename = "ref", default)]
    pub reference: Option<B64>,
    /// Has a passcode.
    pub passcode: bool,
    /// Open limit.
    #[serde(default)]
    pub max_opens: Option<i64>,
    /// Opens so far.
    pub opens: i64,
    /// When it was opened.
    pub opened_at: Vec<String>,
    /// Created.
    pub created_at: String,
    /// Expiry.
    pub expires_at: String,
    /// State.
    pub status: ShareStatus,
    /// When it ended.
    #[serde(default)]
    pub ended_at: Option<String>,
    /// Why it ended.
    #[serde(default)]
    pub end_reason: Option<ShareEndReason>,
}

/// `GET /shares` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareList {
    /// Shares, newest first.
    pub shares: Vec<Share>,
}

/// `POST /shares` body: reserve a share id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateShareRequest {
    /// Vault, or `None` for a text share.
    #[serde(default)]
    pub vault_id: Option<String>,
    /// Seconds (3600..=2592000).
    pub expires_in: i64,
    /// Open limit (1..=100), or `None`.
    #[serde(default)]
    pub max_opens: Option<i64>,
    /// The passcode's Argon2id parameters, or `None`.
    #[serde(default)]
    pub kdf: Option<Kdf>,
    /// HKDF of the passcode key (32 bytes); required with `kdf`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<B64>,
}

/// `PUT /shares/{id}` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadShareRequest {
    /// Ciphertext (at most 64 KiB decoded).
    pub ct: B64,
    /// Encrypted owner reference.
    #[serde(rename = "ref")]
    pub reference: B64,
}

/// `GET /public/shares/{id}` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicShareInfo {
    /// Expiry.
    pub expires_at: String,
    /// Opens left, or `None` for no limit.
    #[serde(default)]
    pub opens_left: Option<i64>,
    /// Passcode KDF, or `None` without a passcode.
    #[serde(default)]
    pub kdf: Option<Kdf>,
}

/// `POST /public/shares/{id}/open` body.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenShareRequest {
    /// Passcode auth, when the share has a passcode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<B64>,
}

/// `POST /public/shares/{id}/open` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedShare {
    /// Ciphertext.
    pub ct: B64,
    /// Opens left, or `None` for no limit.
    #[serde(default)]
    pub opens_left: Option<i64>,
}

// ------------------------------------------------------------------------------------ sync server

/// `BlobMeta` (sync server): one vault or legacy database blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMeta {
    /// Blob id.
    pub id: String,
    /// Quoted hex SHA-256 of the bytes.
    pub etag: String,
    /// Revision, from 1.
    pub revision: i64,
    /// Size in bytes.
    pub size: u64,
    /// Last update (camelCase, as the legacy DatabaseMeta JSON).
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

/// `GET {sync}/vaults` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobList {
    /// Vault blobs in the token's `vlt` claim that exist.
    pub vaults: Vec<BlobMeta>,
}

/// `GET {sync}/databases` response (legacy device-token routes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseList {
    /// Databases.
    pub databases: Vec<BlobMeta>,
}

/// `GET {sync}/vaults/{id}/history` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobHistory {
    /// Kept versions, newest first.
    pub versions: Vec<BlobMeta>,
}

/// `POST {sync}/devices/pairing` response (legacy).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingCode {
    /// `ABCD-EFGH`.
    pub code: String,
    /// Expiry.
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// `POST {sync}/devices/pairing/claim` body (legacy).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingClaimRequest {
    /// The code, trimmed.
    pub code: String,
    /// This device's name.
    #[serde(rename = "deviceName")]
    pub device_name: String,
}

/// `POST {sync}/devices/pairing/claim` response (legacy).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingClaim {
    /// User name on the self-hosted server.
    pub user: String,
    /// The new device's id.
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// The new device token.
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enums_keep_unknown_values() {
        let p: Platform = serde_json::from_value(json!("android")).unwrap();
        assert_eq!(p, Platform::Other("android".into()));
        assert_eq!(serde_json::to_value(&p).unwrap(), json!("android"));
        assert_eq!(serde_json::to_value(Platform::QtMacos).unwrap(), json!("qt-macos"));
        assert_eq!(ShareLinkPolicy::from("off"), ShareLinkPolicy::Off);
    }

    #[test]
    fn patch_fields_tell_absent_from_null() {
        let leave = UpdateServiceAccountRequest { name: Some("n".into()), ..Default::default() };
        assert_eq!(serde_json::to_value(&leave).unwrap(), json!({"name": "n"}));
        let clear = UpdateServiceAccountRequest { expires_at: Some(None), ..Default::default() };
        assert_eq!(serde_json::to_value(&clear).unwrap(), json!({"expires_at": null}));
        let back: UpdateServiceAccountRequest = serde_json::from_value(json!({"expires_at": null})).unwrap();
        assert_eq!(back, clear);
        let back: UpdateServiceAccountRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(back.expires_at, None);
    }

    #[test]
    fn login_finish_is_a_session_or_a_challenge() {
        let mfa: LoginFinishResponse =
            serde_json::from_value(json!({"mfa_required": true, "mfa_token": "m", "methods": ["totp"]})).unwrap();
        assert!(matches!(mfa, LoginFinishResponse::Mfa(ref c) if c.mfa_token == "m"));
        let kdf = json!({"alg": "argon2id", "salt": "AA", "m": 19456, "t": 2, "p": 1});
        let ks = json!({"enc_pk": "a", "sign_pk": "b", "sig": "c", "wrapped": "d"});
        let s: LoginFinishResponse = serde_json::from_value(json!({
            "access_token": "a", "refresh_token": "r", "expires_in": 600, "device_id": "d",
            "user": {"id": "u", "email": "e"}, "kdf": kdf, "keyset": ks
        }))
        .unwrap();
        assert!(matches!(s, LoginFinishResponse::Session(_)));
    }
}
