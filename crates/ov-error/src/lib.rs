//! `OvError`, the one error type every openvireo-core API returns.
//!
//! [`OvErrorCode`] lists the TypeScript SDK's `OpenVireoErrorCode` values one for one
//! (`packages/sdk/src/errors.ts`), plus the codes the SDK throws without listing them and
//! [`OvErrorCode::Internal`] for a panic caught at a binding edge. Every code has a stable wire
//! string (`"plan_limit"`) that bindings expose, so UI code written against the TS SDK keeps
//! matching on the same strings.
//!
//! Server errors use the `{error, code}` body of `openapi.yaml`. A server code that isn't one of
//! these variants keeps its exact string in [`OvError::server_code`], and the variant comes from
//! the HTTP status (the SDK's `codeForStatus`), so [`OvError::wire_code`] still returns what the
//! server sent.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::str::FromStr;

macro_rules! codes {
    ($( $(#[$doc:meta])* $variant:ident => $wire:literal, )+) => {
        /// A machine-readable error code. [`OvErrorCode::as_str`] is the stable wire string.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum OvErrorCode {
            $( $(#[$doc])* $variant, )+
        }

        impl OvErrorCode {
            /// Every code, in declaration order.
            pub const ALL: &'static [OvErrorCode] = &[ $( OvErrorCode::$variant, )+ ];

            /// The stable wire string, e.g. `"plan_limit"`.
            pub const fn as_str(self) -> &'static str {
                match self { $( OvErrorCode::$variant => $wire, )+ }
            }

            /// The code for a wire string, or `None` if it isn't one of these codes.
            pub fn from_wire(s: &str) -> Option<Self> {
                match s { $( $wire => Some(OvErrorCode::$variant), )+ _ => None }
            }
        }
    };
}

codes! {
    // ---- crypto
    /// A versioned format (wrap, seal, token, sealed keyset) has a version this build doesn't know.
    UnsupportedVersion => "unsupported_version",
    /// AEAD authentication failed: wrong key, or the data was changed (SPEC §4, §6).
    DecryptionFailed => "decryption_failed",
    /// The Secret Key is malformed, or doesn't open the keyset (SPEC §2).
    InvalidSecretKey => "invalid_secret_key",
    /// A public-key signature doesn't verify, or keys don't match the account (SPEC §5).
    InvalidPublicKeys => "invalid_public_keys",
    /// A token (JWT, refresh, service-account, invitation) is malformed or invalid (SPEC §9).
    InvalidToken => "invalid_token",
    /// KDF parameters below the minimum or of an unsupported algorithm (SPEC §3).
    WeakKdf => "weak_kdf",
    /// An X25519 public key of low order was rejected (SPEC §6).
    LowOrderPoint => "low_order_point",
    // ---- OPAQUE
    /// An OPAQUE step failed (SPEC §8).
    OpaqueFailed => "opaque_failed",
    // ---- HTTP (server codes from openapi.yaml, plus client-side ones)
    /// 400, or a request the client refuses to build.
    InvalidRequest => "invalid_request",
    /// 401: wrong credentials, or the session is no longer valid.
    Unauthorized => "unauthorized",
    /// 403.
    Forbidden => "forbidden",
    /// 404.
    NotFound => "not_found",
    /// 409.
    Conflict => "conflict",
    /// 429; see [`OvError::retry_after`].
    RateLimited => "rate_limited",
    /// The account has two-step sign-in and no code was given (SPEC §8).
    MfaRequired => "mfa_required",
    /// A wrong TOTP code; the MFA token stays valid for another try (SPEC §8).
    InvalidMfa => "invalid_mfa",
    /// The MFA token is gone (expired, or too many wrong codes): sign in again (SPEC §8).
    MfaExpired => "mfa_expired",
    /// The refresh token or the sign-in session expired (SPEC §9).
    SessionExpired => "session_expired",
    /// A refresh token was presented twice; the whole session is revoked (SPEC §9).
    TokenReused => "token_reused",
    /// 412: the `If-Match` ETag no longer matches (SPEC §13).
    PreconditionFailed => "precondition_failed",
    /// 428: a vault PUT without `If-Match` / `If-None-Match` (SPEC §13).
    PreconditionRequired => "precondition_required",
    /// 410.
    Gone => "gone",
    /// 5xx.
    ServerError => "server_error",
    /// The server couldn't be reached (no network, DNS, refused, TLS, timeout).
    NetworkError => "network_error",
    /// A plain `http://` URL that isn't loopback (SPEC §1 "Transport").
    InsecureUrl => "insecure_url",
    /// No session, or the account is locked.
    SignedOut => "signed_out",
    // ---- account recovery (SPEC §18)
    /// The reset link doesn't work yet; `details` has `notBefore`.
    RecoveryNotReady => "recovery_not_ready",
    /// The reset was cancelled.
    RecoveryCancelled => "recovery_cancelled",
    /// Too many failed restore attempts; an admin unlocks it.
    RestoreLocked => "restore_locked",
    /// The restore proof didn't verify.
    InvalidProof => "invalid_proof",
    // ---- plans (SPEC §19)
    /// A plan limit was reached; `details` has `limit`, `max`, `current`, `plan`, `upgradeUrl`.
    PlanLimit => "plan_limit",
    /// The vault is over its size limit; `details` has `max` (bytes).
    QuotaExceeded => "quota_exceeded",
    // ---- In-App Purchase (SPEC §19)
    /// The plan is billed through Stripe, so the App Store can't change it.
    BilledByStripe => "billed_by_stripe",
    /// The Apple subscription belongs to another account.
    AppleSubscriptionBound => "apple_subscription_bound",
    /// Apple's signed transaction didn't verify.
    AppleVerificationFailed => "apple_verification_failed",
    // ---- vault / sync
    /// The vault key doesn't open the vault's KDBX.
    VaultKeyMismatch => "vault_key_mismatch",
    /// This account holds no key (or not the current key) for the vault.
    NoVaultKey => "no_vault_key",
    /// A KDBX file couldn't be read or written.
    KdbxError => "kdbx_error",
    /// The merge failed.
    MergeFailed => "merge_failed",
    /// The server's copy is older than one this device already saw (SPEC §20).
    ServerRolledBack => "server_rolled_back",
    /// The server no longer has a vault this device synced before.
    ServerLostDatabase => "server_lost_database",
    /// Conditional uploads kept losing the race (412) and the sync gave up.
    TooManyConflicts => "too_many_conflicts",
    /// A malformed `ov://` reference (SPEC §14).
    InvalidReference => "invalid_reference",
    /// No entry (or more than one) matches a reference.
    EntryNotFound => "entry_not_found",
    /// The vault was never synced on this device, so it can't be opened offline (SPEC §20).
    NotAvailableOffline => "not_available_offline",
    /// The vault was created but its first upload failed; syncing it retries.
    VaultUploadFailed => "vault_upload_failed",
    /// The call was cancelled through its `CancelToken`.
    Aborted => "aborted",
    // ---- thrown by the TS SDK but missing from its `OpenVireoErrorCode` union
    /// A share link that can't be parsed (SPEC §22).
    InvalidLink => "invalid_link",
    /// A wrong share-link passcode; `details` has `attemptsLeft` (SPEC §22).
    InvalidPasscode => "invalid_passcode",
    /// The share link needs a passcode and none was given (SPEC §22).
    PasscodeRequired => "passcode_required",
    /// An `otpauth://` URI or TOTP secret that can't be used.
    InvalidTotp => "invalid_totp",
    /// A stored KDBX password hash of the wrong shape.
    InvalidPasswordHash => "invalid_password_hash",
    /// Data over a size limit (e.g. a share payload over 64 KiB).
    TooLarge => "too_large",
    /// The server or this build doesn't support the operation (e.g. no share page).
    Unsupported => "unsupported",
    // ---- core only
    /// A bug: a panic caught at a binding edge, or a broken invariant.
    Internal => "internal",
}

impl OvErrorCode {
    /// The code the TS SDK uses for an HTTP status when the body names no known code
    /// (`codeForStatus` in `http/request.ts`).
    pub const fn for_status(status: u16) -> Self {
        match status {
            400 => OvErrorCode::InvalidRequest,
            401 => OvErrorCode::Unauthorized,
            402 => OvErrorCode::PlanLimit,
            403 => OvErrorCode::Forbidden,
            404 => OvErrorCode::NotFound,
            409 => OvErrorCode::Conflict,
            410 => OvErrorCode::Gone,
            412 => OvErrorCode::PreconditionFailed,
            428 => OvErrorCode::PreconditionRequired,
            429 => OvErrorCode::RateLimited,
            s if s >= 500 => OvErrorCode::ServerError,
            _ => OvErrorCode::InvalidRequest,
        }
    }
}

impl fmt::Display for OvErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The wire string isn't one of the [`OvErrorCode`] values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownCode(pub String);

impl fmt::Display for UnknownCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown error code `{}`", self.0)
    }
}

impl std::error::Error for UnknownCode {}

impl FromStr for OvErrorCode {
    type Err = UnknownCode;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OvErrorCode::from_wire(s).ok_or_else(|| UnknownCode(s.to_string()))
    }
}

/// An error from openvireo-core. Every fallible API returns `Result<T, OvError>`.
///
/// `message` is for people and may change; match on [`OvError::code`] or [`OvError::wire_code`].
/// Messages never contain secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OvError {
    /// What went wrong.
    pub code: OvErrorCode,
    /// A human-readable description (English, not localised).
    pub message: String,
    /// The HTTP status, when the error came from a server response.
    pub status: Option<u16>,
    /// Seconds to wait, from a `Retry-After` header (429, 503).
    pub retry_after: Option<u32>,
    /// Extra data some codes carry, as a JSON object with camelCase keys, matching the TS SDK's
    /// `OpenVireoError.details`: `recovery_not_ready` → `notBefore`; `plan_limit` → `limit`, `max`,
    /// `current`, `plan`, `upgradeUrl`; `quota_exceeded` → `max`; `invalid_passcode` →
    /// `attemptsLeft`; a 409 `deletion_blocked` → `orgs`.
    pub details: Option<String>,
    /// The server's `code` when it isn't one of the [`OvErrorCode`] wire strings (for example
    /// `deletion_blocked` or `confirm_mismatch`). `code` then comes from the HTTP status.
    pub server_code: Option<String>,
}

impl OvError {
    /// An error with a code and message and nothing else.
    pub fn new(code: OvErrorCode, message: impl Into<String>) -> Self {
        OvError { code, message: message.into(), status: None, retry_after: None, details: None, server_code: None }
    }

    /// An [`OvErrorCode::Internal`] error.
    pub fn internal(message: impl Into<String>) -> Self {
        OvError::new(OvErrorCode::Internal, message)
    }

    /// An error built from a server's `{error, code}` body: a known `code` is used as is; an
    /// unknown one is kept in `server_code` and the variant comes from the status.
    pub fn from_server(status: u16, code: Option<&str>, message: impl Into<String>) -> Self {
        let (variant, server_code) = match code {
            Some(c) => match OvErrorCode::from_wire(c) {
                Some(v) => (v, None),
                None => (OvErrorCode::for_status(status), Some(c.to_string())),
            },
            None => (OvErrorCode::for_status(status), None),
        };
        OvError { server_code, ..OvError::new(variant, message).with_status(status) }
    }

    /// Sets the HTTP status.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets `Retry-After` seconds.
    pub fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    /// Sets the details JSON object.
    pub fn with_details(mut self, details_json: impl Into<String>) -> Self {
        self.details = Some(details_json.into());
        self
    }

    /// The code as a string, as the TS SDK's `err.code` would hold it: the server's own code when
    /// it isn't a known variant, else [`OvErrorCode::as_str`].
    pub fn wire_code(&self) -> &str {
        self.server_code.as_deref().unwrap_or(self.code.as_str())
    }

    /// Whether this error (or a given code) matches `code`, like the SDK's `isOpenVireoError(e, code)`.
    pub fn is(&self, code: OvErrorCode) -> bool {
        self.code == code
    }

    /// Whether the server couldn't be reached (no network, or a gateway answering 502/503/504), as
    /// opposed to refusing the request. The SDK's `isUnreachable`; offline fallbacks (SPEC §20) use it.
    pub fn is_unreachable(&self) -> bool {
        self.code == OvErrorCode::NetworkError || matches!(self.status, Some(502..=504))
    }
}

impl fmt::Display for OvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.wire_code(), self.message)
    }
}

impl std::error::Error for OvError {}

impl From<OvErrorCode> for OvError {
    fn from(code: OvErrorCode) -> Self {
        OvError::new(code, code.as_str())
    }
}

/// `Result<T, OvError>`.
pub type OvResult<T> = Result<T, OvError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The §2.4 list from rust-core-tasks.md, in order: the TS SDK's codes.
    const TS_CODES: &str =
        "unsupported_version decryption_failed invalid_secret_key invalid_public_keys invalid_token \
        weak_kdf low_order_point opaque_failed invalid_request unauthorized forbidden not_found conflict rate_limited \
        mfa_required invalid_mfa mfa_expired session_expired token_reused precondition_failed precondition_required \
        gone server_error network_error insecure_url signed_out recovery_not_ready recovery_cancelled restore_locked \
        invalid_proof plan_limit quota_exceeded billed_by_stripe apple_subscription_bound apple_verification_failed \
        vault_key_mismatch no_vault_key kdbx_error merge_failed server_rolled_back server_lost_database \
        too_many_conflicts invalid_reference entry_not_found not_available_offline vault_upload_failed aborted";

    #[test]
    fn every_ts_code_has_a_variant_in_order() {
        let ts: Vec<&str> = TS_CODES.split_whitespace().collect();
        let ours: Vec<&str> = OvErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(&ours[..ts.len()], &ts[..]);
        assert_eq!(ours.last(), Some(&"internal"));
    }

    #[test]
    fn wire_strings_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for &c in OvErrorCode::ALL {
            assert!(seen.insert(c.as_str()), "duplicate {c}");
            assert_eq!(c.as_str().parse::<OvErrorCode>(), Ok(c));
        }
        assert!("nope".parse::<OvErrorCode>().is_err());
    }

    #[test]
    fn server_errors_keep_unknown_codes() {
        let e = OvError::from_server(409, Some("deletion_blocked"), "hand over the orgs first");
        assert_eq!(e.code, OvErrorCode::Conflict);
        assert_eq!(e.wire_code(), "deletion_blocked");
        let e = OvError::from_server(402, Some("plan_limit"), "limit");
        assert_eq!((e.code, e.server_code, e.status), (OvErrorCode::PlanLimit, None, Some(402)));
        assert_eq!(OvError::from_server(503, None, "x").code, OvErrorCode::ServerError);
        assert!(OvError::from_server(503, None, "x").is_unreachable());
        assert_eq!(OvErrorCode::for_status(418), OvErrorCode::InvalidRequest);
    }
}
