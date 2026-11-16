//! `OvError` and `TransportError` as UniFFI errors.
//!
//! `ov_error::OvErrorCode` is `#[non_exhaustive]`, so it can't be a UniFFI remote enum; this crate
//! mirrors it variant for variant (a test checks the two lists match). `OvError` is a struct in
//! the core, and UniFFI errors are enums, so it crosses as a single-variant enum whose fields are
//! the core's fields plus `wire_code`, the stable string UI code matches on (rust-core-tasks.md
//! §2.4). Host implementations throw the same type back into the core.

use ov_core::host as core_host;

macro_rules! codes {
    ($( $variant:ident, )+) => {
        /// The error code: `ov_error::OvErrorCode` one for one (wire strings via
        /// [`error_code_wire`](crate::error_code_wire)).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
        pub enum OvErrorCode {
            $(
                #[allow(missing_docs)]
                $variant,
            )+
        }

        impl From<ov_error::OvErrorCode> for OvErrorCode {
            fn from(c: ov_error::OvErrorCode) -> Self {
                match c {
                    $( ov_error::OvErrorCode::$variant => OvErrorCode::$variant, )+
                    // A code added to the core after this binding was built.
                    _ => OvErrorCode::Internal,
                }
            }
        }

        impl From<OvErrorCode> for ov_error::OvErrorCode {
            fn from(c: OvErrorCode) -> Self {
                match c {
                    $( OvErrorCode::$variant => ov_error::OvErrorCode::$variant, )+
                }
            }
        }
    };
}

codes! {
    UnsupportedVersion, DecryptionFailed, InvalidSecretKey, InvalidPublicKeys, InvalidToken, WeakKdf,
    LowOrderPoint, OpaqueFailed, InvalidRequest, Unauthorized, Forbidden, NotFound, Conflict, RateLimited,
    MfaRequired, InvalidMfa, MfaExpired, SessionExpired, TokenReused, PreconditionFailed,
    PreconditionRequired, Gone, ServerError, NetworkError, InsecureUrl, SignedOut, RecoveryNotReady,
    RecoveryCancelled, RestoreLocked, InvalidProof, PlanLimit, QuotaExceeded, BilledByStripe,
    AppleSubscriptionBound, AppleVerificationFailed, VaultKeyMismatch, NoVaultKey, KdbxError, MergeFailed,
    ServerRolledBack, ServerLostDatabase, TooManyConflicts, InvalidReference, EntryNotFound,
    NotAvailableOffline, VaultUploadFailed, Aborted, InvalidLink, InvalidPasscode, PasscodeRequired,
    InvalidTotp, InvalidPasswordHash, TooLarge, Unsupported, Internal,
}

/// Every error the core returns (`ov_error::OvError`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum OvError {
    /// The one variant; Swift reads the fields through the `OvError` extension in
    /// `Sources/OpenVireoRustCore/OvError+Fields.swift`.
    Failure {
        /// The typed code.
        code: OvErrorCode,
        /// What the TS SDK's `err.code` would hold: the server's own code when it isn't one of
        /// `OvErrorCode`, else the code's wire string. Ignored when a host throws the error.
        wire_code: String,
        /// Human-readable message (English, for logs).
        message: String,
        /// HTTP status, for server errors.
        status: Option<u16>,
        /// `Retry-After` seconds, for `rate_limited`.
        retry_after: Option<u32>,
        /// Extra details as a JSON object string (camelCase keys).
        details: Option<String>,
        /// The server's code when it isn't one of `OvErrorCode`.
        server_code: Option<String>,
    },
}

impl std::fmt::Display for OvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let OvError::Failure { wire_code, message, .. } = self;
        write!(f, "{wire_code}: {message}")
    }
}

impl std::error::Error for OvError {}

impl From<ov_error::OvError> for OvError {
    fn from(e: ov_error::OvError) -> Self {
        OvError::Failure {
            code: e.code.into(),
            wire_code: e.wire_code().to_string(),
            message: e.message,
            status: e.status,
            retry_after: e.retry_after,
            details: e.details,
            server_code: e.server_code,
        }
    }
}

impl From<OvError> for ov_error::OvError {
    fn from(e: OvError) -> Self {
        let OvError::Failure { code, message, status, retry_after, details, server_code, .. } = e;
        ov_error::OvError { code: code.into(), message, status, retry_after, details, server_code }
    }
}

impl OvError {
    /// An `internal` error (a caught panic, or a host that threw something unexpected).
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        ov_error::OvError::internal(message).into()
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for OvError {
    /// A host method threw an error that isn't an `OvError`.
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        OvError::internal(format!("host threw an unexpected error: {}", e.reason))
    }
}

/// Why a host HTTP request didn't produce a response (`ov_core::host::TransportError`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum TransportError {
    /// No network, DNS failure or connection refused.
    Offline,
    /// The request timed out.
    Timeout,
    /// TLS failed; the text is for logs.
    Tls {
        /// Detail for logs.
        message: String,
    },
    /// The platform cancelled the request.
    Cancelled,
    /// Anything else; the text is for logs.
    Other {
        /// Detail for logs.
        message: String,
    },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Offline => f.write_str("offline"),
            TransportError::Timeout => f.write_str("timeout"),
            TransportError::Tls { message } => write!(f, "TLS: {message}"),
            TransportError::Cancelled => f.write_str("cancelled"),
            TransportError::Other { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<TransportError> for core_host::TransportError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Offline => core_host::TransportError::Offline,
            TransportError::Timeout => core_host::TransportError::Timeout,
            TransportError::Tls { message } => core_host::TransportError::Tls(message),
            TransportError::Cancelled => core_host::TransportError::Cancelled,
            TransportError::Other { message } => core_host::TransportError::Other(message),
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for TransportError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        TransportError::Other { message: format!("host threw an unexpected error: {}", e.reason) }
    }
}

/// The wire string of `code`, e.g. `"plan_limit"`.
#[uniffi::export]
pub fn error_code_wire(code: OvErrorCode) -> String {
    ov_error::OvErrorCode::from(code).as_str().to_string()
}

/// The code for a wire string, or `nil` for an unknown one.
#[uniffi::export]
pub fn error_code_from_wire(wire: String) -> Option<OvErrorCode> {
    ov_error::OvErrorCode::from_wire(&wire).map(Into::into)
}

/// An `OvError` with `code` and `message`, for hosts to throw (the other fields empty).
#[uniffi::export]
pub fn make_ov_error(code: OvErrorCode, message: String) -> OvError {
    ov_error::OvError::new(code.into(), message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_core_code_round_trips() {
        for &c in ov_error::OvErrorCode::ALL {
            let ours = OvErrorCode::from(c);
            assert_eq!(ov_error::OvErrorCode::from(ours), c, "{c}");
            assert_eq!(error_code_wire(ours), c.as_str());
            assert_eq!(error_code_from_wire(c.as_str().into()), Some(ours));
        }
        assert_eq!(error_code_from_wire("nope".into()), None);
    }

    #[test]
    fn error_keeps_server_code_and_wire_code() {
        let core = ov_error::OvError::from_server(409, Some("deletion_pending"), "pending").with_retry_after(3);
        let ours = OvError::from(core.clone());
        let OvError::Failure { code, wire_code, server_code, .. } = &ours;
        assert_eq!(*code, OvErrorCode::Conflict);
        assert_eq!(wire_code, "deletion_pending");
        assert_eq!(server_code.as_deref(), Some("deletion_pending"));
        assert_eq!(ov_error::OvError::from(ours), core);
    }
}
