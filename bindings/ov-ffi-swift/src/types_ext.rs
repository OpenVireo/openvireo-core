//! Local mirrors of the facade records that can't be UniFFI remote types, because they hold a
//! tuple list, a handle or an `OvError`. Each converts from (and, where the core takes it as
//! input, to) the `ov_core` type.

use std::sync::Arc;

use ov_core::{api as core, host as core_host};

use crate::error::OvError;
use crate::handles::{TotpChallenge, Vault};

/// One HTTP header.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpHeader {
    /// Header name.
    pub name: String,
    /// Header value (may be a bearer token: never log it).
    pub value: String,
}

/// A request for the platform to send (`ov_core::host::HttpRequest`).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpRequest {
    /// Method.
    pub method: core_host::Method,
    /// Absolute URL.
    pub url: String,
    /// Headers, in order.
    pub headers: Vec<HttpHeader>,
    /// Body bytes (`nil` for no body).
    pub body: Option<Vec<u8>>,
    /// Keep alive past page unload (web only).
    pub keepalive: bool,
}

/// A response the platform received (`ov_core::host::HttpResponse`).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Headers, in order.
    pub headers: Vec<HttpHeader>,
    /// Body bytes (empty for none).
    pub body: Vec<u8>,
}

fn headers_in(h: Vec<(String, String)>) -> Vec<HttpHeader> {
    h.into_iter().map(|(name, value)| HttpHeader { name, value }).collect()
}

fn headers_out(h: Vec<HttpHeader>) -> Vec<(String, String)> {
    h.into_iter().map(|x| (x.name, x.value)).collect()
}

impl From<core_host::HttpRequest> for HttpRequest {
    fn from(r: core_host::HttpRequest) -> Self {
        HttpRequest {
            method: r.method,
            url: r.url,
            headers: headers_in(r.headers),
            body: r.body,
            keepalive: r.keepalive,
        }
    }
}

impl From<HttpResponse> for core_host::HttpResponse {
    fn from(r: HttpResponse) -> Self {
        core_host::HttpResponse { status: r.status, headers: headers_out(r.headers), body: r.body }
    }
}

/// The result of `login` / `submitTotp` (`ov_core::api::LoginStep`).
#[derive(uniffi::Enum)]
pub enum LoginStep {
    /// Two-step verification is on: ask for a code and call `submitTotp`.
    NeedsTotp {
        /// Pass back to `submitTotp`.
        challenge: Arc<TotpChallenge>,
    },
    /// Signed in and unlocked.
    Unlocked {
        /// The unlock result.
        unlocked: core::Unlocked,
    },
}

impl From<core::LoginStep> for LoginStep {
    fn from(s: core::LoginStep) -> Self {
        match s {
            core::LoginStep::NeedsTotp(c) => LoginStep::NeedsTotp { challenge: Arc::new(TotpChallenge(c)) },
            core::LoginStep::Unlocked(unlocked) => LoginStep::Unlocked { unlocked },
        }
    }
}

/// The result of an import (`ov_core::api::ImportOutcome`).
#[derive(uniffi::Record)]
pub struct ImportOutcome {
    /// The vault the entries went into.
    pub vault: Arc<Vault>,
    /// Whether the result reached the server.
    pub uploaded: bool,
    /// Why the upload failed, when it did (the import itself still succeeded).
    pub upload_error: Option<OvError>,
    /// The merge report, for merge imports.
    pub report: Option<core::SyncReport>,
}

impl From<core::ImportOutcome> for ImportOutcome {
    fn from(o: core::ImportOutcome) -> Self {
        ImportOutcome {
            vault: Arc::new(Vault(o.vault)),
            uploaded: o.uploaded,
            upload_error: o.upload_error.map(Into::into),
            report: o.report,
        }
    }
}

/// Which vault keys were rotated (`ov_core::api::RotationReport`).
#[derive(Clone, uniffi::Record)]
pub struct RotationReport {
    /// Vaults rotated.
    pub rotated: Vec<String>,
    /// Vaults that failed, with why.
    pub failed: Vec<RotationFailure>,
}

/// One vault whose key rotation failed.
#[derive(Clone, uniffi::Record)]
pub struct RotationFailure {
    /// The vault.
    pub vault_id: String,
    /// Why.
    pub error: OvError,
}

impl From<core::RotationReport> for RotationReport {
    fn from(r: core::RotationReport) -> Self {
        RotationReport {
            rotated: r.rotated,
            failed: r
                .failed
                .into_iter()
                .map(|f| RotationFailure { vault_id: f.vault_id, error: f.error.into() })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_round_trip_keeps_header_order() {
        let req = core_host::HttpRequest {
            method: core_host::Method::Post,
            url: "https://example.test/x".into(),
            headers: vec![("a".into(), "1".into()), ("b".into(), "2".into())],
            body: Some(vec![1, 2]),
            keepalive: true,
        };
        let ffi = HttpRequest::from(req.clone());
        assert_eq!(ffi.headers[1].name, "b");
        let resp = core_host::HttpResponse::from(HttpResponse { status: 204, headers: ffi.headers, body: vec![] });
        assert_eq!(resp.headers, req.headers);
        assert_eq!(resp.header("B"), Some("2"));
    }
}
