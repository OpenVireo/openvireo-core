//! TOTP codes for entries (RFC 6238), as the SDK's `share/totp.ts` and the iOS `KDBX/TOTP.swift`
//! compute them from KeePassXC's `otp` field or the legacy `TOTP Seed` / `TOTP Settings` fields.

use ov_error::OvError;

use super::{FieldRecord, SecretBytes};

/// The TOTP hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (default).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// Parameters of an `otpauth://totp/…` URI.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpParams {
    /// The decoded secret.
    pub secret: SecretBytes,
    /// Digits (6-8; Steam's 5-character codes use `encoder`).
    pub digits: u32,
    /// Period in seconds (default 30).
    pub period: u32,
    /// The hash.
    pub algorithm: TotpAlgorithm,
    /// `steam` for Steam Guard codes.
    pub encoder: Option<String>,
}

impl std::fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpParams")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// A current TOTP code.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpCode {
    /// The code.
    pub code: SecretBytes,
    /// Seconds until it changes.
    pub remaining: u32,
}

impl std::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpCode").field("remaining", &self.remaining).finish()
    }
}

/// Parses an `otpauth://totp/…` URI; `invalid_totp` if it can't be used.
pub fn parse_totp_uri(uri: SecretBytes) -> Result<TotpParams, OvError> {
    let uri = crate::impls::util::secret_text(uri, "TOTP URI")?;
    let p = ov_share::parse_totp_uri(&uri)?;
    Ok(TotpParams {
        secret: p.secret.clone(),
        digits: p.digits,
        period: p.period,
        algorithm: match p.algorithm {
            ov_share::TotpAlgorithm::Sha1 => TotpAlgorithm::Sha1,
            ov_share::TotpAlgorithm::Sha256 => TotpAlgorithm::Sha256,
            ov_share::TotpAlgorithm::Sha512 => TotpAlgorithm::Sha512,
        },
        encoder: p.steam.then(|| "steam".to_owned()),
    })
}

/// The code at `now_ms` (Unix milliseconds).
pub fn totp_code(params: TotpParams, now_ms: i64) -> TotpCode {
    let p = ov_share::TotpParams {
        secret: params.secret.clone(),
        algorithm: match params.algorithm {
            TotpAlgorithm::Sha1 => ov_share::TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256 => ov_share::TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512 => ov_share::TotpAlgorithm::Sha512,
        },
        digits: params.digits,
        period: params.period,
        steam: params.encoder.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("steam")),
    };
    let c = ov_share::totp_code(&p, now_ms);
    TotpCode { code: c.code.as_bytes().to_vec(), remaining: c.remaining }
}

/// An entry's TOTP as an `otpauth://` URI, from its `otp` field or the legacy KeePassXC fields;
/// `None` if it has none. `label` names the issuer in a built URI.
pub fn entry_totp_uri(fields: Vec<FieldRecord>, label: String) -> Option<SecretBytes> {
    let fields = crate::impls::share::entry_fields(&fields);
    ov_share::entry_totp_uri(&fields, &label).map(|u| u.as_bytes().to_vec())
}
