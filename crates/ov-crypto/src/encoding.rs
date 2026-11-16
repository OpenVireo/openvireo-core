//! SPEC §1 encodings: base64url without padding (decoders also accept padding and the standard
//! alphabet, as the TS SDK's `fromB64u` does), lowercase hex and constant-time comparison.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use ov_error::{OvError, OvErrorCode};
use subtle::ConstantTimeEq;

const ENCODE: GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const DECODE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// base64url without padding (SPEC §1).
pub fn b64u(bytes: &[u8]) -> String {
    ENCODE.encode(bytes)
}

/// Decodes base64url, with or without `=` padding. The standard alphabet's `+` and `/` are
/// accepted too, so values from other implementations decode.
///
/// Fails with [`OvErrorCode::InvalidRequest`] on any other character or an impossible length.
/// Callers that know what the value is map the error to their own code (for example
/// `invalid_token`).
pub fn from_b64u(s: &str) -> Result<Vec<u8>, OvError> {
    let trimmed = s.trim_end_matches('=');
    let decoded = if trimmed.contains(['+', '/']) {
        DECODE.decode(trimmed.replace('+', "-").replace('/', "_"))
    } else {
        DECODE.decode(trimmed)
    };
    decoded.map_err(|_| OvError::new(OvErrorCode::InvalidRequest, "invalid base64url"))
}

/// Decodes base64url into exactly `N` bytes, failing with `code` on bad input or the wrong length.
pub(crate) fn from_b64u_array<const N: usize>(s: &str, code: OvErrorCode, what: &str) -> Result<[u8; N], OvError> {
    let v = from_b64u(s).map_err(|_| OvError::new(code, format!("{what} is not valid base64url")))?;
    v.as_slice().try_into().map_err(|_| OvError::new(code, format!("{what} must be {N} bytes")))
}

/// Lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Constant-time comparison of two byte strings (SPEC §1). The length is not secret.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_padded_unpadded_and_standard() {
        assert_eq!(from_b64u("AQI").unwrap(), [1, 2]);
        assert_eq!(from_b64u("AQI=").unwrap(), [1, 2]);
        assert_eq!(b64u(&[0xfb, 0xff]), "-_8");
        assert_eq!(from_b64u("-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(from_b64u("+/8=").unwrap(), [0xfb, 0xff]);
        assert!(from_b64u("A").is_err());
        assert!(from_b64u("A*BC").is_err());
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
