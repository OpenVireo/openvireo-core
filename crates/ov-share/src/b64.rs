//! base64url as SPEC §1 defines it: encoded without padding; decoders also accept padding. Like the
//! TS SDK's `fromB64u`, decoding ignores the unused low bits of the last character.

use base64::alphabet::URL_SAFE;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

const ENCODE: GeneralPurpose = GeneralPurpose::new(&URL_SAFE, GeneralPurposeConfig::new().with_encode_padding(false));

const DECODE: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// base64url without padding.
pub fn b64u(bytes: &[u8]) -> String {
    ENCODE.encode(bytes)
}

/// Decodes base64url, with or without padding. Fails with `code` on anything else.
pub(crate) fn decode(text: &str, code: OvErrorCode, what: &str) -> Result<Zeroizing<Vec<u8>>, OvError> {
    DECODE.decode(text).map(Zeroizing::new).map_err(|_| OvError::new(code, format!("{what} isn't base64url")))
}

/// Decodes base64url, with or without padding; `invalid_request` on anything else.
pub fn from_b64u(text: &str) -> Result<Zeroizing<Vec<u8>>, OvError> {
    decode(text, OvErrorCode::InvalidRequest, "the value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_padding_and_trailing_bits() {
        assert_eq!(b64u(&[0xfb, 0xff]), "-_8");
        assert_eq!(from_b64u("-_8").unwrap().as_slice(), &[0xfb, 0xff]);
        assert_eq!(from_b64u("-_8=").unwrap().as_slice(), &[0xfb, 0xff]);
        // "-_9" has a non-zero unused bit; fromB64u ignores it
        assert_eq!(from_b64u("-_9").unwrap().as_slice(), &[0xfb, 0xff]);
        assert!(from_b64u("a+b/").is_err());
        assert!(from_b64u("a").is_err());
    }
}
