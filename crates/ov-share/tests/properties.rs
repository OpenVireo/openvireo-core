//! Property tests: `parse_share_link` (and the other parsers of untrusted text) never panic, and
//! links, padding and payloads round-trip.

use ov_error::OvErrorCode;
use ov_share::{
    decrypt_share_payload, encrypt_share_payload, pad_share, parse_share_link, parse_totp_uri, share_key_from_hash,
    share_link, text_share_payload, unpad_share,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    /// Arbitrary strings: an error, never a panic.
    #[test]
    fn parse_share_link_never_panics(s in any::<String>()) {
        if let Err(e) = parse_share_link(&s) {
            prop_assert_eq!(e.code, OvErrorCode::InvalidLink);
        }
        let _ = share_key_from_hash(&s);
        let _ = parse_totp_uri(&s);
    }

    /// Strings built to be near-misses of a real link (right shape, random bytes in between).
    #[test]
    fn parse_share_link_near_misses_never_panic(
        base in ".{0,40}",
        id in "[A-Za-z0-9_-]{20,24}|.{22}",
        slash in "/?",
        hash in "#?",
        key in "[A-Za-z0-9_-]{41,45}|.{43}",
        tail in "\\PC{0,3}",
    ) {
        let s = format!("{base}/{id}{slash}{hash}{key}{tail}");
        if let Ok(p) = parse_share_link(&s) {
            prop_assert_eq!(p.id.len(), 22);
        }
    }

    /// Any base without line terminators, any id and key: format then parse gives them back.
    #[test]
    fn link_round_trips(
        base in "[^\n\r\u{2028}\u{2029}]{0,60}",
        id in "[A-Za-z0-9_-]{22}",
        key in any::<[u8; 32]>(),
    ) {
        let link = share_link(&base, &id, &key);
        let parts = parse_share_link(&link).unwrap();
        // share_link strips trailing slashes; JS trim() strips surrounding white space
        let want = base.trim_end_matches('/').trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
        prop_assert_eq!(parts.base.as_str(), want);
        prop_assert_eq!(parts.id, id);
        prop_assert_eq!(*parts.key, key);
    }

    #[test]
    fn padding_round_trips(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let padded = pad_share(&data);
        prop_assert_eq!(padded.len() % 512, 0);
        prop_assert!(padded.len() > data.len());
        prop_assert_eq!(unpad_share(&padded).unwrap(), &data[..]);
    }

    #[test]
    fn unpad_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1100)) {
        let _ = unpad_share(&data);
    }

    #[test]
    fn payload_round_trips(text in any::<String>(), title in proptest::option::of(any::<String>()), key in any::<[u8; 32]>()) {
        let p = text_share_payload(&text, title.as_deref(), Some("Sam"));
        let ct = encrypt_share_payload(&key, "AAAAAAAAAAAAAAAAAAAAAA", &p, None).unwrap();
        prop_assert_eq!(decrypt_share_payload(&key, "AAAAAAAAAAAAAAAAAAAAAA", &ct, None).unwrap(), p);
    }

    #[test]
    fn decrypt_never_panics(ct in proptest::collection::vec(any::<u8>(), 0..200), key in any::<[u8; 32]>()) {
        prop_assert!(decrypt_share_payload(&key, "AAAAAAAAAAAAAAAAAAAAAA", &ct, None).is_err());
    }
}
