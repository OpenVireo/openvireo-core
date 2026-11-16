//! Share links (SPEC §22): padding, passcode and content keys, payload and reference
//! encryption, link format and parsing, payload builders and TOTP.
//!
//! A port of the TS SDK's `crypto/share.ts`, `share/index.ts` and `share/totp.ts`. Nothing here does
//! I/O: [`ShareOpen`] prepares the `POST …/open` body and decrypts the `ct` the caller fetched, and
//! the facade (`ov-core`) sends the requests.
//!
//! - [`crypto`]: the SPEC §22 key schedule and envelopes ([`encrypt_share_payload`],
//!   [`decrypt_share_payload`], [`encrypt_share_ref`], [`decrypt_share_ref`], …).
//! - [`link`]: `<base>/<id>#<K>` ([`share_link`], [`parse_share_link`], [`share_key_from_hash`]).
//! - [`payload`]: what a link holds and how an entry becomes one ([`shareable_fields`],
//!   [`item_share_payload`], [`text_share_payload`]).
//! - [`open`]: opening a link without an account, minus HTTP ([`ShareOpen`]).
//! - [`totp`]: RFC 6238 codes for `otpauth://totp/` URIs ([`parse_totp_uri`], [`totp_code`],
//!   [`entry_totp_uri`]).
//!
//! Keys come back in [`zeroize::Zeroizing`] buffers, and the records holding field values wipe them
//! when dropped. `Debug` never prints a key, passcode or field value.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod b64;
pub mod crypto;
pub mod link;
pub mod open;
pub mod payload;
pub mod totp;

pub use b64::{b64u, from_b64u};
pub use crypto::{
    check_kdf_params, decrypt_share_payload, decrypt_share_ref, encrypt_share_payload,
    encrypt_share_payload_with_nonce, encrypt_share_ref, encrypt_share_ref_with_nonce, new_share_key, pad_share,
    passcode_bytes, share_aad, share_auth, share_auth_hash, share_content_key, share_passcode_key, share_ref_aad,
    share_ref_key, unpad_share, KdfMin, KdfParams, KDF_MIN, SHARE_KEY_BYTES, SHARE_MAX_CT_BYTES, SHARE_PAD,
};
pub use link::{parse_share_link, share_key_from_hash, share_link, ShareLinkParts, SHARE_ID_CHARS, SHARE_KEY_CHARS};
pub use open::{open_share, ShareOpen};
pub use payload::{
    default_share_fields, item_share_payload, shareable_fields, text_share_payload, EntryField, ShareField,
    SharePayload, ShareRef, ShareableField, DEFAULT_SHARE_FIELDS,
};
pub use totp::{entry_totp_uri, parse_totp_uri, totp_code, TotpAlgorithm, TotpCode, TotpParams};
