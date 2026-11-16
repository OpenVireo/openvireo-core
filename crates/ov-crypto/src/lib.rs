//! OpenVireo account cryptography (SPEC §1-§7, §9, §18), ported from the TS SDK's
//! `packages/sdk/src/crypto/`.
//!
//! - [`primitives`]: HKDF, XChaCha20-Poly1305, Argon2, randomness (frozen, W0-B).
//! - [`curves`]: X25519 (with low-order point rejection) and Ed25519.
//! - [`encoding`]: base64url, hex, constant-time comparison.
//! - [`secret_key`]: the Secret Key and its `K1-…` form (§2).
//! - [`auk`]: KDF parameters, the `weak_kdf` floor and the Account Unlock Key (§3).
//! - [`envelope`]: `wrap`/`unwrap` (§4), `seal`/`unseal` (§6) and the [`envelope::aad`] strings.
//! - [`keyset`]: keysets, signed public keys, fingerprints, wrapped keysets (§5).
//! - [`vault_name`]: encrypted vault names (§4, §7).
//! - [`tokens`]: service-account and refresh tokens (§9).
//! - [`jwt`]: access-token decoding and EdDSA verification against a JWKS (§9).
//! - [`restore`]: the restore proof and reseal (§18).
//!
//! Every fallible function returns [`ov_error::OvError`] with the SDK's codes. Secret outputs come
//! back in [`zeroize::Zeroizing`] buffers.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auk;
pub mod curves;
pub mod encoding;
pub mod envelope;
pub mod keyset;
pub mod primitives;
pub mod secret_key;
pub mod vault_name;

pub use zeroize::Zeroizing;
