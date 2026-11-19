//! UniFFI Swift binding of the ov-core facade (rust-core-tasks.md §2.3, task W1-BS).
//!
//! `cargo xtask xcframework` builds this crate for iOS, the iOS simulator and macOS, generates the
//! Swift module `OpenVireoRustCore` and packs `OpenVireoCore.xcframework` (see `xtask/src/xcframework.rs`).
//!
//! - [`types`]: the facade's records and enums, exposed as they are (UniFFI remote types).
//! - [`types_ext`]: local mirrors of the records that hold handles, tuples or errors.
//! - [`handles`], [`account_ext`]: the handles as objects; every method goes through `guard`,
//!   so a panic becomes `OvError { code: internal }`.
//! - [`host`]: the Host traits as foreign traits Swift implements.
//! - [`error`]: `OvError` / `TransportError`.
//! - [`primitives`]: SHA-256, HKDF, XChaCha20-Poly1305, Argon2id, randomness.
//! - [`crypto`]: the rest of `ov-crypto` (Secret Key, AUK, envelopes, keysets, vault names,
//!   tokens, JWTs, restore proofs, curves, Argon2 of every variant), with explicit-nonce options.
//! - [`opaque`]: OPAQUE client steps and `opaque_ids`; the server steps with feature `test-server`.
//! - [`kdbx`]: a `.kdbx` header (version, KDF) read without the key.
//! - [`share_crypto`]: share-link keys, padding, envelopes and link format (SPEC §22).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

uniffi::setup_scaffolding!("ov_ffi_swift");

pub mod account_ext;
pub mod crypto;
pub mod error;
mod guard;
pub mod handles;
pub mod host;
pub mod kdbx;
pub mod opaque;
pub mod primitives;
pub mod share_crypto;
pub mod types;
pub mod types_ext;

pub use error::{OvError, OvErrorCode, TransportError};

/// The core's version (the `ov-core` crate version).
#[uniffi::export]
pub fn version() -> String {
    ov_core::version().to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_the_core_version() {
        assert_eq!(super::version(), ov_core::version());
    }
}
