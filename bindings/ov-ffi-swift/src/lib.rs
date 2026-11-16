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
//! - [`primitives`]: a few `ov-crypto` primitives, for smoke tests and Swift-side checks.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

uniffi::setup_scaffolding!("ov_ffi_swift");

pub mod account_ext;
pub mod error;
mod guard;
pub mod handles;
pub mod host;
pub mod primitives;
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
