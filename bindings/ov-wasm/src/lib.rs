//! wasm-bindgen binding of the ov-core facade: the `@openvireo/core-wasm` npm package.
//!
//! `cargo xtask wasm` builds it (wasm-bindgen `--target web`, then `wasm-opt -Oz`) into
//! `bindings/ov-wasm/pkg/`. Apps use the package's `index.js`, which loads the module, installs
//! the `OvError` class and the panic handling ([`error`]), and re-exports everything here.
//!
//! - [`handles`]: one class per facade handle (`OvClient`, `Account`, `Vault`, …) and the free
//!   functions, one export per facade method (rust-core-tasks.md §2.3).
//! - `records`: every facade record and enum as a plain JS value plus its TypeScript type.
//! - `host`: the JS `Host` object → [`ov_core::host::Host`].
//! - [`crypto`]: the frozen `ov-crypto` primitives.

#![warn(missing_docs)]

mod convert;
pub mod crypto;
pub mod error;
pub mod handles;
mod host;
mod records;

use wasm_bindgen::prelude::*;

/// The core's version (`ov-core` crate version).
#[wasm_bindgen]
pub fn version() -> String {
    ov_core::version().to_string()
}
