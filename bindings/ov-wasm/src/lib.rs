//! wasm-bindgen binding of openvireo-core: the `@openvireo/core-wasm` npm package.
//!
//! `cargo xtask wasm` builds two modules from this source:
//!
//! - **full** (`ov_wasm`, this crate): the facade handles plus every low-level export below;
//! - **lite** (`ov_wasm_lite`, `bindings/ov-wasm-lite`): only the modules marked *shared*, for
//!   pages that need primitives, share links and TOTP without the whole core (the public share page).
//!
//! The shared modules are compiled into both crates (lite includes them with `#[path]`), so a lite
//! export behaves exactly like the full module's export of the same name. The package's loaders
//! (`index.js`, `sync.js`, `lite.js`, `lite-sync.js`) instantiate a module, install the `OvError` class
//! and the panic handling ([`error`]), and return the exports. See `bindings/ov-wasm/README.md`.
//!
//! - [`handles`]: one class per facade handle (`OvClient`, `Account`, `Vault`, …), one export per
//!   facade method (rust-core-tasks.md §2.3).
//! - `records`: every facade record and enum as a plain JS value plus its TypeScript type.
//! - `host`: the JS `Host` object → [`ov_core::host::Host`].
//! - [`primitives`] *(shared)*: SHA-256, HKDF, XChaCha20-Poly1305, Argon2, random bytes.
//! - [`curves`]: X25519 and Ed25519.
//! - [`share`] *(shared)*: share-link crypto, links, payloads, `ShareOpen`, TOTP.
//! - [`account_crypto`]: Secret Key, AUK, envelopes, keysets, vault names, tokens, JWT, restore.
//! - [`opaque`]: OPAQUE client and test-server steps.
//! - [`kdbx`]: the `Kdbx` handle and `kdbxMerge` (read/merge/write on bytes).
//! - [`wipe`] *(shared)*: the zero-on-free allocator and the stack scrub.

#![warn(missing_docs)]

pub mod account_crypto;
mod convert;
pub mod curves;
pub mod error;
pub mod handles;
mod host;
mod json;
pub mod kdbx;
pub mod opaque;
pub mod primitives;
mod records;
pub mod share;
pub mod wipe;

use wasm_bindgen::prelude::*;

/// The core's version (`ov-core` crate version).
#[wasm_bindgen]
pub fn version() -> String {
    ov_core::version().to_string()
}
