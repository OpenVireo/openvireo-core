//! The lite module of `@openvireo/core-wasm` (`@openvireo/core-wasm/lite`): the primitives, share
//! links and TOTP, without the facade, OPAQUE, KDBX or the account crypto. For pages that only open
//! share links (the public share page) or need a hash or an AEAD, so they don't load the whole core.
//!
//! There is no code of its own here: the modules are `bindings/ov-wasm`'s shared ones, compiled
//! again into this crate, so every export behaves exactly like the full module's export of the
//! same name. `cargo xtask wasm` builds both modules into one package.

#![warn(missing_docs)]

#[allow(dead_code, unused_imports, unused_macros)]
#[path = "../../ov-wasm/src/convert.rs"]
mod convert;
#[allow(dead_code)]
#[path = "../../ov-wasm/src/error.rs"]
pub mod error;
#[path = "../../ov-wasm/src/primitives.rs"]
pub mod primitives;
#[path = "../../ov-wasm/src/share.rs"]
pub mod share;
#[path = "../../ov-wasm/src/wipe.rs"]
pub mod wipe;

use wasm_bindgen::prelude::*;

/// The core's version (the workspace version, as the full module's `version()`).
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
