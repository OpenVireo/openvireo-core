//! openvireo-core: the client side of the OpenVireo protocol (accounts, vaults, sharing, share
//! links, sync) in one Rust crate that every client calls: web and the extension through WASM,
//! iOS through Swift, the desktop through C++, and the `ov` CLI natively (rust-core.md).
//!
//! - [`api`]: the facade the bindings expose. Start at [`api::OvClient`].
//! - [`host`]: the traits each platform implements (HTTP, secure storage, offline cache, clock,
//!   logs). The core does no I/O of its own.
//!
//! Both modules are the frozen `contract-v1` (rust-core-tasks.md §2.2, §2.3).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// On wasm32 the Host and its trait objects are deliberately not Send/Sync (JS values can't cross
// threads, host.rs), and the client still shares state through Arc; there is only one thread.
#![cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]

pub mod api;
pub mod host;
mod impls;
mod state;

pub use ov_error::{OvError, OvErrorCode};

/// The core's version (the `ov-core` crate version), for the bindings' smoke tests and logs.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
