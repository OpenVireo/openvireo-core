//! `ov`, the OpenVireo command-line client: the library behind the `ov` binary.
//!
//! A port of the TS CLI (`openvireo-sdk/packages/cli`): the command tree with the TS arguments,
//! help and exit codes ([`cli`], [`args`]), the platform Host for `ov-core` ([`host`]: reqwest, the
//! `session.json` store, a file cache), sign-in and the vault source on `ov-core` ([`session`],
//! [`source`]), and the pure CLI logic (templates, env files, masking, `ov run`, password
//! generation).
//!
//! The binary is `ov`, never `openvireo` (that name is the Linux desktop app).

// `unsafe` only in `tty` (libc termios and gethostname), which allows it explicitly.
#![deny(unsafe_code)]
#![warn(missing_docs)]

/// The CLI version as a literal, so [`cli::USAGE`] can be built with `concat!`: the openvireo-core
/// release (the workspace version), which `cargo xtask release verify` checks `ov version` against.
#[macro_export]
macro_rules! version {
    () => {
        env!("CARGO_PKG_VERSION")
    };
}

pub mod args;
pub mod cache;
pub mod cli;
pub mod connect;
pub mod generate;
pub mod host;
pub mod http;
pub mod item;
pub mod js;
pub mod mask;
pub mod plan;
pub mod reference;
pub mod run;
pub mod session;
pub mod source;
pub mod store;
pub mod template;
pub mod tty;
