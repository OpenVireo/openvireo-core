//! `ov`, the OpenVireo command-line client: the library behind the `ov` binary.
//!
//! A port of the TS CLI (`openvireo-sdk/packages/cli`). W1-L built the skeleton: the command tree
//! with the TS arguments, help and exit codes ([`cli`], [`args`]), the platform Host for `ov-core`
//! ([`host`]: reqwest, the `session.json` store, a file cache), and the pure CLI logic (templates,
//! env files, masking, `ov run`, password generation). W3-L3 wires the commands to `ov-core`.
//!
//! The binary is `ov`, never `openvireo` (that name is the Linux desktop app).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The CLI version as a literal, so [`cli::USAGE`] can be built with `concat!`. It follows the TS
/// CLI (`VERSION` in session.ts) until the TS CLI is retired.
#[macro_export]
macro_rules! version {
    () => {
        "0.11.0"
    };
}

pub mod js;
pub mod mask;
pub mod reference;
pub mod run;
pub mod source;
pub mod template;
