//! OpenVireo account cryptography (SPEC §1-§7, §9, §18).
//!
//! [`primitives`] is the frozen base (W0-B). Wave 1 (W1-C1) adds the Secret Key, AUK, wrap/seal
//! envelopes, keysets, vault names, tokens, JWT and restore-proof modules on top of it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod primitives;
