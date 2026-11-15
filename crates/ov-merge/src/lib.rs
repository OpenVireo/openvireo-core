//! Three-way KDBX merge on the `ov_kdbx::model` types: bytes in, bytes out at the facade, with
//! the same rules as the SDK's `merge/` (history, deletions and Recycle Bin, UUID matching,
//! timestamps).
//!
//! Filled in by W1-M.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
