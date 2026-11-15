//! The vault sync state machine (SPEC §11, §20): download, merge, conditional upload with
//! retries, deletions, rollback and lost-database detection, the offline cache and the clock-skew
//! check.
//!
//! Filled in by W2-Y.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
