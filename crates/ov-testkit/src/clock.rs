//! Deterministic clocks for tests.
//!
//! Both types have an inherent `now_unix_ms(&self) -> i64`, the same signature as
//! `ov_core::host::Clock::now_unix_ms`. ov-testkit doesn't depend on ov-core yet (the two were written in
//! parallel in Wave 0); the lead adds `impl ov_core::host::Clock for FixedClock` (and `ManualClock`) once
//! both are on develop.

use std::sync::atomic::{AtomicI64, Ordering};

/// A clock that always returns the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    ms: i64,
}

impl FixedClock {
    /// A clock stopped at `unix_ms` milliseconds since the Unix epoch.
    pub const fn new(unix_ms: i64) -> Self {
        Self { ms: unix_ms }
    }

    /// A clock stopped at `unix_seconds` seconds since the Unix epoch.
    pub const fn from_secs(unix_seconds: i64) -> Self {
        Self { ms: unix_seconds * 1000 }
    }

    /// A clock stopped at a `YYYY-MM-DDTHH:MM:SSZ` time (e.g. a merge fixture's `now`).
    pub fn at_utc(timestamp: &str) -> Self {
        Self::from_secs(crate::utc_seconds(timestamp))
    }

    /// Milliseconds since the Unix epoch.
    pub fn now_unix_ms(&self) -> i64 {
        self.ms
    }
}

/// A clock that tests can set and advance. Thread-safe, so it can be shared through an `Arc`.
#[derive(Debug, Default)]
pub struct ManualClock {
    ms: AtomicI64,
}

impl ManualClock {
    /// A clock starting at `unix_ms`.
    pub const fn new(unix_ms: i64) -> Self {
        Self { ms: AtomicI64::new(unix_ms) }
    }

    /// Sets the time.
    pub fn set(&self, unix_ms: i64) {
        self.ms.store(unix_ms, Ordering::SeqCst);
    }

    /// Moves the time by `delta_ms` (negative goes back) and returns the new time.
    pub fn advance(&self, delta_ms: i64) -> i64 {
        self.ms.fetch_add(delta_ms, Ordering::SeqCst) + delta_ms
    }

    /// Milliseconds since the Unix epoch.
    pub fn now_unix_ms(&self) -> i64 {
        self.ms.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed() {
        let c = FixedClock::from_secs(1_792_224_060);
        assert_eq!(c.now_unix_ms(), 1_792_224_060_000);
        assert_eq!(c.now_unix_ms(), c.now_unix_ms());
        assert_eq!(FixedClock::at_utc("1970-01-01T00:00:01Z"), FixedClock::new(1000));
    }

    #[test]
    fn manual() {
        let c = ManualClock::new(10);
        assert_eq!(c.advance(5), 15);
        assert_eq!(c.advance(-20), -5);
        c.set(42);
        assert_eq!(c.now_unix_ms(), 42);
    }
}
