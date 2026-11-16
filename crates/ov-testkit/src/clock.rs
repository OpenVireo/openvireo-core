//! Deterministic clocks for tests.
//!
//! Both implement [`ov_host::Clock`], so a test can pass `Arc::new(FixedClock::…)` as
//! `Host::clock`. They also keep an inherent `now_unix_ms` for tests that don't import the trait.

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

impl ov_host::Clock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        FixedClock::now_unix_ms(self)
    }
}

impl ov_host::Clock for ManualClock {
    fn now_unix_ms(&self) -> i64 {
        ManualClock::now_unix_ms(self)
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

    #[test]
    fn implements_host_clock() {
        use std::sync::Arc;
        let clock: Arc<dyn ov_host::Clock> = Arc::new(ManualClock::new(5));
        assert_eq!(clock.now_unix_ms(), 5);
        let fixed: Arc<dyn ov_host::Clock> = Arc::new(FixedClock::at_utc("2026-01-01T00:00:00Z"));
        assert_eq!(fixed.now_unix_ms(), 1_767_225_600_000);
    }
}
