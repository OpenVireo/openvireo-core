//! The `ov_core::host::Host` for the CLI: reqwest, the `session.json` store, a file cache, the
//! system clock and stderr logs.

use std::sync::Arc;

use ov_core::host::{Clock, Host, Level, LogSink};
use ov_error::OvError;

use crate::cache::FileCache;
use crate::http::ReqwestTransport;
use crate::session::{config_dir, store_for, Env};

/// Wall-clock time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> i64 {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
    }
}

/// Core log lines on stderr, at or above a level. The TS CLI printed none, so the default is off;
/// `OPENVIREO_LOG=error|warn|info|debug|trace` turns them on.
#[derive(Clone, Copy, Debug)]
pub struct StderrLog {
    max: Option<Level>,
}

impl StderrLog {
    /// The level from `OPENVIREO_LOG` (off when unset or unknown).
    pub fn from_env(env: &Env) -> Self {
        let max = match env.get("OPENVIREO_LOG").map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("error") => Some(Level::Error),
            Some("warn") => Some(Level::Warn),
            Some("info") => Some(Level::Info),
            Some("debug") => Some(Level::Debug),
            Some("trace") => Some(Level::Trace),
            _ => None,
        };
        StderrLog { max }
    }
}

impl LogSink for StderrLog {
    fn log(&self, level: Level, target: &str, msg: &str) {
        if self.max.is_some_and(|max| level <= max) {
            eprintln!("ov [{level:?} {target}] {msg}");
        }
    }
}

/// The CLI's Host for this environment (config dir from [`config_dir`]).
pub fn cli_host(env: &Env) -> Result<Host, OvError> {
    let http = ReqwestTransport::new().map_err(OvError::from)?;
    Ok(Host {
        http: Arc::new(http),
        store: Arc::new(store_for(env)),
        cache: Arc::new(FileCache::new(config_dir(env).join("cache"))),
        clock: Arc::new(SystemClock),
        log: Arc::new(StderrLog::from_env(env)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_host() {
        let env: Env = [("OPENVIREO_CONFIG_DIR".to_string(), "/nonexistent".to_string())].into_iter().collect();
        let host = cli_host(&env).unwrap();
        assert!(host.clock.now_unix_ms() > 1_700_000_000_000);
        let log = StderrLog::from_env(&[("OPENVIREO_LOG".to_string(), "Info".to_string())].into_iter().collect());
        assert_eq!(log.max, Some(Level::Info));
        assert_eq!(StderrLog::from_env(&Env::new()).max, None);
    }
}
