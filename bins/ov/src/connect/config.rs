//! The `ov connect` environment (port of `configFromEnv` in `packages/connect/src/server.ts`):
//!
//! - `OPENVIREO_SERVICE_ACCOUNT_TOKEN` (or `OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE`)
//! - `OPENVIREO_CONNECT_TOKENS` (JSON) or `OPENVIREO_CONNECT_TOKENS_FILE`; and/or
//!   `OPENVIREO_CONNECT_TOKEN` (or `_FILE`: one plain token, read access to every vault, or write
//!   with `OPENVIREO_CONNECT_TOKEN_ACCESS=write`)
//! - `OPENVIREO_CONNECT_HOST` (127.0.0.1), `OPENVIREO_CONNECT_PORT` (8080, 0 = any free port),
//!   `OPENVIREO_CONNECT_CACHE_TTL` (seconds, 5)
//! - `OPENVIREO_CONNECT_TLS_CERT` and `OPENVIREO_CONNECT_TLS_KEY` (PEM files, both or neither) to
//!   serve HTTPS
//!
//! A variable wins over its `_FILE` form; `_FILE` contents are trimmed.

use std::time::Duration;

use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use super::tokens::{hash_token, parse_tokens, Access, ConnectToken};
use crate::session::Env;

/// The server's configuration.
pub struct Config {
    /// The service account token connect signs in with.
    pub sa_token: Zeroizing<String>,
    /// Its own bearer tokens.
    pub tokens: Vec<ConnectToken>,
    /// Address to listen on.
    pub host: String,
    /// Port (0: any free port).
    pub port: u16,
    /// How long a downloaded vault is used before a HEAD check.
    pub cache_ttl: Duration,
    /// PEM certificate chain and key files, to serve HTTPS.
    pub tls: Option<Tls>,
}

/// The PEM files for HTTPS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tls {
    /// Certificate chain.
    pub cert: String,
    /// Private key.
    pub key: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("tokens", &self.tokens.len())
            .field("host", &self.host)
            .field("port", &self.port)
            .field("cache_ttl", &self.cache_ttl)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

fn invalid(message: impl Into<String>) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, message)
}

fn set<'a>(env: &'a Env, name: &str) -> Option<&'a str> {
    env.get(name).map(String::as_str).filter(|v| !v.is_empty())
}

/// `readMaybe`: the variable, else the trimmed contents of the file `<name>_FILE` names.
fn read_maybe(env: &Env, name: &str) -> Result<Option<Zeroizing<String>>, OvError> {
    if let Some(v) = set(env, name) {
        return Ok(Some(Zeroizing::new(v.to_string())));
    }
    let Some(file) = set(env, &format!("{name}_FILE")) else { return Ok(None) };
    let bytes = Zeroizing::new(std::fs::read(file).map_err(|e| crate::js::io_error(&e, "open", file))?);
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    Ok(Some(Zeroizing::new(crate::js::trim(&text).to_string())))
}

impl Config {
    /// Reads and checks the configuration (`configFromEnv`).
    pub fn from_env(env: &Env) -> Result<Config, OvError> {
        let sa_token = read_maybe(env, "OPENVIREO_SERVICE_ACCOUNT_TOKEN")?
            .filter(|t| !t.is_empty())
            .ok_or_else(|| invalid("set OPENVIREO_SERVICE_ACCOUNT_TOKEN (or OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE)"))?;
        let mut tokens = Vec::new();
        if let Some(list) = read_maybe(env, "OPENVIREO_CONNECT_TOKENS")?.filter(|t| !t.is_empty()) {
            tokens.extend(parse_tokens(&list)?);
        }
        if let Some(single) = read_maybe(env, "OPENVIREO_CONNECT_TOKEN")?.filter(|t| !t.is_empty()) {
            let access = if env.get("OPENVIREO_CONNECT_TOKEN_ACCESS").map(String::as_str) == Some("write") {
                Access::Write
            } else {
                Access::Read
            };
            tokens.push(ConnectToken {
                name: "default".into(),
                sha256: hash_token(&single),
                vaults: vec!["*".into()],
                access,
            });
        }
        if tokens.is_empty() {
            return Err(invalid(
                "no connect tokens: set OPENVIREO_CONNECT_TOKENS_FILE or OPENVIREO_CONNECT_TOKEN (create one with `ov connect token`)",
            ));
        }
        let port_text = env.get("OPENVIREO_CONNECT_PORT");
        let port = match port_text {
            None => 8080,
            Some(t) => {
                match crate::js::number(t).filter(|n| crate::js::is_integer(*n) && (0.0..=65535.0).contains(n)) {
                    Some(n) => n as u16,
                    None => return Err(invalid(format!("bad OPENVIREO_CONNECT_PORT: {t}"))),
                }
            }
        };
        let cache_ttl = match env.get("OPENVIREO_CONNECT_CACHE_TTL") {
            None => Duration::from_secs(5),
            Some(t) => match crate::js::number(t).filter(|n| n.is_finite() && *n >= 0.0) {
                Some(n) => Duration::try_from_secs_f64(n).unwrap_or(Duration::MAX),
                None => return Err(invalid(format!("bad OPENVIREO_CONNECT_CACHE_TTL: {t}"))),
            },
        };
        let tls = match (set(env, "OPENVIREO_CONNECT_TLS_CERT"), set(env, "OPENVIREO_CONNECT_TLS_KEY")) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some(Tls { cert: cert.into(), key: key.into() }),
            _ => return Err(invalid("set both OPENVIREO_CONNECT_TLS_CERT and OPENVIREO_CONNECT_TLS_KEY")),
        };
        // TS passes an empty host to node, which then listens on every interface; here it means the
        // default, so an empty variable never exposes the server by accident.
        let host = set(env, "OPENVIREO_CONNECT_HOST").unwrap_or("127.0.0.1").to_string();
        Ok(Config { sa_token, tokens, host, port, cache_ttl, tls })
    }

    /// The URL host part: IPv6 addresses in brackets.
    pub fn url_host(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}
