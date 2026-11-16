//! Credentials, ported from `packages/cli/src/session.ts`: `OPENVIREO_SERVICE_ACCOUNT_TOKEN` wins;
//! otherwise the user session saved by `ov login` (refresh token, device id and trusted Secret Key
//! in `<config dir>/session.json`, mode 0600), unlocked with the master password
//! (`OPENVIREO_PASSWORD` or a prompt) for each command.
//!
//! Everything that needs `ov-core` (signing in, unlocking, the account calls) stops with
//! [`not_implemented`] until W3-L3. The checks that come first in the TS (no session, no token) run
//! for real, so a signed-out `ov` already answers exactly like the TS one.

use std::collections::HashMap;
use std::path::PathBuf;

use ov_core::host::SecureStore;
use ov_error::{OvError, OvErrorCode};

use crate::store::FileStore;

/// The issuer `ov login` uses when none is given or saved.
pub const DEFAULT_ISSUER: &str = "https://accounts.openvireo.com";
/// The version `ov` reports. It follows the TS CLI's (`VERSION` in session.ts) until the TS CLI is
/// retired, so `ov --help` and `ov version` stay byte-identical.
pub const VERSION: &str = crate::version!();
/// The store key holding the issuer of the saved session (the TS `cli:issuer`).
pub const ISSUER_KEY: &str = "cli:issuer";

/// The process environment, as the TS `io.env`.
pub type Env = HashMap<String, String>;

fn non_empty<'a>(env: &'a Env, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str).filter(|v| !v.is_empty())
}

/// `configDir`: `$OPENVIREO_CONFIG_DIR`, else `<$XDG_CONFIG_HOME | %APPDATA% (Windows) |
/// $HOME/.config>/openvireo`.
pub fn config_dir(env: &Env) -> PathBuf {
    if let Some(dir) = non_empty(env, "OPENVIREO_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    let base = if let Some(xdg) = non_empty(env, "XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if let Some(appdata) = non_empty(env, "APPDATA").filter(|_| cfg!(windows)) {
        PathBuf::from(appdata)
    } else {
        home_dir(env).join(".config")
    };
    base.join("openvireo")
}

/// `env.HOME || os.homedir()`.
fn home_dir(env: &Env) -> PathBuf {
    if let Some(home) = non_empty(env, "HOME") {
        return PathBuf::from(home);
    }
    if let Some(profile) = non_empty(env, "USERPROFILE") {
        return PathBuf::from(profile);
    }
    std::env::home_dir().unwrap_or_default()
}

/// Where `ov login` keeps the session: `<config dir>/session.json`.
pub fn session_path(env: &Env) -> PathBuf {
    config_dir(env).join("session.json")
}

/// The session store (the TS `storageFor(env)`).
pub fn store_for(env: &Env) -> FileStore {
    FileStore::new(session_path(env))
}

/// `serviceAccountToken`: `OPENVIREO_SERVICE_ACCOUNT_TOKEN`, else the contents of
/// `OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE`, trimmed.
pub fn service_account_token(env: &Env) -> Result<Option<String>, OvError> {
    if let Some(t) = non_empty(env, "OPENVIREO_SERVICE_ACCOUNT_TOKEN") {
        return Ok(Some(crate::js::trim(t).to_string()));
    }
    if let Some(file) = non_empty(env, "OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE") {
        let text = std::fs::read_to_string(file).map_err(|e| crate::js::io_error(&e, "open", file))?;
        return Ok(Some(crate::js::trim(&text).to_string()));
    }
    Ok(None)
}

/// The issuer of the session saved by `ov login`, if any.
pub async fn saved_issuer(store: &FileStore) -> Result<Option<String>, OvError> {
    Ok(store.get(ISSUER_KEY).await?.map(|v| String::from_utf8_lossy(&v).into_owned()))
}

/// The error every core-backed step returns until W3-L3 wires `ov-core` in.
pub fn not_implemented(what: &str) -> OvError {
    OvError::new(OvErrorCode::Internal, format!("{what} is not implemented yet in this build of ov (W3-L3)"))
}

/// The start of `openSource`: a service account, else the saved session. Without either, fails
/// exactly like the TS.
pub async fn open_source(env: &Env) -> Result<std::convert::Infallible, OvError> {
    if service_account_token(env)?.is_some() {
        return Err(not_implemented("signing in with a service account token"));
    }
    if saved_issuer(&store_for(env)).await?.is_none() {
        return Err(OvError::new(
            OvErrorCode::SignedOut,
            "not signed in: set OPENVIREO_SERVICE_ACCOUNT_TOKEN or run `ov login`",
        ));
    }
    Err(not_implemented("unlocking the saved session"))
}

/// The start of `unlockedUser` (`ov account delete|restore`).
pub async fn unlocked_user(env: &Env) -> Result<std::convert::Infallible, OvError> {
    if saved_issuer(&store_for(env)).await?.is_none() {
        return Err(OvError::new(OvErrorCode::SignedOut, "not signed in: run `ov login`"));
    }
    Err(not_implemented("unlocking the saved session"))
}

/// `login`.
pub async fn login(
    _env: &Env,
    _issuer: Option<String>,
    _email: Option<String>,
    _secret_key: Option<String>,
) -> Result<String, OvError> {
    Err(not_implemented("ov login"))
}

/// `logout`: "Not signed in" without a saved session.
pub async fn logout(env: &Env, _forget: bool) -> Result<String, OvError> {
    if saved_issuer(&store_for(env)).await?.is_none() {
        return Ok("Not signed in".to_string());
    }
    Err(not_implemented("ov logout"))
}

/// `whoami`.
pub async fn whoami(env: &Env) -> Result<Vec<(String, String)>, OvError> {
    if service_account_token(env)?.is_some() {
        return Err(not_implemented("signing in with a service account token"));
    }
    if saved_issuer(&store_for(env)).await?.is_none() {
        return Err(OvError::new(
            OvErrorCode::SignedOut,
            "not signed in: set OPENVIREO_SERVICE_ACCOUNT_TOKEN or run `ov login`",
        ));
    }
    Err(not_implemented("ov whoami"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn config_dir_follows_the_ts_rules() {
        assert_eq!(config_dir(&env(&[("OPENVIREO_CONFIG_DIR", "/c"), ("HOME", "/h")])), PathBuf::from("/c"));
        assert_eq!(config_dir(&env(&[("XDG_CONFIG_HOME", "/x"), ("HOME", "/h")])), PathBuf::from("/x/openvireo"));
        assert_eq!(config_dir(&env(&[("HOME", "/h")])), PathBuf::from("/h/.config/openvireo"));
        assert_eq!(config_dir(&env(&[("XDG_CONFIG_HOME", ""), ("HOME", "/h")])), PathBuf::from("/h/.config/openvireo"));
        let appdata = config_dir(&env(&[("APPDATA", "/a"), ("HOME", "/h")]));
        if cfg!(windows) {
            assert_eq!(appdata, PathBuf::from("/a/openvireo"));
        } else {
            assert_eq!(appdata, PathBuf::from("/h/.config/openvireo"));
        }
        assert_eq!(session_path(&env(&[("OPENVIREO_CONFIG_DIR", "/c")])), PathBuf::from("/c/session.json"));
    }

    #[test]
    fn service_account_token_is_trimmed() {
        assert_eq!(service_account_token(&env(&[("OPENVIREO_SERVICE_ACCOUNT_TOKEN", " t \n")])).unwrap().unwrap(), "t");
        assert_eq!(service_account_token(&env(&[])).unwrap(), None);
    }
}
