//! Credentials, ported from `packages/cli/src/session.ts`: `OPENVIREO_SERVICE_ACCOUNT_TOKEN` wins;
//! otherwise the user session saved by `ov login` (refresh token, device id and trusted Secret Key
//! in `<config dir>/session.json`, mode 0600), unlocked with the master password
//! (`OPENVIREO_PASSWORD` or a prompt) for each command.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ov_core::api::{
    Account, CancelToken, ClientConfig, DeletionOutcome, DeviceInfo, LoginInput, LoginStep, OvClient, Platform,
    ServiceAccount,
};
use ov_core::host::SecureStore;
use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::cli::Io;
use crate::host::cli_host;
use crate::plan::{describe_plan, short_day, APPLE_SUBSCRIPTIONS_URL};
use crate::source::Source;
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
pub fn service_account_token(env: &Env) -> Result<Option<Zeroizing<String>>, OvError> {
    if let Some(t) = non_empty(env, "OPENVIREO_SERVICE_ACCOUNT_TOKEN") {
        return Ok(Some(Zeroizing::new(crate::js::trim(t).to_string())));
    }
    if let Some(file) = non_empty(env, "OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE") {
        let text = Zeroizing::new(std::fs::read_to_string(file).map_err(|e| crate::js::io_error(&e, "open", file))?);
        return Ok(Some(Zeroizing::new(crate::js::trim(&text).to_string())));
    }
    Ok(None)
}

/// The issuer of the session saved by `ov login`, if any.
pub async fn saved_issuer(store: &FileStore) -> Result<Option<String>, OvError> {
    Ok(store.get(ISSUER_KEY).await?.map(|v| String::from_utf8_lossy(&v).into_owned()))
}

/// `device()`: `openvireo on <host name>`, at most 64 characters, platform `cli`.
fn device() -> DeviceInfo {
    let name: String = format!("openvireo on {}", crate::tty::hostname()).chars().take(64).collect();
    DeviceInfo { id: None, name, platform: Platform::Cli }
}

/// A core client over this process's Host, and the session store that Host uses (one instance, so
/// the core's writes and `cli:issuer` never overwrite each other).
pub struct Session {
    /// The core client.
    pub client: OvClient,
    /// `<config dir>/session.json`, shared with the client's Host.
    pub store: Arc<FileStore>,
}

/// The client for this invocation.
pub fn session(io: &Io) -> Result<Session, OvError> {
    session_with(io, None)
}

fn session_with(io: &Io, server: Option<ov_core::api::ServerConfig>) -> Result<Session, OvError> {
    let store = Arc::new(store_for(&io.env));
    let host = cli_host(&io.env, store.clone(), io.http.clone(), io.clock.clone())?;
    let client = OvClient::new(ClientConfig { device: device(), offline: false, server }, host);
    Ok(Session { client, store })
}

fn nc() -> CancelToken {
    CancelToken::new()
}

/// `ask`: a question on the terminal, or `invalid_request` when there is none.
pub fn ask(io: &mut Io, question: &str, hidden: bool) -> Result<String, OvError> {
    match io.prompt.as_mut() {
        Some(p) => p(question, hidden),
        None => {
            let what = question.trim_end().strip_suffix(':').unwrap_or(question.trim_end()).trim_end();
            Err(OvError::new(
                OvErrorCode::InvalidRequest,
                format!("{what} is needed, but there is no terminal to ask on"),
            ))
        }
    }
}

fn signed_out(message: &str) -> OvError {
    OvError::new(OvErrorCode::SignedOut, message)
}

/// Signs in with a service account token; also returns the server's issuer (TS `sa.config.issuer`).
/// The core discovers the server named in the token.
async fn service_account(io: &Io, token: &str) -> Result<(ServiceAccount, String), OvError> {
    let s = session(io)?;
    let sa = ServiceAccount::from_token(s.client, token.as_bytes().to_vec(), nc()).await?;
    let issuer = sa.issuer();
    Ok((sa, issuer))
}

/// The saved, signed-in (still locked) user session.
async fn saved_account(io: &Io, not_signed_in: &str) -> Result<(Session, Account), OvError> {
    let s = session(io)?;
    let Some(issuer) = saved_issuer(&s.store).await? else { return Err(signed_out(not_signed_in)) };
    let account = s.client.connect(issuer, nc()).await?;
    if !account.is_signed_in() {
        return Err(signed_out("the saved session has ended: run `ov login` again"));
    }
    Ok((s, account))
}

/// The master password: `OPENVIREO_PASSWORD`, else a hidden question.
fn password(io: &mut Io, question: &str) -> Result<Zeroizing<String>, OvError> {
    match io.env.get("OPENVIREO_PASSWORD") {
        Some(p) => Ok(Zeroizing::new(p.clone())),
        None => Ok(Zeroizing::new(ask(io, question, true)?)),
    }
}

/// `openSource`: the vault source for this invocation.
pub async fn open_source(io: &mut Io) -> Result<Source, OvError> {
    if let Some(token) = service_account_token(&io.env)? {
        let (sa, _) = service_account(io, &token).await?;
        return Ok(Source::service_account(sa));
    }
    let (account, _) = unlock(io, "not signed in: set OPENVIREO_SERVICE_ACCOUNT_TOKEN or run `ov login`").await?;
    Ok(Source::user(account))
}

async fn unlock(io: &mut Io, not_signed_in: &str) -> Result<(Account, Zeroizing<String>), OvError> {
    let (_, account) = saved_account(io, not_signed_in).await?;
    let email = account.email().unwrap_or_default();
    let pw = password(io, &format!("Master password for {email}: "))?;
    account.unlock(pw.as_bytes().to_vec(), None, nc()).await?;
    Ok((account, pw))
}

/// `unlockedUser`: the saved, unlocked user session (not a service account), and the password.
pub async fn unlocked_user(io: &mut Io) -> Result<(Account, Zeroizing<String>), OvError> {
    unlock(io, "not signed in: run `ov login`").await
}

/// Signs in, answering a TOTP challenge with "Authenticator code: " until it is right (TS
/// `totp: () => ask(…)`; a wrong code asks again, a dropped challenge fails).
async fn sign_in(
    io: &mut Io,
    account: &Account,
    email: &str,
    password: &str,
    secret_key: Option<&str>,
) -> Result<(), OvError> {
    let input = LoginInput {
        email: email.to_string(),
        password: password.as_bytes().to_vec(),
        secret_key: secret_key.map(|k| k.as_bytes().to_vec()),
        totp: None,
        trust_device: true,
    };
    let mut step = account.login(input, nc()).await?;
    loop {
        let challenge = match step {
            LoginStep::Unlocked(_) => return Ok(()),
            LoginStep::NeedsTotp(c) => c,
        };
        let code = ask(io, "Authenticator code: ", false)?;
        step = match account.submit_totp(challenge.clone(), code, nc()).await {
            Err(e) if e.code == OvErrorCode::InvalidMfa => LoginStep::NeedsTotp(challenge),
            other => other?,
        };
    }
}

/// `login`.
pub async fn login(
    io: &mut Io,
    issuer: Option<String>,
    email: Option<String>,
    secret_key: Option<String>,
) -> Result<String, OvError> {
    let s = session(io)?;
    let issuer = match issuer.or_else(|| io.env.get("OPENVIREO_ISSUER").cloned()) {
        Some(i) => i,
        None => saved_issuer(&s.store).await?.unwrap_or_else(|| DEFAULT_ISSUER.to_string()),
    };
    let issuer = issuer.trim_end_matches('/').to_string();
    let account = s.client.connect(issuer.clone(), nc()).await?;
    let email = match email {
        Some(e) => e,
        None => crate::js::trim(&ask(io, "Email: ", false)?).to_string(),
    };
    let pw = password(io, "Master password: ")?;
    let mut sk = secret_key.or_else(|| io.env.get("OPENVIREO_SECRET_KEY").cloned()).map(Zeroizing::new);
    let given = sk.as_ref().is_some_and(|k| !k.is_empty());
    if let Err(e) = sign_in(io, &account, &email, &pw, sk.as_deref().map(String::as_str)).await {
        if e.code != OvErrorCode::InvalidSecretKey || given {
            return Err(e);
        }
        // First sign-in on this machine: the Secret Key from the Emergency Kit.
        sk = Some(Zeroizing::new(ask(io, "Secret Key (K1-…): ", true)?));
        sign_in(io, &account, &email, &pw, sk.as_deref().map(String::as_str)).await?;
    }
    s.store.set(ISSUER_KEY, issuer.as_bytes()).await?;
    account.lock();
    Ok(format!("Signed in to {issuer} as {email}"))
}

/// `logout`: signs out; `forget` also removes the Secret Key from this machine.
pub async fn logout(io: &mut Io, forget: bool) -> Result<String, OvError> {
    let s = session(io)?;
    let Some(issuer) = saved_issuer(&s.store).await? else { return Ok("Not signed in".to_string()) };
    let account = s.client.connect(issuer, nc()).await?;
    account.sign_out(forget, nc()).await?;
    s.store.delete(ISSUER_KEY).await?;
    Ok(if forget { "Signed out, and the Secret Key was removed from this machine" } else { "Signed out" }.to_string())
}

/// The TS `deletion_blocked` / `confirm_mismatch` errors. Neither is an SDK error code; only the
/// message shows (exit 1).
fn deletion_error(message: &str) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, message)
}

/// `deleteAccount`: schedules the signed-in account's deletion (SPEC §23), printing what happens
/// first and asking for the email unless `yes` (then `email` must be given and match).
pub async fn delete_account(
    io: &mut Io,
    yes: bool,
    email_flag: Option<String>,
    print: &mut dyn FnMut(&str),
) -> Result<String, OvError> {
    let (account, pw) = unlocked_user(io).await?;
    let email = account.email().unwrap_or_default();
    let preview = account.deletion_preview(nc()).await?;
    if let Some(at) = &preview.scheduled_for {
        return Ok(format!("{email} is already scheduled for deletion on {}", short_day(at)));
    }
    print(&format!(
        "Deleting {email} locks it now and erases it on {}. Until then, `ov account restore` keeps it.",
        short_day(&preview.erase_on)
    ));
    for v in &preview.vaults {
        let shared: Vec<&str> =
            v.shared_with.iter().map(|s| s.display.as_deref().unwrap_or(s.principal.as_str())).collect();
        let with = if shared.is_empty() {
            String::new()
        } else {
            format!(" (shared with {}, who lose it)", shared.join(", "))
        };
        print(&format!("  vault {} is deleted{with}", v.name.as_deref().unwrap_or(&v.id)));
    }
    for o in &preview.orgs {
        print(&match o.outcome {
            DeletionOutcome::Leave => format!("  you leave {}", o.name),
            DeletionOutcome::Delete => format!("  {} is deleted with you", o.name),
            DeletionOutcome::Blocked => {
                format!("  {}: you are its only owner; make someone else an owner or delete it first", o.name)
            }
        });
    }
    match &preview.subscription {
        Some(s) if s.manage == "app_store" => print(&format!(
            "  your {} plan is billed by Apple and keeps renewing: cancel it on your iPhone or in your Apple ID settings ({APPLE_SUBSCRIPTIONS_URL})",
            s.plan
        )),
        Some(s) => print(&format!("  your {} plan stops renewing", s.plan)),
        None => {}
    }
    if preview.share_links > 0 {
        let n = preview.share_links;
        print(&format!("  {n} share link{} stop working now", if n == 1 { "" } else { "s" }));
    }
    if preview.blocked {
        return Err(deletion_error(
            "hand over or delete the organizations above first (in the web app or desktop app)",
        ));
    }
    let confirm = if !yes {
        crate::js::trim(&ask(io, &format!("Type {email} to delete it: "), false)?).to_string()
    } else {
        match email_flag.filter(|e| !e.is_empty()) {
            Some(e) => e,
            None => return Err(OvError::new(OvErrorCode::InvalidRequest, "--yes needs --email <the account email>")),
        }
    };
    if confirm.to_lowercase() != email.to_lowercase() {
        return Err(deletion_error("that isn't this account's email; nothing was deleted"));
    }
    let at = account.delete_account(pw.as_bytes().to_vec(), confirm, nc()).await?;
    Ok(format!(
        "{email} is locked and will be deleted on {}. To keep it, run `ov login` and `ov account restore` before then.",
        short_day(&at)
    ))
}

/// `restoreAccount`: restores the signed-in account while it is pending deletion.
pub async fn restore_account(io: &mut Io) -> Result<String, OvError> {
    let (account, pw) = unlocked_user(io).await?;
    let email = account.email().unwrap_or_default();
    if account.deletion_scheduled_for().is_none() {
        return Ok(format!("{email} isn't scheduled for deletion"));
    }
    account.restore_account(pw.as_bytes().to_vec(), nc()).await?;
    account.lock();
    Ok(format!("{email} was restored"))
}

/// `whoami`: `kind`, `principal`, then `email`, `issuer` and `plan` for a user, or `issuer` for a
/// service account.
pub async fn whoami(io: &mut Io) -> Result<Vec<(String, String)>, OvError> {
    let kv = |k: &str, v: String| (k.to_string(), v);
    if let Some(token) = service_account_token(&io.env)? {
        let (sa, issuer) = service_account(io, &token).await?;
        sa.close();
        return Ok(vec![kv("kind", "service-account".into()), kv("principal", sa.principal()), kv("issuer", issuer)]);
    }
    let s = session(io)?;
    let Some(issuer) = saved_issuer(&s.store).await? else {
        return Err(signed_out("not signed in: set OPENVIREO_SERVICE_ACCOUNT_TOKEN or run `ov login`"));
    };
    let account = s.client.connect(issuer.clone(), nc()).await?;
    let (Some(user_id), Some(email)) = (account.user_id(), account.email()) else {
        return Err(signed_out("the saved session has ended: run `ov login` again"));
    };
    let mut who = vec![
        kv("kind", "user".into()),
        kv("principal", format!("user:{user_id}")),
        kv("email", email),
        kv("issuer", issuer.clone()),
    ];
    // Offline, or an older server: whoami still answers from the saved session.
    if let Ok(me) = account.me(nc()).await {
        let plan = me.plan.map(|p| crate::plan::Plan {
            id: p.id,
            billing: p.billing.map(|b| crate::plan::Billing {
                source: b.source,
                interval: b.interval,
                status: b.status,
                renews_at: b.renews_at,
                ends_at: b.ends_at,
                manage: b.manage,
            }),
        });
        if let Some(line) = describe_plan(plan.as_ref(), &issuer) {
            who.push(kv("plan", line));
        }
    }
    Ok(who)
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
        assert_eq!(
            service_account_token(&env(&[("OPENVIREO_SERVICE_ACCOUNT_TOKEN", " t \n")])).unwrap().unwrap().as_str(),
            "t"
        );
        assert!(service_account_token(&env(&[])).unwrap().is_none());
    }

    #[test]
    fn device_names_are_cut_to_64_characters() {
        let d = device();
        assert!(d.name.starts_with("openvireo on ") && d.name.chars().count() <= 64);
        assert_eq!(d.platform, Platform::Cli);
    }
}
