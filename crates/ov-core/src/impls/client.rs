//! [`OvClient`]: discovery (with the offline copy), connecting an account, sessions on a shared
//! device and opening share links.

use std::sync::{Arc, Mutex};

use ov_error::OvError;
use ov_protocol::auth::{parse_open_share, parse_public_share, AuthApi};
use ov_protocol::discovery::{build_discovery, parse_discovery, OpenVireoConfiguration};
use ov_protocol::sync::SyncApi;
use ov_protocol::types::OpenShareRequest;

use super::account::config_meta_name;
use super::convert::{api_kdf, crypto_kdf, from_stored, server_config, wire_config};
use super::net::send;
use super::share::api_payload;
use super::tokens::{SignedOutSignal, StoredSession, TokenManager, SESSION_KEY};
use super::util::{secret_text, to_json};
use crate::api::{Account, CancelToken, OpenedShare, OvClient, SecretBytes, ServerConfig, SessionState, ShareInfo};
use crate::host::Host;
use crate::state::{AccountInner, AccountState};

/// SPEC §10 discovery; with the offline cache, the copy from the last success when unreachable.
/// Returns the document and whether it came from the cache.
pub(crate) async fn discover_raw(
    client: &OvClient,
    issuer: &str,
    cancel: &CancelToken,
) -> Result<(OpenVireoConfiguration, bool), OvError> {
    let host = &client.inner.host;
    let offline = client.inner.config.offline;
    let name = config_meta_name(issuer);
    let result = async { parse_discovery(&send(host, build_discovery(issuer)?, cancel).await?) }.await;
    match result {
        Ok(c) => {
            if offline {
                host.cache.save_meta("", &name, &to_json(&c)).await?;
            }
            Ok((c, false))
        }
        Err(e) => {
            if offline && e.is_unreachable() {
                if let Some(raw) = host.cache.load_meta("", &name).await? {
                    return Ok((from_stored(&raw, "discovery document")?, true));
                }
            }
            Err(e)
        }
    }
}

pub(crate) async fn discover(client: &OvClient, issuer: &str, cancel: &CancelToken) -> Result<ServerConfig, OvError> {
    Ok(server_config(&discover_raw(client, issuer, cancel).await?.0))
}

pub(crate) async fn connect(client: &OvClient, issuer: String, cancel: CancelToken) -> Result<Account, OvError> {
    let (config, offline) = match &client.inner.config.server {
        Some(c) => (c.clone(), false),
        None => {
            let (c, offline) = discover_raw(client, &issuer, &cancel).await?;
            (server_config(&c), offline)
        }
    };
    // Checks every URL (SPEC §1).
    let wire = wire_config(&config);
    let auth = AuthApi::new(&wire.api)?;
    let sync = SyncApi::new(&wire.sync)?;
    let signal = Arc::new(SignedOutSignal::default());
    let tokens = TokenManager::new(client.inner.host.clone(), auth.clone(), SESSION_KEY, signal.clone());
    let cache_user = tokens.load().await?.map(|s| s.user_id);
    let state = AccountState {
        client: client.inner.clone(),
        config,
        auth,
        sync,
        tokens,
        signal,
        inner: Mutex::new(AccountInner { offline, cache_user, ..AccountInner::default() }),
    };
    Ok(Account { inner: Arc::new(state) })
}

/// SPEC §21, with no network. A crash while moving a session can leave it under both keys: the
/// active one wins and the parked copy goes.
pub(crate) async fn session_state(host: &Host, issuer: &str, user_id: &str) -> Result<SessionState, OvError> {
    let parked = Account::parked_key(issuer, user_id);
    if let Some(raw) = host.store.get(SESSION_KEY).await? {
        if serde_json::from_slice::<StoredSession>(&raw).is_ok_and(|s| s.user_id == user_id) {
            host.store.delete(&parked).await?;
            return Ok(SessionState::Active);
        }
    }
    Ok(if host.store.get(&parked).await?.is_some() { SessionState::Parked } else { SessionState::SignedOut })
}

pub(crate) async fn share_info(
    client: &OvClient,
    api: &str,
    id: &str,
    cancel: &CancelToken,
) -> Result<ShareInfo, OvError> {
    let auth = AuthApi::new(api)?;
    let i = parse_public_share(&send(&client.inner.host, auth.build_public_share(id), cancel).await?)?;
    Ok(ShareInfo {
        expires_at: i.expires_at,
        opens_left: i.opens_left.map(|n| n.clamp(0, u32::MAX as i64) as u32),
        kdf: i.kdf.as_ref().map(api_kdf),
    })
}

pub(crate) async fn open_share(
    client: &OvClient,
    api: &str,
    link: SecretBytes,
    passcode: Option<SecretBytes>,
    info: Option<ShareInfo>,
    cancel: &CancelToken,
) -> Result<OpenedShare, OvError> {
    let link = secret_text(link, "share link")?;
    let passcode = passcode.map(|p| secret_text(p, "passcode")).transpose()?;
    let parts = ov_share::parse_share_link(&link)?;
    let info = match info {
        Some(i) => i,
        None => share_info(client, api, &parts.id, cancel).await?,
    };
    let kdf = info.kdf.as_ref().map(|k| {
        crypto_kdf(&ov_protocol::types::Kdf { alg: k.alg.clone(), salt: k.salt.clone(), m: k.m, t: k.t, p: k.p })
    });
    let open = ov_share::ShareOpen::new(parts, kdf.as_ref(), passcode.as_deref().map(String::as_str))?;
    let auth = AuthApi::new(api)?;
    let body = OpenShareRequest { auth: open.auth().map(str::to_owned) };
    let res = send(&client.inner.host, auth.build_open_share(open.id(), &body), cancel).await?;
    let opened = parse_open_share(&res)?;
    let payload = open.decrypt_b64u(&opened.ct)?;
    Ok(OpenedShare {
        payload: api_payload(&payload),
        opens_left: opened.opens_left.map(|n| n.clamp(0, u32::MAX as i64) as u32),
    })
}
