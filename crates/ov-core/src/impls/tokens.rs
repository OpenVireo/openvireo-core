//! Access-token lifecycle for a signed-in device (SPEC §9), a port of the SDK's
//! `auth/token-manager.ts`: refresh shortly before expiry, one refresh at a time (single flight),
//! persist the rotated refresh token before using the new access token, and treat a rejected refresh
//! (reuse, revoked device, expiry) as signed out.

use std::sync::{Arc, Mutex};
use std::task::Waker;

use ov_error::{OvError, OvErrorCode};
use ov_protocol::auth::{parse_refresh, AuthApi};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::net::send;
use super::util::{lock, signed_out, to_json};
use crate::api::{CancelToken, SignedOutReason};
use crate::host::Host;

/// The SecureStore key of the open session (the TS SDK's `NamespacedStorage("ov:")` + `session`).
pub(crate) const SESSION_KEY: &str = "ov:session";

/// Refresh this long before `exp`.
const MARGIN_MS: i64 = 60_000;

/// A stored session, the TS `StoredSession` JSON.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredSession {
    pub issuer: String,
    pub user_id: String,
    pub email: String,
    pub device_id: String,
    #[serde(with = "zeroizing_string")]
    pub refresh_token: Zeroizing<String>,
}

/// Serde for a secret string kept in a `Zeroizing` buffer.
mod zeroizing_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub(super) fn serialize<S: Serializer>(v: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(d).map(Zeroizing::new)
    }
}

#[derive(Default)]
struct State {
    session: Option<StoredSession>,
    loaded: bool,
    access: Option<(Zeroizing<String>, i64)>,
    /// Bumped on every new access token, so a waiter on the refresh lock sees someone else's refresh.
    generation: u64,
}

/// Signed-out notifications: a counter plus the last reason, and wakers waiting for a change.
#[derive(Default)]
pub(crate) struct SignedOutSignal {
    inner: Mutex<(u64, Option<SignedOutReason>, Vec<Waker>)>,
}

impl SignedOutSignal {
    pub(crate) fn fire(&self, reason: SignedOutReason) {
        let wakers = {
            let mut g = lock(&self.inner);
            g.0 += 1;
            g.1 = Some(reason);
            std::mem::take(&mut g.2)
        };
        for w in wakers {
            w.wake();
        }
    }

    pub(crate) fn count(&self) -> u64 {
        lock(&self.inner).0
    }

    /// Completes with the reason once the counter passes `seen`.
    pub(crate) fn wait(&self, seen: u64) -> impl std::future::Future<Output = SignedOutReason> + '_ {
        std::future::poll_fn(move |cx| {
            let mut g = lock(&self.inner);
            if g.0 > seen {
                return std::task::Poll::Ready(g.1.unwrap_or(SignedOutReason::Logout));
            }
            if !g.2.iter().any(|w| w.will_wake(cx.waker())) {
                g.2.push(cx.waker().clone());
            }
            std::task::Poll::Pending
        })
    }
}

/// One session in the SecureStore under `key`.
pub(crate) struct TokenManager {
    host: Host,
    auth: AuthApi,
    key: String,
    state: Mutex<State>,
    refresh_lock: futures::lock::Mutex<()>,
    pub(crate) signal: Arc<SignedOutSignal>,
}

fn reason_for(code: OvErrorCode) -> SignedOutReason {
    match code {
        OvErrorCode::TokenReused => SignedOutReason::TokenReused,
        OvErrorCode::SessionExpired => SignedOutReason::SessionExpired,
        _ => SignedOutReason::Unauthorized,
    }
}

impl TokenManager {
    pub(crate) fn new(host: Host, auth: AuthApi, key: impl Into<String>, signal: Arc<SignedOutSignal>) -> Self {
        TokenManager {
            host,
            auth,
            key: key.into(),
            state: Mutex::new(State::default()),
            refresh_lock: futures::lock::Mutex::new(()),
            signal,
        }
    }

    fn now(&self) -> i64 {
        self.host.clock.now_unix_ms()
    }

    /// The stored session, read once from the store. An unreadable store is an error.
    pub(crate) async fn load(&self) -> Result<Option<StoredSession>, OvError> {
        {
            let s = lock(&self.state);
            if s.loaded || s.session.is_some() {
                return Ok(s.session.clone());
            }
        }
        let raw = self.host.store.get(&self.key).await?;
        let parsed = raw.and_then(|r| serde_json::from_slice::<StoredSession>(&r).ok());
        let mut s = lock(&self.state);
        if !s.loaded {
            s.session = parsed;
            s.loaded = true;
        }
        Ok(s.session.clone())
    }

    /// The session in memory, without the store.
    pub(crate) fn current(&self) -> Option<StoredSession> {
        lock(&self.state).session.clone()
    }

    fn set_access(&self, s: &mut State, token: &str, expires_in: i64) {
        let mut expires_at = self.now() + expires_in.saturating_mul(1000);
        if let Ok(d) = ov_crypto::jwt::decode_jwt(token) {
            if let Some(exp) = d.claims.exp {
                expires_at = expires_at.min(exp.saturating_mul(1000));
            }
        }
        s.access = Some((Zeroizing::new(token.to_owned()), expires_at));
        s.generation += 1;
    }

    /// After a sign-in: keep the session and its first access token.
    pub(crate) async fn start(&self, session: StoredSession, access: &str, expires_in: i64) -> Result<(), OvError> {
        let json = Zeroizing::new(to_json(&session));
        {
            let mut s = lock(&self.state);
            s.session = Some(session);
            s.loaded = true;
            self.set_access(&mut s, access, expires_in);
        }
        self.host.store.set(&self.key, &json).await
    }

    /// Changes the stored email (SPEC §16).
    pub(crate) async fn update_email(&self, email: &str) -> Result<(), OvError> {
        let json = {
            let mut s = lock(&self.state);
            let Some(sess) = s.session.as_mut() else { return Ok(()) };
            sess.email = email.to_owned();
            Zeroizing::new(to_json(&*sess))
        };
        self.host.store.set(&self.key, &json).await
    }

    /// The access token held now, if it hasn't expired.
    pub(crate) fn access_token_now(&self) -> Option<Zeroizing<String>> {
        let s = lock(&self.state);
        s.access.as_ref().filter(|(_, at)| *at > self.now()).map(|(t, _)| t.clone())
    }

    /// A valid access token, refreshing first if it expires within a minute (or `force`).
    pub(crate) async fn access_token(&self, force: bool, cancel: &CancelToken) -> Result<Zeroizing<String>, OvError> {
        if !force {
            let s = lock(&self.state);
            if let Some((t, at)) = &s.access {
                if at - MARGIN_MS > self.now() {
                    return Ok(t.clone());
                }
            }
        }
        self.refresh_now(cancel).await
    }

    /// Single-flight refresh: a caller that waited for someone else's refresh uses its token.
    pub(crate) async fn refresh_now(&self, cancel: &CancelToken) -> Result<Zeroizing<String>, OvError> {
        let seen = lock(&self.state).generation;
        let _guard = self.refresh_lock.lock().await;
        {
            let s = lock(&self.state);
            if s.generation != seen {
                if let Some((t, _)) = &s.access {
                    return Ok(t.clone());
                }
            }
        }
        let session = self.load().await?.ok_or_else(|| signed_out("not signed in"))?;
        let res = send(&self.host, self.auth.build_refresh(&session.refresh_token), cancel).await?;
        let pair = match parse_refresh(&res) {
            Ok(p) => p,
            Err(e) => {
                if matches!(e.status, Some(401 | 403 | 410)) {
                    let reason = reason_for(e.code);
                    self.clear(reason).await?;
                    let mut out = OvError::new(OvErrorCode::SignedOut, format!("signed out: {}", e.message));
                    out.status = e.status;
                    out.details = Some(format!("{{\"reason\":\"{}\"}}", e.wire_code()));
                    return Err(out);
                }
                return Err(e);
            }
        };
        // Persist the rotated refresh token before using the new access token
        let updated = StoredSession { refresh_token: Zeroizing::new(pair.refresh_token.clone()), ..session };
        self.host.store.set(&self.key, &Zeroizing::new(to_json(&updated))).await?;
        let mut s = lock(&self.state);
        s.session = Some(updated);
        self.set_access(&mut s, &pair.access_token, pair.expires_in);
        Ok(Zeroizing::new(pair.access_token))
    }

    /// Forgets the session (logout, or the server refused it) and tells the listeners.
    pub(crate) async fn clear(&self, reason: SignedOutReason) -> Result<(), OvError> {
        {
            let mut s = lock(&self.state);
            s.session = None;
            s.access = None;
            s.loaded = true;
        }
        let r = self.host.store.delete(&self.key).await;
        // This device's own sign-out isn't reported (`Account::signed_out`).
        if reason != SignedOutReason::Logout {
            self.signal.fire(reason);
        }
        r
    }

    /// Moves the session to `key` without ending it (SPEC §21): written before it is deleted, so a
    /// crash leaves both and the active key wins. False with no session.
    pub(crate) async fn set_aside(&self, key: &str) -> Result<bool, OvError> {
        let _guard = self.refresh_lock.lock().await;
        let Some(raw) = self.host.store.get(&self.key).await? else { return Ok(false) };
        self.host.store.set(key, &raw).await?;
        self.host.store.delete(&self.key).await?;
        let mut s = lock(&self.state);
        s.session = None;
        s.access = None;
        s.loaded = true;
        Ok(true)
    }

    /// Moves a session set aside back. False when `key` holds none.
    pub(crate) async fn resume(&self, key: &str) -> Result<bool, OvError> {
        let Some(raw) = self.host.store.get(key).await? else { return Ok(false) };
        let session: StoredSession = serde_json::from_slice(&raw)
            .map_err(|_| OvError::new(OvErrorCode::SignedOut, "the parked session can't be read"))?;
        self.host.store.set(&self.key, &raw).await?;
        self.host.store.delete(key).await?;
        let mut s = lock(&self.state);
        s.session = Some(session);
        s.access = None;
        s.loaded = true;
        Ok(true)
    }
}
