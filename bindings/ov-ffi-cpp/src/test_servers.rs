//! W2-E's in-process auth and sync servers (`ov_testkit::servers`) for the desktop's tests, with
//! feature `test-server` (README.md, "Test servers"). Without the feature every function is still
//! declared (the header doesn't change) but `test_servers_start` fails with `internal`, so no
//! [`TestServers`] can exist.
//!
//! A C++ test's `ov::HttpTransport` forwards each request to [`TestServers::handle`] (and
//! `open_stream` to [`TestServers::open_stream`]), so the desktop's own Host (CoreHost) talks to the
//! real protocol in process. [`TestServers::client`] is a shortcut: a `Client` on the servers'
//! own Rust Host (memory store and cache, the servers' clock).

// Without the feature the bodies are compiled out, so the parameters go unused.
#![cfg_attr(not(feature = "test-server"), allow(unused_variables, dead_code))]

use ov_error::{OvError, OvErrorCode};

use crate::edge::{edge, FfiError};
use crate::ffi;
use crate::handles::Client;

type R<T> = Result<T, FfiError>;

#[cfg(feature = "test-server")]
type Inner = ov_testkit::servers::TestServers;
#[cfg(not(feature = "test-server"))]
type Inner = std::convert::Infallible;

#[cfg(feature = "test-server")]
type StreamInner = Box<dyn ov_core::host::ByteStream>;
#[cfg(not(feature = "test-server"))]
type StreamInner = std::convert::Infallible;

/// `ov::TestServers`: both servers on one manual clock.
pub struct TestServers(#[allow(dead_code)] Inner);

/// `ov::TestStream`: an event stream from [`TestServers::open_stream`].
pub struct TestStream(#[allow(dead_code)] StreamInner);

/// Runs `$body` with `$s` bound to the testkit servers; `internal` without the feature (no
/// `TestServers` can be made then anyway).
macro_rules! with {
    ($self:ident, $s:ident => $body:expr) => {{
        #[cfg(feature = "test-server")]
        let r = {
            let $s = &$self.0;
            $body
        };
        #[cfg(not(feature = "test-server"))]
        let r = {
            let _ = $self;
            Err(OvError::new(OvErrorCode::Internal, "openvireo-core was built without the test-server feature"))
        };
        r
    }};
}

fn opt(s: Option<String>) -> String {
    s.unwrap_or_default()
}

/// `ov::test_servers_start()`: fresh servers with the clock at `now_ms` (Unix milliseconds; 0 for
/// the testkit's default 2026-11-15T00:00:00Z) and the default seed.
pub fn test_servers_start(now_ms: i64) -> R<Box<TestServers>> {
    edge(|| {
        #[cfg(feature = "test-server")]
        {
            let start = if now_ms == 0 { 1_794_700_800_000 } else { now_ms };
            let clock = std::sync::Arc::new(ov_testkit::ManualClock::new(start));
            Ok(Box::new(TestServers(ov_testkit::servers::TestServers::new(clock))))
        }
        #[cfg(not(feature = "test-server"))]
        {
            let _ = now_ms;
            Err(OvError::new(OvErrorCode::Internal, "openvireo-core was built without the test-server feature"))
        }
    })
}

#[cfg(feature = "test-server")]
fn request_in(r: &ffi::HttpRequest) -> Result<ov_core::host::HttpRequest, OvError> {
    use ov_core::host::Method as M;
    let method = match r.method {
        ffi::Method::Get => M::Get,
        ffi::Method::Head => M::Head,
        ffi::Method::Post => M::Post,
        ffi::Method::Put => M::Put,
        ffi::Method::Patch => M::Patch,
        ffi::Method::Delete => M::Delete,
        other => return Err(OvError::new(OvErrorCode::InvalidRequest, format!("unknown Method value {}", other.repr))),
    };
    Ok(ov_core::host::HttpRequest {
        method,
        url: r.url.clone(),
        headers: r.headers.iter().map(|h| (h.name.clone(), h.value.clone())).collect(),
        body: r.has_body.then(|| r.body.clone()),
        keepalive: r.keepalive,
    })
}

#[cfg(feature = "test-server")]
fn failure_out(e: ov_core::host::TransportError, failure: &mut ffi::TransportFailure) {
    use ov_core::host::TransportError as T;
    let (kind, message) = match e {
        T::Offline => (ffi::TransportErrorKind::Offline, String::new()),
        T::Timeout => (ffi::TransportErrorKind::Timeout, String::new()),
        T::Tls(m) => (ffi::TransportErrorKind::Tls, m),
        T::Cancelled => (ffi::TransportErrorKind::Cancelled, String::new()),
        T::Other(m) => (ffi::TransportErrorKind::Other, m),
    };
    failure.kind = kind;
    failure.message = message;
}

#[cfg(feature = "test-server")]
fn server_in(name: &str) -> Result<Option<ov_testkit::servers::Server>, OvError> {
    use ov_testkit::servers::Server;
    match name {
        "" => Ok(None),
        "auth" => Ok(Some(Server::Auth)),
        "sync" => Ok(Some(Server::Sync)),
        other => {
            Err(OvError::new(OvErrorCode::InvalidRequest, format!("unknown server {other:?} (auth, sync or empty)")))
        }
    }
}

#[cfg(feature = "test-server")]
fn method_in(name: &str) -> Result<Option<ov_core::host::Method>, OvError> {
    use ov_core::host::Method as M;
    Ok(Some(match name {
        "" => return Ok(None),
        "GET" => M::Get,
        "HEAD" => M::Head,
        "POST" => M::Post,
        "PUT" => M::Put,
        "PATCH" => M::Patch,
        "DELETE" => M::Delete,
        other => return Err(OvError::new(OvErrorCode::InvalidRequest, format!("unknown method {other:?}"))),
    }))
}

impl TestServers {
    /// The auth server's issuer (`https://auth.test`).
    pub fn issuer(&self) -> R<String> {
        edge(|| with!(self, s => Ok(s.issuer())))
    }

    /// The auth API base (`{issuer}/api/v1`).
    pub fn api_url(&self) -> R<String> {
        edge(|| with!(self, s => Ok(s.api_url())))
    }

    /// The sync API base (`https://sync.test/api/v1`); the self-hosted server URL is this without
    /// `/api/v1`.
    pub fn sync_url(&self) -> R<String> {
        edge(|| with!(self, s => Ok(s.sync_url())))
    }

    /// The test clock (Unix milliseconds). A C++ Host's `Clock` should return this.
    pub fn now_ms(&self) -> R<i64> {
        edge(|| with!(self, s => Ok(s.clock().now_unix_ms())))
    }

    /// Sets the test clock.
    pub fn set_now_ms(&self, ms: i64) -> R<()> {
        edge(|| with!(self, s => { s.clock().set(ms); Ok(()) }))
    }

    /// Moves the test clock; returns the new time.
    pub fn advance_ms(&self, delta_ms: i64) -> R<i64> {
        edge(|| with!(self, s => Ok(s.clock().advance(delta_ms))))
    }

    /// Answers one request as the servers' transport does. A transport failure (offline, an
    /// injected fault, another host) is reported through `failure`, as an `ov::HttpTransport` does.
    pub fn handle(&self, req: &ffi::HttpRequest, failure: &mut ffi::TransportFailure) -> R<ffi::HttpResponse> {
        edge(|| {
            with!(self, s => {
                let req = request_in(req)?;
                match ov_testkit::servers::block_on(ov_core::host::HttpTransport::send(s, req)) {
                    Ok(r) => Ok(ffi::HttpResponse {
                        status: r.status,
                        headers: r.headers.into_iter().map(|(name, value)| ffi::Header { name, value }).collect(),
                        body: r.body,
                    }),
                    Err(e) => {
                        failure_out(e, failure);
                        Ok(ffi::HttpResponse { status: 0, headers: Vec::new(), body: Vec::new() })
                    }
                }
            })
        })
    }

    /// Opens an event stream (SPEC §11); poll it with [`TestStream::poll_chunk`]. A transport
    /// failure goes to `failure` and the result is a closed stream.
    pub fn open_stream(&self, req: &ffi::HttpRequest, failure: &mut ffi::TransportFailure) -> R<Box<TestStream>> {
        edge(|| {
            with!(self, s => {
                let req = request_in(req)?;
                match ov_testkit::servers::block_on(ov_core::host::HttpTransport::open_stream(s, req)) {
                    Ok(stream) => Ok(Box::new(TestStream(stream))),
                    Err(e) => {
                        failure_out(e, failure);
                        Err(OvError::new(OvErrorCode::NetworkError, "the stream didn't open (see failure)"))
                    }
                }
            })
        })
    }

    /// A `Client` on the servers' own Rust Host: a fresh memory store and cache (a new device each
    /// call) and the test clock.
    pub fn client(&self, config: &ffi::ClientConfig) -> R<Box<Client>> {
        edge(|| {
            with!(self, s => {
                let config = crate::convert::client_config(config)?;
                Ok(Box::new(Client(ov_core::api::OvClient::new(config, s.host()))))
            })
        })
    }

    // ---- server state

    /// Every host unreachable (`true`) or back.
    pub fn set_offline(&self, offline: bool) -> R<()> {
        edge(|| with!(self, s => { s.set_offline(offline); Ok(()) }))
    }

    /// The next `times` matching requests get `status` (with the usual error body) instead of the
    /// server's answer; `status == 0` is a transport failure (offline). `server` is `auth`, `sync`
    /// or empty (both), `method` e.g. `PUT` or empty (any), `path_contains` empty for any path.
    pub fn fail_next(&self, server: &str, method: &str, path_contains: &str, status: u16, times: usize) -> R<()> {
        edge(|| {
            with!(self, s => {
                use ov_testkit::servers::{Fault, FaultRule};
                let fault = if status == 0 { Fault::Offline } else { Fault::Status(status) };
                let mut rule = FaultRule::new(fault).times(times.max(1));
                if let Some(sv) = server_in(server)? {
                    rule = rule.server(sv);
                }
                if let Some(m) = method_in(method)? {
                    rule = rule.method(m);
                }
                if !path_contains.is_empty() {
                    rule = rule.path(path_contains);
                }
                s.fail_next(rule);
                Ok(())
            })
        })
    }

    /// Drops every pending fault.
    pub fn clear_faults(&self) -> R<()> {
        edge(|| with!(self, s => { s.clear_faults(); Ok(()) }))
    }

    /// The servers' clock runs `ms` ahead of the test clock (clock-skew warnings).
    pub fn set_server_clock_skew_ms(&self, ms: i64) -> R<()> {
        edge(|| with!(self, s => { s.set_server_clock_skew_ms(ms); Ok(()) }))
    }

    /// The requests seen so far, one line each: `<status> <route or server METHOD path>`
    /// (`0` for a fault). Never headers or bodies.
    pub fn requests(&self) -> R<Vec<String>> {
        edge(|| {
            with!(self, s => Ok(s
                .requests()
                .into_iter()
                .map(|r| {
                    let what = r.route.unwrap_or_else(|| format!("{:?} {:?} {}", r.server, r.method, r.path));
                    format!("{} {what}", r.status.unwrap_or(0))
                })
                .collect()))
        })
    }

    /// Forgets the recorded requests.
    pub fn clear_requests(&self) -> R<()> {
        edge(|| with!(self, s => { s.clear_requests(); Ok(()) }))
    }

    /// The sync server checks live access instead of the token's `vlt` claim.
    pub fn set_live_access(&self, live: bool) -> R<()> {
        edge(|| with!(self, s => { s.set_live_access(live); Ok(()) }))
    }

    // ---- blobs (other devices, server accidents)

    /// The vault blob's bytes now; `has == false` when there is none.
    pub fn vault_blob(&self, vault_id: &str) -> R<ffi::OptionalBytes> {
        edge(|| {
            with!(self, s => {
                let b = s.vault_blob(vault_id);
                Ok(ffi::OptionalBytes { has: b.is_some(), value: b.map(|b| b.data).unwrap_or_default() })
            })
        })
    }

    /// The vault blob's revision now (0 when there is none).
    pub fn vault_revision(&self, vault_id: &str) -> R<i64> {
        edge(|| with!(self, s => Ok(s.vault_blob(vault_id).map_or(0, |b| b.revision))))
    }

    /// Stores new vault bytes as another device would.
    pub fn put_vault_blob(&self, vault_id: &str, data: &[u8]) -> R<()> {
        edge(|| with!(self, s => { s.put_vault_blob(vault_id, data); Ok(()) }))
    }

    /// Puts the vault back to an older revision (`server_rolled_back`).
    pub fn rollback_vault(&self, vault_id: &str, to_revision: i64) -> R<()> {
        edge(|| with!(self, s => { s.rollback_vault(vault_id, to_revision); Ok(()) }))
    }

    /// Loses the vault's blob and history (`server_lost_database`).
    pub fn lose_vault(&self, vault_id: &str) -> R<()> {
        edge(|| with!(self, s => { s.lose_vault(vault_id); Ok(()) }))
    }

    /// A self-hosted device token for `user`.
    pub fn add_device_token(&self, token: &str, user: &str) -> R<()> {
        edge(|| with!(self, s => { s.add_device_token(token, user); Ok(()) }))
    }

    /// Ends every open event stream.
    pub fn close_streams(&self) -> R<()> {
        edge(|| with!(self, s => { s.close_streams(); Ok(()) }))
    }

    // ---- accounts

    /// A user's id by email; empty when unknown.
    pub fn user_id(&self, email: &str) -> R<String> {
        edge(|| with!(self, s => Ok(opt(s.user_id(email)))))
    }

    /// Sets the TOTP code the server accepts for `email` (two-step on); empty turns it off. Whether
    /// the user exists.
    pub fn set_totp_code(&self, email: &str, code: &str) -> R<bool> {
        edge(|| with!(self, s => Ok(s.set_totp_code(email, (!code.is_empty()).then_some(code)))))
    }

    /// The current TOTP code for `email`; empty when two-step is off.
    pub fn totp_now(&self, email: &str) -> R<String> {
        edge(|| with!(self, s => Ok(opt(s.totp_now(email)))))
    }

    /// The last email-change code sent to a user; empty when none.
    pub fn email_code(&self, user_id: &str) -> R<String> {
        edge(|| with!(self, s => Ok(opt(s.email_code(user_id)))))
    }

    /// Approves a recovery request (SPEC §18) usable after `delay_secs`; returns the reset token.
    pub fn approve_reset(&self, email: &str, delay_secs: i64) -> R<String> {
        edge(|| with!(self, s => Ok(s.approve_reset(email, delay_secs))))
    }

    /// The pending invitation token for `email` in an org; empty when none.
    pub fn invitation_token(&self, org_id: &str, email: &str) -> R<String> {
        edge(|| with!(self, s => Ok(opt(s.invitation_token(org_id, email)))))
    }

    /// Adds a confirmed org member directly (`owner`, `admin`, `member`). Whether it worked.
    pub fn add_member(&self, org_id: &str, email: &str, role: &str) -> R<bool> {
        edge(|| with!(self, s => Ok(s.add_member(org_id, email, role))))
    }

    /// Signs a principal (`user:<id>`, `sa:<id>`) out everywhere: its tokens stop working
    /// (revocation; the session-ended event).
    pub fn revoke_sessions(&self, principal: &str) -> R<()> {
        edge(|| with!(self, s => { s.revoke_sessions(principal); Ok(()) }))
    }

    /// Every `access` event the auth server sent, as a JSON array.
    pub fn access_events(&self) -> R<String> {
        edge(|| with!(self, s => Ok(serde_json::Value::Array(s.access_events()).to_string())))
    }

    /// The account deletion grace period (default 30 days; SPEC §23).
    pub fn set_deletion_days(&self, days: i64) -> R<()> {
        edge(|| with!(self, s => { s.set_deletion_days(days); Ok(()) }))
    }

    /// Access-token lifetime (default 600 s).
    pub fn set_access_token_ttl_secs(&self, secs: i64) -> R<()> {
        edge(|| with!(self, s => { s.set_access_token_ttl_secs(secs); Ok(()) }))
    }

    /// How old a token may be for routes that need a recent sign-in (default 5 minutes).
    pub fn set_recent_token_ms(&self, ms: i64) -> R<()> {
        edge(|| with!(self, s => { s.set_recent_token_ms(ms); Ok(()) }))
    }
}

impl TestStream {
    /// The response status.
    pub fn status(&self) -> R<u16> {
        edge(|| with!(self, s => Ok(s.status())))
    }

    /// Doesn't wait: `kind` is `Data` (with `data`), `Pending` (nothing yet: poll again later) or
    /// `End` (closed).
    pub fn poll_chunk(&self) -> R<ffi::TestStreamPoll> {
        edge(|| {
            with!(self, s => {
                use futures::FutureExt as _;
                Ok(match s.next_chunk().now_or_never() {
                    None => ffi::TestStreamPoll { kind: ffi::TestStreamPollKind::Pending, data: Vec::new() },
                    Some(Ok(Some(d))) => ffi::TestStreamPoll { kind: ffi::TestStreamPollKind::Data, data: d },
                    Some(Ok(None)) => ffi::TestStreamPoll { kind: ffi::TestStreamPollKind::End, data: Vec::new() },
                    Some(Err(e)) => return Err(OvError::from(e)),
                })
            })
        })
    }

    /// Closes the stream.
    pub fn close(&self) -> R<()> {
        edge(|| with!(self, s => { s.close(); Ok(()) }))
    }
}
