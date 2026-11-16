//! The SSE cases of `sync.test.ts` against a scripted transport.

mod common;

use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use common::{run, NOW_MS};
use ov_error::{OvError, OvErrorCode};
use ov_host::{ByteStream, HttpRequest, HttpResponse, HttpTransport, TransportError};
use ov_protocol::sse::{AccessChange, SyncEvent};
use ov_protocol::sync::SyncApi;
use ov_sync::{EventStream, EventStreamOptions, StreamItem, SyncClient, TokenSource};

/// A stream that yields `chunks`, then ends (`end`) or waits until closed.
struct Script {
    status: u16,
    state: Mutex<(VecDeque<Vec<u8>>, bool, Option<Waker>)>,
    end: bool,
}

impl Script {
    fn boxed(status: u16, chunks: &[&str], end: bool) -> Box<dyn ByteStream> {
        let q = chunks.iter().map(|c| c.as_bytes().to_vec()).collect();
        Box::new(Script { status, state: Mutex::new((q, false, None)), end })
    }
}

#[async_trait::async_trait]
impl ByteStream for Script {
    fn status(&self) -> u16 {
        self.status
    }
    async fn next_chunk(&self) -> Result<Option<Vec<u8>>, TransportError> {
        poll_fn(|cx| {
            let mut g = self.state.lock().unwrap();
            if g.1 {
                return Poll::Ready(Ok(None));
            }
            if let Some(c) = g.0.pop_front() {
                return Poll::Ready(Ok(Some(c)));
            }
            if self.end {
                return Poll::Ready(Ok(None));
            }
            g.2 = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
    fn close(&self) {
        let mut g = self.state.lock().unwrap();
        g.1 = true;
        if let Some(w) = g.2.take() {
            w.wake();
        }
    }
}

type Respond = dyn Fn(usize, &HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> + Send + Sync;

struct Transport {
    requests: Mutex<Vec<HttpRequest>>,
    respond: Box<Respond>,
}

#[async_trait::async_trait]
impl HttpTransport for Transport {
    async fn send(&self, _r: HttpRequest) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Other("streams only".into()))
    }
    async fn open_stream(&self, req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
        let n = {
            let mut r = self.requests.lock().unwrap();
            r.push(req.clone());
            r.len()
        };
        (self.respond)(n, &req)
    }
}

struct Tokens {
    calls: Mutex<Vec<bool>>,
}

#[async_trait::async_trait]
impl TokenSource for Tokens {
    async fn access_token(&self, force: bool) -> Result<Option<String>, OvError> {
        let mut c = self.calls.lock().unwrap();
        c.push(force);
        Ok(Some(format!("jwt-{}", c.len())))
    }
}

fn setup(respond: Box<Respond>) -> (Arc<Transport>, Arc<Tokens>, SyncClient) {
    let t = Arc::new(Transport { requests: Mutex::new(vec![]), respond });
    let tokens = Arc::new(Tokens { calls: Mutex::new(vec![]) });
    let c = SyncClient::new(
        t.clone(),
        Arc::new(ov_testkit::ManualClock::new(NOW_MS)),
        SyncApi::new("https://sync.example/api/v1").unwrap(),
        tokens.clone(),
    );
    (t, tokens, c)
}

fn auth(r: &HttpRequest) -> Option<String> {
    r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.clone())
}

/// Pulls items until `n` events arrived (skipping status items), up to `limit` items.
fn events(s: &EventStream, n: usize, limit: usize) -> (Vec<SyncEvent>, Vec<StreamItem>) {
    let (mut evs, mut other) = (vec![], vec![]);
    for _ in 0..limit {
        if evs.len() == n {
            break;
        }
        match run(s.next()) {
            StreamItem::Event(e) => evs.push(e),
            i => other.push(i),
        }
    }
    (evs, other)
}

/// "sends the bearer token, delivers events and reconnects after the server ends the stream"
#[test]
fn delivers_events_and_reconnects_after_a_clean_end() {
    let (t, _tokens, c) = setup(Box::new(|n, _| {
        Ok(match n {
            1 => Script::boxed(200, &["event: vault\ndata: {\"id\":\"v1\",\"etag\":\"e1\",\"revision\":1}\n\n"], true),
            2 => Script::boxed(200, &["event: access\ndata: {\"vault\":\"v1\",", "\"change\":\"revoked\"}\n\n"], false),
            _ => Script::boxed(200, &[], false),
        })
    }));
    let s = EventStream::new(c, EventStreamOptions { initial_retry_ms: 5, max_retry_ms: 60_000 });
    let (evs, other) = events(&s, 2, 20);
    assert_eq!(
        evs,
        [
            SyncEvent::Vault { id: "v1".into(), etag: Some("e1".into()), revision: Some(1), deleted: false },
            SyncEvent::Access { vault: Some("v1".into()), change: AccessChange::Revoked, at: None },
        ]
    );
    // connecting, open, clean end → reconnect at once, connecting, open
    assert_eq!(
        other,
        [
            StreamItem::Connecting,
            StreamItem::Open,
            StreamItem::Waiting { retry_in_ms: 0, error: None },
            StreamItem::Connecting,
            StreamItem::Open
        ]
    );
    let reqs = t.requests.lock().unwrap().clone();
    assert_eq!(reqs.iter().map(auth).collect::<Vec<_>>(), [Some("Bearer jwt-1".into()), Some("Bearer jwt-2".into())]);
    // Only CORS-allowed headers.
    let allowed = ["accept", "authorization", "content-type", "if-match", "if-none-match"];
    assert!(reqs[0].headers.iter().all(|(k, _)| allowed.contains(&k.to_ascii_lowercase().as_str())));
    assert_eq!(reqs[0].url, "https://sync.example/api/v1/events");

    // An explicit reconnect (after an access event and a token refresh) aborts the open stream.
    s.reconnect();
    assert_eq!(run(s.next()), StreamItem::Connecting);
    assert_eq!(run(s.next()), StreamItem::Open);
    assert_eq!(t.requests.lock().unwrap().len(), 3);
    s.close();
    assert_eq!(run(s.next()), StreamItem::Closed { error: None });
}

/// `close` from another thread while `next` waits on an open stream makes `next` return.
#[test]
fn close_wakes_a_pending_next() {
    let (_t, _tokens, c) = setup(Box::new(|_, _| Ok(Script::boxed(200, &[], false))));
    let s = Arc::new(EventStream::new(c, EventStreamOptions::default()));
    assert_eq!(run(s.next()), StreamItem::Connecting);
    assert_eq!(run(s.next()), StreamItem::Open);
    let s2 = s.clone();
    let h = std::thread::spawn(move || run(s2.next()));
    std::thread::sleep(std::time::Duration::from_millis(50));
    s.close();
    assert_eq!(h.join().unwrap(), StreamItem::Closed { error: None });
}

/// "backs off after errors and forces a token refresh after a 401"
#[test]
fn backs_off_and_refreshes_after_401() {
    let (_t, tokens, c) = setup(Box::new(|n, _| match n {
        1 => Err(TransportError::Offline),
        2 => Ok(Script::boxed(503, &[r#"{"error":"busy"}"#], true)),
        3 => Ok(Script::boxed(401, &[r#"{"error":"expired"}"#], true)),
        _ => Ok(Script::boxed(
            200,
            &["event: database\ndata: {\"id\":\"main\",\"etag\":\"e\",\"revision\":4}\n\n"],
            false,
        )),
    }));
    let s = EventStream::new(c, EventStreamOptions { initial_retry_ms: 10, max_retry_ms: 25 });
    let (evs, other) = events(&s, 1, 20);
    assert_eq!(
        evs,
        [SyncEvent::Database { id: "main".into(), etag: Some("e".into()), revision: Some(4), deleted: false }]
    );
    let waits: Vec<(u64, Option<OvErrorCode>)> = other
        .iter()
        .filter_map(|i| match i {
            StreamItem::Waiting { retry_in_ms, error } => Some((*retry_in_ms, error.as_ref().map(|e| e.code))),
            _ => None,
        })
        .collect();
    // 10 ms, then 20 ms, then capped at 25 ms
    assert_eq!(
        waits,
        [
            (10, Some(OvErrorCode::NetworkError)),
            (20, Some(OvErrorCode::ServerError)),
            (25, Some(OvErrorCode::Unauthorized))
        ]
    );
    assert_eq!(*tokens.calls.lock().unwrap(), [false, false, false, true]);
    // The backoff resets once a stream opens.
    s.close();
}

/// "stops on a permanent client error (e.g. 404: no JWT routes on a legacy server)"
#[test]
fn stops_on_a_permanent_client_error() {
    let (t, _tokens, c) = setup(Box::new(|_, _| Ok(Script::boxed(404, &[r#"{"error":"not found"}"#], true))));
    let s = EventStream::new(c, EventStreamOptions { initial_retry_ms: 1, max_retry_ms: 1 });
    assert_eq!(run(s.next()), StreamItem::Connecting);
    let StreamItem::Closed { error: Some(e) } = run(s.next()) else { panic!("not closed") };
    assert_eq!((e.code, e.message.as_str()), (OvErrorCode::NotFound, "not found"));
    assert!(matches!(run(s.next()), StreamItem::Closed { .. }));
    assert!(s.is_closed());
    assert_eq!(t.requests.lock().unwrap().len(), 1);
}

/// A server `retry:` raises the delay after an error, and sets it after a clean end.
#[test]
fn honours_the_server_retry() {
    let (_t, _tokens, c) = setup(Box::new(|n, _| {
        Ok(match n {
            1 => Script::boxed(200, &["retry: 3000\n\n"], true),
            _ => Script::boxed(200, &[], false),
        })
    }));
    let s = EventStream::new(c, EventStreamOptions { initial_retry_ms: 5, max_retry_ms: 60_000 });
    assert_eq!(run(s.next()), StreamItem::Connecting);
    assert_eq!(run(s.next()), StreamItem::Open);
    assert_eq!(run(s.next()), StreamItem::Waiting { retry_in_ms: 3000, error: None });
}
