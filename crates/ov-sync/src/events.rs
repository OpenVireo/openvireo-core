//! The `{sync}/events` stream (SPEC §11, TS `EventStream`): connects with the bearer token, parses
//! `vault`, `access` and legacy `database` events, and reconnects: right after a clean end (the
//! server closes JWT streams at the token's `exp`), with exponential backoff after errors, with a
//! forced token refresh after a 401, and never after a permanent client error (e.g. 404 from a
//! legacy server without JWT routes).
//!
//! The Host has no timer, so the stream is pulled: [`EventStream::next`] returns
//! [`StreamItem::Waiting`] with the delay, the caller waits that long (or not, to reconnect early)
//! and calls `next` again. [`close`](EventStream::close) and [`reconnect`](EventStream::reconnect)
//! may be called from another task while `next` is pending; the open stream is closed so it returns.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ov_error::{OvError, OvErrorCode};
use ov_host::{ByteStream, HttpResponse, TransportError};
use ov_protocol::sse::{classify_stream_status, to_sync_event, Backoff, SseParser, StreamStart, SyncEvent};

use crate::client::SyncClient;

/// The most of an error body read to get the server's message.
const MAX_ERROR_BODY: usize = 64 * 1024;

/// One thing the stream reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamItem {
    /// About to connect (the next `next` call connects).
    Connecting,
    /// Connected; events follow.
    Open,
    /// An event.
    Event(SyncEvent),
    /// Not connected: wait `retry_in_ms`, then call `next` again. `error` is why (`None` after a
    /// clean end).
    Waiting {
        /// The delay before reconnecting.
        retry_in_ms: u64,
        /// What went wrong.
        error: Option<OvError>,
    },
    /// Closed for good: by [`EventStream::close`], or after a permanent client error (`error`).
    Closed {
        /// The permanent error, if that was the reason.
        error: Option<OvError>,
    },
}

/// Backoff settings (TS `initialRetryMs` 1000, `maxRetryMs` 60000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventStreamOptions {
    /// The first delay after an error.
    pub initial_retry_ms: u64,
    /// The cap.
    pub max_retry_ms: u64,
}

impl Default for EventStreamOptions {
    fn default() -> Self {
        EventStreamOptions { initial_retry_ms: 1000, max_retry_ms: 60_000 }
    }
}

enum Phase {
    /// Report `Connecting` next.
    Idle,
    /// Connect on the next call.
    Connect,
    /// Reading the open stream.
    Reading,
}

struct Inner {
    phase: Phase,
    closed: bool,
    closed_error: Option<OvError>,
    reconnect: bool,
    force_refresh: bool,
    backoff: Backoff,
    queue: VecDeque<StreamItem>,
    stream: Option<Arc<dyn ByteStream>>,
    parser: SseParser,
    /// Bumped by close/reconnect so a read that was in flight is discarded.
    run: u64,
}

/// An event stream. Create it with [`EventStream::new`] and pull items with [`next`](Self::next).
pub struct EventStream {
    client: SyncClient,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EventStream { .. }")
    }
}

impl EventStream {
    /// A stream on `client`'s `events` route. Nothing is sent until the first [`next`](Self::next).
    pub fn new(client: SyncClient, opts: EventStreamOptions) -> Self {
        EventStream {
            client,
            inner: Mutex::new(Inner {
                phase: Phase::Idle,
                closed: false,
                closed_error: None,
                reconnect: false,
                force_refresh: false,
                backoff: Backoff::new(opts.initial_retry_ms, opts.max_retry_ms),
                queue: VecDeque::new(),
                stream: None,
                parser: SseParser::new(),
                run: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Drops the current connection and connects again on the next call, with the backoff reset
    /// (e.g. after an `access` event and a token refresh).
    pub fn reconnect(&self) {
        let mut g = self.lock();
        if g.closed {
            return;
        }
        g.reconnect = true;
        g.run += 1;
        g.queue.clear();
        if let Some(s) = g.stream.take() {
            s.close();
        }
    }

    /// Closes the stream; `next` returns [`StreamItem::Closed`] from now on.
    pub fn close(&self) {
        let mut g = self.lock();
        g.closed = true;
        g.run += 1;
        g.queue.clear();
        if let Some(s) = g.stream.take() {
            s.close();
        }
    }

    /// Whether the stream is closed.
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// The next item.
    pub async fn next(&self) -> StreamItem {
        loop {
            let (stream, run) = {
                let mut g = self.lock();
                if g.closed {
                    return StreamItem::Closed { error: g.closed_error.clone() };
                }
                if g.reconnect {
                    g.reconnect = false;
                    g.backoff.reset();
                    g.stream = None;
                    g.phase = Phase::Idle;
                }
                if let Some(item) = g.queue.pop_front() {
                    return item;
                }
                match g.phase {
                    Phase::Idle => {
                        g.phase = Phase::Connect;
                        return StreamItem::Connecting;
                    }
                    Phase::Connect => (None, g.run),
                    Phase::Reading => (g.stream.clone(), g.run),
                }
            };
            match stream {
                None => {
                    if let Some(item) = self.connect(run).await {
                        return item;
                    }
                }
                Some(s) => {
                    if let Some(item) = self.read(s, run).await {
                        return item;
                    }
                }
            }
        }
    }

    /// Schedules a reconnect after an error: `Waiting` with the backoff delay.
    fn backoff(g: &mut Inner, error: OvError) -> StreamItem {
        let delay = g.backoff.next_delay(g.parser.retry);
        g.stream = None;
        g.phase = Phase::Idle;
        StreamItem::Waiting { retry_in_ms: delay, error: Some(error) }
    }

    async fn connect(&self, run: u64) -> Option<StreamItem> {
        let force = std::mem::take(&mut self.lock().force_refresh);
        let opened = match self.client.token_source().access_token(force).await {
            Ok(token) => {
                let req = self.client.api().build_events(token.as_deref());
                self.client.http().open_stream(req).await.map_err(OvError::from)
            }
            Err(e) => Err(e),
        };
        let mut stream: Arc<dyn ByteStream> = match opened {
            Ok(s) => Arc::from(s),
            Err(e) => {
                let mut g = self.lock();
                if g.run != run || g.closed {
                    return None;
                }
                g.parser = SseParser::new();
                return Some(Self::backoff(&mut g, e));
            }
        };
        let status = stream.status();
        let start = if (200..300).contains(&status) {
            StreamStart::Open
        } else {
            let body = read_error_body(&mut stream).await;
            classify_stream_status(&HttpResponse { status, headers: Vec::new(), body })
        };
        let mut g = self.lock();
        if g.run != run || g.closed {
            stream.close();
            return None;
        }
        g.parser = SseParser::new();
        Some(match start {
            StreamStart::Open => {
                g.backoff.reset();
                g.stream = Some(stream);
                g.phase = Phase::Reading;
                StreamItem::Open
            }
            StreamStart::RetryWithRefresh(e) => {
                g.force_refresh = true;
                Self::backoff(&mut g, e)
            }
            StreamStart::Retry(e) => Self::backoff(&mut g, e),
            StreamStart::Stop(e) => {
                g.closed = true;
                g.closed_error = Some(e.clone());
                StreamItem::Closed { error: Some(e) }
            }
        })
    }

    async fn read(&self, stream: Arc<dyn ByteStream>, run: u64) -> Option<StreamItem> {
        let chunk = stream.next_chunk().await;
        let mut guard = self.lock();
        let g = &mut *guard;
        if g.run != run || g.closed {
            return None;
        }
        match chunk {
            Ok(Some(bytes)) => {
                let events = g.parser.feed(&bytes);
                for ev in events.iter().filter_map(to_sync_event) {
                    g.queue.push_back(StreamItem::Event(ev));
                }
                g.queue.pop_front()
            }
            Ok(None) => {
                // Clean end (e.g. the JWT expired): reconnect right away with a fresh token
                g.stream = None;
                g.phase = Phase::Idle;
                Some(StreamItem::Waiting { retry_in_ms: Backoff::after_clean_end(g.parser.retry), error: None })
            }
            Err(TransportError::Cancelled) => {
                g.stream = None;
                g.phase = Phase::Idle;
                Some(StreamItem::Waiting {
                    retry_in_ms: g.backoff.next_delay(g.parser.retry),
                    error: Some(OvError::new(OvErrorCode::Aborted, "the event stream was cancelled")),
                })
            }
            Err(e) => Some(Self::backoff(g, e.into())),
        }
    }
}

async fn read_error_body(stream: &mut Arc<dyn ByteStream>) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < MAX_ERROR_BODY {
        match stream.next_chunk().await {
            Ok(Some(c)) => body.extend_from_slice(&c),
            _ => break,
        }
    }
    stream.close();
    body
}
