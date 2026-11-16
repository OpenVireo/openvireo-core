//! Server-sent events from `{sync}/events` (SPEC §11), ported from `sync/events.ts`: the
//! incremental `text/event-stream` parser, the event types, and the pure parts of the reconnect
//! policy (what a status means, and the backoff). The stream loop itself is ov-sync's.

use ov_error::OvError;
use serde_json::Value;

use crate::error::error_from_response;
use crate::http::HttpResponse;

/// One event as framed on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawSseEvent {
    /// `event:` (`"message"` when absent).
    pub event: String,
    /// The `data:` lines joined with `\n`.
    pub data: String,
    /// The last `id:` seen on the stream.
    pub id: Option<String>,
}

/// Incremental `text/event-stream` parser (WHATWG rules: CR, LF or CRLF line ends, comments,
/// multi-line data, `retry`). Feed it chunks of bytes as they arrive; a UTF-8 character split
/// across chunks is fine, since lines only end at CR or LF.
#[derive(Clone, Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
    event: String,
    data: Vec<String>,
    id: Option<String>,
    started: bool,
    /// The last `retry:` value, in milliseconds.
    pub retry: Option<u64>,
}

impl SseParser {
    /// A new parser.
    pub fn new() -> Self {
        SseParser::default()
    }

    /// Adds a chunk and returns the events it completed.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<RawSseEvent> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut start = 0;
        while let Some(rel) = self.buf[start..].iter().position(|&b| b == b'\r' || b == b'\n') {
            let end = start + rel;
            let crlf = self.buf[end] == b'\r' && self.buf.get(end + 1) == Some(&b'\n');
            // A lone CR at the end of the buffer may be the first half of a CRLF.
            if self.buf[end] == b'\r' && end + 1 == self.buf.len() {
                break;
            }
            let mut line = &self.buf[start..end];
            if !self.started {
                // TextDecoder drops a leading byte-order mark.
                line = line.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(line);
                self.started = true;
            }
            let line = String::from_utf8_lossy(line).into_owned();
            start = end + if crlf { 2 } else { 1 };
            if let Some(ev) = self.line(&line) {
                out.push(ev);
            }
        }
        self.buf.drain(..start);
        out
    }

    fn line(&mut self, line: &str) -> Option<RawSseEvent> {
        if line.is_empty() {
            let ev = (!self.data.is_empty()).then(|| RawSseEvent {
                event: if self.event.is_empty() { "message".into() } else { self.event.clone() },
                data: self.data.join("\n"),
                id: self.id.clone(),
            });
            self.event.clear();
            self.data.clear();
            return ev;
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = match line.find(':') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => (line, ""),
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => self.event = value.to_string(),
            "data" => self.data.push(value.to_string()),
            "id" => self.id = Some(value.to_string()),
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                if let Ok(ms) = value.parse() {
                    self.retry = Some(ms);
                }
            }
            _ => {}
        }
        None
    }
}

crate::types::wire_enum! {
    /// What changed in an `access` event (SPEC §11, §23).
    AccessChange {
        /// Access to a vault was granted.
        Granted => "granted",
        /// Access to a vault was revoked.
        Revoked => "revoked",
        /// A key rotation started.
        Rotating => "rotating",
        /// A key rotation finished.
        Rotated => "rotated",
        /// Org membership changed.
        Org => "org",
        /// The account is scheduled for deletion; `at` is the erase date.
        DeletionScheduled => "deletion_scheduled",
        /// The account was deleted.
        AccountDeleted => "account_deleted",
    }
}

/// A parsed event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncEvent {
    /// A vault blob changed (JWT streams).
    Vault {
        /// Vault id.
        id: String,
        /// New etag.
        etag: Option<String>,
        /// New revision.
        revision: Option<i64>,
        /// The blob was deleted.
        deleted: bool,
    },
    /// The caller's access changed: refresh the JWT, list vaults again and reconnect.
    Access {
        /// The vault, or `None` for account- or org-wide changes.
        vault: Option<String>,
        /// What changed (`Other("")` when the server sent no string).
        change: AccessChange,
        /// The erase date of `deletion_scheduled`.
        at: Option<String>,
    },
    /// A legacy database changed (device-token streams).
    Database {
        /// Database id.
        id: String,
        /// New etag.
        etag: Option<String>,
        /// New revision.
        revision: Option<i64>,
        /// The database was deleted.
        deleted: bool,
    },
    /// Any other event, or data that isn't JSON.
    Unknown {
        /// The event name.
        event: String,
        /// The raw data.
        data: String,
    },
}

/// `toSyncEvent`: a typed event, or `None` for a `vault`/`database` event without an id.
pub fn to_sync_event(e: &RawSseEvent) -> Option<SyncEvent> {
    let unknown = || SyncEvent::Unknown { event: e.event.clone(), data: e.data.clone() };
    let Ok(j) = serde_json::from_str::<Value>(&e.data) else { return Some(unknown()) };
    let str_field = |k: &str| j.get(k).and_then(Value::as_str).map(str::to_string);
    match e.event.as_str() {
        "vault" | "database" => {
            let id = str_field("id").filter(|id| !id.is_empty())?;
            let etag = str_field("etag");
            let revision = j.get("revision").and_then(Value::as_i64);
            let deleted = j.get("deleted") == Some(&Value::Bool(true));
            Some(if e.event == "vault" {
                SyncEvent::Vault { id, etag, revision, deleted }
            } else {
                SyncEvent::Database { id, etag, revision, deleted }
            })
        }
        "access" => {
            // The SDK reads j.vault on any JSON value; `null` data would throw there.
            if j.is_null() {
                return None;
            }
            let change =
                str_field("change").map_or(AccessChange::Other(String::new()), |c| AccessChange::from(c.as_str()));
            Some(SyncEvent::Access { vault: str_field("vault"), change, at: str_field("at") })
        }
        _ => Some(unknown()),
    }
}

/// What to do with the status an event stream opened with (`EventStream.connect`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamStart {
    /// 2xx: read events; reset the backoff.
    Open,
    /// 401: the token was rejected. Retry after the backoff with a forced token refresh.
    RetryWithRefresh(OvError),
    /// A transient failure (5xx, 408, 429, redirects): retry after the backoff.
    Retry(OvError),
    /// A permanent client error (e.g. 404: no JWT routes on a legacy server): stop and close.
    Stop(OvError),
}

/// Classifies the response a stream opened with. For an error status, pass the body read so far
/// (or empty) to get the server's message.
pub fn classify_stream_status(res: &HttpResponse) -> StreamStart {
    match res.status {
        200..=299 => StreamStart::Open,
        401 => StreamStart::RetryWithRefresh(
            OvError::new(ov_error::OvErrorCode::Unauthorized, "event stream rejected the token").with_status(401),
        ),
        s if (300..400).contains(&s) && s != 304 => StreamStart::Retry(crate::error::check_redirect(res).unwrap_err()),
        s if (400..500).contains(&s) && s != 408 && s != 429 => StreamStart::Stop(error_from_response(res)),
        _ => StreamStart::Retry(error_from_response(res)),
    }
}

/// Exponential backoff for reconnecting (`initialRetryMs` 1000, doubling to `maxRetryMs` 60000).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backoff {
    initial_ms: u64,
    max_ms: u64,
    current_ms: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff::new(1000, 60_000)
    }
}

impl Backoff {
    /// A backoff starting at `initial_ms` and capped at `max_ms`.
    pub fn new(initial_ms: u64, max_ms: u64) -> Self {
        Backoff { initial_ms, max_ms, current_ms: initial_ms }
    }

    /// The delay before the next attempt after an error; doubles the following one, up to the cap.
    pub fn next_delay(&mut self, server_retry_ms: Option<u64>) -> u64 {
        if let Some(r) = server_retry_ms {
            self.current_ms = self.current_ms.max(r);
        }
        let delay = self.current_ms;
        self.current_ms = self.current_ms.saturating_mul(2).min(self.max_ms);
        delay
    }

    /// Back to the initial delay (after a stream opened, or an explicit reconnect).
    pub fn reset(&mut self) {
        self.current_ms = self.initial_ms;
    }

    /// The delay after a clean end of stream (e.g. the JWT expired): the server's `retry`, or 0.
    pub fn after_clean_end(server_retry_ms: Option<u64>) -> u64 {
        server_retry_ms.unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{request_header, response};
    use crate::sync::SyncApi;
    use ov_error::OvErrorCode;

    fn raw(event: &str, data: &str, id: Option<&str>) -> RawSseEvent {
        RawSseEvent { event: event.into(), data: data.into(), id: id.map(str::to_string) }
    }

    /// sync.test.ts "parses fields, multi-line data, comments, CRLF and split chunks".
    #[test]
    fn parses_fields_multiline_data_comments_crlf_and_split_chunks() {
        let mut p = SseParser::new();
        let mut evs = Vec::new();
        evs.extend(
            p.feed(b": keepalive\r\nevent: vault\r\ndata: {\"id\":\"v1\",\"etag\":\"e\",\"revision\":3}\r\n\r\n"),
        );
        evs.extend(p.feed(b"event: access\ndata: {\"vault\":null,"));
        evs.extend(p.feed(b"\"change\":\"org\"}\n\nretry: 5000\nid: 7\ndata: a\ndata: b\n\n"));
        evs.extend(p.feed(b"event: database\rdata: {\"id\":\"db\",\"deleted\":true}\r\r"));
        // a trailing CR may be half of a CRLF, so that event is only complete with the next chunk
        evs.extend(p.feed(b": ping\n"));
        assert_eq!(
            evs,
            [
                raw("vault", r#"{"id":"v1","etag":"e","revision":3}"#, None),
                raw("access", r#"{"vault":null,"change":"org"}"#, None),
                raw("message", "a\nb", Some("7")),
                raw("database", r#"{"id":"db","deleted":true}"#, Some("7")),
            ]
        );
        assert_eq!(p.retry, Some(5000));
        let typed: Vec<Option<SyncEvent>> = evs.iter().map(to_sync_event).collect();
        assert_eq!(
            typed,
            [
                Some(SyncEvent::Vault { id: "v1".into(), etag: Some("e".into()), revision: Some(3), deleted: false }),
                Some(SyncEvent::Access { vault: None, change: AccessChange::Org, at: None }),
                Some(SyncEvent::Unknown { event: "message".into(), data: "a\nb".into() }),
                Some(SyncEvent::Database { id: "db".into(), etag: None, revision: None, deleted: true }),
            ]
        );
    }

    #[test]
    fn byte_level_edge_cases() {
        let mut p = SseParser::new();
        // BOM, a UTF-8 character split across chunks, a CRLF split across chunks.
        let mut evs = p.feed(b"\xEF\xBB\xBFdata: caf\xC3");
        evs.extend(p.feed(b"\xA9\r"));
        evs.extend(p.feed(b"\n\r\n"));
        assert_eq!(evs, [raw("message", "café", None)]);
        // retry must be all digits; a field with no colon has an empty value.
        let evs = p.feed(b"retry: 5x\nretry\ndata\n\n");
        assert_eq!((evs, p.retry), (vec![raw("message", "", None)], None));
        // Byte-at-a-time feeding gives the same result.
        let stream = b"event: vault\r\ndata: {\"id\":\"v\"}\r\n\r\n";
        let mut p = SseParser::new();
        let evs: Vec<_> = stream.iter().flat_map(|b| p.feed(&[*b])).collect();
        assert_eq!(evs, [raw("vault", r#"{"id":"v"}"#, None)]);
    }

    #[test]
    fn typed_events() {
        assert_eq!(to_sync_event(&raw("vault", r#"{"etag":"e"}"#, None)), None);
        assert_eq!(to_sync_event(&raw("vault", r#"{"id":""}"#, None)), None);
        assert_eq!(
            to_sync_event(&raw("access", r#"{"vault":"v1","change":"deletion_scheduled","at":"2026-12-15"}"#, None)),
            Some(SyncEvent::Access {
                vault: Some("v1".into()),
                change: AccessChange::DeletionScheduled,
                at: Some("2026-12-15".into())
            })
        );
        assert_eq!(
            to_sync_event(&raw("access", r#"{"change":"new_thing"}"#, None)),
            Some(SyncEvent::Access { vault: None, change: AccessChange::Other("new_thing".into()), at: None })
        );
        assert_eq!(
            to_sync_event(&raw("vault", "not json", None)),
            Some(SyncEvent::Unknown { event: "vault".into(), data: "not json".into() })
        );
        assert_eq!(
            to_sync_event(&raw("vault", r#"{"id":"v","revision":"3","deleted":"yes"}"#, None)),
            Some(SyncEvent::Vault { id: "v".into(), etag: None, revision: None, deleted: false })
        );
    }

    /// sync.test.ts "sends the bearer token" and "sends only CORS-allowed headers, so browsers need
    /// no refused preflight".
    #[test]
    fn stream_request_sends_only_cors_allowed_headers() {
        let r = SyncApi::new("https://sync.example/api/v1").unwrap().build_events(Some("jwt-1"));
        assert_eq!(r.url, "https://sync.example/api/v1/events");
        assert_eq!(request_header(&r, "authorization"), Some("Bearer jwt-1"));
        assert_eq!(request_header(&r, "accept"), Some("text/event-stream"));
        let allowed = ["accept", "authorization", "content-type", "if-match", "if-none-match"];
        assert!(r.headers.iter().all(|(k, _)| allowed.contains(&k.to_ascii_lowercase().as_str())));
    }

    /// sync.test.ts "backs off after errors and forces a token refresh after a 401" and "stops on a
    /// permanent client error (e.g. 404: no JWT routes on a legacy server)".
    #[test]
    fn reconnect_policy() {
        assert_eq!(classify_stream_status(&response(200, &[], "")), StreamStart::Open);
        assert!(
            matches!(classify_stream_status(&response(503, &[], r#"{"error":"busy"}"#)), StreamStart::Retry(e) if e.message == "busy")
        );
        assert!(
            matches!(classify_stream_status(&response(401, &[], r#"{"error":"expired"}"#)), StreamStart::RetryWithRefresh(e) if e.status == Some(401))
        );
        assert!(
            matches!(classify_stream_status(&response(404, &[], r#"{"error":"not found"}"#)), StreamStart::Stop(e) if e.code == OvErrorCode::NotFound)
        );
        assert!(matches!(classify_stream_status(&response(429, &[], "")), StreamStart::Retry(_)));
        assert!(matches!(classify_stream_status(&response(408, &[], "")), StreamStart::Retry(_)));
        assert!(matches!(classify_stream_status(&response(302, &[], "")), StreamStart::Retry(_)));

        // 10 ms, then 20 ms, then capped at 25 ms.
        let mut b = Backoff::new(10, 25);
        assert_eq!([b.next_delay(None), b.next_delay(None), b.next_delay(None)], [10, 20, 25]);
        b.reset();
        assert_eq!(b.next_delay(None), 10);
        // A server `retry` raises the delay.
        assert_eq!(b.next_delay(Some(5000)), 5000);
        assert_eq!(Backoff::after_clean_end(None), 0);
        assert_eq!(Backoff::after_clean_end(Some(5000)), 5000);
        assert_eq!(Backoff::default().next_delay(None), 1000);
    }
}
