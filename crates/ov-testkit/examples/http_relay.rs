//! The in-memory auth and sync servers ([`TestServers`]) on a loopback HTTP relay, for binding
//! smoke tests that run the platform's own HTTP transport (the Python package's `UrllibTransport`
//! and `HttpxTransport`, the Kotlin hosts) against them. The servers start empty: no accounts.
//!
//! A client sends every request to `http://127.0.0.1:<port><path>` with the request's real URL
//! (`https://auth.test/…`, `https://sync.test/…`) in the `x-ov-relay-url` header, the same
//! convention as `ov`'s `OPENVIREO_TEST_RELAY` relay (`bins/ov/tests/support`). A request with
//! `Accept: text/event-stream` goes through `open_stream` and its chunks are written as they
//! arrive (close-delimited body), so streaming crosses a real socket. Before each request the
//! servers' clock is moved to the wall clock, so clients on the system clock agree with it.
//!
//! Prints one JSON line, `{"relay": "http://127.0.0.1:<port>", "issuer": "https://auth.test", …}`,
//! then serves until stdin closes. HTTP/1.1, one request per connection, `Content-Length` request
//! bodies only.
//!
//! Test tooling only: `cargo run -p ov-testkit --example http_relay` (`cargo xtask python --smoke`
//! builds and starts it).

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use ov_host::{HttpRequest, HttpResponse, Method, TransportError};
use ov_testkit::servers::{block_on, TestServers, DEVICE_TOKEN, PAIRING_CODE};
use ov_testkit::ManualClock;

/// The header holding a request's real URL.
const RELAY_URL_HEADER: &str = "x-ov-relay-url";

fn wall_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn main() {
    let servers = TestServers::new(Arc::new(ManualClock::new(wall_ms())));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let relay = format!("http://{}", listener.local_addr().expect("local address"));
    let info = serde_json::json!({
        "relay": relay,
        "issuer": servers.issuer(),
        "api": servers.api_url(),
        "sync": servers.sync_url(),
        "deviceToken": DEVICE_TOKEN,
        "pairingCode": PAIRING_CODE,
    });
    let mut out = std::io::stdout();
    writeln!(out, "{info}").expect("stdout");
    out.flush().expect("stdout");

    let s = servers.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let s = s.clone();
            std::thread::spawn(move || {
                let _ = relay_one(conn, &s);
            });
        }
    });

    // Serve until the caller closes our stdin (or kills us).
    let mut line = String::new();
    while std::io::stdin().lock().read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
        line.clear();
    }
}

/// One parsed request: the core's `HttpRequest`, and whether the client asked for a stream.
fn read_request(conn: &mut TcpStream) -> std::io::Result<Option<(HttpRequest, bool)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let method = match lines.next().unwrap_or("").split(' ').next().unwrap_or("") {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        _ => return Ok(None),
    };
    let mut headers = Vec::new();
    let mut url = None;
    let mut length = 0usize;
    let mut stream = false;
    for line in lines.filter(|l| !l.is_empty()) {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        match k.to_ascii_lowercase().as_str() {
            RELAY_URL_HEADER => url = Some(v),
            "content-length" => length = v.parse().unwrap_or(0),
            // What the HTTP client adds for the hop; the servers never see them.
            "host" | "connection" | "accept-encoding" | "keep-alive" | "user-agent" => {}
            "accept" => {
                stream |= v.contains("text/event-stream");
                headers.push((k, v));
            }
            _ => headers.push((k, v)),
        }
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let Some(url) = url else {
        let res = text(400, &format!("missing {RELAY_URL_HEADER}"));
        write_response(conn, method, &res)?;
        return Ok(None);
    };
    let has_body = length > 0 || matches!(method, Method::Post | Method::Put | Method::Patch);
    Ok(Some((HttpRequest { method, url, headers, body: has_body.then_some(body), keepalive: false }, stream)))
}

fn relay_one(mut conn: TcpStream, servers: &TestServers) -> std::io::Result<()> {
    let Some((req, stream)) = read_request(&mut conn)? else { return Ok(()) };
    servers.clock().set(wall_ms());
    let method = req.method;
    if !stream {
        let res = block_on(servers.http().send(req)).unwrap_or_else(|e| transport_failure(&e));
        return write_response(&mut conn, method, &res);
    }
    let body = match block_on(servers.http().open_stream(req)) {
        Ok(b) => b,
        Err(e) => return write_response(&mut conn, method, &transport_failure(&e)),
    };
    let head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.status()
    );
    conn.write_all(head.as_bytes())?;
    conn.flush()?;
    while let Ok(Some(c)) = block_on(body.next_chunk()) {
        if conn.write_all(&c).and_then(|()| conn.flush()).is_err() {
            // The client went away.
            body.close();
            return Ok(());
        }
    }
    conn.shutdown(std::net::Shutdown::Both)
}

/// The servers refused the request at the transport level (an unknown host is `Offline`): 502,
/// with the reason in `x-ov-relay-error`.
fn transport_failure(e: &TransportError) -> HttpResponse {
    let mut res = text(502, &format!("relay: {e:?}"));
    res.headers.push(("x-ov-relay-error".into(), format!("{e:?}")));
    res
}

fn text(status: u16, msg: &str) -> HttpResponse {
    HttpResponse { status, headers: vec![("Content-Type".into(), "text/plain".into())], body: msg.as_bytes().to_vec() }
}

fn write_response(conn: &mut TcpStream, method: Method, res: &HttpResponse) -> std::io::Result<()> {
    let head = method == Method::Head;
    let mut out = format!("HTTP/1.1 {} X\r\n", res.status);
    for (k, v) in &res.headers {
        let length = k.eq_ignore_ascii_case("content-length");
        if (head || !length) && !k.eq_ignore_ascii_case("connection") {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    let body: &[u8] = if head { &[] } else { &res.body };
    if !head || !res.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    conn.write_all(out.as_bytes())?;
    conn.write_all(body)?;
    conn.flush()?;
    conn.shutdown(std::net::Shutdown::Write)
}
