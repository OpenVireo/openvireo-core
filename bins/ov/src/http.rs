//! The `HttpTransport` for `ov`: reqwest with rustls. The CLI has no platform app around it, so
//! this is the one place where the core's HTTP is done in Rust (rust-core.md, Phase 6).
//!
//! As host.rs requires: no redirects (the SDK uses `redirect: "error"`), no cookies, and only the
//! headers the core gives plus `User-Agent: openvireo/<version>` (what the TS CLI sends). Header
//! values are never logged.

use std::error::Error as _;
use std::sync::atomic::{AtomicBool, Ordering};

use ov_core::host::{ByteStream, HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
use tokio::sync::Mutex;

use crate::session::VERSION;

/// reqwest-backed [`HttpTransport`].
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// A transport with the CLI's `User-Agent`.
    pub fn new() -> Result<Self, TransportError> {
        Self::with_user_agent(&format!("openvireo/{VERSION}"))
    }

    /// A transport with another `User-Agent` (`ov connect` sends `openvireo-connect/<version>`).
    pub fn with_user_agent(user_agent: &str) -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| TransportError::Other(format!("can't start the HTTP client: {e}")))?;
        Ok(ReqwestTransport { client })
    }

    fn build(&self, req: HttpRequest) -> reqwest::RequestBuilder {
        let method = match req.method {
            Method::Get => reqwest::Method::GET,
            Method::Head => reqwest::Method::HEAD,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Patch => reqwest::Method::PATCH,
            Method::Delete => reqwest::Method::DELETE,
        };
        let mut b = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            b = b.header(k, v);
        }
        if let Some(body) = req.body {
            b = b.body(body);
        }
        b
    }
}

fn headers(r: &reqwest::Response) -> Vec<(String, String)> {
    r.headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect()
}

/// Maps a reqwest error to the contract's [`TransportError`]. The text never holds header values
/// (reqwest errors carry the URL at most).
fn transport_error(e: reqwest::Error) -> TransportError {
    if e.is_timeout() {
        return TransportError::Timeout;
    }
    let mut chain = String::new();
    let mut source = e.source();
    while let Some(s) = source {
        chain.push_str(": ");
        chain.push_str(&s.to_string());
        source = s.source();
    }
    let lower = chain.to_lowercase();
    if lower.contains("certificate") || lower.contains("tls") || lower.contains("handshake") {
        return TransportError::Tls(chain.trim_start_matches(": ").to_string());
    }
    if e.is_connect() {
        return TransportError::Offline;
    }
    TransportError::Other(format!("{}{chain}", e.without_url()))
}

#[async_trait::async_trait]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let r = self.build(req).send().await.map_err(transport_error)?;
        let status = r.status().as_u16();
        let headers = headers(&r);
        let body = r.bytes().await.map_err(transport_error)?.to_vec();
        Ok(HttpResponse { status, headers, body })
    }

    async fn open_stream(&self, req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
        let r = self.build(req).send().await.map_err(transport_error)?;
        Ok(Box::new(ReqwestStream {
            status: r.status().as_u16(),
            response: Mutex::new(Some(r)),
            closed: AtomicBool::new(false),
        }))
    }
}

/// An open response body, read chunk by chunk.
struct ReqwestStream {
    status: u16,
    response: Mutex<Option<reqwest::Response>>,
    closed: AtomicBool,
}

#[async_trait::async_trait]
impl ByteStream for ReqwestStream {
    fn status(&self) -> u16 {
        self.status
    }

    async fn next_chunk(&self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut guard = self.response.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            *guard = None;
        }
        let Some(r) = guard.as_mut() else { return Ok(None) };
        match r.chunk().await.map_err(transport_error)? {
            Some(c) => Ok(Some(c.to_vec())),
            None => {
                *guard = None;
                Ok(None)
            }
        }
    }

    fn close(&self) {
        // Dropping the response closes the connection. A read in flight holds the lock; it
        // finishes, and the next `next_chunk` sees the flag and drops the response.
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.response.try_lock() {
            *guard = None;
        }
    }
}

/// The header carrying the real URL of a request sent through the test relay.
pub const RELAY_URL_HEADER: &str = "x-ov-relay-url";

/// Debug builds only: with `OPENVIREO_TEST_RELAY=http://127.0.0.1:<port>`, every request goes to
/// that loopback relay instead, with its real URL in [`RELAY_URL_HEADER`]. The black-box tests and
/// the golden diff (`tests/golden/`) use it to run the `ov` binary against the in-memory test
/// servers (`https://auth.test`, `https://sync.test`), which have no network address. Release
/// builds don't have it.
#[cfg(debug_assertions)]
pub fn test_relay(env: &crate::session::Env) -> Option<std::sync::Arc<dyn HttpTransport>> {
    let base = env.get("OPENVIREO_TEST_RELAY").filter(|u| u.starts_with("http://127.0.0.1:"))?;
    let inner = ReqwestTransport::new().ok()?;
    Some(std::sync::Arc::new(RelayTransport { inner, base: base.trim_end_matches('/').to_string() }))
}

/// Release builds: no relay.
#[cfg(not(debug_assertions))]
pub fn test_relay(_env: &crate::session::Env) -> Option<std::sync::Arc<dyn HttpTransport>> {
    None
}

/// See [`test_relay`].
#[cfg(debug_assertions)]
struct RelayTransport {
    inner: ReqwestTransport,
    base: String,
}

#[cfg(debug_assertions)]
impl RelayTransport {
    fn rewrite(&self, mut req: HttpRequest) -> HttpRequest {
        let path = req.url.split_once("://").and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()));
        let original = std::mem::replace(&mut req.url, format!("{}{}", self.base, path.unwrap_or_else(|| "/".into())));
        req.headers.push((RELAY_URL_HEADER.to_string(), original));
        req
    }
}

#[cfg(debug_assertions)]
#[async_trait::async_trait]
impl HttpTransport for RelayTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.inner.send(self.rewrite(req)).await
    }

    async fn open_stream(&self, req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
        self.inner.open_stream(self.rewrite(req)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A one-shot HTTP server on loopback that answers `response` and returns the request it got.
    fn serve_once(response: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 8192];
            let n = s.read(&mut buf).unwrap();
            s.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (url, handle)
    }

    fn req(method: Method, url: String) -> HttpRequest {
        HttpRequest {
            method,
            url,
            headers: vec![("X-Test".into(), "1".into())],
            body: Some(b"hi".to_vec()),
            keepalive: false,
        }
    }

    #[tokio::test]
    async fn sends_and_does_not_follow_redirects() {
        let (url, server) = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno",
        );
        let t = ReqwestTransport::new().unwrap();
        let r = t.send(req(Method::Post, format!("{url}/x"))).await.unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.header("location"), Some("http://127.0.0.1:1/"));
        assert_eq!(r.body, b"no");
        let got = server.join().unwrap().to_lowercase();
        assert!(got.starts_with("post /x http/1.1"), "{got}");
        assert!(got.contains("x-test: 1"));
        assert!(got.contains(&format!("user-agent: openvireo/{VERSION}")));
    }

    #[tokio::test]
    async fn ov_connect_sends_its_own_user_agent() {
        let (url, server) = serve_once("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        let t = ReqwestTransport::with_user_agent(&crate::connect::user_agent()).unwrap();
        assert_eq!(t.send(req(Method::Get, url)).await.unwrap().status, 204);
        let got = server.join().unwrap().to_lowercase();
        assert!(got.contains(&format!("user-agent: openvireo-connect/{VERSION}\r\n")), "{got}");
    }

    #[tokio::test]
    async fn streams_chunks() {
        let (url, server) =
            serve_once("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: 1\n\n");
        let t = ReqwestTransport::new().unwrap();
        let s = t.open_stream(req(Method::Get, url)).await.unwrap();
        assert_eq!(s.status(), 200);
        let mut all = Vec::new();
        while let Some(c) = s.next_chunk().await.unwrap() {
            all.extend(c);
        }
        assert_eq!(all, b"data: 1\n\n");
        s.close();
        assert_eq!(s.next_chunk().await.unwrap(), None);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn a_refused_connection_is_offline() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let t = ReqwestTransport::new().unwrap();
        let e = t.send(req(Method::Get, format!("http://127.0.0.1:{port}/"))).await.unwrap_err();
        assert_eq!(e, TransportError::Offline);
    }
}
