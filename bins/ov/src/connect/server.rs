//! Runs the [`handler`](super::handler) on hyper (port of `startConnect` and `toNodeListener` in
//! `packages/connect/src/server.ts`): HTTP/1.1 on a TCP listener, optionally TLS (rustls on ring).
//!
//! What TS didn't have: a header read timeout (30 s), a TLS handshake timeout (10 s), a cap on
//! concurrent connections ([`MAX_CONNECTIONS`]; more wait in the listen backlog), request bodies
//! read only up to the limit and wiped after the response, and a graceful shutdown that lets
//! requests in flight finish (up to [`DRAIN`]).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_LENGTH;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use ov_error::{OvError, OvErrorCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::rustls;
use zeroize::Zeroizing;

use super::config::{Config, Tls};
use super::handler::{handle, BodyTooLarge, State};

/// The most connections served at once.
pub const MAX_CONNECTIONS: usize = 512;
/// How long a client has to send the request head.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client has to finish the TLS handshake.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long shutdown waits for requests in flight.
pub const DRAIN: Duration = Duration::from_secs(10);

/// A listening server.
pub struct Running {
    /// `http(s)://<host>:<port>`, with the port actually bound.
    pub url: String,
    /// The bound address.
    pub addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Stops accepting, lets requests in flight finish (up to [`DRAIN`]) and returns.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

fn invalid(message: String) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, message)
}

/// The TLS acceptor for the PEM certificate chain and key.
fn tls_acceptor(tls: &Tls) -> Result<tokio_rustls::TlsAcceptor, OvError> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(&tls.cert)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| invalid(format!("can't read OPENVIREO_CONNECT_TLS_CERT {}: {e}", tls.cert)))?;
    if certs.is_empty() {
        return Err(invalid(format!("no certificate in OPENVIREO_CONNECT_TLS_CERT {}", tls.cert)));
    }
    let key = PrivateKeyDer::from_pem_file(&tls.key)
        .map_err(|e| invalid(format!("can't read OPENVIREO_CONNECT_TLS_KEY {}: {e}", tls.key)))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|b| b.with_no_client_auth().with_single_cert(certs, key))
        .map_err(|e| invalid(format!("bad TLS certificate or key: {e}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Listens on the configured address and serves `state` until [`Running::shutdown`].
pub async fn start(config: &Config, state: Arc<State>) -> Result<Running, OvError> {
    let tls = config.tls.as_ref().map(tls_acceptor).transpose()?;
    let listener = TcpListener::bind((config.host.as_str(), config.port))
        .await
        .map_err(|e| invalid(format!("can't listen on {}:{}: {e}", config.url_host(), config.port)))?;
    let addr = listener.local_addr().map_err(|e| OvError::internal(e.to_string()))?;
    let url = format!("{}://{}:{}", if tls.is_some() { "https" } else { "http" }, config.url_host(), addr.port());
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(accept_loop(listener, tls, state, stop_rx));
    Ok(Running { url, addr, stop, task })
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}

async fn accept_loop(
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    state: Arc<State>,
    mut stop: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = tokio::select! {
            p = slots.clone().acquire_owned() => match p { Ok(p) => p, Err(_) => break },
            () = stopped(&mut stop) => break,
        };
        let stream = tokio::select! {
            r = listener.accept() => match r {
                Ok((s, _)) => s,
                Err(_) => {
                    // Out of file descriptors and the like: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = stopped(&mut stop) => break,
        };
        let (tls, state, stop) = (tls.clone(), state.clone(), stop.clone());
        tokio::spawn(async move {
            match tls {
                None => serve(stream, state, stop).await,
                Some(acceptor) => {
                    if let Ok(Ok(s)) = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        serve(s, state, stop).await;
                    }
                }
            }
            drop(permit);
        });
    }
    drop(listener);
    // Wait for the connections in flight (each holds a slot).
    let all = u32::try_from(MAX_CONNECTIONS).unwrap_or(u32::MAX);
    let _ = tokio::time::timeout(DRAIN, slots.acquire_many(all)).await;
}

async fn serve<I>(io: I, state: Arc<State>, mut stop: watch::Receiver<bool>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(respond(&state, req).await) }
    });
    let mut builder = http1::Builder::new();
    builder.timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
    let conn = builder.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        () = stopped(&mut stop) => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(DRAIN, conn.as_mut()).await;
        }
    }
}

/// Reads the body (up to the limit), runs the handler, and hands hyper the response.
async fn respond(state: &State, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let max = state.max_body();
    let (parts, mut body) = req.into_parts();
    let declared =
        parts.headers.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u128>().ok());
    let mut too_large = declared.is_some_and(|n| n > max as u128);
    let mut buf = Zeroizing::new(Vec::new());
    if !too_large {
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else { break };
            if let Ok(data) = frame.into_data() {
                if buf.len() + data.len() > max {
                    too_large = true;
                    break;
                }
                buf.extend_from_slice(&data);
            }
        }
    }
    // The handler's copy is wiped when the request is dropped.
    let mut req = Request::from_parts(parts, Bytes::from_owner(buf));
    if too_large {
        req.extensions_mut().insert(BodyTooLarge);
    }
    handle(state, req).await.map(Full::new)
}
