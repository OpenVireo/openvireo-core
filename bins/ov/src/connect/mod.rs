//! `ov connect`: the REST server for vault items (port of `packages/connect`, which ran on the TS
//! SDK as `openvireo-connect`). `ov connect [serve]` runs it, configured by the environment
//! ([`config`]); `ov connect token` makes a bearer token; `ov connect version` prints the version.
//!
//! - [`config`]: the environment
//! - [`tokens`]: connect's own bearer tokens
//! - [`handler`]: the routes, as a pure `handle(&State, Request<Bytes>) -> Response<Bytes>`
//! - [`server`]: hyper, TLS, the connection limits and graceful shutdown

pub mod config;
pub mod handler;
pub mod server;
pub mod tokens;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ov_core::api::{CancelToken, ClientConfig, DeviceInfo, OvClient, Platform, ServiceAccount};
use ov_core::host::HttpTransport;
use ov_error::{OvError, OvErrorCode};

use crate::cli::{CliError, Io};
use crate::run::Out;

use self::config::Config;
use self::handler::{Options, State};
use self::tokens::{new_token, Access};

/// How `ov connect` names itself in its usage, version and log lines.
pub const PROG: &str = "ov connect";

/// The User-Agent connect sends to the auth and sync servers.
pub fn user_agent() -> String {
    format!("openvireo-connect/{}", crate::session::VERSION)
}

/// A future that resolves when the server should stop.
pub type Stop = Pin<Box<dyn Future<Output = ()> + Send>>;

/// `connectUsage("ov connect")`.
pub fn usage() -> String {
    let col = " ".repeat(PROG.len() + 15);
    let row = |cmd: &str, what: &str| format!("  {:<w$}{what}\n", format!("{PROG} {cmd}"), w = col.len() - 2);
    format!(
        "Usage:\n{}  {PROG} token [--name N] [--vault V]... [--write]\n{col}create a bearer token; prints it and its config entry\n{}",
        row("[serve]", "run the REST server (configured by environment, see README)"),
        row("version", "print the version"),
    )
}

fn write(out: &Out, s: &str) {
    use std::io::Write as _;
    if let Ok(mut w) = out.lock() {
        let _ = w.write_all(s.as_bytes());
        let _ = w.flush();
    }
}

/// `new Date().toISOString()`.
fn iso_now() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let s = crate::plan::iso_from_unix_s(i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    format!("{}.{:03}Z", &s[..s.len() - 5], d.subsec_millis())
}

/// SIGINT or SIGTERM (Unix), Ctrl-C (Windows).
async fn until_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `ov connect …` (`connectMain`). `stop` replaces the signals (tests).
pub async fn main(args: &[String], io: &mut Io, stop: Option<Stop>) -> Result<i32, CliError> {
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => ("serve", &[][..]),
    };
    match cmd {
        "-h" | "--help" | "help" => {
            write(&io.stdout, &usage());
            Ok(0)
        }
        "version" | "--version" => {
            write(&io.stdout, &format!("{PROG} {}\n", crate::session::VERSION));
            Ok(0)
        }
        "token" => token(rest, io),
        "serve" => {
            if !rest.is_empty() {
                return Err(OvError::new(
                    OvErrorCode::InvalidRequest,
                    format!("unexpected arguments: {}", rest.join(" ")),
                )
                .into());
            }
            serve(io, stop).await
        }
        _ => {
            write(&io.stderr, &usage());
            Ok(2)
        }
    }
}

/// The options of `ov connect token`.
const TOKEN_OPTS: &[crate::args::Opt] = &[
    crate::args::Opt { long: "name", short: None, kind: crate::args::Kind::Str },
    crate::args::Opt { long: "vault", short: None, kind: crate::args::Kind::Multi },
    crate::args::Opt { long: "write", short: None, kind: crate::args::Kind::Bool },
];

fn token(args: &[String], io: &mut Io) -> Result<i32, CliError> {
    if let Some(msg) = crate::args::node_check(args, TOKEN_OPTS) {
        return Err(CliError::Usage(msg));
    }
    let (mut name, mut vaults, mut write_access) = (None::<String>, Vec::new(), false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (key, inline) = match a.strip_prefix("--").filter(|k| !k.is_empty()) {
            Some(k) => match k.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (k, None),
            },
            None => {
                let pos = if a == "--" { it.next().unwrap_or(a) } else { a };
                return Err(CliError::Usage(format!(
                    "Unexpected argument '{pos}'. This command does not take positional arguments"
                )));
            }
        };
        match key {
            "write" => write_access = true,
            "name" => name = inline.or_else(|| it.next().cloned()),
            "vault" => vaults.extend(inline.or_else(|| it.next().cloned())),
            other => return Err(CliError::Usage(format!("unknown option --{other}"))),
        }
    }
    let access = if write_access { Access::Write } else { Access::Read };
    let (token, entry) = new_token(name.as_deref().unwrap_or("default"), &vaults, access)?;
    write(&io.stdout, &format!("{}\n", token.as_str()));
    let entry = serde_json::to_string(&entry).map_err(|e| OvError::internal(e.to_string()))?;
    write(
        &io.stderr,
        &format!(
            "Give the token above to the client and add this entry to OPENVIREO_CONNECT_TOKENS_FILE (the token itself is not stored):\n{entry}\n"
        ),
    );
    Ok(0)
}

/// Signs in with the configured SA token, sending connect's User-Agent: the process's Host for
/// `env`, with `http` and `clock` replacing reqwest and the system clock when given (tests).
pub async fn sign_in(
    config: &Config,
    env: &crate::session::Env,
    http: Option<Arc<dyn HttpTransport>>,
    clock: Option<Arc<dyn ov_core::host::Clock>>,
) -> Result<ServiceAccount, OvError> {
    let http: Arc<dyn HttpTransport> = match http {
        Some(h) => h,
        None => Arc::new(crate::http::ReqwestTransport::with_user_agent(&user_agent()).map_err(OvError::from)?),
    };
    let store = Arc::new(crate::session::store_for(env));
    let host = crate::host::cli_host(env, store, Some(http), clock)?;
    let device = DeviceInfo { id: None, name: "openvireo-connect".into(), platform: Platform::Cli };
    let client = OvClient::new(ClientConfig { device, offline: false, server: None }, host);
    ServiceAccount::from_token(client, config.sa_token.as_bytes().to_vec(), CancelToken::new()).await
}

async fn serve(io: &mut Io, stop: Option<Stop>) -> Result<i32, CliError> {
    let config = Config::from_env(&io.env)?;
    let stop = stop.unwrap_or_else(|| Box::pin(until_signal()));
    let sa = sign_in(&config, &io.env, io.http.clone(), io.clock.clone()).await?;
    let err = io.stderr.clone();
    let log: handler::Log = Arc::new(move |line: &str| write(&err, &format!("{} {line}\n", iso_now())));
    let state = State::new(
        sa.clone(),
        config.tokens.clone(),
        Options { cache_ttl: config.cache_ttl, log: Some(log), ..Options::default() },
    );
    let running = match server::start(&config, state).await {
        Ok(r) => r,
        Err(e) => {
            sa.close();
            return Err(e.into());
        }
    };
    let n = config.tokens.len();
    write(&io.stderr, &format!("{PROG} listening on {} ({n} token{})\n", running.url, if n == 1 { "" } else { "s" }));
    stop.await;
    running.shutdown().await;
    sa.close();
    Ok(0)
}
