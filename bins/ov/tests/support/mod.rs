//! The TS CLI tests' world (`packages/sdk/test/helpers/world.ts`) on W2-E's in-memory servers, a
//! harness that runs `ov` in-process like `cli.test.ts` does, and a loopback relay that lets the
//! `ov` binary (and the TS CLI, for the golden diff) reach the servers over HTTP.

#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ov_core::api::*;
use ov_core::host::{Clock, HttpRequest, Method};
use ov_testkit::servers::TestServers;
use ov_testkit::ManualClock;

/// The SDK tests' cheap KDF (`m=19456, t=2`).
pub const KDF: KdfOverrides = KdfOverrides { m: Some(19456), t: Some(2), p: Some(1) };
/// Alice's master password (world.ts).
pub const PASSWORD: &str = "correct horse ü";
/// Alice's email.
pub const ALICE: &str = "alice@example.com";

fn nc() -> CancelToken {
    CancelToken::new()
}

/// The world.ts setup: alice with org "Acme", org vaults "Team Infra" (GitHub, Deploy/Database) and
/// "Private" (Bank), and two service accounts on "Team Infra" (read and write).
pub struct World {
    pub servers: TestServers,
    pub alice: Account,
    pub secret_key: String,
    pub vault_id: String,
    pub other_vault_id: String,
    pub read_token: String,
    pub write_token: String,
}

fn fields(pairs: &[(&str, &str)]) -> Vec<FieldInput> {
    pairs.iter().map(|(k, v)| FieldInput { name: (*k).into(), value: v.as_bytes().to_vec(), protected: None }).collect()
}

fn add(v: &Vault, group: String, pairs: &[(&str, &str)]) {
    v.add_entry(group, EntryInput { fields: fields(pairs), ..Default::default() }).unwrap();
}

/// `makeWorld()` on servers whose clock starts at `now_ms`. The sync server checks the auth
/// server's live vault access (as world.ts's `syncFetch` does).
pub async fn make_world(now_ms: i64) -> World {
    let servers = TestServers::new(Arc::new(ManualClock::new(now_ms)));
    servers.set_live_access(true);
    let client = OvClient::new(
        ClientConfig {
            device: DeviceInfo { id: None, name: "test".into(), platform: Platform::Web },
            offline: false,
            server: None,
        },
        servers.host(),
    );
    let alice = client.connect(servers.issuer(), nc()).await.unwrap();
    let new = alice
        .register(
            RegisterInput {
                email: ALICE.into(),
                password: PASSWORD.as_bytes().to_vec(),
                kdf: Some(KDF),
                trust_device: true,
            },
            nc(),
        )
        .await
        .unwrap();
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let vault = alice.create_vault("Team Infra".into(), Some(org.id.clone()), nc()).await.unwrap();
    add(
        &vault,
        vault.root_group_id(),
        &[("Title", "GitHub"), ("UserName", "ci"), ("Password", "s3cret"), ("URL", "https://github.com")],
    );
    let deploy = vault.add_group(None, "Deploy".into()).unwrap();
    add(
        &vault,
        deploy,
        &[("Title", "Database"), ("UserName", "app"), ("Password", "pg-pa$$word"), ("Notes", "multi\nline")],
    );
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    let other = alice.create_vault("Private".into(), Some(org.id.clone()), nc()).await.unwrap();
    add(&other, other.root_group_id(), &[("Title", "Bank"), ("Password", "nope")]);
    other.sync(SyncOptions::default(), nc()).await.unwrap();

    let sa = |name: &str, role: VaultRole| NewServiceAccount {
        name: name.into(),
        vaults: vec![VaultGrantRequest { vault_id: vault.id(), role }],
        expires_at: None,
        secret_name: None,
    };
    let read = alice.create_service_account(org.id.clone(), sa("ci-read", VaultRole::Read), nc()).await.unwrap();
    let write = alice.create_service_account(org.id.clone(), sa("ci-write", VaultRole::Write), nc()).await.unwrap();
    World {
        secret_key: String::from_utf8(new.secret_key.clone()).unwrap(),
        vault_id: vault.id(),
        other_vault_id: other.id(),
        read_token: String::from_utf8(read.token).unwrap(),
        write_token: String::from_utf8(write.token).unwrap(),
        alice,
        servers,
    }
}

impl World {
    /// `editBetweenGetAndPut`: once `skip_gets` GETs of the Team Infra blob have passed, the next one
    /// is followed by another device's upload that sets `fields` on the entry `title` (so the PUT
    /// after it gets a 412). Returns a flag that turns true when it fired.
    pub async fn edit_between_get_and_put(
        &self,
        title: &str,
        pairs: &[(&str, &str)],
        skip_gets: usize,
    ) -> Arc<Mutex<bool>> {
        let before = self.servers.vault_blob(&self.vault_id).unwrap();
        // The other device's edit, made on alice's copy and uploaded, then the server put back.
        let v = self.alice.open_vault(self.vault_id.clone(), nc()).await.unwrap();
        let id = v.entries(false).into_iter().find(|e| e.title == title).unwrap().id;
        v.edit_entry(id, EntryInput { fields: fields(pairs), ..Default::default() }).unwrap();
        v.sync(SyncOptions::default(), nc()).await.unwrap();
        let edited = self.servers.vault_blob(&self.vault_id).unwrap();
        self.servers.put_vault_blob(&self.vault_id, &before.data);
        let fired = Arc::new(Mutex::new(false));
        let (flag, vault_id, seen) = (fired.clone(), self.vault_id.clone(), Arc::new(Mutex::new(0usize)));
        self.servers.set_after_get(Some(Arc::new(move |s: &TestServers, id: &str| {
            if id != vault_id || *flag.lock().unwrap() {
                return;
            }
            let mut n = seen.lock().unwrap();
            *n += 1;
            if *n > skip_gets {
                *flag.lock().unwrap() = true;
                s.put_vault_blob(id, &edited.data);
            }
        })));
        fired
    }

    /// PUTs the sync server answered so far.
    pub fn puts(&self) -> usize {
        self.servers.requests().iter().filter(|r| r.method == Method::Put).count()
    }

    /// Alice's user id.
    pub fn alice_id(&self) -> String {
        self.servers.user_id(ALICE).unwrap()
    }
}

// --------------------------------------------------------------------------------- harness

/// A writer the harness reads back.
#[derive(Clone, Default)]
pub struct Buf(pub Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// What one `ov` run returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Answers a question (`hidden` or not), recording it.
pub type Answer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Runs `ov` in-process on the world's servers, as `cli.test.ts`'s `openvireo()` helper does: the
/// environment is `PATH`, `OPENVIREO_CONFIG_DIR=<dir>/config` and `env`.
pub struct Cli {
    pub servers: TestServers,
    pub dir: PathBuf,
}

impl Cli {
    pub fn new(servers: &TestServers, name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ov-cli-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Cli { servers: servers.clone(), dir }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    pub async fn run(&self, argv: &[&str], env: &[(&str, &str)], stdin: Option<&str>, prompt: Option<Answer>) -> Run {
        let (out, err) = (Buf::default(), Buf::default());
        let mut vars: ov_cli::session::Env = [
            ("PATH".to_string(), std::env::var("PATH").unwrap_or_default()),
            ("OPENVIREO_CONFIG_DIR".to_string(), self.dir.join("config").to_string_lossy().into_owned()),
        ]
        .into_iter()
        .collect();
        for (k, v) in env {
            vars.insert((*k).into(), (*v).into());
        }
        let input = stdin.unwrap_or("").to_string();
        let mut io = ov_cli::cli::Io {
            env: vars,
            stdout: Arc::new(Mutex::new(Box::new(out.clone()))),
            stderr: Arc::new(Mutex::new(Box::new(err.clone()))),
            stdin: Box::new(move || Ok(input.clone())),
            prompt: prompt.map(|p| -> ov_cli::cli::Prompt { Box::new(move |q: &str, _hidden| Ok(p(q))) }),
            http: Some(self.servers.http()),
            clock: Some(self.servers.clock() as Arc<dyn Clock>),
        };
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let code = ov_cli::cli::main(&argv, &mut io).await;
        Run { code, stdout: out.text(), stderr: err.text() }
    }

    /// No extra environment, no stdin, no terminal.
    pub async fn ov(&self, argv: &[&str], env: &[(&str, &str)]) -> Run {
        self.run(argv, env, None, None).await
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ----------------------------------------------------------------------------------- relay

/// Serves `servers` on `127.0.0.1:<port>` for clients that put a request's real URL in the
/// `x-ov-relay-url` header (`ov` debug builds with `OPENVIREO_TEST_RELAY`, and the TS CLI driver of
/// the golden diff). HTTP/1.1, one request per connection, `Content-Length` bodies only. With
/// `follow_wall_clock`, the servers' clock is moved to the wall clock before each request, so
/// clients on the system clock agree with it.
pub async fn serve_relay(servers: TestServers, follow_wall_clock: bool) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let servers = servers.clone();
            tokio::spawn(async move {
                let _ = relay_one(stream, servers, follow_wall_clock).await;
            });
        }
    });
    (url, handle)
}

fn wall_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

async fn relay_one(mut stream: tokio::net::TcpStream, servers: TestServers, follow: bool) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = match first.next().unwrap_or("") {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        _ => Method::Get,
    };
    let mut headers = Vec::new();
    let mut url = None;
    let mut length = 0usize;
    for line in lines.filter(|l| !l.is_empty()) {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        match k.to_ascii_lowercase().as_str() {
            "x-ov-relay-url" => url = Some(v),
            "content-length" => length = v.parse().unwrap_or(0),
            "host" | "connection" | "accept-encoding" | "keep-alive" => {}
            _ => headers.push((k, v)),
        }
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if follow {
        servers.clock().set(wall_ms());
    }
    let req = HttpRequest {
        method,
        url: url.unwrap_or_default(),
        headers,
        body: if length > 0 || matches!(method, Method::Post | Method::Put | Method::Patch) {
            Some(body)
        } else {
            None
        },
        keepalive: false,
    };
    let res = match servers.http().send(req).await {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("relay: {e:?}");
            ov_core::host::HttpResponse { status: 502, headers: vec![], body: msg.into_bytes() }
        }
    };
    let head = method == Method::Head;
    let mut out = format!("HTTP/1.1 {} X\r\n", res.status);
    for (k, v) in &res.headers {
        let length = k.eq_ignore_ascii_case("content-length");
        if (head || !length) && !k.eq_ignore_ascii_case("connection") {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    let body = if head { Vec::new() } else { res.body.clone() };
    if !head || !res.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    stream.write_all(out.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}
