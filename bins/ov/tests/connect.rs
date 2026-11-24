//! `ov connect`: `packages/connect/test/connect.test.ts` ported onto W2-E's in-memory servers (the
//! world.ts setup in `support`), plus what only the Rust server has: two PUTs racing on one vault,
//! and HTTPS.
//!
//! Most cases drive the handler directly (`handle(&State, Request<Bytes>)`, no sockets), as the TS
//! test drove `createConnectHandler`; the listener tests go through `server::start` on loopback.
//! The TLS certificate in `tests/fixtures/connect-{ca,cert,key}.pem` is a throwaway test CA and a
//! `localhost` / `127.0.0.1` leaf valid until 2126, made with openssl (`ov` has no certificate
//! generator and doesn't get one for a test). The keys protect nothing.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::Bytes;
use hyper::{Request, Response};
use ov_cli::cli::Io;
use ov_cli::connect::config::Config;
use ov_cli::connect::handler::{handle, Options, State};
use ov_cli::connect::server;
use ov_cli::connect::tokens::{hash_token, new_token, parse_tokens, Access, ConnectToken};
use ov_core::api::{CancelToken, ClientConfig, DeviceInfo, OvClient, Platform, ServiceAccount};
use ov_core::host::{Clock, Method};
use ov_testkit::servers::Server;
use serde_json::{json, Value};
use support::{make_world, Buf, Cli, World};

const NOW_MS: i64 = 1_794_700_800_000;
const READ: &str = "ov_ct_read";
const WRITE: &str = "ov_ct_write";
const SCOPED: &str = "ov_ct_scoped";

fn tokens() -> Vec<ConnectToken> {
    let t = |name: &str, token: &str, vault: &str, access| ConnectToken {
        name: name.into(),
        sha256: hash_token(token),
        vaults: vec![vault.into()],
        access,
    };
    vec![
        t("eso", READ, "*", Access::Read),
        t("app", WRITE, "Team Infra", Access::Write),
        t("other", SCOPED, "Private", Access::Write),
    ]
}

async fn sa(w: &World, token: &str) -> ServiceAccount {
    let client = OvClient::new(
        ClientConfig {
            device: DeviceInfo { id: None, name: "connect".into(), platform: Platform::Cli },
            offline: false,
            server: None,
        },
        w.servers.host(),
    );
    ServiceAccount::from_token(client, token.as_bytes().to_vec(), CancelToken::new()).await.unwrap()
}

struct Res {
    status: u16,
    body: Value,
    text: String,
    headers: hyper::HeaderMap,
}

impl Res {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// The TS test's `client()`: requests to a handler on `sa` with the test tokens.
struct Client {
    state: Arc<State>,
    log: Arc<Mutex<Vec<String>>>,
}

#[derive(Default)]
struct Req<'a> {
    token: Option<&'a str>,
    body: Option<Value>,
    accept: Option<&'a str>,
}

impl Client {
    fn new(sa: ServiceAccount, cache_ttl: Duration) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        let opts = Options {
            cache_ttl,
            log: Some(Arc::new(move |l: &str| sink.lock().unwrap().push(l.to_string()))),
            ..Options::default()
        };
        Client { state: State::new(sa, tokens(), opts), log }
    }

    async fn call(&self, method: &str, path: &str, p: Req<'_>) -> Res {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(t) = p.token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        if let Some(a) = p.accept {
            b = b.header("accept", a);
        }
        let body = match &p.body {
            Some(v) => {
                b = b.header("content-type", "application/json");
                Bytes::from(serde_json::to_vec(v).unwrap())
            }
            None => Bytes::new(),
        };
        res(handle(&self.state, b.body(body).unwrap()).await)
    }

    async fn get(&self, path: &str, token: &str) -> Res {
        self.call("GET", path, Req { token: Some(token), ..Req::default() }).await
    }

    async fn put(&self, path: &str, token: &str, body: Value) -> Res {
        self.call("PUT", path, Req { token: Some(token), body: Some(body), ..Req::default() }).await
    }
}

fn res(r: Response<Bytes>) -> Res {
    let text = String::from_utf8(r.body().to_vec()).unwrap();
    Res {
        status: r.status().as_u16(),
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
        headers: r.headers().clone(),
    }
}

fn sync_calls(w: &World) -> Vec<Method> {
    w.servers.requests().into_iter().filter(|r| r.server == Server::Sync).map(|r| r.method).collect()
}

fn blob_len(w: &World) -> usize {
    w.servers.vault_blob(&w.vault_id).unwrap().data.len()
}

// --------------------------------------------------------------------------- REST API

#[tokio::test]
async fn needs_one_of_its_own_bearer_tokens_except_for_health() {
    let w = make_world(NOW_MS).await;
    let c = Client::new(sa(&w, &w.read_token).await, Duration::ZERO);
    assert_eq!(c.call("GET", "/health", Req::default()).await.body, json!({ "status": "ok" }));
    assert_eq!(c.call("GET", "/ready", Req::default()).await.status, 200);
    for token in [None, Some(""), Some("nope"), Some(w.read_token.as_str())] {
        let r = c.call("GET", "/v1/vaults", Req { token, ..Req::default() }).await;
        assert_eq!((r.status, r.body["code"].as_str()), (401, Some("unauthorized")), "{token:?}");
        assert_eq!(r.header("www-authenticate"), Some("Bearer"));
    }
    assert_eq!(c.get("/v2/x", READ).await.status, 404);
}

#[tokio::test]
async fn lists_vaults_and_items_without_values_the_token_may_use() {
    let w = make_world(NOW_MS).await;
    let c = Client::new(sa(&w, &w.read_token).await, Duration::ZERO);
    assert_eq!(
        c.get("/v1/vaults", READ).await.text,
        format!("{{\"vaults\":[{{\"id\":\"{}\",\"name\":\"Team Infra\",\"role\":\"read\"}}]}}", w.vault_id)
    );
    assert_eq!(c.get(&format!("/v1/vaults/{}", w.vault_id), READ).await.body["name"], "Team Infra");
    // The token is scoped to another vault: the SA's vault looks like it doesn't exist.
    assert_eq!(c.get("/v1/vaults", SCOPED).await.body, json!({ "vaults": [] }));
    let scoped = c.get("/v1/vaults/Team%20Infra/items", SCOPED).await;
    assert_eq!((scoped.status, scoped.body["error"].as_str()), (404, Some("vault \"Team Infra\" not found")));
    // Not shared with the SA at all.
    assert_eq!(c.get(&format!("/v1/vaults/{}/items", w.other_vault_id), READ).await.status, 404);
    let items = c.get("/v1/vaults/Team%20Infra/items", READ).await;
    let mut titles: Vec<&str> =
        items.body["items"].as_array().unwrap().iter().map(|i| i["title"].as_str().unwrap()).collect();
    titles.sort();
    assert_eq!(titles, ["Database", "GitHub"]);
    assert!(!items.text.contains("s3cret"));
}

#[tokio::test]
async fn returns_an_item_with_its_values_or_one_field() {
    let w = make_world(NOW_MS).await;
    let c = Client::new(sa(&w, &w.read_token).await, Duration::ZERO);
    let gh = c.get("/v1/vaults/Team%20Infra/items/GitHub", READ).await;
    assert_eq!(gh.status, 200);
    assert_eq!(gh.header("cache-control"), Some("no-store"));
    assert_eq!(gh.header("content-type"), Some("application/json"));
    let f = &gh.body["fields"];
    assert_eq!(
        (f["Title"].as_str(), f["UserName"].as_str(), f["URL"].as_str()),
        (Some("GitHub"), Some("ci"), Some("https://github.com"))
    );
    assert_eq!(f["Password"], "s3cret");
    // TS key order.
    assert!(
        gh.text.starts_with("{\"id\":\"")
            && gh.text.contains("\",\"title\":\"GitHub\",\"group\":[],\"fields\":{\"Title\""),
        "{}",
        gh.text
    );
    let id = gh.body["id"].as_str().unwrap();
    assert_eq!(c.get(&format!("/v1/vaults/{}/items/{id}", w.vault_id), READ).await.body["title"], "GitHub");
    let db = c.get("/v1/vaults/Team%20Infra/items/Deploy/Database?field=password", READ).await;
    assert_eq!(db.text, r#"{"value":"pg-pa$$word"}"#);
    let text = c
        .call(
            "GET",
            "/v1/vaults/Team%20Infra/items/Deploy/Database?field=notes",
            Req { token: Some(READ), accept: Some("text/plain"), ..Req::default() },
        )
        .await;
    assert_eq!((text.text.as_str(), text.header("content-type")), ("multi\nline", Some("text/plain; charset=utf-8")));
    let both = c
        .call(
            "GET",
            "/v1/vaults/Team%20Infra/items/Deploy/Database?field=user",
            Req { token: Some(READ), accept: Some("text/plain, application/json"), ..Req::default() },
        )
        .await;
    assert_eq!(both.body, json!({ "value": "app" }));
    let nope = c.get("/v1/vaults/Team%20Infra/items/Deploy/Database?field=nope", READ).await;
    assert_eq!((nope.status, nope.body["error"].as_str()), (404, Some("field \"nope\" not found")));
    let missing = c.get("/v1/vaults/Team%20Infra/items/Nope", READ).await;
    assert_eq!((missing.status, missing.body["code"].as_str()), (404, Some("not_found")));
    assert_eq!(c.get("/v1/vaults/Team%20Infra/items/%zz", READ).await.status, 400);
    // Methods.
    let post = c.call("POST", "/v1/vaults/Team%20Infra/items", Req { token: Some(READ), ..Req::default() }).await;
    assert_eq!((post.status, post.header("allow")), (405, Some("GET")));
    let del =
        c.call("DELETE", "/v1/vaults/Team%20Infra/items/GitHub", Req { token: Some(READ), ..Req::default() }).await;
    assert_eq!((del.status, del.header("allow")), (405, Some("GET, PUT")));
    let post = c.call("POST", "/v1/vaults", Req { token: Some(READ), ..Req::default() }).await;
    assert_eq!((post.status, post.header("allow")), (405, Some("GET")));
    assert_eq!(
        c.call("DELETE", "/v1/vaults/Team%20Infra", Req { token: Some(READ), ..Req::default() }).await.status,
        404
    );
}

#[tokio::test]
async fn rejects_writes_from_a_read_only_token_or_a_read_only_service_account() {
    let w = make_world(NOW_MS).await;
    let (before, puts) = (blob_len(&w), w.puts());
    let ro = Client::new(sa(&w, &w.write_token).await, Duration::ZERO)
        .put("/v1/vaults/Team%20Infra/items/GitHub", READ, json!({ "fields": { "password": "x" } }))
        .await;
    assert_eq!((ro.status, ro.body["error"].as_str()), (403, Some("token \"eso\" is read-only")));
    let sa_ro = Client::new(sa(&w, &w.read_token).await, Duration::ZERO)
        .put("/v1/vaults/Team%20Infra/items/GitHub", WRITE, json!({ "fields": { "password": "x" } }))
        .await;
    assert_eq!((sa_ro.status, sa_ro.body["code"].as_str()), (403, Some("forbidden")));
    assert!(sa_ro.body["error"].as_str().unwrap().contains("can only read"), "{}", sa_ro.text);
    assert_eq!(blob_len(&w), before);
    assert_eq!(w.puts(), puts);
}

#[tokio::test]
async fn creates_and_updates_items_with_the_conditional_put_merging_on_412() {
    let w = make_world(NOW_MS).await;
    let c = Client::new(sa(&w, &w.write_token).await, Duration::ZERO);
    let bad = c.put("/v1/vaults/Team%20Infra/items/X", WRITE, json!({ "fields": { "a": 1 } })).await;
    assert_eq!((bad.status, bad.body["code"].as_str()), (400, Some("invalid_request")));
    let missing =
        c.put("/v1/vaults/Team%20Infra/items/Missing?create=false", WRITE, json!({ "fields": { "a": "1" } })).await;
    assert_eq!(missing.status, 404);

    let created = c
        .put(
            "/v1/vaults/Team%20Infra/items/Apps/Api",
            WRITE,
            json!({ "fields": { "username": "svc", "token": "t-1" }, "protected": { "username": true } }),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.text);
    assert_eq!(created.body["group"], json!(["Apps"]));
    let mut protected: Vec<&str> =
        created.body["protected"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    protected.sort();
    assert_eq!(protected, ["Password", "UserName", "token"]);
    assert!(created.body["fields"].get("token").is_none(), "the response doesn't echo protected values");

    let fired = w.edit_between_get_and_put("GitHub", &[("URL", "https://github.example")], 0).await;
    let puts = w.puts();
    let upd =
        c.put("/v1/vaults/Team%20Infra/items/GitHub", WRITE, json!({ "fields": { "password": "via-connect" } })).await;
    w.servers.set_after_get(None);
    assert_eq!((upd.status, *fired.lock().unwrap()), (200, true), "{}", upd.text);
    assert!(w.puts() - puts >= 2, "the first PUT got a 412");
    let r = Client::new(sa(&w, &w.read_token).await, Duration::ZERO);
    let after = r.get("/v1/vaults/Team%20Infra/items/GitHub", READ).await.body["fields"].clone();
    assert_eq!(
        (after["Password"].as_str(), after["URL"].as_str()),
        (Some("via-connect"), Some("https://github.example"))
    );
    assert_eq!(r.get("/v1/vaults/Team%20Infra/items/Apps/Api?field=token", READ).await.body["value"], "t-1");
    let log = c.log.lock().unwrap().clone();
    assert!(log.contains(&"PUT /v1/vaults/Team%20Infra/items/GitHub 200 token=app".to_string()), "{log:?}");
    assert!(log.contains(&"PUT /v1/vaults/Team%20Infra/items/Missing 404 token=app".to_string()), "{log:?}");
    assert!(!log.join("\n").contains("via-connect"));
}

#[tokio::test]
async fn uses_its_cached_copy_until_the_ttl_then_a_head_check() {
    let w = make_world(NOW_MS).await;
    let reader = sa(&w, &w.read_token).await;
    let c = Client::new(reader.clone(), Duration::from_secs(60));
    c.get("/v1/vaults/Team%20Infra/items/GitHub", READ).await;
    let n = sync_calls(&w).len();
    c.get("/v1/vaults/Team%20Infra/items/GitHub", READ).await;
    assert_eq!(sync_calls(&w).len(), n);
    let ttl0 = Client::new(reader, Duration::ZERO);
    ttl0.get("/v1/vaults/Team%20Infra/items/GitHub", READ).await;
    assert_eq!(sync_calls(&w)[n..], [Method::Head]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_puts_to_one_vault_both_land() {
    let w = make_world(NOW_MS).await;
    let c = Arc::new(Client::new(sa(&w, &w.write_token).await, Duration::ZERO));
    // Warm the SA's copy, so both PUTs start from the same one.
    c.get("/v1/vaults/Team%20Infra/items", WRITE).await;
    let mut tasks = Vec::new();
    for i in 0..6 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let field = format!("f{i}");
            c.put("/v1/vaults/Team%20Infra/items/GitHub", WRITE, json!({ "fields": { field: format!("v{i}") } }))
                .await
                .status
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 200);
    }
    let r = Client::new(sa(&w, &w.read_token).await, Duration::ZERO);
    let fields = r.get("/v1/vaults/Team%20Infra/items/GitHub", READ).await.body["fields"].clone();
    for i in 0..6 {
        assert_eq!(fields[format!("f{i}")], format!("v{i}"), "{fields}");
    }
}

// --------------------------------------------------------------------------- the listener

fn io_for(w: &World, env: &[(&str, &str)]) -> (Io, Buf, Buf) {
    let (out, err) = (Buf::default(), Buf::default());
    let io = Io {
        env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        stdout: Arc::new(Mutex::new(Box::new(out.clone()))),
        stderr: Arc::new(Mutex::new(Box::new(err.clone()))),
        stdin: Box::new(|| Ok(String::new())),
        prompt: None,
        http: Some(w.servers.http()),
        clock: Some(w.servers.clock() as Arc<dyn Clock>),
    };
    (io, out, err)
}

fn http_client(ca: Option<&str>) -> reqwest::Client {
    let mut b = reqwest::Client::builder().no_proxy();
    if let Some(pem) = ca {
        b = b.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap());
    }
    b.build().unwrap()
}

async fn start(w: &World, env: &[(&str, &str)]) -> (server::Running, ServiceAccount) {
    let (io, _, _) = io_for(w, env);
    let config = Config::from_env(&io.env).unwrap();
    let sa = ov_cli::connect::sign_in(&config, &io.env, io.http.clone(), io.clock.clone()).await.unwrap();
    let state =
        State::new(sa.clone(), config.tokens.clone(), Options { cache_ttl: config.cache_ttl, ..Options::default() });
    (server::start(&config, state).await.unwrap(), sa)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_over_http_with_start() {
    let w = make_world(NOW_MS).await;
    let (token, entry) = new_token("eso", &["Team Infra".into()], Access::Read).unwrap();
    let tokens = json!({ "tokens": [entry] }).to_string();
    let env = [
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", w.read_token.as_str()),
        ("OPENVIREO_CONNECT_TOKENS", tokens.as_str()),
        ("OPENVIREO_CONNECT_PORT", "0"),
    ];
    let (running, sa) = start(&w, &env).await;
    assert!(running.url.starts_with("http://127.0.0.1:"), "{}", running.url);
    let http = http_client(None);
    let res = http
        .get(format!("{}/v1/vaults/Team%20Infra/items/Deploy/Database?field=username", running.url))
        .bearer_auth(token.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap(), json!({ "value": "app" }));
    let put = http
        .put(format!("{}/v1/vaults/Team%20Infra/items/GitHub", running.url))
        .bearer_auth(token.as_str())
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 403);

    // A chunked body over 1 MiB is cut off at the limit.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(running.addr).await.unwrap();
    let head = format!(
        "PUT /v1/vaults/Team%20Infra/items/X HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        token.as_str()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    let chunk = vec![b'a'; (1 << 20) + 16];
    s.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await.unwrap();
    let _ = s.write_all(&chunk).await;
    let _ = s.write_all(b"\r\n0\r\n\r\n").await;
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut got)).await;
    let got = String::from_utf8_lossy(&got);
    // The token is read-only, which the handler checks before the body.
    assert!(got.starts_with("HTTP/1.1 403"), "{got}");
    running.shutdown().await;
    sa.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_body_limit_counts_bytes_read() {
    let w = make_world(NOW_MS).await;
    let (token, entry) = new_token("app", &[], Access::Write).unwrap();
    let tokens = json!([entry]).to_string();
    let env = [
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", w.write_token.as_str()),
        ("OPENVIREO_CONNECT_TOKENS", tokens.as_str()),
        ("OPENVIREO_CONNECT_PORT", "0"),
    ];
    let (running, sa) = start(&w, &env).await;
    let puts = w.puts();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(running.addr).await.unwrap();
    let head = format!(
        "PUT /v1/vaults/Team%20Infra/items/X HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        token.as_str()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    let chunk = vec![b'a'; (1 << 20) + 16];
    s.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await.unwrap();
    let _ = s.write_all(&chunk).await;
    let _ = s.write_all(b"\r\n0\r\n\r\n").await;
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut got)).await;
    let got = String::from_utf8_lossy(&got);
    assert!(got.starts_with("HTTP/1.1 400"), "{got}");
    assert!(got.contains(r#"{"error":"request body too large","code":"invalid_request"}"#), "{got}");
    assert_eq!(w.puts(), puts);
    running.shutdown().await;
    sa.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_https_with_a_certificate_and_key() {
    let w = make_world(NOW_MS).await;
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let (cert, key) = (format!("{fixtures}/connect-cert.pem"), format!("{fixtures}/connect-key.pem"));
    let ca = std::fs::read_to_string(format!("{fixtures}/connect-ca.pem")).unwrap();
    let env = [
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", w.read_token.as_str()),
        ("OPENVIREO_CONNECT_TOKEN", "plain-token"),
        ("OPENVIREO_CONNECT_PORT", "0"),
        ("OPENVIREO_CONNECT_TLS_CERT", cert.as_str()),
        ("OPENVIREO_CONNECT_TLS_KEY", key.as_str()),
    ];
    let (running, sa) = start(&w, &env).await;
    assert!(running.url.starts_with("https://127.0.0.1:"), "{}", running.url);
    let http = http_client(Some(&ca));
    let res = http
        .get(format!("{}/v1/vaults/Team%20Infra/items/GitHub?field=password", running.url))
        .bearer_auth("plain-token")
        .send()
        .await
        .unwrap();
    assert_eq!((res.status().as_u16(), res.text().await.unwrap()), (200, r#"{"value":"s3cret"}"#.to_string()));
    // Plain HTTP on the TLS port gets nothing useful.
    assert!(http_client(None).get(format!("http://{}/health", running.addr)).send().await.is_err());
    running.shutdown().await;
    sa.close();
}

// --------------------------------------------------------------------------- configuration

#[test]
fn validates_the_tokens_config_and_the_environment() {
    let a = "a".repeat(64);
    assert!(parse_tokens("nope").unwrap_err().message.contains("not JSON"));
    assert!(parse_tokens(r#"[{"name":"a","sha256":"xyz"}]"#).unwrap_err().message.contains("sha256"));
    assert!(parse_tokens(&format!(r#"[{{"name":"a","sha256":"{a}","access":"admin"}}]"#))
        .unwrap_err()
        .message
        .contains("access"));
    assert_eq!(
        parse_tokens(&format!(r#"[{{"name":"a","sha256":"{a}"}}]"#)).unwrap(),
        vec![ConnectToken { name: "a".into(), sha256: a.clone(), vaults: vec!["*".into()], access: Access::Read }]
    );
    let env = |pairs: &[(&str, &str)]| -> ov_cli::session::Env {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    };
    let err = |pairs: &[(&str, &str)]| Config::from_env(&env(pairs)).unwrap_err().message;
    assert!(err(&[]).contains("OPENVIREO_SERVICE_ACCOUNT_TOKEN"));
    assert!(err(&[("OPENVIREO_SERVICE_ACCOUNT_TOKEN", "ov_sa_x")]).starts_with("no connect tokens"));
    let c = Config::from_env(&env(&[
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", "ov_sa_x"),
        ("OPENVIREO_CONNECT_TOKEN", "t"),
        ("OPENVIREO_CONNECT_TOKEN_ACCESS", "write"),
    ]))
    .unwrap();
    assert_eq!(
        (c.host.as_str(), c.port, c.cache_ttl, c.tokens[0].access),
        ("127.0.0.1", 8080, Duration::from_secs(5), Access::Write)
    );
    let bad_port = [
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", "x"),
        ("OPENVIREO_CONNECT_TOKEN", "t"),
        ("OPENVIREO_CONNECT_PORT", "70000"),
    ];
    assert_eq!(err(&bad_port), "bad OPENVIREO_CONNECT_PORT: 70000");
    let half_tls = [
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", "x"),
        ("OPENVIREO_CONNECT_TOKEN", "t"),
        ("OPENVIREO_CONNECT_TLS_CERT", "c.pem"),
    ];
    assert!(err(&half_tls).contains("both"));
    let bad_ttl = [
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", "x"),
        ("OPENVIREO_CONNECT_TOKEN", "t"),
        ("OPENVIREO_CONNECT_CACHE_TTL", "-1"),
    ];
    assert_eq!(err(&bad_ttl), "bad OPENVIREO_CONNECT_CACHE_TTL: -1");

    // _FILE variants, trimmed.
    let dir = std::env::temp_dir().join(format!("ov-connect-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (sa_file, tokens_file) = (dir.join("sa"), dir.join("tokens.json"));
    std::fs::write(&sa_file, "  ov_sa_from_file\n").unwrap();
    std::fs::write(
        &tokens_file,
        format!("{{\"tokens\":[{{\"name\":\"f\",\"sha256\":\"{a}\",\"vaults\":[\"V\"]}}]}}\n"),
    )
    .unwrap();
    let c = Config::from_env(&env(&[
        ("OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE", sa_file.to_str().unwrap()),
        ("OPENVIREO_CONNECT_TOKENS_FILE", tokens_file.to_str().unwrap()),
        ("OPENVIREO_CONNECT_HOST", "::1"),
        ("OPENVIREO_CONNECT_CACHE_TTL", "0.5"),
    ]))
    .unwrap();
    assert_eq!(
        (c.sa_token.as_str(), c.tokens[0].name.as_str(), c.url_host(), c.cache_ttl),
        ("ov_sa_from_file", "f", "[::1]".to_string(), Duration::from_millis(500))
    );
    let missing = dir.join("missing");
    assert_eq!(
        err(&[("OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE", missing.to_str().unwrap())]),
        format!("ENOENT: no such file or directory, open '{}'", missing.display())
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn ov_connect_token_prints_a_token_and_its_config_entry() {
    let servers = ov_testkit::servers::TestServers::new(Arc::new(ov_testkit::ManualClock::new(NOW_MS)));
    let cli = Cli::new(&servers, "connect-token");
    let r = cli.ov(&["connect", "token", "--name", "eso", "--vault", "Team Infra", "--write"], &[]).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    let token = r.stdout.trim();
    assert!(token.starts_with("ov_ct_") && token.len() == 49, "{token}");
    assert!(token[6..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    let last = r.stderr.trim().lines().last().unwrap();
    assert_eq!(
        last,
        format!(r#"{{"name":"eso","sha256":"{}","vaults":["Team Infra"],"access":"write"}}"#, hash_token(token))
    );
    assert!(!r.stderr.contains(token));
    let plain = cli.ov(&["connect", "token"], &[]).await;
    assert!(plain.stderr.trim().ends_with(r#""vaults":["*"],"access":"read"}"#), "{}", plain.stderr);
    let bad = cli.ov(&["connect", "token", "--bogus"], &[]).await;
    assert_eq!(bad.code, 2);
    assert!(bad.stderr.starts_with("ov: Unknown option '--bogus'"), "{}", bad.stderr);
    assert_eq!(cli.ov(&["connect", "token", "extra"], &[]).await.code, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn names_itself_ov_connect() {
    let w = make_world(NOW_MS).await;
    let cli = Cli::new(&w.servers, "connect-names");
    let version = env!("CARGO_PKG_VERSION");
    let help = cli.ov(&["connect", "--help"], &[]).await;
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("  ov connect token [--name N]"), "{}", help.stdout);
    assert_eq!(
        help.stdout,
        "Usage:\n  ov connect [serve]     run the REST server (configured by environment, see README)\n  ov connect token [--name N] [--vault V]... [--write]\n                         create a bearer token; prints it and its config entry\n  ov connect version     print the version\n"
    );
    assert!(cli.ov(&["connect", "help"], &[]).await.stdout.contains("  ov connect [serve] "));
    assert_eq!(cli.ov(&["connect", "--version"], &[]).await.stdout, format!("ov connect {version}\n"));
    assert_eq!(cli.ov(&["connect", "version"], &[]).await.stdout, format!("ov connect {version}\n"));
    let bad = cli.ov(&["connect", "frobnicate"], &[]).await;
    assert_eq!(bad.code, 2);
    assert!(bad.stderr.starts_with("Usage:\n  ov connect [serve]"), "{}", bad.stderr);
    let extra = cli.ov(&["connect", "serve", "x"], &[]).await;
    assert_eq!((extra.code, extra.stderr.as_str()), (1, "ov: unexpected arguments: x\n"));
    assert_eq!(
        cli.ov(&["connect"], &[]).await.stderr,
        "ov: set OPENVIREO_SERVICE_ACCOUNT_TOKEN (or OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE)\n"
    );

    let (_, entry) = new_token("eso", &[], Access::Read).unwrap();
    let tokens = json!([entry]).to_string();
    for argv in [&[][..], &["serve"][..]] {
        let (mut io, _, err) = io_for(
            &w,
            &[
                ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", w.read_token.as_str()),
                ("OPENVIREO_CONNECT_TOKENS", tokens.as_str()),
                ("OPENVIREO_CONNECT_PORT", "0"),
            ],
        );
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let code = ov_cli::connect::main(&argv, &mut io, Some(Box::pin(async {}))).await.unwrap();
        let err = err.text();
        assert_eq!(code, 0);
        let rest = err.strip_prefix("ov connect listening on http://127.0.0.1:").unwrap_or_else(|| panic!("{err}"));
        assert!(rest.ends_with(" (1 token)\n") && rest.split(' ').next().unwrap().parse::<u16>().is_ok(), "{err}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_each_request_with_a_timestamp_and_never_a_value() {
    let w = make_world(NOW_MS).await;
    let (token, entry) = new_token("eso", &[], Access::Read).unwrap();
    let tokens = json!([entry]).to_string();
    let (mut io, _, err) = io_for(
        &w,
        &[
            ("OPENVIREO_SERVICE_ACCOUNT_TOKEN", w.read_token.as_str()),
            ("OPENVIREO_CONNECT_TOKENS", tokens.as_str()),
            ("OPENVIREO_CONNECT_PORT", "0"),
        ],
    );
    let (go, stop) = tokio::sync::oneshot::channel::<()>();
    let err2 = err.clone();
    let server = tokio::spawn(async move {
        ov_cli::connect::main(
            &[],
            &mut io,
            Some(Box::pin(async move {
                let _ = stop.await;
            })),
        )
        .await
        .unwrap()
    });
    let url = loop {
        let text = err2.text();
        if let Some(line) = text.lines().next().filter(|l| l.ends_with(')')) {
            break line.split(' ').nth(4).unwrap().to_string();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let res = http_client(None)
        .get(format!("{url}/v1/vaults/Team%20Infra/items/GitHub?field=password"))
        .bearer_auth(token.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), r#"{"value":"s3cret"}"#);
    go.send(()).unwrap();
    assert_eq!(server.await.unwrap(), 0);
    let text = err.text();
    let line = text.lines().nth(1).unwrap();
    let (time, rest) = line.split_once(' ').unwrap();
    assert_eq!(rest, "GET /v1/vaults/Team%20Infra/items/GitHub 200 token=eso");
    // `new Date().toISOString()`: 2026-11-24T12:34:56.789Z
    assert!(
        time.len() == 24 && time.ends_with('Z') && time.as_bytes()[10] == b'T' && time.as_bytes()[19] == b'.',
        "{time}"
    );
    assert!(!text.contains("s3cret"));
}
