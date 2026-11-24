//! `ov connect` against the recorded answers of the TypeScript connect server
//! (`tests/golden/connect/cases.json`, see the README there): the README's fixture world on the
//! in-memory servers, every case through `handle()` in file order, with the README's normalization.
//! Status, the four headers (`content-type`, `cache-control`, `allow`, `www-authenticate`: present
//! exactly when the fixture has them), the body and the log line must match. Cases with a
//! `divergesFromTs` note already hold the Rust expectation.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::Bytes;
use hyper::Request;
use ov_cli::connect::handler::{handle, Options, State};
use ov_cli::connect::tokens::{hash_token, Access, ConnectToken};
use ov_core::api::*;
use ov_testkit::servers::TestServers;
use ov_testkit::ManualClock;
use serde_json::Value;
use support::{ALICE, KDF, PASSWORD};

const NOW_MS: i64 = 1_794_700_800_000;
const CASES: &str = include_str!("golden/connect/cases.json");
const HEADERS: [&str; 4] = ["content-type", "cache-control", "allow", "www-authenticate"];
const TIME_KEYS: [&str; 5] = ["updatedAt", "createdAt", "modifiedAt", "expiresAt", "time"];

fn nc() -> CancelToken {
    CancelToken::new()
}

fn add(v: &Vault, group: String, pairs: &[(&str, &str)]) -> String {
    let fields = pairs
        .iter()
        .map(|(k, v)| FieldInput { name: (*k).into(), value: v.as_bytes().to_vec(), protected: None })
        .collect();
    v.add_entry(group, EntryInput { fields, ..Default::default() }).unwrap()
}

/// The README's fixture world: returns the handler and the known ids (id → name).
async fn world() -> (Arc<State>, Arc<Mutex<Vec<String>>>, BTreeMap<String, String>) {
    let servers = TestServers::new(Arc::new(ManualClock::new(NOW_MS)));
    servers.set_live_access(true);
    let config = |platform| ClientConfig {
        device: DeviceInfo { id: None, name: "golden".into(), platform },
        offline: false,
        server: None,
    };
    let alice = OvClient::new(config(Platform::Web), servers.host()).connect(servers.issuer(), nc()).await.unwrap();
    let input = RegisterInput {
        email: ALICE.into(),
        password: PASSWORD.as_bytes().to_vec(),
        kdf: Some(KDF),
        trust_device: true,
    };
    alice.register(input, nc()).await.unwrap();
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let mut ids = BTreeMap::new();

    let team = alice.create_vault("Team Infra".into(), Some(org.id.clone()), nc()).await.unwrap();
    let gh = &[("Title", "GitHub"), ("UserName", "ci"), ("Password", "s3cret"), ("URL", "https://github.com")];
    ids.insert(add(&team, team.root_group_id(), gh), "GitHub".to_string());
    let deploy = team.add_group(None, "Deploy".into()).unwrap();
    let db = &[
        ("Title", "Database"),
        ("UserName", "app"),
        ("Password", "pg-pa$$word"),
        ("URL", "postgres://db.internal:5432/app"),
        ("Notes", "multi\nline"),
        ("api key", "ak-12345"),
    ];
    ids.insert(add(&team, deploy, db), "Database".into());
    let apps = team.add_group(None, "Apps".into()).unwrap();
    let prod = team.add_group(Some(apps), "Prod".into()).unwrap();
    ids.insert(
        add(&team, prod, &[("Title", "Service"), ("UserName", "svc"), ("Password", "svc-pass")]),
        "Service".into(),
    );
    team.sync(SyncOptions::default(), nc()).await.unwrap();

    let other = alice.create_vault("Other".into(), Some(org.id.clone()), nc()).await.unwrap();
    ids.insert(add(&other, other.root_group_id(), &[("Title", "Token"), ("Password", "other-secret")]), "Token".into());
    other.sync(SyncOptions::default(), nc()).await.unwrap();
    let private = alice.create_vault("Private".into(), Some(org.id.clone()), nc()).await.unwrap();
    ids.insert(add(&private, private.root_group_id(), &[("Title", "Bank"), ("Password", "nope")]), "Bank".into());
    private.sync(SyncOptions::default(), nc()).await.unwrap();
    for (v, name) in [(&team, "Team Infra"), (&other, "Other"), (&private, "Private")] {
        ids.insert(v.id(), name.into());
    }

    let grant = |vault_id: String, role| VaultGrantRequest { vault_id, role };
    let new = NewServiceAccount {
        name: "connect".into(),
        vaults: vec![grant(team.id(), VaultRole::Write), grant(other.id(), VaultRole::Read)],
        expires_at: None,
        secret_name: None,
    };
    let token = alice.create_service_account(org.id.clone(), new, nc()).await.unwrap().token;
    let sa =
        ServiceAccount::from_token(OvClient::new(config(Platform::Cli), servers.host()), token, nc()).await.unwrap();

    let t = |name: &str, plain: &str, vault: &str, access| ConnectToken {
        name: name.into(),
        sha256: hash_token(plain),
        vaults: vec![vault.into()],
        access,
    };
    let tokens = vec![
        t("app", "ov_ct_golden_app", "Team Infra", Access::Write),
        t("ro", "ov_ct_golden_ro", "*", Access::Read),
        t("other", "ov_ct_golden_other", "Other", Access::Write),
    ];
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    let opts = Options {
        cache_ttl: Duration::ZERO,
        log: Some(Arc::new(move |l: &str| sink.lock().unwrap().push(l.to_string()))),
        ..Options::default()
    };
    (State::new(sa, tokens, opts), log, ids)
}

// ------------------------------------------------------------------------- normalization

fn is_hex(b: &[u8]) -> bool {
    b.iter().all(u8::is_ascii_hexdigit)
}

/// Rule 2: anything still shaped like an id (32 hex digits, or 8-4-4-4-12) → `<uuid:?>`.
fn unmapped_ids(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let boundary = |j: usize| j >= b.len() || !b[j].is_ascii_hexdigit();
    while i < b.len() {
        let start_ok = i == 0 || !b[i - 1].is_ascii_hexdigit();
        let dashed = b.len() >= i + 36
            && [8, 13, 18, 23].iter().all(|&d| b[i + d] == b'-')
            && [(0, 8), (9, 13), (14, 18), (19, 23), (24, 36)].iter().all(|&(x, y)| is_hex(&b[i + x..i + y]));
        if start_ok && dashed && boundary(i + 36) {
            out.push_str("<uuid:?>");
            i += 36;
        } else if start_ok && b.len() >= i + 32 && is_hex(&b[i..i + 32]) && boundary(i + 32) {
            out.push_str("<uuid:?>");
            i += 32;
        } else {
            let c = s[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`, the whole string.
fn is_iso_time(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b.get(r).is_some_and(|x| x.iter().all(u8::is_ascii_digit));
    if b.len() < 20
        || !(digits(0..4) && b[4] == b'-' && digits(5..7) && b[7] == b'-' && digits(8..10) && b[10] == b'T')
        || !(digits(11..13) && b[13] == b':' && digits(14..16) && b[16] == b':' && digits(17..19))
    {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match &b[i..] {
        [b'Z'] => true,
        [b'+' | b'-', h1, h2, b':', m1, m2] => [h1, h2, m1, m2].iter().all(|c| c.is_ascii_digit()),
        _ => false,
    }
}

/// Rules 1 and 2 on a string.
fn norm_text(s: &str, ids: &BTreeMap<String, String>) -> String {
    let mut out = s.to_string();
    for (id, name) in ids {
        let tag = format!("<uuid:{name}>");
        out = out.replace(&id.to_lowercase(), &tag).replace(&id.to_uppercase(), &tag).replace(id.as_str(), &tag);
    }
    unmapped_ids(&out)
}

fn norm(v: &mut Value, ids: &BTreeMap<String, String>, key: Option<&str>) {
    match v {
        Value::String(s) => {
            *s = if key.is_some_and(|k| TIME_KEYS.contains(&k)) || is_iso_time(s) {
                "<time>".into()
            } else if key.is_some_and(|k| k.eq_ignore_ascii_case("etag")) {
                "<etag>".into()
            } else {
                norm_text(s, ids)
            };
        }
        Value::Array(a) => a.iter_mut().for_each(|x| norm(x, ids, None)),
        Value::Object(o) => o.iter_mut().for_each(|(k, x)| norm(x, ids, Some(k))),
        _ => {}
    }
}

/// Learns `id` → `title` from objects in a response, for titles with no id yet.
fn learn(v: &Value, ids: &mut BTreeMap<String, String>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| learn(x, ids)),
        Value::Object(o) => {
            if let (Some(Value::String(id)), Some(Value::String(title))) = (o.get("id"), o.get("title")) {
                if !ids.values().any(|n| n == title) {
                    ids.insert(id.clone(), title.clone());
                }
            }
            o.values().for_each(|x| learn(x, ids));
        }
        _ => {}
    }
}

fn body_of(spec: &Value) -> String {
    match spec {
        Value::String(s) => s.clone(),
        Value::Object(o) => {
            let s = |k: &str| o[k].as_str().unwrap_or_default();
            let count = usize::try_from(o["count"].as_u64().unwrap_or(0)).unwrap();
            format!("{}{}{}", s("prefix"), s("repeat").repeat(count), s("suffix"))
        }
        _ => String::new(),
    }
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matches_the_typescript_server() {
    let cases: Vec<Value> = serde_json::from_str(CASES).unwrap();
    assert_eq!(cases.len(), 67, "the fixture changed size: update this test with it");
    let (state, log, mut ids) = world().await;
    let mut failures = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let rq = &case["request"];
        let mut path = rq["path"].as_str().unwrap().to_string();
        for (id, n) in &ids {
            path = path.replace(&format!("<uuid:{n}>"), id);
        }
        let mut b = Request::builder().method(rq["method"].as_str().unwrap()).uri(&path);
        for (k, v) in rq["headers"].as_object().unwrap() {
            b = b.header(k, v.as_str().unwrap());
        }
        log.lock().unwrap().clear();
        let r = handle(&state, b.body(Bytes::from(body_of(&rq["body"]))).unwrap()).await;

        let mut headers = serde_json::Map::new();
        for h in HEADERS {
            if let Some(v) = r.headers().get(h) {
                headers.insert(h.into(), Value::String(v.to_str().unwrap().into()));
            }
        }
        let text = String::from_utf8(r.body().to_vec()).unwrap();
        let is_json = headers.get("content-type").and_then(Value::as_str) == Some("application/json");
        let mut body =
            if is_json { serde_json::from_str(&text).unwrap_or(Value::String(text)) } else { Value::String(text) };
        learn(&body, &mut ids);
        norm(&mut body, &ids, None);
        let lines: Vec<Value> =
            log.lock().unwrap().iter().map(|l| Value::String(format!("<time> {}", norm_text(l, &ids)))).collect();
        let got = serde_json::json!({
            "status": r.status().as_u16(),
            "headers": headers,
            "body": body,
            "log": lines,
        });

        let want = &case["response"];
        let mut diffs = Vec::new();
        for part in ["status", "headers", "body", "log"] {
            if got[part] != want[part] {
                diffs.push(format!(
                    "  {part}:\n    want: {}\n    got:  {}",
                    pretty(&want[part]).replace('\n', "\n          "),
                    pretty(&got[part]).replace('\n', "\n          ")
                ));
            }
        }
        if !diffs.is_empty() {
            let note = case.get("divergesFromTs").map(|n| format!(" (diverges from TS: {n})")).unwrap_or_default();
            failures.push(format!("case \"{name}\"{note}: {} {}\n{}", rq["method"], rq["path"], diffs.join("\n")));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} golden cases differ:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

#[test]
fn normalization_helpers() {
    assert_eq!(unmapped_ids("x 0123456789abcdef0123456789ABCDEF y"), "x <uuid:?> y");
    assert_eq!(unmapped_ids("01234567-89ab-cdef-0123-456789abcdef"), "<uuid:?>");
    assert_eq!(unmapped_ids("0123456789abcdef0123456789abcdef0"), "0123456789abcdef0123456789abcdef0");
    assert!(is_iso_time("2026-11-24T12:34:56.789Z") && is_iso_time("2026-11-24T12:34:56+02:00"));
    assert!(!is_iso_time("2026-11-24") && !is_iso_time("2026-11-24T12:34:56"));
}
