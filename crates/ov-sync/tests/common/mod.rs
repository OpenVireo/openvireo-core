//! Test helpers: databases like the SDK's `test/helpers/dbs.ts`, a small in-memory sync server
//! (the SDK's `FakeSyncServer`: ETag, revision, 412/428, history, `afterGet`, a `Date` header), and
//! the [`World`] the shared scenarios run against (this fake, or W2-E's `ov_testkit::servers`).

#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use ov_host::{ByteStream, HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
use ov_kdbx::model::{Database, Entry, Group, StringField, Timestamp, Uuid};
use ov_kdbx::vault::{create_vault_kdbx, new_uuid, vault_credentials};
use ov_kdbx::CompositeKey;
use ov_protocol::sync::{etag_for, SyncApi};
use ov_sync::{Blob, StaticToken, SyncClient};
use ov_testkit::ManualClock;

pub const KEY: [u8; 32] = [7; 32];
/// The tests' "now": 2026-11-15T12:00:00Z.
pub const NOW_MS: i64 = 1_794_744_000_000;

pub fn run<F: Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

pub fn creds() -> CompositeKey {
    vault_credentials(&KEY).unwrap()
}

// ------------------------------------------------------------------------------------ databases

/// A base database built by `build`, plus local/remote/base copies opened from the same bytes
/// (TS `threeCopies`).
pub struct Copies {
    pub bytes: Vec<u8>,
    pub local: Database,
    pub remote: Database,
    pub base: Database,
}

pub fn three_copies(build: impl FnOnce(&mut Database)) -> Copies {
    let (mut db, key) = create_vault_kdbx("Vault", &KEY, 50).unwrap();
    build(&mut db);
    let bytes = ov_kdbx::write(&db, &key).unwrap();
    let open = || ov_kdbx::read(&bytes, &key).unwrap();
    Copies { local: open(), remote: open(), base: open(), bytes }
}

/// Adds an entry with `fields` at `time` (seconds) to `group` (the root when `None`).
pub fn add_entry(
    db: &mut Database,
    title: &str,
    fields: &[(&str, &str)],
    time: Timestamp,
    group: Option<Uuid>,
) -> Uuid {
    let mut e = Entry::new(new_uuid().unwrap(), time);
    set(&mut e, "Title", title);
    for (k, v) in fields {
        set(&mut e, k, v);
    }
    e.times.creation = time;
    e.times.last_modification = time;
    e.times.location_changed = time;
    let id = e.uuid;
    let g = match group {
        Some(g) => ov_kdbx::entries::find_group_mut(&mut db.root, g).expect("group"),
        None => &mut db.root,
    };
    g.entries.push(e);
    id
}

fn set(e: &mut Entry, k: &str, v: &str) {
    ov_kdbx::entries::set_field(e, k, v, k == "Password");
}

pub fn create_group(db: &mut Database, name: &str, time: Timestamp) -> Uuid {
    let g = Group::new(new_uuid().unwrap(), name, time);
    let id = g.uuid;
    db.root.groups.push(g);
    id
}

fn find_title<'a>(g: &'a Group, title: &str) -> Option<&'a Entry> {
    g.entries.iter().find(|e| e.title() == title).or_else(|| g.groups.iter().find_map(|c| find_title(c, title)))
}

pub fn by_title<'a>(db: &'a Database, title: &str) -> Option<&'a Entry> {
    find_title(&db.root, title)
}

pub fn id_of(db: &Database, title: &str) -> Uuid {
    by_title(db, title).unwrap_or_else(|| panic!("no entry {title}")).uuid
}

pub fn group<'a>(db: &'a Database, name: &str) -> Option<&'a Group> {
    fn find<'a>(g: &'a Group, name: &str) -> Option<&'a Group> {
        g.groups.iter().find(|c| c.name == name).or_else(|| g.groups.iter().find_map(|c| find(c, name)))
    }
    find(&db.root, name)
}

/// Edits like a client: history first, then fields, then the modification time (TS `edit`).
pub fn edit(db: &mut Database, title: &str, fields: &[(&str, &str)], time: Timestamp) {
    let id = id_of(db, title);
    let e = ov_kdbx::entries::find_entry_mut(&mut db.root, id).unwrap();
    let mut old = e.clone();
    old.history.clear();
    e.history.push(old);
    for (k, v) in fields {
        set(e, k, v);
    }
    e.times.last_modification = time;
}

pub fn get(db: &Database, title: &str, field: &str) -> Option<String> {
    by_title(db, title).and_then(|e| e.field(field)).map(|f: &StringField| f.value.to_string())
}

// ------------------------------------------------------------------------------------ the world

/// What the shared scenarios need from a sync server.
pub trait World: Clone + Send + Sync + 'static {
    /// The server's clock (the client's too).
    fn clock(&self) -> Arc<ManualClock>;
    /// A client for the legacy `databases/<id>` routes with the device token.
    fn blob(&self, id: &str) -> Blob;
    /// Another device uploads a version.
    fn upload(&self, id: &str, data: &[u8]);
    /// The newest version on the server.
    fn latest(&self, id: &str) -> Option<Vec<u8>>;
    /// Runs after a successful GET of a blob, before the client can PUT.
    fn set_after_get(&self, f: Option<Box<dyn Fn() + Send + Sync>>);
    /// The server loses every blob.
    fn lose_all(&self);
    /// The methods of the requests so far, uppercase.
    fn methods(&self) -> Vec<String>;
    /// The server's clock runs `ms` ahead of the client's.
    fn set_server_ahead_ms(&self, ms: i64);
}

struct Version {
    data: Vec<u8>,
    etag: String,
    revision: i64,
}

#[derive(Default)]
struct State {
    blobs: HashMap<String, Vec<Version>>,
    methods: Vec<String>,
    after_get: Option<Arc<dyn Fn() + Send + Sync>>,
    ahead_ms: i64,
}

/// The SDK's `FakeSyncServer` as an [`HttpTransport`] on `https://sync.example/api/v1`.
#[derive(Clone)]
pub struct FakeSync {
    clock: Arc<ManualClock>,
    state: Arc<Mutex<State>>,
}

pub const BASE: &str = "https://sync.example/api/v1/";
pub const DEVICE_TOKEN: &str = "dev-token";

impl Default for FakeSync {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeSync {
    pub fn new() -> Self {
        FakeSync { clock: Arc::new(ManualClock::new(NOW_MS)), state: Arc::default() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    pub fn client(&self, token: Option<&str>) -> SyncClient {
        SyncClient::new(
            Arc::new(self.clone()),
            self.clock.clone(),
            SyncApi::self_hosted("https://sync.example/").unwrap(),
            Arc::new(StaticToken(token.map(str::to_string))),
        )
    }

    pub fn store(&self, key: &str, data: &[u8]) {
        let mut s = self.lock();
        let list = s.blobs.entry(key.to_string()).or_default();
        let revision = list.last().map_or(0, |v| v.revision) + 1;
        list.push(Version { data: data.to_vec(), etag: etag_for(data), revision });
    }

    fn handle(&self, req: &HttpRequest) -> (HttpResponse, bool) {
        let mut s = self.lock();
        s.methods.push(req.method.as_str().to_string());
        let date = http_date(self.clock.now_unix_ms() + s.ahead_ms);
        let json = |status: u16, body: String| HttpResponse {
            status,
            headers: vec![("Content-Type".into(), "application/json".into()), ("Date".into(), date.clone())],
            body: body.into_bytes(),
        };
        let header = |n: &str| req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
        let Some(path) = req.url.strip_prefix(BASE) else { return (json(404, "{}".into()), false) };
        if path == "health" {
            return (json(200, r#"{"status":"ok"}"#.into()), false);
        }
        if header("Authorization").as_deref() != Some(&format!("Bearer {DEVICE_TOKEN}")) {
            return (json(401, r#"{"error":"Missing or invalid access token."}"#.into()), false);
        }
        let parts: Vec<&str> = path.split('/').collect();
        let key = match parts.as_slice() {
            [kind @ ("databases" | "vaults"), id, ..] => format!("{kind}/{id}"),
            _ => return (json(404, r#"{"error":"not found"}"#.into()), false),
        };
        let vh = |v: &Version| {
            vec![
                ("ETag".to_string(), v.etag.clone()),
                ("X-Database-Revision".to_string(), v.revision.to_string()),
                ("Date".to_string(), date.clone()),
            ]
        };
        let meta = |v: &Version| {
            format!(
                r#"{{"id":"{}","etag":{},"revision":{},"size":{},"updatedAt":"t"}}"#,
                parts[1],
                serde_json::Value::String(v.etag.clone()),
                v.revision,
                v.data.len()
            )
        };
        match (req.method, parts.len()) {
            (Method::Get | Method::Head, 2) => {
                let Some(v) = s.blobs.get(&key).and_then(|l| l.last()) else {
                    return (json(404, r#"{"error":"Database not found."}"#.into()), false);
                };
                if header("If-None-Match").as_deref() == Some(&v.etag) {
                    return (HttpResponse { status: 304, headers: vh(v), body: vec![] }, false);
                }
                let body = if req.method == Method::Get { v.data.clone() } else { vec![] };
                (HttpResponse { status: 200, headers: vh(v), body }, req.method == Method::Get)
            }
            (Method::Put, 2) => {
                let cur = s.blobs.get(&key).and_then(|l| l.last());
                let (if_match, if_none) = (header("If-Match"), header("If-None-Match"));
                if if_match.is_none() && if_none.is_none() {
                    return (
                        json(428, r#"{"error":"precondition required","code":"precondition_required"}"#.into()),
                        false,
                    );
                }
                if if_none.as_deref() == Some("*") && cur.is_some() {
                    return (json(412, r#"{"error":"exists","code":"precondition_failed"}"#.into()), false);
                }
                if let Some(m) = &if_match {
                    if cur.map(|c| &c.etag) != Some(m) {
                        return (
                            json(
                                412,
                                r#"{"error":"The database was changed on the server.","code":"precondition_failed"}"#
                                    .into(),
                            ),
                            false,
                        );
                    }
                }
                let created = cur.is_none();
                let data = req.body.clone().unwrap_or_default();
                let list = s.blobs.entry(key).or_default();
                let revision = list.last().map_or(0, |v| v.revision) + 1;
                list.push(Version { etag: etag_for(&data), data, revision });
                let v = list.last().unwrap();
                let mut res = json(if created { 201 } else { 200 }, meta(v));
                res.headers.extend(vh(v));
                (res, false)
            }
            (Method::Delete, 2) => {
                if s.blobs.remove(&key).is_some() {
                    (HttpResponse { status: 204, headers: vec![], body: vec![] }, false)
                } else {
                    (json(404, r#"{"error":"Database not found."}"#.into()), false)
                }
            }
            (Method::Get, 3) if parts[2] == "history" => {
                let list = s.blobs.get(&key).map(|l| l.iter().rev().map(meta).collect::<Vec<_>>()).unwrap_or_default();
                (json(200, format!(r#"{{"versions":[{}]}}"#, list.join(","))), false)
            }
            (Method::Get, 4) if parts[2] == "history" => {
                let rev: i64 = parts[3].parse().unwrap_or(-1);
                match s.blobs.get(&key).and_then(|l| l.iter().find(|v| v.revision == rev)) {
                    Some(v) => (HttpResponse { status: 200, headers: vh(v), body: v.data.clone() }, false),
                    None => (json(404, r#"{"error":"Version not found."}"#.into()), false),
                }
            }
            _ => (json(405, r#"{"error":"method not allowed"}"#.into()), false),
        }
    }
}

#[async_trait::async_trait]
impl HttpTransport for FakeSync {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let (res, got) = self.handle(&req);
        if got {
            let hook = self.lock().after_get.clone();
            if let Some(h) = hook {
                h();
            }
        }
        Ok(res)
    }
    async fn open_stream(&self, _req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
        Err(TransportError::Other("no event stream here".into()))
    }
}

impl World for FakeSync {
    fn clock(&self) -> Arc<ManualClock> {
        self.clock.clone()
    }
    fn blob(&self, id: &str) -> Blob {
        self.client(Some(DEVICE_TOKEN)).database(id)
    }
    fn upload(&self, id: &str, data: &[u8]) {
        self.store(&format!("databases/{id}"), data)
    }
    fn latest(&self, id: &str) -> Option<Vec<u8>> {
        self.lock().blobs.get(&format!("databases/{id}")).and_then(|l| l.last()).map(|v| v.data.clone())
    }
    fn set_after_get(&self, f: Option<Box<dyn Fn() + Send + Sync>>) {
        self.lock().after_get = f.map(Arc::from);
    }
    fn lose_all(&self) {
        self.lock().blobs.clear();
    }
    fn methods(&self) -> Vec<String> {
        self.lock().methods.clone()
    }
    fn set_server_ahead_ms(&self, ms: i64) {
        self.lock().ahead_ms = ms;
    }
}

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`).
pub fn http_date(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(m - 1) as usize];
    format!("{wd}, {d:02} {mon} {y} {:02}:{:02}:{:02} GMT", tod / 3600, tod / 60 % 60, tod % 60)
}
