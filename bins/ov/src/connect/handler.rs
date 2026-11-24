//! The REST API of `ov connect` (port of `packages/connect/src/handler.ts`), as a pure async
//! function over a whole request, so tests drive it without sockets:
//!
//! ```text
//! let state = State::new(service_account, tokens, Options::default());
//! let response: http::Response<Bytes> = handle(&state, http::Request<Bytes>).await;
//! ```
//!
//! [`super::server`] puts it on hyper (body read with the size limit, [`BodyTooLarge`] marking a
//! request whose body was cut off).
//!
//! ```text
//! GET  /health                                   liveness (no auth, any method)
//! GET  /ready                                    lists the vaults once (no auth, any method)
//! GET  /v1/vaults                                vaults this token may use
//! GET  /v1/vaults/{vault}                        one vault
//! GET  /v1/vaults/{vault}/items                  items without values
//! GET  /v1/vaults/{vault}/items/{group/…/entry}  one item with its values (?field=name → {"value"})
//! PUT  /v1/vaults/{vault}/items/{group/…/entry}  {"fields":{…}} creates or updates (?create=false: update only)
//! ```
//!
//! `{vault}` is a vault id or name, `{entry}` an entry UUID or title; segments are percent-encoded.
//! A vault outside the token's scope is 404, like one that doesn't exist. Errors are
//! `{"error","code"}`. Every request logs one line (`<METHOD> <raw path> <status> token=<name|->`),
//! never a value.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::body::Bytes;
use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_LENGTH};
use hyper::{Method, Request, Response, StatusCode};
use ov_core::api::{
    CancelToken, CreateMode, EntryRecord, FieldInput, SaVault, ServiceAccount, SyncOptions, Vault, VaultRole,
};
use ov_error::{OvError, OvErrorCode};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::tokens::{allows_vault, authenticate, Access, ConnectToken};
use crate::item::{item_of, item_of_summary, Item};
use crate::js::{decode_uri_component, encode_uri_component};
use crate::source::{role_name, VaultSummary};

/// Receives the request log lines (without a timestamp).
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// Tuning; [`Options::default`] is what `ov connect` uses apart from the cache TTL.
#[derive(Clone)]
pub struct Options {
    /// How long a downloaded vault is used before a HEAD check (default 5 s).
    pub cache_ttl: Duration,
    /// How long the vault list is cached (default 60 s); grants change rarely.
    pub vaults_ttl: Duration,
    /// The largest request body (default 1 MiB).
    pub max_body: usize,
    /// The request log.
    pub log: Option<Log>,
}

impl Default for Options {
    fn default() -> Self {
        Options { cache_ttl: Duration::from_secs(5), vaults_ttl: Duration::from_secs(60), max_body: 1 << 20, log: None }
    }
}

/// A request extension the server adds when the body went over the limit and was not read.
#[derive(Clone, Copy, Debug)]
pub struct BodyTooLarge;

/// The handler's state: the service account, the tokens and the caches.
pub struct State {
    sa: ServiceAccount,
    tokens: Vec<ConnectToken>,
    opts: Options,
    vaults_at: Mutex<Option<Instant>>,
    ready: AtomicBool,
    /// The SA's copy of each vault and when it was last checked.
    cache: Mutex<HashMap<String, (Vault, Instant)>>,
    /// One write lock per vault id: `set_fields`, `sync` and the cache drop never interleave.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl State {
    /// A handler state over a signed-in service account.
    pub fn new(sa: ServiceAccount, tokens: Vec<ConnectToken>, opts: Options) -> Arc<State> {
        Arc::new(State {
            sa,
            tokens,
            opts,
            vaults_at: Mutex::new(None),
            ready: AtomicBool::new(false),
            cache: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
        })
    }

    /// The service account.
    pub fn service_account(&self) -> &ServiceAccount {
        &self.sa
    }

    /// The largest request body.
    pub fn max_body(&self) -> usize {
        self.opts.max_body
    }

    async fn vaults(&self) -> Result<Vec<SaVault>, OvError> {
        let refresh = lock(&self.vaults_at).is_none_or(|at| at.elapsed() > self.opts.vaults_ttl);
        let list = self.sa.vaults(refresh, CancelToken::new()).await?;
        if refresh {
            *lock(&self.vaults_at) = Some(Instant::now());
        }
        self.ready.store(true, Ordering::SeqCst);
        Ok(list)
    }

    /// The vault if this token may use it (404 otherwise, so tokens can't probe other vault names).
    async fn vault_for(&self, token: &ConnectToken, id_or_name: &str) -> Result<SaVault, OvError> {
        self.vaults().await?;
        let not_found =
            || OvError::new(OvErrorCode::NotFound, format!("vault \"{id_or_name}\" not found")).with_status(404);
        let v = match self.sa.vault(id_or_name.to_string(), CancelToken::new()).await {
            Ok(v) => v,
            Err(e) if e.wire_code() == "not_found" => return Err(not_found()),
            Err(e) => return Err(e),
        };
        if !allows_vault(token, &v.id, &v.name) {
            return Err(not_found());
        }
        Ok(v)
    }

    /// The SA's copy of a vault; `pull` (a HEAD check) runs at most once per TTL.
    async fn current(&self, v: &SaVault) -> Result<Vault, OvError> {
        if let Some((db, at)) = lock(&self.cache).get(&v.id) {
            if at.elapsed() < self.opts.cache_ttl {
                return Ok(db.clone());
            }
        }
        let db = self.sa.pull(v.id.clone(), CancelToken::new()).await?;
        lock(&self.cache).insert(v.id.clone(), (db.clone(), Instant::now()));
        Ok(db)
    }

    fn write_lock(&self, vault_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.locks).entry(vault_id.to_string()).or_default().clone()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A body that is wiped when the last reference to it goes.
fn secret_bytes(v: Vec<u8>) -> Bytes {
    Bytes::from_owner(Zeroizing::new(v))
}

fn response(status: u16, content_type: &'static str, body: Vec<u8>) -> Response<Bytes> {
    let mut r = Response::new(secret_bytes(body));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let h = r.headers_mut();
    h.insert("content-type", HeaderValue::from_static(content_type));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    r
}

fn json<T: serde::Serialize + ?Sized>(status: u16, body: &T) -> Response<Bytes> {
    response(status, "application/json", serde_json::to_vec(body).unwrap_or_default())
}

fn fail(status: u16, code: &str, error: &str) -> Response<Bytes> {
    #[derive(serde::Serialize)]
    struct E<'a> {
        error: &'a str,
        code: &'a str,
    }
    json(status, &E { error, code })
}

fn with_header(mut r: Response<Bytes>, name: &'static str, value: &'static str) -> Response<Bytes> {
    r.headers_mut().insert(name, HeaderValue::from_static(value));
    r
}

fn not_allowed(allow: &'static str) -> Response<Bytes> {
    with_header(fail(405, "invalid_request", "method not allowed"), "allow", allow)
}

fn no_route() -> Response<Bytes> {
    fail(404, "not_found", "no such route")
}

/// `errorResponse`: the status for each code; upstream failures are 502 (not the caller's fault).
fn error_response(e: &OvError) -> Response<Bytes> {
    let code = e.wire_code();
    let status = match code {
        "invalid_reference" | "invalid_request" => Some(400),
        "entry_not_found" | "not_found" => Some(404),
        "forbidden" => Some(403),
        "conflict" | "too_many_conflicts" => Some(409),
        _ => None,
    };
    if let Some(s) = status {
        return fail(s, if code == "entry_not_found" { "not_found" } else { code }, &e.message);
    }
    if e.status == Some(401) {
        return fail(502, "upstream_unauthorized", "the service account token was rejected by the auth server");
    }
    if e.code == OvErrorCode::Internal {
        return fail(500, "server_error", "internal error");
    }
    fail(502, "upstream_error", &e.message)
}

/// A header's values joined with `, ` (the fetch `Headers.get`).
fn header(req: &Request<Bytes>, name: hyper::header::HeaderName) -> Option<String> {
    let all: Vec<String> =
        req.headers().get_all(name).iter().map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()).collect();
    if all.is_empty() {
        None
    } else {
        Some(all.join(", "))
    }
}

/// `URLSearchParams.get(name)`: the first value, `+` as space, lenient percent-decoding.
fn query_param(req: &Request<Bytes>, name: &str) -> Option<String> {
    let q = req.uri().query()?;
    let decode = |s: &str| -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() => {
                    let hex = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
                    out.push(hex(b[i + 1]) << 4 | hex(b[i + 2]));
                    i += 2;
                }
                c => out.push(c),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    q.split('&').filter(|p| !p.is_empty()).find_map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (decode(k) == name).then(|| decode(v))
    })
}

/// The standard field an alias stands for.
fn standard_alias(field: &str) -> Option<&'static str> {
    match field.to_lowercase().as_str() {
        "title" => Some("Title"),
        "username" | "user" => Some("UserName"),
        "password" => Some("Password"),
        "url" => Some("URL"),
        "notes" => Some("Notes"),
        _ => None,
    }
}

/// `resolveFieldName`: an exact match, else the standard field of an alias, else a
/// case-insensitive match, else the name as given.
fn resolve_field_name(e: Option<&EntryRecord>, field: &str) -> String {
    if e.is_some_and(|e| e.fields.iter().any(|f| f.name == field)) {
        return field.to_string();
    }
    if let Some(s) = standard_alias(field) {
        return s.to_string();
    }
    let lower = field.to_lowercase();
    e.and_then(|e| e.fields.iter().find(|f| f.name.to_lowercase() == lower))
        .map_or_else(|| field.to_string(), |f| f.name.clone())
}

fn wipe_entry(e: &mut EntryRecord) {
    for f in &mut e.fields {
        f.value.zeroize();
    }
}

fn wipe_item(i: &mut Item) {
    for (_, v) in &mut i.fields {
        v.zeroize();
    }
}

fn wipe_json(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_json),
        Value::Object(o) => o.values_mut().for_each(wipe_json),
        _ => {}
    }
}

/// The item reference the core's lookup takes (the vault segment isn't checked by it).
fn reference(vault_id: &str, path: &[String]) -> String {
    let segs: Vec<String> = path.iter().map(|s| encode_uri_component(s)).collect();
    format!("ov://{}/{}", encode_uri_component(vault_id), segs.join("/"))
}

fn vault_json(v: &SaVault) -> VaultSummary {
    VaultSummary { id: v.id.clone(), name: v.name.clone(), role: role_name(v.role).into() }
}

/// Handles one request. Never fails: errors become `{"error","code"}` responses.
pub async fn handle(state: &State, req: Request<Bytes>) -> Response<Bytes> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let mut name: Option<String> = None;
    let res = match dispatch(state, req, &mut name).await {
        Ok(r) => r,
        Err(e) => error_response(&e),
    };
    if let Some(log) = &state.opts.log {
        log(&format!("{method} {path} {} token={}", res.status().as_u16(), name.as_deref().unwrap_or("-")));
    }
    res
}

async fn dispatch(state: &State, req: Request<Bytes>, name: &mut Option<String>) -> Result<Response<Bytes>, OvError> {
    let path = req.uri().path().to_string();
    let Some(seg) =
        path.split('/').filter(|s| !s.is_empty()).map(decode_uri_component).collect::<Option<Vec<String>>>()
    else {
        return Ok(fail(400, "invalid_request", "bad percent-encoding in the path"));
    };
    if path == "/health" {
        return Ok(json(200, &serde_json::json!({ "status": "ok" })));
    }
    if path == "/ready" {
        if !state.ready.load(Ordering::SeqCst) {
            state.vaults().await?;
        }
        return Ok(json(200, &serde_json::json!({ "status": "ready" })));
    }
    if seg.first().map(String::as_str) != Some("v1") || seg.get(1).map(String::as_str) != Some("vaults") {
        return Ok(no_route());
    }
    let Some(token) = authenticate(&state.tokens, header(&req, AUTHORIZATION).as_deref()) else {
        return Ok(with_header(
            fail(401, "unauthorized", "missing or unknown bearer token"),
            "www-authenticate",
            "Bearer",
        ));
    };
    *name = Some(token.name.clone());
    route(state, req, token, &seg).await
}

async fn route(
    state: &State,
    req: Request<Bytes>,
    token: &ConnectToken,
    seg: &[String],
) -> Result<Response<Bytes>, OvError> {
    let method = req.method().clone();
    if seg.len() == 2 {
        // TS looked up vault `undefined` for other methods (a 500); this is a plain 405.
        if method != Method::GET {
            return Ok(not_allowed("GET"));
        }
        let list: Vec<VaultSummary> =
            state.vaults().await?.iter().filter(|v| allows_vault(token, &v.id, &v.name)).map(vault_json).collect();
        return Ok(json(200, &serde_json::json!({ "vaults": list })));
    }
    let v = state.vault_for(token, &seg[2]).await?;
    if seg.len() == 3 && method == Method::GET {
        return Ok(json(200, &vault_json(&v)));
    }
    if seg.get(3).map(String::as_str) != Some("items") {
        return Ok(no_route());
    }
    if seg.len() == 4 {
        if method != Method::GET {
            return Ok(not_allowed("GET"));
        }
        let db = state.current(&v).await?;
        let items: Vec<Item> = db.entries(false).iter().map(item_of_summary).collect();
        return Ok(json(200, &serde_json::json!({ "items": items })));
    }
    let item_path = &seg[4..];
    let reference = reference(&v.id, item_path);

    if method == Method::GET {
        let db = state.current(&v).await?;
        let mut entry = db.find(reference)?;
        let out = get_item(&req, &entry);
        wipe_entry(&mut entry);
        return Ok(out);
    }
    if method == Method::PUT {
        return put_item(state, req, token, &v, reference).await;
    }
    Ok(not_allowed("GET, PUT"))
}

fn get_item(req: &Request<Bytes>, entry: &EntryRecord) -> Response<Bytes> {
    let Some(field) = query_param(req, "field") else {
        let mut item = item_of(entry, true);
        let out = json(200, &item);
        wipe_item(&mut item);
        return out;
    };
    let name = resolve_field_name(Some(entry), &field);
    let Some(f) = entry.fields.iter().find(|f| f.name == name) else {
        return fail(404, "not_found", &format!("field \"{field}\" not found"));
    };
    let mut value = Zeroizing::new(String::from_utf8_lossy(&f.value).into_owned());
    let accept = header(req, ACCEPT).unwrap_or_default();
    if accept.contains("text/plain") && !accept.contains("json") {
        let bytes = std::mem::take(&mut *value).into_bytes();
        return response(200, "text/plain; charset=utf-8", bytes);
    }
    let mut body = serde_json::Map::new();
    body.insert("value".into(), Value::String(std::mem::take(&mut *value)));
    let mut body = Value::Object(body);
    let out = json(200, &body);
    wipe_json(&mut body);
    out
}

/// `readJson`: the body as JSON, within the size limit (counted in bytes).
fn read_json(req: &Request<Bytes>, max: usize) -> Result<Value, OvError> {
    let too_large = || OvError::new(OvErrorCode::InvalidRequest, "request body too large");
    let declared = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u128>().ok())
        .unwrap_or(0);
    if declared > max as u128 || req.extensions().get::<BodyTooLarge>().is_some() || req.body().len() > max {
        return Err(too_large());
    }
    serde_json::from_slice(req.body())
        .map_err(|_| OvError::new(OvErrorCode::InvalidRequest, "request body is not JSON"))
}

async fn put_item(
    state: &State,
    req: Request<Bytes>,
    token: &ConnectToken,
    v: &SaVault,
    reference: String,
) -> Result<Response<Bytes>, OvError> {
    if token.access != Access::Write {
        return Ok(fail(403, "forbidden", &format!("token \"{}\" is read-only", token.name)));
    }
    let mut body = read_json(&req, state.opts.max_body)?;
    let checked = check_body(&body);
    wipe_json(&mut body);
    let (inputs, protect) = match checked {
        Ok(x) => x,
        Err(msg) => return Ok(fail(400, "invalid_request", msg)),
    };
    if v.role == VaultRole::Read {
        let shown = if v.name.is_empty() { &v.id } else { &v.name };
        return Ok(fail(403, "forbidden", &format!("this service account can only read vault \"{shown}\"")));
    }
    let create = query_param(&req, "create").as_deref() != Some("false");
    let mode = if create { CreateMode::CreateIfMissing } else { CreateMode::MustExist };

    let write_lock = state.write_lock(&v.id);
    let _guard = write_lock.lock().await;
    let result = async {
        let db = state.sa.open_vault(v.id.clone(), false, CancelToken::new()).await?;
        // `protected` names resolve as ?field= does, against the entry when it exists.
        let existing = db.find(reference.clone()).ok();
        let fields: Vec<FieldInput> = inputs
            .into_iter()
            .map(|(name, value)| {
                let target = resolve_field_name(existing.as_ref(), &name);
                let protected =
                    protect.iter().find(|(k, _)| resolve_field_name(existing.as_ref(), k) == target).map(|(_, p)| *p);
                FieldInput { name, value: std::mem::take(&mut *Zeroizing::new(value)).into_bytes(), protected }
            })
            .collect();
        if let Some(mut e) = existing {
            wipe_entry(&mut e);
        }
        let changed = db.set_fields(reference, fields, mode)?;
        let mut entry = changed.entry;
        let synced = db.sync(SyncOptions::default(), CancelToken::new()).await;
        if let Err(e) = synced {
            wipe_entry(&mut entry);
            // A failed upload leaves the edit in the SA's copy: download it again, so the failed
            // edit is never read back.
            let _ = state.sa.open_vault(v.id.clone(), true, CancelToken::new()).await;
            return Err(e);
        }
        let item = item_of(&entry, false);
        wipe_entry(&mut entry);
        Ok((item, changed.created))
    }
    .await;
    // The SA now holds the merged copy (or a fresh one): use it from the next request.
    lock(&state.cache).remove(&v.id);
    let (mut item, created) = result?;
    let out = json(if created { 201 } else { 200 }, &item);
    wipe_item(&mut item);
    Ok(out)
}

type Checked = (Vec<(String, String)>, Vec<(String, bool)>);

/// The body checks of the TS handler, with its messages.
fn check_body(body: &Value) -> Result<Checked, &'static str> {
    let fields = body.as_object().and_then(|o| o.get("fields"));
    let Some(Value::Object(fields)) = fields else {
        return Err("body must be {\"fields\": {\"<name>\": \"<value>\", …}}");
    };
    let mut out = Vec::with_capacity(fields.len());
    for (k, v) in fields {
        match v {
            Value::String(s) => out.push((k.clone(), s.clone())),
            _ => return Err("body must be {\"fields\": {\"<name>\": \"<value>\", …}}"),
        }
    }
    let mut protect = Vec::new();
    match body.as_object().and_then(|o| o.get("protected")) {
        None => {}
        Some(Value::Object(p)) if p.values().all(Value::is_boolean) => {
            protect = p.iter().map(|(k, v)| (k.clone(), v.as_bool().unwrap_or(false))).collect();
        }
        Some(_) => return Err("\"protected\" must be {\"<name>\": true|false, …}"),
    }
    Ok((out, protect))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(uri: &str) -> Request<Bytes> {
        Request::builder().uri(uri).body(Bytes::new()).unwrap()
    }

    #[test]
    fn reads_query_params_like_url_search_params() {
        assert_eq!(query_param(&req("/x?field=api%20key"), "field").as_deref(), Some("api key"));
        assert_eq!(query_param(&req("/x?a=1&field=a+b&field=2"), "field").as_deref(), Some("a b"));
        assert_eq!(query_param(&req("/x?field=%zz%4"), "field").as_deref(), Some("%zz%4"));
        assert_eq!(query_param(&req("/x?field"), "field").as_deref(), Some(""));
        assert_eq!(query_param(&req("/x"), "field"), None);
    }

    #[test]
    fn maps_errors_like_the_ts() {
        let r = error_response(&OvError::new(OvErrorCode::EntryNotFound, "entry \"x\" not found"));
        assert_eq!(r.status(), 404);
        assert_eq!(&r.body()[..], br#"{"error":"entry \"x\" not found","code":"not_found"}"#);
        assert_eq!(error_response(&OvError::new(OvErrorCode::Unauthorized, "x").with_status(401)).status(), 502);
        assert_eq!(error_response(&OvError::new(OvErrorCode::NetworkError, "x")).status(), 502);
        assert_eq!(error_response(&OvError::internal("x")).status(), 500);
        assert_eq!(error_response(&OvError::new(OvErrorCode::TooManyConflicts, "x")).status(), 409);
    }

    #[test]
    fn checks_bodies() {
        let ok = check_body(&serde_json::json!({"fields": {"a": "1"}, "protected": {"a": true}})).unwrap();
        assert_eq!(ok, (vec![("a".into(), "1".into())], vec![("a".into(), true)]));
        assert!(check_body(&serde_json::json!({"fields": {"a": 1}})).is_err());
        assert!(check_body(&serde_json::json!([1])).is_err());
        assert!(check_body(&serde_json::json!({"fields": {}, "protected": null})).is_err());
    }
}
