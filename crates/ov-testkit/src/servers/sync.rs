//! The in-memory sync server: JWT `vaults/*` routes (`sync-openapi.yaml`), the legacy device-token
//! `databases/*`, pairing and health routes, `GET /events`, and the internal routes. Ported from
//! `sync-server.ts`, plus the role and `vlt` checks of the real JWT mode.

use std::sync::Arc;

use ov_crypto::jwt::{verify_jwt, VaultClaim, VerifyOptions, DEFAULT_SKEW_SECS};
use ov_host::{HttpResponse, Method};
use ov_protocol::sync::etag_for;
use ov_protocol::types::{BlobMeta, PairingClaimRequest};
use serde_json::{json, Value};

use super::http::{empty, error, error_with, http_date, iso, json_response, matches, ok, Params, Req, Res, Table};
use super::memory::StreamPipe;
use super::{World, DEVICE_TOKEN, INTERNAL_TOKEN, PAIRING_CODE};

/// One stored version of a blob.
pub(crate) struct Version {
    pub data: Vec<u8>,
    pub etag: String,
    pub revision: i64,
    pub updated_at_ms: i64,
}

struct Pairing {
    user: String,
    device_id: String,
    token: String,
}

/// An open event stream.
struct StreamReg {
    /// The JWT's principal, or `None` for a device-token (legacy) stream.
    principal: Option<String>,
    /// The vaults in the token's `vlt`.
    vaults: Vec<String>,
    /// The token's `exp` (Unix seconds): the server ends the stream then.
    exp: Option<i64>,
    pipe: Arc<StreamPipe>,
}

pub(crate) struct SyncState {
    /// `vaults/<id>` or `databases/<id>` → versions, oldest first.
    pub blobs: Table<Vec<Version>>,
    /// Device token → user (legacy routes).
    device_tokens: Table<String>,
    pairing: Table<Pairing>,
    streams: Vec<StreamReg>,
}

impl SyncState {
    pub fn new() -> Self {
        let mut device_tokens = Table::default();
        device_tokens.insert(DEVICE_TOKEN, "alice".to_string());
        let mut pairing = Table::default();
        pairing.insert(
            PAIRING_CODE,
            Pairing { user: "alice".into(), device_id: "dev-2".into(), token: "dev-token-2".into() },
        );
        SyncState { blobs: Table::default(), device_tokens, pairing, streams: vec![] }
    }

    pub fn add_device_token(&mut self, token: &str, user: &str) {
        self.device_tokens.insert(token, user.to_string());
    }

    pub fn current(&self, key: &str) -> Option<&Version> {
        self.blobs.get(key).and_then(|v| v.last())
    }

    /// Ends every open stream.
    pub fn close_streams(&mut self) {
        for s in self.streams.drain(..) {
            s.pipe.close();
        }
    }
}

fn rank(role: &str) -> u8 {
    match role {
        "read" => 1,
        "write" => 2,
        "manage" => 3,
        _ => 0,
    }
}

fn meta(key: &str, v: &Version) -> BlobMeta {
    BlobMeta {
        id: key.split_once('/').map_or(key, |(_, id)| id).to_string(),
        etag: v.etag.clone(),
        revision: v.revision,
        size: v.data.len() as u64,
        updated_at: iso(v.updated_at_ms),
    }
}

fn version_headers(v: &Version) -> Vec<(String, String)> {
    vec![
        ("ETag".into(), v.etag.clone()),
        ("X-Database-Revision".into(), v.revision.to_string()),
        ("Last-Modified".into(), http_date(v.updated_at_ms)),
    ]
}

fn bytes(status: u16, data: Vec<u8>, v: &Version) -> HttpResponse {
    let mut headers = vec![("Content-Type".to_string(), "application/octet-stream".to_string())];
    headers.extend(version_headers(v));
    HttpResponse { status, headers, body: data }
}

/// Stores a new version (an upload, or another device writing directly) and publishes the event.
pub(crate) fn store(w: &mut World, key: &str, data: &[u8]) {
    let now = w.now_ms();
    let mut list = w.sync.blobs.remove(key).unwrap_or_default();
    let revision = list.last().map_or(0, |v| v.revision) + 1;
    list.push(Version { data: data.to_vec(), etag: etag_for(data), revision, updated_at_ms: now });
    let etag = list.last().map(|v| v.etag.clone()).unwrap_or_default();
    w.sync.blobs.insert(key, list);
    publish_blob(w, key, json!({ "etag": etag, "revision": revision }));
}

/// Deletes a blob and its history, publishing `deleted: true`. Whether it existed.
pub(crate) fn delete(w: &mut World, key: &str) -> bool {
    let existed = w.sync.blobs.remove(key).is_some();
    if existed {
        publish_blob(w, key, json!({ "deleted": true }));
    }
    existed
}

fn sse(event: &str, data: &Value) -> Vec<u8> {
    format!("event: {event}\ndata: {data}\n\n").into_bytes()
}

/// Closes streams whose token expired (exactly at `exp`, SPEC §11) or that the client closed.
pub(crate) fn end_expired_streams(w: &mut World) {
    let now = w.now_s();
    w.sync.streams.retain(|s| {
        if s.exp.is_some_and(|exp| now >= exp) {
            s.pipe.close();
        }
        !s.pipe.is_closed()
    });
}

/// `event: vault` (JWT streams that may read it) or `event: database` (legacy streams).
fn publish_blob(w: &mut World, key: &str, extra: Value) {
    end_expired_streams(w);
    let Some((kind, id)) = key.split_once('/') else { return };
    let mut data = json!({ "id": id });
    if let (Some(d), Value::Object(e)) = (data.as_object_mut(), extra) {
        d.extend(e);
    }
    for i in 0..w.sync.streams.len() {
        let s = &w.sync.streams[i];
        let deliver = match (&s.principal, kind) {
            (Some(p), "vaults") => {
                if w.live_access {
                    super::auth::live_role(w, p, id).is_some()
                } else {
                    s.vaults.iter().any(|v| v == id)
                }
            }
            (None, "databases") => true,
            _ => false,
        };
        if deliver {
            let event = if kind == "vaults" { "vault" } else { "database" };
            w.sync.streams[i].pipe.push(sse(event, &data));
        }
    }
}

/// `event: access` to every open stream of these subjects (what `/internal/notify` does).
pub(crate) fn notify_access(w: &mut World, subjects: &[String], data: &Value) {
    end_expired_streams(w);
    for s in &w.sync.streams {
        if s.principal.as_ref().is_some_and(|p| subjects.contains(p)) {
            s.pipe.push(sse("access", data));
        }
    }
}

/// A verified JWT caller.
struct Caller {
    principal: String,
    vlt: Vec<VaultClaim>,
    exp: Option<i64>,
}

fn jwt_caller(w: &World, req: &Req) -> Result<Caller, HttpResponse> {
    let token = req.bearer();
    let unauthorized = || error(401, "unauthorized", "Missing or invalid access token.");
    if token.is_empty() || !ov_crypto::jwt::is_jwt(token) {
        return Err(unauthorized());
    }
    let opts = VerifyOptions {
        issuer: super::auth::ISSUER.into(),
        audience: "ov-sync".into(),
        now: w.now_s(),
        skew: DEFAULT_SKEW_SECS,
    };
    let claims = verify_jwt(token, &w.auth.jwks(), &opts).map_err(|_| unauthorized())?;
    Ok(Caller { principal: claims.sub, vlt: claims.vlt.unwrap_or_default(), exp: claims.exp })
}

/// The caller's role on a vault and its quota: from `vlt`, or the live access table.
fn role(w: &World, c: &Caller, vault: &str) -> Option<(u8, Option<u64>)> {
    if w.live_access {
        return super::auth::live_role(w, &c.principal, vault).map(|r| (rank(&r), None));
    }
    c.vlt.iter().find(|v| v.id == vault).map(|v| (rank(&v.r), v.q))
}

fn device_user(w: &World, req: &Req) -> Result<String, HttpResponse> {
    w.sync
        .device_tokens
        .get(req.bearer())
        .cloned()
        .ok_or_else(|| error(401, "unauthorized", "Missing or invalid access token."))
}

type Handled = (Option<&'static str>, Option<HttpResponse>, Option<Arc<StreamPipe>>);

/// Answers a request below `/api/v1`.
pub(crate) fn handle(w: &mut World, req: &Req) -> Handled {
    macro_rules! route {
        ($m:ident $pat:literal, |$p:ident| $body:expr) => {
            if let Some($p) = matches(req, Method::$m, $pat) {
                #[allow(clippy::redundant_closure_call)]
                let res: Res = (|| -> Res { $body })();
                return (Some($pat), Some(res.unwrap_or_else(|e| e)), None);
            }
        };
    }
    if matches(req, Method::Get, "/events").is_some() {
        return match events(w, req) {
            Ok((res, pipe)) => (Some("/events"), Some(res), Some(pipe)),
            Err(e) => (Some("/events"), Some(e), None),
        };
    }
    route!(Get "/health", |_p| ok(200, &json!({ "status": "ok" })));
    // ---- JWT routes
    route!(Get "/vaults", |_p| list_vaults(w, req));
    route!(Get "/vaults/{vault}", |p| vault_route(w, req, &p, Access::Read).and_then(|key| get_blob(w, req, &key)));
    route!(Put "/vaults/{vault}", |p| put_vault(w, req, &p));
    route!(Delete "/vaults/{vault}", |p| {
        let key = vault_route(w, req, &p, Access::Manage)?;
        delete_blob(w, &key)
    });
    route!(Get "/vaults/{vault}/history", |p| vault_route(w, req, &p, Access::Read).and_then(|key| history(w, &key)));
    route!(Get "/vaults/{vault}/history/{revision}", |p| {
        let key = vault_route(w, req, &p, Access::Read)?;
        revision(w, &key, p.get("revision"))
    });
    // ---- legacy device-token routes
    route!(Get "/databases", |_p| {
        device_user(w, req)?;
        let list: Vec<BlobMeta> = w
            .sync
            .blobs
            .iter()
            .filter(|(k, v)| k.starts_with("databases/") && !v.is_empty())
            .map(|(k, v)| meta(k, v.last().expect("not empty")))
            .collect();
        ok(200, &json!({ "databases": list }))
    });
    route!(Get "/databases/{id}", |p| {
        device_user(w, req)?;
        get_blob(w, req, &format!("databases/{}", p.get("id")))
    });
    route!(Put "/databases/{id}", |p| {
        device_user(w, req)?;
        put_blob(w, req, &format!("databases/{}", p.get("id")), None)
    });
    route!(Delete "/databases/{id}", |p| {
        device_user(w, req)?;
        delete_blob(w, &format!("databases/{}", p.get("id")))
    });
    route!(Get "/databases/{id}/history", |p| {
        device_user(w, req)?;
        history(w, &format!("databases/{}", p.get("id")))
    });
    route!(Get "/databases/{id}/history/{revision}", |p| {
        device_user(w, req)?;
        revision(w, &format!("databases/{}", p.get("id")), p.get("revision"))
    });
    route!(Post "/devices/pairing/claim", |_p| {
        let body: PairingClaimRequest =
            req.json().map_err(|_| error(400, "invalid_request", "Unknown or expired pairing code."))?;
        let Some(d) = w.sync.pairing.remove(&body.code) else {
            return Err(error(400, "invalid_request", "Unknown or expired pairing code."));
        };
        w.sync.device_tokens.insert(d.token.clone(), d.user.clone());
        ok(201, &json!({ "user": d.user, "deviceId": d.device_id, "token": d.token }))
    });
    route!(Post "/devices/pairing", |_p| {
        let user = device_user(w, req)?;
        let code = "WXYZ-2345".to_string();
        let device_id = w.uuid();
        let token = format!("dev-token-{}", &device_id[..8]);
        w.sync.pairing.insert(code.clone(), Pairing { user, device_id, token });
        ok(201, &json!({ "code": code, "expiresAt": iso(w.now_ms() + 5 * 60_000) }))
    });
    // ---- internal routes (auth server → sync server)
    route!(Post "/internal/notify", |_p| {
        if req.bearer() != INTERNAL_TOKEN {
            return Err(error(401, "unauthorized", "bad internal token"));
        }
        let v = req.value();
        let subjects: Vec<String> = serde_json::from_value(v["subjects"].clone()).unwrap_or_default();
        notify_access(w, &subjects, &v["data"]);
        Ok(empty(204))
    });
    route!(Delete "/internal/vaults/{vault}", |p| {
        if req.bearer() != INTERNAL_TOKEN {
            return Err(error(401, "unauthorized", "bad internal token"));
        }
        if delete(w, &format!("vaults/{}", p.get("vault"))) {
            Ok(empty(204))
        } else {
            Err(error(404, "not_found", "Vault not found."))
        }
    });
    (None, None, None)
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Manage,
}

/// Checks the JWT and the caller's role on `{vault}`; returns the blob key.
fn vault_route(w: &World, req: &Req, p: &Params, need: Access) -> Result<String, HttpResponse> {
    let c = jwt_caller(w, req)?;
    let vault = p.get("vault");
    let Some((r, _)) = role(w, &c, vault) else {
        return Err(error(403, "forbidden", "no access to this vault"));
    };
    if matches!(need, Access::Manage) && r < 3 {
        return Err(error(403, "forbidden", "manage access needed"));
    }
    Ok(format!("vaults/{vault}"))
}

fn list_vaults(w: &World, req: &Req) -> Res {
    let c = jwt_caller(w, req)?;
    let list: Vec<BlobMeta> = w
        .sync
        .blobs
        .iter()
        .filter_map(|(k, v)| {
            let id = k.strip_prefix("vaults/")?;
            role(w, &c, id)?;
            v.last().map(|v| meta(k, v))
        })
        .collect();
    ok(200, &json!({ "vaults": list }))
}

fn get_blob(w: &World, req: &Req, key: &str) -> Res {
    let Some(v) = w.sync.current(key) else {
        return Err(error(404, "not_found", "Database not found."));
    };
    if req.header("if-none-match") == Some(v.etag.as_str()) {
        return Ok(HttpResponse { status: 304, headers: version_headers(v), body: vec![] });
    }
    Ok(bytes(200, v.data.clone(), v))
}

fn put_vault(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = jwt_caller(w, req)?;
    let vault = p.get("vault");
    let Some((r, q)) = role(w, &c, vault) else {
        return Err(error(403, "forbidden", "no access to this vault"));
    };
    let key = format!("vaults/{vault}");
    let creating = req.header("if-none-match") == Some("*");
    if (creating && r < 3) || r < 2 {
        let need = if creating { "manage" } else { "write" };
        return Err(error(403, "forbidden", &format!("{need} access needed")));
    }
    put_blob(w, req, &key, q)
}

fn put_blob(w: &mut World, req: &Req, key: &str, quota: Option<u64>) -> Res {
    let cur = w.sync.current(key).map(|v| v.etag.clone());
    let if_match = req.header("if-match");
    let if_none = req.header("if-none-match");
    if if_match.is_none() && if_none.is_none() {
        return Err(error(428, "precondition_required", "precondition required"));
    }
    if if_none == Some("*") && cur.is_some() {
        return Err(error(412, "precondition_failed", "The database already exists."));
    }
    if let Some(m) = if_match {
        if cur.as_deref() != Some(m) {
            return Err(error(412, "precondition_failed", "The database was changed on the server."));
        }
    }
    if let Some(max) = quota.filter(|max| req.body.len() as u64 > *max) {
        return Err(error_with(
            413,
            "quota_exceeded",
            "The vault is larger than the plan allows.",
            json!({ "max": max }),
        ));
    }
    store(w, key, &req.body);
    let v = w.sync.current(key).expect("just stored");
    let status = if cur.is_some() { 200 } else { 201 };
    let body = serde_json::to_value(meta(key, v)).expect("serialises");
    let headers: Vec<(&str, String)> = vec![
        ("ETag", v.etag.clone()),
        ("X-Database-Revision", v.revision.to_string()),
        ("Last-Modified", http_date(v.updated_at_ms)),
    ];
    Ok(json_response(status, &body, &headers))
}

fn delete_blob(w: &mut World, key: &str) -> Res {
    if delete(w, key) {
        Ok(empty(204))
    } else {
        Err(error(404, "not_found", "Database not found."))
    }
}

fn history(w: &World, key: &str) -> Res {
    let Some(list) = w.sync.blobs.get(key).filter(|l| !l.is_empty()) else {
        return Err(error(404, "not_found", "Database not found."));
    };
    let versions: Vec<BlobMeta> = list.iter().rev().map(|v| meta(key, v)).collect();
    ok(200, &json!({ "versions": versions }))
}

fn revision(w: &World, key: &str, rev: &str) -> Res {
    let v = rev.parse::<i64>().ok().and_then(|n| w.sync.blobs.get(key)?.iter().find(|v| v.revision == n));
    match v {
        Some(v) => Ok(bytes(200, v.data.clone(), v)),
        None => Err(error(404, "not_found", "Version not found.")),
    }
}

fn events(w: &mut World, req: &Req) -> Result<(HttpResponse, Arc<StreamPipe>), HttpResponse> {
    let pipe = Arc::new(StreamPipe::default());
    let reg = if w.sync.device_tokens.contains(req.bearer()) {
        StreamReg { principal: None, vaults: vec![], exp: None, pipe: pipe.clone() }
    } else {
        let c = jwt_caller(w, req)?;
        let vaults = c.vlt.iter().map(|v| v.id.clone()).collect();
        StreamReg { principal: Some(c.principal), vaults, exp: c.exp, pipe: pipe.clone() }
    };
    end_expired_streams(w);
    w.sync.streams.push(reg);
    pipe.push(b": connected\n\n".to_vec());
    let res = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "text/event-stream".into()), ("Cache-Control".into(), "no-store".into())],
        body: vec![],
    };
    Ok((res, pipe))
}
