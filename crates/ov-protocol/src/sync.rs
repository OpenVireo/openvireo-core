//! Request builders and response parsers for the sync server, ported from `sync/client.ts`: the
//! JWT routes of `sync-openapi.yaml` (`vaults/*`, `events`) and the legacy device-token routes
//! (`databases/*`, `devices/pairing*`, `health`), with conditional GET/HEAD/PUT.
//!
//! The 401 → refresh → retry-once rule of `SyncClient.request` is the caller's (ov-sync): it applies
//! when the token comes from a refreshable source, not to a fixed device token.

use ov_error::{OvError, OvErrorCode};
use sha2::{Digest, Sha256};

use crate::error::{check_redirect, error_from_response, parse_json};
use crate::http::{is_ok, HttpRequest, HttpResponse, Method};
use crate::types::{BlobHistory, BlobList, BlobMeta, DatabaseList, PairingClaim, PairingClaimRequest, PairingCode};
use crate::url::{json_request, seg, to_json, Base};

/// Builds requests for a sync server base URL (`{sync}`, which ends in `/api/v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncApi {
    base: Base,
}

/// One blob: `vaults/<id>` (JWT) or `databases/<id>` (legacy).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobPath(String);

impl BlobPath {
    /// `vaults/<id>`.
    pub fn vault(id: &str) -> Self {
        BlobPath(format!("vaults/{}", seg(id)))
    }

    /// `databases/<id>` (the id is trimmed, as in the SDK).
    pub fn database(id: &str) -> Self {
        BlobPath(format!("databases/{}", seg(id.trim())))
    }

    /// The path relative to the base URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The precondition of a conditional upload (SPEC §13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutCondition {
    /// `If-Match: <etag>`: update exactly that version.
    IfMatch(String),
    /// `If-None-Match: *`: create the blob.
    Create,
}

/// A blob version from the `ETag`, `X-Database-Revision` and `Last-Modified` headers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobVersion {
    /// `ETag` (`""` when absent).
    pub etag: String,
    /// `X-Database-Revision`, `None` when absent or not a number.
    pub revision: Option<i64>,
    /// `Last-Modified`.
    pub last_modified: Option<String>,
}

/// `HEAD` result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadResult {
    /// 200: the blob exists (and differs from `If-None-Match`).
    Ok(BlobVersion),
    /// 304: unchanged from `If-None-Match`.
    NotModified(BlobVersion),
    /// 404.
    NotFound,
}

/// `GET` result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetResult {
    /// 200 with the bytes.
    Ok {
        /// The blob.
        data: Vec<u8>,
        /// Its version.
        version: BlobVersion,
    },
    /// 304: unchanged from `If-None-Match`.
    NotModified(BlobVersion),
    /// 404.
    NotFound,
}

/// `PUT` result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutResult {
    /// 201 (created) rather than 200 (updated).
    pub created: bool,
    /// The new version; the etag and revision fall back to the JSON body when headers are missing.
    pub version: BlobVersion,
    /// The JSON body, when the server sent one.
    pub meta: Option<BlobMeta>,
}

/// One kept version from `<path>/history/<revision>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    /// The bytes.
    pub data: Vec<u8>,
    /// Its version headers.
    pub version: BlobVersion,
}

impl SyncApi {
    /// `sync` is `{sync}` from discovery, e.g. `https://sync.openvireo.com/api/v1`. Fails with
    /// `insecure_url` unless it is https (or loopback http, SPEC §1).
    pub fn new(sync: &str) -> Result<Self, OvError> {
        Ok(SyncApi { base: Base::new(sync, "server")? })
    }

    /// For a self-hosted server URL like `https://sync.example.org`: adds `/api/v1`, as the
    /// desktop does.
    pub fn self_hosted(server_url: &str) -> Result<Self, OvError> {
        SyncApi::new(&format!("{}/api/v1", server_url.trim().trim_end_matches('/')))
    }

    /// The base URL, without a trailing slash.
    pub fn base_url(&self) -> &str {
        self.base.as_str()
    }

    /// A request as `send` makes it (no `Accept`), with a bearer token when given.
    fn raw(&self, method: Method, path: &str, token: Option<&str>, headers: Vec<(String, String)>) -> HttpRequest {
        let mut headers = headers;
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            headers.push(("Authorization".into(), format!("Bearer {t}")));
        }
        HttpRequest { method, url: self.base.url(path), headers, body: None, keepalive: false }
    }

    // ---------------------------------------------------------------- blobs

    /// `HEAD <blob>`, optionally `If-None-Match` → [`parse_blob_head`].
    pub fn build_blob_head(&self, blob: &BlobPath, token: Option<&str>, if_none_match: Option<&str>) -> HttpRequest {
        let h = if_none_match.map(|e| vec![("If-None-Match".to_string(), e.to_string())]).unwrap_or_default();
        self.raw(Method::Head, blob.as_str(), token, h)
    }

    /// `GET <blob>`, optionally `If-None-Match` → [`parse_blob_get`].
    pub fn build_blob_get(&self, blob: &BlobPath, token: Option<&str>, if_none_match: Option<&str>) -> HttpRequest {
        let h = if_none_match.map(|e| vec![("If-None-Match".to_string(), e.to_string())]).unwrap_or_default();
        self.raw(Method::Get, blob.as_str(), token, h)
    }

    /// Conditional `PUT <blob>` → [`parse_blob_put`]. A mismatch is 412 `precondition_failed`.
    pub fn build_blob_put(
        &self,
        blob: &BlobPath,
        token: Option<&str>,
        data: Vec<u8>,
        cond: &PutCondition,
    ) -> HttpRequest {
        let precondition = match cond {
            PutCondition::Create => ("If-None-Match".to_string(), "*".to_string()),
            PutCondition::IfMatch(etag) => ("If-Match".to_string(), etag.clone()),
        };
        let headers = vec![precondition, ("Content-Type".into(), "application/octet-stream".into())];
        HttpRequest { body: Some(data), ..self.raw(Method::Put, blob.as_str(), token, headers) }
    }

    /// `DELETE <blob>`, optionally `If-Match` → [`parse_blob_delete`].
    pub fn build_blob_delete(&self, blob: &BlobPath, token: Option<&str>, if_match: Option<&str>) -> HttpRequest {
        let h = if_match.map(|e| vec![("If-Match".to_string(), e.to_string())]).unwrap_or_default();
        self.raw(Method::Delete, blob.as_str(), token, h)
    }

    /// `GET <blob>/history` → [`parse_history`].
    pub fn build_history(&self, blob: &BlobPath, token: Option<&str>) -> HttpRequest {
        let h = vec![("Accept".to_string(), "application/json".to_string())];
        self.raw(Method::Get, &format!("{}/history", blob.as_str()), token, h)
    }

    /// `GET <blob>/history/<revision>` → [`parse_revision`].
    pub fn build_revision(&self, blob: &BlobPath, token: Option<&str>, revision: i64) -> HttpRequest {
        self.raw(Method::Get, &format!("{}/history/{revision}", blob.as_str()), token, vec![])
    }

    // ---------------------------------------------------------------- lists, events

    /// `GET vaults` (JWT) → [`parse_list_vaults`].
    pub fn build_list_vaults(&self, token: &str) -> HttpRequest {
        json_request(Method::Get, self.base.url("vaults"), Some(token), None)
    }

    /// `GET events` (SPEC §11): only CORS-allowed headers (`Accept: text/event-stream` and
    /// `Authorization`), never `Cache-Control`. Web transports ask `fetch` for `cache: "no-store"`.
    /// Read the stream with [`crate::sse::SseParser`]; see [`crate::sse::classify_stream_status`].
    pub fn build_events(&self, token: Option<&str>) -> HttpRequest {
        self.raw(Method::Get, "events", token, vec![("Accept".into(), "text/event-stream".into())])
    }

    // ---------------------------------------------------------------- legacy device-token routes

    /// `GET health` → [`parse_health`].
    pub fn build_health(&self) -> HttpRequest {
        json_request(Method::Get, self.base.url("health"), None, None)
    }

    /// `GET databases` → [`parse_list_databases`].
    pub fn build_list_databases(&self, token: &str) -> HttpRequest {
        json_request(Method::Get, self.base.url("databases"), Some(token), None)
    }

    /// `POST devices/pairing` (needs a device token) → [`parse_pairing_code`].
    pub fn build_create_pairing_code(&self, token: &str) -> HttpRequest {
        json_request(Method::Post, self.base.url("devices/pairing"), Some(token), Some(b"{}".to_vec()))
    }

    /// `POST devices/pairing/claim` (no token; the code is the credential) → [`parse_pairing_claim`].
    pub fn build_claim_pairing_code(&self, code: &str, device_name: &str) -> HttpRequest {
        let body = PairingClaimRequest { code: code.trim().into(), device_name: device_name.into() };
        json_request(Method::Post, self.base.url("devices/pairing/claim"), None, Some(to_json(&body)))
    }
}

/// The version headers of a blob response.
pub fn blob_version(res: &HttpResponse) -> BlobVersion {
    BlobVersion {
        etag: res.header("ETag").unwrap_or_default().to_string(),
        revision: res.header("X-Database-Revision").and_then(|v| v.trim().parse().ok()),
        last_modified: res.header("Last-Modified").map(str::to_string),
    }
}

/// `HEAD <blob>`: 200, 304 or 404; anything else is an error.
pub fn parse_blob_head(res: &HttpResponse) -> Result<HeadResult, OvError> {
    check_redirect(res)?;
    match res.status {
        404 => Ok(HeadResult::NotFound),
        200 => Ok(HeadResult::Ok(blob_version(res))),
        304 => Ok(HeadResult::NotModified(blob_version(res))),
        _ => Err(error_from_response(res)),
    }
}

/// `GET <blob>`: 200 with the bytes, 304 or 404; anything else is an error.
pub fn parse_blob_get(res: &HttpResponse) -> Result<GetResult, OvError> {
    check_redirect(res)?;
    match res.status {
        404 => Ok(GetResult::NotFound),
        304 => Ok(GetResult::NotModified(blob_version(res))),
        200 => Ok(GetResult::Ok { data: res.body.clone(), version: blob_version(res) }),
        _ => Err(error_from_response(res)),
    }
}

/// `PUT <blob>`: 200 or 201. A 412 is `precondition_failed` with the server's message (and no
/// server code or details, as in the SDK).
pub fn parse_blob_put(res: &HttpResponse) -> Result<PutResult, OvError> {
    check_redirect(res)?;
    if res.status != 200 && res.status != 201 {
        let err = error_from_response(res);
        if res.status == 412 {
            return Err(OvError::new(OvErrorCode::PreconditionFailed, err.message).with_status(412));
        }
        return Err(err);
    }
    let meta: Option<BlobMeta> = serde_json::from_slice(&res.body).ok();
    let mut version = blob_version(res);
    if version.etag.is_empty() {
        version.etag = meta.as_ref().map(|m| m.etag.clone()).unwrap_or_default();
    }
    if version.revision.is_none() {
        version.revision = meta.as_ref().map(|m| m.revision);
    }
    Ok(PutResult { created: res.status == 201, version, meta })
}

/// `DELETE <blob>`: 204 or 200.
pub fn parse_blob_delete(res: &HttpResponse) -> Result<(), OvError> {
    check_redirect(res)?;
    if res.status == 204 || res.status == 200 {
        Ok(())
    } else {
        Err(error_from_response(res))
    }
}

/// `GET <blob>/history`: the kept versions, newest first.
pub fn parse_history(res: &HttpResponse) -> Result<Vec<BlobMeta>, OvError> {
    Ok(parse_json::<BlobHistory>(res)?.versions)
}

/// `GET <blob>/history/<revision>`.
pub fn parse_revision(res: &HttpResponse) -> Result<Revision, OvError> {
    check_redirect(res)?;
    if !is_ok(res) {
        return Err(error_from_response(res));
    }
    Ok(Revision { data: res.body.clone(), version: blob_version(res) })
}

/// `GET vaults`.
pub fn parse_list_vaults(res: &HttpResponse) -> Result<Vec<BlobMeta>, OvError> {
    Ok(parse_json::<BlobList>(res)?.vaults)
}

/// `GET databases`.
pub fn parse_list_databases(res: &HttpResponse) -> Result<Vec<BlobMeta>, OvError> {
    Ok(parse_json::<DatabaseList>(res)?.databases)
}

/// `GET health`, as JSON.
pub fn parse_health(res: &HttpResponse) -> Result<serde_json::Value, OvError> {
    parse_json(res)
}

/// `POST devices/pairing`.
pub fn parse_pairing_code(res: &HttpResponse) -> Result<PairingCode, OvError> {
    parse_json(res)
}

/// `POST devices/pairing/claim`.
pub fn parse_pairing_claim(res: &HttpResponse) -> Result<PairingClaim, OvError> {
    parse_json(res)
}

/// Whether `text` looks like a pairing code: `/^[A-Z2-9]{4}[- ]?[A-Z2-9]{4}$/i` after trimming.
pub fn is_pairing_code(text: &str) -> bool {
    let t = text.trim().as_bytes();
    let ok = |b: &u8| b.is_ascii_alphabetic() || (b'2'..=b'9').contains(b);
    match t.len() {
        8 => t.iter().all(ok),
        9 => (t[4] == b'-' || t[4] == b' ') && t[..4].iter().all(ok) && t[5..].iter().all(ok),
        _ => false,
    }
}

/// The desktop's `SyncServerClient::etagFor`: the quoted hex SHA-256 of the data.
pub fn etag_for(data: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::digest(data)))
}

/// The server's clock from the response's `Date` header, in Unix milliseconds. With the local
/// clock this gives `clockOffsetMs = now - server` (good to about a second).
pub fn server_time_ms(res: &HttpResponse) -> Option<i64> {
    parse_http_date(res.header("Date")?)
}

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, RFC 9110 §5.6.7) in Unix milliseconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let [_, day, month, year, time, zone] = parts.as_slice() else { return None };
    if !matches!(*zone, "GMT" | "UTC" | "Z" | "+0000") {
        return None;
    }
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let month = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(month))? as i64 + 1;
    let day: i64 = day.parse().ok()?;
    let year: i64 = year.parse().ok()?;
    let hms: Vec<i64> = time.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let [h, m, sec] = hms.as_slice() else { return None };
    if !(1..=31).contains(&day) || *h > 23 || *m > 59 || *sec > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400) + h * 3600 + m * 60 + sec) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{request_header, response};

    fn api() -> SyncApi {
        SyncApi::self_hosted("https://sync.example/").unwrap()
    }

    #[test]
    fn urls() {
        assert_eq!(api().base_url(), "https://sync.example/api/v1");
        let s = SyncApi::new("https://sync.example/api/v1").unwrap();
        assert_eq!(
            s.build_blob_get(&BlobPath::vault("v1"), Some("t"), None).url,
            "https://sync.example/api/v1/vaults/v1"
        );
        assert_eq!(
            s.build_blob_get(&BlobPath::database(" main "), None, None).url,
            "https://sync.example/api/v1/databases/main"
        );
        assert_eq!(s.build_history(&BlobPath::vault("v"), None).url, "https://sync.example/api/v1/vaults/v/history");
        assert_eq!(
            s.build_revision(&BlobPath::vault("v"), None, 2).url,
            "https://sync.example/api/v1/vaults/v/history/2"
        );
        assert_eq!(SyncApi::new("http://sync.example").unwrap_err().code, OvErrorCode::InsecureUrl);
    }

    /// Ported from sync.test.ts "conditional GET/HEAD/PUT, history and revisions": the requests.
    #[test]
    fn conditional_requests() {
        let db = BlobPath::database("main");
        let put = api().build_blob_put(&db, Some("dev-token"), vec![1, 2, 3], &PutCondition::Create);
        assert_eq!(put.method, Method::Put);
        assert_eq!(request_header(&put, "if-none-match"), Some("*"));
        assert_eq!(request_header(&put, "content-type"), Some("application/octet-stream"));
        assert_eq!(request_header(&put, "authorization"), Some("Bearer dev-token"));
        assert_eq!(put.body.as_deref(), Some(&[1u8, 2, 3][..]));
        let put = api().build_blob_put(&db, None, vec![4], &PutCondition::IfMatch("\"e\"".into()));
        assert_eq!(request_header(&put, "if-match"), Some("\"e\""));
        assert_eq!(request_header(&put, "authorization"), None);
        let head = api().build_blob_head(&db, Some("t"), Some("\"e\""));
        assert_eq!((head.method, request_header(&head, "if-none-match")), (Method::Head, Some("\"e\"")));
        assert_eq!(request_header(&api().build_blob_get(&db, None, None), "if-none-match"), None);
        let del = api().build_blob_delete(&db, Some("t"), None);
        assert_eq!((del.method, del.headers.len()), (Method::Delete, 1));
    }

    #[test]
    fn conditional_responses() {
        let etag = etag_for(&[1, 2, 3]);
        assert_eq!(etag, "\"039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81\"");
        assert_eq!(parse_blob_get(&response(404, &[], "{}")), Ok(GetResult::NotFound));
        let h: &[(&str, &str)] = &[("ETag", &etag), ("X-Database-Revision", "1"), ("Last-Modified", "x")];
        let v = BlobVersion { etag: etag.clone(), revision: Some(1), last_modified: Some("x".into()) };
        assert_eq!(
            parse_blob_get(&response(200, h, vec![1, 2, 3])),
            Ok(GetResult::Ok { data: vec![1, 2, 3], version: v.clone() })
        );
        assert_eq!(parse_blob_get(&response(304, h, "")), Ok(GetResult::NotModified(v.clone())));
        assert_eq!(parse_blob_head(&response(200, h, "")), Ok(HeadResult::Ok(v.clone())));
        assert_eq!(parse_blob_head(&response(304, h, "")), Ok(HeadResult::NotModified(v.clone())));
        assert_eq!(parse_blob_head(&response(404, &[], "")), Ok(HeadResult::NotFound));
        assert_eq!(parse_blob_head(&response(403, &[], "")).unwrap_err().code, OvErrorCode::Forbidden);

        let created = parse_blob_put(&response(201, h, "")).unwrap();
        assert_eq!(
            (created.created, created.version.revision, created.version.etag.as_str()),
            (true, Some(1), etag.as_str())
        );
        // Headers missing: fall back to the JSON body.
        let meta = r#"{"id":"main","etag":"\"m\"","revision":2,"size":1,"updatedAt":"t"}"#;
        let updated = parse_blob_put(&response(200, &[], meta)).unwrap();
        assert_eq!(
            (updated.created, updated.version.revision, updated.version.etag.as_str()),
            (false, Some(2), "\"m\"")
        );
        assert_eq!(updated.meta.unwrap().size, 1);
        let e = parse_blob_put(&response(412, &[], r#"{"error":"stale","code":"conflict"}"#)).unwrap_err();
        assert_eq!(
            (e.code, e.status, e.message.as_str(), e.server_code),
            (OvErrorCode::PreconditionFailed, Some(412), "stale", None)
        );
        let e = parse_blob_put(&response(413, &[], r#"{"error":"big","code":"quota_exceeded","max":10}"#)).unwrap_err();
        assert_eq!((e.code, e.details.as_deref()), (OvErrorCode::QuotaExceeded, Some(r#"{"max":10}"#)));
        assert_eq!(parse_blob_put(&response(428, &[], "")).unwrap_err().code, OvErrorCode::PreconditionRequired);

        let hist = r#"{"versions":[{"id":"main","etag":"b","revision":2,"size":1,"updatedAt":"t"},{"id":"main","etag":"a","revision":1,"size":3,"updatedAt":"t"}]}"#;
        let revs: Vec<i64> = parse_history(&response(200, &[], hist)).unwrap().iter().map(|m| m.revision).collect();
        assert_eq!(revs, [2, 1]);
        assert_eq!(parse_revision(&response(200, &[], vec![1, 2, 3])).unwrap().data, [1, 2, 3]);
        assert_eq!(parse_blob_delete(&response(204, &[], "")), Ok(()));
        assert_eq!(parse_blob_delete(&response(404, &[], "")).unwrap_err().code, OvErrorCode::NotFound);
    }

    /// Ported from sync.test.ts "pairing: claim a code for a device token, then use it".
    #[test]
    fn pairing() {
        assert!(is_pairing_code("abcd efgh"));
        assert!(is_pairing_code(" ABCD-EFGH "));
        assert!(is_pairing_code("WXYZ2345"));
        assert!(!is_pairing_code("ABCD-EFG1"));
        assert!(!is_pairing_code("ABCD--EFGH"));
        let r = api().build_claim_pairing_code(" ABCD-EFGH ", "Web");
        assert_eq!(r.url, "https://sync.example/api/v1/devices/pairing/claim");
        assert_eq!(request_header(&r, "authorization"), None);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(r.body.as_deref().unwrap()).unwrap(),
            serde_json::json!({"code": "ABCD-EFGH", "deviceName": "Web"})
        );
        let claim =
            parse_pairing_claim(&response(200, &[], r#"{"user":"alice","deviceId":"dev-2","token":"dev-token-2"}"#));
        assert_eq!(claim.unwrap().device_id, "dev-2");
        assert_eq!(parse_pairing_claim(&response(400, &[], r#"{"error":"used"}"#)).unwrap_err().status, Some(400));
        let r = api().build_create_pairing_code("dev-token-2");
        assert_eq!((r.method, r.body.as_deref()), (Method::Post, Some(&b"{}"[..])));
        let code =
            parse_pairing_code(&response(200, &[], r#"{"code":"WXYZ-2345","expiresAt":"2026-10-17T00:05:00Z"}"#));
        assert_eq!(code.unwrap().expires_at, "2026-10-17T00:05:00Z");
        assert_eq!(parse_health(&response(200, &[], r#"{"status":"ok"}"#)).unwrap()["status"], "ok");
    }

    /// Ported from sync.test.ts "clock offset from the server's Date header".
    #[test]
    fn server_clock() {
        let r = response(200, &[("Date", "Sun, 06 Nov 1994 08:49:37 GMT")], "");
        assert_eq!(server_time_ms(&r), Some(784_111_777_000));
        assert_eq!(parse_http_date("Sun, 15 Nov 2026 12:00:00 GMT"), Some(1_794_744_000_000));
        assert_eq!(parse_http_date("Thu, 29 Feb 2024 00:00:00 GMT"), Some(1_709_164_800_000));
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(server_time_ms(&response(200, &[], "")), None);
    }
}
