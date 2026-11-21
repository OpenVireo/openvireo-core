//! HTTP status + body → [`OvError`], ported from `http/request.ts` (`errorFromResponse`,
//! `errorDetails`, the redirect check in `send`, and `sendJson`).

use ov_error::{OvError, OvErrorCode};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};

use crate::http::{is_ok, HttpResponse};

/// The error for a non-2xx response, as `errorFromResponse` builds it:
///
/// - `message` is the body's `error` string, else `HTTP <status>`;
/// - the code is the body's `code` string (kept in `server_code` when it isn't a known code), else
///   the status's code ([`OvErrorCode::for_status`]);
/// - `retry_after` is the `Retry-After` header when it is a whole number of seconds;
/// - `details` carries the extra fields of `recovery_not_ready`, `plan_limit`, `quota_exceeded` and
///   `invalid_passcode` bodies, camelCased.
pub fn error_from_response(res: &HttpResponse) -> OvError {
    let body: Option<Value> = if res.body.is_empty() { None } else { serde_json::from_slice(&res.body).ok() };
    let message = body
        .as_ref()
        .and_then(|b| b.get("error"))
        .and_then(Value::as_str)
        .map_or_else(|| format!("HTTP {}", res.status), str::to_string);
    let code = body.as_ref().and_then(|b| b.get("code")).and_then(Value::as_str);
    let mut err = OvError::from_server(res.status, code, message);
    if let Some(seconds) = retry_after(res) {
        err = err.with_retry_after(seconds);
    }
    if let Some(d) = error_details(err.wire_code(), body.as_ref()) {
        err = err.with_details(d);
    }
    err
}

/// `Retry-After` in whole seconds (`/^\d+$/`; an HTTP date is ignored, as in the SDK). Values past
/// `u32::MAX` saturate.
pub fn retry_after(res: &HttpResponse) -> Option<u32> {
    let v = res.header("Retry-After")?;
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(v.parse::<u64>().map_or(u32::MAX, |n| u32::try_from(n).unwrap_or(u32::MAX)))
}

/// JavaScript truthiness of a parsed body (the SDK's `if (code === "plan_limit" && b)`).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `errorDetails`: the extra fields some error bodies carry, camelCased, as a JSON object string.
fn error_details(code: &str, body: Option<&Value>) -> Option<String> {
    let field = |k: &str| body.and_then(|b| b.get(k));
    let details = match code {
        "recovery_not_ready" => json!({ "notBefore": field("not_before").filter(|v| v.is_string())? }),
        "plan_limit" if body.is_some_and(truthy) => {
            // JSON.stringify drops the keys whose value is undefined.
            let mut m = Map::new();
            for (from, to) in [
                ("limit", "limit"),
                ("max", "max"),
                ("current", "current"),
                ("plan", "plan"),
                ("upgrade_url", "upgradeUrl"),
            ] {
                if let Some(v) = field(from) {
                    m.insert(to.into(), v.clone());
                }
            }
            Value::Object(m)
        }
        "quota_exceeded" => json!({ "max": field("max").filter(|v| v.is_number())? }),
        "invalid_passcode" => json!({ "attemptsLeft": field("attempts_left").filter(|v| v.is_number())? }),
        // SPEC §23 (contract-v1.8): when the account will be erased, and the orgs to hand over first
        "account_pending_deletion" => json!({ "scheduledFor": field("scheduled_for").filter(|v| v.is_string())? }),
        "deletion_blocked" => json!({ "orgs": field("orgs").filter(|v| v.is_array())? }),
        _ => return None,
    };
    Some(details.to_string())
}

/// `send` refuses redirects (they could forward the bearer token elsewhere): any 3xx but 304.
pub fn check_redirect(res: &HttpResponse) -> Result<(), OvError> {
    if (300..400).contains(&res.status) && res.status != 304 {
        return Err(OvError::new(
            OvErrorCode::InvalidRequest,
            "the server answered with a redirect; check the server URL",
        )
        .with_status(res.status));
    }
    Ok(())
}

/// The redirect check, then [`error_from_response`] for anything not 2xx (`sendJson`'s `!res.ok`).
pub fn check_status(res: &HttpResponse) -> Result<(), OvError> {
    check_redirect(res)?;
    if is_ok(res) {
        Ok(())
    } else {
        Err(error_from_response(res))
    }
}

/// `sendJson` for a route that answers with a JSON body: [`check_status`], then the body as `T`.
///
/// A 2xx body that isn't JSON of the expected shape is `server_error` (the SDK would fail later
/// with a `TypeError`). The message names only the serde error category and position, never the
/// body, which may hold tokens.
pub fn parse_json<T: DeserializeOwned>(res: &HttpResponse) -> Result<T, OvError> {
    check_status(res)?;
    let body: &[u8] = if res.body.is_empty() { b"null" } else { &res.body };
    serde_json::from_slice(body).map_err(|e| {
        OvError::new(
            OvErrorCode::ServerError,
            format!(
                "the server's response doesn't match the API ({:?} error at line {}, column {})",
                e.classify(),
                e.line(),
                e.column()
            ),
        )
        .with_status(res.status)
    })
}

/// `sendJson` for a route whose success has no body to read (204, or a body the client ignores).
pub fn parse_empty(res: &HttpResponse) -> Result<(), OvError> {
    check_status(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::response;

    fn err(status: u16, body: &str) -> OvError {
        error_from_response(&response(status, &[], body))
    }

    /// `codeForStatus` in http/request.ts, for a body without a code.
    #[test]
    fn status_table_matches_the_sdk() {
        let table: &[(u16, &str)] = &[
            (400, "invalid_request"),
            (401, "unauthorized"),
            (402, "plan_limit"),
            (403, "forbidden"),
            (404, "not_found"),
            (409, "conflict"),
            (410, "gone"),
            (412, "precondition_failed"),
            (428, "precondition_required"),
            (429, "rate_limited"),
            (500, "server_error"),
            (502, "server_error"),
            (503, "server_error"),
            (504, "server_error"),
            (599, "server_error"),
            (405, "invalid_request"),
            (413, "invalid_request"),
            (418, "invalid_request"),
            (304, "invalid_request"),
        ];
        for &(status, code) in table {
            for body in ["", "not json", r#"{"error":"x"}"#, r#"{"code":5}"#] {
                let e = err(status, body);
                assert_eq!(
                    (e.wire_code(), e.status, e.server_code.as_deref()),
                    (code, Some(status), None),
                    "{status} {body}"
                );
            }
        }
    }

    #[test]
    fn message_and_code_come_from_the_body() {
        let e = err(401, r#"{"error":"wrong code","code":"invalid_mfa"}"#);
        assert_eq!((e.code, e.message.as_str()), (OvErrorCode::InvalidMfa, "wrong code"));
        assert_eq!(err(401, "").message, "HTTP 401");
        assert_eq!(err(500, "<html>").message, "HTTP 500");
        // A body code wins over the status, known or not.
        assert_eq!(err(400, r#"{"error":"x","code":"session_expired"}"#).code, OvErrorCode::SessionExpired);
        let e = err(409, r#"{"error":"hand over","code":"deletion_blocked","orgs":[{"id":"o","name":"n"}]}"#);
        assert_eq!(
            (e.code, e.wire_code(), e.details.as_deref()),
            (OvErrorCode::Conflict, "deletion_blocked", Some(r#"{"orgs":[{"id":"o","name":"n"}]}"#))
        );
        let e =
            err(403, r#"{"error":"pending","code":"account_pending_deletion","scheduled_for":"2026-12-01T00:00:00Z"}"#);
        assert_eq!(
            (e.code, e.wire_code(), e.details.as_deref()),
            (OvErrorCode::Forbidden, "account_pending_deletion", Some(r#"{"scheduledFor":"2026-12-01T00:00:00Z"}"#))
        );
        let e = err(400, r#"{"error":"bad","code":"invalid_code"}"#);
        assert_eq!((e.code, e.wire_code()), (OvErrorCode::InvalidRequest, "invalid_code"));
    }

    #[test]
    fn retry_after_seconds_only() {
        let with = |v: &str| error_from_response(&response(429, &[("retry-after", v)], "")).retry_after;
        assert_eq!(with("30"), Some(30));
        assert_eq!(with("0"), Some(0));
        assert_eq!(with("99999999999"), Some(u32::MAX));
        assert_eq!(with("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(with("-1"), None);
        assert_eq!(with(""), None);
        assert_eq!(err(503, "").retry_after, None);
        let e = error_from_response(&response(503, &[("Retry-After", "5")], ""));
        assert_eq!((e.code, e.retry_after, e.is_unreachable()), (OvErrorCode::ServerError, Some(5), true));
    }

    #[test]
    fn details_are_camel_cased() {
        let e = err(409, r#"{"error":"later","code":"recovery_not_ready","not_before":"2026-11-16T00:00:00Z"}"#);
        assert_eq!(e.details.as_deref(), Some(r#"{"notBefore":"2026-11-16T00:00:00Z"}"#));
        let e = err(409, r#"{"error":"later","code":"recovery_not_ready"}"#);
        assert_eq!(e.details, None);

        let body = r#"{"error":"limit","code":"plan_limit","limit":"personal_vaults","max":1,"current":1,"plan":"free","upgrade_url":"https://x/pricing"}"#;
        let d: Value = serde_json::from_str(err(402, body).details.as_deref().unwrap()).unwrap();
        assert_eq!(
            d,
            json!({"limit":"personal_vaults","max":1,"current":1,"plan":"free","upgradeUrl":"https://x/pricing"})
        );
        // 402 without a body code is plan_limit too, and missing keys are dropped.
        assert_eq!(err(402, r#"{"error":"x","max":3}"#).details.as_deref(), Some(r#"{"max":3}"#));
        assert_eq!(err(402, "").details, None);

        assert_eq!(
            err(413, r#"{"error":"big","code":"quota_exceeded","max":1048576}"#).details.as_deref(),
            Some(r#"{"max":1048576}"#)
        );
        assert_eq!(err(413, r#"{"error":"big","code":"quota_exceeded","max":"1"}"#).details, None);
        assert_eq!(
            err(403, r#"{"error":"no","code":"invalid_passcode","attempts_left":2}"#).details.as_deref(),
            Some(r#"{"attemptsLeft":2}"#)
        );
        assert_eq!(err(403, r#"{"error":"no","code":"invalid_passcode"}"#).details, None);
    }

    #[test]
    fn redirects_and_json() {
        for s in [301, 302, 303, 307, 308] {
            let e = check_status(&response(s, &[("Location", "https://evil")], "")).unwrap_err();
            assert_eq!((e.code, e.status), (OvErrorCode::InvalidRequest, Some(s)));
        }
        assert_eq!(check_redirect(&response(304, &[], "")), Ok(()));
        assert_eq!(parse_empty(&response(204, &[], "")), Ok(()));
        assert_eq!(parse_json::<Value>(&response(200, &[], r#"{"a":1}"#)), Ok(json!({"a":1})));
        assert_eq!(parse_json::<Option<u8>>(&response(204, &[], "")), Ok(None));
        let e = parse_json::<Vec<u8>>(&response(200, &[], r#"{"secret":"tok"}"#)).unwrap_err();
        assert_eq!(e.code, OvErrorCode::ServerError);
        assert!(!e.message.contains("tok"));
        assert_eq!(parse_json::<Value>(&response(404, &[], "")).unwrap_err().code, OvErrorCode::NotFound);
    }
}
