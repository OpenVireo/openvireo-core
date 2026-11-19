//! Serde types ⇄ plain JS values through JSON, for wire-shaped records (public keys, wrapped
//! keysets, JWT claims, request bodies) whose JS shape is exactly their JSON (snake_case keys).

use ov_error::{OvError, OvErrorCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

/// `value` as a plain JS value (`JSON.parse` of its serde JSON).
pub(crate) fn to_js<T: Serialize>(value: &T) -> Result<JsValue, OvError> {
    let text = Zeroizing::new(
        serde_json::to_string(value).map_err(|e| OvError::internal(format!("JSON encoding failed: {e}")))?,
    );
    js_sys::JSON::parse(&text).map_err(|_| OvError::internal("JSON.parse failed"))
}

/// A JS value read as `T` (`JSON.stringify`, then serde). `path` names it in errors.
pub(crate) fn from_js<T: DeserializeOwned>(v: &JsValue, path: &str) -> Result<T, OvError> {
    let bad = |what: String| OvError::new(OvErrorCode::InvalidRequest, format!("{path}: {what}"));
    let text = js_sys::JSON::stringify(v).map_err(|_| bad("not JSON-serialisable".into()))?;
    let text = Zeroizing::new(String::from(text));
    serde_json::from_str(&text).map_err(|e| bad(e.to_string()))
}
