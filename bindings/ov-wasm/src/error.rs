//! `OvError` ⇄ JS, and turning panics into `internal` errors.
//!
//! The package's `index.js` defines `class OvError extends Error` and hands its constructor to
//! [`install`] when the module loads, so every error the core returns is an `instanceof OvError`
//! with `code` (the stable wire string, e.g. `"plan_limit"`), `message`, `status`, `retryAfter`,
//! `details` (parsed JSON object) and `serverCode`. Used without `index.js` (the raw wasm-bindgen
//! glue), errors are plain `Error`s with the same properties and `name = "OvError"`.
//!
//! ## Panics (rust-core-tasks.md §2.3)
//!
//! wasm32-unknown-unknown has no stable `panic = "unwind"`, so `catch_unwind` can't catch a panic
//! here: a panic runs the hook and then traps (`RuntimeError: unreachable`). We meet the rule in two
//! halves:
//!
//! 1. [`install`] sets a panic hook that calls the JS `onPanic(message)` callback before the trap.
//! 2. `index.js` wraps every export: a synchronous trap is caught and rethrown as
//!    `OvError { code: "internal" }` with the panic message; a panic inside an async call (which
//!    traps inside a microtask, so the call's promise would never settle) rejects every pending call
//!    with the same error from `onPanic`.
//!
//! After a panic the instance's memory may be inconsistent (a lock or allocator mid-update), so
//! `index.js` marks the module poisoned: every later call fails with `internal` until the app loads
//! a fresh instance (`loadCore({ fresh: true })`) and makes new handles.

use std::cell::RefCell;

use js_sys::{Function, Reflect};
use ov_error::{OvError, OvErrorCode};
use wasm_bindgen::prelude::*;

use crate::convert::{bad, field, get, obj, set, FromJs, ToJs};

thread_local! {
    static ERROR_CLASS: RefCell<Option<Function>> = const { RefCell::new(None) };
    static ON_PANIC: RefCell<Option<Function>> = const { RefCell::new(None) };
}

/// Called once by `index.js` at load: the `OvError` class to construct errors with, and the
/// callback a panic reports to before the module traps.
#[wasm_bindgen(js_name = "__install")]
pub fn install(error_class: Function, on_panic: Function) {
    ERROR_CLASS.with(|c| *c.borrow_mut() = Some(error_class));
    ON_PANIC.with(|c| *c.borrow_mut() = Some(on_panic));
    std::panic::set_hook(Box::new(|info| {
        let msg = match info.payload().downcast_ref::<&str>() {
            Some(s) => (*s).to_string(),
            None => info.payload().downcast_ref::<String>().cloned().unwrap_or_else(|| "panic".into()),
        };
        let at = info.location().map(|l| format!(" at {}:{}", l.file(), l.line())).unwrap_or_default();
        let text = JsValue::from_str(&format!("the core panicked: {msg}{at}"));
        // `try_with`/`try_borrow`: a panic while the thread-local is torn down or borrowed must not
        // panic again inside the hook.
        let _ = ON_PANIC.try_with(|c| {
            if let Ok(f) = c.try_borrow() {
                if let Some(f) = f.as_ref() {
                    let _ = f.call1(&JsValue::NULL, &text);
                }
            }
        });
    }));
}

/// The JS error for an `OvError`.
pub(crate) fn to_js(e: &OvError) -> JsValue {
    let details = e.details.as_deref().map(|d| js_sys::JSON::parse(d).unwrap_or_else(|_| JsValue::from_str(d)));
    let opts = obj();
    set(&opts, "status", e.status.to_js());
    set(&opts, "retryAfter", e.retry_after.to_js());
    set(&opts, "details", details.unwrap_or(JsValue::UNDEFINED));
    set(&opts, "serverCode", e.server_code.to_js());
    let code = JsValue::from_str(e.wire_code());
    let message = JsValue::from_str(&e.message);
    let class = ERROR_CLASS.with(|c| c.borrow().clone());
    if let Some(class) = class {
        let args = js_sys::Array::of3(&code, &message, &opts);
        if let Ok(err) = Reflect::construct(&class, &args) {
            return err;
        }
    }
    // Raw glue, no index.js: a plain Error carrying the same fields.
    let err = js_sys::Error::new(&e.message);
    err.set_name("OvError");
    let _ = Reflect::set(&err, &"code".into(), &code);
    for key in ["status", "retryAfter", "details", "serverCode"] {
        if let Ok(v) = Reflect::get(&opts, &key.into()) {
            if !v.is_undefined() {
                let _ = Reflect::set(&err, &key.into(), &v);
            }
        }
    }
    err.into()
}

/// Any `Result<T, OvError>` as `Result<JsValue, JsValue>` for a synchronous export.
pub(crate) fn js<T: ToJs>(r: Result<T, OvError>) -> Result<JsValue, JsValue> {
    r.map(|v| v.to_js()).map_err(|e| to_js(&e))
}

/// The `JsValue` error for an argument that didn't convert.
pub(crate) fn arg_err(e: OvError) -> JsValue {
    to_js(&e)
}

impl ToJs for OvError {
    fn to_js(&self) -> JsValue {
        to_js(self)
    }
}

impl crate::convert::Elem for OvError {}

impl FromJs for OvError {
    /// Reads an error back (for `Account.upgradeUrl(error)`): `code` must be a known wire code,
    /// or an untyped server code with a `status`.
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let code: String = field(v, "code", path)?;
        let message: String = field::<Option<String>>(v, "message", path)?.unwrap_or_default();
        let status: Option<u16> = field(v, "status", path)?;
        let mut e = match OvErrorCode::from_wire(&code) {
            Some(c) => OvError::new(c, message),
            None => match status {
                Some(s) => OvError::from_server(s, Some(&code), message),
                None => return Err(bad(&format!("{path}.code"), "an OvError code")),
            },
        };
        e.status = status.or(e.status);
        e.retry_after = field(v, "retryAfter", path)?;
        let details = get(v, "details", path)?;
        e.details = if details.is_undefined() || details.is_null() {
            None
        } else if let Some(s) = details.as_string() {
            Some(s)
        } else {
            js_sys::JSON::stringify(&details).ok().and_then(|s| s.as_string())
        };
        if e.server_code.is_none() {
            e.server_code = field(v, "serverCode", path)?;
        }
        Ok(e)
    }
}
