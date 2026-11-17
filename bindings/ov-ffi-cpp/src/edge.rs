//! The FFI edge: panics become `internal`, failures are recorded for `ov::call()`, and async calls
//! block the calling thread with cancellation.

use std::cell::RefCell;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};

use futures::future::{select, Either};
use ov_core::api::CancelToken;
use ov_error::{OvError, OvErrorCode};

use crate::ffi::ErrorInfo;

thread_local! {
    static LAST_ERROR: RefCell<Option<OvError>> = const { RefCell::new(None) };
}

/// The error a bridged call returns. cxx throws it in C++ as `rust::Error` with this `Display`
/// text (`"<wire code>: <message>"`); the whole OvError is kept for `take_last_error`.
#[derive(Debug)]
pub struct FfiError(pub OvError);

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0.wire_code(), self.0.message)
    }
}

/// `ov::take_last_error()`: the OvError of the last failed call on this thread, then cleared.
pub(crate) fn take_last_error() -> ErrorInfo {
    match LAST_ERROR.with(|l| l.borrow_mut().take()) {
        Some(e) => error_info(&e),
        None => ErrorInfo {
            code: OvErrorCode::Internal.as_str().into(),
            message: "no failed call recorded on this thread".into(),
            ..ErrorInfo::default()
        },
    }
}

pub(crate) fn error_info(e: &OvError) -> ErrorInfo {
    ErrorInfo {
        code: e.wire_code().to_string(),
        message: e.message.clone(),
        status: e.status.unwrap_or(0),
        has_retry_after: e.retry_after.is_some(),
        retry_after: e.retry_after.unwrap_or(0),
        details: e.details.clone().unwrap_or_default(),
        server_code: e.server_code.clone().unwrap_or_default(),
    }
}

/// Runs a synchronous call at the edge: a panic becomes `internal`, and a failure is recorded for
/// `take_last_error` before it is returned.
pub(crate) fn edge<T>(f: impl FnOnce() -> Result<T, OvError>) -> Result<T, FfiError> {
    let result = catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|payload| {
        let what = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".into());
        Err(OvError::internal(format!("panic in openvireo-core: {what}")))
    });
    result.map_err(|e| {
        LAST_ERROR.with(|l| *l.borrow_mut() = Some(e.clone()));
        FfiError(e)
    })
}

/// Runs an async core call to completion on the calling thread. It returns `aborted` as soon as
/// `cancel` fires (even if the core future is still pending), and without starting if it already
/// had.
pub(crate) fn edge_blocking<T, F>(cancel: &CancelToken, make: impl FnOnce() -> F) -> Result<T, FfiError>
where
    F: Future<Output = Result<T, OvError>>,
{
    edge(|| {
        cancel.check()?;
        let fut = Box::pin(make());
        match futures::executor::block_on(select(fut, cancel.cancelled())) {
            Either::Left((result, _)) => result,
            Either::Right(((), _)) => Err(OvError::new(OvErrorCode::Aborted, "cancelled")),
        }
    })
}

/// [`edge_blocking`] with the caller's token, which is also handed to the core call.
pub(crate) fn run<T, F>(
    cancel: &crate::handles::CancelToken,
    make: impl FnOnce(CancelToken) -> F,
) -> Result<T, FfiError>
where
    F: Future<Output = Result<T, OvError>>,
{
    let c = cancel.0.clone();
    edge_blocking(&cancel.0, move || make(c))
}

/// [`edge_blocking`] for an async core call that takes no token (local store reads and writes).
pub(crate) fn block<T, F>(make: impl FnOnce() -> F) -> Result<T, FfiError>
where
    F: Future<Output = Result<T, OvError>>,
{
    edge_blocking(&CancelToken::new(), make)
}

/// Maps an exception a C++ Host method threw. A `what()` that starts with a wire code and `": "`
/// keeps that code; anything else is `internal`.
pub(crate) fn host_exception(e: cxx::Exception) -> OvError {
    let what = e.what();
    if let Some((code, msg)) = what.split_once(": ") {
        if let Some(code) = OvErrorCode::from_wire(code) {
            return OvError::new(code, msg);
        }
    }
    OvError::internal(format!("host: {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panics_become_internal_and_are_recorded() {
        let r: Result<(), FfiError> = edge(|| panic!("boom"));
        let e = r.unwrap_err();
        assert_eq!(e.0.code, OvErrorCode::Internal);
        assert!(e.to_string().starts_with("internal: panic in openvireo-core: boom"));
        let info = take_last_error();
        assert_eq!(info.code, "internal");
        // Taken once.
        assert_eq!(take_last_error().message, "no failed call recorded on this thread");
    }

    #[test]
    fn errors_keep_every_field() {
        let err = OvError::from_server(429, Some("deletion_blocked"), "slow down")
            .with_retry_after(30)
            .with_details(r#"{"orgs":[]}"#);
        let r: Result<(), FfiError> = edge(|| Err(err.clone()));
        assert!(r.is_err());
        let info = take_last_error();
        assert_eq!(info.code, err.wire_code());
        assert_eq!(info.status, 429);
        assert!(info.has_retry_after);
        assert_eq!(info.retry_after, 30);
        assert_eq!(info.details, r#"{"orgs":[]}"#);
        assert_eq!(info.server_code, "deletion_blocked");
    }

    #[test]
    fn success_records_nothing() {
        assert_eq!(edge(|| Ok(7)).unwrap(), 7);
        assert_eq!(take_last_error().message, "no failed call recorded on this thread");
    }

    #[test]
    fn blocking_calls_honour_cancel() {
        let token = CancelToken::new();
        assert_eq!(edge_blocking(&token, || async { Ok(1) }).unwrap(), 1);
        // A pending future is abandoned once the token fires.
        let t2 = token.clone();
        let r: Result<(), FfiError> = edge_blocking(&token, || async move {
            t2.cancel();
            futures::future::pending::<()>().await;
            Ok(())
        });
        assert_eq!(r.unwrap_err().0.code, OvErrorCode::Aborted);
        // Already cancelled: doesn't start.
        let r: Result<(), FfiError> = edge_blocking(&token, || async { panic!("must not run") });
        assert_eq!(r.unwrap_err().0.code, OvErrorCode::Aborted);
        let _ = take_last_error();
    }

    #[test]
    fn todo_stubs_fail_as_internal() {
        let r: Result<(), FfiError> = edge_blocking(&CancelToken::new(), || async { todo!() });
        assert_eq!(r.unwrap_err().0.code, OvErrorCode::Internal);
        let _ = take_last_error();
    }
}
