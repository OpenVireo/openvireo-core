//! The FFI edge: every call into ov-core goes through one of these, so a panic becomes
//! `OvError { code: internal }` instead of crossing into Swift (rust-core-tasks.md §2.3).
//! That is also why every binding method `throws` in Swift, even where the core's method can't
//! fail: today's `todo!()` stubs panic, and Swift would otherwise trap on a non-throwing call.

use std::any::Any;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};

use futures::FutureExt as _;

use crate::error::OvError;

fn panic_error(payload: Box<dyn Any + Send>) -> OvError {
    let text = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into());
    OvError::internal(format!("panic in openvireo-core: {text}"))
}

/// Runs a fallible core call.
pub(crate) fn guard<T>(f: impl FnOnce() -> Result<T, ov_error::OvError>) -> Result<T, OvError> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r.map_err(OvError::from),
        Err(p) => Err(panic_error(p)),
    }
}

/// Runs an infallible core call.
pub(crate) fn guard_ok<T>(f: impl FnOnce() -> T) -> Result<T, OvError> {
    catch_unwind(AssertUnwindSafe(f)).map_err(panic_error)
}

/// Awaits a fallible core future.
pub(crate) async fn guard_async<T>(f: impl Future<Output = Result<T, ov_error::OvError>>) -> Result<T, OvError> {
    match AssertUnwindSafe(f).catch_unwind().await {
        Ok(r) => r.map_err(OvError::from),
        Err(p) => Err(panic_error(p)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OvErrorCode;

    fn code(e: &OvError) -> OvErrorCode {
        let OvError::Failure { code, .. } = e;
        *code
    }

    #[test]
    fn panics_become_internal() {
        let e = guard_ok(|| -> u8 { todo!() }).unwrap_err();
        assert_eq!(code(&e), OvErrorCode::Internal);
        let e = guard(|| -> Result<u8, ov_error::OvError> { panic!("boom {}", 1) }).unwrap_err();
        assert!(e.to_string().contains("boom 1"));
        async fn stub() -> Result<u8, ov_error::OvError> {
            todo!()
        }
        let e = futures::executor::block_on(guard_async(stub())).unwrap_err();
        assert_eq!(code(&e), OvErrorCode::Internal);
    }

    #[test]
    fn errors_pass_through() {
        let e = guard(|| -> Result<(), _> { Err(ov_error::OvErrorCode::Aborted.into()) }).unwrap_err();
        assert_eq!(code(&e), OvErrorCode::Aborted);
    }
}
