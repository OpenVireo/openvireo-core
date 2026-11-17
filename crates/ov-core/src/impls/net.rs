//! Sending requests through the Host transport, raced against the call's [`CancelToken`].

use futures::future::{select, Either};
use futures::pin_mut;
use ov_error::{OvError, OvErrorCode};

use crate::api::CancelToken;
use crate::host::{Host, HttpRequest, HttpResponse};

/// Sends `req`; `aborted` once `cancel` fires, `network_error` when the transport fails.
pub(crate) async fn send(host: &Host, req: HttpRequest, cancel: &CancelToken) -> Result<HttpResponse, OvError> {
    cancel.check()?;
    let fut = host.http.send(req);
    let cancelled = cancel.cancelled();
    pin_mut!(fut, cancelled);
    match select(fut, cancelled).await {
        Either::Left((res, _)) => res.map_err(OvError::from),
        Either::Right(_) => Err(OvError::new(OvErrorCode::Aborted, "cancelled")),
    }
}
