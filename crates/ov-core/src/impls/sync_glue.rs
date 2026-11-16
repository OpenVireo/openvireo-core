//! Glue to W2-Y's `ov-sync` (`sync_kdbx`, the TS-compatible sync state, the clock-skew check and
//! the event stream). `ov-sync` isn't merged yet: until it is, the operations below return
//! [`needs_sync`] (`internal`, "needs ov-sync"). The facade calls only this module for them, so the
//! switch is local.

use ov_error::OvError;

use crate::api::{CancelToken, SyncOptions, SyncReport, Vault};

/// Whether `ov-sync` is wired in. Callers check it before a server-side step whose follow-up needs
/// a sync (so nothing is half-done).
pub(crate) const AVAILABLE: bool = false;

/// The fallback for operations `ov-sync` owns.
pub(crate) fn needs_sync() -> OvError {
    OvError::internal("needs ov-sync")
}

/// SPEC §20: a clock more than five minutes off the server's.
// W2-Y: ov_sync::is_clock_skewed.
pub(crate) fn is_clock_skewed(offset_ms: i64) -> bool {
    offset_ms.unsigned_abs() > 5 * 60 * 1000
}

/// Downloads, merges and uploads an account vault (conditional PUT, merge and retry on 412), keeping
/// the sync state and pending edits in the BlobCache; re-keys to `rekey_to` before the upload
/// (rotation). On success the vault's database, etag, conflicts and the account's clock offset are
/// updated.
// W2-Y: ov_sync::sync_kdbx over vaults/<id> with the account's refreshing token.
pub(crate) async fn sync_account_vault(
    vault: &Vault,
    options: SyncOptions,
    rekey_to: Option<&[u8; 32]>,
    cancel: &CancelToken,
) -> Result<SyncReport, OvError> {
    let _ = (vault, options, rekey_to);
    cancel.check()?;
    Err(needs_sync())
}

/// Syncs a self-hosted database (`databases/<id>`, device token) and returns the merged database
/// encrypted with the same credentials.
// W2-Y: ov_sync::sync_kdbx over databases/<id>, state in the BlobCache.
pub(crate) async fn sync_database(
    sh: &crate::api::SelfHosted,
    database_id: &str,
    kdbx: &[u8],
    credentials: &crate::api::KdbxCredentials,
    cancel: &CancelToken,
) -> Result<crate::api::SelfHostedSyncResult, OvError> {
    let _ = (sh, database_id, kdbx, credentials);
    cancel.check()?;
    Err(needs_sync())
}

/// The next event from an open stream (connect, parse SSE, reconnect with backoff).
// W2-Y: ov_sync event stream.
pub(crate) async fn next_event(
    stream: &crate::api::EventStream,
    cancel: &CancelToken,
) -> Result<Option<crate::api::AccountEvent>, OvError> {
    let _ = stream;
    cancel.check()?;
    Err(needs_sync())
}
