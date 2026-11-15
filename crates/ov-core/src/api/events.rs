//! Live updates from the sync server's event stream (SPEC §11).

use std::sync::Arc;

use ov_error::OvError;

use super::{CancelToken, Rfc3339, SignedOutReason, VaultInfo};
use crate::state::EventStreamState;

/// What the event stream reports, after the account has acted on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountEvent {
    /// A vault changed on the server (`event: vault`). Sync it if `etag` differs from
    /// [`Vault::etag`](crate::api::Vault::etag).
    VaultChanged {
        /// The vault.
        vault_id: String,
        /// Its new ETag.
        etag: Option<String>,
        /// Its new revision.
        revision: Option<u64>,
        /// The vault was deleted.
        deleted: bool,
    },
    /// Access changed (`event: access`): the token was refreshed and this is the new vault list.
    VaultsChanged {
        /// The vault list now.
        vaults: Vec<VaultInfo>,
    },
    /// The session ended because the account was scheduled for deletion or deleted (SPEC §23); the
    /// stream is closed.
    SessionEnded {
        /// Why.
        reason: SignedOutReason,
        /// The erase date, for `DeletionScheduled`.
        at: Option<Rfc3339>,
    },
    /// A legacy self-hosted database changed (`event: database`, SPEC §13).
    DatabaseChanged {
        /// The database.
        database_id: String,
        /// Its new ETag.
        etag: Option<String>,
        /// Its new revision.
        revision: Option<u64>,
        /// It was deleted.
        deleted: bool,
    },
}

/// An open event stream. It reconnects by itself (with a fresh token, after `exp`, and with backoff
/// while offline) until closed or dropped.
#[derive(Clone)]
pub struct EventStream {
    pub(crate) inner: Arc<EventStreamState>,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EventStream { .. }")
    }
}

impl EventStream {
    /// The next event; `None` once the stream is closed. Connection errors while reconnecting are
    /// returned as `Err` and the stream keeps going.
    pub async fn next(&self, cancel: CancelToken) -> Result<Option<AccountEvent>, OvError> {
        todo!()
    }

    /// Reconnects now (e.g. after the app returns to the foreground).
    pub fn reconnect(&self) {
        todo!()
    }

    /// Closes the stream; pending and later [`next`](Self::next) calls return `None`.
    pub fn close(&self) {
        todo!()
    }
}
