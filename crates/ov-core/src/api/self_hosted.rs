//! [`SelfHosted`]: sync without an account (SPEC §13 `standalone` mode). A device token from a
//! pairing code, then whole-database sync of password-protected `.kdbx` files against
//! `databases/<id>` with the same ETag, merge and event logic as account vaults.

use std::sync::Arc;

use ov_error::OvError;

use super::{BlobMeta, CancelToken, EventStream, KdbxCredentials, OvClient, Rfc3339, SecretBytes, SyncReport};
use crate::state::SelfHostedState;

/// A pairing code for another device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingCode {
    /// `ABCD-EFGH`.
    pub code: String,
    /// When it stops working.
    pub expires_at: Rfc3339,
}

/// The result of [`SelfHosted::sync_database`].
#[derive(Clone, PartialEq, Eq)]
pub struct SelfHostedSyncResult {
    /// The merged database, encrypted with the same credentials: save it as the local file.
    pub kdbx: Vec<u8>,
    /// What the sync did.
    pub report: SyncReport,
}

impl std::fmt::Debug for SelfHostedSyncResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfHostedSyncResult").field("report", &self.report).finish()
    }
}

/// A paired self-hosted sync server.
#[derive(Clone)]
pub struct SelfHosted {
    pub(crate) inner: Arc<SelfHostedState>,
}

impl std::fmt::Debug for SelfHosted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SelfHosted { .. }")
    }
}

impl SelfHosted {
    /// A server with a device token already in hand. Checks the URL (SPEC §1 "Transport").
    pub fn connect(client: OvClient, server_url: String, device_token: SecretBytes) -> Result<SelfHosted, OvError> {
        todo!()
    }

    /// Claims a pairing code (`ABCD-EFGH`) for a device token and keeps the token in the
    /// [SecureStore](crate::host::SecureStore).
    pub async fn pair(
        client: OvClient,
        server_url: String,
        code: String,
        device_name: String,
        cancel: CancelToken,
    ) -> Result<SelfHosted, OvError> {
        todo!()
    }

    /// The server paired earlier, from the stored device token; `None` if not paired.
    pub async fn restore(client: OvClient, server_url: String) -> Result<Option<SelfHosted>, OvError> {
        todo!()
    }

    /// The server URL.
    pub fn server_url(&self) -> String {
        todo!()
    }

    /// `GET /health`, as JSON text.
    pub async fn health(&self, cancel: CancelToken) -> Result<String, OvError> {
        todo!()
    }

    /// The databases on the server.
    pub async fn list_databases(&self, cancel: CancelToken) -> Result<Vec<BlobMeta>, OvError> {
        todo!()
    }

    /// A pairing code for another device.
    pub async fn create_pairing_code(&self, cancel: CancelToken) -> Result<PairingCode, OvError> {
        todo!()
    }

    /// Syncs a local database with `databases/<database_id>`, keeping the sync state in the
    /// [BlobCache](crate::host::BlobCache). `kdbx` and the result are encrypted with `credentials`.
    pub async fn sync_database(
        &self,
        database_id: String,
        kdbx: Vec<u8>,
        credentials: KdbxCredentials,
        cancel: CancelToken,
    ) -> Result<SelfHostedSyncResult, OvError> {
        todo!()
    }

    /// The legacy `event: database` stream
    /// ([`AccountEvent::DatabaseChanged`](crate::api::AccountEvent::DatabaseChanged)).
    pub async fn events(&self, cancel: CancelToken) -> Result<EventStream, OvError> {
        todo!()
    }
}
