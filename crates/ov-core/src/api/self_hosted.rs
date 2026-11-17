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
        let token = crate::impls::util::secret_text(device_token, "device token")?;
        SelfHosted::new_impl(client, server_url, token)
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
        SelfHosted::pair_impl(client, server_url, &code, &device_name, &cancel).await
    }

    /// The server paired earlier, from the stored device token; `None` if not paired.
    pub async fn restore(client: OvClient, server_url: String) -> Result<Option<SelfHosted>, OvError> {
        SelfHosted::restore_impl(client, server_url).await
    }

    /// The server URL.
    pub fn server_url(&self) -> String {
        self.inner.server_url.clone()
    }

    /// `GET /health`, as JSON text.
    pub async fn health(&self, cancel: CancelToken) -> Result<String, OvError> {
        self.health_impl(&cancel).await
    }

    /// The databases on the server.
    pub async fn list_databases(&self, cancel: CancelToken) -> Result<Vec<BlobMeta>, OvError> {
        self.list_impl(&cancel).await
    }

    /// A pairing code for another device.
    pub async fn create_pairing_code(&self, cancel: CancelToken) -> Result<PairingCode, OvError> {
        self.pairing_code_impl(&cancel).await
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
        crate::impls::syncing::sync_database(self, &database_id, &kdbx, &credentials, &cancel).await
    }

    /// The legacy `event: database` stream
    /// ([`AccountEvent::DatabaseChanged`](crate::api::AccountEvent::DatabaseChanged)).
    pub async fn events(&self, cancel: CancelToken) -> Result<EventStream, OvError> {
        cancel.check()?;
        let h = &self.inner.client.host;
        let client = ov_sync::SyncClient::new(
            h.http.clone(),
            h.clock.clone(),
            self.inner.sync.clone(),
            std::sync::Arc::new(ov_sync::StaticToken(Some(self.inner.token.to_string()))),
        );
        Ok(crate::impls::syncing::stream(client, None))
    }
}
