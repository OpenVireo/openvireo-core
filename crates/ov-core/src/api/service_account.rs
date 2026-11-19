//! [`ServiceAccount`]: machine access with an `ov_sa_` token (SPEC §9, §15), for the CLI,
//! `openvireo-connect` and the GitHub Action.

use std::sync::Arc;

use ov_error::OvError;

use super::{CancelToken, OvClient, Principal, SecretBytes, ServerConfig, Vault, VaultRole};
use crate::state::ServiceAccountState;

/// A vault granted to a service account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaVault {
    /// The vault id.
    pub id: String,
    /// Its decrypted name.
    pub name: String,
    /// The SA's role.
    pub role: VaultRole,
}

/// The result of [`ServiceAccount::inject`].
#[derive(Clone, PartialEq, Eq)]
pub struct Injected {
    /// The template with every `ov://` reference replaced.
    pub text: SecretBytes,
    /// The values substituted, for masking output.
    pub secrets: Vec<SecretBytes>,
}

impl std::fmt::Debug for Injected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injected").field("secrets", &self.secrets.len()).finish()
    }
}

/// A signed-in service account. SAs have no refresh token: they exchange the secret again when the
/// JWT is about to expire.
#[derive(Clone)]
pub struct ServiceAccount {
    pub(crate) inner: Arc<ServiceAccountState>,
}

impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServiceAccount { .. }")
    }
}

impl ServiceAccount {
    /// Exchanges the token's secret for a JWT and unwraps token → KEK → master key → keyset (SPEC
    /// §9). Discovers the server named in the token unless the client has a
    /// [`ClientConfig::server`](crate::api::ClientConfig::server).
    pub async fn from_token(
        client: OvClient,
        token: SecretBytes,
        cancel: CancelToken,
    ) -> Result<ServiceAccount, OvError> {
        ServiceAccount::from_token_impl(client, token, &cancel).await
    }

    /// The server this SA signed in to: the client's
    /// [`ClientConfig::server`](crate::api::ClientConfig::server), or the one discovered from the
    /// token's URL (TS `sa.config`). Contract-v1.6.
    pub fn server_config(&self) -> ServerConfig {
        self.inner.config.clone()
    }

    /// The server's issuer (`server_config().issuer`). Contract-v1.6.
    pub fn issuer(&self) -> String {
        self.inner.config.issuer.clone()
    }

    /// The SA's id.
    pub fn sa_id(&self) -> String {
        self.inner.sa_id.clone()
    }

    /// `sa:<id>`.
    pub fn principal(&self) -> Principal {
        format!("sa:{}", self.inner.sa_id)
    }

    /// Vaults granted to this SA, names decrypted (cached; `refresh` asks again).
    pub async fn vaults(&self, refresh: bool, cancel: CancelToken) -> Result<Vec<SaVault>, OvError> {
        self.vaults_impl(refresh, &cancel).await
    }

    /// A vault by id or unique name; `not_found` (with how many matched) otherwise.
    pub async fn vault(&self, id_or_name: String, cancel: CancelToken) -> Result<SaVault, OvError> {
        self.vault_impl(&id_or_name, &cancel).await
    }

    /// Downloads and opens a vault (cached; `refresh` downloads again). Edit it with the [`Vault`]
    /// methods and upload with [`Vault::sync`] (TS `edit`).
    pub async fn open_vault(&self, id_or_name: String, refresh: bool, cancel: CancelToken) -> Result<Vault, OvError> {
        self.open_impl(&id_or_name, refresh, &cancel).await
    }

    /// Downloads a vault again, merging with the cached copy (TS `pull`).
    pub async fn pull(&self, id_or_name: String, cancel: CancelToken) -> Result<Vault, OvError> {
        self.pull_impl(&id_or_name, &cancel).await
    }

    /// The value of a secret reference `ov://<vault>/[<group>/…]<entry>/<field>` (SPEC §14).
    pub async fn read(&self, reference: String, cancel: CancelToken) -> Result<SecretBytes, OvError> {
        Ok(self.read_impl(&reference, &cancel).await?.as_bytes().to_vec())
    }

    /// Replaces every `ov://…` reference in a template (up to whitespace, quotes or `}`) with its
    /// value (SPEC §15, `ov inject`).
    pub async fn inject(&self, template: SecretBytes, cancel: CancelToken) -> Result<Injected, OvError> {
        let template = crate::impls::util::secret_text(template, "template")?;
        self.inject_impl(&template, &cancel).await
    }

    /// Sets the field a secret reference names and uploads (needs `write`). With `create`, a missing
    /// entry is created.
    pub async fn write(
        &self,
        reference: String,
        value: SecretBytes,
        create: bool,
        cancel: CancelToken,
    ) -> Result<(), OvError> {
        let value = crate::impls::util::secret_text(value, "field value")?;
        self.write_impl(&reference, &value, create, &cancel).await
    }

    /// Wipes the keyset, vault keys and cached vaults; later calls fail with `signed_out`.
    pub fn close(&self) {
        self.close_impl()
    }
}
