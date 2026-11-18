//! Where secrets come from, ported from `packages/cli/src/source.ts`: a service account
//! (`OPENVIREO_SERVICE_ACCOUNT_TOKEN`) or a signed-in user. Both read the same `ov://` references
//! and write through the core's conditional PUT with merge and retry ([`Vault::sync`]).

use std::collections::HashMap;
use std::sync::Mutex;

use ov_core::api::{Account, CancelToken, ServiceAccount, SyncOptions, Vault, VaultRole};
use ov_error::{OvError, OvErrorCode};

/// `VaultSummary`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSummary {
    /// Vault id.
    pub id: String,
    /// Vault name.
    pub name: String,
    /// `read`, `write` or `manage`.
    pub role: String,
}

/// The wire string of a role.
pub fn role_name(r: VaultRole) -> &'static str {
    match r {
        VaultRole::Read => "read",
        VaultRole::Write => "write",
        VaultRole::Manage => "manage",
    }
}

/// The part of [`Source`] that the pure CLI logic (templates, `ov run`) needs.
#[async_trait::async_trait]
pub trait VaultSource: Send + Sync {
    /// `readField(await open(vault), parseReference(reference))`: `vault` is the reference's vault
    /// segment, already parsed by the caller.
    async fn read(&self, vault: &str, reference: &str) -> Result<String, OvError>;
}

/// `pickVault`: an id, or a unique name.
pub fn pick_vault<'a>(all: &'a [VaultSummary], id_or_name: &str, who: &str) -> Result<&'a VaultSummary, OvError> {
    if let Some(v) = all.iter().find(|v| v.id == id_or_name) {
        return Ok(v);
    }
    let by_name: Vec<&VaultSummary> = all.iter().filter(|v| v.name == id_or_name).collect();
    if by_name.len() == 1 {
        return Ok(by_name[0]);
    }
    let message = if by_name.is_empty() {
        format!("vault \"{id_or_name}\" not found or not shared with {who}")
    } else {
        format!("{} vaults are named \"{id_or_name}\"; use the vault id", by_name.len())
    };
    Err(OvError::new(OvErrorCode::NotFound, message).with_status(404))
}

fn nc() -> CancelToken {
    CancelToken::new()
}

fn forbidden(message: String) -> OvError {
    OvError::new(OvErrorCode::Forbidden, message).with_status(403)
}

enum Inner {
    ServiceAccount(ServiceAccount),
    User {
        account: Account,
        /// The vault list, fetched once per process.
        list: tokio::sync::Mutex<Option<Vec<VaultSummary>>>,
        /// Vaults opened so far, by id (downloaded once per process).
        opened: Mutex<HashMap<String, Vault>>,
    },
}

/// The TS `VaultSource`: a service account or a signed-in, unlocked user.
pub struct Source {
    inner: Inner,
}

impl Source {
    /// `serviceAccountSource`.
    pub fn service_account(sa: ServiceAccount) -> Self {
        Source { inner: Inner::ServiceAccount(sa) }
    }

    /// `userSource`.
    pub fn user(account: Account) -> Self {
        Source {
            inner: Inner::User { account, list: tokio::sync::Mutex::new(None), opened: Mutex::new(HashMap::new()) },
        }
    }

    /// `service-account` or `user`.
    pub fn kind(&self) -> &'static str {
        match self.inner {
            Inner::ServiceAccount(_) => "service-account",
            Inner::User { .. } => "user",
        }
    }

    /// The signed-in user's account, for what only users can do (share links).
    pub fn account(&self) -> Option<&Account> {
        match &self.inner {
            Inner::ServiceAccount(_) => None,
            Inner::User { account, .. } => Some(account),
        }
    }

    /// `listVaults`.
    pub async fn list_vaults(&self) -> Result<Vec<VaultSummary>, OvError> {
        match &self.inner {
            Inner::ServiceAccount(sa) => Ok(sa
                .vaults(false, nc())
                .await?
                .into_iter()
                .map(|v| VaultSummary { id: v.id, name: v.name, role: role_name(v.role).into() })
                .collect()),
            Inner::User { account, list, .. } => {
                let mut guard = list.lock().await;
                if let Some(l) = guard.as_ref() {
                    return Ok(l.clone());
                }
                let l: Vec<VaultSummary> = account
                    .vaults(nc())
                    .await?
                    .into_iter()
                    .map(|v| VaultSummary { id: v.id, name: v.name, role: role_name(v.role).into() })
                    .collect();
                *guard = Some(l.clone());
                Ok(l)
            }
        }
    }

    /// `open`: the vault's current contents (downloaded once per process).
    pub async fn open(&self, id_or_name: &str) -> Result<Vault, OvError> {
        match &self.inner {
            Inner::ServiceAccount(sa) => sa.open_vault(id_or_name.to_string(), false, nc()).await,
            Inner::User { account, opened, .. } => {
                let all = self.list_vaults().await?;
                let id = pick_vault(&all, id_or_name, "this account")?.id.clone();
                if let Some(v) = opened.lock().map_err(|_| OvError::internal("lock poisoned"))?.get(&id) {
                    return Ok(v.clone());
                }
                let v = account.open_vault(id.clone(), nc()).await?;
                opened.lock().map_err(|_| OvError::internal("lock poisoned"))?.insert(id, v.clone());
                Ok(v)
            }
        }
    }

    /// The first half of `edit`: the vault, opened, after checking the role allows writing (a
    /// `read` grant fails before anything is sent). Edit it, then call [`Source::upload`].
    pub async fn open_for_edit(&self, id_or_name: &str) -> Result<Vault, OvError> {
        match &self.inner {
            Inner::ServiceAccount(sa) => {
                let v = sa.vault(id_or_name.to_string(), nc()).await?;
                if v.role == VaultRole::Read {
                    let name = if v.name.is_empty() { &v.id } else { &v.name };
                    return Err(forbidden(format!("this service account can only read vault \"{name}\"")));
                }
                sa.open_vault(v.id, false, nc()).await
            }
            Inner::User { .. } => {
                let all = self.list_vaults().await?;
                let v = pick_vault(&all, id_or_name, "this account")?;
                if v.role == "read" {
                    let name = if v.name.is_empty() { &v.id } else { &v.name };
                    return Err(forbidden(format!("you can only read vault \"{name}\"")));
                }
                self.open(&v.id.clone()).await
            }
        }
    }

    /// The second half of `edit`: uploads the edited vault (merging and retrying on 412).
    pub async fn upload(&self, vault: &Vault) -> Result<(), OvError> {
        vault.sync(SyncOptions::default(), nc()).await.map(|_| ())
    }

    /// `close`: wipes keys (a service account's keyset; a user's keyset and vault keys).
    pub fn close(&self) {
        match &self.inner {
            Inner::ServiceAccount(sa) => sa.close(),
            Inner::User { account, .. } => account.lock(),
        }
    }
}

#[async_trait::async_trait]
impl VaultSource for Source {
    async fn read(&self, vault: &str, reference: &str) -> Result<String, OvError> {
        let v = self.open(vault).await?;
        let bytes = zeroize::Zeroizing::new(v.read_field(reference.to_string())?);
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(id: &str, name: &str) -> VaultSummary {
        VaultSummary { id: id.into(), name: name.into(), role: "write".into() }
    }

    #[test]
    fn picks_by_id_then_unique_name() {
        let all = [v("1", "a"), v("2", "b"), v("3", "b")];
        assert_eq!(pick_vault(&all, "1", "x").unwrap().id, "1");
        assert_eq!(pick_vault(&all, "a", "x").unwrap().id, "1");
        assert_eq!(pick_vault(&all, "b", "x").unwrap_err().message, "2 vaults are named \"b\"; use the vault id");
        assert_eq!(
            pick_vault(&all, "c", "this account").unwrap_err().message,
            "vault \"c\" not found or not shared with this account"
        );
        assert_eq!(role_name(VaultRole::Manage), "manage");
    }
}
