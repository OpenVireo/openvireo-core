//! Where secrets come from, ported from `packages/cli/src/source.ts`: a service account
//! (`OPENVIREO_SERVICE_ACCOUNT_TOKEN`) or a signed-in user.
//!
//! The skeleton only defines the shape; W3-L3 implements [`VaultSource`] on `ov-core`'s
//! `ServiceAccount` and `Account`/`Vault`.

use ov_error::{OvError, OvErrorCode};

use crate::reference::SecretReference;

/// `VaultSummary`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSummary {
    /// Vault id.
    pub id: String,
    /// Vault name.
    pub name: String,
    /// `read`, `write` or `admin`.
    pub role: String,
}

/// The part of the TS `VaultSource` that the pure CLI logic (templates, `ov run`) needs.
#[async_trait::async_trait]
pub trait VaultSource: Send + Sync {
    /// `service-account` or `user`.
    fn kind(&self) -> &str;
    /// `listVaults`.
    async fn list_vaults(&self) -> Result<Vec<VaultSummary>, OvError>;
    /// `readField(await open(r.vault), r)`.
    async fn read_field(&self, r: &SecretReference) -> Result<String, OvError>;
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
    }
}
