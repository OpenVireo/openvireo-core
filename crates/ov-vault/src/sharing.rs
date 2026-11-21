//! Creating vaults and sharing them (SPEC §6, §7): a new vault's first key and grants, including the
//! org vault grant rule, and sealing a vault key to a grantee.
//!
//! Port of `Account.registerVault` and `Account.share` in the TS SDK. The facade sends what these
//! functions build (`POST /vaults`, `POST /vaults/{id}/access`).

use ov_crypto::envelope::seal_vault_key;
use ov_crypto::keyset::{Keyset, PublicKeys as CryptoPublicKeys};
use ov_crypto::vault_name::encrypt_vault_name;
use ov_error::OvError;
use ov_kdbx::vault::KeyVersion;
use ov_protocol::types::{
    CreateVaultRequest, Grant, Member, MemberStatus, Principal, PublicPrincipal, Vault, VaultKey, VaultRole,
};
use zeroize::Zeroizing;

use crate::keyring::VaultKeys;
use crate::keys::{b64u, is_manager, public_of_principal, random_key, random_uuid, trusted, user_principal};

/// The first key version of every vault (SPEC §7).
pub const FIRST_KEY_VERSION: u32 = 1;

/// A vault about to be created: its id, its first key, and the `POST /vaults` body.
pub struct NewVault {
    /// The new vault's id (a random UUID chosen here).
    pub id: String,
    /// The vault key for version 1. Wiped on drop. Make the KDBX with it
    /// (`ov_kdbx::vault::create_vault_kdbx` or `rekey_to_vault_key`).
    pub key: Zeroizing<[u8; 32]>,
    /// The `POST /vaults` body: the encrypted name and the grants, the creator's first.
    pub request: CreateVaultRequest,
}

impl std::fmt::Debug for NewVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewVault")
            .field("id", &self.id)
            .field("key", &"[redacted]")
            .field("request", &self.request)
            .finish()
    }
}

impl NewVault {
    /// The key as a [`KeyVersion`] (version 1), for opening and syncing the new vault.
    pub fn key_version(&self) -> KeyVersion {
        KeyVersion { version: FIRST_KEY_VERSION, key: Zeroizing::new(self.key.to_vec()) }
    }

    /// The vault as `GET /vaults` will list it, from the `POST /vaults` answer: when the server
    /// didn't send the caller's sealed key, the one sent in the request is used, so the keyring can
    /// open the vault before the next list.
    pub fn listing(&self, mut created: Vault) -> Vault {
        if created.keys.is_empty() {
            if let Some(own) = self.request.grants.first() {
                created.keys =
                    vec![VaultKey { key_version: i64::from(FIRST_KEY_VERSION), sealed_key: own.sealed_key.clone() }];
            }
        }
        created
    }
}

/// Builds a new vault: a random id and key, the name encrypted under the key (SPEC §7), and key
/// version 1 sealed to the creator (`manage`).
///
/// For an org vault pass the org and its members (`GET /orgs/{org}/members`): every **confirmed**
/// owner and admin with public keys gets a `manage` grant too, as the server requires (the org vault
/// grant rule, SPEC §7). Invited or unconfirmed owners and admins get theirs when they are confirmed.
/// A member whose key signature doesn't verify fails the whole call (`invalid_public_keys`).
pub fn new_vault(name: &str, me: &str, keyset: &Keyset, org: Option<(&str, &[Member])>) -> Result<NewVault, OvError> {
    let id = random_uuid()?;
    let key = random_key()?;
    let mut grants = vec![Grant {
        principal: me.to_owned(),
        role: VaultRole::Manage,
        key_version: i64::from(FIRST_KEY_VERSION),
        sealed_key: b64u(&seal_vault_key(&keyset.public.enc_pk, &id, &key)?),
    }];
    if let Some((_, members)) = org {
        for m in members {
            let principal = user_principal(&m.user_id);
            let Some(public) = &m.public else { continue };
            if principal == me || !is_manager(&m.role) || m.status != MemberStatus::Confirmed {
                continue;
            }
            // Name the member whose keys don't verify, so the app can say whom to ask (contract-v1.8)
            let pk = trusted(public).map_err(|e| {
                e.with_details(serde_json::json!({ "principal": principal, "email": m.email }).to_string())
            })?;
            grants.push(Grant {
                principal,
                role: VaultRole::Manage,
                key_version: i64::from(FIRST_KEY_VERSION),
                sealed_key: b64u(&seal_vault_key(&pk.enc_pk, &id, &key)?),
            });
        }
    }
    let request = CreateVaultRequest {
        id: id.clone(),
        org_id: org.map(|(o, _)| o.to_owned()),
        encrypted_name: encrypt_vault_name(&key, &id, name)?,
        grants,
    };
    Ok(NewVault { id, key, request })
}

/// A vault key sealed to a grantee, and their fingerprint to compare out of band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedGrant {
    /// The grant for `POST /vaults/{id}/access` (also used to change a role).
    pub grant: Grant,
    /// The grantee's fingerprint (SPEC §5).
    pub fingerprint: String,
}

/// Grants (or changes) access: seals the vault's current key to `grantee` after checking their key
/// signature (SPEC §5, §6). `grantee` is what `GET /principals/{p}/public-key` or
/// `GET /users/lookup?email=` returned.
///
/// Errors: `no_vault_key` if this principal doesn't hold the current key; `invalid_public_keys` for
/// keys that don't verify.
pub fn grant(vault: &VaultKeys, grantee: &PublicPrincipal, role: VaultRole) -> Result<SealedGrant, OvError> {
    let pk = trusted(&public_of_principal(grantee))?;
    seal_grant(vault, &grantee.principal, &pk, role)
}

/// [`grant`] to keys already verified (an org member's, an SA's own).
pub fn seal_grant(
    vault: &VaultKeys,
    principal: &Principal,
    pk: &CryptoPublicKeys,
    role: VaultRole,
) -> Result<SealedGrant, OvError> {
    let current = vault.current_key()?;
    let key = crate::keyring::key_array(&current.key);
    Ok(SealedGrant {
        grant: Grant {
            principal: principal.clone(),
            role,
            key_version: i64::from(current.version),
            sealed_key: b64u(&seal_vault_key(&pk.enc_pk, vault.id(), &key)?),
        },
        fingerprint: pk.fingerprint(),
    })
}
