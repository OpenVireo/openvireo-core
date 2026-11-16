//! Service accounts (SPEC §9 "Service account tokens"): the master key that wraps an SA's keyset,
//! sealed to every org owner and admin; tokens that wrap the master key under a per-secret `kek`;
//! and the SA side, which unwraps token → master → keyset.
//!
//! Port of `Account.createServiceAccount`, `issueServiceAccountSecret`, `sealSaMasterKeys` and the
//! key handling of `service-account.ts` in the TS SDK.

use ov_crypto::envelope::{seal_sa_master, unseal_sa_master};
use ov_crypto::keyset::{generate_keyset, unwrap_keyset, wrap_keyset, Keyset, PublicKeys as CryptoPublicKeys};
use ov_crypto::tokens::{new_sa_secret, unwrap_sa_master, NewSaSecretBody, ParsedSaToken};
use ov_error::{OvError, OvErrorCode};
use ov_protocol::types::{
    CreateServiceAccountRequest, Grant, Member, MemberStatus, NewSaSecret, Principal, SaMasterGrant, ServiceAccount,
    ServiceAccountExchange, ServiceAccountExchangeRequest, VaultRole,
};
use zeroize::Zeroizing;

use crate::keyring::VaultKeys;
use crate::keys::{
    b64u, crypto_wrapped, is_manager, random_key, random_uuid, sa_principal, sealed_bytes, trusted, user_principal,
    wire_wrapped,
};
use crate::sharing::seal_grant;

fn wire_secret(b: NewSaSecretBody) -> NewSaSecret {
    NewSaSecret {
        id: b.id,
        name: b.name,
        secret_hash: b.secret_hash,
        prefix: b.prefix,
        wrapped_master: b.wrapped_master,
        expires_at: b.expires_at,
    }
}

/// What the input of [`new_service_account`] describes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceAccountSpec {
    /// The SA's name.
    pub name: String,
    /// Expiry of the SA and its first secret (RFC 3339), `None` for never.
    pub expires_at: Option<String>,
    /// A name for the first secret.
    pub secret_name: Option<String>,
}

/// A service account about to be created.
pub struct NewServiceAccount {
    /// The SA id (a random UUID chosen here).
    pub sa_id: String,
    /// The `POST /orgs/{org}/service-accounts` body.
    pub request: CreateServiceAccountRequest,
    /// The first `ov_sa_…` token. Show it once; wiped on drop.
    pub token: Zeroizing<String>,
    sa_public: CryptoPublicKeys,
}

impl std::fmt::Debug for NewServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewServiceAccount")
            .field("sa_id", &self.sa_id)
            .field("request", &self.request)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl NewServiceAccount {
    /// `sa:<id>`.
    pub fn principal(&self) -> Principal {
        sa_principal(&self.sa_id)
    }

    /// The SA's public keys.
    pub fn public_keys(&self) -> &CryptoPublicKeys {
        &self.sa_public
    }

    /// A grant of `vault` to the new SA (for `POST /vaults/{id}/access` after the SA exists):
    /// the current vault key sealed to the SA's keyset. `no_vault_key` if it isn't held.
    pub fn vault_grant(&self, vault: &VaultKeys, role: VaultRole) -> Result<Grant, OvError> {
        Ok(seal_grant(vault, &self.principal(), &self.sa_public, role)?.grant)
    }
}

/// Creates a service account in an org (needs owner/admin): its keyset and master key are made
/// here, the keyset is wrapped under the master key, the master key is sealed to every owner and
/// admin in `members` (`GET /orgs/{org}/members`) that is confirmed and has keys, and always to
/// `me`; the first secret's token is built for `issuer`.
///
/// `invalid_public_keys` when an owner's or admin's signature doesn't verify.
pub fn new_service_account(
    issuer: &str,
    me: &str,
    keyset: &Keyset,
    members: &[Member],
    spec: &ServiceAccountSpec,
) -> Result<NewServiceAccount, OvError> {
    let sa_id = random_uuid()?;
    let master = random_key()?;
    let sa_keys = generate_keyset()?;
    let mut master_keys = Vec::new();
    for m in members {
        let principal = user_principal(&m.user_id);
        let Some(public) = &m.public else { continue };
        if !is_manager(&m.role) || (m.status != MemberStatus::Confirmed && principal != me) {
            continue;
        }
        let pk = if principal == me { keyset.public } else { trusted(public)? };
        master_keys.push(SaMasterGrant {
            sa_id: sa_id.clone(),
            principal,
            sealed_key: b64u(&seal_sa_master(&pk.enc_pk, &sa_id, &master)?),
        });
    }
    if !master_keys.iter().any(|k| k.principal == me) {
        master_keys.push(SaMasterGrant {
            sa_id: sa_id.clone(),
            principal: me.to_owned(),
            sealed_key: b64u(&seal_sa_master(&keyset.public.enc_pk, &sa_id, &master)?),
        });
    }
    let secret_id = random_uuid()?;
    let secret =
        new_sa_secret(issuer, &sa_id, &master, &secret_id, spec.secret_name.as_deref(), spec.expires_at.as_deref())?;
    let request = CreateServiceAccountRequest {
        id: sa_id.clone(),
        name: spec.name.clone(),
        expires_at: spec.expires_at.clone(),
        keyset: wire_wrapped(wrap_keyset(&master, &sa_keys)?),
        master_keys,
        secret: wire_secret(secret.body),
    };
    Ok(NewServiceAccount { sa_id, request, token: secret.token, sa_public: sa_keys.public })
}

/// A newly issued SA secret.
pub struct IssuedSaSecret {
    /// The `ov_sa_…` token. Show it once; wiped on drop.
    pub token: Zeroizing<String>,
    /// The `POST /service-accounts/{sa}/secrets` body.
    pub body: NewSaSecret,
}

impl std::fmt::Debug for IssuedSaSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedSaSecret").field("token", &"[redacted]").field("body", &self.body).finish()
    }
}

/// Unseals this owner's/admin's copy of an SA's master key (`ServiceAccount.master_key`).
/// `forbidden` (403) when there is none (members don't hold one); `decryption_failed` when it
/// doesn't open.
pub fn unseal_master(keyset: &Keyset, sa: &ServiceAccount) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let Some(sealed) = &sa.master_key else {
        return Err(
            OvError::new(OvErrorCode::Forbidden, "only org owners and admins hold the SA master key").with_status(403)
        );
    };
    unseal_sa_master(&keyset.enc_sk, &sa.id, &sealed_bytes(sealed)?)
}

/// Issues another secret for an SA (owner/admin) without the old ones: unseals the master key
/// (`GET /service-accounts/{sa}`) and wraps it under a new `kek` (see [`unseal_master`] for errors).
pub fn issue_sa_secret(
    issuer: &str,
    keyset: &Keyset,
    sa: &ServiceAccount,
    name: Option<&str>,
    expires_at: Option<&str>,
) -> Result<IssuedSaSecret, OvError> {
    let master = unseal_master(keyset, sa)?;
    let secret = new_sa_secret(issuer, &sa.id, &master, &random_uuid()?, name, expires_at)?;
    Ok(IssuedSaSecret { token: secret.token, body: wire_secret(secret.body) })
}

/// Seals every SA master key of the org that `keyset` holds to another owner/admin (`principal`,
/// with verified `enc_pk`), for a confirmation or promotion. `sas` is
/// `GET /orgs/{org}/service-accounts`, each refreshed with `GET /service-accounts/{sa}` when the
/// list left `master_key` out; SAs without one are skipped.
pub fn seal_sa_master_keys(
    keyset: &Keyset,
    sas: &[ServiceAccount],
    principal: &str,
    enc_pk: &[u8; 32],
) -> Result<Vec<SaMasterGrant>, OvError> {
    let mut out = Vec::new();
    for sa in sas.iter().filter(|s| s.master_key.is_some()) {
        let master = unseal_master(keyset, sa)?;
        out.push(SaMasterGrant {
            sa_id: sa.id.clone(),
            principal: principal.to_owned(),
            sealed_key: b64u(&seal_sa_master(enc_pk, &sa.id, &master)?),
        });
    }
    Ok(out)
}

/// The `POST /auth/service-account` body for a parsed token.
pub fn exchange_request(token: &ParsedSaToken) -> ServiceAccountExchangeRequest {
    ServiceAccountExchangeRequest { sa_id: token.sa_id.clone(), secret: b64u(token.secret.as_ref()) }
}

/// The SA side of the exchange: unwraps the master key with the token's `kek`, then the SA keyset
/// with the master key. `decryption_failed` for a token that doesn't match; `invalid_public_keys`
/// for a keyset whose public keys don't match its secrets.
pub fn unlock_service_account(token: &ParsedSaToken, exchange: &ServiceAccountExchange) -> Result<Keyset, OvError> {
    let master = unwrap_sa_master(&token.kek, &token.sa_id, &exchange.wrapped_master)?;
    unwrap_keyset(&master, &crypto_wrapped(&exchange.keyset))
}

/// Finds a vault by id, or else by a name that exactly one vault has (SPEC §14). `not_found` (404)
/// otherwise, naming how many vaults share the name.
pub fn find_vault<'a>(
    vaults: impl IntoIterator<Item = &'a VaultKeys>,
    id_or_name: &str,
) -> Result<&'a VaultKeys, OvError> {
    let all: Vec<&VaultKeys> = vaults.into_iter().collect();
    if let Some(v) = all.iter().find(|v| v.id() == id_or_name) {
        return Ok(v);
    }
    let by_name: Vec<&&VaultKeys> = all.iter().filter(|v| v.info.name == id_or_name).collect();
    match by_name.as_slice() {
        [one] => Ok(one),
        [] => Err(OvError::new(
            OvErrorCode::NotFound,
            format!("vault \"{id_or_name}\" not found or not shared with this service account"),
        )
        .with_status(404)),
        many => Err(OvError::new(OvErrorCode::NotFound, format!("{} vaults are named \"{id_or_name}\"", many.len()))
            .with_status(404)),
    }
}

/// Refuses writes to a vault the SA can only read, before anything is uploaded: `forbidden` (403).
pub fn check_writable(vault: &VaultKeys) -> Result<(), OvError> {
    if vault.info.role == VaultRole::Read {
        let shown = if vault.info.name.is_empty() { vault.id() } else { &vault.info.name };
        return Err(OvError::new(
            OvErrorCode::Forbidden,
            format!("this service account can only read vault \"{shown}\""),
        )
        .with_status(403));
    }
    Ok(())
}
