//! Conversions between the wire types of `ov-protocol` and the key types of `ov-crypto`, plus the
//! principal and role helpers the rest of the crate shares.

use ov_crypto::keyset::{self, PublicKeysJson, WrappedKeysetJson};
use ov_error::{OvError, OvErrorCode};
use ov_protocol::types::{OrgRole, Principal, PublicKeys, PublicPrincipal, VaultRole, WrappedKeyset};
use zeroize::Zeroizing;

/// `"user:<id>"`.
pub fn user_principal(user_id: &str) -> Principal {
    format!("user:{user_id}")
}

/// `"sa:<id>"`.
pub fn sa_principal(sa_id: &str) -> Principal {
    format!("sa:{sa_id}")
}

/// Owners and admins manage an org (they hold every org vault with `manage` and the SA master keys).
pub fn is_manager(role: &OrgRole) -> bool {
    matches!(role, OrgRole::Owner | OrgRole::Admin)
}

/// The order of vault roles: `read` < `write` < `manage`. A role this build doesn't know ranks as
/// `read`, so it never grants more than the least.
pub fn role_rank(role: &VaultRole) -> u8 {
    match role {
        VaultRole::Manage => 2,
        VaultRole::Write => 1,
        VaultRole::Read | VaultRole::Other(_) => 0,
    }
}

/// The public half of a wrapped keyset (`Me.keyset`, `Session.keyset`).
pub fn public_of_wrapped(w: &WrappedKeyset) -> PublicKeys {
    PublicKeys { enc_pk: w.enc_pk.clone(), sign_pk: w.sign_pk.clone(), sig: w.sig.clone() }
}

/// The keys of a [`PublicPrincipal`] (`GET /principals/{p}/public-key`, `GET /users/lookup`).
pub fn public_of_principal(p: &PublicPrincipal) -> PublicKeys {
    PublicKeys { enc_pk: p.enc_pk.clone(), sign_pk: p.sign_pk.clone(), sig: p.sig.clone() }
}

/// Wire public keys from parsed ones.
pub fn wire_public(p: &keyset::PublicKeys) -> PublicKeys {
    let j = p.to_json();
    PublicKeys { enc_pk: j.enc_pk, sign_pk: j.sign_pk, sig: j.sig }
}

/// A wire `WrappedKeyset` from `ov-crypto`'s.
pub fn wire_wrapped(w: WrappedKeysetJson) -> WrappedKeyset {
    WrappedKeyset { enc_pk: w.enc_pk, sign_pk: w.sign_pk, sig: w.sig, wrapped: w.wrapped }
}

/// `ov-crypto`'s `WrappedKeysetJson` from the wire type.
pub fn crypto_wrapped(w: &WrappedKeyset) -> WrappedKeysetJson {
    WrappedKeysetJson {
        enc_pk: w.enc_pk.clone(),
        sign_pk: w.sign_pk.clone(),
        sig: w.sig.clone(),
        wrapped: w.wrapped.clone(),
    }
}

/// Parses wire public keys and checks their signature (SPEC §5). Every client does this before
/// sealing anything to a principal. Fails with `invalid_public_keys`.
pub fn trusted(p: &PublicKeys) -> Result<keyset::PublicKeys, OvError> {
    keyset::trusted_public_keys(&PublicKeysJson {
        enc_pk: p.enc_pk.clone(),
        sign_pk: p.sign_pk.clone(),
        sig: p.sig.clone(),
    })
}

/// Decodes a base64url sealed key from the wire. A value that isn't base64url is
/// `decryption_failed`, as a sealed key that doesn't open is.
pub(crate) fn sealed_bytes(b64: &str) -> Result<Vec<u8>, OvError> {
    ov_crypto::encoding::from_b64u(b64)
        .map_err(|_| OvError::new(OvErrorCode::DecryptionFailed, "sealed key is not valid base64url"))
}

/// 32 random bytes for a new vault key or SA master key.
pub(crate) fn random_key() -> Result<Zeroizing<[u8; 32]>, OvError> {
    ov_crypto::primitives::random_array::<32>()
}

/// A random lowercase hyphenated v4 UUID (vault, SA and secret ids are client-chosen).
pub(crate) fn random_uuid() -> Result<String, OvError> {
    Ok(ov_kdbx::vault::new_uuid()?.to_string())
}

pub(crate) fn b64u(bytes: &[u8]) -> String {
    ov_crypto::encoding::b64u(bytes)
}
