//! `ov-crypto` for the platform bindings (SPEC §1-§7, §9, §18): the pieces the iOS app's `Crypto/` code wraps, so it
//! can become thin wrappers (task W3-BS2).
//!
//! - Secret Key (§2), AUK (§3), envelopes `wrap`/`seal` (§4, §6) with the SA and vault-key variants,
//!   keysets and public keys (§5), vault names (§7), tokens and JWTs (§9), restore proofs (§18).
//! - X25519 / Ed25519 ([`ov_crypto::curves`]) and Argon2 with every variant, lane count and output
//!   length (local `.kdbx` files use Argon2d with `p > 1`).
//! - Every randomized call takes optional fixed randomness (`nonce`, `ephemeral_secret_key`), so the
//!   test vectors replay byte for byte. Leave them `nil` in production.
//!
//! Secrets come back as `Data`; the caller wipes them. Byte arrays of the wrong length are
//! `invalid_request`, except where the core has its own code for them (`invalid_secret_key`,
//! `low_order_point`, `invalid_public_keys`, …).

use std::collections::BTreeMap;
use std::sync::Arc;

use ov_crypto::{
    auk, curves, encoding, envelope, jwt, keyset, primitives as p, restore, secret_key, tokens, vault_name,
};
use ov_error::OvErrorCode;
use zeroize::Zeroizing;

use crate::error::OvError;
use crate::guard::{guard, guard_ok};

type R<T> = Result<T, OvError>;
type CoreResult<T> = Result<T, ov_error::OvError>;

/// `bytes` as `[u8; N]`, or `invalid_request` naming `what`.
pub(crate) fn array<const N: usize>(bytes: &[u8], what: &str) -> CoreResult<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| ov_error::OvError::new(OvErrorCode::InvalidRequest, format!("{what} must be {N} bytes")))
}

/// A secret `[u8; N]` that wipes itself.
pub(crate) fn secret<const N: usize>(bytes: &[u8], what: &str) -> CoreResult<Zeroizing<[u8; N]>> {
    array::<N>(bytes, what).map(Zeroizing::new)
}

fn opt_nonce(nonce: Option<Vec<u8>>) -> CoreResult<Option<[u8; p::NONCE_BYTES]>> {
    nonce.map(|n| array::<{ p::NONCE_BYTES }>(&n, "nonce")).transpose()
}

fn nonce_or_random(nonce: Option<Vec<u8>>) -> CoreResult<[u8; p::NONCE_BYTES]> {
    match opt_nonce(nonce)? {
        Some(n) => Ok(n),
        None => p::random_nonce(),
    }
}

fn seal_options(ephemeral_secret_key: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> CoreResult<envelope::SealOptions> {
    Ok(envelope::SealOptions {
        ephemeral_secret_key: ephemeral_secret_key.map(|k| secret::<32>(&k, "ephemeral secret key")).transpose()?,
        nonce: opt_nonce(nonce)?,
    })
}

// ------------------------------------------------------------------------- encoding

/// base64url without padding.
#[uniffi::export]
pub fn b64u_encode(bytes: Vec<u8>) -> R<String> {
    guard_ok(|| encoding::b64u(&bytes))
}

/// Decodes base64url, with or without padding; `invalid_request` for anything else.
#[uniffi::export]
pub fn b64u_decode(text: String) -> R<Vec<u8>> {
    guard(|| encoding::from_b64u(&text))
}

/// Constant-time comparison of two byte strings.
#[uniffi::export]
pub fn constant_time_eq(a: Vec<u8>, b: Vec<u8>) -> R<bool> {
    guard_ok(|| encoding::ct_eq(&a, &b))
}

// --------------------------------------------------------------------------- argon2

/// The Argon2 variant ([`ov_crypto::primitives::Argon2Variant`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum Argon2Variant {
    /// Argon2d (KeePass's default for KDBX 4).
    Argon2d,
    /// Argon2i.
    Argon2i,
    /// Argon2id (SPEC §3).
    Argon2id,
}

impl From<Argon2Variant> for p::Argon2Variant {
    fn from(v: Argon2Variant) -> Self {
        match v {
            Argon2Variant::Argon2d => p::Argon2Variant::Argon2d,
            Argon2Variant::Argon2i => p::Argon2Variant::Argon2i,
            Argon2Variant::Argon2id => p::Argon2Variant::Argon2id,
        }
    }
}

/// Argon2 v1.3 with any variant, lane count (`p_lanes`) and output length. No SPEC floor here (use
/// `check_kdf_params` for server parameters); `weak_kdf` for parameters Argon2 itself refuses.
/// Synchronous and memory-bound (`m_kib` KiB): call it off the main thread.
#[uniffi::export]
pub fn argon2(
    variant: Argon2Variant,
    password: Vec<u8>,
    salt: Vec<u8>,
    m_kib: u32,
    t: u32,
    p_lanes: u32,
    out_len: u32,
) -> R<Vec<u8>> {
    guard(|| {
        let params = p::Argon2Params { m_kib, t, p: p_lanes, out_len: out_len as usize };
        p::argon2(variant.into(), &password, &salt, params).map(|k| k.to_vec())
    })
}

// --------------------------------------------------------------------------- curves

/// A random X25519 secret key.
#[uniffi::export]
pub fn x25519_random_secret() -> R<Vec<u8>> {
    guard(|| curves::x25519_random_secret().map(|k| k.to_vec()))
}

/// The X25519 public key of a 32-byte secret key.
#[uniffi::export]
pub fn x25519_public_key(secret_key: Vec<u8>) -> R<Vec<u8>> {
    guard(|| Ok(curves::x25519_public_key(&*secret::<32>(&secret_key, "secret key")?).to_vec()))
}

/// X25519 shared secret; `low_order_point` for a low-order or wrong-length public key.
#[uniffi::export]
pub fn x25519_shared(secret_key: Vec<u8>, public_key: Vec<u8>) -> R<Vec<u8>> {
    guard(|| curves::x25519_shared(&*secret::<32>(&secret_key, "secret key")?, &public_key).map(|k| k.to_vec()))
}

/// The Ed25519 public key of a 32-byte seed.
#[uniffi::export]
pub fn ed25519_public_key(seed: Vec<u8>) -> R<Vec<u8>> {
    guard(|| Ok(curves::ed25519_public_key(&*secret::<32>(&seed, "seed")?).to_vec()))
}

/// An Ed25519 signature (64 bytes) over `message`.
#[uniffi::export]
pub fn ed25519_sign(message: Vec<u8>, seed: Vec<u8>) -> R<Vec<u8>> {
    guard(|| Ok(curves::ed25519_sign(&message, &*secret::<32>(&seed, "seed")?).to_vec()))
}

/// Whether `signature` is a valid Ed25519 signature of `message` by `public_key` (false for any
/// malformed input).
#[uniffi::export]
pub fn ed25519_verify(signature: Vec<u8>, message: Vec<u8>, public_key: Vec<u8>) -> R<bool> {
    guard_ok(|| curves::ed25519_verify(&signature, &message, &public_key))
}

// ----------------------------------------------------------------------- secret key

/// 16 random bytes for a new Secret Key (SPEC §2).
#[uniffi::export]
pub fn generate_secret_key() -> R<Vec<u8>> {
    guard(|| secret_key::generate_secret_key().map(|k| k.to_vec()))
}

/// The display form `K1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX` of 16 raw bytes (secret: wipe it).
#[uniffi::export]
pub fn format_secret_key(raw: Vec<u8>) -> R<String> {
    guard(|| {
        let raw = Zeroizing::new(
            <[u8; secret_key::SECRET_KEY_BYTES]>::try_from(raw.as_slice())
                .map_err(|_| ov_error::OvError::new(OvErrorCode::InvalidSecretKey, "a Secret Key is 16 bytes"))?,
        );
        Ok(secret_key::format_secret_key(&raw).to_string())
    })
}

/// Parses a Secret Key leniently (case, spaces, O/I/L); `invalid_secret_key` otherwise.
#[uniffi::export]
pub fn parse_secret_key(display: String) -> R<Vec<u8>> {
    guard(|| secret_key::parse_secret_key(&display).map(|k| k.to_vec()))
}

// ------------------------------------------------------------------------------ AUK

fn kdf_in(k: ov_core::api::KdfParams) -> auk::KdfParams {
    auk::KdfParams { alg: k.alg, salt: k.salt, m: k.m, t: k.t, p: k.p }
}

fn kdf_out(k: auk::KdfParams) -> ov_core::api::KdfParams {
    ov_core::api::KdfParams { alg: k.alg, salt: k.salt, m: k.m, t: k.t, p: k.p }
}

fn kdf_min_in(m: Option<ov_core::api::KdfMin>) -> auk::KdfMin {
    m.map_or(auk::KDF_MIN, |m| auk::KdfMin { m: m.m, t: m.t })
}

fn derive_options(allow_weak: bool, kdf_min: Option<ov_core::api::KdfMin>) -> auk::DeriveAukOptions {
    auk::DeriveAukOptions { allow_weak, kdf_min: kdf_min_in(kdf_min) }
}

/// UTF-8 of NFKC(password), not trimmed: the KDF and OPAQUE password input (SPEC §3, §8).
#[uniffi::export]
pub fn password_bytes(password: String) -> R<Vec<u8>> {
    guard_ok(|| auk::password_bytes(&password).to_vec())
}

/// KDF parameters for a new account: the production defaults (m = 64 MiB, t = 3, p = 1) and a
/// random salt.
#[uniffi::export]
pub fn new_kdf_params() -> R<ov_core::api::KdfParams> {
    guard(|| auk::new_kdf_params().map(kdf_out))
}

/// KDF parameters with this cost and a random salt.
#[uniffi::export]
pub fn new_kdf_params_with(m: u32, t: u32, p_lanes: u32) -> R<ov_core::api::KdfParams> {
    guard(|| auk::new_kdf_params_with(m, t, p_lanes).map(kdf_out))
}

/// The SPEC §3 floor (`m >= 19456`, `t >= 2`).
#[uniffi::export]
pub fn kdf_minimum() -> ov_core::api::KdfMin {
    ov_core::api::KdfMin { m: auk::KDF_MIN.m, t: auk::KDF_MIN.t }
}

/// `weak_kdf` for parameters below `kdf_min` (the SPEC floor when `nil`), `p = 0` or not Argon2id.
#[uniffi::export]
pub fn check_kdf_params(kdf: ov_core::api::KdfParams, kdf_min: Option<ov_core::api::KdfMin>) -> R<()> {
    guard(|| auk::check_kdf_params(&kdf_in(kdf), kdf_min_in(kdf_min)))
}

/// Argon2id of the normalized password (SPEC §3 `stretched`, 32 bytes). `allow_weak` skips the
/// floor (test vectors only).
#[uniffi::export]
pub fn stretch_password(
    password: String,
    kdf: ov_core::api::KdfParams,
    allow_weak: bool,
    kdf_min: Option<ov_core::api::KdfMin>,
) -> R<Vec<u8>> {
    guard(|| auk::stretch_password(&password, &kdf_in(kdf), derive_options(allow_weak, kdf_min)).map(|k| k.to_vec()))
}

/// The Account Unlock Key: HKDF(stretched, Secret Key, "ov-auk-v1") (SPEC §3).
#[uniffi::export]
pub fn derive_auk(
    password: String,
    kdf: ov_core::api::KdfParams,
    secret_key: Vec<u8>,
    allow_weak: bool,
    kdf_min: Option<ov_core::api::KdfMin>,
) -> R<Vec<u8>> {
    guard(|| {
        let sk = secret::<{ secret_key::SECRET_KEY_BYTES }>(&secret_key, "secret key")?;
        auk::derive_auk(&password, &kdf_in(kdf), &sk, derive_options(allow_weak, kdf_min)).map(|k| k.to_vec())
    })
}

/// The AUK from an already stretched password.
#[uniffi::export]
pub fn auk_from_stretched(stretched: Vec<u8>, secret_key: Vec<u8>) -> R<Vec<u8>> {
    guard(|| {
        let s = secret::<32>(&stretched, "stretched password")?;
        let sk = secret::<{ secret_key::SECRET_KEY_BYTES }>(&secret_key, "secret key")?;
        Ok(auk::auk_from_stretched(&s, &sk).to_vec())
    })
}

// ------------------------------------------------------------------------ envelopes

/// The AAD strings of SPEC §4-§7, §22 (`Envelope.AAD` in Swift).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum AadKind {
    /// `ov-keyset-v1` (the id is ignored).
    Keyset,
    /// `ov-vault-key|<vault>`.
    VaultKey,
    /// `ov-vault-name|<vault>`.
    VaultName,
    /// `ov-sa-master-v1|<sa>`.
    SaMaster,
    /// `ov-share-v1|<share>`.
    Share,
    /// `ov-share-ref|<share>`.
    ShareRef,
}

/// The AAD string of `kind` for `id`.
#[uniffi::export]
pub fn envelope_aad(kind: AadKind, id: String) -> String {
    match kind {
        AadKind::Keyset => envelope::aad::KEYSET.to_string(),
        AadKind::VaultKey => envelope::aad::vault_key(&id),
        AadKind::VaultName => envelope::aad::vault_name(&id),
        AadKind::SaMaster => envelope::aad::sa_master(&id),
        AadKind::Share => envelope::aad::share(&id),
        AadKind::ShareRef => envelope::aad::share_ref(&id),
    }
}

/// `0x01 ‖ nonce ‖ XChaCha20-Poly1305(key, plaintext, aad)` (SPEC §4). A random nonce unless
/// `nonce` (24 bytes, test vectors only).
#[uniffi::export]
pub fn envelope_wrap(key: Vec<u8>, plaintext: Vec<u8>, aad: String, nonce: Option<Vec<u8>>) -> R<Vec<u8>> {
    guard(|| {
        let key = secret::<32>(&key, "key")?;
        Ok(envelope::wrap_with_nonce(&key, &plaintext, &aad, &nonce_or_random(nonce)?))
    })
}

/// Opens [`envelope_wrap`]; `unsupported_version` or `decryption_failed`.
#[uniffi::export]
pub fn envelope_unwrap(key: Vec<u8>, blob: Vec<u8>, aad: String) -> R<Vec<u8>> {
    guard(|| envelope::unwrap(&*secret::<32>(&key, "key")?, &blob, &aad).map(|p| p.to_vec()))
}

/// Seals to an X25519 public key (SPEC §6). Fresh ephemeral key and nonce unless given (test
/// vectors only). `low_order_point` for a bad recipient key. Verify the recipient's signed public
/// keys first (`trusted_public_keys`).
#[uniffi::export]
pub fn envelope_seal(
    recipient_enc_pk: Vec<u8>,
    plaintext: Vec<u8>,
    aad: String,
    ephemeral_secret_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> R<Vec<u8>> {
    guard(|| envelope::seal_with(&recipient_enc_pk, &plaintext, &aad, &seal_options(ephemeral_secret_key, nonce)?))
}

/// Opens a sealed box with the recipient's X25519 secret key.
#[uniffi::export]
pub fn envelope_unseal(recipient_enc_sk: Vec<u8>, sealed: Vec<u8>, aad: String) -> R<Vec<u8>> {
    guard(|| envelope::unseal(&*secret::<32>(&recipient_enc_sk, "secret key")?, &sealed, &aad).map(|p| p.to_vec()))
}

/// The AEAD key of a sealed box as the recipient derives it (test vectors' `derived_key_hex`).
#[uniffi::export]
pub fn envelope_seal_derived_key(recipient_enc_sk: Vec<u8>, sealed: Vec<u8>) -> R<Vec<u8>> {
    guard(|| envelope::seal_derived_key(&*secret::<32>(&recipient_enc_sk, "secret key")?, &sealed).map(|k| k.to_vec()))
}

/// Seals a 32-byte vault key to a member (AAD `ov-vault-key|<vault>`).
#[uniffi::export]
pub fn seal_vault_key(
    recipient_enc_pk: Vec<u8>,
    vault_id: String,
    vault_key: Vec<u8>,
    ephemeral_secret_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> R<Vec<u8>> {
    guard(|| {
        let key = secret::<32>(&vault_key, "vault key")?;
        envelope::seal_vault_key_with(&recipient_enc_pk, &vault_id, &key, &seal_options(ephemeral_secret_key, nonce)?)
    })
}

/// Unseals a member's vault key (`decryption_failed` unless it is 32 bytes).
#[uniffi::export]
pub fn unseal_vault_key(enc_sk: Vec<u8>, vault_id: String, sealed: Vec<u8>) -> R<Vec<u8>> {
    guard(|| envelope::unseal_vault_key(&*secret::<32>(&enc_sk, "secret key")?, &vault_id, &sealed).map(|k| k.to_vec()))
}

/// Seals a service account's master key to an owner or admin (AAD `ov-sa-master-v1|<sa>`).
#[uniffi::export]
pub fn seal_sa_master(
    recipient_enc_pk: Vec<u8>,
    sa_id: String,
    master: Vec<u8>,
    ephemeral_secret_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> R<Vec<u8>> {
    guard(|| {
        let key = secret::<32>(&master, "master key")?;
        envelope::seal_sa_master_with(&recipient_enc_pk, &sa_id, &key, &seal_options(ephemeral_secret_key, nonce)?)
    })
}

/// Unseals a service account's master key.
#[uniffi::export]
pub fn unseal_sa_master(enc_sk: Vec<u8>, sa_id: String, sealed: Vec<u8>) -> R<Vec<u8>> {
    guard(|| envelope::unseal_sa_master(&*secret::<32>(&enc_sk, "secret key")?, &sa_id, &sealed).map(|k| k.to_vec()))
}

// -------------------------------------------------------------------------- keysets

/// The `PublicKeys` JSON of `openapi.yaml` (base64url fields), as the server sends it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PublicKeysJson {
    /// X25519 public key.
    pub enc_pk: String,
    /// Ed25519 public key.
    pub sign_pk: String,
    /// Signature over `"ov-pubkeys-v1" ‖ enc_pk ‖ sign_pk`.
    pub sig: String,
}

/// The `WrappedKeyset` JSON of `openapi.yaml`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WrappedKeysetJson {
    /// X25519 public key.
    pub enc_pk: String,
    /// Ed25519 public key.
    pub sign_pk: String,
    /// Signature over the public keys.
    pub sig: String,
    /// base64url `wrap(key, enc_sk ‖ sign_seed, "ov-keyset-v1")`.
    pub wrapped: String,
}

/// A decrypted keyset (SPEC §5). The secrets are `Data`: wipe them when the account locks.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct Keyset {
    /// X25519 secret key.
    pub enc_sk: Vec<u8>,
    /// Ed25519 seed.
    pub sign_seed: Vec<u8>,
    /// The public half with its signature and fingerprint.
    pub public_keys: ov_core::api::PublicKeys,
}

impl std::fmt::Debug for Keyset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyset").field("public_keys", &self.public_keys).finish_non_exhaustive()
    }
}

fn pk_out(pk: &keyset::PublicKeys) -> ov_core::api::PublicKeys {
    ov_core::api::PublicKeys {
        enc_pk: pk.enc_pk.to_vec(),
        sign_pk: pk.sign_pk.to_vec(),
        sig: pk.sig.to_vec(),
        fingerprint: pk.fingerprint(),
    }
}

fn pk_in(pk: &ov_core::api::PublicKeys) -> CoreResult<keyset::PublicKeys> {
    let bad =
        |what: &str| ov_error::OvError::new(OvErrorCode::InvalidPublicKeys, format!("{what} has the wrong length"));
    Ok(keyset::PublicKeys {
        enc_pk: pk.enc_pk.as_slice().try_into().map_err(|_| bad("enc_pk"))?,
        sign_pk: pk.sign_pk.as_slice().try_into().map_err(|_| bad("sign_pk"))?,
        sig: pk.sig.as_slice().try_into().map_err(|_| bad("sig"))?,
    })
}

fn pk_json_in(j: PublicKeysJson) -> keyset::PublicKeysJson {
    keyset::PublicKeysJson { enc_pk: j.enc_pk, sign_pk: j.sign_pk, sig: j.sig }
}

fn ks_out(ks: &keyset::Keyset) -> Keyset {
    Keyset { enc_sk: ks.enc_sk.to_vec(), sign_seed: ks.sign_seed.to_vec(), public_keys: pk_out(&ks.public) }
}

fn ks_in(ks: &Keyset) -> CoreResult<keyset::Keyset> {
    let enc_sk = secret::<32>(&ks.enc_sk, "enc_sk")?;
    let sign_seed = secret::<32>(&ks.sign_seed, "sign_seed")?;
    Ok(keyset::keyset_from_secrets(&enc_sk, &sign_seed))
}

fn wrapped_out(w: keyset::WrappedKeysetJson) -> WrappedKeysetJson {
    WrappedKeysetJson { enc_pk: w.enc_pk, sign_pk: w.sign_pk, sig: w.sig, wrapped: w.wrapped }
}

/// A keyset from its two 32-byte secrets (public keys computed and signed).
#[uniffi::export]
pub fn keyset_from_secrets(enc_sk: Vec<u8>, sign_seed: Vec<u8>) -> R<Keyset> {
    guard(|| {
        let enc_sk = secret::<32>(&enc_sk, "enc_sk")?;
        let sign_seed = secret::<32>(&sign_seed, "sign_seed")?;
        Ok(ks_out(&keyset::keyset_from_secrets(&enc_sk, &sign_seed)))
    })
}

/// A fresh random keyset.
#[uniffi::export]
pub fn generate_keyset() -> R<Keyset> {
    guard(|| keyset::generate_keyset().map(|k| ks_out(&k)))
}

/// Wraps `enc_sk ‖ sign_seed` with the AUK or an SA master key. A random nonce unless `nonce`.
/// The keyset's public keys are recomputed from its secrets.
#[uniffi::export]
pub fn wrap_keyset(key: Vec<u8>, keyset: Keyset, nonce: Option<Vec<u8>>) -> R<WrappedKeysetJson> {
    guard(|| {
        let key = secret::<32>(&key, "key")?;
        let ks = ks_in(&keyset)?;
        Ok(wrapped_out(keyset::wrap_keyset_with_nonce(&key, &ks, &nonce_or_random(nonce)?)))
    })
}

/// Unwraps a keyset and checks its secrets match its public keys and signature.
#[uniffi::export]
pub fn unwrap_keyset(key: Vec<u8>, wrapped: WrappedKeysetJson) -> R<Keyset> {
    guard(|| {
        let key = secret::<32>(&key, "key")?;
        let w = keyset::WrappedKeysetJson {
            enc_pk: wrapped.enc_pk,
            sign_pk: wrapped.sign_pk,
            sig: wrapped.sig,
            wrapped: wrapped.wrapped,
        };
        keyset::unwrap_keyset(&key, &w).map(|k| ks_out(&k))
    })
}

/// Parses public keys without checking the signature (`invalid_public_keys` if malformed).
#[uniffi::export]
pub fn public_keys_from_json(json: PublicKeysJson) -> R<ov_core::api::PublicKeys> {
    guard(|| keyset::PublicKeys::from_json(&pk_json_in(json)).map(|k| pk_out(&k)))
}

/// Parses and verifies public keys (`invalid_public_keys` if malformed or `sig` is wrong).
#[uniffi::export]
pub fn trusted_public_keys(json: PublicKeysJson) -> R<ov_core::api::PublicKeys> {
    guard(|| keyset::trusted_public_keys(&pk_json_in(json)).map(|k| pk_out(&k)))
}

/// The JSON form of public keys.
#[uniffi::export]
pub fn public_keys_to_json(keys: ov_core::api::PublicKeys) -> R<PublicKeysJson> {
    guard(|| {
        let j = pk_in(&keys)?.to_json();
        Ok(PublicKeysJson { enc_pk: j.enc_pk, sign_pk: j.sign_pk, sig: j.sig })
    })
}

/// Whether `sig` verifies over the public keys (false for wrong lengths).
#[uniffi::export]
pub fn verify_public_keys(keys: ov_core::api::PublicKeys) -> R<bool> {
    guard_ok(|| pk_in(&keys).is_ok_and(|k| keyset::verify_public_keys(&k)))
}

/// The SPEC §5 fingerprint: 20 bytes of `SHA-256("ov-fp-v1" ‖ enc_pk ‖ sign_pk)`, hex in groups of 4.
#[uniffi::export]
pub fn public_key_fingerprint(enc_pk: Vec<u8>, sign_pk: Vec<u8>) -> R<String> {
    guard_ok(|| keyset::fingerprint(&enc_pk, &sign_pk))
}

// ----------------------------------------------------------------------- vault name

/// The vault-name key, HKDF(vault key, "ov-vault-name-v1").
#[uniffi::export]
pub fn vault_name_key(vault_key: Vec<u8>) -> R<Vec<u8>> {
    guard(|| Ok(vault_name::vault_name_key(&*secret::<32>(&vault_key, "vault key")?).to_vec()))
}

/// Encrypts a vault name (base64url). A random nonce unless `nonce`.
#[uniffi::export]
pub fn encrypt_vault_name(vault_key: Vec<u8>, vault_id: String, name: String, nonce: Option<Vec<u8>>) -> R<String> {
    guard(|| {
        let key = secret::<32>(&vault_key, "vault key")?;
        Ok(vault_name::encrypt_vault_name_with_nonce(&key, &vault_id, &name, &nonce_or_random(nonce)?))
    })
}

/// Decrypts a vault name; `decryption_failed` for the wrong key or vault id.
#[uniffi::export]
pub fn decrypt_vault_name(vault_key: Vec<u8>, vault_id: String, encrypted_name: String) -> R<String> {
    guard(|| vault_name::decrypt_vault_name(&*secret::<32>(&vault_key, "vault key")?, &vault_id, &encrypted_name))
}

// --------------------------------------------------------------------------- tokens

/// A parsed `ov_sa_…` token. `secret` and `kek` are secrets: wipe them.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ParsedSaToken {
    /// The issuer URL.
    pub url: String,
    /// The service account's uuid.
    pub sa_id: String,
    /// The secret the server checks.
    pub secret: Vec<u8>,
    /// The key that unwraps the SA master key.
    pub kek: Vec<u8>,
}

impl std::fmt::Debug for ParsedSaToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedSaToken").field("url", &self.url).field("sa_id", &self.sa_id).finish_non_exhaustive()
    }
}

/// A new SA secret: the token to show once, and the `NewSaSecret` body for the server.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct SaSecretMaterial {
    /// The `ov_sa_…` token (secret, shown once).
    pub token: String,
    /// The secret's id.
    pub id: String,
    /// Optional display name.
    pub name: Option<String>,
    /// Hex SHA-256 of the secret.
    pub secret_hash: String,
    /// First 8 base64url characters of the secret.
    pub prefix: String,
    /// The master key wrapped under the token's `kek` (base64url).
    pub wrapped_master: String,
    /// RFC 3339 expiry.
    pub expires_at: Option<String>,
}

impl std::fmt::Debug for SaSecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaSecretMaterial").field("id", &self.id).field("prefix", &self.prefix).finish_non_exhaustive()
    }
}

/// `ov_sa_` + base64url(`{"v":1,"url","sa_id","secret","kek"}`) (SPEC §9). Secret: wipe it.
#[uniffi::export]
pub fn build_sa_token(url: String, sa_id: String, secret: Vec<u8>, kek: Vec<u8>) -> R<String> {
    guard(|| {
        let s = self::secret::<32>(&secret, "secret")?;
        let k = self::secret::<32>(&kek, "kek")?;
        Ok(tokens::build_sa_token(&url, &sa_id, &s, &k).to_string())
    })
}

/// Parses a service-account token; `invalid_token` otherwise.
#[uniffi::export]
pub fn parse_sa_token(token: String) -> R<ParsedSaToken> {
    guard(|| {
        let t = tokens::parse_sa_token(&token)?;
        Ok(ParsedSaToken { url: t.url.clone(), sa_id: t.sa_id.clone(), secret: t.secret.to_vec(), kek: t.kek.to_vec() })
    })
}

/// What the server stores for an SA secret: hex SHA-256.
#[uniffi::export]
pub fn sa_secret_hash(secret: Vec<u8>) -> R<String> {
    guard(|| Ok(tokens::sa_secret_hash(&*self::secret::<32>(&secret, "secret")?)))
}

/// The first 8 base64url characters of an SA secret.
#[uniffi::export]
pub fn sa_secret_prefix(secret: Vec<u8>) -> R<String> {
    guard(|| Ok(tokens::sa_secret_prefix(&*self::secret::<32>(&secret, "secret")?)))
}

/// `wrap(kek, master, "ov-sa-master-v1|<sa>")` as base64url. A random nonce unless `nonce`.
#[uniffi::export]
pub fn wrap_sa_master(kek: Vec<u8>, sa_id: String, master: Vec<u8>, nonce: Option<Vec<u8>>) -> R<String> {
    guard(|| {
        let k = secret::<32>(&kek, "kek")?;
        let m = secret::<32>(&master, "master key")?;
        Ok(tokens::wrap_sa_master_with_nonce(&k, &sa_id, &m, &nonce_or_random(nonce)?))
    })
}

/// Unwraps an SA master key with the token's `kek`.
#[uniffi::export]
pub fn unwrap_sa_master(kek: Vec<u8>, sa_id: String, wrapped: String) -> R<Vec<u8>> {
    guard(|| tokens::unwrap_sa_master(&*secret::<32>(&kek, "kek")?, &sa_id, &wrapped).map(|k| k.to_vec()))
}

/// Creates an SA secret and `kek` for the master key (unsealed by an owner/admin).
#[uniffi::export]
pub fn new_sa_secret(
    url: String,
    sa_id: String,
    master: Vec<u8>,
    secret_id: String,
    name: Option<String>,
    expires_at: Option<String>,
) -> R<SaSecretMaterial> {
    guard(|| {
        let m = secret::<32>(&master, "master key")?;
        let s = tokens::new_sa_secret(&url, &sa_id, &m, &secret_id, name.as_deref(), expires_at.as_deref())?;
        Ok(SaSecretMaterial {
            token: s.token.to_string(),
            id: s.body.id,
            name: s.body.name,
            secret_hash: s.body.secret_hash,
            prefix: s.body.prefix,
            wrapped_master: s.body.wrapped_master,
            expires_at: s.body.expires_at,
        })
    })
}

/// What the server stores for a refresh token: hex SHA-256 of the UTF-8 token.
#[uniffi::export]
pub fn refresh_token_hash(token: String) -> String {
    tokens::refresh_token_hash(&token)
}

/// A new `ov_rt_…` refresh token.
#[uniffi::export]
pub fn new_refresh_token() -> R<String> {
    guard(|| tokens::new_refresh_token().map(|t| t.to_string()))
}

// ------------------------------------------------------------------------------ JWT

/// A JWK (SPEC §9).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Jwk {
    /// `OKP`.
    pub kty: String,
    /// `Ed25519`.
    pub crv: Option<String>,
    /// base64url public key.
    pub x: Option<String>,
    /// Key id.
    pub kid: Option<String>,
    /// `sig` (JSON `use`).
    pub key_use: Option<String>,
    /// `EdDSA`.
    pub alg: Option<String>,
}

/// A JWK set.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Jwks {
    /// The keys.
    pub keys: Vec<Jwk>,
}

/// A grant in the `vlt` claim.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct VaultClaim {
    /// Vault uuid.
    pub id: String,
    /// `read`, `write` or `manage`.
    pub r: String,
    /// Sync quota in bytes.
    pub q: Option<u64>,
}

/// Access-token claims (SPEC §9).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct AccessClaims {
    /// Issuer.
    pub iss: String,
    /// Audiences (a single-string `aud` becomes one element).
    pub aud: Vec<String>,
    /// `user:<uuid>` or `sa:<uuid>`.
    pub sub: String,
    /// Device uuid.
    pub dev: Option<String>,
    /// Org uuid (service accounts).
    pub org: Option<String>,
    /// Vault grants.
    pub vlt: Option<Vec<VaultClaim>>,
    /// Erase date of a pending deletion (SPEC §23).
    pub del: Option<String>,
    /// Issued at.
    pub iat: Option<i64>,
    /// Not before.
    pub nbf: Option<i64>,
    /// Expiry.
    pub exp: Option<i64>,
    /// Token id.
    pub jti: Option<String>,
    /// Other claims as a JSON object string.
    pub extra_json: String,
}

/// A decoded, unverified JWT.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct DecodedJwt {
    /// The JOSE header's `alg`.
    pub alg: Option<String>,
    /// The JOSE header's `kid`.
    pub kid: Option<String>,
    /// The whole header as JSON.
    pub header_json: String,
    /// The claims.
    pub claims: AccessClaims,
}

/// What [`verify_jwt`] checks.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct JwtVerifyOptions {
    /// Expected `iss`.
    pub issuer: String,
    /// An audience `aud` must contain (`ov-sync`).
    pub audience: String,
    /// Now, Unix seconds.
    pub now: i64,
    /// Allowed skew on `exp`/`nbf`; `nil` = 60 s.
    pub skew: Option<i64>,
}

/// Called once by [`verify_jwt`] when the token's `kid` is unknown (SPEC §9: refetch the JWKS, at
/// most every 30 s; return `nil` to skip). Runs on the calling thread.
#[uniffi::export(with_foreign)]
pub trait JwksRefetcher: Send + Sync {
    /// The issuer's current JWKS, or `nil`.
    fn refetch(&self) -> Result<Option<Jwks>, OvError>;
}

fn jwks_in(j: Jwks) -> jwt::Jwks {
    jwt::Jwks {
        keys: j
            .keys
            .into_iter()
            .map(|k| jwt::Jwk { kty: k.kty, crv: k.crv, x: k.x, kid: k.kid, use_: k.key_use, alg: k.alg })
            .collect(),
    }
}

fn claims_out(c: jwt::AccessClaims) -> AccessClaims {
    let aud = match c.aud {
        None => vec![],
        Some(jwt::Audience::One(a)) => vec![a],
        Some(jwt::Audience::Many(v)) => v,
    };
    let extra: BTreeMap<String, serde_json::Value> = c.extra;
    AccessClaims {
        iss: c.iss,
        aud,
        sub: c.sub,
        dev: c.dev,
        org: c.org,
        vlt: c.vlt.map(|v| v.into_iter().map(|g| VaultClaim { id: g.id, r: g.r, q: g.q }).collect()),
        del: c.del,
        iat: c.iat,
        nbf: c.nbf,
        exp: c.exp,
        jti: c.jti,
        extra_json: serde_json::to_string(&extra).unwrap_or_else(|_| "{}".into()),
    }
}

/// Whether `token` has the three-part JWT shape.
#[uniffi::export]
pub fn is_jwt(token: String) -> bool {
    jwt::is_jwt(&token)
}

/// Decodes a JWT **without verifying it**; `invalid_token` if malformed.
#[uniffi::export]
pub fn decode_jwt(token: String) -> R<DecodedJwt> {
    guard(|| {
        let d = jwt::decode_jwt(&token)?;
        let field = |k: &str| d.header.get(k).and_then(serde_json::Value::as_str).map(str::to_owned);
        Ok(DecodedJwt {
            alg: field("alg"),
            kid: field("kid"),
            header_json: serde_json::Value::Object(d.header.clone()).to_string(),
            claims: claims_out(d.claims),
        })
    })
}

/// Verifies an access token (EdDSA against the JWKS, `iss`, `aud`, `exp`/`nbf` within the skew).
/// Every failure is `unauthorized` (status 401). `refetch` is asked once for an unknown `kid`.
#[uniffi::export]
pub fn verify_jwt(
    token: String,
    jwks: Jwks,
    options: JwtVerifyOptions,
    refetch: Option<Arc<dyn JwksRefetcher>>,
) -> R<AccessClaims> {
    guard(|| {
        let opts = jwt::VerifyOptions {
            issuer: options.issuer,
            audience: options.audience,
            now: options.now,
            skew: options.skew.unwrap_or(jwt::DEFAULT_SKEW_SECS),
        };
        let claims = jwt::verify_jwt_refetching(&token, &jwks_in(jwks), &opts, || match &refetch {
            None => Ok(None),
            Some(r) => r.refetch().map(|j| j.map(jwks_in)).map_err(ov_error::OvError::from),
        })?;
        Ok(claims_out(claims))
    })
}

// -------------------------------------------------------------------------- restore

/// `"ov-restore-v1" ‖ user id ‖ current enc_pk ‖ current sign_pk` (SPEC §18).
#[uniffi::export]
pub fn restore_proof_message(user_id: String, current_enc_pk: Vec<u8>, current_sign_pk: Vec<u8>) -> R<Vec<u8>> {
    guard(|| {
        let e = array::<32>(&current_enc_pk, "enc_pk")?;
        let s = array::<32>(&current_sign_pk, "sign_pk")?;
        Ok(restore::restore_proof_message(&user_id, &e, &s))
    })
}

/// The restore proof: Ed25519 by the old `sign_seed` over [`restore_proof_message`].
#[uniffi::export]
pub fn restore_proof(
    old_sign_seed: Vec<u8>,
    user_id: String,
    current_enc_pk: Vec<u8>,
    current_sign_pk: Vec<u8>,
) -> R<Vec<u8>> {
    guard(|| {
        let seed = secret::<32>(&old_sign_seed, "sign seed")?;
        let e = array::<32>(&current_enc_pk, "enc_pk")?;
        let s = array::<32>(&current_sign_pk, "sign_pk")?;
        Ok(restore::restore_proof(&seed, &user_id, &e, &s).to_vec())
    })
}

/// Whether a restore proof verifies against the archived `sign_pk` (false for malformed input).
#[uniffi::export]
pub fn verify_restore_proof(
    proof: Vec<u8>,
    user_id: String,
    current_enc_pk: Vec<u8>,
    current_sign_pk: Vec<u8>,
    old_sign_pk: Vec<u8>,
) -> R<bool> {
    guard_ok(|| {
        let (Ok(e), Ok(s)) = (array::<32>(&current_enc_pk, "enc_pk"), array::<32>(&current_sign_pk, "sign_pk")) else {
            return false;
        };
        restore::verify_restore_proof(&proof, &user_id, &e, &s, &old_sign_pk)
    })
}

/// Unseals an archived vault key with the old `enc_sk` and seals it to the current `enc_pk`. Fixed
/// randomness only for test vectors.
#[uniffi::export]
pub fn reseal_vault_key(
    old_enc_sk: Vec<u8>,
    current_enc_pk: Vec<u8>,
    vault_id: String,
    sealed: Vec<u8>,
    ephemeral_secret_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> R<Vec<u8>> {
    guard(|| {
        let sk = secret::<32>(&old_enc_sk, "old enc_sk")?;
        let pk = array::<32>(&current_enc_pk, "current enc_pk")?;
        restore::reseal_vault_key_with(&sk, &pk, &vault_id, &sealed, &seal_options(ephemeral_secret_key, nonce)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ov_testkit::{hex_bytes, load_json};
    use serde_json::Value;

    fn v() -> Value {
        load_json("test-vectors.json")
    }

    fn s(v: &Value) -> String {
        v.as_str().unwrap().to_string()
    }

    fn code(e: OvError) -> crate::OvErrorCode {
        let OvError::Failure { code, .. } = e;
        code
    }

    #[test]
    fn secret_key_vectors() {
        for c in v()["secret_key"].as_array().unwrap() {
            let raw = hex_bytes(c["raw_hex"].as_str().unwrap());
            assert_eq!(format_secret_key(raw.clone()).unwrap(), s(&c["display"]));
            assert_eq!(parse_secret_key(s(&c["display"])).unwrap(), raw);
        }
        assert_eq!(code(format_secret_key(vec![0; 15]).unwrap_err()), crate::OvErrorCode::InvalidSecretKey);
    }

    #[test]
    fn keyset_and_seal_vectors() {
        let v = v();
        let k = &v["keyset"];
        let ks = keyset_from_secrets(
            hex_bytes(k["enc_sk_hex"].as_str().unwrap()),
            hex_bytes(k["sign_seed_hex"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(ks.public_keys.fingerprint, s(&k["public"]["fingerprint"]));
        let auk = hex_bytes(k["auk_hex"].as_str().unwrap());
        let w = wrap_keyset(auk.clone(), ks.clone(), Some(hex_bytes(k["nonce_hex"].as_str().unwrap()))).unwrap();
        assert_eq!(w.wrapped, s(&k["wrapped"]));
        assert_eq!(unwrap_keyset(auk, w).unwrap(), ks);
        for c in v["seal"].as_array().unwrap() {
            let sealed = envelope_seal(
                ov_testkit::b64u(c["recipient_enc_pk"].as_str().unwrap()),
                hex_bytes(c["plaintext_hex"].as_str().unwrap()),
                s(&c["aad"]),
                Some(hex_bytes(c["ephemeral_sk_hex"].as_str().unwrap())),
                Some(hex_bytes(c["nonce_hex"].as_str().unwrap())),
            )
            .unwrap();
            assert_eq!(b64u_encode(sealed).unwrap(), s(&c["sealed"]));
        }
    }

    #[test]
    fn wrong_lengths_are_invalid_request() {
        assert_eq!(
            code(envelope_wrap(vec![1; 31], vec![], "a".into(), None).unwrap_err()),
            crate::OvErrorCode::InvalidRequest
        );
        assert_eq!(
            code(envelope_seal(vec![0; 32], vec![], "a".into(), None, None).unwrap_err()),
            crate::OvErrorCode::LowOrderPoint
        );
    }
}
