//! The account crypto of `ov-crypto` (SPEC §2–§9, §18): Secret Key, AUK, envelopes, keysets,
//! vault names, service-account and refresh tokens, JWTs and restore proofs. Full module only.
//!
//! Names and argument order follow the SDK's `@openvireo/sdk/crypto` exports, so the SDK can wrap
//! them one to one. Wire-shaped records (`PublicKeysJson`, `WrappedKeysetJson`, JWT claims, the new
//! SA secret's request body) cross as their JSON (snake_case keys); binary records are camelCase.
//! `nonce`/`ephemeralSk` options exist for the test vectors only.

use js_sys::Uint8Array;
use ov_crypto::auk::{DeriveAukOptions, KdfMin, KdfParams, KDF_MIN};
use ov_crypto::envelope::SealOptions;
use ov_crypto::jwt::{Jwks, VerifyOptions, DEFAULT_SKEW_SECS};
use ov_crypto::keyset::{Keyset, PublicKeys, PublicKeysJson, WrappedKeysetJson};
use ov_crypto::{auk, envelope, jwt, keyset, restore, secret_key, tokens, vault_name};
use ov_error::OvError;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::convert::{arg, array, field, fixed, obj, out, record, set, FromJs, SecretText, ToJs};
use crate::error::{arg_err, js, to_js};
use crate::json;
use crate::primitives::bytes_out;

fn key32(v: Vec<u8>, path: &str) -> Result<Zeroizing<[u8; 32]>, JsValue> {
    let v = Zeroizing::new(v);
    fixed::<32>(&v, path).map_err(arg_err)
}

fn pk32(v: &[u8], path: &str) -> Result<[u8; 32], JsValue> {
    array::<32>(v, path).map_err(arg_err)
}

fn nonce24(v: Option<Vec<u8>>) -> Result<Option<[u8; 24]>, JsValue> {
    v.map(|n| array::<24>(&n, "nonce").map_err(arg_err)).transpose()
}

fn json_out<T: serde::Serialize>(v: &T) -> Result<JsValue, JsValue> {
    json::to_js(v).map_err(|e| to_js(&e))
}

fn json_in<T: serde::de::DeserializeOwned>(v: &JsValue, path: &str) -> Result<T, JsValue> {
    json::from_js(v, path).map_err(arg_err)
}

// ------------------------------------------------------------------------------- secret key

/// A fresh 16-byte Secret Key (SPEC §2).
#[wasm_bindgen(js_name = generateSecretKey)]
pub fn generate_secret_key() -> Result<Uint8Array, JsValue> {
    bytes_out(secret_key::generate_secret_key())
}

/// The display form `K1-XXXXXX-…` (UTF-8).
#[wasm_bindgen(js_name = formatSecretKey)]
pub fn format_secret_key(raw: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let raw = Zeroizing::new(raw);
    let raw = fixed::<16>(&raw, "raw").map_err(arg_err)?;
    Ok(out(secret_key::format_secret_key(&raw).as_bytes()))
}

/// Parses a displayed Secret Key; `invalid_secret_key` when it is malformed.
#[wasm_bindgen(js_name = parseSecretKey)]
pub fn parse_secret_key(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] display: JsValue,
) -> Result<Uint8Array, JsValue> {
    let d: SecretText = arg(&display, "display").map_err(arg_err)?;
    bytes_out(secret_key::parse_secret_key(&d))
}

// -------------------------------------------------------------------------------------- AUK

/// `{ allowWeak?, kdfMin? }` (the SDK's `DeriveAukOptions`).
fn derive_opts(v: &JsValue) -> Result<DeriveAukOptions, JsValue> {
    if v.is_undefined() || v.is_null() {
        return Ok(DeriveAukOptions::default());
    }
    let allow_weak: Option<bool> = field(v, "allowWeak", "opts").map_err(arg_err)?;
    let min: Option<KdfMin> = field(v, "kdfMin", "opts").map_err(arg_err)?;
    Ok(DeriveAukOptions { allow_weak: allow_weak.unwrap_or(false), kdf_min: min.unwrap_or(KDF_MIN) })
}

#[wasm_bindgen(typescript_custom_section)]
const AUK_TS: &str = "\
/** `allowWeak` skips the minimum-cost check (test vectors only); `kdfMin` is the server's `kdf_min`. */
export interface DeriveAukOptions { allowWeak?: boolean; kdfMin?: KdfMin }
export interface KdfOverrides { m?: number; t?: number; p?: number }
";

/// KDF parameters for a new account: the defaults (m = 64 MiB, t = 3, p = 1) with any overrides,
/// and a random salt.
#[wasm_bindgen(js_name = newKdfParams, unchecked_return_type = "KdfParams")]
pub fn new_kdf_params(
    #[wasm_bindgen(unchecked_optional_param_type = "KdfOverrides")] overrides: Option<JsValue>,
) -> Result<JsValue, JsValue> {
    let overrides = overrides.unwrap_or(JsValue::UNDEFINED);
    let (dm, dt, dp) = auk::KDF_DEFAULTS;
    let (m, t, p) = if overrides.is_undefined() || overrides.is_null() {
        (dm, dt, dp)
    } else {
        let get = |k: &str, d: u32| -> Result<u32, JsValue> {
            Ok(field::<Option<u32>>(&overrides, k, "overrides").map_err(arg_err)?.unwrap_or(d))
        };
        (get("m", dm)?, get("t", dt)?, get("p", dp)?)
    };
    js(auk::new_kdf_params_with(m, t, p))
}

/// Refuses parameters below `min` (default the SPEC floor m = 19456, t = 2) or not Argon2id: `weak_kdf`.
#[wasm_bindgen(js_name = checkKdfParams)]
pub fn check_kdf_params(
    #[wasm_bindgen(unchecked_param_type = "KdfParams")] kdf: JsValue,
    #[wasm_bindgen(unchecked_optional_param_type = "KdfMin")] min: Option<JsValue>,
) -> Result<(), JsValue> {
    let min = min.unwrap_or(JsValue::UNDEFINED);
    let kdf: KdfParams = arg(&kdf, "kdf").map_err(arg_err)?;
    let min: Option<KdfMin> = arg(&min, "min").map_err(arg_err)?;
    auk::check_kdf_params(&kdf, min.unwrap_or(KDF_MIN)).map_err(|e| to_js(&e))
}

/// UTF-8 of the NFKC-normalised password (SPEC §3; also the OPAQUE input).
#[wasm_bindgen(js_name = passwordBytes)]
pub fn password_bytes(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] password: JsValue,
) -> Result<Uint8Array, JsValue> {
    let pw: SecretText = arg(&password, "password").map_err(arg_err)?;
    Ok(out(&auk::password_bytes(&pw)))
}

/// Argon2id of the NFKC password with `kdf` (checked against `opts.min` unless `opts.allowWeak`).
#[wasm_bindgen(js_name = stretchPassword)]
pub fn stretch_password(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] password: JsValue,
    #[wasm_bindgen(unchecked_param_type = "KdfParams")] kdf: JsValue,
    #[wasm_bindgen(unchecked_optional_param_type = "DeriveAukOptions")] opts: Option<JsValue>,
) -> Result<Uint8Array, JsValue> {
    let opts = opts.unwrap_or(JsValue::UNDEFINED);
    let pw: SecretText = arg(&password, "password").map_err(arg_err)?;
    let kdf: KdfParams = arg(&kdf, "kdf").map_err(arg_err)?;
    bytes_out(auk::stretch_password(&pw, &kdf, derive_opts(&opts)?))
}

/// The Account Unlock Key: HKDF(stretched password, salt = Secret Key, "ov-auk-v1") (SPEC §3).
#[wasm_bindgen(js_name = deriveAuk)]
pub fn derive_auk(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] password: JsValue,
    #[wasm_bindgen(unchecked_param_type = "KdfParams")] kdf: JsValue,
    secret_key: Vec<u8>,
    #[wasm_bindgen(unchecked_optional_param_type = "DeriveAukOptions")] opts: Option<JsValue>,
) -> Result<Uint8Array, JsValue> {
    let opts = opts.unwrap_or(JsValue::UNDEFINED);
    let pw: SecretText = arg(&password, "password").map_err(arg_err)?;
    let kdf: KdfParams = arg(&kdf, "kdf").map_err(arg_err)?;
    let sk = Zeroizing::new(secret_key);
    let sk = fixed::<16>(&sk, "secretKey").map_err(arg_err)?;
    bytes_out(auk::derive_auk(&pw, &kdf, &sk, derive_opts(&opts)?))
}

// --------------------------------------------------------------------------------- envelopes

/// `0x01 ‖ nonce ‖ XChaCha20-Poly1305(key, plaintext, aad)` (SPEC §4).
#[wasm_bindgen]
pub fn wrap(key: Vec<u8>, plaintext: Vec<u8>, aad: &str, nonce: Option<Vec<u8>>) -> Result<Uint8Array, JsValue> {
    let key = key32(key, "key")?;
    let plaintext = Zeroizing::new(plaintext);
    match nonce24(nonce)? {
        Some(n) => Ok(out(&envelope::wrap_with_nonce(&key, &plaintext, aad, &n))),
        None => bytes_out(envelope::wrap(&key, &plaintext, aad)),
    }
}

/// Opens a [`wrap`] blob; `unsupported_version`/`decryption_failed`.
#[wasm_bindgen]
pub fn unwrap(key: Vec<u8>, blob: &[u8], aad: &str) -> Result<Uint8Array, JsValue> {
    let key = key32(key, "key")?;
    bytes_out(envelope::unwrap(&key, blob, aad))
}

/// `{ ephemeralSecretKey?, nonce? }`: fixed randomness for the vectors.
fn seal_opts(v: &JsValue) -> Result<SealOptions, JsValue> {
    if v.is_undefined() || v.is_null() {
        return Ok(SealOptions::default());
    }
    let esk: Option<Zeroizing<[u8; 32]>> = field(v, "ephemeralSecretKey", "opts").map_err(arg_err)?;
    let nonce: Option<Vec<u8>> = field(v, "nonce", "opts").map_err(arg_err)?;
    Ok(SealOptions { ephemeral_secret_key: esk, nonce: nonce24(nonce)? })
}

#[wasm_bindgen(typescript_custom_section)]
const SEAL_TS: &str = "\
/** Fixed randomness for `seal` (test vectors only). */
export interface SealOptions { ephemeralSecretKey?: Uint8Array; nonce?: Uint8Array }
";

/// Seals to an X25519 public key (SPEC §6); `low_order_point` for a bad key.
#[wasm_bindgen]
pub fn seal(
    recipient_enc_pk: &[u8],
    plaintext: Vec<u8>,
    aad: &str,
    #[wasm_bindgen(unchecked_optional_param_type = "SealOptions")] opts: Option<JsValue>,
) -> Result<Uint8Array, JsValue> {
    let opts = opts.unwrap_or(JsValue::UNDEFINED);
    let plaintext = Zeroizing::new(plaintext);
    bytes_out(envelope::seal_with(recipient_enc_pk, &plaintext, aad, &seal_opts(&opts)?))
}

/// The derived key of a sealed blob (for vectors and debugging).
#[wasm_bindgen(js_name = sealDerivedKey)]
pub fn seal_derived_key(recipient_enc_sk: Vec<u8>, sealed: &[u8]) -> Result<Uint8Array, JsValue> {
    let sk = key32(recipient_enc_sk, "recipientEncSk")?;
    bytes_out(envelope::seal_derived_key(&sk, sealed))
}

/// Opens a sealed blob.
#[wasm_bindgen]
pub fn unseal(recipient_enc_sk: Vec<u8>, sealed: &[u8], aad: &str) -> Result<Uint8Array, JsValue> {
    let sk = key32(recipient_enc_sk, "recipientEncSk")?;
    bytes_out(envelope::unseal(&sk, sealed, aad))
}

/// Seals a vault key (AAD `ov-vault-key|<vaultId>`).
#[wasm_bindgen(js_name = sealVaultKey)]
pub fn seal_vault_key(
    recipient_enc_pk: &[u8],
    vault_id: &str,
    vault_key: Vec<u8>,
    #[wasm_bindgen(unchecked_optional_param_type = "SealOptions")] opts: Option<JsValue>,
) -> Result<Uint8Array, JsValue> {
    let opts = opts.unwrap_or(JsValue::UNDEFINED);
    let vk = key32(vault_key, "vaultKey")?;
    bytes_out(envelope::seal_vault_key_with(recipient_enc_pk, vault_id, &vk, &seal_opts(&opts)?))
}

/// Opens a sealed vault key (32 bytes).
#[wasm_bindgen(js_name = unsealVaultKey)]
pub fn unseal_vault_key(enc_sk: Vec<u8>, vault_id: &str, sealed: &[u8]) -> Result<Uint8Array, JsValue> {
    let sk = key32(enc_sk, "encSk")?;
    bytes_out(envelope::unseal_vault_key(&sk, vault_id, sealed))
}

/// Seals a service account's master key (AAD `ov-sa-master-v1|<saId>`).
#[wasm_bindgen(js_name = sealSaMaster)]
pub fn seal_sa_master(
    recipient_enc_pk: &[u8],
    sa_id: &str,
    master: Vec<u8>,
    #[wasm_bindgen(unchecked_optional_param_type = "SealOptions")] opts: Option<JsValue>,
) -> Result<Uint8Array, JsValue> {
    let opts = opts.unwrap_or(JsValue::UNDEFINED);
    let m = key32(master, "master")?;
    bytes_out(envelope::seal_sa_master_with(recipient_enc_pk, sa_id, &m, &seal_opts(&opts)?))
}

/// Opens a sealed SA master key.
#[wasm_bindgen(js_name = unsealSaMaster)]
pub fn unseal_sa_master(enc_sk: Vec<u8>, sa_id: &str, sealed: &[u8]) -> Result<Uint8Array, JsValue> {
    let sk = key32(enc_sk, "encSk")?;
    bytes_out(envelope::unseal_sa_master(&sk, sa_id, sealed))
}

// ----------------------------------------------------------------------------------- keysets

record!(@no_ts PublicKeysRecord => PublicKeys {
    enc_pk: encPk ": Uint8Array", sign_pk: signPk ": Uint8Array", sig: sig ": Uint8Array", fingerprint: fingerprint ": string",
});

/// `PublicKeys` as the facade's JS record (`{ encPk, signPk, sig, fingerprint }`).
struct PublicKeysRecord {
    enc_pk: Vec<u8>,
    sign_pk: Vec<u8>,
    sig: Vec<u8>,
    fingerprint: String,
}

fn pub_to_js(p: &PublicKeys) -> JsValue {
    PublicKeysRecord {
        enc_pk: p.enc_pk.to_vec(),
        sign_pk: p.sign_pk.to_vec(),
        sig: p.sig.to_vec(),
        fingerprint: p.fingerprint(),
    }
    .to_js()
}

fn pub_from_js(v: &JsValue, path: &str) -> Result<PublicKeys, OvError> {
    let enc_pk: Vec<u8> = field(v, "encPk", path)?;
    let sign_pk: Vec<u8> = field(v, "signPk", path)?;
    let sig: Vec<u8> = field(v, "sig", path)?;
    Ok(PublicKeys {
        enc_pk: array(&enc_pk, &format!("{path}.encPk"))?,
        sign_pk: array(&sign_pk, &format!("{path}.signPk"))?,
        sig: array(&sig, &format!("{path}.sig"))?,
    })
}

impl ToJs for Keyset {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "encSk", self.enc_sk.to_js());
        set(&o, "signSeed", self.sign_seed.to_js());
        set(&o, "encPk", out(&self.public.enc_pk).into());
        set(&o, "signPk", out(&self.public.sign_pk).into());
        set(&o, "sig", out(&self.public.sig).into());
        set(&o, "fingerprint", self.public.fingerprint().to_js());
        o.into()
    }
}

impl FromJs for Keyset {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let enc_sk: Zeroizing<[u8; 32]> = field(v, "encSk", path)?;
        let sign_seed: Zeroizing<[u8; 32]> = field(v, "signSeed", path)?;
        let public = pub_from_js(v, path)?;
        Ok(Keyset { enc_sk, sign_seed, public })
    }
}

#[wasm_bindgen(typescript_custom_section)]
const KEYSET_TS: &str = "\
/** An account or service-account keyset (SPEC §5): X25519 `encSk`, Ed25519 `signSeed` and the signed public keys (the SDK's flat `Keyset`). Wipe the secrets. */
export interface Keyset extends PublicKeys { encSk: Uint8Array; signSeed: Uint8Array }
/** Public keys as the server sends them (base64url, snake_case). */
export interface PublicKeysJson { enc_pk: string; sign_pk: string; sig: string }
/** A wrapped keyset as stored on the server (base64url, snake_case). */
export interface WrappedKeysetJson { enc_pk: string; sign_pk: string; sig: string; wrapped: string }
";

/// The keyset of two 32-byte secrets (computes and signs the public keys).
#[wasm_bindgen(js_name = keysetFromSecrets, unchecked_return_type = "Keyset")]
pub fn keyset_from_secrets(enc_sk: Vec<u8>, sign_seed: Vec<u8>) -> Result<JsValue, JsValue> {
    let (esk, seed) = (key32(enc_sk, "encSk")?, key32(sign_seed, "signSeed")?);
    Ok(keyset::keyset_from_secrets(&esk, &seed).to_js())
}

/// A fresh random keyset.
#[wasm_bindgen(js_name = generateKeyset, unchecked_return_type = "Keyset")]
pub fn generate_keyset() -> Result<JsValue, JsValue> {
    js(keyset::generate_keyset())
}

/// Whether the public keys' signature verifies (`sig` by `signPk` over both keys).
#[wasm_bindgen(js_name = verifyPublicKeys)]
pub fn verify_public_keys(
    #[wasm_bindgen(unchecked_param_type = "PublicKeys")] public: JsValue,
) -> Result<bool, JsValue> {
    Ok(keyset::verify_public_keys(&pub_from_js(&public, "pub").map_err(arg_err)?))
}

/// Decodes server JSON (no signature check; see `trustedPublicKeys`). `invalid_public_keys`.
#[wasm_bindgen(js_name = publicKeysFromJson, unchecked_return_type = "PublicKeys")]
pub fn public_keys_from_json(
    #[wasm_bindgen(unchecked_param_type = "PublicKeysJson")] j: JsValue,
) -> Result<JsValue, JsValue> {
    let j: PublicKeysJson = json_in(&j, "json")?;
    PublicKeys::from_json(&j).map(|p| pub_to_js(&p)).map_err(|e| to_js(&e))
}

/// Decodes server JSON and checks the signature: `invalid_public_keys` when it doesn't verify.
#[wasm_bindgen(js_name = trustedPublicKeys, unchecked_return_type = "PublicKeys")]
pub fn trusted_public_keys(
    #[wasm_bindgen(unchecked_param_type = "PublicKeysJson")] j: JsValue,
) -> Result<JsValue, JsValue> {
    let j: PublicKeysJson = json_in(&j, "json")?;
    keyset::trusted_public_keys(&j).map(|p| pub_to_js(&p)).map_err(|e| to_js(&e))
}

/// Public keys as server JSON.
#[wasm_bindgen(js_name = publicKeysToJson, unchecked_return_type = "PublicKeysJson")]
pub fn public_keys_to_json(
    #[wasm_bindgen(unchecked_param_type = "PublicKeys")] public: JsValue,
) -> Result<JsValue, JsValue> {
    json_out(&pub_from_js(&public, "pub").map_err(arg_err)?.to_json())
}

/// The fingerprint `xxxx xxxx …` (first 20 bytes of SHA-256(encPk ‖ signPk), hex in groups).
#[wasm_bindgen]
pub fn fingerprint(enc_pk: &[u8], sign_pk: &[u8]) -> String {
    keyset::fingerprint(enc_pk, sign_pk)
}

/// Wraps a keyset under `key` (the AUK or an SA master) for the server.
#[wasm_bindgen(js_name = wrapKeyset, unchecked_return_type = "WrappedKeysetJson")]
pub fn wrap_keyset(
    key: Vec<u8>,
    #[wasm_bindgen(unchecked_param_type = "Keyset")] ks: JsValue,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let key = key32(key, "key")?;
    let ks: Keyset = arg(&ks, "ks").map_err(arg_err)?;
    let w = match nonce24(nonce)? {
        Some(n) => keyset::wrap_keyset_with_nonce(&key, &ks, &n),
        None => keyset::wrap_keyset(&key, &ks).map_err(|e| to_js(&e))?,
    };
    json_out(&w)
}

/// Unwraps a server keyset and checks it against its public keys.
#[wasm_bindgen(js_name = unwrapKeyset, unchecked_return_type = "Keyset")]
pub fn unwrap_keyset(
    key: Vec<u8>,
    #[wasm_bindgen(unchecked_param_type = "WrappedKeysetJson")] w: JsValue,
) -> Result<JsValue, JsValue> {
    let key = key32(key, "key")?;
    let w: WrappedKeysetJson = json_in(&w, "wrapped")?;
    js(keyset::unwrap_keyset(&key, &w))
}

// ------------------------------------------------------------------------------- vault names

/// HKDF(vaultKey, "ov-vault-name-v1").
#[wasm_bindgen(js_name = vaultNameKey)]
pub fn vault_name_key(vault_key: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let vk = key32(vault_key, "vaultKey")?;
    Ok(out(&vault_name::vault_name_key(&vk)[..]))
}

/// Encrypts a vault name (base64url, SPEC §7).
#[wasm_bindgen(js_name = encryptVaultName)]
pub fn encrypt_vault_name(
    vault_key: Vec<u8>,
    vault_id: &str,
    name: &str,
    nonce: Option<Vec<u8>>,
) -> Result<String, JsValue> {
    let vk = key32(vault_key, "vaultKey")?;
    match nonce24(nonce)? {
        Some(n) => Ok(vault_name::encrypt_vault_name_with_nonce(&vk, vault_id, name, &n)),
        None => vault_name::encrypt_vault_name(&vk, vault_id, name).map_err(|e| to_js(&e)),
    }
}

/// Decrypts a vault name.
#[wasm_bindgen(js_name = decryptVaultName)]
pub fn decrypt_vault_name(vault_key: Vec<u8>, vault_id: &str, encrypted_name: &str) -> Result<String, JsValue> {
    let vk = key32(vault_key, "vaultKey")?;
    vault_name::decrypt_vault_name(&vk, vault_id, encrypted_name).map_err(|e| to_js(&e))
}

// ------------------------------------------------------------------------------------ tokens

#[wasm_bindgen(typescript_custom_section)]
const TOKENS_TS: &str = "\
/** A service account token's parts (SPEC §9). Wipe `secret` and `kek`. */
export interface SaTokenParts { url: string; saId: string; secret: Uint8Array; kek: Uint8Array }
export interface NewSaSecretInput { url: string; saId: string; master: Uint8Array; secretId: string; name?: string; expiresAt?: string | null }
/** `token` (UTF-8, shown once) and the `POST …/secrets` body as JSON (snake_case). */
export interface NewSaSecret { token: Uint8Array; body: { id: string; name?: string; secret_hash: string; prefix: string; wrapped_master: string; expires_at: string | null } }
";

/// `ov_sa_<base64url JSON>` (UTF-8).
#[wasm_bindgen(js_name = buildSaToken)]
pub fn build_sa_token(
    #[wasm_bindgen(unchecked_param_type = "SaTokenParts")] p: JsValue,
) -> Result<Uint8Array, JsValue> {
    let url: String = field(&p, "url", "p").map_err(arg_err)?;
    let sa_id: String = field(&p, "saId", "p").map_err(arg_err)?;
    let secret: Zeroizing<[u8; 32]> = field(&p, "secret", "p").map_err(arg_err)?;
    let kek: Zeroizing<[u8; 32]> = field(&p, "kek", "p").map_err(arg_err)?;
    Ok(out(tokens::build_sa_token(&url, &sa_id, &secret, &kek).as_bytes()))
}

/// Parses a service account token; `invalid_token`.
#[wasm_bindgen(js_name = parseSaToken, unchecked_return_type = "SaTokenParts")]
pub fn parse_sa_token(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] token: JsValue,
) -> Result<JsValue, JsValue> {
    let t: SecretText = arg(&token, "token").map_err(arg_err)?;
    let p = tokens::parse_sa_token(&t).map_err(|e| to_js(&e))?;
    let o = obj();
    set(&o, "url", p.url.to_js());
    set(&o, "saId", p.sa_id.to_js());
    set(&o, "secret", p.secret.to_js());
    set(&o, "kek", p.kek.to_js());
    Ok(o.into())
}

/// Hex SHA-256 of an SA secret (what the server stores).
#[wasm_bindgen(js_name = saSecretHash)]
pub fn sa_secret_hash(secret: Vec<u8>) -> Result<String, JsValue> {
    Ok(tokens::sa_secret_hash(&*key32(secret, "secret")?))
}

/// The first 8 base64url characters of an SA secret (shown in lists).
#[wasm_bindgen(js_name = saSecretPrefix)]
pub fn sa_secret_prefix(secret: Vec<u8>) -> Result<String, JsValue> {
    Ok(tokens::sa_secret_prefix(&*key32(secret, "secret")?))
}

/// Wraps an SA master key under a token's KEK (base64url).
#[wasm_bindgen(js_name = wrapSaMaster)]
pub fn wrap_sa_master(kek: Vec<u8>, sa_id: &str, master: Vec<u8>, nonce: Option<Vec<u8>>) -> Result<String, JsValue> {
    let (kek, master) = (key32(kek, "kek")?, key32(master, "master")?);
    match nonce24(nonce)? {
        Some(n) => Ok(tokens::wrap_sa_master_with_nonce(&kek, sa_id, &master, &n)),
        None => tokens::wrap_sa_master(&kek, sa_id, &master).map_err(|e| to_js(&e)),
    }
}

/// Unwraps an SA master key.
#[wasm_bindgen(js_name = unwrapSaMaster)]
pub fn unwrap_sa_master(kek: Vec<u8>, sa_id: &str, wrapped: &str) -> Result<Uint8Array, JsValue> {
    let kek = key32(kek, "kek")?;
    bytes_out(tokens::unwrap_sa_master(&kek, sa_id, wrapped))
}

/// Hex SHA-256 of a refresh token.
#[wasm_bindgen(js_name = refreshTokenHash)]
pub fn refresh_token_hash(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] token: JsValue,
) -> Result<String, JsValue> {
    let t: SecretText = arg(&token, "token").map_err(arg_err)?;
    Ok(tokens::refresh_token_hash(&t))
}

/// A fresh `ov_rt_…` refresh token (UTF-8).
#[wasm_bindgen(js_name = newRefreshToken)]
pub fn new_refresh_token() -> Result<Uint8Array, JsValue> {
    tokens::new_refresh_token().map(|t| out(t.as_bytes())).map_err(|e| to_js(&e))
}

/// A new SA secret: the token and the request body.
#[wasm_bindgen(js_name = newSaSecret, unchecked_return_type = "NewSaSecret")]
pub fn new_sa_secret(
    #[wasm_bindgen(unchecked_param_type = "NewSaSecretInput")] p: JsValue,
) -> Result<JsValue, JsValue> {
    let url: String = field(&p, "url", "p").map_err(arg_err)?;
    let sa_id: String = field(&p, "saId", "p").map_err(arg_err)?;
    let master: Zeroizing<[u8; 32]> = field(&p, "master", "p").map_err(arg_err)?;
    let secret_id: String = field(&p, "secretId", "p").map_err(arg_err)?;
    let name: Option<String> = field(&p, "name", "p").map_err(arg_err)?;
    let expires_at: Option<String> = field(&p, "expiresAt", "p").map_err(arg_err)?;
    let s = tokens::new_sa_secret(&url, &sa_id, &master, &secret_id, name.as_deref(), expires_at.as_deref())
        .map_err(|e| to_js(&e))?;
    let o = obj();
    set(&o, "token", s.token.to_js());
    set(&o, "body", json_out(&s.body)?);
    Ok(o.into())
}

// --------------------------------------------------------------------------------------- JWT

#[wasm_bindgen(typescript_custom_section)]
const JWT_TS: &str = "\
/** Access-token claims (SPEC §9) as JSON: `iss`, `aud`, `sub`, `dev`, `org`, `vlt`, `del`, `iat`, `nbf`, `exp`, `jti` and any others. */
export type AccessClaims = { iss: string; aud?: string | string[]; sub: string; [claim: string]: unknown };
export interface Jwks { keys: { kty: string; crv?: string; x?: string; kid?: string; use?: string; alg?: string }[] }
/** `now` in Unix seconds (default: the current time); `skew` defaults to 60 s. */
export interface VerifyJwtOptions { issuer: string; audience: string; now?: number; skew?: number }
";

/// Whether a token looks like a JWT (three dot-separated parts).
#[wasm_bindgen(js_name = isJwt)]
pub fn is_jwt(#[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] token: JsValue) -> Result<bool, JsValue> {
    let t: SecretText = arg(&token, "token").map_err(arg_err)?;
    Ok(jwt::is_jwt(&t))
}

/// Decodes a JWT without verifying it: `{ header, claims }`. `invalid_token` when malformed.
#[wasm_bindgen(js_name = decodeJwt, unchecked_return_type = "{ header: Record<string, unknown>; claims: AccessClaims }")]
pub fn decode_jwt(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] token: JsValue,
) -> Result<JsValue, JsValue> {
    let t: SecretText = arg(&token, "token").map_err(arg_err)?;
    let d = jwt::decode_jwt(&t).map_err(|e| to_js(&e))?;
    let o = obj();
    set(&o, "header", json_out(&d.header)?);
    set(&o, "claims", json_out(&d.claims)?);
    Ok(o.into())
}

/// Verifies an EdDSA access token against a JWKS (signature, `iss`, `aud`, `exp`/`nbf` with skew):
/// the claims, or `unauthorized` (status 401).
#[wasm_bindgen(js_name = verifyJwt, unchecked_return_type = "AccessClaims")]
pub fn verify_jwt(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] token: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Jwks")] jwks: JsValue,
    #[wasm_bindgen(unchecked_param_type = "VerifyJwtOptions")] opts: JsValue,
) -> Result<JsValue, JsValue> {
    let t: SecretText = arg(&token, "token").map_err(arg_err)?;
    let jwks: Jwks = json_in(&jwks, "jwks")?;
    let o = VerifyOptions {
        issuer: field(&opts, "issuer", "opts").map_err(arg_err)?,
        audience: field(&opts, "audience", "opts").map_err(arg_err)?,
        #[allow(clippy::cast_possible_truncation)]
        now: field::<Option<i64>>(&opts, "now", "opts")
            .map_err(arg_err)?
            .unwrap_or((js_sys::Date::now() / 1000.0).floor() as i64),
        skew: field::<Option<i64>>(&opts, "skew", "opts").map_err(arg_err)?.unwrap_or(DEFAULT_SKEW_SECS),
    };
    let claims = jwt::verify_jwt(&t, &jwks, &o).map_err(|e| to_js(&e))?;
    json_out(&claims)
}

// ----------------------------------------------------------------------------------- restore

#[wasm_bindgen(typescript_custom_section)]
const RESTORE_TS: &str = "\
/** The current public keys a restore proof binds (`PublicKeys` will do). */
export interface CurrentKeys { encPk: Uint8Array; signPk: Uint8Array }
";

fn current(v: &JsValue) -> Result<([u8; 32], [u8; 32]), JsValue> {
    let e: Vec<u8> = field(v, "encPk", "current").map_err(arg_err)?;
    let s: Vec<u8> = field(v, "signPk", "current").map_err(arg_err)?;
    Ok((pk32(&e, "current.encPk")?, pk32(&s, "current.signPk")?))
}

/// `"ov-restore-v1" ‖ userId ‖ encPk ‖ signPk` (SPEC §18).
#[wasm_bindgen(js_name = restoreProofMessage)]
pub fn restore_proof_message(
    user_id: &str,
    #[wasm_bindgen(unchecked_param_type = "CurrentKeys")] current_keys: JsValue,
) -> Result<Uint8Array, JsValue> {
    let (e, s) = current(&current_keys)?;
    Ok(out(&restore::restore_proof_message(user_id, &e, &s)))
}

/// The restore proof: the archived keyset's Ed25519 signature over the message.
#[wasm_bindgen(js_name = restoreProof)]
pub fn restore_proof(
    old_sign_seed: Vec<u8>,
    user_id: &str,
    #[wasm_bindgen(unchecked_param_type = "CurrentKeys")] current_keys: JsValue,
) -> Result<Uint8Array, JsValue> {
    let seed = key32(old_sign_seed, "oldSignSeed")?;
    let (e, s) = current(&current_keys)?;
    Ok(out(&restore::restore_proof(&seed, user_id, &e, &s)))
}

/// Whether a restore proof verifies against the archived signing key.
#[wasm_bindgen(js_name = verifyRestoreProof)]
pub fn verify_restore_proof(
    proof: &[u8],
    user_id: &str,
    #[wasm_bindgen(unchecked_param_type = "CurrentKeys")] current_keys: JsValue,
    old_sign_pk: &[u8],
) -> Result<bool, JsValue> {
    let (e, s) = current(&current_keys)?;
    Ok(restore::verify_restore_proof(proof, user_id, &e, &s, old_sign_pk))
}

/// Re-seals an archived vault key to the current keyset.
#[wasm_bindgen(js_name = resealVaultKey)]
pub fn reseal_vault_key(
    old_enc_sk: Vec<u8>,
    current_enc_pk: &[u8],
    vault_id: &str,
    sealed: &[u8],
    #[wasm_bindgen(unchecked_optional_param_type = "SealOptions")] opts: Option<JsValue>,
) -> Result<Uint8Array, JsValue> {
    let opts = opts.unwrap_or(JsValue::UNDEFINED);
    let sk = key32(old_enc_sk, "oldEncSk")?;
    let pk = pk32(current_enc_pk, "currentEncPk")?;
    bytes_out(restore::reseal_vault_key_with(&sk, &pk, vault_id, sealed, &seal_opts(&opts)?))
}
