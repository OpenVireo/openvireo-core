//! Typed `vectors/test-vectors.json`, the contract's test vectors (openvireo `docs/plans/accounts/`).
//!
//! Binary values are base64url without padding unless the field name ends in `_hex` (decode with
//! [`crate::b64u`] and [`crate::hex_bytes`]). Every struct denies unknown fields, so a contract change that
//! adds a section or a field fails `cargo test -p ov-testkit` until it is typed here.

use serde::{Deserialize, Serialize};

/// The top-level sections, in file order. The tests check the JSON has exactly these keys.
pub const SECTIONS: [&str; 16] = [
    "spec",
    "encoding",
    "generated_by",
    "secret_key",
    "auk",
    "keyset",
    "public_keys",
    "seal",
    "seal_negative",
    "vault_name",
    "service_account",
    "refresh_token",
    "jwt",
    "restore_proof",
    "share",
    "vault_kdbx",
];

/// Loads and parses `vectors/test-vectors.json`.
pub fn test_vectors() -> TestVectors {
    crate::load_json("test-vectors.json")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestVectors {
    pub spec: String,
    pub encoding: String,
    pub generated_by: String,
    pub secret_key: Vec<SecretKey>,
    pub auk: Vec<Auk>,
    pub keyset: Keyset,
    pub public_keys: Vec<PublicKeyCase>,
    pub seal: Vec<Seal>,
    pub seal_negative: Vec<SealNegative>,
    pub vault_name: VaultName,
    pub service_account: ServiceAccount,
    pub refresh_token: RefreshToken,
    pub jwt: Jwt,
    pub restore_proof: RestoreProof,
    pub share: Share,
    pub vault_kdbx: VaultKdbx,
}

/// Secret Key: raw bytes and the display form (SPEC §4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretKey {
    pub raw_hex: String,
    pub display: String,
}

/// Argon2id parameters with a base64url salt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kdf {
    pub alg: String,
    pub salt: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

/// Account Unlock Key derivation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auk {
    pub password: String,
    pub password_nfkc_hex: String,
    pub kdf: Kdf,
    pub secret_key_hex: String,
    pub argon2id_hex: String,
    pub auk_hex: String,
}

/// A keyset's public half (base64url keys and signature, hex fingerprint with spaces).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyset {
    pub enc_pk: String,
    pub sign_pk: String,
    pub sig: String,
    pub fingerprint: String,
}

/// A keyset wrapped under the AUK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keyset {
    pub principal: String,
    pub auk_hex: String,
    pub enc_sk_hex: String,
    pub sign_seed_hex: String,
    pub nonce_hex: String,
    pub aad: String,
    pub public: PublicKeyset,
    pub wrapped: String,
}

/// Another principal's keys, flat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyCase {
    pub principal: String,
    pub enc_sk_hex: String,
    pub sign_seed_hex: String,
    pub enc_pk: String,
    pub sign_pk: String,
    pub sig: String,
    pub fingerprint: String,
}

/// A sealed box to a recipient's X25519 key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub recipient_enc_pk: String,
    pub recipient_enc_sk_hex: String,
    pub ephemeral_sk_hex: String,
    pub ephemeral_pk_hex: String,
    pub nonce_hex: String,
    pub aad: String,
    pub plaintext_hex: String,
    pub derived_key_hex: String,
    pub sealed: String,
}

/// A seal that must fail to open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealNegative {
    pub case: String,
    pub sealed: String,
    pub recipient_enc_sk_hex: String,
    pub aad: String,
    pub expect: String,
}

/// A vault name encrypted under the vault key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultName {
    pub vault_id: String,
    pub vault_key_hex: String,
    pub name_key_hex: String,
    pub name: String,
    pub nonce_hex: String,
    pub aad: String,
    pub encrypted_name: String,
}

/// A service-account token and its keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccount {
    pub sa_id: String,
    pub payload_json: String,
    pub token: String,
    pub secret_hash_hex: String,
    pub secret_prefix: String,
    pub master_key_hex: String,
    pub kek_hex: String,
    pub wrapped_master: String,
    pub wrapped_master_nonce_hex: String,
    pub wrapped_master_aad: String,
    pub keyset_enc_sk_hex: String,
    pub keyset_sign_seed_hex: String,
    pub public: PublicKeyset,
    pub wrapped_keyset: String,
    pub wrapped_keyset_nonce_hex: String,
    pub master_sealed_to_admin: MasterSealedToAdmin,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterSealedToAdmin {
    pub admin: String,
    pub ephemeral_sk_hex: String,
    pub nonce_hex: String,
    pub aad: String,
    pub sealed: String,
}

/// A refresh token and the hash the server stores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshToken {
    pub token: String,
    pub stored_hash_hex: String,
}

/// Access-token (JWT) verification cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jwt {
    pub signing_seed_hex: String,
    pub jwks: Jwks,
    /// Unix seconds.
    pub now: i64,
    pub valid: Vec<JwtValid>,
    pub invalid: Vec<JwtInvalid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtValid {
    pub claims: JwtClaims,
    pub token: String,
}

/// Claims of a valid token. Users have `dev`; service accounts have `org` instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtClaims {
    pub iss: String,
    pub aud: Vec<String>,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    pub vlt: Vec<VaultGrant>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultGrant {
    pub id: String,
    pub r: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtInvalid {
    pub case: String,
    pub token: String,
    /// The HTTP status a verifier answers with.
    pub expect: u16,
}

/// Keyset restore proof (account recovery).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreProof {
    pub user_id: String,
    pub old_keyset: String,
    pub old_sign_pk: String,
    pub new_enc_sk_hex: String,
    pub new_sign_seed_hex: String,
    pub new_public: PublicKeyset,
    pub message_hex: String,
    pub proof: String,
    pub reseal: Reseal,
    pub invalid: Vec<RestoreProofInvalid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reseal {
    pub archived_sealed_key: String,
    pub aad: String,
    pub ephemeral_sk_hex: String,
    pub nonce_hex: String,
    pub sealed: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreProofInvalid {
    pub case: String,
    pub proof: String,
    pub expect: String,
}

/// Share links (SPEC §22).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub cases: Vec<ShareCase>,
    #[serde(rename = "ref")]
    pub ref_: ShareRef,
}

/// A share link. Passcode-protected links also have `passcode`, `kdf`, `passcode_key_hex`, `auth` and
/// `auth_sha256_hex`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareCase {
    pub key: String,
    pub id: String,
    pub nonce_hex: String,
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passcode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Kdf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passcode_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_sha256_hex: Option<String>,
    pub padded_hex: String,
    pub aad: String,
    pub content_key_hex: String,
    pub ct: String,
    pub link: String,
}

/// The owner's encrypted reference to a share.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRef {
    pub owner_enc_sk_hex: String,
    pub ref_key_hex: String,
    pub share_id: String,
    pub plaintext: String,
    pub nonce_hex: String,
    pub aad: String,
    #[serde(rename = "ref")]
    pub ref_: String,
}

/// How to open `vault-fixture.kdbx` and what it contains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultKdbx {
    /// Relative to `vectors/`.
    pub file: String,
    pub vault_key_hex: String,
    pub key_file_component: String,
    pub kdf: VaultKdbxKdf,
    pub expect: VaultKdbxExpect,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultKdbxKdf {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultKdbxExpect {
    pub root_group: String,
    pub entry: VaultKdbxEntry,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultKdbxEntry {
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "UserName")]
    pub user_name: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "URL")]
    pub url: String,
}
