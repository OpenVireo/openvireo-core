//! Typed `vectors/opaque-transcripts.json`: deterministic OPAQUE (RFC 9807) runs recorded from the TS SDK
//! (opaque-ke 4.0.1 in WASM) and from libopaque (the C core of the auth server and the desktop client).
//! `vectors/SOURCE.md` says how they were made; `vectors/tools/gen-opaque-transcripts.sh` regenerates them.
//!
//! Every binary value is lowercase hex. A seed (`*_seed_hex`) is the 32-byte ChaCha20Rng seed the SDK's
//! OPAQUE module used for that one operation, so an opaque-ke client given the same seed must produce the
//! same bytes. libopaque seeds drive the tool's seeded libsodium randombytes instead.

use serde::{Deserialize, Serialize};

/// Loads and parses `vectors/opaque-transcripts.json`.
pub fn opaque_transcripts() -> OpaqueTranscripts {
    crate::load_json("opaque-transcripts.json")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueTranscripts {
    pub spec: String,
    pub encoding: String,
    pub generated_by: String,
    pub suite: Suite,
    pub seed_derivation: String,
    pub opaque_ke: OpaqueKeRuns,
    pub libopaque: LibopaqueRuns,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub oprf: String,
    pub key_exchange: String,
    pub ksf: Ksf,
    pub context: String,
    pub password_encoding: String,
}

/// Argon2id parameters of the key stretching function.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ksf {
    pub alg: String,
    /// 19 = 0x13.
    pub version: u32,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt_hex: String,
}

/// opaque-ke client against the SDK's opaque-ke test server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueKeRuns {
    pub description: String,
    pub password: String,
    pub password_nfkc_hex: String,
    pub id_u: String,
    pub id_s: String,
    pub context: String,
    pub registration: OpaqueKeRegistration,
    pub login: OpaqueKeLogin,
    pub login_wrong_password: OpaqueKeFailedLogin,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueKeRegistration {
    pub client_start_seed_hex: String,
    pub request_hex: String,
    pub server_seed_hex: String,
    /// `ServerSetup::serialize()` of the per-user setup made from `server_seed_hex`.
    pub server_setup_hex: String,
    pub response_hex: String,
    pub client_finish_seed_hex: String,
    /// `RegistrationUpload` (the client's record).
    pub record_hex: String,
    pub export_key_hex: String,
    /// The SDK test server's stored form: `u32le len ‖ server setup ‖ u32le len ‖ ServerRegistration`.
    pub stored_record_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueKeLogin {
    pub client_start_seed_hex: String,
    pub ke1_hex: String,
    pub server_seed_hex: String,
    pub ke2_hex: String,
    pub client_finish_seed_hex: String,
    /// KE3, which the server checked.
    pub auth_u_hex: String,
    pub session_key_hex: String,
    pub export_key_hex: String,
}

/// A login with the wrong password: the client must fail on `ke2_hex`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueKeFailedLogin {
    pub password: String,
    pub client_start_seed_hex: String,
    pub ke1_hex: String,
    pub server_seed_hex: String,
    pub ke2_hex: String,
    pub client_finish_seed_hex: String,
    /// `"auth_failed"`.
    pub expect: String,
}

/// Runs involving libopaque.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibopaqueRuns {
    pub description: String,
    pub password: String,
    pub password_nfkc_hex: String,
    pub id_u: String,
    pub id_s: String,
    pub context: String,
    /// libopaque client + server.
    pub registration: LibopaqueRegistration,
    /// libopaque client + server login to `registration`.
    pub login_c_client: LibopaqueLogin,
    /// opaque-ke client (TS SDK) logging in to `registration` on the libopaque server.
    pub login_opaque_ke_client: OpaqueKeOnLibopaqueLogin,
    /// opaque-ke client registering on the libopaque server, then the libopaque client logging in.
    pub opaque_ke_registration: OpaqueKeOnLibopaqueRegistration,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibopaqueRegistration {
    pub seed_hex: String,
    pub request_hex: String,
    /// skS ‖ kU (per-user server keypair and OPRF key).
    pub server_sec_hex: String,
    pub response_hex: String,
    pub record_hex: String,
    pub export_key_hex: String,
    /// libopaque's stored record: kU ‖ skS ‖ record.
    pub user_record_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibopaqueLogin {
    pub seed_hex: String,
    pub ke1_hex: String,
    pub ke2_hex: String,
    pub auth_u_hex: String,
    pub session_key_hex: String,
    pub export_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueKeOnLibopaqueLogin {
    pub client_start_seed_hex: String,
    pub ke1_hex: String,
    /// libopaque tool seed for `CreateCredentialResponse`.
    pub server_seed_hex: String,
    pub ke2_hex: String,
    /// The auth_u libopaque's server expects (its `authU0`).
    pub expected_auth_u_hex: String,
    pub client_finish_seed_hex: String,
    pub auth_u_hex: String,
    pub session_key_hex: String,
    pub export_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueKeOnLibopaqueRegistration {
    pub client_start_seed_hex: String,
    pub request_hex: String,
    pub server_seed_hex: String,
    pub server_sec_hex: String,
    pub response_hex: String,
    pub client_finish_seed_hex: String,
    pub record_hex: String,
    pub export_key_hex: String,
    pub user_record_hex: String,
    pub login_c_client: LibopaqueLogin,
}
