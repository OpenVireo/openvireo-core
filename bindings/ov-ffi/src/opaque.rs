//! OPAQUE (SPEC §8, RFC 9807) for the platform bindings: the client steps over `ov-opaque`, `opaque_ids`, and with
//! the `test-server` feature the opaque-ke server steps the iOS test servers use (task W3-BS2).
//!
//! Every step takes an optional 32-byte `seed`: `nil` uses the platform CSPRNG; a seed runs the step
//! on `ChaCha20Rng::from_seed(seed)`, which is how `vectors/opaque-transcripts.json` replays byte for
//! byte. Never pass a seed in production.
//!
//! The client state between two steps is an object that holds the password; `finish_*` consumes it
//! (a second use is `invalid_request`) and `dispose()` wipes an abandoned one.

use std::sync::{Arc, Mutex};

use ov_error::OvErrorCode;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};

use crate::error::OvError;
use crate::guard::{guard, guard_ok};

type R<T> = Result<T, OvError>;
type CoreResult<T> = Result<T, ov_error::OvError>;

/// The RNG of one step: seeded for vectors, else the OS generator.
enum StepRng {
    Os(OsRng),
    Seeded(Box<ChaCha20Rng>),
}

impl RngCore for StepRng {
    fn next_u32(&mut self) -> u32 {
        match self {
            StepRng::Os(r) => r.next_u32(),
            StepRng::Seeded(r) => r.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            StepRng::Os(r) => r.next_u64(),
            StepRng::Seeded(r) => r.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            StepRng::Os(r) => r.fill_bytes(dest),
            StepRng::Seeded(r) => r.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            StepRng::Os(r) => r.try_fill_bytes(dest),
            StepRng::Seeded(r) => r.try_fill_bytes(dest),
        }
    }
}

impl CryptoRng for StepRng {}

fn rng(seed: Option<Vec<u8>>) -> CoreResult<StepRng> {
    match seed {
        None => Ok(StepRng::Os(OsRng)),
        Some(s) => {
            let s = zeroize::Zeroizing::new(crate::crypto::array::<32>(&s, "seed")?);
            Ok(StepRng::Seeded(Box::new(ChaCha20Rng::from_seed(*s))))
        }
    }
}

/// The OPAQUE identities (SPEC §8).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OpaqueIds {
    /// `idU`: the account email, trimmed and lowercased.
    pub id_u: String,
    /// `idS`: the issuer host.
    pub id_s: String,
}

fn ids_in(ids: OpaqueIds) -> ov_opaque::OpaqueIds {
    ov_opaque::OpaqueIds { id_u: ids.id_u, id_s: ids.id_s }
}

/// `idU` = trimmed, lowercased email; `idS` = the discovery document's `opaque.ids`, or the issuer
/// URL reduced to its host (default port dropped), as the TS SDK's `opaqueIds`.
#[uniffi::export]
pub fn opaque_ids(email: String, issuer_or_host: String) -> OpaqueIds {
    let i = ov_opaque::opaque_ids(&email, &issuer_or_host);
    OpaqueIds { id_u: i.id_u, id_s: i.id_s }
}

/// The default OPAQUE context, `ov-opaque-v1`.
#[uniffi::export]
pub fn opaque_context() -> String {
    ov_opaque::CONTEXT.to_string()
}

macro_rules! state_object {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(uniffi::Object)]
        pub struct $name(Mutex<Option<$inner>>);

        impl $name {
            fn new(s: $inner) -> Arc<Self> {
                Arc::new(Self(Mutex::new(Some(s))))
            }

            fn take(&self) -> CoreResult<$inner> {
                self.0.lock().unwrap_or_else(|e| e.into_inner()).take().ok_or_else(|| {
                    ov_error::OvError::new(
                        OvErrorCode::InvalidRequest,
                        "this OPAQUE state was already used or disposed",
                    )
                })
            }
        }

        #[uniffi::export]
        impl $name {
            /// Wipes the state (it holds the password). A later `finish` is `invalid_request`.
            pub fn dispose(&self) {
                drop(self.0.lock().unwrap_or_else(|e| e.into_inner()).take());
            }
        }
    };
}

state_object!(
    OpaqueRegistrationState,
    ov_opaque::ClientRegistrationState,
    "Client state between the two registration steps (holds the password; wiped when dropped)."
);
state_object!(
    OpaqueLoginState,
    ov_opaque::ClientLoginState,
    "Client state between the two login steps (holds the password; wiped when dropped)."
);

/// [`opaque_start_registration`]'s result.
#[derive(uniffi::Record)]
pub struct OpaqueRegistrationStart {
    /// `request` for `/auth/register/start`.
    pub request: Vec<u8>,
    /// The state for [`opaque_finish_registration`].
    pub state: Arc<OpaqueRegistrationState>,
}

/// [`opaque_finish_registration`]'s result.
#[derive(uniffi::Record)]
pub struct OpaqueRegistrationFinish {
    /// `record` for `/auth/register/finish`.
    pub record: Vec<u8>,
    /// The export key (unused in v1; secret).
    pub export_key: Vec<u8>,
}

/// [`opaque_start_login`]'s result.
#[derive(uniffi::Record)]
pub struct OpaqueLoginStart {
    /// `ke1` for `/auth/login/start`.
    pub ke1: Vec<u8>,
    /// The state for [`opaque_finish_login`].
    pub state: Arc<OpaqueLoginState>,
}

/// [`opaque_finish_login`]'s result. The keys are secrets: wipe them.
#[derive(uniffi::Record)]
pub struct OpaqueLoginFinish {
    /// `authU` (KE3) for `/auth/login/finish`.
    pub auth_u: Vec<u8>,
    /// The session key.
    pub session_key: Vec<u8>,
    /// The export key.
    pub export_key: Vec<u8>,
}

/// Starts a registration. The password is NFKC-normalized and must be 1..65535 bytes
/// (`opaque_failed` otherwise).
#[uniffi::export]
pub fn opaque_start_registration(password: String, seed: Option<Vec<u8>>) -> R<OpaqueRegistrationStart> {
    guard(|| {
        let s = ov_opaque::start_registration(&mut rng(seed)?, &password)?;
        Ok(OpaqueRegistrationStart { request: s.request, state: OpaqueRegistrationState::new(s.state) })
    })
}

/// Finishes a registration on the server's `response`; consumes `state`.
#[uniffi::export]
pub fn opaque_finish_registration(
    state: Arc<OpaqueRegistrationState>,
    response: Vec<u8>,
    ids: OpaqueIds,
    seed: Option<Vec<u8>>,
) -> R<OpaqueRegistrationFinish> {
    guard(|| {
        let st = state.take()?;
        let f = ov_opaque::finish_registration(&mut rng(seed)?, st, &response, &ids_in(ids))?;
        Ok(OpaqueRegistrationFinish { record: f.record, export_key: f.export_key.to_vec() })
    })
}

/// Starts a login (password rules as registration).
#[uniffi::export]
pub fn opaque_start_login(password: String, seed: Option<Vec<u8>>) -> R<OpaqueLoginStart> {
    guard(|| {
        let s = ov_opaque::start_login(&mut rng(seed)?, &password)?;
        Ok(OpaqueLoginStart { ke1: s.ke1, state: OpaqueLoginState::new(s.state) })
    })
}

/// Processes `ke2`; consumes `state`. `opaque_failed` "wrong password" on a wrong password or the
/// fake record for an unknown email (show the same message as a 401). `context`: `nil` =
/// `ov-opaque-v1`.
#[uniffi::export]
pub fn opaque_finish_login(
    state: Arc<OpaqueLoginState>,
    ke2: Vec<u8>,
    ids: OpaqueIds,
    context: Option<String>,
    seed: Option<Vec<u8>>,
) -> R<OpaqueLoginFinish> {
    guard(|| {
        let st = state.take()?;
        let ctx = context.unwrap_or_else(|| ov_opaque::CONTEXT.to_string());
        let f = ov_opaque::finish_login(&mut rng(seed)?, st, &ke2, &ids_in(ids), &ctx)?;
        Ok(OpaqueLoginFinish {
            auth_u: f.auth_u,
            session_key: f.session_key.to_vec(),
            export_key: f.export_key.to_vec(),
        })
    })
}

/// Whether this build has the `opaque_server_*` test steps (feature `test-server`).
#[uniffi::export]
pub fn opaque_has_test_server() -> R<bool> {
    guard_ok(|| cfg!(feature = "test-server"))
}

// --------------------------------------------------------------------- test server

/// [`opaque_server_registration_response`]'s result.
#[cfg(feature = "test-server")]
#[derive(uniffi::Record)]
pub struct OpaqueServerRegistration {
    /// The user's new `ServerSetup` (secret; pass to [`opaque_server_store_record`]).
    pub setup: Vec<u8>,
    /// The response for the client.
    pub response: Vec<u8>,
}

/// [`opaque_server_credential_response`]'s result.
#[cfg(feature = "test-server")]
#[derive(uniffi::Record)]
pub struct OpaqueServerLogin {
    /// `ke2` for the client.
    pub ke2: Vec<u8>,
    /// Server state for [`opaque_server_user_auth`] (secret).
    pub state: Vec<u8>,
}

/// Test server: answers a registration `request` with a new per-user ServerSetup.
#[cfg(feature = "test-server")]
#[uniffi::export]
pub fn opaque_server_registration_response(request: Vec<u8>, seed: Option<Vec<u8>>) -> R<OpaqueServerRegistration> {
    guard(|| {
        let r = ov_opaque::server::registration_response(&mut rng(seed)?, &request)?;
        Ok(OpaqueServerRegistration { setup: r.setup.to_vec(), response: r.response })
    })
}

/// Test server: the stored user record (`setup` ‖ `record`, length-prefixed).
#[cfg(feature = "test-server")]
#[uniffi::export]
pub fn opaque_server_store_record(setup: Vec<u8>, record: Vec<u8>) -> R<Vec<u8>> {
    guard(|| Ok(ov_opaque::server::store_record(&setup, &record)?.to_vec()))
}

/// Test server: answers `ke1` for a stored record. `context`: `nil` = `ov-opaque-v1`.
#[cfg(feature = "test-server")]
#[uniffi::export]
pub fn opaque_server_credential_response(
    ke1: Vec<u8>,
    stored_record: Vec<u8>,
    ids: OpaqueIds,
    context: Option<String>,
    seed: Option<Vec<u8>>,
) -> R<OpaqueServerLogin> {
    guard(|| {
        let ctx = context.unwrap_or_else(|| ov_opaque::CONTEXT.to_string());
        let r = ov_opaque::server::credential_response(&mut rng(seed)?, &ke1, &stored_record, &ids_in(ids), &ctx)?;
        Ok(OpaqueServerLogin { ke2: r.ke2, state: r.state.to_vec() })
    })
}

/// Test server: checks the client's `auth_u`; the server's session key, or `opaque_failed`.
#[cfg(feature = "test-server")]
#[uniffi::export]
pub fn opaque_server_user_auth(state: Vec<u8>, auth_u: Vec<u8>) -> R<Vec<u8>> {
    guard(|| Ok(ov_opaque::server::user_auth(&state, &auth_u)?.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ov_testkit::hex_bytes;
    use serde_json::Value;

    fn seed(v: &Value) -> Option<Vec<u8>> {
        Some(hex_bytes(v.as_str().unwrap()))
    }

    /// The client steps replay the TS SDK's transcript (server side from ov-opaque directly, so
    /// this runs without the `test-server` feature).
    #[test]
    fn client_steps_replay_the_transcript() {
        let t: Value = ov_testkit::load_json("opaque-transcripts.json");
        let o = &t["opaque_ke"];
        let ids = opaque_ids(" Alice@Example.com ".into(), "https://accounts.openvireo.example".into());
        assert_eq!(ids.id_u, o["id_u"].as_str().unwrap());
        assert_eq!(ids.id_s, o["id_s"].as_str().unwrap());
        let pw = o["password"].as_str().unwrap().to_string();

        let reg = &o["registration"];
        let start = opaque_start_registration(pw.clone(), seed(&reg["client_start_seed_hex"])).unwrap();
        assert_eq!(start.request, hex_bytes(reg["request_hex"].as_str().unwrap()));
        let fin = opaque_finish_registration(
            start.state.clone(),
            hex_bytes(reg["response_hex"].as_str().unwrap()),
            ids.clone(),
            seed(&reg["client_finish_seed_hex"]),
        )
        .unwrap();
        assert_eq!(fin.record, hex_bytes(reg["record_hex"].as_str().unwrap()));
        let OvError::Failure { code, .. } =
            opaque_finish_registration(start.state, vec![], ids.clone(), None).err().unwrap();
        assert_eq!(code, crate::OvErrorCode::InvalidRequest);

        let l = &o["login"];
        let start = opaque_start_login(pw, seed(&l["client_start_seed_hex"])).unwrap();
        assert_eq!(start.ke1, hex_bytes(l["ke1_hex"].as_str().unwrap()));
        let fin = opaque_finish_login(
            start.state,
            hex_bytes(l["ke2_hex"].as_str().unwrap()),
            ids,
            None,
            seed(&l["client_finish_seed_hex"]),
        )
        .unwrap();
        assert_eq!(fin.auth_u, hex_bytes(l["auth_u_hex"].as_str().unwrap()));
    }

    #[test]
    fn wrong_password_is_opaque_failed() {
        let ids = opaque_ids("a@b".into(), "x".into());
        let start = opaque_start_registration("right".into(), None).unwrap();
        let srv = ov_opaque::server::registration_response(&mut OsRng, &start.request).unwrap();
        let fin = opaque_finish_registration(start.state, srv.response, ids.clone(), None).unwrap();
        let stored = ov_opaque::server::store_record(&srv.setup, &fin.record).unwrap();
        let login = opaque_start_login("wrong".into(), None).unwrap();
        let cr = ov_opaque::server::credential_response(
            &mut OsRng,
            &login.ke1,
            &stored,
            &ids_in(ids.clone()),
            ov_opaque::CONTEXT,
        )
        .unwrap();
        let OvError::Failure { code, message, .. } =
            opaque_finish_login(login.state, cr.ke2, ids, None, None).err().unwrap();
        assert_eq!(code, crate::OvErrorCode::OpaqueFailed);
        assert_eq!(message, "wrong password");
        let OvError::Failure { code, .. } = opaque_start_login(String::new(), None).err().unwrap();
        assert_eq!(code, crate::OvErrorCode::OpaqueFailed);
    }
}
