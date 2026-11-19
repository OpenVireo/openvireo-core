//! OPAQUE (SPEC §8, RFC 9807) over `ov-opaque`: the client's four steps and the opaque-ke test
//! server's four steps (the SDK's `opaqueServerForTests`). Full module only.
//!
//! Formats match the SDK's `@openvireo/sdk/opaque`: the client state between steps is opaque bytes
//! (`state`, holding the password: wipe it if abandoned), the server's per-user state is `sec`. Every
//! step takes an optional 32-byte `seed` for its ChaCha20 RNG, so `vectors/opaque-transcripts.json`
//! replays byte for byte; without one the seed comes from `crypto.getRandomValues`. Failures are
//! `opaque_failed` ("wrong password" for a failed login, as in the SDK).

use js_sys::Uint8Array;
use ov_error::OvError;
use ov_opaque::{server, ClientLoginState, ClientRegistrationState, OpaqueIds};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::convert::{arg, field, fixed, obj, out, set, FromJs, SecretText, ToJs};
use crate::error::{arg_err, to_js};

#[wasm_bindgen(typescript_custom_section)]
const OPAQUE_TS: &str = "\
/** `idU`: the lowercased, trimmed email; `idS`: the issuer host. */
export interface OpaqueIds { idU: string; idS: string }
export interface OpaqueRegistrationStart { request: Uint8Array; state: Uint8Array }
export interface OpaqueRegistrationFinish { record: Uint8Array; exportKey: Uint8Array }
export interface OpaqueLoginStart { ke1: Uint8Array; state: Uint8Array }
export interface OpaqueLoginFinish { authU: Uint8Array; sessionKey: Uint8Array; exportKey: Uint8Array }
";

impl FromJs for OpaqueIds {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        Ok(OpaqueIds { id_u: field(v, "idU", path)?, id_s: field(v, "idS", path)? })
    }
}
impl ToJs for OpaqueIds {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "idU", self.id_u.to_js());
        set(&o, "idS", self.id_s.to_js());
        o.into()
    }
}

/// The step's RNG: ChaCha20 from `seed`, or from the platform CSPRNG.
fn rng(seed: Option<Vec<u8>>) -> Result<ChaCha20Rng, JsValue> {
    let seed = match seed {
        Some(s) => fixed::<32>(&Zeroizing::new(s), "seed").map_err(arg_err)?,
        None => ov_crypto::primitives::random_array::<32>().map_err(|e| to_js(&e))?,
    };
    Ok(ChaCha20Rng::from_seed(*seed))
}

fn opaque_err(e: ov_opaque::OpaqueError) -> JsValue {
    to_js(&OvError::from(e))
}

fn ctx(context: Option<String>) -> String {
    context.unwrap_or_else(|| ov_opaque::CONTEXT.to_string())
}

fn pairs(items: &[(&str, &[u8])]) -> JsValue {
    let o = obj();
    for (k, v) in items {
        set(&o, k, out(v).into());
    }
    o.into()
}

/// `{ idU, idS }` from an email and the issuer URL or host.
#[wasm_bindgen(js_name = opaqueIds, unchecked_return_type = "OpaqueIds")]
pub fn opaque_ids(email: &str, issuer_or_host: &str) -> JsValue {
    ov_opaque::opaque_ids(email, issuer_or_host).to_js()
}

/// Client registration step 1: `request` for `/auth/register/start`.
#[wasm_bindgen(js_name = opaqueStartRegistration, unchecked_return_type = "OpaqueRegistrationStart")]
pub fn opaque_start_registration(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] password: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let pw: SecretText = arg(&password, "password").map_err(arg_err)?;
    let s = ov_opaque::start_registration(&mut rng(seed)?, &pw).map_err(opaque_err)?;
    Ok(pairs(&[("request", &s.request), ("state", &s.state.to_bytes())]))
}

/// Client registration step 2: the `record` for `/auth/register/finish`. Consumes `state`.
#[wasm_bindgen(js_name = opaqueFinishRegistration, unchecked_return_type = "OpaqueRegistrationFinish")]
pub fn opaque_finish_registration(
    state: Vec<u8>,
    response: &[u8],
    #[wasm_bindgen(unchecked_param_type = "OpaqueIds")] ids: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let state = Zeroizing::new(state);
    let ids: OpaqueIds = arg(&ids, "ids").map_err(arg_err)?;
    let st = ClientRegistrationState::from_bytes(&state).map_err(opaque_err)?;
    let f = ov_opaque::finish_registration(&mut rng(seed)?, st, response, &ids).map_err(opaque_err)?;
    Ok(pairs(&[("record", &f.record), ("exportKey", &f.export_key)]))
}

/// Client login step 1: `ke1` for `/auth/login/start`.
#[wasm_bindgen(js_name = opaqueStartLogin, unchecked_return_type = "OpaqueLoginStart")]
pub fn opaque_start_login(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] password: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let pw: SecretText = arg(&password, "password").map_err(arg_err)?;
    let s = ov_opaque::start_login(&mut rng(seed)?, &pw).map_err(opaque_err)?;
    Ok(pairs(&[("ke1", &s.ke1), ("state", &s.state.to_bytes())]))
}

/// Client login step 2: `authU` for `/auth/login/finish`. `opaque_failed` ("wrong password") for a
/// wrong password or the fake record of an unknown email. Consumes `state`.
#[wasm_bindgen(js_name = opaqueFinishLogin, unchecked_return_type = "OpaqueLoginFinish")]
pub fn opaque_finish_login(
    state: Vec<u8>,
    ke2: &[u8],
    #[wasm_bindgen(unchecked_param_type = "OpaqueIds")] ids: JsValue,
    context: Option<String>,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let state = Zeroizing::new(state);
    let ids: OpaqueIds = arg(&ids, "ids").map_err(arg_err)?;
    let st = ClientLoginState::from_bytes(&state).map_err(opaque_err)?;
    let f = ov_opaque::finish_login(&mut rng(seed)?, st, ke2, &ids, &ctx(context)).map_err(opaque_err)?;
    Ok(pairs(&[("authU", &f.auth_u), ("sessionKey", &f.session_key), ("exportKey", &f.export_key)]))
}

// ------------------------------------------------------------------------------ test server

/// Test server: the registration response, and `sec` (a new per-user `ServerSetup`).
#[wasm_bindgen(js_name = opaqueServerRegistrationResponse, unchecked_return_type = "{ sec: Uint8Array; response: Uint8Array }")]
pub fn opaque_server_registration_response(request: &[u8], seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    let r = server::registration_response(&mut rng(seed)?, request).map_err(opaque_err)?;
    Ok(pairs(&[("sec", &r.setup), ("response", &r.response)]))
}

/// Test server: the stored record (`sec` ‖ the client's registration upload).
#[wasm_bindgen(js_name = opaqueServerStoreRecord)]
pub fn opaque_server_store_record(sec: Vec<u8>, record: &[u8]) -> Result<Uint8Array, JsValue> {
    let sec = Zeroizing::new(sec);
    server::store_record(&sec, record).map(|r| out(&r)).map_err(opaque_err)
}

/// Test server: `ke2` and the login state `sec`.
#[wasm_bindgen(js_name = opaqueServerCredentialResponse, unchecked_return_type = "{ ke2: Uint8Array; sec: Uint8Array }")]
pub fn opaque_server_credential_response(
    ke1: &[u8],
    stored_record: Vec<u8>,
    #[wasm_bindgen(unchecked_param_type = "OpaqueIds")] ids: JsValue,
    context: Option<String>,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let stored = Zeroizing::new(stored_record);
    let ids: OpaqueIds = arg(&ids, "ids").map_err(arg_err)?;
    let r = server::credential_response(&mut rng(seed)?, ke1, &stored, &ids, &ctx(context)).map_err(opaque_err)?;
    Ok(pairs(&[("ke2", &r.ke2), ("sec", &r.state)]))
}

/// Test server: checks `authU`; the server's session key, or `undefined` when it is wrong.
#[wasm_bindgen(js_name = opaqueServerUserAuth, unchecked_return_type = "Uint8Array | undefined")]
pub fn opaque_server_user_auth(sec: Vec<u8>, auth_u: &[u8]) -> JsValue {
    let sec = Zeroizing::new(sec);
    server::user_auth(&sec, auth_u).map_or(JsValue::UNDEFINED, |k| out(&k).into())
}
