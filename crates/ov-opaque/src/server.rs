//! opaque-ke's server side, for tests and local mock servers only (feature `test-server`). The real
//! server is libopaque's C core behind the Flask auth server.
//!
//! Like libopaque's per-user server keypair, every registration makes a new `ServerSetup`, and the
//! OPRF credential id is a constant. Formats match the TS SDK's `opaqueServerForTests` (and the legacy
//! C ABI's ops 10–13), so `vectors/opaque-transcripts.json` replays byte for byte.

use crate::{bad, ids, wire, OpaqueError, OpaqueIds, Suite};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Each user has their own ServerSetup, so the credential id is a constant.
const CREDENTIAL_ID: &[u8] = b"ov";

/// [`registration_response`]'s result.
pub struct RegistrationResponse {
    /// `ServerSetup::serialize()` of the user's new setup. Secret.
    pub setup: Zeroizing<Vec<u8>>,
    /// The response for the client.
    pub response: Vec<u8>,
}

/// Answers a registration `request` with a new per-user ServerSetup.
pub fn registration_response<R: RngCore + CryptoRng>(
    rng: &mut R,
    request: &[u8],
) -> Result<RegistrationResponse, OpaqueError> {
    const WHAT: &str = "registration response failed";
    let setup = ServerSetup::<Suite>::new(rng);
    let r =
        ServerRegistration::start(&setup, RegistrationRequest::deserialize(request).map_err(bad(WHAT))?, CREDENTIAL_ID)
            .map_err(bad(WHAT))?;
    Ok(RegistrationResponse {
        setup: Zeroizing::new(setup.serialize().to_vec()),
        response: r.message.serialize().to_vec(),
    })
}

/// The stored user record: `u32le len ‖ setup ‖ u32le len ‖ ServerRegistration`. Secret.
pub fn store_record(setup: &[u8], record: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    const WHAT: &str = "storing the record failed";
    ServerSetup::<Suite>::deserialize(setup).map_err(bad(WHAT))?;
    let file = ServerRegistration::finish(RegistrationUpload::<Suite>::deserialize(record).map_err(bad(WHAT))?);
    Ok(wire::pack(&[setup, &file.serialize()]))
}

/// [`credential_response`]'s result.
pub struct CredentialResponse {
    /// `ke2` for the client.
    pub ke2: Vec<u8>,
    /// Server state for [`user_auth`]: `ServerLogin` state, context, idU, idS as fields. Secret.
    pub state: Zeroizing<Vec<u8>>,
}

/// Answers `ke1` for a stored record (from [`store_record`]).
pub fn credential_response<R: RngCore + CryptoRng>(
    rng: &mut R,
    ke1: &[u8],
    stored_record: &[u8],
    ids: &OpaqueIds,
    context: &str,
) -> Result<CredentialResponse, OpaqueError> {
    credential_response_raw(rng, ke1, stored_record, context.as_bytes(), ids.id_u.as_bytes(), ids.id_s.as_bytes())
}

pub(crate) fn credential_response_raw<R: RngCore + CryptoRng>(
    rng: &mut R,
    ke1: &[u8],
    stored_record: &[u8],
    context: &[u8],
    id_u: &[u8],
    id_s: &[u8],
) -> Result<CredentialResponse, OpaqueError> {
    const WHAT: &str = "credential response failed";
    let rec = wire::unpack(stored_record, 2).map_err(bad(WHAT))?;
    let setup = ServerSetup::<Suite>::deserialize(rec[0]).map_err(bad(WHAT))?;
    let file = ServerRegistration::<Suite>::deserialize(rec[1]).map_err(bad(WHAT))?;
    let r = ServerLogin::start(
        rng,
        &setup,
        Some(file),
        CredentialRequest::deserialize(ke1).map_err(bad(WHAT))?,
        CREDENTIAL_ID,
        ServerLoginParameters { context: Some(context), identifiers: ids(id_u, id_s) },
    )
    .map_err(bad(WHAT))?;
    let state = Zeroizing::new(r.state.serialize().to_vec());
    Ok(CredentialResponse { ke2: r.message.serialize().to_vec(), state: wire::pack(&[&state, context, id_u, id_s]) })
}

/// Checks the client's `auth_u` and returns the server's session key, or [`OpaqueError::AuthFailed`].
pub fn user_auth(state: &[u8], auth_u: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    let s = wire::unpack(state, 4).map_err(bad("user auth failed"))?;
    let login = ServerLogin::<Suite>::deserialize(s[0]).map_err(bad("user auth failed"))?;
    let fin = CredentialFinalization::<Suite>::deserialize(auth_u).map_err(|_| OpaqueError::AuthFailed)?;
    let r = login
        .finish(fin, ServerLoginParameters { context: Some(s[1]), identifiers: ids(s[2], s[3]) })
        .map_err(|_| OpaqueError::AuthFailed)?;
    Ok(Zeroizing::new(r.session_key.to_vec()))
}
