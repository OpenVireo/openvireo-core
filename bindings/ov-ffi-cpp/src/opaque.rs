//! The OPAQUE client steps (ov-opaque, SPEC §8) for C++, plus, behind the `test-server` feature, the
//! seeded client steps and opaque-ke's server half the desktop's tests stand in for the auth server
//! with. Names and shapes follow the desktop's former `ovd` bridge (README.md, "Desktop swap").
//!
//! Passwords, `idU`, `idS` and the context cross as UTF-8 bytes; the password is NFKC-normalised
//! here. Client states, session keys and export keys are secret: wipe them. Every step is CPU-bound
//! (Argon2id): call it off the GUI thread.
//!
//! Without the `test-server` feature the seeded and server functions are still declared (so the
//! header is the same either way) and fail with `internal`; [`test_server_enabled`] says which.

use ov_error::OvError;
use ov_opaque::{ClientLoginState, ClientRegistrationState, OpaqueIds};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::utf8;
use crate::edge::{edge, FfiError};
use crate::ffi;
use crate::primitives::take;

type R<T> = Result<T, FfiError>;

fn ids(id_u: &[u8], id_s: &[u8]) -> Result<OpaqueIds, OvError> {
    Ok(OpaqueIds { id_u: utf8("idU", id_u)?.to_string(), id_s: utf8("idS", id_s)?.to_string() })
}

fn start_registration_with(rng: &mut (impl RngCore + CryptoRng), password: &[u8]) -> Result<ffi::OpaqueStart, OvError> {
    let r = ov_opaque::start_registration(rng, utf8("the password", password)?)?;
    Ok(ffi::OpaqueStart { message: r.request, state: take(r.state.to_bytes()) })
}

fn finish_registration_with(
    rng: &mut (impl RngCore + CryptoRng),
    state: &[u8],
    response: &[u8],
    id_u: &[u8],
    id_s: &[u8],
) -> Result<Vec<u8>, OvError> {
    let state = ClientRegistrationState::from_bytes(state)?;
    Ok(ov_opaque::finish_registration(rng, state, response, &ids(id_u, id_s)?)?.record)
}

fn start_login_with(rng: &mut (impl RngCore + CryptoRng), password: &[u8]) -> Result<ffi::OpaqueStart, OvError> {
    let r = ov_opaque::start_login(rng, utf8("the password", password)?)?;
    Ok(ffi::OpaqueStart { message: r.ke1, state: take(r.state.to_bytes()) })
}

fn finish_login_with(
    rng: &mut (impl RngCore + CryptoRng),
    state: &[u8],
    ke2: &[u8],
    id_u: &[u8],
    id_s: &[u8],
    context: &[u8],
) -> Result<ffi::OpaqueLogin, OvError> {
    let state = ClientLoginState::from_bytes(state)?;
    let r = ov_opaque::finish_login(rng, state, ke2, &ids(id_u, id_s)?, utf8("the context", context)?)?;
    Ok(ffi::OpaqueLogin { auth_u: r.auth_u, session_key: take(r.session_key), export_key: take(r.export_key) })
}

/// `ov::opaque_start_registration`: `message` is the registration request.
pub(crate) fn opaque_start_registration(password: &[u8]) -> R<ffi::OpaqueStart> {
    edge(|| start_registration_with(&mut rand_core::OsRng, password))
}

/// `ov::opaque_finish_registration`: the registration record to upload.
pub(crate) fn opaque_finish_registration(state: &[u8], response: &[u8], id_u: &[u8], id_s: &[u8]) -> R<Vec<u8>> {
    edge(|| finish_registration_with(&mut rand_core::OsRng, state, response, id_u, id_s))
}

/// `ov::opaque_start_login`: `message` is KE1.
pub(crate) fn opaque_start_login(password: &[u8]) -> R<ffi::OpaqueStart> {
    edge(|| start_login_with(&mut rand_core::OsRng, password))
}

/// `ov::opaque_finish_login`: `opaque_failed` for a wrong password or a tampered KE2.
pub(crate) fn opaque_finish_login(
    state: &[u8],
    ke2: &[u8],
    id_u: &[u8],
    id_s: &[u8],
    context: &[u8],
) -> R<ffi::OpaqueLogin> {
    edge(|| finish_login_with(&mut rand_core::OsRng, state, ke2, id_u, id_s, context))
}

/// `ov::test_server_enabled`: whether this library was built with the `test-server` feature.
pub(crate) fn test_server_enabled() -> bool {
    cfg!(feature = "test-server")
}

#[cfg(feature = "test-server")]
mod imp {
    use super::*;
    use crate::primitives::array;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// The ChaCha20 RNG the transcripts (`vectors/opaque-transcripts.json`) record a seed for.
    fn rng(seed: &[u8]) -> Result<ChaCha20Rng, OvError> {
        Ok(ChaCha20Rng::from_seed(*array::<32>("the seed", seed)?))
    }

    pub(super) fn start_registration_seeded(password: &[u8], seed: &[u8]) -> Result<ffi::OpaqueStart, OvError> {
        start_registration_with(&mut rng(seed)?, password)
    }

    pub(super) fn finish_registration_seeded(
        state: &[u8],
        response: &[u8],
        id_u: &[u8],
        id_s: &[u8],
        seed: &[u8],
    ) -> Result<Vec<u8>, OvError> {
        finish_registration_with(&mut rng(seed)?, state, response, id_u, id_s)
    }

    pub(super) fn start_login_seeded(password: &[u8], seed: &[u8]) -> Result<ffi::OpaqueStart, OvError> {
        start_login_with(&mut rng(seed)?, password)
    }

    pub(super) fn finish_login_seeded(
        state: &[u8],
        ke2: &[u8],
        id_u: &[u8],
        id_s: &[u8],
        context: &[u8],
        seed: &[u8],
    ) -> Result<ffi::OpaqueLogin, OvError> {
        finish_login_with(&mut rng(seed)?, state, ke2, id_u, id_s, context)
    }

    fn registration_response_with(
        rng: &mut (impl RngCore + CryptoRng),
        request: &[u8],
    ) -> Result<ffi::OpaqueServerStep, OvError> {
        let r = ov_opaque::server::registration_response(rng, request)?;
        Ok(ffi::OpaqueServerStep { message: r.response, state: take(r.setup) })
    }

    pub(super) fn registration_response(request: &[u8], seed: &[u8]) -> Result<ffi::OpaqueServerStep, OvError> {
        if seed.is_empty() {
            registration_response_with(&mut rand_core::OsRng, request)
        } else {
            registration_response_with(&mut rng(seed)?, request)
        }
    }

    pub(super) fn store_record(setup: &[u8], record: &[u8]) -> Result<Vec<u8>, OvError> {
        Ok(take(ov_opaque::server::store_record(setup, record)?))
    }

    fn credential_response_with(
        rng: &mut (impl RngCore + CryptoRng),
        ke1: &[u8],
        stored_record: &[u8],
        id_u: &[u8],
        id_s: &[u8],
        context: &[u8],
    ) -> Result<ffi::OpaqueServerStep, OvError> {
        let r = ov_opaque::server::credential_response(
            rng,
            ke1,
            stored_record,
            &ids(id_u, id_s)?,
            utf8("the context", context)?,
        )?;
        Ok(ffi::OpaqueServerStep { message: r.ke2, state: take(r.state) })
    }

    pub(super) fn credential_response(
        ke1: &[u8],
        stored_record: &[u8],
        id_u: &[u8],
        id_s: &[u8],
        context: &[u8],
        seed: &[u8],
    ) -> Result<ffi::OpaqueServerStep, OvError> {
        if seed.is_empty() {
            credential_response_with(&mut rand_core::OsRng, ke1, stored_record, id_u, id_s, context)
        } else {
            credential_response_with(&mut rng(seed)?, ke1, stored_record, id_u, id_s, context)
        }
    }

    pub(super) fn user_auth(state: &[u8], auth_u: &[u8]) -> Result<Vec<u8>, OvError> {
        Ok(take(ov_opaque::server::user_auth(state, auth_u)?))
    }
}

#[cfg(not(feature = "test-server"))]
mod imp {
    //! Built without `test-server`: every test-only function fails with `internal`.

    use super::*;
    use ov_error::OvErrorCode;

    fn off<T>() -> Result<T, OvError> {
        Err(OvError::new(OvErrorCode::Internal, "openvireo-core was built without the test-server feature"))
    }
    pub(super) fn start_registration_seeded(_: &[u8], _: &[u8]) -> Result<ffi::OpaqueStart, OvError> {
        off()
    }
    pub(super) fn finish_registration_seeded(
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, OvError> {
        off()
    }
    pub(super) fn start_login_seeded(_: &[u8], _: &[u8]) -> Result<ffi::OpaqueStart, OvError> {
        off()
    }
    pub(super) fn finish_login_seeded(
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<ffi::OpaqueLogin, OvError> {
        off()
    }
    pub(super) fn registration_response(_: &[u8], _: &[u8]) -> Result<ffi::OpaqueServerStep, OvError> {
        off()
    }
    pub(super) fn store_record(_: &[u8], _: &[u8]) -> Result<Vec<u8>, OvError> {
        off()
    }
    pub(super) fn credential_response(
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<ffi::OpaqueServerStep, OvError> {
        off()
    }
    pub(super) fn user_auth(_: &[u8], _: &[u8]) -> Result<Vec<u8>, OvError> {
        off()
    }
}

/// `ov::opaque_start_registration_seeded` (test-server): [`opaque_start_registration`] with a
/// ChaCha20 RNG from a 32-byte seed, to replay a transcript.
pub(crate) fn opaque_start_registration_seeded(password: &[u8], seed: &[u8]) -> R<ffi::OpaqueStart> {
    edge(|| imp::start_registration_seeded(password, seed))
}

/// `ov::opaque_finish_registration_seeded` (test-server).
pub(crate) fn opaque_finish_registration_seeded(
    state: &[u8],
    response: &[u8],
    id_u: &[u8],
    id_s: &[u8],
    seed: &[u8],
) -> R<Vec<u8>> {
    edge(|| imp::finish_registration_seeded(state, response, id_u, id_s, seed))
}

/// `ov::opaque_start_login_seeded` (test-server).
pub(crate) fn opaque_start_login_seeded(password: &[u8], seed: &[u8]) -> R<ffi::OpaqueStart> {
    edge(|| imp::start_login_seeded(password, seed))
}

/// `ov::opaque_finish_login_seeded` (test-server).
pub(crate) fn opaque_finish_login_seeded(
    state: &[u8],
    ke2: &[u8],
    id_u: &[u8],
    id_s: &[u8],
    context: &[u8],
    seed: &[u8],
) -> R<ffi::OpaqueLogin> {
    edge(|| imp::finish_login_seeded(state, ke2, id_u, id_s, context, seed))
}

/// `ov::opaque_server_registration_response` (test-server): `message` is the response, `state` the
/// per-user server setup (secret) that [`opaque_server_store_record`] takes.
pub(crate) fn opaque_server_registration_response(request: &[u8]) -> R<ffi::OpaqueServerStep> {
    edge(|| imp::registration_response(request, &[]))
}

/// `ov::opaque_server_registration_response_seeded` (test-server).
pub(crate) fn opaque_server_registration_response_seeded(request: &[u8], seed: &[u8]) -> R<ffi::OpaqueServerStep> {
    edge(|| {
        if seed.is_empty() {
            return Err(crate::crypto::invalid("the seed must be 32 bytes"));
        }
        imp::registration_response(request, seed)
    })
}

/// `ov::opaque_server_store_record` (test-server): what the server keeps for the user.
pub(crate) fn opaque_server_store_record(setup: &[u8], record: &[u8]) -> R<Vec<u8>> {
    edge(|| imp::store_record(setup, record))
}

/// `ov::opaque_server_credential_response` (test-server): `message` is KE2, `state` what
/// [`opaque_server_user_auth`] takes.
pub(crate) fn opaque_server_credential_response(
    ke1: &[u8],
    stored_record: &[u8],
    id_u: &[u8],
    id_s: &[u8],
    context: &[u8],
) -> R<ffi::OpaqueServerStep> {
    edge(|| imp::credential_response(ke1, stored_record, id_u, id_s, context, &[]))
}

/// `ov::opaque_server_credential_response_seeded` (test-server).
pub(crate) fn opaque_server_credential_response_seeded(
    ke1: &[u8],
    stored_record: &[u8],
    id_u: &[u8],
    id_s: &[u8],
    context: &[u8],
    seed: &[u8],
) -> R<ffi::OpaqueServerStep> {
    edge(|| {
        if seed.is_empty() {
            return Err(crate::crypto::invalid("the seed must be 32 bytes"));
        }
        imp::credential_response(ke1, stored_record, id_u, id_s, context, seed)
    })
}

/// `ov::opaque_server_user_auth` (test-server): checks the client's `auth_u`; the session key.
pub(crate) fn opaque_server_user_auth(state: &[u8], auth_u: &[u8]) -> R<Vec<u8>> {
    edge(|| imp::user_auth(state, auth_u))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ov_error::OvErrorCode;
    use ov_testkit::{hex_bytes, opaque_transcripts};

    fn code<T>(r: R<T>) -> OvErrorCode {
        let Err(e) = r else { panic!("expected an error") };
        let c = e.0.code;
        let _ = crate::edge::take_last_error();
        c
    }

    /// The unseeded client against the transcript's libopaque record can't be replayed (fresh
    /// randomness), but the client steps run, and a garbage KE2 fails as `opaque_failed`.
    #[test]
    fn client_steps_run() {
        let t = opaque_transcripts().libopaque;
        let start = opaque_start_login(t.password.as_bytes()).unwrap();
        assert_eq!(start.message.len(), hex_bytes(&t.login_opaque_ke_client.ke1_hex).len());
        let ke2 = hex_bytes(&t.login_opaque_ke_client.ke2_hex);
        let err =
            code(opaque_finish_login(&start.state, &ke2, t.id_u.as_bytes(), t.id_s.as_bytes(), t.context.as_bytes()));
        assert_eq!(err, OvErrorCode::OpaqueFailed);
        assert_eq!(code(opaque_finish_login(b"junk", &ke2, b"a", b"b", b"c")), OvErrorCode::OpaqueFailed);

        let reg = opaque_start_registration(t.password.as_bytes()).unwrap();
        let response = hex_bytes(&t.opaque_ke_registration.response_hex);
        let record = opaque_finish_registration(&reg.state, &response, t.id_u.as_bytes(), t.id_s.as_bytes()).unwrap();
        assert_eq!(record.len(), hex_bytes(&t.opaque_ke_registration.record_hex).len());
        assert_eq!(code(opaque_start_login(&[0xff])), OvErrorCode::InvalidRequest);
    }

    #[cfg(not(feature = "test-server"))]
    #[test]
    fn test_only_functions_fail_without_the_feature() {
        assert!(!test_server_enabled());
        assert_eq!(code(opaque_start_login_seeded(b"pw", &[0; 32])), OvErrorCode::Internal);
        assert_eq!(code(opaque_server_registration_response(b"x")), OvErrorCode::Internal);
        assert_eq!(code(opaque_server_user_auth(b"x", b"y")), OvErrorCode::Internal);
    }

    /// `cargo test -p ov-ffi-cpp --features test-server`: the libopaque replay and the full
    /// opaque-ke transcript through these functions.
    #[cfg(feature = "test-server")]
    #[test]
    fn transcripts_replay() {
        assert!(test_server_enabled());
        let all = opaque_transcripts();

        // The opaque-ke client logging in to an account libopaque registered
        let t = &all.libopaque;
        let (u, s, c) = (t.id_u.as_bytes(), t.id_s.as_bytes(), t.context.as_bytes());
        let l = &t.login_opaque_ke_client;
        let start = opaque_start_login_seeded(t.password.as_bytes(), &hex_bytes(&l.client_start_seed_hex)).unwrap();
        assert_eq!(hex::encode(&start.message), l.ke1_hex);
        let fin = opaque_finish_login_seeded(
            &start.state,
            &hex_bytes(&l.ke2_hex),
            u,
            s,
            c,
            &hex_bytes(&l.client_finish_seed_hex),
        )
        .unwrap();
        assert_eq!(hex::encode(&fin.auth_u), l.auth_u_hex);
        assert_eq!(hex::encode(&fin.session_key), l.session_key_hex);
        assert_eq!(hex::encode(&fin.export_key), l.export_key_hex);
        // and registering on the libopaque server
        let r = &t.opaque_ke_registration;
        let start =
            opaque_start_registration_seeded(t.password.as_bytes(), &hex_bytes(&r.client_start_seed_hex)).unwrap();
        assert_eq!(hex::encode(&start.message), r.request_hex);
        let record = opaque_finish_registration_seeded(
            &start.state,
            &hex_bytes(&r.response_hex),
            u,
            s,
            &hex_bytes(&r.client_finish_seed_hex),
        )
        .unwrap();
        assert_eq!(hex::encode(&record), r.record_hex);

        // The whole opaque-ke run, server included
        let t = &all.opaque_ke;
        let (u, s, c) = (t.id_u.as_bytes(), t.id_s.as_bytes(), t.context.as_bytes());
        let reg = &t.registration;
        let start =
            opaque_start_registration_seeded(t.password.as_bytes(), &hex_bytes(&reg.client_start_seed_hex)).unwrap();
        let srv = opaque_server_registration_response_seeded(&start.message, &hex_bytes(&reg.server_seed_hex)).unwrap();
        assert_eq!(hex::encode(&srv.message), reg.response_hex);
        assert_eq!(hex::encode(&srv.state), reg.server_setup_hex);
        let record = opaque_finish_registration_seeded(
            &start.state,
            &srv.message,
            u,
            s,
            &hex_bytes(&reg.client_finish_seed_hex),
        )
        .unwrap();
        assert_eq!(hex::encode(&record), reg.record_hex);
        let stored = opaque_server_store_record(&srv.state, &record).unwrap();
        assert_eq!(hex::encode(&stored), reg.stored_record_hex);
        let lg = &t.login;
        let start = opaque_start_login_seeded(t.password.as_bytes(), &hex_bytes(&lg.client_start_seed_hex)).unwrap();
        let srv =
            opaque_server_credential_response_seeded(&start.message, &stored, u, s, c, &hex_bytes(&lg.server_seed_hex))
                .unwrap();
        assert_eq!(hex::encode(&srv.message), lg.ke2_hex);
        let fin =
            opaque_finish_login_seeded(&start.state, &srv.message, u, s, c, &hex_bytes(&lg.client_finish_seed_hex))
                .unwrap();
        assert_eq!(hex::encode(&fin.session_key), lg.session_key_hex);
        assert_eq!(hex::encode(opaque_server_user_auth(&srv.state, &fin.auth_u).unwrap()), lg.session_key_hex);

        // Unseeded server round trip
        let start = opaque_start_registration(b"pw").unwrap();
        let srv = opaque_server_registration_response(&start.message).unwrap();
        let record = opaque_finish_registration(&start.state, &srv.message, b"u", b"s").unwrap();
        let stored = opaque_server_store_record(&srv.state, &record).unwrap();
        let start = opaque_start_login(b"pw").unwrap();
        let srv = opaque_server_credential_response(&start.message, &stored, b"u", b"s", b"ctx").unwrap();
        let fin = opaque_finish_login(&start.state, &srv.message, b"u", b"s", b"ctx").unwrap();
        assert_eq!(opaque_server_user_auth(&srv.state, &fin.auth_u).unwrap(), fin.session_key);
        assert_eq!(code(opaque_start_login_seeded(b"pw", &[0; 3])), OvErrorCode::InvalidRequest);
    }
}
