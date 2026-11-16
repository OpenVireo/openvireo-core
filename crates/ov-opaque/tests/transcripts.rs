//! Native opaque-ke replay of `vectors/opaque-transcripts.json` (see vectors/SOURCE.md): every seed is the
//! ChaCha20Rng seed the TS SDK's OPAQUE module used for one operation, so the same seed must give the
//! same bytes here. Covers the SDK's opaque-ke runs and the libopaque runs that an opaque-ke client took
//! part in (libopaque-only steps used libsodium's RNG, so they can't be replayed by opaque-ke).

use ov_opaque::{
    finish_login, finish_registration, opaque_ids, password_bytes, start_login, start_registration, OpaqueError,
    OpaqueIds, CONTEXT,
};
use ov_testkit::{hex_bytes, opaque_transcripts};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn rng(seed_hex: &str) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(ov_testkit::hex_array(seed_hex))
}

fn ids(id_u: &str, id_s: &str) -> OpaqueIds {
    let ids = opaque_ids(id_u, id_s);
    assert_eq!((ids.id_u.as_str(), ids.id_s.as_str()), (id_u, id_s));
    ids
}

#[test]
fn suite_matches_the_transcripts() {
    let t = opaque_transcripts();
    assert_eq!(t.suite.context, CONTEXT);
    assert_eq!((t.suite.ksf.alg.as_str(), t.suite.ksf.version, t.suite.ksf.m_kib), ("argon2id", 0x13, 65536));
    assert_eq!((t.suite.ksf.t, t.suite.ksf.p), (2, 1));
    assert_eq!(hex_bytes(&t.suite.ksf.salt_hex), [0u8; 16]);
    assert_eq!(t.suite.oprf, "ristretto255-SHA512");
    assert_eq!(t.opaque_ke.context, CONTEXT);
    assert_eq!(t.libopaque.context, CONTEXT);
    assert_eq!(hex::encode(password_bytes(&t.opaque_ke.password)), t.opaque_ke.password_nfkc_hex);
    // "Ünïcödé pässwörd ﬁ": NFKC turns the ligature into "fi".
    assert_eq!(hex::encode(password_bytes(&t.libopaque.password)), t.libopaque.password_nfkc_hex);
}

#[test]
#[cfg(feature = "test-server")] // the SDK test server is opaque-ke's server side
fn opaque_ke_registration_and_login() {
    let t = opaque_transcripts().opaque_ke;
    let ids = ids(&t.id_u, &t.id_s);

    let reg = &t.registration;
    let start = start_registration(&mut rng(&reg.client_start_seed_hex), &t.password).unwrap();
    assert_eq!(hex::encode(&start.request), reg.request_hex);
    let srv = ov_opaque::server::registration_response(&mut rng(&reg.server_seed_hex), &start.request).unwrap();
    assert_eq!(hex::encode(&*srv.setup), reg.server_setup_hex);
    assert_eq!(hex::encode(&srv.response), reg.response_hex);
    let fin = finish_registration(&mut rng(&reg.client_finish_seed_hex), start.state, &srv.response, &ids).unwrap();
    assert_eq!(hex::encode(&fin.record), reg.record_hex);
    assert_eq!(hex::encode(&*fin.export_key), reg.export_key_hex);
    let stored = ov_opaque::server::store_record(&srv.setup, &fin.record).unwrap();
    assert_eq!(hex::encode(&*stored), reg.stored_record_hex);

    let l = &t.login;
    let start = start_login(&mut rng(&l.client_start_seed_hex), &t.password).unwrap();
    assert_eq!(hex::encode(&start.ke1), l.ke1_hex);
    let srv = ov_opaque::server::credential_response(&mut rng(&l.server_seed_hex), &start.ke1, &stored, &ids, CONTEXT)
        .unwrap();
    assert_eq!(hex::encode(&srv.ke2), l.ke2_hex);
    let fin = finish_login(&mut rng(&l.client_finish_seed_hex), start.state, &srv.ke2, &ids, CONTEXT).unwrap();
    assert_eq!(hex::encode(&fin.auth_u), l.auth_u_hex);
    assert_eq!(hex::encode(&*fin.session_key), l.session_key_hex);
    assert_eq!(hex::encode(&*fin.export_key), l.export_key_hex);
    let server_key = ov_opaque::server::user_auth(&srv.state, &fin.auth_u).unwrap();
    assert_eq!(hex::encode(&*server_key), l.session_key_hex);

    let w = &t.login_wrong_password;
    assert_eq!(w.expect, "auth_failed");
    let start = start_login(&mut rng(&w.client_start_seed_hex), &w.password).unwrap();
    assert_eq!(hex::encode(&start.ke1), w.ke1_hex);
    let srv = ov_opaque::server::credential_response(&mut rng(&w.server_seed_hex), &start.ke1, &stored, &ids, CONTEXT)
        .unwrap();
    assert_eq!(hex::encode(&srv.ke2), w.ke2_hex);
    let err = finish_login(&mut rng(&w.client_finish_seed_hex), start.state, &srv.ke2, &ids, CONTEXT).unwrap_err();
    assert_eq!(err, OpaqueError::AuthFailed);
}

/// The opaque-ke client logging in to an account libopaque registered (the desktop → web/iOS case).
#[test]
fn opaque_ke_client_logs_in_to_a_libopaque_record() {
    let t = opaque_transcripts().libopaque;
    let ids = ids(&t.id_u, &t.id_s);
    let l = &t.login_opaque_ke_client;
    let start = start_login(&mut rng(&l.client_start_seed_hex), &t.password).unwrap();
    assert_eq!(hex::encode(&start.ke1), l.ke1_hex);
    let fin =
        finish_login(&mut rng(&l.client_finish_seed_hex), start.state, &hex_bytes(&l.ke2_hex), &ids, CONTEXT).unwrap();
    assert_eq!(hex::encode(&fin.auth_u), l.auth_u_hex);
    assert_eq!(l.auth_u_hex, l.expected_auth_u_hex);
    assert_eq!(hex::encode(&*fin.session_key), l.session_key_hex);
    assert_eq!(hex::encode(&*fin.export_key), l.export_key_hex);
    assert_eq!(l.export_key_hex, t.registration.export_key_hex);
    assert_eq!(l.session_key_hex.len(), 128);

    // The same ke2 with the wrong password must fail.
    let start = start_login(&mut rng(&l.client_start_seed_hex), "wrong").unwrap();
    let err = finish_login(&mut rng(&l.client_finish_seed_hex), start.state, &hex_bytes(&l.ke2_hex), &ids, CONTEXT);
    assert_eq!(err.unwrap_err(), OpaqueError::AuthFailed);
}

/// The opaque-ke client registering on the libopaque server (the web/iOS signup flow).
#[test]
fn opaque_ke_client_registers_on_libopaque() {
    let t = opaque_transcripts().libopaque;
    let ids = ids(&t.id_u, &t.id_s);
    let r = &t.opaque_ke_registration;
    let start = start_registration(&mut rng(&r.client_start_seed_hex), &t.password).unwrap();
    assert_eq!(hex::encode(&start.request), r.request_hex);
    let fin = finish_registration(&mut rng(&r.client_finish_seed_hex), start.state, &hex_bytes(&r.response_hex), &ids)
        .unwrap();
    assert_eq!(hex::encode(&fin.record), r.record_hex);
    assert_eq!(hex::encode(&*fin.export_key), r.export_key_hex);
    // libopaque stores kU ‖ skS ‖ record.
    assert!(r.user_record_hex.ends_with(&r.record_hex));
}

/// The client states survive `to_bytes`/`from_bytes` (the legacy ABI and any FFI hop use it).
#[test]
fn states_round_trip_through_bytes() {
    let t = opaque_transcripts().opaque_ke;
    let ids = ids(&t.id_u, &t.id_s);
    let reg = &t.registration;
    let start = start_registration(&mut rng(&reg.client_start_seed_hex), &t.password).unwrap();
    let state = ov_opaque::ClientRegistrationState::from_bytes(&start.state.to_bytes()).unwrap();
    let fin =
        finish_registration(&mut rng(&reg.client_finish_seed_hex), state, &hex_bytes(&reg.response_hex), &ids).unwrap();
    assert_eq!(hex::encode(&fin.record), reg.record_hex);
    assert!(ov_opaque::ClientLoginState::from_bytes(b"junk").is_err());
    assert_eq!(
        format!("{:?}", start_login(&mut rng(&reg.client_start_seed_hex), "pw").unwrap().state),
        "ClientLoginState(redacted)"
    );
}
