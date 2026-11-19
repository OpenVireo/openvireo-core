//! The in-process test servers through the C++ bridge's Rust side (feature `test-server`), and the
//! desktop's contract-v1.6 calls (`Account::sync_vault_kdbx`, `vault_kdbx_credentials`,
//! `access_token`) driven against them.

#![cfg(feature = "test-server")]

use ov_ffi_cpp::ffi;
use ov_ffi_cpp::{new_cancel_token, test_servers_start};

fn config() -> ffi::ClientConfig {
    ffi::ClientConfig {
        device_id: String::new(),
        device_name: "ctest".into(),
        platform: ffi::Platform::QtMacos,
        offline: true,
        has_server: false,
        server: Default::default(),
    }
}

fn failure() -> ffi::TransportFailure {
    ffi::TransportFailure { kind: ffi::TransportErrorKind::None, message: String::new() }
}

fn get(url: String) -> ffi::HttpRequest {
    ffi::HttpRequest { method: ffi::Method::Get, url, headers: vec![], has_body: false, body: vec![], keepalive: false }
}

#[test]
fn a_cpp_transport_reaches_the_servers_and_faults_apply() {
    let s = test_servers_start(0).unwrap();
    assert_eq!(s.issuer().unwrap(), "https://auth.test");
    let mut f = failure();
    let r = s.handle(&get(format!("{}/.well-known/openvireo-configuration", s.issuer().unwrap())), &mut f).unwrap();
    assert_eq!((r.status, f.kind), (200, ffi::TransportErrorKind::None));
    assert!(String::from_utf8(r.body).unwrap().contains("\"issuer\""));
    s.fail_next("auth", "GET", "openvireo-configuration", 0, 1).unwrap();
    let mut f = failure();
    s.handle(&get(format!("{}/.well-known/openvireo-configuration", s.issuer().unwrap())), &mut f).unwrap();
    assert_eq!(f.kind, ffi::TransportErrorKind::Offline);
    s.fail_next("sync", "", "", 503, 1).unwrap();
    let mut f = failure();
    assert_eq!(s.handle(&get(format!("{}/health", s.sync_url().unwrap())), &mut f).unwrap().status, 503);
    assert!(s.requests().unwrap().iter().any(|l| l.starts_with("200 ")));
    assert!(s.fail_next("nope", "", "", 500, 1).is_err());
    let t0 = s.now_ms().unwrap();
    assert_eq!(s.advance_ms(1000).unwrap(), t0 + 1000);
}

#[test]
fn the_desktop_syncs_a_vault_file_and_borrows_the_token() {
    let s = test_servers_start(0).unwrap();
    let c = s.client(&config()).unwrap();
    let tok = new_cancel_token();
    let a = c.connect(&s.issuer().unwrap(), &tok).unwrap();
    let kdf = ffi::KdfOverrides { has_m: true, m: 19456, has_t: true, t: 2, has_p: true, p: 1 };
    a.register_account(
        ffi::RegisterInput { email: "d@example.com".into(), password: b"pw".to_vec(), kdf, trust_device: true },
        &tok,
    )
    .unwrap();
    assert!(!s.user_id("d@example.com").unwrap().is_empty());
    let token = a.access_token(false, &tok).unwrap();
    assert_eq!(String::from_utf8(token).unwrap().split('.').count(), 3);

    let v = a.create_vault("Desk", "", &tok).unwrap();
    let id = v.id().unwrap();
    let creds = a.vault_kdbx_credentials(&id, &tok).unwrap();
    assert!(!creds.has_password && creds.key_file.len() == 32);
    let copy = v.copy_without_remotes(creds).unwrap();
    copy.set_kdf(ffi::KdbxKdf {
        kind: ffi::KdbxKdfKind::Argon2id,
        memory: 1 << 20,
        iterations: 2,
        parallelism: 1,
        rounds: 0,
    })
    .unwrap();
    let file = copy.save_local(&tok).unwrap();
    let opts = ffi::SyncOptions { local_changed: true, accept_server_state: false };
    let r = a.sync_vault_kdbx(&id, file, false, vec![], opts, &tok).unwrap();
    assert!(s.vault_revision(&id).unwrap() >= 1);
    assert!(s.vault_blob(&id).unwrap().has);

    s.lose_vault(&id).unwrap();
    let e = a.sync_vault_kdbx(&id, r.kdbx.clone(), false, vec![], opts, &tok).err().unwrap();
    assert!(e.to_string().starts_with("server_lost_database"), "{e}");
    let accept = ffi::SyncOptions { local_changed: true, accept_server_state: true };
    let again = a.sync_vault_kdbx(&id, r.kdbx, false, vec![], accept, &tok).unwrap();
    assert_eq!(again.report.outcome, ffi::SyncOutcome::Created);

    // Revocation ends the session.
    let principal = a.principal().unwrap();
    s.revoke_sessions(&principal).unwrap();
    s.advance_ms(3_600_000).unwrap();
    assert!(a.access_token(true, &tok).is_err());
}
