//! Contract-v1.7: local files opened and saved with a password hash, self-hosted sync with
//! `local_changed` / `accept_server_state`, and one wrong-key code.

mod servers_common;

use ov_core::api::*;
use ov_core::host::Method;
use ov_core::OvErrorCode;
use servers_common::*;

fn creds(pw: &str) -> KdbxCredentials {
    KdbxCredentials { password: Some(pw.as_bytes().to_vec()), ..Default::default() }
}

fn hash_creds(pw: &str) -> KdbxCredentials {
    KdbxCredentials { password_hash: Some(ov_kdbx::vault::password_hash(pw).to_vec()), ..Default::default() }
}

fn set_field(v: &Vault, title: &str, name: &str, value: &str) {
    let id = find_title(v, title).id;
    v.edit_entry(
        id,
        EntryInput {
            fields: vec![FieldInput { name: name.into(), value: value.as_bytes().to_vec(), protected: None }],
            ..Default::default()
        },
    )
    .unwrap();
}

#[tokio::test]
async fn a_local_file_opens_and_saves_with_the_password_hash() {
    let s = servers();
    let c = device(&s, false);
    let v = c.create_local("Home".into(), creds("correct horse ü"), nc()).await.unwrap();
    add_entry(&v, "Mail", "m1");
    let bytes = v.save_local(nc()).await.unwrap();

    // Opened from the hash (on both entry points), edited and saved: still the password's file
    for opened in [
        Vault::open_local(bytes.clone(), hash_creds("correct horse ü"), nc()).await.unwrap(),
        c.open_local(bytes.clone(), hash_creds("correct horse ü"), nc()).await.unwrap(),
    ] {
        set_field(&opened, "Mail", "Password", "m2");
        let saved = opened.save_local(nc()).await.unwrap();
        let back = Vault::open_local(saved, creds("correct horse ü"), nc()).await.unwrap();
        assert_eq!(field(&find_title(&back, "Mail"), "Password"), b"m2");
    }

    // With a key file as well
    let kf = vec![7u8; 32];
    let both = KdbxCredentials { password: Some(b"pw".to_vec()), key_file: Some(kf.clone()), password_hash: None };
    let v2 = Vault::create_local("Two".into(), both.clone(), nc()).await.unwrap();
    let b2 = v2.save_local(nc()).await.unwrap();
    let hk = KdbxCredentials { key_file: Some(kf), ..hash_creds("pw") };
    Vault::open_local(b2.clone(), hk, nc()).await.unwrap();
    assert_eq!(
        Vault::open_local(b2, hash_creds("pw"), nc()).await.unwrap_err().code,
        OvErrorCode::VaultKeyMismatch,
        "the key file is still needed"
    );

    // Both a password and its hash, or a hash of the wrong length: invalid_request
    let mixed =
        KdbxCredentials { password: Some("correct horse ü".as_bytes().to_vec()), ..hash_creds("correct horse ü") };
    assert_eq!(Vault::open_local(bytes.clone(), mixed, nc()).await.unwrap_err().code, OvErrorCode::InvalidRequest);
    let short = KdbxCredentials { password_hash: Some(vec![0; 31]), ..Default::default() };
    assert_eq!(Vault::open_local(bytes.clone(), short, nc()).await.unwrap_err().code, OvErrorCode::InvalidRequest);
    // A wrong hash is a wrong key
    assert_eq!(
        Vault::open_local(bytes, hash_creds("nope"), nc()).await.unwrap_err().code,
        OvErrorCode::VaultKeyMismatch
    );
}

/// `Vault::open_local` and `ov_kdbx::read` agree: a wrong key is `vault_key_mismatch` (TS 0.11), a
/// damaged file `kdbx_error`.
#[tokio::test]
async fn a_wrong_key_is_a_vault_key_mismatch_everywhere() {
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    let bytes = v.save_local(nc()).await.unwrap();
    let e = Vault::open_local(bytes.clone(), creds("no"), nc()).await.unwrap_err();
    let low = ov_kdbx::read(&bytes, &ov_kdbx::vault::password_credentials(Some("no"), None)).unwrap_err();
    assert_eq!((e.code, low.code), (OvErrorCode::VaultKeyMismatch, OvErrorCode::VaultKeyMismatch));
    let e = Vault::open_local(b"not a kdbx".to_vec(), creds("pw"), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::KdbxError);
}

async fn paired(s: &ov_testkit::servers::TestServers) -> SelfHosted {
    let url = s.sync_url().trim_end_matches("/api/v1").to_owned();
    s.add_device_token("dev-1", "alice");
    SelfHosted::connect(device(s, false), url, b"dev-1".to_vec()).unwrap()
}

fn db_requests(s: &ov_testkit::servers::TestServers, method: Method) -> usize {
    s.requests().iter().filter(|r| r.method == method && r.path.contains("/databases/home")).count()
}

#[tokio::test]
async fn self_hosted_sync_checks_with_a_head_when_nothing_changed_locally() {
    let s = servers();
    let sh = paired(&s).await;
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    add_entry(&v, "Wifi", "hunter2");
    let first = sh.sync_database("home".into(), v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    assert_eq!(first.report.outcome, SyncOutcome::Created);

    // Unchanged on both sides: a HEAD, no download, the same bytes back (with the hash, no KDF needed)
    let opts = SyncOptions { local_changed: false, accept_server_state: false };
    let (gets, heads) = (db_requests(&s, Method::Get), db_requests(&s, Method::Head));
    let r = sh.sync_database_with("home".into(), first.kdbx.clone(), hash_creds("pw"), opts, nc()).await.unwrap();
    assert_eq!((r.report.outcome, r.report.attempts), (SyncOutcome::Unchanged, 0));
    assert_eq!(r.kdbx, first.kdbx);
    assert_eq!(r.report.etag, first.report.etag);
    assert_eq!((db_requests(&s, Method::Get) - gets, db_requests(&s, Method::Head) - heads), (0, 1));

    // Another device uploads: the HEAD sees it, one download, merged
    let other = Vault::open_local(first.kdbx.clone(), creds("pw"), nc()).await.unwrap();
    add_entry(&other, "Bank", "b");
    s.put_database_blob("home", &other.save_local(nc()).await.unwrap());
    let gets = db_requests(&s, Method::Get);
    let r = sh.sync_database_with("home".into(), first.kdbx.clone(), hash_creds("pw"), opts, nc()).await.unwrap();
    assert_eq!(r.report.outcome, SyncOutcome::Pulled);
    assert_eq!(db_requests(&s, Method::Get) - gets, 1);
    let merged = Vault::open_local(r.kdbx, creds("pw"), nc()).await.unwrap();
    assert_eq!(field(&find_title(&merged, "Bank"), "Password"), b"b");
    assert_eq!(field(&find_title(&merged, "Wifi"), "Password"), b"hunter2");

    // The default still downloads
    let gets = db_requests(&s, Method::Get);
    sh.sync_database("home".into(), merged.save_local(nc()).await.unwrap(), hash_creds("pw"), nc()).await.unwrap();
    assert_eq!(db_requests(&s, Method::Get) - gets, 1);
}

#[tokio::test]
async fn self_hosted_sync_accepts_the_server_state_after_a_rollback() {
    let s = servers();
    let sh = paired(&s).await;
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    add_entry(&v, "Wifi", "1");
    let r1 = sh.sync_database("home".into(), v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    let v = Vault::open_local(r1.kdbx, creds("pw"), nc()).await.unwrap();
    set_field(&v, "Wifi", "Password", "2");
    let r2 = sh.sync_database("home".into(), v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    assert_eq!(r2.report.outcome, SyncOutcome::Uploaded);
    s.rollback_database("home", 1);
    let e = sh.sync_database("home".into(), r2.kdbx.clone(), creds("pw"), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerRolledBack);
    // The HEAD path reports it too
    let check = SyncOptions { local_changed: false, accept_server_state: false };
    let e = sh.sync_database_with("home".into(), r2.kdbx.clone(), creds("pw"), check, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerRolledBack);
    let accept = SyncOptions { local_changed: true, accept_server_state: true };
    let r = sh.sync_database_with("home".into(), r2.kdbx, creds("pw"), accept, nc()).await.unwrap();
    assert_eq!(r.report.outcome, SyncOutcome::Uploaded);
    let after = sh.sync_database("home".into(), r.kdbx, creds("pw"), nc()).await.unwrap();
    assert_ne!(after.report.outcome, SyncOutcome::Uploaded);
}

/// A wrong Secret Key (the password is accepted, the keyset doesn't unwrap) and a wrong password
/// (OPAQUE refuses) are both `unauthorized` / 401, told apart by `details`; the session the server
/// opened for the accepted password is logged out.
#[tokio::test]
async fn sign_in_failures_say_which_secret_was_wrong() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    register(&alice, "alice@example.com", "pw alice").await;
    let bob = connect(&device(&s, false), &s).await;
    let bob_kit = register(&bob, "bob@example.com", "pw bob").await;

    let other = connect(&device(&s, false), &s).await;
    s.clear_requests();
    let e =
        other.login(login_input("alice@example.com", "pw alice", Some(&bob_kit.secret_key)), nc()).await.unwrap_err();
    assert_eq!((e.code, e.status), (OvErrorCode::Unauthorized, Some(401)));
    assert_eq!(e.details.as_deref(), Some(r#"{"reason":"keyset_unwrap_failed"}"#));
    let paths: Vec<(Method, String, Option<u16>)> =
        s.requests().into_iter().map(|r| (r.method, r.path, r.status)).collect();
    assert!(
        paths.iter().any(|(m, p, st)| *m == Method::Post && p.ends_with("/auth/logout") && st.is_some_and(|c| c < 300)),
        "{paths:?}"
    );
    assert!(!other.is_signed_in());

    let e = other.login(login_input("alice@example.com", "wrong", Some(&bob_kit.secret_key)), nc()).await.unwrap_err();
    assert_eq!((e.code, e.status), (OvErrorCode::Unauthorized, Some(401)));
    assert_eq!(e.details.as_deref(), Some(r#"{"reason":"opaque_refused"}"#));
    let e = other.login(login_input("nobody@example.com", "x", Some(&bob_kit.secret_key)), nc()).await.unwrap_err();
    assert_eq!(e.details.as_deref(), Some(r#"{"reason":"opaque_refused"}"#));
}
