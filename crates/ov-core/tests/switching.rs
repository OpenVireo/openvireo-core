//! SDK `switching.test.ts` (SPEC §21) against the W2-E servers.

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

#[tokio::test]
async fn comes_back_with_only_the_password_with_no_sign_in_or_totp() {
    let s = servers();
    let c = device(&s, true);
    let acct = connect(&c, &s).await;
    let alice = register(&acct, "alice@example.com", "pw").await.user_id;
    let vault = acct.create_vault("Hers".into(), None, nc()).await.unwrap();
    add_entry(&vault, "Mail", "s3cret");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    assert_eq!(c.session_state(s.issuer(), alice.clone()).await.unwrap(), SessionState::Active);

    assert!(acct.park_session().await.unwrap());
    assert!(!acct.is_signed_in() && !acct.is_unlocked());
    assert_eq!(c.session_state(s.issuer(), alice.clone()).await.unwrap(), SessionState::Parked);

    let bob = register(&acct, "bob@example.com", "bob").await.user_id;
    assert!(acct.vaults(nc()).await.unwrap().is_empty());
    acct.park_session().await.unwrap();

    s.clear_requests();
    assert!(acct.resume_session(alice.clone()).await.unwrap());
    acct.unlock(b"pw".to_vec(), None, nc()).await.unwrap();
    assert_eq!(acct.email().as_deref(), Some("alice@example.com"));
    assert!(!s.requests().iter().any(|r| r.path.contains("/auth/login")));
    let reopened = acct.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&reopened, "Mail"), "Password"), b"s3cret");
    assert_eq!(c.session_state(s.issuer(), bob).await.unwrap(), SessionState::Parked);
}

#[tokio::test]
async fn comes_back_offline_from_the_cache() {
    let s = servers();
    let c = device(&s, true);
    let acct = connect(&c, &s).await;
    let alice = register(&acct, "alice@example.com", "pw").await.user_id;
    let vault = acct.create_vault("Hers".into(), None, nc()).await.unwrap();
    add_entry(&vault, "Mail", "s3cret");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    acct.vaults(nc()).await.unwrap();
    acct.park_session().await.unwrap();

    s.set_offline(true);
    assert!(acct.resume_session(alice).await.unwrap());
    let u = acct.unlock(b"pw".to_vec(), None, nc()).await.unwrap();
    assert!(u.offline && acct.is_offline());
    let v = acct.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&v, "Mail"), "Password"), b"s3cret");
}

#[tokio::test]
async fn refuses_to_resume_over_another_open_account_and_has_nothing_to_resume_once_ended() {
    let s = servers();
    let c = device(&s, true);
    let acct = connect(&c, &s).await;
    let alice = register(&acct, "alice@example.com", "pw").await.user_id;
    acct.park_session().await.unwrap();
    register(&acct, "bob@example.com", "bob").await;
    let e = acct.resume_session(alice.clone()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerError);
    assert!(acct.resume_session(acct.user_id().unwrap()).await.unwrap());
    acct.sign_out_parked(alice.clone(), nc()).await.unwrap();
    acct.park_session().await.unwrap();
    assert!(!acct.resume_session(alice).await.unwrap());
}

#[tokio::test]
async fn checks_a_parked_session_rotates_it_ends_it_on_a_refusal_and_changes_nothing_with_no_answer() {
    let s = servers();
    let c = device(&s, true);
    let acct = connect(&c, &s).await;
    let alice = register(&acct, "alice@example.com", "pw").await.user_id;
    acct.park_session().await.unwrap();
    assert_eq!(acct.check_parked_session(alice.clone(), nc()).await.unwrap(), ParkedCheck::Valid);
    s.set_offline(true);
    assert_eq!(acct.check_parked_session(alice.clone(), nc()).await.unwrap(), ParkedCheck::NoAnswer);
    s.set_offline(false);
    s.revoke_sessions(&format!("user:{alice}"));
    assert_eq!(acct.check_parked_session(alice.clone(), nc()).await.unwrap(), ParkedCheck::Ended);
    assert_eq!(c.session_state(s.issuer(), alice).await.unwrap(), SessionState::SignedOut);
}

#[tokio::test]
async fn forgets_a_device_signed_out_refuses_the_open_account_and_leaves_others_alone() {
    let s = servers();
    let c = device(&s, true);
    let acct = connect(&c, &s).await;
    register(&acct, "alice@example.com", "pw").await;
    assert!(acct.has_secret_key("alice@example.com".into()).await.unwrap());
    let e = acct.forget_device("alice@example.com".into()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerError);
    acct.sign_out(false, nc()).await.unwrap();
    assert!(acct.has_secret_key("alice@example.com".into()).await.unwrap());
    acct.forget_device("alice@example.com".into()).await.unwrap();
    assert!(!acct.has_secret_key("alice@example.com".into()).await.unwrap());
    let e = acct.login(login_input("alice@example.com", "pw", None), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidSecretKey);
}

#[tokio::test]
async fn logs_out_on_unload_with_a_request_that_outlives_the_page() {
    let s = servers();
    let c = device(&s, false);
    let acct = connect(&c, &s).await;
    register(&acct, "alice@example.com", "pw").await;
    let req = acct.sign_out_on_unload().expect("a token in hand after sign-up");
    assert!(req.keepalive);
    assert!(!acct.is_unlocked());
    let res = s.http().send(req).await.unwrap();
    assert_eq!(res.status / 100, 2);
}
