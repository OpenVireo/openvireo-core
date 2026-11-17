//! SDK `recovery.test.ts` (SPEC §18) against the W2-E servers.

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

async fn setup() -> (ov_testkit::servers::TestServers, Account, NewAccount, String) {
    let s = servers();
    let a = connect(&device(&s, true), &s).await;
    let kit = register(&a, "alice@example.com", "old pw").await;
    let v = a.create_vault("Hers".into(), None, nc()).await.unwrap();
    add_entry(&v, "Mail", "s3cret");
    v.sync(SyncOptions::default(), nc()).await.unwrap();
    let id = v.id();
    (s, a, kit, id)
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn shows_what_the_reset_will_do_then_starts_the_account_with_new_keys() {
    let (s, a, kit, _) = setup().await;
    let old_fp = a.fingerprint().unwrap();
    let token = s.approve_reset("alice@example.com", 0);
    let info = a.recover_info(token.clone().into_bytes(), nc()).await.unwrap();
    assert_eq!((info.email.as_str(), info.personal_vaults), ("alice@example.com", 1));
    let fresh = connect(&device(&s, true), &s).await;
    let new = fresh.recover(token.into_bytes(), b"new pw".to_vec(), Some(KDF), true, nc()).await.unwrap();
    assert_ne!(new.secret_key, kit.secret_key);
    assert_eq!(new.user_id, kit.user_id);
    assert!(fresh.is_unlocked());
    assert_ne!(fresh.fingerprint().unwrap(), old_fp);
    assert!(fresh.vaults(nc()).await.unwrap().is_empty());
    let st = fresh.recovery_status(nc()).await.unwrap();
    assert!(st.archived && !st.locked);
    // The old device was signed out.
    assert_eq!(a.verify_session(nc()).await.unwrap_err().code, OvErrorCode::SignedOut);
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn surfaces_recovery_not_ready_and_recovery_cancelled() {
    let (s, a, _, _) = setup().await;
    let token = s.approve_reset("alice@example.com", 3600);
    let e = a.recover_info(token.clone().into_bytes(), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::RecoveryNotReady);
    assert!(e.details.unwrap().contains("notBefore"));
    s.cancel_reset(&token);
    assert_eq!(a.recover_info(token.into_bytes(), nc()).await.unwrap_err().code, OvErrorCode::RecoveryCancelled);
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn says_when_there_is_no_archive() {
    let (_, a, _, _) = setup().await;
    assert!(!a.recovery_status(nc()).await.unwrap().archived);
}

async fn reset(s: &ov_testkit::servers::TestServers) -> Account {
    let token = s.approve_reset("alice@example.com", 0);
    let fresh = connect(&device(s, true), s).await;
    fresh.recover(token.into_bytes(), b"new pw".to_vec(), Some(KDF), true, nc()).await.unwrap();
    fresh
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn re_seals_the_archived_vault_keys_to_the_new_keyset() {
    let (s, _, kit, vault_id) = setup().await;
    let fresh = reset(&s).await;
    let n = fresh.restore_from_archive(b"old pw".to_vec(), kit.secret_key.clone(), nc()).await.unwrap();
    assert_eq!(n, 1);
    let v = fresh.open_vault(vault_id, nc()).await.unwrap();
    assert_eq!(field(&find_title(&v, "Mail"), "Password"), b"s3cret");
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn refuses_a_wrong_old_password_with_401_and_restores_nothing() {
    let (s, _, kit, _) = setup().await;
    let fresh = reset(&s).await;
    let e = fresh.restore_from_archive(b"nope".to_vec(), kit.secret_key, nc()).await.unwrap_err();
    assert_eq!((e.code, e.status), (OvErrorCode::Unauthorized, Some(401)));
    assert!(fresh.vaults(nc()).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn fails_locally_on_a_wrong_old_secret_key_before_finish() {
    let (s, _, _, _) = setup().await;
    let fresh = reset(&s).await;
    let other = fresh.secret_key().await.unwrap().unwrap();
    let e = fresh.restore_from_archive(b"old pw".to_vec(), other, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidSecretKey);
    assert!(!s.requests().iter().any(|r| r.path.contains("/restore/finish")));
}
