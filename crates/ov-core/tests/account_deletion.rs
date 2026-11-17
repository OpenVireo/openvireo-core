//! SDK `account-deletion.test.ts` (SPEC §23) against the W2-E servers.

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

#[tokio::test]
async fn previews_schedules_signs_in_to_a_pending_account_and_restores_it() {
    let s = servers();
    let a = connect(&device(&s, true), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let v = a.create_vault("Hers".into(), None, nc()).await.unwrap();
    let p = a.deletion_preview(nc()).await.unwrap();
    assert!(p.scheduled_for.is_none() && !p.blocked);
    assert_eq!(p.vaults[0].name.as_deref(), Some("Hers"));
    assert_eq!(p.vaults[0].id, v.id());

    let e = a.delete_account(b"wrong".to_vec(), "alice@example.com".into(), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::Unauthorized);
    let at = a.delete_account(b"pw".to_vec(), "alice@example.com".into(), nc()).await.unwrap();
    assert!(!a.is_signed_in());
    // The Secret Key stays, so the user can still sign in and restore.
    assert!(a.has_secret_key("alice@example.com".into()).await.unwrap());

    let u = login(&a, "alice@example.com", "pw", None).await;
    assert_eq!(u.deletion_scheduled_for.as_deref(), Some(at.as_str()));
    assert_eq!(a.deletion_scheduled_for(), Some(at));
    a.restore_account(b"pw".to_vec(), nc()).await.unwrap();
    assert!(a.deletion_scheduled_for().is_none());
    assert_eq!(a.vaults(nc()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn refuses_a_wrong_confirmation() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let e = a.delete_account(b"pw".to_vec(), "someone@example.com".into(), nc()).await.unwrap_err();
    assert_eq!(e.wire_code(), "confirm_mismatch");
    assert!(a.is_signed_in());
}

#[tokio::test]
async fn gives_a_shared_vault_away() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let b = connect(&device(&s, false), &s).await;
    register(&b, "bob@example.com", "pw").await;
    let v = a.create_vault("Shared".into(), None, nc()).await.unwrap();
    let g = a.share_vault(v.id(), Grantee::Email("bob@example.com".into()), VaultRole::Write, nc()).await.unwrap();
    a.transfer_vault(v.id(), g.principal, nc()).await.unwrap();
    assert!(a.vaults(nc()).await.unwrap().is_empty());
    b.verify_session(nc()).await.unwrap();
    let bv = b.vaults(nc()).await.unwrap();
    assert_eq!((bv[0].name.as_str(), bv[0].role), ("Shared", VaultRole::Manage));
}
