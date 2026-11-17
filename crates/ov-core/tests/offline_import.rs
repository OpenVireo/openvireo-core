//! SDK `offline-import.test.ts` (Move to account, offline vaults, SPEC §20) against the W2-E servers.

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

fn local_creds() -> KdbxCredentials {
    KdbxCredentials { password: Some(b"local".to_vec()), key_file: None }
}

async fn local_db() -> Vault {
    let v = Vault::create_local("My Passwords".into(), local_creds(), nc()).await.unwrap();
    add_entry(&v, "Bank", "1234");
    v
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn re_keys_a_copy_to_a_fresh_vault_key_and_uploads_it_leaving_the_original() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let local = local_db().await;
    let before = local.save_local(nc()).await.unwrap();
    let out = a.import_vault(local.clone(), ImportMode::NewVault { name: None, org_id: None }, nc()).await.unwrap();
    assert!(out.uploaded, "{:?}", out.upload_error);
    assert_eq!(out.vault.name(), "My Passwords");
    assert!(s.requests().iter().any(|r| r.method == ov_core::host::Method::Put && r.path.contains("/vaults/")));
    // The original still opens with its password.
    Vault::open_local(before, local_creds(), nc()).await.unwrap();
    let again = a.open_vault(out.vault.id(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&again, "Bank"), "Password"), b"1234");
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn returns_the_created_vault_with_the_error_when_the_first_upload_fails() {
    use ov_testkit::servers::{Fault, FaultRule, Server};
    let s = servers();
    let a = connect(&device(&s, true), &s).await;
    register(&a, "alice@example.com", "pw").await;
    s.fail_next(
        FaultRule::new(Fault::Status(503))
            .server(Server::Sync)
            .method(ov_core::host::Method::Put)
            .path("/vaults/")
            .times(3),
    );
    let out = a
        .import_vault(local_db().await, ImportMode::NewVault { name: Some("Named".into()), org_id: None }, nc())
        .await
        .unwrap();
    assert!(!out.uploaded);
    assert_eq!(out.upload_error.unwrap().code, OvErrorCode::VaultUploadFailed);
    assert!(out.vault.has_pending_edits().await.unwrap());
    s.clear_faults();
    out.vault.sync(SyncOptions::default(), nc()).await.unwrap();
    assert!(!out.vault.has_pending_edits().await.unwrap());
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn unlocks_and_opens_synced_vaults_without_the_network() {
    let s = servers();
    let c = device(&s, true);
    let a = connect(&c, &s).await;
    register(&a, "alice@example.com", "pw").await;
    let v = a.create_vault("Hers".into(), None, nc()).await.unwrap();
    add_entry(&v, "Mail", "s3cret");
    v.sync(SyncOptions::default(), nc()).await.unwrap();
    a.lock();

    s.set_offline(true);
    let u = a.unlock(b"pw".to_vec(), None, nc()).await.unwrap();
    assert!(u.offline);
    assert_eq!(a.vaults(nc()).await.unwrap()[0].name, "Hers");
    let off = a.open_vault(v.id(), nc()).await.unwrap();
    assert!(off.is_offline());
    add_entry(&off, "New", "n");
    assert_eq!(off.sync(SyncOptions::default(), nc()).await.unwrap_err().code, OvErrorCode::NetworkError);
    assert!(a.has_pending_edits(v.id()).await.unwrap());
    assert!(c.has_pending_edits(a.user_id().unwrap()).await.unwrap());

    s.set_offline(false);
    a.reconnect(nc()).await.unwrap();
    off.sync(SyncOptions::default(), nc()).await.unwrap();
    assert!(!a.has_pending_edits(v.id()).await.unwrap());
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn cant_open_a_vault_offline_that_was_never_synced_on_this_device() {
    let s = servers();
    let a = connect(&device(&s, true), &s).await;
    let kit = register(&a, "alice@example.com", "pw").await;
    let v = a.create_vault("Hers".into(), None, nc()).await.unwrap();
    let other = connect(&device(&s, true), &s).await;
    login(&other, "alice@example.com", "pw", Some(&kit.secret_key)).await;
    other.vaults(nc()).await.unwrap();
    s.set_offline(true);
    assert_eq!(other.open_vault(v.id(), nc()).await.unwrap_err().code, OvErrorCode::NotAvailableOffline);
}

#[tokio::test]
async fn forgets_the_offline_cache_on_sign_out() {
    let s = servers();
    let a = connect(&device(&s, true), &s).await;
    register(&a, "alice@example.com", "pw").await;
    a.vaults(nc()).await.unwrap();
    assert!(a.cached_kdf().await.unwrap().is_some());
    a.sign_out(false, nc()).await.unwrap();
    assert!(a.cached_kdf().await.unwrap().is_none());
}

#[tokio::test]
async fn keeps_no_offline_cache_unless_asked_to() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    a.lock();
    s.set_offline(true);
    assert_eq!(a.unlock(b"pw".to_vec(), None, nc()).await.unwrap_err().code, OvErrorCode::NetworkError);
}
