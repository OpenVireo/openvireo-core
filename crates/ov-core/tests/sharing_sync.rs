//! The SDK `account.test.ts` cases that need ov-vault and ov-sync: share → revoke + rotate →
//! service account, HEAD-skip sync, org confirm → promote → remove and rotate, self-hosted database
//! sync, and the event stream, against the W2-E servers.

mod servers_common;

use ov_core::api::*;
use ov_core::host::Method;
use ov_core::OvErrorCode;
use servers_common::*;

fn set_field(v: &Vault, title: &str, field_name: &str, value: &str) {
    let id = find_title(v, title).id;
    v.edit_entry(
        id,
        EntryInput {
            fields: vec![FieldInput { name: field_name.into(), value: value.as_bytes().to_vec(), protected: None }],
            ..Default::default()
        },
    )
    .unwrap();
}

#[tokio::test]
async fn share_revoke_rotate_and_a_service_account() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    let kit = register(&alice, "alice@example.com", "correct horse ü").await;
    let vault = alice.create_vault("Team Infra".into(), None, nc()).await.unwrap();
    add_entry(&vault, "GitHub", "s3cret");
    set_field(&vault, "GitHub", "username", "ci");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    assert_eq!(vault.read_field("ov://Team%20Infra/GitHub/password".into()).unwrap(), b"s3cret");

    // Second device.
    let alice2 = connect(&device(&s, false), &s).await;
    login(&alice2, "alice@example.com", "correct horse ü", Some(&kit.secret_key)).await;
    let v2 = alice2.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(v2.read_field("ov://Team%20Infra/GitHub/password".into()).unwrap(), b"s3cret");

    // Share with Bob, who reads it.
    let bob = connect(&device(&s, false), &s).await;
    register(&bob, "bob@example.com", "bob pw").await;
    let shared =
        alice.share_vault(vault.id(), Grantee::Email("bob@example.com".into()), VaultRole::Read, nc()).await.unwrap();
    assert_eq!(shared.fingerprint, bob.fingerprint().unwrap());
    let bv = bob.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(bv.read_field("ov://x/GitHub/username".into()).unwrap(), b"ci");

    // Revoke → rotation: Bob loses access; the blob is re-keyed; the other device follows.
    let bob_principal = bob.principal().unwrap();
    alice.revoke(vault.id(), vec![bob_principal], nc()).await.unwrap();
    let info = alice.vaults(nc()).await.unwrap().into_iter().find(|v| v.id == vault.id()).unwrap();
    assert_eq!((info.current_key_version, info.pending_key_version, info.name.as_str()), (2, None, "Team Infra"));
    assert!(alice.members(vault.id(), nc()).await.unwrap().iter().all(|m| m.principal != shared.principal));
    bob.verify_session(nc()).await.unwrap();
    assert!(bob.vaults(nc()).await.unwrap().is_empty());
    assert!(bv.sync(SyncOptions::default(), nc()).await.is_err(), "Bob's old key no longer syncs");
    alice2.vaults(nc()).await.unwrap();
    let again = alice2.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(again.read_field("ov://x/GitHub/password".into()).unwrap(), b"s3cret");
    assert_eq!(alice2.vaults(nc()).await.unwrap()[0].name, "Team Infra");

    // A service account in an org, with write access.
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let created = alice
        .create_service_account(
            org.id.clone(),
            NewServiceAccount {
                name: "ci".into(),
                vaults: vec![VaultGrantRequest { vault_id: vault.id(), role: VaultRole::Write }],
                expires_at: None,
                secret_name: None,
            },
            nc(),
        )
        .await
        .unwrap();
    assert!(created.token.starts_with(b"ov_sa_"));
    let sa = ServiceAccount::from_token(device(&s, false), created.token.clone(), nc()).await.unwrap();
    assert_eq!(sa.read(format!("ov://{}/GitHub/password", vault.id()), nc()).await.unwrap(), b"s3cret");
    let inj = sa.inject(b"TOKEN=ov://Team%20Infra/GitHub/password\n".to_vec(), nc()).await.unwrap();
    assert_eq!(inj.text, b"TOKEN=s3cret\n");
    assert_eq!(inj.secrets, vec![b"s3cret".to_vec()]);
    sa.write("ov://Team%20Infra/GitHub/password".into(), b"rotated-by-ci".to_vec(), false, nc()).await.unwrap();
    again.sync(SyncOptions::default(), nc()).await.unwrap();
    assert_eq!(again.read_field("ov://x/GitHub/password".into()).unwrap(), b"rotated-by-ci");

    // A second secret, issued by an admin who doesn't have the first.
    let second = alice.issue_service_account_secret(sa.sa_id(), None, None, nc()).await.unwrap();
    let sa2 = ServiceAccount::from_token(device(&s, false), second.token, nc()).await.unwrap();
    assert_eq!(sa2.read("ov://Team%20Infra/GitHub/password".into(), nc()).await.unwrap(), b"rotated-by-ci");
    sa.close();
    sa2.close();
    assert_eq!(
        sa.read("ov://Team%20Infra/GitHub/password".into(), nc()).await.unwrap_err().code,
        OvErrorCode::SignedOut
    );

    alice.sign_out(false, nc()).await.unwrap();
    assert!(!alice.is_signed_in());
}

#[tokio::test]
async fn a_read_only_service_account_cant_write() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    register(&alice, "alice@example.com", "pw").await;
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let vault = alice.create_vault("Infra".into(), Some(org.id.clone()), nc()).await.unwrap();
    add_entry(&vault, "DB", "pw1");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    let input = NewServiceAccount {
        name: "reader".into(),
        vaults: vec![VaultGrantRequest { vault_id: vault.id(), role: VaultRole::Read }],
        expires_at: None,
        secret_name: None,
    };
    let created = alice.create_service_account(org.id.clone(), input, nc()).await.unwrap();
    let sa = ServiceAccount::from_token(device(&s, false), created.token, nc()).await.unwrap();
    assert_eq!(sa.vaults(false, nc()).await.unwrap()[0].role, VaultRole::Read);
    let e = sa.write("ov://Infra/DB/password".into(), b"x".to_vec(), false, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::Forbidden);
    let e = sa.read("ov://Nope/DB/password".into(), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::NotFound);
}

#[tokio::test]
async fn checks_with_a_head_and_skips_the_download_when_the_etag_still_matches() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    let kit = register(&alice, "alice@example.com", "pw").await;
    let vault = alice.create_vault("Infra".into(), None, nc()).await.unwrap();
    assert!(vault.etag().is_some_and(|e| !e.is_empty()));
    let sync_methods = |from: usize| -> Vec<Method> {
        s.requests()[from..].iter().filter(|r| r.path.contains("/vaults/")).map(|r| r.method).collect()
    };
    let before = s.requests().len();
    let r = vault.sync(SyncOptions { local_changed: false, ..Default::default() }, nc()).await.unwrap();
    assert_eq!(r.outcome, SyncOutcome::Unchanged);
    assert_eq!(sync_methods(before), vec![Method::Head]);

    // Another device changed it: the HEAD misses, so it downloads, and a pull doesn't upload.
    let other = connect(&device(&s, false), &s).await;
    login(&other, "alice@example.com", "pw", Some(&kit.secret_key)).await;
    let theirs = other.open_vault(vault.id(), nc()).await.unwrap();
    add_entry(&theirs, "New", "x");
    theirs.sync(SyncOptions::default(), nc()).await.unwrap();
    let mark = s.requests().len();
    vault.sync(SyncOptions { local_changed: false, ..Default::default() }, nc()).await.unwrap();
    let m = sync_methods(mark);
    assert!(m.contains(&Method::Get) && !m.contains(&Method::Put), "{m:?}");
    assert_eq!(vault.etag(), theirs.etag());
    assert_eq!(field(&find_title(&vault, "New"), "Password"), b"x");
    let mark2 = s.requests().len();
    let outcome = vault.sync(SyncOptions::default(), nc()).await.unwrap().outcome;
    assert!(matches!(outcome, SyncOutcome::Pulled | SyncOutcome::Unchanged), "{outcome:?}");
    let outcome = theirs.sync(SyncOptions::default(), nc()).await.unwrap().outcome;
    assert!(matches!(outcome, SyncOutcome::Pulled | SyncOutcome::Unchanged), "{outcome:?}");
    assert!(!sync_methods(mark2).contains(&Method::Put));
}

#[tokio::test]
async fn confirm_with_chosen_vaults_then_promote_to_admin_then_remove_and_rotate() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    register(&alice, "alice@example.com", "pw").await;
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let infra = alice.create_vault("Infra".into(), Some(org.id.clone()), nc()).await.unwrap();
    add_entry(&infra, "GitHub", "s3cret");
    infra.sync(SyncOptions::default(), nc()).await.unwrap();
    let payroll = alice.create_vault("Payroll".into(), Some(org.id.clone()), nc()).await.unwrap();
    let sa = alice
        .create_service_account(
            org.id.clone(),
            NewServiceAccount { name: "ci".into(), vaults: vec![], expires_at: None, secret_name: None },
            nc(),
        )
        .await
        .unwrap()
        .service_account;

    let bob = connect(&device(&s, false), &s).await;
    register(&bob, "bob@example.com", "bob pw").await;
    assert!(s.add_member(&org.id, "bob@example.com", "member"));
    let pending = alice
        .org_members(org.id.clone(), nc())
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == "bob@example.com")
        .unwrap();
    assert_eq!(pending.status, MemberStatus::Accepted);

    // A member gets only the vaults picked for them, and no SA master keys.
    let confirmed = alice
        .confirm_member(
            org.id.clone(),
            pending,
            vec![VaultGrantRequest { vault_id: infra.id(), role: VaultRole::Read }],
            nc(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed.status, MemberStatus::Confirmed);
    bob.verify_session(nc()).await.unwrap();
    let listed: Vec<(String, VaultRole)> =
        bob.vaults(nc()).await.unwrap().into_iter().map(|v| (v.name, v.role)).collect();
    assert_eq!(listed, vec![("Infra".to_owned(), VaultRole::Read)]);
    let bv = bob.open_vault(infra.id(), nc()).await.unwrap();
    assert_eq!(bv.read_field("ov://Infra/GitHub/password".into()).unwrap(), b"s3cret");
    let e = bob.issue_service_account_secret(sa.id.clone(), None, None, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::Forbidden);

    // Promotion: manage on every org vault, and the SA master key.
    alice.set_member_role(org.id.clone(), confirmed.clone(), OrgRole::Admin, nc()).await.unwrap();
    bob.verify_session(nc()).await.unwrap();
    let mut listed: Vec<(String, VaultRole)> =
        bob.vaults(nc()).await.unwrap().into_iter().map(|v| (v.name, v.role)).collect();
    listed.sort();
    assert_eq!(listed, vec![("Infra".to_owned(), VaultRole::Manage), ("Payroll".to_owned(), VaultRole::Manage)]);
    let issued = bob.issue_service_account_secret(sa.id.clone(), None, None, nc()).await.unwrap();
    assert!(issued.token.starts_with(b"ov_sa_"));

    // Removal: access goes at once, and both vault keys rotate.
    let report = alice.remove_member(org.id.clone(), confirmed.user_id.clone(), nc()).await.unwrap();
    let mut rotated = report.rotated.clone();
    rotated.sort();
    let mut expected = vec![infra.id(), payroll.id()];
    expected.sort();
    assert_eq!((rotated, report.failed.len()), (expected, 0), "{:?}", report.failed);
    bob.verify_session(nc()).await.unwrap();
    assert!(bob.vaults(nc()).await.unwrap().is_empty());
    let info = alice.vaults(nc()).await.unwrap().into_iter().find(|v| v.id == infra.id()).unwrap();
    assert_eq!(info.current_key_version, 2);
    let reopened = alice.open_vault(infra.id(), nc()).await.unwrap();
    assert_eq!(reopened.read_field("ov://Infra/GitHub/password".into()).unwrap(), b"s3cret");
}

#[tokio::test]
async fn refuses_a_vault_from_another_org() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    register(&alice, "alice@example.com", "pw").await;
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let personal = alice.create_vault("Personal".into(), None, nc()).await.unwrap();
    let bob = connect(&device(&s, false), &s).await;
    register(&bob, "bob@example.com", "bob pw").await;
    assert!(s.add_member(&org.id, "bob@example.com", "member"));
    let m = alice
        .org_members(org.id.clone(), nc())
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == "bob@example.com")
        .unwrap();
    let e = alice
        .confirm_member(
            org.id.clone(),
            m,
            vec![VaultGrantRequest { vault_id: personal.id(), role: VaultRole::Read }],
            nc(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidRequest);
}

#[tokio::test]
async fn writes_by_reference_and_sets_item_fields() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    register(&alice, "alice@example.com", "pw").await;
    let vault = alice.create_vault("Infra".into(), None, nc()).await.unwrap();
    vault.write_field("ov://Infra/Servers/DB/password".into(), b"pw1".to_vec(), true, nc()).await.unwrap();
    let found = vault.find("ov://Infra/Servers/DB".into()).unwrap();
    assert_eq!((found.group_path.clone(), field(&found, "Password")), (vec!["Servers".to_owned()], b"pw1".as_slice()));
    let r = vault
        .set_fields(
            "ov://Infra/Servers/DB".into(),
            vec![FieldInput { name: "username".into(), value: b"admin".to_vec(), protected: None }],
            CreateMode::MustExist,
        )
        .unwrap();
    assert!(!r.created);
    assert_eq!(field(&r.entry, "UserName"), b"admin");
    let e = vault.read_field("ov://Infra/Nope/password".into()).unwrap_err();
    assert_eq!(e.code, OvErrorCode::EntryNotFound);
    let e = vault.read_field("not a reference".into()).unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidReference);
}

#[tokio::test]
async fn pairs_and_syncs_a_password_database_through_databases() {
    let s = servers();
    let c = device(&s, false);
    let url = s.sync_url().trim_end_matches("/api/v1").to_owned();
    s.add_device_token("dev-1", "alice");
    let first = SelfHosted::connect(c.clone(), url.clone(), b"dev-1".to_vec()).unwrap();
    let code = first.create_pairing_code(nc()).await.unwrap();
    let sh = SelfHosted::pair(c.clone(), url.clone(), code.code, "Web".into(), nc()).await.unwrap();
    let creds = KdbxCredentials { password: Some(b"pw".to_vec()), key_file: None };
    let local = Vault::create_local("Home".into(), creds.clone(), nc()).await.unwrap();
    add_entry(&local, "Wifi", "hunter2");
    let bytes = local.save_local(nc()).await.unwrap();
    let r = sh.sync_database("home".into(), bytes, creds.clone(), nc()).await.unwrap();
    assert_eq!(r.report.outcome, SyncOutcome::Created);
    let restored = SelfHosted::restore(c, format!("{url}/")).await.unwrap().unwrap();
    let ids: Vec<String> = restored.list_databases(nc()).await.unwrap().into_iter().map(|d| d.id).collect();
    assert_eq!(ids, vec!["home".to_owned()]);
    let merged = Vault::open_local(r.kdbx, creds.clone(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&merged, "Wifi"), "Password"), b"hunter2");
    // Nothing changed: the next sync uploads nothing.
    let again = sh.sync_database("home".into(), merged.save_local(nc()).await.unwrap(), creds, nc()).await.unwrap();
    assert!(matches!(again.report.outcome, SyncOutcome::Unchanged | SyncOutcome::Pulled), "{:?}", again.report.outcome);
}

#[tokio::test]
async fn the_event_stream_reports_a_vault_change() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    let kit = register(&alice, "alice@example.com", "pw").await;
    let vault = alice.create_vault("Infra".into(), None, nc()).await.unwrap();
    let stream = alice.subscribe(nc()).await.unwrap();
    let other = connect(&device(&s, false), &s).await;
    login(&other, "alice@example.com", "pw", Some(&kit.secret_key)).await;
    let theirs = other.open_vault(vault.id(), nc()).await.unwrap();
    // The stream connects on the first poll (join polls it first); then the other device uploads.
    let change = async {
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        add_entry(&theirs, "New", "x");
        theirs.sync(SyncOptions::default(), nc()).await.unwrap();
    };
    let (ev, ()) = tokio::join!(stream.next(nc()), change);
    let ev = ev.unwrap();
    match ev {
        Some(AccountEvent::VaultChanged { vault_id, etag, deleted, .. }) => {
            assert_eq!(vault_id, vault.id());
            assert!(!deleted);
            assert_eq!(etag, theirs.etag());
        }
        other => panic!("unexpected {other:?}"),
    }
    stream.close();
    assert_eq!(stream.next(nc()).await.unwrap(), None);
}
