//! SDK `account.test.ts` (sign-in, TOTP, settings, orgs) against the W2-E servers.

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn register_vault_second_device_share_and_service_account() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    let kit = register(&a, "alice@example.com", "pw").await;
    assert_eq!(kit.emergency_kit.email, "alice@example.com");
    let vault = a.create_vault("Personal".into(), None, nc()).await.unwrap();
    add_entry(&vault, "GitHub", "gh-pass");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();

    // Second device: needs the Secret Key the first time.
    let a2 = connect(&device(&s, false), &s).await;
    let e = a2.login(login_input("alice@example.com", "pw", None), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidSecretKey);
    login(&a2, "alice@example.com", "pw", Some(&kit.secret_key)).await;
    let names: Vec<String> = a2.vaults(nc()).await.unwrap().into_iter().map(|v| v.name).collect();
    assert_eq!(names, ["Personal"]);
    let v2 = a2.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&v2, "GitHub"), "Password"), b"gh-pass");

    // Share with Bob.
    let b = connect(&device(&s, false), &s).await;
    register(&b, "bob@example.com", "pw2").await;
    let g = a.share_vault(vault.id(), Grantee::Email("bob@example.com".into()), VaultRole::Read, nc()).await.unwrap();
    assert_eq!(g.fingerprint, b.fingerprint().unwrap());
    b.verify_session(nc()).await.unwrap();
    let bv = b.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&bv, "GitHub"), "Password"), b"gh-pass");
    let members = a.members(vault.id(), nc()).await.unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|m| m.is_you && m.role == VaultRole::Manage));
}

#[tokio::test]
async fn a_wrong_password_is_unauthorized() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    let kit = register(&a, "alice@example.com", "pw").await;
    let a2 = connect(&device(&s, false), &s).await;
    let e = a2.login(login_input("alice@example.com", "nope", Some(&kit.secret_key)), nc()).await.unwrap_err();
    assert_eq!((e.code, e.status), (OvErrorCode::Unauthorized, Some(401)));
}

async fn with_totp(s: &ov_testkit::servers::TestServers) -> (Account, Vec<u8>) {
    let a = connect(&device(s, false), s).await;
    let kit = register(&a, "alice@example.com", "pw").await;
    let setup = a.start_two_step(nc()).await.unwrap();
    assert!(String::from_utf8(setup.uri).unwrap().starts_with("otpauth://totp/"));
    a.confirm_two_step(s.totp_now("alice@example.com").unwrap(), nc()).await.unwrap();
    (a, kit.secret_key)
}

#[tokio::test]
async fn asks_again_after_a_wrong_code_with_the_invalid_mfa_error() {
    let s = servers();
    let (_, sk) = with_totp(&s).await;
    let a2 = connect(&device(&s, false), &s).await;
    let LoginStep::NeedsTotp(ch) = a2.login(login_input("alice@example.com", "pw", Some(&sk)), nc()).await.unwrap()
    else {
        panic!("expected a TOTP challenge")
    };
    assert_eq!(ch.attempt(), 1);
    let e = a2.submit_totp(ch.clone(), "000000".into(), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidMfa);
    assert_eq!(ch.attempt(), 2);
    assert_eq!(ch.last_error().unwrap().code, OvErrorCode::InvalidMfa);
    let step = a2.submit_totp(ch, s.totp_now("alice@example.com").unwrap(), nc()).await.unwrap();
    assert!(matches!(step, LoginStep::Unlocked(_)));
    assert!(a2.is_unlocked());
}

#[tokio::test]
async fn fails_at_once_with_a_fixed_wrong_code() {
    let s = servers();
    let (_, sk) = with_totp(&s).await;
    let a2 = connect(&device(&s, false), &s).await;
    let mut input = login_input("alice@example.com", "pw", Some(&sk));
    input.totp = Some("000000".into());
    assert_eq!(a2.login(input, nc()).await.unwrap_err().code, OvErrorCode::InvalidMfa);
}

#[tokio::test]
async fn ends_the_login_once_the_server_drops_the_token_after_the_5th_wrong_code() {
    let s = servers();
    let (_, sk) = with_totp(&s).await;
    let a2 = connect(&device(&s, false), &s).await;
    let LoginStep::NeedsTotp(ch) = a2.login(login_input("alice@example.com", "pw", Some(&sk)), nc()).await.unwrap()
    else {
        panic!()
    };
    // As in the SDK test (`asked` is 6): the 5th wrong code is still invalid_mfa and drops the
    // token, so the 6th attempt is the one that fails with mfa_expired.
    for _ in 0..5 {
        let e = a2.submit_totp(ch.clone(), "000000".into(), nc()).await.unwrap_err();
        assert_eq!(e.code, OvErrorCode::InvalidMfa);
    }
    let e = a2.submit_totp(ch.clone(), "000000".into(), nc()).await.unwrap_err();
    assert_eq!((e.code, e.status), (OvErrorCode::MfaExpired, Some(401)));
}

#[tokio::test]
#[ignore = "BUG: ov-core impls/sync_glue.rs is still the pre-ov-sync stub (AVAILABLE = false, \"needs ov-sync\")"]
async fn changes_the_password_same_keys_and_secret_key_vaults_still_open() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    let kit = register(&a, "alice@example.com", "old").await;
    let fp = a.fingerprint().unwrap();
    let vault = a.create_vault("V".into(), None, nc()).await.unwrap();
    add_entry(&vault, "E", "x");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    let e = a.change_password(b"wrong".to_vec(), b"new".to_vec(), Some(KDF), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::Unauthorized);
    a.change_password(b"old".to_vec(), b"new".to_vec(), Some(KDF), nc()).await.unwrap();

    let a2 = connect(&device(&s, false), &s).await;
    let e = a2.login(login_input("alice@example.com", "old", Some(&kit.secret_key)), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::Unauthorized);
    login(&a2, "alice@example.com", "new", Some(&kit.secret_key)).await;
    assert_eq!(a2.fingerprint().unwrap(), fp);
    let v = a2.open_vault(vault.id(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&v, "E"), "Password"), b"x");
}

#[tokio::test]
async fn changes_the_email_the_new_one_signs_in_keys_and_vaults_stay() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    let kit = register(&a, "alice@example.com", "pw").await;
    a.request_email_change("alice2@example.com".into(), nc()).await.unwrap();
    let code = s.email_code(&kit.user_id).unwrap();
    a.change_email("alice2@example.com".into(), code, b"pw".to_vec(), nc()).await.unwrap();
    assert_eq!(a.email().as_deref(), Some("alice2@example.com"));
    assert!(a.has_secret_key("alice2@example.com".into()).await.unwrap());
    assert!(!a.has_secret_key("alice@example.com".into()).await.unwrap());
    let a2 = connect(&device(&s, false), &s).await;
    login(&a2, "alice2@example.com", "pw", Some(&kit.secret_key)).await;
}

#[tokio::test]
async fn makes_a_one_time_link_to_the_auth_website() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let url = String::from_utf8(a.web_session_url(Some("/settings".into()), nc()).await.unwrap()).unwrap();
    assert!(url.starts_with(&format!("{}/session/claim?code=", s.issuer())), "{url}");
    assert!(url.ends_with("&next=%2Fsettings"));
}

#[tokio::test]
async fn only_gives_the_secret_key_while_unlocked() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    let kit = register(&a, "alice@example.com", "pw").await;
    assert_eq!(a.secret_key().await.unwrap().unwrap(), kit.secret_key);
    a.lock();
    assert_eq!(a.secret_key().await.unwrap_err().code, OvErrorCode::SignedOut);
}

#[tokio::test]
async fn orgs_invite_accept_and_confirm_a_member_without_vaults() {
    let s = servers();
    let owner = connect(&device(&s, false), &s).await;
    register(&owner, "owner@example.com", "pw").await;
    let org = owner.create_org("Acme".into(), nc()).await.unwrap();
    assert_eq!(org.role, OrgRole::Owner);
    let member = connect(&device(&s, false), &s).await;
    register(&member, "m@example.com", "pw").await;
    owner.invite(org.id.clone(), "m@example.com".into(), OrgRole::Member, nc()).await.unwrap();
    let token = s.invitation_token(&org.id, "m@example.com").unwrap();
    member.accept_invitation(token.into_bytes(), nc()).await.unwrap();
    let pending = owner
        .org_members(org.id.clone(), nc())
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == "m@example.com")
        .unwrap();
    assert_eq!(pending.status, MemberStatus::Accepted);
    let confirmed = owner.confirm_member(org.id.clone(), pending, vec![], nc()).await.unwrap();
    assert_eq!(confirmed.status, MemberStatus::Confirmed);
    assert_eq!(member.orgs(nc()).await.unwrap()[0].name, "Acme");
}

#[tokio::test]
async fn self_hosted_pairs_with_a_code_and_lists_databases() {
    let s = servers();
    let c = device(&s, false);
    // A device token for the first device, then pairing a second one.
    let first = SelfHosted::connect(c.clone(), s.sync_url().trim_end_matches("/api/v1").into(), {
        s.add_device_token("u1", "alice");
        b"u1".to_vec()
    })
    .unwrap();
    let code = first.create_pairing_code(nc()).await.unwrap();
    let second = SelfHosted::pair(c.clone(), first.server_url(), code.code, "laptop".into(), nc()).await.unwrap();
    assert!(second.list_databases(nc()).await.unwrap().is_empty());
    let again = SelfHosted::restore(c, first.server_url()).await.unwrap();
    assert!(again.is_some());
}
