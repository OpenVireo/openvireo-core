//! Ports of the SDK's `test/service-account.test.ts` (item references and helpers, the read-grant
//! refusal) and the service-account part of `account.test.ts` (create → token → exchange → read
//! and write by reference → a second secret issued by an admin), on the pure ov-vault API.
//!
//! The rest of `service-account.test.ts` (412 merge/retry, HEAD-before-GET pulls, serialised
//! concurrent edits, dropping the cache after a rejected upload) is sync and facade behaviour,
//! ported by W2-Y/W2-A.

mod common;

use common::*;
use ov_crypto::tokens::{parse_sa_token, unwrap_sa_master};
use ov_error::OvErrorCode;
use ov_protocol::types::{MemberStatus, OrgRole, VaultRole};
use ov_vault::items::{find_item, list_items, set_item_fields, CreateMode, FieldUpdate, ItemValues};
use ov_vault::keys::sa_principal;
use ov_vault::service_account::*;
use ov_vault::{
    find_entry, inject, parse_item_reference, parse_reference, read_field, write_field, ItemReference, Keyring,
    VaultKeys,
};
use zeroize::Zeroizing;

fn item_ref(group: &[&str], entry: &str) -> ItemReference {
    ItemReference { vault: "Team Infra".into(), group_path: group.iter().map(|s| s.to_string()).collect(), entry: entry.into() }
}

fn update(name: &str, value: &str) -> FieldUpdate {
    FieldUpdate { name: name.into(), value: Zeroizing::new(value.into()), protected: None }
}

#[test]
fn parses_item_references() {
    let r = parse_item_reference("ov://Team%20Infra/GitHub").unwrap();
    assert_eq!((r.vault.as_str(), r.group_path.is_empty(), r.entry.as_str()), ("Team Infra", true, "GitHub"));
    let r = parse_item_reference("ov://v/a/b%2Fc/Entry").unwrap();
    assert_eq!((r.vault.as_str(), r.group_path.clone(), r.entry.as_str()), ("v", vec!["a".to_owned(), "b/c".to_owned()], "Entry"));
    for bad in ["ov://v", "ov://v//e", "https://v/e", "ov://v/%zz"] {
        let e = parse_item_reference(bad).unwrap_err();
        assert!(e.is(OvErrorCode::InvalidReference), "{bad}");
        assert!(["reference", "encoding", "expected"].iter().any(|w| e.message.contains(w)), "{bad}: {}", e.message);
    }
}

/// alice, an org with the SA, and "Team Infra" holding GitHub (root) and Database (in Deploy).
struct World {
    server: Server,
    alice: User,
    vault: VaultKeys,
    read_token: Zeroizing<String>,
    write_token: Zeroizing<String>,
}

fn world() -> World {
    let mut server = Server::default();
    let alice = User::new("alice");
    server.register(&alice);
    server.create_org("acme", &alice);
    let nv = ov_vault::new_vault("Team Infra", &alice.principal(), &alice.keyset, Some(("acme", &server.members["acme"]))).unwrap();
    let created = server.create_vault(&alice.principal(), &nv.request).unwrap();
    let vault = VaultKeys::from_vault(&nv.listing(created), &alice.keyset);
    let (mut db, ck) = ov_kdbx::vault::create_vault_kdbx("Team Infra", &nv.key[..], NOW).unwrap();
    entry(&mut db, "GitHub", "ci", "s3cret");
    let root = db.root.uuid;
    let deploy = ov_kdbx::entries::create_group(&mut db, root, "Deploy", NOW).unwrap();
    let data = ov_kdbx::entries::EntryData { title: "Database".into(), ..Default::default() };
    ov_kdbx::entries::add_entry(&mut db, deploy, &data, NOW).unwrap();
    server.blobs.insert(nv.id.clone(), ov_kdbx::write(&db, &ck).unwrap());

    let mut tokens = Vec::new();
    for (name, role) in [("reader", VaultRole::Read), ("writer", VaultRole::Write)] {
        let sa = new_service_account(ISSUER, &alice.principal(), &alice.keyset, &server.members["acme"], &ServiceAccountSpec {
            name: name.into(),
            ..Default::default()
        })
        .unwrap();
        server.create_sa("acme", &sa.request);
        let g = sa.vault_grant(&vault, role).unwrap();
        server.grant_access(&alice.principal(), vault.id(), &[g]).unwrap();
        tokens.push(sa.token);
    }
    let write_token = tokens.pop().unwrap();
    let read_token = tokens.pop().unwrap();
    World { server, alice, vault, read_token, write_token }
}

/// The SA side: token → exchange → keyset → vault list.
fn sa_login(server: &Server, token: &str) -> (Keyring, String) {
    let t = parse_sa_token(token).unwrap();
    let ex = server.exchange(&exchange_request(&t)).unwrap();
    let ks = unlock_service_account(&t, &ex).unwrap();
    let mut keyring = Keyring::new();
    keyring.ingest_list(&server.list_vaults(&sa_principal(&t.sa_id)), &ks);
    (keyring, t.sa_id.clone())
}

fn sa_read(server: &Server, keyring: &Keyring, reference: &str) -> Zeroizing<String> {
    let r = parse_reference(reference).unwrap();
    let v = find_vault(keyring.iter(), &r.vault).unwrap();
    read_field(&open(server, v).unwrap(), &r).unwrap()
}

#[test]
fn lists_reads_and_sets_whole_items() {
    let w = world();
    let (keyring, _) = sa_login(&w.server, &w.read_token);
    let v = find_vault(keyring.iter(), "Team Infra").unwrap();
    let mut db = open(&w.server, v).unwrap();

    let items = list_items(&db);
    let mut pairs: Vec<_> = items.iter().map(|i| (i.title.clone(), i.group.join("/"))).collect();
    pairs.sort();
    assert_eq!(pairs, [("Database".to_owned(), "Deploy".to_owned()), ("GitHub".to_owned(), String::new())]);
    assert!(items[0].fields.is_empty());

    let gh = find_item(&db, &item_ref(&[], "GitHub"), ItemValues::Unprotected).unwrap();
    assert_eq!((gh.field("Title"), gh.field("UserName")), (Some("GitHub"), Some("ci")));
    assert_eq!(gh.field("Password"), None);
    assert!(gh.protected.contains(&"Password".to_owned()));
    assert!(gh.id.len() == 32 && gh.id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert!(gh.updated_at.ends_with(".000Z"));
    let by_id = find_item(&db, &item_ref(&[], &gh.id), ItemValues::All).unwrap();
    assert_eq!(by_id.field("Password"), Some("s3cret"));

    let out = set_item_fields(&mut db, &item_ref(&["New", "Sub"], "Api"), &[update("username", "u"), update("token", "t0k")], CreateMode::CreateIfMissing, NOW + 5).unwrap();
    let api = find_item(&db, &item_ref(&["New", "Sub"], "Api"), ItemValues::All).unwrap();
    let mut prot = api.protected.clone();
    prot.sort();
    assert_eq!((out.created, api.field("UserName"), api.field("token"), prot), (true, Some("u"), Some("t0k"), vec!["Password".to_owned(), "token".to_owned()]));
    assert_eq!(api.group, ["New", "Sub"]);

    let e = set_item_fields(&mut db, &item_ref(&[], "GitHub"), &[update("x", "1")], CreateMode::CreateOnly, NOW).unwrap_err();
    assert!(e.is(OvErrorCode::Conflict) && e.status == Some(409) && e.message.contains("already exists"));
    let e = set_item_fields(&mut db, &item_ref(&[], "Missing"), &[update("x", "1")], CreateMode::MustExist, NOW).unwrap_err();
    assert!(e.is(OvErrorCode::EntryNotFound) && e.message.contains("not found"));
}

#[test]
fn refuses_writes_with_a_read_grant_before_uploading_anything() {
    let w = world();
    let (keyring, _) = sa_login(&w.server, &w.read_token);
    let r = parse_reference("ov://Team%20Infra/GitHub/password").unwrap();
    let v = find_vault(keyring.iter(), &r.vault).unwrap();
    let e = check_writable(v).unwrap_err();
    assert!(e.is(OvErrorCode::Forbidden) && e.status == Some(403));
    assert!(e.message.contains("can only read vault \"Team Infra\""), "{}", e.message);
    let (keyring, _) = sa_login(&w.server, &w.write_token);
    assert!(check_writable(find_vault(keyring.iter(), &r.vault).unwrap()).is_ok());
}

#[test]
fn creates_an_sa_reads_and_writes_by_reference_and_issues_a_second_secret() {
    let mut w = world();
    assert!(w.write_token.starts_with("ov_sa_"));
    let (keyring, sa_id) = sa_login(&w.server, &w.write_token);
    // by id and by name
    assert_eq!(&*sa_read(&w.server, &keyring, &format!("ov://{}/GitHub/password", w.vault.id())), "s3cret");
    let injected = inject("TOKEN=ov://Team%20Infra/GitHub/password\n", |r| Ok(sa_read(&w.server, &keyring, r))).unwrap();
    assert_eq!(&*injected.text, "TOKEN=s3cret\n");
    assert_eq!(injected.secrets.len(), 1);

    // write: edit the latest copy and upload it under the vault key
    let r = parse_reference("ov://Team%20Infra/GitHub/password").unwrap();
    let v = find_vault(keyring.iter(), &r.vault).unwrap();
    check_writable(v).unwrap();
    let mut db = open(&w.server, v).unwrap();
    write_field(&mut db, &r, "rotated-by-ci", false, None, NOW + 10).unwrap();
    let ck = ov_kdbx::vault::vault_credentials(&v.current_key().unwrap().key).unwrap();
    w.server.blobs.insert(v.id().to_owned(), ov_kdbx::write(&db, &ck).unwrap());
    assert_eq!(&*sa_read(&w.server, &keyring, "ov://Team%20Infra/GitHub/password"), "rotated-by-ci");
    // alice sees it too
    let alice_db = open(&w.server, &w.vault).unwrap();
    let (entry, _) = find_entry(&alice_db, &[], "GitHub").unwrap();
    assert_eq!(entry.field_text("Password"), "rotated-by-ci");
    assert_eq!(entry.history.len(), 1);

    // a second secret, issued by an admin without the first one
    let issued = issue_sa_secret(ISSUER, &w.alice.keyset, &w.server.get_sa(&w.alice.principal(), &sa_id), Some("second"), None).unwrap();
    assert_eq!(issued.body.name.as_deref(), Some("second"));
    assert_eq!(issued.body.prefix.len(), 8);
    w.server.issue_secret(&sa_id, &issued.body);
    let (keyring2, _) = sa_login(&w.server, &issued.token);
    assert_eq!(&*sa_read(&w.server, &keyring2, "ov://Team%20Infra/GitHub/password"), "rotated-by-ci");
    assert_ne!(*issued.token, *w.write_token);
}

#[test]
fn the_master_key_is_sealed_to_every_confirmed_owner_and_admin_and_the_creator() {
    let mut server = Server::default();
    let (alice, adm, inv, mem) = (User::new("alice"), User::new("adm"), User::new("inv"), User::new("mem"));
    for u in [&alice, &adm, &inv, &mem] {
        server.register(u);
    }
    // alice is an accepted (not yet confirmed) admin herself: she is still included
    let members = vec![
        member(&alice, OrgRole::Admin, MemberStatus::Accepted),
        member(&adm, OrgRole::Owner, MemberStatus::Confirmed),
        member(&inv, OrgRole::Admin, MemberStatus::Invited),
        member(&mem, OrgRole::Member, MemberStatus::Confirmed),
    ];
    let sa = new_service_account(ISSUER, &alice.principal(), &alice.keyset, &members, &ServiceAccountSpec {
        name: "ci".into(),
        expires_at: Some("2030-01-01T00:00:00Z".into()),
        secret_name: Some("first".into()),
    })
    .unwrap();
    let to: Vec<_> = sa.request.master_keys.iter().map(|k| k.principal.clone()).collect();
    assert_eq!(to, [alice.principal(), adm.principal()]);
    assert_eq!(sa.request.secret.expires_at.as_deref(), Some("2030-01-01T00:00:00Z"));
    assert_eq!(sa.request.secret.name.as_deref(), Some("first"));
    assert_eq!(sa.principal(), sa_principal(&sa.sa_id));
    assert!(!format!("{sa:?}").contains(&*sa.token));

    // not in the list at all: added anyway
    let sa2 = new_service_account(ISSUER, &alice.principal(), &alice.keyset, &[], &ServiceAccountSpec::default()).unwrap();
    assert_eq!(sa2.request.master_keys.len(), 1);
    assert_eq!(sa2.request.master_keys[0].principal, alice.principal());

    // every sealed copy opens to the master key the token wraps
    server.create_org("acme", &alice);
    server.create_sa("acme", &sa.request);
    let t = parse_sa_token(&sa.token).unwrap();
    let master = unwrap_sa_master(&t.kek, &t.sa_id, &sa.request.secret.wrapped_master).unwrap();
    for u in [&alice, &adm] {
        assert_eq!(*unseal_master(&u.keyset, &server.get_sa(&u.principal(), &sa.sa_id)).unwrap(), *master);
    }
    assert!(unseal_master(&mem.keyset, &server.get_sa(&mem.principal(), &sa.sa_id)).unwrap_err().is(OvErrorCode::Forbidden));
}

#[test]
fn finds_vaults_by_id_or_unique_name() {
    let mut server = Server::default();
    let alice = User::new("alice");
    server.register(&alice);
    let mut keyring = Keyring::new();
    for name in ["A", "B", "B"] {
        let nv = ov_vault::new_vault(name, &alice.principal(), &alice.keyset, None).unwrap();
        let created = server.create_vault(&alice.principal(), &nv.request).unwrap();
        keyring.ingest(&nv.listing(created), &alice.keyset);
    }
    let a = find_vault(keyring.iter(), "A").unwrap();
    assert_eq!(find_vault(keyring.iter(), a.id()).unwrap().id(), a.id());
    let e = find_vault(keyring.iter(), "B").unwrap_err();
    assert!(e.is(OvErrorCode::NotFound) && e.status == Some(404) && e.message.contains("2 vaults are named \"B\""));
    let e = find_vault(keyring.iter(), "C").unwrap_err();
    assert!(e.message.contains("not found or not shared"));
}

#[test]
fn a_token_for_another_sa_or_a_tampered_exchange_fails() {
    let w = world();
    let t = parse_sa_token(&w.read_token).unwrap();
    let mut ex = w.server.exchange(&exchange_request(&t)).unwrap();
    let other = parse_sa_token(&w.write_token).unwrap();
    assert!(unlock_service_account(&other, &ex).unwrap_err().is(OvErrorCode::DecryptionFailed));
    ex.keyset.enc_pk = w.server.publics[&w.alice.principal()].enc_pk.clone();
    assert!(unlock_service_account(&t, &ex).unwrap_err().is(OvErrorCode::InvalidPublicKeys));
}
