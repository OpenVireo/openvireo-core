//! The sharing parts of the SDK's `test/account.test.ts`, on the pure ov-vault API against the
//! in-memory server state of `common`: share → read → revoke + rotate, and the org member flows
//! (confirm with chosen vaults, promote, remove and rotate, refusals).

mod common;

use common::*;
use ov_error::OvErrorCode;
use ov_kdbx::vault::{open_with_key_versions, KeyVersion};
use ov_protocol::types::{MemberStatus, OrgRole, VaultRole};
use ov_vault::keys::user_principal;
use ov_vault::orgs::{
    confirm_member_request, member_keys, missing_vaults, promotion, set_member_role_request, VaultChoice,
};
use ov_vault::service_account::{issue_sa_secret, new_service_account, seal_sa_master_keys, ServiceAccountSpec};
use ov_vault::{grant, new_vault, parse_reference, read_field, Keyring, VaultKeys};
use zeroize::Zeroizing;

fn password(server: &Server, v: &VaultKeys, reference: &str) -> String {
    let db = open(server, v).unwrap();
    read_field(&db, &parse_reference(reference).unwrap()).unwrap().to_string()
}

/// Creates a vault as the facade does: POST /vaults, then the first upload.
fn create(server: &mut Server, me: &User, name: &str, org: Option<&str>, entries: &[(&str, &str, &str)]) -> VaultKeys {
    let members = org.map(|o| server.members[o].clone());
    let nv = new_vault(name, &me.principal(), &me.keyset, org.zip(members.as_deref())).unwrap();
    let created = server.create_vault(&me.principal(), &nv.request).unwrap();
    let listed = nv.listing(created);
    let keys = VaultKeys::from_vault(&listed, &me.keyset);
    assert_eq!(keys.info.name, name);
    assert_eq!(*keys.current_key_bytes().unwrap(), *nv.key);
    server.blobs.insert(nv.id.clone(), vault_blob(name, &nv.key, entries));
    keys
}

fn vault_of(server: &Server, u: &User, id: &str) -> VaultKeys {
    VaultKeys::from_vault(&server.vault(&u.principal(), id).expect("vault listed"), &u.keyset)
}

#[test]
fn register_vault_share_revoke_and_rotate() {
    let mut server = Server::default();
    let alice = User::new("alice");
    let bob = User::new("bob");
    server.register(&alice);
    server.register(&bob);

    let mut vault = create(&mut server, &alice, "Team Infra", None, &[("GitHub", "ci", "s3cret")]);
    let listed: Vec<_> =
        server.list_vaults(&alice.principal()).iter().map(|v| VaultKeys::from_vault(v, &alice.keyset).info).collect();
    assert_eq!(
        listed.iter().map(|v| (v.name.as_str(), v.role.clone())).collect::<Vec<_>>(),
        [("Team Infra", VaultRole::Manage)]
    );
    assert_eq!(password(&server, &vault, "ov://Team%20Infra/GitHub/password"), "s3cret");

    // a second device of alice's: the same keyset unseals the same key
    let mut device2 = Keyring::new();
    device2.ingest_list(&server.list_vaults(&alice.principal()), &alice.keyset);
    assert_eq!(password(&server, device2.get(vault.id()).unwrap(), "ov://Team%20Infra/GitHub/password"), "s3cret");

    // share with bob (looked up by email), who reads it
    let shared = grant(&vault, &server.lookup("bob@example.com"), VaultRole::Read).unwrap();
    assert_eq!(shared.fingerprint, bob.keyset.public.fingerprint());
    assert_eq!(shared.grant.principal, bob.principal());
    assert_eq!(shared.grant.key_version, 1);
    server.grant_access(&alice.principal(), vault.id(), &[shared.grant]).unwrap();
    let bv = vault_of(&server, &bob, vault.id());
    assert_eq!(bv.info.role, VaultRole::Read);
    assert!(!bv.can_manage());
    assert_eq!(bv.info.name, "Team Infra");
    assert_eq!(password(&server, &bv, "ov://x/GitHub/username"), "ci");
    let old_blob = server.blobs[vault.id()].clone();
    let bob_old_keys: Vec<KeyVersion> = bv.keys().to_vec();

    // bob can't rotate (read role)
    let access = server.list_access(vault.id());
    let e = ov_vault::plan_rotation(&bv, &bob.principal(), &access, &[]).unwrap_err();
    assert!(e.is(OvErrorCode::Forbidden) && e.status == Some(403));

    // revoke → rotation: bob loses access, the blob is re-keyed, alice's other device follows
    rotate(&mut server, &alice, &mut vault, &[bob.principal()]);
    let sv = &server.vaults[vault.id()];
    assert_eq!((sv.current, sv.pending, sv.access.contains_key(&bob.principal())), (2, None, false));
    assert!(server.list_vaults(&bob.principal()).is_empty());
    let new_blob = server.blobs[vault.id()].clone();
    assert_ne!(old_blob, new_blob);
    // the old key no longer opens the new blob (bob's copy still in memory)
    let err = open_with_key_versions(&new_blob, &bob_old_keys).unwrap_err();
    assert!(err.is(OvErrorCode::VaultKeyMismatch), "{err:?}");
    // an all-zero key doesn't either
    let zero = KeyVersion { version: 1, key: Zeroizing::new(vec![0u8; 32]) };
    assert!(open_with_key_versions(&old_blob, &[zero]).unwrap_err().is(OvErrorCode::VaultKeyMismatch));

    // alice's second device: the new list carries only version 2, the name is re-encrypted
    let ingested = device2.ingest_list(&server.list_vaults(&alice.principal()), &alice.keyset);
    assert!(ingested.dropped.is_empty());
    let again = device2.get(vault.id()).unwrap();
    assert_eq!((again.info.current_key_version, again.keys().len()), (2, 1));
    assert_eq!(again.info.name, "Team Infra");
    assert_eq!(password(&server, again, "ov://x/GitHub/password"), "s3cret");

    // bob's keyring drops the vault on his next list
    let mut bobs = Keyring::new();
    bobs.ingest(&server.vault(&alice.principal(), vault.id()).unwrap(), &bob.keyset); // keys sealed to alice: none open
    assert!(bobs.get(vault.id()).unwrap().current_key().unwrap_err().is(OvErrorCode::NoVaultKey));
    let ingested = bobs.ingest_list(&server.list_vaults(&bob.principal()), &bob.keyset);
    assert_eq!(ingested.dropped, [vault.id().to_owned()]);
    assert!(bobs.is_empty());
}

#[test]
fn a_crash_between_upload_and_activate_still_opens_with_either_key() {
    let mut server = Server::default();
    let alice = User::new("alice");
    server.register(&alice);
    let mut vault = create(&mut server, &alice, "Personal", None, &[("Wifi", "", "hunter2")]);
    let access = server.list_access(vault.id());
    let plan = ov_vault::plan_rotation(&vault, &alice.principal(), &access, &[]).unwrap();
    assert!(plan.principals_needing_keys().is_empty());
    let req = plan.start_request(&alice.keyset.public, &[]).unwrap();
    assert_eq!((req.key_version, req.remove.clone()), (2, Some(vec![])));
    server.start_rotation(vault.id(), &req);
    // listed during the rotation: both versions, newest first
    let listed = vault_of(&server, &alice, vault.id());
    assert_eq!(listed.keys().iter().map(|k| k.version).collect::<Vec<_>>(), [2, 1]);
    assert_eq!(listed.info.pending_key_version, Some(2));
    // the old blob opens (falls back to version 1) before the re-keyed upload
    assert_eq!(password(&server, &listed, "ov://p/Wifi/password"), "hunter2");
    // and after it
    vault.add_key(plan.new_key());
    let mut db = open(&server, &vault).unwrap();
    let ck = ov_kdbx::vault::rekey_to_vault_key(&mut db, &plan.new_key().key).unwrap();
    server.blobs.insert(vault.id().to_owned(), ov_kdbx::write(&db, &ck).unwrap());
    let (_, opened_with) = open_with_key_versions(&server.blobs[vault.id()], listed.keys()).unwrap();
    assert_eq!(opened_with, 2);
}

#[test]
fn rotation_keeps_roles_and_needs_every_members_keys() {
    let mut server = Server::default();
    let (alice, bob, carol) = (User::new("alice"), User::new("bob"), User::new("carol"));
    for u in [&alice, &bob, &carol] {
        server.register(u);
    }
    let mut vault = create(&mut server, &alice, "Shared", None, &[("GitHub", "ci", "s3cret")]);
    for (u, role) in [(&bob, VaultRole::Write), (&carol, VaultRole::Read)] {
        let g = grant(&vault, &server.public_principal(&u.principal()), role).unwrap();
        server.grant_access(&alice.principal(), vault.id(), &[g.grant]).unwrap();
    }
    let access = server.list_access(vault.id());
    let plan =
        ov_vault::plan_rotation(&vault, &alice.principal(), &access, &[carol.principal(), carol.principal()]).unwrap();
    assert_eq!(plan.removed(), [carol.principal()]);
    let mut kept: Vec<_> = plan.members().iter().map(|m| (m.principal.clone(), m.role.clone())).collect();
    kept.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(kept, [(alice.principal(), VaultRole::Manage), (bob.principal(), VaultRole::Write)]);
    assert_eq!(plan.principals_needing_keys(), [bob.principal()]);
    // bob's keys missing → invalid_public_keys
    assert!(plan.start_request(&alice.keyset.public, &[]).unwrap_err().is(OvErrorCode::InvalidPublicKeys));
    // keys whose signature is wrong → invalid_public_keys
    let mut forged = server.public_principal(&bob.principal());
    forged.enc_pk = server.publics[&carol.principal()].enc_pk.clone();
    assert!(plan.start_request(&alice.keyset.public, &[forged]).unwrap_err().is(OvErrorCode::InvalidPublicKeys));

    rotate(&mut server, &alice, &mut vault, &[carol.principal()]);
    let bv = vault_of(&server, &bob, vault.id());
    assert_eq!((bv.info.role.clone(), bv.info.current_key_version), (VaultRole::Write, 2));
    assert!(bv.can_write());
    assert_eq!(password(&server, &bv, "ov://x/GitHub/password"), "s3cret");
    assert!(server.vault(&carol.principal(), vault.id()).is_none());
}

#[test]
fn grant_refuses_forged_keys_and_a_missing_current_key() {
    let mut server = Server::default();
    let (alice, bob, eve) = (User::new("alice"), User::new("bob"), User::new("eve"));
    for u in [&alice, &bob, &eve] {
        server.register(u);
    }
    let vault = create(&mut server, &alice, "V", None, &[]);
    let mut forged = server.public_principal(&bob.principal());
    forged.enc_pk = server.publics[&eve.principal()].enc_pk.clone();
    assert!(grant(&vault, &forged, VaultRole::Read).unwrap_err().is(OvErrorCode::InvalidPublicKeys));
    // a listing whose current version this principal doesn't hold
    let mut listed = server.vault(&alice.principal(), vault.id()).unwrap();
    listed.current_key_version = 2;
    let stale = VaultKeys::from_vault(&listed, &alice.keyset);
    let e = grant(&stale, &server.public_principal(&bob.principal()), VaultRole::Read).unwrap_err();
    assert!(e.is(OvErrorCode::NoVaultKey));
}

#[test]
fn org_vaults_are_sealed_to_every_confirmed_owner_and_admin() {
    let mut server = Server::default();
    let (alice, admin, invited, member) = (User::new("alice"), User::new("adm"), User::new("inv"), User::new("mem"));
    for u in [&alice, &admin, &invited, &member] {
        server.register(u);
    }
    server.create_org("acme", &alice);
    server.members.get_mut("acme").unwrap().extend([
        common::member(&admin, OrgRole::Admin, MemberStatus::Confirmed),
        common::member(&invited, OrgRole::Admin, MemberStatus::Accepted),
        common::member(&member, OrgRole::Member, MemberStatus::Confirmed),
    ]);
    let nv = new_vault("Infra", &alice.principal(), &alice.keyset, Some(("acme", &server.members["acme"]))).unwrap();
    assert_eq!(nv.request.org_id.as_deref(), Some("acme"));
    let got: Vec<_> = nv.request.grants.iter().map(|g| (g.principal.clone(), g.role.clone(), g.key_version)).collect();
    assert_eq!(got, [(alice.principal(), VaultRole::Manage, 1), (admin.principal(), VaultRole::Manage, 1)]);
    server.create_vault(&alice.principal(), &nv.request).unwrap();
    assert_eq!(vault_of(&server, &admin, &nv.id).info.name, "Infra");

    // without the admin's grant the server refuses (the rule the client follows)
    let personal = new_vault("Infra2", &alice.principal(), &alice.keyset, None).unwrap();
    let mut req = personal.request.clone();
    req.org_id = Some("acme".into());
    assert!(server.create_vault(&alice.principal(), &req).unwrap_err().is(OvErrorCode::InvalidRequest));

    // an admin with a forged signature fails the whole call
    let mut members = server.members["acme"].clone();
    members[1].public.as_mut().unwrap().enc_pk = members[3].public.as_ref().unwrap().enc_pk.clone();
    let e = new_vault("X", &alice.principal(), &alice.keyset, Some(("acme", &members))).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidPublicKeys));
    // ... and names the member (contract-v1.8)
    let details: serde_json::Value = serde_json::from_str(e.details.as_deref().expect("details")).unwrap();
    assert_eq!(details["principal"], admin.principal());
    assert_eq!(details["email"], members[1].email);
}

#[test]
fn confirm_with_chosen_vaults_then_promote_then_remove_and_rotate() {
    let mut server = Server::default();
    let (alice, bob) = (User::new("alice"), User::new("bob"));
    server.register(&alice);
    server.register(&bob);
    server.create_org("acme", &alice);
    let infra = create(&mut server, &alice, "Infra", Some("acme"), &[("GitHub", "", "s3cret")]);
    let payroll = create(&mut server, &alice, "Payroll", Some("acme"), &[]);
    let sa = new_service_account(
        ISSUER,
        &alice.principal(),
        &alice.keyset,
        &server.members["acme"],
        &ServiceAccountSpec { name: "ci".into(), ..Default::default() },
    )
    .unwrap();
    server.create_sa("acme", &sa.request);

    server.add_member("acme", &bob);
    let pending = server.find_member("acme", "bob");
    assert_eq!(pending.status, MemberStatus::Accepted);

    // alice's keyring, as listVaults leaves it
    let mut keyring = Keyring::new();
    keyring.ingest_list(&server.list_vaults(&alice.principal()), &alice.keyset);

    // a member gets only the vaults picked for them, and no SA master keys
    let target = member_keys(&pending).unwrap();
    assert!(!target.manager);
    let picked = [VaultChoice { vault_id: infra.id().to_owned(), role: VaultRole::Read }];
    assert!(missing_vaults(&keyring, &picked).is_empty());
    let req = confirm_member_request("acme", &target, &keyring, &picked, Some(vec![])).unwrap();
    assert_eq!(req.sa_master_keys, None);
    let grants = req.grants.as_ref().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        (grants[0].vault_id.as_str(), grants[0].role.clone(), grants[0].key_version),
        (infra.id(), VaultRole::Read, 1)
    );
    let confirmed = server.confirm_member(&alice.principal(), "acme", "bob", &req);
    assert_eq!(confirmed.status, MemberStatus::Confirmed);
    let bobs: Vec<_> =
        server.list_vaults(&bob.principal()).iter().map(|v| VaultKeys::from_vault(v, &bob.keyset)).collect();
    assert_eq!(
        bobs.iter().map(|v| (v.info.name.as_str(), v.info.role.clone())).collect::<Vec<_>>(),
        [("Infra", VaultRole::Read)]
    );
    assert_eq!(password(&server, &bobs[0], "ov://Infra/GitHub/password"), "s3cret");
    let e = issue_sa_secret(ISSUER, &bob.keyset, &server.get_sa(&bob.principal(), &sa.sa_id), None, None).unwrap_err();
    assert!(e.is(OvErrorCode::Forbidden) && e.status == Some(403));

    // promotion: the SA master key, then manage on every org vault alice manages
    let promoted = promotion(&confirmed, &OrgRole::Admin).unwrap().expect("a promotion");
    let masters = seal_sa_master_keys(
        &alice.keyset,
        &server.list_sas(&alice.principal(), "acme"),
        &promoted.principal,
        &promoted.public.enc_pk,
    )
    .unwrap();
    assert_eq!(masters.len(), 1);
    server.set_member_role("acme", "bob", &set_member_role_request(OrgRole::Admin, Some(masters)));
    for v in keyring.managed_org_vaults("acme") {
        let g = grant(v, &server.public_principal(&bob.principal()), VaultRole::Manage).unwrap();
        server.grant_access(&alice.principal(), v.id(), &[g.grant]).unwrap();
    }
    let mut bobs: Vec<_> = server
        .list_vaults(&bob.principal())
        .iter()
        .map(|v| VaultKeys::from_vault(v, &bob.keyset).info)
        .map(|i| (i.name, i.role))
        .collect();
    bobs.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(bobs, [("Infra".to_owned(), VaultRole::Manage), ("Payroll".to_owned(), VaultRole::Manage)]);
    let issued = issue_sa_secret(ISSUER, &bob.keyset, &server.get_sa(&bob.principal(), &sa.sa_id), None, None).unwrap();
    assert!(issued.token.starts_with("ov_sa_"));
    // not a promotion: a demotion, or a member not yet confirmed
    assert!(promotion(&confirmed, &OrgRole::Member).unwrap().is_none());
    assert!(promotion(&pending, &OrgRole::Admin).unwrap().is_none());

    // removal: access goes at once, both vaults are flagged, alice rotates them
    server.remove_member("acme", "bob");
    keyring.ingest_list(&server.list_vaults(&alice.principal()), &alice.keyset);
    let mut flagged: Vec<String> = keyring.flagged_for_rotation("acme").iter().map(|v| v.id().to_owned()).collect();
    flagged.sort();
    let mut want = vec![infra.id().to_owned(), payroll.id().to_owned()];
    want.sort();
    assert_eq!(flagged, want);
    for id in &flagged {
        let mut v = keyring.get(id).unwrap().clone();
        rotate(&mut server, &alice, &mut v, &[]);
    }
    assert!(server.list_vaults(&bob.principal()).is_empty());
    assert_eq!(server.vaults[infra.id()].current, 2);
    keyring.ingest_list(&server.list_vaults(&alice.principal()), &alice.keyset);
    assert!(keyring.flagged_for_rotation("acme").is_empty());
    assert_eq!(password(&server, keyring.get(infra.id()).unwrap(), "ov://Infra/GitHub/password"), "s3cret");
}

#[test]
fn an_admin_is_confirmed_with_every_managed_org_vault_and_the_sa_master_keys() {
    let mut server = Server::default();
    let (alice, carol) = (User::new("alice"), User::new("carol"));
    server.register(&alice);
    server.register(&carol);
    server.create_org("acme", &alice);
    let infra = create(&mut server, &alice, "Infra", Some("acme"), &[]);
    let _personal = create(&mut server, &alice, "Personal", None, &[]);
    let sa = new_service_account(
        ISSUER,
        &alice.principal(),
        &alice.keyset,
        &server.members["acme"],
        &ServiceAccountSpec::default(),
    )
    .unwrap();
    server.create_sa("acme", &sa.request);
    server.members.get_mut("acme").unwrap().push(common::member(&carol, OrgRole::Admin, MemberStatus::Accepted));

    let mut keyring = Keyring::new();
    keyring.ingest_list(&server.list_vaults(&alice.principal()), &alice.keyset);
    let target = member_keys(&server.find_member("acme", "carol")).unwrap();
    assert!(target.manager);
    let masters = seal_sa_master_keys(
        &alice.keyset,
        &server.list_sas(&alice.principal(), "acme"),
        &target.principal,
        &target.public.enc_pk,
    )
    .unwrap();
    // picked vaults are ignored for an admin: every managed org vault, with manage
    let req = confirm_member_request("acme", &target, &keyring, &[], Some(masters)).unwrap();
    let grants = req.grants.as_ref().unwrap();
    assert_eq!(
        grants.iter().map(|g| (g.vault_id.as_str(), g.role.clone())).collect::<Vec<_>>(),
        [(infra.id(), VaultRole::Manage)]
    );
    assert_eq!(req.sa_master_keys.as_ref().map(Vec::len), Some(1));
    server.confirm_member(&alice.principal(), "acme", "carol", &req);
    assert!(issue_sa_secret(ISSUER, &carol.keyset, &server.get_sa(&carol.principal(), &sa.sa_id), None, None).is_ok());
}

#[test]
fn refuses_a_vault_from_another_org_or_a_member_without_keys() {
    let mut server = Server::default();
    let (alice, bob) = (User::new("alice"), User::new("bob"));
    server.register(&alice);
    server.register(&bob);
    server.create_org("acme", &alice);
    let personal = create(&mut server, &alice, "Personal", None, &[]);
    server.add_member("acme", &bob);
    let m = server.find_member("acme", "bob");
    let mut keyring = Keyring::new();
    keyring.ingest_list(&server.list_vaults(&alice.principal()), &alice.keyset);

    let target = member_keys(&m).unwrap();
    let picked = [VaultChoice { vault_id: personal.id().to_owned(), role: VaultRole::Read }];
    let e = confirm_member_request("acme", &target, &keyring, &picked, None).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidRequest) && e.status == Some(400), "{e:?}");

    let mut no_keys = m.clone();
    no_keys.public = None;
    let e = member_keys(&no_keys).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidRequest) && e.status == Some(400));

    // a vault the keyring hasn't loaded is reported, and refused until loaded
    let unknown = [VaultChoice { vault_id: "not-loaded".into(), role: VaultRole::Read }];
    assert_eq!(missing_vaults(&keyring, &unknown), ["not-loaded"]);
    assert!(confirm_member_request("acme", &target, &keyring, &unknown, None).unwrap_err().is(OvErrorCode::NotFound));
    assert_eq!(user_principal("bob"), target.principal);
}
