//! Contract-v1.8: the core gaps the iOS migration found (W3-A5). Recycle Bin restore back to the
//! previous group, edits made during a sync kept, `restore_entry` on a binned entry, the web app's
//! plain export, unsynced edits kept on an accidental session end, a pull that doesn't upload, and
//! the older iOS asks (pending rotations, deletion details, sharing to confirmed keys, self-hosted
//! download and health).

mod servers_common;

use std::sync::{Arc, Mutex};

use ov_core::api::*;
use ov_core::host::{BlobCache, HttpResponse, Method};
use ov_core::OvErrorCode;
use ov_testkit::servers::{Fault, FaultRule, MemoryCache, MemoryStore, Server, TestServers};
use servers_common::*;

fn creds(pw: &str) -> KdbxCredentials {
    KdbxCredentials { password: Some(pw.as_bytes().to_vec()), ..Default::default() }
}

fn f(name: &str, value: &str) -> FieldInput {
    FieldInput { name: name.into(), value: value.as_bytes().to_vec(), protected: None }
}

fn entry_in(v: &Vault, group: &str, title: &str, password: &str) -> String {
    v.add_entry(
        group.into(),
        EntryInput { fields: vec![f("Title", title), f("Password", password)], ..Default::default() },
    )
    .unwrap()
}

fn set_password(v: &Vault, id: &str, value: &str) {
    v.edit_entry(id.into(), EntryInput { fields: vec![f("Password", value)], ..Default::default() }).unwrap();
}

fn group_path(v: &Vault, id: &str) -> String {
    v.entry(id.into()).unwrap().group_path.join("/")
}

fn titles(v: &Vault) -> Vec<String> {
    let mut t: Vec<String> = v.entries(false).into_iter().map(|e| e.title).collect();
    t.sort();
    t
}

/// A signed-up account with one vault holding `Mail`, synced; the device's cache is returned too.
async fn account_with_vault(s: &TestServers, offline: bool) -> (Account, NewAccount, Vault, Arc<MemoryCache>) {
    let cache = Arc::new(MemoryCache::new());
    let c = OvClient::new(config(offline), s.host_with(Arc::new(MemoryStore::new()), cache.clone()));
    let a = connect(&c, s).await;
    let kit = register(&a, "alice@example.com", "correct horse ü").await;
    let v = a.create_vault("Home".into(), None, nc()).await.unwrap();
    add_entry(&v, "Mail", "m1");
    v.sync(SyncOptions::default(), nc()).await.unwrap();
    (a, kit, v, cache)
}

async fn second_device(s: &TestServers, kit: &NewAccount) -> Account {
    let a = connect(&device(s, false), s).await;
    login(&a, "alice@example.com", "correct horse ü", Some(&kit.secret_key)).await;
    a
}

fn puts(s: &TestServers, vault_id: &str) -> usize {
    s.requests().iter().filter(|r| r.method == Method::Put && r.path.contains(&format!("/vaults/{vault_id}"))).count()
}

// ------------------------------------------------------------------ 1. Recycle Bin restore location

#[tokio::test]
async fn the_recycle_bin_restores_to_the_previous_group_in_a_saved_file() {
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    let work = v.add_group(None, "Work".into()).unwrap();
    let finance = v.add_group(None, "Finance".into()).unwrap();
    let banks = v.add_group(Some(finance.clone()), "Banks".into()).unwrap();
    let server = entry_in(&v, &work, "Server", "s");
    let bank = entry_in(&v, &banks, "Bank", "b");
    v.delete_entry(server.clone()).unwrap();
    v.delete_group(banks.clone()).unwrap();
    assert!(v.is_in_recycle_bin(server.clone()) && v.is_in_recycle_bin(bank.clone()));

    // The previous group survives a save: the file is KDBX 4.1 and still opens with ov-kdbx
    let bytes = v.save_local(nc()).await.unwrap();
    let header = ov_kdbx::peek_header(&bytes).unwrap();
    assert_eq!((header.version.major, header.version.minor), (4, 1));
    ov_kdbx::read(&bytes, &ov_kdbx::vault::password_credentials(Some("pw"), None)).unwrap();
    let back = Vault::open_local(bytes, creds("pw"), nc()).await.unwrap();

    back.restore_from_recycle_bin(server.clone()).unwrap();
    back.restore_from_recycle_bin(banks.clone()).unwrap();
    assert_eq!(group_path(&back, &server), "Work");
    assert_eq!(group_path(&back, &bank), "Finance/Banks");
    assert!(!back.is_in_recycle_bin(server.clone()) && !back.is_in_recycle_bin(bank.clone()));

    // A file that never used a 4.1 feature stays KDBX 4.0
    let plain = Vault::create_local("Plain".into(), creds("pw"), nc()).await.unwrap();
    add_entry(&plain, "One", "1");
    let header = ov_kdbx::peek_header(&plain.save_local(nc()).await.unwrap()).unwrap();
    assert_eq!((header.version.major, header.version.minor), (4, 0));
}

#[tokio::test]
async fn an_account_vault_restores_to_the_previous_group_on_another_device() {
    let s = servers();
    let (_a, kit, v, _) = account_with_vault(&s, false).await;
    let work = v.ensure_group("Work".into()).unwrap();
    let id = entry_in(&v, &work, "VPN", "v");
    v.sync(SyncOptions::default(), nc()).await.unwrap();
    v.delete_entry(id.clone()).unwrap();
    v.sync(SyncOptions::default(), nc()).await.unwrap();

    let other = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();
    assert!(other.is_in_recycle_bin(id.clone()));
    other.restore_from_recycle_bin(id.clone()).unwrap();
    assert_eq!(group_path(&other, &id), "Work");
}

// ------------------------------------------------------------------ 2. edits made during a sync

#[tokio::test]
async fn edits_made_while_a_sync_runs_are_kept_and_upload_next() {
    let s = servers();
    let (a, kit, v, _) = account_with_vault(&s, true).await;
    let mail = find_title(&v, "Mail").id;
    set_password(&v, &mail, "m2");

    // While the sync is between its download and its upload, the app edits the same handle
    let during = v.clone();
    let mail_id = mail.clone();
    let fired = Arc::new(Mutex::new(false));
    let once = fired.clone();
    s.set_after_get(Some(Arc::new(move |_s: &TestServers, _id: &str| {
        let mut f = once.lock().unwrap();
        if !*f {
            *f = true;
            add_entry(&during, "Added during sync", "d");
            during
                .edit_entry(
                    mail_id.clone(),
                    EntryInput { fields: vec![f_user("me@example.com")], ..Default::default() },
                )
                .unwrap();
        }
    })));
    let r = v.sync(SyncOptions::default(), nc()).await.unwrap();
    s.set_after_get(None);
    assert!(*fired.lock().unwrap(), "the hook ran");
    assert_eq!(r.outcome, SyncOutcome::Uploaded);

    // Nothing the app did is lost
    assert_eq!(titles(&v), ["Added during sync", "Mail"]);
    let rec = v.entry(mail.clone()).unwrap();
    assert_eq!(field(&rec, "Password"), b"m2");
    assert_eq!(field(&rec, "UserName"), b"me@example.com");
    // ... and the same call uploaded them in a second round, without downloading again
    assert!(!v.has_pending_edits().await.unwrap());
    assert!(!a.has_pending_edits(v.id()).await.unwrap());
    assert_eq!(r.attempts, 2);
    let other = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();
    assert_eq!(titles(&other), ["Added during sync", "Mail"]);
    let rec = find_title(&other, "Mail");
    assert_eq!((field(&rec, "Password"), field(&rec, "UserName")), (&b"m2"[..], &b"me@example.com"[..]));
}

fn f_user(v: &str) -> FieldInput {
    f("UserName", v)
}

#[tokio::test]
async fn edits_made_during_a_pull_are_kept() {
    let s = servers();
    let (_a, kit, v, _) = account_with_vault(&s, false).await;
    let b = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();
    add_entry(&b, "From B", "b");
    b.sync(SyncOptions::default(), nc()).await.unwrap();

    let during = v.clone();
    s.set_after_get(Some(Arc::new(move |_s: &TestServers, _id: &str| {
        if during.entries(false).iter().all(|e| e.title != "Local") {
            add_entry(&during, "Local", "l");
        }
    })));
    let r = v.sync(SyncOptions { local_changed: false, accept_server_state: false }, nc()).await.unwrap();
    s.set_after_get(None);
    assert_eq!(titles(&v), ["From B", "Local", "Mail"]);
    // the pull, then the local edit's upload
    assert_eq!(r.outcome, SyncOutcome::Uploaded);
    let again = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();
    assert_eq!(titles(&again), ["From B", "Local", "Mail"]);
}

// ------------------------------------------------------------------ 3. restore_entry on a binned entry

#[tokio::test]
async fn restoring_a_version_of_a_binned_entry_keeps_its_history_and_leaves_the_bin() {
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    let work = v.add_group(None, "Work".into()).unwrap();
    let id = entry_in(&v, &work, "VPN", "v1");
    let version = v.copy_without_remotes(None).unwrap();
    set_password(&v, &id, "v2");
    set_password(&v, &id, "v3");
    v.delete_entry(id.clone()).unwrap();
    let before = v.entry(id.clone()).unwrap().history_count;
    assert_eq!(before, 2);

    v.restore_entry(version, id.clone(), "Elsewhere".into()).unwrap();
    let rec = v.entry(id.clone()).unwrap();
    assert!(!v.is_in_recycle_bin(id.clone()), "out of the bin");
    assert_eq!(group_path(&v, &id), "Work", "back in its previous group");
    assert_eq!(field(&rec, "Password"), b"v1");
    assert_eq!(rec.history_count, 3, "v1, v2 and the binned v3 are history");
    let hist: Vec<Vec<u8>> = v.history(id.clone()).unwrap().iter().map(|h| field(h, "Password").to_vec()).collect();
    assert_eq!(hist, [b"v1".to_vec(), b"v2".to_vec(), b"v3".to_vec()]);
    assert!(v.group_id_at("Elsewhere".into()).is_none());
}

#[tokio::test]
async fn restoring_a_binned_entry_whose_group_is_gone_uses_the_path() {
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    let work = v.add_group(None, "Work".into()).unwrap();
    let id = entry_in(&v, &work, "VPN", "v1");
    let version = v.copy_without_remotes(None).unwrap();
    set_password(&v, &id, "v2");
    v.delete_entry(id.clone()).unwrap();
    v.delete_group(work.clone()).unwrap();
    // its previous group is in the bin too: it goes to the version's path
    v.restore_entry(version, id.clone(), "Restored".into()).unwrap();
    assert!(!v.is_in_recycle_bin(id.clone()));
    assert_eq!(group_path(&v, &id), "Restored");
    assert_eq!(v.entry(id.clone()).unwrap().history_count, 2);
}

// ------------------------------------------------------------------ 4. plain export = the web app's

const EXPECTED_CSV: &str = include_str!("fixtures/export_plain/expected.csv");
const EXPECTED_JSON: &str = include_str!("fixtures/export_plain/expected.json");

#[tokio::test]
async fn export_plain_writes_the_web_apps_bytes() {
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    let root = v.root_group_id();
    let entry = |group: &str, t: &str, u: &str, p: &str, url: &str, n: &str| {
        v.add_entry(
            group.into(),
            EntryInput {
                fields: vec![f("Title", t), f("UserName", u), f("Password", p), f("URL", url), f("Notes", n)],
                ..Default::default()
            },
        )
        .unwrap()
    };
    entry(&root, "Mail \"personal\"", "me@example.com", "p,w\"1", "https://mail.example.com/a/b", "line1\nline2");
    entry(&root, "", "", "x", "", "tab\there \u{1} ctl");
    let work = v.add_group(None, "Work".into()).unwrap();
    entry(&work, "VPN", "ops", "ü✓ 🔑", "", "</script> \u{2028} \\ end");
    let servers = v.add_group(Some(work.clone()), "Servers".into()).unwrap();
    entry(&servers, "db", "root", "s3cr3t\\", "ssh://db", "");
    let gone = entry(&root, "Binned", "", "", "", "");
    v.delete_entry(gone).unwrap();

    let csv = String::from_utf8(v.export_plain(ExportFormat::Csv, None).unwrap()).unwrap();
    assert_eq!(csv, EXPECTED_CSV);
    let json = String::from_utf8(v.export_plain(ExportFormat::Json, None).unwrap()).unwrap();
    assert_eq!(json, EXPECTED_JSON);

    // Chosen groups only; nothing chosen with entries gives the header alone and `[]`
    let csv = String::from_utf8(v.export_plain(ExportFormat::Csv, Some(vec![servers])).unwrap()).unwrap();
    assert_eq!(
        csv,
        "Folder,Title,Username,Password,URL,Notes\n\"Servers\",\"db\",\"root\",\"s3cr3t\\\",\"ssh://db\",\"\""
    );
    let empty = v.add_group(None, "Empty".into()).unwrap();
    let csv = String::from_utf8(v.export_plain(ExportFormat::Csv, Some(vec![empty.clone()])).unwrap()).unwrap();
    assert_eq!(csv, "Folder,Title,Username,Password,URL,Notes");
    assert_eq!(v.export_plain(ExportFormat::Json, Some(vec![empty])).unwrap(), b"[]");
}

// ------------------------------------------------------------------ 5. accidental session end

fn refresh_refused(code: &str) -> FaultRule {
    let body = format!(r#"{{"error":"refused","code":"{code}"}}"#).into_bytes();
    FaultRule::new(Fault::Response(HttpResponse {
        status: 401,
        headers: vec![("content-type".into(), "application/json".into())],
        body,
    }))
    .server(Server::Auth)
    .path("auth/refresh")
}

/// Edits kept offline, then the session ends with `code` on the next refresh.
async fn pending_then_session_end(
    s: &TestServers,
    code: &str,
) -> (Account, NewAccount, Vault, Arc<MemoryCache>, String) {
    let (a, kit, v, cache) = account_with_vault(s, true).await;
    let user = a.user_id().unwrap();
    s.set_offline(true);
    add_entry(&v, "Offline edit", "o");
    assert_eq!(v.sync(SyncOptions::default(), nc()).await.unwrap_err().code, OvErrorCode::NetworkError);
    s.set_offline(false);
    a.keep_autofill_edit(v.id(), v.entry(find_title(&v, "Mail").id).unwrap(), String::new()).await.unwrap();
    s.fail_next(refresh_refused(code));
    let e = a.access_token(true, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::SignedOut);
    (a, kit, v, cache, user)
}

#[tokio::test]
async fn an_accidental_session_end_keeps_unsynced_edits_for_the_next_sign_in() {
    for code in ["token_reused", "session_expired"] {
        let s = servers();
        let (a, _kit, v, cache, user) = pending_then_session_end(&s, code).await;
        // Only the vault with edits is kept, and only its edits: no sync state, base or meta records
        assert!(cache.meta_keys().iter().all(|(u, _)| u != &user), "{code}: meta records go");
        assert_eq!(cache.vault_keys(), [(user.clone(), v.id())], "{code}");
        let rec = cache.load(&user, &v.id()).await.unwrap().unwrap();
        assert!(rec.pending.is_some() && rec.autofill.is_some(), "{code}: pending and AutoFill edits kept");
        assert!(rec.state.is_empty() && rec.base.is_none(), "{code}: state and base go");

        // The same user signs in again: the edits merge in and upload
        login(&a, "alice@example.com", "correct horse ü", None).await;
        let again = a.open_vault(v.id(), nc()).await.unwrap();
        assert_eq!(titles(&again), ["Mail", "Offline edit"], "{code}");
        again.sync(SyncOptions::default(), nc()).await.unwrap();
        assert!(!a.has_pending_edits(v.id()).await.unwrap());
    }
}

#[tokio::test]
async fn a_refused_session_or_a_sign_out_wipes_everything() {
    // Revoked (`unauthorized`): nothing is kept
    let s = servers();
    let (_a, _kit, _v, cache, user) = pending_then_session_end(&s, "unauthorized").await;
    assert!(cache.vault_keys().iter().all(|(u, _)| u != &user));
    assert!(cache.meta_keys().iter().all(|(u, _)| u != &user));

    // An explicit sign-out, edits waiting or not: nothing is kept
    let s = servers();
    let (a, _kit, v, cache) = account_with_vault(&s, true).await;
    let user = a.user_id().unwrap();
    s.set_offline(true);
    add_entry(&v, "Offline edit", "o");
    v.sync(SyncOptions::default(), nc()).await.unwrap_err();
    s.set_offline(false);
    a.sign_out(false, nc()).await.unwrap();
    assert!(cache.vault_keys().iter().all(|(u, _)| u != &user));
    assert!(cache.meta_keys().iter().all(|(u, _)| u != &user));
}

// ------------------------------------------------------------------ 7. a pull doesn't upload

#[tokio::test]
async fn a_pull_with_no_local_changes_does_not_upload() {
    let s = servers();
    let (_a, kit, v, _) = account_with_vault(&s, false).await;
    let b = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();
    // Same second as the first device's last sync (the clock doesn't move)
    set_password(&b, &find_title(&b, "Mail").id, "from b");
    add_entry(&b, "New on B", "n");
    b.sync(SyncOptions::default(), nc()).await.unwrap();

    let before = puts(&s, &v.id());
    let r = v.sync(SyncOptions { local_changed: false, accept_server_state: false }, nc()).await.unwrap();
    assert_eq!(r.outcome, SyncOutcome::Pulled);
    assert_eq!(puts(&s, &v.id()), before, "no upload");
    assert_eq!(field(&find_title(&v, "Mail"), "Password"), b"from b");
    assert_eq!(titles(&v), ["Mail", "New on B"]);

    // And the next pull finds nothing new
    let r = v.sync(SyncOptions { local_changed: false, accept_server_state: false }, nc()).await.unwrap();
    assert_eq!(r.outcome, SyncOutcome::Unchanged);

    // A second later as well
    s.clock().advance(5_000);
    set_password(&b, &find_title(&b, "Mail").id, "again");
    b.sync(SyncOptions::default(), nc()).await.unwrap();
    let before = puts(&s, &v.id());
    let r = v.sync(SyncOptions { local_changed: false, accept_server_state: false }, nc()).await.unwrap();
    assert_eq!((r.outcome, puts(&s, &v.id())), (SyncOutcome::Pulled, before));
}

// ------------------------------------------------------------------ 11. Meta/CustomData kept

const REMOTES: &str = r#"[{"name":"backup","type":"command","uploadCommand":"scp {DB_PATH} host:"},{"name":"server","type":"syncServer","url":"https://sync.example"}]"#;

fn meta(v: &Vault, key: &str) -> Option<String> {
    v.meta_custom_data(key.into())
}

#[tokio::test]
async fn importing_a_kdbx_keeps_its_database_custom_data() {
    let s = servers();
    let (a, kit, target, _) = account_with_vault(&s, false).await;
    let file = Vault::create_local("Laptop".into(), creds("pw"), nc()).await.unwrap();
    add_entry(&file, "Router", "r");
    file.set_meta_custom_data("Foo".into(), Some("1".into())).unwrap();
    file.set_meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS".into(), Some(REMOTES.into())).unwrap();
    let bytes = file.save_local(nc()).await.unwrap();

    // Into a new vault: all of it, minus the server remotes
    let out = a
        .import_kdbx(bytes.clone(), creds("pw"), ImportMode::NewVault { name: None, org_id: None }, nc())
        .await
        .unwrap();
    assert_eq!(meta(&out.vault, "Foo").as_deref(), Some("1"), "the imported handle");
    let other = second_device(&s, &kit).await.open_vault(out.vault.id(), nc()).await.unwrap();
    assert_eq!(meta(&other, "Foo").as_deref(), Some("1"));
    let remotes = meta(&other, "KPXC_REMOTE_SYNC_SETTINGS").unwrap();
    assert!(remotes.contains("backup") && !remotes.contains("syncServer"), "{remotes}");

    // Merged into a vault: the items it lacks, never the remote settings
    target.set_meta_custom_data("Mine".into(), Some("kept".into())).unwrap();
    target.sync(SyncOptions::default(), nc()).await.unwrap();
    a.import_kdbx(bytes, creds("pw"), ImportMode::Merge { vault_id: target.id() }, nc()).await.unwrap();
    let merged = second_device(&s, &kit).await.open_vault(target.id(), nc()).await.unwrap();
    assert_eq!(meta(&merged, "Foo").as_deref(), Some("1"));
    assert_eq!(meta(&merged, "Mine").as_deref(), Some("kept"));
    assert_eq!(meta(&merged, "KPXC_REMOTE_SYNC_SETTINGS"), None);
}

#[tokio::test]
async fn sync_merges_database_custom_data_three_ways() {
    let s = servers();
    let (_a, kit, v, _) = account_with_vault(&s, false).await;
    v.set_meta_custom_data("Shared".into(), Some("v1".into())).unwrap();
    v.set_meta_custom_data("Doomed".into(), Some("x".into())).unwrap();
    v.sync(SyncOptions::default(), nc()).await.unwrap();
    let b = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();

    // B adds one item and removes another; A changes a third thing meanwhile
    s.clock().advance(2_000);
    b.set_meta_custom_data("FromB".into(), Some("b".into())).unwrap();
    b.set_meta_custom_data("Doomed".into(), None).unwrap();
    b.sync(SyncOptions::default(), nc()).await.unwrap();
    v.set_meta_custom_data("FromA".into(), Some("a".into())).unwrap();
    v.sync(SyncOptions::default(), nc()).await.unwrap();

    for (who, h) in [
        ("A", &v),
        ("B", &{
            b.sync(SyncOptions { local_changed: false, accept_server_state: false }, nc()).await.unwrap();
            b.clone()
        }),
    ] {
        assert_eq!(meta(h, "FromB").as_deref(), Some("b"), "{who}");
        assert_eq!(meta(h, "FromA").as_deref(), Some("a"), "{who}");
        assert_eq!(meta(h, "Shared").as_deref(), Some("v1"), "{who}");
        assert_eq!(meta(h, "Doomed"), None, "{who}");
    }
}

// ------------------------------------------------------------------ 12. open_vault: one GET

#[tokio::test]
async fn opening_a_vault_with_nothing_local_is_one_get() {
    let s = servers();
    let (_a, kit, v, _) = account_with_vault(&s, false).await;
    let b = second_device(&s, &kit).await;
    let gets = |s: &TestServers| {
        s.requests()
            .iter()
            .filter(|r| {
                r.server == Server::Sync && r.method == Method::Get && r.path.ends_with(&format!("/vaults/{}", v.id()))
            })
            .count()
    };
    let before = gets(&s);
    let opened = b.open_vault(v.id(), nc()).await.unwrap();
    assert_eq!(gets(&s) - before, 1);
    assert_eq!(titles(&opened), ["Mail"]);
    // and it syncs from that state: nothing new is Unchanged
    let r = opened.sync(SyncOptions { local_changed: false, accept_server_state: false }, nc()).await.unwrap();
    assert_eq!(r.outcome, SyncOutcome::Unchanged);
}

// ------------------------------------------------------------------ 6. older iOS asks

fn activate_fails(vault_id: &str, version: u32) -> FaultRule {
    FaultRule::new(Fault::Status(500))
        .server(Server::Auth)
        .method(Method::Post)
        .path(&format!("/vaults/{vault_id}/keys/{version}/activate"))
}

#[tokio::test]
async fn a_rotation_left_pending_by_this_account_is_finished_first() {
    let s = servers();
    let (a, kit, v, _) = account_with_vault(&s, false).await;
    s.fail_next(activate_fails(&v.id(), 2));
    a.rotate_vault_key(v.id(), vec![], nc()).await.unwrap_err();
    let info = a.vaults(nc()).await.unwrap().into_iter().find(|i| i.id == v.id()).unwrap();
    assert_eq!((info.current_key_version, info.pending_key_version), (1, Some(2)));

    // Another device of the same account rotates: version 2 is finished, then 3 is made
    let other = second_device(&s, &kit).await;
    other.rotate_vault_key(v.id(), vec![], nc()).await.unwrap();
    let info = other.vaults(nc()).await.unwrap().into_iter().find(|i| i.id == v.id()).unwrap();
    assert_eq!((info.current_key_version, info.pending_key_version, info.name.as_str()), (3, None, "Home"));
    let opened = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();
    assert_eq!(titles(&opened), ["Mail"]);
}

#[tokio::test]
async fn another_members_pending_rotation_is_rotation_pending_until_24_hours_pass() {
    let s = servers();
    let (a, _kit, v, _) = account_with_vault(&s, false).await;
    assert!(s.start_pending_rotation(&v.id(), 2));
    let e = a.rotate_vault_key(v.id(), vec![], nc()).await.unwrap_err();
    assert_eq!((e.code, e.wire_code(), e.status), (OvErrorCode::Conflict, "rotation_pending", Some(409)));

    s.clock().advance(25 * 3_600_000);
    a.rotate_vault_key(v.id(), vec![], nc()).await.unwrap();
    let info = a.vaults(nc()).await.unwrap().into_iter().find(|i| i.id == v.id()).unwrap();
    assert_eq!((info.current_key_version, info.pending_key_version), (2, None));
    assert_eq!(titles(&a.open_vault(v.id(), nc()).await.unwrap()), ["Mail"]);
}

#[tokio::test]
async fn sharing_to_confirmed_keys_refuses_changed_ones() {
    let s = servers();
    let (a, _kit, v, _) = account_with_vault(&s, false).await;
    let bob = connect(&device(&s, false), &s).await;
    register(&bob, "bob@example.com", "bob pw").await;
    let shown = a.look_up("bob@example.com".into(), nc()).await.unwrap();

    let mut stale = shown.public_keys.clone();
    stale.enc_pk[0] ^= 1;
    let e = a
        .share_vault_with_keys(v.id(), Grantee::Email("bob@example.com".into()), VaultRole::Read, stale, nc())
        .await
        .unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidPublicKeys);
    assert_eq!(a.members(v.id(), nc()).await.unwrap().len(), 1, "nothing was granted");

    let g = a
        .share_vault_with_keys(
            v.id(),
            Grantee::Email("bob@example.com".into()),
            VaultRole::Read,
            shown.public_keys,
            nc(),
        )
        .await
        .unwrap();
    assert_eq!(g.fingerprint, bob.fingerprint().unwrap());
    assert_eq!(titles(&bob.open_vault(v.id(), nc()).await.unwrap()), ["Mail"]);
}

async fn paired(s: &TestServers) -> SelfHosted {
    let url = s.sync_url().trim_end_matches("/api/v1").to_owned();
    s.add_device_token("dev-1", "alice");
    SelfHosted::connect(device(s, false), url, b"dev-1".to_vec()).unwrap()
}

#[tokio::test]
async fn self_hosted_downloads_a_database_without_its_key() {
    let s = servers();
    let sh = paired(&s).await;
    assert_eq!(sh.download("home".into(), nc()).await.unwrap(), None);
    let v = Vault::create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    add_entry(&v, "Wifi", "w");
    let first = sh.sync_database("home".into(), v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    let got = sh.download("home".into(), nc()).await.unwrap().expect("a copy");
    assert_eq!(got, s.database_blob("home").unwrap().data, "the server's bytes");
    assert_eq!(first.report.outcome, SyncOutcome::Created);
    let opened = Vault::open_local(got, creds("pw"), nc()).await.unwrap();
    assert_eq!(titles(&opened), ["Wifi"]);
}

fn health_answers(status: u16, content_type: &str, body: &str) -> FaultRule {
    FaultRule::new(Fault::Response(HttpResponse {
        status,
        headers: vec![("content-type".into(), content_type.into())],
        body: body.as_bytes().to_vec(),
    }))
    .server(Server::Sync)
    .path("/health")
}

#[tokio::test]
async fn self_hosted_health_says_when_an_address_is_not_a_sync_server() {
    let s = servers();
    let sh = paired(&s).await;
    assert!(sh.health(nc()).await.unwrap().contains("\"status\""));

    for (status, ct, body) in [
        (404, "text/html", "<html>Not found</html>"),
        (200, "text/html", "<html>Welcome</html>"),
        (200, "application/json", r#"{"hello":"world"}"#),
        (401, "application/json", r#"{"message":"login"}"#),
    ] {
        s.fail_next(health_answers(status, ct, body));
        let e = sh.health(nc()).await.unwrap_err();
        assert_eq!((e.wire_code(), e.status), ("not_sync_server", Some(status)), "{status} {body}");
    }
    // Unreachable stays unreachable; the sync server's own error stays its own
    s.fail_next(health_answers(503, "text/html", "<html>down</html>"));
    assert!(sh.health(nc()).await.unwrap_err().is_unreachable());
    s.fail_next(health_answers(429, "application/json", r#"{"error":"slow down","code":"rate_limited"}"#));
    assert_eq!(sh.health(nc()).await.unwrap_err().code, OvErrorCode::RateLimited);
    s.fail_next(FaultRule::new(Fault::Offline).server(Server::Sync).path("/health"));
    assert_eq!(sh.health(nc()).await.unwrap_err().code, OvErrorCode::NetworkError);
}

#[tokio::test]
async fn deletion_errors_carry_their_details() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let org = a.create_org("Acme".into(), nc()).await.unwrap();
    let bob = connect(&device(&s, false), &s).await;
    register(&bob, "bob@example.com", "pw").await;
    assert!(s.add_member(&org.id, "bob@example.com", "member"));
    let m =
        a.org_members(org.id.clone(), nc()).await.unwrap().into_iter().find(|m| m.email == "bob@example.com").unwrap();
    a.confirm_member(org.id.clone(), m, vec![], nc()).await.unwrap();
    let e = a.delete_account(b"pw".to_vec(), "alice@example.com".into(), nc()).await.unwrap_err();
    assert_eq!(e.wire_code(), "deletion_blocked");
    let d: serde_json::Value = serde_json::from_str(e.details.as_deref().expect("details")).unwrap();
    assert_eq!(d["orgs"][0]["id"], org.id.as_str());

    let a = connect(&device(&s, false), &s).await;
    register(&a, "carol@example.com", "pw").await;
    let at = a.delete_account(b"pw".to_vec(), "carol@example.com".into(), nc()).await.unwrap();
    login(&a, "carol@example.com", "pw", None).await;
    let e = a.create_vault("New".into(), None, nc()).await.unwrap_err();
    assert_eq!((e.wire_code(), e.status), ("account_pending_deletion", Some(403)));
    let d: serde_json::Value = serde_json::from_str(e.details.as_deref().expect("details")).unwrap();
    assert_eq!(d["scheduledFor"], at.as_str());
}

// ------------------------------------------------------------------ 9, 10. SA vault files, profile

#[tokio::test]
async fn a_service_account_syncs_a_vault_file() {
    let s = servers();
    let (a, kit, v, _) = account_with_vault(&s, false).await;
    let org = a.create_org("Acme".into(), nc()).await.unwrap();
    let created = a
        .create_service_account(
            org.id,
            NewServiceAccount {
                name: "ci".into(),
                vaults: vec![VaultGrantRequest { vault_id: v.id(), role: VaultRole::Write }],
                expires_at: None,
                secret_name: None,
            },
            nc(),
        )
        .await
        .unwrap();
    let sa = ServiceAccount::from_token(device(&s, false), created.token, nc()).await.unwrap();
    let file_creds = sa.vault_kdbx_credentials(v.id(), nc()).await.unwrap();
    let server_copy = s.vault_blob(&v.id()).unwrap().data;
    let file = Vault::open_local(server_copy.clone(), file_creds.clone(), nc()).await.unwrap();
    add_entry(&file, "From CI", "c");
    let edited = file.save_local(nc()).await.unwrap();
    let r = sa.sync_vault_kdbx(v.id(), edited, Some(server_copy), SyncOptions::default(), nc()).await.unwrap();
    assert_eq!(r.report.outcome, SyncOutcome::Uploaded);
    assert_eq!(r.credentials, file_creds);
    let back = Vault::open_local(r.kdbx, r.credentials, nc()).await.unwrap();
    assert_eq!(titles(&back), ["From CI", "Mail"]);
    let opened = second_device(&s, &kit).await.open_vault(v.id(), nc()).await.unwrap();
    assert_eq!(titles(&opened), ["From CI", "Mail"]);
}

#[tokio::test]
async fn the_profile_carries_the_kdf_and_the_keyset_public_keys() {
    let s = servers();
    let (a, _kit, _v, _) = account_with_vault(&s, false).await;
    let p = a.me(nc()).await.unwrap();
    assert_eq!((p.kdf.alg.as_str(), p.kdf.m, p.kdf.t), ("argon2id", KDF.m.unwrap(), KDF.t.unwrap()));
    assert_eq!(p.public_keys.fingerprint, a.fingerprint().unwrap());
    assert_eq!(p.public_keys.enc_pk.len(), 32);
}
