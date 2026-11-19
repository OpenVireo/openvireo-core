//! contract-v1.6 additions (docs/adr/0001-contract.md § contract-v1.6): entry last use, colours,
//! custom icons and field order, caller-chosen ids, attachment protection, every record in one call,
//! importing between open vaults, local-file metadata and KDFs, self-hosted version history, the
//! service account's server and local vaults on the Host clock. Account, SA and self-hosted cases run
//! against W2-E's in-memory servers.

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use ov_kdbx::model::{Argon2Type, Kdf};
use servers_common::*;

fn creds(pw: &str) -> KdbxCredentials {
    KdbxCredentials { password: Some(pw.as_bytes().to_vec()), key_file: None }
}

fn text(name: &str, value: &str) -> FieldInput {
    FieldInput { name: name.into(), value: value.as_bytes().to_vec(), protected: None }
}

async fn local(name: &str) -> Vault {
    Vault::create_local(name.into(), creds("pw"), nc()).await.unwrap()
}

/// The KDF a `.kdbx` was saved with.
fn kdf_of(bytes: &[u8], pw: &str) -> Kdf {
    let key = ov_kdbx::vault::password_credentials(Some(pw), None);
    ov_kdbx::read(bytes, &key).unwrap().header.kdf
}

#[tokio::test]
async fn entries_report_last_use_and_every_record_comes_in_one_call() {
    let v = local("Home").await;
    let a = add_entry(&v, "Mail", "one");
    add_entry(&v, "Bank", "two");
    let s = v.entries(false);
    assert!(s.iter().all(|e| e.usage_count == 0 && e.last_access_at.is_none()));

    // A file another app used: UsageCount 3, LastAccessTime set.
    let bytes = v.save_local(nc()).await.unwrap();
    let key = ov_kdbx::vault::password_credentials(Some("pw"), None);
    let mut db = ov_kdbx::read(&bytes, &key).unwrap();
    let uid = ov_kdbx::entries::parse_uuid_string(&a).unwrap();
    let e = ov_kdbx::entries::find_entry_mut(&mut db.root, uid).unwrap();
    e.times.usage_count = 3;
    e.times.last_access = 1_700_000_123;
    let v = Vault::open_local(ov_kdbx::write(&db, &key).unwrap(), creds("pw"), nc()).await.unwrap();
    let mail = v.entries(false).into_iter().find(|e| e.id == a).unwrap();
    assert_eq!((mail.usage_count, mail.last_access_at), (3, Some(1_700_000_123)));
    let rec = v.entry(a.clone()).unwrap();
    assert_eq!((rec.usage_count, rec.last_access_at), (3, Some(1_700_000_123)));

    // entry_records == entry() for each entry, in entries() order; the Recycle Bin only on request.
    let records = v.entry_records(false);
    let ids: Vec<String> = v.entries(false).into_iter().map(|e| e.id).collect();
    assert_eq!(records.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), ids);
    for r in &records {
        assert_eq!(*r, v.entry(r.id.clone()).unwrap());
    }
    v.delete_entry(a.clone()).unwrap();
    assert_eq!(v.entry_records(false).len(), 1);
    assert_eq!(v.entry_records(true).len(), 2);
}

#[tokio::test]
async fn edits_set_colours_custom_icons_and_field_order() {
    let v = local("Home").await;
    let icon = v.add_custom_icon(vec![0x89, b'P', b'N', b'G']).unwrap();
    let id = v
        .add_entry(
            v.root_group_id(),
            EntryInput {
                fields: vec![text("Title", "Mail"), text("Zeta", "z"), text("Alpha", "a"), text("Mid", "m")],
                foreground_color: Some("#FF0000".into()),
                background_color: Some("#00ff00".into()),
                custom_icon: Some(Some(icon.clone())),
                field_order: Some(vec!["Mid".into(), "Zeta".into(), "Nope".into()]),
                ..Default::default()
            },
        )
        .unwrap();
    let e = v.entry(id.clone()).unwrap();
    assert_eq!((e.foreground_color.as_str(), e.background_color.as_str()), ("#FF0000", "#00ff00"));
    assert_eq!(e.custom_icon.as_deref(), Some(icon.as_str()));
    let names: Vec<&str> = e.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["Title", "UserName", "Password", "URL", "Notes", "Mid", "Zeta", "Alpha"]);

    // Reorder, clear the icon and one colour; history keeps the old version.
    v.edit_entry(
        id.clone(),
        EntryInput {
            custom_icon: Some(None),
            background_color: Some(String::new()),
            field_order: Some(vec!["Alpha".into(), "Zeta".into(), "Mid".into(), "Title".into()]),
            ..Default::default()
        },
    )
    .unwrap();
    let e = v.entry(id.clone()).unwrap();
    assert_eq!((e.custom_icon.as_deref(), e.background_color.as_str()), (None, ""));
    assert_eq!(e.foreground_color, "#FF0000");
    let names: Vec<&str> = e.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["Title", "UserName", "Password", "URL", "Notes", "Alpha", "Zeta", "Mid"]);
    assert_eq!(e.history_count, 1);

    // Survives a save.
    let again = Vault::open_local(v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    assert_eq!(again.entry(id.clone()).unwrap(), e);

    // Bad input changes nothing.
    let bad = EntryInput { foreground_color: Some("red".into()), ..Default::default() };
    assert_eq!(v.edit_entry(id.clone(), bad).unwrap_err().code, OvErrorCode::InvalidRequest);
    let bad = EntryInput { custom_icon: Some(Some("ab".repeat(16))), ..Default::default() };
    assert_eq!(v.edit_entry(id.clone(), bad).unwrap_err().code, OvErrorCode::NotFound);
    assert_eq!(v.entry(id).unwrap(), e);
}

#[tokio::test]
async fn adds_an_entry_with_a_chosen_id() {
    let v = local("Home").await;
    let want = "0123456789abcdef0123456789abcdef";
    let dashed = "01234567-89AB-CDEF-0123-456789ABCDEF";
    let input = EntryInput { fields: vec![text("Title", "Mine")], ..Default::default() };
    assert_eq!(v.add_entry_with_id(dashed.into(), v.root_group_id(), input.clone()).unwrap(), want);
    assert_eq!(v.entry(want.into()).unwrap().fields[0].value, b"Mine");
    let e = v.add_entry_with_id(want.into(), v.root_group_id(), input.clone()).unwrap_err();
    assert_eq!(e.code, OvErrorCode::Conflict);
    let e = v.add_entry_with_id("nope".into(), v.root_group_id(), input.clone()).unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidRequest);
    let e = v.add_entry_with_id("00".repeat(16), v.root_group_id(), input.clone()).unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidRequest);
    let e = v.add_entry_with_id("11".repeat(16), "22".repeat(16), input.clone()).unwrap_err();
    assert_eq!(e.code, OvErrorCode::NotFound);

    // Deleted for good, then added again with the same id: the deletion record goes.
    v.delete_entry(want.into()).unwrap(); // into the Recycle Bin
    v.delete_entry(want.into()).unwrap(); // for good
    let bytes = v.save_local(nc()).await.unwrap();
    let key = ov_kdbx::vault::password_credentials(Some("pw"), None);
    let uid = ov_kdbx::entries::parse_uuid_string(want).unwrap();
    assert!(ov_kdbx::read(&bytes, &key).unwrap().deleted_objects.iter().any(|d| d.uuid == uid));
    v.add_entry_with_id(want.into(), v.root_group_id(), input).unwrap();
    let bytes = v.save_local(nc()).await.unwrap();
    assert!(!ov_kdbx::read(&bytes, &key).unwrap().deleted_objects.iter().any(|d| d.uuid == uid));
}

#[tokio::test]
async fn attachments_keep_their_protected_flag() {
    let v = local("Home").await;
    let id = add_entry(&v, "Files", "pw");
    v.set_attachment_with(id.clone(), "plain.txt".into(), b"hello".to_vec(), Some(false)).unwrap();
    v.set_attachment(id.clone(), "secret.bin".into(), b"s3cret".to_vec()).unwrap();
    let flags = |v: &Vault| -> Vec<(String, u64, bool)> {
        v.entry(id.clone()).unwrap().attachments.into_iter().map(|a| (a.name, a.size, a.protected)).collect()
    };
    assert_eq!(flags(&v), [("plain.txt".into(), 5, false), ("secret.bin".into(), 6, true)]);
    // `None` keeps the replaced attachment's flag.
    v.set_attachment_with(id.clone(), "plain.txt".into(), b"hello!".to_vec(), None).unwrap();
    v.set_attachment_with(id.clone(), "new.bin".into(), b"n".to_vec(), None).unwrap();
    assert_eq!(
        flags(&v),
        [("secret.bin".into(), 6, true), ("plain.txt".into(), 6, false), ("new.bin".into(), 1, true)]
    );
    let again = Vault::open_local(v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    assert_eq!(flags(&again), flags(&v));
    assert_eq!(again.attachment(id, "plain.txt".into()).unwrap(), b"hello!");
}

#[tokio::test]
async fn imports_one_open_vault_into_another() {
    let source = local("Work").await;
    add_entry(&source, "VPN", "v");
    let sub = source.ensure_group("Servers/Prod".into()).unwrap();
    source.add_entry(sub, EntryInput { fields: vec![text("Title", "db")], ..Default::default() }).unwrap();
    let gone = add_entry(&source, "Old", "o");
    source.delete_entry(gone).unwrap(); // the Recycle Bin is never imported
    assert_eq!(source.import_preview(), ImportPreview { entries: 2, groups: 2 });

    let target = local("Home").await;
    add_entry(&target, "Mail", "m");
    let into = target.ensure_group("Imported".into()).unwrap();
    let targets = target.import_targets();
    assert_eq!(targets[0], ImportTarget { group_id: target.root_group_id(), path: "Home".into() });
    assert!(targets.iter().any(|t| t.group_id == into && t.path == "Home / Imported"));

    // Copies under a chosen group: fresh ids, the source unchanged.
    let before = source.entry_records(true);
    let r =
        target.import_from(source.clone(), LocalImportMode::Copies { parent_group_id: Some(into.clone()) }).unwrap();
    assert_eq!((r.added, r.updated, r.unchanged, r.groups_added), (2, 0, 0, 3));
    assert!(!r.changes.is_empty());
    assert_eq!(source.entry_records(true), before);
    let vpn = target.entries(false).into_iter().find(|e| e.title == "VPN").unwrap();
    assert_eq!(vpn.group_path, ["Imported", "Work"]);
    assert!(before.iter().all(|b| b.id != vpn.id));

    // Merge by UUID: twice changes nothing the second time.
    let merged = local("Home2").await;
    let r = merged.import_from(source.clone(), LocalImportMode::Merge).unwrap();
    assert_eq!((r.added, r.updated), (2, 0));
    let r = merged.import_from(source.clone(), LocalImportMode::Merge).unwrap();
    assert_eq!((r.added, r.updated, r.unchanged), (0, 0, 2));
    assert!(merged.entries(false).iter().any(|e| e.title == "db" && e.group_path == ["Servers", "Prod"]));

    // A vault can import itself as copies (no deadlock).
    let r = source.import_from(source.clone(), LocalImportMode::Copies { parent_group_id: None }).unwrap();
    assert_eq!(r.added, 2);
    let e = target.import_from(source, LocalImportMode::Copies { parent_group_id: Some("33".repeat(16)) });
    assert_eq!(e.unwrap_err().code, OvErrorCode::NotFound);
}

#[tokio::test]
async fn local_metadata_copies_and_kdf_choices() {
    let v = local("Home").await;
    add_entry(&v, "Mail", "m");
    v.set_name("Family".into()).unwrap();
    assert_eq!(v.name(), "Family");
    assert_eq!(v.meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS".into()), None);
    let remotes = r#"[{"type":"syncServer","url":"https://sync.example"},{"type":"command","name":"rsync"}]"#;
    v.set_meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS".into(), Some(remotes.into())).unwrap();
    v.set_meta_custom_data("Other".into(), Some("x".into())).unwrap();
    v.set_meta_custom_data("Other".into(), None).unwrap();
    assert_eq!(v.meta_custom_data("Other".into()), None);
    let reopened = Vault::open_local(v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    assert_eq!(reopened.name(), "Family");
    assert_eq!(reopened.meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS".into()).as_deref(), Some(remotes));

    // A copy keeps its own credentials, drops server remotes (command remotes stay), and is separate.
    let copy = v.copy_without_remotes(None).unwrap();
    let kept = copy.meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS".into()).unwrap();
    assert!(kept.contains("rsync") && !kept.contains("syncServer"), "{kept}");
    copy.set_name("Copy".into()).unwrap();
    assert_eq!(v.name(), "Family");
    let bytes = copy.save_local(nc()).await.unwrap();
    assert_eq!(Vault::open_local(bytes, creds("pw"), nc()).await.unwrap().name(), "Copy");
    // ... or new credentials.
    let other = v.copy_without_remotes(Some(creds("other"))).unwrap();
    assert!(Vault::open_local(other.save_local(nc()).await.unwrap(), creds("other"), nc()).await.is_ok());

    // KDF choices.
    v.set_kdf(KdbxKdf::Argon2id { memory: 2 * 1024 * 1024, iterations: 3, parallelism: 2 }).unwrap();
    match kdf_of(&v.save_local(nc()).await.unwrap(), "pw") {
        Kdf::Argon2 { kind, memory, iterations, parallelism, .. } => {
            assert_eq!((kind, memory, iterations, parallelism), (Argon2Type::Id, 2 * 1024 * 1024, 3, 2))
        }
        k => panic!("{k:?}"),
    }
    v.set_kdf(KdbxKdf::AesKdf { rounds: 1000 }).unwrap();
    assert!(matches!(kdf_of(&v.save_local(nc()).await.unwrap(), "pw"), Kdf::AesKdf { rounds: 1000, .. }));
    let bad = KdbxKdf::Argon2d { memory: 4096, iterations: 1, parallelism: 1 };
    assert_eq!(v.set_kdf(bad).unwrap_err().code, OvErrorCode::InvalidRequest);
    let bad = KdbxKdf::Argon2d { memory: 1 << 20, iterations: 0, parallelism: 1 };
    assert_eq!(v.set_kdf(bad).unwrap_err().code, OvErrorCode::InvalidRequest);
    assert_eq!(v.set_kdf(KdbxKdf::AesKdf { rounds: 0 }).unwrap_err().code, OvErrorCode::InvalidRequest);

    // Export with a chosen KDF; the plain export keeps kdbxweb's.
    let kdf = KdbxKdf::Argon2d { memory: 1 << 20, iterations: 4, parallelism: 1 };
    let out = v.export_kdbx_with(creds("ex"), None, kdf, nc()).await.unwrap();
    assert!(matches!(kdf_of(&out, "ex"), Kdf::Argon2 { kind: Argon2Type::D, iterations: 4, .. }));
    let out = v.export_kdbx(creds("ex"), None, nc()).await.unwrap();
    assert!(matches!(kdf_of(&out, "ex"), Kdf::Argon2 { kind: Argon2Type::D, iterations: 2, memory: 1_048_576, .. }));
}

#[tokio::test]
async fn account_vaults_refuse_local_only_edits_and_copy_with_the_database_default_kdf() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "kit@example.com", "pw kit").await;
    let vault = a.create_vault("Shared".into(), None, nc()).await.unwrap();
    add_entry(&vault, "Mail", "m");
    assert_eq!(vault.set_name("x".into()).unwrap_err().code, OvErrorCode::InvalidRequest);
    assert_eq!(vault.set_kdf(KdbxKdf::DatabaseDefault).unwrap_err().code, OvErrorCode::InvalidRequest);
    assert_eq!(vault.copy_without_remotes(None).unwrap_err().code, OvErrorCode::InvalidRequest);
    // Custom data is fine on an account vault (it syncs).
    vault.set_meta_custom_data("Note".into(), Some("hi".into())).unwrap();
    assert_eq!(vault.meta_custom_data("Note".into()).as_deref(), Some("hi"));

    let copy = vault.copy_without_remotes(Some(creds("file pw"))).unwrap();
    assert!(copy.info().is_none() && !copy.is_read_only());
    let bytes = copy.save_local(nc()).await.unwrap();
    match kdf_of(&bytes, "file pw") {
        Kdf::Argon2 { kind, memory, iterations, parallelism, .. } => {
            assert_eq!((kind, memory, iterations, parallelism), (Argon2Type::D, 64 << 20, 10, 2))
        }
        k => panic!("{k:?}"),
    }
    let opened = Vault::open_local(bytes, creds("file pw"), nc()).await.unwrap();
    assert_eq!(field(&find_title(&opened, "Mail"), "Password"), b"m");

    // An old version is read-only, but a copy of it is a normal local file.
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    let rev = a.vault_history(vault.id(), nc()).await.unwrap()[0].revision;
    let old = a.open_vault_version(vault.id(), rev, nc()).await.unwrap();
    assert_eq!(old.import_from(vault.clone(), LocalImportMode::Merge).unwrap_err().code, OvErrorCode::InvalidRequest);
    let c = old.copy_without_remotes(Some(creds("v"))).unwrap();
    add_entry(&c, "New", "n");

    // Importing an account vault into a local file (and back) works on open handles.
    let home = local("Home").await;
    home.import_from(vault.clone(), LocalImportMode::Merge).unwrap();
    assert_eq!(field(&find_title(&home, "Mail"), "Password"), b"m");
    add_entry(&home, "Local only", "l");
    let r = vault.import_from(home, LocalImportMode::Copies { parent_group_id: None }).unwrap();
    assert_eq!(r.added, 2);
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
}

#[tokio::test]
async fn self_hosted_history_and_versions() {
    let s = servers();
    let c = device(&s, false);
    let url = s.sync_url().trim_end_matches("/api/v1").to_owned();
    s.add_device_token("dev-1", "alice");
    let sh = SelfHosted::connect(c.clone(), url, b"dev-1".to_vec()).unwrap();
    let local = c.create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    add_entry(&local, "Wifi", "first");
    let r1 = sh.sync_database("home".into(), local.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    let v1 = c.open_local(r1.kdbx, creds("pw"), nc()).await.unwrap();
    s.clock().advance(5_000);
    let id = find_title(&v1, "Wifi").id;
    v1.edit_entry(id.clone(), EntryInput { fields: vec![text("Password", "second")], ..Default::default() }).unwrap();
    sh.sync_database("home".into(), v1.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();

    let history = sh.history("home".into(), nc()).await.unwrap();
    assert_eq!(history.len(), 2, "{history:?}");
    assert_eq!(history.iter().filter(|h| h.is_current).count(), 1);
    let oldest = history.iter().min_by_key(|h| h.revision).unwrap();
    let old = sh.open_version("home".into(), oldest.revision, creds("pw"), nc()).await.unwrap();
    assert!(old.is_read_only() && old.info().is_none());
    assert_eq!(field(&find_title(&old, "Wifi"), "Password"), b"first");
    assert_eq!(
        old.add_entry(old.root_group_id(), EntryInput::default()).unwrap_err().code,
        OvErrorCode::InvalidRequest
    );
    let newest = history.iter().max_by_key(|h| h.revision).unwrap();
    let new = sh.open_version("home".into(), newest.revision, creds("pw"), nc()).await.unwrap();
    assert_eq!(field(&find_title(&new, "Wifi"), "Password"), b"second");
    assert_eq!(v1.version_difference(old.clone(), id).unwrap(), VersionDifference::Changed);

    let wrong = sh.open_version("home".into(), oldest.revision, creds("nope"), nc()).await.unwrap_err();
    assert_eq!(wrong.code, OvErrorCode::VaultKeyMismatch);
    assert!(sh.history("missing".into(), nc()).await.unwrap_or_default().is_empty());
}

#[tokio::test]
async fn a_service_account_reports_its_server() {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    register(&alice, "alice@example.com", "pw").await;
    let vault = alice.create_vault("Infra".into(), None, nc()).await.unwrap();
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let created = alice
        .create_service_account(
            org.id,
            NewServiceAccount {
                name: "ci".into(),
                vaults: vec![VaultGrantRequest { vault_id: vault.id(), role: VaultRole::Read }],
                expires_at: None,
                secret_name: None,
            },
            nc(),
        )
        .await
        .unwrap();
    // Discovered from the token's URL (the client has no server configured).
    let sa = ServiceAccount::from_token(device(&s, false), created.token, nc()).await.unwrap();
    assert_eq!(sa.issuer(), s.issuer());
    let config = sa.server_config();
    assert_eq!(config.issuer, s.issuer());
    assert_eq!(config.sync.trim_end_matches('/'), s.sync_url().trim_end_matches('/'));
}

#[tokio::test]
async fn local_vaults_from_the_client_use_the_host_clock() {
    let s = servers();
    let c = device(&s, false);
    let now_s = s.clock().now_unix_ms() / 1000;
    let v = c.create_local("Home".into(), creds("pw"), nc()).await.unwrap();
    let id = add_entry(&v, "Mail", "m");
    assert_eq!(v.entry(id.clone()).unwrap().modified_at, now_s);
    s.clock().advance(3_600_000);
    let v = c.open_local(v.save_local(nc()).await.unwrap(), creds("pw"), nc()).await.unwrap();
    v.edit_entry(id.clone(), EntryInput { fields: vec![text("Password", "n")], ..Default::default() }).unwrap();
    assert_eq!(v.entry(id).unwrap().modified_at, now_s + 3600);
    let wrong = c.open_local(v.save_local(nc()).await.unwrap(), creds("no"), nc()).await.unwrap_err();
    assert_eq!(wrong.code, OvErrorCode::KdbxError);
}

/// Light Argon2id so the test files open fast.
const LIGHT: KdbxKdf = KdbxKdf::Argon2id { memory: 1 << 20, iterations: 2, parallelism: 1 };

#[tokio::test]
async fn syncs_an_account_vault_held_as_kdbx_bytes() {
    let s = servers();
    let a = connect(&device(&s, true), &s).await; // offline data on: the sync state is cached
    let kit = register(&a, "desk@example.com", "pw desk").await;
    let vault = a.create_vault("Desk".into(), None, nc()).await.unwrap();
    add_entry(&vault, "Mail", "m");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    let id = vault.id();

    // The desktop's file: the vault under its vault key.
    let creds = a.vault_kdbx_credentials(id.clone(), nc()).await.unwrap();
    assert!(creds.password.is_none() && creds.key_file.as_ref().is_some_and(|k| k.len() == 32));
    let copy = vault.copy_without_remotes(Some(creds.clone())).unwrap();
    copy.set_kdf(LIGHT).unwrap();
    let file = copy.save_local(nc()).await.unwrap();

    // Nothing changed locally: nothing to upload.
    let r = a.sync_vault_kdbx(id.clone(), file, None, SyncOptions::default(), nc()).await.unwrap();
    assert!(matches!(r.report.outcome, SyncOutcome::Unchanged | SyncOutcome::Pulled), "{:?}", r.report.outcome);
    assert_eq!(r.credentials, creds);
    assert!(r.report.etag.is_some());

    // An edit in the file uploads; the vault handle sees it.
    let local = Vault::open_local(r.kdbx, r.credentials.clone(), nc()).await.unwrap();
    add_entry(&local, "From desktop", "d");
    let r = a
        .sync_vault_kdbx(id.clone(), local.save_local(nc()).await.unwrap(), None, SyncOptions::default(), nc())
        .await
        .unwrap();
    assert_eq!(r.report.outcome, SyncOutcome::Uploaded);
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&vault, "From desktop"), "Password"), b"d");

    // An edit on the other side comes down into the file.
    add_entry(&vault, "From web", "w");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    let r = a
        .sync_vault_kdbx(id.clone(), r.kdbx, None, SyncOptions { local_changed: false, ..Default::default() }, nc())
        .await
        .unwrap();
    assert_eq!(r.report.outcome, SyncOutcome::Pulled);
    let merged = Vault::open_local(r.kdbx.clone(), r.credentials.clone(), nc()).await.unwrap();
    assert_eq!(field(&find_title(&merged, "From web"), "Password"), b"w");

    // The server lost the vault: an error, then "continue anyway" uploads the file again.
    s.lose_vault(&id);
    let e = a.sync_vault_kdbx(id.clone(), r.kdbx.clone(), None, SyncOptions::default(), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerLostDatabase);
    let accept = SyncOptions { accept_server_state: true, ..Default::default() };
    let again = a.sync_vault_kdbx(id.clone(), r.kdbx, None, accept, nc()).await.unwrap();
    assert_eq!(again.report.outcome, SyncOutcome::Created);

    // A base passed in is used when there is no cached state (another device, offline data off).
    let b = connect(&device(&s, false), &s).await;
    login(&b, "desk@example.com", "pw desk", Some(&kit.secret_key)).await;
    let r = b.sync_vault_kdbx(id.clone(), again.kdbx.clone(), Some(again.kdbx.clone()), SyncOptions::default(), nc());
    assert!(r.await.is_ok());
    let e = b.sync_vault_kdbx(id, b"not a kdbx".to_vec(), None, SyncOptions::default(), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::KdbxError);
}

#[tokio::test]
async fn lends_the_session_token_and_refreshes_it() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "tok@example.com", "pw tok").await;
    let t1 = a.access_token(false, nc()).await.unwrap();
    assert_eq!(a.access_token(false, nc()).await.unwrap(), t1, "a valid token is reused");
    let t2 = a.access_token(true, nc()).await.unwrap();
    assert_ne!(t2, t1, "force_refresh refreshes");
    let jwt = String::from_utf8(t2).unwrap();
    assert_eq!(jwt.split('.').count(), 3);
    a.sign_out(false, nc()).await.unwrap();
    assert_eq!(a.access_token(false, nc()).await.unwrap_err().code, OvErrorCode::SignedOut);
}
