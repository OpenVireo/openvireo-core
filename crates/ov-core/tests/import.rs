//! SDK `import.test.ts` at the facade level: importing a `.kdbx` into an account by merge and as
//! copies (the merge rules themselves are tested in ov-merge).

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

fn creds() -> KdbxCredentials {
    KdbxCredentials { password: Some(b"file".to_vec()), key_file: None, password_hash: None }
}

async fn file_with(title: &str) -> Vec<u8> {
    let v = Vault::create_local("Imported File".into(), creds(), nc()).await.unwrap();
    add_entry(&v, title, "p");
    v.save_local(nc()).await.unwrap()
}

#[tokio::test]
async fn merges_a_file_into_a_vault_and_twice_changes_nothing() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let v = a.create_vault("Target".into(), None, nc()).await.unwrap();
    let bytes = file_with("From file").await;
    let out = a.import_kdbx(bytes.clone(), creds(), ImportMode::Merge { vault_id: v.id() }, nc()).await.unwrap();
    assert!(out.uploaded);
    assert_eq!(out.vault.name(), "Target");
    assert_eq!(field(&find_title(&out.vault, "From file"), "Password"), b"p");
    let again = a.import_kdbx(bytes, creds(), ImportMode::Merge { vault_id: v.id() }, nc()).await.unwrap();
    assert_eq!(again.vault.entries(false).len(), 1);
}

#[tokio::test]
async fn imports_as_copies_under_a_group_named_after_the_file() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let v = a.create_vault("Target".into(), None, nc()).await.unwrap();
    let bytes = file_with("Copy me").await;
    for _ in 0..2 {
        a.import_kdbx(bytes.clone(), creds(), ImportMode::Copies { vault_id: v.id() }, nc()).await.unwrap();
    }
    let opened = a.open_vault(v.id(), nc()).await.unwrap();
    let copies: Vec<_> = opened.entries(false).into_iter().filter(|e| e.title == "Copy me").collect();
    assert_eq!(copies.len(), 2);
    assert_ne!(copies[0].id, copies[1].id);
    assert_eq!(copies[0].group_path, vec!["Imported File".to_owned()]);
}

#[tokio::test]
async fn a_wrong_file_password_is_a_vault_key_mismatch() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let bytes = file_with("x").await;
    let bad = KdbxCredentials { password: Some(b"nope".to_vec()), key_file: None, password_hash: None };
    let e = a.import_kdbx(bytes, bad, ImportMode::NewVault { name: None, org_id: None }, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::VaultKeyMismatch);
}

fn pw_creds(pw: &str) -> KdbxCredentials {
    KdbxCredentials { password: Some(pw.as_bytes().to_vec()), ..Default::default() }
}

/// "importing the same file twice changes nothing", with entries that have history: edits a minute
/// apart, and edits within one second (history items with the same time).
#[tokio::test]
async fn re_importing_entries_with_history_changes_nothing() {
    for step_ms in [60_000, 0] {
        re_import(step_ms).await;
    }
}

async fn re_import(step_ms: i64) {
    let s = servers();
    let c = device(&s, false);
    let src = c.create_local("Home".into(), pw_creds("pw"), nc()).await.unwrap();
    add_entry(&src, "Mail", "m1");
    for pw in ["m2", "m3"] {
        s.clock().advance(step_ms);
        let id = find_title(&src, "Mail").id;
        let input = FieldInput { name: "Password".into(), value: pw.as_bytes().to_vec(), protected: None };
        src.edit_entry(id, EntryInput { fields: vec![input], ..Default::default() }).unwrap();
    }
    let mail = find_title(&src, "Mail").id;
    assert_eq!(src.history(mail.clone()).unwrap().len(), 2);
    let src = c.open_local(src.save_local(nc()).await.unwrap(), pw_creds("pw"), nc()).await.unwrap();

    let target = c.create_local("Work".into(), pw_creds("work"), nc()).await.unwrap();
    let first = target.import_from(src.clone(), LocalImportMode::Merge).unwrap();
    assert_eq!((first.added, first.updated, first.unchanged), (1, 0, 0));
    let again = target.import_from(src.clone(), LocalImportMode::Merge).unwrap();
    assert_eq!((again.added, again.updated, again.unchanged), (0, 0, 1), "{:?}", again.changes);
    assert!(again.changes.is_empty());
    assert_eq!(target.history(mail.clone()).unwrap().len(), 2);

    // After a save and reopen of the target too
    let target = c.open_local(target.save_local(nc()).await.unwrap(), pw_creds("work"), nc()).await.unwrap();
    let third = target.import_from(src, LocalImportMode::Merge).unwrap();
    assert_eq!((third.added, third.updated, third.unchanged), (0, 0, 1), "{:?}", third.changes);
}
