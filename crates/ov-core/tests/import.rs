//! SDK `import.test.ts` at the facade level: importing a `.kdbx` into an account by merge and as
//! copies (the merge rules themselves are tested in ov-merge).

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

fn creds() -> KdbxCredentials {
    KdbxCredentials { password: Some(b"file".to_vec()), key_file: None }
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
async fn a_wrong_file_password_is_a_kdbx_error() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let bytes = file_with("x").await;
    let bad = KdbxCredentials { password: Some(b"nope".to_vec()), key_file: None };
    let e = a.import_kdbx(bytes, bad, ImportMode::NewVault { name: None, org_id: None }, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::KdbxError);
}
