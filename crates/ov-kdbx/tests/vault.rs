//! The `vault_kdbx` vector, unknown-element passthrough, vault helpers and entry operations.

use ov_error::OvErrorCode;
use ov_kdbx::entries::{self, EntryData, EntryEdit, FieldValue};
use ov_kdbx::model::{Argon2Type, Kdf};
use ov_kdbx::vault::{self, KeyVersion};
use ov_kdbx::CompositeKey;
use ov_testkit::kdbx;
use zeroize::Zeroizing;

const NOW: i64 = 1_790_000_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn spike(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spikes/kdbx/files").join(name)).unwrap()
}

#[test]
fn vault_kdbx_vector() {
    let v = ov_testkit::test_vectors().vault_kdbx;
    let key = vault::vault_credentials(&hex(&v.vault_key_hex)).unwrap();
    let db = ov_kdbx::read(&kdbx::bytes(&v.file), &key).unwrap();
    match &db.header.kdf {
        Kdf::Argon2 { kind, memory, iterations, parallelism, .. } => {
            assert_eq!(v.kdf.alg, "argon2id");
            assert_eq!(*kind, Argon2Type::Id);
            assert_eq!(*memory, u64::from(v.kdf.m_kib) * 1024);
            assert_eq!(*iterations, u64::from(v.kdf.t));
            assert_eq!(*parallelism, v.kdf.p);
        }
        other => panic!("unexpected KDF {other:?}"),
    }
    let s = vault::kdf_settings(&db);
    assert_eq!((s.kdf.as_str(), s.m, s.t, s.p), ("argon2id", Some(1024 * 1024), Some(2), Some(1)));
    assert_eq!(db.root.name, v.expect.root_group);
    let e = entries::find_entry(&db.root, db.root.entries[0].uuid).unwrap();
    assert_eq!(e.field_text("Title"), v.expect.entry.title);
    assert_eq!(e.field_text("UserName"), v.expect.entry.user_name);
    assert_eq!(e.field_text("Password"), v.expect.entry.password);
    assert_eq!(e.field_text("URL"), v.expect.entry.url);
    assert!(e.field("Password").unwrap().protected);
}

#[test]
fn wrong_key_is_vault_key_mismatch() {
    let bytes = kdbx::bytes(kdbx::VAULT_FIXTURE);
    let e = ov_kdbx::read(&bytes, &CompositeKey::new().with_key_file(&[0u8; 32])).unwrap_err();
    assert_eq!(e.code, OvErrorCode::VaultKeyMismatch);
    let e = ov_kdbx::read(b"not a database at all", &CompositeKey::new().with_password("x")).unwrap_err();
    assert_eq!(e.code, OvErrorCode::KdbxError);
}

#[test]
fn unknown_elements_survive_two_saves_in_place() {
    let key = CompositeKey::new().with_password("spike pw");
    let mut bytes = spike("kdbxweb-unknown.kdbx");
    let original = ov_kdbx::read(&bytes, &key).unwrap();
    for _ in 0..2 {
        bytes = ov_kdbx::write(&ov_kdbx::read(&bytes, &key).unwrap(), &key).unwrap();
        let db = ov_kdbx::read(&bytes, &key).unwrap();
        assert_eq!(db, original);
        let names = |l: &[ov_kdbx::model::XmlElement]| l.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&db.unknown_file), ["ZzUnknownFile"]);
        assert_eq!(names(&db.unknown_root), ["ZzUnknownRoot"]);
        assert_eq!(names(&db.meta.unknown), ["ZzUnknownMeta"]);
        assert_eq!(db.meta.unknown[0].attributes, [("a".to_string(), "1".to_string())]);
        assert_eq!(db.meta.unknown[0].text, "meta-text");
        assert_eq!(db.meta.unknown[0].children[0].name, "Child");
        assert_eq!(db.meta.unknown[0].children[0].text, "nested");
        assert_eq!(names(&db.root.unknown), ["ZzUnknownGroup"]);
        let work = &db.root.groups.iter().find(|g| g.name == "Work").unwrap();
        let server = &work.entries[0];
        assert_eq!(server.title(), "Server");
        assert_eq!(names(&server.unknown), ["ZzUnknownEntry"]);
        assert_eq!(names(&server.auto_type.as_ref().unwrap().unknown), ["ZzUnknownAutoType"]);
        let total = db.unknown_file.len()
            + db.unknown_root.len()
            + db.meta.unknown.len()
            + db.root.unknown.len()
            + server.unknown.len()
            + server.auto_type.as_ref().unwrap().unknown.len();
        assert_eq!(total, 6);
        // Content the spike's generator wrote.
        let keys: Vec<&str> = server.strings.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(keys, ["Title", "UserName", "Password", "URL", "Notes", "Zeta custom", "Alpha custom", "PIN"]);
        assert_eq!(server.field_text("Password"), "second pw ✓");
        assert_eq!(server.history[0].field_text("Password"), "first pw");
        assert!(server.field("PIN").unwrap().protected);
        assert_eq!(server.quality_check, None);
        assert_eq!(&*db.binaries[server.binaries[0].index as usize].data, b"attached from kdbxweb");
        assert_eq!(vault::sync_generation(&db), 7);
        assert_eq!(db.deleted_objects.len(), 1);
    }
}

#[test]
fn vault_helpers() {
    let k1 = [1u8; 32];
    let k2 = [2u8; 32];
    let (mut db, key) = vault::create_vault_kdbx("Team", &k1, NOW).unwrap();
    assert_eq!(db.root.name, "Team");
    assert_eq!(vault::kdf_settings(&db).kdf, "argon2id");
    assert_eq!(vault::sync_generation(&db), 0);
    vault::set_sync_generation(&mut db, 42, NOW);
    assert_eq!(vault::sync_generation(&db), 42);
    assert_eq!(db.meta.custom_data[0].last_modification, None, "4.0 has no custom data times");

    db.meta.custom_data.push(ov_kdbx::model::CustomDataItem {
        key: vault::REMOTE_SETTINGS_KEY.into(),
        value: r#"[{"type":"syncServer","url":"x"},{"type":"command","cmd":"rsync"}]"#.into(),
        last_modification: None,
    });
    vault::drop_server_remotes(&mut db);
    assert_eq!(db.meta.custom_data_value(vault::REMOTE_SETTINGS_KEY), Some(r#"[{"cmd":"rsync","type":"command"}]"#));
    db.meta.custom_data[1].value = "not json".into();
    vault::drop_server_remotes(&mut db);
    assert_eq!(db.meta.custom_data_value(vault::REMOTE_SETTINGS_KEY), None);

    let v1 = ov_kdbx::write(&db, &key).unwrap();
    let mut copy = vault::copy_kdbx(&db);
    let key2 = vault::rekey_to_vault_key(&mut copy, &k2).unwrap();
    assert_ne!(copy.header.kdf, db.header.kdf, "fresh salt");
    let v2 = ov_kdbx::write(&copy, &key2).unwrap();

    let kv = |version, k: &[u8; 32]| KeyVersion { version, key: Zeroizing::new(k.to_vec()) };
    let (opened, version) = vault::open_with_key_versions(&v1, &[kv(2, &k2), kv(1, &k1)]).unwrap();
    assert_eq!((version, opened.root.name.as_str()), (1, "Team"));
    let (_, version) = vault::open_with_key_versions(&v2, &[kv(1, &k1), kv(2, &k2)]).unwrap();
    assert_eq!(version, 2);
    let e = vault::open_with_key_versions(&v2, &[kv(1, &k1)]).unwrap_err();
    assert_eq!(e.code, OvErrorCode::VaultKeyMismatch);
    assert_eq!(vault::open_with_key_versions(&v2, &[]).unwrap_err().code, OvErrorCode::NoVaultKey);
    assert_eq!(vault::vault_credentials(&[0; 31]).unwrap_err().code, OvErrorCode::NoVaultKey);

    // the password hash is equivalent to the password
    let pw = ov_kdbx::write(&db, &vault::password_credentials(Some("pw"), None)).unwrap();
    let hash = vault::password_hash("pw");
    ov_kdbx::read(&pw, &vault::password_hash_credentials(hash.as_ref()).unwrap()).unwrap();
}

#[test]
fn entry_operations() {
    let (mut db, key) = vault::create_vault_kdbx("Ops", &[3u8; 32], NOW).unwrap();
    db.meta.history_max_items = 2;
    let root = db.root.uuid;
    let work = entries::create_group(&mut db, root, "Work", NOW).unwrap();
    let data = EntryData {
        title: "Mail".into(),
        username: "me".into(),
        password_value: Zeroizing::new("pw0".into()),
        tags: vec!["a".into()],
        expiry_time: Some(NOW + 10),
        ..EntryData::default()
    };
    let id = entries::add_entry(&mut db, work, &data, NOW).unwrap();
    for i in 1..=3 {
        let edit = EntryEdit {
            password_value: Some(Zeroizing::new(format!("pw{i}"))),
            fields: vec![("PIN".into(), FieldValue { value: Zeroizing::new("1".into()), protected: true })],
            expiry_time: Some(None),
            ..EntryEdit::default()
        };
        entries::edit_entry(&mut db, id, &edit, NOW + i).unwrap();
    }
    let e = entries::find_entry(&db.root, id).unwrap();
    assert_eq!(e.field_text("Password"), "pw3");
    assert_eq!(e.history.len(), 2, "trimmed to HistoryMaxItems");
    assert_eq!(e.history[0].field_text("Password"), "pw1");
    assert!(!e.times.expires);
    assert_eq!(e.times.last_modification, NOW + 3);

    let (list, groups) = entries::collect_all_db_data(&db);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].group_name, "Work");
    assert_eq!(list[0].uuid, entries::uuid_string(&id));
    assert_eq!(entries::parse_uuid_string(&list[0].uuid), Some(id));
    assert_eq!(groups.len(), 2);

    // delete → recycle bin, delete again → gone for good with a tombstone
    entries::delete_entry(&mut db, id, NOW + 5).unwrap();
    let rb = db.meta.recycle_bin_uuid.unwrap();
    let bin = entries::find_group(&db.root, rb).unwrap();
    assert_eq!(bin.entries[0].uuid, id);
    assert_eq!(bin.entries[0].times.location_changed, NOW + 5);
    entries::delete_entry(&mut db, id, NOW + 6).unwrap();
    assert!(entries::find_entry(&db.root, id).is_none());
    assert_eq!(db.deleted_objects.last().unwrap().uuid, id);

    entries::rename_group(&mut db, work, "Job", NOW).unwrap();
    entries::set_group_icon(&mut db, work, 7, NOW).unwrap();
    let id2 = entries::add_entry(&mut db, work, &data, NOW).unwrap();
    let exported = entries::export_selected_groups(&db, &[work], NOW).unwrap();
    assert_eq!(exported.root.groups[0].name, "Job");
    assert_eq!(exported.root.groups[0].entries[0].title(), "Mail");

    entries::delete_group(&mut db, work, NOW).unwrap();
    entries::empty_recycle_bin(&mut db, NOW).unwrap();
    assert!(db.deleted_objects.iter().any(|d| d.uuid == id2), "entries inside a deleted group are tombstoned");
    assert!(db.deleted_objects.iter().any(|d| d.uuid == work));
    assert_eq!(entries::delete_group(&mut db, root, NOW).unwrap_err().code, OvErrorCode::InvalidRequest);
    assert_eq!(entries::delete_entry(&mut db, id2, NOW).unwrap_err().code, OvErrorCode::EntryNotFound);

    let back = ov_kdbx::read(&ov_kdbx::write(&db, &key).unwrap(), &key).unwrap();
    assert_eq!(back, db);
}
