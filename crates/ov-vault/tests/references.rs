//! `ov://` references (SPEC §14, `vault/reference.ts`): parsing, formatting, lookup rules,
//! field aliases, writes with history, and templates.

use ov_error::OvErrorCode;
use ov_kdbx::entries::{add_entry, create_group, delete_entry, uuid_string, EntryData};
use ov_kdbx::model::Database;
use ov_kdbx::vault::create_kdbx;
use ov_vault::reference::{percent_decode, percent_encode};
use ov_vault::{
    find_entry, find_references, format_item_reference, format_reference, inject, parse_reference, read_field,
    resolve_field_name, write_field, SecretReference,
};
use zeroize::Zeroizing;

const NOW: i64 = 1_700_000_000;

fn r(s: &str) -> SecretReference {
    parse_reference(s).unwrap()
}

fn read(db: &Database, s: &str) -> String {
    read_field(db, &r(s)).unwrap().to_string()
}

fn db() -> Database {
    let mut db = create_kdbx("V", NOW).unwrap();
    let root = db.root.uuid;
    let add = |db: &mut Database, g, t: &str, u: &str, p: &str| {
        add_entry(
            db,
            g,
            &EntryData {
                title: t.into(),
                username: u.into(),
                password_value: Zeroizing::new(p.into()),
                ..Default::default()
            },
            NOW,
        )
        .unwrap()
    };
    add(&mut db, root, "GitHub", "ci", "s3cret");
    let infra = create_group(&mut db, root, "Infra", NOW).unwrap();
    let sub = create_group(&mut db, infra, "a/b", NOW).unwrap();
    add(&mut db, infra, "Dup", "one", "1");
    add(&mut db, sub, "Dup", "two", "2");
    add(&mut db, sub, "Deep", "d", "deep");
    let trashed = add(&mut db, root, "Trashed", "t", "gone");
    delete_entry(&mut db, trashed, NOW).unwrap();
    db
}

#[test]
fn parses_and_formats() {
    let p = r("ov://Team%20Infra/Group/Sub%2FDir/Entry/pass%C3%BCword");
    assert_eq!(p.vault, "Team Infra");
    assert_eq!(p.group_path, ["Group", "Sub/Dir"]);
    assert_eq!((p.entry.as_str(), p.field.as_str()), ("Entry", "passüword"));
    assert_eq!(format_reference(&p), "ov://Team%20Infra/Group/Sub%2FDir/Entry/pass%C3%BCword");
    assert_eq!(parse_reference(&format_reference(&p)).unwrap(), p);
    assert_eq!(format_item_reference(&p.item()), "ov://Team%20Infra/Group/Sub%2FDir/Entry");
    for bad in [
        "ov://v/e",
        "ov://v//f",
        "ov:/v/e/f",
        "OV://v/e/f",
        "ov://v/e/%E0%A4",
        "ov://v/e/%",
        "ov://v/e/%g0",
        "ov:///e/f",
    ] {
        assert!(parse_reference(bad).unwrap_err().is(OvErrorCode::InvalidReference), "{bad}");
    }
}

#[test]
fn percent_coding_matches_javascript() {
    assert_eq!(percent_encode("a b/c?d!~*'()-_.é"), "a%20b%2Fc%3Fd!~*'()-_.%C3%A9");
    assert_eq!(percent_decode("%41%c3%a9+").as_deref(), Some("Aé+"));
    assert_eq!(percent_decode("%ff"), None);
    assert_eq!(percent_decode("%4"), None);
}

#[test]
fn finds_entries_by_title_uuid_and_group_path() {
    let db = db();
    assert_eq!(read(&db, "ov://v/GitHub/password"), "s3cret");
    // aliases (any case), exact and case-insensitive names
    assert_eq!(read(&db, "ov://v/GitHub/USER"), "ci");
    assert_eq!(read(&db, "ov://v/GitHub/Title"), "GitHub");
    assert_eq!(read(&db, "ov://v/GitHub/url"), "");
    // titles under a group are searched recursively; a group segment narrows it
    assert_eq!(read(&db, "ov://v/Deep/password"), "deep");
    assert_eq!(read(&db, "ov://v/Infra/a%2Fb/Dup/username"), "two");
    let e = read_field(&db, &r("ov://v/Infra/Dup/username")).unwrap_err();
    assert!(e.is(OvErrorCode::EntryNotFound) && e.message.contains("2 entries are titled \"Dup\""), "{}", e.message);
    // UUIDs: 32 hex, dashed, any case, and KDBX base64
    let (gh, path) = find_entry(&db, &[], "GitHub").unwrap();
    assert!(path.is_empty());
    let hex = gh.uuid.simple().to_string();
    for id in [hex.clone(), hex.to_uppercase(), gh.uuid.hyphenated().to_string(), uuid_string(&gh.uuid)] {
        let id = percent_encode(&id);
        assert_eq!(read(&db, &format!("ov://v/{id}/password")), "s3cret", "{id}");
    }
    let (deep, path) = find_entry(&db, &["Infra".into()], "Deep").unwrap();
    assert_eq!(path, ["Infra", "a/b"]);
    assert_eq!(deep.title(), "Deep");
    // the Recycle Bin is skipped; missing groups, entries and fields are entry_not_found
    for (s, msg) in [
        ("ov://v/Trashed/password", "entry \"Trashed\" not found"),
        ("ov://v/Nope/Deep/password", "group \"Nope\" not found"),
        ("ov://v/GitHub/nofield", "field \"nofield\" not found"),
    ] {
        let e = read_field(&db, &r(s)).unwrap_err();
        assert!(e.is(OvErrorCode::EntryNotFound) && e.message == msg, "{s}: {}", e.message);
    }
}

#[test]
fn resolves_field_names() {
    let mut db = db();
    write_field(&mut db, &r("ov://v/GitHub/API%20Key"), "k", false, None, NOW).unwrap();
    let (gh, _) = find_entry(&db, &[], "GitHub").unwrap();
    assert_eq!(resolve_field_name(gh, "API Key"), "API Key");
    assert_eq!(resolve_field_name(gh, "api key"), "API Key");
    assert_eq!(resolve_field_name(gh, "PASSWORD"), "Password");
    assert_eq!(resolve_field_name(gh, "new"), "new");
}

#[test]
fn writes_keep_history_and_protect_password_and_custom_fields() {
    let mut db = db();
    let before = find_entry(&db, &[], "GitHub").unwrap().0.clone();
    write_field(&mut db, &r("ov://v/GitHub/password"), "new", false, None, NOW + 60).unwrap();
    write_field(&mut db, &r("ov://v/GitHub/token"), "t", false, None, NOW + 61).unwrap();
    write_field(&mut db, &r("ov://v/GitHub/notes"), "plain", false, None, NOW + 62).unwrap();
    write_field(&mut db, &r("ov://v/GitHub/shown"), "x", false, Some(false), NOW + 63).unwrap();
    let (gh, _) = find_entry(&db, &[], "GitHub").unwrap();
    assert_eq!(gh.history.len(), 4);
    assert_eq!(gh.history[0].field_text("Password"), "s3cret");
    assert!(gh.history.iter().all(|h| h.history.is_empty()));
    assert_eq!((gh.times.last_modification, gh.times.creation), (NOW + 63, before.times.creation));
    let prot = |k: &str| gh.field(k).unwrap().protected;
    assert_eq!((prot("Password"), prot("token"), prot("Notes"), prot("shown")), (true, true, false, false));
    // missing without create → entry_not_found; with create it is made (groups too)
    assert!(write_field(&mut db, &r("ov://v/X/Y/password"), "p", false, None, NOW)
        .unwrap_err()
        .is(OvErrorCode::EntryNotFound));
    write_field(&mut db, &r("ov://v/X/Y/password"), "p", true, None, NOW).unwrap();
    assert_eq!(read(&db, "ov://v/X/Y/password"), "p");
    let (y, path) = find_entry(&db, &["X".into()], "Y").unwrap();
    assert_eq!((path.as_slice(), y.history.len()), (&["X".to_owned()][..], 0));
    // an ambiguous title is never "created"
    let e = write_field(&mut db, &r("ov://v/Infra/Dup/password"), "p", true, None, NOW).unwrap_err();
    assert!(e.message.contains("2 entries"));
}

#[test]
fn history_limits_apply_on_write() {
    let mut db = db();
    db.meta.history_max_items = 2;
    for i in 0..5 {
        write_field(&mut db, &r("ov://v/GitHub/password"), &format!("p{i}"), false, None, NOW + i).unwrap();
    }
    let (gh, _) = find_entry(&db, &[], "GitHub").unwrap();
    assert_eq!(gh.history.iter().map(|h| h.field_text("Password").to_owned()).collect::<Vec<_>>(), ["p2", "p3"]);
}

#[test]
fn finds_references_in_templates() {
    let t =
        "A=ov://v/e/f\nB=\"ov://v/e/g\" C='ov://v/x%20y/h'`ov://v/e/f`{{ ov://v/e/i }} ov:// ov://ov://v/e/j\u{3000}x";
    let found: Vec<&str> = find_references(t).into_iter().map(|r| &t[r]).collect();
    assert_eq!(found, ["ov://v/e/f", "ov://v/e/g", "ov://v/x%20y/h", "ov://v/e/f", "ov://v/e/i", "ov://ov://v/e/j"]);

    let mut calls = Vec::new();
    let out = inject(t, |s| {
        calls.push(s.to_owned());
        Ok(Zeroizing::new(format!("<{}>", s.len())))
    })
    .unwrap();
    assert_eq!(calls.len(), 5, "each distinct reference is resolved once");
    assert!(out.text.starts_with("A=<10>\nB=\"<10>\""));
    assert_eq!(out.secrets.len(), 5);
    assert!(!format!("{out:?}").contains("<10>"));

    let e = inject("x=ov://v/e/f", |_| Err(ov_error::OvError::new(OvErrorCode::EntryNotFound, "nope"))).unwrap_err();
    assert!(e.is(OvErrorCode::EntryNotFound));
    assert_eq!(&*inject("no refs", |_| unreachable!()).unwrap().text, "no refs");
}
