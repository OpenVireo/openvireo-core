//! The `sync.test.ts` and `deletions.test.ts` cases, as scenarios over any [`World`]: the fake in
//! `common` (`tests/sync.rs`) or W2-E's `ov_testkit::servers` (`tests/servers.rs`).

#![allow(dead_code)]

use ov_error::OvErrorCode;
use ov_kdbx::entries::{delete_entry, delete_group, empty_recycle_bin};
use ov_kdbx::model::Database;
use ov_kdbx::vault::vault_credentials;
use ov_sync::{is_clock_skewed, sync_kdbx, SyncOptions, SyncOutcome, SyncResult, SyncState, CLOCK_SKEW_WARNING_MS};

use crate::common::*;

fn sync<W: World>(w: &W, db: &mut Database, state: Option<&SyncState>) -> SyncResult {
    let c = [creds()];
    let k = creds();
    run(sync_kdbx(&w.blob("db"), db, &SyncOptions::new(&k, &c).state(state))).unwrap()
}

fn setup() -> Copies {
    three_copies(|db| {
        add_entry(db, "A", &[("Password", "p"), ("URL", "x")], 100, None);
    })
}

/// "creates, then pulls, then uploads merged changes, keeping a base copy"
pub fn creates_pulls_uploads<W: World>(w: &W) {
    let Copies { mut local, mut remote, .. } = setup();
    let first = sync(w, &mut local, None);
    assert_eq!(first.outcome, SyncOutcome::Created);
    assert_eq!(first.state.revision, 1);
    assert!(first.state.base.is_some());

    // device 2 starts from the server copy, edits URL and uploads
    let dev2 = sync(w, &mut remote, None);
    assert_eq!(dev2.outcome, SyncOutcome::Pulled);
    let mut d2 = dev2.db;
    edit(&mut d2, "A", &[("URL", "y")], 300);
    let up2 = sync(w, &mut d2, Some(&dev2.state));
    assert_eq!(up2.outcome, SyncOutcome::Uploaded);

    // device 1 changed Password meanwhile: the base copy lets both changes survive
    edit(&mut local, "A", &[("Password", "p2")], 200);
    let r = sync(w, &mut local, Some(&first.state));
    assert_eq!(r.outcome, SyncOutcome::Uploaded);
    assert_eq!(r.conflicts, vec![]);
    assert_eq!((get(&r.db, "A", "Password"), get(&r.db, "A", "URL")), (Some("p2".into()), Some("y".into())));
    let server = ov_kdbx::read(&w.latest("db").unwrap(), &creds()).unwrap();
    assert_eq!((get(&server, "A", "Password"), get(&server, "A", "URL")), (Some("p2".into()), Some("y".into())));
    assert_eq!(r.state.revision, 3);
    let json = ov_sync::serialize_sync_state(&r.state);
    assert_eq!(ov_sync::serialize_sync_state(&ov_sync::deserialize_sync_state(&json).unwrap()), json);
}

/// "on 412 downloads the newer version, merges it too and retries"
pub fn retries_on_412<W: World>(w: &W) {
    let Copies { mut local, remote, .. } = setup();
    let first = sync(w, &mut local, None);
    edit(&mut local, "A", &[("Password", "mine")], 200);
    // another device uploads between our GET and PUT, once
    let remote = std::sync::Mutex::new(Some(remote));
    let w2 = w.clone();
    w.set_after_get(Some(Box::new(move || {
        if let Some(mut r) = remote.lock().unwrap().take() {
            edit(&mut r, "A", &[("Notes", "theirs")], 250);
            w2.upload("db", &ov_kdbx::write(&r, &creds()).unwrap());
        }
    })));
    let before = w.methods().iter().filter(|m| *m == "PUT").count();
    let r = sync(w, &mut local, Some(&first.state));
    w.set_after_get(None);
    assert_eq!(r.attempts, 2);
    assert_eq!(w.methods().iter().filter(|m| *m == "PUT").count() - before, 2); // 412, success
    let server = ov_kdbx::read(&w.latest("db").unwrap(), &creds()).unwrap();
    assert_eq!(
        (get(&server, "A", "Password"), get(&server, "A", "Notes")),
        (Some("mine".into()), Some("theirs".into()))
    );
}

/// A 412 retry merges against the base by content when every edit falls in the second of the last
/// sync (the SDK's service-account race with a fixed clock): the snapshot's whole-second times say
/// the local entry is unchanged, and without the base the other device's newer copy won whole,
/// putting this device's change in history only.
pub fn retries_on_412_with_same_second_edits<W: World>(w: &W) {
    let now_s = NOW_MS / 1000;
    let Copies { mut local, remote, .. } = three_copies(|db| {
        add_entry(db, "A", &[("Password", "p"), ("URL", "x")], now_s, None);
    });
    let first = sync(w, &mut local, None);
    edit(&mut local, "A", &[("Password", "mine")], now_s);
    let remote = std::sync::Mutex::new(Some(remote));
    let w2 = w.clone();
    w.set_after_get(Some(Box::new(move || {
        if let Some(mut r) = remote.lock().unwrap().take() {
            // the other device's clock is a second ahead
            edit(&mut r, "A", &[("Notes", "theirs")], now_s + 1);
            w2.upload("db", &ov_kdbx::write(&r, &creds()).unwrap());
        }
    })));
    let r = sync(w, &mut local, Some(&first.state));
    w.set_after_get(None);
    assert_eq!((r.outcome, r.attempts), (SyncOutcome::Uploaded, 2));
    assert_eq!(r.conflicts, vec![]);
    let server = ov_kdbx::read(&w.latest("db").unwrap(), &creds()).unwrap();
    assert_eq!(
        (get(&server, "A", "Password"), get(&server, "A", "Notes")),
        (Some("mine".into()), Some("theirs".into()))
    );
}

/// Both sides changed the same field in the sync's second: a conflict found by content, with the
/// field named, though the snapshot's times miss it.
pub fn same_second_edits_of_one_field_conflict<W: World>(w: &W) {
    let now_s = NOW_MS / 1000;
    let Copies { mut local, mut remote, .. } = three_copies(|db| {
        add_entry(db, "A", &[("Password", "p")], now_s, None);
    });
    let first = sync(w, &mut local, None);
    let dev2 = sync(w, &mut remote, None);
    let mut d2 = dev2.db;
    edit(&mut d2, "A", &[("Password", "theirs")], now_s + 1);
    sync(w, &mut d2, Some(&dev2.state));
    edit(&mut local, "A", &[("Password", "mine")], now_s);
    let r = sync(w, &mut local, Some(&first.state));
    assert_eq!(r.conflicts.len(), 1);
    assert_eq!(r.conflicts[0].fields, vec!["Password".to_owned()]);
}

/// With `remote_is_base` the first attempt uploads against the base without downloading.
pub fn uploads_against_a_fresh_base_without_a_download<W: World>(w: &W) {
    let Copies { mut local, .. } = setup();
    let first = sync(w, &mut local, None);
    edit(&mut local, "A", &[("Password", "mine")], 200);
    let before = w.methods();
    let (c, k) = ([creds()], creds());
    let opts = SyncOptions::new(&k, &c).state(Some(&first.state)).remote_is_base(true);
    let r = run(sync_kdbx(&w.blob("db"), &mut local, &opts)).unwrap();
    let after = w.methods();
    assert_eq!(&after[before.len()..], ["PUT"]);
    assert_eq!(r.outcome, SyncOutcome::Uploaded);
    let server = ov_kdbx::read(&w.latest("db").unwrap(), &creds()).unwrap();
    assert_eq!(get(&server, "A", "Password"), Some("mine".into()));
}

/// "gives up after maxAttempts when the server keeps changing"
pub fn gives_up_after_max_attempts<W: World>(w: &W) {
    let Copies { mut local, remote, .. } = setup();
    let first = sync(w, &mut local, None);
    edit(&mut local, "A", &[("Password", "mine")], 200);
    let n = std::sync::Arc::new(std::sync::Mutex::new((0i64, remote)));
    let (n2, w2) = (n.clone(), w.clone());
    w.set_after_get(Some(Box::new(move || {
        let mut g = n2.lock().unwrap();
        g.0 += 1;
        let i = g.0;
        edit(&mut g.1, "A", &[("Notes", &format!("theirs {i}"))], 250 + i);
        w2.upload("db", &ov_kdbx::write(&g.1, &creds()).unwrap());
    })));
    let c = [creds()];
    let k = creds();
    let opts = SyncOptions::new(&k, &c).state(Some(&first.state)).max_attempts(3);
    let e = run(sync_kdbx(&w.blob("db"), &mut local, &opts)).unwrap_err();
    w.set_after_get(None);
    assert_eq!((e.code, e.status), (OvErrorCode::TooManyConflicts, Some(412)));
    assert_eq!(n.lock().unwrap().0, 3);
}

/// "HEAD-checks when nothing changed locally, and detects rollbacks and lost databases"
pub fn head_check_rollback_and_loss<W: World>(w: &W) {
    let Copies { mut local, .. } = setup();
    let first = sync(w, &mut local, None);
    let c = [creds()];
    let k = creds();
    let blob = w.blob("db");
    let again =
        run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&first.state)).local_changed(false)))
            .unwrap();
    assert_eq!(again.outcome, SyncOutcome::Unchanged);
    assert_eq!(again.attempts, 0);
    assert_eq!(w.methods().last().map(String::as_str), Some("HEAD"));

    let ahead = SyncState { revision: 7, ..first.state.clone() };
    let e = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&ahead)))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerRolledBack);
    // The HEAD path checks the revision too
    let e = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&ahead)).local_changed(false)))
        .unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerRolledBack);
    // So does the sync generation
    let newer = SyncState { generation: 99, ..first.state.clone() };
    let e = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&newer)))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerRolledBack);
    // Confirmed by the user: start over from the server
    let r = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&ahead)).accept_server_state(true)))
        .unwrap();
    assert_eq!(r.state.revision, 1);

    w.lose_all();
    let e = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&first.state)))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::ServerLostDatabase);
    let r = run(sync_kdbx(
        &blob,
        &mut local,
        &SyncOptions::new(&k, &c).state(Some(&first.state)).accept_server_state(true),
    ))
    .unwrap();
    assert_eq!(r.outcome, SyncOutcome::Created);
}

/// "re-keys before upload (rotation) and opens with the first credentials that work"
pub fn rekeys_before_upload<W: World>(w: &W) {
    let Copies { mut local, .. } = setup();
    sync(w, &mut local, None);
    let new_key = [9u8; 32];
    let c = [vault_credentials(&new_key).unwrap(), creds()];
    let k = creds();
    let rekey = |db: &mut Database| Ok(Some(ov_kdbx::vault::rekey_to_vault_key(db, &new_key)?));
    let r = run(sync_kdbx(&w.blob("db"), &mut local, &SyncOptions::new(&k, &c).before_upload(&rekey))).unwrap();
    assert_eq!(r.outcome, SyncOutcome::Uploaded);
    assert_eq!(r.credentials_index, Some(1));
    let data = w.latest("db").unwrap();
    assert_eq!(ov_kdbx::read(&data, &creds()).unwrap_err().code, OvErrorCode::VaultKeyMismatch);
    let db = ov_kdbx::read(&data, &vault_credentials(&new_key).unwrap()).unwrap();
    assert_eq!(get(&db, "A", "Password"), Some("p".into()));
    // The result's key is the new one
    assert!(ov_kdbx::read(&ov_kdbx::write(&r.db, &r.key).unwrap(), &vault_credentials(&new_key).unwrap()).is_ok());
}

/// "measures this computer's clock against the server's on every sync"
pub fn measures_clock_offset<W: World>(w: &W) {
    let Copies { mut local, .. } = three_copies(|db| {
        add_entry(db, "A", &[], 100, None);
    });
    w.set_server_ahead_ms(0);
    let first = sync(w, &mut local, None);
    assert!(first.clock_offset_ms.unwrap().abs() < 1500);
    assert!(!is_clock_skewed(first.clock_offset_ms));

    w.set_server_ahead_ms(-2 * CLOCK_SKEW_WARNING_MS); // this computer is 10 minutes ahead
    let c = [creds()];
    let k = creds();
    let mut db = first.db;
    let second = run(sync_kdbx(
        &w.blob("db"),
        &mut db,
        &SyncOptions::new(&k, &c).state(Some(&first.state)).local_changed(false),
    ))
    .unwrap();
    w.set_server_ahead_ms(0);
    let minutes = second.clock_offset_ms.unwrap() as f64 / 60_000.0;
    assert!((minutes - 10.0).abs() < 0.05, "{minutes}");
    assert!(second.clock_skewed());
}

// ----------------------------------------------------------------------------- deletions.test.ts

/// A vault with "Work" (holding "In Work") and "Loose" both in the Recycle Bin, and "Kept" outside.
fn binned() -> Copies {
    three_copies(|db| {
        let work = create_group(db, "Work", 100);
        add_entry(db, "In Work", &[], 100, Some(work));
        let loose = add_entry(db, "Loose", &[], 100, None);
        add_entry(db, "Kept", &[], 100, None);
        delete_group(db, work, 100).unwrap();
        delete_entry(db, loose, 100).unwrap();
    })
}

fn bin(db: &Database) -> &ov_kdbx::model::Group {
    ov_kdbx::entries::find_group(&db.root, db.meta.recycle_bin_uuid.unwrap()).unwrap()
}

/// Both devices start from the server copy `bytes`, each with a state; returns their states.
fn two_devices<W: World>(w: &W, c: &mut Copies) -> (SyncState, SyncState) {
    w.upload("db", &c.bytes);
    let a = sync(w, &mut c.local, None);
    let b = sync(w, &mut c.remote, None);
    (a.state, b.state)
}

/// "a group deleted from the Recycle Bin stays deleted on both sides"
pub fn deleted_from_bin_stays_deleted<W: World>(w: &W) {
    let mut c = binned();
    let (sl, sr) = two_devices(w, &mut c);
    let work = group(&c.local, "Work").unwrap().uuid;
    delete_group(&mut c.local, work, 1000).unwrap();
    let loose = id_of(&c.local, "Loose");
    delete_entry(&mut c.local, loose, 1000).unwrap();
    let up = sync(w, &mut c.local, Some(&sl));
    assert_eq!(up.outcome, SyncOutcome::Uploaded);
    let down = sync(w, &mut c.remote, Some(&sr));
    for db in [&up.db, &down.db, &c.remote] {
        assert!(group(db, "Work").is_none());
        assert!(by_title(db, "In Work").is_none());
        assert!(by_title(db, "Loose").is_none());
        assert!(by_title(db, "Kept").is_some());
        assert!(bin(db).groups.is_empty() && bin(db).entries.is_empty());
    }
    let ids = |db: &Database| {
        let mut v: Vec<_> = db.deleted_objects.iter().map(|d| d.uuid).collect();
        v.sort();
        v
    };
    assert_eq!(ids(&down.db), ids(&up.db)); // passed on, for the devices that sync next
    assert_eq!(ids(&up.db).len(), 3);
}

/// "deletions made on the server copy are applied locally"
pub fn server_deletions_apply_locally<W: World>(w: &W) {
    let mut c = binned();
    let (sl, sr) = two_devices(w, &mut c);
    empty_recycle_bin(&mut c.remote, 1000).unwrap();
    sync(w, &mut c.remote, Some(&sr));
    let r = sync(w, &mut c.local, Some(&sl));
    assert!(group(&c.local, "Work").is_none());
    assert!(by_title(&c.local, "Loose").is_none());
    // (ov-merge reports the applied deletions as a change to both copies, so this may upload.)
    assert!(matches!(r.outcome, SyncOutcome::Pulled | SyncOutcome::Uploaded));
    let server = ov_kdbx::read(&w.latest("db").unwrap(), &creds()).unwrap();
    assert!(group(&server, "Work").is_none() && by_title(&server, "Loose").is_none());
}

/// "an entry edited on the other side is kept, whatever the clocks say"
pub fn edited_entry_beats_deletion<W: World>(w: &W) {
    let mut c = binned();
    let (sl, sr) = two_devices(w, &mut c);
    // The deleting device's clock is far ahead: its deletion looks newer than the edit
    let kept = id_of(&c.remote, "Kept");
    ov_kdbx::entries::delete_entry(&mut c.remote, kept, 1000).unwrap(); // to the bin
    ov_kdbx::entries::delete_entry(&mut c.remote, kept, 1_000_000_000).unwrap(); // for good
    sync(w, &mut c.remote, Some(&sr));
    edit(&mut c.local, "Kept", &[("Notes", "edited")], 500);
    let r = sync(w, &mut c.local, Some(&sl));
    for db in [&c.local, &r.db] {
        assert_eq!(get(db, "Kept", "Notes"), Some("edited".into()));
    }
    let server = ov_kdbx::read(&w.latest("db").unwrap(), &creds()).unwrap();
    assert_eq!(get(&server, "Kept", "Notes"), Some("edited".into()));
}

/// "a deletion is applied even when the deleting device's clock is behind"
pub fn deletion_applies_with_clock_behind<W: World>(w: &W) {
    let mut c = binned();
    let (sl, sr) = two_devices(w, &mut c);
    let kept = id_of(&c.local, "Kept");
    let e = ov_kdbx::entries::find_entry(&c.local.root, kept).unwrap().clone();
    c.local.root.entries.retain(|x| x.uuid != kept);
    c.local.deleted_objects.push(ov_kdbx::model::DeletedObject { uuid: e.uuid, deletion_time: 1 });
    sync(w, &mut c.local, Some(&sl));
    sync(w, &mut c.remote, Some(&sr));
    assert!(by_title(&c.remote, "Kept").is_none());
    assert!(by_title(&c.local, "Kept").is_none());
}

/// "a group that gained an entry on the other side is kept with it; the deleted entries go"
pub fn group_gaining_entry_is_kept<W: World>(w: &W) {
    let mut c = binned();
    let (sl, sr) = two_devices(w, &mut c);
    let work = group(&c.local, "Work").unwrap().uuid;
    delete_group(&mut c.local, work, 1000).unwrap();
    sync(w, &mut c.local, Some(&sl));
    add_entry(&mut c.remote, "New in Work", &[], 600, Some(work));
    let r = sync(w, &mut c.remote, Some(&sr));
    let back = sync(w, &mut c.local, Some(&r.state));
    for db in [&c.remote, &back.db] {
        assert!(group(db, "Work").is_some());
        assert!(by_title(db, "New in Work").is_some());
        assert!(by_title(db, "In Work").is_none());
    }
}

/// "a renamed group is kept"
pub fn renamed_group_is_kept<W: World>(w: &W) {
    let mut c = binned();
    let (sl, sr) = two_devices(w, &mut c);
    let work = group(&c.remote, "Work").unwrap().uuid;
    let g = ov_kdbx::entries::find_group_mut(&mut c.remote.root, work).unwrap();
    g.name = "Work 2".into();
    g.times.last_modification = 700;
    sync(w, &mut c.remote, Some(&sr));
    delete_group(&mut c.local, work, 1000).unwrap();
    sync(w, &mut c.local, Some(&sl));
    assert!(group(&c.local, "Work 2").is_some());
}

/// "without a base nothing is deleted": a device with no state (so no base) syncing a deletion
/// gets the item back from the server copy instead of losing it there.
pub fn without_base_nothing_is_deleted<W: World>(w: &W) {
    let mut c = binned();
    w.upload("db", &c.bytes);
    let loose = id_of(&c.local, "Loose");
    delete_entry(&mut c.local, loose, 1000).unwrap();
    let r = sync(w, &mut c.local, None);
    assert!(by_title(&c.local, "Loose").is_some());
    let server = ov_kdbx::read(&w.latest("db").unwrap_or(c.bytes.clone()), &creds()).unwrap();
    assert!(by_title(&server, "Loose").is_some());
    assert!(by_title(&r.db, "Loose").is_some());
}
