//! `sync.test.ts` and `deletions.test.ts` against W2-E's `ov_testkit::servers` fake sync server
//! (legacy `databases/` routes with `DEVICE_TOKEN`), plus the special states through E's fault
//! helpers. Gated until W2-E merges: the lead removes the two lines below and reruns.
#![allow(unexpected_cfgs)]
#![cfg(ov_test_servers)]

mod common;
mod scenarios;

use std::sync::{Arc, Mutex};

use common::*;
use ov_error::OvErrorCode;
use ov_protocol::sync::SyncApi;
use ov_sync::{sync_kdbx, Blob, StaticToken, SyncClient, SyncOptions, SyncOutcome};
use ov_testkit::servers::{TestServers, DEVICE_TOKEN as E_DEVICE_TOKEN};
use ov_testkit::ManualClock;

#[derive(Clone)]
struct E {
    s: TestServers,
    clock: Arc<ManualClock>,
}

impl E {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(NOW_MS));
        E { s: TestServers::new(clock.clone()), clock }
    }
    fn client(&self) -> SyncClient {
        SyncClient::new(
            self.s.http(),
            self.clock.clone(),
            SyncApi::new(&self.s.sync_url()).unwrap(),
            Arc::new(StaticToken(Some(E_DEVICE_TOKEN.to_string()))),
        )
    }
}

impl World for E {
    fn clock(&self) -> Arc<ManualClock> {
        self.clock.clone()
    }
    fn blob(&self, id: &str) -> Blob {
        self.client().database(id)
    }
    fn upload(&self, id: &str, data: &[u8]) {
        self.s.put_database_blob(id, data);
    }
    fn latest(&self, id: &str) -> Option<Vec<u8>> {
        self.s.database_blob(id).map(|b| b.data)
    }
    fn set_after_get(&self, f: Option<Box<dyn Fn() + Send + Sync>>) {
        self.s.set_after_get(
            f.map(|f| Box::new(move |_: &TestServers, _: &str| f()) as Box<dyn Fn(&TestServers, &str) + Send + Sync>),
        );
    }
    fn lose_all(&self) {
        self.s.lose_all_blobs();
    }
    fn methods(&self) -> Vec<String> {
        self.s.requests().iter().map(|r| format!("{:?}", r.method).to_uppercase()).collect()
    }
    fn set_server_ahead_ms(&self, ms: i64) {
        self.s.set_server_clock_skew_ms(ms);
    }
}

macro_rules! scenario {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            scenarios::$name(&E::new());
        }
    )*};
}

scenario!(
    creates_pulls_uploads,
    retries_on_412,
    gives_up_after_max_attempts,
    head_check_rollback_and_loss,
    rekeys_before_upload,
    measures_clock_offset,
    deleted_from_bin_stays_deleted,
    server_deletions_apply_locally,
    edited_entry_beats_deletion,
    deletion_applies_with_clock_behind,
    group_gaining_entry_is_kept,
    renamed_group_is_kept,
    without_base_nothing_is_deleted,
);

fn synced(e: &E) -> (ov_kdbx::model::Database, ov_sync::SyncState) {
    let Copies { mut local, .. } = three_copies(|db| {
        add_entry(db, "A", &[], 100, None);
    });
    let (c, k) = ([creds()], creds());
    let r = run(sync_kdbx(&e.blob("db"), &mut local, &SyncOptions::new(&k, &c))).unwrap();
    edit(&mut local, "A", &[("URL", "2")], 200);
    let r = run(sync_kdbx(&e.blob("db"), &mut local, &SyncOptions::new(&k, &c).state(Some(&r.state)))).unwrap();
    (local, r.state)
}

/// The server restored from a backup (E's `rollback_database`): `server_rolled_back`.
#[test]
fn server_restored_from_backup_is_a_rollback() {
    let e = E::new();
    let (mut local, state) = synced(&e);
    e.s.rollback_database("db", 1);
    let (c, k) = ([creds()], creds());
    let err = run(sync_kdbx(&e.blob("db"), &mut local, &SyncOptions::new(&k, &c).state(Some(&state)))).unwrap_err();
    assert_eq!(err.code, OvErrorCode::ServerRolledBack);
}

/// The server lost the database (E's `lose_database`): `server_lost_database`.
#[test]
fn server_lost_the_database() {
    let e = E::new();
    let (mut local, state) = synced(&e);
    e.s.lose_database("db");
    let (c, k) = ([creds()], creds());
    let err = run(sync_kdbx(&e.blob("db"), &mut local, &SyncOptions::new(&k, &c).state(Some(&state)))).unwrap_err();
    assert_eq!(err.code, OvErrorCode::ServerLostDatabase);
    let r = run(sync_kdbx(
        &e.blob("db"),
        &mut local,
        &SyncOptions::new(&k, &c).state(Some(&state)).accept_server_state(true),
    ))
    .unwrap();
    assert_eq!(r.outcome, SyncOutcome::Created);
}

/// Offline (E's `set_offline`): `network_error`, and the sync works again afterwards.
#[test]
fn offline_then_back() {
    let e = E::new();
    let (mut local, state) = synced(&e);
    e.s.set_offline(true);
    let (c, k) = ([creds()], creds());
    let err = run(sync_kdbx(&e.blob("db"), &mut local, &SyncOptions::new(&k, &c).state(Some(&state)))).unwrap_err();
    assert_eq!(err.code, OvErrorCode::NetworkError);
    e.s.set_offline(false);
    let r =
        run(sync_kdbx(&e.blob("db"), &mut local, &SyncOptions::new(&k, &c).state(Some(&state)).local_changed(false)))
            .unwrap();
    assert_eq!(r.outcome, SyncOutcome::Unchanged);
}

/// Precondition retries through `set_after_get`: another device uploads once between our GET and PUT.
#[test]
fn precondition_retry_with_after_get() {
    let e = E::new();
    let (mut local, state) = synced(&e);
    let other = Mutex::new(Some(ov_kdbx::read(&e.latest("db").unwrap(), &creds()).unwrap()));
    e.s.set_after_get(Some(Box::new(move |s: &TestServers, _key: &str| {
        if let Some(mut db) = other.lock().unwrap().take() {
            edit(&mut db, "A", &[("Notes", "theirs")], 250);
            s.put_database_blob("db", &ov_kdbx::write(&db, &creds()).unwrap());
        }
    })));
    edit(&mut local, "A", &[("Password", "mine")], 300);
    let (c, k) = ([creds()], creds());
    let r = run(sync_kdbx(&e.blob("db"), &mut local, &SyncOptions::new(&k, &c).state(Some(&state)))).unwrap();
    e.s.set_after_get(None);
    assert_eq!((r.outcome, r.attempts), (SyncOutcome::Uploaded, 2));
    assert_eq!((get(&r.db, "A", "Password"), get(&r.db, "A", "Notes")), (Some("mine".into()), Some("theirs".into())));
}
