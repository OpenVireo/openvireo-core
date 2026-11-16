//! `sync.test.ts` and `deletions.test.ts` against the in-test fake sync server (`common::FakeSync`),
//! plus the client, TS state fixture, cancel and progress.

mod common;
mod scenarios;

use std::sync::{Arc, Mutex};

use common::*;
use ov_error::OvErrorCode;
use ov_protocol::sync::{etag_for, GetResult, HeadResult, PutCondition};
use ov_sync::{deserialize_sync_state, serialize_sync_state, sync_kdbx, SyncOptions, SyncOutcome, SyncStep};

macro_rules! scenario {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            scenarios::$name(&FakeSync::new());
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

/// "conditional GET/HEAD/PUT, history and revisions"
#[test]
fn conditional_requests_history_and_revisions() {
    let s = FakeSync::new();
    let c = s.client(Some(DEVICE_TOKEN));
    let db = c.database("main");
    run(async {
        assert_eq!(db.get(None).await.unwrap(), GetResult::NotFound);
        let one = [1u8, 2, 3];
        let created = db.put(&one, &PutCondition::Create).await.unwrap();
        assert!(created.created);
        assert_eq!((created.version.revision, created.version.etag.clone()), (Some(1), etag_for(&one)));
        let e = db.put(&one, &PutCondition::Create).await.unwrap_err();
        assert_eq!((e.code, e.status), (OvErrorCode::PreconditionFailed, Some(412)));
        let etag = created.version.etag.clone();
        assert!(matches!(db.get(None).await.unwrap(), GetResult::Ok { version, .. } if version.revision == Some(1)));
        assert!(matches!(db.get(Some(&etag)).await.unwrap(), GetResult::NotModified(_)));
        assert!(matches!(db.head(Some(&etag)).await.unwrap(), HeadResult::NotModified(_)));
        assert!(matches!(db.head(None).await.unwrap(), HeadResult::Ok(v) if v.revision == Some(1)));
        let e = db.put(&[4], &PutCondition::IfMatch("\"stale\"".into())).await.unwrap_err();
        assert_eq!(e.code, OvErrorCode::PreconditionFailed);
        let updated = db.put(&[4], &PutCondition::IfMatch(etag)).await.unwrap();
        assert_eq!((updated.created, updated.version.revision), (false, Some(2)));
        let revs: Vec<i64> = db.history().await.unwrap().iter().map(|m| m.revision).collect();
        assert_eq!(revs, [2, 1]);
        assert_eq!(db.revision(1).await.unwrap().data, [1, 2, 3]);
        assert_eq!(c.health().await.unwrap()["status"], "ok");
        db.delete(None).await.unwrap();
        assert_eq!(db.get(None).await.unwrap(), GetResult::NotFound);
        // A fixed token isn't refreshed: a 401 is returned as is.
        let e = s.client(Some("wrong")).database("main").get(None).await.unwrap_err();
        assert_eq!(e.code, OvErrorCode::Unauthorized);
    });
}

/// "vault routes with a refreshable JWT (401 → forced refresh → retry)"
#[test]
fn refreshable_token_retries_once_after_401() {
    struct Tokens(Mutex<Vec<bool>>);
    #[async_trait::async_trait]
    impl ov_sync::TokenSource for Tokens {
        async fn access_token(&self, force: bool) -> Result<Option<String>, ov_error::OvError> {
            self.0.lock().unwrap().push(force);
            Ok(Some(if force { DEVICE_TOKEN } else { "expired" }.into()))
        }
    }
    let s = FakeSync::new();
    s.store("vaults/v1", &[9]);
    let tokens = Arc::new(Tokens(Mutex::new(vec![])));
    let c = ov_sync::SyncClient::new(
        Arc::new(s.clone()),
        World::clock(&s),
        ov_protocol::sync::SyncApi::new("https://sync.example/api/v1").unwrap(),
        tokens.clone(),
    );
    assert!(matches!(run(c.vault("v1").get(None)).unwrap(), GetResult::Ok { .. }));
    assert_eq!(*tokens.0.lock().unwrap(), [false, true]);
}

/// A state the TS SDK stored (`tests/fixtures/ts-sync-state.json`, made by
/// `gen-ts-sync-state.mjs` with SDK `syncKdbx` + `serializeSyncState`) reads back and keeps
/// syncing: the server still has that version, so a HEAD says unchanged.
#[test]
fn ts_sync_state_carries_over() {
    let json = include_str!("fixtures/ts-sync-state.json").trim();
    let state = deserialize_sync_state(json).unwrap();
    assert_eq!(state.etag, "\"c141373a48c4e0c946cebce63f33f1a6575e52d5a850e0410d4ca28f822e006a\"");
    assert_eq!((state.revision, state.generation), (1, 0));
    let id = ov_sync::state::parse_uuid_id("RS3gXnCcsJmdLCFCOKDZ6w==").unwrap();
    assert_eq!(state.snapshot, vec![(id, 100_000)]);
    let base = state.base.clone().unwrap();
    assert_eq!(etag_for(&base), state.etag);
    assert_eq!(serialize_sync_state(&state), json, "the TS JSON is reproduced byte for byte");

    // The base is a kdbxweb file: it opens, and the sync carries on from it.
    let mut local = ov_kdbx::read(&base, &creds()).unwrap();
    assert_eq!(get(&local, "A", "Password"), Some("p".into()));
    let s = FakeSync::new();
    s.store("databases/db", &base);
    let (c, k) = ([creds()], creds());
    let blob = World::blob(&s, "db");
    let r = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&state)).local_changed(false))).unwrap();
    assert_eq!(r.outcome, SyncOutcome::Unchanged);
    edit(&mut local, "A", &[("URL", "u")], 200);
    let r = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&state)))).unwrap();
    assert_eq!((r.outcome, r.state.revision), (SyncOutcome::Uploaded, 2));
    assert_eq!(r.conflicts, vec![]);
}

#[test]
fn reports_progress_and_stops_when_cancelled() {
    let s = FakeSync::new();
    let Copies { mut local, .. } = three_copies(|db| {
        add_entry(db, "A", &[], 100, None);
    });
    let steps = Mutex::new(Vec::new());
    let progress = |st: SyncStep| steps.lock().unwrap().push(st);
    let (c, k) = ([creds()], creds());
    let blob = World::blob(&s, "db");
    let first = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).progress(&progress))).unwrap();
    assert_eq!(*steps.lock().unwrap(), [SyncStep::Downloading, SyncStep::Uploading]);
    steps.lock().unwrap().clear();
    edit(&mut local, "A", &[("URL", "u")], 200);
    run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).state(Some(&first.state)).progress(&progress))).unwrap();
    assert_eq!(*steps.lock().unwrap(), [SyncStep::Downloading, SyncStep::Merging, SyncStep::Uploading]);

    let cancelled = || true;
    let e = run(sync_kdbx(&blob, &mut local, &SyncOptions::new(&k, &c).cancel(&cancelled))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::Aborted);
}

/// Offline: the transport's error comes back as `network_error` and the working copy is intact.
#[test]
fn offline_is_a_network_error() {
    struct Down;
    #[async_trait::async_trait]
    impl ov_host::HttpTransport for Down {
        async fn send(&self, _r: ov_host::HttpRequest) -> Result<ov_host::HttpResponse, ov_host::TransportError> {
            Err(ov_host::TransportError::Offline)
        }
        async fn open_stream(
            &self,
            _r: ov_host::HttpRequest,
        ) -> Result<Box<dyn ov_host::ByteStream>, ov_host::TransportError> {
            Err(ov_host::TransportError::Offline)
        }
    }
    let client = ov_sync::SyncClient::new(
        Arc::new(Down),
        Arc::new(ov_testkit::ManualClock::new(NOW_MS)),
        ov_protocol::sync::SyncApi::self_hosted("https://sync.example").unwrap(),
        Arc::new(ov_sync::StaticToken(None)),
    );
    let Copies { mut local, .. } = three_copies(|db| {
        add_entry(db, "A", &[], 100, None);
    });
    let before = local.clone();
    let (c, k) = ([creds()], creds());
    let e = run(sync_kdbx(&client.database("db"), &mut local, &SyncOptions::new(&k, &c))).unwrap_err();
    assert!(e.is_unreachable());
    assert_eq!(e.code, OvErrorCode::NetworkError);
    assert!(local == before);
}
