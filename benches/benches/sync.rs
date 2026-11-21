//! A sync round trip (`ov_sync::sync_kdbx`) against ov-testkit's in-memory sync server, as
//! ov-sync's `tests/servers.rs` runs it: another device uploaded a version since this device's
//! last sync, so the sync downloads it, opens it and the base, merges, saves and uploads.
//! `round_trip_cached` is the same with the base already opened in a [`BaseCache`], as a
//! `VaultSession` keeps it between syncs. `local_edit` / `local_edit_cached`: nobody else uploaded,
//! so the server copy is the base (the cache opens neither).

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ov_benches::{three_way, T_MERGE};
use ov_kdbx::model::Database;
use ov_kdbx::CompositeKey;
use ov_protocol::sync::SyncApi;
use ov_sync::{sync_kdbx, BaseCache, Blob, StaticToken, SyncClient, SyncOptions, SyncOutcome, SyncState};
use ov_testkit::servers::{TestServers, DEVICE_TOKEN};
use ov_testkit::ManualClock;

fn blob(servers: &TestServers, clock: Arc<ManualClock>) -> Blob {
    SyncClient::new(
        servers.http(),
        clock,
        SyncApi::new(&servers.sync_url()).expect("sync url"),
        Arc::new(StaticToken(Some(DEVICE_TOKEN.to_string()))),
    )
    .database("bench")
}

/// The server has `base`, this device synced it, then another device uploaded `remote`.
fn setup(base: &[u8], remote: &[u8], key: &CompositeKey) -> (TestServers, Blob, SyncState) {
    let clock = Arc::new(ManualClock::new(T_MERGE * 1000));
    let servers = TestServers::new(clock.clone());
    servers.put_database_blob("bench", base);
    let blob = blob(&servers, clock);
    let mut copy = ov_kdbx::read(base, key).expect("read base");
    let creds = [key.clone()];
    let mut opts = SyncOptions::new(key, &creds);
    opts.local_changed = false;
    let first = futures::executor::block_on(sync_kdbx(&blob, &mut copy, &opts)).expect("first sync");
    servers.put_database_blob("bench", remote);
    (servers, blob, first.state)
}

fn round_trip(
    blob: &Blob,
    local: &mut Database,
    state: &SyncState,
    key: &CompositeKey,
    cache: Option<&BaseCache>,
) -> SyncOutcome {
    let creds = [key.clone()];
    let mut opts = SyncOptions::new(key, &creds);
    opts.state = Some(state);
    opts.base_cache = cache;
    futures::executor::block_on(sync_kdbx(blob, local, &opts)).expect("sync").outcome
}

fn sync(c: &mut Criterion) {
    let mut g = c.benchmark_group("sync");
    g.sample_size(15);
    for total in [100u32, 5000] {
        let (base, local, remote, key) = three_way(total);
        let base_bytes = ov_kdbx::write(&base, &key).expect("write base");
        let remote_bytes = ov_kdbx::write(&remote, &key).expect("write remote");
        {
            let (_s, blob, state) = setup(&base_bytes, &remote_bytes, &key);
            let outcome = round_trip(&blob, &mut local.clone(), &state, &key, None);
            assert_eq!(outcome, SyncOutcome::Uploaded, "the round trip merges and uploads");
        }
        let opened_base = ov_kdbx::read(&base_bytes, &key).expect("read base");
        g.bench_function(format!("round_trip/{total}"), |b| {
            b.iter_batched(
                || {
                    let (s, blob, state) = setup(&base_bytes, &remote_bytes, &key);
                    (s, blob, state, local.clone())
                },
                |(_s, blob, state, mut local)| round_trip(&blob, &mut local, &state, &key, None),
                BatchSize::PerIteration,
            )
        });
        for cached in [false, true] {
            let name = if cached { "local_edit_cached" } else { "local_edit" };
            g.bench_function(format!("{name}/{total}"), |b| {
                b.iter_batched(
                    || {
                        let (s, blob, state) = setup(&base_bytes, &base_bytes, &key);
                        let cache = BaseCache::new();
                        if cached {
                            cache.keep(state.base.as_deref().expect("a base"), &key, opened_base.clone());
                        }
                        (s, blob, state, local.clone(), cache)
                    },
                    |(_s, blob, state, mut local, cache)| {
                        round_trip(&blob, &mut local, &state, &key, cached.then_some(&cache))
                    },
                    BatchSize::PerIteration,
                )
            });
        }
        g.bench_function(format!("round_trip_cached/{total}"), |b| {
            b.iter_batched(
                || {
                    let (s, blob, state) = setup(&base_bytes, &remote_bytes, &key);
                    let cache = BaseCache::new();
                    cache.keep(state.base.as_deref().expect("a base"), &key, opened_base.clone());
                    (s, blob, state, local.clone(), cache)
                },
                |(_s, blob, state, mut local, cache)| round_trip(&blob, &mut local, &state, &key, Some(&cache)),
                BatchSize::PerIteration,
            )
        });
    }
    g.finish();
}

criterion_group!(benches, sync);
criterion_main!(benches);
