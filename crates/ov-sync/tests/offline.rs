//! Offline (SPEC §20): `VaultSession` keeps edits in the `BlobCache` while the server can't be
//! reached, opens the cached copy offline, and uploads the edits once back online (TS
//! `AccountVault.sync` / `openLocalCopy`).

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use ov_error::{OvError, OvErrorCode};
use ov_host::{BlobCache, ByteStream, CachedVault, HttpRequest, HttpResponse, HttpTransport, TransportError};
use ov_kdbx::vault::KeyVersion;
use ov_protocol::sync::SyncApi;
use ov_sync::{SessionSyncOptions, StaticToken, SyncClient, SyncOutcome, VaultCache, VaultSession};
use zeroize::Zeroizing;

#[derive(Default)]
struct MemoryCache(Mutex<HashMap<(String, String), CachedVault>>);

#[async_trait::async_trait]
impl BlobCache for MemoryCache {
    async fn load(&self, u: &str, v: &str) -> Result<Option<CachedVault>, OvError> {
        Ok(self.0.lock().unwrap().get(&(u.into(), v.into())).cloned())
    }
    async fn save(&self, u: &str, v: &str, c: &CachedVault) -> Result<(), OvError> {
        self.0.lock().unwrap().insert((u.into(), v.into()), c.clone());
        Ok(())
    }
    async fn remove(&self, u: &str, v: &str) -> Result<(), OvError> {
        self.0.lock().unwrap().remove(&(u.into(), v.into()));
        Ok(())
    }
    async fn list(&self, u: &str) -> Result<Vec<String>, OvError> {
        Ok(self.0.lock().unwrap().keys().filter(|k| k.0 == u).map(|k| k.1.clone()).collect())
    }
    async fn load_meta(&self, _u: &str, _n: &str) -> Result<Option<Vec<u8>>, OvError> {
        Ok(None)
    }
    async fn save_meta(&self, _u: &str, _n: &str, _v: &[u8]) -> Result<(), OvError> {
        Ok(())
    }
    async fn clear_user(&self, u: &str) -> Result<(), OvError> {
        self.0.lock().unwrap().retain(|k, _| k.0 != u);
        Ok(())
    }
}

/// The fake server behind a switch.
struct Switch {
    server: FakeSync,
    offline: AtomicBool,
}

#[async_trait::async_trait]
impl HttpTransport for Switch {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }
        self.server.send(req).await
    }
    async fn open_stream(&self, _req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
        Err(TransportError::Offline)
    }
}

fn keys() -> Vec<KeyVersion> {
    vec![KeyVersion { version: 1, key: Zeroizing::new(KEY.to_vec()) }]
}

struct Device {
    net: Arc<Switch>,
    cache: Arc<MemoryCache>,
    client: SyncClient,
}

fn device(server: &FakeSync) -> Device {
    let net = Arc::new(Switch { server: server.clone(), offline: AtomicBool::new(false) });
    let client = SyncClient::new(
        net.clone(),
        World::clock(server),
        SyncApi::new("https://sync.example/api/v1").unwrap(),
        Arc::new(StaticToken(Some(DEVICE_TOKEN.into()))),
    );
    Device { net, cache: Arc::new(MemoryCache::default()), client }
}

impl Device {
    fn session(&self) -> VaultSession {
        VaultSession::new(Some(VaultCache::new(self.cache.clone(), "user-1", "v1")))
    }
    fn offline(&self, on: bool) {
        self.net.offline.store(on, Ordering::SeqCst);
    }
}

#[test]
fn edits_made_offline_survive_a_restart_and_upload_later() {
    let server = FakeSync::new();
    let Copies { bytes, .. } = three_copies(|db| {
        add_entry(db, "A", &[("Password", "p")], 100, None);
    });
    server.store("vaults/v1", &bytes);
    let d = device(&server);
    let blob = d.client.vault("v1");

    let mut s = d.session();
    let r = run(s.sync(&blob, &keys(), SessionSyncOptions::default())).unwrap();
    assert_eq!(r.outcome, SyncOutcome::Pulled);
    assert!(!s.offline);
    assert_eq!(s.etag(), Some(r.state.etag.as_str()));
    let rec = run(d.cache.load("user-1", "v1")).unwrap().unwrap();
    assert!(rec.base.is_some() && rec.pending.is_none());

    // Offline: the edit is kept as pending and the error is network_error.
    edit(s.db.as_mut().unwrap(), "A", &[("Password", "offline")], 200);
    d.offline(true);
    let e = run(s.sync(&blob, &keys(), SessionSyncOptions::default())).unwrap_err();
    assert_eq!(e.code, OvErrorCode::NetworkError);
    assert!(s.offline && s.has_pending());
    assert!(run(d.cache.load("user-1", "v1")).unwrap().unwrap().pending.is_some());

    // The app restarts, still offline: the pending copy opens.
    let mut s = d.session();
    run(s.open_local_copy(&keys(), "Vault", &e)).unwrap();
    assert!(s.offline);
    assert_eq!(get(s.db.as_ref().unwrap(), "A", "Password"), Some("offline".into()));

    // Back online: the edit is merged and uploaded, and pending goes.
    d.offline(false);
    let r = run(s.sync(&blob, &keys(), SessionSyncOptions::default())).unwrap();
    assert_eq!(r.outcome, SyncOutcome::Uploaded);
    assert!(!s.offline && !s.has_pending());
    assert!(run(d.cache.load("user-1", "v1")).unwrap().unwrap().pending.is_none());
    let latest = {
        let blob = d.client.vault("v1");
        match run(blob.get(None)).unwrap() {
            ov_protocol::sync::GetResult::Ok { data, .. } => data,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(get(&ov_kdbx::read(&latest, &creds()).unwrap(), "A", "Password"), Some("offline".into()));
}

#[test]
fn opens_the_last_synced_copy_offline() {
    let server = FakeSync::new();
    let Copies { bytes, .. } = three_copies(|db| {
        add_entry(db, "A", &[("URL", "u")], 100, None);
    });
    server.store("vaults/v1", &bytes);
    let d = device(&server);
    run(d.session().sync(&d.client.vault("v1"), &keys(), SessionSyncOptions::default())).unwrap();

    d.offline(true);
    let mut s = d.session();
    let e = run(s.sync(&d.client.vault("v1"), &keys(), SessionSyncOptions::default())).unwrap_err();
    assert!(e.is_unreachable() && s.offline);
    run(s.open_local_copy(&keys(), "Vault", &e)).unwrap();
    assert_eq!(get(s.db.as_ref().unwrap(), "A", "URL"), Some("u".into()));
    // Nothing was edited, so nothing is pending.
    assert!(!s.has_pending());
}

#[test]
fn a_vault_never_synced_here_is_not_available_offline() {
    let server = FakeSync::new();
    let d = device(&server);
    d.offline(true);
    let mut s = d.session();
    let e = run(s.sync(&d.client.vault("v1"), &keys(), SessionSyncOptions::default())).unwrap_err();
    let e = run(s.open_local_copy(&keys(), "Work", &e)).unwrap_err();
    assert_eq!(e.code, OvErrorCode::NotAvailableOffline);
    assert!(e.message.contains("\"Work\""));
}

#[test]
fn keep_edits_makes_the_working_copy_durable() {
    let server = FakeSync::new();
    let Copies { bytes, .. } = three_copies(|db| {
        add_entry(db, "A", &[], 100, None);
    });
    server.store("vaults/v1", &bytes);
    let d = device(&server);
    let mut s = d.session();
    run(s.sync(&d.client.vault("v1"), &keys(), SessionSyncOptions::default())).unwrap();
    edit(s.db.as_mut().unwrap(), "A", &[("Notes", "kept")], 300);
    run(s.keep_edits()).unwrap();
    assert!(s.has_pending());
    // A new session (the app was killed) starts from the kept copy and uploads it.
    let mut s2 = d.session();
    let r = run(s2.sync(&d.client.vault("v1"), &keys(), SessionSyncOptions::default())).unwrap();
    assert_eq!(r.outcome, SyncOutcome::Uploaded);
    assert_eq!(get(&r.db, "A", "Notes"), Some("kept".into()));
}

#[test]
fn rotation_rekeys_the_upload() {
    let server = FakeSync::new();
    let Copies { bytes, .. } = three_copies(|db| {
        add_entry(db, "A", &[], 100, None);
    });
    server.store("vaults/v1", &bytes);
    let d = device(&server);
    let mut s = d.session();
    let new_key = [3u8; 32];
    let opts = SessionSyncOptions { rekey_to: Some(&new_key), ..Default::default() };
    let r = run(s.sync(&d.client.vault("v1"), &keys(), opts)).unwrap();
    assert_eq!(r.outcome, SyncOutcome::Uploaded);
    // The next sync needs the new key version, and finds it first.
    let mut both = keys();
    both.push(KeyVersion { version: 2, key: Zeroizing::new(new_key.to_vec()) });
    let r = run(s.sync(
        &d.client.vault("v1"),
        &both,
        SessionSyncOptions { local_changed: Some(false), ..Default::default() },
    ))
    .unwrap();
    assert_eq!((r.outcome, r.credentials_index), (SyncOutcome::Unchanged, None));
    let mut fresh = d.session();
    let r = run(fresh.sync(&d.client.vault("v1"), &both, SessionSyncOptions::default())).unwrap();
    assert_eq!(r.credentials_index, Some(0));
}
