//! Service-account writes and pulls against the W2-E servers: the 412 race (another device uploads
//! between the SA's download and its upload) must merge field by field against the base, as TS 0.11
//! did, and the SA downloads only as often as it needs to.

mod servers_common;

use std::sync::{Arc, Mutex};

use ov_core::api::*;
use ov_core::host::Method;
use ov_testkit::servers::TestServers;
use servers_common::*;

fn set_field(v: &Vault, title: &str, field_name: &str, value: &str) {
    let id = find_title(v, title).id;
    v.edit_entry(
        id,
        EntryInput {
            fields: vec![FieldInput { name: field_name.into(), value: value.as_bytes().to_vec(), protected: None }],
            ..Default::default()
        },
    )
    .unwrap();
}

struct World {
    s: TestServers,
    alice: Account,
    vault_id: String,
    write_token: Vec<u8>,
    read_token: Vec<u8>,
}

/// Alice's org vault "Team Infra" with "GitHub" (UserName ci, Password s3cret), and a write and a
/// read service account on it (the SDK's `world.ts`).
async fn world() -> World {
    let s = servers();
    let alice = connect(&device(&s, false), &s).await;
    register(&alice, "alice@example.com", "correct horse ü").await;
    let org = alice.create_org("Acme".into(), nc()).await.unwrap();
    let vault = alice.create_vault("Team Infra".into(), Some(org.id.clone()), nc()).await.unwrap();
    add_entry(&vault, "GitHub", "s3cret");
    set_field(&vault, "GitHub", "UserName", "ci");
    vault.sync(SyncOptions::default(), nc()).await.unwrap();
    let mut tokens = Vec::new();
    for (name, role) in [("ci-write", VaultRole::Write), ("ci-read", VaultRole::Read)] {
        let input = NewServiceAccount {
            name: name.into(),
            vaults: vec![VaultGrantRequest { vault_id: vault.id(), role }],
            expires_at: None,
            secret_name: None,
        };
        tokens.push(alice.create_service_account(org.id.clone(), input, nc()).await.unwrap().token);
    }
    let read_token = tokens.pop().unwrap();
    let write_token = tokens.pop().unwrap();
    World { s, alice, vault_id: vault.id(), write_token, read_token }
}

/// Another device edits `title` right after the next `skip + 1`-th GET of the vault (TS
/// `editBetweenGetAndPut`) on a clock `advance_ms` ahead of the SA's (one second: its copy of the
/// entry is newer, so a merge without the base keeps it whole). Returns whether it fired.
async fn edit_between_get_and_put(w: &World, title: &'static str, fields: &'static [(&'static str, &'static str)], skip: usize, advance_ms: i64) -> Arc<Mutex<bool>> {
    let creds = w.alice.vault_kdbx_credentials(w.vault_id.clone(), nc()).await.unwrap();
    let fired = Arc::new(Mutex::new(false));
    let skip = Arc::new(Mutex::new(skip));
    let (f2, vault_id) = (fired.clone(), w.vault_id.clone());
    let client = device(&w.s, false);
    w.s.set_after_get(Some(Arc::new(move |s: &TestServers, id: &str| {
        if id != vault_id || *f2.lock().unwrap() {
            return;
        }
        {
            let mut n = skip.lock().unwrap();
            if *n > 0 {
                *n -= 1;
                return;
            }
        }
        *f2.lock().unwrap() = true;
        s.clock().advance(advance_ms);
        let cur = s.vault_blob(id).unwrap().data;
        let other = ov_testkit::servers::block_on(client.open_local(cur, creds.clone(), nc())).unwrap();
        for (k, v) in fields {
            set_field(&other, title, k, v);
        }
        let bytes = ov_testkit::servers::block_on(other.save_local(nc())).unwrap();
        s.put_vault_blob(id, &bytes);
        // Only the other device's clock was off: the SA's stays where it was
        s.clock().advance(-advance_ms);
    })));
    fired
}

fn count(s: &TestServers, method: Method, vault_id: &str) -> usize {
    s.requests().iter().filter(|r| r.method == method && r.path.ends_with(&format!("/vaults/{vault_id}"))).count()
}

async fn read(w: &World, reference: &str) -> String {
    let fresh = ServiceAccount::from_token(device(&w.s, false), w.read_token.clone(), nc()).await.unwrap();
    let v = String::from_utf8(fresh.read(reference.into(), nc()).await.unwrap()).unwrap();
    fresh.close();
    v
}

/// SDK `service-account.test.ts` "merges and retries on 412 when another client uploads in between".
#[tokio::test]
async fn a_write_that_hits_412_merges_field_by_field_against_the_base() {
    let w = world().await;
    let sa = ServiceAccount::from_token(device(&w.s, false), w.write_token.clone(), nc()).await.unwrap();
    sa.open_vault(w.vault_id.clone(), false, nc()).await.unwrap();
    let fired = edit_between_get_and_put(&w, "GitHub", &[("UserName", "changed-elsewhere")], 0, 1_000).await;
    let puts = count(&w.s, Method::Put, &w.vault_id);
    sa.write("ov://Team%20Infra/GitHub/password".into(), b"from-sa".to_vec(), false, nc()).await.unwrap();
    w.s.set_after_get(None);
    assert!(*fired.lock().unwrap());
    assert_eq!(count(&w.s, Method::Put, &w.vault_id) - puts, 2, "412, then the merged upload");
    assert_eq!(read(&w, "ov://Team%20Infra/GitHub/password").await, "from-sa");
    assert_eq!(read(&w, "ov://Team%20Infra/GitHub/username").await, "changed-elsewhere");
    sa.close();
}

/// The same race when the SA hasn't opened the vault yet (the CLI's `ov rotate`: one process per
/// write), with the other device's edit after the SA's download (SDK `cli.test.ts`).
#[tokio::test]
async fn a_first_write_that_hits_412_keeps_both_changes() {
    let w = world().await;
    let sa = ServiceAccount::from_token(device(&w.s, false), w.write_token.clone(), nc()).await.unwrap();
    let fired = edit_between_get_and_put(&w, "GitHub", &[("Notes", "edited on another device")], 0, 1_000).await;
    let puts = count(&w.s, Method::Put, &w.vault_id);
    sa.write("ov://Team%20Infra/GitHub/password".into(), b"rotated-in-race".to_vec(), false, nc()).await.unwrap();
    w.s.set_after_get(None);
    assert!(*fired.lock().unwrap());
    assert_eq!(count(&w.s, Method::Put, &w.vault_id) - puts, 2, "412, then the merged upload");
    assert_eq!(read(&w, "ov://Team%20Infra/GitHub/password").await, "rotated-in-race");
    assert_eq!(read(&w, "ov://Team%20Infra/GitHub/notes").await, "edited on another device");
    sa.close();
}

/// A write by an SA that hasn't opened the vault downloads it once before its PUT (TS: once).
#[tokio::test]
async fn a_first_write_downloads_once_before_its_put() {
    let w = world().await;
    let sa = ServiceAccount::from_token(device(&w.s, false), w.write_token.clone(), nc()).await.unwrap();
    let (gets, puts) = (count(&w.s, Method::Get, &w.vault_id), count(&w.s, Method::Put, &w.vault_id));
    sa.write("ov://Team%20Infra/GitHub/password".into(), b"new".to_vec(), false, nc()).await.unwrap();
    assert_eq!(count(&w.s, Method::Get, &w.vault_id) - gets, 1);
    assert_eq!(count(&w.s, Method::Put, &w.vault_id) - puts, 1);
    // A second write on the open copy: one GET (the conditional PUT's merge), one PUT.
    sa.write("ov://Team%20Infra/GitHub/password".into(), b"newer".to_vec(), false, nc()).await.unwrap();
    assert_eq!(count(&w.s, Method::Get, &w.vault_id) - gets, 2);
    assert_eq!(read(&w, "ov://Team%20Infra/GitHub/password").await, "newer");
    sa.close();
}

/// `open_vault` and `pull` download a changed vault with one GET; `pull` of an unchanged one is a
/// HEAD only (SDK "pull only downloads when the server has a new version").
#[tokio::test]
async fn open_and_pull_download_once() {
    let w = world().await;
    let sa = ServiceAccount::from_token(device(&w.s, false), w.read_token.clone(), nc()).await.unwrap();
    let gets = count(&w.s, Method::Get, &w.vault_id);
    sa.open_vault(w.vault_id.clone(), false, nc()).await.unwrap();
    assert_eq!(count(&w.s, Method::Get, &w.vault_id) - gets, 1);
    let gets = count(&w.s, Method::Get, &w.vault_id);
    sa.pull(w.vault_id.clone(), nc()).await.unwrap();
    assert_eq!(count(&w.s, Method::Get, &w.vault_id), gets, "HEAD → 304");
    assert_eq!(count(&w.s, Method::Head, &w.vault_id), 1);
    let writer = ServiceAccount::from_token(device(&w.s, false), w.write_token.clone(), nc()).await.unwrap();
    writer.write("ov://Team%20Infra/GitHub/password".into(), b"pulled".to_vec(), false, nc()).await.unwrap();
    let gets = count(&w.s, Method::Get, &w.vault_id);
    let v = sa.pull(w.vault_id.clone(), nc()).await.unwrap();
    assert_eq!(count(&w.s, Method::Get, &w.vault_id) - gets, 1);
    assert_eq!(v.read_field("ov://x/GitHub/password".into()).unwrap(), b"pulled");
    writer.close();
    sa.close();
}

/// The race at every ordering of the three clocks within and across seconds: the snapshot (the
/// download), the SA's edit and the other device's edit. Which copy is newer, or a tie, must not
/// decide which change survives.
#[tokio::test]
async fn the_412_merge_does_not_depend_on_the_clock() {
    let mut failed = Vec::new();
    for before_write in [0i64, 400, 1_000, 3_000] {
        for in_hook in [-2_000i64, 0, 400, 1_000] {
            let w = world().await;
            let sa = ServiceAccount::from_token(device(&w.s, false), w.write_token.clone(), nc()).await.unwrap();
            sa.open_vault(w.vault_id.clone(), false, nc()).await.unwrap();
            w.s.clock().advance(before_write);
            let fired = edit_between_get_and_put(&w, "GitHub", &[("UserName", "changed-elsewhere")], 0, in_hook).await;
            sa.write("ov://Team%20Infra/GitHub/password".into(), b"from-sa".to_vec(), false, nc()).await.unwrap();
            w.s.set_after_get(None);
            assert!(*fired.lock().unwrap());
            let got = (
                read(&w, "ov://Team%20Infra/GitHub/password").await,
                read(&w, "ov://Team%20Infra/GitHub/username").await,
            );
            if got != ("from-sa".to_owned(), "changed-elsewhere".to_owned()) {
                failed.push((before_write, in_hook, got));
            }
            sa.close();
        }
    }
    assert!(failed.is_empty(), "lost a change (ms before the write, ms in the hook, result): {failed:?}");
}
