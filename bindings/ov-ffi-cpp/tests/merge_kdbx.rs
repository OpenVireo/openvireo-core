//! `merge_kdbx` (the bridge's bytes-in/bytes-out sync merge) against every merge fixture in
//! `vectors/merge-fixtures/`: each copy is built with ov-merge's own fixture adapter, written as
//! KDBX with a throwaway key (as the desktop does), merged through the bridge function, read back,
//! and compared with the fixture's expected projection and conflicts.
//!
//! Also checks the `.kdbx` copies of fixtures the C++ smoke merges (`smoke/fixtures/`). Regenerate
//! them with `cargo test -p ov-ffi-cpp --test merge_kdbx -- --ignored write_smoke_fixtures`.

#[path = "../../../crates/ov-merge/tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::{build, normalize, project};
use ov_ffi_cpp::ffi::{ChangeSubject, ChangeType};
use ov_ffi_cpp::merge_kdbx;
use ov_kdbx::model::{Argon2Type, Database, Kdf};
use ov_kdbx::CompositeKey;
use ov_testkit::{merge_fixtures, utc_seconds};

/// The password of the smoke's fixture copies; the key component is its SHA-256.
const SMOKE_PASSWORD: &str = "ov-ffi-cpp merge fixture";
/// The fixtures the C++ smoke merges.
const SMOKE_FIXTURES: [&str; 2] = ["07-no-base-newer-wins", "11-moved-here-edited-there"];

fn smoke_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("smoke/fixtures")
}

/// A cheap KDF, so 14 fixtures × 8 KDBX reads and writes stay fast.
fn cheap(mut db: Database) -> Database {
    db.header.kdf = Kdf::Argon2 {
        kind: Argon2Type::Id,
        salt: vec![7; 32],
        memory: 1 << 20,
        iterations: 1,
        parallelism: 1,
        version: 0x13,
        secret: None,
        associated_data: None,
    };
    db
}

fn component(password: &str) -> [u8; 32] {
    ov_crypto::primitives::sha256(password.as_bytes())
}

fn key(component: &[u8; 32]) -> CompositeKey {
    CompositeKey::new().with_password_hash(component)
}

#[test]
fn every_merge_fixture_through_merge_kdbx() {
    let fixtures = merge_fixtures();
    assert_eq!(fixtures.len(), 14);
    let mut failures = Vec::new();
    for (name, fx) in &fixtures {
        // A throwaway key, as SyncEngine::mergeAccountVault makes one per merge
        let k: [u8; 32] = ov_crypto::primitives::random_bytes(32).unwrap().as_slice().try_into().unwrap();
        let ck = key(&k);
        let local = ov_kdbx::write(&cheap(build(&fx.local)), &ck).unwrap();
        let remote = ov_kdbx::write(&cheap(build(&fx.remote)), &ck).unwrap();
        let base = fx.base.as_ref().map(|b| ov_kdbx::write(&cheap(build(b)), &ck).unwrap()).unwrap_or_default();
        let base_key: &[u8] = if base.is_empty() { &[] } else { &k };

        let r = merge_kdbx(&local, &k, &remote, &k, &base, base_key, utc_seconds(&fx.now)).unwrap();
        assert_eq!(r.local.is_empty(), !r.local_changed, "{name}");
        assert_eq!(r.remote.is_empty(), !r.remote_changed, "{name}");
        let merged_local = ov_kdbx::read(if r.local_changed { &r.local } else { &local }, &ck).unwrap();
        let merged_remote = ov_kdbx::read(if r.remote_changed { &r.remote } else { &remote }, &ck).unwrap();

        let got = project(&merged_local);
        let theirs = project(&merged_remote);
        if theirs.entries != got.entries || theirs.groups != got.groups {
            failures.push(format!("{name}: remote differs from local"));
        }
        let want = normalize(&fx.expected.result);
        if got != want {
            failures.push(format!("{name}: result\n got {got:#?}\nwant {want:#?}"));
        }
        let conflicts: BTreeMap<String, Vec<String>> =
            r.conflicts.iter().map(|c| (c.uuid.clone(), c.fields.clone())).collect();
        if conflicts != fx.expected.conflicts {
            failures.push(format!("{name}: conflicts {conflicts:?}, want {:?}", fx.expected.conflicts));
        }
        for c in &r.changes {
            let uuid_ok = match c.subject {
                ChangeSubject::Database => c.uuid.is_empty(),
                _ => c.uuid.len() == 16,
            };
            if !uuid_ok {
                failures.push(format!("{name}: change {c:?}"));
            }
        }
        if (r.local_changed || r.remote_changed) && r.changes.is_empty() {
            failures.push(format!("{name}: copies changed but no changes reported"));
        }
    }
    assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n\n"));
}

#[test]
fn moved_here_edited_there_reports_the_changes() {
    let fx = merge_fixtures().into_iter().find(|(n, _)| n.starts_with("11-")).unwrap().1;
    let k = component("k");
    let ck = key(&k);
    let local = ov_kdbx::write(&cheap(build(&fx.local)), &ck).unwrap();
    let remote = ov_kdbx::write(&cheap(build(&fx.remote)), &ck).unwrap();
    let base = ov_kdbx::write(&cheap(build(fx.base.as_ref().unwrap())), &ck).unwrap();
    let r = merge_kdbx(&local, &k, &remote, &k, &base, &k, utc_seconds(&fx.now)).unwrap();
    assert!(r.local_changed && r.remote_changed);
    let entry = r.changes.iter().find(|c| c.subject == ChangeSubject::Entry).expect("an entry change");
    assert_eq!(entry.uuid, hex::decode("a1000000000040008000000000000001").unwrap());
    assert!(matches!(entry.change, ChangeType::Modified | ChangeType::Moved), "{entry:?}");
    assert_eq!(entry.title, "Bank");
}

#[test]
fn bad_keys_and_bytes_fail_cleanly() {
    let fx = &merge_fixtures()[0].1;
    let k = component("k");
    let local = ov_kdbx::write(&cheap(build(&fx.local)), &key(&k)).unwrap();
    let err = |r: Result<ov_ffi_cpp::ffi::KdbxMergeResult, ov_ffi_cpp::FfiError>| {
        let Err(e) = r else { panic!("expected an error") };
        e.0.wire_code().to_string()
    };
    assert_eq!(err(merge_kdbx(&local, &k[..31], &local, &k, &[], &[], 0)), "invalid_request");
    assert_eq!(err(merge_kdbx(&local, &[k, k, k].concat(), &local, &k, &[], &[], 0)), "invalid_request");
    let wrong = component("other");
    assert_ne!(err(merge_kdbx(&local, &wrong, &local, &k, &[], &[], 0)), "internal");
    assert_ne!(err(merge_kdbx(b"not a kdbx", &k, &local, &k, &[], &[], 0)), "internal");
    // Two components (password + 32-byte key file) are accepted
    let two = CompositeKey::new().with_password_hash(&k).with_key_file(&wrong);
    let local2 = ov_kdbx::write(&cheap(build(&fx.local)), &two).unwrap();
    let both = [k, wrong].concat();
    merge_kdbx(&local2, &both, &local2, &both, &[], &[], 0).unwrap();
}

/// The smoke's committed copies are the fixtures' databases under [`SMOKE_PASSWORD`].
#[test]
fn smoke_fixtures_match_the_vectors() {
    let all = merge_fixtures();
    let ck = CompositeKey::new().with_password(SMOKE_PASSWORD);
    for name in SMOKE_FIXTURES {
        let fx = &all.iter().find(|(n, _)| n.trim_end_matches(".json") == name).unwrap().1;
        let sides = [("local", Some(&fx.local)), ("remote", Some(&fx.remote)), ("base", fx.base.as_ref())];
        for (side, spec) in sides {
            let path = smoke_dir().join(format!("{name}.{side}.kdbx"));
            match spec {
                Some(spec) => {
                    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
                        panic!("{}: {e} (run the ignored write_smoke_fixtures test)", path.display())
                    });
                    let db = ov_kdbx::read(&bytes, &ck).unwrap();
                    assert_eq!(project(&db), project(&build(spec)), "{}", path.display());
                }
                None => assert!(!path.exists(), "{} has no base", name),
            }
        }
    }
}

#[test]
#[ignore = "writes smoke/fixtures/*.kdbx"]
fn write_smoke_fixtures() {
    let all = merge_fixtures();
    let ck = CompositeKey::new().with_password(SMOKE_PASSWORD);
    std::fs::create_dir_all(smoke_dir()).unwrap();
    for name in SMOKE_FIXTURES {
        let fx = &all.iter().find(|(n, _)| n.trim_end_matches(".json") == name).unwrap().1;
        let sides = [("local", Some(&fx.local)), ("remote", Some(&fx.remote)), ("base", fx.base.as_ref())];
        for (side, spec) in sides {
            if let Some(spec) = spec {
                let path = smoke_dir().join(format!("{name}.{side}.kdbx"));
                std::fs::write(&path, ov_kdbx::write(&cheap(build(spec)), &ck).unwrap()).unwrap();
            }
        }
    }
}
