//! Every `.kdbx` fixture in `vectors/` and the kdbxweb + iOS files of `corpus/kdbx/` opens, writes and reopens equal.

use ov_kdbx::model::{Database, KdbxVersion};
use ov_kdbx::CompositeKey;
use ov_testkit::kdbx;
use std::path::PathBuf;

fn vault_key() -> Vec<u8> {
    hex(&ov_testkit::test_vectors().vault_kdbx.vault_key_hex)
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A file from the KDBX spike, now in `corpus/kdbx/{kdbxweb,ios}/` (W1-K3).
fn spike(name: &str) -> PathBuf {
    let dir = if name.starts_with("ios-") { "ios" } else { "kdbxweb" };
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/kdbx").join(dir).join(name)
}

/// (label, bytes, key)
pub fn fixtures() -> Vec<(String, Vec<u8>, CompositeKey)> {
    let pw = |p: &str| CompositeKey::new().with_password(p);
    let vk = || CompositeKey::new().with_key_file(&vault_key());
    let mut v = vec![
        (kdbx::VAULT_FIXTURE.to_string(), kdbx::bytes(kdbx::VAULT_FIXTURE), vk()),
        (kdbx::DESKTOP_KDBX31.to_string(), kdbx::bytes(kdbx::DESKTOP_KDBX31), pw(kdbx::DESKTOP_PASSWORD)),
        (kdbx::DESKTOP_KDBX4_ARGON2D.to_string(), kdbx::bytes(kdbx::DESKTOP_KDBX4_ARGON2D), pw(kdbx::DESKTOP_PASSWORD)),
    ];
    for (name, key) in [
        ("kdbxweb-vault.kdbx", vk()),
        ("kdbxweb-unknown.kdbx", pw("spike pw")),
        ("kdbxweb-unknown-leaf.kdbx", pw("spike pw")),
        ("ios-interop.kdbx", pw(kdbx::DESKTOP_PASSWORD)),
        ("ios-passkey.kdbx", pw("interop")),
    ] {
        v.push((name.to_string(), std::fs::read(spike(name)).unwrap(), key));
    }
    v
}

fn upgraded(mut db: Database, written: KdbxVersion) -> Database {
    db.header.version = written;
    db
}

#[test]
fn every_fixture_opens_and_round_trips() {
    for (name, bytes, key) in fixtures() {
        let db = ov_kdbx::read(&bytes, &key).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let out = ov_kdbx::write(&db, &key).unwrap_or_else(|e| panic!("{name}: write: {e:?}"));
        let back = ov_kdbx::read(&out, &key).unwrap_or_else(|e| panic!("{name}: reread: {e:?}"));
        let expected_version = ov_kdbx::write_version(&db);
        assert_eq!(back.header.version, expected_version, "{name}");
        assert_eq!(back, upgraded(db.clone(), expected_version), "{name}: write → read differs");
        let again = ov_kdbx::read(&ov_kdbx::write(&back, &key).unwrap(), &key).unwrap();
        assert_eq!(again, back, "{name}: second save differs");
        println!(
            "{name}: {:?}, {} entries in root, {} binaries",
            db.header.version,
            db.root.entries.len(),
            db.binaries.len()
        );
    }
}

/// Writes every fixture's rewrite to `target/k2-rewrites/` for checking with the desktop CLI.
#[test]
#[ignore = "manual interop check with openvireo-cli"]
fn dump_rewrites() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/k2-rewrites");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes, key) in fixtures() {
        let db = ov_kdbx::read(&bytes, &key).unwrap();
        let file = dir.join(name.replace('/', "_"));
        std::fs::write(file, ov_kdbx::write(&db, &key).unwrap()).unwrap();
    }
}
