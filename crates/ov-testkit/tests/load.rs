//! Loads every vector file with its typed loader and checks nothing is left untyped.

use ov_testkit::{
    b64u, hex, hex_bytes, kdbx, merge_fixtures, opaque_transcripts, read_vector, test_vectors, utc_seconds,
    vector_path, vectors_dir, FixedClock,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

fn raw_json(relative: &str) -> serde_json::Value {
    serde_json::from_slice(&read_vector(relative)).unwrap()
}

/// Typed value serialised back must equal the file: no field dropped, renamed or reshaped.
fn assert_lossless<T: Serialize>(relative: &str, typed: &T) {
    assert_eq!(serde_json::to_value(typed).unwrap(), raw_json(relative), "{relative} does not round-trip");
}

#[test]
fn test_vectors_every_section_is_typed() {
    let raw = raw_json("test-vectors.json");
    let keys: Vec<&str> = raw.as_object().unwrap().keys().map(String::as_str).collect();
    let mut expected = ov_testkit::test_vectors::SECTIONS.to_vec();
    let mut got = keys.clone();
    expected.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, expected, "test-vectors.json sections changed: type the new ones in ov-testkit");

    let tv = test_vectors();
    assert_lossless("test-vectors.json", &tv);
}

#[test]
fn test_vectors_decode() {
    let tv = test_vectors();
    assert_eq!(tv.spec, "ov v1");
    assert_eq!(tv.secret_key.len(), 3);
    for sk in &tv.secret_key {
        assert_eq!(hex_bytes(&sk.raw_hex).len(), 16);
    }
    for a in &tv.auk {
        if a.password.is_ascii() {
            assert_eq!(hex_bytes(&a.password_nfkc_hex), a.password.as_bytes(), "ASCII passwords are already NFKC");
        }
        assert_eq!(b64u(&a.kdf.salt).len(), 16);
        assert_eq!(hex_bytes(&a.auk_hex).len(), 32);
    }
    assert_eq!(b64u(&tv.keyset.public.enc_pk).len(), 32);
    assert_eq!(b64u(&tv.keyset.public.sig).len(), 64);
    assert!(!tv.seal.is_empty() && !tv.seal_negative.is_empty());
    assert!(tv.jwt.valid.iter().any(|v| v.claims.dev.is_some()));
    assert!(tv.jwt.valid.iter().any(|v| v.claims.org.is_some()));
    assert!(tv.jwt.invalid.iter().all(|c| c.expect == 401));
    assert!(tv.share.cases.iter().any(|c| c.passcode.is_some() && c.kdf.is_some()));
    assert_eq!(tv.vault_kdbx.file, kdbx::VAULT_FIXTURE);
    assert_eq!(hex_bytes(&tv.vault_kdbx.vault_key_hex), hex_bytes(&tv.vault_name.vault_key_hex));
    let clock = FixedClock::from_secs(tv.jwt.now);
    assert_eq!(clock.now_unix_ms(), tv.jwt.now * 1000);
}

#[test]
fn merge_fixtures_load() {
    let fixtures = merge_fixtures();
    assert_eq!(fixtures.len(), 10);
    for (name, f) in &fixtures {
        assert_lossless(&format!("merge-fixtures/{name}"), f);
        let now = FixedClock::at_utc(&f.now).now_unix_ms();
        assert_eq!(now, utc_seconds(&f.now) * 1000);
        for db in [Some(&f.local), Some(&f.remote), f.base.as_ref()].into_iter().flatten() {
            for e in &db.entries {
                utc_seconds(&e.modified);
            }
            for d in &db.deleted {
                utc_seconds(&d.time);
            }
        }
        let uuids: Vec<&str> = f.expected.result.entries.iter().map(|e| e.uuid.as_str()).collect();
        assert!(uuids.windows(2).all(|w| w[0] < w[1]), "{name}: result entries sorted by uuid");
    }
    assert!(fixtures.iter().any(|(_, f)| f.base.is_none()), "a no-base case");
    assert!(fixtures.iter().any(|(_, f)| !f.expected.conflicts.is_empty()), "a conflict case");
    vector_path("merge-fixtures/README.md");
}

#[test]
fn opaque_transcripts_load() {
    let t = opaque_transcripts();
    assert_lossless("opaque-transcripts.json", &t);
    assert_eq!(t.suite.context, "ov-opaque-v1");
    assert_eq!((t.suite.ksf.m_kib, t.suite.ksf.t, t.suite.ksf.p), (65536, 2, 1));
    assert_eq!(hex_bytes(&t.suite.ksf.salt_hex), [0u8; 16]);

    let k = &t.opaque_ke;
    assert_eq!(hex_bytes(&k.password_nfkc_hex), k.password.as_bytes());
    assert_eq!(hex_bytes(&k.login.ke1_hex).len(), 96);
    assert_eq!(hex_bytes(&k.login.ke2_hex).len(), 320);
    assert_eq!(hex_bytes(&k.login.export_key_hex).len(), 64);
    assert_eq!(k.login.export_key_hex, k.registration.export_key_hex);
    assert_eq!(k.login_wrong_password.expect, "auth_failed");

    let l = &t.libopaque;
    assert_eq!(l.login_c_client.export_key_hex, l.registration.export_key_hex);
    let x = &l.login_opaque_ke_client;
    assert_eq!(x.auth_u_hex, x.expected_auth_u_hex, "opaque-ke's KE3 is what libopaque expects");
    assert_eq!(x.export_key_hex, l.registration.export_key_hex);
    assert_eq!(hex_bytes(&x.ke1_hex).len(), 96);
    assert_eq!(hex_bytes(&x.ke2_hex).len(), 320);
    assert_eq!(hex_bytes(&l.registration.user_record_hex).len(), 32 + 32 + 192);
    let r = &l.opaque_ke_registration;
    assert_eq!(r.login_c_client.export_key_hex, r.export_key_hex);
    // libopaque's stored record ends with the client's registration record
    assert!(r.user_record_hex.ends_with(&r.record_hex));
}

#[test]
fn kdbx_fixtures_are_kdbx() {
    const SIG: [u8; 8] = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
    for (file, major) in [(kdbx::VAULT_FIXTURE, 4), (kdbx::DESKTOP_KDBX31, 3), (kdbx::DESKTOP_KDBX4_ARGON2D, 4)] {
        let b = kdbx::bytes(file);
        assert_eq!(b[..8], SIG, "{file}: KDBX signature");
        assert_eq!(u16::from_le_bytes([b[10], b[11]]), major, "{file}: major version");
        assert!(kdbx::path(file).is_absolute());
    }
    assert_eq!(hex!("03d9a29a"), SIG[..4]);
}

/// Every file under vectors/ is listed (with its checksum) in a SOURCE.md; `cargo xtask vectors` checks
/// the checksums.
#[test]
fn every_vector_file_is_in_a_source_md() {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let root = vectors_dir();
    let mut files = Vec::new();
    walk(&root, &mut files);
    let mut listed = BTreeSet::new();
    for source in files.iter().filter(|p| p.file_name().unwrap() == "SOURCE.md") {
        let base = source.parent().unwrap();
        for line in std::fs::read_to_string(source).unwrap().lines() {
            let mut parts = line.split_whitespace();
            if let (Some(sum), Some(path), None) = (parts.next(), parts.next(), parts.next()) {
                if sum.len() == 64 && sum.bytes().all(|b| b.is_ascii_hexdigit()) {
                    listed.insert(base.join(path));
                }
            }
        }
    }
    let unlisted: Vec<_> = files
        .iter()
        .filter(|p| p.file_name().unwrap() != "SOURCE.md" && p.file_name().unwrap() != ".DS_Store")
        .filter(|p| !listed.contains(*p))
        .map(|p| p.strip_prefix(&root).unwrap().display().to_string())
        .collect();
    assert!(unlisted.is_empty(), "files not listed in any SOURCE.md: {unlisted:?}");
}
