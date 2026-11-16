//! Black-box checks of the `ov` binary against the TS CLI's behaviour.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use ov_core::host::SecureStore;

fn ov(args: &[&str], home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ov"))
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn empty_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ov-cli-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A test data file exactly as stored in git. `tests/.gitattributes` marks these `-text`, so a
/// checkout never turns LF into CRLF (Windows `core.autocrlf`); fail clearly if one did.
fn stored(rel: &str) -> Vec<u8> {
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap();
    assert!(!bytes.contains(&b'\r'), "{rel} was checked out with CRLF line endings; see tests/.gitattributes");
    bytes
}

fn golden_help() -> Vec<u8> {
    stored("tests/golden/help.txt")
}

#[test]
fn help_is_byte_identical_to_the_ts_cli() {
    let home = empty_home("help");
    for (args, code) in [(&["--help"][..], 0), (&["-h"], 0), (&["help"], 0), (&[], 2)] {
        let out = ov(args, &home);
        assert_eq!(out.status.code(), Some(code), "{args:?}");
        assert_eq!(out.stdout, golden_help(), "{args:?}");
        assert!(out.stderr.is_empty());
    }
    let out = ov(&["--version"], &home);
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "ov 0.11.0\n");
}

#[test]
fn usage_errors_exit_2_and_failures_exit_1() {
    let home = empty_home("codes");
    let out = ov(&["bogus"], &home);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(String::from_utf8(out.stderr).unwrap(), "ov: unknown command \"bogus\" (see ov help)\n");
    let out = ov(&["read", "ov://v/e/f"], &home);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "ov: not signed in: set OPENVIREO_SERVICE_ACCOUNT_TOKEN or run `ov login`\n"
    );
    let out = ov(&["logout"], &home);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8(out.stderr).unwrap(), "Not signed in\n");
}

#[test]
fn run_without_references_runs_the_command() {
    let home = empty_home("run");
    let out = ov(&["run", "--", "sh", "-c", "echo ok; exit 5"], &home);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "ok\n");
}

/// A session saved by the TS `ov login` is found where the TS keeps it and read back unchanged.
#[tokio::test]
async fn reads_a_session_written_by_the_ts_cli() {
    let fixture_bytes = stored("tests/fixtures/ts-session.json");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ts-session.json");
    let home = empty_home("session");
    let dir = home.join(".config/openvireo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(&fixture, dir.join("session.json")).unwrap();

    let env: ov_cli::session::Env = [("HOME".to_string(), home.to_string_lossy().into_owned())].into_iter().collect();
    assert_eq!(ov_cli::session::session_path(&env), dir.join("session.json"));
    let store = ov_cli::session::store_for(&env);
    let get = |k: &'static str| {
        let store = &store;
        async move { store.get(k).await.unwrap().map(|v| String::from_utf8(v.to_vec()).unwrap()) }
    };
    assert_eq!(get("cli:issuer").await.as_deref(), Some("https://accounts.example.com"));
    assert_eq!(get("device:srv_test:usr_test").await.as_deref(), Some("dev_fake"));
    let session: serde_json::Value = serde_json::from_str(&get("session").await.unwrap()).unwrap();
    assert_eq!(session["refreshToken"], "fake-refresh\n\"quoted\" ü ✓");

    // Rewriting every value in place gives back the TS file byte for byte.
    for k in ["session", "device:srv_test:usr_test", "secret_key:srv_test:usr_test", "cli:issuer"] {
        let v = get(k).await.unwrap();
        store.set(k, v.as_bytes()).await.unwrap();
    }
    assert_eq!(std::fs::read(dir.join("session.json")).unwrap(), fixture_bytes);

    // With a saved session, commands get past "not signed in" (to the core, W3-L3).
    let out = ov(&["whoami"], &home);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr).unwrap().contains("not implemented yet"));
    std::fs::remove_dir_all(home).unwrap();
}
