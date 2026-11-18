//! The real `ov` binary against W2-E's in-memory servers, through the loopback relay (debug builds
//! read `OPENVIREO_TEST_RELAY`): service-account reads and writes, a user login from flags and the
//! environment (no terminal), reading as the user, `whoami`, `logout`. The in-process port of
//! `cli.test.ts` (`commands.rs`) covers the rest, including the prompts.

mod support;

use std::io::Write;
use std::path::Path;

use support::{make_world, serve_relay, Run, ALICE, PASSWORD};

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binary_runs_against_the_test_servers() {
    let w = make_world(now_ms()).await;
    let (relay, server) = serve_relay(w.servers.clone(), true).await;
    let dir = std::env::temp_dir().join(format!("ov-binary-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (relay2, dir2) = (relay.clone(), dir.clone());
    let read_token = w.read_token.clone();
    let write_token = w.write_token.clone();
    let secret_key = w.secret_key.clone();
    let vault_id = w.vault_id.clone();
    let run = move |argv: &[&str], env: &[(&str, &str)], stdin: &str| ov_binary(&relay2, &dir2, argv, env, stdin);

    let checks = tokio::task::spawn_blocking(move || {
        let reader = [("OPENVIREO_SERVICE_ACCOUNT_TOKEN", read_token.as_str())];
        let writer = [("OPENVIREO_SERVICE_ACCOUNT_TOKEN", write_token.as_str())];
        let r = run(&["read", "ov://Team%20Infra/GitHub/password"], &reader, "");
        assert_eq!((r.code, r.stdout.as_str(), r.stderr.as_str()), (0, "s3cret\n", ""));
        let r = run(&["vault", "list"], &reader, "");
        assert_eq!(r.stdout, format!("{vault_id}  read    Team Infra\n"));
        let r = run(&["rotate", "ov://Team%20Infra/GitHub/password", "--stdin"], &writer, "from-the-binary\n");
        assert_eq!((r.code, r.stderr.as_str()), (0, "Rotated ov://Team%20Infra/GitHub/password\n"));
        let r = run(&["inject"], &reader, "pw={{ ov://Team%20Infra/GitHub/password }}\n");
        assert_eq!(r.stdout, "pw=from-the-binary\n");
        let r = run(&["read", "ov://Team%20Infra/GitHub/nope"], &reader, "");
        assert_eq!((r.code, r.stderr.as_str()), (1, "ov: field \"nope\" not found\n"));

        // No terminal: everything from flags and the environment.
        let r = run(
            &["login", "--issuer", "https://auth.test/", "--email", ALICE],
            &[("OPENVIREO_PASSWORD", PASSWORD)],
            "",
        );
        assert_eq!(r.stderr, "ov: Secret Key (K1-…) is needed, but there is no terminal to ask on\n");
        let r = run(
            &["login", "--issuer", "https://auth.test/", "--email", ALICE, "--secret-key", &secret_key],
            &[("OPENVIREO_PASSWORD", PASSWORD)],
            "",
        );
        assert_eq!((r.code, r.stderr.as_str()), (0, "Signed in to https://auth.test as alice@example.com\n"));
        let user = [("OPENVIREO_PASSWORD", PASSWORD)];
        let r = run(&["read", "ov://Private/Bank/password"], &user, "");
        assert_eq!(r.stdout, "nope\n");
        let r = run(&["whoami"], &[], "");
        assert!(
            r.stdout.starts_with("kind: user\nprincipal: user:")
                && r.stdout.ends_with("email: alice@example.com\nissuer: https://auth.test\n"),
            "{r:?}"
        );
        let r = run(&["read", "ov://Private/Bank/password"], &[], "");
        assert_eq!(
            r.stderr,
            "ov: Master password for alice@example.com is needed, but there is no terminal to ask on\n"
        );
        assert_eq!(run(&["logout"], &[], "").stderr, "Signed out\n");
        assert_eq!(run(&["logout"], &[], "").stderr, "Not signed in\n");
    });
    let result = checks.await;
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
    result.unwrap();
}

/// Runs the `ov` binary through a relay.
fn ov_binary(relay: &str, dir: &Path, argv: &[&str], env: &[(&str, &str)], stdin: &str) -> Run {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ov"));
    cmd.args(argv)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("OPENVIREO_CONFIG_DIR", dir.join("config"))
        .env("OPENVIREO_TEST_RELAY", relay)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}
