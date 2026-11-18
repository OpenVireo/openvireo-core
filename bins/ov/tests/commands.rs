//! `packages/cli/test/cli.test.ts`, ported: every command against W2-E's in-memory auth and sync
//! servers, with the world.ts setup. Like the TS test, `ov` runs in-process (`ov_cli::cli::main`
//! with the servers as its transport, the TS `fetch`), so prompts can be answered; `binary.rs` runs
//! the real `ov` binary through a loopback relay.

mod support;

use std::sync::{Arc, Mutex};

use ov_cli::mask::MASK;
use ov_core::api::{CancelToken, ClientConfig, DeviceInfo, OvClient, Platform, ServiceAccount};
use support::{make_world, Answer, Cli, Run, World, ALICE, PASSWORD};

const NOW_MS: i64 = 1_794_700_800_000;

fn reader(w: &World) -> [(&'static str, String); 1] {
    [("OPENVIREO_SERVICE_ACCOUNT_TOKEN", w.read_token.clone())]
}

fn writer(w: &World) -> [(&'static str, String); 1] {
    [("OPENVIREO_SERVICE_ACCOUNT_TOKEN", w.write_token.clone())]
}

fn env<'a>(pairs: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    pairs.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

fn run(code: i32, stdout: &str, stderr: &str) -> Run {
    Run { code, stdout: stdout.into(), stderr: stderr.into() }
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

async fn setup(name: &str) -> (World, Cli) {
    let w = make_world(NOW_MS).await;
    let cli = Cli::new(&w.servers, name);
    (w, cli)
}

// ----------------------------------------------------------------------- ov read / inject

#[tokio::test]
async fn reads_a_field_by_vault_name_or_id_entry_title_or_uuid_with_a_group_path() {
    let (w, cli) = setup("read").await;
    let r = reader(&w);
    let r = env(&r);
    assert_eq!(cli.ov(&["read", "ov://Team%20Infra/GitHub/password"], &r).await, run(0, "s3cret\n", ""));
    let by_id = format!("ov://{}/Deploy/Database/username", w.vault_id);
    assert_eq!(cli.ov(&["read", "-n", &by_id], &r).await.stdout, "app");
    let got = cli.ov(&["item", "get", "ov://Team%20Infra/GitHub", "--json"], &r).await;
    let id = serde_json::from_str::<serde_json::Value>(&got.stdout).unwrap()["id"].as_str().unwrap().to_string();
    assert_eq!(cli.ov(&["read", &format!("ov://Team%20Infra/{id}/url")], &r).await.stdout, "https://github.com\n");
    let file = cli.path("secret.txt");
    cli.ov(&["read", "ov://Team%20Infra/GitHub/password", "-o", file.to_str().unwrap()], &r).await;
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "s3cret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[tokio::test]
async fn fails_cleanly_on_bad_references_and_missing_data() {
    let (w, cli) = setup("read-bad").await;
    let r = reader(&w);
    let r = env(&r);
    let cases = [
        ("ov://Team%20Infra/GitHub", "expected ov://<vault>/<entry>/<field>"),
        ("https://x/y/z", "not a ov:// reference"),
        ("ov://Team%20Infra/Nope/password", "entry \"Nope\" not found"),
        ("ov://Team%20Infra/GitHub/nope", "field \"nope\" not found"),
        ("ov://Private/Bank/password", "vault \"Private\" not found or not shared"),
    ];
    for (reference, msg) in cases {
        let out = cli.ov(&["read", reference], &r).await;
        assert_eq!((out.code, out.stdout.as_str()), (1, ""), "{reference}");
        assert!(out.stderr.contains(msg), "{reference}: {}", out.stderr);
        assert!(!out.stderr.contains("\n    at "), "no stack trace");
    }
    assert_eq!(cli.ov(&["read"], &r).await.code, 2);
    assert_eq!(
        cli.ov(&["read", "ov://a/b/c"], &[]).await,
        run(1, "", "ov: not signed in: set OPENVIREO_SERVICE_ACCOUNT_TOKEN or run `ov login`\n")
    );
}

#[tokio::test]
async fn injects_bare_and_braced_references_from_stdin_or_a_file() {
    let (w, cli) = setup("inject").await;
    let r = reader(&w);
    let r = env(&r);
    let tpl = "user: ov://Team%20Infra/Deploy/Database/username\ndsn: postgres://app:{{ ov://Team%20Infra/Deploy/Database/password }}@db/app\n";
    assert_eq!(
        cli.run(&["inject"], &r, Some(tpl), None).await.stdout,
        "user: app\ndsn: postgres://app:pg-pa$$word@db/app\n"
    );
    let (in_file, out_file) = (cli.path("config.tpl"), cli.path("config.yml"));
    std::fs::write(&in_file, tpl).unwrap();
    let out = cli.ov(&["inject", "-i", in_file.to_str().unwrap(), "-o", out_file.to_str().unwrap()], &r).await;
    assert_eq!(out.code, 0);
    assert_eq!(std::fs::read_to_string(&out_file).unwrap().split('\n').next(), Some("user: app"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&out_file).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

// --------------------------------------------------------------------------------- ov run

/// The TS test's Node script, as a shell script: writes the secret whole and split across two
/// writes 20 ms apart, then stderr, then whether the token reached the child.
#[cfg(unix)]
const RUN_SCRIPT: &str = r#"p="$DB_PASSWORD"
printf 'pw=%s\n' "$p"
printf 'half=%s' "$(printf %s "$p" | cut -c1-4)"
sleep 0.02
printf '%s\n' "$(printf %s "$p" | cut -c5-)"
echo "stderr $GH user=$DB_USER plain=$PLAIN" >&2
echo "token-in-env=${OPENVIREO_SERVICE_ACCOUNT_TOKEN:-none} len=${#p}"
exit 3"#;

#[cfg(unix)]
#[tokio::test]
async fn run_resolves_references_from_env_files_and_the_environment_and_masks_them() {
    let (w, cli) = setup("run").await;
    let env_file = cli.path(".env.tpl");
    std::fs::write(
        &env_file,
        "DB_PASSWORD=\"ov://Team%20Infra/Deploy/Database/password\"\nDB_USER=ov://Team%20Infra/Deploy/Database/username\nPLAIN=hello\n",
    )
    .unwrap();
    let r = cli
        .ov(
            &["run", "--env-file", env_file.to_str().unwrap(), "--", "/bin/sh", "-c", RUN_SCRIPT],
            &[("OPENVIREO_SERVICE_ACCOUNT_TOKEN", &w.read_token), ("GH", "ov://Team%20Infra/GitHub/password")],
        )
        .await;
    assert_eq!(r.code, 3);
    assert_eq!(r.stdout, format!("pw={MASK}\nhalf={MASK}\ntoken-in-env=none len=11\n"));
    assert_eq!(r.stderr, format!("stderr {MASK} user={MASK} plain=hello\n"));
    assert!(!(r.stdout.clone() + &r.stderr).contains("s3cret") && !(r.stdout + &r.stderr).contains("pg-pa"));
}

#[cfg(unix)]
#[tokio::test]
async fn run_passes_output_through_with_no_masking_and_needs_no_credentials_without_references() {
    let (w, cli) = setup("run-plain").await;
    let r = cli
        .ov(
            &["run", "--no-masking", "--", "/bin/sh", "-c", "echo \"$X\" >/dev/null"],
            &[("OPENVIREO_SERVICE_ACCOUNT_TOKEN", &w.read_token), ("X", "ov://Team%20Infra/GitHub/password")],
        )
        .await;
    assert_eq!(r.code, 0); // inherited stdio: the child wrote to the real terminal
    let plain = cli.ov(&["run", "--", "/bin/sh", "-c", "echo \"ok $Y\""], &[("Y", "y")]).await;
    assert_eq!((plain.code, plain.stdout.as_str()), (0, "ok y\n"));
    assert_eq!(cli.ov(&["run"], &env(&reader(&w))).await.code, 2);
    let missing = cli.ov(&["run", "--", "/nonexistent/cmd"], &[]).await;
    assert_eq!(missing.code, 1);
    assert!(missing.stderr.contains("ENOENT"), "{}", missing.stderr);
}

// ------------------------------------------------------------------- ov item / rotate (writes)

#[tokio::test]
async fn rejects_writes_with_a_read_only_grant_before_uploading_anything() {
    let (w, cli) = setup("readonly").await;
    let before = w.puts();
    let r = reader(&w);
    let r = env(&r);
    for argv in [
        &["rotate", "ov://Team%20Infra/GitHub/password", "--generate"][..],
        &["item", "edit", "ov://Team%20Infra/GitHub", "username=x"],
        &["item", "create", "ov://Team%20Infra/New", "password=x"],
    ] {
        assert_eq!(
            cli.ov(argv, &r).await,
            run(1, "", "ov: this service account can only read vault \"Team Infra\"\n"),
            "{argv:?}"
        );
    }
    assert_eq!(w.puts(), before);
}

#[tokio::test]
async fn creates_edits_and_reads_whole_items() {
    let (w, cli) = setup("items").await;
    let (r, wr) = (reader(&w), writer(&w));
    let (r, wr) = (env(&r), env(&wr));
    let created = cli
        .ov(
            &[
                "item",
                "create",
                "ov://Team%20Infra/Apps/Stripe",
                "username=billing",
                "url=https://stripe.com",
                "api_key=sk_live_1",
                "--generate",
                "--length",
                "20",
                "--charset",
                "letters,digits",
                "--json",
            ],
            &wr,
        )
        .await;
    assert_eq!(created.code, 0, "{}", created.stderr);
    let id = created.stderr.strip_prefix("Created Apps/Stripe (").and_then(|s| s.strip_suffix(")\n")).unwrap();
    assert!(is_hex32(id), "{}", created.stderr);
    let item: serde_json::Value = serde_json::from_str(&created.stdout).unwrap();
    assert_eq!(item["fields"]["UserName"], "billing");
    assert!(item["fields"].get("api_key").is_none());
    let mut protected: Vec<&str> = item["protected"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    protected.sort();
    assert_eq!(protected, ["Password", "api_key"]);
    let pw = cli.ov(&["read", "ov://Team%20Infra/Apps/Stripe/password"], &r).await.stdout.trim().to_string();
    assert!(pw.len() == 20 && pw.bytes().all(|b| b.is_ascii_alphanumeric()), "{pw}");

    assert!(cli
        .ov(&["item", "create", "ov://Team%20Infra/Apps/Stripe", "x=y"], &wr)
        .await
        .stderr
        .contains("already exists"));
    assert!(cli.ov(&["item", "edit", "ov://Team%20Infra/Apps/Nope", "x=y"], &wr).await.stderr.contains("not found"));
    assert_eq!(cli.ov(&["item", "edit", "ov://Team%20Infra/Apps/Stripe"], &wr).await.code, 2);
    assert_eq!(cli.ov(&["item", "edit", "ov://Team%20Infra/Apps/Stripe", "noequals"], &wr).await.code, 2);

    let edited = cli
        .run(
            &["item", "edit", "ov://Team%20Infra/Apps/Stripe", "username=billing2", "--stdin-field", "api_key"],
            &wr,
            Some("sk_live_2\n"),
            None,
        )
        .await;
    assert_eq!(edited.code, 0, "{}", edited.stderr);
    let shown = cli.ov(&["item", "get", "ov://Team%20Infra/Apps/Stripe"], &r).await;
    assert!(shown.stdout.contains("  UserName: billing2\n"), "{}", shown.stdout);
    assert!(shown.stdout.contains("  api_key: <concealed>\n"));
    assert!(cli
        .ov(&["item", "get", "ov://Team%20Infra/Apps/Stripe", "--reveal"], &r)
        .await
        .stdout
        .contains("  api_key: sk_live_2\n"));
    let list = cli.ov(&["item", "list", "Team Infra"], &r).await.stdout;
    assert!(
        list.lines().any(|l| l.split_once("  ").is_some_and(|(id, p)| is_hex32(id) && p == "Apps/Stripe")),
        "{list}"
    );
    assert!(!list.contains("sk_live"));
}

#[tokio::test]
async fn rotates_a_field_with_a_generated_value_or_one_from_stdin() {
    let (w, cli) = setup("rotate").await;
    let (r, wr) = (reader(&w), writer(&w));
    let (r, wr) = (env(&r), env(&wr));
    let out = cli.ov(&["rotate", "ov://Team%20Infra/Deploy/Database/password", "--generate", "--print"], &wr).await;
    assert_eq!((out.code, out.stderr.as_str()), (0, "Rotated ov://Team%20Infra/Deploy/Database/password\n"));
    let value = out.stdout.trim().to_string();
    assert_eq!(value.len(), 32);
    let client = OvClient::new(
        ClientConfig {
            device: DeviceInfo { id: None, name: "t".into(), platform: Platform::Cli },
            offline: false,
            server: None,
        },
        w.servers.host(),
    );
    let sa = ServiceAccount::from_token(client, w.read_token.as_bytes().to_vec(), CancelToken::new()).await.unwrap();
    let read = sa.read("ov://Team%20Infra/Deploy/Database/password".into(), CancelToken::new()).await.unwrap();
    assert_eq!(String::from_utf8(read).unwrap(), value);
    sa.close();
    let piped = cli
        .run(&["rotate", "ov://Team%20Infra/Deploy/Database/password", "--stdin"], &wr, Some("from-stdin\n"), None)
        .await;
    assert_eq!(piped.stdout, "");
    assert_eq!(cli.ov(&["read", "ov://Team%20Infra/Deploy/Database/password"], &r).await.stdout, "from-stdin\n");
    assert_eq!(cli.ov(&["rotate", "ov://Team%20Infra/Deploy/Database/password"], &wr).await.code, 2);
    assert_eq!(
        cli.run(&["rotate", "ov://Team%20Infra/Deploy/Database/password", "--stdin"], &wr, Some(""), None).await.code,
        2
    );
}

#[tokio::test]
async fn merges_and_retries_when_another_client_uploads_during_the_write() {
    let (w, cli) = setup("race").await;
    let (r, wr) = (reader(&w), writer(&w));
    let (r, wr) = (env(&r), env(&wr));
    // The TS test lets 1 GET through (download, then the sync's GET). The core's sync GETs twice
    // before its PUT, so the other device's upload lands after the third to force the 412.
    let fired = w.edit_between_get_and_put("GitHub", &[("Notes", "edited on another device")], 2).await;
    let before = w.puts();
    let out =
        cli.run(&["rotate", "ov://Team%20Infra/GitHub/password", "--stdin"], &wr, Some("rotated-in-race"), None).await;
    w.servers.set_after_get(None);
    assert_eq!((out.code, *fired.lock().unwrap(), w.puts() - before), (0, true, 2), "{}", out.stderr);
    assert_eq!(cli.ov(&["read", "ov://Team%20Infra/GitHub/password"], &r).await.stdout, "rotated-in-race\n");
    assert_eq!(cli.ov(&["read", "ov://Team%20Infra/GitHub/notes"], &r).await.stdout, "edited on another device\n");
}

// --------------------------------------------------------------------- ov vault / whoami / login

#[tokio::test]
async fn lists_vaults_and_shows_the_principal() {
    let (w, cli) = setup("vaults").await;
    assert_eq!(
        cli.ov(&["vault", "list"], &env(&reader(&w))).await.stdout,
        format!("{}  read    Team Infra\n", w.vault_id)
    );
    let who = cli.ov(&["whoami"], &env(&writer(&w))).await.stdout;
    let lines: Vec<&str> = who.lines().collect();
    assert_eq!(lines.len(), 3, "{who}");
    assert_eq!(lines[0], "kind: service-account");
    let sa = lines[1].strip_prefix("principal: sa:").unwrap();
    assert!(sa.len() == 36 && sa.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'), "{who}");
    assert_eq!(lines[2], "issuer: https://auth.test");
}

/// Answers world.ts's questions and records them.
fn answers(
    asked: Arc<Mutex<Vec<String>>>,
    secret_key: String,
    extra: &'static [(&'static str, &'static str)],
) -> Answer {
    Arc::new(move |q: &str| {
        asked.lock().unwrap().push(q.to_string());
        if q.starts_with("Email") {
            ALICE.into()
        } else if q.starts_with("Master") {
            PASSWORD.into()
        } else if q.starts_with("Secret Key") {
            secret_key.clone()
        } else {
            extra.iter().find(|(p, _)| q.starts_with(p)).map(|(_, a)| a.to_string()).unwrap_or_default()
        }
    })
}

#[tokio::test]
async fn works_with_a_human_login() {
    let (w, cli) = setup("login").await;
    let issuer = [("OPENVIREO_ISSUER", "https://auth.test")];
    let asked = Arc::new(Mutex::new(Vec::new()));
    let prompt = answers(asked.clone(), w.secret_key.clone(), &[]);
    // A fresh machine: alice's world client kept the Secret Key, this one hasn't.
    let r = cli.run(&["login"], &issuer, None, Some(prompt.clone())).await;
    assert_eq!(r, run(0, "", "Signed in to https://auth.test as alice@example.com\n"));
    assert_eq!(*asked.lock().unwrap(), ["Email: ", "Master password: ", "Secret Key (K1-…): "]);
    let session = cli.path("config/session.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&session).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(!std::fs::read_to_string(&session).unwrap().contains(PASSWORD));

    // Later commands: the trusted Secret Key is stored, only the password is needed.
    let pw = [("OPENVIREO_PASSWORD", PASSWORD)];
    assert_eq!(cli.ov(&["read", "ov://Team%20Infra/GitHub/username"], &pw).await.stdout, "ci\n");
    asked.lock().unwrap().clear();
    assert!(cli.run(&["vault", "list"], &[], None, Some(prompt.clone())).await.stdout.contains("manage  Private"));
    assert_eq!(*asked.lock().unwrap(), ["Master password for alice@example.com: "]);
    assert_eq!(
        cli.ov(&["read", "ov://Private/Bank/password"], &[("OPENVIREO_PASSWORD", "wrong")]).await.stderr,
        "ov: wrong password or Secret Key\n"
    );
    assert!(cli.ov(&["read", "ov://a/b/c"], &[]).await.stderr.contains("no terminal"));

    let rot = cli.run(&["rotate", "ov://Private/Bank/password", "--stdin"], &pw, Some("by-human"), None).await;
    assert_eq!(rot.code, 0, "{}", rot.stderr);
    assert_eq!(cli.ov(&["read", "ov://Private/Bank/password"], &pw).await.stdout, "by-human\n");
    let who = cli.ov(&["whoami"], &[]).await.stdout;
    assert!(who.starts_with("kind: user\nprincipal: user:") && who.contains("\nemail: alice@example.com\n"), "{who}");

    // The plan and who bills it (SPEC §19).
    let alice = w.alice_id();
    let billing = |source: &str, renews: Option<&str>, ends: Option<&str>, manage: &str| ov_protocol::types::Billing {
        source: source.into(),
        interval: "year".into(),
        status: "active".into(),
        renews_at: renews.map(Into::into),
        ends_at: ends.map(Into::into),
        manage: manage.into(),
    };
    let plan = |id: &str, b: Option<ov_protocol::types::Billing>| ov_protocol::types::Plan {
        id: Some(id.into()),
        limits: Default::default(),
        billing: b,
    };
    w.servers
        .set_plan(&alice, plan("premium", Some(billing("apple", Some("2027-11-08T12:00:00Z"), None, "app_store"))));
    assert!(cli.ov(&["whoami"], &[]).await.stdout.contains(
        "plan: Premium, renews 8 November 2027, billed by Apple. Manage it on your iPhone or in your Apple ID settings (https://apps.apple.com/account/subscriptions).\n"
    ));
    w.servers.set_plan(&alice, plan("premium", Some(billing("stripe", None, Some("2027-01-31T00:00:00Z"), "website"))));
    assert!(cli
        .ov(&["whoami"], &[])
        .await
        .stdout
        .contains("plan: Premium, ends 31 January 2027. Manage it at https://auth.test/subscription/pricing.\n"));
    w.servers.set_plan(&alice, plan("free", None));
    assert!(cli.ov(&["whoami"], &[]).await.stdout.contains("plan: Free\n"));
    // The SA token takes precedence over the saved session.
    assert!(!cli.ov(&["vault", "list"], &env(&reader(&w))).await.stdout.contains("Private"));

    assert_eq!(cli.ov(&["logout"], &[]).await.stderr, "Signed out\n");
    assert!(cli.ov(&["read", "ov://a/b/c"], &pw).await.stderr.contains("not signed in"));
    assert_ne!(cli.ov(&["logout", "--nope"], &[]).await.code, 0);
    assert_eq!(cli.ov(&["logout", "--forget"], &[]).await.stderr, "Not signed in\n");
}

#[tokio::test]
async fn makes_share_links_as_a_user() {
    let (w, cli) = setup("share").await;
    let issuer = [("OPENVIREO_ISSUER", "https://auth.test")];
    let prompt = answers(Arc::default(), w.secret_key.clone(), &[("Passcode", "tiger lily")]);
    assert_eq!(cli.run(&["login"], &issuer, None, Some(prompt.clone())).await.code, 0);
    let user = [("OPENVIREO_PASSWORD", PASSWORD)];
    let api = w.servers.api_url();
    let client = OvClient::new(
        ClientConfig {
            device: DeviceInfo { id: None, name: "t".into(), platform: Platform::Web },
            offline: false,
            server: None,
        },
        w.servers.host(),
    );

    let r = cli
        .ov(&["share", "ov://Team%20Infra/GitHub", "--field", "UserName", "--field", "Password", "--once"], &user)
        .await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.ends_with("opens once. Anyone with the link can open it.\n"), "{}", r.stderr);
    let url = r.stdout.trim().to_string();
    let (base, rest) = url.rsplit_once('/').unwrap();
    let (id, key) = rest.split_once('#').unwrap();
    let b64u =
        |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    assert!(base.starts_with("https://") && b64u(id, 22) && b64u(key, 43), "{url}");
    let opened =
        client.open_share(api.clone(), url.clone().into_bytes(), None, None, CancelToken::new()).await.unwrap();
    let got: Vec<(String, bool)> = opened.payload.fields.iter().map(|f| (f.k.clone(), !f.value.is_empty())).collect();
    assert_eq!(got, [("username".to_string(), true), ("password".to_string(), true)]);
    assert_eq!(opened.payload.fields[0].value, b"ci");
    let again = client.open_share(api.clone(), url.into_bytes(), None, None, CancelToken::new()).await.unwrap_err();
    assert_eq!(again.code, ov_core::OvErrorCode::NotFound);

    let text = cli
        .run(
            &["share", "--text", "--title", "Door", "--passcode", "--expires", "1h"],
            &user,
            Some("4321\n"),
            Some(prompt.clone()),
        )
        .await;
    assert_eq!(text.code, 0, "{}", text.stderr);
    let door = client
        .open_share(
            api.clone(),
            text.stdout.trim().as_bytes().to_vec(),
            Some(b"tiger lily".to_vec()),
            None,
            CancelToken::new(),
        )
        .await
        .unwrap();
    assert_eq!((door.payload.title.as_deref(), door.payload.fields[0].value.as_slice()), (Some("Door"), &b"4321"[..]));

    let list = cli.ov(&["share", "list"], &user).await.stdout;
    let lines: Vec<&str> = list.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "{list}");
    let words: Vec<&str> = lines[1].split_whitespace().collect();
    assert_eq!(&words[1..], ["GitHub", "1/1", "opens", "ended", "(opened)"], "{list}");
    let id = lines[0].split(' ').next().unwrap();
    assert_eq!(cli.ov(&["share", "revoke", id], &user).await.stderr, format!("Revoked {id}\n"));

    assert_eq!(
        cli.ov(&["share", "ov://Team%20Infra/GitHub", "--field", "Nope"], &user).await.stderr,
        "ov: GitHub has no Nope to share\n"
    );
    assert_eq!(cli.ov(&["share", "ov://Team%20Infra/GitHub", "--expires", "soon"], &user).await.code, 2);
    assert_eq!(
        cli.ov(&["share", "ov://Team%20Infra/GitHub"], &env(&reader(&w))).await.stderr,
        "ov: share links are made by users, not service accounts\n"
    );
    cli.ov(&["logout"], &[]).await;
}

#[tokio::test]
async fn schedules_an_account_deletion_and_restores_it() {
    let (w, cli) = setup("delete").await;
    let issuer = [("OPENVIREO_ISSUER", "https://auth.test")];
    let typed = |answer: &'static str| -> Answer {
        let sk = w.secret_key.clone();
        Arc::new(move |q: &str| {
            if q.starts_with("Email") {
                ALICE.into()
            } else if q.starts_with("Master") {
                PASSWORD.into()
            } else if q.starts_with("Secret Key") {
                sk.clone()
            } else if q.starts_with("Type") {
                answer.into()
            } else {
                String::new()
            }
        })
    };
    assert_eq!(cli.run(&["login"], &issuer, None, Some(typed(""))).await.code, 0);
    let user = [("OPENVIREO_PASSWORD", PASSWORD)];
    // An Apple-billed plan can't be stopped by the server: the user is told to cancel it at Apple.
    let alice = w.alice_id();
    w.servers.set_plan(
        &alice,
        ov_protocol::types::Plan {
            id: Some("premium".into()),
            limits: Default::default(),
            billing: Some(ov_protocol::types::Billing {
                source: "apple".into(),
                interval: "year".into(),
                status: "active".into(),
                renews_at: Some("2027-11-08T12:00:00Z".into()),
                ends_at: None,
                manage: "app_store".into(),
            }),
        },
    );
    let wrong = cli.run(&["account", "delete"], &user, None, Some(typed("bob@example.com"))).await;
    assert!(
        wrong.stderr.contains(
            "your premium plan is billed by Apple and keeps renewing: cancel it on your iPhone or in your Apple ID settings"
        ),
        "{}",
        wrong.stderr
    );
    w.servers.set_plan(
        &alice,
        ov_protocol::types::Plan { id: Some("free".into()), limits: Default::default(), billing: None },
    );
    let last = wrong.stderr.lines().last().unwrap_or("").to_string();
    assert_eq!((wrong.code, last.as_str()), (1, "ov: that isn't this account's email; nothing was deleted"));
    assert!(cli.ov(&["account", "delete", "--yes"], &user).await.stderr.contains("--yes needs --email"));

    let r = cli.run(&["account", "delete"], &user, None, Some(typed(ALICE))).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.starts_with("Deleting alice@example.com locks it now and erases it on 20"), "{}", r.stderr);
    assert!(
        r.stderr.contains(" is locked and will be deleted on 20") && r.stderr.contains(". To keep it"),
        "{}",
        r.stderr
    );
    assert_eq!(cli.ov(&["vault", "list"], &user).await.code, 1);

    assert_eq!(cli.run(&["login"], &issuer, None, Some(typed(""))).await.code, 0);
    let pending = cli.ov(&["vault", "list"], &user).await;
    assert!(pending.stderr.contains("scheduled for deletion"), "{pending:?}");
    assert_eq!(cli.ov(&["account", "restore"], &user).await.stderr, "alice@example.com was restored\n");
    assert!(cli.ov(&["vault", "list"], &user).await.stdout.contains("Private"));
    assert_eq!(cli.ov(&["account", "restore"], &user).await.stderr, "alice@example.com isn't scheduled for deletion\n");
    cli.ov(&["logout"], &[]).await;
}

#[tokio::test]
async fn prints_usage_and_versions() {
    let servers = ov_testkit::servers::TestServers::new(Arc::new(ov_testkit::ManualClock::new(NOW_MS)));
    let cli = Cli::new(&servers, "usage");
    assert!(cli.ov(&["help"], &[]).await.stdout.contains("ov run [--env-file .env.tpl]"));
    assert_eq!(cli.ov(&[], &[]).await.code, 2);
    assert_eq!(cli.ov(&["version"], &[]).await.stdout, "ov 0.11.0\n");
    assert_eq!(cli.ov(&["frobnicate"], &[]).await.stderr, "ov: unknown command \"frobnicate\" (see ov help)\n");
    // `ov connect` hands over to openvireo-connect (W1-L); its own tests cover `token` and `--help`.
}
