//! Live interop with libopaque's C core (feature `interop`): this crate's opaque-ke client against the TS
//! SDK's `test/interop/opaque_server.py`, a line-JSON bridge to libopaque's Python binding (the Flask auth
//! server's code path), which also offers libopaque's C client (the desktop's).
//!
//! The same environment as the SDK's `test/opaque-interop.test.ts`:
//!   OPENVIREO_OPAQUE_PYTHON=<python with pysodium>  OPENVIREO_OPAQUE_PYBINDING=<libopaque/python>
//!   LIBOPAQUE=<libopaque.dylib|so>  [LIBSODIUM=<libsodium.dylib|so>]
//! plus the script: OPENVIREO_OPAQUE_SERVER=<path to opaque_server.py>, or OV_SDK=<openvireo-sdk checkout>
//! (default: ../openvireo-sdk next to this workspace). Without them the test prints why and skips.
#![cfg(feature = "interop")]

use ov_opaque::{finish_login, finish_registration, opaque_ids, start_login, start_registration, OpaqueIds, CONTEXT};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    ids: OpaqueIds,
}

impl Server {
    fn call(&mut self, mut m: Value) -> Value {
        m["idU"] = json!(self.ids.id_u);
        m["idS"] = json!(self.ids.id_s);
        writeln!(self.stdin, "{m}").unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "opaque_server.py exited (see its stderr)");
        let r: Value = serde_json::from_str(&line).unwrap();
        assert!(r.get("error").is_none(), "opaque_server.py: {}", r["error"]);
        r
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|p| p.exists())
}

fn script() -> Option<PathBuf> {
    if let Some(p) = env_path("OPENVIREO_OPAQUE_SERVER") {
        return Some(p);
    }
    let sdk =
        env_path("OV_SDK").unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../openvireo-sdk"));
    Some(sdk.join("packages/sdk/test/interop/opaque_server.py")).filter(|p| p.exists())
}

fn start() -> Option<Server> {
    let missing = |what: &str| {
        eprintln!("SKIPPED: OPAQUE interop needs {what} (see tests/interop.rs)");
        None
    };
    let Some(py) = env_path("OPENVIREO_OPAQUE_PYTHON") else { return missing("OPENVIREO_OPAQUE_PYTHON") };
    let Some(binding) = env_path("OPENVIREO_OPAQUE_PYBINDING") else { return missing("OPENVIREO_OPAQUE_PYBINDING") };
    if env_path("LIBOPAQUE").is_none() {
        return missing("LIBOPAQUE");
    }
    let Some(script) = script() else { return missing("opaque_server.py (OPENVIREO_OPAQUE_SERVER or OV_SDK)") };
    let mut child = Command::new(py)
        .arg("-I")
        .arg(script)
        .arg(binding)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn python");
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    Some(Server { child, stdin, stdout, ids: opaque_ids("alice@example.com", "openvireo.example") })
}

/// Deterministic client randomness is fine here: the libopaque side uses its own RNG.
fn rng(label: &str) -> ChaCha20Rng {
    use sha2::Digest;
    ChaCha20Rng::from_seed(sha2::Sha256::digest(label.as_bytes()).into())
}

fn register(s: &mut Server, pw: &str) {
    let start = start_registration(&mut rng(&format!("reg/{pw}")), pw).unwrap();
    let r = s.call(json!({"op": "reg", "M": hex::encode(&start.request)}));
    let response = hex::decode(r["pub"].as_str().unwrap()).unwrap();
    let ids = s.ids.clone();
    let fin = finish_registration(&mut rng("reg-finish"), start.state, &response, &ids).unwrap();
    s.call(json!({"op": "store", "rec": hex::encode(&fin.record)}));
}

/// A full login: libopaque checks auth_u and both sides agree on the session key.
fn login(s: &mut Server, pw: &str) -> bool {
    let start = start_login(&mut rng(&format!("login/{pw}")), pw).unwrap();
    let r = s.call(json!({"op": "login", "pub": hex::encode(&start.ke1)}));
    let ke2 = hex::decode(r["resp"].as_str().unwrap()).unwrap();
    let ids = s.ids.clone();
    let Ok(fin) = finish_login(&mut rng("login-finish"), start.state, &ke2, &ids, CONTEXT) else { return false };
    let ok = s.call(json!({"op": "auth", "authU": hex::encode(&fin.auth_u)}))["ok"] == json!(true);
    ok && r["sk"].as_str() == Some(hex::encode(&*fin.session_key).as_str())
}

#[test]
fn live_login_against_libopaque() {
    let Some(mut s) = start() else { return };
    for pw in ["correct horse battery staple", "Ünïcödé pässwörd ﬁ"] {
        let nfkc = hex::encode(ov_opaque::password_bytes(pw));

        register(&mut s, pw);
        assert!(login(&mut s, pw), "opaque-ke register + login: {pw}");
        assert!(!login(&mut s, &format!("{pw}x")), "wrong password must fail: {pw}");

        register(&mut s, pw);
        assert_eq!(
            s.call(json!({"op": "c_login", "pw": nfkc}))["ok"],
            json!(true),
            "opaque-ke register → C login: {pw}"
        );

        s.call(json!({"op": "c_register", "pw": nfkc}));
        assert!(login(&mut s, pw), "C register → opaque-ke login: {pw}");
        eprintln!("interop ok: {pw}");
    }
}
