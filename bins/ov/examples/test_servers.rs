//! W2-E's in-memory auth and sync servers with the TS CLI tests' world (world.ts), served on a
//! loopback relay for the golden diff (`tests/golden/diff.mjs`). Prints one JSON line (the relay
//! URL, tokens, Secret Key, vault ids), then serves until stdin closes.
//!
//! Test tooling only: run with `cargo run -p ov --example test_servers`.

#[path = "../tests/support/mod.rs"]
mod support;

use std::io::{BufRead, Write};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let w = support::make_world(now).await;
    let (relay, _server) = support::serve_relay(w.servers.clone(), true).await;
    let info = serde_json::json!({
        "relay": relay,
        "readToken": w.read_token,
        "writeToken": w.write_token,
        "secretKey": w.secret_key,
        "password": support::PASSWORD,
        "email": support::ALICE,
        "vaultId": w.vault_id,
        "otherVaultId": w.other_vault_id,
    });
    let mut out = std::io::stdout();
    writeln!(out, "{info}").unwrap();
    out.flush().unwrap();
    // Serve until the caller closes our stdin (or kills us).
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        while std::io::stdin().lock().read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
            line.clear();
        }
    })
    .await
    .unwrap();
}
