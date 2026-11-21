# Testing

Behaviour is defined by the contract's fixtures (the SPEC test vectors, OPAQUE transcripts, merge
fixtures, the `.kdbx` corpus), not by any one client. When a vector passes, the behaviour is right.
Where the vectors are silent, the TypeScript SDK's 0.x behaviour was the tie-breaker.

## The gate: `cargo xtask ci`

```sh
cargo install --locked cargo-deny   # once
cargo xtask ci
```

It runs, in order, and stops at the first failure:

1. `cargo fmt --all --check` (120 columns, `rustfmt.toml`)
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
3. `cargo test --workspace --locked`, then `cargo test -p ov-ffi-cpp --features test-server`
4. `cargo deny check` (licences, advisories, bans; `deny.toml`)
5. `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS=-D warnings`
6. `cargo xtask vectors`: every checksum in `vectors/**/SOURCE.md`
7. `cargo xtask openapi --check`: every example in the OpenAPI copies round-trips through ov-protocol
8. a wasm32 build and wasm32 clippy of the portable crates plus `ov-wasm` and `ov-wasm-lite`
9. on macOS, an iOS build (device, simulator arm64 and x86_64) of the portable crates plus `ov-ffi-swift`
10. `cargo xtask unlinked`: no code from a crate with an ignored advisory (crypto-bigint) is linked into
    a wasm module
11. `cargo xtask size`: raw and gzip size of both wasm modules

"Portable" means every crate under `crates/` except those marked `[package.metadata.ov] native-only = true`
(today only `ov-testkit`). On 2026-11-20 the workspace ran 557 tests with 0 failures.

GitHub CI (`.github/workflows/ci.yml`) runs `cargo test --workspace` on Ubuntu, macOS and Windows, and
`cargo xtask ci` on macOS, on every push to `develop`/`main` and on pull requests. Check
`gh run list --branch develop` after a merge: a local green run has missed Windows line-ending and
slow-runner timing failures before.

## Vectors and fixtures

| What | Where | Run |
|---|---|---|
| SPEC test vectors (AUK, keysets, seal, JWT, tokens, restore proofs, share links, vault names) | `vectors/test-vectors.json` | `cargo test -p ov-crypto --test vectors`, `-p ov-share --test vectors`, `-p ov-vault` |
| OPAQUE transcripts: the TS SDK's opaque-ke and libopaque, including opaque-ke signing in to a libopaque-registered account | `vectors/opaque-transcripts.json` | `cargo test -p ov-opaque --test transcripts` |
| Merge fixtures recorded from the desktop's sync merge (14 cases) | `vectors/merge-fixtures/` | `cargo test -p ov-merge --test merge_fixtures` |
| OpenAPI copies of the auth and sync servers | `vectors/openapi/` | `cargo xtask openapi --check`, `cargo test -p ov-protocol` |
| `.kdbx` files from the contract and the desktop | `vectors/vault-fixture.kdbx`, `vectors/kdbx/` | `cargo test -p ov-kdbx` |
| `.kdbx` files written by other apps (kdbxweb, KeePassXC, iOS) | `corpus/kdbx/` (`manifest.tsv`) | `cargo test -p ov-kdbx --test corpus -- --nocapture` |

`ov-testkit` loads all of these as typed data. The corpus harness opens each file, saves it, reopens it
and requires an equal model; with `OV_KEEPASSXC_CLI` and `OV_SDK` set it also checks that KeePassXC's CLI
and kdbxweb read the rewrite. The 5,000-entry KeePassXC file is generated, not committed
(`node corpus/kdbx/gen-keepassxc.mjs --5k`). GPL test files from KeePassXC's repo are deliberately not
copied in.

`cargo test -p ov-opaque --features interop --test interop` runs a live login against libopaque through
the SDK's `test/interop/opaque_server.py` (environment in the test's header; it skips without it).

Property tests (`proptest`) cover merge symmetry and idempotence and share-link parsing.

## The facade against in-memory servers

`ov-testkit`'s `TestServers` are in-memory auth and sync servers: real EdDSA JWTs, a `ManualClock`, every
typed route of the OpenAPI files, and fault injection. `crates/ov-core/tests/` ports the SDK's account,
switching, recovery, deletion, import, sharing and share-link suites onto them, plus one file per contract
tag (`contract_v16.rs`, `contract_v17.rs`, `contract_v18.rs`). `crates/ov-sync/tests/servers.rs` runs the
sync engine against them. The C++ binding exposes the same servers under its `test-server` feature
(`ov::test_servers_start`), which the desktop's `testaccountcore`, `testaccountmanager` and
`testsyncengine` use.

## The bindings

| Binding | Run |
|---|---|
| wasm | `cargo xtask wasm`, then in `bindings/ov-wasm`: `npm ci && npx vitest run && npx tsc -p tsconfig.json` (Node and jsdom smoke, Host adapters, low-level vectors, lite/full parity, memory wiping, an esbuild bundle, one file per contract tag) |
| Swift | `cargo xtask xcframework --smoke` (macOS): `swift test` in `bindings/ov-ffi-swift/SmokeTests` against the vectors and transcripts |
| C++ | `cargo test -p ov-ffi-cpp [--features test-server]`; `cargo xtask cpp --check-coverage` (every facade item bridged, 0 missing); the CMake smoke in `bindings/ov-ffi-cpp/smoke/` (commands at the top of its `CMakeLists.txt`, built with `-Wall -Wextra -Werror`) |

## The `ov` CLI

```sh
cargo test -p ov                                   # unit, in-process commands, the binary, every TS cli.test.ts case
node bins/ov/tests/golden/diff.mjs --rust-only     # the binary against the recorded TS transcript
node bins/ov/tests/golden/diff.mjs --ts-cli <sdk>/packages/cli/dist/index.js   # live, against the TS CLI
```

The golden diff runs both CLIs against the same in-memory servers (`cargo run -p ov --example
test_servers`) and compares exit code, stdout and stderr case by case. On 2026-11-18 112 of 114 cases were
identical; the two known differences are listed in `KNOWN` in `diff.mjs` (kdbxweb drops the protected
flag of an empty Password; ov-kdbx keeps it). `ov --help` is byte-identical to the TS CLI's.

## Cross-client end-to-end

`e2e/` runs the real clients against the local stack (the auth server with Postgres, Redis and the mail
catcher, plus the sync server, from the workspace `compose.yaml`): `ov` and the SDK script each other,
iOS runs its e2e suites, the desktop runs its live-server tests and its `openvireo-kdbx` reader.

```sh
# ov + SDK (the SDK checkout needs `npm ci && npm run build -w packages/sdk`)
OV_E2E_SDK_DIR=~/kpnx/openvireo-sdk e2e/run.sh

# the whole matrix on a throwaway stack
OV_E2E_FRESH=1 \
OV_E2E_SDK_DIR=~/kpnx/openvireo-sdk \
OV_E2E_IOS_DIR=~/kpnx/openvireo-ios \
OV_E2E_DESKTOP_BUILD=~/kpnx/openvireo/cmake-build-debug \
e2e/run.sh
```

- `OV_E2E_FRESH=1` stops your everyday stack (its volumes stay), runs a throwaway compose project
  `openvireo-e2e-<pid>` with new volumes on the same ports, deletes it with `down -v` and starts your
  everyday services again. Without it the run uses, and adds accounts to, your everyday stack.
- The run clears the auth server's registration rate limit in Redis every two seconds (a run registers
  about 15 accounts; the server allows 5 a minute per IP). It does this only against the local stack.
- `OV_COMPOSE_FILE` points at the stack (default: the `compose.yaml` in the folder that holds the main
  openvireo-core checkout, i.e. the workspace). `OV_E2E_ONLY=2,5` runs some scenarios; `OV_E2E_STRICT=1` makes known failures fail the run.
- It prints a scenario × client matrix and exits 1 if any cell failed. Logs and `matrix.txt` go to
  `OV_E2E_OUT_DIR` or a new temporary folder.
- The iOS cells build its vendored core first (more than 10 GB). Each run makes and deletes its own
  simulator.

The scenarios (register and sign in across clients, concurrent edits, Recycle Bin, vault sharing, share
links, key rotation, account deletion and restore), which client takes part in each, and the known
failures are in [e2e/README.md](../e2e/README.md). On 2026-11-21 (task W3-X) every cell passed except 6b,
which `f9af5be` fixed the same day: when a vault's server copy doesn't open with the keys the core holds
(`vault_key_mismatch`), it fetches that vault's keys once more and retries. `KNOWN` is empty since.
