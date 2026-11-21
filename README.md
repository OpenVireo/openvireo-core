# openvireo-core

The shared Rust core of the OpenVireo password manager: account crypto, OPAQUE sign-in, sessions,
vault keys and sharing, share links, sync, KDBX and the three-way merge. Written once, called from every
client:

| Client | Binding |
|---|---|
| Web SDK (`@openvireo/sdk` 1.0) and the web app | WASM (`bindings/ov-wasm`, `bindings/ov-wasm-lite`) |
| iOS app and AutoFill | Swift via UniFFI (`bindings/ov-ffi`) |
| Desktop (Qt) | C++ via cxx (`bindings/ov-ffi-cpp`) |
| `ov` CLI | native binary (`bins/ov`) |
| Python scripts | Python via UniFFI (`bindings/python`, package `openvireo`) |
| JVM and Android | Kotlin and Java via UniFFI (`bindings/kotlin`, `com.openvireo:openvireo-core-jvm` / `-android`) |

The core does no I/O. Each platform passes in a small `Host` (HTTP transport, secure store, offline
cache, clock, log sink), so TLS, proxies and the Keychain stay with the platform.

> **Status:** every client runs on the core (`contract-v1.8`). No release has been cut yet, and until
> `1.0.0` the API can change; each client pins an exact commit.

## Layout

```
crates/      ov-error, ov-http, ov-host (the frozen contract types), ov-crypto, ov-opaque,
             ov-protocol, ov-kdbx, ov-merge, ov-share, ov-vault, ov-sync, ov-core (the facade),
             ov-testkit (test-only: vector loaders, in-memory auth and sync servers)
bindings/    ov-wasm, ov-wasm-lite, ov-ffi, ov-ffi-cpp
bins/ov/     native CLI
vectors/     contract test vectors, copied unchanged from the protocol spec
corpus/kdbx/ .kdbx files written by other apps, for round-trip tests
e2e/         cross-client end-to-end tests against the local stack
xtask/       build and check tasks
docs/        architecture, contract, building, testing, open items, ADRs
```

Crates depend only downward: `ov-core` → domain crates → `ov-crypto`. Only `bindings/*` and `bins/*`
know about a platform.

## Documentation

- [Architecture](docs/architecture.md): crate map, the Host, the facade, errors, secrets
- [The frozen contract](docs/contract.md): what is frozen, how it changes, the `contract-v1.N` tags
- [Building](docs/building.md): the CLI, the wasm package, the xcframework, the C++ library, and how
  each client consumes them
- [Testing](docs/testing.md): `cargo xtask ci`, vectors and the corpus, binding tests, the golden CLI diff,
  cross-client e2e
- [Open items](docs/open-items.md): known bugs and follow-ups
- [API coverage](docs/api-coverage.md): every public method of the TS SDK and the iOS `Account` → the facade
- ADRs: [0001 the contract](docs/adr/0001-contract.md), [0002 our own KDBX crate](docs/adr/0002-kdbx.md)
- [Language bindings](docs/bindings/README.md): which binding to use, with guides for
  [Python](docs/bindings/python.md) and [Kotlin and Java](docs/bindings/kotlin-java.md)
- Each binding's README: [wasm](bindings/ov-wasm/README.md), [UniFFI/Swift](bindings/ov-ffi/README.md),
  [C++](bindings/ov-ffi-cpp/README.md), [Python](bindings/python/README.md),
  [Kotlin/Java](bindings/kotlin/README.md); [e2e](e2e/README.md)
- The API itself: `cargo doc --workspace --no-deps --open`

## Building

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on first use.

```sh
cargo build --workspace
cargo test --workspace
cargo xtask ci        # fmt, clippy -D warnings, test, cargo deny, rustdoc, vectors, openapi, wasm32 + iOS builds, size
cargo xtask help      # all tasks
```

`cargo xtask ci` needs [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)
(`cargo install --locked cargo-deny`). The iOS builds run on macOS only. Building each binding:
[docs/building.md](docs/building.md).

## Dependencies

New dependencies are pinned exactly in the root `Cargo.toml` (`[workspace.dependencies]`) and
must pass `cargo deny` (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode licences only, plus MPL-2.0 for the
UniFFI crates).

## Security

Please report vulnerabilities privately to admin@openvireo.com. See
[SECURITY.md](https://github.com/openvireo/.github/blob/main/SECURITY.md).

## Licence

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. That lets
the same code go into the MIT iOS app, the MIT/Apache SDK and the GPL desktop app.

Third-party crates compiled in are under permissive licences, except UniFFI's runtime crates
(`uniffi_core` and friends), which are MPL-2.0 and are compiled into the UniFFI binding (`ov-ffi`) only. MPL-2.0 is
file-level: shipping them unmodified needs their notice and a pointer to their source, which the iOS
app's `scripts/build-vendor.sh` writes into `CORE-THIRD-PARTY-LICENSES.txt`.
