# openvireo-core

The shared Rust core of the OpenVireo password manager: account crypto, OPAQUE, vault keys and
sharing, share links, sync, KDBX and merge. Written once, called from every client:

| Client | Binding |
|---|---|
| Web SDK (`@openvireo/sdk`) and browser extension | WASM (`bindings/ov-wasm`) |
| iOS app and AutoFill | Swift via UniFFI (`bindings/ov-ffi-swift`) |
| Desktop (Qt) | C++ via cxx (`bindings/ov-ffi-cpp`) |
| `ov` CLI | native binary (`bins/ov`) |

The core does no I/O. Each platform passes in a small `Host` (HTTP transport, secure store, offline
cache, clock, log sink), so TLS, proxies and the Keychain stay with the platform.

> **Status:** early. The crates are being built in waves; until `1.0.0` the API can change. Today the
> workspace holds `ov-opaque`, the OPAQUE (RFC 9807) client that moved here from `openvireo-sdk`
> with its history.

## Layout

```
crates/      ov-error, ov-crypto, ov-opaque, ov-protocol, ov-kdbx, ov-merge, ov-share,
             ov-vault, ov-sync, ov-core (the facade), ov-testkit
bindings/    ov-wasm, ov-ffi-swift, ov-ffi-cpp
bins/ov/     native CLI
vectors/     contract test vectors, copied unchanged from the protocol spec
xtask/       build and check tasks
```

Crates depend only downward: `ov-core` → domain crates → `ov-crypto`. Only `bindings/*` and `bins/*`
know about a platform.

## Building

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on first use.

```sh
cargo build --workspace
cargo test --workspace
cargo xtask ci        # fmt, clippy -D warnings, test, cargo deny, vectors, wasm32 + iOS builds, size
cargo xtask help      # all tasks
```

`cargo xtask ci` needs [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)
(`cargo install --locked cargo-deny`). The iOS builds run on macOS only.

## Dependencies

New dependencies are pinned exactly in the root `Cargo.toml` (`[workspace.dependencies]`) and
must pass `cargo deny` (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode licences only).

## Security

Please report vulnerabilities privately to admin@openvireo.com. See
[SECURITY.md](https://github.com/openvireo/.github/blob/main/SECURITY.md).

## Licence

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
