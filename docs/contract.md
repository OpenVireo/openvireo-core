# The frozen contract

Three apps and the CLI build against the core's API. To keep them from breaking each other, the
interfaces that cross a crate or binding boundary are **frozen**: they change only on purpose, in a
reviewed commit on `develop` that gets a `contract-v1.N` tag.

## What is frozen

| Contract | Files |
|---|---|
| The facade: names, signatures, records and enums (not the method bodies) | `crates/ov-core/src/api/**` |
| The Host traits | `crates/ov-host/**`, re-exported by `crates/ov-core/src/host.rs` |
| HTTP request and response types | `crates/ov-http/**` |
| Errors and their wire codes | `crates/ov-error/**` |
| The KDBX document model | `crates/ov-kdbx/src/model.rs` |
| Crypto primitives | `crates/ov-crypto/src/primitives.rs` |
| Copies of the protocol contract | `vectors/**` (see `vectors/SOURCE.md`) |

The method bodies behind the facade live in `crates/ov-core/src/impls/` and `state.rs`, which are not
frozen. A fix there needs no tag, as long as no public signature or documented behaviour changes.

`vectors/` holds unchanged copies of the protocol contract, whose original lives in the desktop repo
(`openvireo/docs/plans/accounts/`: `SPEC.md`, `test-vectors.json`, `vault-fixture.kdbx`, the OpenAPI
files) and in the merge fixtures the desktop records. The core never edits them. When the contract
changes there, the new files are copied in with their checksums (`cargo xtask vectors` checks them).

## How a change goes in

1. Someone needs a frozen interface to change: a new facade method, a record field, a new error code.
   They write it up as a CONTRACT-REQUEST (what, why, which clients need it). Work that can't wait uses a
   workaround with a `// CONTRACT-REQUEST:` comment meanwhile.
2. The owner (the lead) decides. Rejected requests use the existing contract.
3. An accepted change lands on `develop` as its own commit, separate from the implementation, so it can be
   reviewed alone. It must be **additive** wherever possible: new methods and new optional fields, no
   removed or renamed public items. Every binding exports the change in the same round
   (wasm `.d.ts`, Swift, C++ with `cargo xtask cpp --check-coverage` at 0 missing).
4. `cargo xtask ci` passes on the merge, and GitHub CI is green on all four jobs.
5. The lead tags the merge `contract-v1.N` and records it in [ADR 0001](adr/0001-contract.md) (one section per
   tag) and in [api-coverage.md](api-coverage.md).
6. Each client moves to the new tag in its own repo: the iOS `CORE_REV` in `scripts/build-vendor.sh`, the
   desktop `rev` in `src/account/ovcore/Cargo.toml`, a rebuilt `@openvireo/core-wasm` tarball in the SDK's
   `packages/sdk/vendor/core-wasm/` (until the package is published).

Adding a record field is still a **source** break for Rust code that builds the record with a struct
literal (the bindings and tests), which is why each addition lands in every binding at once.

## The tags

| Tag | Commit | Date | What changed |
|---|---|---|---|
| `contract-v1` | `2e10b62` | 2026-11-15 | The Wave 0 freeze: facade with `todo!()` bodies, Host, errors, KDBX model, primitives, vectors |
| `contract-v1.1` | `2aef3fa` | 2026-11-15 | `unicode-normalization` allowed (NFKC for SPEC §3, §8, §22) |
| `contract-v1.2` | `b00a895` | 2026-11-15 | `Method` / `HttpRequest` / `HttpResponse` moved unchanged into `ov-http`; OpenAPI copies in `vectors/openapi/`; `cxx-build` allowed |
| `contract-v1.3` | `4de89f8` | 2026-11-15 | `salsa20` (KDBX 3.1) and `sha1` (TOTP) allowed; `keepass` dropped (ADR 0002); reqwest on the OS trust store |
| `contract-v1.4` | `151e7ff` | 2026-11-15 | `libc` allowed for `bins/ov` |
| `contract-v1.5` | `65f8717` | 2026-11-15 | The Host traits moved unchanged into `ov-host`, re-exported as `ov_core::host`; rustdoc `-D warnings` in CI |
| `contract-v1.6` | `ca2f211` | 2026-11-19 | What iOS and the desktop needed to move onto the facade: entry usage and colours, field order, `add_entry_with_id`, attachment protected flag, `entry_records`, import between vaults, local-file metadata and KDF, self-hosted history, `OvClient::open_local` / `create_local`, `Account::sync_vault_kdbx`, `access_token`, `SyncOptions::accept_server_state`; `windows-sys` for `bins/ov` |
| `contract-v1.7` | `80ae01b` | 2026-11-20 | `KdbxCredentials.password_hash`, `SelfHosted::sync_database_with`; a wrong local-file key is `vault_key_mismatch` (was `kdbx_error`); sign-in `details.reason` |
| `contract-v1.8` | `966606d` | 2026-11-20 | `share_vault_with_keys`, `SelfHosted::download`, service-account `vault_kdbx_credentials` / `sync_vault_kdbx`, `Profile.kdf` + `public_keys`, `not_sync_server`, `rotation_pending`; behaviour fixes (Recycle Bin restore location, edits made during `Vault::sync` kept, plain export = the web app's bytes) |
| `contract-v1.9` | `de11502` | 2026-11-21 | `Platform::Android` (wire `android`) in the facade, every binding and `ov-protocol` |
| `contract-v1.10` | (tagged) | 2026-11-24 | `hyper`, `hyper-util`, `http-body-util`, `tokio-rustls`, `rustls-pki-types` for `bins/ov` (`ov connect`); tokio `net` in `ov`; `httpdate` new in the lock |

Tags 1.1 to 1.5 also cover the dependency allow-list (the root `Cargo.toml`, `[workspace.dependencies]`),
which is managed the same way. Details of 1.6 to 1.8 are in ADR 0001.

## Dependencies

New dependencies follow the same path: an OWNER-REQUEST, then an exact pin (`=x.y.z`) in the root
`Cargo.toml`. `cargo deny` allows only MIT, Apache-2.0, BSD, ISC, Zlib and Unicode licences, plus
MPL-2.0 for the UniFFI crates (see the README's licence section). `reqwest`, `libc`, `windows-sys`
and `tokio` (outside tests) are for `bins/ov` only.
