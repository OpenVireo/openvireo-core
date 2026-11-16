# vectors/

Frozen copies of the OpenVireo contract plus generated OPAQUE transcripts. Don't edit these files: when
the contract changes, copy the new files in, update the checksums below and the SOURCE.md next to them,
and run `cargo xtask vectors` and `cargo test -p ov-testkit`. Typed loaders are in `crates/ov-testkit`.
The dev guide's `scripts/check-contract-copies.sh` compares the copies with their canonical sources.

| Path | What | Canonical source |
|---|---|---|
| `test-vectors.json` | SPEC test vectors (AUK, keyset, seal, JWT, share links, ...) | openvireo `docs/plans/accounts/test-vectors.json` |
| `vault-fixture.kdbx` | the contract's account vault (see `vault_kdbx` in test-vectors.json) | openvireo `docs/plans/accounts/vault-fixture.kdbx` |
| `merge-fixtures/` | three-way merge cases from the desktop merge | see `merge-fixtures/SOURCE.md` |
| `openapi/` | auth + sync server OpenAPI contracts | see `openapi/SOURCE.md` |
| `kdbx/` | `.kdbx` files written by the desktop app | see `kdbx/SOURCE.md` |
| `opaque-transcripts.json` | deterministic OPAQUE runs, TS SDK (opaque-ke) and libopaque | generated here, see below |
| `tools/` | the generators for `opaque-transcripts.json` | this repo |

## Copied files

From openvireo (`github.com/openvireo/openvireo`), branch `develop`, at HEAD
`14873339afc6faa2dbf450200b17aec69aa58df7` (2026-11-15), copied unchanged:

- `test-vectors.json`: last changed in `f7276e5fa2f41d4b6735f6bbf8fae1a4b1db7cf4` (2026-11-07, "Contract:
  share links (SPEC §22)"). Made by openvireo's `docs/plans/accounts/tools/gen.mjs`.
- `vault-fixture.kdbx`: last changed in `88dffc10a78b3fefb8379067e08825ea8c822c57` (2026-10-24).

## opaque-transcripts.json

Deterministic OPAQUE runs (SPEC §8, RFC 9807: ristretto255 OPRF + 3DH, SHA-512, KSF Argon2id v1.3
64 MiB / t=2 / p=1 / all-zero 16-byte salt, context `ov-opaque-v1`, password = UTF-8 of NFKC):

- `opaque_ke`: the TS SDK's client (`@openvireo/sdk/opaque`, opaque-ke 4.0.1 compiled to WASM) against
  the SDK's opaque-ke test server (`opaqueServerForTests`): registration, login, and a wrong-password
  login that must fail. The SDK takes one 32-byte seed per operation from `crypto.getRandomValues`
  (a ChaCha20Rng seed inside the module); the generator replaces `getRandomValues` with named seeds and
  checks each operation takes exactly one. Same seed, same bytes.
- `libopaque`: libopaque (the C core of the Flask auth server and the desktop client), unmodified static
  libraries, driven by `tools/libopaque-transcript.c`, which installs a seeded libsodium `randombytes`
  implementation (call n gets `randombytes_buf_deterministic(BLAKE2b-256(seed ‖ u64le n))`). Recorded:
  - `registration`: libopaque client + server registration (per-user server keypair): request, server
    secret (skS ‖ kU), response, registration record, export key, stored user record.
  - `login_c_client`: the libopaque client logging in to that record.
  - `login_opaque_ke_client`: **the opaque-ke client logging in to the account libopaque registered**,
    on the libopaque server. The generator checks the opaque-ke KE3 equals libopaque's expected `authU`,
    both sides get the same session key, and opaque-ke recovers libopaque's export key. A Rust replay:
    start a client login with `client_start_seed_hex` (must give `ke1_hex`), finish it on `ke2_hex`
    (must give `auth_u_hex`, `session_key_hex`, `export_key_hex`).
  - `opaque_ke_registration`: the opaque-ke client registering on the libopaque server (the web flow),
    then the libopaque client logging in.
- Every seed is `SHA-256(UTF-8 "ov-opaque-transcripts/v1/" ‖ label)` and is recorded next to its step.

Regenerate (macOS or Linux with a C compiler and Node ≥ 20):

```sh
vectors/tools/gen-opaque-transcripts.sh            # writes vectors/opaque-transcripts.json
```

It builds `target/vector-tools/libopaque-transcript` (`tools/build-libopaque-tool.sh`) and runs
`tools/gen-opaque-transcripts.mjs`. Inputs, both read-only:

- `OV_SDK`: an openvireo-sdk checkout with `packages/sdk/dist` built (`npm run build`), default
  `/Users/bongani/kpnx/openvireo-sdk`. Recorded with SDK `develop` at
  `fd5e5318ae7db680ba625253a6561ded33d08870` (OPAQUE last changed in `0021f02de77dfb94d4b46986021c8250ada5dc59`),
  `vendor/opaque/opaque-wasm.js` SHA-256 `3586f4501f8616264267907cd9aed548776db8ed3c3533bf9d51f9a2c6075e3d`.
- `OV_OPAQUE_PREFIX`: static libsodium 1.0.20, liboprf `f925b87`, libopaque `6e9ac92`, as built by openvireo's
  `.github/scripts/build-opaque.sh PREFIX`, default `/Users/bongani/kpnx/.deps/prefix`. Recorded with
  `libopaque.a` SHA-256 `ac49059f7095b8d0dfd0d0482009cba3f2dc8da4002db16a5e6edcacd332d0ab`, `liboprf.a`
  `24ab247856cc70849b7f75893e5f5d040249ec8d814405919ffe1601f24ade67`, `libsodium.a`
  `e2b7a9a0749072d3b3d571e40a65de6995e1919ced4c9ad00fd5eb80441a0b1a` (Apple clang 21, arm64).

The whole file is deterministic: a regeneration must be byte-identical (`git diff --exit-code vectors/`).

## Checksums

```
ce8997cedafa1146420d020ed2beb9215afe77d2fbb6903f72c865990aa752c1  test-vectors.json
f0bc7a8034bb6eb578e7dc83594ba255b5a74cd27b6f30cf9ed8c4398993c224  vault-fixture.kdbx
a40d2bd90ed0c747bdcbce9d41055e342b7bfed3fddf43b0eab27e8973eba909  opaque-transcripts.json
7cb9d7d89327c99a0a73568d4bb389dc9f3656f511031645506c8105c371e044  tools/build-libopaque-tool.sh
30db0ef7e3623bc448f5b04d00a13e964174bcad66dabd07735b3778c54f58e6  tools/gen-opaque-transcripts.mjs
1c005cf4312c3d3fd456a4204d790a65b76f1aceb7c8eb29a76aba53b08df4fd  tools/gen-opaque-transcripts.sh
3332c26a373eded98d8221752e46894522897a176c4f4f2653435bc08cb28b1f  tools/libopaque-transcript.c
```
