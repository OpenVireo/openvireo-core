# Open items

Known bugs, gaps and follow-ups on `develop` at `f9af5be` (2026-11-21, after every client moved onto
`contract-v1.8`). Remove an item when its fix lands.

## Bugs

- **Edits kept after an accidental session end lose their base.** Since contract-v1.8, `clear_user` keeps
  unsynced edits after `token_reused` / `session_expired`, but on the next sign-in they merge two-way, by
  modification time, instead of three-way against their base.
- **`SelfHosted::health` on a server that answers `{code, error}`** returns `not_found`, not
  `not_sync_server`.
- **`import_into`'s change list prints custom-data values** (`Adding custom data KEY [VALUE]`), for example
  KeePassXC-Browser's keys, into the change text that apps show or log.

## Gaps in the API

- `Vault::export_kdbx` writes a new database: entries get new UUIDs, and history, attachments and custom
  data aren't kept. That's right for "export selected groups", the only place the clients use it, but the
  rustdoc doesn't warn. A local copy of a whole vault is `copy_without_remotes` + `set_kdf` + `save_local`.
  An exact-bytes export isn't there yet.
- No `SelfHosted::sync_vault` on a `Vault` handle that keeps edits made during the sync, as `Vault::sync`
  does since contract-v1.8. iOS replays such edits itself.
- Service accounts: no live events (`ServiceAccount::subscribe` / `access_token`), no key versions in
  `SaVault`, no `ServiceAccount::vault_history` (desktop requests).
- The KDBX model doesn't keep the AES-KDF UUID variant (files with `7c02bb82…` are rewritten with
  `c9d9f39a…`), the header field order, or unknown children of `Times`, `String`, `Binary`,
  `Association`, `Item`, `Icon` and `DeletedObject` (none are in the corpus). Deferred to the fuzz and
  hardening work.

## Build, release and tooling

- **Releases:** 1.0.0 was the first, then 1.1.0, 1.2.0 (`ov connect` in Rust) and 1.2.1 (first on Maven Central, PyPI and SwiftPM). Everything carries the workspace version, `ov version` included. The web
  app still vendors `@openvireo/core-wasm` as a tarball (switching it to the published package is
  optional), and iOS and the desktop build the core from a pinned commit.
- `deny.toml` ignores RUSTSEC-2026-0387 (crypto-bigint via opaque-ke 4.0.1). `cargo xtask unlinked` proves
  none of that code is linked into the wasm modules. The real fix needs opaque-ke 5 (only a pre-release
  exists).
- `cargo xtask cpp` reuses stale headers after its `--out` folder is deleted.
- The full wasm module is about 905 KB gzip after wasm-opt (lite about 192 KB); the size work is part of
  hardening.
- The desktop's `build.yml` (packaging, signing and its Rust step) hadn't run on GitHub yet; the first run
  is the nightly on 2026-11-23.

## Cross-client end-to-end

- iOS and the desktop take part through their own suites, not on accounts made by another client: they
  need a hook to sign in to an account given in the environment. The desktop's live-server mode covers
  self-hosted sync only.
- `ov` has no commands to register, delete entries, use the Recycle Bin, share vaults, rotate vault keys or
  open share links (the TS CLI didn't either), so the SDK does those steps in the e2e scenarios.
- iOS `AccountFlowUITests` stops finding "Create account" once about ten accounts are remembered on one
  simulator; `e2e/run.sh` makes a fresh simulator per run.

## Client-side follow-ups seen during the migration

- SDK: `core/full.ts` pulls the lite module's base64 into the full bundle through `fromCore` (about
  241 KB gzip).
- Web: `SyncRunner` still queues edits behind a running sync (self-hosted reopen).
- iOS: one StoreKit test (`FreeTrialTests`) failed once on GitHub CI and passed on rerun.
