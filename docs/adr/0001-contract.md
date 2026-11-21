# ADR 0001: The `contract-v1` interfaces

- Status: proposed (W0-B), accepted when the lead tags `contract-v1`
- Date: 2026-11-15
- Plan: `openvireo-dev-guide/plans/rust-core.md`, tasks `plans/rust-core-tasks.md` §2

## Context

Wave 1 and Wave 2 build ten-plus crates in parallel. They can only do that against interfaces that
don't move: the error type, the platform Host, the facade the bindings expose, the KDBX document model
that the reader/writer and the merge share, and the crypto primitives everything else calls. This ADR
records what W0-B wrote for §2.2-§2.5 and every choice the task page left open.

## Decision

### What is frozen

| Contract | File | Frozen |
|---|---|---|
| Errors (§2.4) | `crates/ov-error/**` | whole crate |
| Host (§2.2) | `crates/ov-core/src/host.rs` | whole file |
| Facade (§2.3) | `crates/ov-core/src/api/**` | names, signatures, records and enums; **not** the `todo!()` bodies |
| KDBX model (§2.5) | `crates/ov-kdbx/src/model.rs` | whole file |
| Primitives | `crates/ov-crypto/src/primitives.rs` | whole file (implemented, with vectors) |

The facade's method bodies are `todo!()`. W2-A replaces them, ideally with one-line calls into its own
modules, without changing a signature. The handles (`OvClient`, `Account`, `Vault`, `ServiceAccount`,
`SelfHosted`, `EventStream`, `TotpChallenge`) each hold `pub(crate) inner: Arc<state::XState>`; the state
structs live in `crates/ov-core/src/state.rs`, which is **not** frozen, so W2-A can add fields freely.
`lib.rs` allows `unused_variables` and `dead_code` until the stubs are gone.

### Errors

- `OvErrorCode` lists the TS `OpenVireoErrorCode` union one for one, in order, then the seven codes the
  TS SDK throws without listing them (`invalid_link`, `invalid_passcode`, `passcode_required`,
  `invalid_totp`, `invalid_password_hash`, `too_large`, `unsupported`), then `internal`. The share page
  matches on `invalid_passcode` / `passcode_required`, so they need variants.
- `OvError` has the five §2.4 fields plus `server_code: Option<String>`. The server sends codes the SDK
  passes through untyped (`deletion_blocked`, `confirm_mismatch`, `deletion_pending`, `billed_by_apple`,
  `invalid_code`, `per_seat_plan`, `upstream_error`, …). `OvError::from_server` keeps such a code in
  `server_code` and takes the variant from the status (`codeForStatus`). `wire_code()` returns what
  the TS `err.code` would have held, so UI string matching keeps working everywhere.
- `details` is a JSON object string with the SDK's camelCase keys. `is_unreachable()` is the SDK's
  `isUnreachable` (network error or 502/503/504), which every offline fallback uses.

### Host

As §2.2, with these gaps filled:

- `MaybeSend`/`MaybeSync`: blanket traits, `Send`/`Sync` natively and empty on wasm32. Async traits use
  `async_trait`, `?Send` on wasm32 (checked by the wasm32 build in `cargo xtask ci`).
- `Method` (GET HEAD POST PUT PATCH DELETE). `HttpRequest` has a `keepalive` flag (for
  `sign_out_on_unload` on the web). Transports must not follow redirects. `Debug` never prints header
  values (bearer tokens).
- `ByteStream` is a Host trait with `&self` methods (`status`, `next_chunk`, `close`), so it can be a
  UniFFI/cxx foreign object; no `futures::Stream` in the contract.
- `TransportError` converts to `OvError`: `Cancelled` → `aborted`, the rest → `network_error`.
- `SecureStore` values are bytes (`Zeroizing<Vec<u8>>` out). Keys are the names the TS SDK and iOS
  already use, so stored sessions and Secret Keys carry over.
- `BlobCache` is keyed by **user and vault**, not vault alone: two accounts on one device can share a
  vault (SPEC §21), and the TS SDK already keys its offline state `sync:<user>:<vault>`. It also has
  `list`, `clear_user` and small `load_meta`/`save_meta` records (discovery document, wrapped keyset +
  KDF, vault list) that offline unlock needs. `CachedVault` holds the core-serialized sync state plus
  the encrypted `base`, `pending` and (iOS) `autofill` KDBX copies. All of it is ciphertext or public.
- `Level` has five levels. `Host` is `Clone` and `Debug` (opaque).

### Facade

- One Rust method per public TS/Swift method; `docs/api-coverage.md` maps all 342 of them (313 mapped,
  29 "not ported" with a reason, none unmapped).
- Sign-in lives on `Account` (as in both clients), not on separate `Signup`/`Login` types:
  `register`, `login → LoginStep { NeedsTotp(TotpChallenge) | Unlocked(Unlocked) }`, `submit_totp`.
  `TotpChallenge` is an opaque handle (it holds the MFA token and, until the code arrives, the material
  needed to unlock), not a plain record. Offline unlock is part of `unlock` (as in both clients), so
  there is no separate `unlock_offline`.
- `Unlocked` and `NewAccount` carry the AUK (the iOS biometric unlock needs it).
- Callbacks become pull APIs, since FFI has no closures: `Account::signed_out` (await in a loop) and
  `EventStream::next`. Subscribing is on `Account` (both clients), not on `Vault`.
- Share-link opening needs HTTP, so `open_share` / `share_info` are `OvClient` methods (taking `api`),
  not free functions. Payload builders, TOTP and `deletion_expired` are free functions.
- The web's `sealUnlocked` / `resumeUnlocked` keep their WebCrypto AES-GCM seal (non-extractable key,
  format `s1`) in the TS wrapper; the core exposes `unlocked_keyset_secret` and `resume_unlocked`.
- `VaultUploadError` becomes `ImportOutcome { uploaded, upload_error }`.
- `Vault` covers account vaults, local files (`open_local`, `create_local`, `save_local`) and read-only
  history versions. Edits are local until `sync`, except `write_field` (as TS `AccountVault.write`).
- Records use RFC 3339 strings for server times and Unix seconds for KDBX times; ids are lowercase
  hyphenated UUIDs (server) or 32 hex digits (KDBX).
- Secrets cross as `SecretBytes = Vec<u8>`; `Debug` impls on records that hold secrets redact them.
- `CancelToken` is implemented (not a stub): `cancel`, `is_cancelled`, `check` (→ `aborted`) and a
  `cancelled()` future. Every network or KDF call takes one.
- `ov_core::version()` exists for the bindings' smoke tests.

### KDBX model

- Header settings are part of the model (`version`, `cipher`, `compression`, `kdf`,
  `public_custom_data`, unknown header fields), because the merge's result keeps the server's header.
  Per-save randoms (master seed, IV, inner stream key) and derived values (HeaderHash, header HMAC) are
  not.
- Attachments are a pool (`Database::binaries`) referenced by index (`BinaryRef`), as KDBX stores them.
- `AutoType` is structured (enabled, obfuscation, default sequence, associations) with its own
  `unknown` list, so desktop auto-type settings round-trip and merge field by field.
- `unknown: Vec<XmlElement>` on `Database` (file and root level), `Meta`, `Group`, `Entry` and
  `AutoType`. `XmlElement` text is in clear; a `Protected="True"` attribute is kept and the writer
  re-applies the inner stream.
- Protected string values and attachment data are `Zeroizing` and redacted in `Debug`.
- Every element name KeePassXC's `KdbxXmlReader` reads has a field.

### Primitives

`sha256`, `hkdf_sha256` (+ `hkdf_sha256_32`), `aead_encrypt` / `aead_decrypt` (XChaCha20-Poly1305 over
fixed-size key and nonce arrays; AAD as bytes), `argon2` (d / i / id, version 0x13) and
`argon2id_32`, `fill_random` / `random_bytes` / `random_array` / `random_key` / `random_nonce`.
Derived secrets come back `Zeroizing`. Tested against RFC 5869 A.1-A.3, draft-irtf-cfrg-xchacha-03
A.3.1 (plus tamper cases) and the SPEC's `auk` vectors (Argon2id and the AUK HKDF).

## contract-v1.6 (2026-11-19, W3-A3)

User-approved 2026-11-19 (rust-core-tasks.md §9): the eight facade CONTRACT-REQUESTs from W3-BS2
(`bindings/ov-ffi-swift/README.md`), W3-L3's `ServiceAccount` issuer, and W2-A's local-vault clock.
Everything is **additive** (new fields, new methods, new records); no existing method signature
changed. The one source-level break is for Rust code that builds `EntrySummary`, `EntryRecord`,
`AttachmentInfo`, `EntryInput` or `SyncOptions` with a struct literal that lists every field: such
code needs the new fields (`EntryInput` and `SyncOptions` have `Default`, so
`..Default::default()` keeps working).

| # | Request | Added |
|---|---|---|
| 1 | last use of an entry | `EntrySummary` and `EntryRecord`: `last_access_at: Option<i64>` (`None` while `UsageCount` is 0), `usage_count: u32` |
| 2 | colours, custom icon, field order | `EntryInput`: `foreground_color` / `background_color: Option<String>` (`#RRGGBB`, empty clears), `custom_icon: Option<Option<String>>` (`Some(None)` clears; the id must be a custom icon of the database), `field_order: Option<Vec<String>>` (custom fields after the standard ones) |
| 3 | caller-chosen entry id | `Vault::add_entry_with_id(entry_id, group_id, input)` (`conflict` if it exists; drops a deletion record for the id) |
| 4 | attachment protected flag | `AttachmentInfo.protected`; `Vault::set_attachment_with(entry_id, name, data, protected: Option<bool>)` (`None` keeps the replaced attachment's flag). `set_attachment` is unchanged (protected, as before) |
| 5 | every entry with values in one call | `Vault::entry_records(include_recycle_bin)` |
| 6 | import into an open vault, with a preview | `Vault::import_from(source: Vault, LocalImportMode::{Merge, Copies { parent_group_id }}) -> ImportSummary`, `Vault::import_preview() -> ImportPreview { entries, groups }`, `Vault::import_targets() -> Vec<ImportTarget>`, over `ov_merge::{import_into, import_as_copies, import_targets, import_preview}` |
| 7 | local-file metadata | `Vault::set_name` (local only), `Vault::meta_custom_data` / `set_meta_custom_data`, `Vault::copy_without_remotes(credentials: Option<KdbxCredentials>)` (`ov_kdbx::vault::drop_server_remotes`; a copy of an account vault gets `KdbxKdf::DatabaseDefault`), `Vault::set_kdf(KdbxKdf)` (local only), `Vault::export_kdbx_with(credentials, group_ids, kdf, cancel)`. `export_kdbx` keeps kdbxweb's KDF (Argon2d 1 MiB, t = 2, p = 1), now documented |
| 8 | self-hosted version history | `SelfHosted::history(database_id)`, `SelfHosted::open_version(database_id, revision, credentials)` (a read-only `Vault`) |
| 9 | the SA's server (W3-L3) | `ServiceAccount::server_config()`, `ServiceAccount::issuer()` |
| 10 | local vaults on the Host clock (W2-A) | `OvClient::open_local`, `OvClient::create_local`: as `Vault::open_local` / `create_local`, but edits are stamped with the Host `Clock`. The `Vault` constructors keep their behaviour (system clock; on wasm32 one second after the newest time in the file) |

Added the same day for the desktop (W3-ID2, user-approved, relayed by the lead):

| # | Request | Added |
|---|---|---|
| 11 | sync an account vault the desktop holds as a file | `Account::sync_vault_kdbx(vault_id, kdbx, base: Option<Vec<u8>>, SyncOptions) -> VaultKdbxSyncResult { kdbx, credentials, report: SyncReport }` on `ov_sync::sync_kdbx` (all key versions open the file; 412 merge-and-retry; one token refresh on 403); `Account::vault_kdbx_credentials(vault_id) -> KdbxCredentials` (the newest vault key as a raw key file). The sync state is kept in the BlobCache record `kdbx-file:<vault id>`, apart from `Vault::sync`'s |
| 12 | "continue anyway" | `SyncOptions::accept_server_state` (default `false`), honoured by `Vault::sync` too. `server_rolled_back` / `server_lost_database` stay errors, as in `ov-sync` |
| 13 | borrow the core's session | `Account::access_token(force_refresh: bool) -> SecretBytes` (refreshes when about to expire; a refused refresh ends the session) |

Deviations from the request: (11) the result reuses `SyncReport` (outcome, ETag, conflicts, changes,
attempts, clock offset) instead of separate `etag` / `outcome` / `MergeReport` / `conflicts` /
`clock_offset_ms` fields, and adds the `credentials` the merged file is under (after a rotation the
server copy can still be under an older key). (13) `force_refresh: bool` instead of
`audience: Option<String>`: SPEC §9 has one access token for the auth and sync servers, so there is
no audience to choose; forcing a refresh is what a caller needs after a 403 for a newly shared
vault. `SyncOptions` gained a field, so struct literals need `..Default::default()`.

`KdbxKdf` is `DatabaseDefault` (KeePassXC's default for new databases: Argon2d, 64 MiB, 10 iterations,
2 lanes, as iOS `KDF.databaseDefault`), `Argon2d` / `Argon2id { memory (bytes), iterations, parallelism }`
or `AesKdf { rounds }`; every choice gets a fresh salt, and Argon2 upgrades a KDBX 3.1 database to 4.

Not added: `SelfHostedSync.normalize` / `sameServer` (BS2's optional extra in request 7); a "mark entry
used" edit (no client increments `UsageCount` today; iOS only reads it).

## contract-v1.7 (2026-11-20, W3-A4)

User-approved 2026-11-20. Additive, except one error code:

| # | Change |
|---|---|
| 1 | `KdbxCredentials.password_hash: Option<SecretBytes>`: the password's SHA-256 (the composite key's password component, TS `passwordHash`) instead of `password`; with or without `key_file`. Both `password` and `password_hash`, or a hash that isn't 32 bytes: `invalid_request`. Honoured everywhere credentials are (open/create/save local, export, import, self-hosted sync and versions) |
| 2 | `SelfHosted::sync_database_with(database_id, kdbx, credentials, SyncOptions)`: `local_changed: false` sends a HEAD first and, when the server is unchanged, returns `kdbx` itself (`Unchanged`, nothing decrypted, no KDF); `accept_server_state` as for account vaults. `sync_database` = the defaults |
| 3 | A wrong local-file key is `vault_key_mismatch` (TS 0.11, and what `ov_kdbx::read` / `Kdbx.read` say) from `Vault::open_local`, `OvClient::open_local` and `Account::import_kdbx`; was `kdbx_error`. A damaged file stays `kdbx_error` |
| 4 | Sign-in `unauthorized` / 401 carries `details` `{"reason":"keyset_unwrap_failed"}` (password accepted, keyset doesn't unwrap: wrong Secret Key; also an offline unlock or password check with a wrong password) or `{"reason":"opaque_refused"}` (OPAQUE refused: wrong email or password). After `keyset_unwrap_failed` on sign-in the core logs out the server session it opened |

Behaviour (no signature change): sync opens the base whenever the copies differ (the snapshot's
whole-second times missed same-second edits, so a service account's 412 retry kept the other copy
whole); a service account downloads a vault with one GET and a write to an unopened vault uploads
against that copy; merging history keeps every item of a second.

## contract-v1.8 (2026-11-20, W3-A5)

The core gaps the iOS migration (W3-II2b, W3-II3) and the desktop (W3-ID2c) found. Additive; the
behaviour changes are listed and documented on the methods. New signatures:

| # | Change |
|---|---|
| 1 | `Account::share_vault_with_keys(vault_id, grantee, role, PublicKeys)`: the grantee's keys are fetched and compared with the ones the user confirmed; different → `invalid_public_keys`, nothing sealed |
| 2 | `SelfHosted::download(database_id) -> Option<Vec<u8>>`: `GET databases/<id>` without the key; `None` for 404 |
| 3 | `ServiceAccount::vault_kdbx_credentials`, `ServiceAccount::sync_vault_kdbx` (as the `Account` ones; no offline cache, so the base is the caller's) |
| 4 | `Profile.kdf: KdfParams`, `Profile.public_keys: PublicKeys` (signature checked; a change means the keyset was replaced by recovery). Source-level break for Rust struct literals of `Profile` only |

Behaviour changes:

| # | Change |
|---|---|
| 5 | Moves and deletes record `PreviousParentGroup` on every KDBX version (kdbxweb did on 4.1 only, and new vaults are 4.0, so Recycle Bin restores went to the root). `ov_kdbx::write_version` raises a 4.0 database to 4.1 when it holds a 4.1 element (`ov_kdbx::uses_kdbx41_elements`: `PreviousParentGroup`, group tags, `QualityCheck`, custom icon names/times, custom data times; not `SettingsChanged`, which kdbxweb writes into 4.0 files), as KeePassXC 2.7's `kdbxVersionRequired` does. KeePassXC 2.7+ and KeePass 2.48+ read every 4.1 element; KDBX 4 readers that check only the major version (KeePassXC 2.6, kdbxweb) open the file and drop them. The sync merge carries the moved-last copy's `PreviousParentGroup` |
| 6 | `Vault::sync` merges edits made to the handle while it ran (three-way, base = the copy the round started from) and uploads them in up to two more rounds of the same call (against the copy just uploaded: no download); later edits, or a later round that can't reach the server, stay as unsynced edits. The report combines the rounds (outcome = the most a round did) |
| 7 | `Vault::restore_entry` on an entry in the Recycle Bin moves it out (previous group, else `group_path`) and edits it, keeping its history (was: replaced by the version's copy) |
| 8 | `Vault::export_plain` writes the web app's bytes: unquoted CSV header, no final newline, JSON keys `folder, title, username, passwordValue, url, notes`; `folder` is the group's own name (`Root` when empty), an empty title `(Untitled Entry)` (fixture `crates/ov-core/tests/fixtures/export_plain/`, written by the web code) |
| 9 | A session that ends by accident (`token_reused`, `session_expired`: the refused refresh's `details.reason`) keeps each vault's `pending` and `autofill` parts of the offline cache (no state, base or meta records) for the same user's next sign-in, SPEC §20; every other end (`unauthorized`, deletion) and `sign_out` / `sign_out_parked` / `delete_account` wipe everything with `BlobCache::clear_user` |
| 10 | `rotate_vault_key` / `revoke`: a pending rotation this account holds the key for is finished first (re-key, activate, name); one it doesn't is `conflict` 409 with `server_code` `rotation_pending` until it is activated or 24 hours old (then the server replaces it, as the auth server does) |
| 11 | `SelfHosted::health`: a page that isn't a sync server's (non-JSON, no `status`, an error without `{error, code}`) is `invalid_request` with `server_code` `not_sync_server` and the page's status |
| 12 | `details` for 409 `deletion_blocked` (`{"orgs": [...]}`) and 403 `account_pending_deletion` (`{"scheduledFor": ...}`) |
| 13 | `create_vault` / `import_kdbx`: an org owner/admin whose keys don't verify is `invalid_public_keys` with `details` `{"principal", "email"}` |
| 14 | `Meta/CustomData` merges three ways in sync (an item another device added was dropped); `import_kdbx` into a vault (merge) brings the source's items the vault lacks, never its remote settings or generated keys; a new vault keeps all of it minus the server remotes |
| 15 | `open_vault` with nothing kept locally is one GET (was a download plus a sync that downloaded again); a rolled-back server is still detected against a cached state |
| 16 | Merge: an entry only one side changed (by content), in the same second as the other copy, is taken whole instead of combined, so a pull with nothing changed locally doesn't upload (W3-IW3 smoke). A changed side whose clock is behind is still combined (merge fixture 03) |

## Consequences

- Wave 1/2 agents build against these files and raise a CONTRACT-REQUEST for any change.
- The api-coverage table is the checklist for W2-A ("no `todo!()` left") and W3 integrations.
- `rand_core` is not needed by the primitives (randomness goes through `getrandom` directly).
