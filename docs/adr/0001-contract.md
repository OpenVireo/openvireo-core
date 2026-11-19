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
`AttachmentInfo` or `EntryInput` with a struct literal that lists every field: such code needs the new
fields (`EntryInput` has `Default`, so `..Default::default()` keeps working).

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

`KdbxKdf` is `DatabaseDefault` (KeePassXC's default for new databases: Argon2d, 64 MiB, 10 iterations,
2 lanes, as iOS `KDF.databaseDefault`), `Argon2d` / `Argon2id { memory (bytes), iterations, parallelism }`
or `AesKdf { rounds }`; every choice gets a fresh salt, and Argon2 upgrades a KDBX 3.1 database to 4.

Not added: `SelfHostedSync.normalize` / `sameServer` (BS2's optional extra in request 7); a "mark entry
used" edit (no client increments `UsageCount` today; iOS only reads it).

## Consequences

- Wave 1/2 agents build against these files and raise a CONTRACT-REQUEST for any change.
- The api-coverage table is the checklist for W2-A ("no `todo!()` left") and W3 integrations.
- `rand_core` is not needed by the primitives (randomness goes through `getrandom` directly).
