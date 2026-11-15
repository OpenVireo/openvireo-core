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

## Consequences

- Wave 1/2 agents build against these files and raise a CONTRACT-REQUEST for any change.
- The api-coverage table is the checklist for W2-A ("no `todo!()` left") and W3 integrations.
- `rand_core` is not needed by the primitives (randomness goes through `getrandom` directly).
