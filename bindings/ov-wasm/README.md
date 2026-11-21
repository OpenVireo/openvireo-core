# `@openvireo/core-wasm` (bindings/ov-wasm)

openvireo-core compiled to WebAssembly with wasm-bindgen. `cargo xtask wasm` builds the package into
`bindings/ov-wasm/pkg/`. It contains two modules:

| Module | Crate | What it has | Size after wasm-opt (raw / gzip -9) |
|---|---|---|---|
| **full** | `bindings/ov-wasm` | the facade handles (`OvClient`, `Account`, `Vault`, …) plus every low-level export below | 2,196,927 B / 882,649 B |
| **lite** | `bindings/ov-wasm-lite` | primitives (SHA-256, HKDF, XChaCha20-Poly1305, Argon2, random), share links, TOTP | 405,134 B / 191,467 B |

With the module embedded as base64 (the default), a lite-only browser bundle built with esbuild is
558 KB raw / 244 KB gzip -9, which is what the public share page pays. The full module costs about
1.15 MB gzip -9 embedded. These figures come from `cargo xtask wasm` and `test/bundle.node.test.js`
on 2026-11-19.

The lite crate has no source of its own. It compiles the full crate's *shared* modules (`convert`,
`error`, `primitives`, `share`, `wipe`) a second time through `#[path]`, so a lite export behaves
exactly like the full export of the same name. CI's wasm32 build and clippy of `ov-wasm` therefore
cover the lite code too.

## Entry points

| Import | Function | Notes |
|---|---|---|
| `@openvireo/core-wasm` | `loadCore(opts?) → Promise<Core>` | Full module, async. `{ wasm }` takes the .wasm as bytes, a `WebAssembly.Module`, a URL or a `Response`. `{ fresh: true }` gives a new instance (after a panic); it needs Node, Bun or unbundled ESM. |
| `@openvireo/core-wasm/sync` | `loadCoreSync(opts?) → Core` | Full module, **no top-level await**. Uses wasm-bindgen's `initSync` on the first call, then caches it. It shares its instance with `loadCore()`. |
| `@openvireo/core-wasm/lite` | `loadLite(opts?) → Promise<LiteCore>` | Lite module, async. |
| `@openvireo/core-wasm/lite-sync` | `loadLiteSync(opts?) → LiteCore` | Lite module, sync. It shares its instance with `loadLite()`. |
| `@openvireo/core-wasm/host` | `fetchTransport`, `indexedDbCache`, `memoryStore`, `memoryCache`, `systemClock`, `consoleLog` | JS Host adapters for `OvClient`. |
| `@openvireo/core-wasm/ov_wasm_bg.wasm`, `/ov_wasm_lite_bg.wasm` | | The raw modules, for `{ wasm: new URL(...) }`. |

- **Bundlers.** Every import in the loaders is a literal (`import("./gen/ov_wasm.js")`), so webpack,
  Turbopack, esbuild and Rollup/Vite include the glue and the embedded module. The SDK's
  `vendor/core-wasm/loader.patch` is no longer needed. The only computed import is `fresh: true`,
  which carries `webpackIgnore`, `turbopackIgnore` and `@vite-ignore` comments.
  `test/bundle.node.test.js` bundles all four entries with esbuild and runs the bundle in Node with
  no `node_modules` next to it.
- **Synchronous APIs.** A library whose public functions are synchronous (the SDK's `sha256`,
  `wrap`, `seal`, keysets, …) calls `loadCoreSync()` or `loadLiteSync()` inside those functions.
  Synchronous compilation works in Node, Bun, Deno and workers. Browsers may refuse to compile a
  large module synchronously on the main thread. There, `await loadCore()` once at startup, and the
  synchronous calls that follow reuse the same instance.
- **Errors** are `OvError` (`code` is the wire string, plus `status`, `retryAfter`, `details` and
  `serverCode`). It is one class shared by all entries. The SDK maps it to `OpenVireoError` with
  the same code.
- **Panics** become `OvError("internal")` and poison that instance only (see `npm/internal.js`).

## Conventions

- **Secrets in and out.** Secret bytes are `Uint8Array`, and the caller wipes what it receives.
  Text secrets (passwords, passcodes, links, tokens, the Secret Key display) are accepted as a
  `string` *or* UTF-8 `Uint8Array` as input, and are always returned as `Uint8Array`. Field values
  in share payloads and TOTP codes are UTF-8 `Uint8Array`, as in the facade records.
- **Wire-shaped records cross as their JSON, with snake_case keys:** `PublicKeysJson`,
  `WrappedKeysetJson`, JWT claims, `Jwks`, and the `newSaSecret` body. The SDK passes these to and
  from the server unchanged. Binary records use camelCase: `Keyset` (flat, as the SDK's), and
  `PublicKeys`, which adds `fingerprint`.
- **Option names follow the SDK:** `DeriveAukOptions { allowWeak, kdfMin }`,
  `SealOptions { ephemeralSecretKey, nonce }`, `Argon2Params { type, password, salt, m, t, p, dkLen }`,
  `VerifyJwtOptions { issuer, audience, now?, skew? }`, `TotpParams.steam`. The facade's
  `encoder: "steam"` is accepted too. `nonce`/`seed`/`ephemeralSecretKey` arguments exist for test
  vectors only.
- **KDBX ids** are kdbxweb's: base64 of the 16 UUID bytes, as the SDK's `getUuidString`. Hex and
  hyphenated UUIDs are accepted as input. The facade's `EntryRecord.id` is hex. Times are Unix
  seconds, except snapshots, which use milliseconds as the SDK does.
- **OPAQUE** client state is opaque bytes between steps, the same as the SDK's
  `OpaqueClientState.sec`.

## Wiping linear memory

wasm-bindgen copies `&[u8]`/`&str` arguments into the module's memory and frees them unzeroed.
`src/wipe.rs` and the exports deal with this in three ways:

1. Exports take secret arguments owned (`Vec<u8>`, or read from a `JsValue`) and wrap them in
   `Zeroizing`. They build outputs as a `Uint8Array` straight from a `Zeroizing` buffer.
2. The module's global allocator on wasm32 (`ZeroOnFree`) zeroes every heap block when it is freed.
   This covers wasm-bindgen's own copies, Argon2's memory blocks and the serde buffers in the domain
   crates. Cost: one `memory.fill` per free, about 10–20 ms per 64 MiB Argon2 run.
3. The loaders call the hidden `__scrubStack` export after every call returns, and when an async
   call settles. It zeroes the 64 KiB of dead shadow stack.

`test/wipe.node.test.js` scans the instance's memory after AEAD, passcode, share-link, AUK, OPAQUE
and KDBX calls, and finds no copy of the secrets.

## SDK export → binding map

How `@openvireo/sdk` (`packages/sdk/src/index.ts` and its subpaths) can implement each public
export:

- **L** means the call is in both modules (lite and full).
- **F** means the call is in the full module only.
- "TS" means the export stays TypeScript, for the reason given.

Calls are synchronous unless the SDK export is async. An async SDK export keeps its signature and
resolves with the core's result.

### `@openvireo/sdk/crypto` (also re-exported at the top level)

| SDK export | Binding |
|---|---|
| `sha256` | `sha256` (L) |
| `hkdf(ikm, salt, info, length)` | `hkdfSha256(ikm, salt, utf8(info), length)` (L) |
| `argon2(params)` | `argon2(params)` (L): same `Argon2Params`, all three types, any `dkLen` |
| `setArgon2Impl`, `nobleArgon2` | TS. The hook stays; the default implementation becomes `argon2`. `nobleArgon2` is a pure-JS fallback that needs `@noble/hashes`, so it can't be a wrapper. Keep it, or drop it from the public API. |
| `SECRET_KEY_BYTES`, `generateSecretKey`, `formatSecretKey`, `parseSecretKey` | constant: TS. The functions are `generateSecretKey`, `fromUtf8(formatSecretKey(raw))` and `parseSecretKey` (F). |
| `KDF_DEFAULTS`, `KDF_MIN`, `newKdfParams`, `checkKdfParams`, `passwordBytes`, `stretchPassword`, `deriveAuk` | constants: TS. The functions are the same names (F). `stretchPassword` and `deriveAuk` are async in the SDK. |
| `wrap`, `unwrap`, `seal`, `sealDerivedKey`, `unseal`, `sealVaultKey`, `unsealVaultKey`, `sealSaMaster`, `unsealSaMaster` | same names (F); `aad` is a string |
| `AAD` | TS (string constants) |
| `keysetFromSecrets`, `generateKeyset`, `verifyPublicKeys`, `publicKeysFromJson`, `trustedPublicKeys`, `publicKeysToJson`, `wrapKeyset`, `unwrapKeyset` | same names (F) |
| `fingerprint(pub)` | `fingerprint(pub.encPk, pub.signPk)` (F) |
| `wipeKeyset` | TS (fills the arrays) |
| `vaultNameKey`, `encryptVaultName`, `decryptVaultName` | same names (F) |
| `SA_TOKEN_PREFIX`, `REFRESH_TOKEN_PREFIX` | TS |
| `buildSaToken`, `parseSaToken`, `saSecretHash`, `saSecretPrefix`, `wrapSaMaster`, `unwrapSaMaster`, `refreshTokenHash`, `newRefreshToken`, `newSaSecret` | same names (F). Token outputs are UTF-8: wrap them in `fromUtf8`. |
| `decodeJwt`, `isJwt` | same names (F) |
| `verifyJwt(token, jwks, opts)` | `verifyJwt` (F). For `opts.refetchJwks`, the SDK catches the unknown-kid `unauthorized`, refetches once and calls again (the core has `verify_jwt_refetching`, but a JS callback inside a synchronous call isn't worth it). |
| `restoreProofMessage`, `restoreProof`, `verifyRestoreProof`, `resealVaultKey` | same names (F) |
| `SHARE_KEY_BYTES`, `SHARE_PAD`, `SHARE_MAX_CT_BYTES` | TS |
| `padShare`, `unpadShare`, `sharePasscodeKey`, `shareContentKey`, `shareAuth`, `shareAuthHash`, `encryptSharePayload`, `decryptSharePayload`, `shareRefKey`, `encryptShareRef`, `decryptShareRef`, `shareKeyFromHash` | same names (L). Payloads map `shared_by` ↔ `sharedBy`, and string values ↔ UTF-8. |
| `shareLink` | `fromUtf8(shareLink(...))` (L) |
| `parseShareLink` | `parseShareLink` (L) |
| `utf8`, `fromUtf8`, `concat`, `toHex`, `fromHex`, `b64u`, `fromB64u`, `ctEqual`, `wipe`, `randomBytes`, `exactBuffer`, `randomUuid` | TS (byte helpers; `randomBytes` could call `randomBytes` (L), from the same CSPRNG) |
| errors (`OpenVireoError`, `isOpenVireoError`, `isUnreachable`) | TS. The SDK's error class; `OvError` maps to it. |
| X25519/Ed25519 (internal to the SDK's crypto) | `x25519PublicKey`, `x25519Shared`, `x25519RandomSecret`, `ed25519PublicKey`, `ed25519Sign`, `ed25519Verify` (F) |

### `@openvireo/sdk/opaque`

| SDK export | Binding |
|---|---|
| `OPAQUE_CONTEXT` | TS |
| `opaqueIds` | `opaqueIds` (F) |
| `loadOpaque` | `loadCore()` (F); the SDK can keep the name |
| `OpaqueClientState` | TS class around the `state` bytes |
| `startRegistration` / `finishRegistration` / `startLogin` / `finishLogin` | `opaqueStartRegistration` / `opaqueFinishRegistration(state.sec, …)` / `opaqueStartLogin` / `opaqueFinishLogin(state.sec, …)` (F). A failed login is `opaque_failed` "wrong password". |
| `opaqueServerForTests.{registrationResponse, storeRecord, credentialResponse, userAuth}` | `opaqueServerRegistrationResponse`, `opaqueServerStoreRecord`, `opaqueServerCredentialResponse`, `opaqueServerUserAuth` (F) |

### `@openvireo/sdk/share` and the top-level share exports

| SDK export | Binding |
|---|---|
| `DEFAULT_SHARE_FIELDS` | `defaultShareFields()` (L) |
| `shareableFields(item)` | `shareableFields(fields)` (L), with `item.fields` mapped to `FieldRecord[]` |
| `itemSharePayload` | `itemSharePayload` (L) |
| `textSharePayload` | `textSharePayload` (L) |
| `getShareInfo(api, id, http)` | TS `fetch` of `GET {api}/public/shares/{id}`, or `OvClient.shareInfo` (F) |
| `openShare(link, passcode, http)` | TS `fetch` + `new ShareOpen(link, info.kdf, passcode)`, then `requestBody()` and `decrypt(ct)` (L); or `OvClient.openShare` (F). The share page then loads only the lite module. |
| `parseTotpUri` | `parseTotpUri` (L) |
| `totpCode(params, now)` | `totpCode(params, now)`, with `code` read through `fromUtf8` (L) |
| `entryTotpUri(fields, label)` | `entryTotpUri(Object.entries(fields).map(([name, value]) => ({ name, value: utf8(value), protected: false })), label)` (L) |
| `base32Decode` | `base32Decode(text)` (L), `ov_share::base32_decode` (public since W3-A3) |

### `@openvireo/sdk/vault` and `@openvireo/sdk/merge`

kdbxweb objects can't cross the boundary, so the binding's KDBX is bytes in and bytes out. `Kdbx`
is one decrypted database: `Kdbx.read(bytes, key)`, operations, then `write()`. `kdbxMerge` is the
whole sync merge on file bytes. Entry editing is the facade's `Vault`
(`Vault.openLocal`/`createLocal`/`saveLocal`).

| SDK export | Binding |
|---|---|
| `openKdbx` / `saveKdbx` | `Kdbx.read` / `kdbx.write()` (F) |
| `passwordHash` | `kdbxPasswordHash` (F) |
| `createVaultKdbx` | `Kdbx.createVault` (F) |
| `rekeyToVaultKey` / `applyVaultKdf` / `kdfSettings` / `copyKdbx` / `dropServerRemotes` / `openWithKeyVersions` / `syncGeneration` / `setSyncGeneration` | `kdbx.rekeyToVaultKey` / `applyVaultKdf` / `kdfSettings` / `clone` / `dropServerRemotes` / `Kdbx.openWithKeyVersions` / `syncGeneration` / `setSyncGeneration` (F) |
| `collectAllDbData` | `kdbx.entries()` + `groups()` (F) |
| `mergeDatabases(local, remote, base)` | `local.mergeWithBase(remote, base)` or `local.merge(remote)`, or `kdbxMerge(localBytes, remoteBytes, baseBytes, key)` (F). The report's `conflicts` is an array of `{ uuid, fields }`; the SDK builds its `Map` from it. |
| `snapshotOf` / `needsCommonBase` / `findConflicts` / `hasPendingDeletions` | `kdbx.snapshot()` (a `Record<id, ms>`, as the SDK's `Snapshot`) / `needsCommonBase` / `findConflicts` / `hasPendingDeletions` (F) |
| `importInto` / `importAsCopies` / `importTargets` | `target.importFrom(source)` / `importAsCopies` / `importTargets` (F) |
| `VAULT_KDF`, `REMOTE_SETTINGS_KEY`, `SYNC_GENERATION_KEY`, `parseReference`, `formatReference`, `REFERENCE_PATTERN`, `DEFAULT_ATTRIBUTES`, `seconds`, `entrySeconds` | TS (constants and string or date helpers) |

These **can't be thin wrappers while the SDK's public types are kdbxweb's** (`Kdbx`, `KdbxEntry`,
`KdbxGroup`, `CredentialsFactory`):

- `initKdbx`, `vaultCredentials`, `passwordCredentials`, `passwordHashCredentials`
- `decryptKdbx`, `createNewKdbx`
- `getUuidString`, `fieldText`, `findGroupInKdbx`, `findEntryInKdbx`
- `addEntryToDb`, `editEntryInDb`, `deleteEntryFromDb`, `createGroupInDb`, `deleteGroupFromDb`,
  `emptyRecycleBinInDb`, `renameGroupInDb`, `setGroupIconInDb`, `exportSelectedGroupsToKdbx`
- `findEntry`, `resolveFieldName`, `readField`, `writeField`
- `parseItemReference`, `entryId`, `itemOf`, `listItems`, `isProtectedByDefault`, `setItemFields`
- `binaryBytes`, `fieldsOf`, `sameValue`, `sameFields`, `fieldName`, `applyField`,
  `resolveFields`, `conflictingFields`, `combineEntries`

Each takes or returns a live kdbxweb object and mutates it in place. The core has all of them
(`ov-kdbx::entries`, `ov-merge`, and the facade `Vault`), but on its own model. Wrapping them would
mean a KDBX decrypt and encrypt (an Argon2 run) per call, or keeping kdbxweb next to the core.
Either the SDK keeps kdbxweb for these, or a major version replaces the kdbxweb types with handles
(`Kdbx`/`Vault`). That is a user decision.

### `@openvireo/sdk/auth`, `@openvireo/sdk/sync`, and the account classes

| SDK export | Binding |
|---|---|
| `Account`, `AccountVault`, `deletionExpired`, `ServiceAccount`, `SelfHostedSync` | the facade: `OvClient` + `Account` / `Vault` / `ServiceAccount` / `SelfHosted` handles, and `deletionExpired` (F). There is one Rust method for each public method (core `docs/api-coverage.md`). |
| `VaultUploadError` | TS (error class) |
| `AuthClient`, `discover`, `fetchJwks`, `staticToken`, `SyncClient`, `BlobHandle`, `HttpError` | TS. These are typed `fetch` clients (JSON in and out, one call per endpoint). `ov-protocol`'s builders and parsers aren't exported. They would add a wasm hop per request and share no logic worth the surface. The logic that matters (token refresh, the sync engine, conflict handling) is the facade's. |
| `TokenManager`, storage classes (`MemoryStorage`, `IndexedDbStorage`, `EncryptedStorage`, `NamespacedStorage`, `browserStorage`, `nonExtractableIdbKey`, `FileStorage`) | TS. Platform storage is a non-goal of the core. The facade takes it as the Host `SecureStore`. |
| `syncKdbx`, `serializeSyncState`, `deserializeSyncState`, `isClockSkewed`, `CLOCK_SKEW_WARNING_MS` | `syncKdbx` drives `SyncClient` and kdbxweb databases, so it isn't thin. Its merge step can call `kdbxMerge` (F); the whole engine is the facade's `Vault.sync()`. The others stay TS (JSON and arithmetic). |
| `SseParser`, `toSyncEvent`, `EventStream`, `subscribeEvents` | TS (a string-chunk parser with no crypto), or the facade's `Account.events()` |
| `isMfaChallenge`, `APPLE_SUBSCRIPTIONS_URL` and the `auth/types` types | TS |

### Facade additions in contract-v1.6

User decision 2026-11-19: the SDK's next major exposes the core's handles instead of kdbxweb, so the
kdbxweb-shaped exports above become `Vault` calls. These were added to the facade for that (and for
iOS); all on the full module (F):

| Need | Binding |
|---|---|
| local files on the app's clock | `client.openLocal(kdbx, credentials, signal?)`, `client.createLocal(name, credentials, signal?)` (`Vault.openLocal` / `createLocal` keep working, on the system clock) |
| last use of an entry | `EntrySummary` / `EntryRecord`: `lastAccessAt?` (only when `usageCount > 0`), `usageCount` |
| colours, custom icon, field order | `EntryInput`: `foregroundColor?` / `backgroundColor?` (`"#RRGGBB"`, `""` clears), `customIcon?` (`null` clears, absent keeps), `fieldOrder?` |
| every entry with values | `vault.entryRecords(includeRecycleBin)` |
| an entry with a chosen id | `vault.addEntryWithId(id, groupId, input)` (`conflict` if taken) |
| attachment protected flag | `AttachmentInfo.protected`; `vault.setAttachmentWith(entryId, name, data, protected?)` |
| import one open vault into another | `vault.importFrom(source, { kind: "merge" } \| { kind: "copies", parentGroupId? })` → `ImportSummary`; `source.importPreview()` → `{ entries, groups }`; `vault.importTargets()` |
| file metadata | `vault.setName(name)` (local), `metaCustomData(key)`, `setMetaCustomData(key, value?)` |
| "save a copy" / KDF | `vault.copyWithoutRemotes(credentials?)`, `vault.setKdf(kdf)` (local), `vault.exportKdbxWith(credentials, groupIds?, kdf)`; `KdbxKdf` is `{ kind: "databaseDefault" }`, `{ kind: "argon2d" \| "argon2id", memory, iterations, parallelism }` or `{ kind: "aesKdf", rounds }` |
| self-hosted version history | `selfHosted.history(databaseId)`, `selfHosted.openVersion(databaseId, revision, credentials)` |
| a service account's server | `sa.serverConfig()`, `sa.issuer()` |
| sync an account vault held as a file (desktop-style) | `account.syncVaultKdbx(vaultId, kdbx, base?, options?)` → `VaultKdbxSyncResult { kdbx, credentials, report }`; `account.vaultKdbxCredentials(vaultId)`; `SyncOptions.acceptServerState?` ("continue anyway" after `server_rolled_back` / `server_lost_database`, also for `vault.sync`) |
| borrow the session token | `account.accessToken(forceRefresh)` (UTF-8 JWT bytes; never log it) |

### Facade additions in contract-v1.7

| Need | Binding |
|---|---|
| open or sync a file with the kept password hash | `KdbxCredentials.passwordHash?` (`core.kdbxPasswordHash(password)`, 32 bytes; not together with `password`) on `Vault.openLocal`, `client.openLocal`, `selfHosted.syncDatabase*`, `exportKdbx*`, imports |
| self-hosted sync without a download when nothing changed | `selfHosted.syncDatabaseWith(databaseId, kdbx, credentials, { localChanged, acceptServerState })`: `localChanged: false` sends a HEAD; unchanged → `report.outcome === "unchanged"` and the same bytes back |
| one wrong-key code | a wrong local-file key is `vault_key_mismatch` (was `kdbx_error`) |
| wrong Secret Key vs wrong password | sign-in `unauthorized` errors have `details.reason` `"keyset_unwrap_failed"` or `"opaque_refused"` |

### Facade additions in contract-v1.8

| Need | Binding |
|---|---|
| share to the keys the user confirmed | `account.shareVaultWithKeys(vaultId, grantee, role, publicKeys)` (`invalid_public_keys` if they changed) |
| a self-hosted database's bytes without its key | `selfHosted.download(databaseId)` → `Uint8Array \| undefined` |
| a service account's vault as a file | `sa.vaultKdbxCredentials(vaultId)`, `sa.syncVaultKdbx(vaultId, kdbx, base?, options?)` |
| the profile's KDF and keyset keys | `Profile.kdf`, `Profile.publicKeys` |
| not a sync server | `selfHosted.health()` rejects with `code: "not_sync_server"` |

Behaviour changes (no new calls): Recycle Bin restore to the previous group (files become KDBX 4.1 when
needed), `vault.sync()` keeps edits made while it runs, `restoreEntry` on a binned entry keeps its
history, `exportPlain` = the ExportDialog's bytes, `rotation_pending`, deletion `details`, accidental
session ends keep unsynced edits, `openVault` is one GET.

Record fields added in v1.6 (`usageCount`, `AttachmentInfo.protected`, `SyncOptions.acceptServerState`) default when a JS record that
lacks them comes back in (`applyAutofillEdits`, `keepAutofillEdit`).

## Building and testing

```sh
cargo xtask wasm                      # builds both modules into pkg/ (needs wasm-bindgen-cli 0.2.130 and binaryen)
cd bindings/ov-wasm && npm ci
npx vitest run                        # 11 files: smoke (Node, jsdom), host, low-level vectors, shared/lite parity, wipe, lite panic, esbuild bundle, contract-v1.6, contract-v1.7, contract-v1.8
npx tsc -p tsconfig.json              # the .d.ts describe the API (test/types.ts)
```

`cargo xtask wasm` honours `$CARGO_TARGET_DIR` (`$CARGO_TARGET_DIR/wasm-pkg`). If the target dir is
shared with another checkout, give each checkout its own xtask binary
(`cargo run -p xtask --target-dir <own dir> -- wasm`). The `cargo xtask` alias runs whichever
`target/debug/xtask` was built last.
