# ov-ffi-swift

The UniFFI Swift binding of openvireo-core: the Swift module `OpenVireoRustCore` over
`OpenVireoCore.xcframework` (binary target `OpenVireoRustCoreFFI`).

## Build and test

```sh
cargo xtask xcframework                 # every slice: ios, ios-sim (arm64+x86_64), macos (arm64+x86_64)
cargo xtask xcframework --test-server   # also the opaque_server_* steps (for test targets)
cargo xtask xcframework --macos-only    # only the macOS slice, enough for `swift test`
cargo xtask xcframework --smoke         # then `swift test` in SmokeTests/ (implies --test-server)
```

The static libraries and the bindgen dylib are always built with the same features, so the
generated Swift never calls a symbol the libraries lack. Release builds leave `test-server` off.

## What the binding exports

- The facade (`OvClient`, `Account`, `Vault`, `ServiceAccount`, `SelfHosted`, `EventStream`, the
  Host foreign traits) in `handles.rs`, `account_ext.rs`, `host.rs`.
- `primitives.rs`: SHA-256, HKDF, XChaCha20-Poly1305, Argon2id-32, random bytes.
- `crypto.rs`: Secret Key, AUK, envelopes (wrap/unwrap/seal/unseal, vault-key and SA-master
  variants, derived key), keysets, public keys and fingerprints, vault names, SA and refresh tokens,
  JWT decode/verify (with a `JwksRefetcher` foreign callback), restore proofs, X25519/Ed25519,
  Argon2 of every variant, lane count and output length, base64url.
- `opaque.rs`: `opaqueIds`, `opaqueContext`, the client steps (state objects, consumed once), and
  with `test-server` the four server steps.
- `share_crypto.rs`: share-link keys, padding, payload/reference envelopes on JSON bytes, link
  format and parsing.
- `kdbx.rs`: `kdbxPeekHeader` (version + KDF without the key).

Every randomized call takes optional fixed randomness (`nonce`, `ephemeralSecretKey`, OPAQUE
`seed`), so the suites can call it synchronously with fixed inputs. Leave these `nil` in
production. Secrets come back as `Data`, and the caller wipes them.

## iOS internal symbols → binding calls

For W3-II2. The left column is what `OpenVireoCoreTests` / `OpenVireoKitTests` and the app call
today, from `OpenVireoCore/{Crypto,Opaque,KDBX,Merge,Sync,Auth}`.

| iOS symbol | Binding call |
|---|---|
| `SecretKey.generate / format / parse` | `generateSecretKey`, `formatSecretKey(raw:)`, `parseSecretKey(display:)` |
| `KdfParams.new()`, `.check(minimum:)`, `.defaults`, `.minimum` | `newKdfParams()`, `newKdfParamsWith(m:t:pLanes:)`, `checkKdfParams(kdf:kdfMin:)`, `kdfMinimum()` |
| `AUK.passwordBytes / stretch / derive` | `passwordBytes(password:)`, `stretchPassword(password:kdf:allowWeak:kdfMin:)`, `deriveAuk(...)`, `aukFromStretched(...)` |
| `Envelope.AAD.*` | `envelopeAad(kind:id:)` |
| `Envelope.wrap(key:plaintext:aad:nonce:)` / `unwrap` | `envelopeWrap(key:plaintext:aad:nonce:)` / `envelopeUnwrap` |
| `Envelope.seal(to:…ephemeralSecretKey:nonce:)` / `unseal` / `sealDerivedKey` | `envelopeSeal(...)` / `envelopeUnseal` / `envelopeSealDerivedKey` |
| `Envelope.sealVaultKey / unsealVaultKey / sealSAMaster / unsealSAMaster` | `sealVaultKey` / `unsealVaultKey` / `sealSaMaster` / `unsealSaMaster` (optional fixed randomness) |
| `Keyset(encSk:signSeed:)`, `Keyset.generate()` | `keysetFromSecrets`, `generateKeyset` (record `Keyset{encSk, signSeed, publicKeys}`) |
| `keyset.wrapped(with:nonce:)`, `Keyset(unwrapping:with:)` | `wrapKeyset(key:keyset:nonce:)`, `unwrapKeyset(key:wrapped:)` |
| `PublicKeysJSON`, `WrappedKeysetJSON` | records `PublicKeysJson`, `WrappedKeysetJson` (camelCase fields) |
| `PublicKeys(json:)`, `PublicKeys(trusted:)`, `.isValid`, `.json`, `.fingerprint` | `publicKeysFromJson`, `trustedPublicKeys`, `verifyPublicKeys`, `publicKeysToJson`, `PublicKeys.fingerprint` / `publicKeyFingerprint` |
| `VaultName.key / encrypt / decrypt` | `vaultNameKey`, `encryptVaultName(...nonce:)`, `decryptVaultName` |
| `Tokens.buildServiceAccountToken / parseServiceAccountToken` | `buildSaToken`, `parseSaToken` (record `ParsedSaToken`) |
| `Tokens.serviceAccountSecretHash / Prefix`, `wrapSAMaster / unwrapSAMaster`, `refreshTokenHash` | `saSecretHash`, `saSecretPrefix`, `wrapSaMaster(...nonce:)`, `unwrapSaMaster`, `refreshTokenHash`; also `newSaSecret`, `newRefreshToken` |
| `JWT.isJWT / decode / verify(…refetch:)`, `JWKS`, `AccessClaims` | `isJwt`, `decodeJwt`, `verifyJwt(token:jwks:options:refetch:)` (sync; `JwksRefetcher` protocol), records `Jwks`/`Jwk` (`use` → `keyUse`), `AccessClaims` (`aud` always an array, other claims in `extraJson`) |
| `RestoreProof.message / sign / verify / resealVaultKey` | `restoreProofMessage`, `restoreProof`, `verifyRestoreProof`, `resealVaultKey(...ephemeralSecretKey:nonce:)` |
| `Primitives.x25519* / ed25519*` | `x25519PublicKey`, `x25519Shared`, `x25519RandomSecret`, `ed25519PublicKey`, `ed25519Sign`, `ed25519Verify` |
| `Primitives.sha256 / hkdf / aeadEncrypt / aeadDecrypt`, `Data.random` | `sha256`, `hkdfSha256`, `aeadEncrypt`, `aeadDecrypt`, `randomBytes` |
| `Primitives.argon2id`, Cargon2 (KDBX Argon2d, lanes > 1) | `argon2(variant:password:salt:mKib:t:pLanes:outLen:)`, `argon2id32` |
| `Data(base64URL:)`, `.base64URL` | `b64uDecode` / `b64uEncode` (the core also accepts `+` and `/`, which the Swift extension rejected) |
| `Opaque.IDs(email:issuerOrHost:)`, `Opaque.context` | `opaqueIds(email:issuerOrHost:)`, `opaqueContext()` |
| `Opaque.startRegistration / finishRegistration / startLogin / finishLogin` | `opaqueStartRegistration(password:seed:)`, `opaqueFinishRegistration(state:response:ids:seed:)`, `opaqueStartLogin`, `opaqueFinishLogin(state:ke2:ids:context:seed:)`; `ClientState.dispose()` → `state.dispose()` |
| `Opaque.ServerForTests.*` | `opaqueServerRegistrationResponse`, `opaqueServerStoreRecord`, `opaqueServerCredentialResponse`, `opaqueServerUserAuth` (throws `opaque_failed`, where Swift returned nil); needs `--test-server` |
| `ShareLink.pad / padded / unpadded / maxCiphertext` | `sharePadBlock`, `sharePad`, `shareUnpad`, `shareMaxCiphertext` |
| `ShareLink.passcodeKey / contentKey / auth / sha256` | `sharePasscodeKey`, `shareContentKey`, `shareAuth`, `shareAuthHash` |
| `ShareLink.encrypt / decrypt` (JSON bytes) | `shareEncrypt(payloadJson:linkKey:shareId:passcodeKey:nonce:)`, `shareDecrypt` |
| `ShareLink.refKey / encryptRef / decryptRef / link` | `shareRefKey`, `shareEncryptRef`, `shareDecryptRef`, `shareLink`; also `parseShareLink`, `shareKeyFromHash`, `newShareKey` |
| `TOTP(uri:)`, `TOTP(entry:)`, `.code(at:)`, `.remaining(at:)` | `parseTotpUri`, `entryTotpUri(fields:label:)`, `totpCode(params:nowMs:)` (`TotpCode.remaining`) |
| `KDBXFile.peekKDF` (AutoFill memory check) | `kdbxPeekHeader(kdbx:)` |
| `Database.open(_:key:)` / `.create` / `.save(key:)`, `CompositeKey(password:keyFile:)` | `Vault.openLocal(kdbx:credentials:cancel:)`, `Vault.createLocal`, `vault.saveLocal`, `KdbxCredentials(password:keyFile:)` |
| `CompositeKey(vaultKey:)`, `CompositeKey.keyFileComponent` | none needed: account vaults open through `Account.openVault`; a raw 32-byte key file works as `KdbxCredentials(keyFile:)` |
| `Database` editing (`entries`, `groupPaths`, `addEntry`, `updateEntry`, …) | `Vault` methods, see the Kit table below |
| `Export.rows / csv / json` | `vault.exportPlain(format:groupIds:)` |
| `Importer.importInto / importAsCopies` (into an account vault) | `account.importKdbx(kdbx:credentials:mode:)` / `account.importVault(source:mode:)` with `ImportMode.merge` / `.copies` |
| `Importer.*` into a **local** database, `importableEntries`, `importTargets` | `Vault.importFrom`, `importPreview`, `importTargets` (contract-v1.6) |
| `Merger.merge`, `Merger.Conflict`, `snapshot`, `needsCommonBase`, `conflictingFields` | inside the core: `vault.sync` / `selfHosted.syncDatabase` merge, and `vault.conflicts()` returns `SyncConflict`. `MergeFixtureTests` are covered by ov-merge's Rust tests over the same `vectors/merge-fixtures` (they build databases with set timestamps, which the facade can't). No Swift merge export (see follow-ups) |
| `SyncEngine.sync`, `SyncClient.*`, `AuthClient.*`, `TokenManager` | the facade (`Vault.sync`, `Account`, `OvClient.discover`); the suites' `MemoryAccountServer`/`MemorySyncServer` become Host-level HTTP fakes |
| `SyncEngine.isClockSkewed` | `SyncReport` / `AccountEvent` skew warning from the facade |
| `SelfHostedSync.pair / restore / unpair / normalize / sameServer` | `SelfHosted.pair`, `restoreSelfHosted`, `SelfHosted.connect`; unpair = delete the stored token via the SecureStore; normalize/sameServer: not in the core (stay in Swift) |
| `Gzip`, `VariantDictionary`, `XMLConverter`, `Ciphers` | internal to ov-kdbx, with no Swift equivalent needed |
| `Passkey`, `CredentialMatcher`, `CredentialRecord` (`OpenVireoCore/AutoFill`) | stay in Swift, but read `EntryRecord.fields` instead of `Entry` |

## Kit on the core `Vault`

User decision 2026-11-18: OpenVireoKit uses the core's `Vault` directly. `VaultModelTests` runs
the main flow (open a local Argon2d file, groups by path, add/edit with history, attachments,
custom icons, move, Recycle Bin, save/reopen, CSV export).

| What Kit does with `Database` today | Binding call | Status |
|---|---|---|
| open local file (`decrypt`), wrong key → `OpenError.wrongKey` | `Vault.openLocal`; `kdbx_error` "the password or key file is wrong" | ok |
| create local (`addNewLocal`) | `Vault.createLocal(name:credentials:)` | ok |
| save local (`persist` → `save(key:)`) | `vault.saveLocal()` | ok |
| `meta.databaseName` / root name for the vault title | `vault.name()` | ok |
| `entries()` → `model(...)` for every entry (title, user, password, notes, URL, OTP, custom fields, attachments, expiry, icon, colours) | `vault.entries(includeRecycleBin:)` for the list + `vault.entry(entryId:)` per entry for values | ok; `vault.entryRecords(includeRecycleBin:)` gives every entry with values in one call (contract-v1.6) |
| `lastUsed` (`times.usageCount > 0 ? times.lastAccess`) | `EntrySummary.lastAccessAt` / `usageCount` (also on `EntryRecord`) | ok (contract-v1.6) |
| `groupPaths` → `EntryGroup(name: path, symbol: iconID)` | `vault.groups()` (`path`, `iconId`, `isRecycleBin`) | ok (join `path` with `/`) |
| `groupUUID(at:)`, `group(at:create:)` | `vault.groupIdAt(path:)`, `vault.ensureGroup(path:)` | ok |
| `addEntry(_, groupPath:)` with a UUID Kit chose | `vault.addEntryWithId(entryId:groupId:input:)` (or `addEntry`, which returns a new id) | ok (contract-v1.6) |
| `updateEntry` + `apply`: title/user/password/URL/notes, tags (incl. `Favorite`), `iconID`, OTP fields (`otp`, remove `TOTP Seed`/`TOTP Settings`), expiry | `vault.editEntry(entryId:input:)` (`fields`, `removeFields`, `tags`, `iconId`, `expiry`) | ok, history kept by the core |
| `applyExtras`: custom fields in the screen's order | `EntryInput.fieldOrder` | ok (contract-v1.6) |
| `backgroundColor` / `foregroundColor` write | `EntryInput.foregroundColor` / `backgroundColor` (`#RRGGBB`, `""` clears) | ok (contract-v1.6) |
| `customIcon(for: png)` + `entry.customIcon = uuid` | `vault.addCustomIcon(png:)` + `EntryInput.customIcon` (`.some(nil)` clears) | ok (contract-v1.6) |
| custom icon PNG for display (`meta.customIcons`) | `EntrySummary.customIcon` id + `vault.customIcon(iconId:)` | ok |
| attachments: names, data, protected flag; replace the whole list | `EntryRecord.attachments` (name, size), `vault.attachment`, `setAttachment`, `removeAttachment` | ok; `AttachmentInfo.protected`, `setAttachmentWith(entryId:name:data:protected:)` (contract-v1.6) |
| `moveEntry(toGroupPath:)` | `ensureGroup(path:)` + `moveEntry(entryId:groupId:)` | ok |
| `deleteEntry` (Recycle Bin) | `vault.deleteEntry` | ok |
| `recycleBinContents`, `isInRecycleBin`, `restoreFromRecycleBin`, `emptyRecycleBin` | `entries(includeRecycleBin: true)` + `inRecycleBin`, `groups()` + `isInRecycleBin(id:)`, `restoreFromRecycleBin(id:)`, `emptyRecycleBin()` | ok |
| `addGroup(named:under:)`, `renameGroup`, `moveGroup`, `deleteGroup` | `addGroup(parentId:name:)`, `renameGroup`, `moveGroup`, `deleteGroup` | ok |
| version history: `account.history` / `openVersion` → snapshot `Database` | `account.vaultHistory`, `account.openVaultVersion` → read-only `Vault` | ok |
| `difference(from:)`, `restoreEntry(old, groupPath:, from:)` | `vault.versionDifference(version:entryId:)`, `vault.restoreEntry(version:entryId:groupPath:)` | ok |
| entry history | `vault.history(entryId:)` | ok |
| account vault edit → sync (`editAccountVault`), edits during a sync re-applied | `vault` edits + `vault.sync(options:)`; `keepEdits`, `hasPendingEdits`; the core keeps the working copy | ok |
| `Merger.Conflict` after a sync | `vault.conflicts()` → `SyncConflict` | ok |
| AutoFill edits (`AutoFillEdits.apply`) | `vault.applyAutofillEdits(edits:)`, `account.keepAutofillEdit` / `autofillEdits` | ok |
| passkey reports (`apply(reports)`: drop KPEX_PASSKEY_* fields + tag, rename user) | `editEntry` with `removeFields` / `tags` / `fields` | ok |
| AutoFill identities (`CredentialRecord.records(for:)`) | `entries()` + `entry(entryId:)` (password, URL fields, `otp`, KPEX_PASSKEY_*) | ok; `entryRecords(includeRecycleBin:)` for speed (contract-v1.6) |
| share link from an entry (`database.entry(id)`) | `vault.entry` → `account.createShare` / `itemSharePayload` | ok |
| move local DB to the account (`importVault(database, name:, orgID:)`) | `account.importVault(source: vault, mode: .newVault(name:orgId:))` | ok |
| import a `.kdbx` into an account vault (merge / copies) | `account.importKdbx(mode: .merge / .copies)` | ok |
| import into a **local** database; preview counts (`importableEntries`, `importableGroupCount`), copies under a chosen group | `vault.importFrom(source:mode: .merge / .copies(parentGroupId:))`, `source.importPreview()`, `vault.importTargets()` | ok (contract-v1.6) |
| export CSV/JSON of chosen groups | `vault.exportPlain(format:groupIds:)` | ok |
| export `.kdbx` with a new password (`kdf = .databaseDefault`, drop `KPXC_REMOTE_SYNC_SETTINGS`, set name) | whole database: `copyWithoutRemotes(credentials:)` (account vaults get `.databaseDefault`) + `setName` + `saveLocal`; selected groups: `exportKdbxWith(credentials:groupIds:kdf:)` | ok (contract-v1.6) |
| "save a copy" as a new local DB with a new name, remotes dropped | `copyWithoutRemotes(credentials:)` + `setName(name:)` + `setKdf(kdf:)` + `saveLocal` | ok (contract-v1.6) |
| self-hosted: link/unlink (`linkSyncServer`, `syncServerRemote`, `remotes` in `KPXC_REMOTE_SYNC_SETTINGS`) | `metaCustomData(key:)` / `setMetaCustomData(key:value:)` on `KPXC_REMOTE_SYNC_SETTINGS` | ok (contract-v1.6) |
| self-hosted sync of a linked DB | `selfHosted.syncDatabase(databaseId:kdbx:credentials:)` on `saveLocal()` bytes, then `Vault.openLocal` on the result | works; Kit re-opens the merged bytes. `syncDatabaseWith(databaseId:kdbx:credentials:options:)` with `localChanged: false` only sends a HEAD when nothing changed (contract-v1.7) |
| reopen a DB from the kept password hash | `KdbxCredentials(password: nil, keyFile:, passwordHash: sha256(password))` | ok (contract-v1.7); a wrong key is `.vaultKeyMismatch` |
| self-hosted version history (`server.history`, `openVersion`) | `selfHosted.history(databaseId:)`, `selfHosted.openVersion(databaseId:revision:credentials:)` (read-only `Vault`) | ok (contract-v1.6) |
| `database` events while linked | `selfHosted.events()` | ok |
| offline cache (`OfflineAccessTests`) | the core's `BlobCache` Host + `account.openOffline` / `cachedVaults` | ok; the existing Swift cache needs a one-off migration or a resync (W3-II2) |

### CONTRACT-REQUESTs (frozen `crates/ov-core/src/api/**`)

All eight were approved and added as **contract-v1.6** (W3-A3, 2026-11-19; `docs/adr/0001-contract.md`
§ contract-v1.6). The new `EntryInput`, `EntrySummary`, `EntryRecord` and `AttachmentInfo` fields
have UniFFI defaults, so existing Swift initializers still compile. Also new: `OvClient.openLocal` /
`createLocal` (local files on the Host clock) and `ServiceAccount.serverConfig()` / `issuer()`.
`SelfHostedSync.normalize` / `sameServer` were not added. `SmokeTests/ContractV16Tests.swift` covers
the additions.

**contract-v1.7** (W3-A4, 2026-11-20): `KdbxCredentials.passwordHash` (UniFFI default `nil`, so
`KdbxCredentials(password:keyFile:)` still compiles), `SelfHosted.syncDatabaseWith(databaseId:kdbx:credentials:options:)`,
`.vaultKeyMismatch` for a wrong local-file key (was `.kdbxError`), and `OvError.details`
`{"reason":"keyset_unwrap_failed"}` / `{"reason":"opaque_refused"}` on sign-in failures.
`SmokeTests/ContractV17Tests.swift` covers them.

**contract-v1.8** (W3-A5, 2026-11-20): `Account.shareVaultWithKeys(vaultId:grantee:role:keys:cancel:)`,
`SelfHosted.download(databaseId:cancel:)` (`Data?`), `ServiceAccount.vaultKdbxCredentials` /
`syncVaultKdbx`, `Profile.kdf` / `publicKeys`; `serverCode` `rotation_pending` and `not_sync_server`;
deletion `details`. Behaviour changes that let the app drop its workarounds: Recycle Bin restore to the
previous group (KDBX 4.1 when needed), `Vault.sync` keeps edits made while it runs (no replay),
`restoreEntry` on a binned entry keeps its history, `exportPlain` is the web app's format, and the core
keeps unsynced edits itself after `token_reused` / `session_expired`, so `BlobCache.clearUser` should
now remove everything. `SmokeTests/ContractV18Tests.swift` covers them.
