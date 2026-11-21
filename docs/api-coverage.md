# API coverage: TS SDK and iOS → `ov_core::api`

Every public method of the clients the facade replaces, and the Rust method that covers it (rust-core-tasks.md
§2.3, task W0-B). A row's **Rust** column is either a facade item (paths are relative to `ov_core::api`) or
**not ported** with the reason. Nothing is left unmapped.

Sources, as of 2026-11-15:

- TS: `openvireo-sdk/packages/sdk/src/` — `account.ts` (`Account`, `AccountVault`, `deletionExpired`,
  `VaultUploadError`), `service-account.ts`, `self-hosted.ts`, the share and TOTP functions exported from
  `index.ts`, the `vault/` operations the web app runs on `AccountVault.db`, and `auth/client.ts`'s
  `AuthClient`, which `Account` exposes publicly as `account.auth` (the web app calls it for orgs, devices,
  two-step and service accounts).
- Swift: `openvireo-ios/OpenVireoCore/Account/*.swift` — the `Account` actor, its `public extension`s, and the
  public helper types defined in those files.

Conventions in the Rust column: `Account::x` is a method on `Account`, `Vault::x` on `Vault`, and so on.
Property getters map to methods of the same meaning. TS methods that take an options object map to Rust
parameters or an input record. Every network call also takes a `CancelToken` (not repeated below).

Lower-level module exports of the TS SDK (`crypto/*`, `opaque`, `sync/*`, `merge/*`, `vault/kdbx.ts`
helpers) are the domain crates' public APIs (`ov-crypto`, `ov-opaque`, `ov-sync`, `ov-merge`, `ov-kdbx`),
not the facade, and are out of scope here.

## 1. TS `Account` (`account.ts`)

| TS | Rust | Notes |
|---|---|---|
| `static connect(opts)` | `OvClient::connect` | `AccountOptions` → `ClientConfig` (device, offline, server) + the Host |
| `get offline` | `Account::is_offline` | |
| `get signedIn` | `Account::is_signed_in` | |
| `get deletionScheduledFor` | `Account::deletion_scheduled_for` | |
| `get unlocked` | `Account::is_unlocked` | |
| `get userId` | `Account::user_id` | |
| `get email` | `Account::email` | |
| `get principal` | `Account::principal` | |
| `get fingerprint` | `Account::fingerprint` | |
| `get shareBase` | `Account::share_base` | |
| `readonly config` | `Account::server_config` | |
| `readonly auth` (AuthClient) | not ported: the facade has no raw API client; every `AuthClient` call is covered in §7 | |
| `readonly sync` (SyncClient) | not ported: internal to `ov-sync`; vault sync is `Vault::sync`, history `Account::vault_history` | |
| `readonly tokens` (TokenManager) | not ported: token refresh is internal to the core (W2-A, `token-manager.ts`) | |
| `onSignedOut(listener)` | `Account::signed_out` | callback → awaitable (loop on it); FFI has no closures |
| `hasSecretKey(email)` | `Account::has_secret_key` | |
| `register({email, password, kdf, trustDevice})` | `Account::register` | `RegisterInput`; returns `NewAccount` (Secret Key, kit, AUK) |
| `login({email, password, secretKey, totp, trustDevice})` | `Account::login`, `Account::submit_totp` | `totp` string → `LoginInput::totp`; `TotpPrompt` callback → `LoginStep::NeedsTotp` + `submit_totp` |
| `unlock(password, secretKey?)` | `Account::unlock` | offline fallback included |
| `sealUnlocked(key)` | `Account::unlocked_keyset_secret` | the AES-GCM seal under a non-extractable WebCrypto key stays in the TS wrapper (format `s1` unchanged) |
| `resumeUnlocked(sealed, key)` | `Account::resume_unlocked` | the wrapper decrypts with WebCrypto, the core checks the keys against the account |
| `changePassword({current, next, kdf})` | `Account::change_password` | |
| `requestEmailChange(email)` | `Account::request_email_change` | |
| `changeEmail({email, code, password})` | `Account::change_email` | |
| `secretKey()` | `Account::secret_key` | |
| `webSessionUrl(next?)` | `Account::web_session_url` | |
| `recoverInfo(token)` | `Account::recover_info` | |
| `recover({token, password, kdf, trustDevice})` | `Account::recover` | |
| `recoveryStatus()` | `Account::recovery_status` | |
| `restoreFromArchive({oldPassword, oldSecretKey})` | `Account::restore_from_archive` | |
| `reconnect()` | `Account::reconnect` | |
| `lock()` | `Account::lock` | |
| `logout({forgetDevice})` | `Account::sign_out` | |
| `deletionPreview()` | `Account::deletion_preview` | |
| `deleteAccount({password, confirm})` | `Account::delete_account` | |
| `restoreAccount({password})` | `Account::restore_account` | |
| `transferVault(vaultId, to)` | `Account::transfer_vault` | |
| `static sessionState(storage, {issuer, userId})` | `OvClient::session_state` | |
| `static hasPendingEdits(storage, userId)` | `OvClient::has_pending_edits` | |
| `parkSession()` | `Account::park_session` | |
| `resumeSession(userId)` | `Account::resume_session` | |
| `checkParkedSession(userId)` | `Account::check_parked_session` | |
| `logoutParked(userId)` | `Account::sign_out_parked` | |
| `forgetDevice(email)` | `Account::forget_device` | |
| `logoutOnUnload()` | `Account::sign_out_on_unload` | returns the `keepalive` request for the page to fire; the core can't outlive the page |
| `listVaults()` | `Account::vaults` | |
| `openVault(vaultId)` | `Account::open_vault` | |
| `verifiedPublicKeys(principal)` | `Account::verified_public_keys` | |
| `createVault(name, {orgId})` | `Account::create_vault` | |
| `importVault(source, {name, orgId})` | `Account::import_vault`, `Account::import_kdbx` | `ImportMode::NewVault`; bytes + credentials form added for the web/desktop import flows |
| `share(vaultId, {email \| principal}, role)` | `Account::share_vault` | `Grantee::Email` / `Grantee::Principal` |
| `revoke(vaultId, principals)` | `Account::revoke` | |
| `rotate(vaultId, {remove})` | `Account::rotate_vault_key` | |
| `createShare(payload, opts)` | `Account::create_share` | |
| `listShares()` | `Account::list_shares` | |
| `revokeShare(id)` | `Account::revoke_share` | |
| `createServiceAccount(orgId, {...})` | `Account::create_service_account` | `NewServiceAccount` |
| `issueServiceAccountSecret(saId, {name, expiresAt})` | `Account::issue_service_account_secret` | |
| `confirmMember(orgId, member, vaults)` | `Account::confirm_member` | |
| `setMemberRole(orgId, member, role)` | `Account::set_member_role` | |
| `removeMember(orgId, userId)` | `Account::remove_member` | `RotationReport` |
| `subscribe({onVaultChanged, onVaultsChanged, onError})` | `Account::subscribe` → `EventStream::next` | handlers → `AccountEvent` variants; `onError` → `Err` from `next` |
| `loadState(vaultId)` *(@internal)* | not ported: internal; sync state lives in `BlobCache` (`CachedVault::state`) | |
| `saveState(vaultId, state)` *(@internal)* | not ported: internal, as `loadState` | |
| `get keepsOfflineData` *(@internal)* | not ported: internal; `ClientConfig::offline` | |
| `loadPending(vaultId)` *(@internal)* | not ported: internal; `CachedVault::pending` | |
| `savePending(vaultId, data)` *(@internal)* | not ported: internal; `CachedVault::pending` | |
| `deletePending(vaultId)` *(@internal)* | not ported: internal; `CachedVault::pending` | |
| `deletionExpired(scheduledFor, now)` (free fn) | `deletion_expired` | |
| `class VaultUploadError` | `ImportOutcome::uploaded` / `ImportOutcome::upload_error` | an error carrying a live vault can't cross FFI; the outcome record carries both |

## 2. TS `AccountVault` (`account.ts`)

| TS | Rust | Notes |
|---|---|---|
| `db` (kdbxweb `Kdbx`) | `Vault` (its reading and editing methods, §6) | no KDBX object crosses FFI |
| `offline` | `Vault::is_offline` | |
| `info` | `Vault::info` | |
| `get id` | `Vault::id` | |
| `get name` | `Vault::name` | |
| `get etag` | `Vault::etag` | |
| `sync({rekeyTo, localChanged})` | `Vault::sync` | `SyncOptions::local_changed`; `rekeyTo` is internal to rotation (`Account::rotate_vault_key`) |
| `openLocalCopy(cause)` *(@internal)* | not ported: internal; the offline fallback inside `Account::open_vault` | |
| `read(ref)` | `Vault::read_field` | |
| `write(ref, value, {create})` | `Vault::write_field` | |

## 3. TS `ServiceAccount` (`service-account.ts`)

| TS | Rust | Notes |
|---|---|---|
| `static fromToken(token, http)` | `ServiceAccount::from_token` | |
| `readonly saId` | `ServiceAccount::sa_id` | |
| `readonly config` | not ported: the discovery document is internal to the SA handle; the issuer is in the token | |
| `readonly auth` | not ported: raw API client, as `Account.auth` | |
| `readonly sync` | not ported: raw sync client, as `Account.sync` | |
| `get principal` | `ServiceAccount::principal` | |
| `listVaults(refresh)` | `ServiceAccount::vaults` | |
| `vault(idOrName)` | `ServiceAccount::vault` | |
| `openVault(idOrName, refresh)` | `ServiceAccount::open_vault` | returns a `Vault` |
| `pull(idOrName)` | `ServiceAccount::pull` | |
| `edit(idOrName, fn)` | `ServiceAccount::open_vault` + `Vault` edits + `Vault::sync` | closures can't cross FFI |
| `read(ref)` | `ServiceAccount::read` | |
| `inject(template)` | `ServiceAccount::inject` | |
| `write(ref, value, {create})` | `ServiceAccount::write` | |
| `close()` | `ServiceAccount::close` | |

## 4. TS `SelfHostedSync` (`self-hosted.ts`)

| TS | Rust | Notes |
|---|---|---|
| `constructor(serverUrl, deviceToken, opts)` | `SelfHosted::connect` | |
| `static pair(serverUrl, code, deviceName, opts)` | `SelfHosted::pair` | |
| `static restore(serverUrl, opts)` | `SelfHosted::restore` | |
| `readonly client` | not ported: raw sync client | |
| `readonly serverUrl` | `SelfHosted::server_url` | |
| `readonly deviceToken` | not ported: a secret kept in the `SecureStore`; never handed back | |
| `health()` | `SelfHosted::health` | |
| `listDatabases()` | `SelfHosted::list_databases` | |
| `createPairingCode()` | `SelfHosted::create_pairing_code` | |
| `syncDatabase(databaseId, p)` | `SelfHosted::sync_database` | bytes + credentials in, merged bytes + report out; with options (`localChanged`, `acceptServerState`): `SelfHosted::sync_database_with` (contract-v1.7) |
| `events(opts)` | `SelfHosted::events` | |

## 5. TS share and TOTP functions (`share/index.ts`, `share/totp.ts`)

| TS | Rust | Notes |
|---|---|---|
| `getShareInfo(api, id)` | `OvClient::share_info` | needs the Host for HTTP, so it is a client method |
| `openShare(api, link, {passcode, info})` | `OvClient::open_share` | as `getShareInfo` |
| `DEFAULT_SHARE_FIELDS` | `default_share_fields` | |
| `shareableFields(item)` | `shareable_fields` | |
| `itemSharePayload(item, names, sharedBy)` | `item_share_payload` | |
| `textSharePayload(text, title, sharedBy)` | `text_share_payload` | |
| `parseTotpUri(uri)` | `parse_totp_uri` | |
| `totpCode(params, now)` | `totp_code` | |
| `entryTotpUri(fields, label)` | `entry_totp_uri` | |
| `base32Decode(text)` | not ported: helper inside `ov-share`'s TOTP code | |
| `crypto/share.ts` exports (`padShare`, `encryptSharePayload`, `parseShareLink`, …) | not ported: `ov-share` domain API, used by the facade | |

## 6. TS vault operations on `AccountVault.db` (`vault/entries.ts`, `items.ts`, `reference.ts`)

| TS | Rust | Notes |
|---|---|---|
| `collectAllDbData(db)` | `Vault::entries`, `Vault::groups` | |
| `listItems(db)` | `Vault::entries` | `include_recycle_bin = false` |
| `itemOf(entry, {reveal})` | `Vault::entry` | values always included; the caller decides what to show |
| `findEntryInKdbx(group, id)` | `Vault::entry` | |
| `findGroupInKdbx(group, id)` | `Vault::groups` | |
| `findEntry(db, ref)` | `Vault::find` | |
| `readField(db, ref)` | `Vault::read_field` | |
| `writeField(db, ref, value, opts)` | `Vault::set_fields` | local edit; `Vault::write_field` also syncs |
| `setItemFields(db, ref, fields, opts)` | `Vault::set_fields` | `CreateMode` |
| `decryptKdbx(buffer, password)` | `Vault::open_local` | |
| `createNewKdbx(name, password)` | `Vault::create_local` | |
| `addEntryToDb(db, groupUuid, data)` | `Vault::add_entry` | `EntryInput` |
| `editEntryInDb(db, uuid, data)` | `Vault::edit_entry` | |
| `deleteEntryFromDb(db, uuid)` | `Vault::delete_entry` | |
| `createGroupInDb(db, parent, name)` | `Vault::add_group` | |
| `deleteGroupFromDb(db, uuid)` | `Vault::delete_group` | |
| `emptyRecycleBinInDb(db)` | `Vault::empty_recycle_bin` | |
| `renameGroupInDb(db, uuid, name)` | `Vault::rename_group` | |
| `setGroupIconInDb(db, uuid, icon)` | `Vault::set_group_icon` | |
| `exportSelectedGroupsToKdbx(db, groups, password)` | `Vault::export_kdbx` | |
| `getUuidString`, `fieldText`, `entryId`, `isProtectedByDefault`, `resolveFieldName` | not ported: helpers of the kdbxweb representation; ids are hex strings in every record | |
| `parseReference`, `formatReference`, `parseItemReference`, `REFERENCE_PATTERN` | not ported: `ov-vault` domain API (`ov://` references, SPEC §14), used by the facade | |

## 7. TS `AuthClient` (`auth/client.ts`, public as `account.auth`)

| TS | Rust | Notes |
|---|---|---|
| `withTokens(tokens)` | not ported: internal plumbing | |
| `registerStart` / `registerFinish` | `Account::register` | internal steps |
| `loginStart` / `loginFinish` / `loginMfa` | `Account::login`, `Account::submit_totp` | internal steps |
| `refresh(refreshToken)` | not ported: internal token refresh; `Account::verify_session` forces one | |
| `logout()` | `Account::sign_out` | |
| `serviceAccountExchange` | `ServiceAccount::from_token` | internal step |
| `recoverInfo` / `recoverStart` / `recoverFinish` | `Account::recover_info`, `Account::recover` | |
| `me()` | `Account::me` | |
| `passwordStart` / `passwordFinish` | `Account::change_password` | internal steps |
| `deletionPreview()` | `Account::deletion_preview` | |
| `scheduleDeletion(confirm)` | `Account::delete_account` | |
| `cancelDeletion()` | `Account::restore_account` | |
| `emailRequest` / `emailStart` / `emailFinish` | `Account::request_email_change`, `Account::change_email` | |
| `recoveryStatus()` | `Account::recovery_status` | |
| `restoreStart` / `restoreVerify` / `restoreFinish` | `Account::restore_from_archive` | internal steps |
| `createWebSession()` | `Account::web_session_url` | |
| `totpStart()` | `Account::start_two_step` | |
| `totpConfirm(totp)` | `Account::confirm_two_step` | |
| `totpDisable(totp)` | `Account::disable_two_step` | |
| `lookupUser(email)` | `Account::look_up` | |
| `publicKey(principal)` | `Account::verified_public_keys`, `Account::recipient` | always verified |
| `listDevices()` | `Account::devices` | |
| `revokeDevice(id)` | `Account::revoke_device` | |
| `createOrg(name)` | `Account::create_org` | |
| `getOrg(org)` | `Account::org` | |
| `renameOrg(org, name)` | `Account::rename_org` | |
| `setOrgShareLinks(org, policy)` | `Account::set_org_share_links` | |
| `deleteOrg(org)` | `Account::delete_org` | |
| `listMembers(org)` | `Account::org_members` | |
| `setMemberRole(org, user, body)` | `Account::set_member_role` | seals SA master keys as needed |
| `removeMember(org, user)` | `Account::remove_member` | |
| `confirmMember(org, user, body)` | `Account::confirm_member` | |
| `listInvitations(org)` | `Account::invitations` | |
| `invite(org, body)` | `Account::invite` | |
| `cancelInvitation(org, id)` | `Account::cancel_invitation` | |
| `acceptInvitation(token)` | `Account::accept_invitation` | |
| `listVaults()` | `Account::vaults` | |
| `createVault(body)` | `Account::create_vault` | |
| `getVault(vault)` | `Account::open_vault`, `Account::vaults` | internal (single-vault refresh) |
| `renameVault(vault, encryptedName)` | `Account::rename_vault` | encrypts the name |
| `deleteVault(vault)` | `Account::delete_vault` | |
| `transferVault(vault, principal)` | `Account::transfer_vault` | |
| `listAccess(vault)` | `Account::members` | |
| `grantAccess(vault, grants)` | `Account::share_vault`, `Account::change_role` | seals the key |
| `startRotation` / `activateKey` | `Account::rotate_vault_key` | internal steps |
| `listServiceAccounts(org)` | `Account::service_accounts` | |
| `createServiceAccount(org, body)` | `Account::create_service_account` | |
| `getServiceAccount(sa)` | `Account::service_accounts` | internal in `issue_service_account_secret` |
| `updateServiceAccount(sa, body)` | `Account::update_service_account` | |
| `deleteServiceAccount(sa)` | `Account::delete_service_account` | |
| `listSaSecrets(sa)` | `Account::service_account_secrets` | |
| `issueSaSecret(sa, body)` | `Account::issue_service_account_secret` | |
| `updateSaSecret(sa, id, body)` | `Account::set_secret_expiry` | |
| `revokeSaSecret(sa, id)` | `Account::revoke_secret` | |
| `createShare` / `uploadShare` | `Account::create_share` | internal steps |
| `listShares()` | `Account::list_shares` | |
| `revokeShare(id)` | `Account::revoke_share` | |
| `audit(org, {before, limit})` | `Account::audit_log` | |
| `discover(issuer)` (free fn) | `OvClient::discover` | |
| `fetchJwks(uri)` (free fn) | not ported: internal to JWT verification (`ov-crypto` / `ov-protocol`) | |
| `staticToken(token)` (free fn) | not ported: internal plumbing | |

## 8. Swift `Account` (`Account.swift`)

| Swift | Rust | Notes |
|---|---|---|
| `static connect(issuer:store:folder:deviceName:http:current:)` | `OvClient::new` + `OvClient::connect` | store/folder/http → `Host`; `current` (AutoFill's server file) stays in the app |
| `config` | `Account::server_config` | |
| `device` | `OvClient::config` (`ClientConfig::device`) | |
| `offline` | `Account::is_offline` | |
| `deletionScheduledFor` | `Account::deletion_scheduled_for` | |
| `clockOffset` | `Account::clock_offset_ms` | |
| `static wrongPasswordOffline` | not ported: UI text, stays in the app (localised there) | |
| `session` | `Account::stored_session` | |
| `storedSession()` | `Account::stored_session` | |
| `isUnlocked` | `Account::is_unlocked` | |
| `verifySession()` | `Account::verify_session` | |
| `onSignedOut(_:)` | `Account::signed_out` | |
| `principal` | `Account::principal` | |
| `hasSecretKey(email:)` | `Account::has_secret_key` | |
| `storedSecretKey(email:)` | `Account::stored_secret_key` | |
| `fingerprint` | `Account::fingerprint` | |
| `register(email:password:)` | `Account::register` | |
| `login(email:password:secretKey:totp:)` | `Account::login`, `Account::submit_totp` | returns the AUK in `Unlocked::auk` |
| `unlock(password:)` | `Account::unlock` | |
| `unlock(auk:)` | `Account::unlock_with_auk` | |
| `lock()` | `Account::lock` | |
| `signOut()` | `Account::sign_out` | `forget_device = false` |
| `listVaults()` | `Account::vaults` | |
| `cachedVaults()` | `Account::cached_vaults` | |
| `refreshProfile()` | `Account::me` | `me` always refreshes the offline copy |
| `hasAnyPendingEdits()` | `Account::has_any_pending_edits` | |
| `keepEdits(_:)` | `Vault::keep_edits` | |
| `hasPendingEdits(_:)` | `Account::has_pending_edits` | |
| `openVault(_:)` | `Account::open_vault` | |
| `sync(_:localChanged:rekeyTo:)` | `Vault::sync` | `rekeyTo` is internal to rotation |
| `createVault(name:database:orgID:)` | `Account::create_vault`, `Account::import_vault` | with `database` it is an import |
| `renameVault(_:to:)` | `Account::rename_vault` | |
| `deleteVault(_:)` | `Account::delete_vault` | |
| `watch(_:)` | `Account::subscribe` | `Update.vaultChanged` / `.vaultsChanged` → `AccountEvent` |
| `cachedKdf()` | `Account::cached_kdf` | |
| `OpenedVault.info` / `.state` / `.offline` / `.conflicts` | `Vault::info`, `Vault::etag`, `Vault::is_offline`, `Vault::conflicts` | the sync state itself is internal |
| `OpenedVault.database` | `Vault` (its reading and editing methods) | |

## 9. Swift `Account` extensions

| Swift | Rust | Notes |
|---|---|---|
| **Account+AutoFill** | | |
| `openOffline(_:)` | `Account::open_offline` | |
| `openCopy(_:)` | `Account::open_copy` | |
| `keepAutoFillEdit(_:groupPath:vaultID:)` | `Account::keep_autofill_edit` | |
| `autoFillEdits(_:)` | `Account::autofill_edits` | |
| `clearAutoFillEdits(_:)` | `Account::clear_autofill_edits` | |
| `AutoFillEdits.apply(_:to:)` | `Vault::apply_autofill_edits` | |
| **Account+Deletion** | | |
| `static parseDate(_:)` | not ported: Swift date parsing; records carry RFC 3339 strings | |
| `static deletionExpired(_:now:)` | `deletion_expired` | |
| `deletionPreview()` | `Account::deletion_preview` | |
| `deleteAccount(password:confirm:)` | `Account::delete_account` | |
| `restoreAccount(password:)` | `Account::restore_account` | |
| `transferVault(_:to:)` | `Account::transfer_vault` | |
| `endSession(userID:email:reason:)` | `Account::signed_out` / `AccountEvent::SessionEnded` | internal step the core runs itself on `deletion_scheduled` / `account_deleted` |
| **Account+History** | | |
| `history(of:)` | `Account::vault_history` | |
| `openVersion(of:revision:)` | `Account::open_vault_version` | read-only `Vault` |
| `VaultHistory.versions(_:)` | `Account::vault_history` | |
| `VaultHistory.open(_:revision:keys:)` | `Account::open_vault_version` | |
| `Database.difference(from:)` | `Vault::version_difference` | |
| `Database.restoreEntry(_:groupPath:from:)` | `Vault::restore_entry` | |
| **Account+Import** | | |
| `importVault(_:name:orgID:)` | `Account::import_vault` | `ImportMode::NewVault` |
| `static vaultName(_:for:)` | `Account::import_vault` | internal (name defaulting) |
| `static vaultCopy(of:name:now:)` | `Account::import_vault` | internal (copy, rename root, drop remotes) |
| **Account+Orgs** | | |
| `createOrg(name:)` | `Account::create_org` | |
| `org(_:)` | `Account::org` | |
| `renameOrg(_:name:)` | `Account::rename_org` | |
| `deleteOrg(_:)` | `Account::delete_org` | |
| `members(ofOrg:)` | `Account::org_members` | |
| `invitations(ofOrg:)` | `Account::invitations` | |
| `invite(_:to:role:)` | `Account::invite` | |
| `cancelInvitation(_:in:)` | `Account::cancel_invitation` | |
| `acceptInvitation(token:)` | `Account::accept_invitation` | |
| `confirmMember(_:in:vaults:)` | `Account::confirm_member` | |
| `setRole(_:of:in:)` | `Account::set_member_role` | |
| `removeMember(_:from:)` | `Account::remove_member` | |
| `rotateFlagged(_:)` | `Account::rotate_flagged` | |
| `managedOrgVaults(_:)` | `Account::managed_org_vaults` | |
| `recipient(_:display:)` | `Account::recipient` | |
| `serviceAccounts(ofOrg:)` | `Account::service_accounts` | |
| `createServiceAccount(in:name:vaults:expiresAt:…)` | `Account::create_service_account` | |
| `issueSecret(for:name:expiresAt:)` | `Account::issue_service_account_secret` | |
| `secrets(of:)` | `Account::service_account_secrets` | |
| `setSecretExpiry(_:of:to:)` | `Account::set_secret_expiry` | |
| `revokeSecret(_:of:)` | `Account::revoke_secret` | |
| `updateServiceAccount(_:name:expiresAt:disabled:)` | `Account::update_service_account` | `ServiceAccountUpdate` (`ExpiryChange` for the `Date??`) |
| `deleteServiceAccount(_:)` | `Account::delete_service_account` | |
| `auditLog(of:before:)` | `Account::audit_log` | |
| `static rfc3339(_:)` | not ported: Swift date formatting; records carry RFC 3339 strings | |
| **Account+Plan** | | |
| `Plan.Limit.*` | `plan_limits::*` | |
| `Plan.hasBilling` | `Plan::has_billing` | |
| `Plan.limit(_:)` | `Plan::limit` | |
| `Plan.has(_:)` | `Plan::has` | |
| `plan()` | `Account::plan` | |
| `vaultQuota(_:)` | `Account::vault_quota` | |
| `upgradeURL(for:)` | `Account::upgrade_url` | |
| `static upgradeURL(upgradeURL:issuer:)` | `Account::upgrade_url` | the static form is its implementation |
| `appleEligibility(org:)` | `Account::apple_eligibility` | |
| `reportAppleTransaction(_:)` | `Account::report_apple_transaction` | |
| **Account+Settings** | | |
| `changePassword(current:new:)` | `Account::change_password` | returns the new AUK |
| `requestEmailChange(to:)` | `Account::request_email_change` | |
| `changeEmail(to:code:password:)` | `Account::change_email` | |
| `me()` | `Account::me` | |
| `startTwoStep()` | `Account::start_two_step` | |
| `confirmTwoStep(code:)` | `Account::confirm_two_step` | |
| `disableTwoStep(code:)` | `Account::disable_two_step` | |
| `devices()` | `Account::devices` | |
| `revokeDevice(_:)` | `Account::revoke_device` | |
| `secretKeyForKit()` | `Account::secret_key` | |
| `webSessionURL(next:)` | `Account::web_session_url` | |
| `recoverInfo(token:)` | `Account::recover_info` | |
| `recover(token:password:)` | `Account::recover` | `NewAccount` carries the AUK |
| `recoveryStatus()` | `Account::recovery_status` | |
| `restoreFromArchive(oldPassword:oldSecretKey:)` | `Account::restore_from_archive` | |
| **Account+ShareLinks** | | |
| `SharePayload.entry(_:fields:)` | `item_share_payload` | |
| `SharePayload.text(_:title:)` | `text_share_payload` | |
| `ShareLinks.defaultFields` | `default_share_fields` | |
| `ShareLinks.shareableFields(_:)` | `shareable_fields` | |
| `ShareLinks.describe(_:now:)` | not ported: UI text ("Opened 2 of 5 · ends in 3 days"), localised in each app | |
| `shareBase` | `Account::share_base` | |
| `shareBlockedReason(orgID:)` | `Account::share_blocked_reason` | |
| `createShare(_:options:)` | `Account::create_share` | |
| `listShares()` | `Account::list_shares` | |
| `revokeShare(_:)` | `Account::revoke_share` | |
| **Account+Sharing** | | |
| `members(of:)` | `Account::members` | |
| `verifiedPublicKeys(_:)` | `Account::verified_public_keys` | |
| `lookUp(email:)` | `Account::look_up` | |
| `share(_:with:role:)` | `Account::share_vault` | `Grantee::Principal(recipient.principal)` |
| `changeRole(_:of:to:)` | `Account::change_role` | |
| `remove(_:from:)` | `Account::revoke` | |
| `rotateKey(_:removing:)` | `Account::rotate_vault_key` | |
| **Account+Switching** | | |
| `RememberedAccounts.init(store:)` | `OvClient::new` | the list lives in the Host's `SecureStore` |
| `RememberedAccounts.all()` | `OvClient::remembered_accounts` | |
| `RememberedAccounts.remember(email:issuer:userID:)` | `OvClient::remember_account` | |
| `RememberedAccounts.setDeletion(issuer:userID:at:)` | `OvClient::set_remembered_deletion` | |
| `RememberedAccounts.markChecked(_:at:)` | `OvClient::mark_remembered_checked` | time from the Host clock |
| `RememberedAccounts.forget(_:)` | `OvClient::forget_remembered` | |
| `static sessionState(of:store:)` | `OvClient::session_state` | |
| `static hasUnsyncedEdits(userID:folder:)` | `OvClient::has_pending_edits` | |
| `setAsideSession()` | `Account::park_session` | |
| `resumeSession(userID:)` | `Account::resume_session` | |
| `checkSetAsideSession(userID:)` | `Account::check_parked_session` | |
| `signOutSetAside(userID:)` | `Account::sign_out_parked` | |
| `forgetDevice(email:)` | `Account::forget_device` | |
| **SecureStore.swift** | | |
| `protocol SecureStore` (`get` / `set` / `delete`) | `crate::host::SecureStore` | a Host trait; values are bytes, not strings |
| `MemoryStore` | not ported: a test/in-memory Host implementation stays on each platform (`ov-testkit` has the Rust one) | |
| `KeychainStore` | not ported: the iOS Host's `SecureStore` implementation (W3-II) | |

## 10. contract-v1.6 additions (2026-11-19)

The iOS OpenVireoKit calls that moved onto the core `Vault` (W3-BS2's CONTRACT-REQUESTs 1-8, see
`bindings/ov-ffi/README.md`), the `ov` CLI's issuer lookup and local vaults on the Host clock.
Details in `docs/adr/0001-contract.md` § contract-v1.6.

| Client | Rust | Notes |
|---|---|---|
| Swift Kit `lastUsed` (`times.usageCount > 0 ? times.lastAccess`) | `EntrySummary::last_access_at`, `EntryRecord::last_access_at`, `usage_count` | request 1 |
| Swift Kit `applyExtras`: custom fields in the editor's order | `EntryInput::field_order` | request 2 |
| Swift Kit `backgroundColor` / `foregroundColor` write | `EntryInput::{foreground_color, background_color}` | request 2 |
| Swift Kit `entry.customIcon = uuid` (and clear) | `EntryInput::custom_icon` | request 2; ids from `Vault::add_custom_icon` |
| Swift Kit `addEntry(_, groupPath:)` with the model's UUID | `Vault::add_entry_with_id` | request 3 |
| Swift Kit attachment protected flag (read, write) | `AttachmentInfo::protected`, `Vault::set_attachment_with` | request 4 |
| Swift Kit `entries()` → `model(...)` for every entry; AutoFill `CredentialRecord.records(for:)` | `Vault::entry_records` | request 5 |
| Swift `Importer.merge` / `importCopies(into:under:)` into a local database | `Vault::import_from` (`LocalImportMode`) | request 6; `ImportSummary` |
| Swift `Importer.importableEntries(_:).count`, `importableGroupCount(_:)` | `Vault::import_preview` | request 6; `ImportPreview` |
| Swift `Importer.importTargets(_:)` | `Vault::import_targets` | request 6; `ImportTarget` |
| Swift Kit `meta.databaseName = …` (local) | `Vault::set_name` | request 7 |
| Swift Kit `meta[customData:]` get / set (`KPXC_REMOTE_SYNC_SETTINGS`, links) | `Vault::meta_custom_data`, `Vault::set_meta_custom_data` | request 7 |
| Swift Kit `exportCopy` / "save a copy" (remotes dropped) | `Vault::copy_without_remotes` + `Vault::set_name` + `Vault::save_local` | request 7 |
| Swift Kit `copy.kdf = .databaseDefault` | `Vault::set_kdf(KdbxKdf::DatabaseDefault)`; `Vault::export_kdbx_with` | request 7; `KdbxKdf` |
| Swift Kit `server.history`, `openVersion` (self-hosted) | `SelfHosted::history`, `SelfHosted::open_version` | request 8 |
| TS `ServiceAccount.config` (`sa.config.issuer`, used by `ov`) | `ServiceAccount::server_config`, `ServiceAccount::issuer` | W3-L3; replaces `bins/ov`'s own token decoding |
| local `.kdbx` opened or created with the app's clock | `OvClient::open_local`, `OvClient::create_local` | W2-A; `Vault::open_local` / `create_local` unchanged |
| desktop `SyncEngine` account-vault sync of the open `Database` (serialized) | `Account::sync_vault_kdbx`, `Account::vault_kdbx_credentials` | W3-ID2; `VaultKdbxSyncResult` |
| desktop "continue anyway" after a server rollback / lost database | `SyncOptions::accept_server_state` | W3-ID2 |
| desktop code still on its own HTTP (`AuthClient`) borrowing the session | `Account::access_token` | W3-ID2 |

## 12. contract-v1.8 additions (2026-11-20)

From the iOS migration (W3-II2b, W3-II3) and the desktop (W3-ID2c). Details and the behaviour changes in
`docs/adr/0001-contract.md` § contract-v1.8.

| Client | Rust | Notes |
|---|---|---|
| Swift `share(_:with:role:)` with the fingerprint the user compared; desktop VaultSharing | `Account::share_vault_with_keys` | `invalid_public_keys` when the keys changed since they were shown |
| Swift `SelfHostedSync.download` (first copy of a linked DB) | `SelfHosted::download` | `None` for 404 |
| Swift `SelfHostedSync.pair` health check | `SelfHosted::health` | `server_code` `not_sync_server` |
| desktop service-account session (C++ `AuthClient` exchange + `GET /vaults`) | `ServiceAccount::vault_kdbx_credentials`, `ServiceAccount::sync_vault_kdbx` | as the Account ones |
| desktop offline profile; keyset replaced by recovery | `Profile.kdf`, `Profile.public_keys` | from `Account::me` |
| Swift/desktop rotation finishing a pending one | `Account::rotate_vault_key` | `server_code` `rotation_pending` |
| Swift deletion screens | `OvError::details` | `deletion_blocked` → `orgs`; `account_pending_deletion` → `scheduledFor` |
| Swift `Export` / web ExportDialog | `Vault::export_plain` | the web app's bytes |
| Swift `restoreEntry` keeping history | `Vault::restore_entry` | binned entry leaves the bin |
| Swift edits replayed after a sync (`editsDuringSync`) | `Vault::sync` | merged by the core |
| Swift `FileBlobCache.clearUser` keeping unsynced edits | the core on `token_reused` / `session_expired` | `clear_user` now always wipes all |

## 11. contract-v1.7 additions (2026-11-20)

From the SDK 1.0 migration (W3-IW2) and the desktop (W3-ID2). Details in
`docs/adr/0001-contract.md` § contract-v1.7.

| Client | Rust | Notes |
|---|---|---|
| TS `passwordHashCredentials(hash)` / kdbxweb `getHash` kept across reloads (web), with `openLocalVault` and self-hosted sync | `KdbxCredentials::password_hash` | the password's SHA-256; with or without `key_file`; `invalid_request` with `password` too |
| TS 0.11 `syncDatabase({ localChanged: false })` / `acceptServerState` | `SelfHosted::sync_database_with(.., SyncOptions)` | HEAD first; unchanged returns the input bytes without a KDF run |
| TS 0.11 `openKdbx` wrong key → `vault_key_mismatch` | `Vault::open_local`, `OvClient::open_local`, `Account::import_kdbx` | was `kdbx_error` |
| desktop: wrong Secret Key vs wrong password after sign-in | `OvError::details` `{"reason":"keyset_unwrap_failed"}` / `{"reason":"opaque_refused"}` | both `unauthorized` / 401; the core logs out the session a failed unwrap leaves |
