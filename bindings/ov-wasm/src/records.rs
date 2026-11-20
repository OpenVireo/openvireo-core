//! Every facade record and enum as a plain JS value, with its TypeScript declaration.
//!
//! Plain records go through [`record!`]/[`unit_enum!`]; enums with data become tagged objects
//! (`{ kind: "...", ... }`) written by hand below. Handles inside records (`ImportOutcome.vault`,
//! `LoginStep.challenge`) become the wasm-bindgen classes from `handles.rs`.
//!
//! The records marked `@no_ts` have the same JS shape as a domain type a shared module declares
//! (`share.rs`: `SharePayload`, `TotpParams`, `KdfParams`, …), so their TypeScript comes from there.

use ov_core::api::*;
use ov_core::host::{CachedVault, HttpRequest, HttpResponse, Level, Method};
use ov_error::OvError;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::convert::{bad, field, obj, record, set, unit_enum, FromJs, ToJs};
use crate::handles::{TotpChallengeJs, VaultJs};

#[wasm_bindgen(typescript_custom_section)]
const PREAMBLE: &str = "\
import type { OvError } from \"../index.js\";
/** Server times: RFC 3339 strings. KDBX times: Unix seconds. Secrets: Uint8Array (UTF-8 for text); wipe them when done. */
export type Rfc3339 = string;
/** `user:<id>`, `sa:<id>`. */
export type Principal = string;
";

// ------------------------------------------------------------------------------------ config

record!(ServerConfig => ServerConfig {
    issuer: issuer ": string", api: api ": string", sync: sync ": string", jwks_uri: jwksUri ": string",
    opaque: opaque ": OpaqueConfig", kdf_min: kdfMin "?: KdfMin", web: web "?: string", share: share "?: string",
});
record!(OpaqueConfig => OpaqueConfig { lib: lib ": string", version: version ": string", context: context ": string", ids: ids ": string" });
record!(@no_ts KdfMin => KdfMin { m: m ": number", t: t ": number" });
unit_enum!(Platform => Platform {
    QtLinux => "qt-linux", QtMacos => "qt-macos", QtWindows => "qt-windows", Web => "web", Cli => "cli",
    Connect => "connect", Ios => "ios",
});
record!(DeviceInfo => DeviceInfo { id: id "?: string", name: name ": string", platform: platform ": Platform" });
record!(ClientConfig => ClientConfig { device: device ": DeviceInfo", offline: offline ": boolean", server: server "?: ServerConfig" });

// ------------------------------------------------------------------------------------ crypto

record!(@no_ts KdfParams => KdfParams { alg: alg ": string", salt: salt ": string", m: m ": number", t: t ": number", p: p ": number" });
record!(KdfOverrides => KdfOverrides { m: m "?: number", t: t "?: number", p: p "?: number" });
record!(PublicKeys => PublicKeys { enc_pk: encPk ": Uint8Array", sign_pk: signPk ": Uint8Array", sig: sig ": Uint8Array", fingerprint: fingerprint ": string" });

// ---------------------------------------------------------------------------------- sessions

record!(StoredSession => StoredSession { issuer: issuer ": string", user_id: userId ": string", email: email ": string", device_id: deviceId ": string" });
unit_enum!(SignedOutReason => SignedOutReason {
    TokenReused => "token_reused", SessionExpired => "session_expired", Unauthorized => "unauthorized",
    Logout => "logout", DeletionScheduled => "deletion_scheduled", AccountDeleted => "account_deleted",
});
unit_enum!(SessionState => SessionState { Active => "active", Parked => "parked", SignedOut => "signed_out" });
unit_enum!(ParkedCheck => ParkedCheck { Valid => "valid", Ended => "ended", NoAnswer => "no_answer" });
record!(RememberedAccount => RememberedAccount {
    email: email ": string", issuer: issuer ": string", user_id: userId ": string", last_used_at: lastUsedAt ": Rfc3339",
    checked_at: checkedAt "?: Rfc3339", deletion_scheduled_for: deletionScheduledFor "?: Rfc3339",
});
record!(NewAccount => NewAccount { user_id: userId ": string", secret_key: secretKey ": Uint8Array", emergency_kit: emergencyKit ": EmergencyKit", auk: auk ": Uint8Array" });
record!(EmergencyKit => EmergencyKit { email: email ": string", issuer: issuer ": string", web: web "?: string" });
record!(Profile => Profile {
    id: id ": string", email: email ": string", name: name "?: string", totp_enabled: totpEnabled ": boolean",
    plan: plan "?: Plan", orgs: orgs ": OrgMembership[]", deletion_scheduled_for: deletionScheduledFor "?: Rfc3339",
});
record!(Device => Device {
    id: id ": string", name: name ": string", platform: platform ": string", created_at: createdAt ": Rfc3339",
    last_seen_at: lastSeenAt ": Rfc3339", current: current ": boolean",
});
record!(TotpSetup => TotpSetup { secret: secret ": Uint8Array", uri: uri ": Uint8Array" });
record!(ReconnectResult => ReconnectResult { vaults: vaults ": VaultInfo[]", dropped: dropped ": string[]" });
record!(RecoveryReset => RecoveryReset {
    email: email ": string", not_before: notBefore ": Rfc3339", expires_at: expiresAt ": Rfc3339", archive_days: archiveDays ": number",
    personal_vaults: personalVaults ": number", shared_grants: sharedGrants ": number", sole_admin_orgs: soleAdminOrgs ": string[]",
});
record!(RecoveryStatus => RecoveryStatus {
    archived: archived ": boolean", email: email "?: string", expires_at: expiresAt "?: Rfc3339", vaults: vaults "?: number", locked: locked ": boolean",
});

// ---------------------------------------------------------------------------------- deletion

record!(DeletionPreview => DeletionPreview {
    scheduled_for: scheduledFor "?: Rfc3339", erase_on: eraseOn ": Rfc3339", vaults: vaults ": DeletionVault[]", orgs: orgs ": DeletionOrg[]",
    subscription: subscription "?: DeletionSubscription", share_links: shareLinks ": number", blocked: blocked ": boolean",
});
record!(DeletionVault => DeletionVault { id: id ": string", name: name "?: string", shared_with: sharedWith ": DeletionShare[]" });
record!(DeletionShare => DeletionShare { principal: principal ": Principal", display: display "?: string", role: role ": VaultRole" });
unit_enum!(DeletionOutcome => DeletionOutcome { Leave => "leave", Delete => "delete", Blocked => "blocked" });
record!(DeletionOrg => DeletionOrg { id: id ": string", name: name ": string", role: role ": OrgRole", outcome: outcome ": DeletionOutcome", members: members ": DeletionCandidate[]" });
record!(DeletionCandidate => DeletionCandidate { id: id ": string", email: email ": string", role: role ": OrgRole" });
record!(DeletionSubscription => DeletionSubscription { plan: plan ": string", period_end: periodEnd "?: Rfc3339", source: source ": string", manage: manage ": string" });

// ------------------------------------------------------------------------------------- plans

record!(Plan => Plan { id: id "?: string", limits: limits ": PlanLimit[]", billing: billing "?: Billing" });
record!(PlanLimit => PlanLimit { name: name ": string", value: value "?: number" });
record!(Billing => Billing {
    source: source ": string", interval: interval ": string", status: status ": string", renews_at: renewsAt "?: Rfc3339",
    ends_at: endsAt "?: Rfc3339", manage: manage ": string",
});
record!(AppleEligibility => AppleEligibility { eligible: eligible ": boolean", reason: reason "?: string" });
record!(AppleTransactionResult => AppleTransactionResult { subject: subject ": string", plan: plan ": Plan" });

// ------------------------------------------------------------------------------ vaults, roles

unit_enum!(VaultRole => VaultRole { Read => "read", Write => "write", Manage => "manage" });
unit_enum!(OrgRole => OrgRole { Owner => "owner", Admin => "admin", Member => "member" });
unit_enum!(MemberStatus => MemberStatus { Invited => "invited", Accepted => "accepted", Confirmed => "confirmed" });
unit_enum!(ShareLinkPolicy => ShareLinkPolicy { On => "on", Managers => "managers", Off => "off" });
record!(VaultInfo => VaultInfo {
    id: id ": string", name: name ": string", role: role ": VaultRole", org_id: orgId "?: string",
    current_key_version: currentKeyVersion ": number", pending_key_version: pendingKeyVersion "?: number",
    rotation_required: rotationRequired ": boolean",
});
record!(VaultVersion => VaultVersion { revision: revision ": number", etag: etag ": string", size: size "?: number", saved_at: savedAt "?: Rfc3339", is_current: isCurrent ": boolean" });
record!(BlobMeta => BlobMeta { id: id ": string", etag: etag ": string", revision: revision ": number", size: size ": number", updated_at: updatedAt ": Rfc3339" });
record!(SyncOptions => SyncOptions {
    local_changed: localChanged ": boolean", accept_server_state: acceptServerState "?: boolean" via crate::convert::field_or_default,
});
unit_enum!(SyncOutcome => SyncOutcome { Unchanged => "unchanged", Pulled => "pulled", Uploaded => "uploaded", Created => "created" });
unit_enum!(ConflictKind => ConflictKind {
    EditedOnBoth => "edited-on-both", DeletedHereEditedThere => "deleted-here-edited-there", EditedHereDeletedThere => "edited-here-deleted-there",
});
record!(SyncConflict => SyncConflict { uuid: uuid ": string", kind: kind ": ConflictKind", title: title ": string", fields: fields ": string[]" });
unit_enum!(ChangeType => ChangeType { Added => "added", Modified => "modified", Moved => "moved", Deleted => "deleted", Metadata => "metadata" });
record!(MergeChange => MergeChange { change: change ": ChangeType", uuid: uuid "?: string", title: title "?: string", group: group "?: string", details: details ": string" });
record!(SyncReport => SyncReport {
    outcome: outcome ": SyncOutcome", conflicts: conflicts ": SyncConflict[]", changes: changes ": MergeChange[]", attempts: attempts ": number",
    etag: etag "?: string", clock_offset_ms: clockOffsetMs "?: number", clock_skewed: clockSkewed ": boolean",
});
record!(AutoFillEdits => AutoFillEdits { vault_id: vaultId ": string", entries: entries ": AutoFillEdit[]", version: version ": string" });
record!(AutoFillEdit => AutoFillEdit { entry: entry ": EntryRecord", group_path: groupPath ": string" });

// ----------------------------------------------------------------------------------- sharing

record!(VaultMember => VaultMember { principal: principal ": Principal", role: role ": VaultRole", display: display ": string", key_version: keyVersion ": number", is_you: isYou ": boolean" });
record!(ShareRecipient => ShareRecipient { principal: principal ": Principal", email: email "?: string", name: name "?: string", public_keys: publicKeys ": PublicKeys" });
record!(GrantResult => GrantResult { principal: principal ": Principal", fingerprint: fingerprint ": string" });
record!(VaultGrantRequest => VaultGrantRequest { vault_id: vaultId ": string", role: role ": VaultRole" });
record!(Org => Org {
    id: id ": string", name: name ": string", role: role ": OrgRole", plan: plan "?: Plan",
    item_share_links: itemShareLinks "?: ShareLinkPolicy", created_at: createdAt ": Rfc3339",
});
record!(OrgMembership => OrgMembership {
    id: id ": string", name: name ": string", role: role ": OrgRole", status: status ": MemberStatus", plan: plan "?: Plan",
    item_share_links: itemShareLinks "?: ShareLinkPolicy",
});
record!(Member => Member {
    user_id: userId ": string", email: email ": string", name: name "?: string", role: role ": OrgRole", status: status ": MemberStatus",
    public_keys: publicKeys "?: PublicKeys",
});
record!(Invitation => Invitation { id: id ": string", email: email ": string", role: role ": OrgRole", expires_at: expiresAt ": Rfc3339", invited_by: invitedBy ": Principal" });
record!(RotationReport => RotationReport { rotated: rotated ": string[]", failed: failed ": RotationFailure[]" });
record!(RotationFailure => RotationFailure { vault_id: vaultId ": string", error: error ": OvError" });

// -------------------------------------------------------------------------- service accounts

record!(ServiceAccountInfo => ServiceAccountInfo {
    id: id ": string", org_id: orgId ": string", name: name ": string", public_keys: publicKeys "?: PublicKeys",
    created_by: createdBy "?: Principal", created_at: createdAt "?: Rfc3339", expires_at: expiresAt "?: Rfc3339", disabled: disabled ": boolean",
});
record!(NewServiceAccount => NewServiceAccount { name: name ": string", vaults: vaults ": VaultGrantRequest[]", expires_at: expiresAt "?: Rfc3339", secret_name: secretName "?: string" });
record!(CreatedServiceAccount => CreatedServiceAccount { service_account: serviceAccount ": ServiceAccountInfo", token: token ": Uint8Array" });
record!(IssuedSecret => IssuedSecret { token: token ": Uint8Array", id: id ": string", prefix: prefix ": string" });
record!(SaSecretInfo => SaSecretInfo {
    id: id ": string", prefix: prefix ": string", name: name "?: string", created_at: createdAt ": Rfc3339",
    last_used_at: lastUsedAt "?: Rfc3339", expires_at: expiresAt "?: Rfc3339",
});
record!(ServiceAccountUpdate => ServiceAccountUpdate { name: name "?: string", expires_at: expiresAt ": ExpiryChange", disabled: disabled "?: boolean" });
record!(AuditEvent => AuditEvent {
    id: id ": string", at: at ": Rfc3339", actor: actor ": Principal", action: action ": string", target: target "?: string",
    ip: ip "?: string", details: details "?: string",
});
record!(AuditPage => AuditPage { events: events ": AuditEvent[]", next: next "?: string" });
record!(SaVault => SaVault { id: id ": string", name: name ": string", role: role ": VaultRole" });
record!(Injected => Injected { text: text ": Uint8Array", secrets: secrets ": Uint8Array[]" });

// ------------------------------------------------------------------------------ self-hosted

record!(PairingCode => PairingCode { code: code ": string", expires_at: expiresAt ": Rfc3339" });
record!(SelfHostedSyncResult => SelfHostedSyncResult { kdbx: kdbx ": Uint8Array", report: report ": SyncReport" });
record!(VaultKdbxSyncResult => VaultKdbxSyncResult { kdbx: kdbx ": Uint8Array", credentials: credentials ": KdbxCredentials", report: report ": SyncReport" });

// ------------------------------------------------------------------------------------- TOTP

unit_enum!(@no_ts TotpAlgorithm => TotpAlgorithm { Sha1 => "SHA1", Sha256 => "SHA256", Sha512 => "SHA512" });
record!(@no_ts TotpParams => TotpParams { secret: secret ": Uint8Array", digits: digits ": number", period: period ": number", algorithm: algorithm ": TotpAlgorithm", encoder: encoder "?: string" });
record!(@no_ts TotpCode => TotpCode { code: code ": Uint8Array", remaining: remaining ": number" });

// ------------------------------------------------------------------------------- share links

record!(ShareOptions => ShareOptions {
    expires_in: expiresIn ": number", max_opens: maxOpens "?: number", passcode: passcode "?: Uint8Array",
    vault_id: vaultId "?: string", entry_id: entryId "?: string",
});
record!(CreatedShare => CreatedShare { id: id ": string", url: url ": Uint8Array", expires_at: expiresAt ": Rfc3339" });
record!(@no_ts ShareRef => ShareRef { vault: vault "?: string", entry: entry "?: string", title: title ": string" });
record!(ShareListing => ShareListing {
    id: id ": string", vault_id: vaultId "?: string", reference: reference "?: ShareRef", passcode: passcode ": boolean",
    max_opens: maxOpens "?: number", opens: opens ": number", opened_at: openedAt ": Rfc3339[]", created_at: createdAt ": Rfc3339",
    expires_at: expiresAt ": Rfc3339", status: status ": string", ended_at: endedAt "?: Rfc3339", end_reason: endReason "?: string",
});
record!(@no_ts SharePayload => SharePayload { v: v ": number", kind: kind ": string", title: title "?: string", shared_by: sharedBy "?: string", fields: fields ": ShareField[]" });
record!(@no_ts ShareField => ShareField { k: k ": string", label: label ": string", value: value ": Uint8Array", protected: protected ": boolean" });
record!(@no_ts ShareableField => ShareableField { name: name ": string", kind: kind ": string", label: label ": string", value: value ": Uint8Array", protected: protected ": boolean" });
record!(ShareInfo => ShareInfo { expires_at: expiresAt ": Rfc3339", opens_left: opensLeft "?: number", kdf: kdf "?: KdfParams" });
record!(OpenedShare => OpenedShare { payload: payload ": SharePayload", opens_left: opensLeft "?: number" });

// ------------------------------------------------------------------------------------ vaults

record!(KdbxCredentials => KdbxCredentials { password: password "?: Uint8Array", key_file: keyFile "?: Uint8Array", password_hash: passwordHash "?: Uint8Array" });
record!(EntrySummary => EntrySummary {
    id: id ": string", group_id: groupId ": string", group_path: groupPath ": string[]", title: title ": string", username: username ": string",
    url: url ": string", tags: tags ": string[]", protected_fields: protectedFields ": string[]", icon_id: iconId ": number",
    custom_icon: customIcon "?: string", modified_at: modifiedAt ": number", expires_at: expiresAt "?: number", in_recycle_bin: inRecycleBin ": boolean",
    last_access_at: lastAccessAt "?: number", usage_count: usageCount ": number" via crate::convert::field_or_default,
});
record!(@no_ts FieldRecord => FieldRecord { name: name ": string", value: value ": Uint8Array", protected: protected ": boolean" });
record!(AttachmentInfo => AttachmentInfo {
    name: name ": string", size: size ": number", protected: protected ": boolean" via crate::convert::field_or_default,
});
record!(EntryRecord => EntryRecord {
    id: id ": string", group_id: groupId ": string", group_path: groupPath ": string[]", fields: fields ": FieldRecord[]", tags: tags ": string[]",
    icon_id: iconId ": number", custom_icon: customIcon "?: string", foreground_color: foregroundColor ": string",
    background_color: backgroundColor ": string", override_url: overrideUrl ": string", created_at: createdAt ": number",
    modified_at: modifiedAt ": number", expires_at: expiresAt "?: number", attachments: attachments ": AttachmentInfo[]",
    history_count: historyCount ": number", quality_check: qualityCheck ": boolean",
    last_access_at: lastAccessAt "?: number", usage_count: usageCount ": number" via crate::convert::field_or_default,
});
record!(GroupInfo => GroupInfo {
    id: id ": string", name: name ": string", parent_id: parentId "?: string", path: path ": string[]", icon_id: iconId ": number",
    notes: notes ": string", is_recycle_bin: isRecycleBin ": boolean", entry_count: entryCount ": number",
});
record!(FieldInput => FieldInput { name: name ": string", value: value ": Uint8Array", protected: protected "?: boolean" });
record!(EntryInput => EntryInput {
    fields: fields ": FieldInput[]", remove_fields: removeFields ": string[]", tags: tags "?: string[]", icon_id: iconId "?: number", expiry: expiry ": EntryExpiry",
    foreground_color: foregroundColor "?: string", background_color: backgroundColor "?: string",
    custom_icon: customIcon "?: string | null" via crate::convert::field_change, field_order: fieldOrder "?: string[]",
});
unit_enum!(CreateMode => CreateMode { MustExist => "must_exist", CreateIfMissing => "create_if_missing", CreateOnly => "create_only" });
record!(SetFieldsResult => SetFieldsResult { entry: entry ": EntryRecord", created: created ": boolean" });
unit_enum!(VersionDifference => VersionDifference { Same => "same", Changed => "changed", Deleted => "deleted" });
unit_enum!(ExportFormat => ExportFormat { Csv => "csv", Json => "json" });
record!(ImportSummary => ImportSummary {
    added: added ": number", updated: updated ": number", unchanged: unchanged ": number", groups_added: groupsAdded ": number",
    changes: changes ": MergeChange[]",
});
record!(ImportPreview => ImportPreview { entries: entries ": number", groups: groups ": number" });
record!(ImportTarget => ImportTarget { group_id: groupId ": string", path: path ": string" });

// ------------------------------------------------------------------------------------ host

record!(CachedVault => CachedVault { state: state ": Uint8Array", base: base "?: Uint8Array", pending: pending "?: Uint8Array", autofill: autofill "?: Uint8Array" });
record!(HttpResponse => HttpResponse { status: status ": number", headers: headers ": [string, string][]", body: body ": Uint8Array" });
record!(HttpRequest => HttpRequest {
    method: method ": HttpMethod", url: url ": string", headers: headers ": [string, string][]", body: body "?: Uint8Array", keepalive: keepalive ": boolean",
});
unit_enum!(Method => HttpMethod { Get => "GET", Head => "HEAD", Post => "POST", Put => "PUT", Patch => "PATCH", Delete => "DELETE" });
unit_enum!(Level => LogLevel { Error => "error", Warn => "warn", Info => "info", Debug => "debug", Trace => "trace" });

// --------------------------------------------------------------------- enums with data (tagged)

/// `{ kind }` of a tagged object.
fn kind(v: &JsValue, path: &str) -> Result<String, OvError> {
    field(v, "kind", path)
}

fn tagged(k: &str) -> js_sys::Object {
    let o = obj();
    set(&o, "kind", JsValue::from_str(k));
    o
}

#[wasm_bindgen(typescript_custom_section)]
const TAGGED: &str = r#"
/** How `Account.importKdbx` / `importVault` brings a database in. */
export type ImportMode =
  | { kind: "newVault"; name?: string; orgId?: string }
  | { kind: "merge"; vaultId: string }
  | { kind: "copies"; vaultId: string };
export interface ImportOutcome { vault: Vault; uploaded: boolean; uploadError?: OvError; report?: SyncReport }
/** Who `Account.shareVault` grants to. */
export type Grantee = { kind: "email"; email: string } | { kind: "principal"; principal: Principal };
/** `keep` leaves the expiry as it is, `never` clears it. */
export type ExpiryChange = { kind: "keep" } | { kind: "never" } | { kind: "at"; at: Rfc3339 };
/** Entry expiry edit; `at` is Unix seconds. */
export type EntryExpiry = { kind: "keep" } | { kind: "never" } | { kind: "at"; at: number };
/** How `Vault.importFrom` brings another open vault in (contract-v1.6); `copies` goes under `parentGroupId` (the root when absent). */
export type LocalImportMode = { kind: "merge" } | { kind: "copies"; parentGroupId?: string };
/** The key derivation a password-protected `.kdbx` is saved with (contract-v1.6); `memory` is in bytes. */
export type KdbxKdf =
  | { kind: "databaseDefault" }
  | { kind: "argon2d"; memory: number; iterations: number; parallelism: number }
  | { kind: "argon2id"; memory: number; iterations: number; parallelism: number }
  | { kind: "aesKdf"; rounds: number };
export type LoginStep = { kind: "needsTotp"; challenge: TotpChallenge } | { kind: "unlocked"; unlocked: Unlocked };
export interface Unlocked { auk: Uint8Array; offline: boolean; deletionScheduledFor?: Rfc3339 }
export interface RegisterInput { email: string; password: Uint8Array; kdf?: KdfOverrides; trustDevice: boolean }
export interface LoginInput { email: string; password: Uint8Array; secretKey?: Uint8Array; totp?: string; trustDevice: boolean }
export type AccountEvent =
  | { kind: "vaultChanged"; vaultId: string; etag?: string; revision?: number; deleted: boolean }
  | { kind: "vaultsChanged"; vaults: VaultInfo[] }
  | { kind: "sessionEnded"; reason: SignedOutReason; at?: Rfc3339 }
  | { kind: "databaseChanged"; databaseId: string; etag?: string; revision?: number; deleted: boolean };
"#;

impl FromJs for ImportMode {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        match kind(v, path)?.as_str() {
            "newVault" => Ok(ImportMode::NewVault { name: field(v, "name", path)?, org_id: field(v, "orgId", path)? }),
            "merge" => Ok(ImportMode::Merge { vault_id: field(v, "vaultId", path)? }),
            "copies" => Ok(ImportMode::Copies { vault_id: field(v, "vaultId", path)? }),
            _ => Err(bad(&format!("{path}.kind"), "\"newVault\" | \"merge\" | \"copies\"")),
        }
    }
}

impl FromJs for LocalImportMode {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        match kind(v, path)?.as_str() {
            "merge" => Ok(LocalImportMode::Merge),
            "copies" => Ok(LocalImportMode::Copies { parent_group_id: field(v, "parentGroupId", path)? }),
            _ => Err(bad(&format!("{path}.kind"), "\"merge\" | \"copies\"")),
        }
    }
}

impl FromJs for KdbxKdf {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let argon = |v: &JsValue| -> Result<(u64, u64, u32), OvError> {
            Ok((field(v, "memory", path)?, field(v, "iterations", path)?, field(v, "parallelism", path)?))
        };
        match kind(v, path)?.as_str() {
            "databaseDefault" => Ok(KdbxKdf::DatabaseDefault),
            "argon2d" => {
                argon(v).map(|(memory, iterations, parallelism)| KdbxKdf::Argon2d { memory, iterations, parallelism })
            }
            "argon2id" => {
                argon(v).map(|(memory, iterations, parallelism)| KdbxKdf::Argon2id { memory, iterations, parallelism })
            }
            "aesKdf" => Ok(KdbxKdf::AesKdf { rounds: field(v, "rounds", path)? }),
            _ => Err(bad(&format!("{path}.kind"), "\"databaseDefault\" | \"argon2d\" | \"argon2id\" | \"aesKdf\"")),
        }
    }
}

impl ToJs for ImportOutcome {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "vault", VaultJs(self.vault.clone()).into());
        set(&o, "uploaded", self.uploaded.to_js());
        set(&o, "uploadError", self.upload_error.to_js());
        set(&o, "report", self.report.to_js());
        o.into()
    }
}

impl FromJs for Grantee {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        match kind(v, path)?.as_str() {
            "email" => Ok(Grantee::Email(field(v, "email", path)?)),
            "principal" => Ok(Grantee::Principal(field(v, "principal", path)?)),
            _ => Err(bad(&format!("{path}.kind"), "\"email\" | \"principal\"")),
        }
    }
}

impl ToJs for ExpiryChange {
    fn to_js(&self) -> JsValue {
        match self {
            ExpiryChange::Keep => tagged("keep").into(),
            ExpiryChange::Never => tagged("never").into(),
            ExpiryChange::At(at) => {
                let o = tagged("at");
                set(&o, "at", at.to_js());
                o.into()
            }
        }
    }
}
impl FromJs for ExpiryChange {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        match kind(v, path)?.as_str() {
            "keep" => Ok(ExpiryChange::Keep),
            "never" => Ok(ExpiryChange::Never),
            "at" => Ok(ExpiryChange::At(field(v, "at", path)?)),
            _ => Err(bad(&format!("{path}.kind"), "\"keep\" | \"never\" | \"at\"")),
        }
    }
}

impl ToJs for EntryExpiry {
    fn to_js(&self) -> JsValue {
        match self {
            EntryExpiry::Keep => tagged("keep").into(),
            EntryExpiry::Never => tagged("never").into(),
            EntryExpiry::At(at) => {
                let o = tagged("at");
                set(&o, "at", at.to_js());
                o.into()
            }
        }
    }
}
impl FromJs for EntryExpiry {
    /// A missing expiry means `keep`.
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        if v.is_undefined() || v.is_null() {
            return Ok(EntryExpiry::Keep);
        }
        match kind(v, path)?.as_str() {
            "keep" => Ok(EntryExpiry::Keep),
            "never" => Ok(EntryExpiry::Never),
            "at" => Ok(EntryExpiry::At(field(v, "at", path)?)),
            _ => Err(bad(&format!("{path}.kind"), "\"keep\" | \"never\" | \"at\"")),
        }
    }
}

impl ToJs for Unlocked {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "auk", self.auk.to_js());
        set(&o, "offline", self.offline.to_js());
        set(&o, "deletionScheduledFor", self.deletion_scheduled_for.to_js());
        o.into()
    }
}

impl ToJs for LoginStep {
    fn to_js(&self) -> JsValue {
        match self {
            LoginStep::NeedsTotp(c) => {
                let o = tagged("needsTotp");
                set(&o, "challenge", TotpChallengeJs(c.clone()).into());
                o.into()
            }
            LoginStep::Unlocked(u) => {
                let o = tagged("unlocked");
                set(&o, "unlocked", u.to_js());
                o.into()
            }
        }
    }
}

impl FromJs for RegisterInput {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        Ok(RegisterInput {
            email: field(v, "email", path)?,
            password: field(v, "password", path)?,
            kdf: field(v, "kdf", path)?,
            trust_device: field::<Option<bool>>(v, "trustDevice", path)?.unwrap_or(true),
        })
    }
}

impl FromJs for LoginInput {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        Ok(LoginInput {
            email: field(v, "email", path)?,
            password: field(v, "password", path)?,
            secret_key: field(v, "secretKey", path)?,
            totp: field(v, "totp", path)?,
            trust_device: field::<Option<bool>>(v, "trustDevice", path)?.unwrap_or(true),
        })
    }
}

impl ToJs for AccountEvent {
    fn to_js(&self) -> JsValue {
        match self {
            AccountEvent::VaultChanged { vault_id, etag, revision, deleted } => {
                let o = tagged("vaultChanged");
                set(&o, "vaultId", vault_id.to_js());
                set(&o, "etag", etag.to_js());
                set(&o, "revision", revision.to_js());
                set(&o, "deleted", deleted.to_js());
                o.into()
            }
            AccountEvent::VaultsChanged { vaults } => {
                let o = tagged("vaultsChanged");
                set(&o, "vaults", vaults.to_js());
                o.into()
            }
            AccountEvent::SessionEnded { reason, at } => {
                let o = tagged("sessionEnded");
                set(&o, "reason", reason.to_js());
                set(&o, "at", at.to_js());
                o.into()
            }
            AccountEvent::DatabaseChanged { database_id, etag, revision, deleted } => {
                let o = tagged("databaseChanged");
                set(&o, "databaseId", database_id.to_js());
                set(&o, "etag", etag.to_js());
                set(&o, "revision", revision.to_js());
                set(&o, "deleted", deleted.to_js());
                o.into()
            }
        }
    }
}

/// `()` results resolve to `undefined`.
impl ToJs for () {
    fn to_js(&self) -> JsValue {
        JsValue::UNDEFINED
    }
}
