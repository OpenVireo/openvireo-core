//! Conversions for the records of the facade areas bridged after the first desktop paths
//! (settings, recovery, deletion, plans, sharing and orgs, service accounts, share links, TOTP,
//! the full `Vault` editing surface). Same rules as `convert.rs`: `Option<String>` is an empty
//! string, other options a `has_*` flag, and enums from C++ are checked.

use ov_core::api as core;
use ov_error::{OvError, OvErrorCode};

use crate::convert::{sync_report, vault_info};
use crate::edge::error_info;
use crate::ffi;

pub(crate) fn opt(s: Option<String>) -> String {
    s.unwrap_or_default()
}

pub(crate) fn some(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn bad_enum(what: &str, repr: impl std::fmt::Debug) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, format!("unknown {what} value {repr:?}"))
}

/// Both directions for a fieldless enum named the same in the core and the bridge. The way in
/// rejects values C++ made up.
macro_rules! enum_map {
    ($t:ident, $out:ident, $into:ident, [$($v:ident),+ $(,)?]) => {
        #[allow(dead_code)]
        pub(crate) fn $out(x: core::$t) -> ffi::$t {
            match x {
                $(core::$t::$v => ffi::$t::$v,)+
            }
        }

        #[allow(dead_code)]
        pub(crate) fn $into(x: ffi::$t) -> Result<core::$t, OvError> {
            match x {
                $(ffi::$t::$v => Ok(core::$t::$v),)+
                other => Err(bad_enum(stringify!($t), other.repr)),
            }
        }
    };
}

enum_map!(VaultRole, vault_role, vault_role_in, [Read, Write, Manage]);
enum_map!(OrgRole, org_role, org_role_in, [Owner, Admin, Member]);
enum_map!(MemberStatus, member_status, member_status_in, [Invited, Accepted, Confirmed]);
enum_map!(ShareLinkPolicy, share_link_policy, share_link_policy_in, [On, Managers, Off]);
enum_map!(ParkedCheck, parked_check, parked_check_in, [Valid, Ended, NoAnswer]);
enum_map!(DeletionOutcome, deletion_outcome, deletion_outcome_in, [Leave, Delete, Blocked]);
enum_map!(CreateMode, create_mode, create_mode_in, [MustExist, CreateIfMissing, CreateOnly]);
enum_map!(VersionDifference, version_difference, version_difference_in, [Same, Changed, Deleted]);
enum_map!(ExportFormat, export_format, export_format_in, [Csv, Json]);
enum_map!(TotpAlgorithm, totp_algorithm, totp_algorithm_in, [Sha1, Sha256, Sha512]);
enum_map!(
    SignedOutReason,
    signed_out_reason,
    signed_out_reason_in,
    [TokenReused, SessionExpired, Unauthorized, Logout, DeletionScheduled, AccountDeleted]
);
enum_map!(Platform, platform, platform_in, [QtLinux, QtMacos, QtWindows, Web, Cli, Connect, Ios]);

// --------------------------------------------------------------------------------- generic

pub(crate) fn opt_bytes(b: Option<Vec<u8>>) -> ffi::OptionalBytes {
    ffi::OptionalBytes { has: b.is_some(), value: b.unwrap_or_default() }
}

pub(crate) fn opt_u64(v: Option<u64>) -> ffi::OptionalU64 {
    ffi::OptionalU64 { has: v.is_some(), value: v.unwrap_or(0) }
}

pub(crate) fn opt_i64(v: Option<i64>) -> ffi::OptionalI64 {
    ffi::OptionalI64 { has: v.is_some(), value: v.unwrap_or(0) }
}

pub(crate) fn opt_error(e: Option<OvError>) -> ffi::OptionalError {
    ffi::OptionalError { has: e.is_some(), error: e.as_ref().map(error_info).unwrap_or_default() }
}

/// An `ErrorInfo` from C++ back into an `OvError` (for `Account::upgrade_url`).
pub(crate) fn error_from_info(e: &ffi::ErrorInfo) -> OvError {
    let mut err = if !e.server_code.is_empty() {
        OvError::from_server(e.status, Some(&e.server_code), e.message.clone())
    } else {
        OvError::new(OvErrorCode::from_wire(&e.code).unwrap_or(OvErrorCode::Internal), e.message.clone())
    };
    if e.status != 0 {
        err.status = Some(e.status);
    }
    if e.has_retry_after {
        err.retry_after = Some(e.retry_after);
    }
    if !e.details.is_empty() {
        err.details = Some(e.details.clone());
    }
    err
}

pub(crate) fn client_config_to_ffi(c: core::ClientConfig) -> ffi::ClientConfig {
    ffi::ClientConfig {
        device_id: opt(c.device.id),
        device_name: c.device.name,
        platform: platform(c.device.platform),
        offline: c.offline,
        has_server: c.server.is_some(),
        server: c.server.map(crate::convert::server_config_to_ffi).unwrap_or_default(),
    }
}

pub(crate) fn placeholder_vault_info() -> ffi::VaultInfo {
    ffi::VaultInfo {
        id: String::new(),
        name: String::new(),
        role: ffi::VaultRole::Read,
        org_id: String::new(),
        current_key_version: 0,
        has_pending_key_version: false,
        pending_key_version: 0,
        rotation_required: false,
    }
}

pub(crate) fn placeholder_sync_report() -> ffi::SyncReport {
    ffi::SyncReport {
        outcome: ffi::SyncOutcome::Unchanged,
        conflicts: Vec::new(),
        changes: Vec::new(),
        attempts: 0,
        etag: String::new(),
        has_clock_offset: false,
        clock_offset_ms: 0,
        clock_skewed: false,
    }
}

// ------------------------------------------------------------------------ crypto, sessions

pub(crate) fn kdf_params(k: core::KdfParams) -> ffi::KdfParams {
    ffi::KdfParams { alg: k.alg, salt: k.salt, m: k.m, t: k.t, p: k.p }
}

pub(crate) fn kdf_params_in(k: &ffi::KdfParams) -> core::KdfParams {
    core::KdfParams { alg: k.alg.clone(), salt: k.salt.clone(), m: k.m, t: k.t, p: k.p }
}

pub(crate) fn kdf_overrides_in(k: ffi::KdfOverrides) -> Option<core::KdfOverrides> {
    (k.has_m || k.has_t || k.has_p).then_some(core::KdfOverrides {
        m: k.has_m.then_some(k.m),
        t: k.has_t.then_some(k.t),
        p: k.has_p.then_some(k.p),
    })
}

pub(crate) fn public_keys(k: core::PublicKeys) -> ffi::PublicKeys {
    ffi::PublicKeys { enc_pk: k.enc_pk, sign_pk: k.sign_pk, sig: k.sig, fingerprint: k.fingerprint }
}

pub(crate) fn public_keys_in(k: &ffi::PublicKeys) -> core::PublicKeys {
    core::PublicKeys {
        enc_pk: k.enc_pk.clone(),
        sign_pk: k.sign_pk.clone(),
        sig: k.sig.clone(),
        fingerprint: k.fingerprint.clone(),
    }
}

pub(crate) fn stored_session(s: Option<core::StoredSession>) -> ffi::OptionalStoredSession {
    ffi::OptionalStoredSession {
        has: s.is_some(),
        value: s
            .map(|s| ffi::StoredSession {
                issuer: s.issuer,
                user_id: s.user_id,
                email: s.email,
                device_id: s.device_id,
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn register_input(i: ffi::RegisterInput) -> core::RegisterInput {
    core::RegisterInput {
        email: i.email,
        password: i.password,
        kdf: kdf_overrides_in(i.kdf),
        trust_device: i.trust_device,
    }
}

pub(crate) fn new_account(a: core::NewAccount) -> ffi::NewAccount {
    ffi::NewAccount {
        user_id: a.user_id,
        secret_key: a.secret_key,
        emergency_kit: ffi::EmergencyKit {
            email: a.emergency_kit.email,
            issuer: a.emergency_kit.issuer,
            web: opt(a.emergency_kit.web),
        },
        auk: a.auk,
    }
}

pub(crate) fn reconnect_result(r: core::ReconnectResult) -> ffi::ReconnectResult {
    ffi::ReconnectResult { vaults: r.vaults.into_iter().map(vault_info).collect(), dropped: r.dropped }
}

pub(crate) fn opt_vault_list(v: Option<Vec<core::VaultInfo>>) -> ffi::OptionalVaultList {
    ffi::OptionalVaultList { has: v.is_some(), vaults: v.unwrap_or_default().into_iter().map(vault_info).collect() }
}

pub(crate) fn opt_vault_info(v: Option<core::VaultInfo>) -> ffi::OptionalVaultInfo {
    ffi::OptionalVaultInfo { has: v.is_some(), value: v.map(vault_info).unwrap_or_else(placeholder_vault_info) }
}

pub(crate) fn opt_http_request(r: Option<ov_core::host::HttpRequest>) -> ffi::OptionalHttpRequest {
    ffi::OptionalHttpRequest {
        has: r.is_some(),
        value: r.map(crate::convert::http_request).unwrap_or(ffi::HttpRequest {
            method: ffi::Method::Get,
            url: String::new(),
            headers: Vec::new(),
            has_body: false,
            body: Vec::new(),
            keepalive: false,
        }),
    }
}

// -------------------------------------------------------------------------- settings, plans

pub(crate) fn plan(p: core::Plan) -> ffi::Plan {
    ffi::Plan {
        id: opt(p.id),
        limits: p
            .limits
            .into_iter()
            .map(|l| ffi::PlanLimit { name: l.name, has_value: l.value.is_some(), value: l.value.unwrap_or(0) })
            .collect(),
        has_billing: p.billing.is_some(),
        billing: p
            .billing
            .map(|b| ffi::Billing {
                source: b.source,
                interval: b.interval,
                status: b.status,
                renews_at: opt(b.renews_at),
                ends_at: opt(b.ends_at),
                manage: b.manage,
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn plan_in(p: &ffi::Plan) -> core::Plan {
    core::Plan {
        id: some(&p.id),
        limits: p
            .limits
            .iter()
            .map(|l| core::PlanLimit { name: l.name.clone(), value: l.has_value.then_some(l.value) })
            .collect(),
        billing: p.has_billing.then(|| core::Billing {
            source: p.billing.source.clone(),
            interval: p.billing.interval.clone(),
            status: p.billing.status.clone(),
            renews_at: some(&p.billing.renews_at),
            ends_at: some(&p.billing.ends_at),
            manage: p.billing.manage.clone(),
        }),
    }
}

pub(crate) fn opt_plan(p: Option<core::Plan>) -> ffi::OptionalPlan {
    ffi::OptionalPlan { has: p.is_some(), value: p.map(plan).unwrap_or_default() }
}

fn policy_or_default(p: Option<core::ShareLinkPolicy>) -> (bool, ffi::ShareLinkPolicy) {
    (p.is_some(), p.map(share_link_policy).unwrap_or(ffi::ShareLinkPolicy::On))
}

pub(crate) fn org_membership(o: core::OrgMembership) -> ffi::OrgMembership {
    let (has_item_share_links, item_share_links) = policy_or_default(o.item_share_links);
    ffi::OrgMembership {
        id: o.id,
        name: o.name,
        role: org_role(o.role),
        status: member_status(o.status),
        has_plan: o.plan.is_some(),
        plan: o.plan.map(plan).unwrap_or_default(),
        has_item_share_links,
        item_share_links,
    }
}

pub(crate) fn profile(p: core::Profile) -> ffi::Profile {
    ffi::Profile {
        id: p.id,
        email: p.email,
        name: opt(p.name),
        totp_enabled: p.totp_enabled,
        has_plan: p.plan.is_some(),
        plan: p.plan.map(plan).unwrap_or_default(),
        orgs: p.orgs.into_iter().map(org_membership).collect(),
        deletion_scheduled_for: opt(p.deletion_scheduled_for),
    }
}

pub(crate) fn device(d: core::Device) -> ffi::Device {
    ffi::Device {
        id: d.id,
        name: d.name,
        platform: d.platform,
        created_at: d.created_at,
        last_seen_at: d.last_seen_at,
        current: d.current,
    }
}

pub(crate) fn totp_setup(t: core::TotpSetup) -> ffi::TotpSetup {
    ffi::TotpSetup { secret: t.secret, uri: t.uri }
}

pub(crate) fn recovery_reset(r: core::RecoveryReset) -> ffi::RecoveryReset {
    ffi::RecoveryReset {
        email: r.email,
        not_before: r.not_before,
        expires_at: r.expires_at,
        archive_days: r.archive_days,
        personal_vaults: r.personal_vaults,
        shared_grants: r.shared_grants,
        sole_admin_orgs: r.sole_admin_orgs,
    }
}

pub(crate) fn recovery_status(r: core::RecoveryStatus) -> ffi::RecoveryStatus {
    ffi::RecoveryStatus {
        archived: r.archived,
        email: opt(r.email),
        expires_at: opt(r.expires_at),
        has_vaults: r.vaults.is_some(),
        vaults: r.vaults.unwrap_or(0),
        locked: r.locked,
    }
}

pub(crate) fn deletion_preview(d: core::DeletionPreview) -> ffi::DeletionPreview {
    ffi::DeletionPreview {
        scheduled_for: opt(d.scheduled_for),
        erase_on: d.erase_on,
        vaults: d
            .vaults
            .into_iter()
            .map(|v| ffi::DeletionVault {
                id: v.id,
                name: opt(v.name),
                shared_with: v
                    .shared_with
                    .into_iter()
                    .map(|s| ffi::DeletionShare {
                        principal: s.principal,
                        display: opt(s.display),
                        role: vault_role(s.role),
                    })
                    .collect(),
            })
            .collect(),
        orgs: d
            .orgs
            .into_iter()
            .map(|o| ffi::DeletionOrg {
                id: o.id,
                name: o.name,
                role: org_role(o.role),
                outcome: deletion_outcome(o.outcome),
                members: o
                    .members
                    .into_iter()
                    .map(|m| ffi::DeletionCandidate { id: m.id, email: m.email, role: org_role(m.role) })
                    .collect(),
            })
            .collect(),
        has_subscription: d.subscription.is_some(),
        subscription: d
            .subscription
            .map(|s| ffi::DeletionSubscription {
                plan: s.plan,
                period_end: opt(s.period_end),
                source: s.source,
                manage: s.manage,
            })
            .unwrap_or_default(),
        share_links: d.share_links,
        blocked: d.blocked,
    }
}

pub(crate) fn apple_eligibility(a: core::AppleEligibility) -> ffi::AppleEligibility {
    ffi::AppleEligibility { eligible: a.eligible, reason: opt(a.reason) }
}

pub(crate) fn apple_transaction(a: core::AppleTransactionResult) -> ffi::AppleTransactionResult {
    ffi::AppleTransactionResult { subject: a.subject, plan: plan(a.plan) }
}

// --------------------------------------------------------------------------- vaults, history

pub(crate) fn vault_version(v: core::VaultVersion) -> ffi::VaultVersion {
    ffi::VaultVersion {
        revision: v.revision,
        etag: v.etag,
        has_size: v.size.is_some(),
        size: v.size.unwrap_or(0),
        saved_at: opt(v.saved_at),
        is_current: v.is_current,
    }
}

pub(crate) fn blob_meta(b: core::BlobMeta) -> ffi::BlobMeta {
    ffi::BlobMeta { id: b.id, etag: b.etag, revision: b.revision, size: b.size, updated_at: b.updated_at }
}

pub(crate) fn import_mode_in(m: &ffi::ImportMode) -> Result<core::ImportMode, OvError> {
    Ok(match m.kind {
        ffi::ImportModeKind::NewVault => core::ImportMode::NewVault { name: some(&m.name), org_id: some(&m.org_id) },
        ffi::ImportModeKind::Merge => core::ImportMode::Merge { vault_id: m.vault_id.clone() },
        ffi::ImportModeKind::Copies => core::ImportMode::Copies { vault_id: m.vault_id.clone() },
        other => return Err(bad_enum("ImportModeKind", other.repr)),
    })
}

pub(crate) fn import_outcome(o: core::ImportOutcome) -> ffi::ImportOutcome {
    ffi::ImportOutcome {
        vault: Box::new(crate::handles::Vault(o.vault)),
        uploaded: o.uploaded,
        has_upload_error: o.upload_error.is_some(),
        upload_error: o.upload_error.as_ref().map(error_info).unwrap_or_default(),
        has_report: o.report.is_some(),
        report: o.report.map(sync_report).unwrap_or_else(placeholder_sync_report),
    }
}

pub(crate) fn field_record(f: core::FieldRecord) -> ffi::FieldRecord {
    ffi::FieldRecord { name: f.name, value: f.value, is_protected: f.protected }
}

pub(crate) fn field_record_in(f: &ffi::FieldRecord) -> core::FieldRecord {
    core::FieldRecord { name: f.name.clone(), value: f.value.clone(), protected: f.is_protected }
}

pub(crate) fn entry_record(e: core::EntryRecord) -> ffi::EntryRecord {
    ffi::EntryRecord {
        id: e.id,
        group_id: e.group_id,
        group_path: e.group_path,
        fields: e.fields.into_iter().map(field_record).collect(),
        tags: e.tags,
        icon_id: e.icon_id,
        custom_icon: opt(e.custom_icon),
        foreground_color: e.foreground_color,
        background_color: e.background_color,
        override_url: e.override_url,
        created_at: e.created_at,
        modified_at: e.modified_at,
        has_expires_at: e.expires_at.is_some(),
        expires_at: e.expires_at.unwrap_or(0),
        attachments: e.attachments.into_iter().map(|a| ffi::AttachmentInfo { name: a.name, size: a.size }).collect(),
        history_count: e.history_count,
        quality_check: e.quality_check,
    }
}

pub(crate) fn entry_record_in(e: &ffi::EntryRecord) -> core::EntryRecord {
    core::EntryRecord {
        id: e.id.clone(),
        group_id: e.group_id.clone(),
        group_path: e.group_path.clone(),
        fields: e.fields.iter().map(field_record_in).collect(),
        tags: e.tags.clone(),
        icon_id: e.icon_id,
        custom_icon: some(&e.custom_icon),
        foreground_color: e.foreground_color.clone(),
        background_color: e.background_color.clone(),
        override_url: e.override_url.clone(),
        created_at: e.created_at,
        modified_at: e.modified_at,
        expires_at: e.has_expires_at.then_some(e.expires_at),
        attachments: e
            .attachments
            .iter()
            .map(|a| core::AttachmentInfo { name: a.name.clone(), size: a.size })
            .collect(),
        history_count: e.history_count,
        quality_check: e.quality_check,
    }
}

pub(crate) fn autofill_edits(e: core::AutoFillEdits) -> ffi::AutoFillEdits {
    ffi::AutoFillEdits {
        vault_id: e.vault_id,
        entries: e
            .entries
            .into_iter()
            .map(|a| ffi::AutoFillEdit { entry: entry_record(a.entry), group_path: a.group_path })
            .collect(),
        version: e.version,
    }
}

pub(crate) fn autofill_edits_in(e: &ffi::AutoFillEdits) -> core::AutoFillEdits {
    core::AutoFillEdits {
        vault_id: e.vault_id.clone(),
        entries: e
            .entries
            .iter()
            .map(|a| core::AutoFillEdit { entry: entry_record_in(&a.entry), group_path: a.group_path.clone() })
            .collect(),
        version: e.version.clone(),
    }
}

pub(crate) fn opt_autofill_edits(e: Option<core::AutoFillEdits>) -> ffi::OptionalAutoFillEdits {
    ffi::OptionalAutoFillEdits { has: e.is_some(), value: e.map(autofill_edits).unwrap_or_default() }
}

pub(crate) fn field_input(f: ffi::FieldInput) -> core::FieldInput {
    core::FieldInput { name: f.name, value: f.value, protected: f.has_protected.then_some(f.is_protected) }
}

fn entry_expiry_in(e: ffi::EntryExpiry) -> Result<core::EntryExpiry, OvError> {
    Ok(match e.kind {
        ffi::ExpiryKind::Keep => core::EntryExpiry::Keep,
        ffi::ExpiryKind::Never => core::EntryExpiry::Never,
        ffi::ExpiryKind::At => core::EntryExpiry::At(e.at),
        other => return Err(bad_enum("ExpiryKind", other.repr)),
    })
}

pub(crate) fn entry_input(e: ffi::EntryInput) -> Result<core::EntryInput, OvError> {
    Ok(core::EntryInput {
        expiry: entry_expiry_in(e.expiry)?,
        fields: e.fields.into_iter().map(field_input).collect(),
        remove_fields: e.remove_fields,
        tags: e.has_tags.then_some(e.tags),
        icon_id: e.has_icon_id.then_some(e.icon_id),
    })
}

pub(crate) fn set_fields_result(r: core::SetFieldsResult) -> ffi::SetFieldsResult {
    ffi::SetFieldsResult { entry: entry_record(r.entry), created: r.created }
}

/// `None` (every group) for an empty list.
pub(crate) fn group_ids(ids: Vec<String>) -> Option<Vec<String>> {
    (!ids.is_empty()).then_some(ids)
}

// ------------------------------------------------------------------------- sharing and orgs

pub(crate) fn vault_member(m: core::VaultMember) -> ffi::VaultMember {
    ffi::VaultMember {
        principal: m.principal,
        role: vault_role(m.role),
        display: m.display,
        key_version: m.key_version,
        is_you: m.is_you,
    }
}

pub(crate) fn share_recipient(r: core::ShareRecipient) -> ffi::ShareRecipient {
    ffi::ShareRecipient {
        principal: r.principal,
        email: opt(r.email),
        name: opt(r.name),
        public_keys: public_keys(r.public_keys),
    }
}

pub(crate) fn grantee_in(g: &ffi::Grantee) -> Result<core::Grantee, OvError> {
    Ok(match g.kind {
        ffi::GranteeKind::Email => core::Grantee::Email(g.value.clone()),
        ffi::GranteeKind::Principal => core::Grantee::Principal(g.value.clone()),
        other => return Err(bad_enum("GranteeKind", other.repr)),
    })
}

pub(crate) fn grant_result(g: core::GrantResult) -> ffi::GrantResult {
    ffi::GrantResult { principal: g.principal, fingerprint: g.fingerprint }
}

pub(crate) fn grant_requests_in(v: Vec<ffi::VaultGrantRequest>) -> Result<Vec<core::VaultGrantRequest>, OvError> {
    v.into_iter().map(|g| Ok(core::VaultGrantRequest { vault_id: g.vault_id, role: vault_role_in(g.role)? })).collect()
}

pub(crate) fn org(o: core::Org) -> ffi::Org {
    let (has_item_share_links, item_share_links) = policy_or_default(o.item_share_links);
    ffi::Org {
        id: o.id,
        name: o.name,
        role: org_role(o.role),
        has_plan: o.plan.is_some(),
        plan: o.plan.map(plan).unwrap_or_default(),
        has_item_share_links,
        item_share_links,
        created_at: o.created_at,
    }
}

pub(crate) fn member(m: core::Member) -> ffi::Member {
    ffi::Member {
        user_id: m.user_id,
        email: m.email,
        name: opt(m.name),
        role: org_role(m.role),
        status: member_status(m.status),
        has_public_keys: m.public_keys.is_some(),
        public_keys: m.public_keys.map(public_keys).unwrap_or_default(),
    }
}

pub(crate) fn member_in(m: &ffi::Member) -> Result<core::Member, OvError> {
    Ok(core::Member {
        user_id: m.user_id.clone(),
        email: m.email.clone(),
        name: some(&m.name),
        role: org_role_in(m.role)?,
        status: member_status_in(m.status)?,
        public_keys: m.has_public_keys.then(|| public_keys_in(&m.public_keys)),
    })
}

pub(crate) fn invitation(i: core::Invitation) -> ffi::Invitation {
    ffi::Invitation {
        id: i.id,
        email: i.email,
        role: org_role(i.role),
        expires_at: i.expires_at,
        invited_by: i.invited_by,
    }
}

pub(crate) fn rotation_report(r: core::RotationReport) -> ffi::RotationReport {
    ffi::RotationReport {
        rotated: r.rotated,
        failed: r
            .failed
            .into_iter()
            .map(|f| ffi::RotationFailure { vault_id: f.vault_id, error: error_info(&f.error) })
            .collect(),
    }
}

pub(crate) fn audit_page(p: core::AuditPage) -> ffi::AuditPage {
    ffi::AuditPage {
        events: p
            .events
            .into_iter()
            .map(|e| ffi::AuditEvent {
                id: e.id,
                at: e.at,
                actor: e.actor,
                action: e.action,
                target: opt(e.target),
                ip: opt(e.ip),
                details: opt(e.details),
            })
            .collect(),
        next: opt(p.next),
    }
}

// ------------------------------------------------------------------------ service accounts

pub(crate) fn service_account_info(s: core::ServiceAccountInfo) -> ffi::ServiceAccountInfo {
    ffi::ServiceAccountInfo {
        id: s.id,
        org_id: s.org_id,
        name: s.name,
        has_public_keys: s.public_keys.is_some(),
        public_keys: s.public_keys.map(public_keys).unwrap_or_default(),
        created_by: opt(s.created_by),
        created_at: opt(s.created_at),
        expires_at: opt(s.expires_at),
        disabled: s.disabled,
    }
}

pub(crate) fn new_service_account_in(n: &ffi::NewServiceAccount) -> Result<core::NewServiceAccount, OvError> {
    Ok(core::NewServiceAccount {
        name: n.name.clone(),
        vaults: grant_requests_in(n.vaults.clone())?,
        expires_at: some(&n.expires_at),
        secret_name: some(&n.secret_name),
    })
}

pub(crate) fn created_service_account(c: core::CreatedServiceAccount) -> ffi::CreatedServiceAccount {
    ffi::CreatedServiceAccount { service_account: service_account_info(c.service_account), token: c.token }
}

pub(crate) fn issued_secret(s: core::IssuedSecret) -> ffi::IssuedSecret {
    ffi::IssuedSecret { token: s.token, id: s.id, prefix: s.prefix }
}

pub(crate) fn sa_secret_info(s: core::SaSecretInfo) -> ffi::SaSecretInfo {
    ffi::SaSecretInfo {
        id: s.id,
        prefix: s.prefix,
        name: opt(s.name),
        created_at: s.created_at,
        last_used_at: opt(s.last_used_at),
        expires_at: opt(s.expires_at),
    }
}

pub(crate) fn expiry_change_in(e: &ffi::ExpiryChange) -> Result<core::ExpiryChange, OvError> {
    Ok(match e.kind {
        ffi::ExpiryKind::Keep => core::ExpiryChange::Keep,
        ffi::ExpiryKind::Never => core::ExpiryChange::Never,
        ffi::ExpiryKind::At => core::ExpiryChange::At(e.at.clone()),
        other => return Err(bad_enum("ExpiryKind", other.repr)),
    })
}

pub(crate) fn service_account_update_in(u: &ffi::ServiceAccountUpdate) -> Result<core::ServiceAccountUpdate, OvError> {
    Ok(core::ServiceAccountUpdate {
        name: some(&u.name),
        expires_at: expiry_change_in(&u.expires_at)?,
        disabled: u.has_disabled.then_some(u.disabled),
    })
}

pub(crate) fn sa_vault(v: core::SaVault) -> ffi::SaVault {
    ffi::SaVault { id: v.id, name: v.name, role: vault_role(v.role) }
}

pub(crate) fn injected(i: core::Injected) -> ffi::Injected {
    ffi::Injected { text: i.text, secrets: i.secrets.into_iter().map(|value| ffi::Bytes { value }).collect() }
}

pub(crate) fn pairing_code(p: core::PairingCode) -> ffi::PairingCode {
    ffi::PairingCode { code: p.code, expires_at: p.expires_at }
}

pub(crate) fn self_hosted_sync_result(r: core::SelfHostedSyncResult) -> ffi::SelfHostedSyncResult {
    ffi::SelfHostedSyncResult { kdbx: r.kdbx, report: sync_report(r.report) }
}

// ------------------------------------------------------------------------------ share links

pub(crate) fn share_options_in(o: ffi::ShareOptions) -> core::ShareOptions {
    core::ShareOptions {
        expires_in: o.expires_in,
        max_opens: o.has_max_opens.then_some(o.max_opens),
        passcode: o.has_passcode.then_some(o.passcode),
        vault_id: some(&o.vault_id),
        entry_id: some(&o.entry_id),
    }
}

pub(crate) fn created_share(c: core::CreatedShare) -> ffi::CreatedShare {
    ffi::CreatedShare { id: c.id, url: c.url, expires_at: c.expires_at }
}

pub(crate) fn share_listing(s: core::ShareListing) -> ffi::ShareListing {
    ffi::ShareListing {
        id: s.id,
        vault_id: opt(s.vault_id),
        has_reference: s.reference.is_some(),
        reference: s
            .reference
            .map(|r| ffi::ShareRef { vault: opt(r.vault), entry: opt(r.entry), title: r.title })
            .unwrap_or_default(),
        passcode: s.passcode,
        has_max_opens: s.max_opens.is_some(),
        max_opens: s.max_opens.unwrap_or(0),
        opens: s.opens,
        opened_at: s.opened_at,
        created_at: s.created_at,
        expires_at: s.expires_at,
        status: s.status,
        ended_at: opt(s.ended_at),
        end_reason: opt(s.end_reason),
    }
}

pub(crate) fn share_payload(p: core::SharePayload) -> ffi::SharePayload {
    ffi::SharePayload {
        v: p.v,
        kind: p.kind,
        title: opt(p.title),
        shared_by: opt(p.shared_by),
        fields: p
            .fields
            .into_iter()
            .map(|f| ffi::ShareField { k: f.k, label: f.label, value: f.value, is_protected: f.protected })
            .collect(),
    }
}

pub(crate) fn share_payload_in(p: ffi::SharePayload) -> core::SharePayload {
    core::SharePayload {
        v: p.v,
        kind: p.kind,
        title: some(&p.title),
        shared_by: some(&p.shared_by),
        fields: p
            .fields
            .into_iter()
            .map(|f| core::ShareField { k: f.k, label: f.label, value: f.value, protected: f.is_protected })
            .collect(),
    }
}

pub(crate) fn shareable_field(f: core::ShareableField) -> ffi::ShareableField {
    ffi::ShareableField { name: f.name, kind: f.kind, label: f.label, value: f.value, is_protected: f.protected }
}

pub(crate) fn share_info(i: core::ShareInfo) -> ffi::ShareInfo {
    ffi::ShareInfo {
        expires_at: i.expires_at,
        has_opens_left: i.opens_left.is_some(),
        opens_left: i.opens_left.unwrap_or(0),
        has_kdf: i.kdf.is_some(),
        kdf: i.kdf.map(kdf_params).unwrap_or_default(),
    }
}

pub(crate) fn share_info_in(i: &ffi::ShareInfo) -> core::ShareInfo {
    core::ShareInfo {
        expires_at: i.expires_at.clone(),
        opens_left: i.has_opens_left.then_some(i.opens_left),
        kdf: i.has_kdf.then(|| kdf_params_in(&i.kdf)),
    }
}

pub(crate) fn opened_share(o: core::OpenedShare) -> ffi::OpenedShare {
    ffi::OpenedShare {
        payload: share_payload(o.payload),
        has_opens_left: o.opens_left.is_some(),
        opens_left: o.opens_left.unwrap_or(0),
    }
}

// ------------------------------------------------------------------------------------- TOTP

pub(crate) fn totp_params(p: core::TotpParams) -> ffi::TotpParams {
    ffi::TotpParams {
        secret: p.secret,
        digits: p.digits,
        period: p.period,
        algorithm: totp_algorithm(p.algorithm),
        encoder: opt(p.encoder),
    }
}

pub(crate) fn totp_params_in(p: ffi::TotpParams) -> Result<core::TotpParams, OvError> {
    Ok(core::TotpParams {
        algorithm: totp_algorithm_in(p.algorithm)?,
        encoder: some(&p.encoder),
        secret: p.secret,
        digits: p.digits,
        period: p.period,
    })
}

pub(crate) fn totp_code(c: core::TotpCode) -> ffi::TotpCode {
    ffi::TotpCode { code: c.code, remaining: c.remaining }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> core::EntryRecord {
        core::EntryRecord {
            id: "a".repeat(32),
            group_id: "b".repeat(32),
            group_path: vec!["Work".into()],
            fields: vec![core::FieldRecord { name: "Password".into(), value: b"pw".to_vec(), protected: true }],
            tags: vec!["t".into()],
            icon_id: 3,
            custom_icon: None,
            foreground_color: String::new(),
            background_color: "#ffffff".into(),
            override_url: String::new(),
            created_at: 1,
            modified_at: 2,
            expires_at: Some(9),
            attachments: vec![core::AttachmentInfo { name: "f".into(), size: 4 }],
            history_count: 1,
            quality_check: true,
        }
    }

    #[test]
    fn entries_round_trip() {
        let e = entry();
        assert_eq!(entry_record_in(&entry_record(e.clone())), e);
        let edits = core::AutoFillEdits {
            vault_id: "v".into(),
            entries: vec![core::AutoFillEdit { entry: e, group_path: "Work".into() }],
            version: "7".into(),
        };
        assert_eq!(autofill_edits_in(&autofill_edits(edits.clone())), edits);
    }

    #[test]
    fn plans_round_trip() {
        let p = core::Plan {
            id: Some("premium".into()),
            limits: vec![
                core::PlanLimit { name: "members".into(), value: Some(6) },
                core::PlanLimit { name: "vault_bytes".into(), value: None },
            ],
            billing: Some(core::Billing {
                source: "stripe".into(),
                interval: "year".into(),
                status: "active".into(),
                renews_at: Some("2027-01-01T00:00:00Z".into()),
                ends_at: None,
                manage: "https://x".into(),
            }),
        };
        assert_eq!(plan_in(&plan(p.clone())), p);
        assert_eq!(plan_in(&plan(core::Plan { id: None, limits: vec![], billing: None })).billing, None);
    }

    #[test]
    fn share_records_round_trip() {
        let info = core::ShareInfo {
            expires_at: "2026-12-01T00:00:00Z".into(),
            opens_left: Some(2),
            kdf: Some(core::KdfParams { alg: "argon2id".into(), salt: "s".into(), m: 1, t: 2, p: 3 }),
        };
        assert_eq!(share_info_in(&share_info(info.clone())), info);
        let payload = core::SharePayload {
            v: 1,
            kind: "entry".into(),
            title: Some("T".into()),
            shared_by: None,
            fields: vec![core::ShareField {
                k: "password".into(),
                label: "Password".into(),
                value: b"x".to_vec(),
                protected: true,
            }],
        };
        assert_eq!(share_payload_in(share_payload(payload.clone())), payload);
    }

    #[test]
    fn flattened_inputs_map() {
        let m = ffi::ImportMode {
            kind: ffi::ImportModeKind::NewVault,
            name: String::new(),
            org_id: "o".into(),
            vault_id: String::new(),
        };
        assert_eq!(import_mode_in(&m).unwrap(), core::ImportMode::NewVault { name: None, org_id: Some("o".into()) });
        let bad = ffi::ImportMode { kind: ffi::ImportModeKind { repr: 9 }, ..m };
        assert_eq!(import_mode_in(&bad).unwrap_err().code, OvErrorCode::InvalidRequest);

        let input = ffi::EntryInput {
            fields: vec![ffi::FieldInput {
                name: "password".into(),
                value: b"v".to_vec(),
                has_protected: false,
                is_protected: false,
            }],
            remove_fields: vec![],
            has_tags: false,
            tags: vec!["ignored".into()],
            has_icon_id: true,
            icon_id: 4,
            expiry: ffi::EntryExpiry { kind: ffi::ExpiryKind::At, at: 99 },
        };
        let core_input = entry_input(input).unwrap();
        assert_eq!(core_input.fields[0].protected, None);
        assert_eq!(
            (core_input.tags, core_input.icon_id, core_input.expiry),
            (None, Some(4), core::EntryExpiry::At(99))
        );

        assert_eq!(kdf_overrides_in(ffi::KdfOverrides::default()), None);
        let k = ffi::KdfOverrides { has_t: true, t: 4, ..Default::default() };
        assert_eq!(kdf_overrides_in(k), Some(core::KdfOverrides { m: None, t: Some(4), p: None }));

        assert_eq!(vault_role_in(ffi::VaultRole { repr: 77 }).unwrap_err().code, OvErrorCode::InvalidRequest);
        assert_eq!(org_role_in(ffi::OrgRole::Admin).unwrap(), core::OrgRole::Admin);
    }

    #[test]
    fn errors_round_trip_through_info() {
        let e = OvError::from_server(402, Some("plan_limit"), "limit").with_details(r#"{"upgradeUrl":"x"}"#);
        let back = error_from_info(&error_info(&e));
        assert_eq!(back.code, e.code);
        assert_eq!(back.details, e.details);
        assert_eq!(back.status, Some(402));
        let custom = OvError::from_server(409, Some("deletion_blocked"), "orgs");
        let back = error_from_info(&error_info(&custom));
        assert_eq!(back.wire_code(), "deletion_blocked");
    }
}
