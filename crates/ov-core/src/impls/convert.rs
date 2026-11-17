//! Conversions between the wire types (`ov_protocol::types`), the domain crates' types and the
//! facade records (`crate::api`).

use ov_crypto::keyset::{PublicKeys as CryptoPublicKeys, WrappedKeysetJson};
use ov_protocol::discovery::OpenVireoConfiguration;
use ov_protocol::types as w;

use super::util::internal;
use crate::api::{self as a};
use ov_error::OvError;

// ------------------------------------------------------------------------------- discovery

pub(crate) fn server_config(c: &OpenVireoConfiguration) -> a::ServerConfig {
    a::ServerConfig {
        issuer: c.issuer.clone(),
        api: c.api.clone(),
        sync: c.sync.clone(),
        jwks_uri: c.jwks_uri.clone(),
        opaque: a::OpaqueConfig {
            lib: c.opaque.lib.clone(),
            version: c.opaque.version.clone(),
            context: c.opaque.context.clone(),
            ids: c.opaque.ids.clone(),
        },
        kdf_min: c.kdf_min.as_ref().map(|k| a::KdfMin { m: k.m, t: k.t }),
        web: c.web.clone(),
        share: c.share.clone(),
    }
}

pub(crate) fn wire_config(c: &a::ServerConfig) -> OpenVireoConfiguration {
    OpenVireoConfiguration {
        issuer: c.issuer.clone(),
        api: c.api.clone(),
        sync: c.sync.clone(),
        jwks_uri: c.jwks_uri.clone(),
        opaque: ov_protocol::discovery::OpaqueConfig {
            lib: c.opaque.lib.clone(),
            version: c.opaque.version.clone(),
            context: c.opaque.context.clone(),
            ids: c.opaque.ids.clone(),
        },
        kdf_min: c.kdf_min.map(|k| ov_protocol::discovery::KdfMin { m: k.m, t: k.t }),
        web: c.web.clone(),
        share: c.share.clone(),
    }
}

// ----------------------------------------------------------------------------------- crypto

pub(crate) fn kdf_min(c: &a::ServerConfig) -> ov_crypto::auk::KdfMin {
    // The stricter of the server's floor and the SPEC §3 minimum.
    let base = ov_crypto::auk::KDF_MIN;
    match c.kdf_min {
        Some(k) => ov_crypto::auk::KdfMin { m: k.m.max(base.m), t: k.t.max(base.t) },
        None => base,
    }
}

pub(crate) fn crypto_kdf(k: &w::Kdf) -> ov_crypto::auk::KdfParams {
    ov_crypto::auk::KdfParams { alg: k.alg.clone(), salt: k.salt.clone(), m: k.m, t: k.t, p: k.p }
}

pub(crate) fn wire_kdf(k: &ov_crypto::auk::KdfParams) -> w::Kdf {
    w::Kdf { alg: k.alg.clone(), salt: k.salt.clone(), m: k.m, t: k.t, p: k.p }
}

pub(crate) fn api_kdf(k: &w::Kdf) -> a::KdfParams {
    a::KdfParams { alg: k.alg.clone(), salt: k.salt.clone(), m: k.m, t: k.t, p: k.p }
}

pub(crate) fn crypto_wrapped(k: &w::WrappedKeyset) -> WrappedKeysetJson {
    WrappedKeysetJson {
        enc_pk: k.enc_pk.clone(),
        sign_pk: k.sign_pk.clone(),
        sig: k.sig.clone(),
        wrapped: k.wrapped.clone(),
    }
}

pub(crate) fn wire_wrapped(k: &WrappedKeysetJson) -> w::WrappedKeyset {
    w::WrappedKeyset {
        enc_pk: k.enc_pk.clone(),
        sign_pk: k.sign_pk.clone(),
        sig: k.sig.clone(),
        wrapped: k.wrapped.clone(),
    }
}

pub(crate) fn crypto_public_json(k: &w::PublicKeys) -> ov_crypto::keyset::PublicKeysJson {
    ov_crypto::keyset::PublicKeysJson { enc_pk: k.enc_pk.clone(), sign_pk: k.sign_pk.clone(), sig: k.sig.clone() }
}

pub(crate) fn api_public_keys(k: &CryptoPublicKeys) -> a::PublicKeys {
    a::PublicKeys {
        enc_pk: k.enc_pk.to_vec(),
        sign_pk: k.sign_pk.to_vec(),
        sig: k.sig.to_vec(),
        fingerprint: k.fingerprint(),
    }
}

/// Public keys as the server sent them, signature not checked (a member before confirmation).
pub(crate) fn api_public_keys_unchecked(k: &w::PublicKeys) -> Option<a::PublicKeys> {
    CryptoPublicKeys::from_json(&crypto_public_json(k)).ok().map(|p| api_public_keys(&p))
}

// ------------------------------------------------------------------------------------ enums

pub(crate) fn vault_role(r: &w::VaultRole) -> a::VaultRole {
    match r {
        w::VaultRole::Manage => a::VaultRole::Manage,
        w::VaultRole::Write => a::VaultRole::Write,
        _ => a::VaultRole::Read,
    }
}

pub(crate) fn wire_vault_role(r: a::VaultRole) -> w::VaultRole {
    match r {
        a::VaultRole::Read => w::VaultRole::Read,
        a::VaultRole::Write => w::VaultRole::Write,
        a::VaultRole::Manage => w::VaultRole::Manage,
    }
}

pub(crate) fn org_role(r: &w::OrgRole) -> a::OrgRole {
    match r {
        w::OrgRole::Owner => a::OrgRole::Owner,
        w::OrgRole::Admin => a::OrgRole::Admin,
        _ => a::OrgRole::Member,
    }
}

pub(crate) fn wire_org_role(r: a::OrgRole) -> w::OrgRole {
    match r {
        a::OrgRole::Owner => w::OrgRole::Owner,
        a::OrgRole::Admin => w::OrgRole::Admin,
        a::OrgRole::Member => w::OrgRole::Member,
    }
}

pub(crate) fn member_status(s: &w::MemberStatus) -> a::MemberStatus {
    match s {
        w::MemberStatus::Confirmed => a::MemberStatus::Confirmed,
        w::MemberStatus::Accepted => a::MemberStatus::Accepted,
        _ => a::MemberStatus::Invited,
    }
}

pub(crate) fn share_policy(p: &w::ShareLinkPolicy) -> a::ShareLinkPolicy {
    match p {
        w::ShareLinkPolicy::Off => a::ShareLinkPolicy::Off,
        w::ShareLinkPolicy::Managers => a::ShareLinkPolicy::Managers,
        _ => a::ShareLinkPolicy::On,
    }
}

pub(crate) fn wire_share_policy(p: a::ShareLinkPolicy) -> w::ShareLinkPolicy {
    match p {
        a::ShareLinkPolicy::On => w::ShareLinkPolicy::On,
        a::ShareLinkPolicy::Managers => w::ShareLinkPolicy::Managers,
        a::ShareLinkPolicy::Off => w::ShareLinkPolicy::Off,
    }
}

// ------------------------------------------------------------------------------- account

pub(crate) fn plan(p: &w::Plan) -> a::Plan {
    a::Plan {
        id: p.id.clone(),
        limits: p.limits.iter().map(|(k, v)| a::PlanLimit { name: k.clone(), value: *v }).collect(),
        billing: p.billing.as_ref().map(|b| a::Billing {
            source: b.source.clone(),
            interval: b.interval.clone(),
            status: b.status.clone(),
            renews_at: b.renews_at.clone(),
            ends_at: b.ends_at.clone(),
            manage: b.manage.clone(),
        }),
    }
}

pub(crate) fn org_membership(o: &w::MeOrg) -> a::OrgMembership {
    a::OrgMembership {
        id: o.id.clone(),
        name: o.name.clone(),
        role: org_role(&o.role),
        status: member_status(&o.status),
        plan: o.plan.as_ref().map(plan),
        item_share_links: o.item_share_links.as_ref().map(share_policy),
    }
}

pub(crate) fn profile(m: &w::Me) -> a::Profile {
    a::Profile {
        id: m.id.clone(),
        email: m.email.clone(),
        name: m.name.clone(),
        totp_enabled: m.mfa.totp.unwrap_or(false),
        plan: m.plan.as_ref().map(plan),
        orgs: m.orgs.iter().flatten().map(org_membership).collect(),
        deletion_scheduled_for: m.deletion_scheduled_for.clone(),
    }
}

pub(crate) fn device(d: &w::Device) -> a::Device {
    a::Device {
        id: d.id.clone(),
        name: d.name.clone(),
        platform: d.platform.as_str().to_owned(),
        created_at: d.created_at.clone(),
        last_seen_at: d.last_seen_at.clone(),
        current: d.current,
    }
}

pub(crate) fn wire_platform(p: a::Platform) -> w::Platform {
    w::Platform::from(p.as_str())
}

pub(crate) fn recovery_reset(r: &w::RecoveryReset) -> a::RecoveryReset {
    a::RecoveryReset {
        email: r.email.clone(),
        not_before: r.not_before.clone(),
        expires_at: r.expires_at.clone(),
        archive_days: r.archive_days.unwrap_or(30).clamp(0, u32::MAX as i64) as u32,
        personal_vaults: r.archives.personal_vaults.unwrap_or(0).max(0) as u32,
        shared_grants: r.archives.shared_grants.unwrap_or(0).max(0) as u32,
        sole_admin_orgs: r.archives.sole_admin_orgs.clone().unwrap_or_default(),
    }
}

pub(crate) fn recovery_status(r: &w::RecoveryArchive) -> a::RecoveryStatus {
    a::RecoveryStatus {
        archived: r.archived,
        email: r.email.clone(),
        expires_at: r.expires_at.clone(),
        vaults: r.vaults.map(|v| v.max(0) as u32),
        locked: r.locked.unwrap_or(false),
    }
}

pub(crate) fn deletion_outcome(o: &w::DeletionOutcome) -> a::DeletionOutcome {
    match o {
        w::DeletionOutcome::Delete => a::DeletionOutcome::Delete,
        w::DeletionOutcome::Blocked => a::DeletionOutcome::Blocked,
        _ => a::DeletionOutcome::Leave,
    }
}

// --------------------------------------------------------------------------------- orgs

pub(crate) fn org(o: &w::Org) -> a::Org {
    a::Org {
        id: o.id.clone(),
        name: o.name.clone(),
        role: org_role(&o.role),
        plan: o.plan.as_ref().map(plan),
        item_share_links: o.item_share_links.as_ref().map(share_policy),
        created_at: o.created_at.clone(),
    }
}

pub(crate) fn member(m: &w::Member) -> a::Member {
    a::Member {
        user_id: m.user_id.clone(),
        email: m.email.clone(),
        name: m.name.clone(),
        role: org_role(&m.role),
        status: member_status(&m.status),
        public_keys: m.public.as_ref().and_then(api_public_keys_unchecked),
    }
}

pub(crate) fn invitation(i: &w::Invitation) -> a::Invitation {
    a::Invitation {
        id: i.id.clone(),
        email: i.email.clone(),
        role: org_role(&i.role),
        expires_at: i.expires_at.clone(),
        invited_by: i.invited_by.clone(),
    }
}

pub(crate) fn service_account(s: &w::ServiceAccount) -> a::ServiceAccountInfo {
    a::ServiceAccountInfo {
        id: s.id.clone(),
        org_id: s.org_id.clone(),
        name: s.name.clone(),
        public_keys: s.public.as_ref().and_then(api_public_keys_unchecked),
        created_by: s.created_by.clone(),
        created_at: s.created_at.clone(),
        expires_at: s.expires_at.clone(),
        disabled: s.disabled.unwrap_or(false),
    }
}

pub(crate) fn sa_secret(s: &w::SaSecret) -> a::SaSecretInfo {
    a::SaSecretInfo {
        id: s.id.clone(),
        prefix: s.prefix.clone(),
        name: s.name.clone(),
        created_at: s.created_at.clone(),
        last_used_at: s.last_used_at.clone(),
        expires_at: s.expires_at.clone(),
    }
}

pub(crate) fn audit_page(p: &w::AuditPage) -> a::AuditPage {
    a::AuditPage {
        events: p
            .events
            .iter()
            .map(|e| a::AuditEvent {
                id: e.id.clone(),
                at: e.at.clone(),
                actor: e.actor.clone(),
                action: e.action.clone(),
                target: e.target.clone(),
                ip: e.ip.clone(),
                details: e.details.as_ref().map(|d| serde_json::Value::Object(d.clone()).to_string()),
            })
            .collect(),
        next: p.next.clone(),
    }
}

// --------------------------------------------------------------------------------- sync

pub(crate) fn blob_meta(b: &w::BlobMeta) -> a::BlobMeta {
    a::BlobMeta {
        id: b.id.clone(),
        etag: b.etag.clone(),
        revision: b.revision.max(0) as u64,
        size: b.size,
        updated_at: b.updated_at.clone(),
    }
}

/// An entry or group UUID as 32 lowercase hex digits.
pub(crate) fn uuid_hex(u: &ov_kdbx::model::Uuid) -> String {
    u.simple().to_string()
}

/// `ov_merge` change records → facade records (W1-M follow-up).
pub(crate) fn merge_change(c: &ov_merge::MergeChange) -> a::MergeChange {
    a::MergeChange {
        change: match c.change {
            ov_merge::ChangeType::Added => a::ChangeType::Added,
            ov_merge::ChangeType::Modified => a::ChangeType::Modified,
            ov_merge::ChangeType::Moved => a::ChangeType::Moved,
            ov_merge::ChangeType::Deleted => a::ChangeType::Deleted,
            ov_merge::ChangeType::Metadata => a::ChangeType::Metadata,
        },
        uuid: c.uuid.as_ref().map(uuid_hex),
        title: c.title.clone(),
        group: c.group.clone(),
        details: c.details.clone(),
    }
}

/// `ov_merge::SyncConflict` → facade record.
pub(crate) fn sync_conflict(c: &ov_merge::SyncConflict) -> a::SyncConflict {
    a::SyncConflict {
        uuid: uuid_hex(&c.uuid),
        kind: match c.kind {
            ov_merge::ConflictKind::EditedOnBoth => a::ConflictKind::EditedOnBoth,
            ov_merge::ConflictKind::DeletedHereEditedThere => a::ConflictKind::DeletedHereEditedThere,
            ov_merge::ConflictKind::EditedHereDeletedThere => a::ConflictKind::EditedHereDeletedThere,
        },
        title: c.title.clone(),
        fields: c.fields.clone(),
    }
}

/// Parses JSON we stored ourselves; `internal` when it is damaged.
pub(crate) fn from_stored<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, OvError> {
    serde_json::from_slice(bytes).map_err(|_| internal(format!("the stored {what} can't be read")))
}
