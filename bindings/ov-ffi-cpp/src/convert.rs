//! Conversions between the core's records and the bridge's flat shared structs.
//!
//! `Option<String>` crosses as an empty string, other options as a `has_*` flag plus a value.
//! Shared enums coming from C++ can hold any integer, so those conversions reject unknown values.

use ov_core::api as core;
use ov_core::host as h;
use ov_error::OvError;

use crate::ffi;

fn opt_string(s: Option<String>) -> String {
    s.unwrap_or_default()
}

fn string_opt(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn bad_enum(what: &str, repr: impl std::fmt::Debug) -> OvError {
    OvError::new(ov_error::OvErrorCode::InvalidRequest, format!("unknown {what} value {repr:?}"))
}

// ------------------------------------------------------------------------------------ host

pub(crate) fn http_request(r: h::HttpRequest) -> ffi::HttpRequest {
    ffi::HttpRequest {
        method: match r.method {
            h::Method::Get => ffi::Method::Get,
            h::Method::Head => ffi::Method::Head,
            h::Method::Post => ffi::Method::Post,
            h::Method::Put => ffi::Method::Put,
            h::Method::Patch => ffi::Method::Patch,
            h::Method::Delete => ffi::Method::Delete,
        },
        url: r.url,
        headers: r.headers.into_iter().map(|(name, value)| ffi::Header { name, value }).collect(),
        has_body: r.body.is_some(),
        body: r.body.unwrap_or_default(),
        keepalive: r.keepalive,
    }
}

pub(crate) fn http_response(r: ffi::HttpResponse) -> h::HttpResponse {
    h::HttpResponse {
        status: r.status,
        headers: r.headers.into_iter().map(|hd| (hd.name, hd.value)).collect(),
        body: r.body,
    }
}

pub(crate) fn no_failure() -> ffi::TransportFailure {
    ffi::TransportFailure { kind: ffi::TransportErrorKind::None, message: String::new() }
}

/// `None` when the C++ side reported no failure.
pub(crate) fn transport_error(f: ffi::TransportFailure) -> Option<h::TransportError> {
    Some(match f.kind {
        ffi::TransportErrorKind::None => return None,
        ffi::TransportErrorKind::Offline => h::TransportError::Offline,
        ffi::TransportErrorKind::Timeout => h::TransportError::Timeout,
        ffi::TransportErrorKind::Tls => h::TransportError::Tls(f.message),
        ffi::TransportErrorKind::Cancelled => h::TransportError::Cancelled,
        ffi::TransportErrorKind::Other => h::TransportError::Other(f.message),
        other => h::TransportError::Other(format!("unknown transport error kind {}: {}", other.repr, f.message)),
    })
}

pub(crate) fn cached_vault_to_ffi(v: &h::CachedVault) -> ffi::CachedVault {
    ffi::CachedVault {
        state: v.state.clone(),
        has_base: v.base.is_some(),
        base: v.base.clone().unwrap_or_default(),
        has_pending: v.pending.is_some(),
        pending: v.pending.clone().unwrap_or_default(),
        has_autofill: v.autofill.is_some(),
        autofill: v.autofill.clone().unwrap_or_default(),
    }
}

pub(crate) fn cached_vault_from_ffi(v: ffi::CachedVault) -> h::CachedVault {
    h::CachedVault {
        state: v.state,
        base: v.has_base.then_some(v.base),
        pending: v.has_pending.then_some(v.pending),
        autofill: v.has_autofill.then_some(v.autofill),
    }
}

pub(crate) fn level(l: h::Level) -> ffi::LogLevel {
    match l {
        h::Level::Error => ffi::LogLevel::Error,
        h::Level::Warn => ffi::LogLevel::Warn,
        h::Level::Info => ffi::LogLevel::Info,
        h::Level::Debug => ffi::LogLevel::Debug,
        h::Level::Trace => ffi::LogLevel::Trace,
    }
}

// ---------------------------------------------------------------------------------- facade

pub(crate) fn server_config_to_ffi(c: core::ServerConfig) -> ffi::ServerConfig {
    ffi::ServerConfig {
        issuer: c.issuer,
        api: c.api,
        sync: c.sync,
        jwks_uri: c.jwks_uri,
        opaque_lib: c.opaque.lib,
        opaque_version: c.opaque.version,
        opaque_context: c.opaque.context,
        opaque_ids: c.opaque.ids,
        has_kdf_min: c.kdf_min.is_some(),
        kdf_min_m: c.kdf_min.map_or(0, |k| k.m),
        kdf_min_t: c.kdf_min.map_or(0, |k| k.t),
        web: opt_string(c.web),
        share: opt_string(c.share),
    }
}

pub(crate) fn server_config_from_ffi(c: &ffi::ServerConfig) -> core::ServerConfig {
    core::ServerConfig {
        issuer: c.issuer.clone(),
        api: c.api.clone(),
        sync: c.sync.clone(),
        jwks_uri: c.jwks_uri.clone(),
        opaque: core::OpaqueConfig {
            lib: c.opaque_lib.clone(),
            version: c.opaque_version.clone(),
            context: c.opaque_context.clone(),
            ids: c.opaque_ids.clone(),
        },
        kdf_min: c.has_kdf_min.then_some(core::KdfMin { m: c.kdf_min_m, t: c.kdf_min_t }),
        web: string_opt(&c.web),
        share: string_opt(&c.share),
    }
}

pub(crate) fn client_config(c: &ffi::ClientConfig) -> Result<core::ClientConfig, OvError> {
    let platform = match c.platform {
        ffi::Platform::QtLinux => core::Platform::QtLinux,
        ffi::Platform::QtMacos => core::Platform::QtMacos,
        ffi::Platform::QtWindows => core::Platform::QtWindows,
        ffi::Platform::Web => core::Platform::Web,
        ffi::Platform::Cli => core::Platform::Cli,
        ffi::Platform::Connect => core::Platform::Connect,
        ffi::Platform::Ios => core::Platform::Ios,
        ffi::Platform::Android => core::Platform::Android,
        other => return Err(bad_enum("Platform", other.repr)),
    };
    Ok(core::ClientConfig {
        device: core::DeviceInfo { id: string_opt(&c.device_id), name: c.device_name.clone(), platform },
        offline: c.offline,
        server: c.has_server.then(|| server_config_from_ffi(&c.server)),
    })
}

pub(crate) fn remembered_account(a: core::RememberedAccount) -> ffi::RememberedAccount {
    ffi::RememberedAccount {
        email: a.email,
        issuer: a.issuer,
        user_id: a.user_id,
        last_used_at: a.last_used_at,
        checked_at: opt_string(a.checked_at),
        deletion_scheduled_for: opt_string(a.deletion_scheduled_for),
    }
}

pub(crate) fn session_state(s: core::SessionState) -> ffi::SessionState {
    match s {
        core::SessionState::Active => ffi::SessionState::Active,
        core::SessionState::Parked => ffi::SessionState::Parked,
        core::SessionState::SignedOut => ffi::SessionState::SignedOut,
    }
}

pub(crate) fn login_input(i: ffi::LoginInput) -> core::LoginInput {
    core::LoginInput {
        email: i.email,
        password: i.password,
        secret_key: i.has_secret_key.then_some(i.secret_key),
        totp: string_opt(&i.totp),
        trust_device: i.trust_device,
    }
}

pub(crate) fn unlocked(u: core::Unlocked) -> ffi::Unlocked {
    ffi::Unlocked { auk: u.auk, offline: u.offline, deletion_scheduled_for: opt_string(u.deletion_scheduled_for) }
}

pub(crate) fn vault_info(v: core::VaultInfo) -> ffi::VaultInfo {
    ffi::VaultInfo {
        id: v.id,
        name: v.name,
        role: match v.role {
            core::VaultRole::Read => ffi::VaultRole::Read,
            core::VaultRole::Write => ffi::VaultRole::Write,
            core::VaultRole::Manage => ffi::VaultRole::Manage,
        },
        org_id: opt_string(v.org_id),
        current_key_version: v.current_key_version,
        has_pending_key_version: v.pending_key_version.is_some(),
        pending_key_version: v.pending_key_version.unwrap_or(0),
        rotation_required: v.rotation_required,
    }
}

pub(crate) fn kdbx_credentials(c: ffi::KdbxCredentials) -> core::KdbxCredentials {
    core::KdbxCredentials {
        password: c.has_password.then_some(c.password),
        key_file: c.has_key_file.then_some(c.key_file),
        password_hash: c.has_password_hash.then_some(c.password_hash),
    }
}

pub(crate) fn entry_summary(e: core::EntrySummary) -> ffi::EntrySummary {
    ffi::EntrySummary {
        id: e.id,
        group_id: e.group_id,
        group_path: e.group_path,
        title: e.title,
        username: e.username,
        url: e.url,
        tags: e.tags,
        protected_fields: e.protected_fields,
        icon_id: e.icon_id,
        custom_icon: opt_string(e.custom_icon),
        modified_at: e.modified_at,
        has_expires_at: e.expires_at.is_some(),
        expires_at: e.expires_at.unwrap_or(0),
        in_recycle_bin: e.in_recycle_bin,
        has_last_access_at: e.last_access_at.is_some(),
        last_access_at: e.last_access_at.unwrap_or(0),
        usage_count: e.usage_count,
    }
}

pub(crate) fn group_info(g: core::GroupInfo) -> ffi::GroupInfo {
    ffi::GroupInfo {
        id: g.id,
        name: g.name,
        parent_id: opt_string(g.parent_id),
        path: g.path,
        icon_id: g.icon_id,
        notes: g.notes,
        is_recycle_bin: g.is_recycle_bin,
        entry_count: g.entry_count,
    }
}

pub(crate) fn sync_conflict(c: core::SyncConflict) -> ffi::SyncConflict {
    ffi::SyncConflict {
        uuid: c.uuid,
        kind: match c.kind {
            core::ConflictKind::EditedOnBoth => ffi::ConflictKind::EditedOnBoth,
            core::ConflictKind::DeletedHereEditedThere => ffi::ConflictKind::DeletedHereEditedThere,
            core::ConflictKind::EditedHereDeletedThere => ffi::ConflictKind::EditedHereDeletedThere,
        },
        title: c.title,
        fields: c.fields,
    }
}

pub(crate) fn merge_change(c: core::MergeChange) -> ffi::MergeChange {
    ffi::MergeChange {
        change: match c.change {
            core::ChangeType::Added => ffi::ChangeType::Added,
            core::ChangeType::Modified => ffi::ChangeType::Modified,
            core::ChangeType::Moved => ffi::ChangeType::Moved,
            core::ChangeType::Deleted => ffi::ChangeType::Deleted,
            core::ChangeType::Metadata => ffi::ChangeType::Metadata,
        },
        uuid: opt_string(c.uuid),
        title: opt_string(c.title),
        group: opt_string(c.group),
        details: c.details,
    }
}

pub(crate) fn sync_report(r: core::SyncReport) -> ffi::SyncReport {
    ffi::SyncReport {
        outcome: match r.outcome {
            core::SyncOutcome::Unchanged => ffi::SyncOutcome::Unchanged,
            core::SyncOutcome::Pulled => ffi::SyncOutcome::Pulled,
            core::SyncOutcome::Uploaded => ffi::SyncOutcome::Uploaded,
            core::SyncOutcome::Created => ffi::SyncOutcome::Created,
        },
        conflicts: r.conflicts.into_iter().map(sync_conflict).collect(),
        changes: r.changes.into_iter().map(merge_change).collect(),
        attempts: r.attempts,
        etag: opt_string(r.etag),
        has_clock_offset: r.clock_offset_ms.is_some(),
        clock_offset_ms: r.clock_offset_ms.unwrap_or(0),
        clock_skewed: r.clock_skewed,
    }
}

fn signed_out_reason(r: core::SignedOutReason) -> ffi::SignedOutReason {
    match r {
        core::SignedOutReason::TokenReused => ffi::SignedOutReason::TokenReused,
        core::SignedOutReason::SessionExpired => ffi::SignedOutReason::SessionExpired,
        core::SignedOutReason::Unauthorized => ffi::SignedOutReason::Unauthorized,
        core::SignedOutReason::Logout => ffi::SignedOutReason::Logout,
        core::SignedOutReason::DeletionScheduled => ffi::SignedOutReason::DeletionScheduled,
        core::SignedOutReason::AccountDeleted => ffi::SignedOutReason::AccountDeleted,
    }
}

pub(crate) fn account_event(e: Option<core::AccountEvent>) -> ffi::AccountEvent {
    let mut out = ffi::AccountEvent {
        kind: ffi::AccountEventKind::Closed,
        id: String::new(),
        etag: String::new(),
        has_revision: false,
        revision: 0,
        deleted: false,
        vaults: Vec::new(),
        reason: ffi::SignedOutReason::Logout,
        at: String::new(),
    };
    let e_kind = match &e {
        Some(core::AccountEvent::DatabaseChanged { .. }) => EventKind::Database,
        _ => EventKind::Vault,
    };
    match e {
        None => {}
        Some(core::AccountEvent::VaultChanged { vault_id: id, etag, revision, deleted })
        | Some(core::AccountEvent::DatabaseChanged { database_id: id, etag, revision, deleted }) => {
            out.kind = if matches!(e_kind, EventKind::Vault) {
                ffi::AccountEventKind::VaultChanged
            } else {
                ffi::AccountEventKind::DatabaseChanged
            };
            out.id = id;
            out.etag = opt_string(etag);
            out.has_revision = revision.is_some();
            out.revision = revision.unwrap_or(0);
            out.deleted = deleted;
        }
        Some(core::AccountEvent::VaultsChanged { vaults }) => {
            out.kind = ffi::AccountEventKind::VaultsChanged;
            out.vaults = vaults.into_iter().map(vault_info).collect();
        }
        Some(core::AccountEvent::SessionEnded { reason, at }) => {
            out.kind = ffi::AccountEventKind::SessionEnded;
            out.reason = signed_out_reason(reason);
            out.at = opt_string(at);
        }
    }
    out
}

enum EventKind {
    Vault,
    Database,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_flatten() {
        assert_eq!(account_event(None).kind, ffi::AccountEventKind::Closed);
        let db = account_event(Some(core::AccountEvent::DatabaseChanged {
            database_id: "d".into(),
            etag: Some("e".into()),
            revision: Some(3),
            deleted: false,
        }));
        assert_eq!(db.kind, ffi::AccountEventKind::DatabaseChanged);
        assert_eq!((db.id.as_str(), db.etag.as_str(), db.has_revision, db.revision), ("d", "e", true, 3));
        let v = account_event(Some(core::AccountEvent::VaultChanged {
            vault_id: "v".into(),
            etag: None,
            revision: None,
            deleted: true,
        }));
        assert_eq!(v.kind, ffi::AccountEventKind::VaultChanged);
        assert!(v.deleted && !v.has_revision && v.etag.is_empty());
    }

    #[test]
    fn server_config_round_trips() {
        let c = core::ServerConfig {
            issuer: "https://a".into(),
            api: "https://a/api/v1".into(),
            sync: "https://s/api/v1".into(),
            jwks_uri: "https://a/jwks".into(),
            opaque: core::OpaqueConfig {
                lib: "opaque-ke".into(),
                version: "4".into(),
                context: "ov-opaque-v1".into(),
                ids: "a".into(),
            },
            kdf_min: Some(core::KdfMin { m: 19456, t: 2 }),
            web: None,
            share: Some("https://share".into()),
        };
        assert_eq!(server_config_from_ffi(&server_config_to_ffi(c.clone())), c);
    }

    #[test]
    fn unknown_enum_values_are_rejected() {
        let cfg = ffi::ClientConfig {
            device_id: String::new(),
            device_name: "d".into(),
            platform: ffi::Platform { repr: 200 },
            offline: true,
            has_server: false,
            server: ffi::ServerConfig::default(),
        };
        assert_eq!(client_config(&cfg).unwrap_err().code, ov_error::OvErrorCode::InvalidRequest);
        let ok = ffi::ClientConfig { platform: ffi::Platform::QtMacos, ..cfg };
        let core_cfg = client_config(&ok).unwrap();
        assert_eq!(core_cfg.device.platform, core::Platform::QtMacos);
        assert_eq!(core_cfg.device.id, None);
    }

    #[test]
    fn transport_failures_map() {
        assert!(transport_error(no_failure()).is_none());
        let f = ffi::TransportFailure { kind: ffi::TransportErrorKind::Tls, message: "cert".into() };
        assert_eq!(transport_error(f), Some(h::TransportError::Tls("cert".into())));
    }
}
