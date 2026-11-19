//! The rest of the facade for C++: the remaining `Vault`, `ov::Client`, `TotpChallenge` and
//! `CancelToken` methods, the `ServiceAccount` and `SelfHosted` handles, and the facade's free
//! functions and record helpers (`Plan::limit` as `plan_limit`, `Platform::as_str` as
//! `platform_as_str`, ...).

use ov_core::api as core;
use ov_error::{OvError, OvErrorCode};

use crate::convert::{self, sync_conflict};
use crate::edge::{block, edge, run, FfiError};
use crate::ffi;
use crate::handles::{CancelToken, Client, EventStream, TotpChallenge, Vault};
use crate::records::{self as rec, some};

type R<T> = Result<T, FfiError>;

// ------------------------------------------------------------------- small handle extras

impl CancelToken {
    /// [`core::CancelToken::check`]: `aborted` once cancelled.
    pub fn check(&self) -> R<()> {
        edge(|| self.0.check())
    }
}

impl TotpChallenge {
    /// [`core::TotpChallenge::last_error`].
    pub fn last_error(&self) -> R<ffi::OptionalError> {
        edge(|| Ok(rec::opt_error(self.0.last_error())))
    }
}

impl Client {
    /// [`core::OvClient::config`].
    pub fn config(&self) -> R<ffi::ClientConfig> {
        edge(|| Ok(rec::client_config_to_ffi(self.0.config())))
    }

    /// [`core::OvClient::remember_account`].
    pub fn remember_account(&self, email: &str, issuer: &str, user_id: &str) -> R<()> {
        block(|| self.0.remember_account(email.into(), issuer.into(), user_id.into()))
    }

    /// [`core::OvClient::set_remembered_deletion`]; an empty `at` clears it.
    pub fn set_remembered_deletion(&self, issuer: &str, user_id: &str, at: &str) -> R<()> {
        block(|| self.0.set_remembered_deletion(issuer.into(), user_id.into(), some(at)))
    }

    /// [`core::OvClient::mark_remembered_checked`].
    pub fn mark_remembered_checked(&self, issuer: &str, user_id: &str) -> R<()> {
        block(|| self.0.mark_remembered_checked(issuer.into(), user_id.into()))
    }

    /// [`core::OvClient::share_info`].
    pub fn share_info(&self, api: &str, share_id: &str, cancel: &CancelToken) -> R<ffi::ShareInfo> {
        run(cancel, |c| async move { self.0.share_info(api.into(), share_id.into(), c).await.map(rec::share_info) })
    }

    /// [`core::OvClient::open_share`].
    pub fn open_share(&self, api: &str, input: ffi::OpenShareInput, cancel: &CancelToken) -> R<ffi::OpenedShare> {
        let passcode = input.has_passcode.then_some(input.passcode);
        let info = input.has_info.then(|| rec::share_info_in(&input.info));
        let link = input.link;
        run(
            cancel,
            |c| async move { self.0.open_share(api.into(), link, passcode, info, c).await.map(rec::opened_share) },
        )
    }
}

// -------------------------------------------------------------------------------- Vault

impl Vault {
    /// [`core::Vault::info`].
    pub fn info(&self) -> R<ffi::OptionalVaultInfo> {
        edge(|| Ok(rec::opt_vault_info(self.0.info())))
    }

    /// [`core::Vault::conflicts`].
    pub fn conflicts(&self) -> R<Vec<ffi::SyncConflict>> {
        edge(|| Ok(self.0.conflicts().into_iter().map(sync_conflict).collect()))
    }

    /// [`core::Vault::root_group_id`].
    pub fn root_group_id(&self) -> R<String> {
        edge(|| Ok(self.0.root_group_id()))
    }

    /// [`core::Vault::entry`].
    pub fn entry(&self, entry_id: &str) -> R<ffi::EntryRecord> {
        edge(|| self.0.entry(entry_id.into()).map(rec::entry_record))
    }

    /// [`core::Vault::find`].
    pub fn find(&self, reference: &str) -> R<ffi::EntryRecord> {
        edge(|| self.0.find(reference.into()).map(rec::entry_record))
    }

    /// [`core::Vault::history`].
    pub fn history(&self, entry_id: &str) -> R<Vec<ffi::EntryRecord>> {
        edge(|| Ok(self.0.history(entry_id.into())?.into_iter().map(rec::entry_record).collect()))
    }

    /// [`core::Vault::attachment`]. Wipe the result.
    pub fn attachment(&self, entry_id: &str, name: &str) -> R<Vec<u8>> {
        edge(|| self.0.attachment(entry_id.into(), name.into()))
    }

    /// [`core::Vault::custom_icon`].
    pub fn custom_icon(&self, icon_id: &str) -> R<Vec<u8>> {
        edge(|| self.0.custom_icon(icon_id.into()))
    }

    /// [`core::Vault::group_id_at`]; empty when there is no such group.
    pub fn group_id_at(&self, path: &str) -> R<String> {
        edge(|| Ok(rec::opt(self.0.group_id_at(path.into()))))
    }

    /// [`core::Vault::is_in_recycle_bin`].
    pub fn is_in_recycle_bin(&self, id: &str) -> R<bool> {
        edge(|| Ok(self.0.is_in_recycle_bin(id.into())))
    }

    /// [`core::Vault::set_fields`].
    pub fn set_fields(
        &self,
        reference: &str,
        fields: Vec<ffi::FieldInput>,
        create: ffi::CreateMode,
    ) -> R<ffi::SetFieldsResult> {
        edge(|| {
            let create = rec::create_mode_in(create)?;
            let fields = fields.into_iter().map(rec::field_input).collect();
            self.0.set_fields(reference.into(), fields, create).map(rec::set_fields_result)
        })
    }

    /// [`core::Vault::add_entry`].
    pub fn add_entry(&self, group_id: &str, input: ffi::EntryInput) -> R<String> {
        edge(|| self.0.add_entry(group_id.into(), rec::entry_input(input)?))
    }

    /// [`core::Vault::edit_entry`].
    pub fn edit_entry(&self, entry_id: &str, input: ffi::EntryInput) -> R<()> {
        edge(|| self.0.edit_entry(entry_id.into(), rec::entry_input(input)?))
    }

    /// [`core::Vault::move_entry`].
    pub fn move_entry(&self, entry_id: &str, group_id: &str) -> R<()> {
        edge(|| self.0.move_entry(entry_id.into(), group_id.into()))
    }

    /// [`core::Vault::delete_entry`].
    pub fn delete_entry(&self, entry_id: &str) -> R<()> {
        edge(|| self.0.delete_entry(entry_id.into()))
    }

    /// [`core::Vault::restore_from_recycle_bin`].
    pub fn restore_from_recycle_bin(&self, id: &str) -> R<()> {
        edge(|| self.0.restore_from_recycle_bin(id.into()))
    }

    /// [`core::Vault::empty_recycle_bin`].
    pub fn empty_recycle_bin(&self) -> R<()> {
        edge(|| self.0.empty_recycle_bin())
    }

    /// [`core::Vault::set_attachment`].
    pub fn set_attachment(&self, entry_id: &str, name: &str, data: Vec<u8>) -> R<()> {
        edge(|| self.0.set_attachment(entry_id.into(), name.into(), data))
    }

    /// [`core::Vault::remove_attachment`].
    pub fn remove_attachment(&self, entry_id: &str, name: &str) -> R<()> {
        edge(|| self.0.remove_attachment(entry_id.into(), name.into()))
    }

    /// [`core::Vault::add_custom_icon`].
    pub fn add_custom_icon(&self, png: Vec<u8>) -> R<String> {
        edge(|| self.0.add_custom_icon(png))
    }

    /// [`core::Vault::add_group`]; an empty `parent_id` is the root.
    pub fn add_group(&self, parent_id: &str, name: &str) -> R<String> {
        edge(|| self.0.add_group(some(parent_id), name.into()))
    }

    /// [`core::Vault::ensure_group`].
    pub fn ensure_group(&self, path: &str) -> R<String> {
        edge(|| self.0.ensure_group(path.into()))
    }

    /// [`core::Vault::rename_group`].
    pub fn rename_group(&self, group_id: &str, name: &str) -> R<()> {
        edge(|| self.0.rename_group(group_id.into(), name.into()))
    }

    /// [`core::Vault::set_group_icon`].
    pub fn set_group_icon(&self, group_id: &str, icon_id: u32) -> R<()> {
        edge(|| self.0.set_group_icon(group_id.into(), icon_id))
    }

    /// [`core::Vault::move_group`].
    pub fn move_group(&self, group_id: &str, parent_id: &str) -> R<()> {
        edge(|| self.0.move_group(group_id.into(), parent_id.into()))
    }

    /// [`core::Vault::delete_group`].
    pub fn delete_group(&self, group_id: &str) -> R<()> {
        edge(|| self.0.delete_group(group_id.into()))
    }

    /// [`core::Vault::version_difference`].
    pub fn version_difference(&self, version: &Vault, entry_id: &str) -> R<ffi::VersionDifference> {
        edge(|| self.0.version_difference(version.0.clone(), entry_id.into()).map(rec::version_difference))
    }

    /// [`core::Vault::restore_entry`].
    pub fn restore_entry(&self, version: &Vault, entry_id: &str, group_path: &str) -> R<()> {
        edge(|| self.0.restore_entry(version.0.clone(), entry_id.into(), group_path.into()))
    }

    /// [`core::Vault::apply_autofill_edits`].
    pub fn apply_autofill_edits(&self, edits: &ffi::AutoFillEdits) -> R<bool> {
        edge(|| self.0.apply_autofill_edits(rec::autofill_edits_in(edits)))
    }

    /// [`core::Vault::keep_edits`].
    pub fn keep_edits(&self) -> R<()> {
        block(|| self.0.keep_edits())
    }

    /// [`core::Vault::has_pending_edits`].
    pub fn has_pending_edits(&self) -> R<bool> {
        block(|| self.0.has_pending_edits())
    }

    /// [`core::Vault::export_plain`]; an empty `group_ids` is every group. Wipe the result.
    pub fn export_plain(&self, format: ffi::ExportFormat, group_ids: Vec<String>) -> R<Vec<u8>> {
        edge(|| self.0.export_plain(rec::export_format_in(format)?, rec::group_ids(group_ids)))
    }
}

// ----------------------------------------------------------------------- ServiceAccount

/// `ov::ServiceAccount`: [`core::ServiceAccount`].
pub struct ServiceAccount(pub(crate) core::ServiceAccount);

/// `ov::service_account_from_token()`: [`core::ServiceAccount::from_token`].
pub fn service_account_from_token(client: &Client, token: Vec<u8>, cancel: &CancelToken) -> R<Box<ServiceAccount>> {
    run(cancel, |c| async move {
        core::ServiceAccount::from_token(client.0.clone(), token, c).await.map(|s| Box::new(ServiceAccount(s)))
    })
}

impl ServiceAccount {
    /// [`core::ServiceAccount::sa_id`].
    pub fn sa_id(&self) -> R<String> {
        edge(|| Ok(self.0.sa_id()))
    }

    /// [`core::ServiceAccount::principal`].
    pub fn principal(&self) -> R<String> {
        edge(|| Ok(self.0.principal()))
    }

    /// [`core::ServiceAccount::vaults`].
    pub fn vaults(&self, refresh: bool, cancel: &CancelToken) -> R<Vec<ffi::SaVault>> {
        run(cancel, |c| async move { Ok(self.0.vaults(refresh, c).await?.into_iter().map(rec::sa_vault).collect()) })
    }

    /// [`core::ServiceAccount::vault`].
    pub fn vault(&self, id_or_name: &str, cancel: &CancelToken) -> R<ffi::SaVault> {
        run(cancel, |c| async move { self.0.vault(id_or_name.into(), c).await.map(rec::sa_vault) })
    }

    /// [`core::ServiceAccount::open_vault`].
    pub fn open_vault(&self, id_or_name: &str, refresh: bool, cancel: &CancelToken) -> R<Box<Vault>> {
        run(
            cancel,
            |c| async move { self.0.open_vault(id_or_name.into(), refresh, c).await.map(|v| Box::new(Vault(v))) },
        )
    }

    /// [`core::ServiceAccount::pull`].
    pub fn pull(&self, id_or_name: &str, cancel: &CancelToken) -> R<Box<Vault>> {
        run(cancel, |c| async move { self.0.pull(id_or_name.into(), c).await.map(|v| Box::new(Vault(v))) })
    }

    /// [`core::ServiceAccount::read`]. Wipe the result.
    pub fn read(&self, reference: &str, cancel: &CancelToken) -> R<Vec<u8>> {
        run(cancel, |c| self.0.read(reference.into(), c))
    }

    /// [`core::ServiceAccount::inject`].
    pub fn inject(&self, tmpl: Vec<u8>, cancel: &CancelToken) -> R<ffi::Injected> {
        run(cancel, |c| async move { self.0.inject(tmpl, c).await.map(rec::injected) })
    }

    /// [`core::ServiceAccount::write`].
    pub fn write(&self, reference: &str, value: Vec<u8>, create: bool, cancel: &CancelToken) -> R<()> {
        run(cancel, |c| self.0.write(reference.into(), value, create, c))
    }

    /// [`core::ServiceAccount::close`].
    pub fn close(&self) -> R<()> {
        edge(|| {
            self.0.close();
            Ok(())
        })
    }
}

// --------------------------------------------------------------------------- SelfHosted

/// `ov::SelfHosted`: [`core::SelfHosted`].
pub struct SelfHosted(pub(crate) core::SelfHosted);

/// `ov::RestoredSelfHosted`: the `Option<SelfHosted>` of [`core::SelfHosted::restore`].
pub struct RestoredSelfHosted(Option<core::SelfHosted>);

/// `ov::self_hosted_connect()`: [`core::SelfHosted::connect`].
pub fn self_hosted_connect(client: &Client, server_url: &str, device_token: Vec<u8>) -> R<Box<SelfHosted>> {
    edge(|| {
        core::SelfHosted::connect(client.0.clone(), server_url.into(), device_token).map(|s| Box::new(SelfHosted(s)))
    })
}

/// `ov::self_hosted_pair()`: [`core::SelfHosted::pair`].
pub fn self_hosted_pair(
    client: &Client,
    server_url: &str,
    code: &str,
    device_name: &str,
    cancel: &CancelToken,
) -> R<Box<SelfHosted>> {
    run(cancel, |c| async move {
        core::SelfHosted::pair(client.0.clone(), server_url.into(), code.into(), device_name.into(), c)
            .await
            .map(|s| Box::new(SelfHosted(s)))
    })
}

/// `ov::self_hosted_restore()`: [`core::SelfHosted::restore`].
pub fn self_hosted_restore(client: &Client, server_url: &str) -> R<Box<RestoredSelfHosted>> {
    block(|| async {
        core::SelfHosted::restore(client.0.clone(), server_url.into()).await.map(|s| Box::new(RestoredSelfHosted(s)))
    })
}

impl RestoredSelfHosted {
    /// A device token was stored for the server.
    pub fn is_paired(&self) -> bool {
        self.0.is_some()
    }

    /// The paired server (call once); `invalid_request` when not paired or already taken.
    pub fn take(&mut self) -> R<Box<SelfHosted>> {
        edge(|| {
            self.0
                .take()
                .map(|s| Box::new(SelfHosted(s)))
                .ok_or_else(|| OvError::new(OvErrorCode::InvalidRequest, "not paired (or already taken)"))
        })
    }
}

impl SelfHosted {
    /// [`core::SelfHosted::server_url`].
    pub fn server_url(&self) -> R<String> {
        edge(|| Ok(self.0.server_url()))
    }

    /// [`core::SelfHosted::health`].
    pub fn health(&self, cancel: &CancelToken) -> R<String> {
        run(cancel, |c| self.0.health(c))
    }

    /// [`core::SelfHosted::list_databases`].
    pub fn list_databases(&self, cancel: &CancelToken) -> R<Vec<ffi::BlobMeta>> {
        run(cancel, |c| async move { Ok(self.0.list_databases(c).await?.into_iter().map(rec::blob_meta).collect()) })
    }

    /// [`core::SelfHosted::create_pairing_code`].
    pub fn create_pairing_code(&self, cancel: &CancelToken) -> R<ffi::PairingCode> {
        run(cancel, |c| async move { self.0.create_pairing_code(c).await.map(rec::pairing_code) })
    }

    /// [`core::SelfHosted::sync_database`].
    pub fn sync_database(
        &self,
        database_id: &str,
        kdbx: Vec<u8>,
        credentials: ffi::KdbxCredentials,
        cancel: &CancelToken,
    ) -> R<ffi::SelfHostedSyncResult> {
        run(cancel, |c| async move {
            self.0
                .sync_database(database_id.into(), kdbx, convert::kdbx_credentials(credentials), c)
                .await
                .map(rec::self_hosted_sync_result)
        })
    }

    /// [`core::SelfHosted::events`].
    pub fn events(&self, cancel: &CancelToken) -> R<Box<EventStream>> {
        run(cancel, |c| async move { self.0.events(c).await.map(|s| Box::new(EventStream(s))) })
    }
}

// ------------------------------------------------------------ free functions, record helpers

/// `ov::platform_as_str()`: [`core::Platform::as_str`].
pub fn platform_as_str(platform: ffi::Platform) -> R<String> {
    edge(|| Ok(rec::platform_in(platform)?.as_str().to_string()))
}

/// `ov::plan_limit()`: [`core::Plan::limit`].
pub fn plan_limit(plan: &ffi::Plan, name: &str) -> R<ffi::OptionalI64> {
    edge(|| Ok(rec::opt_i64(rec::plan_in(plan).limit(name))))
}

/// `ov::plan_has()`: [`core::Plan::has`].
pub fn plan_has(plan: &ffi::Plan, name: &str) -> R<bool> {
    edge(|| Ok(rec::plan_in(plan).has(name)))
}

/// `ov::plan_has_billing()`: [`core::Plan::has_billing`].
pub fn plan_has_billing(plan: &ffi::Plan) -> R<bool> {
    edge(|| Ok(rec::plan_in(plan).has_billing()))
}

/// `ov::deletion_expired()`: [`core::deletion_expired`]; an empty `scheduled_for` is none.
pub fn deletion_expired(scheduled_for: &str, now_ms: i64) -> R<bool> {
    edge(|| Ok(core::deletion_expired(some(scheduled_for), now_ms)))
}

/// `ov::default_share_fields()`: [`core::default_share_fields`].
pub fn default_share_fields() -> R<Vec<String>> {
    edge(|| Ok(core::default_share_fields()))
}

/// `ov::shareable_fields()`: [`core::shareable_fields`].
pub fn shareable_fields(entry: &ffi::EntryRecord) -> R<Vec<ffi::ShareableField>> {
    edge(|| Ok(core::shareable_fields(rec::entry_record_in(entry)).into_iter().map(rec::shareable_field).collect()))
}

/// `ov::item_share_payload()`: [`core::item_share_payload`]; an empty `shared_by` is none.
pub fn item_share_payload(entry: &ffi::EntryRecord, names: Vec<String>, shared_by: &str) -> R<ffi::SharePayload> {
    edge(|| Ok(rec::share_payload(core::item_share_payload(rec::entry_record_in(entry), names, some(shared_by)))))
}

/// `ov::text_share_payload()`: [`core::text_share_payload`]; empty strings are none.
pub fn text_share_payload(text: Vec<u8>, title: &str, shared_by: &str) -> R<ffi::SharePayload> {
    edge(|| Ok(rec::share_payload(core::text_share_payload(text, some(title), some(shared_by)))))
}

/// `ov::parse_totp_uri()`: [`core::parse_totp_uri`].
pub fn parse_totp_uri(uri: Vec<u8>) -> R<ffi::TotpParams> {
    edge(|| core::parse_totp_uri(uri).map(rec::totp_params))
}

/// `ov::totp_code()`: [`core::totp_code`].
pub fn totp_code(params: ffi::TotpParams, now_ms: i64) -> R<ffi::TotpCode> {
    edge(|| Ok(rec::totp_code(core::totp_code(rec::totp_params_in(params)?, now_ms))))
}

/// `ov::entry_totp_uri()`: [`core::entry_totp_uri`].
pub fn entry_totp_uri(fields: Vec<ffi::FieldRecord>, label: &str) -> R<ffi::OptionalBytes> {
    edge(|| {
        let fields = fields.iter().map(rec::field_record_in).collect();
        Ok(rec::opt_bytes(core::entry_totp_uri(fields, label.into())))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ffi::Plan {
        rec::plan(core::Plan {
            id: Some("free".into()),
            limits: vec![core::PlanLimit { name: "members".into(), value: Some(1) }],
            billing: None,
        })
    }

    #[test]
    fn record_helpers_work_without_the_core_bodies() {
        let p = plan();
        assert_eq!(plan_limit(&p, "members").unwrap(), ffi::OptionalI64 { has: true, value: 1 });
        assert!(!plan_limit(&p, "audit_days").unwrap().has);
        assert!(plan_has(&p, "members").unwrap());
        assert!(plan_has_billing(&p).unwrap());
        assert_eq!(platform_as_str(ffi::Platform::QtWindows).unwrap(), "qt-windows");
        assert_eq!(platform_as_str(ffi::Platform { repr: 99 }).unwrap_err().0.code, OvErrorCode::InvalidRequest);
        let _ = crate::edge::take_last_error();
    }

    #[test]
    fn cancel_token_check() {
        let t = crate::handles::new_cancel_token();
        assert!(t.check().is_ok());
        t.cancel();
        assert_eq!(t.check().unwrap_err().0.code, OvErrorCode::Aborted);
        let _ = crate::edge::take_last_error();
    }
}
