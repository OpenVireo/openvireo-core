//! The opaque handles C++ holds (`rust::Box<ov::Client>` and friends) and their bridged methods.
//!
//! Each method is a thin edge wrapper over the frozen facade (`ov_core::api`): it converts the
//! flat records, runs async calls to completion on the calling thread with the caller's
//! [`CancelToken`], and catches panics.

use cxx::UniquePtr;
use ov_core::api as core;
use ov_error::{OvError, OvErrorCode};

use crate::convert;
use crate::edge::{edge, edge_blocking, FfiError};
use crate::ffi;

type R<T> = Result<T, FfiError>;

/// `ov::CancelToken`: cancels the calls it is passed to. See [`core::CancelToken`].
pub struct CancelToken(pub(crate) core::CancelToken);

/// `ov::new_cancel_token()`.
pub fn new_cancel_token() -> Box<CancelToken> {
    Box::new(CancelToken(core::CancelToken::new()))
}

impl CancelToken {
    /// Another handle to the same token.
    #[allow(clippy::should_implement_trait)]
    pub fn clone(&self) -> Box<CancelToken> {
        Box::new(CancelToken(self.0.clone()))
    }

    /// Cancels every call holding this token; they return `aborted`.
    pub fn cancel(&self) {
        self.0.cancel()
    }

    /// Whether [`cancel`](Self::cancel) was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

// ------------------------------------------------------------------------------- Client

/// `ov::Client`: [`core::OvClient`].
pub struct Client(pub(crate) core::OvClient);

/// `ov::new_client()`: a client over the C++ Host. Does no I/O.
pub fn new_client(
    config: &ffi::ClientConfig,
    http: UniquePtr<ffi::HttpTransport>,
    store: UniquePtr<ffi::SecureStore>,
    cache: UniquePtr<ffi::BlobCache>,
    clock: UniquePtr<ffi::Clock>,
    log: UniquePtr<ffi::LogSink>,
) -> R<Box<Client>> {
    edge(|| {
        let config = convert::client_config(config)?;
        let host = crate::host::host_from_cpp(http, store, cache, clock, log)?;
        Ok(Box::new(Client(core::OvClient::new(config, host))))
    })
}

impl Client {
    /// [`core::OvClient::discover`].
    pub fn discover(&self, issuer: &str, cancel: &CancelToken) -> R<ffi::ServerConfig> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move {
            self.0.discover(issuer.to_string(), c).await.map(convert::server_config_to_ffi)
        })
    }

    /// [`core::OvClient::connect`].
    pub fn connect(&self, issuer: &str, cancel: &CancelToken) -> R<Box<Account>> {
        let c = cancel.0.clone();
        edge_blocking(
            &cancel.0,
            || async move { self.0.connect(issuer.to_string(), c).await.map(|a| Box::new(Account(a))) },
        )
    }

    /// [`core::OvClient::remembered_accounts`].
    pub fn remembered_accounts(&self) -> R<Vec<ffi::RememberedAccount>> {
        edge_blocking(&core::CancelToken::new(), || async {
            Ok(self.0.remembered_accounts().await?.into_iter().map(convert::remembered_account).collect())
        })
    }

    /// [`core::OvClient::forget_remembered`].
    pub fn forget_remembered(&self, issuer: &str, user_id: &str) -> R<()> {
        edge_blocking(&core::CancelToken::new(), || self.0.forget_remembered(issuer.into(), user_id.into()))
    }

    /// [`core::OvClient::session_state`].
    pub fn session_state(&self, issuer: &str, user_id: &str) -> R<ffi::SessionState> {
        edge_blocking(&core::CancelToken::new(), || async {
            self.0.session_state(issuer.into(), user_id.into()).await.map(convert::session_state)
        })
    }

    /// [`core::OvClient::has_pending_edits`].
    pub fn has_pending_edits(&self, user_id: &str) -> R<bool> {
        edge_blocking(&core::CancelToken::new(), || self.0.has_pending_edits(user_id.into()))
    }
}

// ------------------------------------------------------------------------------ Account

/// `ov::Account`: [`core::Account`].
pub struct Account(pub(crate) core::Account);

impl Account {
    /// [`core::Account::server_config`].
    pub fn server_config(&self) -> R<ffi::ServerConfig> {
        edge(|| Ok(convert::server_config_to_ffi(self.0.server_config())))
    }

    /// [`core::Account::is_offline`].
    pub fn is_offline(&self) -> R<bool> {
        edge(|| Ok(self.0.is_offline()))
    }

    /// [`core::Account::is_signed_in`].
    pub fn is_signed_in(&self) -> R<bool> {
        edge(|| Ok(self.0.is_signed_in()))
    }

    /// [`core::Account::is_unlocked`].
    pub fn is_unlocked(&self) -> R<bool> {
        edge(|| Ok(self.0.is_unlocked()))
    }

    /// [`core::Account::user_id`]; empty when signed out.
    pub fn user_id(&self) -> R<String> {
        edge(|| Ok(self.0.user_id().unwrap_or_default()))
    }

    /// [`core::Account::email`]; empty when signed out.
    pub fn email(&self) -> R<String> {
        edge(|| Ok(self.0.email().unwrap_or_default()))
    }

    /// [`core::Account::login`].
    pub fn login(&self, input: ffi::LoginInput, cancel: &CancelToken) -> R<Box<LoginStep>> {
        let c = cancel.0.clone();
        edge_blocking(
            &cancel.0,
            || async move { self.0.login(convert::login_input(input), c).await.map(LoginStep::boxed) },
        )
    }

    /// [`core::Account::submit_totp`].
    pub fn submit_totp(&self, challenge: &TotpChallenge, code: &str, cancel: &CancelToken) -> R<Box<LoginStep>> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move {
            self.0.submit_totp(challenge.0.clone(), code.to_string(), c).await.map(LoginStep::boxed)
        })
    }

    /// [`core::Account::unlock`]; an empty `secret_key` uses the one this device keeps.
    pub fn unlock(&self, password: Vec<u8>, secret_key: Vec<u8>, cancel: &CancelToken) -> R<ffi::Unlocked> {
        let c = cancel.0.clone();
        let secret_key = (!secret_key.is_empty()).then_some(secret_key);
        edge_blocking(&cancel.0, || async move { self.0.unlock(password, secret_key, c).await.map(convert::unlocked) })
    }

    /// [`core::Account::lock`].
    pub fn lock(&self) -> R<()> {
        edge(|| {
            self.0.lock();
            Ok(())
        })
    }

    /// [`core::Account::sign_out`].
    pub fn sign_out(&self, forget_device: bool, cancel: &CancelToken) -> R<()> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || self.0.sign_out(forget_device, c))
    }

    /// [`core::Account::vaults`].
    pub fn vaults(&self, cancel: &CancelToken) -> R<Vec<ffi::VaultInfo>> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move {
            Ok(self.0.vaults(c).await?.into_iter().map(convert::vault_info).collect())
        })
    }

    /// [`core::Account::open_vault`].
    pub fn open_vault(&self, vault_id: &str, cancel: &CancelToken) -> R<Box<Vault>> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move {
            self.0.open_vault(vault_id.to_string(), c).await.map(|v| Box::new(Vault(v)))
        })
    }

    /// [`core::Account::subscribe`].
    pub fn subscribe(&self, cancel: &CancelToken) -> R<Box<EventStream>> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move { self.0.subscribe(c).await.map(|s| Box::new(EventStream(s))) })
    }
}

// ---------------------------------------------------------------- LoginStep, TotpChallenge

/// `ov::LoginStep`: [`core::LoginStep`]. Ask [`needs_totp`](Self::needs_totp), then take the
/// challenge or the unlocked result.
pub struct LoginStep(Option<core::LoginStep>);

impl LoginStep {
    fn boxed(step: core::LoginStep) -> Box<LoginStep> {
        Box::new(LoginStep(Some(step)))
    }

    /// The account asks for a TOTP code.
    pub fn needs_totp(&self) -> bool {
        matches!(self.0, Some(core::LoginStep::NeedsTotp(_)))
    }

    /// The challenge to pass to `Account::submit_totp`; `invalid_request` when signed in.
    pub fn challenge(&self) -> R<Box<TotpChallenge>> {
        edge(|| match &self.0 {
            Some(core::LoginStep::NeedsTotp(c)) => Ok(Box::new(TotpChallenge(c.clone()))),
            _ => Err(OvError::new(OvErrorCode::InvalidRequest, "the sign-in doesn't need a TOTP code")),
        })
    }

    /// The unlocked result (moves the AUK out, so call it once); `invalid_request` otherwise.
    pub fn take_unlocked(&mut self) -> R<ffi::Unlocked> {
        edge(|| match self.0.take() {
            Some(core::LoginStep::Unlocked(u)) => Ok(convert::unlocked(u)),
            other => {
                self.0 = other;
                Err(OvError::new(OvErrorCode::InvalidRequest, "the sign-in isn't unlocked (or was already taken)"))
            }
        })
    }
}

/// `ov::TotpChallenge`: [`core::TotpChallenge`].
pub struct TotpChallenge(pub(crate) core::TotpChallenge);

impl TotpChallenge {
    /// [`core::TotpChallenge::attempt`].
    pub fn attempt(&self) -> R<u32> {
        edge(|| Ok(self.0.attempt()))
    }
}

// -------------------------------------------------------------------------------- Vault

/// `ov::Vault`: [`core::Vault`].
pub struct Vault(pub(crate) core::Vault);

/// `ov::vault_open_local()`: [`core::Vault::open_local`].
pub fn vault_open_local(kdbx: Vec<u8>, credentials: ffi::KdbxCredentials, cancel: &CancelToken) -> R<Box<Vault>> {
    let c = cancel.0.clone();
    edge_blocking(&cancel.0, || async move {
        core::Vault::open_local(kdbx, convert::kdbx_credentials(credentials), c).await.map(|v| Box::new(Vault(v)))
    })
}

/// `ov::vault_create_local()`: [`core::Vault::create_local`].
pub fn vault_create_local(name: &str, credentials: ffi::KdbxCredentials, cancel: &CancelToken) -> R<Box<Vault>> {
    let c = cancel.0.clone();
    edge_blocking(&cancel.0, || async move {
        core::Vault::create_local(name.to_string(), convert::kdbx_credentials(credentials), c)
            .await
            .map(|v| Box::new(Vault(v)))
    })
}

impl Vault {
    /// [`core::Vault::save_local`].
    pub fn save_local(&self, cancel: &CancelToken) -> R<Vec<u8>> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || self.0.save_local(c))
    }

    /// [`core::Vault::id`].
    pub fn id(&self) -> R<String> {
        edge(|| Ok(self.0.id()))
    }

    /// [`core::Vault::name`].
    pub fn name(&self) -> R<String> {
        edge(|| Ok(self.0.name()))
    }

    /// [`core::Vault::etag`]; empty when none.
    pub fn etag(&self) -> R<String> {
        edge(|| Ok(self.0.etag().unwrap_or_default()))
    }

    /// [`core::Vault::is_offline`].
    pub fn is_offline(&self) -> R<bool> {
        edge(|| Ok(self.0.is_offline()))
    }

    /// [`core::Vault::is_read_only`].
    pub fn is_read_only(&self) -> R<bool> {
        edge(|| Ok(self.0.is_read_only()))
    }

    /// [`core::Vault::entries`].
    pub fn entries(&self, include_recycle_bin: bool) -> R<Vec<ffi::EntrySummary>> {
        edge(|| Ok(self.0.entries(include_recycle_bin).into_iter().map(convert::entry_summary).collect()))
    }

    /// [`core::Vault::groups`].
    pub fn groups(&self) -> R<Vec<ffi::GroupInfo>> {
        edge(|| Ok(self.0.groups().into_iter().map(convert::group_info).collect()))
    }

    /// [`core::Vault::read_field`]. The caller wipes the result.
    pub fn read_field(&self, reference: &str) -> R<Vec<u8>> {
        edge(|| self.0.read_field(reference.to_string()))
    }

    /// [`core::Vault::write_field`].
    pub fn write_field(
        &self,
        reference: &str,
        value: Vec<u8>,
        create: bool,
        cancel: &CancelToken,
    ) -> R<ffi::SyncReport> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move {
            self.0.write_field(reference.to_string(), value, create, c).await.map(convert::sync_report)
        })
    }

    /// [`core::Vault::sync`].
    pub fn sync(&self, local_changed: bool, cancel: &CancelToken) -> R<ffi::SyncReport> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move {
            self.0.sync(core::SyncOptions { local_changed }, c).await.map(convert::sync_report)
        })
    }

    /// [`core::Vault::export_kdbx`]; an empty `group_ids` is every group.
    pub fn export_kdbx(
        &self,
        credentials: ffi::KdbxCredentials,
        group_ids: Vec<String>,
        cancel: &CancelToken,
    ) -> R<Vec<u8>> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || {
            self.0.export_kdbx(convert::kdbx_credentials(credentials), crate::records::group_ids(group_ids), c)
        })
    }
}

// -------------------------------------------------------------------------- EventStream

/// `ov::EventStream`: [`core::EventStream`].
pub struct EventStream(pub(crate) core::EventStream);

impl EventStream {
    /// [`core::EventStream::next`]; `kind == Closed` once the stream is closed.
    pub fn next(&self, cancel: &CancelToken) -> R<ffi::AccountEvent> {
        let c = cancel.0.clone();
        edge_blocking(&cancel.0, || async move { self.0.next(c).await.map(convert::account_event) })
    }

    /// [`core::EventStream::reconnect`].
    pub fn reconnect(&self) -> R<()> {
        edge(|| {
            self.0.reconnect();
            Ok(())
        })
    }

    /// [`core::EventStream::close`].
    pub fn close(&self) -> R<()> {
        edge(|| {
            self.0.close();
            Ok(())
        })
    }
}
