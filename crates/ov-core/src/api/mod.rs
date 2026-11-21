//! The facade: the only API the bindings (`ov-wasm`, `ov-ffi`, `ov-ffi-cpp`) and the `ov`
//! CLI see.
//!
//! **Frozen contract** (rust-core-tasks.md §2.3, tag `contract-v1`; later additions up to
//! `contract-v1.6` are listed in `docs/adr/0001-contract.md`): the names, signatures and records in
//! this module don't change without a CONTRACT-REQUEST. The method bodies (W2-A) only orchestrate:
//! they call the domain crates through `crate::impls`.
//!
//! The API has one Rust method for each public method of the TypeScript SDK's `Account`,
//! `AccountVault`, `ServiceAccount` and `SelfHostedSync` and of the iOS app's `Account` and its
//! extensions; `docs/api-coverage.md` maps every one.
//!
//! Binding rules (§2.3):
//! - Types that cross FFI are plain records and enums: no generics, lifetimes or trait objects
//!   except the [Host](crate::host) traits. Handles ([`OvClient`], [`Account`], [`Vault`],
//!   [`ServiceAccount`], [`SelfHosted`], [`EventStream`], [`TotpChallenge`]) are cheap `Clone`
//!   objects (an `Arc` inside) that are safe to share between threads.
//! - Secrets cross as `Vec<u8>` ([`SecretBytes`], UTF-8 for text). The core wipes the inputs it
//!   is given; the caller wipes the outputs it receives.
//! - Every fallible call returns `Result<T, OvError>`; bindings turn a panic into
//!   `OvError { code: Internal }`.
//! - Calls that may touch the network or run a KDF are `async` and take a [`CancelToken`]. A
//!   cancelled call returns `aborted`.

mod account;
mod client;
mod events;
mod plan;
mod self_hosted;
mod service_account;
mod settings;
mod share_links;
mod sharing;
mod totp;
mod types;
mod vault;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use ov_error::{OvError, OvErrorCode};

pub use account::{Account, LoginInput, LoginStep, RegisterInput, TotpChallenge, Unlocked};
pub use client::{deletion_expired, OvClient};
pub use events::{AccountEvent, EventStream};
pub use self_hosted::{PairingCode, SelfHosted, SelfHostedSyncResult};
pub use service_account::{Injected, SaVault, ServiceAccount};
pub use share_links::{
    default_share_fields, item_share_payload, shareable_fields, text_share_payload, CreatedShare, OpenedShare,
    ShareField, ShareInfo, ShareListing, ShareOptions, SharePayload, ShareRef, ShareableField,
};
pub use totp::{entry_totp_uri, parse_totp_uri, totp_code, TotpAlgorithm, TotpCode, TotpParams};
pub use types::*;
pub use vault::{
    AttachmentInfo, CreateMode, EntryExpiry, EntryInput, EntryRecord, EntrySummary, ExportFormat, FieldInput,
    FieldRecord, GroupInfo, ImportPreview, ImportSummary, ImportTarget, KdbxCredentials, KdbxKdf, LocalImportMode,
    SetFieldsResult, Vault, VersionDifference,
};

pub use ov_error::{OvError as Error, OvErrorCode as ErrorCode};

/// Cancels a running call. Clone it, pass it to the call, and call [`CancelToken::cancel`] from
/// anywhere; the call stops at its next step and returns `aborted`.
///
/// A token stays cancelled. Use a fresh token per call (or one token for a group of calls that
/// should stop together).
#[derive(Clone, Default)]
pub struct CancelToken {
    inner: Arc<CancelInner>,
}

#[derive(Default)]
struct CancelInner {
    cancelled: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelToken").field("cancelled", &self.is_cancelled()).finish()
    }
}

impl CancelToken {
    /// A token that isn't cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels every call holding this token.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        let wakers = std::mem::take(&mut *self.inner.wakers.lock().unwrap_or_else(|p| p.into_inner()));
        for w in wakers {
            w.wake();
        }
    }

    /// Whether [`cancel`](Self::cancel) was called.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// `Err(aborted)` once cancelled. Long calls check this between steps.
    pub fn check(&self) -> Result<(), OvError> {
        if self.is_cancelled() {
            Err(OvError::new(OvErrorCode::Aborted, "cancelled"))
        } else {
            Ok(())
        }
    }

    /// A future that completes when the token is cancelled (for racing against I/O).
    pub fn cancelled(&self) -> Cancelled {
        Cancelled { token: self.clone() }
    }
}

/// Completes when its [`CancelToken`] is cancelled. Returned by [`CancelToken::cancelled`].
#[derive(Debug)]
pub struct Cancelled {
    token: CancelToken,
}

impl Future for Cancelled {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.token.is_cancelled() {
            return Poll::Ready(());
        }
        {
            let mut wakers = self.token.inner.wakers.lock().unwrap_or_else(|p| p.into_inner());
            if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
                wakers.push(cx.waker().clone());
            }
        }
        // Cancelled between the first check and registering: don't miss the wake-up.
        if self.token.is_cancelled() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Wake;

    struct Flag(AtomicBool);
    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>(_: &T) {}

    /// UniFFI and cxx need `Send + Sync` handles and `Send` futures on native targets.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn handles_are_send_sync_and_futures_send() {
        assert_send_sync::<OvClient>();
        assert_send_sync::<Account>();
        assert_send_sync::<Vault>();
        assert_send_sync::<ServiceAccount>();
        assert_send_sync::<SelfHosted>();
        assert_send_sync::<EventStream>();
        assert_send_sync::<TotpChallenge>();
        assert_send_sync::<crate::host::Host>();
        let account: Option<Account> = None;
        if let Some(a) = account {
            assert_send(&a.login(
                LoginInput { email: String::new(), password: vec![], secret_key: None, totp: None, trust_device: true },
                CancelToken::new(),
            ));
            assert_send(&a.vaults(CancelToken::new()));
        }
        let vault: Option<Vault> = None;
        if let Some(v) = vault {
            assert_send(&v.sync(SyncOptions::default(), CancelToken::new()));
        }
    }

    #[test]
    fn cancel_token_wakes_and_checks() {
        let token = CancelToken::new();
        assert!(token.check().is_ok());
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let mut fut = token.cancelled();
        assert!(Pin::new(&mut fut).poll(&mut cx).is_pending());
        token.clone().cancel();
        assert!(flag.0.load(Ordering::SeqCst));
        assert!(Pin::new(&mut fut).poll(&mut cx).is_ready());
        assert_eq!(token.check().unwrap_err().code, OvErrorCode::Aborted);
    }
}
