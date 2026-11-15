//! Private state behind the facade handles. **Not frozen**: W2-A owns this file and adds whatever
//! fields the implementation needs, without touching the handles' public API in `api/`.

use crate::api::ClientConfig;
use crate::host::Host;

/// Behind [`OvClient`](crate::api::OvClient).
pub(crate) struct ClientState {
    pub(crate) host: Host,
    pub(crate) config: ClientConfig,
}

/// Behind [`Account`](crate::api::Account).
pub(crate) struct AccountState;

/// Behind [`TotpChallenge`](crate::api::TotpChallenge): the MFA token and what finishing the
/// sign-in needs (wiped on drop).
pub(crate) struct TotpState;

/// Behind [`Vault`](crate::api::Vault).
pub(crate) struct VaultState;

/// Behind [`ServiceAccount`](crate::api::ServiceAccount).
pub(crate) struct ServiceAccountState;

/// Behind [`SelfHosted`](crate::api::SelfHosted).
pub(crate) struct SelfHostedState;

/// Behind [`EventStream`](crate::api::EventStream).
pub(crate) struct EventStreamState;
