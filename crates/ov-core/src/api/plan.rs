//! Plans and limits, and In-App Purchase (SPEC §19). Limits only stop new things and the server's
//! check is what counts: clients use these to explain and grey out, never to refuse on their own.

use ov_error::OvError;

use super::{Account, AppleEligibility, AppleTransactionResult, CancelToken, Plan};

impl Account {
    /// The account's personal plan (from `GET /me`); `None` on a server without billing.
    pub async fn plan(&self, cancel: CancelToken) -> Result<Option<Plan>, OvError> {
        todo!()
    }

    /// A vault's sync quota in bytes, from the access token's `vlt` claim (`q`); `None` when only the
    /// server's own limit applies.
    pub async fn vault_quota(&self, vault_id: String) -> Result<Option<u64>, OvError> {
        todo!()
    }

    /// Where to change plan after a `plan_limit` error: the error's `upgradeUrl` when it is a
    /// `/subscription/` page of this account's auth site (same scheme or https, host and port), else
    /// the site's `subscription/pricing` page. `None` when the issuer has no host.
    pub fn upgrade_url(&self, error: OvError) -> Option<String> {
        todo!()
    }

    /// Whether the App Store may sell a plan to this user (`org_id` `None`) or to one of their orgs.
    pub async fn apple_eligibility(
        &self,
        org_id: Option<String>,
        cancel: CancelToken,
    ) -> Result<AppleEligibility, OvError> {
        todo!()
    }

    /// Reports a StoreKit transaction's JWS to the auth server; returns the plan now.
    pub async fn report_apple_transaction(
        &self,
        jws: String,
        cancel: CancelToken,
    ) -> Result<AppleTransactionResult, OvError> {
        todo!()
    }
}
