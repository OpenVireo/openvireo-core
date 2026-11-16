//! Plans and limits, and In-App Purchase (SPEC §19). Limits only stop new things and the server's
//! check is what counts: clients use these to explain and grey out, never to refuse on their own.

use ov_error::OvError;

use super::{Account, AppleEligibility, AppleTransactionResult, CancelToken, Plan};

impl Account {
    /// The account's personal plan (from `GET /me`); `None` on a server without billing.
    pub async fn plan(&self, cancel: CancelToken) -> Result<Option<Plan>, OvError> {
        let me = self.call(&cancel, |a, t| a.build_me(t), ov_protocol::auth::parse_me).await?;
        Ok(me.plan.as_ref().map(crate::impls::convert::plan))
    }

    /// A vault's sync quota in bytes, from the access token's `vlt` claim (`q`); `None` when only the
    /// server's own limit applies.
    pub async fn vault_quota(&self, vault_id: String) -> Result<Option<u64>, OvError> {
        let Some(token) = self.inner.tokens.access_token_now() else { return Ok(None) };
        let Ok(d) = ov_crypto::jwt::decode_jwt(&token) else { return Ok(None) };
        Ok(d.claims.vlt.unwrap_or_default().into_iter().find(|v| v.id == vault_id).and_then(|v| v.q))
    }

    /// Where to change plan after a `plan_limit` error: the error's `upgradeUrl` when it is a
    /// `/subscription/` page of this account's auth site (same scheme or https, host and port), else
    /// the site's `subscription/pricing` page. `None` when the issuer has no host.
    pub fn upgrade_url(&self, error: OvError) -> Option<String> {
        crate::impls::plan::upgrade_url(error.details.as_deref(), &self.inner.config.issuer)
    }

    /// Whether the App Store may sell a plan to this user (`org_id` `None`) or to one of their orgs.
    pub async fn apple_eligibility(
        &self,
        org_id: Option<String>,
        cancel: CancelToken,
    ) -> Result<AppleEligibility, OvError> {
        let e = self
            .call(&cancel, |a, t| a.build_apple_eligibility(t, org_id.as_deref()), ov_protocol::auth::parse_apple_eligibility)
            .await?;
        Ok(AppleEligibility { eligible: e.eligible, reason: e.reason })
    }

    /// Reports a StoreKit transaction's JWS to the auth server; returns the plan now.
    pub async fn report_apple_transaction(
        &self,
        jws: String,
        cancel: CancelToken,
    ) -> Result<AppleTransactionResult, OvError> {
        let r = self
            .call(&cancel, |a, t| a.build_report_apple_transaction(t, &jws), ov_protocol::auth::parse_apple_transaction)
            .await?;
        Ok(AppleTransactionResult { subject: r.subject, plan: crate::impls::convert::plan(&r.plan) })
    }
}
