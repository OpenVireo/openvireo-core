//! Test-side controls: seed and inspect server state, simulate other devices and server accidents.

use ov_protocol::types::{OrgRole, Plan};
use serde_json::Value;

use super::{auth, sync, BlobData, TestServers};

impl TestServers {
    // -------------------------------------------------------------------------------- sync server

    fn blob(&self, key: &str) -> Option<BlobData> {
        let w = self.world();
        w.sync.current(key).map(|v| BlobData { data: v.data.clone(), etag: v.etag.clone(), revision: v.revision })
    }

    /// The vault blob's current version.
    pub fn vault_blob(&self, vault_id: &str) -> Option<BlobData> {
        self.blob(&format!("vaults/{vault_id}"))
    }

    /// A legacy database's current version.
    pub fn database_blob(&self, id: &str) -> Option<BlobData> {
        self.blob(&format!("databases/{id}"))
    }

    /// Every kept version of a vault blob, oldest first.
    pub fn vault_history(&self, vault_id: &str) -> Vec<BlobData> {
        let w = self.world();
        w.sync
            .blobs
            .get(&format!("vaults/{vault_id}"))
            .map(|l| {
                l.iter()
                    .map(|v| BlobData { data: v.data.clone(), etag: v.etag.clone(), revision: v.revision })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Another device uploads `data` as the vault's next revision (no precondition); open streams
    /// get the `vault` event.
    pub fn put_vault_blob(&self, vault_id: &str, data: &[u8]) {
        sync::store(&mut self.world(), &format!("vaults/{vault_id}"), data);
    }

    /// The same for a legacy database.
    pub fn put_database_blob(&self, id: &str, data: &[u8]) {
        sync::store(&mut self.world(), &format!("databases/{id}"), data);
    }

    fn rollback(&self, key: &str, to_revision: i64) {
        let mut w = self.world();
        if let Some(list) = w.sync.blobs.get_mut(key) {
            list.retain(|v| v.revision <= to_revision);
            if list.is_empty() {
                w.sync.blobs.remove(key);
            }
        }
    }

    /// The sync server was restored from a backup: the vault's versions after `to_revision` are
    /// gone (so its revision goes back), without any event. `to_revision` 0 drops them all.
    pub fn rollback_vault(&self, vault_id: &str, to_revision: i64) {
        self.rollback(&format!("vaults/{vault_id}"), to_revision);
    }

    /// [`rollback_vault`](Self::rollback_vault) for a legacy database.
    pub fn rollback_database(&self, id: &str, to_revision: i64) {
        self.rollback(&format!("databases/{id}"), to_revision);
    }

    /// The sync server lost the vault's blob and history, without any event.
    pub fn lose_vault(&self, vault_id: &str) {
        self.world().sync.blobs.remove(&format!("vaults/{vault_id}"));
    }

    /// The sync server lost a legacy database and its history, without any event.
    pub fn lose_database(&self, id: &str) {
        self.world().sync.blobs.remove(&format!("databases/{id}"));
    }

    /// The sync server lost every blob (a new, empty database), without any event.
    pub fn lose_all_blobs(&self) {
        self.world().sync.blobs.clear();
    }

    /// The sync server ends every open event stream (a restart); clients reconnect.
    pub fn close_streams(&self) {
        self.world().sync.close_streams();
    }

    /// Ends the streams whose token's `exp` has passed on the servers' clock (the real server does
    /// it on a timer; call this after advancing the clock).
    pub fn end_expired_streams(&self) {
        sync::end_expired_streams(&mut self.world());
    }

    /// Lets another legacy device token use the `databases/*` routes.
    pub fn add_device_token(&self, token: &str, user: &str) {
        self.world().sync.add_device_token(token, user);
    }

    // -------------------------------------------------------------------------------- auth server

    /// The JWKS the auth server signs access tokens with.
    pub fn jwks(&self) -> ov_crypto::jwt::Jwks {
        self.world().auth.jwks()
    }

    /// The user id of an account.
    pub fn user_id(&self, email: &str) -> Option<String> {
        auth::user_id(&self.world(), email)
    }

    /// Approves an account reset (what the admin review does) and returns the `ov_rc_` token of the
    /// mailed link; it works `delay_secs` from now on the servers' clock, for 72 hours (SPEC §18).
    pub fn approve_reset(&self, email: &str, delay_secs: i64) -> String {
        auth::approve_reset(&mut self.world(), email, delay_secs)
    }

    /// The notice's cancel link.
    pub fn cancel_reset(&self, token: &str) {
        auth::cancel_reset(&mut self.world(), token);
    }

    /// Gives the user a fixed TOTP code (`None` removes it): logins then need `POST /auth/login/mfa`
    /// with it, as the TS fake's `totp` map. Whether the user exists.
    pub fn set_totp_code(&self, email: &str, code: Option<&str>) -> bool {
        auth::set_totp_code(&mut self.world(), email, code)
    }

    /// The code the server accepts now for the user: from the TOTP enrolled with `POST /me/totp`
    /// (confirmed or pending), else the fixed code.
    pub fn totp_now(&self, email: &str) -> Option<String> {
        auth::totp_now(&self.world(), email)
    }

    /// The 8-digit code "mailed" by `POST /me/email`, by user id.
    pub fn email_code(&self, user_id: &str) -> Option<String> {
        self.world().auth.email_codes.get(user_id).map(|(_, c)| c.clone())
    }

    /// The token "mailed" with an org invitation.
    pub fn invitation_token(&self, org_id: &str, email: &str) -> Option<String> {
        auth::invitation_token(&self.world(), org_id, email)
    }

    /// Adds an existing user to an org as `accepted` (the invitation skipped), for an admin to
    /// confirm. `role` is `owner`, `admin` or `member`. Whether the user and org exist.
    pub fn add_member(&self, org_id: &str, email: &str, role: &str) -> bool {
        auth::add_member(&mut self.world(), org_id, email, OrgRole::from(role))
    }

    /// The user's personal plan in `GET /me` and the deletion preview (SPEC §19). Its
    /// `limits.vault_bytes` becomes the `q` quota in the user's next tokens.
    pub fn set_plan(&self, user_id: &str, plan: Plan) {
        self.world().auth.plans.insert(user_id, plan);
    }

    /// How old a token may be for the routes that need a recent sign-in (default 5 minutes).
    pub fn set_recent_token_ms(&self, ms: i64) {
        self.world().auth.recent_token_ms = ms;
    }

    /// Access-token lifetime (default 600 s).
    pub fn set_access_token_ttl_secs(&self, secs: i64) {
        self.world().auth.token_ttl_secs = secs;
    }

    /// The deletion grace period (default 30 days).
    pub fn set_deletion_days(&self, days: i64) {
        self.world().auth.deletion_days = days;
    }

    /// Signs a principal out everywhere: its access and refresh tokens stop working.
    pub fn revoke_sessions(&self, principal: &str) {
        self.world().auth.revoke_principal(principal);
    }

    /// Every `access` event the auth server sent, as `{"subjects": [...], "data": {...}}`.
    pub fn access_events(&self) -> Vec<Value> {
        self.world().auth.access_events.clone()
    }
}
