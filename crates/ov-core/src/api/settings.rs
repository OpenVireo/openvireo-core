//! Account settings (SPEC §16), two-step sign-in (§8), devices, recovery (§18) and deletion (§23).

use ov_error::OvError;

use super::{
    Account, CancelToken, DeletionPreview, Device, KdfOverrides, NewAccount, Principal, Profile, RecoveryReset,
    RecoveryStatus, Rfc3339, SecretBytes, TotpSetup,
};

impl Account {
    // ------------------------------------------------------------------------ profile (§16)

    /// `GET /me`: the signed-in user, plan and orgs, and (contract-v1.8) the KDF parameters and the
    /// keyset's public keys. Also refreshes the copy kept for offline unlock and follows an email
    /// change made on another device (Swift `me` and `refreshProfile`). Keys that don't verify are
    /// `invalid_public_keys`.
    pub async fn me(&self, cancel: CancelToken) -> Result<Profile, OvError> {
        self.me_impl(&cancel).await
    }

    /// Changes the master password (SPEC §16): checks the current one by unwrapping the keyset,
    /// registers OPAQUE again and wraps the same keyset with the new AUK, so vault keys keep
    /// working. The Secret Key stays. The server signs out the other devices. Returns the new AUK.
    pub async fn change_password(
        &self,
        current: SecretBytes,
        next: SecretBytes,
        kdf: Option<KdfOverrides>,
        cancel: CancelToken,
    ) -> Result<SecretBytes, OvError> {
        self.change_password_impl(current, next, kdf, &cancel).await
    }

    /// Email change, step 1 (SPEC §16): the server mails an 8-digit code to the new address.
    pub async fn request_email_change(&self, email: String, cancel: CancelToken) -> Result<(), OvError> {
        self.request_email_change_impl(&email, &cancel).await
    }

    /// Email change, step 2: with the mailed code and the master password (checked first), registers
    /// OPAQUE again under the new email. Keys, Secret Key and vaults stay as they are; what this
    /// device keeps under the old email moves to the new one.
    pub async fn change_email(
        &self,
        email: String,
        code: String,
        password: SecretBytes,
        cancel: CancelToken,
    ) -> Result<(), OvError> {
        self.change_email_impl(&email, &code, password, &cancel).await
    }

    /// The Secret Key kept on this device, to show the Emergency Kit again (SPEC §2). Needs the
    /// account unlocked (`signed_out` otherwise).
    pub async fn secret_key(&self) -> Result<Option<SecretBytes>, OvError> {
        self.secret_key_impl().await
    }

    /// A one-time link (valid 60 seconds) that signs the browser in to the auth website and opens
    /// `next`, a path there such as `/settings` (SPEC §16).
    pub async fn web_session_url(&self, next: Option<String>, cancel: CancelToken) -> Result<SecretBytes, OvError> {
        self.web_session_impl(next, &cancel).await
    }

    // ------------------------------------------------------------------- two-step (§8)

    /// Starts TOTP enrolment: a new secret and `otpauth://` URI to show as a QR code.
    pub async fn start_two_step(&self, cancel: CancelToken) -> Result<TotpSetup, OvError> {
        let e = self.call(&cancel, |a, t| a.build_totp_start(t), ov_protocol::auth::parse_totp_start).await?;
        Ok(TotpSetup { secret: e.secret.into_bytes(), uri: e.otpauth_uri.into_bytes() })
    }

    /// Turns two-step sign-in on with a code from the authenticator.
    pub async fn confirm_two_step(&self, code: String, cancel: CancelToken) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_totp_confirm(t, code.trim()), ov_protocol::parse_empty).await
    }

    /// Turns two-step sign-in off (needs a current code).
    pub async fn disable_two_step(&self, code: String, cancel: CancelToken) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_totp_disable(t, code.trim()), ov_protocol::parse_empty).await
    }

    // ---------------------------------------------------------------------------- devices

    /// Devices signed in to the account.
    pub async fn devices(&self, cancel: CancelToken) -> Result<Vec<Device>, OvError> {
        let l = self.call(&cancel, |a, t| a.build_list_devices(t), ov_protocol::auth::parse_devices).await?;
        Ok(l.devices.iter().map(crate::impls::convert::device).collect())
    }

    /// Signs a device out (revokes its session).
    pub async fn revoke_device(&self, device_id: String, cancel: CancelToken) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_revoke_device(t, &device_id), ov_protocol::parse_empty).await
    }

    // --------------------------------------------------------------------- recovery (§18)

    /// What an approved reset will do, for the recovery page. Works signed out.
    /// `recovery_not_ready` (409, `details.notBefore`) before the link works, `recovery_cancelled`
    /// (410) after a cancel, `session_expired` (410) once used or expired.
    pub async fn recover_info(&self, token: SecretBytes, cancel: CancelToken) -> Result<RecoveryReset, OvError> {
        let token = crate::impls::util::secret_text(token, "reset token")?;
        self.recover_info_impl(&token, &cancel).await
    }

    /// Resets the account with an approved `ov_rc_` token (SPEC §18): a new Secret Key, KDF salt and
    /// keyset as [`register`](Self::register) makes them, a new OPAQUE record, and the old keys and
    /// vaults archived for 30 days. This device ends up signed in and unlocked; every other device
    /// is signed out. Show the new Secret Key once. Errors as [`recover_info`](Self::recover_info).
    pub async fn recover(
        &self,
        token: SecretBytes,
        password: SecretBytes,
        kdf: Option<KdfOverrides>,
        trust_device: bool,
        cancel: CancelToken,
    ) -> Result<NewAccount, OvError> {
        self.recover_impl(token, password, kdf, trust_device, &cancel).await
    }

    /// Whether a recovery archive exists, until when, and whether it is locked (SPEC §18).
    pub async fn recovery_status(&self, cancel: CancelToken) -> Result<RecoveryStatus, OvError> {
        let r = self.call(&cancel, |a, t| a.build_recovery_status(t), ov_protocol::auth::parse_recovery_status).await?;
        Ok(crate::impls::convert::recovery_status(&r))
    }

    /// Restores the vaults archived by a reset into the current keys (SPEC §18) with the old master
    /// password and old Secret Key. Needs the account unlocked. Returns how many grants were
    /// restored. `unauthorized` for a wrong old password; `invalid_secret_key` (before anything is
    /// restored) when the old Secret Key doesn't open the archived keyset; `restore_locked`,
    /// `invalid_proof`, `session_expired`, `not_found` from the server.
    pub async fn restore_from_archive(
        &self,
        old_password: SecretBytes,
        old_secret_key: SecretBytes,
        cancel: CancelToken,
    ) -> Result<u32, OvError> {
        self.restore_from_archive_impl(old_password, old_secret_key, &cancel).await
    }

    // --------------------------------------------------------------------- deletion (§23)

    /// What deleting this account will do. Vault names are decrypted when the vault list can be read.
    pub async fn deletion_preview(&self, cancel: CancelToken) -> Result<DeletionPreview, OvError> {
        self.deletion_preview_impl(&cancel).await
    }

    /// Schedules this account's deletion (SPEC §23): checks the master password, then the server
    /// locks the account and erases it on the returned date. `confirm` is the email as the user
    /// typed it. This device is signed out and its offline cache deleted; the Secret Key stays so the
    /// user can still restore. A 409 `deletion_blocked` lists the orgs to hand over first, in
    /// `details` as `{"orgs": [{"id", "name"}, ...]}` (contract-v1.8). While an account is pending
    /// deletion, any other call the server refuses is 403 `account_pending_deletion` with `details`
    /// `{"scheduledFor": "<RFC 3339>"}` (contract-v1.8); restore it with
    /// [`restore_account`](Self::restore_account).
    pub async fn delete_account(
        &self,
        password: SecretBytes,
        confirm: String,
        cancel: CancelToken,
    ) -> Result<Rfc3339, OvError> {
        self.delete_account_impl(password, &confirm, &cancel).await
    }

    /// Restores this account while it is pending deletion, after signing in to it (SPEC §23).
    pub async fn restore_account(&self, password: SecretBytes, cancel: CancelToken) -> Result<(), OvError> {
        self.restore_account_impl(password, &cancel).await
    }

    /// Gives a personal vault to someone who already has access (SPEC §23). They become its owner
    /// with `manage`, this account loses access, and the new owner should rotate the key.
    pub async fn transfer_vault(&self, vault_id: String, to: Principal, cancel: CancelToken) -> Result<(), OvError> {
        self.call(&cancel, |a, t| a.build_transfer_vault(t, &vault_id, &to), ov_protocol::auth::parse_vault).await?;
        self.refresh_token(&cancel).await?;
        self.load_vault_list(&cancel).await.map(|_| ())
    }
}
