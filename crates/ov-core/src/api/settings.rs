//! Account settings (SPEC §16), two-step sign-in (§8), devices, recovery (§18) and deletion (§23).

use ov_error::OvError;

use super::{
    Account, CancelToken, DeletionPreview, Device, KdfOverrides, NewAccount, Principal, Profile, RecoveryReset,
    RecoveryStatus, Rfc3339, SecretBytes, TotpSetup,
};

impl Account {
    // ------------------------------------------------------------------------ profile (§16)

    /// `GET /me`: the signed-in user, plan and orgs. Also refreshes the copy kept for offline unlock
    /// and follows an email change made on another device (Swift `me` and `refreshProfile`).
    pub async fn me(&self, cancel: CancelToken) -> Result<Profile, OvError> {
        todo!()
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
        todo!()
    }

    /// Email change, step 1 (SPEC §16): the server mails an 8-digit code to the new address.
    pub async fn request_email_change(&self, email: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
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
        todo!()
    }

    /// The Secret Key kept on this device, to show the Emergency Kit again (SPEC §2). Needs the
    /// account unlocked (`signed_out` otherwise).
    pub async fn secret_key(&self) -> Result<Option<SecretBytes>, OvError> {
        todo!()
    }

    /// A one-time link (valid 60 seconds) that signs the browser in to the auth website and opens
    /// `next`, a path there such as `/settings` (SPEC §16).
    pub async fn web_session_url(&self, next: Option<String>, cancel: CancelToken) -> Result<SecretBytes, OvError> {
        todo!()
    }

    // ------------------------------------------------------------------- two-step (§8)

    /// Starts TOTP enrolment: a new secret and `otpauth://` URI to show as a QR code.
    pub async fn start_two_step(&self, cancel: CancelToken) -> Result<TotpSetup, OvError> {
        todo!()
    }

    /// Turns two-step sign-in on with a code from the authenticator.
    pub async fn confirm_two_step(&self, code: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// Turns two-step sign-in off (needs a current code).
    pub async fn disable_two_step(&self, code: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    // ---------------------------------------------------------------------------- devices

    /// Devices signed in to the account.
    pub async fn devices(&self, cancel: CancelToken) -> Result<Vec<Device>, OvError> {
        todo!()
    }

    /// Signs a device out (revokes its session).
    pub async fn revoke_device(&self, device_id: String, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    // --------------------------------------------------------------------- recovery (§18)

    /// What an approved reset will do, for the recovery page. Works signed out.
    /// `recovery_not_ready` (409, `details.notBefore`) before the link works, `recovery_cancelled`
    /// (410) after a cancel, `session_expired` (410) once used or expired.
    pub async fn recover_info(&self, token: SecretBytes, cancel: CancelToken) -> Result<RecoveryReset, OvError> {
        todo!()
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
        todo!()
    }

    /// Whether a recovery archive exists, until when, and whether it is locked (SPEC §18).
    pub async fn recovery_status(&self, cancel: CancelToken) -> Result<RecoveryStatus, OvError> {
        todo!()
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
        todo!()
    }

    // --------------------------------------------------------------------- deletion (§23)

    /// What deleting this account will do. Vault names are decrypted when the vault list can be read.
    pub async fn deletion_preview(&self, cancel: CancelToken) -> Result<DeletionPreview, OvError> {
        todo!()
    }

    /// Schedules this account's deletion (SPEC §23): checks the master password, then the server
    /// locks the account and erases it on the returned date. `confirm` is the email as the user
    /// typed it. This device is signed out and its offline cache deleted; the Secret Key stays so the
    /// user can still restore. A 409 `deletion_blocked` lists the orgs to hand over first.
    pub async fn delete_account(
        &self,
        password: SecretBytes,
        confirm: String,
        cancel: CancelToken,
    ) -> Result<Rfc3339, OvError> {
        todo!()
    }

    /// Restores this account while it is pending deletion, after signing in to it (SPEC §23).
    pub async fn restore_account(&self, password: SecretBytes, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }

    /// Gives a personal vault to someone who already has access (SPEC §23). They become its owner
    /// with `manage`, this account loses access, and the new owner should rotate the key.
    pub async fn transfer_vault(&self, vault_id: String, to: Principal, cancel: CancelToken) -> Result<(), OvError> {
        todo!()
    }
}
