//! Share links (SPEC §22): no-login links to one item or a text, encrypted with a key that only the
//! link's fragment holds. Creating and listing need an account; opening doesn't
//! ([`OvClient::open_share`](crate::api::OvClient::open_share)).

use ov_error::OvError;

use super::{Account, CancelToken, EntryRecord, KdfParams, Rfc3339, SecretBytes};

/// Options of a new share link.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareOptions {
    /// Lifetime in seconds: 3600 to 30 days, and at most the plan's `share_link_days`.
    pub expires_in: u32,
    /// Opens allowed; `None` is unlimited until it expires.
    pub max_opens: Option<u32>,
    /// A passcode the recipient types as well as opening the link.
    pub passcode: Option<SecretBytes>,
    /// The vault the item came from (for the org policy and the owner's list); `None` for text.
    pub vault_id: Option<String>,
    /// The entry it came from; `None` for text.
    pub entry_id: Option<String>,
}

impl std::fmt::Debug for ShareOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareOptions")
            .field("expires_in", &self.expires_in)
            .field("max_opens", &self.max_opens)
            .field("passcode", &self.passcode.is_some())
            .field("vault_id", &self.vault_id)
            .field("entry_id", &self.entry_id)
            .finish()
    }
}

/// A share link just made.
#[derive(Clone, PartialEq, Eq)]
pub struct CreatedShare {
    /// The share id.
    pub id: String,
    /// The link to send. Its fragment (after `#`) is the key and is never sent to a server.
    pub url: SecretBytes,
    /// When it expires.
    pub expires_at: Rfc3339,
}

impl std::fmt::Debug for CreatedShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedShare").field("id", &self.id).field("expires_at", &self.expires_at).finish()
    }
}

/// Which item a share came from, readable only by its owner (encrypted under a key derived from
/// their `enc_sk`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRef {
    /// The vault.
    pub vault: Option<String>,
    /// The entry UUID (32 lowercase hex digits).
    pub entry: Option<String>,
    /// The title when shared.
    pub title: String,
}

/// A share link in its owner's list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareListing {
    /// The share id.
    pub id: String,
    /// The vault it came from.
    pub vault_id: Option<String>,
    /// Where it came from; `None` when made with keys this account no longer has.
    pub reference: Option<ShareRef>,
    /// It has a passcode.
    pub passcode: bool,
    /// Opens allowed.
    pub max_opens: Option<u32>,
    /// Opens so far.
    pub opens: u32,
    /// When it was opened.
    pub opened_at: Vec<Rfc3339>,
    /// Created.
    pub created_at: Rfc3339,
    /// Expiry.
    pub expires_at: Rfc3339,
    /// `pending`, `active` or `ended`.
    pub status: String,
    /// When it ended.
    pub ended_at: Option<Rfc3339>,
    /// `expired`, `opened`, `revoked`, `passcode`, `access_lost` or `policy`.
    pub end_reason: Option<String>,
}

/// What a share link holds (SPEC §22). Pages render every value as plain text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePayload {
    /// Format version, 1.
    pub v: u32,
    /// `entry` or `text`.
    pub kind: String,
    /// The title.
    pub title: Option<String>,
    /// Chosen by the sender and shown as such.
    pub shared_by: Option<String>,
    /// The fields.
    pub fields: Vec<ShareField>,
}

/// One field of a [`SharePayload`]. `Debug` hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareField {
    /// `username`, `password`, `url`, `notes`, `totp`, `custom` or `text` (open set).
    pub k: String,
    /// The label to show.
    pub label: String,
    /// The value.
    pub value: SecretBytes,
    /// Hidden until shown.
    pub protected: bool,
}

impl std::fmt::Debug for ShareField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareField")
            .field("k", &self.k)
            .field("label", &self.label)
            .field("protected", &self.protected)
            .finish()
    }
}

/// A field an entry can share, for the share dialog's checkboxes.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareableField {
    /// The entry field name, e.g. `UserName`.
    pub name: String,
    /// The share kind it becomes.
    pub kind: String,
    /// The label.
    pub label: String,
    /// The value.
    pub value: SecretBytes,
    /// Protected in the entry.
    pub protected: bool,
}

impl std::fmt::Debug for ShareableField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareableField").field("name", &self.name).field("kind", &self.kind).finish()
    }
}

/// What the public page knows before opening a share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareInfo {
    /// Expiry.
    pub expires_at: Rfc3339,
    /// Opens left; `None` is unlimited until it expires.
    pub opens_left: Option<u32>,
    /// Set when the share needs a passcode.
    pub kdf: Option<KdfParams>,
}

/// An opened share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedShare {
    /// The decrypted payload.
    pub payload: SharePayload,
    /// Opens left after this one.
    pub opens_left: Option<u32>,
}

impl Account {
    /// Where links point: the discovery `share` URL, else `<web>/s`; `None` when neither is known.
    pub fn share_base(&self) -> Option<String> {
        self.share_base_url()
    }

    /// Why this account can't make a share link from a vault of `org_id` (the org's policy, SPEC
    /// §22), as text for the UI; `None` when it can (or for personal vaults).
    pub async fn share_blocked_reason(&self, org_id: Option<String>) -> Result<Option<String>, OvError> {
        self.share_blocked(org_id).await
    }

    /// Makes a share link for `payload` (see [`item_share_payload`] and [`text_share_payload`]). The
    /// content is encrypted here with a fresh key that only the link holds; `unsupported` when the
    /// server has no share page.
    pub async fn create_share(
        &self,
        payload: SharePayload,
        options: ShareOptions,
        cancel: CancelToken,
    ) -> Result<CreatedShare, OvError> {
        self.create_share_impl(payload, options, &cancel).await
    }

    /// This account's share links, newest first, with those that ended in the last 30 days.
    pub async fn list_shares(&self, cancel: CancelToken) -> Result<Vec<ShareListing>, OvError> {
        self.list_shares_impl(&cancel).await
    }

    /// Ends a share link at once; its content is deleted from the server.
    pub async fn revoke_share(&self, share_id: String, cancel: CancelToken) -> Result<(), OvError> {
        self.revoke_share_impl(&share_id, &cancel).await
    }
}

/// The fields an item shares by default: `UserName`, `Password`, `URL`. The rest are opt-in.
pub fn default_share_fields() -> Vec<String> {
    ov_share::default_share_fields()
}

/// The fields of an entry that can be shared (standard ones first, then custom; TOTP as a code
/// source), in display order.
pub fn shareable_fields(entry: EntryRecord) -> Vec<ShareableField> {
    crate::impls::share::shareable(&entry)
}

/// A payload with the named fields of an entry.
pub fn item_share_payload(entry: EntryRecord, names: Vec<String>, shared_by: Option<String>) -> SharePayload {
    let fields = crate::impls::share::entry_fields(&entry.fields);
    crate::impls::share::api_payload(&ov_share::item_share_payload(&fields, &names, shared_by.as_deref()))
}

/// A payload holding a text.
pub fn text_share_payload(text: SecretBytes, title: Option<String>, shared_by: Option<String>) -> SharePayload {
    let text = String::from_utf8_lossy(&text).into_owned();
    let text = zeroize::Zeroizing::new(text);
    crate::impls::share::api_payload(&ov_share::text_share_payload(&text, title.as_deref(), shared_by.as_deref()))
}
