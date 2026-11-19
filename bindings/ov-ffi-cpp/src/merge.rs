//! The sync merge on serialized vaults (ov-merge `merge_in_place` on ov-kdbx) for C++: the desktop's
//! account-vault merge path, bytes in and bytes out (README.md, "Desktop swap").
//!
//! The caller serialises its copies with a throwaway key (random 32 bytes as the password
//! component), so the user's real vault key never crosses; the merged copies come back written with
//! the same key and KDF, and the caller loads them back into its own model.

use ov_error::OvError;
use ov_kdbx::CompositeKey;
use ov_merge::{ChangeSubject as Subject, ChangeType as Change};

use crate::crypto::invalid;
use crate::edge::{edge, FfiError};
use crate::ffi;

/// The ov-kdbx key whose composite hash is KeePassXC's: SHA-256 of the components' raw 32-byte keys
/// in order (one or two: password and/or key file).
fn composite_key(what: &str, components: &[u8]) -> Result<CompositeKey, OvError> {
    let (parts, rest) = components.as_chunks::<32>();
    if parts.is_empty() || parts.len() > 2 || !rest.is_empty() {
        return Err(invalid(format!("{what} is one or two 32-byte components, got {} bytes", components.len())));
    }
    let mut key = CompositeKey::new().with_password_hash(&parts[0]);
    if let Some(second) = parts.get(1) {
        // A 32-byte key file is used as it is, so this is the second raw component
        key = key.with_key_file(second);
    }
    Ok(key)
}

fn change(c: &ov_merge::MergeChange) -> ffi::KdbxMergeChange {
    ffi::KdbxMergeChange {
        change: match c.change {
            Change::Added => ffi::ChangeType::Added,
            Change::Modified => ffi::ChangeType::Modified,
            Change::Moved => ffi::ChangeType::Moved,
            Change::Deleted => ffi::ChangeType::Deleted,
            Change::Metadata => ffi::ChangeType::Metadata,
        },
        subject: match c.subject {
            Subject::Entry => ffi::ChangeSubject::Entry,
            Subject::Group => ffi::ChangeSubject::Group,
            Subject::Database => ffi::ChangeSubject::Database,
        },
        uuid: c.uuid.map(|u| u.as_bytes().to_vec()).unwrap_or_default(),
        title: c.title.clone().unwrap_or_default(),
        group: c.group.clone().unwrap_or_default(),
        details: c.details.clone(),
    }
}

/// `ov::merge_kdbx`: the three-way sync merge of two KDBX copies against their common base (an
/// empty `base` means none) at `now` (Unix seconds). Each `*_key` is the copy's composite key as
/// one or two raw 32-byte components. A copy comes back (written with its own key and KDF) only
/// when the merge changed it; otherwise its bytes are empty.
pub fn merge_kdbx(
    local: &[u8],
    local_key: &[u8],
    remote: &[u8],
    remote_key: &[u8],
    base: &[u8],
    base_key: &[u8],
    now: i64,
) -> Result<ffi::KdbxMergeResult, FfiError> {
    edge(|| {
        let local_key = composite_key("local_key", local_key)?;
        let remote_key = composite_key("remote_key", remote_key)?;
        let mut l = ov_kdbx::read(local, &local_key)?;
        let mut r = ov_kdbx::read(remote, &remote_key)?;
        let b = if base.is_empty() { None } else { Some(ov_kdbx::read(base, &composite_key("base_key", base_key)?)?) };
        let report = ov_merge::merge_in_place(&mut l, &mut r, b.as_ref(), now);
        Ok(ffi::KdbxMergeResult {
            local: if report.local_changed { ov_kdbx::write(&l, &local_key)? } else { Vec::new() },
            remote: if report.remote_changed { ov_kdbx::write(&r, &remote_key)? } else { Vec::new() },
            local_changed: report.local_changed,
            remote_changed: report.remote_changed,
            changes: report.changes.iter().map(change).collect(),
            conflicts: report
                .conflicts
                .iter()
                .map(|c| ffi::KdbxMergeConflict {
                    uuid: c.uuid.hyphenated().to_string(),
                    title: c.title.clone(),
                    fields: c.fields.clone(),
                })
                .collect(),
        })
    })
}
