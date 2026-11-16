//! Target-build probe for check 4: one exported function that opens a .kdbx with a raw 32-byte key
//! file and saves it again, so keepass-rs's open + save paths are linked. Built for
//! wasm32-unknown-unknown and aarch64-apple-ios; `--features baseline` builds the same export
//! without keepass-rs, to measure what keepass-rs adds to the wasm.

/// Opens `data` with `key` (32 bytes) and writes it back as KDBX 4.1. Returns the new length, or
/// 0 on error. Inputs are (ptr, len) pairs so the export has a C ABI.
///
/// # Safety
/// The pointers must be valid for the given lengths.
#[no_mangle]
pub unsafe extern "C" fn spike_rewrite(data: *const u8, len: usize, key: *const u8, key_len: usize) -> usize {
    // SAFETY: the caller guarantees both ranges are valid.
    let (data, key) = unsafe { (core::slice::from_raw_parts(data, len), core::slice::from_raw_parts(key, key_len)) };
    rewrite(data, key).map_or(0, |v| v.len())
}

#[cfg(not(feature = "baseline"))]
fn rewrite(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    use keepass::{Database, DatabaseKey};
    let k = || DatabaseKey::new().with_keyfile(&mut std::io::Cursor::new(key.to_vec())).ok();
    let mut db = Database::parse(data, k()?).ok()?;
    db.config.version = keepass::config::DatabaseVersion::KDB4(1);
    let mut out = Vec::new();
    db.save(&mut out, k()?).ok()?;
    Some(out)
}

#[cfg(feature = "baseline")]
fn rewrite(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut v = data.to_vec();
    v.extend_from_slice(key);
    Some(v)
}
