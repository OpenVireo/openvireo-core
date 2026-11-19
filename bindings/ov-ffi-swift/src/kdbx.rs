//! A `.kdbx` file's outer header, read without the key (task W3-BS2): the iOS AutoFill extension
//! checks a local file's KDF memory against its memory limit before unlocking it (`KDBXFile.peekKDF`).
//! Opening, editing and saving go through `Vault.open_local` / `save_local`.

use ov_kdbx::model;

use crate::error::OvError;
use crate::guard::guard;

/// A KDBX key-derivation function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum KdbxKdfKind {
    /// AES-KDF (KDBX 3.1 and some 4.x files).
    AesKdf,
    /// Argon2d.
    Argon2d,
    /// Argon2id.
    Argon2id,
    /// A KDF the core doesn't know (opening the file fails).
    Other,
}

/// What [`kdbx_peek_header`] reads.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct KdbxHeaderInfo {
    /// Major version (3 or 4).
    pub version_major: u16,
    /// Minor version.
    pub version_minor: u16,
    /// The KDF.
    pub kdf: KdbxKdfKind,
    /// Argon2 memory in bytes (0 for AES-KDF).
    pub memory_bytes: u64,
    /// Argon2 iterations, or AES-KDF rounds.
    pub iterations: u64,
    /// Argon2 lanes (0 for AES-KDF).
    pub parallelism: u32,
}

/// Reads a `.kdbx` file's version and KDF without the key; `kdbx_error` if it isn't a KDBX file.
#[uniffi::export]
pub fn kdbx_peek_header(kdbx: Vec<u8>) -> Result<KdbxHeaderInfo, OvError> {
    guard(|| {
        let h = ov_kdbx::peek_header(&kdbx)?;
        let (kdf, memory_bytes, iterations, parallelism) = match &h.kdf {
            model::Kdf::AesKdf { rounds, .. } => (KdbxKdfKind::AesKdf, 0, *rounds, 0),
            model::Kdf::Argon2 { kind, memory, iterations, parallelism, .. } => {
                let k = match kind {
                    model::Argon2Type::D => KdbxKdfKind::Argon2d,
                    model::Argon2Type::Id => KdbxKdfKind::Argon2id,
                };
                (k, *memory, *iterations, *parallelism)
            }
            model::Kdf::Other(_) => (KdbxKdfKind::Other, 0, 0, 0),
        };
        Ok(KdbxHeaderInfo {
            version_major: h.version.major,
            version_minor: h.version.minor,
            kdf,
            memory_bytes,
            iterations,
            parallelism,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peeks_the_desktop_fixtures() {
        let h = kdbx_peek_header(ov_testkit::read_vector("kdbx/desktop-kdbx4-argon2d.kdbx")).unwrap();
        assert_eq!((h.version_major, h.kdf), (4, KdbxKdfKind::Argon2d));
        assert!(h.memory_bytes > 0 && h.parallelism >= 1);
        let h = kdbx_peek_header(ov_testkit::read_vector("kdbx/desktop-kdbx31.kdbx")).unwrap();
        assert_eq!((h.version_major, h.kdf), (3, KdbxKdfKind::AesKdf));
        let OvError::Failure { code, .. } = kdbx_peek_header(b"nope".to_vec()).unwrap_err();
        assert_eq!(code, crate::OvErrorCode::KdbxError);
    }
}
