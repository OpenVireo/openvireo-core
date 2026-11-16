//! Little-endian byte reading and the crate's error constructors.

use ov_error::{OvError, OvErrorCode};

/// A `kdbx_error` with `message`.
pub(crate) fn err(message: impl Into<String>) -> OvError {
    OvError::new(OvErrorCode::KdbxError, message)
}

/// The key doesn't open the file (TS `mapError`: kdbxweb `InvalidKey` → `vault_key_mismatch`).
pub(crate) fn wrong_key() -> OvError {
    OvError::new(OvErrorCode::VaultKeyMismatch, "wrong key for this database")
}

fn truncated() -> OvError {
    err("the file is truncated")
}

/// A cursor over a byte slice.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let r = &self.data[self.pos..];
        self.pos = self.data.len();
        r
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], OvError> {
        if self.remaining() < n {
            return Err(truncated());
        }
        let r = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(r)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], OvError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, OvError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, OvError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, OvError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
}

/// Reads a little-endian integer of exactly `N` bytes.
pub(crate) fn le_exact<const N: usize>(v: &[u8], what: &str) -> Result<[u8; N], OvError> {
    v.try_into().map_err(|_| err(format!("{what} has the wrong size")))
}
