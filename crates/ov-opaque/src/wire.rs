//! Field lists, `u32 LE length ‖ bytes` per field: the client state format and the legacy C ABI's
//! input/output format.

use zeroize::Zeroizing;

/// The input wasn't exactly `n` well-formed fields.
pub(crate) struct Malformed;

/// Splits `b` into exactly `n` fields.
pub(crate) fn unpack(mut b: &[u8], n: usize) -> Result<Vec<&[u8]>, Malformed> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if b.len() < 4 {
            return Err(Malformed);
        }
        let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if b.len() - 4 < len {
            return Err(Malformed);
        }
        out.push(&b[4..4 + len]);
        b = &b[4 + len..];
    }
    if !b.is_empty() {
        return Err(Malformed);
    }
    Ok(out)
}

/// Joins fields. The result may hold secrets, so it is wiped on drop.
pub(crate) fn pack(fields: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(fields.iter().map(|f| 4 + f.len()).sum()));
    for f in fields {
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(f);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejects() {
        let p = pack(&[b"ab", b"", b"c"]);
        assert_eq!(&p[..], &[2, 0, 0, 0, b'a', b'b', 0, 0, 0, 0, 1, 0, 0, 0, b'c']);
        assert_eq!(unpack(&p, 3).ok().unwrap(), vec![&b"ab"[..], b"", b"c"]);
        assert!(unpack(&p, 2).is_err()); // trailing bytes
        assert!(unpack(&p, 4).is_err()); // too few
        assert!(unpack(&[5, 0, 0, 0, 1], 1).is_err()); // short field
        assert!(unpack(&[1, 0], 1).is_err()); // short length
    }
}
