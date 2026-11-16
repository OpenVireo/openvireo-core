//! SPEC §2: the 128-bit Secret Key and its `K1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX` display form.
//!
//! Port of `packages/sdk/src/crypto/secret-key.ts`.

use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::primitives::random_array;

/// Secret Key length (bytes).
pub const SECRET_KEY_BYTES: usize = 16;

/// Crockford base32 (no I, L, O, U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 128 bits plus two zero padding bits = 26 × 5.
const CHARS: usize = 26;

fn invalid(msg: impl Into<String>) -> OvError {
    OvError::new(OvErrorCode::InvalidSecretKey, msg)
}

/// 16 random bytes for a new account (SPEC §2). Created on the client; the server never sees it.
pub fn generate_secret_key() -> Result<Zeroizing<[u8; SECRET_KEY_BYTES]>, OvError> {
    random_array::<SECRET_KEY_BYTES>()
}

/// The display form: `K1-` + Crockford base32 of the 128 bits big-endian, padded with two zero
/// bits to 26 characters, grouped 6-5-5-5-5.
pub fn format_secret_key(raw: &[u8; SECRET_KEY_BYTES]) -> Zeroizing<String> {
    let mut chars = Zeroizing::new([0u8; CHARS]);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &b in raw {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            chars[n] = CROCKFORD[((acc >> bits) & 31) as usize];
            n += 1;
        }
        acc &= (1 << bits) - 1;
    }
    // 128 = 25 × 5 + 3: the last 3 bits plus two zero padding bits.
    chars[n] = CROCKFORD[((acc << 2) & 31) as usize];
    let s = &chars[..];
    let mut out = Zeroizing::new(String::with_capacity(33));
    out.push_str("K1");
    for (from, to) in [(0, 6), (6, 11), (11, 16), (16, 21), (21, 26)] {
        out.push('-');
        out.extend(s[from..to].iter().map(|&c| c as char));
    }
    out
}

/// Parses a displayed Secret Key, forgiving the way people type it: whitespace and `-` are
/// removed, letters are uppercased, and `O→0`, `I→1`, `L→1`.
///
/// Fails with [`OvErrorCode::InvalidSecretKey`] without the `K1` prefix, without exactly 26
/// characters after it, with a character outside the alphabet, or with the padding bits set.
pub fn parse_secret_key(display: &str) -> Result<Zeroizing<[u8; SECRET_KEY_BYTES]>, OvError> {
    let cleaned: Zeroizing<String> =
        Zeroizing::new(display.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>());
    let upper = Zeroizing::new(cleaned.to_uppercase());
    let s: Zeroizing<Vec<char>> = Zeroizing::new(
        upper
            .chars()
            .map(|c| match c {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            })
            .collect(),
    );
    if s.len() < 2 || s[0] != 'K' || s[1] != '1' {
        return Err(invalid("a Secret Key starts with K1"));
    }
    let body = &s[2..];
    if body.len() != CHARS {
        return Err(invalid("a Secret Key has 26 characters after K1"));
    }
    let mut out = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &c in body {
        let v = u8::try_from(c)
            .ok()
            .and_then(|b| CROCKFORD.iter().position(|&x| x == b))
            .ok_or_else(|| invalid(format!("invalid character \"{c}\" in Secret Key")))?;
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 && n < SECRET_KEY_BYTES {
            bits -= 8;
            out[n] = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    // 130 - 128 = 2 padding bits remain in `acc`.
    if acc != 0 {
        return Err(invalid("invalid Secret Key (padding bits are set)"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_random_keys() {
        for _ in 0..50 {
            let raw = generate_secret_key().unwrap();
            assert_eq!(*parse_secret_key(&format_secret_key(&raw)).unwrap(), *raw);
        }
    }

    #[test]
    fn rejects_bad_prefix_length_padding_and_characters() {
        let err = |s: &str| parse_secret_key(s).unwrap_err();
        assert!(err("K2-000000-00000-00000-00000-00000").is(OvErrorCode::InvalidSecretKey));
        assert!(err("K1-000000-00000-00000-00000-0000").message.contains("26 characters"));
        assert!(err("K1-ZZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ").message.contains("padding"));
        assert!(err("K1-UUUUUU-00000-00000-00000-00000").message.contains("invalid character"));
        assert!(err("").is(OvErrorCode::InvalidSecretKey));
    }
}
