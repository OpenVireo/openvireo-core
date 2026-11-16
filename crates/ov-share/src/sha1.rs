//! SHA-1 (FIPS 180-4) and HMAC-SHA1 (RFC 2104), only for RFC 6238 TOTP codes, whose default hash
//! is HMAC-SHA1. Nothing else in the core uses SHA-1.
// OWNER-REQUEST: `sha1` (RustCrypto, =0.10.6, same digest 0.10 generation as sha2) isn't on the
// allow-list; this small implementation stands in for it and can be swapped for `Hmac<Sha1>`.

use zeroize::Zeroizing;

const BLOCK: usize = 64;

/// SHA-1 of `data`.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Zeroizing::new(data.to_vec());
    msg.push(0x80);
    while msg.len() % BLOCK != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut w = Zeroizing::new([0u32; 80]);
    for chunk in msg.as_chunks::<BLOCK>().0 {
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (o, x) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        o.copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// HMAC-SHA1(key, msg).
pub(crate) fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        k[..20].copy_from_slice(&sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Zeroizing::new(Vec::with_capacity(BLOCK + msg.len()));
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = sha1(&inner);
    let mut outer = Zeroizing::new(Vec::with_capacity(BLOCK + 20));
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        hex::encode(b)
    }

    #[test]
    fn fips_180_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&sha1(&vec![b'a'; 1_000_000])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        // lengths around the padding boundary
        assert_eq!(hex(&sha1(&[b'a'; 55])), "c1c8bbdc22796e28c0e15163d20899b65621d65a");
        assert_eq!(hex(&sha1(&[b'a'; 64])), "0098ba824b5c16427bd7a1122a5a442a25ec644d");
    }

    #[test]
    fn rfc_2202_hmac_vectors() {
        assert_eq!(hex(&hmac_sha1(&[0x0b; 20], b"Hi There")), "b617318655057264e28bc0b6fb378c8ef146be00");
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac_sha1(&[0xaa; 80], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }
}
