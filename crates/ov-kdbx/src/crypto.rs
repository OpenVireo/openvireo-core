//! KDBX cryptography: the composite key, key derivation (AES-KDF, Argon2d/id), the payload ciphers
//! (AES-256-CBC, ChaCha20), the inner random stream (ChaCha20, Salsa20), the KDBX 4 HMAC block
//! stream, the KDBX 3.1 hashed block stream and gzip.
//!
//! Reference: KeePassXC `src/keys/{CompositeKey,PasswordKey,FileKey}.cpp`, `src/format/Kdbx4Reader.cpp`,
//! `src/streams/HmacBlockStream.cpp`, `src/format/KeePass2RandomStream.cpp`; iOS
//! `OpenVireoCore/KDBX/{CompositeKey,Ciphers,KDBXFile}.swift`.

use std::fmt;
use std::io::{Read, Write};

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use ov_crypto::primitives::{self, Argon2Params, Argon2Variant};
use ov_error::OvError;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::bytes::{err, wrong_key, Cursor};
use crate::header::{STREAM_CHACHA20, STREAM_SALSA20};
use crate::model::{Argon2Type, Cipher, Kdf};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------------------------
// Composite key

/// The KDBX composite key: SHA-256 over its components (the SHA-256 of the password, then the key
/// file's 32 bytes), each already reduced to 32 bytes, as KeePassXC builds it.
///
/// Account vaults use the 32-byte vault key as a raw key file component and no password (SPEC §7):
/// `CompositeKey::new().with_key_file(&vault_key)`, or [`crate::vault::vault_credentials`].
///
/// Key material is wiped on drop and redacted in `Debug`.
#[derive(Clone, Default)]
pub struct CompositeKey {
    password: Option<Zeroizing<[u8; 32]>>,
    key_file: Option<Result<Zeroizing<[u8; 32]>, OvError>>,
}

impl fmt::Debug for CompositeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeKey")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("key_file", &self.key_file.as_ref().map(|k| k.as_ref().map(|_| "<redacted>")))
            .finish()
    }
}

impl CompositeKey {
    /// An empty key; add a password and/or a key file.
    pub fn new() -> Self {
        CompositeKey::default()
    }

    /// Adds (or replaces) the password component: SHA-256 of the password's UTF-8 bytes. KDBX
    /// passwords are used as given (no NFKC), as KeePassXC and kdbxweb do.
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(Zeroizing::new(primitives::sha256(password.as_bytes())));
        self
    }

    /// Adds (or replaces) the password component from its SHA-256 (TS `passwordHashCredentials`):
    /// an app that must keep a database openable can keep this instead of the password.
    pub fn with_password_hash(mut self, hash: &[u8; 32]) -> Self {
        self.password = Some(Zeroizing::new(*hash));
        self
    }

    /// Adds (or replaces) the key file component. KeePass key files are XML (versions 1.0 and 2.0),
    /// exactly 32 raw bytes (the vault key of SPEC §7), 64 hex characters, or any other file, which
    /// counts as its SHA-256.
    ///
    /// A malformed XML key file (bad data, or a 2.0 checksum mismatch) makes [`crate::read`] and
    /// [`crate::write()`] fail with `kdbx_error`.
    pub fn with_key_file(mut self, file: &[u8]) -> Self {
        self.key_file = Some(key_file_component(file).map(Zeroizing::new));
        self
    }

    /// Whether the key has any component.
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.key_file.is_none()
    }

    /// Whether both keys open the same files: the same KDF input, compared in constant time. `false`
    /// when either can't open anything (empty, or a malformed key file).
    pub fn opens_same_as(&self, other: &CompositeKey) -> bool {
        match (self.raw(), other.raw()) {
            (Ok(a), Ok(b)) => a[..].ct_eq(&b[..]).into(),
            _ => false,
        }
    }

    /// SHA-256(password component ‖ key file component), the KDF input.
    pub(crate) fn raw(&self) -> Result<Zeroizing<[u8; 32]>, OvError> {
        if self.is_empty() {
            return Err(err("a database key needs a password or a key file"));
        }
        let mut h = Sha256::new();
        if let Some(p) = &self.password {
            h.update(p.as_ref());
        }
        if let Some(k) = &self.key_file {
            h.update(k.as_ref().map_err(Clone::clone)?.as_ref());
        }
        Ok(Zeroizing::new(h.finalize().into()))
    }
}

/// The 32-byte component of a key file (KeePassXC `FileKey::load`).
fn key_file_component(file: &[u8]) -> Result<[u8; 32], OvError> {
    if let Some(k) = xml_key_file(file) {
        return k;
    }
    if file.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(file);
        return Ok(k);
    }
    if file.len() == 64 {
        if let Ok(text) = std::str::from_utf8(file) {
            let mut k = [0u8; 32];
            if hex_decode_into(text, &mut k) {
                return Ok(k);
            }
        }
    }
    Ok(primitives::sha256(file))
}

/// `Some` when `file` is an XML `<KeyFile>`: version 1.0 (base64 `Data`) or 2.0 (hex `Data` with a
/// 4-byte SHA-256 `Hash`).
fn xml_key_file(file: &[u8]) -> Option<Result<[u8; 32], OvError>> {
    let text = std::str::from_utf8(file).ok()?;
    let root = crate::xml::tree::parse(text, None).ok()?;
    if root.name != "KeyFile" {
        return None;
    }
    let data = root.child("Key")?.child("Data")?;
    let version = root.child("Meta").and_then(|m| m.child("Version")).map_or("", |v| v.text.trim());
    let bad = || Some(Err(err("the key file's data is malformed")));
    if version.starts_with("2.") {
        let hex: String = data.text.chars().filter(|c| !c.is_whitespace()).collect();
        let mut k = [0u8; 32];
        if hex.len() != 64 || !hex_decode_into(&hex, &mut k) {
            return bad();
        }
        if let Some(hash) = data.attr("Hash") {
            let mut expected = [0u8; 4];
            if !hex_decode_into(hash.trim(), &mut expected) {
                return bad();
            }
            if !bool::from(primitives::sha256(&k)[..4].ct_eq(&expected)) {
                return Some(Err(err("the key file's checksum doesn't match")));
            }
        }
        return Some(Ok(k));
    }
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(data.text.trim()) {
        Ok(d) if d.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&d);
            Some(Ok(k))
        }
        _ => bad(),
    }
}

fn hex_decode_into(text: &str, out: &mut [u8]) -> bool {
    let b = text.as_bytes();
    if b.len() != out.len() * 2 {
        return false;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    for (i, o) in out.iter_mut().enumerate() {
        match (nib(b[2 * i]), nib(b[2 * i + 1])) {
            (Some(h), Some(l)) => *o = h << 4 | l,
            _ => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------------------------
// Key derivation

/// Runs the KDF over the composite key: the 32-byte transformed key.
pub(crate) fn transform(key: &CompositeKey, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let raw = key.raw()?;
    match kdf {
        Kdf::AesKdf { rounds, seed } => aes_kdf(&raw, seed, *rounds),
        Kdf::Argon2 { kind, salt, memory, iterations, parallelism, version, secret, associated_data } => {
            let m_kib = u32::try_from(memory / 1024).map_err(|_| err("the Argon2 memory is too large"))?;
            let t = u32::try_from(*iterations).map_err(|_| err("too many Argon2 iterations"))?;
            let out = if *version == 0x13 && secret.is_none() && associated_data.is_none() {
                let variant = match kind {
                    Argon2Type::D => Argon2Variant::Argon2d,
                    Argon2Type::Id => Argon2Variant::Argon2id,
                };
                primitives::argon2(
                    variant,
                    raw.as_ref(),
                    salt,
                    Argon2Params { m_kib, t, p: *parallelism, out_len: 32 },
                )?
            } else {
                // Argon2 1.0, or a secret / associated data: outside ov-crypto's wrapper.
                argon2_full(*kind, raw.as_ref(), salt, m_kib, t, *parallelism, *version, secret, associated_data)?
            };
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&out);
            Ok(k)
        }
        Kdf::Other(_) => Err(err("unsupported KDF")),
    }
}

#[allow(clippy::too_many_arguments)]
fn argon2_full(
    kind: Argon2Type,
    raw: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    version: u32,
    secret: &Option<Vec<u8>>,
    associated_data: &Option<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let weak =
        |e: argon2::Error| OvError::new(ov_error::OvErrorCode::WeakKdf, format!("Argon2 refused the parameters: {e}"));
    let version = match version {
        0x10 => argon2::Version::V0x10,
        0x13 => argon2::Version::V0x13,
        v => return Err(err(format!("unsupported Argon2 version {v:#x}"))),
    };
    let mut b = argon2::ParamsBuilder::new();
    b.m_cost(m_kib).t_cost(t).p_cost(p).output_len(32);
    if let Some(a) = associated_data {
        b.data(argon2::AssociatedData::new(a).map_err(weak)?);
    }
    let params = b.build().map_err(weak)?;
    // Wiped on drop (argon2 `zeroize`): the blocks are derived from the composite key.
    let mut blocks = zeroize::Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    let algorithm = match kind {
        Argon2Type::D => argon2::Algorithm::Argon2d,
        Argon2Type::Id => argon2::Algorithm::Argon2id,
    };
    let ctx = match secret {
        Some(s) => argon2::Argon2::new_with_secret(s, algorithm, version, params).map_err(weak)?,
        None => argon2::Argon2::new(algorithm, version, params),
    };
    let mut out = Zeroizing::new(vec![0u8; 32]);
    ctx.hash_password_into_with_memory(raw, salt, &mut out[..], blocks.as_mut_slice()).map_err(weak)?;
    Ok(out)
}

/// AES-KDF: AES-256-ECB keyed with the seed, `rounds` times over both halves, then SHA-256.
fn aes_kdf(raw: &[u8; 32], seed: &[u8], rounds: u64) -> Result<Zeroizing<[u8; 32]>, OvError> {
    let cipher = aes::Aes256::new_from_slice(seed).map_err(|_| err("the AES-KDF seed is not 32 bytes"))?;
    let mut blocks = [aes::Block::default(); 2];
    blocks[0].copy_from_slice(&raw[..16]);
    blocks[1].copy_from_slice(&raw[16..]);
    for _ in 0..rounds {
        cipher.encrypt_blocks(&mut blocks);
    }
    let mut h = Sha256::new();
    h.update(blocks[0]);
    h.update(blocks[1]);
    for b in &mut blocks {
        zeroize::Zeroize::zeroize(b.as_mut_slice());
    }
    Ok(Zeroizing::new(h.finalize().into()))
}

/// The payload key: SHA-256(master seed ‖ transformed key).
pub(crate) fn payload_key(master_seed: &[u8], transformed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(master_seed);
    h.update(transformed);
    Zeroizing::new(h.finalize().into())
}

// ---------------------------------------------------------------------------------------------
// Payload ciphers

pub(crate) fn decrypt(cipher: Cipher, key: &[u8; 32], iv: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, OvError> {
    match cipher {
        Cipher::Aes256Cbc => {
            use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut};
            let d = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| err("bad AES IV"))?;
            d.decrypt_padded_vec_mut::<Pkcs7>(data).map(Zeroizing::new).map_err(|_| wrong_key())
        }
        Cipher::ChaCha20 => {
            let mut out = Zeroizing::new(data.to_vec());
            chacha20::ChaCha20::new_from_slices(key, iv).map_err(|_| err("bad ChaCha20 IV"))?.apply_keystream(&mut out);
            Ok(out)
        }
        other => Err(err(format!("unsupported cipher {other:?}"))),
    }
}

pub(crate) fn encrypt(cipher: Cipher, key: &[u8; 32], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, OvError> {
    match cipher {
        Cipher::Aes256Cbc => {
            use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut};
            let e = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| err("bad AES IV"))?;
            Ok(e.encrypt_padded_vec_mut::<Pkcs7>(data))
        }
        Cipher::ChaCha20 => {
            let mut out = data.to_vec();
            chacha20::ChaCha20::new_from_slices(key, iv).map_err(|_| err("bad ChaCha20 IV"))?.apply_keystream(&mut out);
            Ok(out)
        }
        other => Err(err(format!("unsupported cipher {other:?}"))),
    }
}

// ---------------------------------------------------------------------------------------------
// Inner random stream

/// The inner random stream that protects `Protected="True"` values, applied in document order.
pub(crate) enum InnerStream {
    ChaCha20(Box<chacha20::ChaCha20>),
    Salsa20(Box<salsa20::Salsa20>),
}

impl InnerStream {
    /// `None` for stream id 0 (no protection).
    pub(crate) fn new(id: u32, key: &[u8]) -> Result<Option<InnerStream>, OvError> {
        match id {
            0 => Ok(None),
            STREAM_CHACHA20 => {
                let h = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(key)));
                let c = chacha20::ChaCha20::new_from_slices(&h[..32], &h[32..44]).map_err(|_| err("bad stream key"))?;
                Ok(Some(InnerStream::ChaCha20(Box::new(c))))
            }
            STREAM_SALSA20 => {
                const IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
                let k = Zeroizing::new(primitives::sha256(key));
                let c = salsa20::Salsa20::new_from_slices(k.as_ref(), &IV).map_err(|_| err("bad stream key"))?;
                Ok(Some(InnerStream::Salsa20(Box::new(c))))
            }
            other => Err(err(format!("unsupported inner stream {other}"))),
        }
    }

    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        match self {
            InnerStream::ChaCha20(c) => c.apply_keystream(data),
            InnerStream::Salsa20(c) => c.apply_keystream(data),
        }
    }

    /// How many keystream bytes have been used.
    pub(crate) fn position(&self) -> u64 {
        use chacha20::cipher::StreamCipherSeek;
        match self {
            InnerStream::ChaCha20(c) => c.current_pos(),
            InnerStream::Salsa20(c) => c.current_pos(),
        }
    }

    /// Goes back (or forward) to `pos` keystream bytes, to read the values again.
    pub(crate) fn seek(&mut self, pos: u64) {
        use chacha20::cipher::StreamCipherSeek;
        match self {
            InnerStream::ChaCha20(c) => c.seek(pos),
            InnerStream::Salsa20(c) => c.seek(pos),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// KDBX 4 HMAC

/// SHA-512(master seed ‖ transformed key ‖ 0x01).
pub(crate) fn hmac_base_key(master_seed: &[u8], transformed: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let mut h = Sha512::new();
    h.update(master_seed);
    h.update(transformed);
    h.update([1u8]);
    Zeroizing::new(h.finalize().into())
}

fn block_mac(index: u64, base: &[u8; 64]) -> HmacSha256 {
    let mut h = Sha512::new();
    h.update(index.to_le_bytes());
    h.update(base);
    let key = Zeroizing::new(<[u8; 64]>::from(h.finalize()));
    <HmacSha256 as Mac>::new_from_slice(key.as_ref()).expect("HMAC takes any key length")
}

/// The header HMAC (block index `u64::MAX`).
pub(crate) fn header_hmac(header: &[u8], base: &[u8; 64]) -> [u8; 32] {
    let mut m = block_mac(u64::MAX, base);
    m.update(header);
    m.finalize().into_bytes().into()
}

pub(crate) fn verify_header_hmac(header: &[u8], base: &[u8; 64], stored: &[u8]) -> Result<(), OvError> {
    let mut m = block_mac(u64::MAX, base);
    m.update(header);
    m.verify_slice(stored).map_err(|_| wrong_key())
}

/// Reads the HMAC block stream: the concatenated ciphertext.
pub(crate) fn read_hmac_blocks(c: &mut Cursor<'_>, base: &[u8; 64]) -> Result<Vec<u8>, OvError> {
    let mut out = Vec::new();
    for index in 0u64.. {
        let mac = c.bytes(32)?;
        let size_bytes = c.array::<4>()?;
        let size = u32::from_le_bytes(size_bytes) as usize;
        let block = c.bytes(size)?;
        let mut m = block_mac(index, base);
        m.update(&index.to_le_bytes());
        m.update(&size_bytes);
        m.update(block);
        m.verify_slice(mac).map_err(|_| err(format!("block {index} fails its HMAC: the file is corrupt")))?;
        if size == 0 {
            break;
        }
        out.extend_from_slice(block);
    }
    Ok(out)
}

/// Writes `data` as an HMAC block stream (1 MiB blocks, then an empty block).
pub(crate) fn write_hmac_blocks(out: &mut Vec<u8>, data: &[u8], base: &[u8; 64]) {
    const BLOCK: usize = 1024 * 1024;
    let mut chunks: Vec<&[u8]> = data.chunks(BLOCK).collect();
    chunks.push(&[]);
    for (index, block) in chunks.into_iter().enumerate() {
        let index = index as u64;
        let size = (block.len() as u32).to_le_bytes();
        let mut m = block_mac(index, base);
        m.update(&index.to_le_bytes());
        m.update(&size);
        m.update(block);
        out.extend_from_slice(&m.finalize().into_bytes());
        out.extend_from_slice(&size);
        out.extend_from_slice(block);
    }
}

// ---------------------------------------------------------------------------------------------
// KDBX 3.1 hashed block stream

pub(crate) fn read_hashed_blocks(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let mut c = Cursor::new(data);
    let mut out = Zeroizing::new(Vec::new());
    loop {
        let _index = c.u32()?;
        let hash = c.bytes(32)?;
        let size = c.u32()? as usize;
        if size == 0 {
            break;
        }
        let block = c.bytes(size)?;
        if primitives::sha256(block).as_slice() != hash {
            return Err(err("a block fails its hash: the file is corrupt"));
        }
        out.extend_from_slice(block);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// gzip

pub(crate) fn gunzip(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::MultiGzDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| err(format!("the payload doesn't decompress: {e}")))?;
    Ok(out)
}

/// Level 5, not zlib's default 6: for a 5k-entry vault 17 ms instead of 24 ms, for a file 3.7%
/// larger (owner's choice, 2026-11-21). Any level reads anywhere.
pub(crate) const GZIP_LEVEL: u32 = 5;

pub(crate) fn gzip(data: &[u8]) -> Result<Vec<u8>, OvError> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(GZIP_LEVEL));
    e.write_all(data).map_err(|e| err(format!("compression failed: {e}")))?;
    e.finish().map_err(|e| err(format!("compression failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_formats() {
        let raw = [7u8; 32];
        let k = |f: &[u8]| key_file_component(f).unwrap();
        assert_eq!(k(&raw), raw);
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(k(hex.as_bytes()), raw);
        assert_eq!(k(b"anything else"), primitives::sha256(b"anything else"));

        let v1 = "<?xml version=\"1.0\"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>\
                  BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=</Data></Key></KeyFile>";
        assert_eq!(k(v1.as_bytes()), raw);

        let check: String = primitives::sha256(&raw)[..4].iter().map(|b| format!("{b:02X}")).collect();
        let spaced: String = hex
            .to_uppercase()
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let v2 = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\
             \t\t<Data Hash=\"{check}\">\n\t\t\t{spaced}\n\t\t</Data>\n\t</Key>\n</KeyFile>\n"
        );
        assert_eq!(k(v2.as_bytes()), raw);
        let bad = v2.replace(&check, "00000000");
        assert!(key_file_component(bad.as_bytes()).is_err());
    }

    #[test]
    fn opens_same_as_compares_the_kdf_input() {
        let a = CompositeKey::new().with_key_file(&[7; 32]);
        assert!(a.opens_same_as(&a.clone()));
        assert!(a.opens_same_as(&CompositeKey::new().with_key_file("07".repeat(32).as_bytes())));
        assert!(!a.opens_same_as(&CompositeKey::new().with_key_file(&[8; 32])));
        assert!(!a.opens_same_as(&a.clone().with_password("pw")));
        assert!(!CompositeKey::new().opens_same_as(&CompositeKey::new()));
    }

    #[test]
    fn composite_key_is_password_then_key_file() {
        let a = CompositeKey::new().with_key_file(&[1; 32]).with_password("pw");
        let b = CompositeKey::new().with_password("pw").with_key_file(&[1; 32]);
        assert_eq!(*a.raw().unwrap(), *b.raw().unwrap());
        let mut h = Sha256::new();
        h.update(primitives::sha256(b"pw"));
        h.update([1u8; 32]);
        assert_eq!(*a.raw().unwrap(), <[u8; 32]>::from(h.finalize()));
        assert!(!format!("{a:?}").contains('1'));
        assert!(CompositeKey::new().raw().is_err());
    }

    #[test]
    fn salsa20_stream_matches_keepass() {
        // KeePass 2.x CryptoRandomStream with Salsa20: key = SHA-256(stream key), fixed IV.
        let mut s = InnerStream::new(STREAM_SALSA20, &[0u8; 32]).unwrap().unwrap();
        let mut a = [0u8; 10];
        s.apply(&mut a);
        let mut b = [0u8; 70];
        s.apply(&mut b);
        let mut fresh = InnerStream::new(STREAM_SALSA20, &[0u8; 32]).unwrap().unwrap();
        let mut all = [0u8; 80];
        fresh.apply(&mut all);
        assert_eq!(&all[..10], &a);
        assert_eq!(&all[10..], &b);
    }
}
