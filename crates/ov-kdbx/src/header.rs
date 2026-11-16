//! The outer header (KDBX 3.1 and 4.x), VariantDictionary, and the KDBX 4 inner header.
//!
//! Reference: KeePassXC `src/format/Kdbx4Reader.cpp`, `Kdbx3Reader.cpp`, `KeePass2.cpp`
//! (`kdfToParameters`, `parametersToKdf`).

use ov_error::OvError;
use uuid::Uuid;

use crate::bytes::{err, le_exact, Cursor};
use crate::model::{Argon2Type, Cipher, Compression, Header, KdbxVersion, Kdf, Variant, VariantDictionary};

pub(crate) const SIGNATURE_1: u32 = 0x9AA2_D903;
pub(crate) const SIGNATURE_2: u32 = 0xB54B_FB67;

const CIPHER_AES256: Uuid = Uuid::from_u128(0x31c1f2e6_bf71_4350_be58_05216afc5aff);
const CIPHER_CHACHA20: Uuid = Uuid::from_u128(0xd6038a2b_8b6f_4cb5_a524_339a31dbb59a);
const CIPHER_TWOFISH: Uuid = Uuid::from_u128(0xad68f29f_576f_4bb9_a36a_d47af965346c);

/// AES-KDF (KeePass 2.x and KDBX 3.1; also what this crate writes for AES-KDF).
pub(crate) const KDF_AES_KDBX3: Uuid = Uuid::from_u128(0xc9d9f39a_628a_4460_bf74_0d08c18a4fea);
/// AES-KDF as KeePassXC names it for KDBX 4 (read as [`Kdf::AesKdf`]).
pub(crate) const KDF_AES_KDBX4: Uuid = Uuid::from_u128(0x7c02bb82_79a7_4ac0_927d_114a00648238);
pub(crate) const KDF_ARGON2D: Uuid = Uuid::from_u128(0xef636ddf_8c29_444b_91f7_a9a403e30a0c);
pub(crate) const KDF_ARGON2ID: Uuid = Uuid::from_u128(0x9e298b19_56db_4773_b23d_fc3ec6f0a1e6);

/// Inner random stream ids.
pub(crate) const STREAM_SALSA20: u32 = 2;
pub(crate) const STREAM_CHACHA20: u32 = 3;

impl Cipher {
    pub(crate) fn from_uuid(u: Uuid) -> Cipher {
        match u {
            CIPHER_AES256 => Cipher::Aes256Cbc,
            CIPHER_CHACHA20 => Cipher::ChaCha20,
            CIPHER_TWOFISH => Cipher::Twofish,
            other => Cipher::Other(other),
        }
    }

    pub(crate) fn uuid(self) -> Uuid {
        match self {
            Cipher::Aes256Cbc => CIPHER_AES256,
            Cipher::ChaCha20 => CIPHER_CHACHA20,
            Cipher::Twofish => CIPHER_TWOFISH,
            Cipher::Other(u) => u,
        }
    }

    /// The IV length the cipher needs.
    pub(crate) fn iv_len(self) -> Result<usize, OvError> {
        match self {
            Cipher::Aes256Cbc => Ok(16),
            Cipher::ChaCha20 => Ok(12),
            Cipher::Twofish => Err(err("the Twofish cipher is not supported")),
            Cipher::Other(u) => Err(err(format!("unknown cipher {u}"))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// VariantDictionary

const VD_END: u8 = 0x00;
const VD_U32: u8 = 0x04;
const VD_U64: u8 = 0x05;
const VD_BOOL: u8 = 0x08;
const VD_I32: u8 = 0x0C;
const VD_I64: u8 = 0x0D;
const VD_STRING: u8 = 0x18;
const VD_BYTES: u8 = 0x42;

impl VariantDictionary {
    /// Parses a serialized VariantDictionary.
    pub(crate) fn parse(data: &[u8]) -> Result<VariantDictionary, OvError> {
        let mut c = Cursor::new(data);
        let version = c.u16()?;
        if version & 0xFF00 != 0x0100 {
            return Err(err(format!("unsupported VariantDictionary version {version:#06x}")));
        }
        let mut items = Vec::new();
        loop {
            let ty = c.u8()?;
            if ty == VD_END {
                break;
            }
            let klen = c.u32()? as usize;
            let key = std::str::from_utf8(c.bytes(klen)?)
                .map_err(|_| err("a VariantDictionary key is not UTF-8"))?
                .to_owned();
            let vlen = c.u32()? as usize;
            let v = c.bytes(vlen)?;
            let value = match ty {
                VD_U32 => Variant::U32(u32::from_le_bytes(le_exact(v, &key)?)),
                VD_U64 => Variant::U64(u64::from_le_bytes(le_exact(v, &key)?)),
                VD_BOOL => Variant::Bool(le_exact::<1>(v, &key)?[0] != 0),
                VD_I32 => Variant::I32(i32::from_le_bytes(le_exact(v, &key)?)),
                VD_I64 => Variant::I64(i64::from_le_bytes(le_exact(v, &key)?)),
                VD_STRING => Variant::String(
                    std::str::from_utf8(v).map_err(|_| err("a VariantDictionary string is not UTF-8"))?.to_owned(),
                ),
                VD_BYTES => Variant::Bytes(v.to_vec()),
                other => return Err(err(format!("unknown VariantDictionary type {other:#04x}"))),
            };
            items.push((key, value));
        }
        Ok(VariantDictionary { version, items })
    }

    /// Serializes in item order.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        for (key, value) in &self.items {
            let (ty, bytes): (u8, Vec<u8>) = match value {
                Variant::U32(v) => (VD_U32, v.to_le_bytes().to_vec()),
                Variant::U64(v) => (VD_U64, v.to_le_bytes().to_vec()),
                Variant::Bool(v) => (VD_BOOL, vec![u8::from(*v)]),
                Variant::I32(v) => (VD_I32, v.to_le_bytes().to_vec()),
                Variant::I64(v) => (VD_I64, v.to_le_bytes().to_vec()),
                Variant::String(v) => (VD_STRING, v.as_bytes().to_vec()),
                Variant::Bytes(v) => (VD_BYTES, v.clone()),
            };
            out.push(ty);
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        out.push(VD_END);
        out
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Variant> {
        self.items.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn uint(&self, key: &str) -> Option<u64> {
        match self.get(key)? {
            Variant::U32(v) => Some(u64::from(*v)),
            Variant::U64(v) => Some(*v),
            Variant::I32(v) => u64::try_from(*v).ok(),
            Variant::I64(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    fn bytes(&self, key: &str) -> Option<&[u8]> {
        match self.get(key)? {
            Variant::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

impl Kdf {
    /// The typed KDF of a KDBX 4 `KdfParameters` dictionary. Unknown KDFs (or ones whose
    /// parameters don't parse) stay as [`Kdf::Other`] so they round-trip.
    pub(crate) fn from_dictionary(d: VariantDictionary) -> Kdf {
        let Some(uuid) = d.bytes("$UUID").and_then(|b| Uuid::from_slice(b).ok()) else {
            return Kdf::Other(d);
        };
        match uuid {
            KDF_AES_KDBX3 | KDF_AES_KDBX4 => match (d.uint("R"), d.bytes("S")) {
                (Some(rounds), Some(seed)) => Kdf::AesKdf { rounds, seed: seed.to_vec() },
                _ => Kdf::Other(d),
            },
            KDF_ARGON2D | KDF_ARGON2ID => {
                let kind = if uuid == KDF_ARGON2D { Argon2Type::D } else { Argon2Type::Id };
                let (Some(salt), Some(memory), Some(iterations), Some(parallelism)) =
                    (d.bytes("S"), d.uint("M"), d.uint("I"), d.uint("P"))
                else {
                    return Kdf::Other(d);
                };
                let Ok(parallelism) = u32::try_from(parallelism) else { return Kdf::Other(d) };
                let version = d.uint("V").map_or(Some(0x13), |v| u32::try_from(v).ok());
                let Some(version) = version else { return Kdf::Other(d) };
                Kdf::Argon2 {
                    kind,
                    salt: salt.to_vec(),
                    memory,
                    iterations,
                    parallelism,
                    version,
                    secret: d.bytes("K").map(<[u8]>::to_vec),
                    associated_data: d.bytes("A").map(<[u8]>::to_vec),
                }
            }
            _ => Kdf::Other(d),
        }
    }

    /// The `KdfParameters` dictionary written for this KDF, in KeePassXC's key order.
    pub(crate) fn to_dictionary(&self) -> VariantDictionary {
        let bytes = |u: Uuid| Variant::Bytes(u.as_bytes().to_vec());
        match self {
            Kdf::AesKdf { rounds, seed } => VariantDictionary {
                version: 0x0100,
                items: vec![
                    ("$UUID".into(), bytes(KDF_AES_KDBX3)),
                    ("R".into(), Variant::U64(*rounds)),
                    ("S".into(), Variant::Bytes(seed.clone())),
                ],
            },
            Kdf::Argon2 { kind, salt, memory, iterations, parallelism, version, secret, associated_data } => {
                let uuid = match kind {
                    Argon2Type::D => KDF_ARGON2D,
                    Argon2Type::Id => KDF_ARGON2ID,
                };
                let mut items = vec![
                    ("$UUID".into(), bytes(uuid)),
                    ("S".into(), Variant::Bytes(salt.clone())),
                    ("P".into(), Variant::U32(*parallelism)),
                    ("M".into(), Variant::U64(*memory)),
                    ("I".into(), Variant::U64(*iterations)),
                    ("V".into(), Variant::U32(*version)),
                ];
                if let Some(k) = secret {
                    items.push(("K".into(), Variant::Bytes(k.clone())));
                }
                if let Some(a) = associated_data {
                    items.push(("A".into(), Variant::Bytes(a.clone())));
                }
                VariantDictionary { version: 0x0100, items }
            }
            Kdf::Other(d) => d.clone(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Outer header

/// The outer header as read: the model's settings plus the per-file values needed to decrypt.
pub(crate) struct RawHeader {
    pub(crate) header: Header,
    pub(crate) master_seed: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    /// KDBX 3.1 only: inner stream key, stream start bytes and stream id.
    pub(crate) protected_stream_key: Vec<u8>,
    pub(crate) stream_start: Vec<u8>,
    pub(crate) stream_id: u32,
    /// Bytes from the signature to the end of the header (hashed and HMACed).
    pub(crate) len: usize,
}

/// Reads the signature, version and outer header fields.
pub(crate) fn read_outer(data: &[u8]) -> Result<RawHeader, OvError> {
    let mut c = Cursor::new(data);
    if c.u32().ok() != Some(SIGNATURE_1) || c.u32().ok() != Some(SIGNATURE_2) {
        return Err(err("not a KeePass database"));
    }
    let minor = c.u16()?;
    let major = c.u16()?;
    if major != 3 && major != 4 {
        return Err(err(format!("unsupported KDBX version {major}.{minor}")));
    }
    let v4 = major == 4;

    let mut cipher = None;
    let mut compression = Compression::None;
    let mut master_seed = Vec::new();
    let mut iv = Vec::new();
    let mut kdf = None;
    let mut public_custom_data = None;
    let mut unknown_fields = Vec::new();
    let mut transform_seed = None;
    let mut transform_rounds = None;
    let mut protected_stream_key = Vec::new();
    let mut stream_start = Vec::new();
    let mut stream_id = 0;
    loop {
        let id = c.u8()?;
        let size = if v4 { c.u32()? as usize } else { usize::from(c.u16()?) };
        let value = c.bytes(size)?;
        match (id, v4) {
            (0, _) => break,
            (2, _) => {
                let u = Uuid::from_slice(value).map_err(|_| err("bad cipher id"))?;
                cipher = Some(Cipher::from_uuid(u));
            }
            (3, _) => {
                compression = match u32::from_le_bytes(le_exact(value, "compression flags")?) {
                    0 => Compression::None,
                    1 => Compression::Gzip,
                    other => return Err(err(format!("unknown compression {other}"))),
                }
            }
            (4, _) => master_seed = value.to_vec(),
            (7, _) => iv = value.to_vec(),
            (11, true) => kdf = Some(Kdf::from_dictionary(VariantDictionary::parse(value)?)),
            (12, true) => public_custom_data = Some(VariantDictionary::parse(value)?),
            (5, false) => transform_seed = Some(value.to_vec()),
            (6, false) => transform_rounds = Some(u64::from_le_bytes(le_exact(value, "transform rounds")?)),
            (8, false) => protected_stream_key = value.to_vec(),
            (9, false) => stream_start = value.to_vec(),
            (10, false) => stream_id = u32::from_le_bytes(le_exact(value, "inner stream id")?),
            _ => unknown_fields.push((id, value.to_vec())),
        }
    }
    let cipher = cipher.ok_or_else(|| err("the header has no cipher"))?;
    if master_seed.len() != 32 {
        return Err(err("the header's master seed is not 32 bytes"));
    }
    if iv.len() != cipher.iv_len()? {
        return Err(err("the header's IV has the wrong length"));
    }
    let kdf = if v4 {
        kdf.ok_or_else(|| err("the header has no KDF parameters"))?
    } else {
        match (transform_seed, transform_rounds) {
            (Some(seed), Some(rounds)) => Kdf::AesKdf { rounds, seed },
            _ => return Err(err("the header has no transform seed or rounds")),
        }
    };
    Ok(RawHeader {
        header: Header {
            version: KdbxVersion { major, minor },
            cipher,
            compression,
            kdf,
            public_custom_data,
            unknown_fields,
        },
        master_seed,
        iv,
        protected_stream_key,
        stream_start,
        stream_id,
        len: c.position(),
    })
}

/// Writes a KDBX 4 outer header (`version` must be 4.x).
pub(crate) fn write_outer(header: &Header, version: KdbxVersion, master_seed: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_1.to_le_bytes());
    out.extend_from_slice(&SIGNATURE_2.to_le_bytes());
    out.extend_from_slice(&version.minor.to_le_bytes());
    out.extend_from_slice(&version.major.to_le_bytes());
    let mut field = |id: u8, value: &[u8]| {
        out.push(id);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    };
    field(2, header.cipher.uuid().as_bytes());
    let compression: u32 = match header.compression {
        Compression::None => 0,
        Compression::Gzip => 1,
    };
    field(3, &compression.to_le_bytes());
    field(4, master_seed);
    field(7, iv);
    field(11, &header.kdf.to_dictionary().serialize());
    if let Some(pcd) = &header.public_custom_data {
        field(12, &pcd.serialize());
    }
    for (id, value) in &header.unknown_fields {
        // Field ids this writer emits itself, or that mean something else in KDBX 4, aren't copied.
        if !matches!(id, 0 | 2 | 3 | 4 | 7 | 11 | 12) {
            field(*id, value);
        }
    }
    field(0, b"\r\n\r\n");
    out
}

// ---------------------------------------------------------------------------------------------
// KDBX 4 inner header

pub(crate) struct InnerHeader {
    pub(crate) stream_id: u32,
    pub(crate) stream_key: zeroize::Zeroizing<Vec<u8>>,
    pub(crate) binaries: Vec<crate::model::Binary>,
    /// Offset of the XML after the inner header.
    pub(crate) len: usize,
}

pub(crate) fn read_inner(data: &[u8]) -> Result<InnerHeader, OvError> {
    let mut c = Cursor::new(data);
    let mut stream_id = 0;
    let mut stream_key = zeroize::Zeroizing::new(Vec::new());
    let mut binaries = Vec::new();
    loop {
        let id = c.u8()?;
        let size = c.u32()? as usize;
        let value = c.bytes(size)?;
        match id {
            0 => break,
            1 => stream_id = u32::from_le_bytes(le_exact(value, "inner stream id")?),
            2 => *stream_key = value.to_vec(),
            3 => {
                let (flags, content) = value.split_first().ok_or_else(|| err("an inner-header binary is empty"))?;
                binaries.push(crate::model::Binary {
                    data: zeroize::Zeroizing::new(content.to_vec()),
                    protected: flags & 1 != 0,
                });
            }
            _ => {} // unknown inner header fields are skipped, as KeePassXC does
        }
    }
    Ok(InnerHeader { stream_id, stream_key, binaries, len: c.position() })
}

pub(crate) fn write_inner(out: &mut Vec<u8>, stream_key: &[u8], binaries: &[crate::model::Binary]) {
    let field = |out: &mut Vec<u8>, id: u8, parts: &[&[u8]]| {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        out.push(id);
        out.extend_from_slice(&(len as u32).to_le_bytes());
        for p in parts {
            out.extend_from_slice(p);
        }
    };
    field(out, 1, &[&STREAM_CHACHA20.to_le_bytes()]);
    field(out, 2, &[stream_key]);
    for b in binaries {
        field(out, 3, &[&[u8::from(b.protected)], &b.data]);
    }
    field(out, 0, &[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_dictionary_round_trips_all_types_in_order() {
        let d = VariantDictionary {
            version: 0x0100,
            items: vec![
                ("z".into(), Variant::U32(7)),
                ("a".into(), Variant::U64(u64::MAX)),
                ("b".into(), Variant::Bool(true)),
                ("i".into(), Variant::I32(-3)),
                ("l".into(), Variant::I64(-9_000_000_000)),
                ("s".into(), Variant::String("héllo".into())),
                ("$UUID".into(), Variant::Bytes(vec![1, 2, 3])),
            ],
        };
        assert_eq!(VariantDictionary::parse(&d.serialize()).unwrap(), d);
    }

    #[test]
    fn unknown_kdf_stays_other() {
        let d = VariantDictionary {
            version: 0x0100,
            items: vec![("$UUID".into(), Variant::Bytes(vec![9; 16])), ("X".into(), Variant::U32(1))],
        };
        let kdf = Kdf::from_dictionary(d.clone());
        assert_eq!(kdf, Kdf::Other(d.clone()));
        assert_eq!(kdf.to_dictionary(), d);
    }
}
