//! KDBX for OpenVireo vaults (SPEC §7, §20): the frozen document [`model`] (W0-B), and the reader,
//! writer and vault helpers built on it (W1-K2, ADR 0002).
//!
//! - [`read`] opens KDBX 4.0, 4.1 and 3.1 files: AES-KDF and Argon2d/id; AES-256-CBC and ChaCha20
//!   payloads; ChaCha20 and Salsa20 inner streams; gzip; attachments and custom icons.
//! - [`write`] saves KDBX 4.0 or 4.1, matching [`model::Header::version`] (a 3.1 file is upgraded to
//!   4.0, or to 4.1 when it uses a 4.1 feature). The KDF parameters, salt included, are written as
//!   the model holds them; the master seed, IV and inner stream key are fresh on every save.
//!   Elements nobody read aren't invented, and unknown elements are written back in their parent.
//! - [`vault`] holds the account-vault helpers of the SDK's `vault/kdbx.ts`, and [`entries`] the
//!   entry and group operations of `vault/entries.ts`.
//!
//! Keys are [`CompositeKey`]s: `CompositeKey::new().with_password("…")`, `.with_key_file(&bytes)`.
//! A wrong key fails with `vault_key_mismatch`; anything else wrong with a file is `kdbx_error`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod bytes;
mod crypto;
pub mod entries;
mod header;
pub mod model;
pub mod vault;
mod xml;

pub use crypto::CompositeKey;
use ov_crypto::primitives;
use ov_error::OvError;

use crate::bytes::{err, wrong_key, Cursor};
use crate::crypto::InnerStream;
use crate::model::{Compression, Database, Entry, Group, Header, KdbxVersion};

/// Opens a KDBX 3.1 or 4.x file.
///
/// Errors: `vault_key_mismatch` when `key` doesn't open it; `kdbx_error` when it isn't a KDBX file,
/// is corrupt or uses something unsupported (Twofish, an unknown KDF); `weak_kdf` when Argon2
/// refuses the file's parameters.
pub fn read(bytes: &[u8], key: &CompositeKey) -> Result<Database, OvError> {
    let raw = header::read_outer(bytes)?;
    let header_bytes = &bytes[..raw.len];
    let mut c = Cursor::new(bytes);
    c.bytes(raw.len)?;
    let transformed;
    let mut binaries;
    let doc = if raw.header.version.major >= 4 {
        let stored_hash = c.bytes(32)?;
        let stored_hmac = c.bytes(32)?;
        if primitives::sha256(header_bytes).as_slice() != stored_hash {
            return Err(err("the header fails its hash: the file is corrupt"));
        }
        transformed = crypto::transform(key, &raw.header.kdf)?;
        let base = crypto::hmac_base_key(&raw.master_seed, &transformed);
        crypto::verify_header_hmac(header_bytes, &base, stored_hmac)?;
        let ciphertext = crypto::read_hmac_blocks(&mut c, &base)?;
        let pkey = crypto::payload_key(&raw.master_seed, &transformed);
        let mut plain = crypto::decrypt(raw.header.cipher, &pkey, &raw.iv, &ciphertext)
            .map_err(|e| if e.is(ov_error::OvErrorCode::VaultKeyMismatch) { err("the payload is corrupt") } else { e })?;
        if raw.header.compression == Compression::Gzip {
            plain = crypto::gunzip(&plain)?;
        }
        let inner = header::read_inner(&plain)?;
        let mut stream = InnerStream::new(inner.stream_id, &inner.stream_key)?;
        let xml = std::str::from_utf8(&plain[inner.len..]).map_err(|_| err("the XML is not UTF-8"))?;
        let tree = xml::tree::parse(xml, stream.as_mut())?;
        binaries = inner.binaries;
        xml::read::document(tree, &mut binaries)?
    } else {
        transformed = crypto::transform(key, &raw.header.kdf)?;
        let pkey = crypto::payload_key(&raw.master_seed, &transformed);
        let plain = crypto::decrypt(raw.header.cipher, &pkey, &raw.iv, c.rest())?;
        if plain.len() < 32 || raw.stream_start.len() != 32 || !bool_eq(&plain[..32], &raw.stream_start) {
            return Err(wrong_key());
        }
        let mut payload = crypto::read_hashed_blocks(&plain[32..])?;
        if raw.header.compression == Compression::Gzip {
            payload = crypto::gunzip(&payload)?;
        }
        let mut stream = InnerStream::new(raw.stream_id, &raw.protected_stream_key)?;
        let xml = std::str::from_utf8(&payload).map_err(|_| err("the XML is not UTF-8"))?;
        let tree = xml::tree::parse(xml, stream.as_mut())?;
        binaries = Vec::new();
        let doc = xml::read::document(tree, &mut binaries)?;
        if let Some(h) = &doc.header_hash {
            if h.as_slice() != primitives::sha256(header_bytes).as_slice() {
                return Err(err("the header doesn't match its HeaderHash: the file is corrupt"));
            }
        }
        doc
    };
    drop(transformed);
    Ok(Database {
        header: raw.header,
        meta: doc.meta,
        root: doc.root,
        deleted_objects: doc.deleted_objects,
        binaries,
        unknown_file: doc.unknown_file,
        unknown_root: doc.unknown_root,
    })
}

fn bool_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Saves `db` as KDBX 4 with `key`.
///
/// The version is [`Header::version`] when it is 4.x; a 3.1 database is written as 4.0, or 4.1
/// when it uses a KDBX 4.1 feature ([`uses_kdbx41`]). The KDF parameters (salt included) come from
/// the model; the master seed, IV and inner stream key (ChaCha20) are fresh.
pub fn write(db: &Database, key: &CompositeKey) -> Result<Vec<u8>, OvError> {
    let version = write_version(db);
    let h = &db.header;
    let master_seed = primitives::random_bytes(32)?;
    let iv = primitives::random_bytes(h.cipher.iv_len()?)?;
    let header_bytes = header::write_outer(h, version, &master_seed, &iv);

    let transformed = crypto::transform(key, &h.kdf)?;
    let base = crypto::hmac_base_key(&master_seed, &transformed);
    let pkey = crypto::payload_key(&master_seed, &transformed);
    drop(transformed);

    let stream_key = primitives::random_bytes(64)?;
    let stream = InnerStream::new(header::STREAM_CHACHA20, &stream_key)?.expect("ChaCha20 is a stream");
    let mut plain = zeroize::Zeroizing::new(Vec::new());
    header::write_inner(&mut plain, &stream_key, &db.binaries);
    plain.extend_from_slice(&xml::write::document(db, stream)?);
    if h.compression == Compression::Gzip {
        plain = zeroize::Zeroizing::new(crypto::gzip(&plain)?);
    }
    let ciphertext = crypto::encrypt(h.cipher, &pkey, &iv, &plain)?;
    drop(plain);

    let mut out = Vec::with_capacity(header_bytes.len() + 64 + ciphertext.len() + 128);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&primitives::sha256(&header_bytes));
    out.extend_from_slice(&crypto::header_hmac(&header_bytes, &base));
    crypto::write_hmac_blocks(&mut out, &ciphertext, &base);
    Ok(out)
}

/// The outer header of a KDBX file, read without the key (cipher, KDF, version).
pub fn peek_header(bytes: &[u8]) -> Result<Header, OvError> {
    Ok(header::read_outer(bytes)?.header)
}

/// The version [`write`] uses for `db`.
pub fn write_version(db: &Database) -> KdbxVersion {
    let v = db.header.version;
    if v.major >= 4 {
        v
    } else if uses_kdbx41(db) {
        KdbxVersion { major: 4, minor: 1 }
    } else {
        KdbxVersion { major: 4, minor: 0 }
    }
}

/// Whether `db` holds anything only KDBX 4.1 stores: custom icon names or times, custom data
/// times, group tags, `PreviousParentGroup`, `QualityCheck` or `SettingsChanged`.
pub fn uses_kdbx41(db: &Database) -> bool {
    fn cd(items: &[model::CustomDataItem]) -> bool {
        items.iter().any(|i| i.last_modification.is_some())
    }
    fn entry(e: &Entry) -> bool {
        e.quality_check.is_some() || e.previous_parent_group.is_some() || cd(&e.custom_data) || e.history.iter().any(entry)
    }
    fn group(g: &Group) -> bool {
        !g.tags.is_empty()
            || g.previous_parent_group.is_some()
            || cd(&g.custom_data)
            || g.entries.iter().any(entry)
            || g.groups.iter().any(group)
    }
    let m = &db.meta;
    m.settings_changed.is_some()
        || cd(&m.custom_data)
        || m.custom_icons.iter().any(|i| i.name.is_some() || i.last_modification.is_some())
        || group(&db.root)
}
