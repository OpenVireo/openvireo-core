//! KDBX for OpenVireo vaults (SPEC §7, §20): the frozen document [`model`] (W0-B), and the reader,
//! writer and vault helpers built on it (W1-K2, ADR 0002).
//!
//! - [`read`] opens KDBX 4.0, 4.1 and 3.1 files: AES-KDF and Argon2d/id; AES-256-CBC and ChaCha20
//!   payloads; ChaCha20 and Salsa20 inner streams; gzip; attachments and custom icons.
//! - [`write()`] saves KDBX 4.0 or 4.1, matching [`model::Header::version`] (a 3.1 file is upgraded to
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

pub use crypto::{check_kdf_limits, CompositeKey, MAX_AES_KDF_ROUNDS, MAX_ARGON2_MEMORY, MAX_ARGON2_WORK};
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
        let mut plain = crypto::decrypt(raw.header.cipher, &pkey, &raw.iv, &ciphertext).map_err(|e| {
            if e.is(ov_error::OvErrorCode::VaultKeyMismatch) {
                err("the payload is corrupt")
            } else {
                e
            }
        })?;
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
/// The version is [`Header::version`] when it is 4.x; a 3.1 database is written as 4.0. Either is
/// raised to 4.1 when the database uses a KDBX 4.1 feature ([`uses_kdbx41`] for a 3.1 database,
/// [`uses_kdbx41_elements`] for a 4.0 one), as KeePassXC 2.7's `kdbxVersionRequired` does, so a 4.1
/// element is never written into a 4.0 file. The KDF parameters (salt included) come from
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
    // Sized once: growing would leave a copy of the plaintext to wipe each time
    let binaries: usize = db.binaries.iter().map(|b| b.data.len() + 8).sum();
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(128 + binaries + xml::write::estimated_len(db)));
    header::write_inner(&mut plain, &stream_key, &db.binaries);
    let mut plain = xml::write::document_into(db, stream, plain)?;
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

/// The version [`write()`] uses for `db`.
pub fn write_version(db: &Database) -> KdbxVersion {
    const V40: KdbxVersion = KdbxVersion { major: 4, minor: 0 };
    const V41: KdbxVersion = KdbxVersion { major: 4, minor: 1 };
    if db.header.version.major < 4 {
        return if uses_kdbx41(db) { V41 } else { V40 };
    }
    // A 4.0 file keeps its version unless it now holds a 4.1 element only (`SettingsChanged` doesn't
    // count: kdbxweb writes it into 4.0 files and older readers ignore it)
    let v = db.header.version;
    if v < V41 && uses_kdbx41_elements(db) {
        V41
    } else {
        v
    }
}

/// Whether `db` holds anything only KDBX 4.1 stores: custom icon names or times, custom data
/// times, group tags, `PreviousParentGroup`, `QualityCheck` or `SettingsChanged`.
pub fn uses_kdbx41(db: &Database) -> bool {
    db.meta.settings_changed.is_some() || uses_kdbx41_elements(db)
}

/// [`uses_kdbx41`] without `SettingsChanged`: whether `db` holds a 4.1 element a 4.0 file has no
/// place for (custom icon names or times, custom data times, group tags, `PreviousParentGroup`,
/// `QualityCheck`), which raises a 4.0 database to 4.1 when it is written.
pub fn uses_kdbx41_elements(db: &Database) -> bool {
    fn cd(items: &[model::CustomDataItem]) -> bool {
        items.iter().any(|i| i.last_modification.is_some())
    }
    fn entry(e: &Entry) -> bool {
        e.quality_check.is_some()
            || e.previous_parent_group.is_some()
            || cd(&e.custom_data)
            || e.history.iter().any(entry)
    }
    fn group(g: &Group) -> bool {
        !g.tags.is_empty()
            || g.previous_parent_group.is_some()
            || cd(&g.custom_data)
            || g.entries.iter().any(entry)
            || g.groups.iter().any(group)
    }
    let m = &db.meta;
    cd(&m.custom_data)
        || m.custom_icons.iter().any(|i| i.name.is_some() || i.last_modification.is_some())
        || group(&db.root)
}

#[cfg(test)]
mod kdf_limit_tests {
    use super::*;
    use crate::model::{Argon2Type, Kdf};
    use ov_error::OvErrorCode;

    fn argon2(memory: u64, iterations: u64) -> Kdf {
        Kdf::Argon2 {
            kind: Argon2Type::Id,
            salt: vec![1; 32],
            memory,
            iterations,
            parallelism: 1,
            version: 0x13,
            secret: None,
            associated_data: None,
        }
    }

    fn too_large(r: Result<impl Sized, ov_error::OvError>, param: &str) {
        let Err(e) = r else { panic!("expected too_large for {param}") };
        assert_eq!(e.code, OvErrorCode::TooLarge, "{e}");
        assert!(e.details.as_deref().unwrap_or("").contains(&format!("\"kdf_param\":\"{param}\"")), "{e:?}");
    }

    #[test]
    fn limits_take_their_values_and_refuse_one_more() {
        let gib = 1u64 << 30;
        assert!(check_kdf_limits(&argon2(MAX_ARGON2_MEMORY, 16)).is_ok());
        too_large(check_kdf_limits(&argon2(MAX_ARGON2_MEMORY + 1024, 1)), "memory");
        assert!(check_kdf_limits(&argon2(64 << 20, 256)).is_ok());
        too_large(check_kdf_limits(&argon2(64 << 20, 257)), "work");
        too_large(check_kdf_limits(&argon2(gib, u64::MAX)), "work");
        assert!(check_kdf_limits(&Kdf::AesKdf { rounds: MAX_AES_KDF_ROUNDS, seed: vec![2; 32] }).is_ok());
        too_large(check_kdf_limits(&Kdf::AesKdf { rounds: MAX_AES_KDF_ROUNDS + 1, seed: vec![2; 32] }), "rounds");
        // KeePassXC's defaults and its longest unlock setting open
        assert!(check_kdf_limits(&argon2(64 << 20, 10)).is_ok());
        assert!(check_kdf_limits(&argon2(64 << 20, 150)).is_ok());
    }

    /// A file whose header asks for `kdf`: refused before the KDF runs (a 4 TiB Argon2 would abort
    /// the process, 2⁶⁴ rounds would never end), whatever the key.
    #[test]
    fn files_over_the_limits_are_refused_before_the_kdf_runs() {
        let (db, key) = vault::create_vault_kdbx("V", &[3; 32], 1_700_000_000).unwrap();
        for (kdf, param) in [
            (argon2(u64::from(u32::MAX) * 1024, 2), "memory"),
            (argon2(512 << 20, u64::from(u32::MAX)), "work"),
            (Kdf::AesKdf { rounds: u64::MAX, seed: vec![2; 32] }, "rounds"),
        ] {
            let mut h = db.header.clone();
            h.kdf = kdf;
            let header = header::write_outer(&h, h.version, &[4; 32], &[5; 16]);
            let mut file = header.clone();
            file.extend_from_slice(&primitives::sha256(&header));
            file.extend_from_slice(&[0; 32 + 64]);
            let started = std::time::Instant::now();
            too_large(read(&file, &key), param);
            assert!(started.elapsed().as_secs() < 2, "refused at once");
            // Nor written: this build couldn't open it again
            let mut big = db.clone();
            big.header = h;
            too_large(write(&big, &key), param);
        }
    }

    #[test]
    fn kdf_choices_over_the_limits_are_refused() {
        too_large(vault::argon2_kdf(Argon2Type::Id, MAX_ARGON2_MEMORY * 2, 1, 1), "memory");
        too_large(vault::argon2_kdf(Argon2Type::D, 512 << 20, 100, 4), "work");
        too_large(vault::aes_kdf(MAX_AES_KDF_ROUNDS + 1), "rounds");
        assert!(vault::argon2_kdf(Argon2Type::Id, 64 << 20, 10, 4).is_ok());
        assert!(vault::aes_kdf(60_000_000).is_ok());
    }
}
