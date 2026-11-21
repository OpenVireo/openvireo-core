//! Account vault helpers, ported from the SDK's `vault/kdbx.ts`.
//!
//! Account vaults use the 32-byte vault key as a raw key file component with no password, and
//! Argon2id with m = 1 MiB, t = 2, p = 1 (SPEC §7). kdbxweb's `Kdbx` holds its credentials; the
//! model doesn't, so these helpers return a [`CompositeKey`] where the TS code set
//! `db.credentials`.

use ov_crypto::primitives;
use ov_error::{OvError, OvErrorCode};

use crate::model::{
    Argon2Type, Cipher, Compression, CustomDataItem, Database, Group, Header, KdbxVersion, Kdf, Meta, Timestamp, Uuid,
};
use crate::CompositeKey;

/// The vault KDF memory (SPEC §7): 1 MiB, in bytes as KDBX stores it.
pub const VAULT_KDF_MEMORY: u64 = 1024 * 1024;
/// The vault KDF iterations (SPEC §7).
pub const VAULT_KDF_ITERATIONS: u64 = 2;
/// The vault KDF parallelism (SPEC §7).
pub const VAULT_KDF_PARALLELISM: u32 = 1;

/// KeePassXC's remote sync settings in Meta custom data (Qt `CustomData::RemoteProgramSettings`).
pub const REMOTE_SETTINGS_KEY: &str = "KPXC_REMOTE_SYNC_SETTINGS";
/// The sync generation in Meta custom data (KeePassXC `KPXC_SYNC_GENERATION`).
pub const SYNC_GENERATION_KEY: &str = "KPXC_SYNC_GENERATION";

/// A random v4 UUID for a new group or entry.
pub fn new_uuid() -> Result<Uuid, OvError> {
    let b = primitives::random_array::<16>()?;
    Ok(uuid::Builder::from_random_bytes(*b).into_uuid())
}

/// Account vault credentials: the vault key as a raw key file component, no password.
/// Fails with `no_vault_key` unless the key is 32 bytes.
pub fn vault_credentials(vault_key: &[u8]) -> Result<CompositeKey, OvError> {
    if vault_key.len() != 32 {
        return Err(OvError::new(OvErrorCode::NoVaultKey, "a vault key is 32 bytes"));
    }
    Ok(CompositeKey::new().with_key_file(vault_key))
}

/// Password (and optional key file) credentials, for local and self-hosted databases.
pub fn password_credentials(password: Option<&str>, key_file: Option<&[u8]>) -> CompositeKey {
    let mut k = CompositeKey::new();
    if let Some(p) = password {
        k = k.with_password(p);
    }
    if let Some(f) = key_file {
        k = k.with_key_file(f);
    }
    k
}

/// SHA-256 of the password: the password component of a composite key (TS `passwordHash`).
pub fn password_hash(password: &str) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(primitives::sha256(password.as_bytes()))
}

/// Credentials from a [`password_hash`] (TS `passwordHashCredentials`); `invalid_request` unless
/// it is 32 bytes.
pub fn password_hash_credentials(hash: &[u8]) -> Result<CompositeKey, OvError> {
    let h: &[u8; 32] =
        hash.try_into().map_err(|_| OvError::new(OvErrorCode::InvalidRequest, "a password hash is 32 bytes"))?;
    Ok(CompositeKey::new().with_password_hash(h))
}

/// The vault KDF with a fresh 32-byte salt.
pub fn vault_kdf() -> Result<Kdf, OvError> {
    Ok(Kdf::Argon2 {
        kind: Argon2Type::Id,
        salt: primitives::random_bytes(32)?.to_vec(),
        memory: VAULT_KDF_MEMORY,
        iterations: VAULT_KDF_ITERATIONS,
        parallelism: VAULT_KDF_PARALLELISM,
        version: 0x13,
        secret: None,
        associated_data: None,
    })
}

/// Sets the vault KDF (Argon2id, 1 MiB, t = 2, p = 1, fresh salt). A KDBX 3.1 database (which
/// can't hold Argon2) is upgraded to KDBX 4 first.
pub fn apply_vault_kdf(db: &mut Database) -> Result<(), OvError> {
    if db.header.version.major < 4 {
        db.header.version = crate::write_version(db);
    }
    db.header.kdf = vault_kdf()?;
    Ok(())
}

/// KeePassXC's default Argon2d memory for new databases: 64 MiB, in bytes.
pub const DATABASE_DEFAULT_KDF_MEMORY: u64 = 64 * 1024 * 1024;
/// KeePassXC's default Argon2d iterations for new databases.
pub const DATABASE_DEFAULT_KDF_ITERATIONS: u64 = 10;
/// KeePassXC's default Argon2d lanes for new databases.
pub const DATABASE_DEFAULT_KDF_PARALLELISM: u32 = 2;

/// An Argon2 KDF with a fresh 32-byte salt. `memory` is in bytes (a multiple of 1 KiB, at least 8 KiB
/// per lane), `iterations` at least 1, `parallelism` 1 to 255; `invalid_request` otherwise.
pub fn argon2_kdf(kind: Argon2Type, memory: u64, iterations: u64, parallelism: u32) -> Result<Kdf, OvError> {
    let bad = |m: &str| Err(OvError::new(OvErrorCode::InvalidRequest, m.to_owned()));
    if !(1..=255).contains(&parallelism) {
        return bad("Argon2 parallelism must be 1 to 255");
    }
    if iterations == 0 || iterations > u64::from(u32::MAX) {
        return bad("Argon2 iterations must be at least 1");
    }
    if !memory.is_multiple_of(1024) || memory / 1024 > u64::from(u32::MAX) || memory < 8 * 1024 * u64::from(parallelism)
    {
        return bad("Argon2 memory must be whole KiB, at least 8 KiB per lane");
    }
    // Not more than this build would open again (`too_large`)
    crate::check_kdf_limits(&Kdf::Argon2 {
        kind,
        salt: Vec::new(),
        memory,
        iterations,
        parallelism,
        version: 0x13,
        secret: None,
        associated_data: None,
    })?;
    Ok(Kdf::Argon2 {
        kind,
        salt: primitives::random_bytes(32)?.to_vec(),
        memory,
        iterations,
        parallelism,
        version: 0x13,
        secret: None,
        associated_data: None,
    })
}

/// KeePassXC's default KDF for new databases (Argon2d, 64 MiB, 10 iterations, 2 lanes), fresh salt.
pub fn database_default_kdf() -> Result<Kdf, OvError> {
    argon2_kdf(
        Argon2Type::D,
        DATABASE_DEFAULT_KDF_MEMORY,
        DATABASE_DEFAULT_KDF_ITERATIONS,
        DATABASE_DEFAULT_KDF_PARALLELISM,
    )
}

/// AES-KDF with `rounds` (at least 1) and a fresh 32-byte seed.
pub fn aes_kdf(rounds: u64) -> Result<Kdf, OvError> {
    if rounds == 0 {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "AES-KDF rounds must be at least 1"));
    }
    crate::check_kdf_limits(&Kdf::AesKdf { rounds, seed: Vec::new() })?;
    Ok(Kdf::AesKdf { rounds, seed: primitives::random_bytes(32)?.to_vec() })
}

/// Sets the database's KDF. Argon2 needs KDBX 4, so a KDBX 3.1 database is upgraded first.
pub fn set_kdf(db: &mut Database, kdf: Kdf) {
    if matches!(kdf, Kdf::Argon2 { .. }) && db.header.version.major < 4 {
        db.header.version = crate::write_version(db);
    }
    db.header.kdf = kdf;
}

/// The KDF settings in the TS shape: `kdf` is `"argon2id"`, `"argon2d"`, `"aes"` or `"other"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfSettings {
    /// The KDF name.
    pub kdf: String,
    /// Argon2 memory in bytes.
    pub m: Option<u64>,
    /// Argon2 iterations, or AES-KDF rounds.
    pub t: Option<u64>,
    /// Argon2 parallelism.
    pub p: Option<u32>,
}

/// The database's KDF settings (TS `kdfSettings`).
pub fn kdf_settings(db: &Database) -> KdfSettings {
    match &db.header.kdf {
        Kdf::Argon2 { kind, memory, iterations, parallelism, .. } => KdfSettings {
            kdf: match kind {
                Argon2Type::Id => "argon2id",
                Argon2Type::D => "argon2d",
            }
            .into(),
            m: Some(*memory),
            t: Some(*iterations),
            p: Some(*parallelism),
        },
        Kdf::AesKdf { rounds, .. } => KdfSettings { kdf: "aes".into(), m: None, t: Some(*rounds), p: None },
        Kdf::Other(_) => KdfSettings { kdf: "other".into(), m: None, t: None, p: None },
    }
}

/// A new, empty database as kdbxweb's `Kdbx.create` makes it: KDBX 4.0, AES-256, gzip, Argon2d
/// (1 MiB, t = 2, p = 1, fresh salt), the root group and the database named `name`, the Recycle
/// Bin enabled (its group is made on first delete).
pub fn create_kdbx(name: &str, now: Timestamp) -> Result<Database, OvError> {
    let mut kdf = vault_kdf()?;
    if let Kdf::Argon2 { kind, .. } = &mut kdf {
        *kind = Argon2Type::D;
    }
    Ok(Database {
        header: Header {
            version: KdbxVersion { major: 4, minor: 0 },
            cipher: Cipher::Aes256Cbc,
            compression: Compression::Gzip,
            kdf,
            public_custom_data: None,
            unknown_fields: Vec::new(),
        },
        meta: Meta {
            database_name: name.to_owned(),
            database_name_changed: Some(now),
            database_description_changed: Some(now),
            default_user_name_changed: Some(now),
            master_key_changed: Some(now),
            recycle_bin_changed: Some(now),
            entry_templates_group_changed: Some(now),
            ..Meta::default()
        },
        root: Group::new(new_uuid()?, name, now),
        deleted_objects: Vec::new(),
        binaries: Vec::new(),
        unknown_file: Vec::new(),
        unknown_root: Vec::new(),
    })
}

/// A new account vault: KDBX 4, the vault KDF, the root group named after the vault (TS
/// `createVaultKdbx`). Returns the database and its key.
pub fn create_vault_kdbx(name: &str, vault_key: &[u8], now: Timestamp) -> Result<(Database, CompositeKey), OvError> {
    let key = vault_credentials(vault_key)?;
    let mut db = create_kdbx(name, now)?;
    apply_vault_kdf(&mut db)?;
    Ok((db, key))
}

/// Re-keys a database to a vault key (rotation, "Move to account"): upgrades KDBX 3.1 to 4 and
/// sets the vault KDF. Save with the returned key.
pub fn rekey_to_vault_key(db: &mut Database, vault_key: &[u8]) -> Result<CompositeKey, OvError> {
    let key = vault_credentials(vault_key)?;
    apply_vault_kdf(db)?;
    Ok(key)
}

/// A separate copy of a database with its unsaved changes (TS `copyKdbx`). The model is plain
/// data, so this is a deep clone; no save and load (and no KDF run) are needed.
pub fn copy_kdbx(db: &Database) -> Database {
    db.clone()
}

/// Drops sync-server and account-vault remotes from KeePassXC's remote settings, keeping
/// command-based ones, as Qt does when it moves a database to an account. Unreadable settings are
/// dropped. Kept remotes are re-serialised (`serde_json`, keys in sorted order).
pub fn drop_server_remotes(db: &mut Database) {
    let cd = &mut db.meta.custom_data;
    let Some(pos) = cd.iter().position(|i| i.key == REMOTE_SETTINGS_KEY) else { return };
    let kept: Vec<serde_json::Value> = match serde_json::from_str::<serde_json::Value>(&cd[pos].value) {
        Ok(serde_json::Value::Array(items)) => items
            .into_iter()
            .filter(|r| !matches!(r.get("type").and_then(|t| t.as_str()), Some("syncServer" | "accountVault")))
            .collect(),
        _ => Vec::new(),
    };
    if kept.is_empty() {
        cd.remove(pos);
    } else {
        cd[pos].value = serde_json::Value::Array(kept).to_string();
    }
}

/// One vault key and its version.
#[derive(Clone)]
pub struct KeyVersion {
    /// The key version (SPEC §7).
    pub version: u32,
    /// The 32-byte vault key.
    pub key: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for KeyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyVersion").field("version", &self.version).finish_non_exhaustive()
    }
}

/// Opens a vault with the newest key first, falling back to older ones (SPEC §7), so a crash
/// between the re-keyed upload and `activate` never locks anyone out. Returns the database and
/// the version that opened it. `no_vault_key` when `keys` is empty; the last `vault_key_mismatch`
/// when none fits; any other error at once.
pub fn open_with_key_versions(data: &[u8], keys: &[KeyVersion]) -> Result<(Database, u32), OvError> {
    if keys.is_empty() {
        return Err(OvError::new(OvErrorCode::NoVaultKey, "no vault key available"));
    }
    let mut sorted: Vec<&KeyVersion> = keys.iter().collect();
    sorted.sort_by_key(|k| std::cmp::Reverse(k.version));
    let mut last = None;
    for k in sorted {
        match crate::read(data, &vault_credentials(&k.key)?) {
            Ok(db) => return Ok((db, k.version)),
            Err(e) if e.is(OvErrorCode::VaultKeyMismatch) => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.expect("at least one key was tried"))
}

/// The sync generation in Meta custom data; 0 when absent or not a number (TS `syncGeneration`).
pub fn sync_generation(db: &Database) -> u64 {
    db.meta.custom_data_value(SYNC_GENERATION_KEY).and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

/// Sets the sync generation (TS `setSyncGeneration`). The item keeps its place; its
/// `LastModificationTime` is set to `now` on KDBX 4.1 databases (4.0 has no such element).
pub fn set_sync_generation(db: &mut Database, generation: u64, now: Timestamp) {
    let v41 = db.header.version >= KdbxVersion { major: 4, minor: 1 };
    set_custom_data(&mut db.meta.custom_data, SYNC_GENERATION_KEY, &generation.to_string(), v41.then_some(now));
}

/// Sets `key` in a custom data list, in place when present, else appended.
pub fn set_custom_data(items: &mut Vec<CustomDataItem>, key: &str, value: &str, last_modification: Option<Timestamp>) {
    match items.iter_mut().find(|i| i.key == key) {
        Some(i) => {
            i.value = value.to_owned();
            i.last_modification = last_modification;
        }
        None => items.push(CustomDataItem { key: key.to_owned(), value: value.to_owned(), last_modification }),
    }
}
