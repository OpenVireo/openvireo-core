//! The `.kdbx` fixtures under `vectors/`.
//!
//! - `vault-fixture.kdbx`: the contract's account vault, opened with the raw vault key as a key-file
//!   component and no password (see [`crate::TestVectors::vault_kdbx`]).
//! - `kdbx/desktop-kdbx31.kdbx`, `kdbx/desktop-kdbx4-argon2d.kdbx`: written by the desktop app, password
//!   [`DESKTOP_PASSWORD`] (see `vectors/kdbx/SOURCE.md` for what they contain).

use std::path::PathBuf;

/// The password of both desktop-written fixtures.
pub const DESKTOP_PASSWORD: &str = "desktop pw ✓";

/// KDBX 3.1, AES-KDF, AES-256, written by the desktop CLI.
pub const DESKTOP_KDBX31: &str = "kdbx/desktop-kdbx31.kdbx";

/// KDBX 4.0, Argon2d, written by the iOS app then saved by the desktop CLI.
pub const DESKTOP_KDBX4_ARGON2D: &str = "kdbx/desktop-kdbx4-argon2d.kdbx";

/// The contract's account vault fixture.
pub const VAULT_FIXTURE: &str = "vault-fixture.kdbx";

/// Every `.kdbx` fixture, relative to `vectors/`.
pub const ALL: [&str; 3] = [VAULT_FIXTURE, DESKTOP_KDBX31, DESKTOP_KDBX4_ARGON2D];

/// The absolute path of a fixture, e.g. `kdbx::path(kdbx::DESKTOP_KDBX31)`.
pub fn path(fixture: &str) -> PathBuf {
    crate::vector_path(fixture)
}

/// The bytes of a fixture.
pub fn bytes(fixture: &str) -> Vec<u8> {
    crate::read_vector(fixture)
}
