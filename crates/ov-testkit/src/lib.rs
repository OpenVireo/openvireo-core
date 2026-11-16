//! Test helpers for openvireo-core. Use it as a `[dev-dependencies]` entry only.
//!
//! - [`vectors_dir`] and [`vector_path`]: where the frozen copies of the contract live (`vectors/`).
//! - [`mod@test_vectors`]: typed `vectors/test-vectors.json` (SPEC test vectors), see [`TestVectors`].
//! - [`merge`]: typed `vectors/merge-fixtures/*.json`, see [`merge_fixtures`].
//! - [`opaque`]: typed `vectors/opaque-transcripts.json`, see [`opaque_transcripts`].
//! - [`kdbx`]: the `.kdbx` fixtures and their keys.
//! - [`hex!`], [`hex_bytes`], [`hex_array`], [`b64u`]: decode test data.
//! - [`FixedClock`], [`ManualClock`]: deterministic time.
//!
//! The vector data is public test data, not secrets, so the types derive `Debug`.

use std::path::{Path, PathBuf};

pub mod clock;
pub mod kdbx;
pub mod merge;
pub mod opaque;
pub mod test_vectors;

pub use clock::{FixedClock, ManualClock};
pub use merge::{merge_fixtures, MergeFixture};
pub use opaque::{opaque_transcripts, OpaqueTranscripts};
pub use test_vectors::{test_vectors, TestVectors};

/// The absolute path of the workspace's `vectors/` folder.
pub fn vectors_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    dir.canonicalize().unwrap_or_else(|e| panic!("vectors/ not found at {}: {e}", dir.display()))
}

/// The absolute path of a file under `vectors/`, e.g. `vector_path("kdbx/desktop-kdbx31.kdbx")`.
/// Panics if it doesn't exist.
pub fn vector_path(relative: &str) -> PathBuf {
    let p = vectors_dir().join(relative);
    assert!(p.exists(), "missing vector file {}", p.display());
    p
}

/// Reads a file under `vectors/`. Panics on error.
pub fn read_vector(relative: &str) -> Vec<u8> {
    let p = vector_path(relative);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Reads and parses a JSON file under `vectors/` into `T`. Panics with the path on error.
pub fn load_json<T: serde::de::DeserializeOwned>(relative: &str) -> T {
    let bytes = read_vector(relative);
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("vectors/{relative}: {e}"))
}

/// Decodes hex (upper or lower case). Panics on bad input, with the input in the message.
pub fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
}

/// Decodes hex into exactly `N` bytes. Panics on bad input or the wrong length.
pub fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    let v = hex_bytes(s);
    v.as_slice().try_into().unwrap_or_else(|_| panic!("hex {s:?} is {} bytes, expected {N}", v.len()))
}

/// Decodes base64url without padding (the vectors' default binary encoding). Panics on bad input.
pub fn b64u(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap_or_else(|e| panic!("bad base64url {s:?}: {e}"))
}

/// Decodes hex in tests: `hex!("00ff")` is `vec![0x00, 0xff]`. Several literals are concatenated, so long
/// values can be split across lines. Panics on bad hex.
#[macro_export]
macro_rules! hex {
    ($($s:literal),+ $(,)?) => {
        $crate::hex_bytes(concat!($($s),+))
    };
}

/// Parses a UTC timestamp of the form `YYYY-MM-DDTHH:MM:SSZ` (the merge fixtures' format) into Unix seconds.
/// Panics on anything else.
pub fn utc_seconds(s: &str) -> i64 {
    let b = s.as_bytes();
    let ok = b.len() == 20
        && [4, 7].iter().all(|&i| b[i] == b'-')
        && b[10] == b'T'
        && [13, 16].iter().all(|&i| b[i] == b':')
        && b[19] == b'Z';
    assert!(ok, "not a YYYY-MM-DDTHH:MM:SSZ timestamp: {s:?}");
    let num = |r: std::ops::Range<usize>| -> i64 {
        s[r].parse().unwrap_or_else(|_| panic!("not a YYYY-MM-DDTHH:MM:SSZ timestamp: {s:?}"))
    };
    let (y, m, d) = (num(0..4), num(5..7), num(8..10));
    let (hh, mm, ss) = (num(11..13), num(14..16), num(17..19));
    assert!((1..=12).contains(&m) && (1..=31).contains(&d) && hh < 24 && mm < 60 && ss < 61, "bad timestamp {s:?}");
    // days from civil (Howard Hinnant's algorithm)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hh * 3600 + mm * 60 + ss
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_helpers() {
        assert_eq!(hex!("00ff", "10"), vec![0x00, 0xff, 0x10]);
        assert_eq!(hex_array::<2>("abCD"), [0xab, 0xcd]);
        assert_eq!(b64u("AP8"), vec![0x00, 0xff]);
    }

    #[test]
    #[should_panic(expected = "expected 3")]
    fn hex_array_checks_length() {
        hex_array::<3>("00");
    }

    #[test]
    fn utc() {
        assert_eq!(utc_seconds("1970-01-01T00:00:00Z"), 0);
        assert_eq!(utc_seconds("2026-03-01T12:00:00Z"), 1_772_366_400);
        assert_eq!(utc_seconds("2000-02-29T23:59:59Z"), 951_868_799);
    }
}
