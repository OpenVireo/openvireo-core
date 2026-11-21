//! KDBX XML: the element tree and the model reader and writer.

pub(crate) mod fast;
pub(crate) mod read;
pub(crate) mod tree;
pub(crate) mod write;

/// The KDBX corpus (`corpus/kdbx/manifest.tsv`) for unit tests, which run with the fast-path and
/// writer checks that integration tests don't get.
#[cfg(test)]
pub(crate) mod corpus {
    use std::path::{Path, PathBuf};

    pub(crate) struct File {
        pub(crate) name: String,
        pub(crate) bytes: Vec<u8>,
        pub(crate) key: crate::CompositeKey,
    }

    /// Every file present: required ones must be (CI has no optional or external ones).
    pub(crate) fn files() -> Vec<File> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/kdbx");
        let manifest = std::fs::read_to_string(dir.join("manifest.tsv")).unwrap();
        let ext = std::env::var("OV_KEEPASSXC_SRC")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("kpnx/openvireo"));
        let (mut out, mut required) = (Vec::new(), 0);
        for line in manifest.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            let cols: Vec<&str> = line.split('\t').collect();
            let path = match cols[0].strip_prefix("ext:") {
                Some(p) => ext.join(p),
                None => dir.join(cols[0]),
            };
            required += u32::from(cols[4] == "required");
            let Ok(bytes) = std::fs::read(&path) else {
                assert_ne!(cols[4], "required", "{} is missing", cols[0]);
                continue;
            };
            let mut key = crate::CompositeKey::new();
            match cols[2] {
                "-" => {}
                "<empty>" => key = key.with_password(""),
                pw => key = key.with_password(pw),
            }
            if cols[3] != "-" {
                key = key.with_key_file(&std::fs::read(dir.join(cols[3])).unwrap());
            }
            out.push(File { name: cols[0].to_owned(), bytes, key });
        }
        assert!(required >= 12 && out.len() >= required as usize, "{} files, {required} required", out.len());
        out
    }
}
