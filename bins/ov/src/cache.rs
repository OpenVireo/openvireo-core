//! The offline cache (`BlobCache`, SPEC §20) for `ov`: files under `<config dir>/cache/`.
//!
//! Layout: `cache/<user>/vault-<vault id>.json` (a [`CachedVault`] as JSON with base64 fields) and
//! `cache/<user>/meta-<name>` (raw bytes); `<user>` is `device` for the per-device records
//! (`user_id == ""`) and `u-<user id>` otherwise. Names are percent-encoded so any id is a safe file
//! name. Everything in it is ciphertext or public (host.rs), but files are still 0600.
//!
//! The TS CLI kept no offline cache of its own, so there is nothing to carry over here.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ov_core::host::{BlobCache, CachedVault};
use ov_error::OvError;
use serde::{Deserialize, Serialize};

/// A file-backed [`BlobCache`].
#[derive(Debug)]
pub struct FileCache {
    root: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Record {
    state: String,
    base: Option<String>,
    pending: Option<String>,
    autofill: Option<String>,
}

fn encode_name(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' || (b == b'.' && !out.is_empty()) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode_name(s: &str) -> Option<String> {
    crate::js::decode_uri_component(s)
}

fn cache_error(what: &str, path: &Path, e: impl std::fmt::Display) -> OvError {
    OvError::internal(format!("can't {what} {}: {e}", path.display()))
}

fn read_opt(path: &Path) -> Result<Option<Vec<u8>>, OvError> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(cache_error("read", path, e)),
    }
}

fn remove_opt(path: &Path) -> Result<(), OvError> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(cache_error("remove", path, e)),
        _ => Ok(()),
    }
}

fn b64(v: &Option<Vec<u8>>) -> Option<String> {
    v.as_ref().map(|b| B64.encode(b))
}

fn unb64(path: &Path, v: Option<String>) -> Result<Option<Vec<u8>>, OvError> {
    v.map(|s| B64.decode(s).map_err(|e| cache_error("read", path, e))).transpose()
}

impl FileCache {
    /// A cache rooted at `root` (normally `<config dir>/cache`).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FileCache { root: root.into() }
    }

    fn user_dir(&self, user_id: &str) -> PathBuf {
        if user_id.is_empty() {
            self.root.join("device")
        } else {
            self.root.join(format!("u-{}", encode_name(user_id)))
        }
    }

    fn vault_path(&self, user_id: &str, vault_id: &str) -> PathBuf {
        self.user_dir(user_id).join(format!("vault-{}.json", encode_name(vault_id)))
    }

    fn meta_path(&self, user_id: &str, name: &str) -> PathBuf {
        self.user_dir(user_id).join(format!("meta-{}", encode_name(name)))
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), OvError> {
        let dir = path.parent().unwrap_or(&self.root);
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).map_err(|e| cache_error("create", dir, e))?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(format!(".{}.tmp", std::process::id()));
        let tmp = PathBuf::from(tmp);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let run = || -> std::io::Result<()> {
            use std::io::Write;
            let mut f = opts.open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        };
        run().map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            cache_error("write", path, e)
        })
    }
}

#[async_trait::async_trait]
impl BlobCache for FileCache {
    async fn load(&self, user_id: &str, vault_id: &str) -> Result<Option<CachedVault>, OvError> {
        let path = self.vault_path(user_id, vault_id);
        let Some(bytes) = read_opt(&path)? else { return Ok(None) };
        let r: Record = serde_json::from_slice(&bytes).map_err(|e| cache_error("read", &path, e))?;
        Ok(Some(CachedVault {
            state: unb64(&path, Some(r.state))?.unwrap_or_default(),
            base: unb64(&path, r.base)?,
            pending: unb64(&path, r.pending)?,
            autofill: unb64(&path, r.autofill)?,
        }))
    }

    async fn save(&self, user_id: &str, vault_id: &str, v: &CachedVault) -> Result<(), OvError> {
        let path = self.vault_path(user_id, vault_id);
        let r = Record {
            state: B64.encode(&v.state),
            base: b64(&v.base),
            pending: b64(&v.pending),
            autofill: b64(&v.autofill),
        };
        let bytes = serde_json::to_vec(&r).map_err(|e| cache_error("write", &path, e))?;
        self.write(&path, &bytes)
    }

    async fn remove(&self, user_id: &str, vault_id: &str) -> Result<(), OvError> {
        remove_opt(&self.vault_path(user_id, vault_id))
    }

    async fn list(&self, user_id: &str) -> Result<Vec<String>, OvError> {
        let dir = self.user_dir(user_id);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(cache_error("list", &dir, e)),
        };
        let mut out = Vec::new();
        for entry in entries {
            let name = entry.map_err(|e| cache_error("list", &dir, e))?.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name.strip_prefix("vault-").and_then(|n| n.strip_suffix(".json")) {
                out.extend(decode_name(id));
            }
        }
        out.sort();
        Ok(out)
    }

    async fn load_meta(&self, user_id: &str, name: &str) -> Result<Option<Vec<u8>>, OvError> {
        read_opt(&self.meta_path(user_id, name))
    }

    async fn save_meta(&self, user_id: &str, name: &str, value: &[u8]) -> Result<(), OvError> {
        self.write(&self.meta_path(user_id, name), value)
    }

    async fn clear_user(&self, user_id: &str) -> Result<(), OvError> {
        let dir = self.user_dir(user_id);
        match std::fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(cache_error("remove", &dir, e)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stores_vaults_and_meta_per_user() {
        let root = std::env::temp_dir().join(format!("ov-cache-test-{}", std::process::id()));
        let c = FileCache::new(&root);
        let v = CachedVault { state: b"s".to_vec(), base: Some(vec![0, 1, 2]), pending: None, autofill: None };
        c.save("u/1", "v:1", &v).await.unwrap();
        c.save("u/1", "..", &v).await.unwrap();
        c.save_meta("", "config:https://a.example/", b"{}").await.unwrap();
        assert_eq!(c.load("u/1", "v:1").await.unwrap(), Some(v.clone()));
        assert_eq!(c.load("u/2", "v:1").await.unwrap(), None);
        assert_eq!(c.list("u/1").await.unwrap(), vec!["..", "v:1"]);
        assert_eq!(c.load_meta("", "config:https://a.example/").await.unwrap().unwrap(), b"{}");
        c.remove("u/1", "..").await.unwrap();
        c.remove("u/1", "..").await.unwrap();
        assert_eq!(c.list("u/1").await.unwrap(), vec!["v:1"]);
        c.clear_user("u/1").await.unwrap();
        assert!(c.list("u/1").await.unwrap().is_empty());
        assert!(c.load_meta("", "config:https://a.example/").await.unwrap().is_some());
        std::fs::remove_dir_all(root).unwrap();
    }
}
