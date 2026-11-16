//! The `SecureStore` for `ov`: one JSON file, the same file and format as the TS SDK's
//! `FileStorage` (`packages/sdk/src/auth/storage-node.ts`), so a session saved by the TS `ov login`
//! carries over.
//!
//! The file is a flat JSON object of string keys to string values, written with 2-space
//! indentation (`JSON.stringify(data, null, 2)`), keys in insertion order, atomically (a
//! `<path>.<pid>.tmp` file renamed over it) with mode 0600 in a 0700 directory.
//!
//! `SecureStore` values are bytes, but the TS file holds strings, so values must be UTF-8 (every
//! value the TS SDK stores is: JSON, base64url or plain text). Non-UTF-8 values are refused rather
//! than written in a form the TS CLI couldn't read.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ov_core::host::SecureStore;
use ov_error::OvError;
use serde::de::{Deserializer, MapAccess, Visitor};
use zeroize::Zeroizing;

type Entries = Vec<(String, Zeroizing<String>)>;

/// A file-backed [`SecureStore`]. Safe to share between tasks; reads and writes are serialized.
pub struct FileStore {
    path: PathBuf,
    cache: Mutex<Option<Entries>>,
}

impl fmt::Debug for FileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileStore").field("path", &self.path).finish_non_exhaustive()
    }
}

/// Parses a JSON object keeping key order. Non-string values keep their JSON text.
struct OrderedMap(Entries);

impl<'de> serde::Deserialize<'de> for OrderedMap {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = OrderedMap;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<OrderedMap, A::Error> {
                let mut out: Entries = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, serde_json::Value>()? {
                    let text = match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    // A repeated key: the last one wins, in the first one's place (as JSON.parse).
                    if let Some(slot) = out.iter_mut().find(|(ek, _)| *ek == k) {
                        slot.1 = Zeroizing::new(text);
                    } else {
                        out.push((k, Zeroizing::new(text)));
                    }
                }
                Ok(OrderedMap(out))
            }
        }
        d.deserialize_map(V)
    }
}

fn store_error(what: &str, path: &Path, e: impl fmt::Display) -> OvError {
    OvError::internal(format!("can't {what} {}: {e}", path.display()))
}

/// `JSON.stringify(data, null, 2)` for a flat object of strings.
fn serialize(entries: &Entries) -> Result<Zeroizing<String>, serde_json::Error> {
    if entries.is_empty() {
        return Ok(Zeroizing::new("{}".to_string()));
    }
    let mut out = Zeroizing::new(String::from("{\n"));
    for (i, (k, v)) in entries.iter().enumerate() {
        out.push_str("  ");
        out.push_str(&serde_json::to_string(k)?);
        out.push_str(": ");
        out.push_str(&Zeroizing::new(serde_json::to_string(v.as_str())?));
        out.push_str(if i + 1 < entries.len() { ",\n" } else { "\n" });
    }
    out.push('}');
    Ok(out)
}

impl FileStore {
    /// A store backed by `path` (normally `<config dir>/session.json`). Nothing is read until the
    /// first call.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileStore { path: path.into(), cache: Mutex::new(None) }
    }

    /// The file this store uses.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self, cache: &mut Option<Entries>) -> Result<(), OvError> {
        if cache.is_some() {
            return Ok(());
        }
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let text = std::str::from_utf8(&bytes).map_err(|e| store_error("read", &self.path, e))?;
                let map: OrderedMap = serde_json::from_str(text).map_err(|e| store_error("read", &self.path, e))?;
                *cache = Some(map.0);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => *cache = Some(Vec::new()),
            Err(e) => return Err(store_error("read", &self.path, e)),
        }
        Ok(())
    }

    fn persist(&self, entries: &Entries) -> Result<(), OvError> {
        let dir = self.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).map_err(|e| store_error("create", dir, e))?;

        let mut tmp = self.path.clone().into_os_string();
        tmp.push(format!(".{}.tmp", std::process::id()));
        let tmp = PathBuf::from(tmp);
        let body = serialize(entries).map_err(|e| store_error("write", &self.path, e))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let write = || -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
            #[cfg(unix)]
            std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
            std::fs::rename(&tmp, &self.path)
        };
        write().map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            store_error("write", &self.path, e)
        })
    }

    fn with<T>(&self, f: impl FnOnce(&mut Entries) -> Result<T, OvError>) -> Result<T, OvError> {
        let mut guard = self.cache.lock().map_err(|_| OvError::internal("the session store lock is poisoned"))?;
        self.load(&mut guard)?;
        let entries = guard.as_mut().ok_or_else(|| OvError::internal("the session store didn't load"))?;
        f(entries)
    }
}

#[async_trait::async_trait]
impl SecureStore for FileStore {
    async fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, OvError> {
        self.with(|e| Ok(e.iter().find(|(k, _)| k == key).map(|(_, v)| Zeroizing::new(v.as_bytes().to_vec()))))
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), OvError> {
        let text = std::str::from_utf8(value)
            .map_err(|_| OvError::internal(format!("the ov session store holds text only; {key} isn't UTF-8")))?;
        self.with(|e| {
            let value = Zeroizing::new(text.to_string());
            match e.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value,
                None => e.push((key.to_string(), value)),
            }
            self.persist(e)
        })
    }

    async fn delete(&self, key: &str) -> Result<(), OvError> {
        self.with(|e| {
            let before = e.len();
            e.retain(|(k, _)| k != key);
            if e.len() == before {
                return Ok(());
            }
            self.persist(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ov-store-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn round_trips_and_writes_the_ts_format() {
        let dir = scratch("roundtrip");
        let path = dir.join("nested").join("session.json");
        let s = FileStore::new(&path);
        assert_eq!(s.get("missing").await.unwrap(), None);
        s.set("cli:issuer", b"https://a.example").await.unwrap();
        s.set("session", b"{\"q\":\"\\n\"}").await.unwrap();
        s.set("cli:issuer", b"https://b.example").await.unwrap();
        s.delete("nope").await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "{\n  \"cli:issuer\": \"https://b.example\",\n  \"session\": \"{\\\"q\\\":\\\"\\\\n\\\"}\"\n}"
        );
        let again = FileStore::new(&path);
        assert_eq!(again.get("session").await.unwrap().unwrap().as_slice(), b"{\"q\":\"\\n\"}");
        again.delete("cli:issuer").await.unwrap();
        again.delete("session").await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
        assert!(again.set("bin", &[0xff, 0xfe]).await.is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
