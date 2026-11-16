//! What a client keeps per synced database (TS `SyncState`), and its JSON form.
//!
//! The JSON is the TS SDK's `serializeSyncState` byte for byte (same keys, same order, the base as
//! unpadded base64url, snapshot keys as kdbxweb's base64 UUID ids), so the state a web client
//! stored before the switch to the core reads back unchanged.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ov_error::{OvError, OvErrorCode};
use ov_host::CachedVault;
use ov_kdbx::model::Uuid;
use ov_merge::Snapshot;
use serde_json::Value;

/// The sync state of one database (TS `SyncState`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    /// The server's ETag at the last sync.
    pub etag: String,
    /// The highest revision this device has seen (`-1` when the server sent none).
    pub revision: i64,
    /// The highest sync generation this device has seen (rollback detection).
    pub generation: u64,
    /// Entry UUID → modification time in milliseconds at the last sync.
    pub snapshot: Snapshot,
    /// The server's bytes at the last sync (an encrypted `.kdbx`): the merge base for the next sync,
    /// and the offline copy.
    pub base: Option<Vec<u8>>,
    /// When the last sync finished, as an RFC 3339 time with milliseconds (`toISOString`).
    pub last_sync: String,
}

impl std::fmt::Debug for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncState")
            .field("etag", &self.etag)
            .field("revision", &self.revision)
            .field("generation", &self.generation)
            .field("snapshot_len", &self.snapshot.len())
            .field("base_len", &self.base.as_ref().map(Vec::len))
            .field("last_sync", &self.last_sync)
            .finish()
    }
}

/// `serializeSyncState`: `{"etag","revision","generation","snapshot","base"?,"lastSync"}`.
pub fn serialize_sync_state(s: &SyncState) -> String {
    serialize(s, true)
}

fn serialize(s: &SyncState, with_base: bool) -> String {
    let q = |v: &str| Value::String(v.to_owned()).to_string();
    let mut out = String::with_capacity(128 + s.snapshot.len() * 40 + s.base.as_ref().map_or(0, |b| b.len() * 4 / 3));
    out.push_str("{\"etag\":");
    out.push_str(&q(&s.etag));
    out.push_str(&format!(",\"revision\":{},\"generation\":{},\"snapshot\":{{", s.revision, s.generation));
    for (i, (id, ms)) in s.snapshot.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&q(&uuid_id(id)));
        out.push(':');
        out.push_str(&ms.to_string());
    }
    out.push('}');
    if let (true, Some(b)) = (with_base, &s.base) {
        out.push_str(",\"base\":");
        out.push_str(&q(&URL_SAFE_NO_PAD.encode(b)));
    }
    out.push_str(",\"lastSync\":");
    out.push_str(&q(&s.last_sync));
    out.push('}');
    out
}

/// `deserializeSyncState`. Missing fields take their zero value, unknown keys are ignored, and
/// snapshot keys that aren't 16-byte base64 ids are dropped. `invalid_request` when the text isn't
/// a JSON object.
pub fn deserialize_sync_state(json: &str) -> Result<SyncState, OvError> {
    let bad = |m: &str| OvError::new(OvErrorCode::InvalidRequest, format!("unreadable sync state: {m}"));
    let v: Value = serde_json::from_str(json).map_err(|_| bad("not JSON"))?;
    let o = v.as_object().ok_or_else(|| bad("not an object"))?;
    let num = |v: &Value| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64));
    // serde_json's map sorts keys; the snapshot is read again in document order.
    let raw: RawState = serde_json::from_str(json).map_err(|_| bad("not an object"))?;
    let mut snapshot = Snapshot::new();
    for (k, v) in raw.snapshot.0 {
        if let (Some(id), Some(ms)) = (parse_uuid_id(&k), num(&v)) {
            snapshot.push((id, ms));
        }
    }
    let base = match o.get("base") {
        Some(Value::String(b)) if !b.is_empty() => Some(decode_b64(b).ok_or_else(|| bad("base is not base64"))?),
        _ => None,
    };
    Ok(SyncState {
        etag: o.get("etag").and_then(Value::as_str).unwrap_or_default().to_owned(),
        revision: o.get("revision").and_then(num).unwrap_or(0),
        generation: o.get("generation").and_then(num).map_or(0, |g| g.max(0) as u64),
        snapshot,
        base,
        last_sync: o.get("lastSync").and_then(Value::as_str).unwrap_or_default().to_owned(),
    })
}

#[derive(serde::Deserialize)]
struct RawState {
    #[serde(default)]
    snapshot: Ordered,
}

/// A JSON object's members in document order (anything else reads as empty).
#[derive(Default)]
struct Ordered(Vec<(String, Value)>);

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Ordered, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = m.next_entry::<String, Value>()? {
                    out.push((k, v));
                }
                Ok(Ordered(out))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut s: A) -> Result<Ordered, A::Error> {
                while s.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Ordered::default())
            }
            fn visit_bool<E>(self, _: bool) -> Result<Ordered, E> {
                Ok(Ordered::default())
            }
            fn visit_i64<E>(self, _: i64) -> Result<Ordered, E> {
                Ok(Ordered::default())
            }
            fn visit_u64<E>(self, _: u64) -> Result<Ordered, E> {
                Ok(Ordered::default())
            }
            fn visit_f64<E>(self, _: f64) -> Result<Ordered, E> {
                Ok(Ordered::default())
            }
            fn visit_str<E>(self, _: &str) -> Result<Ordered, E> {
                Ok(Ordered::default())
            }
            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// The state as the offline cache keeps it (SPEC §20): the JSON without the base in
/// [`CachedVault::state`], the base in [`CachedVault::base`]. `pending` and `autofill` are left
/// empty for the caller to fill.
pub fn to_cached(s: &SyncState) -> CachedVault {
    CachedVault { state: serialize(s, false).into_bytes(), base: s.base.clone(), pending: None, autofill: None }
}

/// The state from a cached record: [`CachedVault::base`] wins over a base inside the JSON (a state
/// stored by the TS SDK carries it there). `None` when the record holds no state.
pub fn from_cached(c: &CachedVault) -> Result<Option<SyncState>, OvError> {
    if c.state.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&c.state)
        .map_err(|_| OvError::new(OvErrorCode::InvalidRequest, "unreadable sync state: not UTF-8"))?;
    let mut s = deserialize_sync_state(text)?;
    if c.base.is_some() {
        s.base = c.base.clone();
    }
    Ok(Some(s))
}

/// kdbxweb's `KdbxUuid.id`: the 16 bytes in standard, padded base64.
pub fn uuid_id(id: &Uuid) -> String {
    STANDARD.encode(id.as_bytes())
}

/// The UUID from a kdbxweb id (standard or url-safe base64, padded or not).
pub fn parse_uuid_id(s: &str) -> Option<Uuid> {
    let bytes = decode_b64(s)?;
    Uuid::from_slice(&bytes).ok()
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    let t = s.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(t).or_else(|_| STANDARD_NO_PAD.decode(t)).ok()
}

/// Unix milliseconds as `Date.prototype.toISOString` writes them: `2026-11-15T12:00:00.000Z`.
pub fn iso_time(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let ms = unix_ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z", tod / 3600, tod / 60 % 60, tod % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SyncState {
        SyncState {
            etag: "\"e\\1\"".into(),
            revision: 3,
            generation: 2,
            snapshot: vec![(Uuid::from_bytes([0x45; 16]), 100_000), (Uuid::from_bytes([1; 16]), 2000)],
            base: Some(vec![0xfb, 0xff, 1, 2]),
            last_sync: "2026-11-15T12:00:00.000Z".into(),
        }
    }

    #[test]
    fn round_trips_in_ts_key_order() {
        let s = sample();
        let json = serialize_sync_state(&s);
        assert_eq!(
            json,
            r#"{"etag":"\"e\\1\"","revision":3,"generation":2,"snapshot":{"RUVFRUVFRUVFRUVFRUVFRQ==":100000,"AQEBAQEBAQEBAQEBAQEBAQ==":2000},"base":"-_8BAg","lastSync":"2026-11-15T12:00:00.000Z"}"#
        );
        assert_eq!(deserialize_sync_state(&json).unwrap(), s);
        assert_eq!(serialize_sync_state(&deserialize_sync_state(&json).unwrap()), json);
        // No base: the key is left out, as JSON.stringify drops undefined.
        let none = SyncState { base: None, ..s };
        assert!(!serialize_sync_state(&none).contains("base"));
    }

    #[test]
    fn lenient_reads() {
        let s = deserialize_sync_state(r#"{"etag":"x","snapshot":{"nope":1,"AQEBAQEBAQEBAQEBAQEBAQ":5.0},"extra":true}"#)
            .unwrap();
        assert_eq!((s.revision, s.generation, s.base, s.last_sync.as_str()), (0, 0, None, ""));
        assert_eq!(s.snapshot, vec![(Uuid::from_bytes([1; 16]), 5)]);
        assert_eq!(deserialize_sync_state("[]").unwrap_err().code, OvErrorCode::InvalidRequest);
        assert_eq!(deserialize_sync_state("{").unwrap_err().code, OvErrorCode::InvalidRequest);
        // Standard alphabet with padding is accepted for the base too.
        assert_eq!(deserialize_sync_state(r#"{"base":"+/8BAg=="}"#).unwrap().base, Some(vec![0xfb, 0xff, 1, 2]));
    }

    #[test]
    fn cached_form_keeps_the_base_apart() {
        let s = sample();
        let c = to_cached(&s);
        assert!(!String::from_utf8(c.state.clone()).unwrap().contains("base"));
        assert_eq!(c.base, s.base);
        assert_eq!(from_cached(&c).unwrap(), Some(s.clone()));
        // A TS-format state with the base inside the JSON.
        let ts = CachedVault { state: serialize_sync_state(&s).into_bytes(), base: None, pending: None, autofill: None };
        assert_eq!(from_cached(&ts).unwrap(), Some(s));
        let empty = CachedVault { state: vec![], base: None, pending: None, autofill: None };
        assert_eq!(from_cached(&empty).unwrap(), None);
    }

    #[test]
    fn iso_times() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(1_794_744_000_123), "2026-11-15T12:00:00.123Z");
        assert_eq!(iso_time(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
        assert_eq!(iso_time(-1), "1969-12-31T23:59:59.999Z");
    }
}
