//! Small helpers: secret text, RFC 3339 times, UUIDs, randomness, errors.

use ov_error::{OvError, OvErrorCode};
use zeroize::{Zeroize, Zeroizing};

use crate::api::SecretBytes;

/// Secret bytes as UTF-8 text, wiping the input; `invalid_request` when it isn't UTF-8.
pub(crate) fn secret_text(mut bytes: SecretBytes, what: &str) -> Result<Zeroizing<String>, OvError> {
    let out = match std::str::from_utf8(&bytes) {
        Ok(s) => Ok(Zeroizing::new(s.to_owned())),
        Err(_) => Err(OvError::new(OvErrorCode::InvalidRequest, format!("the {what} is not UTF-8"))),
    };
    bytes.zeroize();
    out
}

/// The CSPRNG for OPAQUE (the platform's, through `getrandom`).
pub(crate) fn rng() -> rand_core::OsRng {
    rand_core::OsRng
}

/// A random v4 UUID, lowercase and hyphenated (server ids).
pub(crate) fn random_uuid() -> Result<String, OvError> {
    Ok(ov_kdbx::vault::new_uuid()?.hyphenated().to_string())
}

/// `signed_out`.
pub(crate) fn signed_out(msg: &str) -> OvError {
    OvError::new(OvErrorCode::SignedOut, msg)
}

/// `Internal` with a message.
pub(crate) fn internal(msg: impl Into<String>) -> OvError {
    OvError::internal(msg)
}

/// Locks a std mutex, ignoring poisoning (a panic elsewhere leaves plain data behind).
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// JSON to bytes (our own records can't fail to serialise).
pub(crate) fn to_json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

// ------------------------------------------------------------------------------------- time

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unix milliseconds as RFC 3339 UTC with milliseconds (`2026-11-15T10:00:00.000Z`, like JS
/// `toISOString`).
pub(crate) fn rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", s / 3600, (s / 60) % 60, s % 60)
}

/// Parses an RFC 3339 / ISO 8601 date-time (`Z` or `±hh:mm`, optional fraction, or a bare date) to
/// Unix milliseconds, like JS `Date.parse` for the forms servers send.
pub(crate) fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let num = |t: &str| -> Option<i64> {
        if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    let (date, rest) = match s.find(['T', 't', ' ']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut dp = date.split('-');
    let (y, m, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    let Some(rest) = rest else { return Some(days * 86_400_000) };
    let (time, offset_ms) = if let Some(t) = rest.strip_suffix(['Z', 'z']) {
        (t, 0)
    } else if let Some(i) = rest.rfind(['+', '-']) {
        let (t, off) = rest.split_at(i);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let mut op = off[1..].split(':');
        let oh = num(op.next()?)?;
        let om = op.next().map(num).unwrap_or(Some(0))?;
        (t, sign * (oh * 3600 + om * 60) * 1000)
    } else {
        (rest, 0)
    };
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (time, None),
    };
    let mut tp = hms.split(':');
    let (h, mi) = (num(tp.next()?)?, num(tp.next()?)?);
    let sec = tp.next().map(num).unwrap_or(Some(0))?;
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let ms = match frac {
        Some(f) => {
            let digits: String = f.chars().take(3).collect();
            num(&format!("{digits:0<3}"))?
        }
        None => 0,
    };
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000 + ms) - offset_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trips() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        let t = parse_rfc3339("2026-11-15T10:00:00Z").unwrap();
        assert_eq!(rfc3339(t), "2026-11-15T10:00:00.000Z");
        assert_eq!(parse_rfc3339("2026-11-15T12:00:00.5+02:00"), Some(t + 500));
        assert_eq!(parse_rfc3339("2026-11-15"), Some(t - 10 * 3_600_000));
        assert_eq!(parse_rfc3339("1960-02-29T00:00:00Z"), Some(-310_521_600_000));
        assert_eq!(parse_rfc3339("nope"), None);
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
    }
}
