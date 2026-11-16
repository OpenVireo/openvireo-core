//! The "last modified" time of database custom data (§5): the `_LAST_MODIFIED` item, which KeePassXC
//! writes as Qt's `QDateTime::toString()` of a UTC time (`"Tue Mar 3 10:00:00 2026 GMT"`) and other
//! apps as ISO 8601; otherwise the latest `LastModificationTime` of the items.

use ov_kdbx::model::{CustomDataItem, Timestamp};

/// Unix seconds, or `None` when there is no usable time.
pub(crate) fn custom_data_time(items: &[CustomDataItem]) -> Option<Timestamp> {
    if let Some(stamp) = items.iter().find(|i| i.key == "_LAST_MODIFIED").and_then(|i| parse(&i.value)) {
        return Some(stamp);
    }
    items.iter().filter_map(|i| i.last_modification).max()
}

/// ISO 8601 (`2026-03-03T10:00:00Z`, optional fraction and offset) or Qt text date
/// (`Tue Mar 3 10:00:00 2026`, optional `GMT`/`UTC`), read as UTC.
pub(crate) fn parse(s: &str) -> Option<Timestamp> {
    let s = s.trim();
    parse_iso(s).or_else(|| parse_qt(s))
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn hms(s: &str) -> Option<i64> {
    let s = s.split('.').next()?;
    let mut it = s.split(':');
    let (h, m, sec) = (num(it.next()?)?, num(it.next()?)?, num(it.next().unwrap_or("0"))?);
    if it.next().is_some() || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    Some(h * 3600 + m * 60 + sec)
}

fn parse_iso(s: &str) -> Option<Timestamp> {
    let (date, rest) = s.split_once(['T', ' '])?;
    let mut d = date.split('-');
    let (y, m, day) = (num(d.next()?)?, num(d.next()?)?, num(d.next()?)?);
    if d.next().is_some() {
        return None;
    }
    let (clock, offset) = if let Some(c) = rest.strip_suffix('Z') {
        (c, 0)
    } else if let Some(i) = rest.rfind(['+', '-']) {
        let (c, o) = rest.split_at(i);
        let sign = if o.starts_with('-') { -1 } else { 1 };
        let o = &o[1..];
        let (oh, om) = o.split_once(':').unwrap_or((o.get(..2)?, o.get(2..).unwrap_or("0")));
        (c, sign * (num(oh)? * 3600 + num(if om.is_empty() { "0" } else { om })? * 60))
    } else {
        (rest, 0)
    };
    Some(days(y, m, day)? * 86400 + hms(clock)? - offset)
}

fn parse_qt(s: &str) -> Option<Timestamp> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    // [weekday] month day time year [zone]
    let parts = match parts.first() {
        Some(p) if month(p).is_none() => &parts[1..],
        _ => &parts[..],
    };
    let [mon, day, clock, year, zone @ ..] = parts else { return None };
    if !matches!(zone, [] | ["GMT"] | ["UTC"] | ["Z"]) {
        return None;
    }
    Some(days(num(year)?, month(mon)?, num(day)?)? * 86400 + hms(clock)?)
}

fn month(s: &str) -> Option<i64> {
    const NAMES: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    NAMES.iter().position(|n| s.eq_ignore_ascii_case(n)).map(|i| i as i64 + 1)
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_qt_and_iso() {
        let t = 1_772_532_000; // 2026-03-03T10:00:00Z
        assert_eq!(parse("Tue Mar 3 10:00:00 2026 GMT"), Some(t));
        assert_eq!(parse("Tue Mar 3 10:00:00 2026"), Some(t));
        assert_eq!(parse("2026-03-03T10:00:00Z"), Some(t));
        assert_eq!(parse("2026-03-03T10:00:00.250Z"), Some(t));
        assert_eq!(parse("2026-03-03T12:00:00+02:00"), Some(t));
        assert_eq!(parse("not a date"), None);
        assert_eq!(parse(""), None);
    }
}
