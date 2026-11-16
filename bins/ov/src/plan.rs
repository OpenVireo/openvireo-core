//! `describePlan` from `packages/cli/src/session.ts`: one line for a plan and who bills it
//! (SPEC §19), for `ov whoami`.

use serde::Deserialize;

/// Where an App Store subscription is managed (`APPLE_SUBSCRIPTIONS_URL` in the SDK).
pub const APPLE_SUBSCRIPTIONS_URL: &str = "https://apps.apple.com/account/subscriptions";

/// The `plan` object of `GET /auth/me` (the fields `describePlan` reads).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Plan {
    /// `free`, `premium`, `org_free`, `families`, `teams`, `business`, another id, or null.
    pub id: Option<String>,
    /// Who bills a paid plan; null on a free plan or when billing is off.
    #[serde(default)]
    pub billing: Option<Billing>,
}

/// How a paid plan is billed.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Billing {
    /// `stripe` or `apple`.
    #[serde(default)]
    pub source: String,
    /// `month` or `year`.
    #[serde(default)]
    pub interval: String,
    /// `active`, `trialing` or `past_due`.
    #[serde(default)]
    pub status: String,
    /// When it renews, or null.
    #[serde(default)]
    pub renews_at: Option<String>,
    /// When it ends because it was set not to renew, or null.
    #[serde(default)]
    pub ends_at: Option<String>,
    /// `website` or `app_store`.
    #[serde(default)]
    pub manage: String,
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, usize, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, (m - 1) as usize, d)
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The UTC calendar day of an ISO 8601 timestamp, as `new Date(iso)` would read it:
/// `YYYY-MM-DD[THH:MM[:SS[.fff]][Z|±HH:MM]]` (a date alone is UTC; a time without a zone is
/// treated as UTC too, since the server always sends `Z`).
fn utc_day(iso: &str) -> Option<(i64, usize, i64)> {
    let (date, time) = match iso.split_once(['T', 't', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (iso, None),
    };
    let mut dp = date.split('-');
    let (y, m, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut minutes = 0i64;
    if let Some(t) = time {
        let (clock, offset) = if let Some(c) = t.strip_suffix(['Z', 'z']) {
            (c, 0)
        } else if let Some(i) = t.rfind(['+', '-']) {
            let (c, z) = t.split_at(i);
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let (oh, om) = z[1..].split_once(':').unwrap_or((&z[1..], "0"));
            (c, sign * (num(oh)? * 60 + num(om)?))
        } else {
            (t, 0)
        };
        let mut cp = clock.split(':');
        let h = num(cp.next()?)?;
        let mi = num(cp.next()?)?;
        minutes = h * 60 + mi - offset;
    }
    Some(civil_from_days(days_from_civil(y, m, d) + minutes.div_euclid(24 * 60)))
}

/// `longDay`: e.g. `22 November 2026`.
fn long_day(iso: &str) -> String {
    match utc_day(iso) {
        Some((y, m, d)) => format!("{d} {} {y}", MONTHS[m]),
        None => "Invalid Date".to_string(),
    }
}

/// `day`: e.g. `2026-11-22`.
pub fn short_day(iso: &str) -> String {
    match utc_day(iso) {
        Some((y, m, d)) => format!("{y:04}-{:02}-{d:02}", m + 1),
        None => "Invalid Date".to_string(),
    }
}

fn plan_name(id: &str) -> &str {
    match id {
        "free" | "org_free" => "Free",
        "premium" => "Premium",
        "families" => "Families",
        "teams" => "Teams",
        "business" => "Business",
        other => other,
    }
}

/// `describePlan`: e.g. "Premium, renews 8 November 2027, billed by Apple. Manage it on your
/// iPhone or in your Apple ID settings (…)". `None` when billing is off.
pub fn describe_plan(plan: Option<&Plan>, issuer: &str) -> Option<String> {
    let plan = plan?;
    let id = plan.id.as_deref().filter(|s| !s.is_empty())?;
    let name = plan_name(id);
    let Some(b) = &plan.billing else {
        return Some(name.to_string());
    };
    let trial = b.status == "trialing";
    let every = if b.interval == "year" { "yearly" } else { "monthly" };
    let ends = b.ends_at.as_deref().filter(|s| !s.is_empty());
    let renews = b.renews_at.as_deref().filter(|s| !s.is_empty());
    let when = match (ends, renews) {
        (Some(e), _) => format!(", {} {}", if trial { "free trial, ends" } else { "ends" }, long_day(e)),
        (None, Some(r)) if trial => format!(", free trial until {}, then billed {every}", long_day(r)),
        (None, Some(r)) => format!(", renews {}", long_day(r)),
        (None, None) if trial => ", free trial".to_string(),
        (None, None) => String::new(),
    };
    let late = if b.status == "past_due" { " (payment being retried)" } else { "" };
    if b.manage == "app_store" {
        let by = if trial && ends.is_none() && renews.is_some() { " by Apple" } else { ", billed by Apple" };
        return Some(format!(
            "{name}{when}{late}{by}. Manage it on your iPhone or in your Apple ID settings ({APPLE_SUBSCRIPTIONS_URL})."
        ));
    }
    let base = issuer.strip_suffix('/').unwrap_or(issuer);
    Some(format!("{name}{when}{late}. Manage it at {base}/subscription/pricing."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn billing(source: &str, interval: &str, renews: Option<&str>, ends: Option<&str>, manage: &str) -> Billing {
        Billing {
            source: source.into(),
            interval: interval.into(),
            status: "trialing".into(),
            renews_at: renews.map(Into::into),
            ends_at: ends.map(Into::into),
            manage: manage.into(),
        }
    }

    // units.test.ts: describe("describePlan") "shows a free trial and when it ends"
    #[test]
    fn shows_a_free_trial_and_when_it_ends() {
        let issuer = "https://accounts.example.com/";
        let apple = Plan {
            id: Some("premium".into()),
            billing: Some(billing("apple", "year", Some("2026-11-22T12:00:00Z"), None, "app_store")),
        };
        let got = describe_plan(Some(&apple), issuer).unwrap();
        assert!(got.starts_with("Premium, free trial until "), "{got}");
        assert!(got.contains("2026, then billed yearly by Apple. Manage it on your iPhone"), "{got}");
        assert_eq!(
            got,
            "Premium, free trial until 22 November 2026, then billed yearly by Apple. Manage it on your iPhone or in your Apple ID settings (https://apps.apple.com/account/subscriptions)."
        );

        let stripe = Plan {
            id: Some("premium".into()),
            billing: Some(billing("stripe", "month", None, Some("2026-11-22T12:00:00Z"), "website")),
        };
        let got = describe_plan(Some(&stripe), issuer).unwrap();
        assert!(got.starts_with("Premium, free trial, ends "), "{got}");
        assert!(got.ends_with("2026. Manage it at https://accounts.example.com/subscription/pricing."), "{got}");
    }

    #[test]
    fn other_plans_and_dates() {
        assert_eq!(describe_plan(None, "x"), None);
        assert_eq!(describe_plan(Some(&Plan { id: None, billing: None }), "x"), None);
        assert_eq!(describe_plan(Some(&Plan { id: Some("org_free".into()), billing: None }), "x").unwrap(), "Free");
        let mut b = billing("stripe", "year", Some("2027-11-08T00:00:00Z"), None, "website");
        b.status = "past_due".into();
        let p = Plan { id: Some("families".into()), billing: Some(b) };
        assert_eq!(
            describe_plan(Some(&p), "https://a.example").unwrap(),
            "Families, renews 8 November 2027 (payment being retried). Manage it at https://a.example/subscription/pricing."
        );
        assert_eq!(long_day("2026-12-31T23:30:00-01:00"), "1 January 2027");
        assert_eq!(short_day("2024-02-29T00:00:00.000Z"), "2024-02-29");
        assert_eq!(short_day("2026-03-01T00:30:00+01:00"), "2026-02-28");
    }
}
