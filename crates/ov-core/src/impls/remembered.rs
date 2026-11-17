//! The accounts this device remembers for switching (SPEC §21), kept in the SecureStore under
//! `remembered_accounts` as a JSON list, like the iOS `RememberedAccounts`. Dates are RFC 3339; the
//! iOS app's older encoding (seconds since 2001-01-01, `userID`) is read too.

use ov_error::OvError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::util::{parse_rfc3339, rfc3339, to_json};
use crate::api::RememberedAccount;
use crate::host::Host;

pub(crate) const KEY: &str = "remembered_accounts";

/// Seconds between 1970-01-01 and 2001-01-01 (Foundation's reference date).
const APPLE_EPOCH_S: f64 = 978_307_200.0;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    email: String,
    issuer: String,
    #[serde(alias = "userID")]
    user_id: String,
    last_used_at: Value,
    #[serde(default)]
    checked_at: Option<Value>,
    #[serde(default)]
    deletion_scheduled_for: Option<Value>,
}

fn date(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => n.as_f64().map(|s| rfc3339(((s + APPLE_EPOCH_S) * 1000.0) as i64)),
        _ => None,
    }
}

fn from_stored(s: Stored) -> RememberedAccount {
    RememberedAccount {
        email: s.email,
        issuer: s.issuer,
        user_id: s.user_id,
        last_used_at: date(&s.last_used_at).unwrap_or_default(),
        checked_at: s.checked_at.as_ref().and_then(date),
        deletion_scheduled_for: s.deletion_scheduled_for.as_ref().and_then(date),
    }
}

fn to_stored(a: &RememberedAccount) -> Stored {
    Stored {
        email: a.email.clone(),
        issuer: a.issuer.clone(),
        user_id: a.user_id.clone(),
        last_used_at: Value::String(a.last_used_at.clone()),
        checked_at: a.checked_at.clone().map(Value::String),
        deletion_scheduled_for: a.deletion_scheduled_for.clone().map(Value::String),
    }
}

/// Every remembered account, most recently used first. An unreadable list is empty.
pub(crate) async fn all(host: &Host) -> Result<Vec<RememberedAccount>, OvError> {
    let raw = host.store.get(KEY).await?;
    let mut list: Vec<RememberedAccount> = raw
        .and_then(|r| serde_json::from_slice::<Vec<Stored>>(&r).ok())
        .unwrap_or_default()
        .into_iter()
        .map(from_stored)
        .collect();
    list.sort_by_key(|a| std::cmp::Reverse(parse_rfc3339(&a.last_used_at).unwrap_or(i64::MIN)));
    Ok(list)
}

pub(crate) async fn save(host: &Host, list: &[RememberedAccount]) -> Result<(), OvError> {
    let stored: Vec<Stored> = list.iter().map(to_stored).collect();
    host.store.set(KEY, &to_json(&stored)).await
}

/// Changes the entry for (`issuer`, `user_id`), if any.
pub(crate) async fn update(
    host: &Host,
    issuer: &str,
    user_id: &str,
    f: impl FnOnce(&mut RememberedAccount),
) -> Result<(), OvError> {
    let mut list = all(host).await?;
    if let Some(a) = list.iter_mut().find(|a| a.issuer == issuer && a.user_id == user_id) {
        f(a);
        save(host, &list).await?;
    }
    Ok(())
}
