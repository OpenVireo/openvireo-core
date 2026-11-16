//! Plans (SPEC §19): where to send the user after a `plan_limit` error.

/// `(scheme, host, port, path)` of an absolute URL; the port is explicit or the scheme's default.
fn parts(url: &str) -> Option<(String, String, Option<u16>, String)> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest[..end].rsplit_once('@').map_or(&rest[..end], |(_, a)| a).to_ascii_lowercase();
    let path_end = rest[end..].find(['?', '#']).map_or(rest.len(), |i| end + i);
    let path = if end < rest.len() { rest[end..path_end].to_owned() } else { "/".to_owned() };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.contains(']') => (h.to_owned(), Some(p.parse().ok()?)),
        _ => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    let default = match scheme.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    Some((scheme, host, port.or(default), if path.is_empty() { "/".into() } else { path }))
}

/// The error's `upgradeUrl` when it is a `/subscription/` page of the auth site (https or the site's
/// scheme, same host and port), else `<issuer>/subscription/pricing`; `None` when the issuer has no
/// host (Swift `Account.upgradeURL`).
pub(crate) fn upgrade_url(details: Option<&str>, issuer: &str) -> Option<String> {
    let (site_scheme, site_host, site_port, _) = parts(issuer)?;
    let candidate = details
        .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
        .and_then(|v| v.get("upgradeUrl").or_else(|| v.get("upgrade_url")).and_then(|u| u.as_str()).map(str::to_owned));
    if let Some(u) = candidate {
        if let Some((scheme, host, port, path)) = parts(&u) {
            if (scheme == "https" || scheme == site_scheme)
                && host == site_host
                && port == site_port
                && path.starts_with("/subscription/")
            {
                return Some(u);
            }
        }
    }
    Some(format!("{}/subscription/pricing", issuer.trim().trim_end_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_urls() {
        let issuer = "https://accounts.example";
        let d = r#"{"upgradeUrl":"https://accounts.example/subscription/upgrade?plan=premium"}"#;
        assert_eq!(upgrade_url(Some(d), issuer).unwrap(), "https://accounts.example/subscription/upgrade?plan=premium");
        let evil = r#"{"upgradeUrl":"https://evil.example/subscription/x"}"#;
        assert_eq!(upgrade_url(Some(evil), issuer).unwrap(), "https://accounts.example/subscription/pricing");
        let other = r#"{"upgradeUrl":"https://accounts.example/settings"}"#;
        assert_eq!(upgrade_url(Some(other), issuer).unwrap(), "https://accounts.example/subscription/pricing");
        assert_eq!(upgrade_url(None, "not a url"), None);
    }
}
