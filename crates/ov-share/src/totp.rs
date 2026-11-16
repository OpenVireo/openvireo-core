//! RFC 6238 codes for `otpauth://totp/` URIs, so a share page can show the current one-time code.
//! Ported from the TS SDK's `share/totp.ts`.

use hmac::{Hmac, Mac};
use ov_error::{OvError, OvErrorCode};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::payload::EntryField;

/// The TOTP hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (default).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// Parameters of an `otpauth://totp/…` URI. The secret is wiped on drop; `Debug` hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpParams {
    /// The decoded secret.
    pub secret: Vec<u8>,
    /// The hash.
    pub algorithm: TotpAlgorithm,
    /// Digits, 1 to 10 (5 for Steam).
    pub digits: u32,
    /// Period in seconds (default 30).
    pub period: u32,
    /// Steam Guard codes (`encoder=steam`) use their own 5-character alphabet.
    pub steam: bool,
}

impl Drop for TotpParams {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpParams")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("steam", &self.steam)
            .finish_non_exhaustive()
    }
}

/// A one-time code and the seconds it has left. `Debug` hides the code.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpCode {
    /// The code.
    pub code: Zeroizing<String>,
    /// Seconds until it changes.
    pub remaining: u32,
}

impl std::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpCode").field("remaining", &self.remaining).finish_non_exhaustive()
    }
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEAM: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

fn invalid(msg: impl Into<String>) -> OvError {
    OvError::new(OvErrorCode::InvalidTotp, msg)
}

/// JavaScript's `\s`: Unicode white space, line terminators and the byte order mark.
fn is_js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// RFC 4648 base32, case-insensitive, ignoring white space, `=` and `-`; `invalid_totp` otherwise.
pub(crate) fn base32_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, OvError> {
    let clean = Zeroizing::new(text.to_uppercase());
    let mut out = Zeroizing::new(Vec::with_capacity(clean.len() * 5 / 8));
    let (mut bits, mut value) = (0u32, 0u32);
    for c in clean.chars().filter(|&c| !is_js_space(c) && c != '=' && c != '-') {
        let i = u8::try_from(c)
            .ok()
            .and_then(|b| BASE32.iter().position(|&x| x == b))
            .ok_or_else(|| invalid("the TOTP secret isn't base32"))?;
        value = ((value << 5) | i as u32) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((value >> bits) as u8);
        }
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// `application/x-www-form-urlencoded` decoding, as `URLSearchParams` does it: `+` is a space, bad
/// `%` sequences stay as they are, invalid UTF-8 becomes U+FFFD.
fn form_decode(text: &str) -> Zeroizing<String> {
    let b = text.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

/// The first value of `name` in a query string.
fn query_get(query: &str, name: &str) -> Option<Zeroizing<String>> {
    query.split('&').filter(|s| !s.is_empty()).find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (form_decode(k).as_str() == name).then(|| form_decode(v))
    })
}

/// JavaScript's `Number(text)` for the values a URI holds, then an integer check. `None` for
/// anything that isn't a whole number.
fn js_integer(text: &str) -> Option<f64> {
    let t = text.trim_matches(is_js_space);
    let n = if t.is_empty() { 0.0 } else { t.parse::<f64>().ok()? };
    (n.is_finite() && n.fract() == 0.0).then_some(n)
}

/// Reads an `otpauth://totp/…?secret=…` URI (`algorithm`, `digits`, `period` and KeePassXC's
/// `encoder=steam` are optional); `invalid_totp` if it can't be used.
pub fn parse_totp_uri(uri: &str) -> Result<TotpParams, OvError> {
    let uri = uri.trim_matches(is_js_space);
    let (scheme, rest) = uri.split_once(':').ok_or_else(|| invalid("not an otpauth URI"))?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err(invalid("not an otpauth://totp URI"));
    }
    let rest = rest.strip_prefix("//").ok_or_else(|| invalid("not an otpauth://totp URI"))?;
    let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split_once(':').map_or(host, |(h, _)| h);
    if !host.eq_ignore_ascii_case("totp") {
        return Err(invalid("not an otpauth://totp URI"));
    }
    let query = rest.split_once('?').map_or("", |(_, q)| q);

    let secret = base32_decode(query_get(query, "secret").as_deref().map_or("", |s| s.as_str()))?;
    if secret.is_empty() {
        return Err(invalid("the TOTP secret is missing"));
    }
    let steam = query_get(query, "encoder").is_some_and(|e| e.to_lowercase() == "steam");
    let algorithm = match query_get(query, "algorithm").map(|a| a.to_uppercase()).as_deref() {
        None | Some("SHA1") => TotpAlgorithm::Sha1,
        Some("SHA256") => TotpAlgorithm::Sha256,
        Some("SHA512") => TotpAlgorithm::Sha512,
        Some(other) => return Err(invalid(format!("unsupported algorithm {other}"))),
    };
    let bad = || invalid("bad digits or period");
    let digits =
        if steam { 5.0 } else { query_get(query, "digits").map_or(Some(6.0), |d| js_integer(&d)).ok_or_else(bad)? };
    let period = query_get(query, "period").map_or(Some(30.0), |p| js_integer(&p)).ok_or_else(bad)?;
    if !(1.0..=10.0).contains(&digits) || !(1.0..=u32::MAX as f64).contains(&period) {
        return Err(bad());
    }
    Ok(TotpParams { secret: secret.to_vec(), algorithm, digits: digits as u32, period: period as u32, steam })
}

/// HMAC with the given digest over `key` and `msg`.
macro_rules! hmac_with {
    ($digest:ty, $key:expr, $msg:expr) => {{
        let mut m = <Hmac<$digest> as Mac>::new_from_slice($key).expect("HMAC takes any key length");
        m.update($msg);
        m.finalize().into_bytes().to_vec()
    }};
}

fn mac(params: &TotpParams, msg: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(match params.algorithm {
        TotpAlgorithm::Sha1 => hmac_with!(Sha1, &params.secret, msg),
        TotpAlgorithm::Sha256 => hmac_with!(Sha256, &params.secret, msg),
        TotpAlgorithm::Sha512 => hmac_with!(Sha512, &params.secret, msg),
    })
}

/// The code at `now_ms` (Unix milliseconds) and the seconds it has left.
pub fn totp_code(params: &TotpParams, now_ms: i64) -> TotpCode {
    let period = i64::from(params.period.max(1));
    let seconds = now_ms.div_euclid(1000);
    let counter = seconds.div_euclid(period);
    let mac = mac(params, &counter.to_be_bytes());
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let mut bin = u32::from_be_bytes([mac[offset] & 0x7f, mac[offset + 1], mac[offset + 2], mac[offset + 3]]);
    let mut code = Zeroizing::new(String::with_capacity(params.digits as usize));
    if params.steam {
        for _ in 0..params.digits {
            code.push(STEAM[(bin % STEAM.len() as u32) as usize] as char);
            bin /= STEAM.len() as u32;
        }
    } else {
        let digits = params.digits.min(10);
        let n = u64::from(bin) % 10u64.pow(digits);
        code.push_str(&format!("{n:0width$}", width = digits as usize));
    }
    TotpCode { code, remaining: (period - seconds.rem_euclid(period)) as u32 }
}

/// JavaScript's `encodeURIComponent`.
fn encode_uri_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `URLSearchParams` serialisation of one value (`application/x-www-form-urlencoded`).
fn form_encode(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"*-._".contains(&b) {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// An `otpauth://` URI for a KeePass entry's TOTP: its `otp` field when that is a URI (KeePassXC), or
/// the older `TOTP Seed` and `TOTP Settings` (`30;6`, `30;S` for Steam) fields. `None` without either.
/// `label` names the account in a built URI.
pub fn entry_totp_uri(fields: &[EntryField], label: &str) -> Option<Zeroizing<String>> {
    let get = |name: &str| fields.iter().find(|f| f.name == name).map(|f| f.value.as_str());
    let otp = get("otp").map(|o| o.trim_matches(is_js_space));
    if let Some(o) = otp {
        if o.len() >= 10 && o.is_char_boundary(10) && o[..10].eq_ignore_ascii_case("otpauth://") {
            return Some(Zeroizing::new(o.to_string()));
        }
    }
    let seed_source = match get("TOTP Seed") {
        Some(s) => s,
        None => otp.filter(|o| !o.contains("://")).unwrap_or(""),
    };
    let seed: Zeroizing<String> = Zeroizing::new(seed_source.chars().filter(|&c| !is_js_space(c)).collect());
    if seed.is_empty() {
        return None;
    }
    // Missing or empty settings mean 30 seconds and 6 digits, as on iOS. (The TS SDK writes an empty
    // `period=` when `TOTP Settings` is absent, which its own parser then refuses.)
    let settings = get("TOTP Settings").unwrap_or("");
    let mut parts = settings.split(';');
    let period = parts.next().filter(|p| !p.is_empty()).unwrap_or("30");
    let digits = parts.next().filter(|d| !d.is_empty()).unwrap_or("6");
    let mut uri = Zeroizing::new(format!(
        "otpauth://totp/{}?secret={}&period={}",
        encode_uri_component(label),
        form_encode(&seed).as_str(),
        form_encode(period).as_str()
    ));
    if digits.eq_ignore_ascii_case("S") {
        uri.push_str("&encoder=steam");
    } else {
        uri.push_str("&digits=");
        uri.push_str(&form_encode(digits));
    }
    Some(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32() {
        assert_eq!(base32_decode("JBSW Y3DP-EHPK3PXP==").unwrap().as_slice(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(base32_decode("jbswy3dp").unwrap().as_slice(), b"Hello");
        assert_eq!(base32_decode("JBSW1").unwrap_err().code, OvErrorCode::InvalidTotp);
        assert_eq!(base32_decode("JBSWé").unwrap_err().code, OvErrorCode::InvalidTotp);
        assert!(base32_decode("").unwrap().is_empty());
    }

    #[test]
    fn parses_uris() {
        let p = parse_totp_uri(" otpauth://TOTP/Bank:me%40x?secret=JBSWY3DP&digits=8&period=60&algorithm=sha256#x ")
            .unwrap();
        assert_eq!((p.algorithm, p.digits, p.period, p.steam), (TotpAlgorithm::Sha256, 8, 60, false));
        let s = parse_totp_uri("otpauth://totp/a?secret=JBSWY3DP&encoder=Steam&digits=8").unwrap();
        assert_eq!((s.digits, s.steam), (5, true));
        let d = parse_totp_uri("otpauth://totp?secret=JBSW%20Y3DP").unwrap();
        assert_eq!((d.secret.as_slice(), d.digits, d.period), (&b"Hello"[..], 6, 30));
        for bad in [
            "https://example.com",
            "otpauth://hotp/a?secret=JBSWY3DP",
            "otpauth:totp/a?secret=JBSWY3DP",
            "otpauth://totp/a",
            "otpauth://totp/a?secret=JBSWY3DP&algorithm=MD5",
            "otpauth://totp/a?secret=JBSWY3DP&digits=11",
            "otpauth://totp/a?secret=JBSWY3DP&digits=6.5",
            "otpauth://totp/a?secret=JBSWY3DP&period=0",
            "otpauth://totp/a?secret=JBSWY3DP&period=",
            "otpauth://totp/a?secret=!!",
            "not a uri",
            "",
        ] {
            assert_eq!(parse_totp_uri(bad).unwrap_err().code, OvErrorCode::InvalidTotp, "{bad}");
        }
    }

    #[test]
    fn form_decoding() {
        assert_eq!(form_decode("a+b%20c%zz%4").as_str(), "a b c%zz%4");
        assert_eq!(form_decode("%").as_str(), "%");
        assert_eq!(form_decode("%C3%A9").as_str(), "é");
    }

    /// RFC 6238 Appendix B, all 18 rows (8 digits, 30 s).
    #[test]
    fn rfc_6238_appendix_b() {
        let seed = |s: &str, n: usize| s.bytes().cycle().take(n).collect::<Vec<u8>>();
        let rows: [(i64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in rows {
            for (algorithm, secret, want) in [
                (TotpAlgorithm::Sha1, seed("12345678901234567890", 20), sha1),
                (TotpAlgorithm::Sha256, seed("12345678901234567890", 32), sha256),
                (TotpAlgorithm::Sha512, seed("1234567890", 64), sha512),
            ] {
                let params = TotpParams { secret, algorithm, digits: 8, period: 30, steam: false };
                let code = totp_code(&params, t * 1000);
                assert_eq!(code.code.as_str(), want, "{algorithm:?} at {t}");
                assert_eq!(code.remaining as i64, 30 - t % 30);
            }
        }
    }

    #[test]
    fn rfc_6238_through_a_uri() {
        // the TS test: the RFC seed as base32 in a URI
        let uri = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8";
        let p = parse_totp_uri(uri).unwrap();
        assert_eq!(totp_code(&p, 59_000).code.as_str(), "94287082");
        assert_eq!(totp_code(&p, 59_999).remaining, 1);
    }

    #[test]
    fn steam_codes() {
        let p = parse_totp_uri("otpauth://totp/s?secret=JBSWY3DPEHPK3PXP&encoder=steam").unwrap();
        let code = totp_code(&p, 1_700_000_000_000);
        assert_eq!(code.code.len(), 5);
        assert!(code.code.bytes().all(|b| STEAM.contains(&b)));
        assert!(!format!("{code:?}{p:?}").contains(code.code.as_str()));
    }

    #[test]
    fn reads_keepass_totp_fields() {
        let f = |pairs: &[(&str, &str)]| pairs.iter().map(|(n, v)| EntryField::new(*n, *v, false)).collect::<Vec<_>>();
        let uri = entry_totp_uri(&f(&[("otp", "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP")]), "x").unwrap();
        assert_eq!(uri.as_str(), "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP");

        let legacy = entry_totp_uri(&f(&[("TOTP Seed", "JBSW Y3DP"), ("TOTP Settings", "60;8")]), "Bank & Co").unwrap();
        assert_eq!(legacy.as_str(), "otpauth://totp/Bank%20%26%20Co?secret=JBSWY3DP&period=60&digits=8");
        let p = parse_totp_uri(&legacy).unwrap();
        assert_eq!((p.period, p.digits), (60, 8));

        let steam = entry_totp_uri(&f(&[("TOTP Seed", "JBSWY3DP"), ("TOTP Settings", "30;S")]), "OpenVireo").unwrap();
        let p = parse_totp_uri(&steam).unwrap();
        assert_eq!((p.steam, p.digits), (true, 5));

        // no settings: 30 s, 6 digits (deviation from TS, matches iOS)
        let bare = entry_totp_uri(&f(&[("TOTP Seed", "JBSWY3DP")]), "OpenVireo").unwrap();
        let p = parse_totp_uri(&bare).unwrap();
        assert_eq!((p.period, p.digits), (30, 6));

        // a bare seed in `otp`
        assert!(entry_totp_uri(&f(&[("otp", "JBSWY3DP")]), "x").is_some());
        assert!(entry_totp_uri(&f(&[("otp", "https://x")]), "x").is_none());
        assert!(entry_totp_uri(&f(&[("Title", "x")]), "x").is_none());
        // an empty TOTP Seed wins over `otp`, as `??` does in TS
        assert!(entry_totp_uri(&f(&[("TOTP Seed", ""), ("otp", "JBSWY3DP")]), "x").is_none());
    }
}
