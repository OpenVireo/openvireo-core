//! Password generation for `ov rotate --generate` and `ov item create|edit --generate`, ported from
//! `packages/cli/src/generate.ts`.

use ov_error::{OvError, OvErrorCode};
use zeroize::Zeroizing;

use crate::js;

/// The character sets, in the TS order. Symbols leave out quotes, backslash, backtick and space, so
/// generated values are safer to paste into shells and .env files.
pub const CHARSETS: [(&str, &str); 4] = [
    ("lower", "abcdefghijklmnopqrstuvwxyz"),
    ("upper", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("digits", "0123456789"),
    ("symbols", "!#$%&()*+,-./:;<=>?@[]^_{|}~"),
];

fn charset(name: &str) -> Option<&'static str> {
    CHARSETS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

/// `parseCharsets`: a comma-separated list of `letters`, `lower`, `upper`, `digits`, `symbols`.
pub fn parse_charsets(spec: &str) -> Result<Vec<String>, OvError> {
    let names: Vec<String> = spec.split(',').map(|s| js::trim(s).to_lowercase()).filter(|s| !s.is_empty()).collect();
    for n in &names {
        if n != "letters" && charset(n).is_none() {
            return Err(OvError::new(
                OvErrorCode::InvalidRequest,
                format!("unknown charset \"{n}\" (use letters, lower, upper, digits, symbols)"),
            ));
        }
    }
    if names.is_empty() {
        return Err(OvError::new(OvErrorCode::InvalidRequest, "empty charset"));
    }
    Ok(names)
}

fn random_u32() -> Result<u32, OvError> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| OvError::internal(format!("no randomness: {e}")))?;
    Ok(u32::from_be_bytes(b))
}

/// A uniformly random index below `n` (rejection sampling, no modulo bias).
fn random_below(n: u32) -> Result<u32, OvError> {
    let limit = (0x1_0000_0000u64 / u64::from(n)) * u64::from(n);
    loop {
        let v = random_u32()?;
        if u64::from(v) < limit {
            return Ok(v % n);
        }
    }
}

/// `generatePassword`: a random password with at least one character from every chosen set.
/// `length` defaults to 32 and `charsets` to letters, digits, symbols.
pub fn generate_password(length: Option<f64>, charsets: Option<&[String]>) -> Result<Zeroizing<String>, OvError> {
    let length = length.unwrap_or(32.0);
    let default = ["letters".to_string(), "digits".to_string(), "symbols".to_string()];
    let names = charsets.unwrap_or(&default);
    let mut sets: Vec<&str> = Vec::new();
    for n in names {
        let one = [n.as_str()];
        let expanded: &[&str] = if n == "letters" { &["lower", "upper"] } else { &one };
        for e in expanded {
            if let Some(s) = charset(e) {
                if !sets.contains(&s) {
                    sets.push(s);
                }
            }
        }
    }
    let min = sets.len().max(4);
    if !js::is_integer(length) || length < min as f64 || length > 1024.0 {
        return Err(OvError::new(OvErrorCode::InvalidRequest, format!("length must be between {min} and 1024")));
    }
    let length = length as usize;
    let alphabet: Vec<char> = sets.concat().chars().collect();
    let n = u32::try_from(alphabet.len()).map_err(|_| OvError::internal("alphabet too large"))?;
    loop {
        let mut out = Zeroizing::new(String::with_capacity(length));
        for _ in 0..length {
            out.push(alphabet[random_below(n)? as usize]);
        }
        if sets.iter().all(|s| out.chars().any(|c| s.contains(c))) {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // units.test.ts: "uses the chosen sets, at least one of each"
    #[test]
    fn uses_the_chosen_sets_at_least_one_of_each() {
        for _ in 0..50 {
            let p = generate_password(Some(8.0), None).unwrap();
            assert_eq!(p.chars().count(), 8);
            for (_, set) in CHARSETS {
                assert!(p.chars().any(|c| set.contains(c)), "{} lacks {set}", p.as_str());
            }
        }
        let digits = generate_password(Some(40.0), Some(&parse_charsets("digits").unwrap())).unwrap();
        assert!(digits.len() == 40 && digits.chars().all(|c| c.is_ascii_digit()));
        let letters = generate_password(None, Some(&["lower".to_string(), "upper".to_string()])).unwrap();
        assert!(letters.len() == 32 && letters.chars().all(|c| c.is_ascii_alphabetic()));
        let many: std::collections::HashSet<String> =
            (0..20).map(|_| generate_password(None, None).unwrap().to_string()).collect();
        assert_eq!(many.len(), 20);
        assert!(parse_charsets("emoji").unwrap_err().message.contains("unknown charset"));
        assert!(generate_password(Some(3.0), None).unwrap_err().message.contains("length"));
    }

    #[test]
    fn bounds_and_spec_parsing() {
        assert_eq!(parse_charsets(" Digits , ,symbols").unwrap(), vec!["digits", "symbols"]);
        assert_eq!(parse_charsets(" , ").unwrap_err().message, "empty charset");
        assert_eq!(generate_password(Some(1025.0), None).unwrap_err().message, "length must be between 4 and 1024");
        assert_eq!(generate_password(Some(4.5), None).unwrap_err().message, "length must be between 4 and 1024");
        assert_eq!(generate_password(Some(1024.0), None).unwrap().len(), 1024);
    }
}
