//! The few JavaScript semantics the TS CLI relies on, so the Rust port behaves the same on the same
//! input: `\s`, `String.prototype.trim`, `Number(text)`, and URI component coding.

/// Whether `c` matches the JS regex class `\s` (WhiteSpace + LineTerminator). Unlike
/// [`char::is_whitespace`] it includes U+FEFF and excludes U+0085.
pub fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// `s.trim()`.
pub fn trim(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `s.length` (UTF-16 code units).
pub fn len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `Number(text)`: `None` for `NaN`. Accepts what JS accepts (surrounding whitespace, the empty
/// string as 0, `0x`/`0o`/`0b` integers, `Infinity`, decimal and exponent forms).
pub fn number(text: &str) -> Option<f64> {
    let t = trim(text);
    if t.is_empty() {
        return Some(0.0);
    }
    let radix = |s: &str, r: u32| -> Option<f64> {
        if s.is_empty() || !s.chars().all(|c| c.is_digit(r)) {
            return None;
        }
        Some(s.chars().fold(0.0, |acc, c| acc * f64::from(r) + f64::from(c.to_digit(r).unwrap_or(0))))
    };
    for (prefix, r) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return radix(rest, r);
        }
    }
    let (sign, body) = match t.as_bytes()[0] {
        b'+' => (1.0, &t[1..]),
        b'-' => (-1.0, &t[1..]),
        _ => (1.0, t),
    };
    if body == "Infinity" {
        return Some(sign * f64::INFINITY);
    }
    // Rust also accepts "inf", "nan" and "infinity" in any case; JS doesn't.
    if !body.starts_with(|c: char| c.is_ascii_digit() || c == '.')
        || !body.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        return None;
    }
    body.parse::<f64>().ok().map(|v| sign * v)
}

/// `Number.isInteger(n)`.
pub fn is_integer(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0
}

/// `decodeURIComponent(s)`, `None` where JS throws `URIError`.
pub fn decode_uri_component(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `encodeURIComponent(s)`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A file error with Node's wording, e.g. `ENOENT: no such file or directory, open 'x.env'`.
pub fn io_error(e: &std::io::Error, syscall: &str, path: &str) -> ov_error::OvError {
    use std::io::ErrorKind::*;
    let text = match e.kind() {
        NotFound => "ENOENT: no such file or directory".to_string(),
        PermissionDenied => "EACCES: permission denied".to_string(),
        IsADirectory => "EISDIR: illegal operation on a directory".to_string(),
        _ => e.to_string(),
    };
    let syscall = if e.kind() == IsADirectory { "read" } else { syscall };
    let msg =
        if e.kind() == IsADirectory { format!("{text}, {syscall}") } else { format!("{text}, {syscall} '{path}'") };
    ov_error::OvError::new(ov_error::OvErrorCode::InvalidRequest, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_matches_js() {
        assert_eq!(number("12"), Some(12.0));
        assert_eq!(number(" 1e2 "), Some(100.0));
        assert_eq!(number("0x10"), Some(16.0));
        assert_eq!(number(""), Some(0.0));
        assert_eq!(number("1.5"), Some(1.5));
        assert_eq!(number("abc"), None);
        assert_eq!(number("inf"), None);
        assert_eq!(number("nan"), None);
        assert_eq!(number("-Infinity"), Some(f64::NEG_INFINITY));
        assert!(!is_integer(number("1.5").unwrap()));
        assert!(is_integer(number("40").unwrap()));
    }

    #[test]
    fn uri_component_round_trips() {
        assert_eq!(decode_uri_component("Team%20Infra").as_deref(), Some("Team Infra"));
        assert_eq!(decode_uri_component("%E0%A4%A"), None);
        assert_eq!(decode_uri_component("%FF"), None);
        assert_eq!(encode_uri_component("a b/ü!"), "a%20b%2F%C3%BC!");
    }
}
