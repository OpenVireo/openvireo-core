//! Secret references in templates (`ov inject`) and env files (`ov run`), ported from
//! `packages/cli/src/template.ts`. The two TS regexes are hand-written scanners here:
//!
//! - braced: `\{\{\s*(ov:\/\/[^\s}]+)\s*\}\}` (any spacing; needed when text follows the reference)
//! - bare (`REFERENCE_PATTERN`): `ov:\/\/[^\s"'`}]+`

use std::collections::HashMap;

use ov_error::{OvError, OvErrorCode};

use crate::js;
use crate::reference::parse_reference;
use crate::source::VaultSource;

const SCHEME: &str = "ov://";

/// A braced match at byte `start..end`, with the reference inside.
struct Braced<'a> {
    start: usize,
    end: usize,
    reference: &'a str,
}

fn skip_space(text: &str, mut i: usize) -> usize {
    while let Some(c) = text[i..].chars().next().filter(|c| js::is_space(*c)) {
        i += c.len_utf8();
    }
    i
}

/// The braced reference starting exactly at byte `i`, if there is one.
fn braced_at(text: &str, i: usize) -> Option<Braced<'_>> {
    if !text[i..].starts_with("{{") {
        return None;
    }
    let ref_start = skip_space(text, i + 2);
    if !text[ref_start..].starts_with(SCHEME) {
        return None;
    }
    let body = ref_start + SCHEME.len();
    let run = text[body..].find(|c: char| js::is_space(c) || c == '}').unwrap_or(text.len() - body);
    if run == 0 {
        return None;
    }
    let ref_end = body + run;
    let close = skip_space(text, ref_end);
    if !text[close..].starts_with("}}") {
        return None;
    }
    Some(Braced { start: i, end: close + 2, reference: &text[ref_start..ref_end] })
}

/// Every non-overlapping braced match, left to right (like `matchAll` with the `g` flag).
fn braced_matches(text: &str) -> Vec<Braced<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if let Some(m) = braced_at(text, i) {
            i = m.end;
            out.push(m);
        } else {
            i += text[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    out
}

fn is_bare_char(c: char) -> bool {
    !(js::is_space(c) || matches!(c, '"' | '\'' | '`' | '}'))
}

/// Every non-overlapping bare match as a byte range.
fn bare_matches(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = text[from..].find(SCHEME) {
        let start = from + pos;
        let body = start + SCHEME.len();
        let run = text[body..].find(|c: char| !is_bare_char(c)).unwrap_or(text.len() - body);
        if run == 0 {
            from = start + 1;
        } else {
            out.push((start, body + run));
            from = body + run;
        }
    }
    out
}

/// `text.replace(BRACED_REFERENCE, f)`.
fn replace_braced(text: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in braced_matches(text) {
        out.push_str(&text[last..m.start]);
        out.push_str(&f(m.reference));
        last = m.end;
    }
    out.push_str(&text[last..]);
    out
}

/// `text.replace(REFERENCE_PATTERN, f)`.
fn replace_bare(text: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (s, e) in bare_matches(text) {
        out.push_str(&text[last..s]);
        out.push_str(&f(&text[s..e]));
        last = e;
    }
    out.push_str(&text[last..]);
    out
}

/// `findReferences`: braced references first, then bare ones outside braces, without duplicates.
pub fn find_references(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        if !out.iter().any(|o| o == s) {
            out.push(s.to_string());
        }
    };
    for m in braced_matches(text) {
        push(m.reference);
    }
    let rest = replace_braced(text, |_| String::new());
    for (s, e) in bare_matches(&rest) {
        push(&rest[s..e]);
    }
    out
}

/// The second half of `resolveTemplate`: substitutes resolved `values` (reference → value) into
/// `text`, braced references first and then bare ones, exactly as the TS does.
pub fn substitute(text: &str, values: &HashMap<String, String>) -> String {
    let braced = replace_braced(text, |r| values.get(r).cloned().unwrap_or_default());
    replace_bare(&braced, |m| values.get(m).cloned().unwrap_or_else(|| m.to_string()))
}

/// `readReference`.
pub async fn read_reference(src: &dyn VaultSource, reference: &str) -> Result<String, OvError> {
    let r = parse_reference(reference)?;
    src.read(&r.vault, reference).await
}

/// `resolveTemplate`: replaces every reference; returns the text and the values (to mask).
pub async fn resolve_template(src: &dyn VaultSource, text: &str) -> Result<(String, Vec<String>), OvError> {
    let refs = find_references(text);
    let mut values = HashMap::new();
    let mut secrets = Vec::new();
    for r in refs {
        let v = read_reference(src, &r).await?;
        secrets.push(v.clone());
        values.insert(r, v);
    }
    Ok((substitute(text, &values), secrets))
}

fn env_error(file: &str, line: usize, what: &str) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, format!("{file}:{line}: {what}"))
}

/// `/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/` on an already trimmed line.
fn key_value(line: &str) -> Option<(&str, &str)> {
    let mut rest = line;
    if let Some(after) = rest.strip_prefix("export") {
        let spaced = skip_space(after, 0);
        // `export` is only a prefix when followed by space and a valid assignment; otherwise the
        // regex backtracks and tries `export…` as the key itself.
        if spaced > 0 {
            if let Some(kv) = key_value_plain(&after[spaced..]) {
                return Some(kv);
            }
        }
        rest = line;
    }
    key_value_plain(rest)
}

fn key_value_plain(s: &str) -> Option<(&str, &str)> {
    let first = s.chars().next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let key_len = s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(s.len());
    let after = skip_space(s, key_len);
    let value = s[after..].strip_prefix('=')?;
    let value = &value[skip_space(value, 0)..];
    // `.` doesn't match line terminators; the line has none but  /  could appear.
    if value.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        return None;
    }
    Some((&s[..key_len], value))
}

/// `closingQuote`: the index of the first unescaped `"`.
fn closing_quote(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 1;
        } else if b[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// `/\\(.)/g` → `\n`, `\t`, `\r`, else the character itself.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek().copied()) {
            ('\\', Some(n)) if !matches!(n, '\n' | '\r' | '\u{2028}' | '\u{2029}') => {
                chars.next();
                out.push(match n {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    other => other,
                });
            }
            _ => out.push(c),
        }
    }
    out
}

/// `/\s+#.*$/` removed from the end of an unquoted value.
fn strip_trailing_comment(v: &str) -> &str {
    for (i, c) in v.char_indices() {
        if c == '#' && i > 0 && v[..i].ends_with(js::is_space) {
            let start = v[..i].trim_end_matches(js::is_space).len();
            return &v[..start];
        }
    }
    v
}

/// `parseEnvFile`: `KEY=value`, optional `export `, `#` comments, "double quotes" (with \n, \t, \",
/// \\ escapes, may span lines) and 'single quotes' (literal).
pub fn parse_env_file(text: &str, file: &str) -> Result<Vec<(String, String)>, OvError> {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = js::trim(lines[i]);
        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }
        let Some((key, rest)) = key_value(line) else {
            return Err(env_error(file, i + 1, "expected KEY=value"));
        };
        let value;
        let rest_after: String;
        if let Some(body) = rest.strip_prefix('"') {
            let mut body = body.to_string();
            let mut end = closing_quote(&body);
            while end.is_none() && i + 1 < lines.len() {
                i += 1;
                body.push('\n');
                body.push_str(lines[i]);
                end = closing_quote(&body);
            }
            let Some(end) = end else {
                return Err(env_error(file, i + 1, "unterminated \""));
            };
            value = unescape(&body[..end]);
            rest_after = body[end + 1..].to_string();
        } else if let Some(body) = rest.strip_prefix('\'') {
            let Some(end) = body.find('\'') else {
                return Err(env_error(file, i + 1, "unterminated '"));
            };
            value = body[..end].to_string();
            rest_after = body[end + 1..].to_string();
        } else {
            value = js::trim(strip_trailing_comment(rest)).to_string();
            rest_after = String::new();
        }
        let tail = js::trim(&rest_after);
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(env_error(file, i + 1, "unexpected text after the closing quote"));
        }
        out.push((key.to_string(), value));
        i += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // units.test.ts: "finds bare and braced references"
    #[test]
    fn finds_bare_and_braced_references() {
        assert_eq!(
            find_references(
                "A=ov://v/e/f\nB=\"ov://v/e/g\"\nDSN=postgres://u:{{ ov://v/db/password }}@h/{{ov://v/db/name}}"
            ),
            vec!["ov://v/db/password", "ov://v/db/name", "ov://v/e/f", "ov://v/e/g"]
        );
    }

    #[test]
    fn substitutes_like_the_ts() {
        let values: HashMap<String, String> =
            [("ov://v/db/password".to_string(), "pw".to_string()), ("ov://v/e/f".to_string(), "F".to_string())]
                .into_iter()
                .collect();
        assert_eq!(
            substitute("a=ov://v/e/f u:{{ ov://v/db/password }}@h ov://v/unknown/x", &values),
            "a=F u:pw@h ov://v/unknown/x"
        );
        assert_eq!(find_references("{{{ ov://a/b/c }}}"), vec!["ov://a/b/c"]);
        assert!(find_references("ov:// {{ ov:// }}").is_empty());
    }

    // units.test.ts: "parses .env files"
    #[test]
    fn parses_env_files() {
        let text = [
            "# comment",
            "",
            "PLAIN=ov://v/e/f",
            "export SPACED = value with spaces # trailing comment",
            "DQ=\"line1\\nline2 \\\"q\\\" # not a comment\"",
            "SQ='$literal \\n'",
            "MULTI=\"a",
            "b\"",
            "EMPTY=",
        ]
        .join("\r\n");
        let env = parse_env_file(&text, ".env").unwrap();
        let want: Vec<(String, String)> = [
            ("PLAIN", "ov://v/e/f"),
            ("SPACED", "value with spaces"),
            ("DQ", "line1\nline2 \"q\" # not a comment"),
            ("SQ", "$literal \\n"),
            ("MULTI", "a\nb"),
            ("EMPTY", ""),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(env, want);
        assert_eq!(parse_env_file("NOPE", "x.env").unwrap_err().message, "x.env:1: expected KEY=value");
        assert!(parse_env_file("A=\"open", ".env").unwrap_err().message.contains("unterminated"));
        assert!(parse_env_file("A=\"x\" y", ".env").unwrap_err().message.contains("after the closing quote"));
    }

    #[test]
    fn env_file_edge_cases() {
        let env = parse_env_file("export=1\nexportX=2\nA=x#y\nB = 'q' # c", ".env").unwrap();
        assert_eq!(env[0], ("export".into(), "1".into()));
        assert_eq!(env[1], ("exportX".into(), "2".into()));
        assert_eq!(env[2], ("A".into(), "x#y".into()));
        assert_eq!(env[3], ("B".into(), "q".into()));
    }
}
