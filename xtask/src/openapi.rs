//! `cargo xtask openapi [--check]` (owned by W1-P).
//!
//! Reads `vectors/openapi/{openapi,sync-openapi}.yaml`, resolves every `$ref` (including the cross-file
//! `./openapi.yaml#/...` ones), and builds JSON samples for:
//!
//! - every operation (`op`), whether or not it has a JSON body,
//! - every JSON request body and JSON response of each operation,
//! - every `components/schemas` entry and the shared `Error` response.
//!
//! Samples use each `example` the files give and otherwise a value of the declared type. Several
//! variants are made per sample so every `enum` value and every `oneOf` branch appears once, plus a
//! `nulls` variant where every nullable field is `null`. The samples go to
//! `crates/ov-protocol/tests/openapi/samples.json`, and `cargo test -p ov-protocol --test openapi`
//! round-trips each one through the serde type registered for it. A key with no registered type
//! fails that test, so a new endpoint fails CI until it is typed (or excluded with a reason).
//!
//! `--check` fails if samples.json is stale instead of rewriting it. Both forms then run the
//! round-trip test.
//!
//! YAML is read by a small reader for the subset OpenAPI files use (block and flow collections,
//! plain/quoted scalars, `|` blocks, comments); no YAML crate is on the allow-list.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::{cargo, root, run as run_step, Result};

const FILES: [(&str, &str); 2] = [("auth", "openapi.yaml"), ("sync", "sync-openapi.yaml")];
const METHODS: [&str; 6] = ["get", "head", "post", "put", "patch", "delete"];
/// Enough variants to show every value of the longest enum (7) once.
const VARIANTS: usize = 8;

pub fn run(args: &[String]) -> Result {
    let check = match args {
        [] => false,
        [a] if a == "--check" => true,
        _ => return Err("usage: cargo xtask openapi [--check]".into()),
    };
    println!("\n==> openapi samples");
    let dir = spec_dir();
    let mut docs = BTreeMap::new();
    for (tag, name) in FILES {
        let path = dir.join(name);
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let doc = parse_yaml(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        docs.insert(name.to_string(), (tag, doc));
    }
    let samples = build_samples(&docs)?;
    let mut text = serde_json::to_string_pretty(&samples).map_err(|e| e.to_string())?;
    text.push('\n');

    let out = root().join("crates/ov-protocol/tests/openapi/samples.json");
    let current = fs::read_to_string(&out).unwrap_or_default();
    let keys = samples.as_object().map_or(0, Map::len);
    if current == text {
        println!("{} is up to date ({keys} keys, from {})", rel(&out), rel(&dir));
    } else if check {
        return Err(format!("{} is stale: run `cargo xtask openapi` and type the new keys", rel(&out)));
    } else {
        fs::create_dir_all(out.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(&out, text).map_err(|e| format!("{}: {e}", out.display()))?;
        println!("wrote {} ({keys} keys, from {})", rel(&out), rel(&dir));
    }
    run_step("openapi round-trip", cargo().args(["test", "--locked", "-p", "ov-protocol", "--test", "openapi"]))
}

/// The frozen contract copies (SOURCE.md there has their checksums).
fn spec_dir() -> PathBuf {
    root().join("vectors/openapi")
}

fn rel(p: &std::path::Path) -> String {
    p.strip_prefix(root()).unwrap_or(p).display().to_string()
}

// ------------------------------------------------------------------------------------ samples

type Docs = BTreeMap<String, (&'static str, Value)>;

fn build_samples(docs: &Docs) -> Result<Value> {
    let mut out: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (file, (tag, doc)) in docs {
        let paths = doc.get("paths").and_then(Value::as_object).ok_or(format!("{file}: no paths"))?;
        for (path, item) in paths {
            let Some(item) = item.as_object() else { continue };
            for method in METHODS {
                let Some(op) = item.get(method) else { continue };
                let prefix = format!("{tag} {} {path}", method.to_uppercase());
                out.insert(format!("{prefix} op"), vec![Value::Null]);
                if let Some(body) = op.get("requestBody") {
                    let (f, body) = resolve(docs, file, body)?;
                    if let Some(schema) = json_schema(&body) {
                        out.insert(format!("{prefix} request"), variants(docs, &f, &schema)?);
                    }
                }
                for (status, resp) in op.get("responses").and_then(Value::as_object).into_iter().flatten() {
                    if is_error_ref(resp) {
                        continue;
                    }
                    let (f, resp) = resolve(docs, file, resp)?;
                    if let Some(schema) = json_schema(&resp) {
                        out.insert(format!("{prefix} {status}"), variants(docs, &f, &schema)?);
                    }
                }
            }
        }
        let components = doc.get("components");
        for (name, schema) in components.and_then(|c| c.get("schemas")).and_then(Value::as_object).into_iter().flatten()
        {
            out.insert(format!("{tag} schema {name}"), variants(docs, file, schema)?);
        }
        for (name, resp) in components.and_then(|c| c.get("responses")).and_then(Value::as_object).into_iter().flatten()
        {
            if let Some(schema) = json_schema(resp) {
                out.insert(format!("{tag} response {name}"), variants(docs, file, &schema)?);
            }
        }
    }
    serde_json::to_value(out).map_err(|e| e.to_string())
}

fn is_error_ref(resp: &Value) -> bool {
    resp.get("$ref").and_then(Value::as_str).is_some_and(|r| r.ends_with("#/components/responses/Error"))
}

fn json_schema(holder: &Value) -> Option<Value> {
    holder.get("content")?.get("application/json")?.get("schema").cloned()
}

/// Follows a `$ref` (local `#/...` or `./file.yaml#/...`), returning the target and its file.
fn resolve(docs: &Docs, file: &str, v: &Value) -> Result<(String, Value)> {
    let mut file = file.to_string();
    let mut v = v.clone();
    for _ in 0..16 {
        let Some(r) = v.get("$ref").and_then(Value::as_str) else { return Ok((file, v)) };
        let (target_file, pointer) = r.split_once('#').ok_or(format!("{file}: bad $ref {r}"))?;
        if !target_file.is_empty() {
            file = target_file.trim_start_matches("./").to_string();
        }
        let doc = &docs.get(&file).ok_or(format!("$ref {r}: unknown file {file}"))?.1;
        v = doc.pointer(pointer).cloned().ok_or(format!("{file}: $ref {r} not found"))?;
    }
    Err(format!("{file}: $ref loop"))
}

fn variants(docs: &Docs, file: &str, schema: &Value) -> Result<Vec<Value>> {
    let mut out: Vec<Value> = Vec::new();
    for v in (0..VARIANTS).map(Some).chain([None]) {
        let s = sample(docs, file, schema, v, 0)?;
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

/// A sample of `schema`. `variant` picks enum values and oneOf branches; `None` is the `nulls`
/// variant, where every nullable value is null.
fn sample(docs: &Docs, file: &str, schema: &Value, variant: Option<usize>, depth: usize) -> Result<Value> {
    if depth > 32 {
        return Err(format!("{file}: schema nests too deep"));
    }
    let (file, schema) = resolve(docs, file, schema)?;
    let file = file.as_str();
    let next = |s: &Value| sample(docs, file, s, variant, depth + 1);
    let pick = |n: usize| variant.unwrap_or(0) % n;
    if let Some(ex) = schema.get("example") {
        return Ok(ex.clone());
    }
    if let Some(c) = schema.get("const") {
        return Ok(c.clone());
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(branches) = schema.get(key).and_then(Value::as_array) {
            let (nulls, others): (Vec<&Value>, Vec<&Value>) = branches.iter().partition(|b| is_null_schema(b));
            if variant.is_none() && !nulls.is_empty() {
                return Ok(Value::Null);
            }
            return next(others[pick(others.len())]);
        }
    }
    if let Some(parts) = schema.get("allOf").and_then(Value::as_array) {
        let mut merged = Map::new();
        for p in parts {
            if let Value::Object(m) = next(p)? {
                merged.extend(m);
            }
        }
        return Ok(Value::Object(merged));
    }
    let types: Vec<&str> = match schema.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let non_null: Vec<&Value> = values.iter().filter(|v| !v.is_null()).collect();
        if variant.is_none() && (values.iter().any(Value::is_null) || types.contains(&"null")) {
            return Ok(Value::Null);
        }
        return Ok(non_null[pick(non_null.len())].clone());
    }
    if variant.is_none() && types.contains(&"null") {
        return Ok(Value::Null);
    }
    let ty = types.iter().copied().find(|t| *t != "null").unwrap_or(if schema.get("properties").is_some() {
        "object"
    } else {
        "any"
    });
    Ok(match ty {
        "object" => {
            let mut m = Map::new();
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                for (k, s) in props {
                    m.insert(k.clone(), next(s)?);
                }
            } else if let Some(ap) = schema.get("additionalProperties").filter(|a| a.is_object()) {
                m.insert("key".into(), next(ap)?);
            } else {
                m.insert("key".into(), Value::String("value".into()));
            }
            Value::Object(m)
        }
        "array" => Value::Array(vec![next(schema.get("items").unwrap_or(&Value::Null))?]),
        "string" => Value::String(string_sample(&schema)),
        "integer" => schema.get("minimum").cloned().unwrap_or(Value::from(1)),
        "number" => Value::from(1.5),
        "boolean" => Value::Bool(true),
        _ => Value::String("any".into()),
    })
}

fn is_null_schema(s: &Value) -> bool {
    s.get("type").and_then(Value::as_str) == Some("null")
}

fn string_sample(schema: &Value) -> String {
    let format = schema.get("format").and_then(Value::as_str).unwrap_or("");
    let pattern = schema.get("pattern").and_then(Value::as_str).unwrap_or("");
    match (format, pattern) {
        ("uuid", _) => "00000000-0000-4000-8000-000000000001".into(),
        ("date-time", _) => "2026-11-15T12:00:00Z".into(),
        ("email", _) => "user@example.com".into(),
        ("uri", _) => "https://example.com/upgrade".into(),
        (_, p) if p.starts_with("^(user|sa):") => "user:00000000-0000-4000-8000-000000000002".into(),
        (_, "^[A-Za-z0-9_-]{22}$") => "AAAAAAAAAAAAAAAAAAAAAA".into(),
        (_, "^[0-9]{6}$") => "123456".into(),
        (_, "^[A-Za-z0-9_-]*$") => "AAEC".into(),
        _ => match schema.get("minLength").and_then(Value::as_u64) {
            Some(n) => "x".repeat(n as usize),
            None => "text".into(),
        },
    }
}

// ------------------------------------------------------------------------------------ YAML

/// Parses the YAML subset OpenAPI files use into JSON.
fn parse_yaml(text: &str) -> Result<Value> {
    let lines: Vec<Line> = text
        .lines()
        .enumerate()
        .map(|(i, raw)| {
            let content = strip_comment(raw);
            let trimmed = content.trim_end();
            let body = trimmed.trim_start();
            if body.is_empty() {
                // Keep blank lines only for `|` blocks, which need them as newlines.
                return Line { no: i + 1, indent: usize::MAX, text: String::new(), raw: raw.to_string() };
            }
            Line { no: i + 1, indent: trimmed.len() - body.len(), text: body.to_string(), raw: raw.to_string() }
        })
        .collect();
    let mut p = YamlParser { lines, pos: 0 };
    p.skip_blank();
    if p.pos >= p.lines.len() {
        return Ok(Value::Null);
    }
    let indent = p.lines[p.pos].indent;
    let v = p.block(indent)?;
    p.skip_blank();
    if p.pos < p.lines.len() {
        let l = &p.lines[p.pos];
        return Err(format!("line {}: unexpected indentation", l.no));
    }
    Ok(v)
}

struct Line {
    no: usize,
    /// usize::MAX for a blank line.
    indent: usize,
    text: String,
    raw: String,
}

struct YamlParser {
    lines: Vec<Line>,
    pos: usize,
}

fn strip_comment(line: &str) -> &str {
    let mut q = Quotes::default();
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        if c == '#' && !q.inside() && prev_space {
            return &line[..i];
        }
        q.step(c);
        prev_space = c == ' ' || c == '\t';
    }
    line
}

/// Tracks whether a scan is inside a quoted scalar. A quote opens one only where a scalar can
/// start (line start, or after `{ [ , : -` and spaces), so the apostrophe in a plain `didn't` is text.
#[derive(Default)]
struct Quotes {
    single: bool,
    double: bool,
    escaped: bool,
    /// The last non-space character outside quotes.
    last: Option<char>,
}

impl Quotes {
    fn inside(&self) -> bool {
        self.single || self.double
    }

    fn step(&mut self, c: char) {
        let can_open = matches!(self.last, None | Some('{' | '[' | ',' | ':' | '-'));
        match c {
            _ if self.escaped => self.escaped = false,
            '\\' if self.double => self.escaped = true,
            '\'' if self.single => self.single = false,
            '"' if self.double => self.double = false,
            '\'' if !self.double && can_open => self.single = true,
            '"' if !self.single && can_open => self.double = true,
            _ => {}
        }
        if !self.inside() && !c.is_whitespace() {
            self.last = Some(c);
        }
    }
}

impl YamlParser {
    fn skip_blank(&mut self) {
        while self.pos < self.lines.len() && self.lines[self.pos].indent == usize::MAX {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<(usize, &str)> {
        self.skip_blank();
        self.lines.get(self.pos).map(|l| (l.indent, l.text.as_str()))
    }

    fn err(&self, msg: &str) -> String {
        let no = self.lines.get(self.pos).map_or(0, |l| l.no);
        format!("line {no}: {msg}")
    }

    /// A block collection whose lines start at `indent`.
    fn block(&mut self, indent: usize) -> Result<Value> {
        match self.peek() {
            Some((_, t)) if t == "-" || t.starts_with("- ") => self.seq(indent),
            Some(_) => self.map(indent),
            None => Ok(Value::Null),
        }
    }

    fn seq(&mut self, indent: usize) -> Result<Value> {
        let mut out = Vec::new();
        while let Some((i, t)) = self.peek() {
            if i != indent || !(t == "-" || t.starts_with("- ")) {
                break;
            }
            let rest = t[1..].trim_start().to_string();
            if rest.is_empty() {
                self.pos += 1;
                match self.peek() {
                    Some((ni, _)) if ni > indent => out.push(self.block(ni)?),
                    _ => out.push(Value::Null),
                }
            } else if starts_flow(&rest) || find_map_colon(&rest).is_none() {
                self.pos += 1;
                out.push(self.inline_value(&rest, indent)?);
            } else {
                // `- key: value`: re-read this line as a mapping indented past the dash.
                let offset = t.len() - rest.len();
                let l = &mut self.lines[self.pos];
                l.indent += offset;
                l.text = rest;
                let ni = l.indent;
                out.push(self.map(ni)?);
            }
        }
        Ok(Value::Array(out))
    }

    fn map(&mut self, indent: usize) -> Result<Value> {
        let mut out = Map::new();
        while let Some((i, t)) = self.peek() {
            if i != indent {
                if i > indent {
                    return Err(self.err("unexpected indentation"));
                }
                break;
            }
            if t == "-" || t.starts_with("- ") {
                break;
            }
            let t = t.to_string();
            let colon = find_map_colon(&t).ok_or_else(|| self.err("expected `key: value`"))?;
            let key = unquote_key(t[..colon].trim()).map_err(|e| self.err(&e))?;
            let rest = t[colon + 1..].trim().to_string();
            self.pos += 1;
            let value = if rest.is_empty() {
                match self.peek() {
                    Some((ni, _)) if ni > indent => self.block(ni)?,
                    // `key:` followed by a sequence at the same indentation
                    Some((ni, nt)) if ni == indent && (nt == "-" || nt.starts_with("- ")) => self.seq(ni)?,
                    _ => Value::Null,
                }
            } else if rest == "|" || rest == "|-" || rest == "|+" {
                self.literal(indent, rest == "|-")
            } else {
                self.inline_value(&rest, indent)?
            };
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }

    /// A `|` block: every following line indented past `parent`, kept verbatim.
    fn literal(&mut self, parent: usize, strip: bool) -> Value {
        let mut block_indent = None;
        let mut text = String::new();
        while self.pos < self.lines.len() {
            let l = &self.lines[self.pos];
            if l.indent == usize::MAX {
                text.push('\n');
                self.pos += 1;
                continue;
            }
            if l.indent <= parent {
                break;
            }
            let bi = *block_indent.get_or_insert(l.indent);
            text.push_str(l.raw.get(bi..).unwrap_or("").trim_end());
            text.push('\n');
            self.pos += 1;
        }
        let trimmed = text.trim_end_matches('\n');
        Value::String(if strip { trimmed.to_string() } else { format!("{trimmed}\n") })
    }

    /// A value after `key:` or `- `: flow collection (may span lines), quoted or plain scalar
    /// (plain scalars may continue on more-indented lines).
    fn inline_value(&mut self, first: &str, parent: usize) -> Result<Value> {
        let mut text = first.to_string();
        let start_line = self.lines.get(self.pos.saturating_sub(1)).map_or(0, |l| l.no);
        if starts_flow(&text) || text.starts_with('"') || text.starts_with('\'') {
            while !balanced(&text) {
                self.skip_blank();
                let l = self.lines.get(self.pos).ok_or_else(|| self.err("unclosed flow collection or quote"))?;
                text.push(' ');
                text.push_str(&l.text);
                self.pos += 1;
            }
            let mut f = Flow { s: text.as_bytes(), i: 0 };
            let v = f.value(false).map_err(|e| format!("line {start_line}: {e}"))?;
            f.ws();
            if f.i != f.s.len() {
                return Err(format!("line {start_line}: trailing text after value: {}", &text[f.i..]));
            }
            return Ok(v);
        }
        while let Some((i, t)) = self.peek() {
            if i <= parent || find_map_colon(t).is_some() || t.starts_with("- ") {
                break;
            }
            text.push(' ');
            text.push_str(t);
            self.pos += 1;
        }
        Ok(plain_scalar(&text))
    }
}

fn starts_flow(s: &str) -> bool {
    s.starts_with('{') || s.starts_with('[')
}

/// Whether quotes and brackets are closed.
fn balanced(s: &str) -> bool {
    let mut q = Quotes::default();
    let mut depth = 0i32;
    for c in s.chars() {
        if !q.inside() {
            match c {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
        }
        q.step(c);
    }
    depth <= 0 && !q.inside()
}

/// The `:` that separates a block-mapping key from its value (followed by a space or the end),
/// outside quotes. None when the line is not a `key: value` line.
fn find_map_colon(s: &str) -> Option<usize> {
    if starts_flow(s) {
        return None;
    }
    let b = s.as_bytes();
    let mut i = 0;
    if b.first() == Some(&b'\'') || b.first() == Some(&b'"') {
        let q = b[0];
        i = 1;
        while i < b.len() {
            if b[i] == q {
                if q == b'\'' && b.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                break;
            }
            if q == b'"' && b[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        i += 1;
        return (b.get(i) == Some(&b':') && matches!(b.get(i + 1), None | Some(b' '))).then_some(i);
    }
    while i < b.len() {
        if b[i] == b':' && matches!(b.get(i + 1), None | Some(b' ')) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn unquote_key(k: &str) -> Result<String> {
    if k.starts_with('\'') || k.starts_with('"') {
        let mut f = Flow { s: k.as_bytes(), i: 0 };
        match f.value(true)? {
            Value::String(s) => Ok(s),
            _ => Err(format!("bad key {k}")),
        }
    } else {
        Ok(k.to_string())
    }
}

fn plain_scalar(s: &str) -> Value {
    let s = s.trim();
    match s {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => {
            if let Ok(n) = s.parse::<i64>() {
                return Value::from(n);
            }
            if s.contains('.') && s.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b'-') {
                if let Ok(f) = s.parse::<f64>() {
                    return Value::from(f);
                }
            }
            Value::String(s.to_string())
        }
    }
}

/// Flow-style YAML: `{ a: b, c: [d, 'e'] }`.
struct Flow<'a> {
    s: &'a [u8],
    i: usize,
}

impl Flow<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn value(&mut self, in_flow: bool) -> Result<Value> {
        self.ws();
        match self.s.get(self.i) {
            Some(b'{') => self.mapping(),
            Some(b'[') => self.sequence(),
            Some(b'\'') => self.single().map(Value::String),
            Some(b'"') => self.double().map(Value::String),
            Some(_) => {
                let start = self.i;
                while self.i < self.s.len() {
                    let c = self.s[self.i];
                    if in_flow && matches!(c, b',' | b'}' | b']') {
                        break;
                    }
                    if in_flow && c == b':' && matches!(self.s.get(self.i + 1), None | Some(b' ')) {
                        break;
                    }
                    self.i += 1;
                }
                Ok(plain_scalar(std::str::from_utf8(&self.s[start..self.i]).map_err(|e| e.to_string())?))
            }
            None => Ok(Value::Null),
        }
    }

    fn expect(&mut self, c: u8) -> Result {
        self.ws();
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected `{}` at column {}", c as char, self.i + 1))
        }
    }

    fn mapping(&mut self) -> Result<Value> {
        self.expect(b'{')?;
        let mut m = Map::new();
        loop {
            self.ws();
            if self.s.get(self.i) == Some(&b'}') {
                self.i += 1;
                return Ok(Value::Object(m));
            }
            let key = match self.value(true)? {
                Value::String(s) => s,
                Value::Null => String::new(),
                other => other.to_string(),
            };
            self.ws();
            // `{ a, b: c }`: a key with no `:` has a null value (YAML 1.2 flow mappings). The
            // contract relies on this where a plain description contains a comma.
            let v = if matches!(self.s.get(self.i), Some(b',' | b'}')) {
                Value::Null
            } else {
                self.expect(b':')?;
                self.value(true)?
            };
            m.insert(key, v);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {}
                _ => return Err(format!("expected `,` or `}}` at column {}", self.i + 1)),
            }
        }
    }

    fn sequence(&mut self) -> Result<Value> {
        self.expect(b'[')?;
        let mut out = Vec::new();
        loop {
            self.ws();
            if self.s.get(self.i) == Some(&b']') {
                self.i += 1;
                return Ok(Value::Array(out));
            }
            out.push(self.value(true)?);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {}
                _ => return Err(format!("expected `,` or `]` at column {}", self.i + 1)),
            }
        }
    }

    fn single(&mut self) -> Result<String> {
        self.i += 1;
        let mut out = Vec::new();
        while self.i < self.s.len() {
            if self.s[self.i] == b'\'' {
                if self.s.get(self.i + 1) == Some(&b'\'') {
                    out.push(b'\'');
                    self.i += 2;
                    continue;
                }
                self.i += 1;
                return String::from_utf8(out).map_err(|e| e.to_string());
            }
            out.push(self.s[self.i]);
            self.i += 1;
        }
        Err("unclosed single quote".into())
    }

    fn double(&mut self) -> Result<String> {
        self.i += 1;
        let mut out = Vec::new();
        while self.i < self.s.len() {
            match self.s[self.i] {
                b'"' => {
                    self.i += 1;
                    return String::from_utf8(out).map_err(|e| e.to_string());
                }
                b'\\' => {
                    self.i += 1;
                    let c = *self.s.get(self.i).ok_or("dangling escape")?;
                    out.push(match c {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'"' | b'\\' | b'/' => c,
                        _ => return Err(format!("unsupported escape \\{}", c as char)),
                    });
                }
                c => out.push(c),
            }
            self.i += 1;
        }
        Err("unclosed double quote".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_the_subset() {
        let y = "\
# comment
a: 1
b: { x: [ 'on', managers, 'off' ], y: 'it''s', z: \"q#\" } # trailing
c:
  - name: n
    v: true
  - { $ref: './f.yaml#/p' }
  - plain text: no
d: |
  line one

  line two
e:
- 2
'200': { description: OK, content: { application/octet-stream: {} } }
f: a plain
  continued scalar
";
        let v = parse_yaml(y).unwrap();
        assert_eq!(
            v,
            json!({
                "a": 1,
                "b": {"x": ["on", "managers", "off"], "y": "it's", "z": "q#"},
                "c": [{"name": "n", "v": true}, {"$ref": "./f.yaml#/p"}, {"plain text": "no"}],
                "d": "line one\n\nline two\n",
                "e": [2],
                "200": {"description": "OK", "content": {"application/octet-stream": {}}},
                "f": "a plain continued scalar"
            })
        );
    }
}
