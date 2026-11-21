//! The Java facade of the Kotlin binding (`com.openvireo.core.java`, language-bindings.md §3, task
//! B3), generated from the Kotlin that `uniffi-bindgen` writes so it can't drift from the API.
//!
//! **Source.** The generator reads the public declarations of the generated `ov_ffi.kt` rather than
//! UniFFI's own metadata: that file is exactly what a JVM caller sees (Kotlin type names, the
//! `[bindings.kotlin.rename]` renames, `suspend` or not, `@Throws`), so the facade needs no copy of
//! bindgen's naming rules. UniFFI writes those declarations in a fixed shape, one per line:
//!
//! - an object `X`: `public interface XInterface { [suspend] fun `m`(`p`: T, …): R }` plus
//!   `open class X: Disposable, AutoCloseable, XInterface { constructor(`p`: T, …) …
//!   companion object { [suspend] fun `named`(…): X } }`;
//! - a callback interface `X` (a Host part): `public interface X { … }` plus `open class XImpl`;
//! - a record: `data class X (var `f`: T [= default], …)`; an enum variant with fields:
//!   `data class V(val `f`: T, …) : Parent()` inside `sealed class Parent`;
//! - a free function: `[suspend] fun `f`(…): R { … }` at the top level.
//!
//! Comments and string literals are blanked first, so the brace depth of each line is exact. Every
//! public object method, free function and unsigned record field must come out the other end:
//! `FacadeCoverageTest` checks the compiled classes by reflection, so a declaration this parser
//! missed fails the build instead of going missing.
//!
//! **Output** (one file per type, in package `com.openvireo.core.java`):
//!
//! - `J<Object>` for each object whose API Java can't call as is (a `suspend` method, an unsigned
//!   type, or another such object in a signature). `suspend` methods return `CompletableFuture`
//!   (on the wrapper's `CoroutineScope`); a method taking a `CancelToken` gets a second overload
//!   without it that makes (and closes) a fresh token. Objects in and out are `J` wrappers;
//!   unsigned types become the next wider signed type (`UInt` → `Long`), range-checked going in.
//! - `JOv`: every free function as a `@JvmStatic`.
//! - `JRecords`: for records and enum variants with unsigned fields, whose constructors and
//!   getters Kotlin hides from Java, a `new<Record>(…)` factory and `get<Field>(record)` getters.
//!
//! The hand-written runtime it calls (`JScope`, `ovFuture`, `JUnsigned`) and the Host interfaces
//! live in `bindings/kotlin/shared/src/main/kotlin/com/openvireo/core/java`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use crate::Result;

const QUAL: &str = "com.openvireo.core.";
const OUT_PACKAGE: &str = "com.openvireo.core.java";

/// Writes the facade for `ov_ffi` (the generated Kotlin file) into `out_dir`
/// (`<out_dir>/com/openvireo/core/java/*.kt`). Returns how many methods it wrapped.
pub fn generate(ov_ffi: &Path, out_dir: &Path) -> Result<Stats> {
    let src = fs::read_to_string(ov_ffi).map_err(|e| format!("{}: {e}", ov_ffi.display()))?;
    let api = parse(&src)?;
    let files = Gen::new(&api).files()?;
    let dir = out_dir.join("com").join("openvireo").join("core").join("java");
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut stats = Stats::default();
    for (name, text) in &files.sources {
        fs::write(dir.join(name), text).map_err(|e| format!("{name}: {e}"))?;
    }
    stats.files = files.sources.len();
    stats.wrapped = files.wrapped;
    stats.total = files.total;
    Ok(stats)
}

/// What the generator produced: files written, and methods wrapped out of every public method of
/// the objects it wrapped plus every free function and named constructor.
#[derive(Default, Debug)]
pub struct Stats {
    pub files: usize,
    pub wrapped: usize,
    pub total: usize,
}

// ---------------------------------------------------------------------------------------------
// Lexing: blank comments and strings, track brace depth.

/// One line of code without comments or string contents, and the brace depth at its start.
struct Line {
    depth: usize,
    text: String,
}

#[derive(Clone, Copy)]
enum Frame {
    Code,
    /// Inside `${…}` in a string; counts the braces opened inside it.
    Template(usize),
    Str,
    Raw,
    LineComment,
    /// Kotlin block comments nest.
    Block(usize),
}

fn lex(src: &str) -> Result<Vec<Line>> {
    let chars: Vec<char> = src.chars().collect();
    let mut stack = vec![Frame::Code];
    let mut depth = 0usize;
    let mut lines = Vec::new();
    let mut cur = String::new();
    let mut line_depth = 0usize;
    let mut i = 0;
    let at = |j: usize| chars.get(j).copied();
    while i < chars.len() {
        let c = chars[i];
        let next = at(i + 1);
        if c == '\n' {
            if matches!(stack.last(), Some(Frame::LineComment)) {
                stack.pop();
            }
            lines.push(Line { depth: line_depth, text: std::mem::take(&mut cur) });
            line_depth = depth;
            i += 1;
            continue;
        }
        let top = stack.len() - 1;
        // Only code outside any string reaches the output.
        let emit = top == 0;
        match stack[top] {
            Frame::LineComment => i += 1,
            Frame::Block(n) => {
                if c == '*' && next == Some('/') {
                    if n == 0 {
                        stack.pop();
                    } else {
                        stack[top] = Frame::Block(n - 1);
                    }
                    i += 2;
                } else if c == '/' && next == Some('*') {
                    stack[top] = Frame::Block(n + 1);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Frame::Str => {
                if c == '\\' {
                    i += 2;
                } else if c == '"' {
                    stack.pop();
                    if stack.len() == 1 {
                        cur.push('"');
                    }
                    i += 1;
                } else if c == '$' && next == Some('{') {
                    stack.push(Frame::Template(0));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Frame::Raw => {
                if c == '"' && next == Some('"') && at(i + 2) == Some('"') {
                    stack.pop();
                    if stack.len() == 1 {
                        cur.push_str("\"\"\"");
                    }
                    i += 3;
                } else if c == '$' && next == Some('{') {
                    stack.push(Frame::Template(0));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Frame::Code | Frame::Template(_) => {
                if c == '/' && next == Some('/') {
                    stack.push(Frame::LineComment);
                    i += 2;
                } else if c == '/' && next == Some('*') {
                    stack.push(Frame::Block(0));
                    i += 2;
                } else if c == '"' {
                    let raw = next == Some('"') && at(i + 2) == Some('"');
                    if emit {
                        cur.push_str(if raw { "\"\"\"" } else { "\"" });
                    }
                    stack.push(if raw { Frame::Raw } else { Frame::Str });
                    i += if raw { 3 } else { 1 };
                } else if c == '\'' {
                    // A char literal: 'x', '\n', '\u0000'.
                    let mut j = i + 1;
                    if at(j) == Some('\\') {
                        j += 1;
                    }
                    j += 1;
                    while j < chars.len() && chars[j] != '\'' && chars[j] != '\n' {
                        j += 1;
                    }
                    if at(j) != Some('\'') {
                        return Err(format!("kotlin facade: unterminated char literal on line {}", lines.len() + 1));
                    }
                    if emit {
                        cur.push_str("' '");
                    }
                    i = j + 1;
                } else if c == '{' {
                    match stack[top] {
                        Frame::Template(n) => stack[top] = Frame::Template(n + 1),
                        _ => depth += 1,
                    }
                    if emit {
                        cur.push(c);
                    }
                    i += 1;
                } else if c == '}' {
                    match stack[top] {
                        Frame::Template(0) => {
                            stack.pop();
                        }
                        Frame::Template(n) => stack[top] = Frame::Template(n - 1),
                        _ => {
                            depth = depth
                                .checked_sub(1)
                                .ok_or_else(|| format!("kotlin facade: unbalanced `}}` on line {}", lines.len() + 1))?;
                        }
                    }
                    if emit {
                        cur.push(c);
                    }
                    i += 1;
                } else {
                    if emit {
                        cur.push(c);
                    }
                    i += 1;
                }
            }
        }
    }
    lines.push(Line { depth: line_depth, text: cur });
    if depth != 0 || stack.len() != 1 {
        return Err("kotlin facade: the generated Kotlin doesn't lex cleanly (unbalanced braces or strings)".into());
    }
    Ok(lines)
}

// ---------------------------------------------------------------------------------------------
// Parsing the declarations.

#[derive(Clone, Debug, PartialEq)]
struct Ty {
    name: String,
    args: Vec<Ty>,
    nullable: bool,
}

impl Ty {
    fn parse(text: &str) -> Result<Ty> {
        let chars: Vec<char> = text.trim().chars().collect();
        let mut pos = 0;
        let ty = Self::parse_at(&chars, &mut pos)?;
        if pos != chars.len() {
            return Err(format!("kotlin facade: can't parse type `{text}`"));
        }
        Ok(ty)
    }

    fn parse_at(c: &[char], pos: &mut usize) -> Result<Ty> {
        let skip_ws = |pos: &mut usize| {
            while *pos < c.len() && c[*pos] == ' ' {
                *pos += 1;
            }
        };
        skip_ws(pos);
        let start = *pos;
        while *pos < c.len() && (c[*pos].is_alphanumeric() || c[*pos] == '.' || c[*pos] == '_') {
            *pos += 1;
        }
        let full: String = c[start..*pos].iter().collect();
        if full.is_empty() {
            return Err(format!("kotlin facade: empty type in `{}`", c.iter().collect::<String>()));
        }
        let name = full.strip_prefix(QUAL).unwrap_or(&full).to_string();
        let mut args = Vec::new();
        skip_ws(pos);
        if *pos < c.len() && c[*pos] == '<' {
            *pos += 1;
            loop {
                args.push(Self::parse_at(c, pos)?);
                skip_ws(pos);
                match c.get(*pos) {
                    Some(',') => *pos += 1,
                    Some('>') => {
                        *pos += 1;
                        break;
                    }
                    _ => {
                        return Err(format!("kotlin facade: bad type arguments in `{}`", c.iter().collect::<String>()))
                    }
                }
            }
        }
        let mut nullable = false;
        // `kotlin.String??` happens (an optional optional): still one nullable type for Kotlin.
        while *pos < c.len() && c[*pos] == '?' {
            nullable = true;
            *pos += 1;
        }
        skip_ws(pos);
        Ok(Ty { name, args, nullable })
    }

    /// Whether this type (or a type argument) satisfies `f`.
    fn any(&self, f: &dyn Fn(&Ty) -> bool) -> bool {
        f(self) || self.args.iter().any(|a| a.any(f))
    }

    fn render(&self, map: &dyn Fn(&str) -> String) -> String {
        let mut s = map(&self.name);
        if !self.args.is_empty() {
            let args: Vec<String> = self.args.iter().map(|a| a.render(map)).collect();
            write!(s, "<{}>", args.join(", ")).unwrap();
        }
        if self.nullable {
            s.push('?');
        }
        s
    }

    fn is_unit(&self) -> bool {
        self.name == "Unit" || self.name == "kotlin.Unit"
    }
}

#[derive(Clone, Debug)]
struct Param {
    name: String,
    ty: Ty,
    default: Option<String>,
}

#[derive(Clone, Debug)]
struct Func {
    name: String,
    params: Vec<Param>,
    /// `None` for `Unit`.
    ret: Option<Ty>,
    suspend: bool,
    throws: bool,
}

#[derive(Debug, Default)]
struct Object {
    name: String,
    methods: Vec<Func>,
    ctors: Vec<Func>,
    statics: Vec<Func>,
}

#[derive(Debug)]
struct Record {
    /// `EntryInput`, or `KdbxKdf.Argon2d` for an enum variant.
    path: String,
    fields: Vec<Param>,
}

#[derive(Debug, Default)]
struct Api {
    objects: Vec<Object>,
    functions: Vec<Func>,
    records: Vec<Record>,
}

/// Splits `text` at commas outside `<>` and `()`.
fn split_top(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in text.chars() {
        match c {
            '<' | '(' => depth += 1,
            '>' | ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// "`name`: Type = default" → a parameter.
fn parse_param(text: &str) -> Result<Param> {
    let t = text.trim();
    let t = t.strip_prefix("val ").or_else(|| t.strip_prefix("var ")).unwrap_or(t).trim();
    let (name, rest) = t.split_once(':').ok_or_else(|| format!("kotlin facade: bad parameter `{text}`"))?;
    let name = name.trim().trim_matches('`').to_string();
    let (ty, default) = match rest.split_once(" = ") {
        Some((ty, d)) => (ty, Some(d.trim().to_string())),
        None => (rest, None),
    };
    Ok(Param { name, ty: Ty::parse(ty)?, default })
}

/// Parses the `fun` declaration on `line` (one line, as UniFFI writes them). `pending_throws`: an
/// `@Throws` on an earlier line.
fn parse_fun(line: &str, pending_throws: bool) -> Result<Option<Func>> {
    let Some(at) = line.find("fun `") else { return Ok(None) };
    let prefix = &line[..at];
    let words: Vec<&str> = prefix.split(|c: char| c.is_whitespace() || c == ')').collect();
    if words.iter().any(|w| matches!(*w, "private" | "internal" | "protected")) {
        return Ok(None);
    }
    let suspend = words.contains(&"suspend");
    let throws = pending_throws || prefix.contains("@Throws(");
    let rest = &line[at + 5..];
    let end = rest.find('`').ok_or_else(|| format!("kotlin facade: bad fun line `{line}`"))?;
    let name = rest[..end].to_string();
    let rest = rest[end + 1..].trim_start();
    let rest = rest.strip_prefix('(').ok_or_else(|| format!("kotlin facade: no `(` in `{line}`"))?;
    let mut depth = 1;
    let mut close = None;
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close.ok_or_else(|| format!("kotlin facade: `{name}`'s parameters span lines: `{line}`"))?;
    let params = split_top(&rest[..close]).iter().map(|p| parse_param(p)).collect::<Result<Vec<_>>>()?;
    let after = rest[close + 1..].trim();
    let ret = match after.strip_prefix(':') {
        Some(r) => {
            let r = r.split('{').next().unwrap_or("").trim();
            let ty = Ty::parse(r)?;
            (!ty.is_unit()).then_some(ty)
        }
        None => None,
    };
    Ok(Some(Func { name, params, ret, suspend, throws }))
}

/// Parses one record field line (`var `f`: T = d` / `val `f`: T,` / `val `f`: T) : Parent()`).
/// Returns the field, if any, and whether the parameter list ended on this line.
fn parse_field(line: &str) -> Result<(Option<Param>, bool)> {
    let t = line.trim();
    if t.starts_with(')') {
        return Ok((None, true));
    }
    let Some(start) = t.find("var `").or_else(|| t.find("val `")) else { return Ok((None, false)) };
    let body = &t[start + 4..];
    // The field ends at a top-level `,` or `)`.
    let mut depth = 0i32;
    let mut end = body.len();
    let mut closed = false;
    for (i, c) in body.char_indices() {
        match c {
            '<' | '(' => depth += 1,
            '>' => depth -= 1,
            ')' if depth == 0 => {
                end = i;
                closed = true;
                break;
            }
            ')' => depth -= 1,
            ',' if depth == 0 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    Ok((Some(parse_param(&body[..end])?), closed))
}

fn is_annotation(t: &str) -> bool {
    t.starts_with('@') && !t.contains("fun ")
}

/// Index of the last line of the block that opens on or after line `i` (whose depth is `d`).
fn block_end(lines: &[Line], i: usize) -> usize {
    let d = lines[i].depth;
    let mut open = i;
    while open < lines.len() && !lines[open].text.contains('{') {
        open += 1;
    }
    let mut j = open + 1;
    while j < lines.len() && lines[j].depth > d {
        j += 1;
    }
    j.saturating_sub(1).max(open)
}

/// The `fun` declarations at depth `depth` within lines `from..=to`, with their `@Throws`.
fn funs_in(lines: &[Line], from: usize, to: usize, depth: usize) -> Result<Vec<Func>> {
    let mut out = Vec::new();
    let mut throws = false;
    for line in &lines[from..=to.min(lines.len() - 1)] {
        if line.depth != depth {
            continue;
        }
        let t = line.text.trim();
        if t.is_empty() {
            continue;
        }
        if is_annotation(t) {
            throws |= t.contains("@Throws(");
            continue;
        }
        if let Some(f) = parse_fun(t, throws)? {
            out.push(f);
        }
        throws = false;
    }
    Ok(out)
}

fn parse(src: &str) -> Result<Api> {
    let lines = lex(src)?;
    let mut api = Api::default();
    let mut interfaces: BTreeMap<String, Vec<Func>> = BTreeMap::new();
    let mut classes: BTreeMap<String, Object> = BTreeMap::new();
    // name → whether its implementation is `@Throws`, per class.
    let mut throwing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut top_throws = false;
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        let t = line.text.trim();
        if line.depth != 0 || t.is_empty() {
            i += 1;
            continue;
        }
        if is_annotation(t) {
            top_throws |= t.contains("@Throws(");
            i += 1;
            continue;
        }
        let annotated = std::mem::take(&mut top_throws);
        if let Some(name) = t.strip_prefix("public interface ").and_then(|r| r.strip_suffix(" {")) {
            let end = block_end(&lines, i);
            if let Some(obj) = name.strip_suffix("Interface") {
                interfaces.insert(obj.to_string(), funs_in(&lines, i + 1, end, 1)?);
            }
            i = end + 1;
            continue;
        }
        if let Some(rest) = t.strip_prefix("open class ") {
            // `open class Account: Disposable, AutoCloseable, AccountInterface`
            let (name, supers) = rest.split_once(':').unwrap_or((rest, ""));
            let name = name.trim().to_string();
            let end = block_end(&lines, i);
            if supers.split(',').any(|s| s.trim().trim_end_matches('{').trim() == format!("{name}Interface")) {
                let mut obj = Object { name: name.clone(), ..Object::default() };
                let mut throws = false;
                let mut set = BTreeSet::new();
                let mut j = i + 1;
                while j <= end {
                    let l = &lines[j];
                    let lt = l.text.trim();
                    if l.depth != 1 || lt.is_empty() {
                        j += 1;
                        continue;
                    }
                    if is_annotation(lt) {
                        throws |= lt.contains("@Throws(");
                        j += 1;
                        continue;
                    }
                    if lt == "companion object {" {
                        let cend = block_end(&lines, j);
                        obj.statics = funs_in(&lines, j + 1, cend, 2)?;
                        j = cend + 1;
                        throws = false;
                        continue;
                    }
                    if let Some(params) = lt.strip_prefix("constructor(`") {
                        let close = params
                            .rfind(')')
                            .ok_or_else(|| format!("kotlin facade: {name}: constructor spans lines"))?;
                        let ps = split_top(&format!("`{}", &params[..close]))
                            .iter()
                            .map(|p| parse_param(p))
                            .collect::<Result<Vec<_>>>()?;
                        obj.ctors.push(Func {
                            name: "<init>".into(),
                            params: ps,
                            ret: None,
                            suspend: false,
                            throws: throws || lt.contains("@Throws("),
                        });
                    } else if lt.contains("override fun `") || lt.contains("override suspend fun `") {
                        if let Some(f) = parse_fun(lt, throws)? {
                            if f.throws {
                                set.insert(f.name);
                            }
                        }
                    }
                    throws = false;
                    j += 1;
                }
                throwing.insert(name.clone(), set);
                classes.insert(name, obj);
            }
            i = end + 1;
            continue;
        }
        if let Some(rest) = t.strip_prefix("data class ") {
            let name = rest.split(['(', ' ']).next().unwrap_or("").to_string();
            let (rec, next) = parse_record(&lines, i, name)?;
            api.records.push(rec);
            i = next;
            continue;
        }
        if let Some(rest) = t.strip_prefix("sealed class ") {
            let parent = rest.split([' ', ':', '{', '(']).next().unwrap_or("").to_string();
            let end = block_end(&lines, i);
            let mut j = i + 1;
            while j <= end {
                let lt = lines[j].text.trim();
                if lines[j].depth == 1 {
                    if let Some(r) = lt.strip_prefix("data class ") {
                        let v = r.split(['(', ' ']).next().unwrap_or("");
                        let (rec, next) = parse_record(&lines, j, format!("{parent}.{v}"))?;
                        api.records.push(rec);
                        j = next;
                        continue;
                    }
                }
                j += 1;
            }
            i = end + 1;
            continue;
        }
        if t.contains("fun `") {
            if let Some(f) = parse_fun(t, annotated)? {
                api.functions.push(f);
            }
            i = if t.contains('{') { block_end(&lines, i) + 1 } else { i + 1 };
            continue;
        }
        if t.contains('{') {
            i = block_end(&lines, i) + 1;
        } else {
            i += 1;
        }
    }
    for (name, mut obj) in classes {
        let mut methods =
            interfaces.remove(&name).ok_or_else(|| format!("kotlin facade: no {name}Interface for class {name}"))?;
        let set = &throwing[&name];
        for m in &mut methods {
            m.throws = set.contains(&m.name);
        }
        obj.methods = methods;
        api.objects.push(obj);
    }
    if api.objects.is_empty() || api.functions.is_empty() || api.records.is_empty() {
        return Err(format!(
            "kotlin facade: parsed {} objects, {} functions, {} records: the generated Kotlin's shape changed",
            api.objects.len(),
            api.functions.len(),
            api.records.len()
        ));
    }
    Ok(api)
}

/// The record whose `data class` line is `i`; returns it and the line after its parameter list.
fn parse_record(lines: &[Line], i: usize, path: String) -> Result<(Record, usize)> {
    let header = &lines[i].text;
    let mut fields = Vec::new();
    // Fields can start on the header line, after `(`.
    let first = header.split_once('(').map(|(_, r)| r.to_string()).unwrap_or_default();
    let mut j = i;
    let mut text = first;
    loop {
        let (field, closed) = parse_field(&text)?;
        if let Some(f) = field {
            fields.push(f);
        }
        if closed {
            break;
        }
        j += 1;
        if j >= lines.len() {
            return Err(format!("kotlin facade: record {path} never closes"));
        }
        text = lines[j].text.clone();
    }
    Ok((Record { path, fields }, j + 1))
}

// ---------------------------------------------------------------------------------------------
// Code generation.

const UNSIGNED: [(&str, &str, &str); 4] = [
    // (Kotlin type, facade type, JUnsigned checker going in)
    ("kotlin.UByte", "kotlin.Int", "u8"),
    ("kotlin.UShort", "kotlin.Int", "u16"),
    ("kotlin.UInt", "kotlin.Long", "u32"),
    ("kotlin.ULong", "kotlin.Long", "u64"),
];

fn unsigned(name: &str) -> Option<(&'static str, &'static str)> {
    UNSIGNED.iter().find(|(k, _, _)| *k == name).map(|(_, f, c)| (*f, *c))
}

/// Kotlin keywords a parameter name would need backticks for are always backticked, so names are
/// emitted as `name` in backticks.
fn q(name: &str) -> String {
    format!("`{name}`")
}

fn upper_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

struct Files {
    sources: BTreeMap<String, String>,
    wrapped: usize,
    total: usize,
}

struct Gen<'a> {
    api: &'a Api,
    /// Objects that get a `J` wrapper.
    wrapped: BTreeSet<String>,
}

const HEADER: &str =
    "// GENERATED by `cargo xtask kotlin` (xtask/src/kotlin_facade.rs) from the uniffi-bindgen output.\n\
// Do not edit: rerun `cargo xtask kotlin --generate-only`.\n\
@file:Suppress(\"RedundantVisibilityModifier\", \"unused\", \"NAME_SHADOWING\", \"RemoveRedundantQualifierName\")\n\n";

impl<'a> Gen<'a> {
    fn new(api: &'a Api) -> Self {
        // An object needs a wrapper when Java can't use it as is: a `suspend` method, an unsigned
        // type, or (to a fixed point) another wrapped object in a signature.
        let mut wrapped = BTreeSet::new();
        loop {
            let before = wrapped.len();
            for o in &api.objects {
                let needs = o
                    .methods
                    .iter()
                    .chain(&o.ctors)
                    .chain(&o.statics)
                    .any(|f| f.suspend || Self::sig_needs(f, &wrapped));
                if needs {
                    wrapped.insert(o.name.clone());
                }
            }
            if wrapped.len() == before {
                break;
            }
        }
        Gen { api, wrapped }
    }

    fn ty_needs(ty: &Ty, wrapped: &BTreeSet<String>) -> bool {
        ty.any(&|t| unsigned(&t.name).is_some() || wrapped.contains(&t.name))
    }

    fn sig_needs(f: &Func, wrapped: &BTreeSet<String>) -> bool {
        f.params.iter().any(|p| Self::ty_needs(&p.ty, wrapped))
            || f.ret.as_ref().is_some_and(|r| Self::ty_needs(r, wrapped))
    }

    fn needs(&self, ty: &Ty) -> bool {
        Self::ty_needs(ty, &self.wrapped)
    }

    /// The type as the facade shows it.
    fn facade_ty(&self, ty: &Ty) -> String {
        ty.render(&|n| {
            if let Some((f, _)) = unsigned(n) {
                f.to_string()
            } else if self.wrapped.contains(n) {
                format!("J{n}")
            } else {
                n.to_string()
            }
        })
    }

    fn inner_ty(ty: &Ty) -> String {
        ty.render(&|n| n.to_string())
    }

    /// `e` (a facade value of `ty`) as the generated type.
    fn to_inner(&self, ty: &Ty, e: &str) -> Result<String> {
        if !self.needs(ty) {
            return Ok(e.to_string());
        }
        let dot = if ty.nullable { "?." } else { "." };
        if let Some((_, check)) = unsigned(&ty.name) {
            return Ok(if ty.nullable {
                format!("{e}?.let {{ JUnsigned.{check}(it) }}")
            } else {
                format!("JUnsigned.{check}({e})")
            });
        }
        if self.wrapped.contains(&ty.name) {
            return Ok(format!("{e}{dot}unwrap()"));
        }
        if ty.name == "List" && ty.args.len() == 1 {
            return Ok(format!("{e}{dot}map {{ {} }}", self.to_inner(&ty.args[0], "it")?));
        }
        Err(format!("kotlin facade: no conversion into `{}`", Self::inner_ty(ty)))
    }

    /// `e` (a generated value of `ty`) as the facade type; wrappers run on `scope`.
    fn to_facade(&self, ty: &Ty, e: &str, scope: &str) -> Result<String> {
        if !self.needs(ty) {
            return Ok(e.to_string());
        }
        let dot = if ty.nullable { "?." } else { "." };
        if let Some((f, _)) = unsigned(&ty.name) {
            let conv = if f == "kotlin.Long" { "toLong()" } else { "toInt()" };
            return Ok(format!("{e}{dot}{conv}"));
        }
        if self.wrapped.contains(&ty.name) {
            return Ok(if ty.nullable {
                format!("{e}?.let {{ J{}(it, {scope}) }}", ty.name)
            } else {
                format!("J{}({e}, {scope})", ty.name)
            });
        }
        if ty.name == "List" && ty.args.len() == 1 {
            return Ok(format!("{e}{dot}map {{ {} }}", self.to_facade(&ty.args[0], "it", scope)?));
        }
        Err(format!("kotlin facade: no conversion from `{}`", Self::inner_ty(ty)))
    }

    fn params_decl(&self, ps: &[&Param]) -> String {
        ps.iter().map(|p| format!("{}: {}", q(&p.name), self.facade_ty(&p.ty))).collect::<Vec<_>>().join(", ")
    }

    fn args(&self, ps: &[Param]) -> Result<String> {
        Ok(ps.iter().map(|p| self.to_inner(&p.ty, &q(&p.name))).collect::<Result<Vec<_>>>()?.join(", "))
    }

    /// The scope for a static call: the first wrapped parameter's, else the default.
    fn static_scope(&self, f: &Func) -> String {
        f.params
            .iter()
            .find(|p| self.wrapped.contains(&p.ty.name) && !p.ty.nullable)
            .map(|p| format!("{}.scope()", q(&p.name)))
            .unwrap_or_else(|| "JScope.defaultScope()".into())
    }

    /// One facade method (two when it takes a `CancelToken`). `target` is what the call goes to:
    /// `this@JVault.inner`, `Vault` (a named constructor) or `com.openvireo.core` (a free function).
    /// `owner`: the wrapper class for an instance method (`None` for a static).
    fn method(&self, out: &mut String, f: &Func, target: &str, doc: &str, owner: Option<&str>) -> Result<()> {
        // Inside the future's block `this` is the coroutine scope, hence `this@JVault`.
        let scope = match owner {
            Some(cls) => format!("this@{cls}.scope"),
            None => self.static_scope(f),
        };
        let jvm_static = if owner.is_none() { "@JvmStatic " } else { "" };
        let call = format!("{target}.{}({})", q(&f.name), self.args(&f.params)?);
        let cancel = f.params.iter().find(|p| p.ty.name == "CancelToken" && !p.ty.nullable);
        let all: Vec<&Param> = f.params.iter().collect();
        let without: Vec<&Param> =
            f.params.iter().filter(|p| cancel.map(|c| c.name != p.name).unwrap_or(true)).collect();
        let name = q(&f.name);
        if f.suspend {
            let (fut, body) = match &f.ret {
                None => ("CompletableFuture<Void?>".to_string(), format!("{call}; null")),
                Some(r) => (format!("CompletableFuture<{}>", self.facade_ty(r)), self.to_facade(r, &call, &scope)?),
            };
            let token = cancel.map(|c| q(&c.name)).unwrap_or_else(|| "null".into());
            writeln!(out, "    /** {doc} */").unwrap();
            writeln!(out, "    {jvm_static}public fun {name}({}): {fut} =", self.params_decl(&all)).unwrap();
            writeln!(out, "        {scope}.ovFuture({token}, false) {{ {body} }}\n").unwrap();
            if let Some(c) = cancel {
                let cn = q(&c.name);
                writeln!(out, "    /** {doc} With a fresh [CancelToken]: cancel the future to cancel the call. */")
                    .unwrap();
                writeln!(out, "    {jvm_static}public fun {name}({}): {fut} {{", self.params_decl(&without)).unwrap();
                writeln!(out, "        val {cn} = CancelToken()").unwrap();
                writeln!(out, "        return {scope}.ovFuture({cn}, true) {{ {body} }}").unwrap();
                writeln!(out, "    }}\n").unwrap();
            }
        } else {
            let throws = if f.throws { "@Throws(OvException::class) " } else { "" };
            let (ret, body) = match &f.ret {
                None => ("Unit".to_string(), call.clone()),
                Some(r) => (self.facade_ty(r), self.to_facade(r, &call, &scope)?),
            };
            writeln!(out, "    /** {doc} */").unwrap();
            writeln!(out, "    {jvm_static}{throws}public fun {name}({}): {ret} = {body}\n", self.params_decl(&all))
                .unwrap();
            if let Some(c) = cancel {
                let cn = q(&c.name);
                writeln!(out, "    /** {doc} With a fresh [CancelToken]. */").unwrap();
                writeln!(out, "    {jvm_static}{throws}public fun {name}({}): {ret} =", self.params_decl(&without))
                    .unwrap();
                writeln!(out, "        CancelToken().use {{ {cn} -> {body} }}\n").unwrap();
            }
        }
        Ok(())
    }

    fn object(&self, o: &Object) -> Result<String> {
        let n = &o.name;
        let mut s = String::from(HEADER);
        writeln!(s, "package {OUT_PACKAGE}\n").unwrap();
        s.push_str("import com.openvireo.core.*\nimport java.util.concurrent.CompletableFuture\nimport java.util.concurrent.Executor\nimport kotlinx.coroutines.CoroutineScope\n\n");
        writeln!(
            s,
            "/**\n * The Java facade of [com.openvireo.core.{n}]: every `suspend` method returns a [CompletableFuture]\n \
             * that runs on [scope] (cancelling the future cancels the call), objects come back as `J` wrappers\n \
             * on the same scope, and unsigned numbers are the next wider signed type. [unwrap] gives the\n \
             * generated object; [close] frees it.\n */"
        )
        .unwrap();
        writeln!(s, "public class J{n} @JvmOverloads public constructor(").unwrap();
        writeln!(s, "    private val inner: {n},").unwrap();
        writeln!(s, "    private val scope: CoroutineScope = JScope.defaultScope(),").unwrap();
        writeln!(s, ") : AutoCloseable {{").unwrap();
        writeln!(s, "    /** Wraps [inner]; its futures run on [executor]. */").unwrap();
        writeln!(s, "    public constructor(inner: {n}, executor: Executor) : this(inner, JScope.of(executor))\n")
            .unwrap();
        for c in &o.ctors {
            let ps: Vec<&Param> = c.params.iter().collect();
            let decl = self.params_decl(&ps);
            let args = self.args(&c.params)?;
            let throws = if c.throws { "@Throws(OvException::class) " } else { "" };
            let sep = if decl.is_empty() { "" } else { ", " };
            writeln!(s, "    /** [com.openvireo.core.{n}]'s constructor; futures run on the default scope. */")
                .unwrap();
            writeln!(s, "    {throws}public constructor({decl}) : this({n}({args}))\n").unwrap();
            writeln!(s, "    /** [com.openvireo.core.{n}]'s constructor; futures run on [scope]. */").unwrap();
            writeln!(
                s,
                "    {throws}public constructor({decl}{sep}scope: CoroutineScope) : this({n}({args}), scope)\n"
            )
            .unwrap();
            writeln!(s, "    /** [com.openvireo.core.{n}]'s constructor; futures run on [executor]. */").unwrap();
            writeln!(s, "    {throws}public constructor({decl}{sep}executor: Executor) : this({n}({args}), JScope.of(executor))\n")
                .unwrap();
        }
        writeln!(s, "    /** The generated object. */\n    public fun unwrap(): {n} = inner\n").unwrap();
        writeln!(
            s,
            "    /** The scope this wrapper's futures run on. */\n    public fun scope(): CoroutineScope = scope\n"
        )
        .unwrap();
        writeln!(
            s,
            "    /** Frees the generated object's native handle. */\n    override fun close(): Unit = inner.close()\n"
        )
        .unwrap();
        for m in &o.methods {
            if matches!(m.name.as_str(), "unwrap" | "scope" | "close") {
                return Err(format!("kotlin facade: {n}.{} clashes with the wrapper's own method", m.name));
            }
            let cls = format!("J{n}");
            self.method(
                &mut s,
                m,
                &format!("this@{cls}.inner"),
                &format!("[com.openvireo.core.{n}Interface.{}]", m.name),
                Some(&cls),
            )?;
        }
        if !o.statics.is_empty() {
            writeln!(s, "    public companion object {{").unwrap();
            let mut inner = String::new();
            for f in &o.statics {
                self.method(&mut inner, f, n, &format!("[com.openvireo.core.{n}.Companion.{}]", f.name), None)?;
            }
            for line in inner.lines() {
                if line.is_empty() {
                    s.push('\n');
                } else {
                    writeln!(s, "    {line}").unwrap();
                }
            }
            writeln!(s, "    }}").unwrap();
        }
        writeln!(s, "}}").unwrap();
        Ok(s)
    }

    fn free_functions(&self) -> Result<String> {
        let mut s = String::from(HEADER);
        writeln!(s, "package {OUT_PACKAGE}\n").unwrap();
        s.push_str("import com.openvireo.core.*\nimport java.util.concurrent.CompletableFuture\n\n");
        s.push_str(
            "/**\n * The free functions of `com.openvireo.core` (crypto primitives, share links, TOTP, OPAQUE, …) as\n \
             * static methods. `suspend` ones return a [CompletableFuture] on [JScope.defaultScope] (or on the\n \
             * scope of the first wrapper passed in).\n */\npublic object JOv {\n",
        );
        for f in &self.api.functions {
            self.method(&mut s, f, "com.openvireo.core", &format!("[com.openvireo.core.{}]", f.name), None)?;
        }
        s.push_str("}\n");
        Ok(s)
    }

    /// `new<Record>` factories and `get<Field>` getters for records with unsigned fields.
    fn records(&self) -> Result<(String, usize)> {
        let mut s = String::from(HEADER);
        writeln!(s, "package {OUT_PACKAGE}\n").unwrap();
        s.push_str("import com.openvireo.core.*\n\n");
        s.push_str(
            "/**\n * Kotlin hides constructors and getters with unsigned types from Java. For each record and enum\n \
             * variant with an unsigned field, this has a `new<Record>(…)` factory (unsigned → the next wider\n \
             * signed type, range-checked) and a `get<Field>(record)` getter for each unsigned field. Every\n \
             * other field reads as usual (`record.getName()`).\n */\npublic object JRecords {\n",
        );
        let mut count = 0;
        for r in &self.api.records {
            if !r.fields.iter().any(|f| f.ty.any(&|t| unsigned(&t.name).is_some())) {
                continue;
            }
            count += 1;
            let path = &r.path;
            let fname = path.replace('.', "");
            let decl: Vec<String> = r
                .fields
                .iter()
                .map(|f| {
                    let ty = self.facade_ty(&f.ty);
                    match f.default.as_deref().and_then(|d| self.default_value(&f.ty, d)) {
                        Some(d) => format!("{}: {ty} = {d}", q(&f.name)),
                        None => format!("{}: {ty}", q(&f.name)),
                    }
                })
                .collect();
            let args = self.args(&r.fields)?;
            writeln!(s, "    /** A [com.openvireo.core.{path}]. */").unwrap();
            writeln!(s, "    @JvmStatic @JvmOverloads").unwrap();
            writeln!(s, "    public fun new{fname}({}): {path} = {path}({args})\n", decl.join(", ")).unwrap();
            for f in r.fields.iter().filter(|f| f.ty.any(&|t| unsigned(&t.name).is_some())) {
                let get = self.to_facade(&f.ty, &format!("record.{}", q(&f.name)), "JScope.defaultScope()")?;
                writeln!(s, "    /** [com.openvireo.core.{path}.{}]. */", f.name).unwrap();
                writeln!(
                    s,
                    "    @JvmStatic public fun get{}(record: {path}): {} = {get}\n",
                    upper_first(&f.name),
                    self.facade_ty(&f.ty)
                )
                .unwrap();
            }
        }
        s.push_str("}\n");
        Ok((s, count))
    }

    /// A record field's default, carried over when it means the same in the facade type.
    fn default_value(&self, ty: &Ty, d: &str) -> Option<String> {
        if d == "null" && ty.nullable {
            return Some("null".into());
        }
        if !self.needs(ty) {
            return Some(d.to_string());
        }
        let (f, _) = unsigned(&ty.name)?;
        let digits = d.strip_suffix('u').or_else(|| d.strip_suffix("uL"))?;
        digits.chars().all(|c| c.is_ascii_digit()).then(|| {
            if f == "kotlin.Long" {
                format!("{digits}L")
            } else {
                digits.into()
            }
        })
    }

    fn files(&self) -> Result<Files> {
        let mut sources = BTreeMap::new();
        let mut wrapped = 0;
        let mut total = 0;
        for o in &self.api.objects {
            let n = o.methods.len() + o.statics.len();
            total += n;
            if self.wrapped.contains(&o.name) {
                wrapped += n;
                sources.insert(format!("J{}.kt", o.name), self.object(o)?);
            }
        }
        total += self.api.functions.len();
        wrapped += self.api.functions.len();
        sources.insert("JOv.kt".into(), self.free_functions()?);
        let (records, _) = self.records()?;
        sources.insert("JRecords.kt".into(), records);
        Ok(Files { sources, wrapped, total })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
package com.openvireo.core
// a { comment
/* block { /* nested } */ */
val s = "brace { in ${ "nested }" } string"
val c = '{'
public interface ThingInterface {
    /**
     * Docs { with braces.
     */
    suspend fun `fetch`(`id`: kotlin.String, `n`: kotlin.UInt?, `cancel`: CancelToken): List<Thing>
    fun `count`(): kotlin.ULong
    fun `plain`(`x`: kotlin.String): kotlin.String
    companion object
}
open class Thing: Disposable, AutoCloseable, ThingInterface
{
    constructor(`name`: kotlin.String) :
        this(1) { }
    @Throws(OvException::class)override fun `count`(): kotlin.ULong {
        return 1u
    }
    override fun `plain`(`x`: kotlin.String): kotlin.String { return x }
    companion object {
        @Throws(OvException::class)
     suspend fun `open`(`other`: Thing, `cancel`: CancelToken) : Thing {
        return TODO()
    }
    }
}
data class Rec (
    var `a`: kotlin.UInt
    ,
    var `b`: kotlin.String? = null
){
    companion object
}
sealed class Ev {
    data class Changed(
        val `rev`: kotlin.ULong?,
        val `id`: com.openvireo.core.Rec) : Ev()
    {
        companion object
    }
}
    @Throws(OvException::class) fun `hash`(`b`: kotlin.ByteArray): kotlin.ByteArray {
        return b
    }
internal fun `hidden`() {}
"#;

    #[test]
    fn parses_the_shapes() {
        let api = parse(SAMPLE).unwrap();
        assert_eq!(api.objects.len(), 1);
        let o = &api.objects[0];
        assert_eq!(o.name, "Thing");
        assert_eq!(o.methods.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(), ["fetch", "count", "plain"]);
        assert!(o.methods[0].suspend);
        assert!(o.methods[1].throws && !o.methods[2].throws);
        assert_eq!(o.ctors.len(), 1);
        assert_eq!(o.statics.len(), 1);
        assert!(o.statics[0].suspend && o.statics[0].throws);
        assert_eq!(api.functions.len(), 1);
        assert_eq!(api.functions[0].name, "hash");
        assert!(api.functions[0].throws);
        assert_eq!(api.records.len(), 2);
        assert_eq!(api.records[1].path, "Ev.Changed");
        assert_eq!(api.records[1].fields[1].ty.name, "Rec");
        assert_eq!(api.records[0].fields[1].default.as_deref(), Some("null"));
    }

    #[test]
    fn generates_futures_and_conversions() {
        let api = parse(SAMPLE).unwrap();
        let files = Gen::new(&api).files().unwrap();
        let thing = &files.sources["JThing.kt"];
        assert!(thing.contains("public fun `fetch`(`id`: kotlin.String, `n`: kotlin.Long?, `cancel`: CancelToken): CompletableFuture<List<JThing>>"), "{thing}");
        assert!(thing.contains("`n`?.let { JUnsigned.u32(it) }"), "{thing}");
        assert!(
            thing.contains(
                "public fun `fetch`(`id`: kotlin.String, `n`: kotlin.Long?): CompletableFuture<List<JThing>> {"
            ),
            "{thing}"
        );
        assert!(
            thing.contains(
                "@Throws(OvException::class) public fun `count`(): kotlin.Long = this@JThing.inner.`count`().toLong()"
            ),
            "{thing}"
        );
        assert!(thing.contains("@JvmStatic public fun `open`(`other`: JThing, `cancel`: CancelToken)"), "{thing}");
        assert!(thing.contains("`other`.scope().ovFuture"), "{thing}");
        let records = &files.sources["JRecords.kt"];
        assert!(records.contains("public fun newRec(`a`: kotlin.Long, `b`: kotlin.String? = null): Rec"), "{records}");
        assert!(
            records.contains("public fun getRev(record: Ev.Changed): kotlin.Long? = record.`rev`?.toLong()"),
            "{records}"
        );
        assert!(files.sources["JOv.kt"].contains("com.openvireo.core.`hash`(`b`)"));
        assert_eq!(files.total, 5);
        assert_eq!(files.wrapped, 5);
    }

    #[test]
    fn lexer_tracks_depth_past_strings_and_comments() {
        let lines = lex(SAMPLE).unwrap();
        let iface = lines.iter().position(|l| l.text.contains("public interface ThingInterface")).unwrap();
        assert_eq!(lines[iface].depth, 0);
        assert_eq!(lines[iface + 4].depth, 1);
    }
}
