//! Fails when a public method or free function of the facade (`ov_core::api`) has no bridged
//! function in `src/lib.rs` (`cargo xtask cpp --check-coverage` runs this test and prints its
//! report).
//!
//! rustdoc JSON needs nightly, so this scans the source: every `pub fn` / `pub async fn` /
//! `pub const fn` in an inherent `impl <Type> {` block at the top level of
//! `crates/ov-core/src/api/*.rs`, and every top-level `pub fn` there. The bridge side is every `fn`
//! in the bridge's `extern "Rust"` blocks: a method (`self: &T`) or a free function.
//!
//! A facade item `T::m` counts as bridged when the bridge has
//! - the method `m` on `T`'s bridge type (`OvClient` is `ov::Client`), or
//! - the free function `<t>_<m>` (`Vault::open_local` is `vault_open_local`, `Plan::limit` is
//!   `plan_limit`), or
//! - the name in [`ALIASES`].
//!
//! [`EXCLUDED`] lists the deliberate exclusions with their reason (README.md repeats them).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Facade item → bridge function, where the naming rule doesn't give it.
const ALIASES: &[(&str, &str)] = &[
    ("OvClient::new", "new_client"),
    ("CancelToken::new", "new_cancel_token"),
    // `register` is a C++ keyword.
    ("Account::register", "Account::register_account"),
];

/// Facade items that are deliberately not bridged, with the reason.
const EXCLUDED: &[(&str, &str)] = &[(
    "CancelToken::cancelled",
    "returns a Rust future; the bridge races every blocking call against it, and C++ polls is_cancelled()",
)];

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn ident(s: &str) -> String {
    s.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect()
}

/// `Type::method` and `free` items of the facade.
fn facade_items(api_dir: &Path) -> BTreeSet<String> {
    let mut items = BTreeSet::new();
    let mut files: Vec<_> = fs::read_dir(api_dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    for path in files.into_iter().filter(|p| p.extension().is_some_and(|e| e == "rs")) {
        let src = strip_comments(&fs::read_to_string(&path).unwrap());
        let mut current: Option<String> = None;
        for line in src.lines() {
            if let Some(rest) = line.strip_prefix("impl ") {
                // Inherent impls only: `impl Type {`, not `impl Trait for Type {`.
                let head = rest.trim_end().trim_end_matches('{').trim();
                current = (!head.contains(" for ") && !head.contains('<')).then(|| ident(head));
                continue;
            }
            if line.starts_with('}') {
                current = None;
                continue;
            }
            let fn_name = |l: &str| -> Option<String> {
                ["pub fn ", "pub async fn ", "pub const fn "].iter().find_map(|p| l.strip_prefix(p).map(ident))
            };
            match &current {
                Some(ty) => {
                    if let Some(name) = line.strip_prefix("    ").and_then(fn_name) {
                        items.insert(format!("{ty}::{name}"));
                    }
                }
                None => {
                    if let Some(name) = fn_name(line) {
                        items.insert(name);
                    }
                }
            }
        }
    }
    items
}

/// `Type::method` and `free` functions the bridge exports to C++.
fn bridge_items(lib_rs: &Path) -> BTreeSet<String> {
    let src = strip_comments(&fs::read_to_string(lib_rs).unwrap());
    let mut items = BTreeSet::new();
    let mut rest = src.as_str();
    while let Some(start) = rest.find("extern \"Rust\" {") {
        let body = &rest[start..];
        // The block ends at the first closing brace at its own nesting level.
        let mut depth = 0usize;
        let mut end = body.len();
        for (i, c) in body.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let block = &body[..end];
        let mut at = 0;
        while let Some(i) = block[at..].find("fn ") {
            let pos = at + i;
            at = pos + 3;
            let before = block[..pos].chars().last().unwrap_or(' ');
            if before.is_alphanumeric() || before == '_' {
                continue;
            }
            let name = ident(&block[pos + 3..]);
            let after = &block[pos + 3 + name.len()..];
            let Some(params) = after.strip_prefix('(') else { continue };
            let params = params.trim_start();
            if let Some(self_ty) = params.strip_prefix("self:") {
                let ty = self_ty.trim_start().trim_start_matches('&').trim_start_matches("mut ").trim_start();
                items.insert(format!("{}::{name}", ident(ty)));
            } else {
                items.insert(name);
            }
        }
        rest = &body[end..];
    }
    items
}

fn snake(ty: &str) -> String {
    let mut out = String::new();
    for (i, c) in ty.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn bridge_type(facade_ty: &str) -> &str {
    match facade_ty {
        "OvClient" => "Client",
        other => other,
    }
}

/// The facade items with no bridged function, after aliases and exclusions.
fn missing(facade: &BTreeSet<String>, bridge: &BTreeSet<String>) -> Vec<String> {
    facade
        .iter()
        .filter(|item| {
            if EXCLUDED.iter().any(|(e, _)| e == item) {
                return false;
            }
            if let Some((_, to)) = ALIASES.iter().find(|(from, _)| from == item) {
                return !bridge.contains(*to);
            }
            match item.split_once("::") {
                Some((ty, m)) => {
                    !bridge.contains(&format!("{}::{m}", bridge_type(ty)))
                        && !bridge.contains(&format!("{}_{m}", snake(ty)))
                }
                None => !bridge.contains(item.as_str()),
            }
        })
        .cloned()
        .collect()
}

#[test]
fn every_facade_item_is_bridged() {
    let root = manifest();
    let facade = facade_items(&root.join("../../crates/ov-core/src/api"));
    let bridge = bridge_items(&root.join("src/lib.rs"));
    assert!(facade.len() > 100, "the facade scan found only {} items", facade.len());
    for name in ALIASES.iter().map(|(f, _)| f).chain(EXCLUDED.iter().map(|(e, _)| e)) {
        assert!(facade.contains(*name), "ALIASES/EXCLUDED name `{name}`, which the facade no longer has");
    }
    let missing = missing(&facade, &bridge);
    println!("facade items: {} (ov_core::api public methods + free functions)", facade.len());
    println!("bridge functions: {}", bridge.len());
    for (item, why) in EXCLUDED {
        println!("excluded: {item}: {why}");
    }
    for item in &missing {
        println!("missing: {item}");
    }
    println!("missing: {} of {}", missing.len(), facade.len());
    assert!(missing.is_empty(), "{} facade items have no bridged function (listed above)", missing.len());
}

#[test]
fn the_scanners_understand_their_inputs() {
    let dir = std::env::temp_dir().join(format!("ov-ffi-cpp-coverage-{}", std::process::id()));
    let api = dir.join("api");
    fs::create_dir_all(&api).unwrap();
    fs::write(
        api.join("a.rs"),
        "impl Foo {\n    pub fn a(&self) {}\n    pub async fn b(&self) {}\n    fn private(&self) {}\n}\n\
         impl std::fmt::Debug for Foo {\n    pub fn not_me() {}\n}\n\
         impl Bar {\n    pub const fn c(self) {}\n    pub fn new() {}\n}\n\
         pub fn free_one() {}\n// pub fn commented() {}\nmod tests {\n    pub fn nested() {}\n}\n",
    )
    .unwrap();
    let facade = facade_items(&api);
    let want: BTreeSet<String> =
        ["Foo::a", "Foo::b", "Bar::c", "Bar::new", "free_one"].iter().map(|s| s.to_string()).collect();
    assert_eq!(facade, want);

    let lib = dir.join("lib.rs");
    fs::write(
        &lib,
        "mod ffi {\n extern \"C++\" { fn skip(self: &Host); }\n extern \"Rust\" {\n type Foo;\n \
         fn a(self: &Foo) -> Result<()>;\n fn b(\n  self: &mut Foo,\n  x: u8,\n );\n fn bar_c(x: u8);\n \
         // fn foo_commented();\n }\n}\n",
    )
    .unwrap();
    let bridge = bridge_items(&lib);
    let want: BTreeSet<String> = ["Foo::a", "Foo::b", "bar_c"].iter().map(|s| s.to_string()).collect();
    assert_eq!(bridge, want);
    assert_eq!(missing(&facade, &bridge), ["Bar::new", "free_one"]);
    fs::remove_dir_all(&dir).unwrap();
}
