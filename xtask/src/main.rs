//! Build and check tasks for the openvireo-core workspace. Run `cargo xtask help`.

use std::env;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// One module per task-owned command (W1-BW wasm, W1-BS xcframework, W1-BC cpp, W1-P openapi, W4-R release).
mod cpp;
mod kotlin;
mod openapi;
mod release;
mod wasm;
mod xcframework;

const WASM_TARGET: &str = "wasm32-unknown-unknown";
const IOS_TARGETS: [&str; 3] = ["aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios"];

const HELP: &str = "\
cargo xtask <command>

Commands:
  ci            fmt, clippy -D warnings, test, cargo deny, rustdoc -D warnings, vectors, openapi --check, wasm32 build + clippy, iOS build, size report
  vectors       verify every checksum listed in vectors/**/SOURCE.md
  size          build the wasm32 cdylibs in release and print raw + gzip sizes
  unlinked      check that crates with ignored advisories link no code into the wasm cdylibs
  wasm          build the @openvireo/core-wasm package          (W1-BW)
  xcframework   build OpenVireoCore.xcframework                  (W1-BS)
  cpp           build the C++ static libs + headers              (W1-BC)
  kotlin        build + test the Kotlin/JVM binding [--smoke]    (B2)
  openapi       round-trip every OpenAPI example through ov-protocol (W1-P)
  release       build every release artifact the host can build + SHA256SUMS (W4-R; `release --help`)

Portable crates (built for wasm32 and iOS by `ci`) are every package under crates/ except
those that set `[package.metadata.ov] native-only = true` in their Cargo.toml.
";

type Result<T = ()> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("ci") => ci(),
        Some("vectors") => vectors(),
        Some("size") => size(),
        Some("unlinked") => unlinked(),
        Some("wasm") => wasm::run(&args[1..]),
        Some("xcframework") => xcframework::run(&args[1..]),
        Some("cpp") => cpp::run(&args[1..]),
        Some("kotlin") => kotlin::run(&args[1..]),
        Some("openapi") => openapi::run(&args[1..]),
        Some("release") => release::run(&args[1..]),
        None | Some("help" | "-h" | "--help") => {
            print!("{HELP}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command `{other}`\n\n{HELP}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Cargo's target directory: `CARGO_TARGET_DIR` when set, else `<repo>/target`.
fn target_root() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| root().join("target"))
}

fn cargo() -> Command {
    let mut c = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

fn run(step: &str, cmd: &mut Command) -> Result {
    println!("\n==> {step}");
    let status = cmd.status().map_err(|e| format!("{step}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{step} failed ({status})"))
    }
}

fn ci() -> Result {
    run("fmt", cargo().args(["fmt", "--all", "--check"]))?;
    run("clippy", cargo().args(["clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"]))?;
    run("test", cargo().args(["test", "--workspace", "--locked"]))?;
    // The OPAQUE test server and seeded steps only build with this feature; --workspace leaves it off.
    run(
        "test ov-ffi-cpp (test-server)",
        cargo().args(["test", "-p", "ov-ffi-cpp", "--locked", "--features", "test-server"]),
    )?;
    run("deny", cargo().args(["deny", "--locked", "check"]))?;
    run("doc", cargo().args(["doc", "--workspace", "--no-deps", "--locked"]).env("RUSTDOCFLAGS", "-D warnings"))?;
    vectors()?;
    openapi::run(&["--check".into()])?;

    let portable = portable_packages()?;
    let mut wasm = portable.clone();
    wasm.extend(existing_packages(&["ov-wasm", "ov-wasm-lite"])?);
    build_for("wasm32 build", &wasm, &[WASM_TARGET])?;
    // Native clippy can't see wasm32-only code paths (no Send/Sync on the Host, wasm-bindgen glue).
    let mut clippy = cargo();
    clippy.args(["clippy", "--locked", "--target", WASM_TARGET]);
    for p in &wasm {
        clippy.args(["-p", p]);
    }
    run("wasm32 clippy", clippy.args(["--", "-D", "warnings"]))?;

    if cfg!(target_os = "macos") {
        let mut ios = portable;
        ios.extend(existing_packages(&["ov-ffi"])?);
        build_for("iOS build", &ios, &IOS_TARGETS)?;
    } else {
        println!("\n==> iOS build: skipped (needs a macOS host)");
    }

    unlinked()?;
    size()?;
    println!("\nxtask ci: all green");
    Ok(())
}

fn build_for(step: &str, packages: &[String], targets: &[&str]) -> Result {
    if packages.is_empty() {
        println!("\n==> {step}: no portable packages");
        return Ok(());
    }
    let mut cmd = cargo();
    cmd.args(["build", "--locked"]);
    for t in targets {
        cmd.args(["--target", t]);
    }
    for p in packages {
        cmd.args(["-p", p]);
    }
    run(&format!("{step} ({})", packages.join(", ")), &mut cmd)
}

fn metadata() -> Result<serde_json::Value> {
    let out = cargo()
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo metadata: {}", String::from_utf8_lossy(&out.stderr)));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata: {e}"))
}

fn portable_packages() -> Result<Vec<String>> {
    let meta = metadata()?;
    let crates_dir = root().join("crates");
    let mut names = Vec::new();
    for p in meta["packages"].as_array().into_iter().flatten() {
        let manifest = Path::new(p["manifest_path"].as_str().unwrap_or_default());
        let native_only = p["metadata"]["ov"]["native-only"].as_bool().unwrap_or(false);
        if manifest.starts_with(&crates_dir) && !native_only {
            names.push(p["name"].as_str().unwrap_or_default().to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn existing_packages(wanted: &[&str]) -> Result<Vec<String>> {
    let meta = metadata()?;
    Ok(meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p["name"].as_str())
        .filter(|n| wanted.contains(n))
        .map(str::to_string)
        .collect())
}

/// Every `SOURCE.md` under vectors/ lists its files as `<sha256 hex>  <path>` lines (the
/// output format of `shasum -a 256`), with paths relative to the SOURCE.md's folder.
fn vectors() -> Result {
    println!("\n==> vectors");
    let dir = root().join("vectors");
    if !dir.exists() {
        println!("no vectors/ yet");
        return Ok(());
    }
    let mut sources = Vec::new();
    find_named(&dir, "SOURCE.md", &mut sources)?;
    if sources.is_empty() {
        return Err("vectors/ has no SOURCE.md".into());
    }
    let mut checked = 0;
    for source in &sources {
        let base = source.parent().unwrap();
        let text = fs::read_to_string(source).map_err(|e| format!("{}: {e}", source.display()))?;
        for line in text.lines() {
            let Some((sum, path)) = parse_checksum_line(line) else { continue };
            let file = base.join(path);
            let bytes = fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let actual = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes));
            if actual != sum {
                return Err(format!("{}: sha256 {actual}, SOURCE.md says {sum}", file.display()));
            }
            checked += 1;
        }
    }
    println!("{checked} files match their SOURCE.md checksums");
    Ok(())
}

fn parse_checksum_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let (sum, rest) = line.split_once(char::is_whitespace)?;
    let path = rest.trim_start().trim_start_matches('*');
    let is_sum = sum.len() == 64 && sum.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    (is_sum && !path.is_empty() && !path.contains(char::is_whitespace)).then_some((sum, path))
}

fn find_named(dir: &Path, name: &str, out: &mut Vec<PathBuf>) -> Result {
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            find_named(&path, name, out)?;
        } else if path.file_name().is_some_and(|n| n == name) {
            out.push(path);
        }
    }
    Ok(())
}

/// Crates that are in the dependency graph but must never contribute code to a shipped artifact.
/// Each one backs an advisory ignored in deny.toml; the ignore is only valid while this holds.
const UNLINKED_CRATES: [(&str, &str); 1] = [
    // RUSTSEC-2026-0387: crypto-bigint 0.5 via elliptic-curve 0.13 (opaque-ke 4.0.1). The
    // ristretto255 suite does its arithmetic in curve25519-dalek.
    ("crypto_bigint", "RUSTSEC-2026-0387"),
];

/// Portable cdylibs (plus bindings/ov-wasm): what ships as wasm.
fn wasm_cdylibs() -> Result<Vec<String>> {
    let meta = metadata()?;
    let mut wanted = portable_packages()?;
    wanted.push("ov-wasm".into());
    wanted.push("ov-wasm-lite".into());
    Ok(meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| wanted.iter().any(|w| p["name"] == w.as_str()))
        .filter(|p| {
            p["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|t| t["crate_types"].as_array().into_iter().flatten().any(|c| c == "cdylib"))
        })
        .filter_map(|p| p["name"].as_str().map(str::to_string))
        .collect())
}

/// Release-builds each cdylib on its own, as a cdylib only, the way it ships: `cargo build` of an
/// rlib+cdylib package drops `-C lto`, and building several packages together unifies features and
/// lets one share generics with another, so neither size nor symbols would match a shipped module.
fn wasm_release_build(step: &str, cdylibs: &[String], extra: &[&str]) -> Result {
    for p in cdylibs {
        let mut cmd = cargo();
        cmd.args([
            "rustc",
            "--locked",
            "--release",
            "--target",
            WASM_TARGET,
            "-p",
            p,
            "--lib",
            "--crate-type",
            "cdylib",
        ])
        .args(extra);
        run(&format!("{step} ({p})"), &mut cmd)?;
    }
    Ok(())
}

/// Release-builds the wasm cdylibs with symbols kept (same optimisation and LTO as a shipped
/// build) and fails if any function from an UNLINKED_CRATES crate survived linking.
fn unlinked() -> Result {
    let cdylibs = wasm_cdylibs()?;
    if cdylibs.is_empty() {
        println!("\n==> unlinked: no wasm cdylibs");
        return Ok(());
    }
    let target_dir = target_root().join("symbols");
    let target_dir = target_dir.to_str().ok_or("non-UTF-8 target dir")?;
    wasm_release_build(
        "unlinked: release wasm32 build with symbols",
        &cdylibs,
        &["--config", "profile.release.strip=false", "--target-dir", target_dir],
    )?;
    let out_dir = Path::new(target_dir).join(WASM_TARGET).join("release");
    for name in &cdylibs {
        let file = out_dir.join(format!("{}.wasm", name.replace('-', "_")));
        let bytes = fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        // Guard against a silent pass if the name section ever goes missing.
        if !contains(&bytes, b"core") {
            return Err(format!("{}: no symbol names found, can't check", file.display()));
        }
        for (krate, advisory) in UNLINKED_CRATES {
            let defined =
                symbols_mentioning(&bytes, krate).into_iter().filter(|sym| defined_in(sym, krate)).collect::<Vec<_>>();
            if let Some(sym) = defined.first() {
                eprintln!("{name}.wasm: {} function(s) defined in `{krate}`, e.g. {sym}", defined.len());
                return Err(format!(
                    "{name}.wasm links code from `{krate}`, so the deny.toml ignore of {advisory} no longer holds"
                ));
            }
        }
        println!("{name}.wasm: no code from {}", UNLINKED_CRATES.map(|(k, _)| k).join(", "));
    }
    Ok(())
}

/// Every symbol name (a run of printable ASCII in the wasm name section) that mentions `krate`.
fn symbols_mentioning(bytes: &[u8], krate: &str) -> Vec<String> {
    let needle = krate.as_bytes();
    let printable = |b: u8| b.is_ascii_graphic();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(pos) = bytes[i..].windows(needle.len()).position(|w| w == needle) {
        let at = i + pos;
        let start = bytes[..at].iter().rposition(|&b| !printable(b)).map_or(0, |p| p + 1);
        let end = bytes[at..].iter().position(|&b| !printable(b)).map_or(bytes.len(), |p| at + p);
        let sym = String::from_utf8_lossy(&bytes[start..end]).into_owned();
        if !out.contains(&sym) {
            out.push(sym);
        }
        i = end.max(at + 1);
    }
    out
}

/// Whether a mangled symbol is code *defined in* `krate`, not just generic code from another crate
/// that `krate` instantiated (v0 names end with the instantiating crate, e.g. `subtle::black_box::<u8>`
/// instantiated in crypto_bigint is `_RINvCs…_6subtle9black_boxhECs…_13crypto_bigint`).
/// Legacy names: the path starts with the crate (`_ZN13crypto_bigint…`). v0 names: the first crate
/// root (`C` + optional `s<disambiguator>_` + `<len><name>`) in the path is the defining crate.
fn defined_in(sym: &str, krate: &str) -> bool {
    let tagged = format!("{}{krate}", krate.len());
    if let Some(rest) = sym.strip_prefix("_ZN").or_else(|| sym.strip_prefix("__ZN")) {
        return rest.starts_with(&tagged);
    }
    let Some(v0) = sym.strip_prefix("_R").or_else(|| sym.strip_prefix("__R")) else {
        // Not a mangled name (e.g. a data symbol or a demangled path): be strict.
        return sym.contains(&format!("{krate}::")) || sym == krate;
    };
    let b = v0.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'C' {
            let mut j = i + 1;
            if b.get(j) == Some(&b's') {
                while j < b.len() && b[j] != b'_' {
                    j += 1;
                }
                j += 1;
            }
            let digits = b[j.min(b.len())..].iter().take_while(|c| c.is_ascii_digit()).count();
            if digits > 0 {
                let len: usize = v0[j..j + digits].parse().unwrap_or(0);
                let name = v0.get(j + digits..j + digits + len).unwrap_or("");
                return name == krate;
            }
        }
        i += 1;
    }
    false
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Release-builds every portable cdylib (plus bindings/ov-wasm) for wasm32 and reports sizes.
fn size() -> Result {
    let cdylibs = wasm_cdylibs()?;
    if cdylibs.is_empty() {
        println!("\n==> size: no wasm cdylibs");
        return Ok(());
    }
    wasm_release_build("size: release wasm32 build", &cdylibs, &[])?;

    let out_dir = target_root().join(WASM_TARGET).join("release");
    println!("\n{:<32} {:>12} {:>12}", "wasm size report", "raw bytes", "gzip -9");
    for name in &cdylibs {
        let file = out_dir.join(format!("{}.wasm", name.replace('-', "_")));
        let bytes = fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(&bytes).map_err(|e| e.to_string())?;
        let gz = gz.finish().map_err(|e| e.to_string())?;
        println!("{:<32} {:>12} {:>12}", format!("{name}.wasm"), bytes.len(), gz.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{defined_in, symbols_mentioning};

    const K: &str = "crypto_bigint";

    #[test]
    fn generic_code_instantiated_by_the_crate_is_not_its_code() {
        // The false positive W1-BW and W2-A hit: subtle::black_box::<u8>, instantiating crate crypto_bigint.
        assert!(!defined_in("_RINvCs6rnVIDpdKnr_6subtle9black_boxhECs7c5HtyA5TvT_13crypto_bigint", K));
        assert!(!defined_in("_RNvCs6rnVIDpdKnr_6subtle9black_box", K));
        assert!(!defined_in("_ZN6subtle9black_box17h0123456789abcdefE", K));
    }

    #[test]
    fn functions_defined_in_the_crate_are_found() {
        assert!(defined_in("_ZN13crypto_bigint4uint3add17h0123456789abcdefE", K));
        assert!(defined_in("_RNvNtNtCs1a2b3c_13crypto_bigint4uint3add7add_mod", K));
        assert!(defined_in("_RNvMs_NtCs1a2b3c_13crypto_bigint4uintINtB4_4UintKj4_E7add_mod", K)); // inherent impl
        assert!(defined_in("_RNvXs0_NtCs1a2b3c_13crypto_bigint4limbNtB5_4LimbNtNtCsX_4core3ops3Add3add", K)); // trait impl
        assert!(defined_in("_RNvNtC13crypto_bigint4limb3add", K)); // crate root without disambiguator
        assert!(defined_in("crypto_bigint::uint::Uint::add", K)); // already demangled
    }

    #[test]
    fn symbols_are_cut_at_non_printable_bytes() {
        let bytes = b"\x00\x05_RNvNtCs1_13crypto_bigint4limb3add\x01\x02other\x00_RINvCs2_6subtle9black_boxhECs3_13crypto_bigint\x00";
        let syms = symbols_mentioning(bytes, K);
        assert_eq!(syms.len(), 2);
        assert_eq!(syms.iter().filter(|s| defined_in(s, K)).count(), 1);
    }
}
