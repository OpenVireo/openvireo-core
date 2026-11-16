//! Build and check tasks for the openvireo-core workspace. Run `cargo xtask help`.

use std::env;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// One module per task-owned command (W1-BW wasm, W1-BS xcframework, W1-BC cpp, W1-P openapi).
mod cpp;
mod openapi;
mod wasm;
mod xcframework;

const WASM_TARGET: &str = "wasm32-unknown-unknown";
const IOS_TARGETS: [&str; 3] = ["aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios"];

const HELP: &str = "\
cargo xtask <command>

Commands:
  ci            fmt, clippy -D warnings, test, cargo deny, vectors, wasm32 + iOS builds, size report
  vectors       verify every checksum listed in vectors/**/SOURCE.md
  size          build the wasm32 cdylibs in release and print raw + gzip sizes
  unlinked      check that crates with ignored advisories link no code into the wasm cdylibs
  wasm          build the @openvireo/core-wasm package          (W1-BW)
  xcframework   build OpenVireoCore.xcframework                  (W1-BS)
  cpp           build the C++ static libs + headers              (W1-BC)
  openapi       round-trip every OpenAPI example through ov-protocol (W1-P)

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
        Some("openapi") => openapi::run(&args[1..]),
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
    run("deny", cargo().args(["deny", "--locked", "check"]))?;
    vectors()?;

    let portable = portable_packages()?;
    let mut wasm = portable.clone();
    wasm.extend(existing_packages(&["ov-wasm"])?);
    build_for("wasm32 build", &wasm, &[WASM_TARGET])?;

    if cfg!(target_os = "macos") {
        let mut ios = portable;
        ios.extend(existing_packages(&["ov-ffi-swift"])?);
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
    let target_dir = root().join("target").join("symbols");
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
            if contains(&bytes, krate.as_bytes()) {
                return Err(format!(
                    "{name}.wasm links code from `{krate}`, so the deny.toml ignore of {advisory} no longer holds"
                ));
            }
        }
        println!("{name}.wasm: no code from {}", UNLINKED_CRATES.map(|(k, _)| k).join(", "));
    }
    Ok(())
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

    let out_dir = root().join("target").join(WASM_TARGET).join("release");
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
