//! `cargo xtask wasm`: build the @openvireo/core-wasm package. Owned by W1-BW (only that task edits this file).
//!
//! The package holds two modules: **full** (`ov-wasm`: the facade and every low-level export) and
//! **lite** (`ov-wasm-lite`: primitives, share links and TOTP, for the public share page).
//!
//! Steps:
//! 1. release-build `ov-wasm` and `ov-wasm-lite` for wasm32 (symbols kept, so wasm-bindgen can see
//!    the target features; wasm-opt strips them later), in `$CARGO_TARGET_DIR/wasm-pkg` (default
//!    `target/wasm-pkg`) so `xtask size` keeps its cache;
//! 2. `wasm-bindgen --target web` for each (the CLI must be exactly the `wasm-bindgen` crate's
//!    version): full into `gen/`, lite into `gen/lite/`;
//! 3. `wasm-opt -Oz` on each, stripping debug info and producers;
//! 4. assemble `bindings/ov-wasm/pkg/`: the `npm/` template (loaders, OvError, host adapters,
//!    `.d.ts`), the glue, the `.wasm` files, and a `wasm-base64.js` next to each (the module as
//!    base64, which the loaders use by default, like the SDK's opaque module);
//! 5. print the size report (raw and gzip -9) of both modules before and after wasm-opt.
//!
//! Options: `--skip-opt` (no wasm-opt, for quick iterations).

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use crate::{cargo, root, Result, WASM_TARGET};

/// wasm32 features Rust's wasm32-unknown-unknown target enables by default; wasm-opt must accept them.
const WASM_FEATURES: [&str; 6] = [
    "--enable-bulk-memory",
    "--enable-mutable-globals",
    "--enable-nontrapping-float-to-int",
    "--enable-sign-ext",
    "--enable-reference-types",
    "--enable-multivalue",
];

/// One module of the package: the crate, its wasm-bindgen out-name and its folder under `pkg/`.
struct Module {
    label: &'static str,
    package: &'static str,
    out_name: &'static str,
    dir: &'static str,
}

const MODULES: [Module; 2] = [
    Module { label: "full", package: "ov-wasm", out_name: "ov_wasm", dir: "gen" },
    Module { label: "lite", package: "ov-wasm-lite", out_name: "ov_wasm_lite", dir: "gen/lite" },
];

/// Sizes of one module: wasm-bindgen output, after wasm-opt, and the JS glue.
struct Sizes {
    label: &'static str,
    before: Vec<u8>,
    after: Vec<u8>,
    glue: Vec<u8>,
}

pub fn run(args: &[String]) -> Result {
    let mut skip_opt = false;
    for a in args {
        match a.as_str() {
            "--skip-opt" => skip_opt = true,
            other => return Err(format!("wasm: unknown option `{other}` (options: --skip-opt)")),
        }
    }

    let root = root();
    let crate_dir = root.join("bindings").join("ov-wasm");
    let pkg = crate_dir.join("pkg");
    let target_dir = target_root(&root).join("wasm-pkg");
    let target_dir_s = target_dir.to_str().ok_or("non-UTF-8 target dir")?;

    check_wasm_bindgen_version(&root)?;

    let mut build = cargo();
    build.args(["build", "--locked", "--release", "--target", WASM_TARGET]);
    for m in &MODULES {
        build.args(["-p", m.package]);
    }
    crate::run(
        "wasm: release wasm32 build of ov-wasm and ov-wasm-lite",
        build.args(["--config", "profile.release.strip=false", "--target-dir", target_dir_s]),
    )?;

    if pkg.exists() {
        fs::remove_dir_all(&pkg).map_err(|e| format!("{}: {e}", pkg.display()))?;
    }
    copy_dir(&crate_dir.join("npm"), &pkg)?;

    let mut sizes = Vec::new();
    for m in &MODULES {
        let built = target_dir.join(WASM_TARGET).join("release").join(format!("{}.wasm", m.package.replace('-', "_")));
        sizes.push(module(m, &built, &pkg.join(m.dir), skip_opt)?);
    }

    // The package version follows the crate's.
    let manifest = pkg.join("package.json");
    let text = fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let text = text.replace("\"0.0.0-template\"", &format!("\"{}\"", env!("CARGO_PKG_VERSION")));
    fs::write(&manifest, text).map_err(|e| e.to_string())?;

    println!("\n{:<38} {:>12} {:>12}", "wasm package size report", "raw bytes", "gzip -9");
    for s in &sizes {
        let name = format!("{}_bg.wasm", if s.label == "full" { "ov_wasm" } else { "ov_wasm_lite" });
        println!(
            "{:<38} {:>12} {:>12}",
            format!("{} {name} (wasm-bindgen)", s.label),
            s.before.len(),
            gzip_len(&s.before)?
        );
        println!("{:<38} {:>12} {:>12}", format!("{} {name} (final)", s.label), s.after.len(), gzip_len(&s.after)?);
        println!("{:<38} {:>12} {:>12}", format!("{} glue .js", s.label), s.glue.len(), gzip_len(&s.glue)?);
        let b64 = base64(&s.after);
        println!(
            "{:<38} {:>12} {:>12}",
            format!("{} wasm-base64.js (embedded)", s.label),
            b64.len() + 18,
            gzip_len(b64.as_bytes())?
        );
    }
    println!("\npackage: {}", pkg.display());
    Ok(())
}

/// wasm-bindgen, wasm-opt and the base64 copy for one module, into `out` (`gen/` or `gen/lite/`).
fn module(m: &Module, built: &Path, out: &Path, skip_opt: bool) -> Result<Sizes> {
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    crate::run(
        &format!("wasm: wasm-bindgen --target web ({})", m.label),
        Command::new("wasm-bindgen")
            .args(["--target", "web", "--out-name", m.out_name, "--out-dir"])
            .arg(out)
            .arg(built),
    )?;

    let bg = out.join(format!("{}_bg.wasm", m.out_name));
    let before = fs::read(&bg).map_err(|e| format!("{}: {e}", bg.display()))?;
    if skip_opt {
        println!("\n==> wasm: wasm-opt skipped (--skip-opt)");
    } else {
        let opt = out.join(format!("{}_bg.opt.wasm", m.out_name));
        crate::run(
            &format!("wasm: wasm-opt -Oz ({})", m.label),
            Command::new("wasm-opt")
                .arg("-Oz")
                .args(WASM_FEATURES)
                .args(["--strip-debug", "--strip-producers", "-o"])
                .arg(&opt)
                .arg(&bg),
        )
        .map_err(|e| format!("{e} (install binaryen: `brew install binaryen`)"))?;
        fs::rename(&opt, &bg).map_err(|e| e.to_string())?;
    }
    let after = fs::read(&bg).map_err(|e| format!("{}: {e}", bg.display()))?;

    // The module as base64 in an ES module, so the loaders work the same in Node, browsers,
    // bundlers and Bun without resolving a .wasm path.
    let b64 = base64(&after);
    fs::write(out.join("wasm-base64.js"), format!("export default \"{b64}\";\n")).map_err(|e| e.to_string())?;
    fs::write(out.join("wasm-base64.d.ts"), "declare const wasm: string;\nexport default wasm;\n")
        .map_err(|e| e.to_string())?;
    let glue = fs::read(out.join(format!("{}.js", m.out_name))).map_err(|e| e.to_string())?;
    Ok(Sizes { label: m.label, before, after, glue })
}

/// `$CARGO_TARGET_DIR` (relative to the workspace root when relative), else `<root>/target`.
fn target_root(root: &Path) -> std::path::PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(d) if !d.is_empty() => root.join(d),
        _ => root.join("target"),
    }
}

/// The CLI must match the `wasm-bindgen` crate in Cargo.lock exactly, or the glue is incompatible.
fn check_wasm_bindgen_version(root: &Path) -> Result {
    let lock = fs::read_to_string(root.join("Cargo.lock")).map_err(|e| format!("Cargo.lock: {e}"))?;
    let locked = lock
        .split("[[package]]")
        .find(|p| p.contains("name = \"wasm-bindgen\"\n"))
        .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = \"")))
        .map(|v| v.trim_end_matches('"').to_string())
        .ok_or("Cargo.lock has no wasm-bindgen")?;
    let out = Command::new("wasm-bindgen").arg("--version").output().map_err(|e| {
        format!("wasm-bindgen CLI not found ({e}); run `cargo install wasm-bindgen-cli --version {locked} --locked`")
    })?;
    let have = String::from_utf8_lossy(&out.stdout);
    let have = have.split_whitespace().nth(1).unwrap_or_default();
    if have != locked {
        return Err(format!(
            "wasm-bindgen CLI is {have}, Cargo.lock has {locked}; run `cargo install wasm-bindgen-cli --version {locked} --locked`"
        ));
    }
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> Result {
    fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for entry in fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let dest = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &dest)?;
        } else {
            fs::copy(&path, &dest).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    Ok(())
}

fn gzip_len(bytes: &[u8]) -> Result<usize> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(bytes).map_err(|e| e.to_string())?;
    Ok(gz.finish().map_err(|e| e.to_string())?.len())
}

/// Standard base64 with padding (no xtask dependency needed for this).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_rfc4648() {
        for (input, want) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(super::base64(input.as_bytes()), want);
        }
    }
}
