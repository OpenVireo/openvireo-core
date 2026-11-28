//! `cargo xtask cpp`: build the C++ static libs + headers. Owned by W1-BC (only that task edits this file).
//!
//! ```text
//! cargo xtask cpp [--target <triple>]... [--out <dir>] [--debug] [--features <list>]
//! cargo xtask cpp --check-coverage
//! ```
//!
//! `--check-coverage` builds nothing: it runs `bindings/ov-ffi-cpp/tests/coverage.rs`, which lists
//! every public method and free function of `ov_core::api` without a bridged C++ function, and
//! fails unless there are none.
//!
//! Builds `bindings/ov-ffi-cpp` as a static library and lays out one CMake package per target:
//!
//! ```text
//! <out>/<target>/include/ovcore.h, rust/cxx.h, ov-ffi-cpp/...
//! <out>/<target>/lib/libovcore.a            (ovcore.lib for *-windows-msvc)
//! <out>/<target>/lib/cmake/OpenVireoCore/OpenVireoCoreConfig.cmake (+ ConfigVersion)
//! ```
//!
//! `--features test-server` builds the test-only OPAQUE server and seeded steps in (never for a
//! release); the package records its features in `OpenVireoCore_FEATURES`.
//!
//! `<out>` defaults to `<cargo target dir>/ovcore-cpp` (`CARGO_TARGET_DIR` is honoured). `--target universal-apple-darwin` builds
//! aarch64-apple-darwin and x86_64-apple-darwin and joins them with `lipo` (macOS hosts only).
//! Without `--target`, it builds `universal-apple-darwin` on macOS and the host triple elsewhere.
//! Release targets: universal-apple-darwin, x86_64-pc-windows-msvc, aarch64-pc-windows-msvc,
//! x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu (each needs its toolchain: a C++ compiler
//! for the target and `rustup target add <triple>`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{cargo, metadata, root, Result};

const UNIVERSAL_MACOS: &str = "universal-apple-darwin";
const MACOS_TARGETS: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
/// The oldest macOS the desktop supports (override with MACOSX_DEPLOYMENT_TARGET).
const MACOS_DEPLOYMENT_TARGET: &str = "11.0";
const PACKAGE: &str = "ov-ffi-cpp";
const CRATE_LIB: &str = "ov_ffi_cpp";
const TEMPLATES: &str = "bindings/ov-ffi-cpp/cmake";

struct Options {
    targets: Vec<String>,
    out: PathBuf,
    release: bool,
    /// Cargo features of ov-ffi-cpp, comma-separated (empty: none).
    features: String,
}

pub fn run(args: &[String]) -> Result {
    if args.iter().any(|a| a == "--check-coverage") {
        if args.len() != 1 {
            return Err("--check-coverage takes no other arguments".into());
        }
        return check_coverage();
    }
    let opts = parse(args)?;
    let version = core_version()?;
    for target in &opts.targets {
        let pkg = opts.out.join(target);
        if pkg.exists() {
            fs::remove_dir_all(&pkg).map_err(|e| format!("{}: {e}", pkg.display()))?;
        }
        let include = pkg.join("include");
        let lib_dir = pkg.join("lib");
        fs::create_dir_all(&lib_dir).map_err(|e| format!("{}: {e}", lib_dir.display()))?;

        let (lib_file, native) = if target == UNIVERSAL_MACOS {
            if !cfg!(target_os = "macos") {
                return Err(format!("{UNIVERSAL_MACOS} needs a macOS host (lipo)"));
            }
            let mut slices = Vec::new();
            let mut native = Vec::new();
            for t in MACOS_TARGETS {
                let (lib, libs) = build(t, &include, &opts)?;
                slices.push(lib);
                native = libs;
            }
            let dest = lib_dir.join("libovcore.a");
            let mut lipo = Command::new("lipo");
            lipo.arg("-create").args(&slices).arg("-output").arg(&dest);
            crate::run("lipo -create", &mut lipo)?;
            ("libovcore.a".to_string(), native)
        } else {
            let (lib, native) = build(target, &include, &opts)?;
            let name = if target.ends_with("-msvc") { "ovcore.lib" } else { "libovcore.a" };
            fs::copy(&lib, lib_dir.join(name)).map_err(|e| format!("{}: {e}", lib.display()))?;
            (name.to_string(), native)
        };

        write_cmake_package(&pkg, target, &lib_file, &native, &version, &opts)?;
        println!("\nOpenVireoCore {version} for {target}: {}", pkg.display());
        println!("  CMake: -DOpenVireoCore_DIR={}", pkg.join("lib/cmake/OpenVireoCore").display());
    }
    Ok(())
}

/// Runs the bridge coverage test with its report printed.
fn check_coverage() -> Result {
    let mut cmd = cargo();
    cmd.args(["test", "--locked", "-p", PACKAGE, "--test", "coverage", "--", "--nocapture", "--test-threads=1"]);
    crate::run("bridge coverage (ov_core::api vs bindings/ov-ffi-cpp/src/lib.rs)", &mut cmd)
}

fn parse(args: &[String]) -> Result<Options> {
    let mut targets = Vec::new();
    let mut out = target_dir()?.join("ovcore-cpp");
    let mut release = true;
    let mut features = String::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" => targets.push(it.next().ok_or("--target needs a triple")?.clone()),
            "--out" => {
                let p = PathBuf::from(it.next().ok_or("--out needs a directory")?);
                out = if p.is_absolute() { p } else { env::current_dir().map_err(|e| e.to_string())?.join(p) };
            }
            "--debug" => release = false,
            "--features" => features = it.next().ok_or("--features needs a list (e.g. test-server)")?.clone(),
            "-h" | "--help" => {
                return Err(
                    "usage: cargo xtask cpp [--target <triple>]... [--out <dir>] [--debug] [--features <list>]\n\
                     \x20      cargo xtask cpp --check-coverage\n\
                     targets: universal-apple-darwin (macOS host), x86_64/aarch64-pc-windows-msvc,\n\
                     x86_64/aarch64-unknown-linux-gnu, or any triple rustup knows"
                        .into(),
                )
            }
            other => return Err(format!("cpp: unknown argument `{other}` (try --help)")),
        }
    }
    if targets.is_empty() {
        targets.push(if cfg!(target_os = "macos") { UNIVERSAL_MACOS.to_string() } else { host_triple()? });
    }
    Ok(Options { targets, out, release, features })
}

/// Cargo's target directory (`CARGO_TARGET_DIR` or `build.target-dir` aware).
fn target_dir() -> Result<PathBuf> {
    metadata()?["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| "cargo metadata has no target_directory".into())
}

fn host_triple() -> Result<String> {
    let out = Command::new("rustc").arg("-vV").output().map_err(|e| format!("rustc -vV: {e}"))?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_string))
        .ok_or_else(|| "rustc -vV printed no host triple".into())
}

fn core_version() -> Result<String> {
    let meta = metadata()?;
    meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"] == "openvireo-core")
        .and_then(|p| p["version"].as_str())
        .map(str::to_string)
        .ok_or_else(|| "cargo metadata has no openvireo-core".into())
}

/// Builds the static library for one triple, exporting the headers to `include`. Returns the
/// library path and the system libraries it needs (`rustc --print native-static-libs`).
fn build(target: &str, include: &Path, opts: &Options) -> Result<(PathBuf, Vec<String>)> {
    let release = opts.release;
    let mut cmd = cargo();
    cmd.args(["rustc", "--locked", "-p", PACKAGE, "--lib", "--crate-type", "staticlib", "--target", target]);
    // The native-static-libs line is parsed below: no colour codes in it (CI sets CARGO_TERM_COLOR=always)
    cmd.args(["--color", "never"]);
    if release {
        cmd.arg("--release");
    }
    if !opts.features.is_empty() {
        cmd.args(["--features", &opts.features]);
    }
    cmd.args(["--", "--print", "native-static-libs"]);
    cmd.env("OV_CXX_INCLUDE_DIR", include);
    // One macOS floor for the Rust and the C++ (cc) objects; otherwise cc uses the SDK version.
    if target.contains("-apple-darwin") && env::var_os("MACOSX_DEPLOYMENT_TARGET").is_none() {
        cmd.env("MACOSX_DEPLOYMENT_TARGET", MACOS_DEPLOYMENT_TARGET);
    }

    let step = format!("cargo rustc {PACKAGE} --target {target}");
    println!("\n==> {step}");
    let out = cmd.output().map_err(|e| format!("{step}: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprint!("{stderr}");
    if !out.status.success() {
        return Err(format!(
            "{step} failed ({}). Is the target installed (`rustup target add {target}`) and a C++ compiler for it on PATH?",
            out.status
        ));
    }

    let profile_dir = target_dir()?.join(target).join(if release { "release" } else { "debug" });
    let lib = profile_dir.join(if target.ends_with("-msvc") {
        format!("{CRATE_LIB}.lib")
    } else {
        format!("lib{CRATE_LIB}.a")
    });
    if !lib.exists() {
        return Err(format!("{step}: no {}", lib.display()));
    }

    // rustc prints the list only when it actually compiles the crate, so keep the last one seen.
    let cache = profile_dir.join("ovcore-native-static-libs.txt");
    let native = match stderr.lines().find_map(|l| l.split_once("native-static-libs: ").map(|(_, v)| v.trim())) {
        Some(list) => {
            fs::write(&cache, list).map_err(|e| format!("{}: {e}", cache.display()))?;
            list.to_string()
        }
        None => fs::read_to_string(&cache).map_err(|_| {
            format!("{step}: no native-static-libs printed and none cached; run `cargo clean -p {PACKAGE}`")
        })?,
    };
    Ok((lib, native_libs(&native)))
}

/// Linker items for CMake, in rustc's order (repeats can matter for static linking). Drops MSVC
/// `/defaultlib:` switches, since CMake picks the CRT.
fn native_libs(list: &str) -> Vec<String> {
    list.split_whitespace().filter(|item| !item.starts_with('/')).map(str::to_string).collect()
}

fn write_cmake_package(
    pkg: &Path,
    target: &str,
    lib_file: &str,
    native: &[String],
    version: &str,
    opts: &Options,
) -> Result {
    let release = opts.release;
    if !pkg.join("include/ovcore.h").exists() {
        return Err(format!("{}: the build exported no headers", pkg.join("include").display()));
    }
    let dir = pkg.join("lib/cmake/OpenVireoCore");
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let major = version.split('.').next().unwrap_or("0");
    let fill = |name: &str| -> Result<String> {
        let path = root().join(TEMPLATES).join(name);
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(text
            .replace("@TARGET@", target)
            .replace("@PROFILE@", if release { "release" } else { "debug" })
            .replace("@LIB_FILE@", lib_file)
            .replace("@NATIVE_LIBS@", &native.join(";"))
            .replace("@FEATURES@", &opts.features.replace(',', ";"))
            .replace("@VERSION_MAJOR@", major)
            .replace("@VERSION@", version))
    };
    for (template, file) in [
        ("OpenVireoCoreConfig.cmake.in", "OpenVireoCoreConfig.cmake"),
        ("OpenVireoCoreConfigVersion.cmake.in", "OpenVireoCoreConfigVersion.cmake"),
    ] {
        let path = dir.join(file);
        fs::write(&path, fill(template)?).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::native_libs;

    #[test]
    fn native_libs_keep_order_and_drop_switches() {
        assert_eq!(native_libs("-lc -lm -liconv -lc -lm"), ["-lc", "-lm", "-liconv", "-lc", "-lm"]);
        assert_eq!(native_libs("kernel32.lib /defaultlib:msvcrt bcrypt.lib"), ["kernel32.lib", "bcrypt.lib"]);
    }
}
