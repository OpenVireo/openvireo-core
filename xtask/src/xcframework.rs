//! `cargo xtask xcframework`: build OpenVireoCore.xcframework. Owned by W1-BS (only that task edits this file).
//!
//! 1. Release-builds `bindings/ov-ffi` as a static library for iOS (arm64), the iOS
//!    simulator (arm64 + x86_64) and macOS (arm64 + x86_64, for `swift test`).
//! 2. Builds the crate for the host in debug and runs its `uniffi-bindgen` (feature `cli`) on that
//!    dylib, which still has the UniFFI metadata symbols that the stripped release builds lose.
//!    This writes the Swift module `OpenVireoRustCore` and the C module `OpenVireoRustCoreFFI`.
//! 3. `lipo`s the simulator and macOS slices and runs `xcodebuild -create-xcframework`, with the
//!    header and module map under `Headers/OpenVireoRustCoreFFI/` (the layout the iOS app's other
//!    xcframeworks use, so module maps don't collide).
//!
//! Outputs (gitignored), under `bindings/ov-ffi/`:
//! - `build/OpenVireoCore.xcframework`
//! - `Sources/OpenVireoRustCore/OpenVireoRustCore.swift`
//!
//! Flags:
//! - `--test-server`: builds with the crate's `test-server` feature (the `opaque_server_*` steps the
//!   iOS test servers use). Release builds leave it off.
//! - `--macos-only`: builds only the macOS slice (enough for `swift test`; saves disk and time).
//! - `--smoke`: then runs `swift test` in `bindings/ov-ffi/SmokeTests`. Implies `--test-server`,
//!   because the smoke tests replay the OPAQUE transcript through the server steps.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{cargo, root, run as step, Result};

const PACKAGE: &str = "ov-ffi";
const LIB: &str = "libov_ffi";
const FFI_MODULE: &str = "OpenVireoRustCoreFFI";
const SWIFT_MODULE: &str = "OpenVireoRustCore";
const XCFRAMEWORK: &str = "OpenVireoCore.xcframework";

const IOS: &str = "aarch64-apple-ios";
const SIM: [&str; 2] = ["aarch64-apple-ios-sim", "x86_64-apple-ios"];
const MACOS: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];

pub fn run(args: &[String]) -> Result {
    let mut smoke = false;
    let mut test_server = false;
    let mut macos_only = false;
    for a in args {
        match a.as_str() {
            "--smoke" => smoke = true,
            "--test-server" => test_server = true,
            "--macos-only" => macos_only = true,
            other => {
                return Err(format!("xcframework: unknown argument `{other}` (--smoke, --test-server, --macos-only)"))
            }
        }
    }
    test_server |= smoke;
    if !cfg!(target_os = "macos") {
        return Err("xcframework needs a macOS host with Xcode".into());
    }
    let targets: Vec<&str> =
        if macos_only { MACOS.to_vec() } else { std::iter::once(IOS).chain(SIM).chain(MACOS).collect() };
    check_targets(&targets)?;
    // The static libraries and the bindgen dylib must have the same features, or the generated
    // Swift calls symbols the libraries lack.
    let features: &[&str] = if test_server { &["--features", "test-server"] } else { &[] };

    let crate_dir = root().join("bindings").join(PACKAGE);
    let build = crate_dir.join("build");
    let target = target_dir();

    // 1. Static libraries.
    let mut cmd = cargo();
    cmd.args(["build", "--locked", "--release", "--lib", "-p", PACKAGE]).args(features);
    for t in &targets {
        cmd.args(["--target", t]);
    }
    let what = if macos_only { "macos" } else { "ios, ios-sim, macos" };
    step(&format!("xcframework: release static libraries ({what})"), &mut cmd)?;

    // 2. Swift sources from the host debug dylib.
    step(
        "xcframework: host debug build for bindgen",
        cargo().args(["build", "--locked", "--lib", "-p", PACKAGE]).args(features),
    )?;
    let dylib = target.join("debug").join(format!("{LIB}.dylib"));
    let swift_out = build.join("swift");
    reset_dir(&swift_out)?;
    step(
        "xcframework: uniffi-bindgen (Swift)",
        cargo()
            .args(["run", "--locked", "-q", "-p", PACKAGE, "--bin", "uniffi-bindgen"])
            .args(["--features", if test_server { "cli,test-server" } else { "cli" }, "--"])
            .args(["generate", "--language", "swift", "--metadata-no-deps", "--out-dir"])
            .arg(&swift_out)
            .arg(&dylib),
    )?;

    let headers = build.join("include");
    reset_dir(&headers)?;
    let module_headers = headers.join(FFI_MODULE);
    fs::create_dir_all(&module_headers).map_err(|e| e.to_string())?;
    copy(&swift_out.join(format!("{FFI_MODULE}.h")), &module_headers.join(format!("{FFI_MODULE}.h")))?;
    copy(&swift_out.join(format!("{FFI_MODULE}.modulemap")), &module_headers.join("module.modulemap"))?;
    let sources = crate_dir.join("Sources").join(SWIFT_MODULE);
    copy(&swift_out.join(format!("{SWIFT_MODULE}.swift")), &sources.join(format!("{SWIFT_MODULE}.swift")))?;

    // 3. Fat slices and the xcframework.
    let lib = |t: &str| target.join(t).join("release").join(format!("{LIB}.a"));
    let fat = build.join("lib");
    reset_dir(&fat)?;
    let mac = lipo(&fat.join("macos"), &MACOS.map(lib))?;
    let slices =
        if macos_only { vec![mac] } else { vec![lib(IOS), lipo(&fat.join("ios-simulator"), &SIM.map(lib))?, mac] };

    let out = build.join(XCFRAMEWORK);
    if out.exists() {
        fs::remove_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    }
    let mut x = Command::new("xcrun");
    x.arg("xcodebuild").arg("-create-xcframework");
    for l in slices {
        x.arg("-library").arg(l).arg("-headers").arg(&headers);
    }
    x.arg("-output").arg(&out);
    step("xcframework: xcodebuild -create-xcframework", &mut x)?;

    println!("\n{:<48} {:>12}", "xcframework size report", "bytes");
    for entry in fs::read_dir(&out).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.is_dir() {
            println!("{:<48} {:>12}", format!("  {}", p.file_name().unwrap().to_string_lossy()), dir_size(&p)?);
        }
    }
    println!("{:<48} {:>12}", XCFRAMEWORK, dir_size(&out)?);
    println!("\nwrote {}\nwrote {}", out.display(), sources.join(format!("{SWIFT_MODULE}.swift")).display());
    println!(
        "slices: {}; feature test-server: {}",
        if macos_only { "macos only" } else { "ios, ios-sim, macos" },
        if test_server { "on" } else { "off" }
    );

    if smoke {
        let mut t = Command::new("swift");
        t.arg("test").current_dir(crate_dir.join("SmokeTests"));
        step("xcframework: swift test (SmokeTests, macOS)", &mut t)?;
    }
    Ok(())
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| root().join("target"))
}

/// Fails early, with the fix, when a Rust target isn't installed.
fn check_targets(targets: &[&str]) -> Result {
    let out = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .current_dir(root())
        .output()
        .map_err(|e| format!("rustup: {e}"))?;
    let installed = String::from_utf8_lossy(&out.stdout);
    let missing: Vec<&str> = targets.iter().copied().filter(|t| !installed.lines().any(|l| l.trim() == *t)).collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("missing Rust targets; run `rustup target add {}`", missing.join(" ")))
    }
}

fn lipo(dir: &Path, inputs: &[PathBuf]) -> Result<PathBuf> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let out = dir.join(format!("{LIB}.a"));
    let mut cmd = Command::new("xcrun");
    cmd.arg("lipo").arg("-create").args(inputs).arg("-output").arg(&out);
    step(&format!("xcframework: lipo {}", dir.file_name().unwrap().to_string_lossy()), &mut cmd)?;
    Ok(out)
}

fn reset_dir(dir: &Path) -> Result {
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

fn copy(from: &Path, to: &Path) -> Result {
    fs::copy(from, to).map(|_| ()).map_err(|e| format!("copy {} -> {}: {e}", from.display(), to.display()))
}

fn dir_size(dir: &Path) -> Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        total += if meta.is_dir() { dir_size(&entry.path())? } else { meta.len() };
    }
    Ok(total)
}
