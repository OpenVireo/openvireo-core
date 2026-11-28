//! `cargo xtask release`: build every release artifact this host can build, under its final name,
//! plus `SHA256SUMS`. Owned by W4-R (only that task edits this file). `.github/workflows/release.yml`
//! runs it once per runner, signs the `ov` executables, then packs, verifies and publishes.
//!
//! ```text
//! cargo xtask release [--dry-run] [--out <dir>] [--only <kinds>] [--unpacked]
//!                      [--natives <dir>] [--jni-libs <dir>]
//! cargo xtask release pack <dir>
//! cargo xtask release verify <dir> [--dry-run]
//! cargo xtask release jvm-native <rust target> <dir>
//! cargo xtask release publish-maven <release dir> --natives <dir> --jni-libs <dir> [--to github|central]
//!                                    [--skip jvm|android]...
//! ```
//!
//! Kinds (`--only wasm,cpp`; default: every kind the host can build):
//! - `wasm`: `openvireo-core-wasm-<v>.tgz`, the `npm pack` of `@openvireo/core-wasm` (one package
//!   with the full and the lite module, as the SDK consumes it today), ready to publish (GitHub
//!   Packages; npmjs.com too once the SDK goes there).
//! - `xcframework` (macOS only): `OpenVireoCore.xcframework.zip`, its SwiftPM checksum in
//!   `OpenVireoCore.xcframework.zip.checksum`, and `OpenVireoRustCore.swift`, the UniFFI Swift
//!   source that goes with it, with the hand-written `OvError+Fields.swift` (`error.code`, ...)
//!   appended so a consumer adds one file.
//! - `cpp`: `libovcore-<v>-<platform>.tar.gz` (`.zip` on Windows), the `cargo xtask cpp` CMake
//!   package (headers, static library, `OpenVireoCoreConfig.cmake`) plus the licences.
//! - `ov`: `ov-<v>-<platform>.tar.gz` (`.zip` on Windows) holding `ov-<v>-<platform>/ov` (`ov.exe`),
//!   a README and the licences: the same names as the SDK's release, so installers keep working.
//! - `python`: `openvireo-<pep440>-py3-none-<platform>.whl` for this host and the sdist
//!   `openvireo-<pep440>.tar.gz` (`maturin build --release` / `maturin sdist` in
//!   `bindings/python`). The release workflow builds the wheels with maturin-action instead (the
//!   manylinux/musllinux containers); this kind is the local equivalent. The version is the
//!   workspace version in PEP 440 form ([`pep440`]).
//! - `jvm`: `openvireo-core-jvm-<v>.jar` (`bindings/kotlin`, `:core-jvm:jar`) with the natives in
//!   `--natives <dir>` (JNA's layout, every slice of [`NATIVE_SLICES`] required), or without it a
//!   release build of the host slice only (a local dry run). With `--jni-libs <dir>`
//!   (`<abi>/libov_ffi.so` from cargo-ndk) also `openvireo-core-android-<v>.aar`. The Kotlin and
//!   the Java facade are generated from a host debug build (`cargo xtask kotlin --generate-only`),
//!   since the release profile strips UniFFI's metadata.
//!
//! `jvm-native <target> <dir>` builds one jar slice: the release `ov-ffi` cdylib (never
//! `test-server`) for a Rust target in [`NATIVE_SLICES`], copied to `<dir>/<jna prefix>/<file>`.
//! The workflow runs it on each platform's runner and signs the result before `--only jvm`.
//!
//! `publish-maven <release dir>` publishes `com.openvireo:openvireo-core-jvm` and
//! `openvireo-core-android` to GitHub Packages (`./gradlew publish`, `GITHUB_ACTOR` /
//! `GITHUB_TOKEN`): it rebuilds both from the same natives, fails unless they are byte for byte
//! the jar and AAR in `<release dir>` (the verified release assets), then publishes those files.
//! `--skip jvm` / `--skip android` leaves out an artifact that is already published.
//! `--to central` instead writes both to the local Maven repository
//! `bindings/kotlin/build/central-staging` (POMs, Gradle module metadata, sources and javadoc jars and
//! checksums) and uploads nothing: the workflow signs every file there with the release key, zips it and
//! uploads the bundle to the Maven Central Portal.
//!
//! Platforms: a macOS host builds darwin-arm64 and darwin-x64, Linux and Windows their own arch
//! (linux-x64, linux-arm64, windows-x64). On Linux, `ov` is a static musl executable (any distro),
//! needing `rustup target add <arch>-unknown-linux-musl` and musl-gcc (`apt install musl-tools`);
//! libovcore is built for glibc, like the desktop. On Windows, `ov.exe` links the C runtime
//! statically (no VC++ redistributable needed).
//!
//! Without `--dry-run`, the working tree must be clean and HEAD tagged `v<version>`. `--out`
//! (default `<target dir>/release-artifacts`) must be empty or missing. `--unpacked` leaves the
//! `ov-<v>-<platform>/` directories unpacked and writes no `SHA256SUMS`, so the executables can be
//! signed first; `pack <dir>` then archives them and writes `SHA256SUMS` over every file in `<dir>`.
//!
//! `verify <dir>` checks what the host can run: `SHA256SUMS`, then this platform's `ov` archive
//! (`ov version`), its libovcore archive (a CMake consumer built and run with ctest), the
//! xcframework (checksum, and a SwiftPM package over it built and run, on macOS), the npm package
//! (installed and both modules loaded in Node), the Python wheels (every wheel and the sdist carry
//! the version; the one for this host is installed into a fresh venv, imported and checked for the
//! type stubs), the jar (its native slices, then a Java program built against it and run with
//! Gradle) and the AAR (ABIs, classes, 16 KB pages). Outside `--dry-run`, `ov version` must print
//! the release version and the jar must carry every slice.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::kotlin::NATIVE_SLICES;
use crate::{cargo, root, target_root, Result};

/// The workspace version: every artifact carries it, and the release tag must be `v<VERSION>`.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The oldest macOS the binaries run on (the same floor `cargo xtask cpp` uses).
pub(crate) const MACOS_DEPLOYMENT_TARGET: &str = "11.0";
const XCFRAMEWORK: &str = "OpenVireoCore.xcframework";
const SWIFT_SOURCE: &str = "OpenVireoRustCore.swift";
/// Hand-written next to the generated source; the release appends it to `SWIFT_SOURCE`.
const SWIFT_EXTENSIONS: [&str; 1] = ["OvError+Fields.swift"];
const SUMS: &str = "SHA256SUMS";
const LICENCES: [&str; 2] = ["LICENSE-MIT", "LICENSE-APACHE"];
/// SHA-256 of "abc", which every smoke check computes through the core.
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Wasm,
    Xcframework,
    Cpp,
    Ov,
    Python,
    Jvm,
}

impl Kind {
    const ALL: [Kind; 6] = [Kind::Wasm, Kind::Xcframework, Kind::Cpp, Kind::Ov, Kind::Python, Kind::Jvm];

    fn name(self) -> &'static str {
        match self {
            Kind::Wasm => "wasm",
            Kind::Xcframework => "xcframework",
            Kind::Cpp => "cpp",
            Kind::Ov => "ov",
            Kind::Python => "python",
            Kind::Jvm => "jvm",
        }
    }

    fn parse(s: &str) -> Result<Kind> {
        Kind::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or_else(|| format!("release: unknown kind `{s}` (wasm, xcframework, cpp, ov, python, jvm)"))
    }

    fn host_can_build(self) -> bool {
        self != Kind::Xcframework || cfg!(target_os = "macos")
    }
}

struct Options {
    dry_run: bool,
    out: PathBuf,
    kinds: Vec<Kind>,
    unpacked: bool,
    /// `--natives`: the jar's natives in JNA's layout, every slice (else the host slice is built).
    natives: Option<PathBuf>,
    /// `--jni-libs`: the AAR's `<abi>/libov_ffi.so` (else no AAR).
    jni_libs: Option<PathBuf>,
}

const USAGE: &str = "\
usage: cargo xtask release [--dry-run] [--out <dir>] [--only <kinds>] [--unpacked]
                           [--natives <dir>] [--jni-libs <dir>]
       cargo xtask release pack <dir>
       cargo xtask release verify <dir> [--dry-run]
       cargo xtask release jvm-native <rust target> <dir>
       cargo xtask release publish-maven <release dir> --natives <dir> --jni-libs <dir> [--to github|central]
                                         [--skip jvm|android]...
kinds: wasm, xcframework (macOS), cpp, ov, python, jvm (comma-separated; default: all the host can build)";

pub fn run(args: &[String]) -> Result {
    match args.first().map(String::as_str) {
        Some("pack") => match &args[1..] {
            [dir] => pack(&absolute(dir)?),
            _ => Err(USAGE.into()),
        },
        Some("verify") => match &args[1..] {
            [dir] => verify(&absolute(dir)?, false),
            [dir, flag] | [flag, dir] if flag == "--dry-run" => verify(&absolute(dir)?, true),
            _ => Err(USAGE.into()),
        },
        Some("jvm-native") => match &args[1..] {
            [target, dir] => jvm_native(target, &absolute(dir)?),
            _ => Err(USAGE.into()),
        },
        Some("publish-maven") => publish_maven(&args[1..]),
        _ => build(&parse(args)?),
    }
}

fn parse(args: &[String]) -> Result<Options> {
    let mut opts = Options {
        dry_run: false,
        out: target_root().join("release-artifacts"),
        kinds: Vec::new(),
        unpacked: false,
        natives: None,
        jni_libs: None,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dry-run" => opts.dry_run = true,
            "--unpacked" => opts.unpacked = true,
            "--out" => opts.out = absolute(it.next().ok_or("--out needs a directory")?)?,
            "--natives" => opts.natives = Some(absolute(it.next().ok_or("--natives needs a directory")?)?),
            "--jni-libs" => opts.jni_libs = Some(absolute(it.next().ok_or("--jni-libs needs a directory")?)?),
            "--only" => {
                for k in it.next().ok_or("--only needs a list (e.g. cpp,ov)")?.split(',') {
                    let k = Kind::parse(k.trim())?;
                    if !k.host_can_build() {
                        return Err(format!("release: {} needs a macOS host", k.name()));
                    }
                    if !opts.kinds.contains(&k) {
                        opts.kinds.push(k);
                    }
                }
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("release: unknown argument `{other}`\n{USAGE}")),
        }
    }
    if opts.kinds.is_empty() {
        opts.kinds = Kind::ALL.into_iter().filter(|k| k.host_can_build()).collect();
    }
    if (opts.natives.is_some() || opts.jni_libs.is_some()) && !opts.kinds.contains(&Kind::Jvm) {
        return Err("release: --natives and --jni-libs are for the jvm kind".into());
    }
    Ok(opts)
}

fn absolute(p: &str) -> Result<PathBuf> {
    let p = PathBuf::from(p);
    Ok(if p.is_absolute() { p } else { env::current_dir().map_err(|e| e.to_string())?.join(p) })
}

fn build(opts: &Options) -> Result {
    let kinds: Vec<&str> = opts.kinds.iter().map(|k| k.name()).collect();
    println!("==> release {VERSION}: {} into {}", kinds.join(", "), opts.out.display());
    if opts.dry_run {
        println!("dry run: not checking the tree or the tag");
    } else {
        check_release_tree()?;
    }
    check_tools(opts)?;
    if opts.out.exists() && fs::read_dir(&opts.out).map_err(|e| e.to_string())?.next().is_some() {
        return Err(format!("{} is not empty; delete it or pick another --out", opts.out.display()));
    }
    fs::create_dir_all(&opts.out).map_err(|e| format!("{}: {e}", opts.out.display()))?;

    // A fresh work dir each run: `cargo xtask cpp` exports its headers from ov-ffi-cpp's build
    // script, which reruns only when OV_CXX_INCLUDE_DIR changes, so a reused path would come back
    // without headers.
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
    let work = target_root().join("release-work").join(nanos.to_string());
    fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;

    let built = build_kinds(opts, &work);
    if built.is_ok() {
        let _ = fs::remove_dir_all(&work);
    } else {
        eprintln!("release: work dir kept for inspection: {}", work.display());
    }
    built?;

    if opts.unpacked {
        println!("\n==> left ov-{VERSION}-<platform>/ unpacked (--unpacked); `cargo xtask release pack` archives them");
        list(&opts.out)
    } else {
        pack(&opts.out)
    }
}

fn build_kinds(opts: &Options, work: &Path) -> Result {
    for kind in &opts.kinds {
        match kind {
            Kind::Wasm => wasm(&opts.out, work)?,
            Kind::Xcframework => xcframework(&opts.out, work)?,
            Kind::Cpp => cpp(&opts.out, work)?,
            Kind::Ov => ov(&opts.out)?,
            Kind::Python => python(&opts.out)?,
            Kind::Jvm => jvm(opts, work)?,
        }
    }
    Ok(())
}

/// A release comes from a clean checkout of the tagged commit.
fn check_release_tree() -> Result {
    let git = |args: &[&str]| -> Result<String> {
        let out = Command::new("git").args(args).current_dir(root()).output().map_err(|e| format!("git: {e}"))?;
        if !out.status.success() {
            return Err(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let dirty = git(&["status", "--porcelain"])?;
    if !dirty.trim().is_empty() {
        return Err(format!("the working tree has changes (use --dry-run to build anyway):\n{dirty}"));
    }
    let tag = format!("v{VERSION}");
    if !git(&["tag", "--points-at", "HEAD"])?.lines().any(|t| t.trim() == tag) {
        return Err(format!("HEAD is not tagged {tag} (the workspace version is {VERSION}); tag it or use --dry-run"));
    }
    println!("tree clean, HEAD is {tag}");
    Ok(())
}

/// Fails before any long build when a tool or Rust target is missing, with the fix.
fn check_tools(opts: &Options) -> Result {
    let mut targets = Vec::new();
    if opts.kinds.contains(&Kind::Cpp) {
        targets.extend(cpp_targets()?);
    }
    if opts.kinds.contains(&Kind::Ov) {
        targets.extend(ov_targets()?);
    }
    if opts.kinds.contains(&Kind::Xcframework) {
        targets.extend(["aarch64-apple-darwin".to_string(), "x86_64-apple-darwin".to_string()]);
    }
    let out = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .current_dir(root())
        .output()
        .map_err(|e| format!("rustup: {e}"))?;
    let installed = String::from_utf8_lossy(&out.stdout);
    let mut missing: Vec<String> = targets.into_iter().filter(|t| !installed.lines().any(|l| l.trim() == t)).collect();
    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        return Err(format!("missing Rust targets; run `rustup target add {}`", missing.join(" ")));
    }
    if opts.kinds.contains(&Kind::Ov) && cfg!(target_os = "linux") {
        let arch = env::consts::ARCH;
        if !on_path(&format!("{arch}-linux-musl-gcc")) && !on_path("musl-gcc") {
            return Err("ov on Linux is built for musl; install musl-gcc (`sudo apt-get install musl-tools`)".into());
        }
    }
    if opts.kinds.contains(&Kind::Wasm) && !on_path(npm()) {
        return Err("the wasm package is packed with npm; install Node.js".into());
    }
    if opts.kinds.contains(&Kind::Jvm) && !on_path("java") {
        return Err("the jar is built with Gradle; install a JDK 17 or later".into());
    }
    if opts.kinds.contains(&Kind::Python) && !on_path("uv") && !on_path("python3") && !on_path("python") {
        return Err("the wheel is built with maturin in a venv; install uv or Python 3.10+".into());
    }
    Ok(())
}

fn on_path(exe: &str) -> bool {
    let exts: &[&str] = if cfg!(windows) { &["", ".exe", ".cmd"] } else { &[""] };
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|dir| exts.iter().any(|ext| dir.join(format!("{exe}{ext}")).is_file()))
    })
}

fn npm() -> &'static str {
    if cfg!(windows) {
        "npm.cmd"
    } else {
        "npm"
    }
}

/// The release platform name of a Rust target (the SDK's names).
fn platform(target: &str) -> Result<&'static str> {
    Ok(match target {
        "aarch64-apple-darwin" => "darwin-arm64",
        "x86_64-apple-darwin" => "darwin-x64",
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl" => "linux-x64",
        "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" => "linux-arm64",
        "x86_64-pc-windows-msvc" => "windows-x64",
        "aarch64-pc-windows-msvc" => "windows-arm64",
        other => return Err(format!("release: no platform name for {other}")),
    })
}

/// The platform this host runs (what `verify` can execute).
fn host_platform() -> Result<&'static str> {
    let target = match (env::consts::OS, env::consts::ARCH) {
        ("macos", arch) => format!("{arch}-apple-darwin"),
        ("linux", arch) => format!("{arch}-unknown-linux-gnu"),
        ("windows", arch) => format!("{arch}-pc-windows-msvc"),
        (os, arch) => return Err(format!("release: unsupported host {os}/{arch}")),
    };
    platform(&target)
}

fn cpp_targets() -> Result<Vec<String>> {
    let arch = env::consts::ARCH;
    Ok(match env::consts::OS {
        "macos" => vec!["aarch64-apple-darwin".into(), "x86_64-apple-darwin".into()],
        "linux" => vec![format!("{arch}-unknown-linux-gnu")],
        "windows" => vec![format!("{arch}-pc-windows-msvc")],
        os => return Err(format!("release: unsupported host OS {os}")),
    })
}

fn ov_targets() -> Result<Vec<String>> {
    let arch = env::consts::ARCH;
    Ok(match env::consts::OS {
        "linux" => vec![format!("{arch}-unknown-linux-musl")],
        _ => cpp_targets()?,
    })
}

fn is_windows(platform: &str) -> bool {
    platform.starts_with("windows-")
}

// ---- wasm ----------------------------------------------------------------------------------------

fn wasm(out: &Path, work: &Path) -> Result {
    crate::wasm::run(&[])?;
    let pkg = root().join("bindings").join("ov-wasm").join("pkg");
    let stage = work.join("core-wasm");
    copy_dir(&pkg, &stage)?;
    for f in LICENCES {
        copy(&root().join(f), &stage.join(f))?;
    }
    copy(&root().join("bindings").join("ov-wasm").join("README.md"), &stage.join("README.md"))?;

    // The template is private (so a stray `npm publish` from the repo can't happen); the release
    // publishes it.
    let manifest = stage.join("package.json");
    let text = fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let text = publishable_manifest(&text)?;
    fs::write(&manifest, text).map_err(|e| e.to_string())?;

    let mut pack = Command::new(npm());
    pack.args(["pack", "--pack-destination"]).arg(out).current_dir(&stage);
    crate::run("release: npm pack @openvireo/core-wasm", &mut pack)?;
    let tgz = out.join(format!("openvireo-core-wasm-{VERSION}.tgz"));
    if !tgz.is_file() {
        return Err(format!("npm pack wrote no {}", tgz.display()));
    }
    Ok(())
}

/// `pkg/package.json` without `"private": true` (public access instead), at VERSION.
fn publishable_manifest(text: &str) -> Result<String> {
    const PRIVATE: &str = "  \"private\": true,\n";
    if !text.contains(PRIVATE) {
        return Err("bindings/ov-wasm/pkg/package.json: no `\"private\": true,` line to replace".into());
    }
    if !text.contains(&format!("\"version\": \"{VERSION}\"")) {
        return Err(format!("bindings/ov-wasm/pkg/package.json is not at version {VERSION}"));
    }
    // No registry here: the workflow's setup-node picks it, so the same tarball can go to GitHub
    // Packages and npmjs.com (like the SDK's packages).
    let text = text.replace(PRIVATE, "  \"publishConfig\": {\n    \"access\": \"public\"\n  },\n");
    // npm only adds a bare LICENSE by itself, not LICENSE-MIT / LICENSE-APACHE.
    const FILES: &str = "  \"files\": [\n";
    if !text.contains(FILES) {
        return Err("bindings/ov-wasm/pkg/package.json: no `\"files\": [` list".into());
    }
    let text = text.replace(FILES, "  \"files\": [\n    \"LICENSE-MIT\",\n    \"LICENSE-APACHE\",\n");
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("package.json: {e}"))?;
    if json["name"] != "@openvireo/core-wasm" || json.get("private").is_some() {
        return Err("package.json: unexpected name or still private".into());
    }
    Ok(text)
}

// ---- xcframework ---------------------------------------------------------------------------------

fn xcframework(out: &Path, work: &Path) -> Result {
    crate::xcframework::run(&[])?;
    let swift = root().join("bindings").join("ov-ffi");
    let built = swift.join("build").join(XCFRAMEWORK);

    // SwiftPM wants the .xcframework at the top of the zip; ditto keeps symlinks and permissions.
    let zip = out.join(format!("{XCFRAMEWORK}.zip"));
    let mut ditto = Command::new("ditto");
    ditto.args(["-c", "-k", "--sequesterRsrc", "--keepParent"]).arg(&built).arg(&zip);
    crate::run(&format!("release: zip {XCFRAMEWORK}"), &mut ditto)?;

    let checksum = swift_checksum(&zip, work)?;
    if checksum != sha256_file(&zip)? {
        return Err(format!("swift package compute-checksum gave {checksum}, not the zip's SHA-256"));
    }
    fs::write(out.join(format!("{XCFRAMEWORK}.zip.checksum")), format!("{checksum}\n")).map_err(|e| e.to_string())?;
    println!("SwiftPM checksum: {checksum}");
    let sources = swift.join("Sources").join("OpenVireoRustCore");
    fs::write(out.join(SWIFT_SOURCE), swift_source(&sources)?).map_err(|e| e.to_string())
}

/// The generated UniFFI source with the hand-written extensions appended (their `import` lines
/// dropped: the generated file already imports Foundation).
fn swift_source(sources: &Path) -> Result<String> {
    let read = |name: &str| fs::read_to_string(sources.join(name)).map_err(|e| format!("{name}: {e}"));
    let mut text = read(SWIFT_SOURCE)?;
    for name in SWIFT_EXTENSIONS {
        let ext = read(name)?;
        text.push_str(&format!("\n// ---- {name} (hand-written, appended by `cargo xtask release`) ----\n\n"));
        for line in ext.lines().filter(|l| !l.starts_with("import ")) {
            text.push_str(line);
            text.push('\n');
        }
    }
    Ok(text)
}

fn swift_checksum(zip: &Path, cwd: &Path) -> Result<String> {
    let out = Command::new("swift")
        .args(["package", "compute-checksum"])
        .arg(zip)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("swift package compute-checksum: {e}"))?;
    let sum = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || sum.len() != 64 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "swift package compute-checksum failed ({}): {sum} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(sum)
}

// ---- cpp -----------------------------------------------------------------------------------------

fn cpp(out: &Path, work: &Path) -> Result {
    let built = work.join("cpp");
    let stage = work.join("libovcore");
    fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    let built_s = built.to_str().ok_or("non-UTF-8 work dir")?;
    for target in cpp_targets()? {
        crate::cpp::run(&["--target".into(), target.clone(), "--out".into(), built_s.into()])?;
        let platform = platform(&target)?;
        let base = format!("libovcore-{VERSION}-{platform}");
        let dir = stage.join(&base);
        fs::rename(built.join(&target), &dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for f in LICENCES {
            copy(&root().join(f), &dir.join(f))?;
        }
        archive(&stage, &base, out, is_windows(platform))?;
    }
    Ok(())
}

// ---- ov ------------------------------------------------------------------------------------------

fn ov(out: &Path) -> Result {
    for target in ov_targets()? {
        let platform = platform(&target)?;
        let mut cmd = cargo();
        cmd.args(["build", "--locked", "--release", "-p", "openvireo-cli", "--bin", "ov", "--target", &target]);
        if target.ends_with("-apple-darwin") && env::var_os("MACOSX_DEPLOYMENT_TARGET").is_none() {
            cmd.env("MACOSX_DEPLOYMENT_TARGET", MACOS_DEPLOYMENT_TARGET);
        }
        if target.ends_with("-windows-msvc") {
            // Static C runtime: ov.exe runs without the VC++ redistributable. Through rustflags (not
            // `cargo rustc -- …`) so the C code in dependencies is compiled for it too.
            cmd.args(["--config", &format!("target.{target}.rustflags=[\"-C\", \"target-feature=+crt-static\"]")]);
        }
        crate::run(&format!("release: ov for {target}"), &mut cmd)?;

        let exe = if is_windows(platform) { "ov.exe" } else { "ov" };
        let built = target_root().join(&target).join("release").join(exe);
        let dir = out.join(format!("ov-{VERSION}-{platform}"));
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        copy(&built, &dir.join(exe))?;
        make_executable(&dir.join(exe))?;
        for f in LICENCES {
            copy(&root().join(f), &dir.join(f))?;
        }
        fs::write(dir.join("README.md"), ov_readme()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn ov_readme() -> String {
    format!(
        "# ov {VERSION}\n\n\
         `ov`, the OpenVireo command-line client: read, inject and rotate vault secrets from scripts,\n\
         CI and servers. A native build of openvireo-core's `bins/ov`; it needs no Node.\n\n\
         ```sh\n\
         ov help\n\
         ov version\n\
         ```\n\n\
         Documentation: https://developer.openvireo.com/cli/\n\
         Source: https://github.com/OpenVireo/openvireo-core (`bins/ov`)\n\n\
         Licensed under either of MIT (LICENSE-MIT) or Apache-2.0 (LICENSE-APACHE), at your option.\n"
    )
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> Result {
    Ok(())
}

// ---- python --------------------------------------------------------------------------------------

/// The PEP 440 form of a Cargo version, as maturin writes it into the wheel: `1.2.0-beta.1` →
/// `1.2.0b1` (alpha → a, beta → b, rc → rc; a bare `-beta` is `b0`).
fn pep440(version: &str) -> Result<String> {
    let Some((base, pre)) = version.split_once('-') else { return Ok(version.to_string()) };
    let (label, n) = pre.split_once('.').unwrap_or((pre, "0"));
    let tag = match label {
        "alpha" | "a" => "a",
        "beta" | "b" => "b",
        "rc" => "rc",
        _ => return Err(format!("release: no PEP 440 form for the prerelease `{pre}` (use alpha.N, beta.N or rc.N)")),
    };
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("release: no PEP 440 form for the prerelease `{pre}` (use alpha.N, beta.N or rc.N)"));
    }
    Ok(format!("{base}{tag}{n}"))
}

/// The host's wheel and the sdist (the workflow builds the other platforms' with maturin-action).
fn python(out: &Path) -> Result {
    let files = crate::python::release_build(out, true)?;
    check_python_names(out)?;
    if !files.iter().any(|f| f.extension().is_some_and(|x| x == "whl")) {
        return Err(format!("maturin wrote no wheel into {}", out.display()));
    }
    Ok(())
}

/// Every `openvireo-*.whl` and the `openvireo-*.tar.gz` sdist in `dir` carry the release version.
fn check_python_names(dir: &Path) -> Result {
    let pep = pep440(VERSION)?;
    for name in entries(dir)? {
        let wheel = name.starts_with("openvireo-") && name.ends_with(".whl");
        let sdist = name.starts_with("openvireo-") && !name.starts_with("openvireo-core-") && name.ends_with(".tar.gz");
        if (wheel && !name.starts_with(&format!("openvireo-{pep}-")))
            || (sdist && name != format!("openvireo-{pep}.tar.gz"))
        {
            return Err(format!("{name}: not version {pep} (the release is {VERSION})"));
        }
    }
    Ok(())
}

// ---- jvm -----------------------------------------------------------------------------------------

fn jar_name() -> String {
    format!("openvireo-core-jvm-{VERSION}.jar")
}

fn aar_name() -> String {
    format!("openvireo-core-android-{VERSION}.aar")
}

/// One slice of the jar: the release cdylib for `target` at `<dir>/<jna prefix>/<file>`.
fn jvm_native(target: &str, dir: &Path) -> Result {
    let (_, prefix, lib) = NATIVE_SLICES.iter().find(|(t, _, _)| *t == target).ok_or_else(|| {
        let known: Vec<&str> = NATIVE_SLICES.iter().map(|(t, _, _)| *t).collect();
        format!("release: {target} is not a jar slice ({})", known.join(", "))
    })?;
    let mut cmd = cargo();
    // cdylib only (no staticlib), release profile (stripped, LTO), never test-server.
    cmd.args(["rustc", "--locked", "--release", "--lib", "-p", "ov-ffi", "--target", target, "--crate-type", "cdylib"]);
    if target.ends_with("-apple-darwin") && env::var_os("MACOSX_DEPLOYMENT_TARGET").is_none() {
        cmd.env("MACOSX_DEPLOYMENT_TARGET", MACOS_DEPLOYMENT_TARGET);
    }
    if target.ends_with("-windows-msvc") {
        // Static C runtime, like ov.exe: the DLL loads in any JVM without the VC++ redistributable.
        cmd.args(["--config", &format!("target.{target}.rustflags=[\"-C\", \"target-feature=+crt-static\"]")]);
    }
    crate::run(&format!("release: ov-ffi cdylib for {target} (jar slice {prefix})"), &mut cmd)?;
    let dest = dir.join(prefix);
    fs::create_dir_all(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    copy(&target_root().join(target).join("release").join(lib), &dest.join(lib))?;
    println!("{}: {} bytes", dest.join(lib).display(), fs::metadata(dest.join(lib)).map_err(|e| e.to_string())?.len());
    Ok(())
}

/// The jar slice this host runs: (Rust target, JNA prefix).
fn host_slice() -> Result<(&'static str, &'static str)> {
    let triple = match (env::consts::OS, env::consts::ARCH) {
        ("macos", arch) => format!("{arch}-apple-darwin"),
        ("linux", arch) => format!("{arch}-unknown-linux-gnu"),
        ("windows", arch) => format!("{arch}-pc-windows-msvc"),
        (os, arch) => return Err(format!("release: no jar slice for {os}/{arch}")),
    };
    NATIVE_SLICES
        .iter()
        .find(|(t, _, _)| *t == triple)
        .map(|(t, p, _)| (*t, *p))
        .ok_or_else(|| format!("release: no jar slice for {triple}"))
}

fn jvm(opts: &Options, work: &Path) -> Result {
    let natives = match &opts.natives {
        Some(dir) => dir.clone(),
        None => {
            let dir = work.join("jvm-natives");
            jvm_native(host_slice()?.0, &dir)?;
            println!("release: jar with the host slice only (pass --natives for every slice)");
            dir
        }
    };
    // A release needs every slice; a dry run takes whatever --natives holds (at least one).
    let required = match (&opts.natives, opts.dry_run) {
        (Some(_), false) => "all",
        (Some(_), true) => "",
        (None, _) => host_slice()?.1,
    };
    let (jar, aar) = maven_build(&natives, required, opts.jni_libs.as_deref(), &[])?;
    copy(&jar, &opts.out.join(jar_name()))?;
    if let Some(aar) = aar {
        copy(&aar, &opts.out.join(aar_name()))?;
    }
    Ok(())
}

/// Generates the Kotlin and the Java facade, then runs Gradle for the jar (and the AAR with
/// `jni_libs`) plus `extra` tasks, with the release version and the given natives. Returns the jar
/// and the AAR. `required` is `-Pov.requireNatives` (`all`, prefixes, or empty for any). The one
/// place the release's Gradle arguments are spelled out, so `publish-maven` builds exactly what
/// `--only jvm` built.
fn maven_build(
    natives: &Path,
    required: &str,
    jni_libs: Option<&Path>,
    extra: &[&str],
) -> Result<(PathBuf, Option<PathBuf>)> {
    crate::kotlin::run(&["--generate-only".into()])?;
    let project = root().join("bindings").join("kotlin");
    let mut gradle = crate::kotlin::gradlew(&project);
    gradle
        .args(["--console=plain", "-Pov.generate=false"])
        .arg(format!("-Pov.version={VERSION}"))
        .arg(format!("-Pov.nativesDir={}", natives.display()))
        .arg(format!("-Pov.requireNatives={required}"))
        .arg(":core-jvm:jar");
    match jni_libs {
        Some(dir) => {
            gradle
                .args(["-Pov.android=true", "-Pov.requireAbis=all"])
                .arg(format!("-Pov.jniLibsDir={}", dir.display()))
                .arg(":core-android:assembleRelease");
        }
        None => {
            gradle.arg("-Pov.android=false");
        }
    }
    gradle.args(extra);
    crate::run(&format!("release: gradle {}", if extra.is_empty() { "build" } else { "publish" }), &mut gradle)?;
    let jar = project.join("core-jvm").join("build").join("libs").join(jar_name());
    if !jar.is_file() {
        return Err(format!("gradle wrote no {}", jar.display()));
    }
    let aar = match jni_libs {
        Some(_) => Some(crate::kotlin::android::release_aar(&project)?),
        None => None,
    };
    Ok((jar, aar))
}

/// `publish-maven <release dir> --natives <dir> --jni-libs <dir> [--to github|central] [--skip jvm|android]...`
fn publish_maven(args: &[String]) -> Result {
    let mut release = None;
    let mut natives = None;
    let mut jni_libs = None;
    let mut skip = Vec::new();
    let mut central = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--natives" => natives = Some(absolute(it.next().ok_or("--natives needs a directory")?)?),
            "--jni-libs" => jni_libs = Some(absolute(it.next().ok_or("--jni-libs needs a directory")?)?),
            "--to" => match it.next().map(String::as_str) {
                Some("github") => central = false,
                Some("central") => central = true,
                _ => return Err("--to takes github or central".into()),
            },
            "--skip" => match it.next().map(String::as_str) {
                Some(s @ ("jvm" | "android")) => skip.push(s.to_string()),
                _ => return Err("--skip takes jvm or android".into()),
            },
            other if !other.starts_with('-') && release.is_none() => release = Some(absolute(other)?),
            other => return Err(format!("release publish-maven: unexpected `{other}`\n{USAGE}")),
        }
    }
    let (Some(release), Some(natives), Some(jni_libs)) = (release, natives, jni_libs) else {
        return Err(USAGE.into());
    };
    println!(
        "==> release {VERSION}: publish-maven to {} (skipping: {})",
        if central { "the Central staging directory" } else { "GitHub Packages" },
        if skip.is_empty() { "none".into() } else { skip.join(", ") }
    );
    check_release_tree()?;
    let (jar, aar) = maven_build(&natives, "all", Some(&jni_libs), &[])?;
    let aar = aar.ok_or("no AAR")?;
    for (built, name) in [(&jar, jar_name()), (&aar, aar_name())] {
        let verified = release.join(&name);
        let (have, want) = (sha256_file(built)?, sha256_file(&verified)?);
        if have != want {
            return Err(format!(
                "{name}: the rebuild is {have}, the verified release asset is {want}; the Gradle build is not \
                 reproducible, so nothing was published"
            ));
        }
        println!("{name}: rebuilt byte for byte ({have})");
    }
    // The repository names in bindings/kotlin/core-{jvm,android}/build.gradle.kts
    let repo = if central { "CentralStaging" } else { "GitHubPackages" };
    let tasks: Vec<String> = ["jvm", "android"]
        .into_iter()
        .filter(|a| !skip.iter().any(|s| s == a))
        .map(|a| format!(":core-{a}:publishAllPublicationsTo{repo}Repository"))
        .collect();
    if tasks.is_empty() {
        println!("nothing to publish");
        return Ok(());
    }
    if central {
        let staging = root().join("bindings").join("kotlin").join("build").join("central-staging");
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
        }
    } else if env::var_os("GITHUB_TOKEN").is_none() || env::var_os("GITHUB_ACTOR").is_none() {
        return Err("publishing to GitHub Packages needs GITHUB_ACTOR and GITHUB_TOKEN".into());
    }
    let tasks: Vec<&str> = tasks.iter().map(String::as_str).collect();
    // Same arguments, so Gradle reuses the jar and AAR it just built (and compared) and uploads them.
    maven_build(&natives, "all", Some(&jni_libs), &tasks)?;
    Ok(())
}

// ---- pack ----------------------------------------------------------------------------------------

/// Archives every `ov-<VERSION>-<platform>/` in `dir` (after signing) and writes `SHA256SUMS`.
fn pack(dir: &Path) -> Result {
    println!("\n==> release: pack {}", dir.display());
    for name in entries(dir)? {
        let path = dir.join(&name);
        if !path.is_dir() {
            continue;
        }
        let platform = name.strip_prefix(&format!("ov-{VERSION}-")).ok_or_else(|| {
            format!("{}: unexpected directory (only ov-{VERSION}-<platform>/ is packed)", path.display())
        })?;
        let exe = path.join(if is_windows(platform) { "ov.exe" } else { "ov" });
        if !exe.is_file() {
            return Err(format!("{}: missing", exe.display()));
        }
        // Artifact uploads drop the executable bit, so set it here rather than trust the input.
        make_executable(&exe)?;
        archive(dir, &name, dir, is_windows(platform))?;
        fs::remove_dir_all(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    write_sums(dir)?;
    list(dir)
}

/// `<dest>/<base>.tar.gz` (or `.zip`) of `<parent>/<base>/`.
fn archive(parent: &Path, base: &str, dest: &Path, zip: bool) -> Result {
    let file = dest.join(format!("{base}.{}", if zip { "zip" } else { "tar.gz" }));
    if file.exists() {
        fs::remove_file(&file).map_err(|e| e.to_string())?;
    }
    let mut cmd = if zip && cfg!(windows) {
        // Windows' own bsdtar writes zips (`-a` picks the format from the name); Git Bash's GNU tar can't.
        let system = env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let mut c = Command::new(system.join("System32").join("tar.exe"));
        c.args(["-a", "-c", "-f"]).arg(&file).arg(base);
        c
    } else if zip {
        let mut c = Command::new("zip");
        c.args(["-q", "-r", "-X"]).arg(&file).arg(base);
        c
    } else {
        let mut c = Command::new("tar");
        c.arg("-czf").arg(&file).arg(base);
        c
    };
    // No AppleDouble `._*` entries from macOS's tar.
    cmd.current_dir(parent).env("COPYFILE_DISABLE", "1");
    crate::run(&format!("release: pack {}", file.file_name().unwrap().to_string_lossy()), &mut cmd)
}

fn write_sums(dir: &Path) -> Result {
    let mut text = String::new();
    for name in entries(dir)? {
        let path = dir.join(&name);
        if path.is_file() && name != SUMS && !name.ends_with(".asc") {
            text.push_str(&format!("{}  {name}\n", sha256_file(&path)?));
        }
    }
    fs::write(dir.join(SUMS), text).map_err(|e| e.to_string())
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::Digest;
    let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(hex::encode(hasher.finalize()))
}

fn list(dir: &Path) -> Result {
    println!("\n{}:", dir.display());
    for name in entries(dir)? {
        let meta = fs::metadata(dir.join(&name)).map_err(|e| e.to_string())?;
        let size = if meta.is_dir() { "dir".to_string() } else { meta.len().to_string() };
        println!("{size:>12}  {name}");
    }
    Ok(())
}

/// File names in `dir`, sorted.
fn entries(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        names.push(entry.map_err(|e| e.to_string())?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

// ---- verify --------------------------------------------------------------------------------------

/// Checks the packed artifacts in `dir` that this host can run.
fn verify(dir: &Path, dry_run: bool) -> Result {
    println!("==> release {VERSION}: verify {}", dir.display());
    verify_sums(dir)?;
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
    let work = target_root().join("release-verify").join(nanos.to_string());
    fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let result = verify_in(dir, &work, dry_run);
    if result.is_ok() {
        let _ = fs::remove_dir_all(&work);
    } else {
        eprintln!("release: verify dir kept for inspection: {}", work.display());
    }
    result?;
    println!("\nrelease verify: all green");
    Ok(())
}

fn verify_in(dir: &Path, work: &Path, dry_run: bool) -> Result {
    let platform = host_platform()?;
    let ext = if is_windows(platform) { "zip" } else { "tar.gz" };
    let mut checked = Vec::new();

    let ov = dir.join(format!("ov-{VERSION}-{platform}.{ext}"));
    if ov.is_file() {
        verify_ov(&ov, platform, work, dry_run)?;
        checked.push(format!("ov {platform}"));
    }
    let lib = dir.join(format!("libovcore-{VERSION}-{platform}.{ext}"));
    if lib.is_file() {
        verify_libovcore(&lib, platform, work)?;
        checked.push(format!("libovcore {platform}"));
    }
    let zip = dir.join(format!("{XCFRAMEWORK}.zip"));
    if zip.is_file() && cfg!(target_os = "macos") {
        verify_xcframework(dir, &zip, work)?;
        checked.push("xcframework".into());
    }
    let tgz = dir.join(format!("openvireo-core-wasm-{VERSION}.tgz"));
    if tgz.is_file() && on_path(npm()) {
        verify_wasm(&tgz, work)?;
        checked.push("@openvireo/core-wasm".into());
    }
    let names = entries(dir)?;
    if names.iter().any(|n| n.starts_with("openvireo-") && n.ends_with(".whl")) {
        check_python_names(dir)?;
        verify_python(dir, work)?;
        checked.push("python wheel".into());
    }
    let jar = dir.join(jar_name());
    if jar.is_file() && verify_jar(&jar, work, dry_run)? {
        checked.push("jvm jar".into());
    }
    let aar = dir.join(aar_name());
    if aar.is_file() {
        crate::kotlin::android::verify_aar(&aar)?;
        checked.push("android aar".into());
    }
    if checked.is_empty() {
        return Err(format!("nothing in {} this host ({platform}) can check", dir.display()));
    }
    println!("\nchecked: {}", checked.join(", "));
    Ok(())
}

/// Every file is listed in SHA256SUMS with its hash, and SHA256SUMS lists nothing missing.
fn verify_sums(dir: &Path) -> Result {
    let text = fs::read_to_string(dir.join(SUMS)).map_err(|e| format!("{}: {e}", dir.join(SUMS).display()))?;
    let mut listed = Vec::new();
    for line in text.lines() {
        let (sum, name) = line.split_once("  ").ok_or_else(|| format!("{SUMS}: bad line `{line}`"))?;
        let actual = sha256_file(&dir.join(name))?;
        if actual != sum {
            return Err(format!("{name}: sha256 {actual}, {SUMS} says {sum}"));
        }
        listed.push(name.to_string());
    }
    for name in entries(dir)? {
        if name != SUMS && !name.ends_with(".asc") && !listed.contains(&name) {
            return Err(format!("{name} is not in {SUMS}"));
        }
    }
    println!("{SUMS}: {} files match", listed.len());
    Ok(())
}

fn extract(archive: &Path, into: &Path) -> Result {
    fs::create_dir_all(into).map_err(|e| e.to_string())?;
    let mut cmd = if cfg!(windows) {
        let system = env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        Command::new(system.join("System32").join("tar.exe"))
    } else {
        Command::new("tar")
    };
    cmd.arg("-xf").arg(archive).arg("-C").arg(into);
    crate::run(&format!("release: unpack {}", archive.file_name().unwrap().to_string_lossy()), &mut cmd)
}

fn output(cmd: &mut Command, what: &str) -> Result<String> {
    let out = cmd.output().map_err(|e| format!("{what}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{what} failed ({}):\n{}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn verify_ov(archive: &Path, platform: &str, work: &Path, dry_run: bool) -> Result {
    let into = work.join("ov");
    extract(archive, &into)?;
    let dir = into.join(format!("ov-{VERSION}-{platform}"));
    for f in ["README.md", LICENCES[0], LICENCES[1]] {
        if !dir.join(f).is_file() {
            return Err(format!("{}: no {f}", archive.display()));
        }
    }
    let exe = dir.join(if is_windows(platform) { "ov.exe" } else { "ov" });
    println!("\n==> {} version", exe.display());
    let said = output(Command::new(&exe).arg("version"), "ov version")?;
    print!("{said}");
    let want = format!("ov {VERSION}");
    if said.trim() != want {
        let msg = format!("`ov version` printed `{}`, the release is {VERSION}", said.trim());
        if !dry_run {
            return Err(msg);
        }
        println!("warning (dry run): {msg}");
    }
    let help = output(Command::new(&exe).arg("help"), "ov help")?;
    if !help.contains("ov read") {
        return Err(format!("`ov help` doesn't list `ov read`:\n{help}"));
    }
    Ok(())
}

const CMAKE_CONSUMER: &str = r#"cmake_minimum_required(VERSION 3.22)
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS")
project(ovcore_release_check LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(OpenVireoCore @VERSION@ EXACT REQUIRED)
if(NOT OpenVireoCore_FEATURES STREQUAL "")
  message(FATAL_ERROR "release package built with features: ${OpenVireoCore_FEATURES}")
endif()
add_executable(check main.cpp)
target_link_libraries(check PRIVATE OpenVireoCore::ovcore)
enable_testing()
add_test(NAME check COMMAND check)
"#;

const CPP_MAIN: &str = r#"#include <ovcore.h>
#include <cstdio>
#include <string>

int main() {
    const std::string abc = "abc";
    rust::Slice<const std::uint8_t> data(reinterpret_cast<const std::uint8_t *>(abc.data()), abc.size());
    std::string digest;
    for (auto b : ov::sha256(data)) {
        static const char digits[] = "0123456789abcdef";
        digest += digits[b >> 4];
        digest += digits[b & 0xf];
    }
    const std::string version(ov::version());
    std::printf("openvireo-core %s, sha256(\"abc\") = %s\n", version.c_str(), digest.c_str());
    return digest == "@SHA256_ABC@" && version == "@VERSION@" ? 0 : 1;
}
"#;

fn verify_libovcore(archive: &Path, platform: &str, work: &Path) -> Result {
    let into = work.join("libovcore");
    extract(archive, &into)?;
    let pkg = into.join(format!("libovcore-{VERSION}-{platform}"));
    let config = pkg.join("lib").join("cmake").join("OpenVireoCore");
    if !pkg.join("include").join("ovcore.h").is_file() || !config.join("OpenVireoCoreConfig.cmake").is_file() {
        return Err(format!("{}: no include/ovcore.h or CMake package", archive.display()));
    }
    let src = work.join("cpp-consumer");
    fs::create_dir_all(&src).map_err(|e| e.to_string())?;
    fs::write(src.join("CMakeLists.txt"), CMAKE_CONSUMER.replace("@VERSION@", VERSION)).map_err(|e| e.to_string())?;
    fs::write(src.join("main.cpp"), CPP_MAIN.replace("@VERSION@", VERSION).replace("@SHA256_ABC@", SHA256_ABC))
        .map_err(|e| e.to_string())?;
    let build = work.join("cpp-build");
    crate::run(
        "release: cmake configure (libovcore consumer)",
        Command::new("cmake")
            .arg("-S")
            .arg(&src)
            .arg("-B")
            .arg(&build)
            .arg(format!("-DOpenVireoCore_DIR={}", config.display())),
    )?;
    crate::run("release: cmake build", Command::new("cmake").arg("--build").arg(&build).args(["--config", "Release"]))?;
    crate::run(
        "release: ctest",
        Command::new("ctest").arg("--test-dir").arg(&build).args(["-C", "Release", "--output-on-failure", "-V"]),
    )
}

const SWIFT_PACKAGE: &str = r#"// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ReleaseCheck",
    platforms: [.macOS(.v12)],
    targets: [
        .binaryTarget(name: "OpenVireoRustCoreFFI", path: "OpenVireoCore.xcframework"),
        .target(name: "OpenVireoRustCore", dependencies: ["OpenVireoRustCoreFFI"], path: "Sources/OpenVireoRustCore"),
        .executableTarget(name: "check", dependencies: ["OpenVireoRustCore"], path: "Sources/check"),
    ]
)
"#;

const SWIFT_MAIN: &str = r#"import Foundation
import OpenVireoRustCore

let digest = try sha256(data: Data("abc".utf8)).map { String(format: "%02x", $0) }.joined()
print("openvireo-core \(version()), sha256(\"abc\") = \(digest)")
// OvError+Fields.swift is appended to the source: error.code works
let fields = OvError(code: .networkError, message: "check").code == .networkError
exit(digest == "@SHA256_ABC@" && version() == "@VERSION@" && fields ? 0 : 1)
"#;

/// The checksum file matches, and a SwiftPM package over the zip's xcframework and the Swift
/// source builds and runs on this Mac.
fn verify_xcframework(dir: &Path, zip: &Path, work: &Path) -> Result {
    let pkg = work.join("swift-consumer");
    fs::create_dir_all(&pkg).map_err(|e| e.to_string())?;
    let want = fs::read_to_string(dir.join(format!("{XCFRAMEWORK}.zip.checksum")))
        .map_err(|e| format!("{XCFRAMEWORK}.zip.checksum: {e}"))?;
    let have = swift_checksum(zip, &pkg)?;
    if want.trim() != have {
        return Err(format!("{XCFRAMEWORK}.zip.checksum says {}, swift computes {have}", want.trim()));
    }
    println!("SwiftPM checksum matches: {have}");

    crate::run("release: unzip the xcframework", Command::new("ditto").args(["-x", "-k"]).arg(zip).arg(&pkg))?;
    let core = pkg.join("Sources").join("OpenVireoRustCore");
    let check = pkg.join("Sources").join("check");
    fs::create_dir_all(&core).map_err(|e| e.to_string())?;
    fs::create_dir_all(&check).map_err(|e| e.to_string())?;
    copy(&dir.join(SWIFT_SOURCE), &core.join(SWIFT_SOURCE))?;
    fs::write(pkg.join("Package.swift"), SWIFT_PACKAGE).map_err(|e| e.to_string())?;
    fs::write(check.join("main.swift"), SWIFT_MAIN.replace("@VERSION@", VERSION).replace("@SHA256_ABC@", SHA256_ABC))
        .map_err(|e| e.to_string())?;
    crate::run(
        "release: swift run (xcframework consumer, macOS slice)",
        Command::new("swift").args(["run", "-c", "release", "check"]).current_dir(&pkg),
    )
}

const NODE_CHECK: &str = r#"import { loadCoreSync } from "@openvireo/core-wasm/sync";
import { loadLiteSync } from "@openvireo/core-wasm/lite-sync";
import { createRequire } from "node:module";
import { existsSync } from "node:fs";

const hex = (b) => Buffer.from(b).toString("hex");
const abc = new TextEncoder().encode("abc");
const core = loadCoreSync();
const lite = loadLiteSync();
const manifest = createRequire(import.meta.url)("@openvireo/core-wasm/package.json");
console.log(`@openvireo/core-wasm ${manifest.version}: core ${core.version()}, full sha256(abc) ${hex(core.sha256(abc))}, lite ${hex(lite.sha256(abc))}`);
const dir = new URL("./node_modules/@openvireo/core-wasm/", import.meta.url);
const licences = ["LICENSE-MIT", "LICENSE-APACHE", "README.md"].every((f) => existsSync(new URL(f, dir)));
console.log(`licences + README in the package: ${licences}`);
const ok = licences && manifest.version === "@VERSION@" && core.version() === "@VERSION@" && !manifest.private &&
  manifest.publishConfig?.access === "public" &&
  hex(core.sha256(abc)) === "@SHA256_ABC@" && hex(lite.sha256(abc)) === "@SHA256_ABC@";
process.exit(ok ? 0 : 1);
"#;

/// Installs the tarball into an empty project and loads both modules in Node.
fn verify_wasm(tgz: &Path, work: &Path) -> Result {
    let app = work.join("node-consumer");
    fs::create_dir_all(&app).map_err(|e| e.to_string())?;
    fs::write(app.join("package.json"), "{ \"name\": \"release-check\", \"private\": true, \"type\": \"module\" }\n")
        .map_err(|e| e.to_string())?;
    fs::write(app.join("check.mjs"), NODE_CHECK.replace("@VERSION@", VERSION).replace("@SHA256_ABC@", SHA256_ABC))
        .map_err(|e| e.to_string())?;
    crate::run(
        "release: npm install the core-wasm tarball",
        Command::new(npm()).args(["install", "--no-audit", "--no-fund", "--ignore-scripts"]).arg(tgz).current_dir(&app),
    )?;
    crate::run("release: load both modules in Node", Command::new("node").arg("check.mjs").current_dir(&app))
}

const PYTHON_CHECK: &str = r#"import importlib.metadata as md
import pathlib
import sys
import openvireo as ov
version, digest, dist = ov.version(), ov.sha256(b"abc").hex(), md.version("openvireo")
print(f"openvireo {dist} ({ov.__file__}): core {version}, sha256(abc) = {digest}")
# The type stubs (bindings/python/scripts/gen_stubs.py) and the PEP 561 marker ship in the wheel.
pkg = pathlib.Path(ov.__file__).parent
missing = [f for f in ("py.typed", "__init__.pyi", "_core/ov_ffi.pyi") if not (pkg / f).is_file()]
if missing:
    print(f"the wheel lacks {missing}")
sys.exit(0 if (version, digest, dist) == ("@VERSION@", "@SHA256_ABC@", "@PEP440@") and not missing else 1)
"#;

/// Installs the wheel for this host from `dir` (no index, no sdist build) into a fresh venv and
/// runs a check through the core.
fn verify_python(dir: &Path, work: &Path) -> Result {
    let pep = pep440(VERSION)?;
    let python = crate::python::fresh_venv(&work.join("venv"))?;
    crate::run(
        "release: install the wheel for this host into a fresh venv",
        crate::python::pip_install(&python)
            .args(["--no-index", "--only-binary", ":all:", "--find-links"])
            .arg(dir)
            .arg(format!("openvireo=={pep}")),
    )?;
    let script = work.join("check.py");
    fs::write(
        &script,
        PYTHON_CHECK.replace("@VERSION@", VERSION).replace("@SHA256_ABC@", SHA256_ABC).replace("@PEP440@", &pep),
    )
    .map_err(|e| e.to_string())?;
    // -I: isolated, so the import is the installed wheel, never the source tree.
    crate::run("release: import the wheel", Command::new(&python).arg("-I").arg(&script).current_dir(work))
}

const JAVA_SETTINGS: &str = "rootProject.name = \"jvm-release-check\"\n";

const JAVA_BUILD: &str = r#"// A Java consumer of the release jar, with the dependencies its POM declares.
plugins { java }
repositories { mavenCentral() }
dependencies {
    implementation(files("@JAR@"))
    implementation("net.java.dev.jna:jna:@JNA@")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:@COROUTINES@")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:@KOTLIN@")
}
tasks.withType<JavaCompile>().configureEach { options.release.set(11) }
tasks.register<JavaExec>("consumer") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("Check")
}
"#;

const JAVA_MAIN: &str = r#"import com.openvireo.core.java.JOv;
import java.nio.charset.StandardCharsets;

public final class Check {
    public static void main(String[] args) throws Exception {
        StringBuilder digest = new StringBuilder();
        for (byte b : JOv.sha256("abc".getBytes(StandardCharsets.UTF_8))) {
            digest.append(String.format("%02x", b));
        }
        String version = JOv.version();
        System.out.println("openvireo-core-jvm: core " + version + " on " + System.getProperty("os.name") + "/"
            + System.getProperty("os.arch") + ", sha256(\"abc\") = " + digest);
        System.exit(digest.toString().equals("@SHA256_ABC@") && version.equals("@VERSION@") ? 0 : 1);
    }
}
"#;

/// A `[versions]` entry of bindings/kotlin/gradle/libs.versions.toml.
fn kotlin_lib_version(toml: &str, key: &str) -> Result<String> {
    let section = toml.split("[versions]").nth(1).ok_or("libs.versions.toml: no [versions]")?;
    let section = section.split("\n[").next().unwrap_or(section);
    section
        .lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
        .ok_or_else(|| format!("libs.versions.toml: no `{key}` version"))
}

/// The jar's native slices (every one outside a dry run, this host's at least), then a Java
/// program compiled against the jar and run with Gradle (the repository's wrapper). Returns false
/// when it was skipped (no JDK, dry run only).
fn verify_jar(jar: &Path, work: &Path, dry_run: bool) -> Result<bool> {
    let bytes = fs::read(jar).map_err(|e| format!("{}: {e}", jar.display()))?;
    let names: Vec<String> = crate::kotlin::android::zip_entries(&bytes)
        .map_err(|e| format!("{}: {e}", jar.display()))?
        .into_iter()
        .map(|e| e.name)
        .collect();
    let mut missing = Vec::new();
    for (_, prefix, lib) in NATIVE_SLICES {
        let entry = format!("{prefix}/{lib}");
        if names.contains(&entry) {
            println!("{}: {entry}", jar_name());
        } else {
            missing.push(entry);
        }
    }
    let host = format!("{}/", host_slice()?.1);
    if missing.iter().any(|m| m.starts_with(&host)) {
        return Err(format!("{}: no native for this host ({host})", jar.display()));
    }
    if !missing.is_empty() {
        let msg = format!("{} is missing native slices: {}", jar_name(), missing.join(", "));
        if !dry_run {
            return Err(msg);
        }
        println!("warning (dry run): {msg}");
    }
    if !on_path("java") {
        if !dry_run {
            return Err("the jar check needs a JDK 17+ (java on PATH)".into());
        }
        println!("warning (dry run): no java on PATH; the Java consumer check is skipped");
        return Ok(false);
    }

    let toml_path = root().join("bindings").join("kotlin").join("gradle").join("libs.versions.toml");
    let toml = fs::read_to_string(&toml_path).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    let app = work.join("java-consumer");
    let src = app.join("src").join("main").join("java");
    fs::create_dir_all(&src).map_err(|e| e.to_string())?;
    fs::write(app.join("settings.gradle.kts"), JAVA_SETTINGS).map_err(|e| e.to_string())?;
    let build = JAVA_BUILD
        .replace("@JAR@", &jar.display().to_string().replace('\\', "/"))
        .replace("@JNA@", &kotlin_lib_version(&toml, "jna")?)
        .replace("@COROUTINES@", &kotlin_lib_version(&toml, "coroutines")?)
        .replace("@KOTLIN@", &kotlin_lib_version(&toml, "kotlin")?);
    fs::write(app.join("build.gradle.kts"), build).map_err(|e| e.to_string())?;
    fs::write(src.join("Check.java"), JAVA_MAIN.replace("@VERSION@", VERSION).replace("@SHA256_ABC@", SHA256_ABC))
        .map_err(|e| e.to_string())?;
    let mut gradle = crate::kotlin::gradlew(&root().join("bindings").join("kotlin"));
    gradle.arg("-p").arg(&app).args(["--console=plain", "--no-configuration-cache", "consumer"]);
    crate::run("release: Java consumer of the jar (gradle)", &mut gradle)?;
    Ok(true)
}

// ---- helpers -------------------------------------------------------------------------------------

fn copy(from: &Path, to: &Path) -> Result {
    fs::copy(from, to).map(|_| ()).map_err(|e| format!("copy {} -> {}: {e}", from.display(), to.display()))
}

fn copy_dir(from: &Path, to: &Path) -> Result {
    fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for entry in fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let dest = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &dest)?;
        } else {
            copy(&path, &dest)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_match_the_sdk_release_names() {
        assert_eq!(platform("aarch64-apple-darwin").unwrap(), "darwin-arm64");
        assert_eq!(platform("x86_64-apple-darwin").unwrap(), "darwin-x64");
        assert_eq!(platform("x86_64-unknown-linux-musl").unwrap(), "linux-x64");
        assert_eq!(platform("aarch64-unknown-linux-gnu").unwrap(), "linux-arm64");
        assert_eq!(platform("x86_64-pc-windows-msvc").unwrap(), "windows-x64");
        assert!(platform("riscv64gc-unknown-linux-gnu").is_err());
    }

    #[test]
    fn the_manifest_becomes_publishable() {
        let template = format!(
            "{{\n  \"name\": \"@openvireo/core-wasm\",\n  \"version\": \"{VERSION}\",\n  \"private\": true,\n  \"files\": [\n    \"index.js\"\n  ]\n}}\n"
        );
        let text = publishable_manifest(&template).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(json.get("private").is_none());
        assert_eq!(json["publishConfig"]["access"], "public");
        assert_eq!(json["files"], serde_json::json!(["LICENSE-MIT", "LICENSE-APACHE", "index.js"]));
        assert!(publishable_manifest(&template.replace(VERSION, "9.9.9-other")).is_err());
        assert!(publishable_manifest(&text).is_err(), "an already public manifest means the template changed");
    }

    #[test]
    fn versions_become_pep440_as_maturin_writes_them() {
        assert_eq!(pep440("1.2.0").unwrap(), "1.2.0");
        assert_eq!(pep440("1.2.0-alpha.1").unwrap(), "1.2.0a1");
        assert_eq!(pep440("1.2.0-beta.12").unwrap(), "1.2.0b12");
        assert_eq!(pep440("1.2.0-rc.2").unwrap(), "1.2.0rc2");
        assert_eq!(pep440("1.2.0-beta").unwrap(), "1.2.0b0");
        assert!(pep440("1.2.0-nightly.3").is_err());
        assert!(pep440("1.2.0-rc.x").is_err());
    }

    #[test]
    fn python_names_must_carry_the_version() {
        let dir = std::env::temp_dir().join(format!("ov-release-names-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pep = pep440(VERSION).unwrap();
        for f in [
            format!("openvireo-{pep}-py3-none-macosx_11_0_arm64.whl"),
            format!("openvireo-{pep}.tar.gz"),
            format!("openvireo-core-wasm-{VERSION}.tgz"),
            format!("libovcore-{VERSION}-linux-x64.tar.gz"),
        ] {
            fs::write(dir.join(f), b"").unwrap();
        }
        assert!(check_python_names(&dir).is_ok());
        fs::write(dir.join("openvireo-9.9.9-py3-none-win_amd64.whl"), b"").unwrap();
        assert!(check_python_names(&dir).is_err());
        fs::remove_file(dir.join("openvireo-9.9.9-py3-none-win_amd64.whl")).unwrap();
        fs::write(dir.join("openvireo-9.9.9.tar.gz"), b"").unwrap();
        assert!(check_python_names(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn kotlin_versions_come_from_the_catalog() {
        let toml = "[versions]\nkotlin = \"2.4.21\"\njna = \"5.19.1\"\n\n[libraries]\njna = { module = \"x\" }\n";
        assert_eq!(kotlin_lib_version(toml, "kotlin").unwrap(), "2.4.21");
        assert_eq!(kotlin_lib_version(toml, "jna").unwrap(), "5.19.1");
        assert!(kotlin_lib_version(toml, "coroutines").is_err());
        let real = fs::read_to_string(root().join("bindings/kotlin/gradle/libs.versions.toml")).unwrap();
        for key in ["kotlin", "coroutines", "jna"] {
            assert!(kotlin_lib_version(&real, key).is_ok(), "{key}");
        }
    }

    #[test]
    fn every_jar_slice_has_a_host_name() {
        assert!(host_slice().is_ok());
        assert_eq!(NATIVE_SLICES.len(), 5);
    }

    #[test]
    fn kinds_parse_and_xcframework_is_macos_only() {
        assert_eq!(Kind::parse("python").unwrap(), Kind::Python);
        assert_eq!(Kind::parse("jvm").unwrap(), Kind::Jvm);
        assert_eq!(Kind::parse("cpp").unwrap(), Kind::Cpp);
        assert!(Kind::parse("deb").is_err());
        assert_eq!(Kind::Xcframework.host_can_build(), cfg!(target_os = "macos"));
    }
}
