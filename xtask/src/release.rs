//! `cargo xtask release`: build every release artifact this host can build, under its final name,
//! plus `SHA256SUMS`. Owned by W4-R (only that task edits this file). `.github/workflows/release.yml`
//! runs it once per runner, signs the `ov` executables, then packs, verifies and publishes.
//!
//! ```text
//! cargo xtask release [--dry-run] [--out <dir>] [--only <kinds>] [--unpacked]
//! cargo xtask release pack <dir>
//! cargo xtask release verify <dir> [--dry-run]
//! ```
//!
//! Kinds (`--only wasm,cpp`; default: every kind the host can build):
//! - `wasm`: `openvireo-core-wasm-<v>.tgz`, the `npm pack` of `@openvireo/core-wasm` (one package
//!   with the full and the lite module, as the SDK consumes it today), ready to publish (GitHub
//!   Packages; npmjs.com too once the SDK goes there).
//! - `xcframework` (macOS only): `OpenVireoCore.xcframework.zip`, its SwiftPM checksum in
//!   `OpenVireoCore.xcframework.zip.checksum`, and `OpenVireoRustCore.swift`, the UniFFI Swift
//!   source that goes with it.
//! - `cpp`: `libovcore-<v>-<platform>.tar.gz` (`.zip` on Windows), the `cargo xtask cpp` CMake
//!   package (headers, static library, `OpenVireoCoreConfig.cmake`) plus the licences.
//! - `ov`: `ov-<v>-<platform>.tar.gz` (`.zip` on Windows) holding `ov-<v>-<platform>/ov` (`ov.exe`),
//!   a README and the licences: the same names as the SDK's release, so installers keep working.
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
//! xcframework (checksum, and a SwiftPM package over it built and run, on macOS) and the npm package
//! (installed and both modules loaded in Node). Outside `--dry-run`, `ov version` must print the
//! release version.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{cargo, root, target_root, Result};

/// The workspace version: every artifact carries it, and the release tag must be `v<VERSION>`.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The oldest macOS the binaries run on (the same floor `cargo xtask cpp` uses).
const MACOS_DEPLOYMENT_TARGET: &str = "11.0";
const XCFRAMEWORK: &str = "OpenVireoCore.xcframework";
const SWIFT_SOURCE: &str = "OpenVireoRustCore.swift";
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
}

impl Kind {
    const ALL: [Kind; 4] = [Kind::Wasm, Kind::Xcframework, Kind::Cpp, Kind::Ov];

    fn name(self) -> &'static str {
        match self {
            Kind::Wasm => "wasm",
            Kind::Xcframework => "xcframework",
            Kind::Cpp => "cpp",
            Kind::Ov => "ov",
        }
    }

    fn parse(s: &str) -> Result<Kind> {
        Kind::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or_else(|| format!("release: unknown kind `{s}` (wasm, xcframework, cpp, ov)"))
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
}

const USAGE: &str = "\
usage: cargo xtask release [--dry-run] [--out <dir>] [--only <kinds>] [--unpacked]
       cargo xtask release pack <dir>
       cargo xtask release verify <dir> [--dry-run]
kinds: wasm, xcframework (macOS), cpp, ov (comma-separated; default: all the host can build)";

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
        _ => build(&parse(args)?),
    }
}

fn parse(args: &[String]) -> Result<Options> {
    let mut opts =
        Options { dry_run: false, out: target_root().join("release-artifacts"), kinds: Vec::new(), unpacked: false };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dry-run" => opts.dry_run = true,
            "--unpacked" => opts.unpacked = true,
            "--out" => opts.out = absolute(it.next().ok_or("--out needs a directory")?)?,
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
    copy(&swift.join("Sources").join("OpenVireoRustCore").join(SWIFT_SOURCE), &out.join(SWIFT_SOURCE))
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
        cmd.args(["build", "--locked", "--release", "-p", "ov", "--bin", "ov", "--target", &target]);
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
         Documentation: https://openvireo.com/docs/sdk/cli/\n\
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
exit(digest == "@SHA256_ABC@" && version() == "@VERSION@" ? 0 : 1)
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
    fn kinds_parse_and_xcframework_is_macos_only() {
        assert_eq!(Kind::parse("cpp").unwrap(), Kind::Cpp);
        assert!(Kind::parse("deb").is_err());
        assert_eq!(Kind::Xcframework.host_can_build(), cfg!(target_os = "macos"));
    }
}
