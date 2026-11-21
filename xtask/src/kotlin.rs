//! `cargo xtask kotlin`: build and test the Kotlin (JVM) binding in `bindings/kotlin`
//! (language-bindings.md §3, task B2).
//!
//! 1. Builds the `ov-ffi` cdylib for the host in debug: unstripped, so `uniffi-bindgen` can read
//!    its metadata (the release profile strips it, as for the xcframework).
//! 2. Runs `uniffi-bindgen generate --language kotlin` on it into
//!    `bindings/kotlin/build/generated/uniffi/kotlin` (package `com.openvireo.core`, from
//!    `bindings/ov-ffi/uniffi.toml`). Files are rewritten only when they change, so Gradle doesn't
//!    recompile 28k lines of generated Kotlin for nothing.
//!    Then generates the Java facade (`com.openvireo.core.java`, see `kotlin_facade.rs`) from that
//!    Kotlin into `bindings/kotlin/build/generated/facade/kotlin`, the same way.
//! 3. Copies the host library into `bindings/kotlin/build/natives/<jna-prefix>/` (JNA's resource
//!    layout, see [`NATIVE_SLICES`]); the jar picks it up from there.
//! 4. Runs `./gradlew test` in `bindings/kotlin` (with `-Pov.generate=false`, since steps 1-3 are
//!    done).
//!
//! Flags:
//! - `--smoke`: also builds the testkit relay (`cargo build -p ov-testkit --example http_relay`,
//!   the in-memory auth + sync servers on a loopback socket, shared with `xtask python`) and runs
//!   the smoke test against it: register, log in, vault, entry, sync, events stream,
//!   share link, error codes. Implies `--test-server`, as `xcframework --smoke` does.
//! - `--test-server`: builds with the crate's `test-server` feature (the `opaque_server_*` steps).
//! - `--generate-only`: stops after step 3 (Gradle's `:generateBindings` runs this).
//! - `--android` (B4, [`android`]): also builds `libov_ffi.so` for the Android ABIs with cargo-ndk
//!   (release, never `test-server`) into `bindings/kotlin/build/jniLibs`, adds
//!   `:core-android:assembleRelease` to the Gradle run (with `-Pov.android=true
//!   -Pov.requireAbis=all`) and then checks the AAR and prints its sizes. Can't be combined with
//!   `--smoke` / `--test-server`: the generated Kotlin must match the natives' features.
//! - `-- <args>`: passed to Gradle instead of `test` (e.g. `-- build`, `-- publishToMavenLocal`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{cargo, root, run as step, target_root, Result};

pub(crate) mod android;

const PACKAGE: &str = "ov-ffi";

/// Each slice of the jar: the Rust target, the JNA resource prefix and the library's file name.
/// The release matrix (B5) fills `-Pov.nativesDir` with these directories.
pub const NATIVE_SLICES: [(&str, &str, &str); 5] = [
    ("aarch64-apple-darwin", "darwin-aarch64", "libov_ffi.dylib"),
    ("x86_64-apple-darwin", "darwin-x86-64", "libov_ffi.dylib"),
    ("x86_64-unknown-linux-gnu", "linux-x86-64", "libov_ffi.so"),
    ("aarch64-unknown-linux-gnu", "linux-aarch64", "libov_ffi.so"),
    ("x86_64-pc-windows-msvc", "win32-x86-64", "ov_ffi.dll"),
];

/// The host's slice: (JNA prefix, library file name).
fn host_slice() -> Result<(&'static str, &'static str)> {
    let arch = std::env::consts::ARCH;
    let os = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        "windows" => "pc-windows-msvc",
        other => return Err(format!("kotlin: no JNA slice for OS {other}")),
    };
    let triple = format!("{arch}-{os}");
    NATIVE_SLICES
        .iter()
        .find(|(t, _, _)| *t == triple)
        .map(|(_, prefix, lib)| (*prefix, *lib))
        .ok_or_else(|| format!("kotlin: no JNA slice for host {triple}"))
}

pub fn run(args: &[String]) -> Result {
    let mut smoke = false;
    let mut test_server = false;
    let mut generate_only = false;
    let mut android = false;
    let mut gradle_args: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--smoke" => smoke = true,
            "--test-server" => test_server = true,
            "--generate-only" => generate_only = true,
            "--android" => android = true,
            "--" => gradle_args.extend(it.by_ref().cloned()),
            other => {
                return Err(format!(
                    "kotlin: unknown argument `{other}` (--smoke, --test-server, --generate-only, --android, -- <gradle args>)"
                ))
            }
        }
    }
    test_server |= smoke;
    if android && test_server {
        return Err("kotlin: --android can't be combined with --smoke / --test-server: the Android natives are \
                    release builds without test-server, and the generated Kotlin must match them"
            .into());
    }
    if android && !generate_only {
        android::check_tools()?;
    }
    let features: &[&str] = if test_server { &["--features", "test-server"] } else { &[] };
    let project = root().join("bindings").join("kotlin");
    let build = project.join("build");

    // 1. Host debug cdylib.
    step(
        "kotlin: host debug build of ov-ffi",
        cargo().args(["build", "--locked", "--lib", "-p", PACKAGE]).args(features),
    )?;
    let (prefix, lib) = host_slice()?;
    let dylib = target_root().join("debug").join(lib);

    // 2. Kotlin sources.
    let scratch = build.join("uniffi-tmp");
    reset_dir(&scratch)?;
    step(
        "kotlin: uniffi-bindgen (Kotlin)",
        cargo()
            .args(["run", "--locked", "-q", "-p", PACKAGE, "--bin", "uniffi-bindgen"])
            .args(["--features", if test_server { "cli,test-server" } else { "cli" }, "--"])
            .args(["generate", "--language", "kotlin", "--no-format", "--metadata-no-deps", "--out-dir"])
            .arg(&scratch)
            .arg(&dylib),
    )?;
    let generated = build.join("generated").join("uniffi").join("kotlin");
    let changed = sync_tree(&scratch, &generated)?;
    fs::remove_dir_all(&scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
    println!("kotlin: generated sources in {} ({changed} file(s) changed)", generated.display());

    // 2b. The Java facade (`com.openvireo.core.java`), generated from those sources.
    let facade_scratch = build.join("facade-tmp");
    reset_dir(&facade_scratch)?;
    let ov_ffi = generated.join("com").join("openvireo").join("core").join("ov_ffi.kt");
    let stats = crate::kotlin_facade::generate(&ov_ffi, &facade_scratch)?;
    let facade = build.join("generated").join("facade").join("kotlin");
    let changed = sync_tree(&facade_scratch, &facade)?;
    fs::remove_dir_all(&facade_scratch).map_err(|e| format!("{}: {e}", facade_scratch.display()))?;
    println!(
        "kotlin: Java facade in {} ({} files, {}/{} methods wrapped, {changed} file(s) changed)",
        facade.display(),
        stats.files,
        stats.wrapped,
        stats.total
    );

    // 3. The host native, in JNA's layout.
    let natives = build.join("natives").join(prefix);
    fs::create_dir_all(&natives).map_err(|e| format!("{}: {e}", natives.display()))?;
    copy_if_changed(&dylib, &natives.join(lib))?;
    println!("kotlin: native {} ({} bytes)", natives.join(lib).display(), size(&natives.join(lib))?);
    println!("kotlin: feature test-server: {}", if test_server { "on" } else { "off" });
    if generate_only {
        return Ok(());
    }

    if android {
        android::build_jni_libs(&build.join("jniLibs"))?;
    }

    // 4. Gradle.
    let mut gradle = gradlew(&project);
    if gradle_args.is_empty() {
        gradle.arg("test");
    } else {
        gradle.args(&gradle_args);
    }
    gradle.args(["-Pov.generate=false", "--console=plain"]);
    if android {
        gradle.args([":core-android:assembleRelease", "-Pov.android=true", "-Pov.requireAbis=all"]);
    }
    if smoke {
        step(
            "kotlin: build the testkit relay",
            cargo().args(["build", "--locked", "-p", "ov-testkit", "--example", "http_relay"]),
        )?;
        let relay =
            target_root().join("debug").join("examples").join(format!("http_relay{}", std::env::consts::EXE_SUFFIX));
        if !relay.exists() {
            return Err(format!("kotlin: the relay isn't at {}", relay.display()));
        }
        gradle.arg(format!("-Pov.testkitRelay={}", relay.display())).arg("-Pov.requireSmoke=true");
    }
    step("kotlin: gradle", &mut gradle)?;
    if android {
        android::verify_aar(&android::release_aar(&project)?)?;
    }
    Ok(())
}

pub(crate) fn gradlew(project: &Path) -> Command {
    let mut c =
        if cfg!(windows) { Command::new(project.join("gradlew.bat")) } else { Command::new(project.join("gradlew")) };
    c.current_dir(project);
    c
}

/// Makes `to` hold exactly the files of `from`, rewriting only the ones whose bytes differ.
/// Returns how many files were written or removed.
fn sync_tree(from: &Path, to: &Path) -> Result<usize> {
    let mut changed = 0;
    let wanted = files(from)?;
    for rel in &wanted {
        if copy_if_changed(&from.join(rel), &to.join(rel))? {
            changed += 1;
        }
    }
    if to.exists() {
        for rel in files(to)? {
            if !wanted.contains(&rel) {
                fs::remove_file(to.join(&rel)).map_err(|e| format!("{}: {e}", rel.display()))?;
                changed += 1;
            }
        }
    }
    Ok(changed)
}

/// Every file under `dir`, relative to it.
fn files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let p = entry.map_err(|e| e.to_string())?.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p.strip_prefix(dir).map_err(|e| e.to_string())?.to_path_buf());
            }
        }
    }
    Ok(out)
}

fn copy_if_changed(from: &Path, to: &Path) -> Result<bool> {
    let new = fs::read(from).map_err(|e| format!("{}: {e}", from.display()))?;
    if fs::read(to).is_ok_and(|old| old == new) {
        return Ok(false);
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    fs::write(to, new).map_err(|e| format!("{}: {e}", to.display()))?;
    Ok(true)
}

fn reset_dir(dir: &Path) -> Result {
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

fn size(p: &Path) -> Result<u64> {
    fs::metadata(p).map(|m| m.len()).map_err(|e| format!("{}: {e}", p.display()))
}
