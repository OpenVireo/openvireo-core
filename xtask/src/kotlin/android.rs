//! `cargo xtask kotlin --android` (language-bindings.md §3, task B4): the Android AAR.
//!
//! 1. Checks for `cargo ndk` and the Rust Android targets, and prints the install commands when one
//!    is missing (nothing is installed here).
//! 2. Builds `libov_ffi.so` for every ABI in [`ANDROID_ABIS`] with cargo-ndk: release profile
//!    (stripped, LTO), never `test-server`, cdylib only (no staticlib), API level [`MIN_SDK`].
//! 3. Copies them to `bindings/kotlin/build/jniLibs/<abi>/libov_ffi.so`, where `:core-android`
//!    picks them up (the caller then runs `./gradlew :core-android:assembleRelease`).
//! 4. [`verify_aar`]: the AAR has every ABI's `libov_ffi.so`, a `classes.jar` with the generated
//!    binding and the Android hosts, and the consumer R8 rules; prints the sizes. The 64-bit
//!    libraries must have 16 KB-aligned LOAD segments (Google Play requires it for Android 15+).
//!    JNA's `libjnidispatch.so` isn't in this AAR: it comes from JNA's own AAR, a dependency.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{copy_if_changed, size, PACKAGE};
use crate::{cargo, run as step, target_root, Result};

/// Each ABI of the AAR: the Android ABI name (jniLibs directory) and the Rust target.
/// Keep in step with `androidAbis` in bindings/kotlin/core-android/build.gradle.kts.
pub const ANDROID_ABIS: [(&str, &str); 3] = [
    ("arm64-v8a", "aarch64-linux-android"),
    ("armeabi-v7a", "armv7-linux-androideabi"),
    ("x86_64", "x86_64-linux-android"),
];

/// The AAR's minSdk, passed to cargo-ndk as the platform (API level) to link against.
const MIN_SDK: &str = "26";

/// Classes `classes.jar` must contain: the generated binding, a shared host, an Android host, and
/// the Java facade (generated, hand-written shared, Android).
const REQUIRED_CLASSES: [&str; 6] = [
    "com/openvireo/core/OvClient.class",
    "com/openvireo/core/hosts/UrlConnectionTransport.class",
    "com/openvireo/core/hosts/AndroidLogSink.class",
    "com/openvireo/core/java/JOvClient.class",
    "com/openvireo/core/java/JHosts.class",
    "com/openvireo/core/java/JDefaultHosts.class",
];

/// Fails with the install commands when `cargo ndk` or a Rust Android target is missing.
pub fn check_tools() -> Result {
    let mut missing = Vec::new();
    let ndk = cargo().args(["ndk", "--version"]).output();
    if !ndk.is_ok_and(|o| o.status.success()) {
        missing.push("cargo install cargo-ndk --locked".to_string());
    }
    let sysroot = Command::new("rustc")
        .current_dir(crate::root())
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("kotlin --android: rustc --print sysroot: {e}"))?;
    let sysroot = PathBuf::from(String::from_utf8_lossy(&sysroot.stdout).trim());
    let targets: Vec<&str> = ANDROID_ABIS
        .iter()
        .map(|(_, t)| *t)
        .filter(|t| !sysroot.join("lib").join("rustlib").join(t).join("lib").is_dir())
        .collect();
    if !targets.is_empty() {
        missing.push(format!("rustup target add {}", targets.join(" ")));
    }
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "kotlin --android needs cargo-ndk and the Rust Android targets. Install them with:\n  {}\n\
         and an Android NDK (r27+): set ANDROID_NDK_HOME, or install one under $ANDROID_HOME/ndk/.",
        missing.join("\n  ")
    ))
}

/// Builds `libov_ffi.so` for every ABI and copies each to `<jni_libs>/<abi>/libov_ffi.so`.
pub fn build_jni_libs(jni_libs: &Path) -> Result {
    let mut ndk = cargo();
    ndk.arg("ndk");
    for (abi, _) in ANDROID_ABIS {
        ndk.args(["-t", abi]);
    }
    // `rustc --crate-type cdylib`: the crate also lists staticlib, which Android doesn't use and
    // which costs an LTO link and a large archive per target.
    ndk.args(["-P", MIN_SDK, "rustc", "--locked", "--release", "--lib", "-p", PACKAGE, "--crate-type", "cdylib"]);
    step("kotlin: cargo-ndk release build of ov-ffi (arm64-v8a, armeabi-v7a, x86_64)", &mut ndk)?;
    for (abi, triple) in ANDROID_ABIS {
        let built = target_root().join(triple).join("release").join("libov_ffi.so");
        let dest = jni_libs.join(abi).join("libov_ffi.so");
        copy_if_changed(&built, &dest)?;
        println!("kotlin: {} ({} bytes)", dest.display(), size(&dest)?);
    }
    Ok(())
}

/// The release AAR under `core-android/build/outputs/aar/`.
pub fn release_aar(project: &Path) -> Result<PathBuf> {
    let dir = project.join("core-android").join("build").join("outputs").join("aar");
    let entries = fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with("-release.aar")))
        .ok_or_else(|| format!("kotlin --android: no *-release.aar in {}", dir.display()))
}

/// Checks the AAR's natives and classes and prints its size and each ABI's library size.
pub fn verify_aar(aar: &Path) -> Result {
    let bytes = fs::read(aar).map_err(|e| format!("{}: {e}", aar.display()))?;
    let entries = zip_entries(&bytes).map_err(|e| format!("{}: {e}", aar.display()))?;
    let find = |name: &str| entries.iter().find(|e| e.name == name);
    println!("\nkotlin: {} ({})", aar.display(), human(bytes.len() as u64));
    let mut problems = Vec::new();
    for (abi, _) in ANDROID_ABIS {
        let name = format!("jni/{abi}/libov_ffi.so");
        match find(&name) {
            Some(e) => {
                println!("  {name:<34} {:>10} ({} compressed)", human(e.size), human(e.compressed));
                if abi != "armeabi-v7a" {
                    if let Err(p) = check_page_alignment(&e.data(&bytes)?) {
                        problems.push(format!("{name}: {p}"));
                    }
                }
            }
            None => problems.push(format!("{name} is missing")),
        }
    }
    match find("classes.jar") {
        Some(jar) => {
            let jar_bytes = jar.data(&bytes)?;
            let classes = zip_entries(&jar_bytes).map_err(|e| format!("classes.jar: {e}"))?;
            let count = classes.iter().filter(|c| c.name.ends_with(".class")).count();
            println!("  {:<34} {:>10} ({count} classes)", "classes.jar", human(jar.size));
            for class in REQUIRED_CLASSES {
                if !classes.iter().any(|c| c.name == class) {
                    problems.push(format!("classes.jar has no {class}"));
                }
            }
        }
        None => problems.push("classes.jar is missing".into()),
    }
    if find("proguard.txt").is_none() {
        problems.push("proguard.txt (consumer R8 rules) is missing".into());
    }
    if problems.is_empty() {
        println!("kotlin: AAR ok: libov_ffi.so for {}", ANDROID_ABIS.map(|(abi, _)| abi).join(", "));
        Ok(())
    } else {
        Err(format!("kotlin --android: the AAR is incomplete:\n  {}", problems.join("\n  ")))
    }
}

/// A 64-bit ELF shared library must have every LOAD segment aligned to at least 16 KB.
fn check_page_alignment(elf: &[u8]) -> std::result::Result<(), String> {
    let u16_at = |o: usize| elf.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| elf.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u64_at = |o: usize| elf.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    if elf.get(0..6) != Some(b"\x7fELF\x02\x01") {
        return Err("not a little-endian 64-bit ELF file".into());
    }
    let (Some(phoff), Some(phentsize), Some(phnum)) = (u64_at(0x20), u16_at(0x36), u16_at(0x38)) else {
        return Err("truncated ELF header".into());
    };
    for i in 0..usize::from(phnum) {
        let ph = phoff as usize + i * usize::from(phentsize);
        let (Some(kind), Some(align)) = (u32_at(ph), u64_at(ph + 0x30)) else {
            return Err("truncated program header".into());
        };
        const PT_LOAD: u32 = 1;
        if kind == PT_LOAD && align < 0x4000 {
            return Err(format!("LOAD segment aligned to {align:#x}, not 16 KB (0x4000)"));
        }
    }
    Ok(())
}

/// One file in a zip archive (AAR, jar).
struct ZipEntry {
    name: String,
    method: u16,
    compressed: u64,
    size: u64,
    local_header: usize,
}

impl ZipEntry {
    /// The entry's uncompressed bytes (stored or deflated).
    fn data(&self, zip: &[u8]) -> Result<Vec<u8>> {
        let h = self.local_header;
        let field = |o: usize| zip.get(h + o..h + o + 2).map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])));
        let (Some(name_len), Some(extra_len)) = (field(26), field(28)) else {
            return Err(format!("{}: truncated local header", self.name));
        };
        let start = h + 30 + name_len + extra_len;
        let raw =
            zip.get(start..start + self.compressed as usize).ok_or_else(|| format!("{}: truncated data", self.name))?;
        match self.method {
            0 => Ok(raw.to_vec()),
            8 => {
                let mut out = Vec::with_capacity(self.size as usize);
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("{}: {e}", self.name))?;
                Ok(out)
            }
            m => Err(format!("{}: unsupported compression method {m}", self.name)),
        }
    }
}

/// The entries of a zip archive, from its central directory (no zip64: AARs are small).
fn zip_entries(zip: &[u8]) -> Result<Vec<ZipEntry>> {
    let u16_at = |o: usize| zip.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| zip.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let eocd = (0..zip.len().saturating_sub(21))
        .rev()
        .find(|&i| zip[i..].starts_with(b"PK\x05\x06"))
        .ok_or("no zip end-of-central-directory record")?;
    let count = u16_at(eocd + 10).ok_or("truncated zip")?;
    let mut at = u32_at(eocd + 16).ok_or("truncated zip")? as usize;
    let mut entries = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        if u32_at(at) != Some(0x0201_4b50) {
            return Err("bad zip central directory".into());
        }
        let field16 = |o: usize| u16_at(at + o).map(usize::from).ok_or("truncated zip");
        let field32 = |o: usize| u32_at(at + o).ok_or("truncated zip");
        let (name_len, extra_len, comment_len) = (field16(28)?, field16(30)?, field16(32)?);
        let name = zip.get(at + 46..at + 46 + name_len).ok_or("truncated zip")?;
        entries.push(ZipEntry {
            name: String::from_utf8_lossy(name).into_owned(),
            method: field16(10)? as u16,
            compressed: u64::from(field32(20)?),
            size: u64::from(field32(24)?),
            local_header: field32(42)? as usize,
        });
        at += 46 + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

fn human(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MiB", n as f64 / f64::from(1 << 20))
    } else {
        format!("{:.1} KiB", n as f64 / 1024.0)
    }
}
