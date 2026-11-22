//! `cargo xtask python`: build the `openvireo` Python package and run its tests (language-bindings.md
//! B1). Owned by B1 (only that task edits this file).
//!
//! 1. Finds or creates `bindings/python/.venv` (Python 3.10 or later). With `uv` on `PATH` it makes
//!    the venv with a uv-managed Python 3.12, so the system Python doesn't matter; without uv it uses
//!    `python3 -m venv` and needs `python3` ≥ 3.10.
//! 2. Installs `bindings/python/requirements-dev.txt` (maturin, pytest, the httpx/keyring extras).
//! 3. `maturin develop`: builds `bindings/ov-ffi` for the host, generates `openvireo._core` with the
//!    crate's own uniffi-bindgen, and installs the package editable into the venv.
//! 4. Checks the committed type stubs (`openvireo/__init__.pyi`, `openvireo/_core/ov_ffi.pyi`) match
//!    the generated module: `scripts/gen_stubs.py --check`. They're committed rather than generated
//!    per build because writing them imports the built module, and the release workflow's sdist job
//!    and maturin-action wheel jobs (some in manylinux containers) only run maturin; committed, they
//!    reach the sdist and every wheel as plain `python-source` files.
//! 5. Runs `pytest` in `bindings/python`.
//!
//! Flags:
//! - `--smoke`: builds with the crate's `test-server` feature, builds the testkit relay
//!   (`cargo build -p ov-testkit --example http_relay`, the in-memory auth + sync servers on
//!   loopback HTTP) and passes its path to pytest as `OV_TESTKIT_RELAY`; the tests start it. Without
//!   it, the live tests are skipped.
//! - `--wheel`: also builds a release wheel (never with `test-server`) into
//!   `<target>/wheels/` and prints its size.
//! - `--stubs`: rewrites the type stubs from the freshly built module instead of checking them (after
//!   a change to the core's exported API).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{cargo, root, run as step, target_root, Result};

pub fn run(args: &[String]) -> Result {
    let mut smoke = false;
    let mut wheel = false;
    let mut stubs = false;
    for a in args {
        match a.as_str() {
            "--smoke" => smoke = true,
            "--wheel" => wheel = true,
            "--stubs" => stubs = true,
            other => return Err(format!("python: unknown argument `{other}` (--smoke, --wheel, --stubs)")),
        }
    }
    let dir = project();
    let uv = which("uv");
    let venv = dir.join(".venv");
    let python = dev_venv()?;

    // Build + install the package.
    let mut develop = Command::new(bin(&venv, "maturin"));
    develop.arg("develop").current_dir(&dir).env("VIRTUAL_ENV", &venv).env_remove("CONDA_PREFIX");
    if uv.is_some() {
        develop.arg("--uv");
    }
    if smoke {
        develop.args(["--features", "test-server"]);
    }
    step(
        &format!("python: maturin develop (feature test-server: {})", if smoke { "on" } else { "off" }),
        &mut develop,
    )?;

    // Type stubs: the committed ones must match the module just built.
    let mut gen = Command::new(&python);
    gen.arg(dir.join("scripts").join("gen_stubs.py")).current_dir(&dir);
    if stubs {
        step("python: write the type stubs", &mut gen)?;
    } else {
        step("python: the type stubs are current (`--stubs` rewrites them)", gen.arg("--check"))?;
    }

    // Tests.
    let mut pytest = Command::new(&python);
    pytest.args(["-m", "pytest", "-q"]).current_dir(&dir);
    if smoke {
        step(
            "python: build the testkit relay",
            cargo().args(["build", "--locked", "-p", "ov-testkit", "--example", "http_relay"]),
        )?;
        let relay = target_root().join("debug").join("examples").join(exe("http_relay"));
        if !relay.exists() {
            return Err(format!("python: the relay isn't at {}", relay.display()));
        }
        pytest.env("OV_TESTKIT_RELAY", relay);
    } else {
        pytest.env_remove("OV_TESTKIT_RELAY");
    }
    step(&format!("python: pytest{}", if smoke { " (with the testkit relay)" } else { "" }), &mut pytest)?;

    if wheel {
        for p in release_build(&target_root().join("wheels"), false)? {
            let len = fs::metadata(&p).map_err(|e| e.to_string())?.len();
            println!("{:<64} {:>12} bytes", p.file_name().unwrap_or_default().to_string_lossy(), len);
        }
    }
    Ok(())
}

fn project() -> PathBuf {
    root().join("bindings").join("python")
}

/// `bindings/python/.venv` with the dev requirements (maturin, pytest, the extras); returns its Python.
fn dev_venv() -> Result<PathBuf> {
    let dir = project();
    let venv = dir.join(".venv");
    let python = ensure_venv(&dir, &venv, which("uv").as_deref())?;
    let reqs = dir.join("requirements-dev.txt");
    step("python: install dev requirements", pip_install(&python).arg("-r").arg(&reqs)).map(|()| python)
}

/// `pip install` into the venv of `python` (through uv when it's on `PATH`); add the arguments.
pub(crate) fn pip_install(python: &Path) -> Command {
    match which("uv") {
        Some(uv) => {
            let mut c = Command::new(uv);
            c.args(["pip", "install", "--quiet", "--python"]).arg(python);
            c
        }
        None => {
            let mut c = Command::new(python);
            c.args(["-m", "pip", "install", "--quiet", "--disable-pip-version-check"]);
            c
        }
    }
}

/// A new, empty venv at `venv` (replacing one there), for checking an installed wheel; returns its
/// Python. Same interpreter rules as the dev venv.
pub(crate) fn fresh_venv(venv: &Path) -> Result<PathBuf> {
    let parent = venv.parent().ok_or("python: venv path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    if venv.exists() {
        fs::remove_dir_all(venv).map_err(|e| format!("{}: {e}", venv.display()))?;
    }
    ensure_venv(parent, venv, which("uv").as_deref())
}

/// The release build for `cargo xtask release` and `--wheel`: a release wheel for the host (never
/// `test-server`) and, with `sdist`, the source distribution, into `out`. Returns the files written.
/// macOS wheels target [`crate::release::MACOS_DEPLOYMENT_TARGET`] unless `MACOSX_DEPLOYMENT_TARGET`
/// is set, as in the release workflow.
pub(crate) fn release_build(out: &Path, sdist: bool) -> Result<Vec<PathBuf>> {
    let dir = project();
    let venv = dir.join(".venv");
    dev_venv()?;
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let before = listing(out)?;
    let mut build = Command::new(bin(&venv, "maturin"));
    build.args(["build", "--release", "--out"]).arg(out).current_dir(&dir);
    if cfg!(target_os = "macos") && std::env::var_os("MACOSX_DEPLOYMENT_TARGET").is_none() {
        build.env("MACOSX_DEPLOYMENT_TARGET", crate::release::MACOS_DEPLOYMENT_TARGET);
    }
    step("python: release wheel (feature test-server: off)", &mut build)?;
    if sdist {
        let mut sd = Command::new(bin(&venv, "maturin"));
        sd.args(["sdist", "--out"]).arg(out).current_dir(&dir);
        step("python: sdist", &mut sd)?;
    }
    // Files maturin wrote or replaced in this run (the dir may hold older wheels).
    let after = listing(out)?;
    let written: Vec<PathBuf> = after.into_iter().filter(|f| !before.contains(f)).map(|(p, _)| p).collect();
    // maturin packs the whole workspace's Cargo.lock; prune it to the packed crates so the sdist
    // builds with `locked = true` (.github/scripts/sdist_lock.py, as in the release workflow).
    for tarball in written.iter().filter(|p| p.to_string_lossy().ends_with(".tar.gz")) {
        let mut prune = Command::new(bin(&venv, "python"));
        prune.arg(root().join(".github").join("scripts").join("sdist_lock.py")).arg(tarball);
        step("python: prune the sdist's Cargo.lock", &mut prune)?;
    }
    Ok(written)
}

/// (path, modified time) of every file in `dir`.
fn listing(dir: &Path) -> Result<Vec<(PathBuf, std::time::SystemTime)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = entry.map_err(|e| e.to_string())?.path();
        let modified = fs::metadata(&p).and_then(|m| m.modified()).map_err(|e| format!("{}: {e}", p.display()))?;
        if p.is_file() {
            out.push((p, modified));
        }
    }
    Ok(out)
}

/// The venv's Python, creating the venv first when it's missing or too old.
fn ensure_venv(dir: &Path, venv: &Path, uv: Option<&Path>) -> Result<PathBuf> {
    let python = bin(venv, "python");
    if python.exists() && python_ok(&python) {
        return Ok(python);
    }
    if venv.exists() {
        fs::remove_dir_all(venv).map_err(|e| format!("{}: {e}", venv.display()))?;
    }
    match uv {
        Some(uv) => {
            let mut c = Command::new(uv);
            c.args(["venv", "--quiet", "--python", "3.12"]).arg(venv).current_dir(dir);
            step("python: uv venv (Python 3.12)", &mut c)?;
        }
        None => {
            let system = PathBuf::from(if cfg!(windows) { "python" } else { "python3" });
            if !python_ok(&system) {
                return Err("python: needs Python 3.10 or later; install uv (`brew install uv`, or see \
                            https://docs.astral.sh/uv/) and rerun"
                    .into());
            }
            let mut c = Command::new(system);
            c.args(["-m", "venv"]).arg(venv).current_dir(dir);
            step("python: python3 -m venv", &mut c)?;
        }
    }
    Ok(python)
}

/// Whether `python` runs and is 3.10 or later.
fn python_ok(python: &Path) -> bool {
    Command::new(python)
        .args(["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"])
        .status()
        .is_ok_and(|s| s.success())
}

/// A program inside the venv (`bin/` on Unix, `Scripts\` on Windows).
fn bin(venv: &Path, name: &str) -> PathBuf {
    venv.join(if cfg!(windows) { "Scripts" } else { "bin" }).join(exe(name))
}

fn exe(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

/// `name` on `PATH`, if it's there.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(exe(name))).find(|p| p.is_file())
}
