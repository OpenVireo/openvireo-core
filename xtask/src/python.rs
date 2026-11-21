//! `cargo xtask python`: build the `openvireo` Python package and run its tests (language-bindings.md
//! B1). Owned by B1 (only that task edits this file).
//!
//! 1. Finds or creates `bindings/python/.venv` (Python 3.10 or later). With `uv` on `PATH` it makes
//!    the venv with a uv-managed Python 3.12, so the system Python doesn't matter; without uv it uses
//!    `python3 -m venv` and needs `python3` ≥ 3.10.
//! 2. Installs `bindings/python/requirements-dev.txt` (maturin, pytest, the httpx/keyring extras).
//! 3. `maturin develop`: builds `bindings/ov-ffi` for the host, generates `openvireo._core` with the
//!    crate's own uniffi-bindgen, and installs the package editable into the venv.
//! 4. Runs `pytest` in `bindings/python`.
//!
//! Flags:
//! - `--smoke`: builds with the crate's `test-server` feature, builds the testkit relay
//!   (`cargo build -p ov-testkit --example http_relay`, the in-memory auth + sync servers on
//!   loopback HTTP) and passes its path to pytest as `OV_TESTKIT_RELAY`; the tests start it. Without
//!   it, the live tests are skipped.
//! - `--wheel`: also builds a release wheel (never with `test-server`) into
//!   `<target>/wheels/` and prints its size.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{cargo, root, run as step, target_root, Result};

pub fn run(args: &[String]) -> Result {
    let mut smoke = false;
    let mut wheel = false;
    for a in args {
        match a.as_str() {
            "--smoke" => smoke = true,
            "--wheel" => wheel = true,
            other => return Err(format!("python: unknown argument `{other}` (--smoke, --wheel)")),
        }
    }
    let dir = root().join("bindings").join("python");
    let uv = which("uv");
    let venv = dir.join(".venv");
    let python = ensure_venv(&dir, &venv, uv.as_deref())?;

    // Tools.
    let reqs = dir.join("requirements-dev.txt");
    let mut install = match &uv {
        Some(uv) => {
            let mut c = Command::new(uv);
            c.args(["pip", "install", "--quiet", "--python"]).arg(&python);
            c
        }
        None => {
            let mut c = Command::new(&python);
            c.args(["-m", "pip", "install", "--quiet"]);
            c
        }
    };
    step("python: install dev requirements", install.arg("-r").arg(&reqs))?;

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
        let out = target_root().join("wheels");
        let mut build = Command::new(bin(&venv, "maturin"));
        build.args(["build", "--release", "--out"]).arg(&out).current_dir(&dir);
        step("python: release wheel (feature test-server: off)", &mut build)?;
        for entry in fs::read_dir(&out).map_err(|e| format!("{}: {e}", out.display()))? {
            let p = entry.map_err(|e| e.to_string())?.path();
            if p.extension().is_some_and(|x| x == "whl") {
                let len = fs::metadata(&p).map_err(|e| e.to_string())?.len();
                println!("{:<64} {:>12} bytes", p.file_name().unwrap_or_default().to_string_lossy(), len);
            }
        }
    }
    Ok(())
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
