//! Generates the C++ side of the cxx bridge and compiles it into this crate's static library.
//!
//! With `OV_CXX_INCLUDE_DIR` set (by `cargo xtask cpp` or a Corrosion build), the headers a C++
//! consumer needs are also copied there, at the paths the generated code includes them by:
//!
//! ```text
//! $OV_CXX_INCLUDE_DIR/ovcore.h                         umbrella header (include this)
//! $OV_CXX_INCLUDE_DIR/rust/cxx.h                       cxx runtime types
//! $OV_CXX_INCLUDE_DIR/ov-ffi-cpp/src/lib.rs.h          generated bridge
//! $OV_CXX_INCLUDE_DIR/ov-ffi-cpp/include/{host,ovcore}.h
//! ```

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const HEADERS: [&str; 2] = ["include/host.h", "include/ovcore.h"];

fn main() {
    cxx_build::bridge("src/lib.rs").std("c++17").compile("ov-ffi-cpp-bridge");

    println!("cargo:rerun-if-changed=src/lib.rs");
    for h in HEADERS {
        println!("cargo:rerun-if-changed={h}");
    }
    println!("cargo:rerun-if-env-changed=OV_CXX_INCLUDE_DIR");

    if let Some(dest) = env::var_os("OV_CXX_INCLUDE_DIR") {
        export_headers(Path::new(&dest));
    }
}

fn export_headers(dest: &Path) {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let generated = out.join("cxxbridge").join("include");

    copy(&generated.join("ov-ffi-cpp/src/lib.rs.h"), &dest.join("ov-ffi-cpp/src/lib.rs.h"));
    copy(&generated.join("rust/cxx.h"), &dest.join("rust/cxx.h"));
    for h in HEADERS {
        copy(&manifest.join(h), &dest.join("ov-ffi-cpp").join(h));
    }
    fs::write(dest.join("ovcore.h"), "#pragma once\n#include \"ov-ffi-cpp/include/ovcore.h\"\n")
        .unwrap_or_else(|e| panic!("writing {}/ovcore.h: {e}", dest.display()));
}

fn copy(from: &Path, to: &Path) {
    fs::create_dir_all(to.parent().unwrap()).unwrap_or_else(|e| panic!("creating {}: {e}", to.display()));
    // `fs::copy` follows symlinks (cxx-build links some headers), so this writes real files.
    fs::copy(from, to).unwrap_or_else(|e| panic!("copying {} to {}: {e}", from.display(), to.display()));
}
