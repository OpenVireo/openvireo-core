# Building openvireo-core from source with Corrosion, the way the desktop does (rust-core.md,
# Phase 3). Corrosion runs cargo for ov-ffi-cpp; its build script exports the headers to
# OVCORE_INCLUDE_DIR.
#
#   cmake -S bindings/ov-ffi-cpp/example -B target/cpp-corrosion -G Ninja
#   cmake --build target/cpp-corrosion && target/cpp-corrosion/ovcore_example
#
# Corrosion v0.6 builds one Rust target per configure (it ignores CMAKE_OSX_ARCHITECTURES). For a
# macOS universal app, link the `cargo xtask cpp` package (find_package(OpenVireoCore)) instead, or
# configure once per arch with -DRust_CARGO_TARGET=<triple> and lipo the results.

cmake_minimum_required(VERSION 3.22)
# The same macOS floor `cargo xtask cpp` builds for (MACOSX_DEPLOYMENT_TARGET); set before project().
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS")
project(ovcore_corrosion_example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(Corrosion
  GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
  GIT_TAG 1499b14e4906a2890f5cee1547c8848db261753d # v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

# The openvireo-core checkout. The desktop gets it from a pinned git rev instead:
#   FetchContent_Declare(openvireo_core GIT_REPOSITORY <url> GIT_TAG <rev>)
#   FetchContent_MakeAvailable(openvireo_core)   # then use ${openvireo_core_SOURCE_DIR}
set(OPENVIREO_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../.." CACHE PATH "openvireo-core checkout")

corrosion_import_crate(
  MANIFEST_PATH "${OPENVIREO_CORE_DIR}/Cargo.toml"
  CRATES ov-ffi-cpp
  CRATE_TYPES staticlib
  LOCKED
)

set(OVCORE_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/ovcore-include")
corrosion_set_env_vars(ov_ffi_cpp "OV_CXX_INCLUDE_DIR=${OVCORE_INCLUDE_DIR}")

add_executable(ovcore_example main.cpp)
target_include_directories(ovcore_example PRIVATE "${OVCORE_INCLUDE_DIR}")
target_link_libraries(ovcore_example PRIVATE ov_ffi_cpp)
# The headers only exist once cargo has run, so compile after it.
add_dependencies(ovcore_example cargo-build_ov_ffi_cpp)
