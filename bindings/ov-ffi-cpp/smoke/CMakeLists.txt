# Smoke test of the OpenVireoCore CMake package (W1-BC acceptance).
#
#   cargo xtask cpp [--features test-server]
#   cmake -S bindings/ov-ffi-cpp/smoke -B target/cpp-smoke \
#     -DOpenVireoCore_DIR=$PWD/target/ovcore-cpp/universal-apple-darwin/lib/cmake/OpenVireoCore
#   cmake --build target/cpp-smoke && ctest --test-dir target/cpp-smoke --output-on-failure
#
# With a package built with `--features test-server` (OpenVireoCore_FEATURES), the smoke also
# replays the OPAQUE transcripts through the seeded steps and the server half; without it, it checks
# that those fail with `internal`.

cmake_minimum_required(VERSION 3.22)
# The same macOS floor `cargo xtask cpp` builds for (MACOSX_DEPLOYMENT_TARGET); set before project().
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS")
project(ovcore_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenVireoCore 0.0 REQUIRED)

add_executable(ovcore_smoke main.cpp below_facade.cpp)
target_link_libraries(ovcore_smoke PRIVATE OpenVireoCore::ovcore)
# The contract vectors and the .kdbx merge copies are read at run time.
get_filename_component(OV_VECTORS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../vectors" ABSOLUTE)
if("test-server" IN_LIST OpenVireoCore_FEATURES)
  set(_ov_test_server 1)
else()
  set(_ov_test_server 0)
endif()
message(STATUS "OpenVireoCore features: '${OpenVireoCore_FEATURES}'")
target_compile_definitions(ovcore_smoke PRIVATE
  OV_VECTORS_DIR="${OV_VECTORS_DIR}"
  OV_SMOKE_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
  OV_EXPECT_TEST_SERVER=${_ov_test_server})

enable_testing()
add_test(NAME ovcore_smoke COMMAND ovcore_smoke)
