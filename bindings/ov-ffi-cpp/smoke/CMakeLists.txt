# Smoke test of the OpenVireoCore CMake package (W1-BC acceptance).
#
#   cargo xtask cpp
#   cmake -S bindings/ov-ffi-cpp/smoke -B target/cpp-smoke \
#     -DOpenVireoCore_DIR=$PWD/target/ovcore-cpp/universal-apple-darwin/lib/cmake/OpenVireoCore
#   cmake --build target/cpp-smoke && ctest --test-dir target/cpp-smoke --output-on-failure

cmake_minimum_required(VERSION 3.22)
# The same macOS floor `cargo xtask cpp` builds for (MACOSX_DEPLOYMENT_TARGET); set before project().
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS")
project(ovcore_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenVireoCore 0.0 REQUIRED)

add_executable(ovcore_smoke main.cpp)
target_link_libraries(ovcore_smoke PRIVATE OpenVireoCore::ovcore)

enable_testing()
add_test(NAME ovcore_smoke COMMAND ovcore_smoke)
