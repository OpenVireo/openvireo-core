# Building

Everything builds with the toolchain pinned in `rust-toolchain.toml` (Rust 1.98.1, with the wasm32 and
iOS targets); `rustup` installs it on the first `cargo` call in the repo.

```sh
cargo build --workspace
cargo test --workspace
cargo xtask help          # every task
```

A full build of every binding takes more than 10 GB of `target/`. Each `cargo xtask` task honours
`CARGO_TARGET_DIR`. If two checkouts share a target directory, give each one its own xtask binary
(`cargo run -p xtask --target-dir <own dir> -- <task>`): the `cargo xtask` alias runs whichever
`target/debug/xtask` was built last, which may be another checkout's.

## The `ov` CLI

```sh
cargo build --release --locked -p ov      # target/release/ov
./target/release/ov version
```

Native dependencies: none beyond the Rust toolchain. TLS is rustls with the operating system's trust
store (`rustls-tls-native-roots`; webpki-roots is avoided for its CDLA licence).

`ov connect` runs a separate `openvireo-connect` binary from `PATH` (it stays on the TypeScript SDK), so
it isn't part of this build.

## WebAssembly: `@openvireo/core-wasm`

```sh
cargo xtask wasm                     # full + lite modules → bindings/ov-wasm/pkg/
cargo xtask wasm --skip-opt          # no wasm-opt, for quick iterations
cd bindings/ov-wasm/pkg && npm pack  # the tarball the SDK vendors
```

Needs the `wasm-bindgen` CLI at exactly the `wasm-bindgen` crate's version (`cargo install --locked
wasm-bindgen-cli --version 0.2.130`) and binaryen's `wasm-opt`. The task builds both cdylibs for
wasm32 in release, runs wasm-bindgen (`--target web`) and `wasm-opt -Oz`, assembles the npm package
from the `npm/` template and prints a size report. Package entries, loaders and conventions:
[bindings/ov-wasm/README.md](../bindings/ov-wasm/README.md).

How the SDK takes it: `packages/sdk/vendor/core-wasm/` in openvireo-sdk holds the `npm pack` tarball and a
`SOURCE.md` with the commit, sizes and checksums; `package.json` depends on it with `file:`. The web app
vendors the same tarball next to the SDK's and adds an `overrides` entry, because a `file:` dependency
inside a packed package doesn't install for its consumers. Both go away when the package is published.

## Swift: `OpenVireoCore.xcframework`

```sh
cargo xtask xcframework                 # every slice: ios, ios-sim (arm64 + x86_64), macos (arm64 + x86_64)
cargo xtask xcframework --test-server   # also the OPAQUE server steps, for test targets
cargo xtask xcframework --macos-only    # only the macOS slice, enough for `swift test`
cargo xtask xcframework --smoke         # then `swift test` in bindings/ov-ffi/SmokeTests
```

macOS only. Outputs (git-ignored), under `bindings/ov-ffi/`: `build/OpenVireoCore.xcframework` and
the generated `Sources/OpenVireoRustCore/OpenVireoRustCore.swift`. The static libraries and the
bindgen run always use the same features, so the generated Swift never calls a symbol the library
lacks. Never ship a `--test-server` build.

How iOS takes it: `scripts/build-vendor.sh` in openvireo-ios clones this repo at the commit in its
`CORE_REV` (or builds in `CORE_SRC`, a checkout of exactly that commit), runs `cargo xtask xcframework`
twice (with and without `--test-server`), and copies the static libraries per SDK, the C module and the
generated Swift into `Vendor/Frameworks/core/{test,release}/`. The Debug configuration links the test
build, Release the plain one. The app links the static libraries directly rather than the xcframework
bundle. See openvireo-ios `Vendor/core/SOURCE.md`.

## Kotlin/JVM: `com.openvireo:openvireo-core-jvm`

```sh
cargo xtask kotlin                      # host cdylib, uniffi-bindgen kotlin, host native, ./gradlew test
cargo xtask kotlin --smoke              # also the smoke test against the testkit relay (implies --test-server)
cargo xtask kotlin --generate-only      # stop before Gradle (what Gradle's :generateBindings runs)
cargo xtask kotlin -- build             # any Gradle tasks instead of `test`
cargo xtask kotlin --android            # also the Android AAR: cargo-ndk for arm64-v8a, armeabi-v7a, x86_64
```

Needs JDK 17+ (Gradle 9 runs on it); the jar itself targets Java 11. The generated Kotlin and the natives are
built into `bindings/kotlin/build/` (git-ignored), never committed; `-Pov.nativesDir=<dir>` points the
jar at a full set of natives in JNA's layout. The same step generates the Java facade
(`com.openvireo.core.java`, `CompletableFuture` wrappers, `xtask/src/kotlin_facade.rs`) from the generated
Kotlin; it is compiled into the jar and the AAR. Details: [bindings/kotlin/README.md](../bindings/kotlin/README.md).

`--android` needs an Android SDK + NDK r27+, `cargo install cargo-ndk --locked` and `rustup target add
aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` (not in `rust-toolchain.toml`, so
other builds don't download them); it prints these commands if one is missing. Gradle only includes
`:core-android` when an Android SDK is found (`ANDROID_HOME` / `local.properties`) or with
`-Pov.android=true`. Details: [bindings/kotlin/README.md#android](../bindings/kotlin/README.md#android).

## C++: `libovcore` + `<ovcore.h>`

```sh
cargo xtask cpp                                   # CMake package in target/ovcore-cpp/<target>/
cargo xtask cpp --target x86_64-unknown-linux-gnu # one release target (rustup target add it first)
cargo xtask cpp --features test-server            # test builds only
cargo xtask cpp --check-coverage                  # builds nothing: every facade item must be bridged
```

Without `--target` it builds `universal-apple-darwin` on macOS (arm64 + x86_64 joined with `lipo`) and the
host triple elsewhere. The release targets are `universal-apple-darwin`, `x86_64-pc-windows-msvc`,
`aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. A consumer uses
`find_package(OpenVireoCore)` and links `OpenVireoCore::ovcore`. Details:
[bindings/ov-ffi-cpp/README.md](../bindings/ov-ffi-cpp/README.md).

How the desktop takes it: from source, with Corrosion. `src/account/ovcore/` in openvireo is a wrapper
crate (`ov-desktop`) with no code of its own; its `Cargo.toml` depends on `ov-ffi-cpp` by git `rev`, and
its `Cargo.lock` pins the whole core. `cmake/OpenVireoCore.cmake` fetches Corrosion v0.6.1, imports the
wrapper as a static library (with `test-server` when `WITH_TESTS` is on), copies the generated headers
into `<build>/ovcore-include`, and passes `--cfg aes_armv8` on aarch64 (cargo doesn't read this repo's
`.cargo/config.toml` there). Corrosion builds one Rust target per configure, so a macOS build is for one
architecture. To build the desktop against a local core checkout, configure with
`-DOPENVIREO_CORE_SOURCE_DIR=<checkout>` (never for releases).

## Releases

A release is a version tag. Set the workspace version in `Cargo.toml` (`cargo update -w` updates
`Cargo.lock`), merge it to `develop`, and push the tag `v<version>`: the tag must match the version.
The release pipeline (`.github/workflows/release.yml`, `cargo xtask release`) then publishes
`@openvireo/core-wasm` to GitHub Packages, `OpenVireoCore.xcframework.zip` with its checksum and the
Swift source, per-OS `libovcore` archives and signed `ov` binaries (Apple notarization, Azure signing, a
GPG-signed `SHA256SUMS`) to a GitHub release. Run it by hand on `develop` with `publish` off for a dry
run. iOS and the desktop still build the core at a pinned commit, as above.

The bindings are part of the same release:

- **Python**: maturin-action builds the `openvireo` wheels (macOS arm64 and x86_64, manylinux_2_28
  x86_64 and aarch64, musllinux_1_2 x86_64, Windows x64) and the sdist; they are GitHub release
  assets (`pip install openvireo --find-links <release>`), not on PyPI yet. The version is the
  workspace version in PEP 440 form (`1.2.0-beta.1` becomes `1.2.0b1`).
- **Kotlin / Java**: `cargo xtask release jvm-native <target> <dir>` builds one jar slice per platform
  on its own runner; `cargo xtask release --only jvm --natives <dir> --jni-libs <dir>` assembles
  `openvireo-core-jvm-<v>.jar` and `openvireo-core-android-<v>.aar` (the Android libraries from
  `cargo xtask kotlin --android`). Both are release assets, and `cargo xtask release publish-maven`
  publishes them to GitHub Packages as `com.openvireo:openvireo-core-jvm` and
  `com.openvireo:openvireo-core-android`: it rebuilds them (the Gradle archives are reproducible)
  and publishes only when they match the verified assets byte for byte.
- **Signing**: the macOS dylib and the Windows DLL in the jar and inside the macOS and Windows wheels
  get the same Developer ID (notarized) and Azure signatures as `ov`; the wheels are repacked with a
  new `RECORD` (`.github/scripts/wheel_natives.py`). Every asset, wheels, jar and AAR included, is
  in the GPG-signed `SHA256SUMS`, and the wheels, sdist, jar and AAR also get a `.asc` each.
- **Verification**: `cargo xtask release verify` installs the platform's wheel into a fresh venv and
  imports it, runs a Java program against the jar, and checks the AAR, on each of the five release
  platforms.

Locally, `cargo xtask release --dry-run --only python,jvm` builds the host's wheel, the sdist and a jar
with only the host's slice, and `cargo xtask release verify <dir> --dry-run` checks them.

The crates set `publish = false`; nothing goes to crates.io.
