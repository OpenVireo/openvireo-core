# OpenVireo core for Kotlin and the JVM

`com.openvireo:openvireo-core-jvm`: the OpenVireo core (accounts, vaults, sync, share links, KDBX)
for Kotlin and Java 11+ on macOS, Linux and Windows. It is the UniFFI binding of
[`bindings/ov-ffi`](../ov-ffi) (package `com.openvireo.core`), loaded through JNA, plus ready-made
Host parts so a program needs no glue.

## Install

From GitHub Packages (a token with `read:packages` is needed even for public packages):

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/openvireo/openvireo-core")
        credentials {
            username = providers.environmentVariable("GITHUB_ACTOR").get()
            password = providers.environmentVariable("GITHUB_TOKEN").get()
        }
    }
}
dependencies {
    implementation("com.openvireo:openvireo-core-jvm:<core version>")
}
```

The jar carries the native library for `darwin-aarch64`, `darwin-x86-64`, `linux-x86-64`,
`linux-aarch64` and `win32-x86-64`; JNA picks the right one. It depends on JNA 5 and
kotlinx-coroutines-core.

## Quickstart

```kotlin
import com.openvireo.core.*
import com.openvireo.core.hosts.defaultHost
import kotlinx.coroutines.runBlocking
import java.nio.file.Path

fun main() = runBlocking {
    val client = OvClient(
        ClientConfig(DeviceInfo(id = null, name = "my-tool", platform = Platform.CLI), offline = true, server = null),
        defaultHost(cacheDir = Path.of("ov-cache")),
    )
    val account = client.connect("https://accounts.openvireo.com", CancelToken())
    val step = account.login(LoginInput(email, password, secretKey, totp = null, trustDevice = true), CancelToken())
    check(step is LoginStep.Unlocked)
    for (v in account.vaults(CancelToken())) println(v.name)
}
```

Every network or disk call is a `suspend` function; synchronous ones (`Vault.entries`,
`Vault.addEntry`, the crypto functions) are plain. Pass a `CancelToken` and call `cancel()` on it
from anywhere to abort a call with `aborted`.

### Errors

Everything throws `OvException` (one variant, `OvException.Failure`). Read its fields with the
extensions in `com.openvireo.core`:

```kotlin
try {
    account.login(input, CancelToken())
} catch (e: OvException) {
    when (e.code) {
        OvErrorCode.UNAUTHORIZED -> println("wrong password")
        OvErrorCode.NETWORK_ERROR -> println("offline")
        else -> println("${e.wireCode}: ${e.errorMessage}")
    }
}
```

`e.message` is a summary of every field, for logs.

### The Host

`defaultHost(...)` bundles these parts (package `com.openvireo.core.hosts`); replace any of them:

| Part | Default | Notes |
|---|---|---|
| `HttpTransport` | `JavaNetHttpTransport` | `java.net.http`, async, no redirects, no cookies, streams for server events. `UrlConnectionTransport` is the `HttpURLConnection` alternative (it also runs on Android; the JVM's `HttpURLConnection` can't send PATCH). |
| `SecureStore` | `MemoryStore` | Nothing persists, so each run is a new device. Implement `SecureStore` over your OS keychain to keep sessions and trusted Secret Keys; `connect` then restores the session signed in but locked, so call `unlock(password, null)` instead of `login`. |
| `BlobCache` | `FileCache(cacheDir)`, or `MemoryCache` | The offline cache: ciphertext and public data only. |
| `Clock` | `SystemClock` | |
| `LogSink` | `JulLogSink` | `java.util.logging`, logger `openvireo.<module>`. |

Your own Host parts implement the generated interfaces (`HttpTransport`, `SecureStore`,
`BlobCache`, `Clock`, `LogSink`) with `suspend` methods. They are called from the core's threads on
`Dispatchers.Default`, so do blocking I/O with `withContext(Dispatchers.IO)`. Throw
`TransportException` from a transport and `OvException` (`ovException(code, message)`) from a store or
cache; anything else reaches the core as a network error (transport) or `internal`.

### Secrets

Passwords, Secret Keys and field values cross into the JVM as `ByteArray`. The core wipes its own
copies; the JVM can't guarantee that for yours, so `fill(0)` arrays you no longer need.

### Names that differ from Swift

Every generated object is `AutoCloseable` (`close()` frees its native handle), and exceptions are
`Throwable`s, so a few names differ in Kotlin (`bindings/ov-ffi/uniffi.toml`, `[bindings.kotlin.rename]`):
`EventStream.closeStream()`, `ByteStream.closeStream()`, `ServiceAccount.endSession()`,
`OvException.Failure.errorMessage`, `TransportException.Tls/Other.reason`.

## Java

`com.openvireo.core.java` is the whole API without coroutines: every `suspend` method returns a
`CompletableFuture`. It is in the same jar (and AAR).

```java
import com.openvireo.core.*;
import com.openvireo.core.java.*;
import java.nio.file.Path;

JOvClient client = new JOvClient(
    new ClientConfig(new DeviceInfo(null, "my-tool", Platform.CLI), false, null),
    JDefaultHosts.create(Path.of("ov-cache")));
JAccount account = client.connect("https://accounts.openvireo.com").join();
LoginStep step = account.login(new LoginInput(email, password, secretKey, null, true)).join();
if (step instanceof LoginStep.Unlocked) {
    for (VaultInfo v : account.vaults().join()) System.out.println(v.getName());
}
JVault vault = account.openVault(vaultId).join();
String id = vault.addEntry(vault.rootGroupId(), JRecords.newEntryInput(fields, List.of(), null, null, EntryExpiry.Keep.INSTANCE));
vault.sync(new SyncOptions(true, false)).join();
```

- **`J<Object>`** (`JOvClient`, `JAccount`, `JVault`, `JServiceAccount`, `JSelfHosted`,
  `JEventStream`, `JTotpChallenge`) wraps each generated object Java can't use as is. `suspend`
  methods return `CompletableFuture<T>` (`Void` for none); synchronous ones are plain calls. A method
  that takes a `CancelToken` has a second overload without it: cancel the future to cancel the call
  (the coroutine, the Rust future and the token). Objects come back wrapped; `unwrap()` gives the
  generated object, `close()` frees it. `CancelToken`, `Host` and the OPAQUE state objects need no
  wrapper. Wrap an object you got from a record with `new JTotpChallenge(step.getChallenge())`.
- **Threads**: futures run on `JScope.defaultScope()` (a `SupervisorJob` on `Dispatchers.Default`).
  Every wrapper constructor also takes an `Executor` (or a `CoroutineScope`); objects it returns use
  the same one. Don't block on `join()` inside a Host part.
- **`JOv`**: every free function (crypto primitives, share links, TOTP, OPAQUE, wire codes) as a static.
- **Unsigned numbers** are the next wider signed type (`UInt` → `long`, `UShort` → `int`), checked
  going in. Kotlin hides constructors and getters with unsigned types from Java, so records with one
  have a `JRecords.new<Record>(...)` factory and `JRecords.get<Field>(record)` getters, e.g.
  `JRecords.newShareOptions(3600L, 2L, null, null, null)`, `JRecords.getOpensLeft(info)`.
- **Errors**: futures complete exceptionally with `OvException`; `join()` wraps it in
  `CompletionException`, `get()` in `ExecutionException`. `JErrors.code(e)`, `wireCode`, `status`,
  `retryAfter`, ... unwrap those and return `null` for other exceptions. Synchronous methods declare
  `throws OvException` where the core can fail.
- **Host parts in Java**: implement `JHttpTransport` (`send`, `openStream` → `JByteStream`),
  `JSecureStore` and `JBlobCache` with futures; `Clock` and `LogSink` are plain interfaces (lambdas
  work). `JHosts.create(http, store, cache, clock, log)` or `JHosts.builder()` builds the `Host`;
  `JDefaultHosts.builder()` starts from the platform defaults (`JavaNetHttpTransport`/`JulLogSink` on
  the JVM, `UrlConnectionTransport`/`AndroidLogSink` on Android) and takes either Java parts or the
  shipped Kotlin ones. `JHosts.fromKotlin(new JavaNetHttpTransport())` turns a Kotlin part into its
  Java interface, to decorate it. The same rules apply as for Kotlin parts: no redirects, no cookies,
  `TransportException` from a transport, `JErrors.ovException(code, message)` from a store or cache.

The facade is **generated** (`xtask/src/kotlin_facade.rs`) from the uniffi-bindgen Kotlin on every
build, so it can't drift from the core; `FacadeCoverageTest` checks by reflection that every
`suspend` or unsigned member of the generated classes has a counterpart.

## Building

```sh
cargo xtask kotlin            # build the host native + generated Kotlin, then ./gradlew test
cargo xtask kotlin --smoke    # plus the smoke test against the in-memory test servers
cargo xtask kotlin --android  # plus the Android AAR (see Android below)
cd bindings/kotlin && ./gradlew build   # also works on its own: it runs the cargo step itself
```

Needs Rust (the repo's toolchain) and JDK 17+ (to run Gradle 9; the jar targets Java 11).

### How the build is fed

- **Generated Kotlin** is never committed. `cargo xtask kotlin` (or Gradle's `:generateBindings`,
  which runs `cargo xtask kotlin --generate-only`) builds the host `ov-ffi` cdylib in debug, so its
  UniFFI metadata survives, runs `uniffi-bindgen generate --language kotlin` and writes
  `build/generated/uniffi/kotlin/com/openvireo/core/ov_ffi.kt`, only rewriting it when it changes.
  `-Pov.generatedDir=<dir>` uses sources made elsewhere (and skips cargo); `-Pov.generate=false`
  just skips cargo.
- **The Java facade** is generated in the same step from that file into
  `build/generated/facade/kotlin` (`rootProject.extra["ovFacadeDir"]`, compiled into both the jar and
  the AAR). With `-Pov.generatedDir`, pass `-Pov.facadeDir=<dir>` too.
- **Natives** come from a directory in JNA's resource layout:
  `<dir>/{darwin-aarch64,darwin-x86-64}/libov_ffi.dylib`, `<dir>/{linux-x86-64,linux-aarch64}/libov_ffi.so`,
  `<dir>/win32-x86-64/ov_ffi.dll`. The default is `build/natives`, where the xtask copies the host
  slice. A release passes `-Pov.nativesDir=<dir>` with every slice (release builds of `ov-ffi`, one
  per target) and `-Pov.requireNatives=all`, which fails the jar if one is missing. The natives
  must come from the same commit and features as the generated Kotlin.
- **`test-server`**: `--smoke` / `--test-server` (`-Pov.testServer=true` for Gradle's own cargo step)
  build with the OPAQUE server steps. Never publish such a build.
- **Version**: the core version from the root `Cargo.toml`; `-Pov.version=<v>` overrides it.
- **Publishing**: `./gradlew publish` sends the jar, sources and (empty) javadoc jar to GitHub
  Packages with `GITHUB_ACTOR` / `GITHUB_TOKEN`.

### Layout

| Path | What |
|---|---|
| `shared/src/main/kotlin` | Hand-written code for every artifact (JVM jar and the Android AAR): the hosts that run on both, `OvException` field extensions, the Java facade's runtime (`JScope`, `JHosts` and the `J*` Host interfaces, `JErrors`). A source directory, not a Gradle project, because each artifact compiles it next to the generated sources. |
| `core-jvm/` | The JVM jar: `JavaNetHttpTransport`, `JulLogSink`, `defaultHost`, `JDefaultHosts`, natives as resources, tests (Kotlin in `src/test/kotlin`, plain Java in `src/test/java`). |
| `core-android/` | The Android AAR: `AndroidLogSink`, `defaultHost(context)`, `JDefaultHosts`, consumer R8 rules, the instrumented `LoadTest`. Only in the build when an Android SDK is found (see [Android](#android)). |
| `build/generated/uniffi/kotlin`, `build/generated/facade/kotlin`, `build/natives`, `build/jniLibs` | Generated by the xtask, git-ignored. |

### Tests

- `TransportTest`: both transports against a local `com.sun.net.httpserver` server: no redirects,
  no cookies, headers, status codes, timeouts, offline, streaming.
- `HostPartsTest`: the store, caches, clock and log sink.
- `FfiTest`: offline calls through JNA (the Swift `SmokeTests` and `HostTests`).
- `SmokeTest`: register, log in on a second device, vault, entry, sync, a server event over the
  streaming transport, share link and error codes, with both transports, against the testkit relay
  (`crates/ov-testkit/examples/http_relay.rs`). It is skipped unless `-Pov.testkitRelay=<path>` is
  given, which `cargo xtask kotlin --smoke` does.
- `FacadeCoverageTest`: by reflection, every `suspend` or unsigned member, free function, hidden
  record and Host interface of the generated binding has a facade counterpart.
- `JavaFacadeTest` (Java): free functions, `JRecords`, `JErrors`, futures failing with the core's
  code, and cancelling a future cancelling the request in a Java transport.
- `JavaSmokeTest` (Java): the `SmokeTest` steps through the facade only, with a plain-Java
  `JHttpTransport` over `java.net.http` and with the shipped transport via `JHosts.fromKotlin`, and a
  Java `JSecureStore`/`JBlobCache`/`Clock`/`LogSink` on the second device. Skipped like `SmokeTest`.

## Android

`com.openvireo:openvireo-core-android`: the same generated binding and shared hosts as the JVM jar,
as an AAR for Android 8.0+ (minSdk 26) with `libov_ffi.so` for `arm64-v8a`, `armeabi-v7a` and
`x86_64`. It depends on JNA's AAR (`net.java.dev.jna:jna:<ver>@aar`, which brings
`libjnidispatch.so` for every ABI) and kotlinx-coroutines-core.

```kotlin
dependencies {
    implementation("com.openvireo:openvireo-core-android:<core version>")
}
```

```kotlin
import com.openvireo.core.*
import com.openvireo.core.hosts.defaultHost

val client = OvClient(
    ClientConfig(DeviceInfo(id = null, name = Build.MODEL, platform = Platform.CLI), offline = false, server = null),
    defaultHost(applicationContext),
)
```

Call the `suspend` functions from a coroutine (`lifecycleScope`, `viewModelScope`); they never
block the main thread. The synchronous ones (`Vault.entries`, the crypto functions) do CPU work in
the core, so call them off the main thread for big vaults. The core has no Android `Platform` value
yet; until it gets one, use the closest one.

`defaultHost(context)` (package `com.openvireo.core.hosts`) bundles these parts, each replaceable:

| Part | Default | Notes |
|---|---|---|
| `HttpTransport` | `UrlConnectionTransport` | Android's `HttpURLConnection` (OkHttp underneath), which sends PATCH. The app needs the `INTERNET` permission. `JavaNetHttpTransport` isn't in the AAR: Android has no `java.net.http`. |
| `SecureStore` | `MemoryStore` | Nothing persists. Implement `SecureStore` over the Android Keystore (e.g. AES keys in the Keystore wrapping values in app storage) to keep sessions and trusted Secret Keys. |
| `BlobCache` | `FileCache(noBackupFilesDir/openvireo-cache)` | Pass `cacheDir =` for another directory. Not `context.cacheDir`: the system may clear that, which drops the offline copy and edits not yet synced. |
| `Clock` | `SystemClock` | |
| `LogSink` | `AndroidLogSink` | logcat, tag `OpenVireo`, the core module first (`[ov_sync] ...`); `AndroidLogSink(minLevel = Level.INFO)` drops debug and trace. |

### ABIs

JNA's AAR also carries `armeabi`, `x86`, `mips` and `mips64`, which this AAR has no core for. Limit
the app to the three ABIs, or it installs on an `x86` device (an old emulator) and fails when the
core loads:

```kotlin
android {
    defaultConfig {
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }
}
```

### R8 / ProGuard

JNA finds native methods, `Structure` fields and callbacks by reflection, so the AAR ships consumer
rules (`consumer-rules.pro`) that keep `com.sun.jna.**` and the binding's package
`com.openvireo.core.**`. They apply automatically when an app shrinks; nothing to add.

### Size

A release build of the core is roughly the iOS slice per ABI, and the Play Store delivers one ABI
per device (app bundles split native libraries). Measured on 2026-11-21 (`cargo xtask kotlin --android`
prints the current numbers):

| | Uncompressed | In the AAR (deflated) |
|---|---|---|
| `arm64-v8a/libov_ffi.so` | 3.31 MiB | 1.74 MiB |
| `armeabi-v7a/libov_ffi.so` | 2.50 MiB | 1.54 MiB |
| `x86_64/libov_ffi.so` | 4.04 MiB | 1.80 MiB |
| `classes.jar` (859 classes) | 1.47 MiB | |
| The AAR | 6.44 MiB | |

JNA adds about 220 KiB of classes plus a 120-180 KiB `libjnidispatch.so` per ABI. The 64-bit
libraries are linked with 16 KB pages, as Google Play requires for Android 15+; the xtask checks it.

### Building the AAR

```sh
cargo xtask kotlin --android   # host step + cargo-ndk for 3 ABIs + gradle test :core-android:assembleRelease, then checks the AAR
```

It needs, besides the JVM build's Rust and JDK:

- an Android SDK (`ANDROID_HOME`, or `sdk.dir` in `bindings/kotlin/local.properties`) with an NDK
  r27+ under `$ANDROID_HOME/ndk/` (or `ANDROID_NDK_HOME`);
- `cargo install cargo-ndk --locked`;
- `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`.

The xtask installs none of these; it stops and prints these commands if one is missing. The Android
targets are deliberately **not** in `rust-toolchain.toml`: rustup downloads every target listed there
with the toolchain, for every developer and CI job, which isn't worth it for one optional artifact.

What it does:

1. The JVM build's steps 1-3 (host debug build, generated Kotlin).
2. `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P 26 rustc --release --lib -p ov-ffi
   --crate-type cdylib`: release (stripped, LTO), never `test-server`, cdylib only. The libraries go
   to `build/jniLibs/<abi>/libov_ffi.so`. Each ABI adds about 180 MB to `target/<triple>/`.
3. Gradle with `-Pov.android=true -Pov.requireAbis=all`.
4. Opens the AAR: every ABI's `libov_ffi.so` (16 KB-aligned on 64-bit), a `classes.jar` with the
   binding and the Android hosts, and `proguard.txt`; prints the sizes.

`--android` can't be combined with `--smoke` / `--test-server`: the generated Kotlin would declare
the OPAQUE server functions that the release libraries don't have, and UniFFI's load-time checksum
check would fail.

### In the Gradle build

- `:core-android` is only included when an Android SDK is found (`ANDROID_HOME`,
  `ANDROID_SDK_ROOT`, or `sdk.dir` in `local.properties`). `-Pov.android=true` forces it in,
  `-Pov.android=false` leaves it out. Without it, the build is exactly the JVM build, and the
  Android Gradle Plugin is never even downloaded.
- With an SDK, `./gradlew build` also builds the AAR. If `build/jniLibs` doesn't have every ABI yet
  (cargo-ndk hasn't run), that is a warning, not a failure, and the AAR can't load on the missing
  ABIs. `-Pov.requireAbis=all` (or a comma list) makes it a failure; the xtask passes it.
  `-Pov.jniLibsDir=<dir>` takes the libraries from elsewhere (a release job).
- `./gradlew :core-android:publish` sends the AAR and its sources jar to the same GitHub Packages
  repository as the jar.

### On a device

`core-android/src/androidTest` holds `LoadTest`: it loads `libov_ffi.so` through JNA and checks
`version()`, `sha256("abc")` and a client built with `defaultHost(context)`. CI only builds it
(`./gradlew :core-android:assembleAndroidTest`); with a device or emulator attached, run it with:

```sh
cargo xtask kotlin --android
cd bindings/kotlin && ./gradlew :core-android:connectedAndroidTest -Pov.generate=false
```
