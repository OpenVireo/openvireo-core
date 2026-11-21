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
        ClientConfig(DeviceInfo(id = null, name = "my-tool", platform = Platform.CLI), offline = false, server = null),
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
| `SecureStore` | `MemoryStore` | Nothing persists, so each run is a new device. Implement `SecureStore` over your OS keychain to keep sessions and trusted Secret Keys. |
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

## Building

```sh
cargo xtask kotlin            # build the host native + generated Kotlin, then ./gradlew test
cargo xtask kotlin --smoke    # plus the smoke test against the in-memory test servers
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
| `shared/src/main/kotlin` | Hand-written code for every artifact (JVM jar and the Android AAR): the hosts that run on both, `OvException` field extensions. A source directory, not a Gradle project, because each artifact compiles it next to the generated sources. |
| `core-jvm/` | The JVM jar: `JavaNetHttpTransport`, `JulLogSink`, `defaultHost`, natives as resources, tests. |
| `build/generated/uniffi/kotlin`, `build/natives` | Generated by the xtask, git-ignored. |

### Tests

- `TransportTest`: both transports against a local `com.sun.net.httpserver` server: no redirects,
  no cookies, headers, status codes, timeouts, offline, streaming.
- `HostPartsTest`: the store, caches, clock and log sink.
- `FfiTest`: offline calls through JNA (the Swift `SmokeTests` and `HostTests`).
- `SmokeTest`: register, log in on a second device, vault, entry, sync, a server event over the
  streaming transport, share link and error codes, with both transports, against the testkit relay
  (`crates/ov-testkit/examples/http_relay.rs`). It is skipped unless `-Pov.testkitRelay=<path>` is
  given, which `cargo xtask kotlin --smoke` does.
