// Shared configuration for every module of the Kotlin binding.
//
// How the build is fed (see README.md, "How the build is fed"):
// - Generated Kotlin (`com.openvireo.core`, from `uniffi-bindgen kotlin`) is never committed. By
//   default `:generateBindings` runs `cargo xtask kotlin --generate-only`, which builds the host
//   `ov-ffi` cdylib (debug, unstripped: bindgen reads its metadata), writes
//   build/generated/uniffi/kotlin and copies the host native into build/natives/<jna-prefix>/.
//   `-Pov.generatedDir=<dir>` supplies the sources instead (and skips cargo). The same step generates
//   the Java facade (`com.openvireo.core.java`) into build/generated/facade/kotlin (`-Pov.facadeDir`).
// - Natives come from a directory in JNA's resource layout (darwin-aarch64/, darwin-x86-64/,
//   linux-x86-64/, linux-aarch64/, win32-x86-64/). Default build/natives (host slice only);
//   `-Pov.nativesDir=<dir>` points at a full set (the release matrix fills one).
// - `-Pov.requireNatives=all` (or a comma list of prefixes) fails the jar when a slice is missing.
// - The version is the core version (root Cargo.toml `[workspace.package] version`);
//   `-Pov.version=<v>` overrides it.

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
}

val repoRoot: File = rootDir.resolve("../..").canonicalFile

fun cargoVersion(): String {
    val toml = repoRoot.resolve("Cargo.toml").readText()
    val section = toml.substringAfter("[workspace.package]", "")
    return Regex("""(?m)^version\s*=\s*"([^"]+)"""").find(section)?.groupValues?.get(1)
        ?: error("no [workspace.package] version in ${repoRoot.resolve("Cargo.toml")}")
}

val ovVersion: String = providers.gradleProperty("ov.version").orNull ?: cargoVersion()
val generatedOverride: String? = providers.gradleProperty("ov.generatedDir").orNull
val ovGenerate: Boolean = providers.gradleProperty("ov.generate").orNull?.toBoolean() ?: (generatedOverride == null)
val ovTestServer: Boolean = providers.gradleProperty("ov.testServer").orNull?.toBoolean() ?: false

/** The generated Kotlin sources of `ov-ffi` (one file, com/openvireo/core/ov_ffi.kt). */
val ovGeneratedDir: File = generatedOverride?.let { file(it) } ?: layout.buildDirectory.dir("generated/uniffi/kotlin").get().asFile

/**
 * The generated Java facade (`com.openvireo.core.java`, made from the sources above by the same
 * `cargo xtask kotlin --generate-only`). With `-Pov.generatedDir`, pass `-Pov.facadeDir` too.
 */
val ovFacadeDir: File = providers.gradleProperty("ov.facadeDir").orNull?.let { file(it) }
    ?: layout.buildDirectory.dir("generated/facade/kotlin").get().asFile

/** Natives in JNA's resource layout. */
val ovNativesDir: File = providers.gradleProperty("ov.nativesDir").orNull?.let { file(it) }
    ?: layout.buildDirectory.dir("natives").get().asFile

/** Hand-written code shared by the JVM jar and (later) the Android AAR: the default hosts that run on both. */
val ovSharedDir: File = rootDir.resolve("shared/src/main/kotlin")

/** The JNA resource prefixes of every slice the release jar carries, and each one's library file. */
val ovNativeSlices: Map<String, String> = linkedMapOf(
    "darwin-aarch64" to "libov_ffi.dylib",
    "darwin-x86-64" to "libov_ffi.dylib",
    "linux-x86-64" to "libov_ffi.so",
    "linux-aarch64" to "libov_ffi.so",
    "win32-x86-64" to "ov_ffi.dll",
)

extra["ovVersion"] = ovVersion
extra["ovGeneratedDir"] = ovGeneratedDir
extra["ovFacadeDir"] = ovFacadeDir
extra["ovNativesDir"] = ovNativesDir
extra["ovSharedDir"] = ovSharedDir
extra["ovNativeSlices"] = ovNativeSlices

tasks.register<Exec>("generateBindings") {
    group = "build"
    description = "Runs `cargo xtask kotlin --generate-only`: host ov-ffi cdylib, uniffi-bindgen kotlin, host native."
    enabled = ovGenerate
    workingDir(repoRoot)
    commandLine(buildList {
        addAll(listOf("cargo", "xtask", "kotlin", "--generate-only"))
        if (ovTestServer) add("--test-server")
    })
    outputs.dir(ovGeneratedDir)
    outputs.dir(ovFacadeDir)
    // cargo is incremental and the xtask rewrites files only when they change.
    outputs.upToDateWhen { false }
}

subprojects {
    group = "com.openvireo"
    version = ovVersion
}
