// com.openvireo:openvireo-core-android: the same generated Kotlin and shared hosts as the JVM jar,
// the Android-only hosts (android.util.Log, a Context-based defaultHost), JNA's AAR, and
// libov_ffi.so for arm64-v8a, armeabi-v7a and x86_64 as jniLibs (built by
// `cargo xtask kotlin --android` with cargo-ndk). Only included when an Android SDK is found
// (settings.gradle.kts).
//
// Natives: `<jniLibsDir>/<abi>/libov_ffi.so`, default bindings/kotlin/build/jniLibs, where the xtask
// writes release builds; `-Pov.jniLibsDir=<dir>` points elsewhere. `-Pov.requireAbis=all` (or a comma
// list) fails the build when an ABI is missing; without it a missing ABI is only a warning, so a
// plain `./gradlew build` works before the cargo-ndk step has run (the AAR is then not usable).

plugins {
    // On the classpath from the root buildscript (with the Kotlin plugin, which AGP 9's built-in
    // Kotlin compiles with).
    id("com.android.library")
    `maven-publish`
}

val generatedDir = rootProject.extra["ovGeneratedDir"] as File
val sharedDir = rootProject.extra["ovSharedDir"] as File
val facadeDir = rootProject.extra["ovFacadeDir"] as File

/** The ABIs the AAR carries. Keep in step with `ANDROID_ABIS` in xtask/src/kotlin.rs. */
val androidAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

val jniLibsDir: File = providers.gradleProperty("ov.jniLibsDir").orNull?.let { file(it) }
    ?: rootProject.layout.buildDirectory.dir("jniLibs").get().asFile

/**
 * Every Kotlin source directory of the AAR: the generated binding, the generated Java facade
 * (`com.openvireo.core.java`; its future helpers are in kotlinx-coroutines-core) and shared/.
 */
val kotlinSrcDirs: List<File> = listOf(generatedDir, facadeDir, sharedDir)

android {
    namespace = "com.openvireo.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // A library isn't shrunk itself; consumer-rules.pro keeps what JNA reflects on in apps.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    sourceSets {
        named("main") {
            kotlin.directories.addAll(kotlinSrcDirs.map { it.path })
            jniLibs.directories.add(jniLibsDir.path)
        }
    }

    packaging {
        jniLibs {
            // cargo's release profile already strips it (and AGP's strip needs a configured NDK).
            keepDebugSymbols += "**/libov_ffi.so"
        }
    }

    lint {
        // The generated binding references java.lang.ref.Cleaner (API 33) behind a runtime check and
        // falls back to JNA's cleaner; lint can't see the check.
        disable += "NewApi"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

dependencies {
    // JNA's AAR: the Java classes plus libjnidispatch.so for every Android ABI.
    api(variantOf(libs.jna) { artifactType("aar") })
    api(libs.kotlinx.coroutines.core)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}

// Which ABIs must be present: `-Pov.requireAbis=all` or `arm64-v8a,x86_64`.
val requireAbis: List<String> = providers.gradleProperty("ov.requireAbis").orNull.let { p ->
    when {
        p.isNullOrBlank() -> emptyList()
        p == "all" -> androidAbis
        else -> p.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }
}

val checkJniLibs = tasks.register("checkJniLibs") {
    group = "verification"
    description = "Checks <jniLibsDir>/<abi>/libov_ffi.so: every ABI -Pov.requireAbis names must be there."
    val dir = jniLibsDir
    val abis = androidAbis
    val required = requireAbis
    inputs.property("required", required)
    doLast {
        val unknown = required - abis
        require(unknown.isEmpty()) { "unknown ABIs $unknown (known: $abis)" }
        val present = abis.filter { dir.resolve(it).resolve("libov_ffi.so").isFile }
        val missing = required - present
        if (missing.isNotEmpty()) {
            throw GradleException("libov_ffi.so missing from $dir for $missing: run `cargo xtask kotlin --android`")
        }
        if (present.size < abis.size) {
            logger.warn(
                "openvireo: libov_ffi.so only for $present in $dir (want $abis); the AAR won't load on the " +
                    "others. Run `cargo xtask kotlin --android`.",
            )
        } else {
            logger.lifecycle("natives in AAR: ${present.joinToString()}")
        }
    }
}

// Every variant starts at preBuild: the generated Kotlin and the ABI check come first.
tasks.named("preBuild") {
    dependsOn(":generateBindings", checkJniLibs)
}
// The sources jar reads the generated directory without going through preBuild.
tasks.matching { it.name.endsWith("SourcesJar") || it.name.startsWith("source") }.configureEach {
    dependsOn(":generateBindings")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "openvireo-core-android"
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("openvireo-core-android")
                description.set("OpenVireo core for Android: accounts, vaults, sync and share links (UniFFI + JNA)")
                url.set("https://github.com/openvireo/openvireo-core")
                licenses {
                    license {
                        name.set("MIT OR Apache-2.0")
                        url.set("https://github.com/openvireo/openvireo-core#license")
                    }
                }
                scm {
                    url.set("https://github.com/openvireo/openvireo-core")
                }
            }
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/openvireo/openvireo-core")
            credentials {
                username = providers.environmentVariable("GITHUB_ACTOR").orNull
                password = providers.environmentVariable("GITHUB_TOKEN").orNull
            }
        }
    }
}
