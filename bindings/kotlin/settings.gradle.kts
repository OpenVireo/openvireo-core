// The Kotlin binding of openvireo-core (docs: README.md; plan: language-bindings.md §3).
//
// Projects:
//   :core-jvm      com.openvireo:openvireo-core-jvm, the JVM jar with bundled natives
//   :core-android  com.openvireo:openvireo-core-android, the Android AAR (optional, see below)
//   (later) the Java facade reuses the same generated sources and shared/.

pluginManagement {
    repositories {
        // The Android Gradle Plugin, only resolved when :core-android is included.
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // AGP's own tools (aapt2, ...) and androidx.test for :core-android's instrumented test.
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "openvireo-core-kotlin"

include(":core-jvm")

// :core-android needs an Android SDK, so it is only part of the build when one is found:
// `-Pov.android=true|false` decides outright; otherwise ANDROID_HOME, ANDROID_SDK_ROOT or `sdk.dir` in
// local.properties must name an existing directory. Without one, everything else builds as before.
fun androidSdkFound(): Boolean {
    val fromEnv = listOf("ANDROID_HOME", "ANDROID_SDK_ROOT").mapNotNull { providers.environmentVariable(it).orNull }
    val localProperties = settingsDir.resolve("local.properties")
    val fromLocal = if (localProperties.isFile) {
        java.util.Properties().apply { localProperties.inputStream().use { load(it) } }.getProperty("sdk.dir")
    } else {
        null
    }
    return (fromEnv + listOfNotNull(fromLocal)).any { file(it).isDirectory }
}

val includeAndroid: Boolean = providers.gradleProperty("ov.android").orNull?.toBoolean() ?: androidSdkFound()
if (includeAndroid) {
    include(":core-android")
} else {
    logger.info("openvireo: no Android SDK (ANDROID_HOME / local.properties sdk.dir): :core-android is left out")
}
