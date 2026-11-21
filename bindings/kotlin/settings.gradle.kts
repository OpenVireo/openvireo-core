// The Kotlin binding of openvireo-core (docs: README.md; plan: language-bindings.md §3).
//
// Projects:
//   :core-jvm      com.openvireo:openvireo-core-jvm, the JVM jar with bundled natives
//   (later) :core-android and the Java facade reuse the same generated sources and shared/.

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "openvireo-core-kotlin"

include(":core-jvm")
