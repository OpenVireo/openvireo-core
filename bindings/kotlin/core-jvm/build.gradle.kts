// com.openvireo:openvireo-core-jvm: the generated Kotlin binding, the shared default hosts, the
// JVM-only hosts (java.net.http, java.util.logging), the generated Java facade
// (com.openvireo.core.java) and the natives under JNA's resource layout.

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    `maven-publish`
}

base {
    archivesName.set("openvireo-core-jvm")
}

@Suppress("UNCHECKED_CAST")
val nativeSlices = rootProject.extra["ovNativeSlices"] as Map<String, String>
val generatedDir = rootProject.extra["ovGeneratedDir"] as File
val facadeDir = rootProject.extra["ovFacadeDir"] as File
val nativesDir = rootProject.extra["ovNativesDir"] as File
val sharedDir = rootProject.extra["ovSharedDir"] as File

dependencies {
    api(libs.jna)
    api(libs.kotlinx.coroutines.core)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

java {
    withSourcesJar()
    // Empty for now (no Dokka); Maven Central requires one.
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
        freeCompilerArgs.add("-Xjdk-release=11")
    }
}

sourceSets {
    main {
        kotlin.srcDir(files(generatedDir).builtBy(":generateBindings"))
        kotlin.srcDir(files(facadeDir).builtBy(":generateBindings"))
        kotlin.srcDir(sharedDir)
        resources.srcDir(files(nativesDir).builtBy(":generateBindings"))
    }
}

// Which slices must be in the jar: `-Pov.requireNatives=all` or `darwin-aarch64,linux-x86-64`.
val requireNatives: List<String> = providers.gradleProperty("ov.requireNatives").orNull.let { p ->
    when {
        p.isNullOrBlank() -> emptyList()
        p == "all" -> nativeSlices.keys.toList()
        else -> p.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }
}

val checkNatives = tasks.register("checkNatives") {
    group = "verification"
    description = "Checks the natives directory: at least one slice, and every slice -Pov.requireNatives names."
    dependsOn(":generateBindings")
    val dir = nativesDir
    val slices = nativeSlices
    val required = requireNatives
    inputs.property("required", required)
    doLast {
        val unknown = required - slices.keys
        require(unknown.isEmpty()) { "unknown native slices $unknown (known: ${slices.keys})" }
        val present = slices.filter { (prefix, lib) -> dir.resolve(prefix).resolve(lib).isFile }.keys
        if (present.isEmpty()) {
            throw GradleException(
                "no natives in $dir: run `cargo xtask kotlin` (host slice) or pass -Pov.nativesDir=<dir> " +
                    "laid out as ${slices.map { "${it.key}/${it.value}" }}",
            )
        }
        val missing = required - present
        if (missing.isNotEmpty()) throw GradleException("natives missing from $dir: $missing")
        logger.lifecycle("natives in jar: ${present.joinToString()}")
    }
}

tasks.named<Jar>("jar") {
    dependsOn(checkNatives)
    manifest {
        attributes(
            "Implementation-Title" to "openvireo-core-jvm",
            "Implementation-Version" to project.version,
            "Automatic-Module-Name" to "com.openvireo.core",
        )
    }
}

tasks.named<Jar>("sourcesJar") {
    dependsOn(":generateBindings")
    // allSource includes resources: keep the natives out of the sources jar.
    exclude(nativeSlices.keys.map { "$it/**" })
}

tasks.test {
    useJUnitPlatform()
    // The smoke test starts this binary (ov-testkit's `http_relay` example); `cargo xtask kotlin --smoke`
    // passes it. Without it the smoke test is skipped.
    providers.gradleProperty("ov.testkitRelay").orNull?.let { systemProperty("ov.testkitRelay", it) }
    providers.gradleProperty("ov.requireSmoke").orNull?.let { systemProperty("ov.requireSmoke", it) }
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "openvireo-core-jvm"
            from(components["java"])
            pom {
                name.set("openvireo-core-jvm")
                description.set("OpenVireo core for the JVM: accounts, vaults, sync and share links (UniFFI + JNA)")
                url.set("https://github.com/openvireo/openvireo-core")
                licenses {
                    license {
                        name.set("MIT OR Apache-2.0")
                        url.set("https://github.com/openvireo/openvireo-core#license")
                    }
                }
                developers {
                    developer {
                        id.set("openvireo")
                        name.set("OpenVireo")
                        email.set("admin@openvireo.com")
                        url.set("https://openvireo.com")
                    }
                }
                scm {
                    url.set("https://github.com/openvireo/openvireo-core")
                    connection.set("scm:git:https://github.com/openvireo/openvireo-core.git")
                    developerConnection.set("scm:git:ssh://git@github.com/openvireo/openvireo-core.git")
                }
            }
        }
    }
    repositories {
        // A local repository for Maven Central (`cargo xtask release publish-maven --to central`): the
        // release workflow signs every file in it and uploads the bundle to the Central Portal.
        maven {
            name = "CentralStaging"
            url = uri(rootProject.layout.buildDirectory.dir("central-staging"))
        }
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
