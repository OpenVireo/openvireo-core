package com.openvireo.core.java

import com.openvireo.core.Disposable
import com.openvireo.core.OvClient
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.util.concurrent.CompletableFuture
import kotlin.coroutines.Continuation

/**
 * The generated facade covers the generated binding: checked by reflection on the compiled classes,
 * independently of the generator's parser, so a new core method, free function or unsigned record
 * field that the facade misses fails the build. Java can't call a `suspend` function or a member
 * whose JVM name Kotlin mangled (`name-abc123`, because of an unsigned type), so each must have a
 * facade counterpart.
 */
class FacadeCoverageTest {
    private val pkg = "com.openvireo.core"

    /** Every class compiled into `com.openvireo.core` (not subpackages). */
    private val classes: List<Class<*>> by lazy {
        val root = File(OvClient::class.java.protectionDomain.codeSource.location.toURI())
        val dir = root.resolve(pkg.replace('.', '/'))
        check(dir.isDirectory) { "expected compiled classes under $dir" }
        dir.listFiles()!!.filter { it.name.endsWith(".class") }
            .map { Class.forName("$pkg.${it.name.removeSuffix(".class")}", false, javaClass.classLoader) }
    }

    private fun facade(name: String): Class<*>? = try {
        Class.forName("$pkg.java.$name")
    } catch (_: ClassNotFoundException) {
        null
    }

    private val Method.isSuspend get() = parameterTypes.lastOrNull() == Continuation::class.java
    private val Method.baseName get() = name.substringBefore('-')
    private val Method.mangled get() = name.contains('-')

    /** The parameter count Java sees (no continuation). */
    private val Method.arity get() = parameterCount - if (isSuspend) 1 else 0

    private fun Method.takesCancelToken() = parameterTypes.any { it.simpleName == "CancelToken" }

    private fun publicMethods(c: Class<*>, static: Boolean): List<Method> = c.declaredMethods.filter {
        Modifier.isPublic(it.modifiers) && !it.isSynthetic && !it.isBridge && Modifier.isStatic(it.modifiers) == static
    }

    /** Checks [facadeClass] has a counterpart of [m]; returns a problem or null. */
    private fun counterpart(owner: String, m: Method, facadeClass: Class<*>, static: Boolean): String? {
        val candidates = publicMethods(facadeClass, static).filter { it.name == m.baseName }
        if (candidates.isEmpty()) return "$owner.${m.baseName}: no ${facadeClass.simpleName}.${m.baseName}"
        if (m.isSuspend) {
            val futures = candidates.filter { CompletableFuture::class.java.isAssignableFrom(it.returnType) }
            if (futures.none { it.parameterCount == m.arity }) return "$owner.${m.baseName}: no CompletableFuture variant"
            if (m.takesCancelToken() && futures.none { it.parameterCount == m.arity - 1 }) {
                return "$owner.${m.baseName}: no variant without the CancelToken"
            }
        } else if (candidates.none { it.parameterCount == m.arity }) {
            return "$owner.${m.baseName}: no variant with ${m.arity} parameters"
        }
        return null
    }

    @Test
    fun `every object method has a facade counterpart`() {
        val problems = mutableListOf<String>()
        var objects = 0
        var methods = 0
        for (iface in classes.filter { it.isInterface && it.simpleName.endsWith("Interface") }) {
            val name = iface.simpleName.removeSuffix("Interface")
            val obj = classes.singleOrNull { it.simpleName == name } ?: continue
            if (!Disposable::class.java.isAssignableFrom(obj)) continue
            objects++
            val own = publicMethods(iface, static = false)
            val companion = obj.declaredClasses.singleOrNull { it.simpleName == "Companion" }
            val statics = companion?.let { c -> publicMethods(c, static = false) } ?: emptyList()
            val f = facade("J$name")
            if (f == null) {
                // Not wrapped: Java must be able to use it as is.
                (own + statics).filter { it.isSuspend || it.mangled }.forEach {
                    problems += "$name.${it.baseName} needs a facade but there is no J$name"
                }
                continue
            }
            assertTrue(AutoCloseable::class.java.isAssignableFrom(f), "J$name is AutoCloseable")
            assertEquals(obj, f.getMethod("unwrap").returnType, "J$name.unwrap()")
            for (m in own) {
                methods++
                counterpart(name, m, f, static = false)?.let { problems += it }
            }
            for (m in statics) {
                methods++
                counterpart("$name.Companion", m, f, static = true)?.let { problems += it }
            }
        }
        assertTrue(objects >= 10, "found $objects objects: is the classes directory right?")
        assertTrue(methods >= 150, "found $methods object methods")
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    @Test
    fun `every free function is on JOv`() {
        val fileClass = classes.single { it.simpleName == "Ov_ffiKt" }
        // The binding's own runtime helpers, not API.
        val runtime = Regex("^(uniffi|getUniffi|use$)")
        val functions = publicMethods(fileClass, static = true).filterNot { runtime.containsMatchIn(it.name) }
        assertTrue(functions.size >= 80, "found ${functions.size} free functions")
        val problems = functions.mapNotNull { counterpart("ov_ffi", it, JOv::class.java, static = true) }
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    @Test
    fun `records Kotlin hides from Java have factories and getters`() {
        val problems = mutableListOf<String>()
        var hidden = 0
        val all = classes.flatMap { listOf(it) + it.declaredClasses }.distinct()
        for (c in all) {
            if (Throwable::class.java.isAssignableFrom(c) || c.isInterface || c.isEnum) continue
            // A data class: Kotlin generates componentN.
            if (c.declaredMethods.none { it.baseName == "component1" }) continue
            val javaCtor = c.constructors.any { !it.isSynthetic }
            val mangledGetters = c.declaredMethods.filter { Modifier.isPublic(it.modifiers) && it.name.startsWith("get") && it.mangled }
            if (javaCtor && mangledGetters.isEmpty()) continue
            hidden++
            val flat = c.name.removePrefix("$pkg.").replace("$", "")
            if (!javaCtor && JRecords::class.java.methods.none { it.name == "new$flat" && it.returnType == c }) {
                problems += "no JRecords.new$flat"
            }
            for (g in mangledGetters) {
                if (JRecords::class.java.methods.none { it.name == g.baseName && it.parameterTypes.contentEquals(arrayOf(c)) }) {
                    problems += "no JRecords.${g.baseName}($flat)"
                }
            }
        }
        assertTrue(hidden >= 20, "found $hidden hidden records")
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    @Test
    fun `host interfaces Java can't implement have J counterparts`() {
        val problems = mutableListOf<String>()
        val callbacks = classes.filter { c -> c.isInterface && classes.any { it.simpleName == "${c.simpleName}Impl" } }
        assertTrue(callbacks.size >= 6, "found callback interfaces ${callbacks.map { it.simpleName }}")
        for (cb in callbacks) {
            val ms = publicMethods(cb, static = false)
            if (ms.none { it.isSuspend || it.mangled }) continue // Clock, LogSink, JwksRefetcher: implement directly
            val j = facade("J${cb.simpleName}")
            if (j == null) {
                problems += "${cb.simpleName} has suspend or unsigned methods but no J${cb.simpleName}"
                continue
            }
            for (m in ms) {
                if (j.methods.none { it.name == m.baseName && it.parameterCount == m.arity }) {
                    problems += "J${cb.simpleName} lacks ${m.baseName}"
                }
            }
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }
}
