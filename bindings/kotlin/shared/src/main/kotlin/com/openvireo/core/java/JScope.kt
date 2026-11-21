package com.openvireo.core.java

import com.openvireo.core.CancelToken
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.future.future
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor

/**
 * The coroutine scopes the Java facade's futures run on. Every `J` wrapper takes one (its
 * constructors also take an [Executor]); the default is [defaultScope].
 */
public object JScope {
    private val DEFAULT: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * The shared default: a [SupervisorJob] (one failed call doesn't cancel the others) on
     * `Dispatchers.Default`. The core's own work runs on its threads; this scope only resumes the
     * calls, so it is never blocked for long.
     */
    @JvmStatic
    public fun defaultScope(): CoroutineScope = DEFAULT

    /** A scope that resumes calls on [executor] (with its own [SupervisorJob]). */
    @JvmStatic
    public fun of(executor: Executor): CoroutineScope = CoroutineScope(SupervisorJob() + executor.asCoroutineDispatcher())
}

/**
 * Runs [block] as a future on this scope. Cancelling the future cancels the coroutine (which drops
 * the Rust future) and [token]; an [owned] token (one the facade made) is closed when the future
 * completes either way.
 */
internal fun <T> CoroutineScope.ovFuture(token: CancelToken?, owned: Boolean, block: suspend CoroutineScope.() -> T): CompletableFuture<T> {
    val f = future(block = block)
    if (token != null) {
        f.whenComplete { _, _ ->
            if (f.isCancelled) token.cancel()
            if (owned) token.close()
        }
    }
    return f
}

/**
 * The facade takes unsigned numbers as the next wider signed type; these check the range going in
 * (an out-of-range value is a caller bug, so it throws [IllegalArgumentException] at once).
 */
internal object JUnsigned {
    fun u8(v: Int): UByte {
        require(v in 0..0xFF) { "$v is not an unsigned 8-bit value" }
        return v.toUByte()
    }

    fun u16(v: Int): UShort {
        require(v in 0..0xFFFF) { "$v is not an unsigned 16-bit value" }
        return v.toUShort()
    }

    fun u32(v: Long): UInt {
        require(v in 0..0xFFFF_FFFFL) { "$v is not an unsigned 32-bit value" }
        return v.toUInt()
    }

    fun u64(v: Long): ULong {
        require(v >= 0) { "$v is negative (unsigned 64-bit values above Long.MAX_VALUE aren't supported)" }
        return v.toULong()
    }
}
