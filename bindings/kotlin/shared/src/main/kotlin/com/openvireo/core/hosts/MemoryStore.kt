package com.openvireo.core.hosts

import com.openvireo.core.SecureStore
import java.util.concurrent.ConcurrentHashMap

/**
 * A [SecureStore] in memory: nothing survives the process, so every run is a new device (sessions
 * and trusted Secret Keys are forgotten). Good for scripts, servers that sign in each time, and
 * tests. Values are copied in and out; removed and replaced values are wiped. Safe to call
 * concurrently.
 */
public class MemoryStore : SecureStore {
    private val values = ConcurrentHashMap<String, ByteArray>()

    override suspend fun get(key: String): ByteArray? = values[key]?.copyOf()

    override suspend fun set(key: String, value: ByteArray) {
        values.put(key, value.copyOf())?.fill(0)
        // The trait says the host wipes `value` after use; this array was made for this call.
        value.fill(0)
    }

    override suspend fun delete(key: String) {
        values.remove(key)?.fill(0)
    }

    /** The stored keys (for tests and diagnostics; never the values). */
    public fun keys(): Set<String> = values.keys.toSet()
}
