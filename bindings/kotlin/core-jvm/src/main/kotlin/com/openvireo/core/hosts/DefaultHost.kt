@file:JvmName("DefaultHosts")

package com.openvireo.core.hosts

import com.openvireo.core.BlobCache
import com.openvireo.core.Clock
import com.openvireo.core.Host
import com.openvireo.core.HttpTransport
import com.openvireo.core.LogSink
import com.openvireo.core.SecureStore
import java.nio.file.Path

/**
 * A [Host] from the default parts, each replaceable: [JavaNetHttpTransport], a [MemoryStore] (a new
 * device every run: pass a persistent [SecureStore] to keep sessions and trusted Secret Keys), a
 * [FileCache] under [cacheDir] (or a [MemoryCache] when it is `null`), [SystemClock] and
 * [JulLogSink].
 *
 * ```kotlin
 * val client = OvClient(config, defaultHost(cacheDir = Path.of("ov-cache")))
 * ```
 */
@JvmOverloads
public fun defaultHost(
    cacheDir: Path? = null,
    http: HttpTransport = JavaNetHttpTransport(),
    store: SecureStore = MemoryStore(),
    cache: BlobCache = cacheDir?.let { FileCache(it) } ?: MemoryCache(),
    clock: Clock = SystemClock,
    log: LogSink = JulLogSink(),
): Host = Host(http, store, cache, clock, log)
