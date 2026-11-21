@file:JvmName("AndroidHosts")

package com.openvireo.core.hosts

import android.content.Context
import com.openvireo.core.BlobCache
import com.openvireo.core.Clock
import com.openvireo.core.Host
import com.openvireo.core.HttpTransport
import com.openvireo.core.LogSink
import com.openvireo.core.SecureStore
import java.io.File

/**
 * A [Host] from the default Android parts, each replaceable: [UrlConnectionTransport] (Android's
 * `HttpURLConnection`, which sends PATCH), a [MemoryStore] (a new device every run: pass a
 * [SecureStore] over the Android Keystore to keep sessions and trusted Secret Keys), a [FileCache]
 * in [cacheDir], [SystemClock] and [AndroidLogSink].
 *
 * [cacheDir] defaults to `noBackupFilesDir/openvireo-cache`: app-private, not backed up (each device
 * has its own cache), and, unlike `context.cacheDir`, never cleared by the system under storage
 * pressure, which would drop the offline copy and any edits not yet synced. It holds ciphertext and
 * public data only.
 *
 * ```kotlin
 * val client = OvClient(config, defaultHost(applicationContext))
 * ```
 */
@JvmOverloads
public fun defaultHost(
    context: Context,
    cacheDir: File = File(context.noBackupFilesDir, "openvireo-cache"),
    http: HttpTransport = UrlConnectionTransport(),
    store: SecureStore = MemoryStore(),
    cache: BlobCache = FileCache(cacheDir.toPath()),
    clock: Clock = SystemClock,
    log: LogSink = AndroidLogSink(),
): Host = Host(http, store, cache, clock, log)
