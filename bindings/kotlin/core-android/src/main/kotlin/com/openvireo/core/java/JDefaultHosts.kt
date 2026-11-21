package com.openvireo.core.java

import android.content.Context
import com.openvireo.core.Host
import com.openvireo.core.hosts.AndroidLogSink
import com.openvireo.core.hosts.FileCache
import com.openvireo.core.hosts.UrlConnectionTransport
import java.io.File

/**
 * Android's default Host parts for Java (the same as Kotlin's `defaultHost(context)`):
 * `UrlConnectionTransport`, a `MemoryStore` (a new device every run: set a store over the Android
 * Keystore to keep sessions), a `FileCache` in `noBackupFilesDir/openvireo-cache` (or a
 * `MemoryCache` from [builder]), `SystemClock` and `AndroidLogSink`.
 *
 * ```java
 * JOvClient client = new JOvClient(config, JDefaultHosts.create(context));
 * Host custom = JDefaultHosts.builder().store(myKeystoreStore).build();
 * ```
 */
public object JDefaultHosts {
    /** A [JHosts.Builder] with the Android transport and log sink (cache in memory); replace any part. */
    @JvmStatic
    public fun builder(): JHosts.Builder = JHosts.builder().http(UrlConnectionTransport()).log(AndroidLogSink())

    /** The defaults, with the offline cache in `noBackupFilesDir/openvireo-cache`. */
    @JvmStatic
    public fun create(context: Context): Host = create(File(context.noBackupFilesDir, "openvireo-cache"))

    /** The defaults, with the offline cache in files under [cacheDir]. */
    @JvmStatic
    public fun create(cacheDir: File): Host = builder().cache(FileCache(cacheDir.toPath())).build()
}
