package com.openvireo.core.java

import com.openvireo.core.Host
import com.openvireo.core.hosts.FileCache
import com.openvireo.core.hosts.JavaNetHttpTransport
import com.openvireo.core.hosts.JulLogSink
import java.nio.file.Path

/**
 * The JVM's default Host parts for Java (the same as Kotlin's `defaultHost`): `JavaNetHttpTransport`,
 * a `MemoryStore` (a new device every run: set a persistent store to keep sessions), a `FileCache`
 * under a directory or a `MemoryCache`, `SystemClock` and `JulLogSink`.
 *
 * ```java
 * JOvClient client = new JOvClient(config, JDefaultHosts.create(Path.of("ov-cache")));
 * Host custom = JDefaultHosts.builder().store(myKeychainStore).build();
 * ```
 */
public object JDefaultHosts {
    /** A [JHosts.Builder] with every JVM default filled in; replace any part. */
    @JvmStatic
    public fun builder(): JHosts.Builder = JHosts.builder().http(JavaNetHttpTransport()).log(JulLogSink())

    /** The defaults, with the offline cache in memory. */
    @JvmStatic
    public fun create(): Host = builder().build()

    /** The defaults, with the offline cache in files under [cacheDir]. */
    @JvmStatic
    public fun create(cacheDir: Path): Host = builder().cache(FileCache(cacheDir)).build()
}
