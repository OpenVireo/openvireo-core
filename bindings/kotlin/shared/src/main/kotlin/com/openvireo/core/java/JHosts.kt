package com.openvireo.core.java

import com.openvireo.core.BlobCache
import com.openvireo.core.ByteStream
import com.openvireo.core.CachedVault
import com.openvireo.core.Clock
import com.openvireo.core.Host
import com.openvireo.core.HttpHeader
import com.openvireo.core.HttpRequest
import com.openvireo.core.HttpResponse
import com.openvireo.core.HttpTransport
import com.openvireo.core.OpenedStream
import com.openvireo.core.SecureStore
import com.openvireo.core.LogSink
import com.openvireo.core.TransportException
import com.openvireo.core.hosts.MemoryCache
import com.openvireo.core.hosts.MemoryStore
import com.openvireo.core.hosts.SystemClock
import com.openvireo.core.hosts.toTransportException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.future.await
import kotlinx.coroutines.future.future
import kotlinx.coroutines.isActive
import java.util.concurrent.CompletableFuture

// Host parts Java can implement: the generated `HttpTransport`, `ByteStream`, `SecureStore` and
// `BlobCache` have `suspend` methods (and `ByteStream.status` an unsigned type), which Java can't
// implement. `Clock`, `LogSink` and `JwksRefetcher` are plain synchronous interfaces: implement them
// directly (a lambda works for `Clock` and `LogSink`).
//
// `toKotlin(...)` turns these into the generated interfaces (each call `await`s the future, and
// cancelling the call cancels the future); `fromKotlin(...)` goes the other way, so Java can
// wrap or decorate a shipped Kotlin host (`JavaNetHttpTransport`, `FileCache`, ...).

/** An HTTP response for [JHttpTransport.send]: the status (`100..=599`), the headers in order, the body. */
public class JHttpResponse(
    public val status: Int,
    public val headers: List<HttpHeader>,
    public val body: ByteArray,
) {
    init {
        require(status in 100..599) { "HTTP status $status is out of range" }
    }

    /** As the generated record. */
    public fun toKotlin(): HttpResponse = HttpResponse(status.toUShort(), headers, body)

    public companion object {
        /** From the generated record. */
        @JvmStatic
        public fun of(r: HttpResponse): JHttpResponse = JHttpResponse(r.status.toInt(), r.headers, r.body)
    }
}

/**
 * HTTP, as `ov_core::host::HttpTransport` needs it. **Never follow redirects** (a 3xx is a response)
 * and **never add cookies**. Any status is a response: complete with it, not exceptionally. Complete
 * exceptionally with a [TransportException] (`Offline`, `Timeout`, `Tls`, `Cancelled`, `Other`); any
 * other exception is mapped (`ConnectException`/`UnknownHostException` → `Offline`, a
 * `SocketTimeoutException` → `Timeout`, an `SSLException` → `Tls`, else `Other`). The core may cancel
 * the returned future when the call it belongs to is cancelled.
 */
public interface JHttpTransport {
    /** Sends one request and returns the whole response. */
    public fun send(req: HttpRequest): CompletableFuture<JHttpResponse>

    /** Opens a server-sent events stream: complete when the headers arrive; the body follows through [JByteStream]. */
    public fun openStream(req: HttpRequest): CompletableFuture<JByteStream>
}

/** The body of an open stream, read chunk by chunk. */
public interface JByteStream {
    /** The response status the stream was opened with. */
    public fun status(): Int

    /** The next chunk, or `null` when the server closed the stream. Failures as for [JHttpTransport]. */
    public fun nextChunk(): CompletableFuture<ByteArray?>

    /** Closes the stream; later [nextChunk] calls complete with `null`. */
    public fun closeStream()
}

/**
 * Secrets that persist (the OS keychain, for example); keys are chosen by the core. Complete
 * exceptionally with an `OvException` ([JErrors.ovException]) when the store can't be read: that is
 * not the same as a missing key (`null`).
 */
public interface JSecureStore {
    /** The value for [key], or `null`. */
    public fun get(key: String): CompletableFuture<ByteArray?>

    /** Stores [value] under [key], replacing any old value. Wipe [value] after use. */
    public fun set(key: String, value: ByteArray): CompletableFuture<Void?>

    /** Removes [key]; a missing key is not an error. */
    public fun delete(key: String): CompletableFuture<Void?>
}

/** The offline cache (ciphertext and public data only), per user and vault; see `ov_core::host::BlobCache`. */
public interface JBlobCache {
    /** The cached vault, or `null`. */
    public fun load(userId: String, vaultId: String): CompletableFuture<CachedVault?>

    /** Stores the cached vault, replacing the old record. */
    public fun save(userId: String, vaultId: String, v: CachedVault): CompletableFuture<Void?>

    /** Removes one vault's record. */
    public fun remove(userId: String, vaultId: String): CompletableFuture<Void?>

    /** The ids of every vault cached for [userId]. */
    public fun list(userId: String): CompletableFuture<List<String>>

    /** A per-user (or, with `userId == ""`, per-device) record. */
    public fun loadMeta(userId: String, name: String): CompletableFuture<ByteArray?>

    /** Stores a per-user record. */
    public fun saveMeta(userId: String, name: String, value: ByteArray): CompletableFuture<Void?>

    /** Removes everything cached for [userId]. */
    public fun clearUser(userId: String): CompletableFuture<Void?>
}

/**
 * Builds a [Host] from Java, and adapts between the Java Host interfaces and the generated
 * (`suspend`) ones. Each part of a Host is either a Java one ([JHttpTransport], [JSecureStore],
 * [JBlobCache]) or a shipped or Kotlin one (`JavaNetHttpTransport`, `MemoryStore`, `FileCache`, ...).
 * `JDefaultHosts.builder()` starts with the platform's defaults filled in.
 *
 * ```java
 * Host host = JHosts.builder().http(myTransport).log((level, target, msg) -> {}).build();
 * ```
 */
public object JHosts {
    /** A Host from five Java parts. */
    @JvmStatic
    public fun create(http: JHttpTransport, store: JSecureStore, cache: JBlobCache, clock: Clock, log: LogSink): Host =
        Host(toKotlin(http), toKotlin(store), toKotlin(cache), clock, log)

    /**
     * A builder with a [MemoryStore], a [MemoryCache] and [SystemClock]; the HTTP transport and the log
     * sink must be set (or start from `JDefaultHosts.builder()`).
     */
    @JvmStatic
    public fun builder(): Builder = Builder()

    /** Collects the Host parts; [build] makes the [Host]. */
    public class Builder internal constructor() {
        private var http: HttpTransport? = null
        private var store: SecureStore = MemoryStore()
        private var cache: BlobCache = MemoryCache()
        private var clock: Clock = SystemClock
        private var log: LogSink? = null

        public fun http(http: JHttpTransport): Builder = apply { this.http = toKotlin(http) }

        public fun http(http: HttpTransport): Builder = apply { this.http = http }

        public fun store(store: JSecureStore): Builder = apply { this.store = toKotlin(store) }

        public fun store(store: SecureStore): Builder = apply { this.store = store }

        public fun cache(cache: JBlobCache): Builder = apply { this.cache = toKotlin(cache) }

        public fun cache(cache: BlobCache): Builder = apply { this.cache = cache }

        public fun clock(clock: Clock): Builder = apply { this.clock = clock }

        public fun log(log: LogSink): Builder = apply { this.log = log }

        public fun build(): Host = Host(
            checkNotNull(http) { "JHosts.Builder: no HTTP transport (set one, or start from JDefaultHosts.builder())" },
            store,
            cache,
            clock,
            checkNotNull(log) { "JHosts.Builder: no log sink (set one, or start from JDefaultHosts.builder())" },
        )
    }

    /** The generated [HttpTransport] over a [JHttpTransport]. */
    @JvmStatic
    public fun toKotlin(http: JHttpTransport): HttpTransport = (http as? KotlinHttp)?.inner ?: JavaHttp(http)

    /** The generated [ByteStream] over a [JByteStream]. */
    @JvmStatic
    public fun toKotlin(stream: JByteStream): ByteStream = (stream as? KotlinStream)?.inner ?: JavaStream(stream)

    /** The generated [SecureStore] over a [JSecureStore]. */
    @JvmStatic
    public fun toKotlin(store: JSecureStore): SecureStore = (store as? KotlinStore)?.inner ?: JavaStore(store)

    /** The generated [BlobCache] over a [JBlobCache]. */
    @JvmStatic
    public fun toKotlin(cache: JBlobCache): BlobCache = (cache as? KotlinCache)?.inner ?: JavaCache(cache)

    /** A [JHttpTransport] over a Kotlin [HttpTransport] (e.g. `JavaNetHttpTransport`); futures run on [scope]. */
    @JvmStatic
    @JvmOverloads
    public fun fromKotlin(http: HttpTransport, scope: CoroutineScope = JScope.defaultScope()): JHttpTransport =
        (http as? JavaHttp)?.inner ?: KotlinHttp(http, scope)

    /** A [JByteStream] over a Kotlin [ByteStream]. */
    @JvmStatic
    @JvmOverloads
    public fun fromKotlin(stream: ByteStream, scope: CoroutineScope = JScope.defaultScope()): JByteStream =
        (stream as? JavaStream)?.inner ?: KotlinStream(stream, scope)

    /** A [JSecureStore] over a Kotlin [SecureStore] (e.g. `MemoryStore`). */
    @JvmStatic
    @JvmOverloads
    public fun fromKotlin(store: SecureStore, scope: CoroutineScope = JScope.defaultScope()): JSecureStore =
        (store as? JavaStore)?.inner ?: KotlinStore(store, scope)

    /** A [JBlobCache] over a Kotlin [BlobCache] (e.g. `FileCache`). */
    @JvmStatic
    @JvmOverloads
    public fun fromKotlin(cache: BlobCache, scope: CoroutineScope = JScope.defaultScope()): JBlobCache =
        (cache as? JavaCache)?.inner ?: KotlinCache(cache, scope)
}

/** Awaits a transport future, mapping failures to the [TransportException] the core expects. */
private suspend fun <T> transportCall(f: () -> CompletableFuture<T>): T = try {
    f().await()
} catch (e: CancellationException) {
    // Our caller was cancelled (the Rust future was dropped): let the coroutine end. Otherwise the
    // Java side cancelled its own future: the platform cancelled the request.
    if (!currentCoroutineContext().isActive) throw e
    throw TransportException.Cancelled()
} catch (e: TransportException) {
    throw e
} catch (e: Throwable) {
    throw e.toTransportException()
}

private class JavaHttp(val inner: JHttpTransport) : HttpTransport {
    override suspend fun send(req: HttpRequest): HttpResponse = transportCall { inner.send(req) }.toKotlin()

    override suspend fun openStream(req: HttpRequest): OpenedStream = OpenedStream(JHosts.toKotlin(transportCall { inner.openStream(req) }))
}

private class JavaStream(val inner: JByteStream) : ByteStream {
    override fun status(): UShort = inner.status().toUShort()

    override suspend fun nextChunk(): ByteArray? = transportCall { inner.nextChunk() }

    override fun closeStream() = inner.closeStream()
}

private class JavaStore(val inner: JSecureStore) : SecureStore {
    override suspend fun get(key: String): ByteArray? = inner.get(key).await()

    override suspend fun set(key: String, value: ByteArray) {
        inner.set(key, value).await()
    }

    override suspend fun delete(key: String) {
        inner.delete(key).await()
    }
}

private class JavaCache(val inner: JBlobCache) : BlobCache {
    override suspend fun load(userId: String, vaultId: String): CachedVault? = inner.load(userId, vaultId).await()

    override suspend fun save(userId: String, vaultId: String, v: CachedVault) {
        inner.save(userId, vaultId, v).await()
    }

    override suspend fun remove(userId: String, vaultId: String) {
        inner.remove(userId, vaultId).await()
    }

    override suspend fun list(userId: String): List<String> = inner.list(userId).await()

    override suspend fun loadMeta(userId: String, name: String): ByteArray? = inner.loadMeta(userId, name).await()

    override suspend fun saveMeta(userId: String, name: String, value: ByteArray) {
        inner.saveMeta(userId, name, value).await()
    }

    override suspend fun clearUser(userId: String) {
        inner.clearUser(userId).await()
    }
}

private class KotlinHttp(val inner: HttpTransport, private val scope: CoroutineScope) : JHttpTransport {
    override fun send(req: HttpRequest): CompletableFuture<JHttpResponse> = scope.future { JHttpResponse.of(inner.send(req)) }

    override fun openStream(req: HttpRequest): CompletableFuture<JByteStream> =
        scope.future { JHosts.fromKotlin(inner.openStream(req).stream, scope) }
}

private class KotlinStream(val inner: ByteStream, private val scope: CoroutineScope) : JByteStream {
    override fun status(): Int = inner.status().toInt()

    override fun nextChunk(): CompletableFuture<ByteArray?> = scope.future { inner.nextChunk() }

    override fun closeStream() = inner.closeStream()
}

private class KotlinStore(val inner: SecureStore, private val scope: CoroutineScope) : JSecureStore {
    override fun get(key: String): CompletableFuture<ByteArray?> = scope.future { inner.get(key) }

    override fun set(key: String, value: ByteArray): CompletableFuture<Void?> = scope.future { inner.set(key, value); null }

    override fun delete(key: String): CompletableFuture<Void?> = scope.future { inner.delete(key); null }
}

private class KotlinCache(val inner: BlobCache, private val scope: CoroutineScope) : JBlobCache {
    override fun load(userId: String, vaultId: String): CompletableFuture<CachedVault?> = scope.future { inner.load(userId, vaultId) }

    override fun save(userId: String, vaultId: String, v: CachedVault): CompletableFuture<Void?> =
        scope.future { inner.save(userId, vaultId, v); null }

    override fun remove(userId: String, vaultId: String): CompletableFuture<Void?> = scope.future { inner.remove(userId, vaultId); null }

    override fun list(userId: String): CompletableFuture<List<String>> = scope.future { inner.list(userId) }

    override fun loadMeta(userId: String, name: String): CompletableFuture<ByteArray?> = scope.future { inner.loadMeta(userId, name) }

    override fun saveMeta(userId: String, name: String, value: ByteArray): CompletableFuture<Void?> =
        scope.future { inner.saveMeta(userId, name, value); null }

    override fun clearUser(userId: String): CompletableFuture<Void?> = scope.future { inner.clearUser(userId); null }
}
