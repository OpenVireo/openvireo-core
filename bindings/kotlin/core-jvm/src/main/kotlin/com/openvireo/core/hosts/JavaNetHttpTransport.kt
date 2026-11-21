package com.openvireo.core.hosts

import com.openvireo.core.ByteStream
import com.openvireo.core.HttpHeader
import com.openvireo.core.HttpRequest
import com.openvireo.core.HttpResponse
import com.openvireo.core.HttpTransport
import com.openvireo.core.Method
import com.openvireo.core.OpenedStream
import com.openvireo.core.TransportException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.future.await
import kotlinx.coroutines.isActive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpTimeoutException
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.Flow
import java.net.http.HttpRequest as JHttpRequest
import java.net.http.HttpResponse as JHttpResponse

/**
 * The default [HttpTransport] on the JVM: `java.net.http.HttpClient` (JDK 11+), fully asynchronous.
 *
 * As `ov_core::host::HttpTransport` requires:
 * - **No redirects**: the client is built with `Redirect.NEVER`, so a 3xx comes back as a response
 *   and the core refuses it. A client passed in must be built the same way.
 * - **No cookies**: the client has no `CookieHandler` (a client passed in with one is refused).
 * - **Any status is a response**: 4xx/5xx come back with their body, never as an exception.
 * - **Headers**: the request's headers, in order, plus what the platform always adds (`User-Agent`,
 *   `Host`, `Content-Length`). The headers `java.net.http` reserves for itself (`Connection`,
 *   `Content-Length`, `Expect`, `Host`, `Upgrade`) are left to it. Header values may be bearer
 *   tokens and are never logged.
 * - **Errors**: no network, DNS failure or connection refused → `TransportException.Offline`, a
 *   timeout → `Timeout`, TLS → `Tls`, anything else → `Other`.
 * - **Streams** ([openStream], server-sent events): the response comes back when its headers
 *   arrive, and `nextChunk` hands over each piece of the body as it is received.
 *
 * [requestTimeout] bounds the wait for a response's headers (`null` waits forever).
 */
public class JavaNetHttpTransport @JvmOverloads constructor(
    private val client: HttpClient = defaultClient(),
    private val requestTimeout: Duration? = Duration.ofSeconds(60),
) : HttpTransport {

    init {
        require(client.followRedirects() == HttpClient.Redirect.NEVER) {
            "the HttpClient must not follow redirects (HttpClient.Redirect.NEVER)"
        }
        require(!client.cookieHandler().isPresent) { "the HttpClient must not have a CookieHandler" }
    }

    override suspend fun send(req: HttpRequest): HttpResponse {
        val res = call { client.sendAsync(build(req), JHttpResponse.BodyHandlers.ofByteArray()).await() }
        val body = if (req.method == Method.HEAD) ByteArray(0) else res.body() ?: ByteArray(0)
        return HttpResponse(res.statusCode().toUShort(), headersOf(res), body)
    }

    override suspend fun openStream(req: HttpRequest): OpenedStream {
        val res = call { client.sendAsync(build(req), JHttpResponse.BodyHandlers.ofPublisher()).await() }
        return OpenedStream(PublisherByteStream(res.statusCode(), res.body()))
    }

    private suspend fun <T> call(block: suspend () -> T): T = try {
        block()
    } catch (e: CancellationException) {
        // Our caller was cancelled (the Rust future was dropped): let the coroutine end.
        if (!currentCoroutineContext().isActive) throw e
        throw TransportException.Cancelled()
    } catch (e: TransportException) {
        throw e
    } catch (e: Exception) {
        throw mapError(e)
    }

    private fun build(req: HttpRequest): JHttpRequest {
        val b = try {
            JHttpRequest.newBuilder(URI(req.url))
        } catch (e: Exception) {
            throw TransportException.Other("bad URL: ${e.message}")
        }
        requestTimeout?.let { b.timeout(it) }
        for (h in req.headers) {
            if (h.name.lowercase() in RESERVED) continue
            try {
                b.header(h.name, h.value)
            } catch (e: IllegalArgumentException) {
                throw TransportException.Other("header ${h.name} refused by java.net.http")
            }
        }
        val body = req.body
        val publisher = if (body == null) JHttpRequest.BodyPublishers.noBody() else JHttpRequest.BodyPublishers.ofByteArray(body)
        b.method(req.method.name, publisher)
        return b.build()
    }

    private fun headersOf(res: JHttpResponse<*>): List<HttpHeader> =
        res.headers().map().flatMap { (name, values) -> if (name.startsWith(":")) emptyList() else values.map { HttpHeader(name, it) } }

    public companion object {
        /** `java.net.http` sets these itself and refuses them from callers. */
        private val RESERVED = setOf("connection", "content-length", "expect", "host", "upgrade")

        /** A client as the core needs it: `Redirect.NEVER`, no cookie handler, a 30-second connect timeout. */
        @JvmStatic
        public fun defaultClient(): HttpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(30))
            .build()

        internal fun mapError(e: Throwable): TransportException = when (val c = e.unwrapped()) {
            is HttpTimeoutException -> TransportException.Timeout()
            else -> c.toTransportException()
        }
    }
}

/** A [ByteStream] over a `java.net.http` body publisher: one item requested at a time. */
private class PublisherByteStream(
    private val status: Int,
    publisher: Flow.Publisher<List<ByteBuffer>>,
) : ByteStream {
    private val chunks = Channel<ByteArray>(Channel.UNLIMITED)
    @Volatile private var subscription: Flow.Subscription? = null
    @Volatile private var closed = false

    init {
        publisher.subscribe(object : Flow.Subscriber<List<ByteBuffer>> {
            override fun onSubscribe(s: Flow.Subscription) {
                subscription = s
                if (closed) s.cancel() else s.request(1)
            }

            override fun onNext(items: List<ByteBuffer>) {
                val out = ByteArray(items.sumOf { it.remaining() })
                var off = 0
                for (b in items) {
                    val n = b.remaining()
                    b.get(out, off, n)
                    off += n
                }
                if (out.isEmpty()) subscription?.request(1) else chunks.trySend(out)
            }

            override fun onError(t: Throwable) {
                chunks.close(t)
            }

            override fun onComplete() {
                chunks.close()
            }
        })
    }

    override fun status(): UShort = status.toUShort()

    override suspend fun nextChunk(): ByteArray? {
        if (closed) return null
        val r = chunks.receiveCatching()
        r.getOrNull()?.let {
            subscription?.request(1)
            return it
        }
        if (closed) return null
        val cause = r.exceptionOrNull() ?: return null
        throw JavaNetHttpTransport.mapError(cause)
    }

    override fun closeStream() {
        closed = true
        subscription?.cancel()
        chunks.cancel()
    }
}
