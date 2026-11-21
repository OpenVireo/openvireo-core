package com.openvireo.core.hosts

import com.openvireo.core.HttpHeader
import com.openvireo.core.HttpRequest
import com.openvireo.core.HttpResponse
import com.openvireo.core.HttpTransport
import com.openvireo.core.Method
import com.openvireo.core.TransportException
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.time.Duration
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The default transports against a local `com.sun.net.httpserver` server: what
 * `ov_core::host::HttpTransport` requires of them (no redirects, no cookies, headers as given, any
 * status is a response, errors mapped to `TransportException`, streams delivered as they arrive).
 */
class TransportTest {
    private lateinit var server: HttpServer
    private lateinit var base: String
    private val seen = ConcurrentLinkedQueue<Seen>()
    private val streamGate = CountDownLatch(1)

    class Factory(private val make: () -> HttpTransport) {
        operator fun invoke(): HttpTransport = make()
        override fun toString() = ""
    }

    data class Seen(val method: String, val path: String, val headers: Map<String, List<String>>, val body: ByteArray)

    companion object {
        private fun of(name: String, make: () -> HttpTransport) = Arguments.of(name, Factory(make))

        @JvmStatic
        fun transports(): List<Arguments> = listOf(
            of("java.net.http") { JavaNetHttpTransport() },
            of("HttpURLConnection") { UrlConnectionTransport() },
        )

        @JvmStatic
        fun timeoutTransports(): List<Arguments> = listOf(
            of("java.net.http") { JavaNetHttpTransport(requestTimeout = Duration.ofMillis(300)) },
            of("HttpURLConnection") { UrlConnectionTransport(readTimeoutMs = 300) },
        )
    }

    @BeforeEach
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.executor = Executors.newCachedThreadPool()
        server.createContext("/") { ex -> handle(ex) }
        server.start()
        base = "http://127.0.0.1:${server.address.port}"
    }

    @AfterEach
    fun stop() {
        streamGate.countDown()
        server.stop(0)
    }

    private fun handle(ex: HttpExchange) {
        val body = ex.requestBody.readBytes()
        val path = ex.requestURI.path
        seen.add(Seen(ex.requestMethod, path, ex.requestHeaders.mapKeys { it.key.lowercase() }, body))
        fun reply(status: Int, bytes: ByteArray = ByteArray(0)) {
            ex.sendResponseHeaders(status, if (bytes.isEmpty()) -1 else bytes.size.toLong())
            if (bytes.isNotEmpty()) ex.responseBody.use { it.write(bytes) } else ex.close()
        }
        when (path) {
            "/redirect" -> {
                ex.responseHeaders.add("Location", "$base/target")
                reply(302, "moved".toByteArray())
            }
            "/echo" -> {
                ex.responseHeaders.add("X-Reply", "one")
                ex.responseHeaders.add("X-Reply-Order", "a")
                ex.responseHeaders.add("Content-Type", "application/octet-stream")
                reply(200, body)
            }
            "/cookie" -> {
                ex.responseHeaders.add("Set-Cookie", "session=abc; Path=/")
                reply(200, "ok".toByteArray())
            }
            "/status/404" -> reply(404, """{"error":"nope","code":"not_found"}""".toByteArray())
            "/status/500" -> reply(500, "boom".toByteArray())
            "/status/204" -> reply(204)
            "/slow" -> {
                Thread.sleep(3_000)
                reply(200, "late".toByteArray())
            }
            "/stream" -> {
                ex.responseHeaders.add("Content-Type", "text/event-stream")
                ex.sendResponseHeaders(200, 0) // chunked
                ex.responseBody.use { out ->
                    out.write(": connected\n\n".toByteArray())
                    out.flush()
                    // The second event only after the client has read the first: proves chunks arrive as sent.
                    streamGate.await(10, TimeUnit.SECONDS)
                    out.write("data: two\n\n".toByteArray())
                    out.flush()
                }
            }
            "/forever" -> {
                ex.sendResponseHeaders(200, 0)
                try {
                    ex.responseBody.write("data: one\n\n".toByteArray())
                    ex.responseBody.flush()
                    streamGate.await(10, TimeUnit.SECONDS)
                } catch (_: Exception) {
                }
            }
            else -> reply(200, "target".toByteArray())
        }
    }

    private fun req(method: Method, path: String, headers: List<HttpHeader> = emptyList(), body: ByteArray? = null) =
        HttpRequest(method, "$base$path", headers, body, false)

    private fun HttpResponse.header(name: String): String? = headers.firstOrNull { it.name.equals(name, true) }?.value

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `redirects are not followed`(name: String, t: Factory) = runBlocking<Unit> {
        val res = t().send(req(Method.GET, "/redirect"))
        assertEquals(302, res.status.toInt())
        assertEquals("$base/target", res.header("Location"))
        assertEquals("moved", res.body.decodeToString())
        assertFalse(seen.any { it.path == "/target" }, "the redirect was followed")
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `headers and body go out as given and come back`(name: String, t: Factory) = runBlocking<Unit> {
        val headers = listOf(
            HttpHeader("Authorization", "Bearer token-1"),
            HttpHeader("Content-Type", "application/json"),
            HttpHeader("If-Match", "\"etag-1\""),
            HttpHeader("X-Multi", "a"),
            HttpHeader("X-Multi", "b"),
        )
        val body = """{"a":1}""".toByteArray()
        val res = t().send(req(Method.POST, "/echo", headers, body))
        assertEquals(200, res.status.toInt())
        assertArrayEquals(body, res.body)
        assertEquals("one", res.header("x-reply"))
        val s = seen.single()
        assertEquals("POST", s.method)
        assertEquals(listOf("Bearer token-1"), s.headers["authorization"])
        assertEquals(listOf("application/json"), s.headers["content-type"])
        assertEquals(listOf("\"etag-1\""), s.headers["if-match"])
        val multi = s.headers["x-multi"]!!.flatMap { v -> v.split(",").map { it.trim() } }
        assertEquals(listOf("a", "b"), multi)
        assertArrayEquals(body, s.body)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `PUT DELETE and HEAD`(name: String, t: Factory) = runBlocking<Unit> {
        val http = t()
        assertArrayEquals(byteArrayOf(1, 2, 3), http.send(req(Method.PUT, "/echo", body = byteArrayOf(1, 2, 3))).body)
        assertEquals(200, http.send(req(Method.DELETE, "/echo")).status.toInt())
        val head = http.send(req(Method.HEAD, "/echo"))
        assertEquals(200, head.status.toInt())
        assertEquals(0, head.body.size)
        assertEquals(listOf("PUT", "DELETE", "HEAD"), seen.map { it.method })
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `PATCH is sent or refused as a transport error`(name: String, t: Factory) = runBlocking<Unit> {
        try {
            val res = t().send(req(Method.PATCH, "/echo", body = "x".toByteArray()))
            assertEquals(200, res.status.toInt())
            assertEquals("PATCH", seen.single().method)
        } catch (e: TransportException.Other) {
            // The JVM's HttpURLConnection has no PATCH (Android's does).
            assertTrue(name == "HttpURLConnection" && e.reason.contains("PATCH"), e.reason)
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `no cookies are stored or sent`(name: String, t: Factory) = runBlocking<Unit> {
        val http = t()
        http.send(req(Method.GET, "/cookie"))
        http.send(req(Method.GET, "/echo"))
        assertNull(seen.last().headers["cookie"])
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `error statuses are responses with their body`(name: String, t: Factory) = runBlocking<Unit> {
        val http = t()
        val nf = http.send(req(Method.GET, "/status/404"))
        assertEquals(404, nf.status.toInt())
        assertTrue(nf.body.decodeToString().contains("not_found"))
        val err = http.send(req(Method.POST, "/status/500", body = ByteArray(0)))
        assertEquals(500, err.status.toInt())
        assertEquals("boom", err.body.decodeToString())
        val empty = http.send(req(Method.DELETE, "/status/204"))
        assertEquals(204, empty.status.toInt())
        assertEquals(0, empty.body.size)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `connection refused is Offline`(name: String, t: Factory) = runBlocking<Unit> {
        val port = ServerSocket(0).use { it.localPort }
        val e = assertThrows<TransportException> { t().send(HttpRequest(Method.GET, "http://127.0.0.1:$port/x", emptyList(), null, false)) }
        assertInstanceOf(TransportException.Offline::class.java, e)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `an unknown host is Offline`(name: String, t: Factory) = runBlocking<Unit> {
        val e = assertThrows<TransportException> { t().send(HttpRequest(Method.GET, "http://openvireo-test.invalid/x", emptyList(), null, false)) }
        assertInstanceOf(TransportException.Offline::class.java, e)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("timeoutTransports")
    fun `a slow server is Timeout`(name: String, t: Factory) = runBlocking<Unit> {
        val e = assertThrows<TransportException> { t().send(req(Method.GET, "/slow")) }
        assertInstanceOf(TransportException.Timeout::class.java, e)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `a stream delivers chunks as they arrive`(name: String, t: Factory) = runBlocking<Unit> {
        val stream = t().openStream(req(Method.GET, "/stream", listOf(HttpHeader("Accept", "text/event-stream")))).stream
        assertEquals(200, stream.status().toInt())
        val received = StringBuilder()
        withTimeout(10_000) {
            // Everything up to the gate must arrive without the server finishing the response.
            while (!received.contains(": connected\n\n")) received.append(stream.nextChunk()!!.decodeToString())
            streamGate.countDown()
            while (true) received.append((stream.nextChunk() ?: break).decodeToString())
        }
        assertEquals(": connected\n\ndata: two\n\n", received.toString())
        assertNull(stream.nextChunk())
        assertEquals(listOf("text/event-stream"), seen.single().headers["accept"])
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `closing a stream ends it`(name: String, t: Factory) = runBlocking<Unit> {
        val stream = t().openStream(req(Method.GET, "/forever")).stream
        withTimeout(10_000) { assertTrue(stream.nextChunk()!!.isNotEmpty()) }
        stream.closeStream()
        assertNull(stream.nextChunk())
        assertNull(stream.nextChunk())
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    fun `a stream with an error status yields the body`(name: String, t: Factory) = runBlocking<Unit> {
        val stream = t().openStream(req(Method.GET, "/status/404")).stream
        assertEquals(404, stream.status().toInt())
        val body = StringBuilder()
        withTimeout(10_000) { while (true) body.append((stream.nextChunk() ?: break).decodeToString()) }
        assertTrue(body.contains("not_found"), body.toString())
    }

    @org.junit.jupiter.api.Test
    fun `a client that follows redirects or keeps cookies is refused`() {
        val follows = java.net.http.HttpClient.newBuilder().followRedirects(java.net.http.HttpClient.Redirect.NORMAL).build()
        org.junit.jupiter.api.assertThrows<IllegalArgumentException> { JavaNetHttpTransport(follows) }
        val cookies = java.net.http.HttpClient.newBuilder().cookieHandler(java.net.CookieManager()).build()
        org.junit.jupiter.api.assertThrows<IllegalArgumentException> { JavaNetHttpTransport(cookies) }
    }
}

/** `assertThrows` for suspend code. */
inline fun <reified T : Throwable> assertThrows(block: () -> Unit): T {
    try {
        block()
    } catch (e: Throwable) {
        if (e is T) return e
        fail<Unit>("expected ${T::class.simpleName}, got $e")
    }
    fail<Unit>("expected ${T::class.simpleName}, nothing was thrown")
    throw IllegalStateException()
}
