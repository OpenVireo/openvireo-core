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
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.ProtocolException
import java.net.URI

/**
 * An [HttpTransport] over `HttpURLConnection`, run on [dispatcher] (`Dispatchers.IO`). It works on
 * the JVM and on Android (where `HttpURLConnection` is OkHttp underneath); on the JVM prefer
 * `JavaNetHttpTransport`.
 *
 * As `ov_core::host::HttpTransport` requires:
 * - **No redirects**: `instanceFollowRedirects = false`, so a 3xx comes back as a response and the
 *   core refuses it.
 * - **Any status is a response**: 4xx/5xx bodies are read from `errorStream`, not thrown.
 * - **Headers**: the request's headers, in order, plus what the platform always adds
 *   (`User-Agent`, `Host`, `Content-Length`, `Accept-Encoding` on Android). Header values may be
 *   bearer tokens and are never logged.
 * - **Errors**: no network, DNS failure or connection refused → `TransportException.Offline`, a
 *   timeout → `Timeout`, TLS → `Tls`, anything else → `Other`; cancelling the calling coroutine
 *   disconnects the request.
 * - **Cookies**: none are added unless the app installed a process-wide `CookieHandler`
 *   (`CookieHandler.setDefault`), which `HttpURLConnection` always consults. Don't install one in a
 *   process that uses this transport, or use `JavaNetHttpTransport`.
 * - **PATCH**: the JVM's own `HttpURLConnection` can't send it (Android's can); such a request fails
 *   with `TransportException.Other`. The core uses PATCH for org, vault and service-account
 *   renames.
 *
 * [connectTimeoutMs] bounds connecting; [readTimeoutMs] bounds each read of [send] (streams wait
 * without a read timeout, since server-sent events can be quiet for a long time).
 */
public class UrlConnectionTransport @JvmOverloads constructor(
    private val connectTimeoutMs: Int = 30_000,
    private val readTimeoutMs: Int = 60_000,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : HttpTransport {

    override suspend fun send(req: HttpRequest): HttpResponse {
        val conn = open(req, readTimeoutMs)
        return blocking(conn) {
            val status = conn.responseCode
            val headers = headersOf(conn)
            val body = if (req.method == Method.HEAD) ByteArray(0) else bodyOf(conn, status)?.use { it.readBytes() } ?: ByteArray(0)
            HttpResponse(status.toUShort(), headers, body)
        }
    }

    override suspend fun openStream(req: HttpRequest): OpenedStream {
        val conn = open(req, 0)
        val (status, input) = blocking(conn) {
            val status = conn.responseCode
            status to bodyOf(conn, status)
        }
        return OpenedStream(UrlConnectionByteStream(conn, status, input))
    }

    private suspend fun open(req: HttpRequest, readTimeout: Int): HttpURLConnection {
        val conn = try {
            URI(req.url).toURL().openConnection() as? HttpURLConnection
                ?: throw TransportException.Other("not an http(s) URL")
        } catch (e: TransportException) {
            throw e
        } catch (e: Exception) {
            throw e.toTransportException()
        }
        conn.instanceFollowRedirects = false
        conn.useCaches = false
        conn.connectTimeout = connectTimeoutMs
        conn.readTimeout = readTimeout
        try {
            conn.requestMethod = req.method.name
        } catch (_: ProtocolException) {
            throw TransportException.Other(
                "HTTP ${req.method.name} isn't supported by this platform's HttpURLConnection; use JavaNetHttpTransport",
            )
        }
        for (h in req.headers) conn.addRequestProperty(h.name, h.value)
        val body = req.body
        if (body != null && req.method != Method.GET && req.method != Method.HEAD) {
            conn.doOutput = true
            // Buffered (not fixed-length streaming), so a 401 with WWW-Authenticate stays a response.
            blocking(conn) { conn.outputStream.use { it.write(body) } }
        }
        return conn
    }

    /**
     * Runs blocking I/O on [dispatcher]. Cancelling the caller disconnects [conn], which unblocks the
     * I/O thread; platform errors become [TransportException]s.
     */
    private suspend fun <T> blocking(conn: HttpURLConnection, block: () -> T): T = coroutineScope {
        val work = async(dispatcher) {
            try {
                block()
            } catch (e: IOException) {
                throw e.toTransportException()
            }
        }
        try {
            work.await()
        } catch (e: CancellationException) {
            conn.disconnect()
            throw e
        }
    }

    private fun headersOf(conn: HttpURLConnection): List<HttpHeader> =
        conn.headerFields.flatMap { (name, values) -> if (name == null) emptyList() else values.map { HttpHeader(name, it) } }

    private fun bodyOf(conn: HttpURLConnection, status: Int): InputStream? =
        if (status >= 400) conn.errorStream else try {
            conn.inputStream
        } catch (_: IOException) {
            conn.errorStream
        }

    private inner class UrlConnectionByteStream(
        private val conn: HttpURLConnection,
        private val status: Int,
        private val input: InputStream?,
    ) : ByteStream {
        @Volatile private var closed = false

        override fun status(): UShort = status.toUShort()

        override suspend fun nextChunk(): ByteArray? {
            if (closed || input == null) return null
            return try {
                blocking(conn) {
                    val buf = ByteArray(CHUNK_SIZE)
                    val n = input.read(buf)
                    if (n < 0) null else buf.copyOf(n)
                }
            } catch (e: TransportException) {
                if (closed) null else throw e
            }.also { if (it == null) closeStream() }
        }

        override fun closeStream() {
            if (closed) return
            closed = true
            // Disconnect first: closing a chunked stream may otherwise try to drain it for reuse.
            conn.disconnect()
            try {
                input?.close()
            } catch (_: IOException) {
            }
        }
    }
}
