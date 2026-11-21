package com.openvireo.core.hosts

import com.openvireo.core.OvErrorCode
import com.openvireo.core.OvException
import com.openvireo.core.TransportException
import java.io.IOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.nio.channels.UnresolvedAddressException
import java.util.concurrent.CompletionException
import java.util.concurrent.ExecutionException
import javax.net.ssl.SSLException

/** The size of the reads behind `ByteStream.nextChunk` (a chunk may be smaller). */
internal const val CHUNK_SIZE: Int = 16 * 1024

/**
 * An [OvException] a host throws back into the core. The core reads `code` and `message` (the
 * other fields are ignored when a host throws).
 */
public fun ovException(code: OvErrorCode, message: String): OvException =
    OvException.Failure(code, "", message, null, null, null, null)

/** Unwraps `CompletionException` / `ExecutionException` to the cause. */
internal fun Throwable.unwrapped(): Throwable {
    var e: Throwable = this
    while ((e is CompletionException || e is ExecutionException) && e.cause != null) e = e.cause!!
    return e
}

/**
 * Maps a platform failure to the transport error the core expects (`ov_core::host::TransportError`):
 * no network, DNS failure or connection refused → `Offline`; a timeout → `Timeout`; TLS → `Tls`;
 * anything else → `Other`. The core turns all of them into `network_error` (`Cancelled` into
 * `aborted`). The messages are for logs and never contain headers.
 */
internal fun Throwable.toTransportException(): TransportException {
    // ConnectException (and UnresolvedAddressException) are often wrapped by java.net.http.
    var e: Throwable = unwrapped()
    if (e is IOException && e !is ConnectException && e.cause is ConnectException) e = e.cause!!
    return when (e) {
        is TransportException -> e
        is SocketTimeoutException -> TransportException.Timeout()
        is UnknownHostException, is ConnectException, is NoRouteToHostException, is UnresolvedAddressException ->
            TransportException.Offline()
        is SSLException -> TransportException.Tls(e.message ?: e.javaClass.simpleName)
        else -> TransportException.Other(e.message?.let { "${e.javaClass.simpleName}: $it" } ?: e.javaClass.name)
    }
}
