package com.openvireo.core.java

import com.openvireo.core.OvErrorCode
import com.openvireo.core.OvException
import java.util.concurrent.CompletionException
import java.util.concurrent.ExecutionException

/**
 * Reads an [OvException]'s fields from Java, from the exception itself or from what a facade future
 * failed with (`CompletionException` from `join()`, `ExecutionException` from `get()`):
 *
 * ```java
 * try {
 *     account.login(input).join();
 * } catch (CompletionException e) {
 *     if (JErrors.code(e) == OvErrorCode.UNAUTHORIZED) { ... }
 * }
 * ```
 *
 * Every getter returns `null` when [t] isn't (and doesn't wrap) an `OvException`.
 */
public object JErrors {
    /** The `OvException` [t] is or wraps (through `CompletionException` / `ExecutionException` causes), or `null`. */
    @JvmStatic
    public fun ovException(t: Throwable?): OvException? {
        var e = t
        while (e != null) {
            if (e is OvException) return e
            if (e !is CompletionException && e !is ExecutionException) return null
            e = e.cause
        }
        return null
    }

    /** The typed code. */
    @JvmStatic
    public fun code(t: Throwable?): OvErrorCode? = failure(t)?.code

    /** The stable string UI code matches on (the server's own code when it isn't an [OvErrorCode]). */
    @JvmStatic
    public fun wireCode(t: Throwable?): String? = failure(t)?.wireCode

    /** The human-readable message (English, for logs). */
    @JvmStatic
    public fun errorMessage(t: Throwable?): String? = failure(t)?.errorMessage

    /** The HTTP status, for server errors. */
    @JvmStatic
    public fun status(t: Throwable?): Int? = failure(t)?.status?.toInt()

    /** `Retry-After` seconds, for `rate_limited`. */
    @JvmStatic
    public fun retryAfter(t: Throwable?): Long? = failure(t)?.retryAfter?.toLong()

    /** Extra details as a JSON object string (camelCase keys). */
    @JvmStatic
    public fun details(t: Throwable?): String? = failure(t)?.details

    /** The server's code when it isn't one of [OvErrorCode]. */
    @JvmStatic
    public fun serverCode(t: Throwable?): String? = failure(t)?.serverCode

    /**
     * An `OvException` for a Host part to fail with (complete the future exceptionally with it). The
     * core reads [code] and [message]; the other fields are ignored when a host throws.
     */
    @JvmStatic
    public fun ovException(code: OvErrorCode, message: String): OvException =
        OvException.Failure(code, "", message, null, null, null, null)

    private fun failure(t: Throwable?): OvException.Failure? = ovException(t) as? OvException.Failure
}
