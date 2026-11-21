@file:JvmName("OvExceptions")

package com.openvireo.core

// `OvException` has one variant, `Failure` (UniFFI errors are enums). These read its fields without
// a cast, as the Swift binding's `OvError+Fields.swift` does: `catch (e: OvException) { e.code }`.

/** The typed code. */
public val OvException.code: OvErrorCode get() = (this as OvException.Failure).code

/** The stable string UI code matches on: the server's own code when it isn't an [OvErrorCode], else the code's wire string. */
public val OvException.wireCode: String get() = (this as OvException.Failure).wireCode

/** The human-readable message (English, for logs). `message` is a summary of every field. */
public val OvException.errorMessage: String get() = (this as OvException.Failure).errorMessage

/** The HTTP status, for server errors. */
public val OvException.status: Int? get() = (this as OvException.Failure).status?.toInt()

/** `Retry-After` seconds, for `rate_limited`. */
public val OvException.retryAfter: Long? get() = (this as OvException.Failure).retryAfter?.toLong()
