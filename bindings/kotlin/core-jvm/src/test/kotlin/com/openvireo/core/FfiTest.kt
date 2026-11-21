package com.openvireo.core

import com.openvireo.core.hosts.MemoryCache
import com.openvireo.core.hosts.MemoryStore
import com.openvireo.core.hosts.SystemClock
import com.openvireo.core.hosts.assertThrows
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** Offline calls through the generated binding and JNA: the Swift `SmokeTests` and `HostTests`. */
class FfiTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun `version is semver`() {
        assertEquals(3, version().split('.').size)
    }

    @Test
    fun `sha256 of abc`() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex(sha256("abc".toByteArray())))
    }

    @Test
    fun `aead round trip and error codes`() {
        val key = ByteArray(32) { 7 }
        val nonce = ByteArray(24) { 9 }
        val ct = aeadEncrypt(key, nonce, "hi".toByteArray(), ByteArray(0))
        assertArrayEquals("hi".toByteArray(), aeadDecrypt(key, nonce, ct, ByteArray(0)))
        val e = assertThrows<OvException> { aeadDecrypt(ByteArray(32) { 8 }, nonce, ct, ByteArray(0)) }
        assertEquals(OvErrorCode.DECRYPTION_FAILED, e.code)
        assertEquals("decryption_failed", e.wireCode)
    }

    @Test
    fun `facade free function and wire codes`() {
        assertEquals(listOf("UserName", "Password", "URL"), defaultShareFields())
        assertEquals("plan_limit", errorCodeWire(OvErrorCode.PLAN_LIMIT))
        assertEquals(OvErrorCode.PLAN_LIMIT, errorCodeFromWire("plan_limit"))
    }

    private class OfflineHttp : HttpTransport {
        override suspend fun send(req: HttpRequest): HttpResponse = throw TransportException.Offline()
        override suspend fun openStream(req: HttpRequest): OpenedStream = throw TransportException.Offline()
    }

    private fun client(http: HttpTransport = OfflineHttp()) = OvClient(
        ClientConfig(DeviceInfo(null, "smoke", Platform.CLI), false, null),
        Host(http, MemoryStore(), MemoryCache(), SystemClock, com.openvireo.core.hosts.JulLogSink()),
    )

    @Test
    fun `the client keeps its config`() {
        val config = client().config()
        assertEquals("smoke", config.device.name)
        assertEquals(Platform.CLI, config.device.platform)
    }

    /** An async call runs through the Kotlin host: the transport is offline, so discovery fails with network_error. */
    @Test
    fun `an async call uses the host`() = runBlocking<Unit> {
        val e = assertThrows<OvException> { client().discover("https://example.test", CancelToken()) }
        assertEquals(OvErrorCode.NETWORK_ERROR, e.code)
    }

    /** A host that throws something other than its declared error: the core sees it as a transport failure. */
    @Test
    fun `an unexpected host exception becomes network_error`() = runBlocking<Unit> {
        val broken = object : HttpTransport {
            override suspend fun send(req: HttpRequest): HttpResponse = throw IllegalStateException("bug")
            override suspend fun openStream(req: HttpRequest): OpenedStream = throw IllegalStateException("bug")
        }
        val e = assertThrows<OvException> { client(broken).discover("https://example.test", CancelToken()) }
        assertEquals(OvErrorCode.NETWORK_ERROR, e.code)
    }

    @Test
    fun `a local vault round trips through kdbx`() = runBlocking<Unit> {
        val creds = KdbxCredentials("pw".toByteArray(), null)
        val v = client().createLocal("Home", creds, CancelToken())
        val id = v.addEntry(
            v.rootGroupId(),
            EntryInput(listOf(FieldInput("Title", "VPN".toByteArray(), null)), emptyList(), null, null, EntryExpiry.Keep),
        )
        val bytes = v.saveLocal(CancelToken())
        val back = Vault.openLocal(bytes, creds, CancelToken())
        assertEquals("VPN", back.entries(false).single { it.id == id }.title)
    }
}
