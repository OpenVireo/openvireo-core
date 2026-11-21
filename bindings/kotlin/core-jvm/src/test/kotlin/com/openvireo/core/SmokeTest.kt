package com.openvireo.core

import com.openvireo.core.hosts.FileCache
import com.openvireo.core.hosts.JavaNetHttpTransport
import com.openvireo.core.hosts.JulLogSink
import com.openvireo.core.hosts.MemoryCache
import com.openvireo.core.hosts.MemoryStore
import com.openvireo.core.hosts.SystemClock
import com.openvireo.core.hosts.UrlConnectionTransport
import com.openvireo.core.hosts.assertThrows
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The binding end to end against ov-testkit's in-memory auth and sync servers, served on a loopback
 * socket by `ov-testkit-serve` (`cargo xtask kotlin --smoke` builds it and passes its path as
 * `-Pov.testkitServe`). Every request goes through a real default transport and the generated
 * async foreign traits: register, log in on a second device, create a vault, add an entry, sync,
 * receive a server event over the streaming transport, share link, and error codes.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SmokeTest {
    private var server: Process? = null
    private var port = 0

    @BeforeAll
    fun startServer() {
        val exe = System.getProperty("ov.testkitServe")
        if (System.getProperty("ov.requireSmoke") == "true") {
            check(!exe.isNullOrEmpty()) { "ov.requireSmoke is set but ov.testkitServe isn't" }
        }
        assumeTrue(!exe.isNullOrEmpty(), "set -Pov.testkitServe=<path to ov-testkit-serve> (cargo xtask kotlin --smoke)")
        val p = ProcessBuilder(exe!!, "--port", "0").redirectError(ProcessBuilder.Redirect.INHERIT).start()
        server = p
        val line = BufferedReader(InputStreamReader(p.inputStream)).readLine() ?: error("ov-testkit-serve printed nothing")
        port = Regex("""listening on http://127\.0\.0\.1:(\d+)""").find(line)?.groupValues?.get(1)?.toInt()
            ?: error("unexpected first line from ov-testkit-serve: $line")
    }

    @AfterAll
    fun stopServer() {
        server?.let {
            it.outputStream.close() // it exits when stdin closes
            if (!it.waitFor(5, TimeUnit.SECONDS)) it.destroyForcibly()
        }
    }

    /** Sends `https://<host>/<path>` to `http://127.0.0.1:<port>/<host>/<path>` and counts stream traffic. */
    private inner class ToTestkit(private val inner: HttpTransport) : HttpTransport {
        val requests = AtomicInteger()
        val streamsOpened = AtomicInteger()
        val streamChunks = AtomicInteger()

        private fun rewrite(req: HttpRequest): HttpRequest {
            requests.incrementAndGet()
            check(req.url.startsWith("https://")) { "unexpected URL ${req.url}" }
            return req.copy(url = "http://127.0.0.1:$port/" + req.url.removePrefix("https://"))
        }

        override suspend fun send(req: HttpRequest): HttpResponse = inner.send(rewrite(req))

        override suspend fun openStream(req: HttpRequest): OpenedStream {
            val opened = inner.openStream(rewrite(req))
            streamsOpened.incrementAndGet()
            val s = opened.stream
            return OpenedStream(object : ByteStream {
                override fun status(): UShort = s.status()
                override suspend fun nextChunk(): ByteArray? = s.nextChunk()?.also { streamChunks.incrementAndGet() }
                override fun closeStream() = s.closeStream()
            })
        }
    }

    private fun transport(kind: String): HttpTransport = when (kind) {
        "java.net.http" -> JavaNetHttpTransport()
        "HttpURLConnection" -> UrlConnectionTransport()
        else -> error(kind)
    }

    private fun device(http: HttpTransport, cache: BlobCache = MemoryCache()) = OvClient(
        ClientConfig(DeviceInfo(null, "kotlin-smoke", Platform.CLI), false, null),
        Host(http, MemoryStore(), cache, SystemClock, JulLogSink()),
    )

    private val issuer = "https://auth.test"
    private val kdf = KdfOverrides(19456u, 2u, 1u) // the SDK tests' cheap KDF
    private fun ct() = CancelToken()

    private fun entry(title: String, password: String) = EntryInput(
        listOf(FieldInput("Title", title.toByteArray(), null), FieldInput("Password", password.toByteArray(), null)),
        emptyList(),
        null,
        null,
        EntryExpiry.Keep,
    )

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = ["java.net.http", "HttpURLConnection"])
    fun `register, log in, vault, entry, sync, events, share link, errors`(kind: String, @TempDir cacheDir: Path) = runBlocking<Unit> {
        val email = "alice-${kind.lowercase().replace('.', '-')}@example.com"
        val password = "correct horse"

        // Register on device A.
        val httpA = ToTestkit(transport(kind))
        val a = device(httpA).connect(issuer, ct())
        val kit = a.register(RegisterInput(email, password.toByteArray(), kdf, true), ct())
        assertTrue(kit.secretKey.isNotEmpty())
        assertTrue(httpA.requests.get() > 0, "requests went through the Kotlin transport")

        // Log in on device B (Secret Key typed in; file cache).
        val httpB = ToTestkit(transport(kind))
        val b = device(httpB, FileCache(cacheDir)).connect(issuer, ct())
        val step = b.login(LoginInput(email, password.toByteArray(), kit.secretKey, null, true), ct())
        val unlocked = assertInstanceOf(LoginStep.Unlocked::class.java, step).unlocked
        assertFalse(unlocked.offline)

        // A creates a vault, adds an entry and syncs it up.
        val vault = a.createVault("Infra", null, ct())
        val entryId = vault.addEntry(vault.rootGroupId(), entry("VPN", "s3cret"))
        val report = vault.sync(SyncOptions(true), ct())
        assertTrue(report.outcome == SyncOutcome.UPLOADED || report.outcome == SyncOutcome.CREATED, "${report.outcome}")

        // B sees it.
        val theirs = b.openVault(vault.id(), ct())
        val rec = theirs.entry(entryId)
        assertArrayEquals("s3cret".toByteArray(), rec.fields.single { it.name == "Password" }.value)

        // Streaming: A subscribes (GET /events through openStream/nextChunk), B uploads, A gets the event.
        val events = a.subscribe(ct())
        val next = async { events.next(ct()) }
        withTimeout(10_000) { while (httpA.streamChunks.get() == 0) delay(20) } // connected (": connected")
        theirs.addEntry(theirs.rootGroupId(), entry("New", "x"))
        theirs.sync(SyncOptions(true), ct())
        val ev = withTimeout(10_000) { next.await() }
        val changed = assertInstanceOf(AccountEvent.VaultChanged::class.java, ev)
        assertEquals(vault.id(), changed.vaultId)
        assertFalse(changed.deleted)
        assertEquals(1, httpA.streamsOpened.get())
        events.closeStream()
        assertNull(events.next(ct()))

        // A pulls B's entry.
        assertEquals(SyncOutcome.PULLED, vault.sync(SyncOptions(false), ct()).outcome)
        assertTrue(vault.entries(false).any { it.title == "New" })

        // Share link, opened by a device with no account.
        val api = a.serverConfig().api
        val created = a.createShare(textSharePayload("the secret".toByteArray(), "Note", null), ShareOptions(3600u, 2u, null, null, null), ct())
        val anon = device(ToTestkit(transport(kind)))
        val info = anon.shareInfo(api, created.id, ct())
        assertEquals(2u, info.opensLeft)
        val opened = anon.openShare(api, created.url, null, info, ct())
        assertArrayEquals("the secret".toByteArray(), opened.payload.fields[0].value)
        assertEquals(1u, opened.opensLeft)

        // Error codes: a passcode-protected link without the passcode, and a wrong password.
        val locked = a.createShare(textSharePayload("x".toByteArray(), null, null), ShareOptions(3600u, null, "1234".toByteArray(), null, null), ct())
        val e1 = assertThrows<OvException> { anon.openShare(api, locked.url, null, null, ct()) }
        assertEquals(OvErrorCode.PASSCODE_REQUIRED, e1.code)
        assertEquals("passcode_required", e1.wireCode)
        val c = device(ToTestkit(transport(kind))).connect(issuer, ct())
        val e2 = assertThrows<OvException> { c.login(LoginInput(email, "wrong".toByteArray(), kit.secretKey, null, true), ct()) }
        assertEquals(OvErrorCode.UNAUTHORIZED, e2.code)
        assertEquals(401, e2.status)
    }
}
