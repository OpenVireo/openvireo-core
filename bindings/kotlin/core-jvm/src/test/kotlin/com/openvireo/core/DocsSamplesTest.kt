package com.openvireo.core

import com.openvireo.core.hosts.JavaNetHttpTransport
import com.openvireo.core.hosts.MemoryStore
import com.openvireo.core.hosts.defaultHost
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.io.TempDir
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.file.Path
import java.util.ArrayDeque
import java.util.concurrent.TimeUnit

/**
 * The Kotlin samples of docs/bindings/kotlin-java.md against the testkit relay, with the same
 * calls. Only the issuer (`https://auth.test`), the prompts (a queue of answers) and the transport
 * (the default one, sent to the relay) differ. Skipped like [SmokeTest] without
 * `-Pov.testkitRelay`. Keep it in step with the page.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DocsSamplesTest {
    private var server: Process? = null
    private var relay = ""
    private val issuer = "https://auth.test"

    @BeforeAll
    fun startServer() {
        val exe = System.getProperty("ov.testkitRelay")
        assumeTrue(!exe.isNullOrEmpty(), "set -Pov.testkitRelay=<path to the http_relay example> (cargo xtask kotlin --smoke)")
        val p = ProcessBuilder(exe!!).redirectError(ProcessBuilder.Redirect.INHERIT).start()
        server = p
        val line = BufferedReader(InputStreamReader(p.inputStream)).readLine() ?: error("the relay printed nothing")
        relay = Regex(""""relay"\s*:\s*"(http://127\.0\.0\.1:\d+)"""").find(line)!!.groupValues[1]
    }

    @AfterAll
    fun stopServer() {
        server?.let {
            it.outputStream.close()
            if (!it.waitFor(5, TimeUnit.SECONDS)) it.destroyForcibly()
        }
    }

    private inner class ToRelay(private val inner: HttpTransport) : HttpTransport {
        private fun rewrite(req: HttpRequest): HttpRequest {
            val real = java.net.URI(req.url)
            val path = real.rawPath + (real.rawQuery?.let { "?$it" } ?: "")
            return req.copy(url = relay + path, headers = req.headers + HttpHeader("x-ov-relay-url", req.url))
        }

        override suspend fun send(req: HttpRequest): HttpResponse = inner.send(rewrite(req))
        override suspend fun openStream(req: HttpRequest): OpenedStream = inner.openStream(rewrite(req))
    }

    private fun client(cacheDir: Path, store: SecureStore = MemoryStore()) = OvClient(
        ClientConfig(DeviceInfo(id = null, name = "backup tool", platform = Platform.CLI), offline = false, server = null),
        defaultHost(cacheDir = cacheDir, http = ToRelay(JavaNetHttpTransport()), store = store),
    )

    // "Sign in", word for word but for the issuer and `ask`.
    private suspend fun signIn(client: OvClient, email: String, password: ByteArray, ask: (String) -> String): Account {
        val account = client.connect(issuer, CancelToken())
        if (account.isSignedIn()) {
            account.unlock(password, null, CancelToken())
            return account
        }

        val input = LoginInput(email, password, secretKey = null, totp = null, trustDevice = true)
        var step = try {
            account.login(input, CancelToken())
        } catch (e: OvException) {
            if (e.code != OvErrorCode.INVALID_SECRET_KEY) throw e
            account.login(input.copy(secretKey = ask("Secret Key: ").toByteArray()), CancelToken())
        }

        while (step is LoginStep.NeedsTotp) {
            step = try {
                account.submitTotp(step.challenge, ask("Two-step code: "), CancelToken())
            } catch (e: OvException) {
                if (e.code != OvErrorCode.INVALID_MFA) throw e
                step
            }
        }
        return account
    }

    private fun answers(vararg a: String): (String) -> String {
        val q = ArrayDeque(a.toList())
        return { q.removeFirst() }
    }

    private suspend fun register(email: String, dir: Path): Pair<Account, ByteArray> {
        val a = client(dir).connect(issuer, CancelToken())
        val kit = a.register(RegisterInput(email, "pw".toByteArray(), KdfOverrides(19456u, 2u, 1u), true), CancelToken())
        return a to kit.secretKey
    }

    @Test
    fun `sign in, two-step, stored session`(@TempDir dir: Path) = runBlocking<Unit> {
        val email = "docs-kt-signin@example.com"
        val (a, secretKey) = register(email, dir.resolve("a"))
        val params = parseTotpUri(a.startTwoStep(CancelToken()).uri)
        val code = { totpCode(params, System.currentTimeMillis()).code.decodeToString() }
        a.confirmTwoStep(code(), CancelToken())

        val store = MemoryStore()
        val account = signIn(client(dir.resolve("b"), store), email, "pw".toByteArray(), answers(secretKey.decodeToString(), "000000", code()))
        assertTrue(account.isUnlocked())

        // The next run with the same store unlocks the stored session.
        val again = signIn(client(dir.resolve("b"), store), email, "pw".toByteArray(), answers())
        assertTrue(again.isUnlocked())
        assertEquals(emptyList<VaultInfo>(), again.vaults(CancelToken()))
    }

    @Test
    fun `quickstart, add an entry, sync, share, errors`(@TempDir dir: Path) = runBlocking<Unit> {
        val (account, secretKey) = register("docs-kt-vaults@example.com", dir.resolve("a"))
        val vaultId = account.createVault("Personal", null, CancelToken()).id()

        // "Add an entry, sync, share"
        val vault = account.openVault(vaultId, CancelToken())
        val entryId = vault.addEntry(
            vault.ensureGroup("Servers/Prod"),
            EntryInput(
                fields = listOf(
                    FieldInput("Title", "Router".toByteArray(), null),
                    FieldInput("UserName", "admin".toByteArray(), null),
                    FieldInput("Password", "correct horse".toByteArray(), null),
                ),
                removeFields = emptyList(),
                tags = null,
                iconId = null,
                expiry = EntryExpiry.Keep,
            ),
        )
        val report = vault.sync(SyncOptions(localChanged = true), CancelToken())
        assertTrue(report.outcome == SyncOutcome.UPLOADED || report.outcome == SyncOutcome.CREATED)

        val payload = itemSharePayload(vault.entry(entryId), defaultShareFields(), null)
        val share = account.createShare(payload, ShareOptions(3600u, 1u, null, vault.id(), entryId), CancelToken())
        val link = share.url.decodeToString()

        val anon = client(dir.resolve("anon"))
        val api = account.serverConfig().api
        val info = anon.shareInfo(api, parseShareLink(link).id, CancelToken())
        val opened = anon.openShare(api, share.url, null, info, CancelToken())
        assertEquals("correct horse", opened.payload.fields.single { it.k == "password" }.value.decodeToString())

        // The quickstart's loop.
        val lines = mutableListOf<String>()
        for (v in account.vaults(CancelToken())) {
            val open = account.openVault(v.id, CancelToken())
            for (entry in open.entries(false)) {
                lines += "${v.name} / ${entry.groupPath.joinToString("/")} ${entry.title} ${entry.username}"
            }
        }
        assertEquals(listOf("Personal / Servers/Prod Router admin"), lines)
        assertEquals(entryId, vault.find("ov://Personal/Servers/Prod/Router").id)
        assertEquals("correct horse", vault.readField("ov://Personal/Servers/Prod/Router/Password").decodeToString())

        // "Errors"
        val other = client(dir.resolve("c")).connect(issuer, CancelToken())
        val input = LoginInput("docs-kt-vaults@example.com", "wrong".toByteArray(), secretKey, null, true)
        val said = try {
            other.login(input, CancelToken())
            "ok"
        } catch (e: OvException) {
            when (e.code) {
                OvErrorCode.UNAUTHORIZED -> "wrong email, password or Secret Key"
                OvErrorCode.NETWORK_ERROR -> "offline: ${e.errorMessage}"
                OvErrorCode.RATE_LIMITED -> "try again in ${e.retryAfter}s"
                else -> "${e.wireCode} (${e.status}): ${e.errorMessage}"
            }
        }
        assertEquals("wrong email, password or Secret Key", said)
    }
}
