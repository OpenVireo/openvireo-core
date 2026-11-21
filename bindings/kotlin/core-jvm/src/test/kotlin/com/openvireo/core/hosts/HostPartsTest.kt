package com.openvireo.core.hosts

import com.openvireo.core.CachedVault
import com.openvireo.core.Level
import com.openvireo.core.OvErrorCode
import com.openvireo.core.OvException
import com.openvireo.core.code
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.util.logging.Handler
import java.util.logging.LogRecord
import java.util.logging.Logger
import java.util.logging.Level as JulLevel

/** The default store, caches, clock and log sink. */
class HostPartsTest {
    @Test
    fun `MemoryStore copies and wipes`() = runBlocking<Unit> {
        val s = MemoryStore()
        val value = byteArrayOf(1, 2, 3)
        s.set("session", value)
        assertArrayEquals(byteArrayOf(0, 0, 0), value, "the passed value is wiped")
        val got = s.get("session")!!
        assertArrayEquals(byteArrayOf(1, 2, 3), got)
        got.fill(9)
        assertArrayEquals(byteArrayOf(1, 2, 3), s.get("session"), "get returns a copy")
        assertEquals(setOf("session"), s.keys())
        s.delete("session")
        s.delete("missing")
        assertNull(s.get("session"))
    }

    private val v1 = CachedVault(byteArrayOf(1), byteArrayOf(2, 2), null, byteArrayOf())
    private val v2 = CachedVault(byteArrayOf(3), null, byteArrayOf(4), null)

    private fun assertSame(a: CachedVault?, b: CachedVault?) {
        assertArrayEquals(a!!.state, b!!.state)
        assertArrayEquals(a.base, b.base)
        assertArrayEquals(a.pending, b.pending)
        assertArrayEquals(a.autofill, b.autofill)
    }

    private fun exercise(c: com.openvireo.core.BlobCache) = runBlocking<Unit> {
        assertNull(c.load("u1", "v1"))
        assertEquals(emptyList<String>(), c.list("u1"))
        c.save("u1", "v1", v1)
        c.save("u1", "vault/with:odd chars", v2)
        c.save("u2", "v1", v2)
        assertSame(v1, c.load("u1", "v1"))
        assertSame(v2, c.load("u1", "vault/with:odd chars"))
        assertEquals(listOf("v1", "vault/with:odd chars"), c.list("u1"))
        c.save("u1", "v1", v2)
        assertSame(v2, c.load("u1", "v1"))
        c.remove("u1", "v1")
        c.remove("u1", "missing")
        assertEquals(listOf("vault/with:odd chars"), c.list("u1"))
        c.saveMeta("", "config:https://auth.test", byteArrayOf(7))
        c.saveMeta("u1", "profile", byteArrayOf(8))
        assertArrayEquals(byteArrayOf(7), c.loadMeta("", "config:https://auth.test"))
        assertArrayEquals(byteArrayOf(8), c.loadMeta("u1", "profile"))
        assertNull(c.loadMeta("u1", "vaults"))
        c.clearUser("u1")
        assertEquals(emptyList<String>(), c.list("u1"))
        assertNull(c.loadMeta("u1", "profile"))
        assertSame(v2, c.load("u2", "v1"))
        assertArrayEquals(byteArrayOf(7), c.loadMeta("", "config:https://auth.test"))
    }

    @Test
    fun `MemoryCache keeps records per user`() = exercise(MemoryCache())

    @Test
    fun `FileCache keeps records per user, across instances`(@TempDir dir: Path) {
        exercise(FileCache(dir))
        runBlocking {
            assertSame(v2, FileCache(dir).load("u2", "v1"))
        }
        // No temporary files are left behind.
        Files.walk(dir).use { paths -> assertTrue(paths.noneMatch { it.fileName.toString().endsWith(".part") }) }
    }

    @Test
    fun `a corrupt FileCache record is an internal error`(@TempDir dir: Path) = runBlocking<Unit> {
        val c = FileCache(dir)
        c.save("u", "v", v1)
        Files.walk(dir).use { paths -> paths.filter { it.toString().endsWith(".vault") }.forEach { Files.write(it, byteArrayOf(1, 2)) } }
        val e = assertThrows<OvException> { c.load("u", "v") }
        assertEquals(OvErrorCode.INTERNAL, e.code)
    }

    @Test
    fun `SystemClock is the wall clock`() {
        val before = System.currentTimeMillis()
        val now = SystemClock.nowUnixMs()
        assertTrue(now >= before && now <= System.currentTimeMillis())
    }

    @Test
    fun `JulLogSink logs per target`() {
        val records = mutableListOf<LogRecord>()
        val logger = Logger.getLogger("openvireo.ov_sync")
        val handler = object : Handler() {
            override fun publish(r: LogRecord) {
                records.add(r)
            }
            override fun flush() {}
            override fun close() {}
        }
        logger.addHandler(handler)
        logger.level = JulLevel.ALL
        try {
            val sink = JulLogSink()
            sink.log(Level.INFO, "ov_sync", "pulled")
            sink.log(Level.DEBUG, "ov_sync", "detail")
            sink.log(Level.ERROR, "ov_sync", "failed")
        } finally {
            logger.removeHandler(handler)
        }
        assertEquals(listOf(JulLevel.INFO, JulLevel.FINE, JulLevel.SEVERE), records.map { it.level })
        assertEquals(listOf("pulled", "detail", "failed"), records.map { it.message })
    }
}
