package com.openvireo.core.hosts

import com.openvireo.core.BlobCache
import com.openvireo.core.CachedVault
import com.openvireo.core.OvErrorCode
import com.openvireo.core.OvException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption

/**
 * A [BlobCache] in files under [dir] (the offline cache, SPEC §20). Everything the core stores here
 * is ciphertext or public, so ordinary app storage is fine (an app's cache or data directory).
 *
 * Layout: `<dir>/u<hex(userId)>/vaults/<hex(vaultId)>.vault` and
 * `<dir>/u<hex(userId)>/meta/<hex(name)>.bin`. Names are hex so any id is a safe file name; the
 * per-device records (`userId == ""`) live under `<dir>/u/`. Writes go to a temporary file and are
 * moved into place, so a crash leaves the old record or the new one. The I/O runs on [dispatcher].
 */
public class FileCache @JvmOverloads constructor(
    public val dir: Path,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : BlobCache {
    private val lock = Mutex()

    private fun userDir(userId: String): Path = dir.resolve("u" + hex(userId))
    private fun vaultFile(userId: String, vaultId: String): Path =
        userDir(userId).resolve("vaults").resolve(hex(vaultId) + VAULT_EXT)
    private fun metaFile(userId: String, name: String): Path = userDir(userId).resolve("meta").resolve(hex(name) + ".bin")

    override suspend fun load(userId: String, vaultId: String): CachedVault? =
        io { read(vaultFile(userId, vaultId))?.let(::decode) }

    override suspend fun save(userId: String, vaultId: String, v: CachedVault): Unit =
        io { write(vaultFile(userId, vaultId), encode(v)) }

    override suspend fun remove(userId: String, vaultId: String): Unit = io { Files.deleteIfExists(vaultFile(userId, vaultId)); Unit }

    override suspend fun list(userId: String): List<String> = io {
        val vaults = userDir(userId).resolve("vaults")
        if (!Files.isDirectory(vaults)) return@io emptyList()
        Files.newDirectoryStream(vaults).use { entries ->
            entries.mapNotNull { p ->
                p.fileName.toString().takeIf { it.endsWith(VAULT_EXT) }?.removeSuffix(VAULT_EXT)?.let(::unhex)
            }.sorted()
        }
    }

    override suspend fun loadMeta(userId: String, name: String): ByteArray? = io { read(metaFile(userId, name)) }

    override suspend fun saveMeta(userId: String, name: String, value: ByteArray): Unit =
        io { write(metaFile(userId, name), value) }

    override suspend fun clearUser(userId: String): Unit = io { deleteTree(userDir(userId)) }

    private suspend fun <T> io(block: () -> T): T = withContext(dispatcher) {
        lock.withLock {
            try {
                block()
            } catch (e: IOException) {
                throw ovException(OvErrorCode.INTERNAL, "offline cache in $dir: ${e.javaClass.simpleName}: ${e.message}")
            } catch (e: IllegalArgumentException) {
                throw ovException(OvErrorCode.INTERNAL, "offline cache in $dir: corrupt record: ${e.message}")
            }
        }
    }

    private fun read(p: Path): ByteArray? = try {
        Files.readAllBytes(p)
    } catch (_: NoSuchFileException) {
        null
    }

    private fun write(p: Path, bytes: ByteArray) {
        Files.createDirectories(p.parent)
        val tmp = Files.createTempFile(p.parent, ".tmp-", ".part")
        try {
            Files.write(tmp, bytes)
            try {
                Files.move(tmp, p, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    private fun deleteTree(p: Path) {
        if (!Files.exists(p)) return
        if (Files.isDirectory(p)) Files.newDirectoryStream(p).use { children -> children.forEach(::deleteTree) }
        Files.deleteIfExists(p)
    }

    private companion object {
        const val VAULT_EXT = ".vault"
        const val MAGIC = 0x4f564331 // "OVC1"

        fun hex(s: String): String = s.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }

        fun unhex(s: String): String? {
            if (s.length % 2 != 0) return null
            val bytes = ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toIntOrNull(16)?.toByte() ?: return null }
            return String(bytes, Charsets.UTF_8)
        }

        fun encode(v: CachedVault): ByteArray {
            val buf = ByteArrayOutputStream()
            DataOutputStream(buf).use { out ->
                out.writeInt(MAGIC)
                for (part in listOf(v.state, v.base, v.pending, v.autofill)) {
                    if (part == null) {
                        out.writeBoolean(false)
                    } else {
                        out.writeBoolean(true)
                        out.writeInt(part.size)
                        out.write(part)
                    }
                }
            }
            return buf.toByteArray()
        }

        fun decode(bytes: ByteArray): CachedVault {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                require(input.readInt() == MAGIC) { "not a cached vault record" }
                val parts = List(4) {
                    if (input.readBoolean()) {
                        val n = input.readInt()
                        require(n in 0..input.available()) { "bad length" }
                        ByteArray(n).also { input.readFully(it) }
                    } else {
                        null
                    }
                }
                return CachedVault(parts[0] ?: ByteArray(0), parts[1], parts[2], parts[3])
            }
        }
    }
}
