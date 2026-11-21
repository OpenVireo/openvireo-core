package com.openvireo.core.hosts

import com.openvireo.core.BlobCache
import com.openvireo.core.CachedVault
import java.util.concurrent.ConcurrentHashMap

/**
 * A [BlobCache] in memory: the offline cache (SPEC §20) lasts as long as the process. Everything
 * in it is ciphertext or public. Safe to call concurrently.
 */
public class MemoryCache : BlobCache {
    private val vaults = ConcurrentHashMap<String, ConcurrentHashMap<String, CachedVault>>()
    private val meta = ConcurrentHashMap<String, ConcurrentHashMap<String, ByteArray>>()

    override suspend fun load(userId: String, vaultId: String): CachedVault? = vaults[userId]?.get(vaultId)?.copy()

    override suspend fun save(userId: String, vaultId: String, v: CachedVault) {
        vaults.getOrPut(userId) { ConcurrentHashMap() }[vaultId] = v.copy()
    }

    override suspend fun remove(userId: String, vaultId: String) {
        vaults[userId]?.remove(vaultId)
    }

    override suspend fun list(userId: String): List<String> = vaults[userId]?.keys?.sorted() ?: emptyList()

    override suspend fun loadMeta(userId: String, name: String): ByteArray? = meta[userId]?.get(name)?.copyOf()

    override suspend fun saveMeta(userId: String, name: String, value: ByteArray) {
        meta.getOrPut(userId) { ConcurrentHashMap() }[name] = value.copyOf()
    }

    override suspend fun clearUser(userId: String) {
        vaults.remove(userId)
        meta.remove(userId)
    }
}
