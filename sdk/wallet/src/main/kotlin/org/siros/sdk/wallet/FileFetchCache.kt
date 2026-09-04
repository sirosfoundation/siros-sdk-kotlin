// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.siros.sdk.credentials.FetchCache
import org.siros.sdk.credentials.FetchCacheEntry
import timber.log.Timber
import java.io.File

/**
 * A [FetchCache] persisted as one JSON file on device.
 *
 * ### Where, and why not somewhere more protected
 *
 * Under `noBackupFilesDir`: the contents are public issuer metadata
 * documents - the very same bytes any verifier can fetch - plus the URLs
 * they came from, so there is nothing to protect and nothing worth carrying
 * to a new device in a backup. `EncryptedSharedPreferences`/[SessionStore]
 * would add a keystore round-trip per read for no security benefit, and
 * backing it up would restore stale documents onto a device that could
 * simply refetch them.
 *
 * ### Guarantees
 *
 * - Never throws into a caller. A missing, unreadable or corrupt file is
 *   logged at warn and treated as empty; a failed write is logged and the
 *   in-memory state carries on. Display metadata must not be able to take
 *   the wallet down at launch.
 * - Safe under concurrent access from any number of coroutines (one [Mutex]
 *   around both the in-memory map and the file).
 * - Writes are atomic at the file level (write to a sibling temp file, then
 *   rename) so a crash mid-write leaves the previous version, not half a
 *   JSON document.
 * - Bounded: past [maxEntries] the oldest entries by `fetchedAtMillis` are
 *   evicted. A wallet holds tens of credential types, not thousands; the
 *   bound exists so a bug elsewhere cannot grow this file without limit.
 *
 * Reads and writes run on [Dispatchers.IO]; the first [get] or [put] loads
 * the file, after which reads are served from memory.
 *
 * @param file where to persist. The default lives under the app's
 *        no-backup files directory; tests pass a temp file.
 */
class FileFetchCache(
    private val file: File,
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) : FetchCache {

    constructor(context: Context) : this(File(context.noBackupFilesDir, DEFAULT_FILE_NAME))

    private val json = Json { ignoreUnknownKeys = true }
    private val serializer = MapSerializer(String.serializer(), FetchCacheEntry.serializer())
    private val mutex = Mutex()

    /** Null until first loaded; then the authoritative in-memory copy of [file]. */
    private var entries: MutableMap<String, FetchCacheEntry>? = null

    override suspend fun get(key: String): FetchCacheEntry? = withContext(Dispatchers.IO) {
        mutex.withLock { loadLocked()[key] }
    }

    override suspend fun put(key: String, entry: FetchCacheEntry) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val map = loadLocked()
            map[key] = entry
            evictLocked(map)
            persistLocked(map)
        }
    }

    /** Drop every entry - for tests and for a "clear caches" affordance. */
    suspend fun clear() = withContext(Dispatchers.IO) {
        mutex.withLock {
            entries = mutableMapOf()
            try {
                file.delete()
            } catch (e: Exception) {
                Timber.w(e, "FileFetchCache: failed to delete ${file.name}")
            }
        }
    }

    /** Number of entries currently held, for tests. */
    suspend fun size(): Int = withContext(Dispatchers.IO) { mutex.withLock { loadLocked().size } }

    private fun loadLocked(): MutableMap<String, FetchCacheEntry> {
        entries?.let { return it }
        val loaded: MutableMap<String, FetchCacheEntry> = try {
            if (file.isFile) {
                json.decodeFromString(serializer, file.readText()).toMutableMap()
            } else {
                mutableMapOf()
            }
        } catch (e: Exception) {
            // Corrupt or from an incompatible build: start empty rather than
            // fail. Everything in here can be refetched.
            Timber.w(e, "FileFetchCache: ${file.name} unreadable, starting empty")
            mutableMapOf()
        }
        entries = loaded
        return loaded
    }

    private fun evictLocked(map: MutableMap<String, FetchCacheEntry>) {
        if (map.size <= maxEntries) return
        val surplus = map.size - maxEntries
        map.entries
            .sortedBy { it.value.fetchedAtMillis }
            .take(surplus)
            .map { it.key }
            .forEach { map.remove(it) }
    }

    private fun persistLocked(map: Map<String, FetchCacheEntry>) {
        try {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, "${file.name}.tmp")
            tmp.writeText(json.encodeToString(serializer, map))
            if (!tmp.renameTo(file)) {
                // Some filesystems refuse to rename over an existing file.
                file.delete()
                if (!tmp.renameTo(file)) {
                    Timber.w("FileFetchCache: could not move ${tmp.name} into place")
                    tmp.delete()
                }
            }
        } catch (e: Exception) {
            Timber.w(e, "FileFetchCache: failed to persist ${file.name}")
        }
    }

    companion object {
        /** File name under `noBackupFilesDir`. */
        const val DEFAULT_FILE_NAME = "siros-display-metadata-cache.json"

        /** Generous for a wallet, tight enough that a runaway key can't fill the disk. */
        const val DEFAULT_MAX_ENTRIES = 500
    }
}
