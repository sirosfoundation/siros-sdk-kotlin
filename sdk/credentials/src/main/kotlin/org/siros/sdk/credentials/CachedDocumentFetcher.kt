// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * The caching policy shared by [VctmFetcher] and [MddlSchemaFetcher].
 *
 * Two layers, consulted in order:
 *
 * 1. **In-memory, per instance, positive only** ([memoryTtlMillis], 30 min by
 *    default). This is the pre-existing behaviour and is what keeps a burst
 *    of lookups for the same type (re-issuance, several copies of one
 *    credential) down to one network call within a session.
 * 2. **[persistentCache], optional, positive AND negative.** Survives process
 *    restarts, which is the point: the wallet re-hydrates display metadata
 *    for every stored credential on every login (the encrypted private-data
 *    container deliberately does not persist it), so without this layer each
 *    launch repeats every fetch - and, worse, repeats every *failed* fetch,
 *    which is the one the user actually sees as a spinner.
 *
 * ### Persistent-cache semantics
 *
 * - A **HIT** younger than [freshTtlMillis] (24 h) is served with no network.
 * - A **HIT** older than that but younger than [hardTtlMillis] (7 d) is served
 *   immediately, and if a [revalidateScope] was supplied a refresh is
 *   launched on it in the background (deduplicated per key). Without a
 *   scope, stale entries are simply served until the hard TTL - nothing in
 *   display metadata is time-critical enough to block a caller on.
 * - A **HIT** older than the hard TTL is refetched inline. If that refetch
 *   fails, the old body is kept and served: a source that worked last week
 *   and is down today should degrade to "slightly stale" rather than "blank".
 * - A **MISS** whose `nextRetryAtMillis` is in the future returns null
 *   immediately with no network call - or, if the entry still carries a
 *   body from an earlier success, that stale body.
 * - A **MISS** that is due is retried; success flips it to a HIT, failure
 *   pushes `nextRetryAtMillis` out along [FetchBackoff]'s schedule.
 *
 * With no [persistentCache] the class reduces exactly to layer 1, so every
 * caller that constructed a fetcher before this existed sees no change.
 *
 * @param namespace prefix for persistent-cache keys; keeps two fetchers with
 *        the same argument tuple from reading each other's documents.
 * @param parse turns a response body into the document type, or null if the
 *        body is not a valid document. A body that fails to parse is treated
 *        as a fetch failure everywhere, so a 200 with an HTML error page is
 *        a MISS, not a poisoned HIT.
 */
internal class CachedDocumentFetcher<T : Any>(
    private val namespace: String,
    private val parse: (String) -> T?,
    private val memoryTtlMillis: Long,
    private val persistentCache: FetchCache?,
    private val freshTtlMillis: Long,
    private val hardTtlMillis: Long,
    private val revalidateScope: CoroutineScope?,
    private val nowMillis: () -> Long,
) {
    private data class MemoryEntry<T>(val value: T, val expiresAtMillis: Long)

    private val mutex = Mutex()
    private val memory = mutableMapOf<String, MemoryEntry<T>>()

    /** Keys with a background revalidation in flight, so one stale read spawns one refresh. */
    private val revalidating = mutableSetOf<String>()

    /**
     * Resolve the document identified by [keyParts], calling [fetchBody] for
     * the network only when the caches say so. [fetchBody] returns the raw
     * response body of whichever resolution strategy succeeded, or null.
     */
    suspend fun fetch(keyParts: List<String?>, fetchBody: suspend () -> String?): T? {
        val key = fetchCacheKey(namespace, *keyParts.toTypedArray())
        val now = nowMillis()

        mutex.withLock { memory[key] }?.let { entry ->
            if (entry.expiresAtMillis > now) return entry.value
        }

        val cache = persistentCache ?: return fetchAndRemember(key, null, fetchBody)
        val persisted = cache.get(key)

        if (persisted != null) {
            val age = now - persisted.fetchedAtMillis
            when (persisted.status) {
                FetchCacheStatus.HIT -> {
                    val parsed = persisted.body?.let(parse)
                    if (parsed != null && age < hardTtlMillis) {
                        remember(key, parsed, now)
                        if (age >= freshTtlMillis) revalidateInBackground(key, persisted, fetchBody)
                        return parsed
                    }
                    // Hard-expired (or unparseable - a format change since it
                    // was written): fall through to the network, keeping the
                    // old entry so a failure can still serve its body.
                }
                FetchCacheStatus.MISS -> {
                    if (now < persisted.nextRetryAtMillis) {
                        // Not due. The whole point: no network, no waiting.
                        Timber.d(
                            "$namespace: negative-cached, next retry in " +
                                "${(persisted.nextRetryAtMillis - now) / 1000}s for $key",
                        )
                        return persisted.body?.let(parse)?.also { remember(key, it, now) }
                    }
                }
            }
        }

        return fetchAndRemember(key, persisted, fetchBody)
    }

    /**
     * Hit the network, then record the outcome in both layers. On failure
     * with a previous good body available, that body is what the caller gets.
     */
    private suspend fun fetchAndRemember(
        key: String,
        previous: FetchCacheEntry?,
        fetchBody: suspend () -> String?,
    ): T? {
        val body = try {
            fetchBody()
        } catch (e: Exception) {
            Timber.d(e, "$namespace: fetch threw for $key")
            null
        }
        val parsed = body?.let(parse)
        val now = nowMillis()
        if (parsed != null) {
            remember(key, parsed, now)
            persistentCache?.put(key, FetchBackoff.recordHit(body, now))
            return parsed
        }
        persistentCache?.let { cache ->
            val miss = FetchBackoff.recordMiss(previous, now)
            cache.put(key, miss)
            Timber.d(
                "$namespace: recorded miss #${miss.attempts}, next retry in " +
                    "${(miss.nextRetryAtMillis - now) / 1000}s for $key",
            )
        }
        return previous?.body?.let(parse)?.also { remember(key, it, now) }
    }

    private suspend fun remember(key: String, value: T, now: Long) {
        mutex.withLock { memory[key] = MemoryEntry(value, now + memoryTtlMillis) }
    }

    /**
     * Stale-while-revalidate. Runs on [revalidateScope] so the caller's
     * result is not delayed. [fetchBody] is responsible for its own
     * dispatcher (the fetchers wrap the network in `Dispatchers.IO`), so this
     * launches on the scope as given - which is also what lets a test drive
     * it with a test scheduler. A failure here records a MISS like any other,
     * which carries the stale body forward, so a flaky refresh never removes
     * data the UI already had.
     */
    private suspend fun revalidateInBackground(
        key: String,
        previous: FetchCacheEntry,
        fetchBody: suspend () -> String?,
    ) {
        val scope = revalidateScope ?: return
        val claimed = mutex.withLock { revalidating.add(key) }
        if (!claimed) return
        scope.launch {
            try {
                Timber.d("$namespace: revalidating stale entry for $key")
                fetchAndRemember(key, previous, fetchBody)
            } catch (e: Exception) {
                Timber.w(e, "$namespace: background revalidation failed for $key")
            } finally {
                mutex.withLock { revalidating.remove(key) }
            }
        }
    }
}
