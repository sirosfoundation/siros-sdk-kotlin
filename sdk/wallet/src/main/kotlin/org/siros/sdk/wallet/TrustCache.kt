package org.siros.sdk.wallet

import java.time.Instant

/**
 * In-memory cache for trust evaluation results.
 *
 * Provides resilience when the backend is temporarily unreachable by serving
 * cached positive trust results for previously-evaluated verifiers.
 *
 * Security invariants:
 * - Only positive (trusted=true) results are cached (never cache denials)
 * - TTL-based expiry prevents stale trust data
 * - Cache is keyed by full client_id (scheme + identifier)
 */
class TrustCache(
    /** Time-to-live for cache entries (default 1 hour). */
    private val ttl: java.time.Duration = java.time.Duration.ofHours(1),
    /** Maximum number of entries (LRU eviction). */
    private val maxSize: Int = 100,
) {
    private data class Entry(
        val result: TrustResult,
        val cachedAt: Instant,
    )

    private val entries = LinkedHashMap<String, Entry>(maxSize, 0.75f, true)

    /**
     * Store a trust result in the cache.
     * Only trusted=true results are cached (security: never cache denials).
     */
    fun put(identifier: String, result: TrustResult) {
        if (!result.trusted) return // Never cache negative results
        if (identifier.isBlank()) return

        synchronized(entries) {
            entries[identifier] = Entry(result = result, cachedAt = Instant.now())
            // LRU eviction
            while (entries.size > maxSize) {
                val eldest = entries.entries.iterator().next()
                entries.remove(eldest.key)
            }
        }
    }

    /**
     * Retrieve a cached trust result for the given identifier.
     * Returns null if no entry exists or the entry has expired.
     */
    fun get(identifier: String): TrustResult? {
        if (identifier.isBlank()) return null

        synchronized(entries) {
            val entry = entries[identifier] ?: return null
            if (Instant.now().isAfter(entry.cachedAt.plus(ttl))) {
                entries.remove(identifier)
                return null // Expired
            }
            return entry.result
        }
    }

    /** Clear all cached entries. */
    fun clear() {
        synchronized(entries) {
            entries.clear()
        }
    }

    /** Number of cached entries. */
    val size: Int get() = synchronized(entries) { entries.size }
}
