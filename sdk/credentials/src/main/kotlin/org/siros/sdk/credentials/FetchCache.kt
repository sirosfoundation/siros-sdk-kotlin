// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

/**
 * Outcome recorded for one cached fetch.
 *
 * A [MISS] is as much a fact worth remembering as a [HIT]: an issuer that
 * published no type metadata yesterday almost certainly still hasn't today,
 * and asking it again on every app launch costs the user a visible spinner
 * for nothing (see [FetchBackoff]).
 */
@Serializable
enum class FetchCacheStatus { HIT, MISS }

/**
 * One entry in a [FetchCache].
 *
 * @property status whether the last attempt produced a document.
 * @property body the raw response body of the most recent SUCCESSFUL fetch.
 *        Kept even on a [FetchCacheStatus.MISS] entry: when a previously
 *        working source goes away (issuer outage, registry redeploy), the
 *        last good document is far better display data than nothing, so
 *        callers may serve it stale rather than degrading to a blank card.
 * @property fetchedAtMillis wall-clock time of the last successful fetch, or
 *        of the last attempt for an entry that has never succeeded.
 * @property attempts consecutive failed attempts since the last success -
 *        drives the backoff schedule. Reset to 0 on success.
 * @property nextRetryAtMillis for a [FetchCacheStatus.MISS], the earliest
 *        wall-clock time at which the network may be tried again. Ignored
 *        for a [FetchCacheStatus.HIT].
 */
@Serializable
data class FetchCacheEntry(
    val status: FetchCacheStatus,
    val body: String? = null,
    val fetchedAtMillis: Long,
    val attempts: Int = 0,
    val nextRetryAtMillis: Long = 0,
)

/**
 * A persistent key/value store for fetch results, positive and negative.
 *
 * Deliberately tiny and free of Android types so it can be implemented on
 * plain files, a database, or a `MutableMap` in a unit test. Implementations
 * MUST be safe for concurrent access and MUST NOT throw into callers on a
 * corrupt or unreadable backing store - a display-metadata cache that can
 * crash a wallet at launch is worse than no cache at all. Log and start empty.
 *
 * Nothing stored through this interface is secret: the values are public
 * issuer metadata documents and the keys are the URLs they were fetched
 * from. Do not put credentials or tokens in here.
 */
interface FetchCache {
    /** The entry recorded under [key], or null if none (or if the store is unreadable). */
    suspend fun get(key: String): FetchCacheEntry?

    /** Record [entry] under [key], replacing any previous entry. */
    suspend fun put(key: String, entry: FetchCacheEntry)
}

/**
 * The one backoff schedule every negative cache in the SDK uses, so a dead
 * issuer endpoint and a dead logo URL are retried on the same rhythm and a
 * reader of one cache's logs can reason about the other's.
 *
 * Exponential from one hour, capped at a week: `1h, 6h, 24h, 7d, 7d, ...`.
 * The first step is an hour rather than minutes because the callers here run
 * on app launch - a user opening the wallet three times in a morning should
 * see the network hit at most once, and a type-metadata document appearing
 * within the hour after issuance is rare enough that waiting for it is not
 * worth a spinner on every launch in between.
 */
object FetchBackoff {
    private const val HOUR_MILLIS = 60L * 60L * 1000L
    private val schedule = longArrayOf(
        1 * HOUR_MILLIS,
        6 * HOUR_MILLIS,
        24 * HOUR_MILLIS,
        7 * 24 * HOUR_MILLIS,
    )

    /** Longest interval the schedule ever produces - the retry ceiling. */
    val maxIntervalMillis: Long get() = schedule.last()

    /**
     * How long to wait after the [attempts]th consecutive failure
     * (1-based: `attempts = 1` is the first failure).
     */
    fun intervalMillis(attempts: Int): Long =
        schedule[(attempts - 1).coerceIn(0, schedule.size - 1)]

    /** Wall-clock time at which the next retry after [attempts] failures is due. */
    fun nextRetryAt(attempts: Int, nowMillis: Long): Long = nowMillis + intervalMillis(attempts)

    /**
     * The [FetchCacheEntry] to record after a failed attempt at [nowMillis],
     * given the entry that was there before (if any). Carries the previous
     * good body forward so callers can serve it stale - see
     * [FetchCacheEntry.body].
     */
    fun recordMiss(previous: FetchCacheEntry?, nowMillis: Long): FetchCacheEntry {
        val attempts = (previous?.attempts ?: 0) + 1
        return FetchCacheEntry(
            status = FetchCacheStatus.MISS,
            body = previous?.body,
            fetchedAtMillis = previous?.takeIf { it.body != null }?.fetchedAtMillis ?: nowMillis,
            attempts = attempts,
            nextRetryAtMillis = nextRetryAt(attempts, nowMillis),
        )
    }

    /** The [FetchCacheEntry] to record after a successful fetch of [body] at [nowMillis]. */
    fun recordHit(body: String, nowMillis: Long): FetchCacheEntry = FetchCacheEntry(
        status = FetchCacheStatus.HIT,
        body = body,
        fetchedAtMillis = nowMillis,
        attempts = 0,
        nextRetryAtMillis = 0,
    )
}

/**
 * Build a deterministic [FetchCache] key from a namespace and the parts that
 * identify one fetch (issuer URL, scope, vct, registry URL, ...).
 *
 * JSON-array encoded rather than joined with a separator: URLs can legally
 * contain any printable character, so no separator is safe, while a JSON
 * array round-trips every part unambiguously - `["a|b", null]` and
 * `["a", "b", null]` can never collide. The [namespace] prefix keeps two
 * fetchers with identical argument tuples (a VCTM and an MDDL lookup for
 * the same issuer/scope) from reading each other's documents.
 */
fun fetchCacheKey(namespace: String, vararg parts: String?): String {
    val array = JsonArray(parts.map { if (it == null) JsonNull else JsonPrimitive(it) })
    return "$namespace:${Json.encodeToString(JsonArray.serializer(), array)}"
}

/**
 * A [FetchCache] that lives only as long as its instance - for tests, and
 * for consumers who want the negative-caching semantics without any disk
 * footprint.
 */
class InMemoryFetchCache : FetchCache {
    private val mutex = Mutex()
    private val entries = mutableMapOf<String, FetchCacheEntry>()

    override suspend fun get(key: String): FetchCacheEntry? = mutex.withLock { entries[key] }

    override suspend fun put(key: String, entry: FetchCacheEntry) {
        mutex.withLock { entries[key] = entry }
    }

    /** Snapshot of everything stored, for assertions. */
    suspend fun snapshot(): Map<String, FetchCacheEntry> = mutex.withLock { entries.toMap() }
}
