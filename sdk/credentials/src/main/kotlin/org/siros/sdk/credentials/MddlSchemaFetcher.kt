// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.net.URI

/**
 * Fetches MDDL (mso_mdoc) schema documents from credential issuers - the
 * mdoc analogue of [VctmFetcher].
 *
 * Supports two resolution strategies, tried in order:
 * 1. go-wallet-backend's credential-type registry service:
 *    `<registryUrl>/type-metadata?vct=<doctype>` (TS11-backed, cached - the
 *    authoritative source; same `vct` query param name used for VCT lookups
 *    too - the backend's single handler/store is format-blind and uses one
 *    generic param name for both, a historical naming artifact rather than a
 *    bug). Only usable when both `registryUrl` and the doctype are known.
 * 2. Issuer-hosted type metadata endpoint: `<issuer>/type-metadata/<scope>`
 *    (confirmed format-blind server-side: this relay has no
 *    format/`mso_mdoc` branching, so it serves whatever document shape it's
 *    given unchanged).
 *
 * The final result of [fetch] - whichever strategy produced it - is cached
 * in-memory per instance for [cacheTtlSeconds] (default 1800s / 30 minutes,
 * matching the reference wallet-frontend implementation's IndexedDB-backed
 * HTTP cache default). Since [MddlSchemaFetcher] is normally constructed once
 * and held for the lifetime of a wallet session, this cache meaningfully cuts
 * down repeat network calls for the same doctype.
 *
 * Optionally, a [persistentCache] adds a second layer that survives process
 * restarts and remembers *failures* too - a doctype with no published schema
 * is retried on [FetchBackoff]'s schedule rather than on every launch, and
 * [fetch] returns null immediately (no network) while a retry is not yet due.
 * See [CachedDocumentFetcher] for the exact semantics; identical to
 * [VctmFetcher]'s on purpose. Without a persistent cache, a miss across all
 * strategies is retried fresh on every call, as before.
 *
 * @param httpGet optional HTTP GET function for custom HTTP clients.
 *        Takes a URL string, returns the response body string or null on failure.
 *        When null, uses `java.net.HttpURLConnection`.
 * @param cacheTtlSeconds how long a successful [fetch] result stays in the
 *        in-memory cache, in seconds.
 * @param nowMillis time source used for cache expiry, defaulting to the wall clock.
 *        Overridable for deterministic tests.
 * @param persistentCache optional durable cache of positive and negative
 *        results; null (the default) keeps the in-memory-only behaviour.
 * @param persistentFreshTtlSeconds age under which a persisted hit is served
 *        without any refresh (default 24 h).
 * @param persistentHardTtlSeconds age past which a persisted hit is refetched
 *        inline rather than served (default 7 d).
 * @param revalidateScope scope on which a stale-but-not-expired persisted hit
 *        is refreshed in the background; null disables background refresh.
 */
class MddlSchemaFetcher(
    private val httpGet: (suspend (String) -> String?)? = null,
    private val cacheTtlSeconds: Long = 1800,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
    persistentCache: FetchCache? = null,
    persistentFreshTtlSeconds: Long = 24 * 60 * 60,
    persistentHardTtlSeconds: Long = 7 * 24 * 60 * 60,
    revalidateScope: CoroutineScope? = null,
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val cached = CachedDocumentFetcher(
        namespace = "mddl",
        parse = ::parseMddlSchema,
        memoryTtlMillis = cacheTtlSeconds * 1000,
        persistentCache = persistentCache,
        freshTtlMillis = persistentFreshTtlSeconds * 1000,
        hardTtlMillis = persistentHardTtlSeconds * 1000,
        revalidateScope = revalidateScope,
        nowMillis = nowMillis,
    )

    /**
     * Fetch the MDDL schema for a credential configuration.
     *
     * Tries go-wallet-backend's registry service first (authoritative,
     * TS11-backed, cached - see [registryUrl]), then falls back to the
     * issuer's own type-metadata endpoint. Results are cached in-memory for
     * [cacheTtlSeconds] and, when a persistent cache was supplied, durably
     * with negative caching; see the class docs for details.
     *
     * @param issuerUrl the credential issuer URL (e.g. "https://issuer.example.com")
     * @param scope the credential configuration ID / scope
     * @param vct optional mdoc doctype identifier (e.g. "org.iso.18013.5.1.mDL")
     *        used for registry lookup. Named `vct` to match the query param the
     *        registry service actually uses for both SD-JWT VC and mdoc lookups.
     * @param registryUrl optional base URL for go-wallet-backend's credential-type
     *        registry service (e.g. `"https://wallet.example.com/registry"`). When
     *        non-null and [vct] is also known, queried as
     *        `<registryUrl>/type-metadata?vct=<vct>` before the issuer-direct
     *        strategy. When null, or when [vct] isn't known yet at this call
     *        site, this strategy is skipped and resolution falls through to the
     *        existing issuer-direct strategy.
     * @return the parsed [MddlSchema], or null if not available
     */
    suspend fun fetch(
        issuerUrl: String,
        scope: String,
        vct: String? = null,
        registryUrl: String? = null,
    ): MddlSchema? = cached.fetch(listOf(issuerUrl, scope, vct, registryUrl)) {
        // Only the network hop needs IO - see VctmFetcher.fetch for why.
        withContext(Dispatchers.IO) { fetchUncached(issuerUrl, scope, vct, registryUrl) }
    }

    /**
     * Run the resolution strategies in order and return the raw body of the
     * first one that yields a parseable schema - raw rather than parsed so
     * the persistent cache can store exactly what came over the wire.
     */
    private suspend fun fetchUncached(
        issuerUrl: String,
        scope: String,
        vct: String?,
        registryUrl: String?,
    ): String? {
        // Strategy 1: go-wallet-backend's credential-type registry service.
        if (registryUrl != null && vct != null) {
            val encodedVct = java.net.URLEncoder.encode(vct, "UTF-8")
            val registryLookupUrl = "${registryUrl.trimEnd('/')}/type-metadata?vct=$encodedVct"
            fetchFromUrl(registryLookupUrl)?.let { return it }
        }

        // Strategy 2: issuer-hosted type-metadata endpoint
        val baseUrl = issuerUrl.trimEnd('/')
        val typeMetadataUrl = "$baseUrl/type-metadata/$scope"
        return fetchFromUrl(typeMetadataUrl).also {
            if (it == null) Timber.d("No MDDL schema found for scope=$scope vct=$vct")
        }
    }

    /** Parse an MDDL schema from raw JSON, e.g. if embedded in an issuer metadata response. */
    fun parseMddlSchema(jsonString: String): MddlSchema? {
        return try {
            json.decodeFromString(MddlSchema.serializer(), jsonString)
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse MDDL schema JSON")
            null
        }
    }

    /** GET [url] and return its body only if that body parses as an MDDL schema. */
    private suspend fun fetchFromUrl(url: String): String? {
        return try {
            Timber.d("Fetching MDDL schema from $url")
            val body = if (httpGet != null) httpGet.invoke(url) else fetchWithUrlConnection(url)
            body?.takeIf { parseMddlSchema(it) != null }
        } catch (e: Exception) {
            Timber.d(e, "MDDL schema fetch error from $url")
            null
        }
    }

    private fun fetchWithUrlConnection(url: String): String? {
        val connection = URI(url).toURL().openConnection() as java.net.HttpURLConnection
        connection.requestMethod = "GET"
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        return try {
            if (connection.responseCode != 200) {
                Timber.d("MDDL schema fetch failed: ${connection.responseCode} from $url")
                null
            } else {
                connection.inputStream.bufferedReader().use { it.readText() }
            }
        } finally {
            connection.disconnect()
        }
    }
}
