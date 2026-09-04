// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.net.URI

/**
 * Fetches VCTM (Verifiable Credential Type Metadata) from credential issuers.
 *
 * Supports three resolution strategies, tried in order:
 * 1. go-wallet-backend's credential-type registry service: `<registryUrl>/type-metadata?vct=<vct>`
 *    (TS11-backed, cached - the authoritative source, and the same service
 *    the reference wallet-frontend implementation always queries via its
 *    `VCT_REGISTRY_URL` config value; only usable when both [WalletConfig]'s
 *    `registryUrl` and the `vct` identifier are already known at call time)
 * 2. Type metadata endpoint: `<issuer>/type-metadata/<scope>` (issuer-hosted, e.g. the SIROS apigw)
 * 3. Well-known path: `<issuer>/.well-known/vct/<vct-id>`
 *
 * The final result of [fetch] - whichever strategy produced it - is cached
 * in-memory per instance for [cacheTtlSeconds] (default 1800s / 30 minutes,
 * matching the reference wallet-frontend implementation's IndexedDB-backed
 * HTTP cache default). Since [VctmFetcher] is normally constructed once and
 * held for the lifetime of a wallet session, this cache meaningfully cuts
 * down repeat network calls for the same credential type (e.g. re-issuance,
 * or re-hydrating multiple stored credentials of the same type).
 *
 * Optionally, a [persistentCache] adds a second layer that survives process
 * restarts and remembers *failures* too: a type with no published metadata
 * is not re-asked for on every launch but on [FetchBackoff]'s schedule, and
 * [fetch] returns null immediately (no network, no waiting) while a retry is
 * not yet due. See [CachedDocumentFetcher] for the exact semantics. Without
 * a persistent cache, a miss across all strategies is retried fresh on every
 * call, as before.
 *
 * SDK consumers can also parse VCTM from raw JSON using [parseVctm].
 *
 * @param httpGet optional HTTP GET function for custom HTTP clients.
 *        Takes a URL string, returns the response body string or null on failure.
 *        When null, uses `java.net.HttpURLConnection`.
 * @param cacheTtlSeconds how long a successful [fetch] result stays in the
 *        in-memory cache, in seconds.
 * @param nowMillis time source used for cache expiry, defaulting to the wall clock.
 *        Overridable for deterministic tests.
 * @param persistentCache optional on-disk (or otherwise durable) cache of
 *        positive and negative results; null (the default) keeps the
 *        in-memory-only behaviour.
 * @param persistentFreshTtlSeconds age under which a persisted hit is served
 *        without any refresh (default 24 h).
 * @param persistentHardTtlSeconds age past which a persisted hit is refetched
 *        inline rather than served (default 7 d).
 * @param revalidateScope scope on which a stale-but-not-expired persisted hit
 *        is refreshed in the background; null disables background refresh
 *        (stale hits are then served as-is until the hard TTL).
 */
class VctmFetcher(
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
        namespace = "vctm",
        parse = ::parseVctmDocument,
        memoryTtlMillis = cacheTtlSeconds * 1000,
        persistentCache = persistentCache,
        freshTtlMillis = persistentFreshTtlSeconds * 1000,
        hardTtlMillis = persistentHardTtlSeconds * 1000,
        revalidateScope = revalidateScope,
        nowMillis = nowMillis,
    )

    /**
     * Fetch VCTM for a credential configuration.
     *
     * Tries go-wallet-backend's registry service first (authoritative,
     * TS11-backed, cached - see [registryUrl]), then the issuer's own
     * type-metadata endpoint (used by the SIROS apigw), then falls back to
     * the well-known VCT resolution path. Results are cached in-memory for
     * [cacheTtlSeconds] and, when a persistent cache was supplied, on disk
     * with negative caching; see the class docs for details.
     *
     * @param issuerUrl the credential issuer URL (e.g. "https://issuer.example.com")
     * @param scope the credential configuration ID / scope
     * @param vct optional VCT identifier for well-known resolution and registry lookup
     * @param registryUrl optional base URL for go-wallet-backend's credential-type
     *        registry service (e.g. `"https://wallet.example.com/registry"`). When
     *        non-null and [vct] is also known, queried as
     *        `<registryUrl>/type-metadata?vct=<vct>` before the other strategies.
     *        When null, or when [vct] isn't known yet at this call site, this
     *        strategy is skipped and resolution falls through to the existing
     *        issuer-direct strategies (same behavior as the well-known strategy
     *        when [vct] is null).
     * @return the parsed [Vctm], or null if not available
     */
    suspend fun fetch(
        issuerUrl: String,
        scope: String,
        vct: String? = null,
        registryUrl: String? = null,
    ): Vctm? = fetchDocument(issuerUrl, scope, vct, registryUrl)?.vctm

    /**
     * The parsed VCTM together with the exact bytes it was parsed from.
     *
     * The raw document is what an integrity digest is computed over, so a
     * caller checking `vct#integrity` needs it rather than a re-serialisation
     * of the parsed form - which would differ in key order and whitespace and
     * hash to something else entirely.
     */
    suspend fun fetchDocument(
        issuerUrl: String,
        scope: String,
        vct: String? = null,
        registryUrl: String? = null,
    ): VctmDocument? = cached.fetch(listOf(issuerUrl, scope, vct, registryUrl)) {
        // Only the network hop needs IO; cache reads that answer without it
        // (the common case after the first launch) stay on the caller's
        // dispatcher, and a background revalidation launched by the cache
        // layer picks up IO here too rather than needing its own.
        withContext(Dispatchers.IO) { fetchUncached(issuerUrl, scope, vct, registryUrl) }
    }

    /**
     * Run the resolution strategies in order and return the raw body of the
     * first one that yields a parseable VCTM - raw rather than parsed so the
     * persistent cache can store exactly what came over the wire.
     */
    private suspend fun fetchUncached(
        issuerUrl: String,
        scope: String,
        vct: String?,
        registryUrl: String?,
    ): String? {
        // Strategy 1: go-wallet-backend's credential-type registry service
        // (authoritative, TS11-backed, cached - matches wallet-frontend's
        // reference behavior of always querying VCT_REGISTRY_URL first).
        if (registryUrl != null && vct != null) {
            val encodedVct = java.net.URLEncoder.encode(vct, "UTF-8")
            val registryLookupUrl = "${registryUrl.trimEnd('/')}/type-metadata?vct=$encodedVct"
            fetchFromUrl(registryLookupUrl)?.let { return it }
        }

        // Strategy 2: issuer-hosted type-metadata endpoint
        val baseUrl = issuerUrl.trimEnd('/')
        val typeMetadataUrl = "$baseUrl/type-metadata/$scope"
        fetchFromUrl(typeMetadataUrl)?.let { return it }

        // Strategy 3: well-known VCT resolution
        if (vct != null) {
            val wellKnownUrl = resolveWellKnownUrl(vct)
            if (wellKnownUrl != null) {
                fetchFromUrl(wellKnownUrl)?.let { return it }
            }
        }

        Timber.d("No VCTM found for scope=$scope vct=$vct")
        return null
    }

    /**
     * Parse a VCTM from raw JSON string.
     *
     * Useful when the VCTM is embedded in the issuer metadata response
     * or available from a local file.
     */
    private fun parseVctmDocument(jsonString: String): VctmDocument? =
        parseVctm(jsonString)?.let { VctmDocument(raw = jsonString, vctm = it) }

    fun parseVctm(jsonString: String): Vctm? {
        return try {
            json.decodeFromString(Vctm.serializer(), jsonString)
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse VCTM JSON")
            null
        }
    }

    /** GET [url] and return its body only if that body parses as a VCTM. */
    private suspend fun fetchFromUrl(url: String): String? {
        return try {
            Timber.d("Fetching VCTM from $url")
            val body = if (httpGet != null) {
                httpGet.invoke(url)
            } else {
                fetchWithUrlConnection(url)
            }
            body?.takeIf { parseVctm(it) != null }
        } catch (e: Exception) {
            Timber.d(e, "VCTM fetch error from $url")
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
                Timber.d("VCTM fetch failed: ${connection.responseCode} from $url")
                null
            } else {
                connection.inputStream.bufferedReader().use { it.readText() }
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun resolveWellKnownUrl(vct: String): String? {
        return try {
            val uri = URI(vct)
            if (uri.scheme !in listOf("http", "https")) return null
            val path = uri.path?.trimStart('/') ?: return null
            "${uri.scheme}://${uri.authority}/.well-known/vct/$path"
        } catch (_: Exception) {
            null
        }
    }
}
