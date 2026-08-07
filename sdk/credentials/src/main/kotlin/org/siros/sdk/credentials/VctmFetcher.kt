// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
 * HTTP cache default). Only successful (non-null) results are cached; a miss
 * across all strategies is retried fresh on every call so a transient failure
 * or a not-yet-registered type never gets stuck negative for the TTL window.
 * Since [VctmFetcher] is normally constructed once and held for the lifetime
 * of a wallet session, this cache meaningfully cuts down repeat network calls
 * for the same credential type (e.g. re-issuance, or re-hydrating multiple
 * stored credentials of the same type).
 *
 * SDK consumers can also parse VCTM from raw JSON using [parseVctm].
 *
 * @param httpGet optional HTTP GET function for custom HTTP clients.
 *        Takes a URL string, returns the response body string or null on failure.
 *        When null, uses `java.net.HttpURLConnection`.
 * @param cacheTtlSeconds how long a successful [fetch] result stays cached, in seconds.
 * @param nowMillis time source used for cache expiry, defaulting to the wall clock.
 *        Overridable for deterministic tests.
 */
class VctmFetcher(
    private val httpGet: (suspend (String) -> String?)? = null,
    private val cacheTtlSeconds: Long = 1800,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
) {
    private val json = Json { ignoreUnknownKeys = true }

    private data class CacheKey(
        val issuerUrl: String,
        val scope: String,
        val vct: String?,
        val registryUrl: String?,
    )

    private data class CacheEntry(val vctm: Vctm, val expiresAtMillis: Long)

    private val cacheMutex = Mutex()
    private val cache = mutableMapOf<CacheKey, CacheEntry>()

    /**
     * Fetch VCTM for a credential configuration.
     *
     * Tries go-wallet-backend's registry service first (authoritative,
     * TS11-backed, cached - see [registryUrl]), then the issuer's own
     * type-metadata endpoint (used by the SIROS apigw), then falls back to
     * the well-known VCT resolution path. Successful results are cached
     * in-memory for [cacheTtlSeconds]; see the class docs for details.
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
    ): Vctm? = withContext(Dispatchers.IO) {
        val key = CacheKey(issuerUrl, scope, vct, registryUrl)
        val now = nowMillis()

        cacheMutex.withLock { cache[key] }?.let { entry ->
            if (entry.expiresAtMillis > now) return@withContext entry.vctm
        }

        val result = fetchUncached(issuerUrl, scope, vct, registryUrl)
        if (result != null) {
            cacheMutex.withLock {
                cache[key] = CacheEntry(result, now + cacheTtlSeconds * 1000)
            }
        }
        result
    }

    private suspend fun fetchUncached(
        issuerUrl: String,
        scope: String,
        vct: String?,
        registryUrl: String?,
    ): Vctm? {
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
    fun parseVctm(jsonString: String): Vctm? {
        return try {
            json.decodeFromString(Vctm.serializer(), jsonString)
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse VCTM JSON")
            null
        }
    }

    private suspend fun fetchFromUrl(url: String): Vctm? {
        return try {
            Timber.d("Fetching VCTM from $url")
            val body = if (httpGet != null) {
                httpGet.invoke(url)
            } else {
                fetchWithUrlConnection(url)
            }
            if (body != null) parseVctm(body) else null
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
