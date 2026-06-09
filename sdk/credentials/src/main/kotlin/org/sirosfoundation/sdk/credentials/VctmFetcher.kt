// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.credentials

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.net.URI

/**
 * Fetches VCTM (Verifiable Credential Type Metadata) from credential issuers.
 *
 * Supports two resolution strategies:
 * 1. Well-known path: `<issuer>/.well-known/vct/<vct-id>`
 * 2. Type metadata endpoint: `<issuer>/type-metadata/<scope>`
 *
 * SDK consumers can also parse VCTM from raw JSON using [parseVctm].
 *
 * @param httpGet optional HTTP GET function for custom HTTP clients.
 *        Takes a URL string, returns the response body string or null on failure.
 *        When null, uses `java.net.HttpURLConnection`.
 */
class VctmFetcher(
    private val httpGet: (suspend (String) -> String?)? = null,
) {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Fetch VCTM for a credential configuration.
     *
     * Tries the type-metadata endpoint first (used by the SIROS apigw),
     * then falls back to the well-known VCT resolution path.
     *
     * @param issuerUrl the credential issuer URL (e.g. "https://issuer.example.com")
     * @param scope the credential configuration ID / scope
     * @param vct optional VCT identifier for well-known resolution
     * @return the parsed [Vctm], or null if not available
     */
    suspend fun fetch(
        issuerUrl: String,
        scope: String,
        vct: String? = null,
    ): Vctm? = withContext(Dispatchers.IO) {
        // Strategy 1: type-metadata endpoint
        val baseUrl = issuerUrl.trimEnd('/')
        val typeMetadataUrl = "$baseUrl/type-metadata/$scope"
        fetchFromUrl(typeMetadataUrl)?.let { return@withContext it }

        // Strategy 2: well-known VCT resolution
        if (vct != null) {
            val wellKnownUrl = resolveWellKnownUrl(vct)
            if (wellKnownUrl != null) {
                fetchFromUrl(wellKnownUrl)?.let { return@withContext it }
            }
        }

        Timber.d("No VCTM found for scope=$scope vct=$vct")
        null
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
