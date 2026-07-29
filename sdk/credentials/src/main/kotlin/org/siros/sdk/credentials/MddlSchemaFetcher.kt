// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.net.URI

/**
 * Fetches MDDL (mso_mdoc) schema documents from credential issuers - the
 * mdoc analogue of [VctmFetcher], against the same `/type-metadata/<scope>`
 * relay (confirmed format-blind server-side: `go-wallet-backend`'s registry
 * relay has no format/`mso_mdoc` branching, so it serves whatever document
 * shape it's given unchanged - same mechanism, no new backend endpoint).
 *
 * @param httpGet optional HTTP GET function for custom HTTP clients.
 *        Takes a URL string, returns the response body string or null on failure.
 *        When null, uses `java.net.HttpURLConnection`.
 */
class MddlSchemaFetcher(
    private val httpGet: (suspend (String) -> String?)? = null,
) {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Fetch the MDDL schema for a credential configuration.
     *
     * @param issuerUrl the credential issuer URL (e.g. "https://issuer.example.com")
     * @param scope the credential configuration ID / scope
     * @return the parsed [MddlSchema], or null if not available
     */
    suspend fun fetch(issuerUrl: String, scope: String): MddlSchema? = withContext(Dispatchers.IO) {
        val baseUrl = issuerUrl.trimEnd('/')
        val typeMetadataUrl = "$baseUrl/type-metadata/$scope"
        fetchFromUrl(typeMetadataUrl).also {
            if (it == null) Timber.d("No MDDL schema found for scope=$scope")
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

    private suspend fun fetchFromUrl(url: String): MddlSchema? {
        return try {
            Timber.d("Fetching MDDL schema from $url")
            val body = if (httpGet != null) httpGet.invoke(url) else fetchWithUrlConnection(url)
            if (body != null) parseMddlSchema(body) else null
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
