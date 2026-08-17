// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import okhttp3.OkHttpClient
import okhttp3.Request
import timber.log.Timber
import java.security.MessageDigest

/**
 * A single format-specific verification record recorded against a circuit's
 * [ZkSource], mirroring `catalog.VerificationRecord` in
 * `go-zk-circuits/pkg/catalog/types.go` field-for-field. Written exclusively
 * by that service's own tooling (`circuitctl verify-interop`) - never
 * hand-edited, and not itself a trust decision, just descriptive metadata.
 */
@Serializable
data class ZkVerificationRecord(
    val tool: String = "",
    val toolVersion: String = "",
    val verifierIdentity: String = "",
    val date: String = "",
    val result: String = "",
    val notes: String? = null,
)

/**
 * Provenance for a [ZkCircuitDescriptor], mirroring `catalog.Source` in
 * `go-zk-circuits/pkg/catalog/types.go`.
 */
@Serializable
data class ZkSource(
    val origin: String = "",
    val originRef: String? = null,
    val originPath: String? = null,
    val toolchain: String? = null,
    val license: String? = null,
    val openSource: Boolean = false,
    val addedBy: String = "",
    val verifiedBy: List<ZkVerificationRecord> = emptyList(),
)

/**
 * The decompressed-form hash/size of a [ZkArtifact], present when
 * [ZkArtifact.compression] is not `"none"`. Mirrors `catalog.Uncompressed`.
 */
@Serializable
data class ZkUncompressed(
    val hash: String = "",
    val size: Long = 0,
)

/**
 * Describes the downloadable bytes for a circuit, mirroring `catalog.Artifact`
 * in `go-zk-circuits/pkg/catalog/types.go`.
 *
 * NOTE on [url]: in the real deployed service this is a *relative* path (e.g.
 * `/v1/artifacts/sha256/<hex>`, set by `pkg/publish/add.go`'s
 * `entry.Artifact.URL = "/v1/" + catalog.ArtifactFilePath(...)`), not an
 * absolute URL - [ZkCircuitClient.downloadArtifact] resolves it against each
 * configured mirror accordingly. See that method's doc comment.
 *
 * [hash] is over the bytes AS SERVED (compressed, if [compression] != "none");
 * [uncompressed]'s hash is over the decompressed bytes. Neither is the same
 * as the proof system's own circuit identifier that may appear inside
 * [ZkCircuitDescriptor.params].
 */
@Serializable
data class ZkArtifact(
    val url: String = "",
    val hash: String = "",
    val size: Long = 0,
    val compression: String = "",
    val mediaType: String = "",
    val uncompressed: ZkUncompressed? = null,
)

/**
 * One catalog entry - the body of `GET /v1/circuits/{id}.json` and one
 * element of [ZkManifest.circuits] - mirroring `catalog.CircuitDescriptor`
 * in `go-zk-circuits/pkg/catalog/types.go` field-for-field.
 */
@Serializable
data class ZkCircuitDescriptor(
    val id: String,
    val aliases: List<String> = emptyList(),
    val system: String = "",
    val systemVersion: String = "",
    val docTypes: List<String> = emptyList(),
    val published: Boolean = false,
    val status: String = "",
    val params: JsonObject = JsonObject(emptyMap()),
    val artifact: ZkArtifact? = null,
    val source: ZkSource? = null,
    val publishedAt: String = "",
    val deprecatedAt: String? = null,
    val notes: String? = null,
)

/**
 * The top-level document served at `GET /v1/manifest.json`, mirroring
 * `catalog.Manifest` in `go-zk-circuits/pkg/catalog/types.go`.
 */
@Serializable
data class ZkManifest(
    val manifestVersion: Int = 1,
    val generatedAt: String = "",
    val catalog: String = "",
    val circuits: List<ZkCircuitDescriptor> = emptyList(),
    val next: String? = null,
)

/**
 * Thrown by [ZkCircuitClient.downloadArtifact] when no configured source (or
 * URL candidate) produced hash-verified artifact bytes - either every fetch
 * attempt failed outright, or the downloaded bytes' SHA-256 digest never
 * matched [ZkArtifact.hash]. Per the service's own API contract, hash
 * verification is the client's responsibility, not something the server
 * guarantees for you - this exception is how that responsibility is enforced.
 */
class ZkArtifactException(message: String) : Exception(message)

/**
 * Client for the go-zk-circuits catalog REST API - the real, deployed
 * read-only service for discovering/downloading ZK-proof circuit artifacts
 * for the Longfellow-ZKP-pseudonym feature (`https://zk-circuits.fly.dev`
 * today, moving to `https://api.circuits.siros.org` once DNS is live - NOT
 * the bare `circuits.siros.org` human-facing website).
 *
 * DELIBERATELY DIFFERENT fallback semantics than [Ts11RegistryClient]: that
 * class's `sources` are *distinct* registries whose entries are merged
 * together. This class's [sources] are *mirrors of the same catalog* - the
 * literal same service, reachable at a different hostname (e.g. a CDN
 * fallback, or the pre-DNS Fly.io URL alongside the eventual
 * `api.circuits.siros.org` one) - so every method here tries each source **in
 * list order** and returns the first one that succeeds, without ever merging
 * results across sources.
 *
 * @param sources mirror base URLs, tried in order until one succeeds.
 *        Defaults to a single entry, [DEFAULT_ZK_CIRCUIT_URL].
 * @param httpGet optional injectable text-fetch function (URL -> response
 *        body string, or null on failure/non-2xx), for tests. When null, a
 *        real OkHttp-backed implementation is used.
 * @param httpGetBytes optional injectable byte-fetch function (URL -> raw
 *        response bytes, or null on failure/non-2xx), for tests (e.g.
 *        artifact downloads). When null, a real OkHttp-backed implementation
 *        is used.
 * @param httpClient the [OkHttpClient] backing the default (non-injected)
 *        fetch implementations. OkHttp follows redirects by default, which
 *        is required for `GET /v1/circuits/{id}.json` when `id` is an alias
 *        (the server responds with a 301 to the canonical id).
 */
class ZkCircuitClient(
    private val sources: List<String> = listOf(DEFAULT_ZK_CIRCUIT_URL),
    private val httpGet: (suspend (String) -> String?)? = null,
    private val httpGetBytes: (suspend (String) -> ByteArray?)? = null,
    private val httpClient: OkHttpClient = OkHttpClient(),
) {
    private val json = Json { ignoreUnknownKeys = true }

    companion object {
        /** Default zk-circuits catalog base URL (pre-DNS Fly.io deployment). */
        const val DEFAULT_ZK_CIRCUIT_URL = "https://zk-circuits.fly.dev"
    }

    /**
     * `GET /v1/manifest.json` - the full circuit catalog, from the first
     * [sources] entry that serves a parseable manifest (see class docs for
     * the ordered-fallback, non-merging semantics). Returns null if every
     * source failed (network error, non-2xx, or malformed JSON).
     */
    suspend fun fetchManifest(): ZkManifest? = withContext(Dispatchers.IO) {
        for (source in sources) {
            val url = manifestUrl(source)
            val body = fetchRaw(url) ?: continue
            try {
                return@withContext json.decodeFromString(ZkManifest.serializer(), body)
            } catch (e: Exception) {
                Timber.w(e, "Failed to parse zk-circuit manifest from $url")
            }
        }
        if (sources.isNotEmpty()) {
            Timber.w("All ${sources.size} zk-circuit source(s) failed to yield a manifest")
        }
        null
    }

    /**
     * `GET /v1/circuits/{id}.json` - a single circuit descriptor, from the
     * first [sources] entry that serves one, by canonical id or alias (an
     * alias 301-redirects to the canonical id server-side; the default
     * OkHttp-backed fetch follows redirects automatically). Returns null if
     * every source failed.
     */
    suspend fun fetchCircuit(id: String): ZkCircuitDescriptor? = withContext(Dispatchers.IO) {
        for (source in sources) {
            val url = circuitUrl(source, id)
            val body = fetchRaw(url) ?: continue
            try {
                return@withContext json.decodeFromString(ZkCircuitDescriptor.serializer(), body)
            } catch (e: Exception) {
                Timber.w(e, "Failed to parse zk-circuit descriptor '$id' from $url")
            }
        }
        if (sources.isNotEmpty()) {
            Timber.w("All ${sources.size} zk-circuit source(s) failed to yield circuit '$id'")
        }
        null
    }

    /**
     * Downloads a circuit's artifact bytes and verifies their SHA-256 digest
     * against [ZkArtifact.hash] before returning them - the API's docs are
     * explicit that this verification is the client's responsibility, never
     * assumed from a successful HTTP fetch alone.
     *
     * Builds an ordered list of URL candidates and tries each in turn (first
     * hash-verified success wins):
     * - if [ZkArtifact.url] is already an absolute URL, it is the only
     *   candidate (it already pins its own host, so there is nothing to
     *   mirror-fallback across);
     * - otherwise (the real service's current behavior - see [ZkArtifact.url]'s
     *   doc comment) it is a relative path, resolved against every configured
     *   [sources] mirror in order;
     * - if [ZkArtifact.url] is blank, the path is instead constructed from
     *   [ZkArtifact.hash] as `v1/artifacts/{alg}/{hex}` (`sha256` is the only
     *   algorithm the service supports today), again resolved against every
     *   mirror.
     *
     * @throws ZkArtifactException if [descriptor] has no [ZkCircuitDescriptor.artifact],
     *   or if every URL candidate either failed to fetch or failed hash
     *   verification.
     */
    suspend fun downloadArtifact(descriptor: ZkCircuitDescriptor): ByteArray = withContext(Dispatchers.IO) {
        val artifact = descriptor.artifact
            ?: throw ZkArtifactException("Circuit '${descriptor.id}' has no artifact")

        var lastFailure: String? = null
        for (url in candidateArtifactUrls(artifact)) {
            val bytes = fetchBytes(url)
            if (bytes == null) {
                lastFailure = "fetch failed from $url"
                continue
            }
            val actualHash = sha256Hex(bytes)
            if (!actualHash.equals(bareHex(artifact.hash), ignoreCase = true)) {
                Timber.w(
                    "zk-circuit artifact hash mismatch for '${descriptor.id}' from $url: " +
                        "expected ${artifact.hash}, got $actualHash",
                )
                lastFailure = "hash mismatch from $url"
                continue
            }
            return@withContext bytes
        }
        throw ZkArtifactException(
            "Failed to download a hash-verified artifact for circuit '${descriptor.id}' " +
                "from any of ${sources.size} source(s)" + (lastFailure?.let { " (last: $it)" } ?: ""),
        )
    }

    private fun manifestUrl(source: String): String = "${source.trimEnd('/')}/v1/manifest.json"

    private fun circuitUrl(source: String, id: String): String = "${source.trimEnd('/')}/v1/circuits/$id.json"

    /** See [downloadArtifact]'s doc comment for the resolution rules this implements. */
    private fun candidateArtifactUrls(artifact: ZkArtifact): List<String> {
        val url = artifact.url
        if (url.startsWith("http://") || url.startsWith("https://")) {
            return listOf(url)
        }
        val path = if (url.isNotBlank()) url.removePrefix("/") else "v1/artifacts/sha256/${bareHex(artifact.hash)}"
        return sources.map { "${it.trimEnd('/')}/$path" }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /**
     * [ZkArtifact.hash]/[ZkUncompressed.hash] are wire-formatted as
     * `"sha256:<hex>"` (matching go-zk-circuits' own hash field convention),
     * but [sha256Hex] returns a bare hex digest with no prefix - comparing
     * the two directly without stripping this prefix always failed, even
     * for a byte-for-byte-correct download (confirmed live: "expected
     * sha256:44c4b98..., got 44c4b98..." - the same digest, just one side
     * prefixed). Strips it if present; leaves the string as-is otherwise, so
     * a legacy unprefixed hash value would still compare correctly too.
     */
    private fun bareHex(hash: String): String = hash.removePrefix("sha256:")

    private suspend fun fetchRaw(url: String): String? {
        return try {
            if (httpGet != null) httpGet.invoke(url) else fetchTextWithOkHttp(url)
        } catch (e: Exception) {
            Timber.w(e, "zk-circuit fetch error from $url")
            null
        }
    }

    private suspend fun fetchBytes(url: String): ByteArray? {
        return try {
            if (httpGetBytes != null) httpGetBytes.invoke(url) else fetchBytesWithOkHttp(url)
        } catch (e: Exception) {
            Timber.w(e, "zk-circuit artifact fetch error from $url")
            null
        }
    }

    private fun fetchTextWithOkHttp(url: String): String? {
        val request = Request.Builder().url(url).get().build()
        httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                Timber.w("zk-circuit fetch failed: ${response.code} from $url")
                return null
            }
            return response.body?.string()
        }
    }

    private fun fetchBytesWithOkHttp(url: String): ByteArray? {
        val request = Request.Builder().url(url).get().build()
        httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                Timber.w("zk-circuit artifact fetch failed: ${response.code} from $url")
                return null
            }
            return response.body?.bytes()
        }
    }
}
