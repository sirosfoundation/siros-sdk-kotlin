// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.auth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.sirosfoundation.sdk.credentials.AuthException
import timber.log.Timber

/**
 * Response from the AS token endpoint.
 */
@Serializable
data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("token_type") val tokenType: String,
    @SerialName("expires_in") val expiresIn: Int,
)

/**
 * HTTP client for the new Authorization Server endpoints.
 *
 * Handles passkey login/register flows via `/auth/passkey/` and token
 * requests via `/auth/token`. Uses session cookies for authentication
 * (set by the AS on successful login/register).
 *
 * Mirrors the TypeScript `AuthServerClient` from wallet-frontend PR 177.
 */
class AuthServerClient(
    private val baseUrl: String,
    private val tenantId: String = "default",
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .cookieJar(InMemoryCookieJar())
        .build(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    private val pendingTokenMutex = Mutex()
    private val pendingTokenRequests = mutableMapOf<String, AccessToken>()

    // ---- Passkey Login ----

    /**
     * Begin a passkey login flow.
     *
     * @param oidcIdToken Optional OIDC ID token for pre-authenticated login.
     * @return Parsed challenge response with `challengeId` and `getOptions`.
     */
    suspend fun loginBegin(oidcIdToken: String? = null): JsonObject = withContext(Dispatchers.IO) {
        val headers = mutableMapOf(
            "X-Token-Mode" to "session",
            "X-Tenant-ID" to tenantId,
        )
        oidcIdToken?.let { headers["Authorization"] = "Bearer $it" }

        val response = post("/auth/passkey/login/begin", buildJsonObject {}, headers)
        TaggedBinary.decode(response).jsonObject
    }

    /**
     * Finish a passkey login flow.
     *
     * @param challengeId The challenge ID from loginBegin.
     * @param credential The serialized WebAuthn credential assertion.
     * @param oidcIdToken Optional OIDC ID token.
     * @return Login result with `uuid`, `displayName`, `tenantId`.
     */
    suspend fun loginFinish(
        challengeId: String,
        credential: JsonObject,
        oidcIdToken: String? = null,
    ): LoginFinishResult = withContext(Dispatchers.IO) {
        val headers = mutableMapOf(
            "X-Token-Mode" to "session",
            "X-Tenant-ID" to tenantId,
        )
        oidcIdToken?.let { headers["Authorization"] = "Bearer $it" }

        val body = buildJsonObject {
            put("challengeId", challengeId)
            put("credential", credential)
        }
        val response = post("/auth/passkey/login/finish", body, headers)
        json.decodeFromJsonElement(LoginFinishResult.serializer(), response)
    }

    // ---- Passkey Registration ----

    /**
     * Begin a passkey registration flow.
     *
     * @param inviteCode Optional invite code for gated registration.
     * @param oidcIdToken Optional OIDC ID token for pre-authenticated registration.
     * @return Parsed challenge response with `challengeId` and `createOptions`.
     */
    suspend fun registerBegin(
        inviteCode: String? = null,
        oidcIdToken: String? = null,
    ): JsonObject = withContext(Dispatchers.IO) {
        val headers = mutableMapOf(
            "X-Token-Mode" to "session",
            "X-Tenant-ID" to tenantId,
        )
        oidcIdToken?.let { headers["Authorization"] = "Bearer $it" }

        val body = buildJsonObject {
            put("tenantId", tenantId)
            inviteCode?.let { put("inviteCode", it) }
        }
        val response = post("/auth/passkey/register/begin", body, headers)
        TaggedBinary.decode(response).jsonObject
    }

    /**
     * Finish a passkey registration flow.
     *
     * @param challengeId The challenge ID from registerBegin.
     * @param credential The serialized WebAuthn credential attestation.
     * @param displayName Display name for the new user.
     * @param privateData Optional initial private data (encrypted keystore).
     * @param oidcIdToken Optional OIDC ID token.
     * @return Registration result with `uuid`, `displayName`, `tenantId`.
     */
    suspend fun registerFinish(
        challengeId: String,
        credential: JsonObject,
        displayName: String,
        privateData: Any? = null,
        oidcIdToken: String? = null,
    ): RegisterFinishResult = withContext(Dispatchers.IO) {
        val headers = mutableMapOf(
            "X-Token-Mode" to "session",
            "X-Tenant-ID" to tenantId,
        )
        oidcIdToken?.let { headers["Authorization"] = "Bearer $it" }

        val body = buildJsonObject {
            put("challengeId", challengeId)
            put("displayName", displayName)
            put("credential", credential)
        }
        val response = post("/auth/passkey/register/finish", body, headers)
        json.decodeFromJsonElement(RegisterFinishResult.serializer(), response)
    }

    // ---- Token Endpoint ----

    /**
     * Request an access token from the AS token endpoint.
     * De-duplicates concurrent requests for the same audience/TAC combination.
     *
     * @param aud Target audience (e.g., "wallet-backend").
     * @param tac Token Access Control string (e.g., "rwlid").
     * @return Parsed [AccessToken] with claims.
     */
    suspend fun requestAccessToken(aud: String, tac: String? = null): AccessToken {
        val key = "$tenantId::$aud::${tac ?: ""}"

        // Check cache
        pendingTokenMutex.withLock {
            pendingTokenRequests[key]?.let { cached ->
                if (!cached.isExpired()) return cached
                pendingTokenRequests.remove(key)
            }
        }

        val token = withContext(Dispatchers.IO) {
            val body = buildJsonObject {
                put("aud", aud)
                tac?.let { put("tac", it) }
                put("tenant_id", tenantId)
            }
            val response = post("/auth/token", body, mapOf("X-Token-Mode" to "session"))
            val tokenResponse = json.decodeFromJsonElement(TokenResponse.serializer(), response)
            AccessToken(tokenResponse.accessToken)
        }

        pendingTokenMutex.withLock {
            pendingTokenRequests[key] = token
        }
        return token
    }

    // ---- Logout ----

    /**
     * End the current session.
     */
    suspend fun logout(): Unit = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl/auth/session")
            .delete()
            .build()
        httpClient.newCall(request).execute().close()
        pendingTokenMutex.withLock {
            pendingTokenRequests.clear()
        }
    }

    // ---- HTTP Helpers ----

    private fun post(
        path: String,
        body: JsonObject,
        headers: Map<String, String> = emptyMap(),
    ): JsonObject {
        val requestBuilder = Request.Builder()
            .url("$baseUrl$path")
            .header("Content-Type", "application/json")
            .post(body.toString().toRequestBody("application/json".toMediaType()))

        headers.forEach { (k, v) -> requestBuilder.header(k, v) }

        val response = httpClient.newCall(requestBuilder.build()).execute()
        val responseBody = response.body?.string()
            ?: throw AuthException("Empty response from $path")

        if (!response.isSuccessful) {
            Timber.e("AS request failed: ${response.code} — $path")
            throw AuthException("AS request failed: ${response.code}")
        }

        return json.parseToJsonElement(responseBody).jsonObject
    }
}

/**
 * Result of a successful login via the AS.
 */
@Serializable
data class LoginFinishResult(
    val uuid: String,
    val displayName: String,
    val tenantId: String,
)

/**
 * Result of a successful registration via the AS.
 */
@Serializable
data class RegisterFinishResult(
    val uuid: String,
    val displayName: String,
    val tenantId: String,
)
