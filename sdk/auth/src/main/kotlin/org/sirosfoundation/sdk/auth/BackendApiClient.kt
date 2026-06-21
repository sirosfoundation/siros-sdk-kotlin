// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.auth

import org.sirosfoundation.sdk.credentials.BackendApiException
import org.sirosfoundation.sdk.credentials.NetworkException
import org.sirosfoundation.sdk.credentials.CertificationInfo
import org.sirosfoundation.sdk.credentials.SignerSecurityProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber

/**
 * Authenticated HTTP client for the wallet backend REST API.
 *
 * Requires a valid `appToken` (JWT) obtained from [WebAuthnAuthClient.login]
 * or [WebAuthnAuthClient.register].
 */
class BackendApiClient(
    private val baseUrl: String,
    private val tenantId: String = "default",
    private val httpClient: OkHttpClient = OkHttpClient(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    private var appToken: String? = null

    fun setAppToken(token: String) {
        Timber.d("setAppToken: token set")
        appToken = token
    }

    /** GET /user/session/account-info */
    suspend fun getAccountInfo(): JsonObject = get("/user/session/account-info")

    /** GET /storage/vc — list all credentials */
    suspend fun getCredentials(): JsonObject = get("/storage/vc")

    /** POST /storage/vc — store a credential */
    suspend fun storeCredential(credential: JsonObject): JsonObject =
        post("/storage/vc", credential)

    /** GET /storage/vc/:id */
    suspend fun getCredential(id: String): JsonObject = get("/storage/vc/$id")

    /** DELETE /storage/vc/:id */
    suspend fun deleteCredential(id: String): JsonObject = delete("/storage/vc/$id")

    /** GET /issuer/all — list registered issuers */
    suspend fun getIssuers(): JsonElement = getElement("/issuer/all")

    /** GET /issuer/:id/metadata — get cached issuer metadata via the backend proxy */
    suspend fun getIssuerMetadata(id: Long): JsonObject = get("/issuer/$id/metadata")

    /** GET /verifier/all — list registered verifiers */
    suspend fun getVerifiers(): JsonObject = get("/verifier/all")

    /** GET /user/session/private-data */
    suspend fun getPrivateData(): JsonObject = get("/user/session/private-data")

    /** POST /user/session/private-data */
    suspend fun updatePrivateData(data: JsonObject): JsonObject =
        post("/user/session/private-data", data)

    /** GET /health */
    suspend fun healthCheck(): JsonObject = get("/health")

    /** GET /api/v1/tenants/:id/config */
    suspend fun getTenantConfig(): JsonObject = get("/api/v1/tenants/$tenantId/config")

    /** POST /v1/evaluate — AuthZEN trust evaluation via backend proxy */
    suspend fun evaluateTrust(requestBody: JsonObject): JsonObject =
        post("/v1/evaluate", requestBody)

    /** POST /user/session/refresh — refresh appToken using refreshToken */
    suspend fun refreshSession(refreshToken: String): JsonObject = withContext(Dispatchers.IO) {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("refreshToken", kotlinx.serialization.json.JsonPrimitive(refreshToken))
        }
        val request = Request.Builder()
            .url("$baseUrl/user/session/refresh")
            .apply { addCommonHeaders(this) }
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()
        execute(request)
    }

    // ── Wallet Provider endpoints ───────────────────────────────────

    /**
     * POST /wallet-provider/key-attestation/generate — request a key attestation JWT.
     * @param jwks list of JWK objects for the keys to attest
     * @param nonce OpenID4VCI nonce from the issuer
     * @param securityProperties optional WSCD security properties for KA claims (CS-04 §7.1.3)
     * @return key attestation JWT string
     */
    suspend fun requestKeyAttestation(
        jwks: List<JsonObject>,
        nonce: String,
        securityProperties: SignerSecurityProperties? = null,
    ): String {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("jwks", kotlinx.serialization.json.JsonArray(jwks))
            put("openid4vci", kotlinx.serialization.json.buildJsonObject {
                put("nonce", kotlinx.serialization.json.JsonPrimitive(nonce))
            })
            if (securityProperties != null) {
                put("security_properties", kotlinx.serialization.json.buildJsonObject {
                    put("key_storage", kotlinx.serialization.json.JsonArray(
                        securityProperties.keyStorage.map { kotlinx.serialization.json.JsonPrimitive(it) }
                    ))
                    put("user_authentication", kotlinx.serialization.json.JsonArray(
                        securityProperties.userAuthentication.map { kotlinx.serialization.json.JsonPrimitive(it) }
                    ))
                    when (val cert = securityProperties.certification) {
                        is CertificationInfo.None ->
                            put("certification", kotlinx.serialization.json.JsonPrimitive("none"))
                        is CertificationInfo.Certified ->
                            put("certification", kotlinx.serialization.json.buildJsonObject {
                                put("scheme", kotlinx.serialization.json.JsonPrimitive(cert.scheme))
                                put("assurance_level", kotlinx.serialization.json.JsonPrimitive(cert.assuranceLevel))
                            })
                    }
                })
            }
        }
        val result = post("/wallet-provider/key-attestation/generate", body)
        return result["key_attestation"]?.let {
            (it as? kotlinx.serialization.json.JsonPrimitive)?.content
        } ?: throw BackendApiException(0, "Missing key_attestation in response", "")
    }

    /** POST /wallet-provider/wia/challenge — request a WIA challenge nonce. */
    suspend fun requestWIAChallenge(): JsonObject =
        post("/wallet-provider/wia/challenge", JsonObject(emptyMap()))

    /**
     * POST /wallet-provider/wia/generate — generate a Wallet Instance Attestation.
     * @param pop WIA-PoP JWT (typ: oauth-client-attestation-pop+jwt)
     * @param challenge the challenge nonce from requestWIAChallenge()
     * @param nativeAttestation optional platform attestation evidence
     * @return WIA JWT string
     */
    suspend fun generateWIA(
        pop: String,
        challenge: String,
        nativeAttestation: JsonObject? = null,
    ): String {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("pop", kotlinx.serialization.json.JsonPrimitive(pop))
            put("challenge", kotlinx.serialization.json.JsonPrimitive(challenge))
            if (nativeAttestation != null) {
                put("native_attestation", nativeAttestation)
            }
        }
        val result = post("/wallet-provider/wia/generate", body)
        return result["wallet_instance_attestation"]?.let {
            (it as? kotlinx.serialization.json.JsonPrimitive)?.content
        } ?: throw BackendApiException(0, "Missing wallet_instance_attestation in response", "")
    }

    // ── HTTP primitives ─────────────────────────────────────────────

    private suspend fun get(path: String): JsonObject = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl$path")
            .apply { addCommonHeaders(this) }
            .get()
            .build()
        execute(request)
    }

    private suspend fun getElement(path: String): JsonElement = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl$path")
            .apply { addCommonHeaders(this) }
            .get()
            .build()
        executeRaw(request)
    }

    private suspend fun post(path: String, body: JsonObject): JsonObject = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl$path")
            .apply { addCommonHeaders(this) }
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()
        execute(request)
    }

    private suspend fun delete(path: String): JsonObject = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl$path")
            .apply { addCommonHeaders(this) }
            .delete()
            .build()
        execute(request)
    }

    private fun addCommonHeaders(builder: Request.Builder) {
        builder.header("X-Tenant-ID", tenantId)
        if (appToken != null) {
            Timber.d("addCommonHeaders: sending authenticated request")
            builder.header("Authorization", "Bearer $appToken")
        } else {
            Timber.w("addCommonHeaders: appToken is NULL — request will be unauthenticated!")
        }
    }

    private fun execute(request: Request): JsonObject {
        return executeRaw(request).jsonObject
    }

    private fun executeRaw(request: Request): JsonElement {
        val response = try {
            httpClient.newCall(request).execute()
        } catch (e: java.io.IOException) {
            throw NetworkException("Network error: ${request.url}", e)
        }
        val responseBody = response.body?.string() ?: "{}"

        if (!response.isSuccessful) {
            Timber.e("API request failed: ${request.method} ${request.url} -> ${response.code}")
            throw BackendApiException(
                code = response.code,
                message = "API request failed: ${response.code}",
                body = responseBody,
            )
        }

        return if (responseBody.isBlank()) {
            JsonObject(emptyMap())
        } else {
            json.parseToJsonElement(responseBody)
        }
    }
}
