// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

import org.siros.sdk.credentials.BackendApiException
import org.siros.sdk.credentials.NetworkException
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.SignerSecurityProperties
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
 * Supports two auth modes:
 * 1. Legacy: set a static `appToken` via [setAppToken].
 * 2. New AS: provide an [AuthTokens] instance via [setAuthTokens] — tokens
 *    are automatically requested/refreshed per request, and 401 rejections
 *    trigger automatic retry with a fresh token.
 */
class BackendApiClient(
    private val baseUrl: String,
    private val tenantId: String = "default",
    private val httpClient: OkHttpClient = OkHttpClient(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    private var appToken: String? = null
    private var authTokens: AuthTokens? = null

    fun setAppToken(token: String) {
        Timber.d("setAppToken: token set")
        appToken = token
    }

    /**
     * Configure this client to use [AuthTokens] for automatic token management.
     * When set, [setAppToken] is ignored and tokens are obtained from the AS.
     */
    fun setAuthTokens(tokens: AuthTokens) {
        authTokens = tokens
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
        val builder = Request.Builder()
            .url("$baseUrl/user/session/refresh")
            .post(body.toString().toRequestBody("application/json".toMediaType()))
        addCommonHeaders(builder)
        execute(builder.build())
    }

    // ── Wallet Provider endpoints ───────────────────────────────────

    /**
     * POST /wallet-provider/key-attestation/generate — request a key attestation JWT.
     * @param jwks list of JWK objects for the keys to attest
     * @param nonce OpenID4VCI nonce from the issuer
     * @param securityProperties optional WSCD security properties for KA claims (CS-04 §7.1.3)
     * @param walletInstanceId optional WIA JWK Thumbprint (`cnf.jkt`) identifying this wallet
     *   instance, sent as `wallet_instance_id` - lets the backend's KA trust gate look up this
     *   instance's recorded `attestation_source` and lift its `security_properties` clamp when
     *   it's genuinely native-attested. Omitted when null/blank.
     * @return key attestation JWT string
     */
    suspend fun requestKeyAttestation(
        jwks: List<JsonObject>,
        nonce: String,
        securityProperties: SignerSecurityProperties? = null,
        credentialIssuer: String? = null,
        walletInstanceId: String? = null,
    ): String {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("jwks", kotlinx.serialization.json.JsonArray(jwks))
            put("openid4vci", kotlinx.serialization.json.buildJsonObject {
                put("nonce", kotlinx.serialization.json.JsonPrimitive(nonce))
                // Binds the KA's `aud` claim to the target issuer, preventing
                // a KA minted for one issuer from being replayed against
                // another - omitted (server leaves `aud` unset) when unknown.
                if (!credentialIssuer.isNullOrBlank()) {
                    put("credential_issuer", kotlinx.serialization.json.JsonPrimitive(credentialIssuer))
                }
            })
            // The WIA's JWK-thumbprint identity (`cnf.jkt`) - lets the backend's
            // KA trust gate look up this wallet instance's own recorded
            // attestation_source and lift the K3 clamp when it's genuinely
            // native-attested. Omitted whenever the caller has no such WIA.
            if (!walletInstanceId.isNullOrBlank()) {
                put("wallet_instance_id", kotlinx.serialization.json.JsonPrimitive(walletInstanceId))
            }
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
     * @param clientId this wallet's OAuth client_id (e.g. its redirect_uri, per
     *   OID4VCI's unregistered-client convention) - embedded as the WIA JWT's
     *   `sub` claim. draft-ietf-oauth-attestation-based-client-auth-10 requires
     *   "the sub claim MUST specify client_id value of the OAuth Client";
     *   omitting this falls back to the instance identifier (jkt) server-side.
     * @param nativeAttestation optional platform attestation evidence
     * @return WIA JWT string
     */
    suspend fun generateWIA(
        pop: String,
        challenge: String,
        clientId: String? = null,
        nativeAttestation: JsonObject? = null,
    ): String {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("pop", kotlinx.serialization.json.JsonPrimitive(pop))
            put("challenge", kotlinx.serialization.json.JsonPrimitive(challenge))
            if (!clientId.isNullOrBlank()) {
                put("client_id", kotlinx.serialization.json.JsonPrimitive(clientId))
            }
            if (nativeAttestation != null) {
                put("native_attestation", nativeAttestation)
            }
        }
        val result = post("/wallet-provider/wia/generate", body)
        return result["wallet_instance_attestation"]?.let {
            (it as? kotlinx.serialization.json.JsonPrimitive)?.content
        } ?: throw BackendApiException(0, "Missing wallet_instance_attestation in response", "")
    }

    /**
     * POST /wallet-provider/fido2-attestation/register — register a FIDO2/CTAP2
     * hardware-key attestation once, at key-creation time, so the backend can
     * durably mark the wallet instance as hardware-key-attested (see
     * `FIDO2AttestationService` in go-wallet-backend). Throws [BackendApiException]
     * if the backend rejects the attestation (e.g. untrusted AAGUID/chain) or the
     * feature isn't enabled.
     *
     * @param walletInstanceId the WIA JWK Thumbprint (`cnf.jkt`) this key belongs to
     * @param attestationObject the raw CTAP2 makeCredential attestation object
     *   (siros-wscd-manager's `AttestationChain.certificates[0]`)
     * @param clientDataHash the 32-byte hash the attestation signature was computed
     *   over (`AttestationChain.clientDataHash`)
     */
    suspend fun registerFido2Attestation(
        walletInstanceId: String,
        attestationObject: ByteArray,
        clientDataHash: ByteArray,
    ) {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("wallet_instance_id", kotlinx.serialization.json.JsonPrimitive(walletInstanceId))
            put(
                "attestation_object",
                kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(attestationObject)),
            )
            put(
                "client_data_hash",
                kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(clientDataHash)),
            )
        }
        post("/wallet-provider/fido2-attestation/register", body)
    }

    // ── HTTP primitives ─────────────────────────────────────────────

    private suspend fun get(path: String): JsonObject = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .get()
        addCommonHeaders(builder)
        execute(builder.build())
    }

    private suspend fun getElement(path: String): JsonElement = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .get()
        addCommonHeaders(builder)
        executeRaw(builder.build())
    }

    private suspend fun post(path: String, body: JsonObject): JsonObject = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .post(body.toString().toRequestBody("application/json".toMediaType()))
        addCommonHeaders(builder)
        execute(builder.build())
    }

    private suspend fun delete(path: String): JsonObject = withContext(Dispatchers.IO) {
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .delete()
        addCommonHeaders(builder)
        execute(builder.build())
    }

    private suspend fun addCommonHeaders(builder: Request.Builder) {
        builder.header("X-Tenant-ID", tenantId)
        val tokens = authTokens
        if (tokens != null) {
            val token = tokens.ensureBackendToken()
            builder.header("Authorization", "Bearer ${token.raw}")
        } else if (appToken != null) {
            builder.header("Authorization", "Bearer $appToken")
        } else {
            Timber.w("addCommonHeaders: no token source — request will be unauthenticated!")
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
            if (response.code == 401) {
                // Every request in this class authenticates via the backend
                // token (see addCommonHeaders/ensureBackendToken) - feed a 401
                // into AuthTokens' rejection counter so REJECTION_THRESHOLD
                // rejections within REJECTION_WINDOW_MS actually trigger
                // onSessionRejected/logout, instead of silently doing nothing
                // (registerTokenRejection was previously dead code - nothing
                // called it despite AuthTokens already tracking rejections).
                authTokens?.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
            }
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
