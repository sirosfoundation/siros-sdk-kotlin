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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber


private val JSON_MEDIA_TYPE = "application/json".toMediaType()
private const val PRIVATE_DATA_ETAG_HEADER = "X-Private-Data-ETag"

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

    /**
     * POST /v1/resolve — resolve credential issuer metadata through the backend.
     *
     * Unlike fetching the well-known document directly, this returns metadata
     * the backend has already authenticated: it verifies the signed_metadata
     * JWS, evaluates the signer against the trust registry, and (per ARF
     * section 6.6.2.3) reports whether the provider is registered to issue the
     * requested credential types.
     *
     * [credentialTypes] are credential configuration ids from the offer. They
     * are what lets the backend answer "may this provider issue *this*", rather
     * than only "is this provider trusted at all".
     */
    suspend fun resolveIssuer(issuerUrl: String, credentialTypes: List<String> = emptyList()): JsonObject {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("subject_id", kotlinx.serialization.json.JsonPrimitive(issuerUrl))
            put("subject_type", kotlinx.serialization.json.JsonPrimitive("url"))
            put("resource_type", kotlinx.serialization.json.JsonPrimitive("credential_issuer"))
            if (credentialTypes.isNotEmpty()) {
                put(
                    "credential_types",
                    kotlinx.serialization.json.JsonArray(
                        credentialTypes.map { kotlinx.serialization.json.JsonPrimitive(it) },
                    ),
                )
            }
        }
        return post("/v1/resolve", body)
    }

    /**
     * POST /v1/resolve — resolve a "key" subject (a `did:` identifier) to
     * its verification key material, proxied by the backend directly to
     * the PDP (see go-wallet-backend's `AuthZENProxyHandler.Resolve`).
     *
     * Distinct from [resolveIssuer], which always sends
     * `subject_type: "url"` for OpenID4VCI issuer metadata resolution -
     * this is the counterpart for a DID-scheme verifier's
     * `TrustEvaluationRequest.requires_resolution`
     * (go-wallet-backend#396/#401): when the engine cannot resolve the DID
     * itself (no verifier PDP configured), it defers to the frontend/SDK,
     * which must call this before `evaluateTrust`.
     *
     * The response's `context.trust_metadata` is the resolved DID
     * Document - the caller is responsible for extracting a
     * `verificationMethod` entry's `publicKeyJwk` and verifying the
     * accompanying `request_jwt` against it (see
     * [org.siros.sdk.wallet.SirosWallet]'s `resolveDidKeyMaterial`).
     */
    suspend fun resolveKey(subjectId: String): JsonObject {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("subject_id", kotlinx.serialization.json.JsonPrimitive(subjectId))
            put("subject_type", kotlinx.serialization.json.JsonPrimitive("key"))
        }
        return post("/v1/resolve", body)
    }

    /**
     * POST /v1/resolve — resolve a DID through the backend, which delegates to
     * go-trust.
     *
     * DID method resolution is a trust decision: which document is
     * authoritative for an identifier. That belongs to the deployment's trust
     * registry, not to each wallet's own idea of which hosts to believe, so
     * the wallet asks rather than fetches. `did:jwk` is the one exception and
     * never gets here - it carries its own key and resolves offline.
     *
     * DIDs are `subject_type: "key"` on this API, matching wallet-frontend's
     * AuthZEN client; the resolved document comes back under
     * `context.trust_metadata`.
     *
     * Same wire shape as [resolveKey] - that one is the verifier
     * trust-evaluation path (`requires_resolution`), which always gets a
     * response to pick a `verificationMethod` out of and fails closed itself
     * when resolution comes back empty. This one backs [DidResolver] as a
     * generic, best-effort lookup (issuer `did:web` binding, holder-key
     * negotiation): no document is a normal outcome here, not a failure, so
     * it stays nullable instead of throwing.
     *
     * @return the DID document, or null if the backend could not resolve it.
     */
    suspend fun resolveDid(did: String): JsonObject? {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("subject_id", kotlinx.serialization.json.JsonPrimitive(did))
            put("subject_type", kotlinx.serialization.json.JsonPrimitive("key"))
        }
        val response = post("/v1/resolve", body)
        val document = (response["context"] as? JsonObject)?.get("trust_metadata") as? JsonObject
        return document?.takeIf { it["id"] != null }
    }

    /** POST /user/session/refresh — refresh appToken using refreshToken */
    suspend fun refreshSession(refreshToken: String): JsonObject = withContext(Dispatchers.IO) {
        val body = kotlinx.serialization.json.buildJsonObject {
            put("refreshToken", kotlinx.serialization.json.JsonPrimitive(refreshToken))
        }
        val builder = Request.Builder()
            .url("$baseUrl/user/session/refresh")
            .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
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
     * @param credentialId base64url WebAuthn credential id of the passkey this
     *   installation logs in with. The backend records it on the wallet
     *   instance so that suspending or revoking the instance also refuses
     *   login with that passkey (SID-AUTH-06, go-wallet-backend#319). Optional;
     *   older backends ignore it.
     * @return WIA JWT string
     */
    suspend fun generateWIA(
        pop: String,
        challenge: String,
        clientId: String? = null,
        nativeAttestation: JsonObject? = null,
        credentialId: String? = null,
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
            if (!credentialId.isNullOrBlank()) {
                put("credential_id", kotlinx.serialization.json.JsonPrimitive(credentialId))
            }
        }
        val result = post("/wallet-provider/wia/generate", body)
        return result["wallet_instance_attestation"]?.let {
            (it as? kotlinx.serialization.json.JsonPrimitive)?.content
        } ?: throw BackendApiException(0, "Missing wallet_instance_attestation in response", "")
    }

    // ---- Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319) ----

    /** GET /user/session/instances — this user's wallet instances in the current tenant. */
    suspend fun listWalletInstances(): List<WalletInstance> {
        val result = get("/user/session/instances")
        // The backend always sends the array (empty when the user has no
        // instances); its absence is a malformed response, not "no instances".
        val arr = result["instances"] as? kotlinx.serialization.json.JsonArray
            ?: throw BackendApiException(0, "Missing instances in response", "")
        return arr.map { json.decodeFromJsonElement(WalletInstance.serializer(), it) }
    }

    // ---- Account deletion (SID-AUTH-06, go-wallet-backend#352) ----

    /**
     * POST /user/session/delete-begin — start a step-up for account deletion.
     * On [DeleteAccountBegin.Ready] the options must be answered with a fresh
     * passkey assertion within two minutes and passed to [deleteAccount].
     * Needs a token with the `w` scope; an account without a passkey cannot
     * be deleted this way and gets [DeleteAccountBegin.NoPasskey].
     */
    suspend fun deleteAccountBegin(): DeleteAccountBegin {
        val (status, text) = sendRaw("/user/session/delete-begin") { it.post(JsonObject(emptyMap()).toString().toRequestBody(JSON_MEDIA_TYPE)) }
        val fields = parseFields(text)
        val message = fields.string("message")
        return when (status) {
            200 -> DeleteAccountBegin.Ready(parseChallenge(TaggedBinary.decode(json.parseToJsonElement(text)).jsonObject))
            400 -> if (fields.string("error") == ERROR_NO_PASSKEY) {
                DeleteAccountBegin.NoPasskey(message)
            } else {
                throw BackendApiException(status, "API request failed: $status", text)
            }
            401 -> {
                authTokens?.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
                DeleteAccountBegin.SessionRevoked(message)
            }
            403 -> DeleteAccountBegin.Forbidden(message)
            404 -> DeleteAccountBegin.NotFound(message)
            else -> throw BackendApiException(status, "API request failed: $status", text)
        }
    }

    private fun parseChallenge(response: JsonObject): DeleteAccountChallenge {
        val challengeId = (response["challengeId"] as? JsonPrimitive)?.content
            ?: throw BackendApiException(0, "Missing challengeId in response", "")
        val publicKey = response["publicKey"]?.jsonObject
            ?: throw BackendApiException(0, "Missing publicKey in response", "")
        val rpId = (publicKey["rpId"] as? JsonPrimitive)?.content
            ?: throw BackendApiException(0, "Missing rpId in response", "")
        val challenge = (publicKey["challenge"] as? JsonPrimitive)?.content
            ?: throw BackendApiException(0, "Missing challenge in response", "")
        val allow = (publicKey["allowCredentials"] as? JsonArray)?.map {
            val id = (it.jsonObject["id"] as? JsonPrimitive)?.content
                ?: throw BackendApiException(0, "Missing allowCredentials id in response", "")
            AllowCredential(WebAuthnAuthClient.decodeBase64Url(id))
        }
        return DeleteAccountChallenge(
            challengeId = challengeId,
            options = AuthenticateOptions(
                rpId = rpId,
                challenge = WebAuthnAuthClient.decodeBase64Url(challenge),
                allowCredentials = allow,
                userVerification = (publicKey["userVerification"] as? JsonPrimitive)?.content ?: "required",
            ),
        )
    }

    // ---- Adding a passkey to an existing account (go-wallet-backend#453) ----

    /**
     * The `X-Private-Data-ETag` of the most recent response that carried one
     * (private-data reads and writes, a passkey enrolment). Sent as
     * `X-Private-Data-If-Match` by [passkeyRegisterFinish] so that an enrolment
     * cannot overwrite private data another device wrote in the meantime.
     */
    @Volatile
    var privateDataEtag: String? = null
        private set

    /**
     * Restores [privateDataEtag] after a process restart, from whatever this
     * account's SDK-side session storage persisted alongside the cached
     * private-data container.
     *
     * A fresh [BackendApiClient] otherwise starts with a null
     * [privateDataEtag] even when the cached container it will be used
     * against is actually current, so [passkeyRegisterFinish]'s default
     * `ifMatch` omits `X-Private-Data-If-Match` entirely and the backend
     * skips its optimistic-concurrency check - letting this device's
     * enrollment silently clobber a newer write from another device. Call
     * this right after constructing the client for a resumed session, before
     * any private-data-affecting call.
     */
    fun restorePrivateDataEtag(etag: String?) {
        privateDataEtag = etag
    }

    /**
     * POST /user/session/webauthn/register-begin - start adding a passkey to
     * the caller's account. On [AddPasskeyBegin.Ready] run the create ceremony
     * and, if [PasskeyEnrollmentChallenge.authorization] is set, the
     * authorising assertion, then pass both to [passkeyRegisterFinish].
     */
    suspend fun passkeyRegisterBegin(): AddPasskeyBegin {
        val (status, text) = sendRaw("/user/session/webauthn/register-begin") { it.post(JsonObject(emptyMap()).toString().toRequestBody(JSON_MEDIA_TYPE)) }
        val fields = parseFields(text)
        val message = fields.string("message")
        return when (status) {
            200 -> AddPasskeyBegin.Ready(parseEnrollment(TaggedBinary.decode(json.parseToJsonElement(text)).jsonObject))
            401 -> {
                authTokens?.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
                AddPasskeyBegin.SessionRevoked(message)
            }
            403 -> AddPasskeyBegin.Forbidden(message)
            else -> throw BackendApiException(status, "API request failed: $status", text)
        }
    }

    private fun parseEnrollment(response: JsonObject): PasskeyEnrollmentChallenge {
        val challengeId = (response["challengeId"] as? JsonPrimitive)?.content
            ?: throw BackendApiException(0, "Missing challengeId in response", "")
        val publicKey = response["createOptions"]?.jsonObject?.get("publicKey")?.jsonObject
            ?: throw BackendApiException(0, "Missing createOptions.publicKey in response", "")
        fun str(o: JsonObject, name: String, what: String) =
            (o[name] as? JsonPrimitive)?.content ?: throw BackendApiException(0, "Missing $what in response", "")
        val rp = publicKey["rp"]?.jsonObject ?: throw BackendApiException(0, "Missing rp in response", "")
        val user = publicKey["user"]?.jsonObject ?: throw BackendApiException(0, "Missing user in response", "")
        val rpId = str(rp, "id", "rp.id")
        val username = (response["username"] as? JsonPrimitive)?.content
        val userName = (user["name"] as? JsonPrimitive)?.content ?: username ?: ""
        val selection = publicKey["authenticatorSelection"] as? JsonObject
        return PasskeyEnrollmentChallenge(
            challengeId = challengeId,
            username = username,
            createOptions = RegisterOptions(
                rpId = rpId,
                rpName = (rp["name"] as? JsonPrimitive)?.content ?: rpId,
                userId = WebAuthnAuthClient.decodeBase64Url(str(user, "id", "user.id")),
                userName = userName,
                userDisplayName = (user["displayName"] as? JsonPrimitive)?.content ?: userName,
                challenge = WebAuthnAuthClient.decodeBase64Url(str(publicKey, "challenge", "challenge")),
                attestation = (publicKey["attestation"] as? JsonPrimitive)?.content ?: "none",
                authenticatorSelection = selection?.let {
                    AuthenticatorSelection(
                        authenticatorAttachment = (it["authenticatorAttachment"] as? JsonPrimitive)?.content,
                        residentKey = (it["residentKey"] as? JsonPrimitive)?.content ?: "required",
                        userVerification = (it["userVerification"] as? JsonPrimitive)?.content ?: "preferred",
                    )
                },
            ),
            authorization = (response["authorization"] as? JsonObject)?.let { parseAssertionOptions(it) },
        )
    }

    private fun parseAssertionOptions(container: JsonObject): AuthenticateOptions {
        val publicKey = container["publicKey"]?.jsonObject
            ?: throw BackendApiException(0, "Missing authorization.publicKey in response", "")
        val rpId = (publicKey["rpId"] as? JsonPrimitive)?.content
            ?: throw BackendApiException(0, "Missing authorization rpId in response", "")
        val challenge = (publicKey["challenge"] as? JsonPrimitive)?.content
            ?: throw BackendApiException(0, "Missing authorization challenge in response", "")
        val allow = (publicKey["allowCredentials"] as? JsonArray)?.map {
            val id = (it.jsonObject["id"] as? JsonPrimitive)?.content
                ?: throw BackendApiException(0, "Missing allowCredentials id in response", "")
            AllowCredential(WebAuthnAuthClient.decodeBase64Url(id))
        }
        return AuthenticateOptions(
            rpId = rpId,
            challenge = WebAuthnAuthClient.decodeBase64Url(challenge),
            allowCredentials = allow,
            userVerification = (publicKey["userVerification"] as? JsonPrimitive)?.content ?: "required",
        )
    }

    /**
     * POST /user/session/webauthn/register-finish - complete adding a passkey.
     *
     * [credential] is the new passkey, [authorization] the assertion an
     * existing passkey made over [PasskeyEnrollmentChallenge.authorization]
     * (required unless begin returned none), [privateData] the container with
     * the new passkey's PRF entry. [ifMatch] defaults to [privateDataEtag].
     *
     * Every outcome the backend defines is returned as an [AddPasskeyOutcome];
     * only an unexpected status or a network failure throws. A step-up `401` is
     * not counted as a rejected bearer token.
     */
    suspend fun passkeyRegisterFinish(
        challengeId: String,
        credential: RegisterResult,
        nickname: String,
        privateData: ByteArray?,
        authorization: AuthenticateResult?,
        ifMatch: String? = privateDataEtag,
    ): AddPasskeyOutcome {
        val body = buildJsonObject {
            put("challengeId", JsonPrimitive(challengeId))
            put("nickname", JsonPrimitive(nickname))
            put("credential", credential.toAttestationJson())
            if (privateData != null) {
                put("privateData", buildJsonObject { put("\$b64u", JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(privateData))) })
            }
            if (authorization != null) put("authorization", authorization.toAssertionJson())
        }
        val (status, text, etag) = sendRawWithEtag("/user/session/webauthn/register-finish") { b ->
            if (ifMatch != null) b.header("X-Private-Data-If-Match", ifMatch)
            b.post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
        }
        val fields = parseFields(text)
        val message = fields.string("message")
        return when (status) {
            200 -> {
                etag?.let { privateDataEtag = it }
                AddPasskeyOutcome.Added(fields.string("credentialId"))
            }
            404 -> AddPasskeyOutcome.RetryNeeded(message)
            412 -> {
                // Do NOT adopt the server's newer ETag here: this device's cached
                // container has not been updated to match it, so trusting the new
                // version would let a later retry submit stale private data tagged
                // as current, silently clobbering another device's concurrent
                // write. Surface the remote ETag only as data on the conflict so
                // callers can fetch-and-reconcile before retrying with it.
                AddPasskeyOutcome.PrivateDataConflict(etag)
            }
            400, 403 -> AddPasskeyOutcome.RegistrationRejected(status, fields.string("error") ?: message)
            401 -> when (fields.string("error")) {
                ERROR_ENROLLMENT_AUTHORIZATION_REQUIRED -> AddPasskeyOutcome.AuthorizationRequired(message)
                ERROR_ENROLLMENT_AUTHORIZATION_FAILED -> AddPasskeyOutcome.AuthorizationFailed(message)
                else -> {
                    authTokens?.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
                    AddPasskeyOutcome.SessionRevoked(message)
                }
            }
            else -> throw BackendApiException(status, "API request failed: $status", text)
        }
    }

    private fun RegisterResult.toAttestationJson(): JsonObject {
        val id = WebAuthnAuthClient.encodeBase64Url(credentialId)
        return buildJsonObject {
            put("id", JsonPrimitive(id))
            put("rawId", JsonPrimitive(id))
            put("type", JsonPrimitive("public-key"))
            put("response", buildJsonObject {
                put("attestationObject", JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(attestationObject)))
                put("clientDataJSON", JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(clientDataJSON)))
            })
        }
    }

    private fun parseFields(text: String): JsonObject? =
        runCatching { json.parseToJsonElement(text).jsonObject }.getOrNull()

    private fun JsonObject?.string(name: String): String? =
        (this?.get(name) as? JsonPrimitive)?.content?.takeIf { it.isNotBlank() }

    /** Sends the request built by [configure] against [path] and returns the status and body without judging either. */
    private suspend fun sendRaw(path: String, configure: (Request.Builder) -> Request.Builder): Pair<Int, String> =
        sendRawWithEtag(path, configure).let { it.first to it.second }

    /** [sendRaw] that also returns the response's `X-Private-Data-ETag`, if any. */
    private suspend fun sendRawWithEtag(path: String, configure: (Request.Builder) -> Request.Builder): Triple<Int, String, String?> =
        withContext(Dispatchers.IO) {
            val builder = configure(Request.Builder().url("$baseUrl$path"))
            addCommonHeaders(builder)
            val request = builder.build()
            try {
                httpClient.newCall(request).execute().use {
                    Triple(it.code, it.body?.string().orEmpty(), it.header(PRIVATE_DATA_ETAG_HEADER))
                }
            } catch (e: java.io.IOException) {
                throw NetworkException("Network error: ${request.url}", e)
            }
        }

    /**
     * DELETE /user/session — delete the caller's account, authorised by the
     * assertion [credential] that answered [challengeId] and by [confirm]
     * (which must be [DELETE_ACCOUNT_CONFIRMATION]).
     *
     * Every outcome the backend defines is returned as a [DeleteAccountOutcome]
     * rather than thrown; only an unexpected status (or a network failure)
     * throws. A step-up `401` is not counted as a rejected bearer token, so a
     * wrong passkey cannot log the session out.
     */
    suspend fun deleteAccount(
        challengeId: String,
        credential: AuthenticateResult,
        confirm: String,
    ): DeleteAccountOutcome {
        val body = buildJsonObject {
            put("challengeId", JsonPrimitive(challengeId))
            put("credential", credential.toAssertionJson())
            put("confirm", JsonPrimitive(confirm))
        }
        val (status, text) = sendRaw("/user/session") { it.delete(body.toString().toRequestBody(JSON_MEDIA_TYPE)) }
        val fields = parseFields(text)
        fun field(name: String) = fields.string(name)
        val message = field("message")
        val error = field("error")
        // `202` carries its code as `result` (as `200 {"result":"DELETED"}` does).
        val code = field("result")
        return when (status) {
            200 -> DeleteAccountOutcome.Deleted
            202 -> when (code) {
                CODE_DELETION_CLEANUP_PENDING -> DeleteAccountOutcome.CleanupPending
                CODE_DELETION_OPERATOR_REQUIRED -> DeleteAccountOutcome.OperatorRequired
                else -> throw BackendApiException(status, "Unrecognised 202 from account deletion", text)
            }
            409 -> DeleteAccountOutcome.RetryNeeded(message)
            410 -> DeleteAccountOutcome.StepUpExpired(message)
            404 -> DeleteAccountOutcome.NotFound(message)
            400 -> if (error == ERROR_CONFIRMATION_REQUIRED) {
                DeleteAccountOutcome.ConfirmationRequired(message)
            } else {
                throw BackendApiException(status, "API request failed: $status", text)
            }
            401 -> when (error) {
                ERROR_STEP_UP_REQUIRED -> DeleteAccountOutcome.StepUpRequired(message)
                ERROR_STEP_UP_FAILED -> DeleteAccountOutcome.StepUpFailed(message)
                else -> {
                    authTokens?.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
                    DeleteAccountOutcome.SessionRevoked(message)
                }
            }
            else -> throw BackendApiException(status, "API request failed: $status", text)
        }
    }

    private fun AuthenticateResult.toAssertionJson(): JsonObject {
        val id = WebAuthnAuthClient.encodeBase64Url(credentialId)
        return buildJsonObject {
            put("id", JsonPrimitive(id))
            put("rawId", JsonPrimitive(id))
            put("type", JsonPrimitive("public-key"))
            put("response", buildJsonObject {
                put("authenticatorData", JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(authenticatorData)))
                put("clientDataJSON", JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(clientDataJSON)))
                put("signature", JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(signature)))
                userHandle?.let { put("userHandle", JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(it))) }
            })
        }
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
            .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
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
        response.header(PRIVATE_DATA_ETAG_HEADER)?.let { privateDataEtag = it }

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
