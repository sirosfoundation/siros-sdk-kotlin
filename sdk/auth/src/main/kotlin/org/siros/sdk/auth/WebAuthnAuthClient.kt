package org.siros.sdk.auth

import org.siros.sdk.credentials.AuthException
import org.siros.sdk.credentials.NetworkException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
import timber.log.Timber

/**
 * Handles WebAuthn registration/login flows against the wallet backend REST API.
 * Coordinates between the backend challenge endpoints and the [AuthProvider] for
 * credential creation/assertion.
 */
class WebAuthnAuthClient(
    private val baseUrl: String,
    private val tenantId: String = "default",
    private val authProvider: AuthProvider,
    private val httpClient: OkHttpClient = OkHttpClient(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    /** Register a new user with WebAuthn. Returns an authenticated session. */
    suspend fun register(displayName: String, prfSalt: ByteArray? = null): AuthSession = withContext(Dispatchers.IO) {
        // Step 1: Get registration challenge from backend
        val challengeResponse = post(
            "$baseUrl/user/register-webauthn-begin",
            buildJsonObject { put("displayName", displayName) },
        )

        // Decode tagged binary objects ({"$b64u": "..."} → plain strings) in the response
        val options = TaggedBinary.decode(challengeResponse).jsonObject
        val challengeId = options["challengeId"]?.jsonPrimitive?.content
        val publicKey = (options["getOptions"] ?: options["createOptions"])?.jsonObject
            ?.get("publicKey")?.jsonObject
            ?: options["publicKey"]?.jsonObject
            ?: throw AuthException("Missing publicKey in registration challenge")

        val rpId = publicKey["rp"]?.jsonObject?.get("id")?.jsonPrimitive?.content
            ?: throw AuthException("Missing rp.id")
        val rpName = publicKey["rp"]?.jsonObject?.get("name")?.jsonPrimitive?.content ?: rpId
        val challenge = decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing challenge"))
        val user = publicKey["user"]?.jsonObject ?: throw AuthException("Missing user")
        val userId = decodeBase64Url(user["id"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing user.id"))
        val userName = user["name"]?.jsonPrimitive?.content ?: displayName

        // Step 2: Create credential via AuthProvider
        val result = authProvider.register(
            RegisterOptions(
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = displayName,
                challenge = challenge,
                prfSalt = prfSalt,
            )
        )

        // Step 3: Complete registration with backend
        val credential = buildJsonObject {
            put("id", encodeBase64Url(result.credentialId))
            put("rawId", encodeBase64Url(result.credentialId))
            put("type", "public-key")
            put("response", buildJsonObject {
                put("attestationObject", encodeBase64Url(result.attestationObject))
                put("clientDataJSON", encodeBase64Url(result.clientDataJSON))
            })
        }
        val finishBody = buildJsonObject {
            challengeId?.let { put("challengeId", it) }
            put("credential", credential)
        }

        val sessionResponse = post("$baseUrl/user/register-webauthn-finish", finishBody)
        Timber.d("register finish response keys: ${sessionResponse.keys}")
        val session = json.decodeFromJsonElement(AuthSession.serializer(), sessionResponse)
        Timber.d("register session: uuid=...${session.uuid.takeLast(4)}, tenantId=${session.tenantId}")
        session
    }

    /** Authenticate an existing user with WebAuthn. Returns an authenticated session. */
    suspend fun login(prfSalt: ByteArray? = null): AuthSession = withContext(Dispatchers.IO) {
        // Step 1: Get login challenge
        val challengeResponse = post("$baseUrl/user/login-webauthn-begin", buildJsonObject {})
        // Decode tagged binary objects
        val options = TaggedBinary.decode(challengeResponse).jsonObject
        val challengeId = options["challengeId"]?.jsonPrimitive?.content
        val publicKey = (options["getOptions"])?.jsonObject
            ?.get("publicKey")?.jsonObject
            ?: options["publicKey"]?.jsonObject
            ?: throw AuthException("Missing publicKey in login challenge")

        val rpId = publicKey["rpId"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing rpId")
        val challenge = decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing challenge"))

        // Step 2: Authenticate via AuthProvider
        val result = authProvider.authenticate(
            AuthenticateOptions(
                rpId = rpId,
                challenge = challenge,
                prfSalt = prfSalt,
            )
        )

        // Step 3: Complete login with backend
        val credential = buildJsonObject {
            put("id", encodeBase64Url(result.credentialId))
            put("rawId", encodeBase64Url(result.credentialId))
            put("type", "public-key")
            put("response", buildJsonObject {
                put("authenticatorData", encodeBase64Url(result.authenticatorData))
                put("clientDataJSON", encodeBase64Url(result.clientDataJSON))
                put("signature", encodeBase64Url(result.signature))
                result.userHandle?.let { put("userHandle", encodeBase64Url(it)) }
            })
        }
        val finishBody = buildJsonObject {
            challengeId?.let { put("challengeId", it) }
            put("credential", credential)
        }

        val sessionResponse = post("$baseUrl/user/login-webauthn-finish", finishBody)
        Timber.d("login finish response keys: ${sessionResponse.keys}")
        val session = json.decodeFromJsonElement(AuthSession.serializer(), sessionResponse)
        Timber.d("login session: uuid=...${session.uuid.takeLast(4)}, tenantId=${session.tenantId}")
        session
    }

    private fun post(url: String, body: JsonObject): JsonObject {
        val request = Request.Builder()
            .url(url)
            .header("X-Tenant-ID", tenantId)
            .header("Content-Type", "application/json")
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val response = httpClient.newCall(request).execute()
        val responseBody = response.body?.string()
            ?: throw AuthException("Empty response from $url")

        if (!response.isSuccessful) {
            Timber.e("Auth request failed: ${response.code}")
            throw AuthException("Auth request failed: ${response.code}", code = response.code)
        }

        return json.parseToJsonElement(responseBody).jsonObject
    }

    companion object {
        private val base64Url = java.util.Base64.getUrlEncoder().withoutPadding()
        private val base64UrlDecoder = java.util.Base64.getUrlDecoder()

        fun encodeBase64Url(data: ByteArray): String = base64Url.encodeToString(data)
        fun decodeBase64Url(data: String): ByteArray = base64UrlDecoder.decode(data)
    }
}
