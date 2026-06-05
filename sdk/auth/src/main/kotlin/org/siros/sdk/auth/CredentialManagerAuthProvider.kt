// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import timber.log.Timber

/**
 * [AuthProvider] implementation backed by Android Credential Manager.
 *
 * Uses [CreatePublicKeyCredentialRequest] for registration and
 * [GetPublicKeyCredentialOption] for authentication — both accept/return
 * the standard WebAuthn JSON serialization.
 *
 * @param context Activity or Application context. For passkey UI, pass the Activity context.
 */
class CredentialManagerAuthProvider(
    private val context: Context,
) : AuthProvider {

    private val credentialManager = CredentialManager.create(context)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun register(options: RegisterOptions): RegisterResult {
        // Build the WebAuthn PublicKeyCredentialCreationOptions JSON
        val requestJson = buildCreationOptionsJson(options)
        Timber.d("CreatePublicKeyCredentialRequest JSON: $requestJson")

        val request = CreatePublicKeyCredentialRequest(requestJson)
        val response = credentialManager.createCredential(context, request)

        if (response !is CreatePublicKeyCredentialResponse) {
            throw AuthException("Unexpected credential response type: ${response::class.simpleName}")
        }

        return parseRegistrationResponse(response.registrationResponseJson)
    }

    override suspend fun authenticate(options: AuthenticateOptions): AuthenticateResult {
        // Build the WebAuthn PublicKeyCredentialRequestOptions JSON
        val requestJson = buildRequestOptionsJson(options)
        Timber.d("GetPublicKeyCredentialOption JSON: $requestJson")

        val credentialOption = GetPublicKeyCredentialOption(requestJson)
        val request = GetCredentialRequest(listOf(credentialOption))
        val response = credentialManager.getCredential(context, request)

        val credential = response.credential
        if (credential !is PublicKeyCredential) {
            throw AuthException("Unexpected credential type: ${credential::class.simpleName}")
        }

        return parseAuthenticationResponse(credential.authenticationResponseJson)
    }

    override suspend fun getPrfOutput(credentialId: ByteArray, salt: ByteArray): PrfOutput {
        // PRF extension support depends on the authenticator. Build a get request
        // with the PRF extension and attempt to extract the output.
        // Note: Android Credential Manager PRF support is authenticator-dependent.
        throw AuthException("PRF not yet supported on this platform")
    }

    // ── JSON builders ───────────────────────────────────────────────

    private fun buildCreationOptionsJson(options: RegisterOptions): String {
        val obj = buildJsonObject {
            put("challenge", b64url(options.challenge))
            put("rp", buildJsonObject {
                put("id", options.rpId)
                put("name", options.rpName)
            })
            put("user", buildJsonObject {
                put("id", b64url(options.userId))
                put("name", options.userName)
                put("displayName", options.userDisplayName)
            })
            put("pubKeyCredParams", buildJsonArray {
                add(buildJsonObject { put("type", "public-key"); put("alg", -7) })   // ES256
                add(buildJsonObject { put("type", "public-key"); put("alg", -257) }) // RS256
            })
            put("timeout", 60000)
            put("attestation", options.attestation)

            val sel = options.authenticatorSelection ?: AuthenticatorSelection()
            put("authenticatorSelection", buildJsonObject {
                sel.authenticatorAttachment?.let { put("authenticatorAttachment", it) }
                put("residentKey", sel.residentKey)
                put("userVerification", sel.userVerification)
            })
        }
        return obj.toString()
    }

    private fun buildRequestOptionsJson(options: AuthenticateOptions): String {
        val obj = buildJsonObject {
            put("challenge", b64url(options.challenge))
            put("rpId", options.rpId)
            put("timeout", 60000)
            put("userVerification", options.userVerification)

            options.allowCredentials?.let { creds ->
                put("allowCredentials", buildJsonArray {
                    creds.forEach { cred ->
                        add(buildJsonObject {
                            put("type", cred.type)
                            put("id", b64url(cred.id))
                        })
                    }
                })
            }
        }
        return obj.toString()
    }

    // ── Response parsers ────────────────────────────────────────────

    private fun parseRegistrationResponse(responseJson: String): RegisterResult {
        val obj = json.parseToJsonElement(responseJson).jsonObject
        val response = obj["response"]?.jsonObject
            ?: throw AuthException("Missing 'response' in registration response")

        val id = obj["rawId"]?.jsonPrimitive?.content
            ?: obj["id"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing credential id")
        val attestationObject = response["attestationObject"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing attestationObject")
        val clientDataJSON = response["clientDataJSON"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing clientDataJSON")

        return RegisterResult(
            credentialId = b64urlDecode(id),
            attestationObject = b64urlDecode(attestationObject),
            clientDataJSON = b64urlDecode(clientDataJSON),
        )
    }

    private fun parseAuthenticationResponse(responseJson: String): AuthenticateResult {
        val obj = json.parseToJsonElement(responseJson).jsonObject
        val response = obj["response"]?.jsonObject
            ?: throw AuthException("Missing 'response' in authentication response")

        val id = obj["rawId"]?.jsonPrimitive?.content
            ?: obj["id"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing credential id")
        val authenticatorData = response["authenticatorData"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing authenticatorData")
        val clientDataJSON = response["clientDataJSON"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing clientDataJSON")
        val signature = response["signature"]?.jsonPrimitive?.content
            ?: throw AuthException("Missing signature")
        val userHandle = response["userHandle"]?.jsonPrimitive?.content

        return AuthenticateResult(
            credentialId = b64urlDecode(id),
            authenticatorData = b64urlDecode(authenticatorData),
            clientDataJSON = b64urlDecode(clientDataJSON),
            signature = b64urlDecode(signature),
            userHandle = userHandle?.let { b64urlDecode(it) },
        )
    }

    companion object {
        private val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        private val decoder = java.util.Base64.getUrlDecoder()

        private fun b64url(data: ByteArray): String = encoder.encodeToString(data)
        private fun b64urlDecode(data: String): ByteArray = decoder.decode(data)
    }
}
