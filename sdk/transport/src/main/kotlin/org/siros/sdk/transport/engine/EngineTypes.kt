// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** Message types used in the wallet backend engine WebSocket protocol. */
object MessageTypes {
    // Client → Server
    const val HANDSHAKE = "handshake"
    const val FLOW_START = "flow_start"
    const val FLOW_ACTION = "flow_action"
    const val SIGN_RESPONSE = "sign_response"
    const val MATCH_RESPONSE = "match_response"

    // Server → Client
    const val HANDSHAKE_COMPLETE = "handshake_complete"
    const val FLOW_PROGRESS = "flow_progress"
    const val FLOW_COMPLETE = "flow_complete"
    const val FLOW_ERROR = "flow_error"
    const val SIGN_REQUEST = "sign_request"
    const val MATCH_REQUEST = "match_request"
    const val PUSH = "push"
    const val ERROR = "error"
}

/** Base envelope — every engine message carries at least a type. */
@Serializable
data class EngineMessage(
    val type: String,
    @SerialName("flow_id") val flowId: String? = null,
    @SerialName("message_id") val messageId: String? = null,
    val timestamp: String? = null,
)

// ── Client → Server ─────────────────────────────────────────────────

@Serializable
data class HandshakeMessage(
    val type: String = MessageTypes.HANDSHAKE,
    @SerialName("app_token") val appToken: String,
)

@Serializable
data class FlowStartMessage(
    val type: String = MessageTypes.FLOW_START,
    val protocol: String,
    val offer: String? = null,
    @SerialName("credential_offer_uri") val credentialOfferUri: String? = null,
    @SerialName("request_uri") val requestUri: String? = null,
    @SerialName("request_uri_ref") val requestUriRef: String? = null,
    val vct: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("auth_code") val authCode: String? = null,
    @SerialName("code_verifier") val codeVerifier: String? = null,
    val timestamp: String? = null,
)

@Serializable
data class FlowActionMessage(
    val type: String = MessageTypes.FLOW_ACTION,
    @SerialName("flow_id") val flowId: String,
    val action: String,
    val payload: JsonObject? = null,
    val timestamp: String? = null,
)

@Serializable
data class SignResponseMessage(
    val type: String = MessageTypes.SIGN_RESPONSE,
    @SerialName("flow_id") val flowId: String,
    @SerialName("proof_jwt") val proofJwt: String? = null,
    @SerialName("vp_token") val vpToken: String? = null,
    val proofs: List<ProofObject>? = null,
    val timestamp: String? = null,
)

@Serializable
data class ProofObject(
    @SerialName("proof_type") val proofType: String,
    val jwt: String? = null,
    val attestation: String? = null,
)

@Serializable
data class MatchResponseMessage(
    val type: String = MessageTypes.MATCH_RESPONSE,
    @SerialName("flow_id") val flowId: String,
    val matches: List<CredentialMatch>,
    @SerialName("no_match_reason") val noMatchReason: String? = null,
    val error: String? = null,
    val timestamp: String? = null,
)

@Serializable
data class CredentialMatch(
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
    @SerialName("credential_id") val credentialId: String,
    val format: String,
    val vct: String? = null,
    @SerialName("available_claims") val availableClaims: List<String>? = null,
)

// ── Server → Client ─────────────────────────────────────────────────

@Serializable
data class HandshakeCompleteMessage(
    val type: String = MessageTypes.HANDSHAKE_COMPLETE,
    @SerialName("session_id") val sessionId: String,
    val capabilities: List<String>? = null,
    val timestamp: String? = null,
)

@Serializable
data class FlowProgressMessage(
    val type: String = MessageTypes.FLOW_PROGRESS,
    @SerialName("flow_id") val flowId: String,
    val step: String,
    val payload: JsonElement? = null,
    val timestamp: String? = null,
)

@Serializable
data class FlowCompleteMessage(
    val type: String = MessageTypes.FLOW_COMPLETE,
    @SerialName("flow_id") val flowId: String,
    val credentials: List<CredentialResult>? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("type_metadata") val typeMetadata: JsonElement? = null,
    @SerialName("credential_issuer") val credentialIssuer: String? = null,
    @SerialName("selected_credential_configuration_id") val selectedCredentialConfigurationId: String? = null,
    val timestamp: String? = null,
)

@Serializable
data class CredentialResult(
    val format: String,
    val credential: String,
    val vct: String? = null,
    @SerialName("type_metadata") val typeMetadata: JsonElement? = null,
)

@Serializable
data class FlowErrorMessage(
    val type: String = MessageTypes.FLOW_ERROR,
    @SerialName("flow_id") val flowId: String? = null,
    val step: String? = null,
    val error: FlowError,
    val timestamp: String? = null,
)

@Serializable
data class FlowError(
    val code: String,
    val message: String,
    val details: JsonObject? = null,
)

@Serializable
data class SignRequestMessage(
    val type: String = MessageTypes.SIGN_REQUEST,
    @SerialName("flow_id") val flowId: String,
    val action: String,
    val params: SignRequestParams,
    val timestamp: String? = null,
)

@Serializable
data class SignRequestParams(
    val audience: String? = null,
    val nonce: String? = null,
    val issuer: String? = null,
    @SerialName("proof_type") val proofType: String? = null,
    @SerialName("proof_types_supported") val proofTypesSupported: JsonObject? = null,
    val count: Int? = null,
    @SerialName("credentials_to_include") val credentialsToInclude: List<CredentialRef>? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("verifier_jwk_thumbprint") val verifierJwkThumbprint: String? = null,
)

@Serializable
data class CredentialRef(
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
    @SerialName("credential_id") val credentialId: String,
    @SerialName("disclosed_claims") val disclosedClaims: List<String>? = null,
)

@Serializable
data class MatchRequestMessage(
    val type: String = MessageTypes.MATCH_REQUEST,
    @SerialName("flow_id") val flowId: String,
    @SerialName("dcql_query") val dcqlQuery: JsonElement? = null,
    val timestamp: String? = null,
)

@Serializable
data class PushMessage(
    val type: String = MessageTypes.PUSH,
    @SerialName("push_type") val pushType: String,
    val credentials: List<CredentialResult>? = null,
    val timestamp: String? = null,
)

@Serializable
data class ErrorMessage(
    val type: String = MessageTypes.ERROR,
    val code: String,
    @SerialName("message") val details: String,
    val timestamp: String? = null,
)
