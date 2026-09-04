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
    const val CREDENTIAL_NOTIFICATION = "credential_notification"

    // Server → Client
    const val HANDSHAKE_COMPLETE = "handshake_complete"
    const val FLOW_PROGRESS = "flow_progress"
    const val FLOW_COMPLETE = "flow_complete"
    const val FLOW_ERROR = "flow_error"
    const val SIGN_REQUEST = "sign_request"
    const val MATCH_REQUEST = "match_request"
    const val PUSH = "push"
    const val ERROR = "error"
    const val NOTIFICATION_ACK = "notification_ack"
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
    /**
     * OAuth Client Attestation (draft-ietf-oauth-attestation-based-client-auth-04
     * §3.1): a Wallet Instance Attestation JWT (`typ: oauth-client-attestation+jwt`)
     * obtained from this wallet's own backend (`/wallet-provider/wia/generate`).
     * Forwarded by go-wallet-backend as the `OAuth-Client-Attestation` HTTP
     * header on PAR/token requests to the credential issuer - see
     * `internal/engine/client_attestation.go`'s `TransportSuppliedAttestation`.
     */
    @SerialName("client_attestation") val clientAttestation: String? = null,
    /**
     * The matching PoP JWT (`typ: oauth-client-attestation-pop+jwt`), freshly
     * signed per flow with `aud` = the credential issuer's own authorization
     * server, proving possession of the instance key the WIA above is bound
     * to (`cnf.jwk`/`cnf.jkt`). Forwarded as `OAuth-Client-Attestation-PoP`.
     */
    @SerialName("client_attestation_pop") val clientAttestationPoP: String? = null,
    /**
     * Renewal fields (credential re-issuance/renewal plan, Phase 1 Slice 2 -
     * see go-wallet-backend's `internal/engine/oid4vci.go` `Execute`). When
     * [refreshToken] is set, this is a renewal request rather than a fresh
     * issuance: [offer]/[credentialOfferUri] are unused, and [credentialIssuer]/
     * [selectedCredentialConfigurationId] are required instead (the client
     * already knows both from the credential being renewed).
     */
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("credential_issuer") val credentialIssuer: String? = null,
    @SerialName("selected_credential_configuration_id") val selectedCredentialConfigurationId: String? = null,
    /**
     * When set, asks the server to request a `generate_proof` signature
     * using this existing kid instead of a fresh key - same-wallet-unit
     * continuity evidence for a renewal (see
     * [SignRequestParams.reissuanceKid] equivalent server-side). Optional
     * even on a renewal request.
     */
    @SerialName("reissuance_kid") val reissuanceKid: String? = null,
    /**
     * On a renewal request, the private DPoP JWK previously captured from
     * [FlowCompleteMessage.dpopJwk] for this same refresh_token. The issuer
     * binds refresh_token to the exact DPoP key used at initial issuance
     * (RFC 9449/ARF 3.0 §6.6.6.2.2), so the backend must reuse this key
     * rather than generate a fresh one - see go-wallet-backend's
     * FlowStartMessage.DPoPJWK doc comment. Never persisted by the SDK
     * itself beyond whatever the caller does with it (privatedata, Phase 2).
     */
    @SerialName("dpop_jwk") val dpopJwk: String? = null,
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
    @SerialName("message_id") val messageId: String? = null,
    @SerialName("proof_jwt") val proofJwt: String? = null,
    @SerialName("vp_token") val vpToken: String? = null,
    val proofs: List<ProofObject>? = null,
    /**
     * Response to a `request_attestation` sign request (go-wallet-backend
     * `SignActionRequestAttestation`): the Wallet Instance Attestation JWT
     * (`oauth-client-attestation+jwt`) and the per-flow PoP
     * (`oauth-client-attestation-pop+jwt`) signed with the instance key over
     * the `audience`/`issuer` the engine supplied in [SignRequestParams].
     * Both null means "no attestation available - proceed without".
     */
    @SerialName("client_attestation") val clientAttestation: String? = null,
    @SerialName("client_attestation_pop") val clientAttestationPoP: String? = null,
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
    /**
     * OAuth refresh_token the issuer returned alongside this batch, if any
     * (credential re-issuance/renewal plan, Phase 1). The SDK does not
     * persist this durably yet (that's Phase 2 - `privatedata` storage);
     * for now the caller is responsible for holding onto it if a renewal
     * is wanted later.
     */
    @SerialName("refresh_token") val refreshToken: String? = null,
    /**
     * Present only alongside [refreshToken]: the private JWK of the
     * ephemeral DPoP key this flow used for its token exchange. Must be
     * presented back as [FlowStartMessage.dpopJwk] on a renewal request -
     * see that field's doc comment for why. The backend does not persist
     * this itself; the caller is responsible for storing it durably
     * alongside [refreshToken] (e.g. via privatedata).
     */
    @SerialName("dpop_jwk") val dpopJwk: String? = null,
    val timestamp: String? = null,
)

@Serializable
data class CredentialResult(
    val format: String,
    val credential: String,
    val vct: String? = null,
    @SerialName("type_metadata") val typeMetadata: JsonElement? = null,
    @SerialName("notification_id") val notificationId: String? = null,
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
    @SerialName("message_id") val messageId: String? = null,
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
    // The verifier's own session id for this presentation (from the
    // request_uri's "sessionId" query param, forwarded by go-wallet-backend)
    // - a real ZK/PPID pseudonym's verifier_context binds to THIS specific
    // session, not the verifier's static identity (confirmed 2026-08-17,
    // direct report from zk-cred-longfellow's V8/PPID author). Null for
    // non-ZK presentations or verifiers whose request_uri never carried one.
    @SerialName("verifier_session_id") val verifierSessionId: String? = null,
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

/**
 * Outgoing OID4VCI §10 credential lifecycle notification. The client supplies
 * the notification_id obtained at issuance; the backend supplies the issuer
 * endpoint and access token from ephemeral flow state.
 */
@Serializable
data class CredentialNotificationMessage(
    val type: String = MessageTypes.CREDENTIAL_NOTIFICATION,
    @SerialName("flow_id") val flowId: String,
    @SerialName("notification_id") val notificationId: String,
    val event: String,
    @SerialName("event_description") val eventDescription: String? = null,
    val timestamp: String? = null,
)

/** Incoming acknowledgement for a credential_notification. */
@Serializable
data class NotificationAckMessage(
    val type: String = MessageTypes.NOTIFICATION_ACK,
    @SerialName("flow_id") val flowId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
    val status: String,
    val error: String? = null,
    val timestamp: String? = null,
)

/** OID4VCI §10 credential lifecycle event identifiers reportable to the backend. */
object CredentialNotificationEvent {
    const val ACCEPTED = "credential_accepted"
    const val FAILURE = "credential_failure"
}
