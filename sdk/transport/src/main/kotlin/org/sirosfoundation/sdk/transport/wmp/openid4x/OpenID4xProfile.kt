// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.transport.wmp.openid4x

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.sirosfoundation.sdk.transport.wmp.*
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap

// ---------------------------------------------------------------------------
// Flow Type Constants
// ---------------------------------------------------------------------------

object OID4FlowTypes {
    const val OID4VCI = "oid4vci"
    const val OID4VP = "oid4vp"
}

// ---------------------------------------------------------------------------
// OID4VCI Step Constants
// ---------------------------------------------------------------------------

object VCIStep {
    const val PARSING_OFFER = "parsing_offer"
    const val RESOLVING_METADATA = "resolving_metadata"
    const val METADATA_FETCHED = "metadata_fetched"
    const val EVALUATING_TRUST = "evaluating_trust"
    const val TRUST_EVALUATED = "trust_evaluated"
    const val AWAITING_OFFER_ACCEPTANCE = "awaiting_offer_acceptance"
    const val AWAITING_TX_CODE = "awaiting_tx_code"
    const val AUTHORIZATION_PENDING = "authorization_pending"
    const val GENERATING_PROOF = "generating_proof"
    const val REQUESTING_CREDENTIAL = "requesting_credential"
    const val CREDENTIAL_RECEIVED = "credential_received"
}

// ---------------------------------------------------------------------------
// OID4VP Step Constants
// ---------------------------------------------------------------------------

object VPStep {
    const val PARSING_REQUEST = "parsing_request"
    const val REQUEST_PARSED = "request_parsed"
    const val MATCHING_CREDENTIALS = "matching_credentials"
    const val AWAITING_CONSENT = "awaiting_consent"
    const val GENERATING_PRESENTATION = "generating_presentation"
}

// ---------------------------------------------------------------------------
// Action Constants
// ---------------------------------------------------------------------------

object OID4Action {
    const val ACCEPT_OFFER = "accept_offer"
    const val PROVIDE_TX_CODE = "provide_tx_code"
    const val AUTHORIZE = "authorize"
    const val SELECT_CREDENTIALS = "select_credentials"
    const val CANCEL = "cancel"
}

// ---------------------------------------------------------------------------
// Credential Format Constants
// ---------------------------------------------------------------------------

object CredentialFormat {
    const val VC_SD_JWT = "vc+sd-jwt"
    const val DC_SD_JWT = "dc+sd-jwt"
    const val MSO_MDOC = "mso_mdoc"
    const val JWT_VC_JSON = "jwt_vc_json"
}

// ---------------------------------------------------------------------------
// Grant Type Constants
// ---------------------------------------------------------------------------

object GrantType {
    const val AUTHORIZATION_CODE = "authorization_code"
    const val PRE_AUTHORIZED_CODE = "pre-authorized_code"
}

// ---------------------------------------------------------------------------
// Proof Type Constants
// ---------------------------------------------------------------------------

object ProofType {
    const val JWT = "jwt"
    const val ATTESTATION = "attestation"
    const val CWT = "cwt"
}

// ---------------------------------------------------------------------------
// OID4VCI §10 Credential Lifecycle Events
// ---------------------------------------------------------------------------

object CredentialEvent {
    const val ACCEPTED = "credential_accepted"
    const val FAILURE = "credential_failure"
}

// ---------------------------------------------------------------------------
// Typed Data Structures
// ---------------------------------------------------------------------------

@Serializable
data class CredentialConfigurationSupported(
    val format: String,
    val scope: String? = null,
    val vct: String? = null,
    val doctype: String? = null,
    @SerialName("proof_types_supported") val proofTypesSupported: JsonObject? = null,
    val display: List<CredentialDisplay>? = null,
)

@Serializable
data class CredentialDisplay(
    val name: String,
    val locale: String? = null,
    val description: String? = null,
    @SerialName("logo_uri") val logoUri: String? = null,
    @SerialName("logo_alt_text") val logoAltText: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
)

@Serializable
data class CredentialResult(
    val format: String,
    val credential: String,
    val vct: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
)

@Serializable
data class VPTokenResult(
    @SerialName("vp_token") val vpToken: String? = null,
    @SerialName("presentation_submission") val presentationSubmission: JsonElement? = null,
    @SerialName("response_code") val responseCode: String? = null,
)

@Serializable
data class TransactionData(
    val type: String,
    val params: JsonObject? = null,
    @SerialName("credential_ids") val credentialIds: List<String>? = null,
    @SerialName("hash_alg") val hashAlgorithm: String? = null,
)

@Serializable
data class SignSubFlowParams(
    val action: String,
    val nonce: String,
    val audience: String,
    @SerialName("proof_type") val proofType: String? = null,
    @SerialName("parent_flow_id") val parentFlowId: String? = null,
    val count: Int? = null,
    @SerialName("transaction_data") val transactionData: List<TransactionData>? = null,
)

// ---------------------------------------------------------------------------
// Client Attestation (WIA)
// ---------------------------------------------------------------------------

/**
 * Provider for OAuth client attestation (WIA + PoP).
 * Implementations obtain attestation credentials from the wallet provider
 * infrastructure.
 */
interface ClientAttestationProvider {
    /**
     * Obtain a client attestation for the given audience.
     * @param audience The token endpoint URL of the issuer.
     * @return The client attestation pair (WIA JWT + PoP JWT).
     */
    suspend fun getAttestation(audience: String): ClientAttestation
}

@Serializable
data class ClientAttestation(
    /** Wallet Instance Attestation JWT. */
    @SerialName("client_assertion") val clientAssertion: String,
    /** Proof of Possession JWT. */
    @SerialName("client_assertion_pop") val clientAssertionPop: String,
)

// ---------------------------------------------------------------------------
// OpenID4x Profile Implementation
// ---------------------------------------------------------------------------

/**
 * Configuration for the OpenID4x profile.
 *
 * @param onProgress Called for each flow progress notification.
 * @param onSignRequest Called when the engine requests a key proof or VP signature.
 * @param onMatchRequest Called when the engine requests credential matching.
 * @param onTrustEvaluation Called when the engine requests trust evaluation.
 * @param onComplete Called when a flow completes successfully.
 * @param onError Called when a flow fails.
 */
data class OpenID4xConfig(
    val onProgress: (suspend (String, String, JsonObject?) -> Unit)? = null,
    val onSignRequest: (suspend (String, SignSubFlowParams) -> SignSubFlowResult)? = null,
    val onMatchRequest: (suspend (String, JsonObject?) -> MatchResult)? = null,
    val onTrustEvaluation: (suspend (String, JsonObject?) -> TrustResult)? = null,
    val onComplete: (suspend (String, JsonObject?) -> Unit)? = null,
    val onError: (suspend (String, String?, String?) -> Unit)? = null,
    val attestationProvider: ClientAttestationProvider? = null,
)

/** Result of a sign sub-flow request. */
data class SignSubFlowResult(
    val proofs: List<ProofObject>? = null,
    val vpToken: String? = null,
)

@Serializable
data class ProofObject(
    @SerialName("proof_type") val proofType: String = ProofType.JWT,
    val jwt: String? = null,
)

/** Result of a credential matching request. */
data class MatchResult(
    val matches: List<CredentialMatch>,
)

@Serializable
data class CredentialMatch(
    @SerialName("credential_id") val credentialId: String,
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
    @SerialName("disclosed_claims") val disclosedClaims: List<String>? = null,
)

/** Result of trust evaluation. */
data class TrustResult(
    val trusted: Boolean,
    val framework: String? = null,
    val reason: String? = null,
)

// Sub-flow step names used by the engine
private const val STEP_SIGN_REQUEST = "sign_request"
private const val STEP_MATCH_REQUEST = "match_request"
private const val STEP_TRUST_EVALUATION = "trust_evaluation_required"

/**
 * OpenID4x WMP profile for OID4VCI and OID4VP flows.
 *
 * Handles server-initiated flows: the backend engine starts flows and
 * the SDK responds to progress events, sign requests, match requests,
 * and trust evaluations.
 */
class OpenID4xProfile(
    private val config: OpenID4xConfig = OpenID4xConfig(),
) : WmpProfile, WmpFlowHandler {

    private var peer: WmpPeerContext? = null
    private val activeFlowTypes = ConcurrentHashMap<String, String>()

    // ---- WmpProfile ----

    override val name: String = "openid4x"
    override val capabilities: List<String> = listOf("oid4vci", "oid4vp")

    override fun init(ctx: WmpPeerContext) {
        peer = ctx
    }

    // ---- WmpFlowHandler ----

    override val flowTypes: List<String> = listOf(OID4FlowTypes.OID4VCI, OID4FlowTypes.OID4VP)

    override suspend fun startFlow(params: FlowStartParams): FlowStartResult {
        activeFlowTypes[params.flowId] = params.flowType
        return FlowStartResult(flowId = params.flowId, flowType = params.flowType)
    }

    override suspend fun handleProgress(params: FlowProgressParams) {
        val flowId = params.flowId
        val step = params.step
        val payload = params.payload

        Timber.d("OpenID4x progress: flow=$flowId step=$step")

        when {
            // Sign request sub-flow (generate_proof or sign_presentation)
            step == STEP_SIGN_REQUEST || step == VCIStep.GENERATING_PROOF -> {
                handleSignRequest(flowId, payload)
            }
            // Match request (credential selection for VP)
            step == STEP_MATCH_REQUEST || step == VPStep.MATCHING_CREDENTIALS -> {
                handleMatchRequest(flowId, payload)
            }
            // Trust evaluation
            step == STEP_TRUST_EVALUATION || step == VCIStep.EVALUATING_TRUST -> {
                handleTrustEvaluation(flowId, payload)
            }
            // General progress
            else -> {
                config.onProgress?.invoke(flowId, step, payload)
            }
        }
    }

    override suspend fun handleAction(params: FlowActionParams): FlowActionResult {
        return FlowActionResult(flowId = params.flowId, accepted = true)
    }

    override suspend fun handleComplete(params: FlowCompleteParams) {
        config.onComplete?.invoke(params.flowId, params.result)
    }

    override suspend fun handleError(params: FlowErrorParams) {
        config.onError?.invoke(params.flowId, params.code, params.message)
    }

    override suspend fun handleCancel(params: FlowCancelParams) {
        Timber.d("OpenID4x flow cancelled: ${params.flowId} reason=${params.reason}")
    }

    // ---- Sub-flow handlers ----

    private suspend fun handleSignRequest(flowId: String, payload: JsonObject?) {
        val handler = config.onSignRequest ?: return

        val signParams = payload?.let {
            try {
                val codec = peer?.codec ?: WmpCodec()
                codec.json.decodeFromJsonElement(SignSubFlowParams.serializer(), it)
            } catch (e: Exception) {
                Timber.e(e, "Failed to decode sign request params")
                null
            }
        } ?: return

        try {
            val result = handler.invoke(flowId, signParams)
            sendSignResponse(flowId, result)
        } catch (e: Exception) {
            Timber.e(e, "Sign request handler failed")
            sendFlowError(flowId, "SIGN_ERROR", e.message)
        }
    }

    private suspend fun handleMatchRequest(flowId: String, payload: JsonObject?) {
        val handler = config.onMatchRequest ?: return

        try {
            val result = handler.invoke(flowId, payload)
            sendMatchResponse(flowId, result)
        } catch (e: Exception) {
            Timber.e(e, "Match request handler failed")
            sendFlowError(flowId, "MATCH_ERROR", e.message)
        }
    }

    private suspend fun handleTrustEvaluation(flowId: String, payload: JsonObject?) {
        val handler = config.onTrustEvaluation ?: return

        try {
            val result = handler.invoke(flowId, payload)
            sendTrustResult(flowId, result)
        } catch (e: Exception) {
            Timber.e(e, "Trust evaluation handler failed")
            sendTrustResult(flowId, TrustResult(trusted = false, reason = e.message))
        }
    }

    // ---- Response helpers ----

    private suspend fun sendSignResponse(flowId: String, result: SignSubFlowResult) {
        val ctx = peer ?: return
        val params = kotlinx.serialization.json.buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", kotlinx.serialization.json.JsonPrimitive(flowId))
            put("action", kotlinx.serialization.json.JsonPrimitive("sign_response"))
            result.proofs?.let { proofs ->
                put("proofs", ctx.codec.json.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(ProofObject.serializer()),
                    proofs,
                ))
            }
            result.vpToken?.let {
                put("vp_token", kotlinx.serialization.json.JsonPrimitive(it))
            }
        }
        ctx.notify(WmpMethods.FLOW_ACTION, params)
    }

    private suspend fun sendMatchResponse(flowId: String, result: MatchResult) {
        val ctx = peer ?: return
        val params = kotlinx.serialization.json.buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", kotlinx.serialization.json.JsonPrimitive(flowId))
            put("action", kotlinx.serialization.json.JsonPrimitive("match_response"))
            put("matches", ctx.codec.json.encodeToJsonElement(
                kotlinx.serialization.builtins.ListSerializer(CredentialMatch.serializer()),
                result.matches,
            ))
        }
        ctx.notify(WmpMethods.FLOW_ACTION, params)
    }

    private suspend fun sendTrustResult(flowId: String, result: TrustResult) {
        val ctx = peer ?: return
        val params = kotlinx.serialization.json.buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", kotlinx.serialization.json.JsonPrimitive(flowId))
            put("action", kotlinx.serialization.json.JsonPrimitive("trust_result"))
            put("trusted", kotlinx.serialization.json.JsonPrimitive(result.trusted))
            result.framework?.let { put("framework", kotlinx.serialization.json.JsonPrimitive(it)) }
            result.reason?.let { put("reason", kotlinx.serialization.json.JsonPrimitive(it)) }
        }
        ctx.notify(WmpMethods.FLOW_ACTION, params)
    }

    private suspend fun sendFlowError(flowId: String, code: String, message: String?) {
        val ctx = peer ?: return
        val params = kotlinx.serialization.json.buildJsonObject {
            put("wmp", ctx.codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", kotlinx.serialization.json.JsonPrimitive(flowId))
            put("code", kotlinx.serialization.json.JsonPrimitive(code))
            message?.let { put("message", kotlinx.serialization.json.JsonPrimitive(it)) }
        }
        ctx.notify(WmpMethods.FLOW_ERROR, params)
    }
}
